//! Cross-artifact path evidence retains its origin; path matches are candidates.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use rusqlite::{types::ValueRef, Connection};

use super::schema;
use super::{text, text_raw, Cell, Ctx, DerivedDb, SourceRef};

fn local_key(path: &str) -> Option<(String, String)> {
    let shape = crate::overview::classify_path(path);
    (shape.kind == "drive_absolute").then_some((shape.drive, shape.key))
}

fn row_text<'a>(row: &'a rusqlite::Row<'_>, index: usize) -> Result<&'a str> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(""),
        ValueRef::Text(bytes) => Ok(std::str::from_utf8(bytes)?),
        _ => Err(anyhow!("PathReferences: non-text evidence at column {index}")),
    }
}

fn execution_paths(ctx: &Ctx) -> Result<BTreeMap<(String, String), Vec<String>>> {
    let conn = super::stream::open_ro(&ctx.overview_dir().join("ExecutionHistory.sqlite"))?;
    let mut query = conn.prepare(
        "SELECT record_id,COALESCE(NULLIF(program_path_resolved,''),program_path)
         FROM ExecutionHistory WHERE host_id=?1 AND dataset_id=?2 ORDER BY record_id",
    )?;
    let mut rows = query.query(rusqlite::params![ctx.host_id, ctx.dataset_id])?;
    let mut paths: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        if let Some(key) = local_key(row_text(row, 1)?) {
            paths.entry(key).or_default().push(row.get(0)?);
        }
    }
    Ok(paths)
}

fn write_query(
    ctx: &Ctx,
    db: &mut DerivedDb,
    origin_table: &'static str,
    child_table: Option<&'static str>,
    sql: &str,
    executions: &BTreeMap<(String, String), Vec<String>>,
) -> Result<()> {
    let origin_db = format!("{origin_table}.sqlite");
    let conn = super::stream::open_ro(&ctx.overview_dir().join(&origin_db))?;
    let mut query = conn.prepare(sql)?;
    let mut rows = query.query(rusqlite::params![ctx.host_id, ctx.dataset_id])?;
    let mut sources = conn.prepare_cached(
        "SELECT source_dataset_id,source_artifact,source_db,source_table,source_rowid,
             source_field,source_record_key,source_file,source_label
         FROM source_records WHERE record_id=?1 ORDER BY ordinal",
    )?;
    let task_root = if origin_table == "ScheduledTasks" && child_table.is_none() {
        ctx.meta.resolve_path("%SystemRoot%", None)
    } else {
        Cell::Null
    };
    while let Some(row) = rows.next()? {
        let raw = row_text(row, 5)?;
        if raw.is_empty() {
            continue;
        }
        let normalized = row_text(row, 6)?;
        let stored_resolved = row_text(row, 7)?;
        let expanded = if let Cell::Text(root) = &task_root {
            let uri = row_text(row, 4)?;
            let mut path = String::with_capacity(root.len() + 16 + uri.len());
            path.push_str(root.trim_end_matches(['\\', '/']));
            path.push_str(r"\System32\Tasks\");
            path.extend(uri.trim_start_matches(['\\', '/']).chars()
                .map(|ch| if ch == '/' { '\\' } else { ch }));
            Cell::Text(path)
        } else {
            Cell::Null
        };
        let resolved = match &expanded {
            Cell::Text(path) => path.as_str(),
            _ => stored_resolved,
        };
        let origin_basis = row_text(row, 8)?;
        let resolution_basis = if matches!(expanded, Cell::Text(_)) {
            Cell::Text(format!("{origin_basis}:machine_environment"))
        } else {
            text_raw(origin_basis)
        };
        let comparison = if !resolved.is_empty() {
            resolved
        } else if !normalized.is_empty() {
            normalized
        } else {
            raw
        };
        let shape = crate::overview::classify_path(comparison);
        let kind = if shape.kind == "volume_relative" { "unresolved" } else { shape.kind };
        let key = (shape.drive, shape.key);
        let candidates = if kind == "drive_absolute" { executions.get(&key) } else { None };
        let record_id = row_text(row, 0)?;
        let role = row_text(row, 3)?;
        let raw_input = row_text(row, 4)?;
        let mut record = ctx.record(schema::spec("PathReferences").expect("PathReferences schema"));
        record.timestamp(row_text(row, 9)?, row_text(row, 10)?);
        record.set("account", text_raw(row_text(row, 11)?));
        record.set("account_sid", text_raw(row_text(row, 12)?));
        record.set("event_type", text(origin_table));
        record.set("description", text_raw(raw_input));
        record.set("path", Cell::Text(key.1));
        record.set("path_kind", text(kind));
        record.set("target_drive_letter", text(&key.0));
        record.set("target_path", text_raw(raw));
        record.set("target_path_resolved", text_raw(resolved));
        record.set("label", text_raw(raw.rsplit(['\\', '/']).next().unwrap_or(raw)));
        record.set("timestamp_source", text("origin_record"));
        record.child("PathReferenceOrigins", vec![
            text(&origin_db), text(origin_table), text(record_id),
            child_table.map(text).unwrap_or(Cell::Null),
            row.get::<_, Option<i64>>(1)?.map(Cell::Int).unwrap_or(Cell::Null),
            text(row_text(row, 2)?), text(role), text_raw(raw_input), resolution_basis,
        ]);
        for source in sources.query_map([record_id], |source| Ok(SourceRef {
            dataset: source.get(0)?, artifact: source.get(1)?, db: source.get(2)?,
            table: source.get(3)?, rowid: source.get(4)?, field: source.get(5)?,
            record_key: source.get(6)?, file: source.get(7)?, label: source.get(8)?,
        }))? {
            record.source(Some(source?));
        }
        if let Some(candidates) = candidates {
            for execution in candidates {
                record.child("PathReferenceExecutionCandidates", vec![
                    text(execution), text("same_host_dataset_drive_path"),
                ]);
            }
        }
        db.write(record)?;
    }
    Ok(())
}

pub(super) fn write(ctx: &Ctx, db: &mut DerivedDb) -> Result<()> {
    let executions = execution_paths(ctx)?;
    write_query(ctx, db, "ScheduledTasks", Some("TaskActions"),
        "SELECT t.record_id,a.ordinal,'command','scheduled_task_action_command',
             a.command,a.command,NULL,a.command_resolved,
             CASE WHEN a.command_resolved IS NOT NULL THEN 'metadata_environment'
               WHEN instr(a.command,'%')>0 THEN 'unresolved' ELSE 'literal' END,
             t.timestamp,t.timestamp_kind,t.account,t.account_sid
         FROM ScheduledTasks t JOIN TaskActions a ON a.record_id=t.record_id
         WHERE t.host_id=?1 AND t.dataset_id=?2 AND a.action_type='Exec'
         ORDER BY t.record_id,a.ordinal",
        &executions,
    )?;
    write_query(ctx, db, "ScheduledTasks", None,
        r#"SELECT record_id,NULL,'uri','scheduled_task_definition_file',uri,
             '%SystemRoot%\System32\Tasks\'||ltrim(replace(uri,'/','\'),'\'),
             NULL,NULL,'xml_uri_expected_task_store',timestamp,timestamp_kind,account,account_sid
         FROM ScheduledTasks WHERE host_id=?1 AND dataset_id=?2
           AND evidence_kind='task_definition' AND source_format='xml' AND uri IS NOT NULL AND uri<>''
           AND instr(uri,':')=0 AND substr(replace(uri,'/','\'),1,2)<>'\\'
         ORDER BY record_id"#,
        &executions,
    )?;
    write_query(ctx, db, "ServiceHistory", None,
        "SELECT record_id,NULL,'image_path','service_image_path',image_path,executable_path,
             NULL,executable_path_resolved,
             executable_basis||':'||CASE WHEN executable_path_resolved IS NOT NULL
               THEN 'metadata_environment' WHEN instr(executable_path,'%')>0
               THEN 'unresolved' ELSE 'literal' END,
             timestamp,timestamp_kind,account,account_sid
         FROM ServiceHistory WHERE host_id=?1 AND dataset_id=?2
           AND executable_path IS NOT NULL ORDER BY record_id",
        &executions,
    )?;
    write_query(ctx, db, "FirewallHistory", Some("FirewallAppPaths"),
        "SELECT f.record_id,p.ordinal,'path_raw',p.role,p.path_raw,p.path_raw,
             NULL,p.path_resolved,p.resolution_basis,
             f.timestamp,f.timestamp_kind,f.account,f.account_sid
         FROM FirewallHistory f JOIN FirewallAppPaths p ON p.record_id=f.record_id
         WHERE f.host_id=?1 AND f.dataset_id=?2 ORDER BY f.record_id,p.ordinal",
        &executions,
    )?;
    write_query(ctx, db, "WerReports", Some("WerPaths"),
        "SELECT w.record_id,p.ordinal,'path_raw',p.path_role,p.path_raw,p.path_raw,
             p.path_normalized,p.path_resolved,p.path_basis||':'||p.resolution_status,
             w.timestamp,w.timestamp_kind,w.account,w.account_sid
         FROM WerReports w JOIN WerPaths p ON p.record_id=w.record_id
         WHERE w.host_id=?1 AND w.dataset_id=?2 AND p.path_role<>'report_file'
         ORDER BY w.record_id,p.ordinal",
        &executions,
    )?;
    Ok(())
}

pub(super) fn validate(conn: &Connection, out_dir: &Path) -> Result<()> {
    let origins = {
        let mut query = conn.prepare(
            "SELECT DISTINCT origin_db, origin_table FROM PathReferenceOrigins ORDER BY origin_db, origin_table",
        )?;
        let rows = query.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (database, table) in origins {
        let spec = database.strip_suffix(".sqlite").and_then(schema::spec)
            .filter(|spec| spec.table == table)
            .ok_or_else(|| anyhow!("PathReferences: invalid origin database/table {database}/{table}"))?;
        let path = out_dir.join("_OVERVIEW").join(&database);
        if !path.is_file() {
            return Err(anyhow!("PathReferences: missing origin database {database}"));
        }
        conn.execute("ATTACH DATABASE ?1 AS origin_target", [path.to_string_lossy().as_ref()])?;
        let invalid: bool = conn.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM PathReferenceOrigins o
                 JOIN PathReferences p ON p.record_id=o.record_id
                 LEFT JOIN origin_target.{} t ON t.record_id=o.origin_record_id
                   AND t.host_id=p.host_id AND t.dataset_id=p.dataset_id
                 WHERE o.origin_db=?1 AND o.origin_table=?2 AND t.record_id IS NULL)",
                crate::sqlite::quote_ident(&table),
            ),
            rusqlite::params![database, table], |row| row.get(0),
        )?;
        if invalid {
            return Err(anyhow!("PathReferences: missing or foreign origin in {database}/{table}"));
        }
        let children = {
            let mut query = conn.prepare(
                "SELECT DISTINCT origin_child_table FROM PathReferenceOrigins
                 WHERE origin_db=?1 AND origin_table=?2 AND origin_child_table IS NOT NULL",
            )?;
            let rows = query.query_map(rusqlite::params![database, table], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for child in children {
            let child_spec = spec.child(&child)
                .filter(|child| child.columns.contains(&"record_id") && child.columns.contains(&"ordinal"))
                .ok_or_else(|| anyhow!("PathReferences: invalid origin child {database}/{child}"))?;
            let invalid: bool = conn.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM PathReferenceOrigins o
                     LEFT JOIN origin_target.{} t ON t.record_id=o.origin_record_id
                       AND t.ordinal=o.origin_ordinal
                     WHERE o.origin_db=?1 AND o.origin_table=?2 AND o.origin_child_table=?3
                       AND t.record_id IS NULL)",
                    crate::sqlite::quote_ident(child_spec.table),
                ),
                rusqlite::params![database, table, child], |row| row.get(0),
            )?;
            if invalid {
                return Err(anyhow!("PathReferences: missing origin child {database}/{child}"));
            }
        }
        conn.execute_batch("DETACH DATABASE origin_target")?;
    }
    let executions = out_dir.join("_OVERVIEW/ExecutionHistory.sqlite");
    conn.execute("ATTACH DATABASE ?1 AS execution_target", [executions.to_string_lossy().as_ref()])?;
    let invalid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM PathReferenceExecutionCandidates c
         JOIN PathReferences p ON p.record_id=c.record_id
         LEFT JOIN execution_target.ExecutionHistory e ON e.record_id=c.execution_record_id
           AND e.host_id=p.host_id AND e.dataset_id=p.dataset_id
         WHERE e.record_id IS NULL)",
        [], |row| row.get(0),
    )?;
    if invalid {
        return Err(anyhow!("PathReferences: missing or foreign execution candidate"));
    }
    conn.execute_batch("DETACH DATABASE execution_target")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_candidates_require_an_explicit_local_drive() {
        assert_eq!(local_key("C:\\Windows\\agent.exe"), local_key("c:/windows/agent.exe"));
        assert_ne!(local_key("C:\\Windows\\agent.exe"), local_key("D:\\Windows\\agent.exe"));
        for path in ["agent.exe", "C:agent.exe", "\\Device\\HarddiskVolume1\\agent.exe",
            "\\Windows\\agent.exe", "\\\\server\\share\\agent.exe", "%USERPROFILE%\\agent.exe"] {
            assert_eq!(local_key(path), None, "{path}");
        }
    }
}
