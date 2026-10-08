//! Service and registry snapshots are environment evidence, not connections.
use super::{Ctx, DerivedDb};
use crate::overview::EventLogOverviewCache;
use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, events: &EventLogOverviewCache) -> Result<()> {
    let directory = ctx.out_dir.join("REGISTRY");
    let mut paths = match std::fs::read_dir(directory) {
        Ok(entries) => entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            p.extension().is_some_and(|e| e == "sqlite")
                && (stem.eq_ignore_ascii_case("SYSTEM")
                    || stem.strip_prefix("SYSTEM_").is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
        }).collect::<Vec<_>>(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    paths.sort();
    for path in paths {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut selection = conn.prepare("SELECT DISTINCT value_data FROM Registry WHERE lower(key_path) LIKE '%\\select' AND lower(value_name)='current'")?;
        let current = selection.query_map([], |r| r.get::<_, Option<String>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let current = if current.len() == 1 {
            current[0].as_deref().and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0)
        } else { None };
        let active = current.map(|v| format!("controlset{v:03}"));
        let mut query = conn.prepare(
            "SELECT rowid,last_write,key_path,value_name,value_type,value_data,value_data_hex,entry_kind,_source_file
             FROM Registry WHERE lower(key_path) LIKE '%\\services\\lanmanserver%'
             OR (lower(key_path) LIKE '%\\select' AND lower(value_name)='current') ORDER BY rowid")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(2)?;
            let name: Option<String> = row.get(3)?;
            let lower = key.to_ascii_lowercase();
            let kind = if lower.ends_with("\\select") {
                "control_set_selection"
            } else if lower.ends_with("\\services\\lanmanserver") {
                "service_configuration"
            } else if lower.ends_with("\\services\\lanmanserver\\parameters") {
                "share_configuration"
            } else if lower.ends_with("\\services\\lanmanserver\\shares")
                || lower.contains("\\services\\lanmanserver\\shares\\") {
                "share_definition"
            } else { continue };
            let control_set = lower.split('\\').find(|part| part.starts_with("controlset"));
            let control_status = match (control_set, active.as_deref()) {
                (Some(value), Some(selected)) if value == selected => "active",
                (Some(_), Some(_)) => "inactive",
                _ => "unknown",
            };
            let file: Option<String> = row.get(8)?;
            let source = ctx.facts.source_from_row(&path, "Registry", row.get(0)?, file.as_deref(), Some(kind))?
                .ok_or_else(|| anyhow::anyhow!("missing SMB environment facts: {}", path.display()))?;
            db.conn().execute(
                "INSERT INTO SmbEnvironment(environment_id,host_id,dataset_id,evidence_kind,timestamp,timestamp_kind,
                 key_path,value_name,value_type,value_data,value_data_hex,entry_kind,control_set,control_set_status,
                 source_dataset_id,source_db,source_table,source_rowid,source_file)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,kind,
                    row.get::<_,Option<String>>(1)?.filter(|s|!s.is_empty()),"registry_key_last_write",
                    key,name,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,
                    row.get::<_,Option<String>>(6)?,row.get::<_,Option<String>>(7)?,control_set,control_status,
                    source.dataset,source.db,source.table,source.rowid,source.file],
            )?;
        }
    }
    for row in events.rows() {
        if row.get("Provider").map(String::as_str) != Some("Service Control Manager")
            || row.get("Channel").map(String::as_str) != Some("System") { continue; }
        let Some(payload) = row.get("EventData").and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok()) else { continue };
        let field = |key| payload.get(key).and_then(serde_json::Value::as_str);
        let event_id = row.get("EventID").and_then(|s|s.parse::<i64>().ok());
        let (service,kind,state,before,after) = match event_id {
            Some(7036) => (field("param1"),"service_state",field("param2"),None,None),
            Some(7040) => (field("param4"),"service_start_type_change",None,field("param2"),field("param3")),
            Some(7045) => (field("ServiceName"),"service_installation",None,None,field("StartType")),
            _ => continue,
        };
        if !service.is_some_and(|s| s.eq_ignore_ascii_case("LanmanServer")) { continue; }
        let source = ctx.facts.source_from_record_key(
            row.get("_record_key").map(String::as_str).unwrap_or(""),Some("EventData"),
            row.get("_source_file").map(String::as_str),Some(kind))?
            .ok_or_else(||anyhow::anyhow!("missing LanmanServer event provenance"))?;
        db.conn().execute(
            "INSERT INTO SmbEnvironment(environment_id,host_id,dataset_id,evidence_kind,timestamp,timestamp_kind,
             event_id,provider,service_name,state,start_type_before,start_type_after,event_data,
             source_dataset_id,source_db,source_table,source_rowid,source_file)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,kind,
                row.get("timestamp").filter(|s|!s.is_empty()),"event_recorded",event_id,row.get("Provider"),
                service,state,before,after,row.get("EventData"),source.dataset,source.db,source.table,source.rowid,source.file],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::sqlite::Row;

    #[test]
    fn settings_and_state_remain_separate_with_original_generation() {
        let root = std::env::temp_dir().join(format!("wina-smb-environment-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("REGISTRY")).unwrap();
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let registry = root.join("REGISTRY/SYSTEM.sqlite");
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
        INSERT INTO Registry VALUES('2026-01-01', '\ROOT\Select','Current','RegDword','2',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-02', '\ROOT\ControlSet001\Services\LanmanServer','Start','RegDword','4',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-03', '\ROOT\ControlSet002\Services\LanmanServer','Start','RegDword','2',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-04', '\ROOT\ControlSet002\Services\LanmanServer\Shares','Evidence','RegMultiSz','["Path=C:\\Evidence"]',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-04', '\ROOT\ControlSet002\Services\LanmanServer\Shares\Security','','', '',NULL,'key','SYSTEM');"#).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        let event_path = root.join("EVENTLOG/System.sqlite");
        let conn = Connection::open(&event_path).unwrap();
        conn.execute_batch("CREATE TABLE System(EventData TEXT); INSERT INTO System VALUES('{}');").unwrap();
        drop(conn);
        stamp_facts_generation(&event_path, "event-old").unwrap();
        let events = EventLogOverviewCache::from_rows_for_tests(vec![Row::from([
            ("Provider".into(), "Service Control Manager".into()),
            ("Channel".into(), "System".into()),
            ("EventID".into(), "7036".into()),
            ("EventData".into(), r#"{"param1":"LanmanServer","param2":"실행"}"#.into()),
            ("timestamp".into(), "2026-02-01".into()),
            ("_record_key".into(), "System::1".into()),
            ("_source_file".into(), "System.evtx".into()),
        ])]);
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx = Ctx { out_dir: &root, target: &root, host_id: "host", dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(), meta: MetaLookup::load(&root).unwrap() };
        let db = DerivedDb::create(&ctx.overview_dir(), "SmbHistory").unwrap();
        populate(&ctx, &db, &events).unwrap();
        let settings: Vec<(String,String,String)> = db.conn().prepare("SELECT value_data,control_set_status,source_dataset_id FROM SmbEnvironment WHERE value_name='Start' ORDER BY key_path").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(settings, vec![("4".into(),"inactive".into(),"registry-old".into()),("2".into(),"active".into(),"registry-old".into())]);
        let state: (String,String,Option<String>,String) = db.conn().query_row("SELECT evidence_kind,state,start_type_after,source_dataset_id FROM SmbEnvironment WHERE event_id=7036",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(state,("service_state".into(),"실행".into(),None,"event-old".into()));
        let empty_key: (String,String) = db.conn().query_row("SELECT entry_kind,value_data FROM SmbEnvironment WHERE key_path LIKE '%Shares\\Security'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(empty_key,("key".into(),String::new()));
        assert_eq!(db.conn().query_row("SELECT COUNT(*) FROM SmbHistory",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        db.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
