//! Full registry inventory, typed key/value evidence, and verified finding targets.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::schema::{REGISTRY_HIVES_TABLE, REGISTRY_QUICK_TARGETS_TABLE};
use super::{facts_dataset_id, Cell, Ctx, DerivedDb, SourceRef};
use crate::sqlite::quote_ident;

pub(super) const DB_NAME: &str = "RegistryExplorer";

const REGISTRY_DIR: &str = "REGISTRY";
const FACTS_TABLE: &str = "Registry";
const FACTS_ARTIFACT: &str = "Registry";
const MANIFEST_FILE: &str = "RegistryInputs.sqlite";
const MANIFEST_TABLE: &str = "RegistryInputs";
const FINDINGS_DB: &str = "RegistryFindings.sqlite";

// Legacy facts cannot establish a complete tree or raw value payloads.
const REQUIRED_FACTS_COLUMNS: &[&str] = &[
    "entry_kind",
    "key_offset",
    "parent_key_offset",
    "key_name",
    "key_subkey_count",
    "key_value_count",
    "key_read_status",
    "key_read_error",
    "value_offset",
    "value_name_raw",
    "value_type_code",
    "value_data_hex",
    "value_data_text",
    "value_read_status",
    "value_read_error",
];

// Streaming SELECT column positions.
const C_ROWID: usize = 0;
const C_ENTRY_KIND: usize = 1;
const C_KEY_OFFSET: usize = 2;
const C_PARENT_KEY_OFFSET: usize = 3;
const C_KEY_NAME: usize = 4;
const C_KEY_PATH: usize = 5;
const C_LAST_WRITE: usize = 6;
const C_KEY_SUBKEY_COUNT: usize = 7;
const C_KEY_VALUE_COUNT: usize = 8;
const C_KEY_READ_STATUS: usize = 9;
const C_KEY_READ_ERROR: usize = 10;
const C_VALUE_OFFSET: usize = 11;
const C_VALUE_NAME_RAW: usize = 12;
const C_VALUE_DISPLAY_NAME: usize = 13;
const C_VALUE_TYPE_CODE: usize = 14;
const C_VALUE_TYPE_NAME: usize = 15;
const C_VALUE_DATA_HEX: usize = 16;
const C_VALUE_DATA_TEXT: usize = 17;
const C_VALUE_READ_STATUS: usize = 18;
const C_VALUE_READ_ERROR: usize = 19;
const C_RECOVERY: usize = 20;

const KEY_READ_STATUSES: &[&str] = &["ok", "partial"];
const VALUE_READ_STATUSES: &[&str] = &["ok", "empty", "error", "partial"];

struct HiveInput {
    hive_id: String,
    ordinal: usize,
    hive_name: String,
    source_file: Option<String>,
    // Planned host-relative path; failed inputs may have no file.
    facts_db: Option<String>,
    input_status: Option<String>,
    input_error: Option<String>,
    facts_row_count: Option<String>,
    logs_discovered: Option<String>,
    logs_applied: Option<String>,
    log_error: Option<String>,
    inventory_source: &'static str,
}

struct HiveRef {
    hive_id: String,
    hive_name: String,
    facts_db: Option<String>,
    loaded: bool,
}

pub(super) fn build(ctx: &Ctx) -> Result<usize> {
    let inputs = collect_inputs(ctx.out_dir)?;
    let mut db = DerivedDb::create(&ctx.overview_dir(), DB_NAME)?;
    let mut hives: Vec<HiveRef> = Vec::with_capacity(inputs.len());
    for input in &inputs {
        hives.push(write_hive(ctx, &mut db, input)?);
    }
    write_quick_targets(ctx, &mut db, &hives)?;
    db.finish()
}

// Preserve manifest order and distinguish any additional facts-only inputs.
fn collect_inputs(out_dir: &Path) -> Result<Vec<HiveInput>> {
    let dir = out_dir.join(REGISTRY_DIR);
    let mut inputs: Vec<HiveInput> = Vec::new();
    let mut listed: HashSet<String> = HashSet::new();

    let manifest = dir.join(MANIFEST_FILE);
    if manifest.is_file() {
        let conn = Connection::open_with_flags(&manifest, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("레지스트리 입력 목록 열기: {}", manifest.display()))?;
        let sql = format!(
            "SELECT source_file, facts_db, hive_name, status, row_count, error, \
             logs_discovered, logs_applied, log_error FROM {} ORDER BY rowid",
            quote_ident(MANIFEST_TABLE)
        );
        let mut stmt = conn
            .prepare(&sql)
            .with_context(|| format!("레지스트리 입력 목록 조회: {}", manifest.display()))?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;
        for row in rows {
            let (
                source_file,
                facts_db,
                hive_name,
                status,
                row_count,
                error,
                discovered,
                applied,
                log_error,
            ) = row?;
            let facts_db = facts_db.filter(|value| !value.is_empty());
            if let Some(relative) = &facts_db {
                listed.insert(relative.clone());
            }
            let hive_name = hive_name
                .filter(|value| !value.is_empty())
                .or_else(|| facts_db.as_deref().map(stem_of_relative))
                .or_else(|| source_file.as_deref().map(file_name_of))
                .unwrap_or_default();
            inputs.push(HiveInput {
                hive_id: String::new(),
                ordinal: 0,
                hive_name,
                source_file: source_file.filter(|value| !value.is_empty()),
                facts_db,
                input_status: status.filter(|value| !value.is_empty()),
                input_error: error.filter(|value| !value.is_empty()),
                facts_row_count: row_count,
                logs_discovered: discovered,
                logs_applied: applied,
                log_error: log_error.filter(|value| !value.is_empty()),
                inventory_source: "manifest",
            });
        }
    }

    let mut files: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
            .filter_map(|path| {
                let name = path.file_name()?.to_string_lossy().to_string();
                (name != MANIFEST_FILE).then_some(name)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    for name in files {
        let relative = format!("{REGISTRY_DIR}/{name}");
        if listed.contains(&relative) {
            continue;
        }
        inputs.push(HiveInput {
            hive_id: String::new(),
            ordinal: 0,
            hive_name: stem_of_relative(&relative),
            source_file: None,
            facts_db: Some(relative),
            input_status: Some("completed".to_string()),
            input_error: None,
            facts_row_count: None,
            logs_discovered: None,
            logs_applied: None,
            log_error: None,
            inventory_source: "facts_scan",
        });
    }

    for (ordinal, input) in inputs.iter_mut().enumerate() {
        input.ordinal = ordinal;
        input.hive_id = format!("h{ordinal:04}");
    }
    Ok(inputs)
}

fn stem_of_relative(relative: &str) -> String {
    Path::new(relative)
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn file_name_of(path: &str) -> String {
    let trimmed = path.replace('\\', "/");
    trimmed
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("")
        .to_string()
}

// Ignore output-name collision suffixes when classifying backups.
fn is_regback(hive_name: &str) -> bool {
    let lower = hive_name.to_lowercase();
    let base = match lower.rsplit_once('_') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => lower.as_str(),
    };
    base.ends_with("_regback")
}

type FactsOpen = std::result::Result<(Connection, String), (&'static str, Option<String>)>;

fn open_facts(relative: &str, path: &Path) -> Result<FactsOpen> {
    let conn = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(conn) => conn,
        Err(error) => return Ok(Err(("facts_unreadable", Some(error.to_string())))),
    };
    let mut present: HashSet<String> = HashSet::new();
    {
        let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1)")?;
        let names = stmt.query_map([FACTS_TABLE], |row| row.get::<_, String>(0))?;
        for name in names {
            present.insert(name?);
        }
    }
    if present.is_empty() {
        return Ok(Err((
            "facts_unreadable",
            Some(format!("{relative}: {FACTS_TABLE} 테이블이 없습니다")),
        )));
    }
    let missing: Vec<&str> = REQUIRED_FACTS_COLUMNS
        .iter()
        .copied()
        .filter(|column| !present.contains(*column))
        .collect();
    if !missing.is_empty() {
        return Err(anyhow!(
            "{relative}: Registry facts에 {} 컬럼이 없습니다 — 이 하이브를 \
             다시 파싱해야 전체 키·값 저장을 만들 수 있습니다 (구 facts로 \
             계층·원문 값을 추정하지 않습니다)",
            missing.join(", ")
        ));
    }
    let generation = facts_dataset_id(path)?;
    Ok(Ok((conn, generation)))
}

fn write_hive(ctx: &Ctx, db: &mut DerivedDb, input: &HiveInput) -> Result<HiveRef> {
    let completed = input.input_status.as_deref() == Some("completed");
    let path = input
        .facts_db
        .as_ref()
        .map(|relative| ctx.out_dir.join(relative));

    let mut load_status = "not_parsed";
    let mut load_error: Option<String> = None;
    let mut opened: Option<(Connection, String)> = None;
    if completed {
        match path.as_deref() {
            Some(path) if path.is_file() => {
                let relative = input.facts_db.as_deref().unwrap_or_default();
                match open_facts(relative, path)? {
                    Ok(ready) => {
                        load_status = "loaded";
                        opened = Some(ready);
                    }
                    Err((status, error)) => {
                        load_status = status;
                        load_error = error;
                    }
                }
            }
            _ => load_status = "facts_missing",
        }
    }

    // Prefer the manifest's input path; otherwise retain the facts path.
    let mut source_file = input.source_file.clone();
    if source_file.is_none() {
        if let Some((conn, _)) = &opened {
            let lookup = conn
                .query_row(
                    &format!(
                        "SELECT _source_file FROM {} WHERE _source_file <> '' LIMIT 1",
                        quote_ident(FACTS_TABLE)
                    ),
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional();
            match lookup {
                Ok(found) => source_file = found.flatten(),
                // Entries still load; keep why the original path is unknown.
                Err(error) => load_error = Some(format!("_source_file: {error}")),
            }
        }
    }

    let generation = opened.as_ref().map(|(_, generation)| generation.clone());
    let output_name = input
        .facts_db
        .as_deref()
        .map(stem_of_relative)
        .unwrap_or_else(|| input.hive_name.clone());
    let regback = is_regback(&output_name)
        || source_file.as_deref().is_some_and(|path| {
            path.split(['\\', '/'])
                .any(|part| part.eq_ignore_ascii_case("RegBack"))
        });
    db.insert_child(
        REGISTRY_HIVES_TABLE,
        &[
            Cell::Text(input.hive_id.clone()),
            Cell::Int(input.ordinal as i64),
            Cell::Text(ctx.host_id.to_string()),
            Cell::Text(ctx.dataset_id.to_string()),
            Cell::Text(input.hive_name.clone()),
            opt_text(source_file.as_deref()),
            opt_text(input.facts_db.as_deref()),
            opt_text(generation.as_deref()),
            Cell::Text(input.inventory_source.to_string()),
            opt_text(input.input_status.as_deref()),
            Cell::Text(load_status.to_string()),
            opt_text(load_error.as_deref()),
            opt_text(input.input_error.as_deref()),
            int_text(input.facts_row_count.as_deref()),
            int_text(input.logs_discovered.as_deref()),
            int_text(input.logs_applied.as_deref()),
            opt_text(input.log_error.as_deref()),
            Cell::Int(i64::from(regback)),
            Cell::Int(0),
            Cell::Int(0),
            Cell::Int(0),
        ],
    )?;

    if let Some((conn, generation)) = opened {
        let relative = input.facts_db.clone().unwrap_or_default();
        write_entries(ctx, db, input, &relative, &generation, &conn)?;
        resolve_links(db, &input.hive_id)?;
    }

    Ok(HiveRef {
        hive_id: input.hive_id.clone(),
        hive_name: output_name,
        facts_db: input.facts_db.clone(),
        loaded: load_status == "loaded",
    })
}

fn write_entries(
    ctx: &Ctx,
    db: &mut DerivedDb,
    input: &HiveInput,
    relative: &str,
    generation: &str,
    conn: &Connection,
) -> Result<()> {
    let stem = stem_of_relative(relative);
    let hive_id = input.hive_id.as_str();
    let width = db.spec().columns.len();
    let sql = format!(
        "SELECT rowid, entry_kind, key_offset, parent_key_offset, key_name, key_path, last_write, \
         key_subkey_count, key_value_count, key_read_status, key_read_error, \
         value_offset, value_name_raw, value_name, value_type_code, value_type, \
         value_data_hex, value_data_text, value_read_status, value_read_error, _recovery \
         FROM {} ORDER BY rowid",
        quote_ident(FACTS_TABLE)
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    // Deduplicate within this hive only; missing offsets retain path identity.
    let mut seen_offsets: HashSet<String> = HashSet::new();
    let mut path_keys: HashMap<String, String> = HashMap::new();

    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(C_ROWID)?;
        let entry_kind = text_at(row, C_ENTRY_KIND)?;
        let key_offset = text_at(row, C_KEY_OFFSET)?;
        let key_path = text_at(row, C_KEY_PATH)?;
        let recovery = text_at(row, C_RECOVERY)?;
        let recovery = if recovery.is_empty() {
            "live"
        } else {
            recovery
        };

        let (key_record_id, new_key) = if key_offset.is_empty() {
            match path_keys.get(key_path) {
                Some(found) => (found.clone(), false),
                None => {
                    let record_id = format!("{hive_id}:kp:{}", path_keys.len());
                    path_keys.insert(key_path.to_string(), record_id.clone());
                    (record_id, true)
                }
            }
        } else {
            let record_id = format!("{hive_id}:k:{key_offset}");
            let new_key = !seen_offsets.contains(key_offset);
            if new_key {
                seen_offsets.insert(key_offset.to_string());
            }
            (record_id, new_key)
        };

        if new_key {
            let parent_offset = text_at(row, C_PARENT_KEY_OFFSET)?;
            let depth = depth_of(key_path);
            let mut values = vec![Cell::Null; width];
            values[0] = Cell::Text(key_record_id.clone());
            values[1] = Cell::Text(ctx.host_id.to_string());
            values[2] = Cell::Text(ctx.dataset_id.to_string());
            values[3] = Cell::Text(hive_id.to_string());
            values[4] = Cell::Text("key".to_string());
            values[7] = Cell::Text(
                if parent_offset.is_empty() && depth == 0 {
                    "root"
                } else {
                    "unresolved"
                }
                .to_string(),
            );
            values[8] = Cell::Text(key_offset.to_string());
            values[9] = opt_text(Some(parent_offset));
            values[10] = Cell::Text(text_at(row, C_KEY_NAME)?.to_string());
            values[11] = Cell::Text(key_path.to_string());
            values[12] = Cell::Text(key_path.to_lowercase());
            values[13] = Cell::Int(depth);
            values[14] = opt_text(Some(text_at(row, C_LAST_WRITE)?));
            values[15] = int_text(Some(text_at(row, C_KEY_SUBKEY_COUNT)?));
            values[16] = int_text(Some(text_at(row, C_KEY_VALUE_COUNT)?));
            values[17] = Cell::Int(0);
            values[18] = Cell::Int(0);
            values[19] = Cell::Text(status_of(
                text_at(row, C_KEY_READ_STATUS)?,
                "ok",
                KEY_READ_STATUSES,
                relative,
                "key_read_status",
            )?);
            values[20] = opt_text(Some(text_at(row, C_KEY_READ_ERROR)?));
            values[35] = Cell::Text(recovery.to_string());
            values[36] = Cell::Int(rowid);
            db.insert_main(&values)?;
            db.insert_sources(
                &key_record_id,
                &[source_ref(generation, relative, &stem, rowid, "key")],
            )?;
        }

        if entry_kind != "value" {
            continue;
        }
        let record_id = format!("{hive_id}:v:{rowid}");
        let name_raw = text_at(row, C_VALUE_NAME_RAW)?;
        let hex = text_at(row, C_VALUE_DATA_HEX)?;
        let decoded = decode_hex(hex);
        let mut values = vec![Cell::Null; width];
        values[0] = Cell::Text(record_id.clone());
        values[1] = Cell::Text(ctx.host_id.to_string());
        values[2] = Cell::Text(ctx.dataset_id.to_string());
        values[3] = Cell::Text(hive_id.to_string());
        values[4] = Cell::Text("value".to_string());
        values[5] = Cell::Text(key_record_id);
        values[21] = opt_text(Some(text_at(row, C_VALUE_OFFSET)?));
        values[22] = Cell::Text(name_raw.to_string());
        values[23] = Cell::Text(name_raw.to_lowercase());
        values[24] = Cell::Int(i64::from(name_raw.is_empty()));
        values[25] = opt_text(Some(text_at(row, C_VALUE_DISPLAY_NAME)?));
        let type_code = text_at(row, C_VALUE_TYPE_CODE)?;
        values[26] = int_text(Some(type_code));
        values[27] = opt_text(Some(type_code));
        values[28] = opt_text(Some(text_at(row, C_VALUE_TYPE_NAME)?));
        values[30] = Cell::Text(hex.to_string());
        match decoded {
            Some(bytes) => {
                values[31] = Cell::Int(bytes.len() as i64);
                values[29] = Cell::Blob(bytes);
            }
            // Preserve malformed hex verbatim instead of fabricating bytes.
            None => values[31] = Cell::Int(0),
        }
        values[32] = opt_text(Some(text_at(row, C_VALUE_DATA_TEXT)?));
        values[33] = Cell::Text(status_of(
            text_at(row, C_VALUE_READ_STATUS)?,
            "ok",
            VALUE_READ_STATUSES,
            relative,
            "value_read_status",
        )?);
        values[34] = opt_text(Some(text_at(row, C_VALUE_READ_ERROR)?));
        values[35] = Cell::Text(recovery.to_string());
        values[36] = Cell::Int(rowid);
        db.insert_main(&values)?;
        db.insert_sources(
            &record_id,
            &[source_ref(generation, relative, &stem, rowid, "value")],
        )?;
    }
    Ok(())
}

// Per-hive path labels live in RegistryHives, not on every source reference.
fn source_ref(generation: &str, relative: &str, stem: &str, rowid: i64, field: &str) -> SourceRef {
    SourceRef {
        dataset: generation.to_string(),
        artifact: FACTS_ARTIFACT.to_string(),
        db: relative.to_string(),
        table: FACTS_TABLE.to_string(),
        rowid,
        field: Some(field.to_string()),
        record_key: Some(format!("{stem}::{FACTS_TABLE}::{rowid}")),
        file: None,
        label: None,
    }
}

// Resolve only after all keys in this hive exist.
fn resolve_links(db: &DerivedDb, hive_id: &str) -> Result<()> {
    let conn = db.conn();
    conn.execute(
        "UPDATE RegistryExplorer SET parent_record_id = (
             SELECT p.record_id FROM RegistryExplorer p
             WHERE p.hive_id = RegistryExplorer.hive_id AND p.entry_kind = 'key'
               AND p.key_offset = RegistryExplorer.parent_key_offset)
         WHERE hive_id = ?1 AND entry_kind = 'key' AND parent_key_offset IS NOT NULL",
        [hive_id],
    )?;
    conn.execute(
        "UPDATE RegistryExplorer SET parent_status =
             CASE WHEN parent_record_id IS NOT NULL THEN 'linked' ELSE 'unresolved' END
         WHERE hive_id = ?1 AND entry_kind = 'key' AND parent_key_offset IS NOT NULL",
        [hive_id],
    )?;
    conn.execute(
        "UPDATE RegistryExplorer SET
             stored_value_count = (SELECT COUNT(*) FROM RegistryExplorer v
                                   WHERE v.key_record_id = RegistryExplorer.record_id AND v.entry_kind = 'value'),
             stored_subkey_count = (SELECT COUNT(*) FROM RegistryExplorer c
                                    WHERE c.parent_record_id = RegistryExplorer.record_id AND c.entry_kind = 'key')
         WHERE hive_id = ?1 AND entry_kind = 'key'",
        [hive_id],
    )?;
    conn.execute(
        "UPDATE RegistryHives SET
             key_count = (SELECT COUNT(*) FROM RegistryExplorer e
                          WHERE e.hive_id = RegistryHives.hive_id AND e.entry_kind = 'key'),
             value_count = (SELECT COUNT(*) FROM RegistryExplorer e
                            WHERE e.hive_id = RegistryHives.hive_id AND e.entry_kind = 'value'),
             root_count = (SELECT COUNT(*) FROM RegistryExplorer e
                           WHERE e.hive_id = RegistryHives.hive_id AND e.entry_kind = 'key'
                             AND e.parent_status = 'root')
         WHERE hive_id = ?1",
        [hive_id],
    )?;
    Ok(())
}

// Coordinates take precedence; path-only targets require a confirmed hive.
// Missing keys may link to the nearest verified ancestor, never an invented key.
fn write_quick_targets(ctx: &Ctx, db: &mut DerivedDb, hives: &[HiveRef]) -> Result<()> {
    let findings = ctx.overview_dir().join(FINDINGS_DB);
    if !findings.is_file() {
        return Ok(());
    }
    let findings_conn = Connection::open_with_flags(&findings, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("레지스트리 판정 열기: {}", findings.display()))?;
    let mut pending: Vec<Vec<Cell>> = Vec::new();
    {
        let conn = db.conn();
        let mut by_value = conn.prepare(
            "SELECT record_id FROM RegistryExplorer
             WHERE hive_id = ?1 AND entry_kind = 'value' AND source_rowid = ?2",
        )?;
        let mut by_key = conn.prepare(
            "SELECT record_id FROM RegistryExplorer
             WHERE hive_id = ?1 AND entry_kind = 'key' AND source_rowid = ?2",
        )?;
        let mut in_hive = conn.prepare(
            "SELECT record_id, key_path FROM RegistryExplorer
             WHERE entry_kind = 'key' AND key_path_lower = ?1 AND hive_id = ?2",
        )?;
        let mut any_hive = conn.prepare(
            "SELECT record_id, key_path FROM RegistryExplorer
             WHERE entry_kind = 'key' AND key_path_lower = ?1 AND hive_id IN
                   (SELECT hive_id FROM RegistryHives WHERE is_regback = 0)",
        )?;

        let mut stmt = findings_conn.prepare(
            "SELECT f.record_id, f.key_path, f.source, s.ordinal, s.source_db, s.source_table, \
             s.source_rowid FROM RegistryFindings f \
             LEFT JOIN source_records s ON s.record_id = f.record_id \
             ORDER BY f.record_id, s.ordinal",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let finding_id: String = row.get(0)?;
            let key_path: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let hive_name: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
            let ordinal: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let source_db: Option<String> = row.get(4)?;
            let source_table: Option<String> = row.get(5)?;
            let source_rowid: Option<i64> = row.get(6)?;

            let coordinate = match (source_db.as_deref(), source_table.as_deref(), source_rowid) {
                (Some(relative), Some(table), Some(rowid)) if table == FACTS_TABLE => {
                    Some((relative, rowid))
                }
                _ => None,
            };

            let mut resolution = "unresolved";
            let mut basis = "key_path";
            let mut target: Option<(String, &str)> = None;
            let mut target_path: Option<String> = None;
            let mut hive_id: Option<String> = None;
            let mut candidates: i64 = 0;

            if let Some((relative, rowid)) = coordinate {
                basis = "source_records";
                match hives
                    .iter()
                    .find(|h| h.facts_db.as_deref() == Some(relative))
                {
                    None => resolution = "missing_hive",
                    Some(hive) => {
                        hive_id = Some(hive.hive_id.clone());
                        if !hive.loaded {
                            resolution = "unavailable";
                        } else if let Some(found) = first_id(&mut by_value, &hive.hive_id, rowid)? {
                            resolution = "exact_value";
                            candidates = 1;
                            target = Some((found, "value"));
                        } else if let Some(found) = first_id(&mut by_key, &hive.hive_id, rowid)? {
                            resolution = "exact_key";
                            candidates = 1;
                            target = Some((found, "key"));
                        }
                    }
                }
            } else if key_path.is_empty() {
                // Neither coordinates nor a path establish a target.
            } else {
                let named = if hive_name.is_empty() {
                    None
                } else {
                    hives
                        .iter()
                        .find(|hive| hive.hive_name.eq_ignore_ascii_case(&hive_name))
                };
                hive_id = named.map(|hive| hive.hive_id.clone());
                if !hive_name.is_empty() && named.is_none() {
                    resolution = "missing_hive";
                } else if named.is_some_and(|hive| !hive.loaded) {
                    resolution = "unavailable";
                } else {
                    let scope = named.map(|hive| hive.hive_id.clone());
                    let mut found =
                        lookup_keys(&mut in_hive, &mut any_hive, &key_path, scope.as_deref())?;
                    candidates = found.len() as i64;
                    match found.len() {
                        1 if scope.is_none() => {}
                        1 => {
                            let (record_id, path) = found.remove(0);
                            resolution = "parent_key";
                            target = Some((record_id, "key"));
                            target_path = Some(path);
                        }
                        0 if scope.is_some() => {
                            // Stop at the nearest verified ancestor; never choose among ties.
                            let mut remaining = key_path.as_str();
                            while let Some((head, _)) = remaining.rsplit_once('\\') {
                                remaining = head;
                                if remaining.is_empty() {
                                    break;
                                }
                                let mut hits = lookup_keys(
                                    &mut in_hive,
                                    &mut any_hive,
                                    remaining,
                                    scope.as_deref(),
                                )?;
                                if hits.is_empty() {
                                    continue;
                                }
                                candidates = hits.len() as i64;
                                if hits.len() == 1 {
                                    let (record_id, path) = hits.remove(0);
                                    resolution = "ancestor_key";
                                    target = Some((record_id, "key"));
                                    target_path = Some(path);
                                } else {
                                    resolution = "ambiguous";
                                }
                                break;
                            }
                        }
                        0 => {}
                        _ => resolution = "ambiguous",
                    }
                }
            }

            let (target_id, target_kind) = match target {
                Some((id, kind)) => (Cell::Text(id), Cell::Text(kind.to_string())),
                None => (Cell::Null, Cell::Null),
            };
            pending.push(vec![
                Cell::Text(finding_id),
                Cell::Int(ordinal),
                Cell::Text(resolution.to_string()),
                Cell::Text(basis.to_string()),
                target_id,
                target_kind,
                opt_text(target_path.as_deref()),
                opt_text(hive_id.as_deref()),
                opt_text(source_db.as_deref()),
                source_rowid.map(Cell::Int).unwrap_or(Cell::Null),
                opt_text(Some(hive_name.as_str())),
                opt_text(Some(key_path.as_str())),
                Cell::Int(candidates),
            ]);
        }
    }
    for values in pending {
        db.insert_child(REGISTRY_QUICK_TARGETS_TABLE, &values)?;
    }
    Ok(())
}

fn first_id(
    stmt: &mut rusqlite::Statement<'_>,
    hive_id: &str,
    rowid: i64,
) -> Result<Option<String>> {
    let mut rows = stmt.query(rusqlite::params![hive_id, rowid])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

// Try the stored path, then its root-prefixed form; both require actual rows.
fn lookup_keys(
    in_hive: &mut rusqlite::Statement<'_>,
    any_hive: &mut rusqlite::Statement<'_>,
    key_path: &str,
    hive_id: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let lower = key_path.to_lowercase();
    let found = query_keys(in_hive, any_hive, &lower, hive_id)?;
    if !found.is_empty() || lower.starts_with("\\root") {
        return Ok(found);
    }
    query_keys(in_hive, any_hive, &format!("\\root{lower}"), hive_id)
}

fn query_keys(
    in_hive: &mut rusqlite::Statement<'_>,
    any_hive: &mut rusqlite::Statement<'_>,
    key_path_lower: &str,
    hive_id: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let mut found = Vec::new();
    let mut rows = match hive_id {
        Some(id) => in_hive.query(rusqlite::params![key_path_lower, id])?,
        None => any_hive.query(rusqlite::params![key_path_lower])?,
    };
    while let Some(row) = rows.next()? {
        found.push((row.get(0)?, row.get(1)?));
    }
    Ok(found)
}

fn text_at<'a>(row: &'a rusqlite::Row<'_>, index: usize) -> Result<&'a str> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(""),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("Registry facts 문자열이 UTF-8이 아닙니다 (열 {index})")),
        _ => Err(anyhow!("Registry facts 열 {index}은 TEXT여야 합니다")),
    }
}

fn opt_text(value: Option<&str>) -> Cell {
    match value {
        Some(value) if !value.is_empty() => Cell::Text(value.to_string()),
        _ => Cell::Null,
    }
}

// Keep non-numeric source text separately; do not invent an INTEGER.
fn int_text(value: Option<&str>) -> Cell {
    match value.and_then(|value| value.trim().parse::<i64>().ok()) {
        Some(parsed) => Cell::Int(parsed),
        None => Cell::Null,
    }
}

fn status_of(
    value: &str,
    default: &str,
    allowed: &[&str],
    relative: &str,
    column: &str,
) -> Result<String> {
    let value = if value.is_empty() { default } else { value };
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(anyhow!(
            "{relative}: Registry facts {column} 값 '{value}'을 해석할 수 없습니다 \
             (허용: {})",
            allowed.join(", ")
        ))
    }
}

fn depth_of(key_path: &str) -> i64 {
    key_path
        .split('\\')
        .filter(|part| !part.is_empty())
        .count()
        .saturating_sub(1) as i64
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

// Shared current-generation facts fixtures for derived integration tests.
#[cfg(test)]
pub(super) mod fixture {
    use std::path::{Path, PathBuf};

    use rusqlite::Connection;

    pub const COLUMNS: &[&str] = &[
        "last_write",
        "key_path",
        "value_name",
        "value_type",
        "value_data",
        "_recovery",
        "_source_file",
        "entry_kind",
        "key_offset",
        "parent_key_offset",
        "key_name",
        "key_subkey_count",
        "key_value_count",
        "key_read_status",
        "key_read_error",
        "value_offset",
        "value_name_raw",
        "value_type_code",
        "value_data_hex",
        "value_data_text",
        "value_read_status",
        "value_read_error",
    ];

    #[derive(Clone, Default)]
    pub struct FactsRow<'a> {
        pub last_write: &'a str,
        pub key_path: &'a str,
        pub value_name: &'a str,
        pub value_type: &'a str,
        pub value_data: &'a str,
        pub recovery: &'a str,
        pub entry_kind: &'a str,
        pub key_offset: &'a str,
        pub parent_key_offset: &'a str,
        pub key_name: &'a str,
        pub key_subkey_count: &'a str,
        pub key_value_count: &'a str,
        pub key_read_status: &'a str,
        pub key_read_error: &'a str,
        pub value_offset: &'a str,
        pub value_name_raw: &'a str,
        pub value_type_code: &'a str,
        pub value_data_hex: &'a str,
        pub value_data_text: &'a str,
        pub value_read_status: &'a str,
        pub value_read_error: &'a str,
    }

    impl<'a> FactsRow<'a> {
        fn cells(&self, source: &'a str) -> [&'a str; 22] {
            [
                self.last_write,
                self.key_path,
                self.value_name,
                self.value_type,
                self.value_data,
                if self.recovery.is_empty() {
                    "live"
                } else {
                    self.recovery
                },
                source,
                self.entry_kind,
                self.key_offset,
                self.parent_key_offset,
                self.key_name,
                self.key_subkey_count,
                self.key_value_count,
                if self.key_read_status.is_empty() {
                    "ok"
                } else {
                    self.key_read_status
                },
                self.key_read_error,
                self.value_offset,
                self.value_name_raw,
                self.value_type_code,
                self.value_data_hex,
                self.value_data_text,
                self.value_read_status,
                self.value_read_error,
            ]
        }
    }

    pub fn key<'a>(offset: &'a str, parent: &'a str, name: &'a str, path: &'a str) -> FactsRow<'a> {
        FactsRow {
            last_write: "2026-01-01 00:00:00.000",
            key_path: path,
            entry_kind: "key",
            key_offset: offset,
            parent_key_offset: parent,
            key_name: name,
            key_subkey_count: "0",
            key_value_count: "0",
            key_read_status: "ok",
            ..Default::default()
        }
    }

    pub fn value<'a>(
        owner: &FactsRow<'a>,
        offset: &'a str,
        name_raw: &'a str,
        display: &'a str,
        type_code: &'a str,
        type_name: &'a str,
        hex: &'a str,
        text: &'a str,
    ) -> FactsRow<'a> {
        FactsRow {
            entry_kind: "value",
            value_offset: offset,
            value_name_raw: name_raw,
            value_name: display,
            value_type_code: type_code,
            value_type: type_name,
            value_data_hex: hex,
            value_data_text: text,
            value_data: text,
            value_read_status: "ok",
            ..owner.clone()
        }
    }

    pub fn hex_of(text: &str) -> String {
        crate::hex::hex_lower(text.as_bytes())
    }

    pub fn write_hive<'a>(
        out_dir: &Path,
        file: &str,
        source: &'a str,
        rows: &[FactsRow<'a>],
    ) -> PathBuf {
        let path = out_dir.join(super::REGISTRY_DIR).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let columns = COLUMNS
            .iter()
            .map(|name| format!("\"{name}\" TEXT"))
            .collect::<Vec<_>>()
            .join(",");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!("CREATE TABLE Registry({columns});"))
            .unwrap();
        let placeholders = (1..=COLUMNS.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("INSERT INTO Registry VALUES ({placeholders})");
        for row in rows {
            conn.execute(&sql, rusqlite::params_from_iter(row.cells(source)))
                .unwrap();
        }
        drop(conn);
        crate::derived::stamp_facts_generation(&path, "facts-gen-1").unwrap();
        path
    }

    pub fn write_manifest(out_dir: &Path, rows: &[[&str; 9]]) {
        let path = out_dir.join(super::REGISTRY_DIR).join(super::MANIFEST_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE RegistryInputs(source_file TEXT, facts_db TEXT, hive_name TEXT, \
             status TEXT, row_count TEXT, error TEXT, logs_discovered TEXT, \
             logs_applied TEXT, log_error TEXT);",
        )
        .unwrap();
        for row in rows {
            conn.execute(
                "INSERT INTO RegistryInputs VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params_from_iter(row.iter()),
            )
            .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, hex_of, key, value, FactsRow};
    use super::*;
    use crate::derived::{build_all, FactsIndex, MetaLookup};
    use std::path::PathBuf;

    fn fixture_dirs(label: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "wina-regexp-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let out_dir = base.join("out");
        let target = base.join("target");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        (out_dir, target)
    }

    fn open_explorer(out_dir: &Path) -> Connection {
        Connection::open_with_flags(
            out_dir.join("_OVERVIEW").join(format!("{DB_NAME}.sqlite")),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
    }

    fn scalar<T: rusqlite::types::FromSql>(conn: &Connection, sql: &str) -> T {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn strings(conn: &Connection, sql: &str) -> Vec<String> {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |row| row.get::<_, Option<String>>(0))
            .unwrap()
            .map(|value| value.unwrap().unwrap_or_default())
            .collect()
    }

    const RUN_PATH: &str = "\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Run";
    const DUP_PATH: &str = "\\ROOT\\Software\\Dup";

    fn dup_hive(out_dir: &Path, file: &str, source: &str) {
        let root = key("4096", "", "", "\\ROOT");
        let dup = key("8192", "4096", "Dup", DUP_PATH);
        let shared = value(
            &dup, "9000", "Shared", "Shared", "1", "REG_SZ", "6162", "ab",
        );
        fixture::write_hive(out_dir, file, source, &[root, shared]);
    }

    #[test]
    fn every_hive_key_and_value_is_stored_with_real_lineage() {
        let (out_dir, target) = fixture_dirs("full-tree");
        let long = format!("{}END-OF-VALUE", "x".repeat(70_000));
        let long_hex = hex_of(&long);
        let multi = "[\"a\", \"b\"]";

        let root = key("4096", "", "", "\\ROOT");
        let run = key("8192", "4096", "Run", RUN_PATH);
        let empty = key("12288", "4096", "Empty", "\\ROOT\\Empty");
        let orphan = key("16384", "99999", "Orphan", "\\ROOT\\Orphan");
        let partial = FactsRow {
            key_read_status: "partial",
            key_read_error: "선언된 값 수보다 적게 읽혔습니다",
            key_value_count: "3",
            ..key("20480", "4096", "Partial", "\\ROOT\\Partial")
        };
        let default_hex = hex_of("C:\\def.exe");
        let literal_hex = hex_of("C:\\lit.exe");
        let multi_hex = hex_of("ab");
        let orphan_hex = hex_of("x");
        let rows = vec![
            root,
            value(
                &run,
                "9001",
                "",
                "(default)",
                "1",
                "REG_SZ",
                &default_hex,
                "C:\\def.exe",
            ),
            value(
                &run,
                "9002",
                "(default)",
                "(default)",
                "1",
                "REG_SZ",
                &literal_hex,
                "C:\\lit.exe",
            ),
            value(
                &run, "9003", "Updater", "Updater", "1", "REG_SZ", &long_hex, &long,
            ),
            value(
                &run,
                "9004",
                "Blob",
                "Blob",
                "3",
                "REG_BINARY",
                "deadbeef",
                "",
            ),
            value(
                &run,
                "9005",
                "Multi",
                "Multi",
                "7",
                "REG_MULTI_SZ",
                &multi_hex,
                multi,
            ),
            FactsRow {
                value_read_status: "error",
                value_read_error: "셀을 읽지 못했습니다",
                ..value(&run, "9006", "Broken", "Broken", "3", "REG_BINARY", "", "")
            },
            empty,
            value(&orphan, "9007", "X", "X", "1", "REG_SZ", &orphan_hex, "x"),
            partial,
            FactsRow {
                key_read_status: "partial",
                key_read_error: "Invalid parent offset",
                ..key("24576", "", "InvalidParent", "\\ROOT\\InvalidParent")
            },
        ];
        fixture::write_hive(&out_dir, "SOFTWARE.sqlite", "C:\\config\\SOFTWARE", &rows);

        let back_root = key("4096", "", "", "\\ROOT");
        let back_run = key("8192", "4096", "Run", RUN_PATH);
        let back_hex = hex_of("old");
        let back_value = value(
            &back_run, "9001", "Updater", "Updater", "1", "REG_SZ", &back_hex, "old",
        );
        fixture::write_hive(
            &out_dir,
            "SOFTWARE_RegBack.sqlite",
            "C:\\config\\RegBack\\SOFTWARE",
            &[back_root, back_value],
        );
        dup_hive(
            &out_dir,
            "analyst_NTUSER.DAT.sqlite",
            "C:\\Users\\analyst\\NTUSER.DAT",
        );
        dup_hive(
            &out_dir,
            "guest_NTUSER.DAT.sqlite",
            "C:\\Users\\guest\\NTUSER.DAT",
        );

        fixture::write_manifest(
            &out_dir,
            &[
                [
                    "C:\\config\\SOFTWARE",
                    "REGISTRY/SOFTWARE.sqlite",
                    "SOFTWARE",
                    "completed",
                    "11",
                    "",
                    "2",
                    "2",
                    "",
                ],
                [
                    "C:\\config\\SECURITY",
                    "REGISTRY/SECURITY.sqlite",
                    "SECURITY",
                    "skipped_corrupted",
                    "",
                    "regf 서명이 없습니다",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\config\\SAM",
                    "REGISTRY/SAM.sqlite",
                    "SAM",
                    "completed",
                    "4",
                    "",
                    "1",
                    "0",
                    "로그를 적용하지 못했습니다",
                ],
                [
                    "C:\\config\\RegBack\\SOFTWARE",
                    "REGISTRY/SOFTWARE_RegBack.sqlite",
                    "SOFTWARE",
                    "completed",
                    "2",
                    "",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\Users\\analyst\\NTUSER.DAT",
                    "REGISTRY/analyst_NTUSER.DAT.sqlite",
                    "NTUSER.DAT",
                    "completed",
                    "2",
                    "",
                    "0",
                    "0",
                    "",
                ],
            ],
        );

        let report = build_all(&out_dir, &target, "host-1", "ds-1").unwrap().tables;
        let rows_written = report
            .iter()
            .find(|(name, _)| name == DB_NAME)
            .expect("보고에 RegistryExplorer가 있어야 한다")
            .1;
        let conn = open_explorer(&out_dir);

        // Manifest order is authoritative; failed inputs remain visible.
        let inventory: Vec<String> = strings(
            &conn,
            "SELECT hive_name || '|' || inventory_source || '|' || COALESCE(input_status,'')
             || '|' || load_status || '|' || is_regback FROM RegistryHives ORDER BY ordinal",
        );
        assert_eq!(
            inventory,
            vec![
                "SOFTWARE|manifest|completed|loaded|0",
                "SECURITY|manifest|skipped_corrupted|not_parsed|0",
                "SAM|manifest|completed|facts_missing|0",
                "SOFTWARE|manifest|completed|loaded|1",
                "NTUSER.DAT|manifest|completed|loaded|0",
                "guest_NTUSER.DAT|facts_scan|completed|loaded|0",
            ]
        );
        assert_eq!(
            scalar::<i64>(&conn, "SELECT logs_discovered FROM RegistryHives WHERE facts_db='REGISTRY/SOFTWARE.sqlite'"),
            2
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryHives WHERE load_status <> 'loaded'
                 AND (key_count <> 0 OR value_count <> 0 OR facts_dataset_id IS NOT NULL)"
            ),
            0
        );
        assert_eq!(
            scalar::<String>(
                &conn,
                "SELECT source_file FROM RegistryHives WHERE facts_db='REGISTRY/analyst_NTUSER.DAT.sqlite'"
            ),
            "C:\\Users\\analyst\\NTUSER.DAT"
        );

        let software =
            "(SELECT hive_id FROM RegistryHives WHERE facts_db='REGISTRY/SOFTWARE.sqlite')";
        assert_eq!(
            strings(
                &conn,
                &format!(
                    "SELECT key_path || '|' || parent_status || '|' || stored_subkey_count
                     || '|' || stored_value_count || '|' || key_read_status || '|' || key_depth
                     FROM RegistryExplorer WHERE entry_kind='key' AND hive_id={software}
                     ORDER BY key_path"
                )
            ),
            vec![
                "\\ROOT|root|3|0|ok|0",
                "\\ROOT\\Empty|linked|0|0|ok|1",
                "\\ROOT\\InvalidParent|unresolved|0|0|partial|1",
                "\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Run|linked|0|6|ok|4",
                "\\ROOT\\Orphan|unresolved|0|1|ok|1",
                "\\ROOT\\Partial|linked|0|0|partial|1",
            ]
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                &format!("SELECT root_count FROM RegistryHives WHERE hive_id={software}")
            ),
            1
        );

        assert_eq!(
            strings(
                &conn,
                &format!(
                    "SELECT value_name || '|' || value_is_default || '|' || value_display_name
                     || '|' || value_data_text FROM RegistryExplorer
                     WHERE hive_id={software} AND value_display_name='(default)'
                     ORDER BY value_is_default DESC"
                )
            ),
            vec![
                "|1|(default)|C:\\def.exe",
                "(default)|0|(default)|C:\\lit.exe"
            ]
        );

        let (text_len, hex_len, data_len, kind): (i64, i64, i64, String) = conn
            .query_row(
                &format!(
                    "SELECT length(value_data_text), length(value_data_hex), value_data_length,
                     typeof(value_data) FROM RegistryExplorer
                     WHERE hive_id={software} AND value_name='Updater'"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (text_len, data_len, kind.as_str()),
            (70_012, 70_012, "blob")
        );
        assert_eq!(hex_len, 2 * data_len);
        assert_eq!(
            scalar::<i64>(
                &conn,
                &format!(
                    "SELECT COUNT(*) FROM RegistryExplorer
                     WHERE hive_id={software} AND value_data_text LIKE '%END-OF-VALUE'"
                )
            ),
            1,
            "검색은 전체 저장값을 본다 — 미리보기로 잘리지 않는다"
        );
        let (blob, blob_hex, blob_len): (Vec<u8>, String, i64) = conn
            .query_row(
                &format!(
                    "SELECT value_data, value_data_hex, value_data_length FROM RegistryExplorer
                     WHERE hive_id={software} AND value_name='Blob'"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (blob, blob_hex.as_str(), blob_len),
            (vec![0xde, 0xad, 0xbe, 0xef], "deadbeef", 4)
        );
        assert_eq!(
            scalar::<String>(
                &conn,
                &format!(
                    "SELECT value_data_text FROM RegistryExplorer
                     WHERE hive_id={software} AND value_name='Multi'"
                )
            ),
            multi
        );
        assert_eq!(
            strings(
                &conn,
                &format!(
                    "SELECT value_read_status || '|' || (value_read_error IS NOT NULL) || '|'
                     || value_data_length || '|' || value_type_code FROM RegistryExplorer
                     WHERE hive_id={software} AND value_name='Broken'"
                )
            ),
            vec!["error|1|0|3"]
        );

        assert_eq!(
            strings(
                &conn,
                "SELECT h.facts_db FROM RegistryExplorer e JOIN RegistryHives h USING(hive_id)
                 WHERE e.entry_kind='key' AND e.key_path_lower=lower('\\ROOT\\Software\\Dup')
                 ORDER BY h.facts_db"
            ),
            vec![
                "REGISTRY/analyst_NTUSER.DAT.sqlite",
                "REGISTRY/guest_NTUSER.DAT.sqlite"
            ]
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryExplorer e JOIN RegistryHives h USING(hive_id)
                 WHERE h.is_regback=1 AND e.entry_kind='value'"
            ),
            1,
            "RegBack 백업 하이브도 전수 저장에 포함한다"
        );

        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
            0
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryExplorer e
                 LEFT JOIN source_records s ON s.record_id=e.record_id AND s.ordinal=0
                 WHERE s.record_id IS NULL"
            ),
            0
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryExplorer e JOIN RegistryHives h USING(hive_id)
                 JOIN source_records s ON s.record_id=e.record_id
                 WHERE s.source_db <> h.facts_db OR s.source_rowid <> e.source_rowid
                    OR s.source_dataset_id <> h.facts_dataset_id OR s.source_table <> 'Registry'
                    OR s.source_field <> e.entry_kind"
            ),
            0
        );
        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM RegistryExplorer"),
            rows_written as i64
        );

        let findings = Connection::open_with_flags(
            out_dir.join("_OVERVIEW/RegistryFindings.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let autoruns: i64 = findings
            .query_row(
                "SELECT COUNT(*) FROM RegistryFindings WHERE category='자동 실행'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(autoruns > 0, "픽스처가 자동 실행 판정을 만들어야 한다");
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryQuickTargets
                 WHERE resolution='exact_value' AND basis='source_records'"
            ),
            autoruns
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryQuickTargets q
                 JOIN RegistryExplorer e ON e.record_id=q.target_record_id
                 WHERE q.resolution='exact_value' AND e.entry_kind <> 'value'"
            ),
            0
        );
        drop(findings);
        drop(conn);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn legacy_registry_facts_require_explicit_reparse() {
        let (out_dir, target) = fixture_dirs("legacy-facts");
        let path = out_dir.join("REGISTRY").join("SOFTWARE.sqlite");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,
             value_data TEXT,_recovery TEXT,_source_file TEXT,value_data_hex TEXT);
             INSERT INTO Registry VALUES ('2026-01-01 00:00:00.000','\\ROOT\\A','N','REG_SZ','v','live','SOFTWARE','7600');",
        )
        .unwrap();
        drop(conn);
        crate::derived::stamp_facts_generation(&path, "facts-gen-1").unwrap();

        let error = build_all(&out_dir, &target, "host-1", "ds-1").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("entry_kind"), "{message}");
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn facts_source_file_lookup_failure_is_recorded() {
        let (out_dir, target) = fixture_dirs("source-file-error");
        let path = out_dir.join("REGISTRY").join("SOFTWARE.sqlite");
        dup_hive(&out_dir, "SOFTWARE.sqlite", "C:\\Windows\\System32\\config\\SOFTWARE");
        crate::metadata::build_metadata(&out_dir, &target, "host", "ds").unwrap();
        Connection::open(&path).unwrap()
            .execute_batch("ALTER TABLE Registry DROP COLUMN _source_file;").unwrap();
        let ctx = Ctx {
            out_dir: out_dir.as_path(),
            target: target.as_path(),
            host_id: "host",
            dataset_id: "ds",
            facts: FactsIndex::load(&out_dir).unwrap(),
            meta: MetaLookup::load(&out_dir).unwrap(),
        };
        build(&ctx).unwrap();
        let conn = open_explorer(&out_dir);
        let (status, error): (String, Option<String>) = conn.query_row(
            "SELECT load_status, load_error FROM RegistryHives", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(status, "loaded");
        assert!(error.as_deref().is_some_and(|e| e.contains("_source_file")), "{error:?}");
        drop(conn);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn quick_targets_separate_exact_parent_ancestor_and_missing() {
        let (out_dir, target) = fixture_dirs("quick-targets");
        let lsa1 = key(
            "12288",
            "8192",
            "Lsa",
            "\\ROOT\\ControlSet001\\Control\\Lsa",
        );
        let system_rows = vec![
            key("4096", "", "", "\\ROOT"),
            key("8192", "4096", "Control", "\\ROOT\\ControlSet001\\Control"),
            value(
                &lsa1,
                "9001",
                "RunAsPPL",
                "RunAsPPL",
                "4",
                "REG_DWORD",
                "01000000",
                "1",
            ),
            key("16384", "4096", "Control", "\\ROOT\\ControlSet002\\Control"),
            key(
                "20480",
                "16384",
                "Lsa",
                "\\ROOT\\ControlSet002\\Control\\Lsa",
            ),
        ];
        let system = fixture::write_hive(
            &out_dir,
            "SYSTEM.sqlite",
            "C:\\config\\SYSTEM",
            &system_rows,
        );
        fixture::write_hive(
            &out_dir,
            "SOFTWARE.sqlite",
            "C:\\config\\SOFTWARE",
            &[
                key("4096", "", "", "\\ROOT"),
                key(
                    "8192",
                    "4096",
                    "Windows",
                    "\\ROOT\\Policies\\Microsoft\\Windows",
                ),
                key("12288", "4096", "EmptyKey", "\\ROOT\\EmptyKey"),
            ],
        );
        dup_hive(
            &out_dir,
            "analyst_NTUSER.DAT.sqlite",
            "C:\\Users\\analyst\\NTUSER.DAT",
        );
        dup_hive(
            &out_dir,
            "guest_NTUSER.DAT.sqlite",
            "C:\\Users\\guest\\NTUSER.DAT",
        );
        dup_hive(
            &out_dir,
            "SOFTWARE_RegBack.sqlite",
            "C:\\config\\RegBack\\SOFTWARE",
        );
        fixture::write_manifest(
            &out_dir,
            &[
                [
                    "C:\\config\\SYSTEM",
                    "REGISTRY/SYSTEM.sqlite",
                    "SYSTEM",
                    "completed",
                    "5",
                    "",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\config\\SOFTWARE",
                    "REGISTRY/SOFTWARE.sqlite",
                    "SOFTWARE",
                    "completed",
                    "3",
                    "",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\config\\SECURITY",
                    "REGISTRY/SECURITY.sqlite",
                    "SECURITY",
                    "failed",
                    "",
                    "열지 못했습니다",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\config\\RegBack\\SOFTWARE",
                    "REGISTRY/SOFTWARE_RegBack.sqlite",
                    "SOFTWARE",
                    "completed",
                    "2",
                    "",
                    "0",
                    "0",
                    "",
                ],
                [
                    "C:\\Users\\analyst\\NTUSER.DAT",
                    "REGISTRY/analyst_NTUSER.DAT.sqlite",
                    "NTUSER.DAT",
                    "completed",
                    "2",
                    "",
                    "0",
                    "0",
                    "",
                ],
            ],
        );

        let lsa_rowid: i64 = Connection::open(&system)
            .unwrap()
            .query_row(
                "SELECT rowid FROM Registry WHERE value_name_raw='RunAsPPL'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let empty_rowid: i64 = Connection::open(out_dir.join("REGISTRY/SOFTWARE.sqlite"))
            .unwrap()
            .query_row(
                "SELECT rowid FROM Registry WHERE key_name='EmptyKey'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let overview_dir = out_dir.join("_OVERVIEW");
        let findings = crate::derived::create_database(&overview_dir, "RegistryFindings").unwrap();
        let judged: &[(&str, &str, &str)] = &[
            ("f1", "\\ROOT\\ControlSet001\\Control\\Lsa", "SYSTEM"),
            ("f2", "\\ROOT\\ControlSet001\\Control\\Lsa", "SYSTEM"),
            (
                "f3",
                "\\ROOT\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                "SOFTWARE",
            ),
            ("f4", "\\ROOT\\Software\\Dup", ""),
            ("f5", "\\ROOT\\Whatever", "NOPE"),
            ("f6", "\\ROOT\\Whatever", "SECURITY"),
            ("f7", "\\ROOT\\Nowhere", ""),
            ("f8", "\\ROOT\\EmptyKey", "SOFTWARE"),
            ("f9", "\\ROOT\\Software\\Dup", "analyst_NTUSER.DAT"),
            ("f10", "\\ROOT\\EmptyKey", ""),
        ];
        for (record_id, key_path, source) in judged {
            findings
                .execute(
                    "INSERT INTO RegistryFindings(record_id,host_id,dataset_id,overview_name,key_path,source)
                     VALUES (?1,'host','ds','RegistryFindings',?2,?3)",
                    rusqlite::params![record_id, key_path, source],
                )
                .unwrap();
        }
        for (record_id, relative, rowid) in [
            ("f1", "REGISTRY/SYSTEM.sqlite", lsa_rowid),
            ("f8", "REGISTRY/SOFTWARE.sqlite", empty_rowid),
        ] {
            findings
                .execute(
                    "INSERT INTO source_records(record_id,ordinal,source_dataset_id,source_artifact,
                     source_db,source_table,source_rowid)
                     VALUES (?1,0,'facts-gen-1','Registry',?2,'Registry',?3)",
                    rusqlite::params![record_id, relative, rowid],
                )
                .unwrap();
        }
        drop(findings);

        crate::metadata::build_metadata(&out_dir, &target, "host", "ds").unwrap();
        let ctx = Ctx {
            out_dir: out_dir.as_path(),
            target: target.as_path(),
            host_id: "host",
            dataset_id: "ds",
            facts: FactsIndex::load(&out_dir).unwrap(),
            meta: MetaLookup::load(&out_dir).unwrap(),
        };
        build(&ctx).unwrap();

        let conn = open_explorer(&out_dir);
        assert_eq!(
            strings(
                &conn,
                "SELECT finding_record_id || '|' || resolution || '|' || basis || '|'
                 || COALESCE(target_key_path,'-') || '|' || candidate_count
                 FROM RegistryQuickTargets ORDER BY finding_record_id"
            ),
            vec![
                "f1|exact_value|source_records|-|1",
                "f10|unresolved|key_path|-|1",
                "f2|parent_key|key_path|\\ROOT\\ControlSet001\\Control\\Lsa|1",
                "f3|ancestor_key|key_path|\\ROOT\\Policies\\Microsoft\\Windows|1",
                "f4|ambiguous|key_path|-|2",
                "f5|missing_hive|key_path|-|0",
                "f6|unavailable|key_path|-|0",
                "f7|unresolved|key_path|-|0",
                "f8|exact_key|source_records|-|1",
                "f9|parent_key|key_path|\\ROOT\\Software\\Dup|1",
            ]
        );
        assert_eq!(
            scalar::<String>(
                &conn,
                "SELECT finding_key_path FROM RegistryQuickTargets WHERE finding_record_id='f3'"
            ),
            "\\ROOT\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM RegistryQuickTargets q
                 JOIN RegistryExplorer e ON e.record_id=q.target_record_id
                 WHERE q.resolution='exact_key' AND e.key_name <> 'EmptyKey'"
            ),
            0
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT candidate_count FROM RegistryQuickTargets WHERE finding_record_id='f4'"
            ),
            2
        );
        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
            0
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }
}
