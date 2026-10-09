//! Persist supplemental source evidence before deriving overview rows.
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::overview;
use crate::sqlite::Row;

/// Host-relative evidence database.
pub const ANCILLARY_DB: &str = "SUPPLEMENTAL/Ancillary_Records.sqlite";
pub const ANCILLARY_CATEGORY: &str = "SUPPLEMENTAL";
pub const HOSTS_TABLE: &str = "Hosts_Records";

pub const HOSTS_ARTIFACT: &str = "Hosts";

const CREATE_SQL: &str = r#"
CREATE TABLE "Hosts_Records" (
  "ip" TEXT,
  "host_name" TEXT,
  "line_number" INTEGER,
  "raw_line" TEXT,
  "_source_file" TEXT NOT NULL
);
"#;

fn get<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn opt(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Return nonempty facts for partial publication; retain empty schemas in staging.
pub fn prepare_ancillary_facts(
    out_dir: &Path,
    target: &Path,
    dataset_id: &str,
) -> Result<Vec<String>> {
    let dir = out_dir.join(ANCILLARY_CATEGORY);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("보조 증거 폴더 생성: {}", dir.display()))?;
    let path = dir.join("Ancillary_Records.sqlite");
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 보조 증거 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("보조 증거 DB 생성: {}", path.display()))?;
    conn.execute_batch(CREATE_SQL)?;
    conn.execute_batch("BEGIN")?;
    let mut count = 0;
    {
        let mut hosts = conn.prepare(
            "INSERT INTO \"Hosts_Records\" (ip, host_name, line_number, raw_line, _source_file) \
             VALUES (?1,?2,?3,?4,?5)",
        )?;
        for row in overview::ti_from_hosts_file(target) {
            count += hosts.execute(rusqlite::params![
                opt(get(&row, "value")),
                opt(get(&row, "name")),
                opt(get(&row, "line_number")).and_then(|v| v.parse::<i64>().ok()),
                get(&row, "raw_line"),
                get(&row, "_source_file"),
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    drop(conn);
    super::stamp_facts_generation(&path, dataset_id)?;
    let mut published = if count == 0 { Vec::new() } else { vec![ANCILLARY_DB.to_string()] };
    published.extend(super::defender::prepare_inputs(out_dir, target, dataset_id)?);
    published.extend(super::scheduled_tasks::prepare_inputs(out_dir, target, dataset_id)?);
    published.extend(super::wer_reports::prepare_inputs(out_dir, target, dataset_id)?);
    published.extend(super::bits_history::prepare_inputs(out_dir, target, dataset_id)?);
    Ok(published)
}

pub fn ancillary_path(out_dir: &Path) -> std::path::PathBuf {
    out_dir.join(ANCILLARY_CATEGORY).join("Ancillary_Records.sqlite")
}
