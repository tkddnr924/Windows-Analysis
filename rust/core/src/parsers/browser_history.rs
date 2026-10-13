//! Chrome/Chromium "History" SQLite DB — raw table-for-table copy (same as the
//! Python parser), one output table per source table. Recognised by a `urls`
//! table. BLOBs -> hex, NULL -> SQL NULL; column order is the source columns
//! sorted (matching the Python writer). Uses rusqlite (already a dep).
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::Connection;

use crate::hex::hex_lower;
use crate::sqlite::{Row, StreamWriter};

/// None -> SQL NULL (matches Python None); others -> text cell.
fn render(v: ValueRef) -> Option<String> {
    match v {
        ValueRef::Null => None,
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Some(hex_lower(b)),
    }
}

const SKIP: &[&str] = &["sqlite_sequence", "sqlite_stat1", "history_sync_metadata"];

/// History 파싱 결과. 읽지 못한 테이블은 건너뛰되 사유를 남긴다.
#[derive(Debug, Default)]
pub struct HistoryParse {
    pub rows: usize,
    /// 하나 이상 기록했는지. History DB가 아니면 false.
    pub wrote: bool,
    pub table_errors: Vec<String>,
}

/// History DB의 각 원본 테이블을 읽는 즉시 `out`의 동명 테이블로 스트리밍
/// 기록한다 — 수십만 행짜리 방문 기록도 전체를 메모리에 쌓지 않는다.
pub fn parse_history_stream(path: &Path, sides: &[PathBuf], out: &Path) -> Result<HistoryParse> {
    static STAGING_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let seq = STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = parent.join(format!(".history-{}-{seq}", std::process::id()));
    std::fs::create_dir(&staging)?;
    // Like Timeline, read WAL on a private copy; never checkpoint the evidence.
    let parsed = (|| {
        let local = staging.join("History");
        std::fs::copy(path, &local).with_context(|| format!("copy History: {}", path.display()))?;
        for side in sides {
            let suffix = if side.to_string_lossy().to_lowercase().ends_with("-shm") {
                "-shm"
            } else {
                "-wal"
            };
            std::fs::copy(side, staging.join(format!("History{suffix}")))
                .with_context(|| format!("copy History sidecar: {}", side.display()))?;
        }
        let con = Connection::open_with_flags(&local, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        parse_history_tables(&con, out)
    })();
    let cleanup = std::fs::remove_dir_all(&staging);
    let result = parsed?;
    cleanup?;
    Ok(result)
}

fn parse_history_tables(con: &Connection, out: &Path) -> Result<HistoryParse> {
    let names: Vec<String> = {
        let mut stmt = con.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut result = HistoryParse::default();
    if !names.iter().any(|n| n == "urls") {
        return Ok(result); // not a Chrome History DB
    }

    for table in &names {
        if SKIP.contains(&table.as_str()) || table.starts_with("sqlite_") {
            continue;
        }
        let mut stmt = match con.prepare(&format!(
            "SELECT * FROM {}",
            crate::sqlite::quote_ident(table)
        )) {
            Ok(s) => s,
            Err(error) => {
                result.table_errors.push(format!("{table}: {error}"));
                continue;
            }
        };
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let col_refs: Vec<&str> = cols.iter().map(String::as_str).collect();
        let mut q = stmt.query([])?;
        // 첫 행을 먼저 보고 나서야 writer를 만든다 — 빈 테이블을 출력에
        // 만들지 않는 규칙을 COUNT(*) 전수 스캔 없이 유지한다 (수백만 행
        // 테이블을 두 번 훑지 않기 위함).
        let mut writer: Option<StreamWriter> = None;
        while let Some(r) = q.next()? {
            let mut row = Row::new();
            for (i, cname) in cols.iter().enumerate() {
                if let Some(cell) = render(r.get_ref(i)?) {
                    row.insert(cname.clone(), cell);
                }
                // NULL -> omit key -> writer binds SQL NULL (matches Python)
            }
            if writer.is_none() {
                writer = Some(StreamWriter::create(out, table, &col_refs, &[])?);
            }
            writer.as_mut().unwrap().push(row)?;
        }
        if let Some(writer) = writer {
            result.rows += writer.finish()?;
            result.wrote = true;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_wal_history_is_parsed_without_changing_evidence() {
        let root = std::env::temp_dir().join(format!(
            "wina-history-wal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("History");
        let source = Connection::open(&path).unwrap();
        source
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             INSERT INTO urls VALUES (1, 'https://wal.example/committed');",
            )
            .unwrap();
        let wal = root.join("History-wal");
        let before_db = std::fs::read(&path).unwrap();
        let before_wal = std::fs::read(&wal).unwrap();
        let out = root.join("result.sqlite");
        let result =
            parse_history_stream(&path, &super::super::timeline::wal_siblings(&path), &out)
                .unwrap();
        let unchanged = before_db == std::fs::read(&path).unwrap()
            && before_wal == std::fs::read(&wal).unwrap();
        let url = if result.wrote {
            Connection::open(&out)
                .unwrap()
                .query_row("SELECT url FROM urls WHERE id = '1'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap()
        } else {
            String::new()
        };
        drop(source);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!((result.rows, result.wrote), (1, true));
        assert_eq!(url, "https://wal.example/committed");
        assert!(
            unchanged,
            "parsing must not checkpoint or change the evidence"
        );
    }

    #[test]
    fn unreadable_table_is_reported_not_silently_skipped() {
        let root = std::env::temp_dir().join(format!("wina-history-badtable-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("History");
        let source = Connection::open(&path).unwrap();
        source
            .execute_batch(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls VALUES (1, 'https://a.example/');
                 PRAGMA writable_schema=ON;
                 INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql)
                   VALUES ('table', 'bogus', 'bogus', 0, 'CREATE VIRTUAL TABLE bogus USING nosuchmodule');
                 PRAGMA writable_schema=OFF;",
            )
            .unwrap();
        drop(source);
        let out = root.join("result.sqlite");
        let result = parse_history_stream(&path, &[], &out).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!((result.rows, result.wrote), (1, true));
        assert_eq!(result.table_errors.len(), 1, "{:?}", result.table_errors);
        assert!(result.table_errors[0].starts_with("bogus:"));
    }

    #[test]
    fn wal_without_shm_uses_latest_commit_not_uncommitted_changes() {
        let root = std::env::temp_dir().join(format!(
            "wina-history-commit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let collected = root.join("collected");
        std::fs::create_dir_all(&collected).unwrap();
        let live = root.join("History");
        let source = Connection::open(&live).unwrap();
        source
            .execute_batch(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             INSERT INTO urls VALUES (1, 'https://old.example/');
             PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             UPDATE urls SET url = 'https://latest.example/' WHERE id = 1;
             INSERT INTO urls VALUES (2, 'https://committed.example/');
             BEGIN;
             INSERT INTO urls VALUES (3, 'https://uncommitted.example/');",
            )
            .unwrap();
        let path = collected.join("HISTORY");
        let wal = collected.join("HISTORY-wal");
        std::fs::copy(&live, &path).unwrap();
        std::fs::copy(root.join("History-wal"), &wal).unwrap();
        let before_db = std::fs::read(&path).unwrap();
        let before_wal = std::fs::read(&wal).unwrap();
        let out = root.join("result.sqlite");
        let result = parse_history_stream(&path, &[wal.clone()], &out).unwrap();
        assert!(result.table_errors.is_empty());
        let parsed = Connection::open(&out).unwrap();
        let urls: Vec<String> = parsed
            .prepare("SELECT url FROM urls ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let unchanged = before_db == std::fs::read(&path).unwrap()
            && before_wal == std::fs::read(&wal).unwrap()
            && !collected.join("HISTORY-shm").exists();
        drop(parsed);
        drop(source);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!((result.rows, result.wrote), (2, true));
        assert_eq!(
            urls,
            ["https://latest.example/", "https://committed.example/"]
        );
        assert!(
            unchanged,
            "missing SHM must be rebuilt only on the private copy"
        );
    }
}
