//! Chrome/Chromium "History" SQLite DB — raw table-for-table copy (same as the
//! Python parser), one output table per source table. Recognised by a `urls`
//! table. BLOBs -> hex, NULL -> SQL NULL; column order is the source columns
//! sorted (matching the Python writer). Uses rusqlite (already a dep).
use std::path::Path;

use anyhow::Result;
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

/// History DB의 각 원본 테이블을 읽는 즉시 `out`의 동명 테이블로 스트리밍
/// 기록한다 — 수십만 행짜리 방문 기록도 전체를 메모리에 쌓지 않는다.
/// 반환: (총 레코드 수, 하나 이상 기록했는지). History DB가 아니면 (0, false).
pub fn parse_history_stream(path: &Path, out: &Path) -> Result<(usize, bool)> {
    let uri = format!("file:{}?mode=ro&immutable=1", path.display());
    let con = Connection::open_with_flags(
        &uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;

    let names: Vec<String> = {
        let mut stmt = con.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    if !names.iter().any(|n| n == "urls") {
        return Ok((0, false)); // not a Chrome History DB
    }

    let mut total = 0usize;
    let mut wrote = false;
    for table in &names {
        if SKIP.contains(&table.as_str()) || table.starts_with("sqlite_") {
            continue;
        }
        let mut stmt = match con.prepare(&format!("SELECT * FROM {}", crate::sqlite::quote_ident(table))) {
            Ok(s) => s,
            Err(_) => continue,
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
            total += writer.finish()?;
            wrote = true;
        }
    }
    Ok((total, wrote))
}
