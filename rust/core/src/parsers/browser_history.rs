//! Chrome/Chromium "History" SQLite DB — raw table-for-table copy (same as the
//! Python parser), one output table per source table. Recognised by a `urls`
//! table. BLOBs -> hex, NULL -> SQL NULL; column order is the source columns
//! sorted (matching the Python writer). Uses rusqlite (already a dep).
use std::path::Path;

use anyhow::Result;
use rusqlite::types::ValueRef;
use rusqlite::Connection;

use crate::hex::hex_lower;
use crate::sqlite::Row;

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

/// One source table: (table_name, columns, rows).
pub type HistoryTable = (String, Vec<String>, Vec<Row>);

/// Returns one entry per source table, or empty if not a History DB.
pub fn parse_history(path: &Path) -> Result<Vec<HistoryTable>> {
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
        return Ok(Vec::new()); // not a Chrome History DB
    }

    let mut out: Vec<(String, Vec<String>, Vec<Row>)> = Vec::new();
    for table in &names {
        if SKIP.contains(&table.as_str()) || table.starts_with("sqlite_") {
            continue;
        }
        let mut stmt = match con.prepare(&format!("SELECT * FROM \"{}\"", table)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows: Vec<Row> = Vec::new();
        let mut q = stmt.query([])?;
        while let Some(r) = q.next()? {
            let mut row = Row::new();
            for (i, cname) in cols.iter().enumerate() {
                if let Some(cell) = render(r.get_ref(i)?) {
                    row.insert(cname.clone(), cell);
                }
                // NULL -> omit key -> writer binds SQL NULL (matches Python)
            }
            rows.push(row);
        }
        if !rows.is_empty() {
            out.push((table.clone(), cols, rows));
        }
    }
    Ok(out)
}
