//! SRUM (SRUDB.dat, ESE) parser via `libesedb` (FFI to the same libyal C
//! library the Python `pyesedb` binding wraps → identical parsing). Emits one
//! table per SRUM data provider. Improvement over the Python parser: tables are
//! named by their COLUMN SIGNATURE (robust across Windows schema versions),
//! not a fixed provider-GUID map — so e.g. network data usage is recognized
//! whether its columns are BytesSent/BytesRecvd or BytesInBound/BytesOutBound.
use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use libesedb::{EseDb, Value};

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_ole;

pub const SRUM_PREFIX: &[&str] = &["timestamp", "app", "user", "AutoIncId", "AppId", "UserId"];

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{:02x}", x)); }
    s
}

/// A binary SID -> "S-1-5-..." (matches the Python _format_sid).
fn format_sid(data: &[u8]) -> String {
    if data.len() < 8 { return hex_lower(data); }
    let revision = data[0];
    let sub_count = data[1] as usize;
    let authority = data[2..8].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut parts = vec!["S".to_string(), revision.to_string(), authority.to_string()];
    let mut off = 8;
    for _ in 0..sub_count {
        if off + 4 > data.len() { break; }
        let v = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        parts.push(v.to_string());
        off += 4;
    }
    parts.join("-")
}

fn utf16le(b: &[u8]) -> String {
    let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u).trim_end_matches('\u{0}').to_string()
}

/// Integer value out of any integer-ish Value.
fn as_int(v: &Value) -> Option<i64> {
    v.to_i64()
}

/// Render a Value to its sqlite text cell. DATE_TIME is reinterpreted as an OLE
/// automation date (f64), NOT the FILETIME the crate assumes.
fn render(v: &Value) -> String {
    match v {
        Value::Null(_) => String::new(),
        Value::Bool(b) => (if *b { 1 } else { 0 }).to_string(),
        Value::U8(_) | Value::U16(_) | Value::U32(_) | Value::I16(_) | Value::I32(_)
        | Value::I64(_) | Value::Currency(_) => as_int(v).map(|x| x.to_string()).unwrap_or_default(),
        Value::F32(x) => format!("{}", x),
        Value::F64(x) => format!("{}", x),
        Value::DateTime(bits) => fmt_ole(f64::from_bits(*bits)),
        Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) | Value::Guid(b) => hex_lower(b),
        Value::Text(s) | Value::LargeText(s) => s.trim_end_matches('\u{0}').to_string(),
        Value::Long | Value::Multi => String::new(),
    }
}

/// Friendly output name from the data table's column signature (schema-stable),
/// falling back to a cleaned GUID.
fn friendly_name(guid: &str, cols: &[String]) -> String {
    let has = |c: &str| cols.iter().any(|x| x == c);
    if has("BytesSent") || has("BytesRecvd") || has("BytesInBound") || has("BytesOutBound") {
        return "SRUM_NetworkDataUsage".into();
    }
    if has("ForegroundCycleTime") { return "SRUM_ApplicationResourceUsage".into(); }
    if has("ConnectedTime") || has("ConnectStartTime") { return "SRUM_NetworkConnectivityUsage".into(); }
    if has("DurationMS") && has("EndTime") { return "SRUM_ApplicationTimeline".into(); }
    if has("ChargeLevel") || has("DesignedCapacity") { return "SRUM_EnergyUsage".into(); }
    if has("NotificationType") || has("PayloadSize") { return "SRUM_PushNotifications".into(); }
    format!("SRUM_{}", guid.trim_matches(|c| c == '{' || c == '}').replace('-', ""))
}

fn build_id_map(db: &EseDb) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    let table = match db.table_by_name("SruDbIdMapTable") { Ok(t) => t, Err(_) => return map };
    let cols: Vec<String> = match table.iter_columns() {
        Ok(it) => it.filter_map(|c| c.ok()).filter_map(|c| c.name().ok()).collect(),
        Err(_) => return map,
    };
    let idx_of = |n: &str| cols.iter().position(|c| c == n).map(|i| i as i32);
    let (it, ii, ib) = (idx_of("IdType"), idx_of("IdIndex"), idx_of("IdBlob"));
    let (ii, ib) = match (ii, ib) { (Some(a), Some(b)) => (a, b), _ => return map };
    if let Ok(records) = table.iter_records() {
        for rec in records.filter_map(|r| r.ok()) {
            let idx = rec.value(ii).ok().and_then(|v| as_int(&v));
            let id_type = it.and_then(|i| rec.value(i).ok()).and_then(|v| as_int(&v));
            let blob = rec.value(ib).ok();
            if let (Some(idx), Some(v)) = (idx, blob) {
                let bytes: &[u8] = match &v {
                    Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) => b,
                    _ => continue,
                };
                let s = if id_type == Some(3) { format_sid(bytes) } else { utf16le(bytes) };
                map.insert(idx, s);
            }
        }
    }
    map
}

fn dump_table_stream(table: &libesedb::Table, id_map: &HashMap<i64, String>, source: &str, out: &Path, name: &str) -> Result<usize> {
    let cols: Vec<String> = table.iter_columns()?.filter_map(|c| c.ok()).filter_map(|c| c.name().ok()).collect();
    // universe = prefix + each column (TimeStamp->timestamp) + _source_file
    let mut universe: Vec<String> = SRUM_PREFIX.iter().map(|s| s.to_string()).collect();
    for c in &cols { universe.push(if c == "TimeStamp" { "timestamp".to_string() } else { c.clone() }); }
    universe.push("_source_file".to_string());
    let uref: Vec<&str> = universe.iter().map(|s| s.as_str()).collect();
    let mut writer = StreamWriter::create(out, name, &uref, SRUM_PREFIX)?;
    for rec in table.iter_records()?.filter_map(|r| r.ok()) {
        let mut row = Row::new();
        row.insert("_source_file".into(), source.into());
        let (mut app_id, mut user_id) = (None, None);
        for (i, name) in cols.iter().enumerate() {
            let v = match rec.value(i as i32) { Ok(v) => v, Err(_) => continue };
            if name == "AppId" { app_id = as_int(&v); }
            else if name == "UserId" { user_id = as_int(&v); }
            let key = if name == "TimeStamp" { "timestamp" } else { name };
            row.insert(key.into(), render(&v));
        }
        if let Some(a) = app_id { row.insert("app".into(), id_map.get(&a).cloned().unwrap_or_default()); }
        if let Some(u) = user_id { row.insert("user".into(), id_map.get(&u).cloned().unwrap_or_default()); }
        writer.push(row)?;
    }
    writer.finish()
}

pub fn parse_srum_stream(path: &Path, out_db: &Path) -> Result<Vec<(String, usize)>> {
    let source = path.to_string_lossy().to_string();
    let db = EseDb::open(path)?;
    let id_map = build_id_map(&db);
    let mut out: Vec<(String, usize)> = Vec::new();
    for table in db.iter_tables()?.filter_map(|t| t.ok()) {
        let gname = table.name()?;
        if gname.starts_with("MSys") || gname == "SruDbCheckpointTable" || gname == "SruDbIdMapTable" {
            continue;
        }
        let cols: Vec<String> = table.iter_columns()?.filter_map(|c| c.ok()).filter_map(|c| c.name().ok()).collect();
        let name = friendly_name(&gname, &cols);
        let n = dump_table_stream(&table, &id_map, &source, out_db, &name)?;
        out.push((name, n));
    }
    Ok(out)
}
