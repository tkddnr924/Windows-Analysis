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

use crate::hex::{format_binary_sid, hex_lower};
use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_ole;

pub const SRUM_PREFIX: &[&str] = &["timestamp", "app", "user", "AutoIncId", "AppId", "UserId"];

fn utf16le(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
        .trim_end_matches('\u{0}')
        .to_string()
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
        Value::U8(_)
        | Value::U16(_)
        | Value::U32(_)
        | Value::I16(_)
        | Value::I32(_)
        | Value::I64(_)
        | Value::Currency(_) => as_int(v).map(|x| x.to_string()).unwrap_or_default(),
        Value::F32(x) => format!("{}", x),
        Value::F64(x) => format!("{}", x),
        Value::DateTime(bits) => fmt_ole(f64::from_bits(*bits)),
        Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) | Value::Guid(b) => {
            hex_lower(b)
        }
        Value::Text(s) | Value::LargeText(s) => s.trim_end_matches('\u{0}').to_string(),
        // Long/Multi 값은 레코드 수준에서 별도 API로 조회한다(render_record_value).
        Value::Long | Value::Multi => String::new(),
    }
}

/// 레코드의 한 컬럼을 렌더링한다. ESE long value(행 밖에 저장되는 큰 텍스트/
/// 바이너리)와 multi value는 `rec.value()`가 자리표시자만 돌려주므로, 전용
/// API로 실제 내용을 가져온다 — 그냥 render()만 쓰면 해당 셀이 통째로
/// 비어(누락) 나온다.
fn render_record_value(rec: &libesedb::Record, entry: i32, v: &Value) -> String {
    match v {
        Value::Long => match rec.long(entry) {
            Ok(lv) => match lv.variant() {
                Value::Text(_) | Value::LargeText(_) => lv
                    .utf8()
                    .map(|s| s.trim_end_matches('\u{0}').to_string())
                    .unwrap_or_default(),
                _ => hex_lower(&lv.vec().unwrap_or_default()),
            },
            Err(_) => String::new(),
        },
        Value::Multi => match rec.multi(entry) {
            Ok(mv) => match mv.iter_values() {
                Ok(values) => values
                    .filter_map(|value| value.ok())
                    .map(|value| render(&value))
                    .collect::<Vec<_>>()
                    .join(", "),
                Err(_) => String::new(),
            },
            Err(_) => String::new(),
        },
        other => render(other),
    }
}

/// Friendly output name from the data table's column signature (schema-stable),
/// falling back to a cleaned GUID.
fn friendly_name(guid: &str, cols: &[String]) -> String {
    let has = |c: &str| cols.iter().any(|x| x == c);
    if has("BytesSent") || has("BytesRecvd") || has("BytesInBound") || has("BytesOutBound") {
        return "SRUM_NetworkDataUsage".into();
    }
    if has("ForegroundCycleTime") {
        return "SRUM_ApplicationResourceUsage".into();
    }
    if has("ConnectedTime") || has("ConnectStartTime") {
        return "SRUM_NetworkConnectivityUsage".into();
    }
    if has("DurationMS") && has("EndTime") {
        return "SRUM_ApplicationTimeline".into();
    }
    if has("ChargeLevel") || has("DesignedCapacity") {
        return "SRUM_EnergyUsage".into();
    }
    if has("NotificationType") || has("PayloadSize") {
        return "SRUM_PushNotifications".into();
    }
    format!(
        "SRUM_{}",
        guid.trim_matches(|c| c == '{' || c == '}').replace('-', "")
    )
}

fn build_id_map(db: &EseDb, skipped: &mut Skipped) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    let table = match db.table_by_name("SruDbIdMapTable") {
        Ok(t) => t,
        Err(_) => return map,
    };
    let cols: Vec<String> = match table.iter_columns() {
        Ok(it) => it
            .filter_map(|c| c.ok())
            .filter_map(|c| c.name().ok())
            .collect(),
        Err(_) => return map,
    };
    let idx_of = |n: &str| cols.iter().position(|c| c == n).map(|i| i as i32);
    let (it, ii, ib) = (idx_of("IdType"), idx_of("IdIndex"), idx_of("IdBlob"));
    let (ii, ib) = match (ii, ib) {
        (Some(a), Some(b)) => (a, b),
        _ => return map,
    };
    if let Ok(records) = table.iter_records() {
        for rec in records {
            let Ok(rec) = rec else {
                skipped.records += 1;
                continue;
            };
            let idx = rec.value(ii).ok().and_then(|v| as_int(&v));
            let id_type = it.and_then(|i| rec.value(i).ok()).and_then(|v| as_int(&v));
            let blob = rec.value(ib).ok();
            if idx.is_none() || blob.is_none() {
                skipped.values += 1;
            }
            if let (Some(idx), Some(v)) = (idx, blob) {
                let bytes: Vec<u8> = match &v {
                    Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) => b.clone(),
                    // 긴 경로/이름은 long value로 저장된다 — 건너뛰면 해당
                    // app/user 매핑이 통째로 비게 되므로 실제 바이트를 조회한다.
                    Value::Long => match rec.long(ib) {
                        Ok(lv) => lv.vec().unwrap_or_default(),
                        Err(_) => continue,
                    },
                    _ => continue,
                };
                if bytes.is_empty() {
                    continue;
                }
                let s = if id_type == Some(3) {
                    format_binary_sid(&bytes).unwrap_or_else(|| hex_lower(&bytes))
                } else {
                    utf16le(&bytes)
                };
                map.insert(idx, s);
            }
        }
    }
    map
}

/// Integer SRUM columns holding FILETIMEs (sample: every row of
/// NetworkConnectivityUsage.ConnectStartTime, ApplicationTimeline.EndTime and
/// the {7ACBBAA3…} table's StartTime/EndTime). Durations stay raw.
const FILETIME_COLUMNS: &[&str] = &["ConnectStartTime", "StartTime", "EndTime"];

fn filetime_column(name: &str, v: &Value) -> Option<String> {
    if !FILETIME_COLUMNS.contains(&name) {
        return None;
    }
    as_int(v).map(crate::time::fmt_filetime)
}

/// Records and values that libesedb could not read in one table.
#[derive(Default)]
struct Skipped {
    records: usize,
    values: usize,
}

fn dump_table_stream(
    table: &libesedb::Table,
    id_map: &HashMap<i64, String>,
    source: &str,
    out: &Path,
    name: &str,
    skipped: &mut Skipped,
) -> Result<usize> {
    let cols: Vec<String> = table
        .iter_columns()?
        .filter_map(|c| c.ok())
        .filter_map(|c| c.name().ok())
        .collect();
    // universe = prefix + each column (TimeStamp->timestamp) + _source_file
    let mut universe: Vec<String> = SRUM_PREFIX.iter().map(|s| s.to_string()).collect();
    for c in &cols {
        universe.push(if c == "TimeStamp" {
            "timestamp".to_string()
        } else {
            c.clone()
        });
    }
    universe.push("_source_file".to_string());
    let uref: Vec<&str> = universe.iter().map(|s| s.as_str()).collect();
    let mut writer = StreamWriter::create(out, name, &uref, SRUM_PREFIX)?;
    for rec in table.iter_records()? {
        if crate::pipeline::cancelled() {
            break;
        }
        let Ok(rec) = rec else {
            skipped.records += 1;
            continue;
        };
        let mut row = Row::new();
        row.insert("_source_file".into(), source.into());
        let (mut app_id, mut user_id) = (None, None);
        for (i, name) in cols.iter().enumerate() {
            let v = match rec.value(i as i32) {
                Ok(v) => v,
                Err(_) => {
                    skipped.values += 1;
                    continue;
                }
            };
            if name == "AppId" {
                app_id = as_int(&v);
            } else if name == "UserId" {
                user_id = as_int(&v);
            }
            let key = if name == "TimeStamp" {
                "timestamp"
            } else {
                name
            };
            let text = filetime_column(name, &v)
                .unwrap_or_else(|| render_record_value(&rec, i as i32, &v));
            row.insert(key.into(), text);
        }
        if let Some(a) = app_id {
            row.insert("app".into(), id_map.get(&a).cloned().unwrap_or_default());
        }
        if let Some(u) = user_id {
            row.insert("user".into(), id_map.get(&u).cloned().unwrap_or_default());
        }
        writer.push(row)?;
    }
    writer.finish()
}

/// Per-table row counts plus unreadable-record notes (empty when clean).
pub struct SrumParse {
    pub tables: Vec<(String, usize)>,
    pub skipped: Vec<String>,
}

pub fn parse_srum_stream(path: &Path, out_db: &Path) -> Result<SrumParse> {
    let source = path.to_string_lossy().to_string();
    let db = EseDb::open(path).map_err(|e| {
        anyhow::anyhow!(
            "SRUDB.dat is corrupted or dirty (requires esentutl /p). Original error: {}",
            e
        )
    })?;
    let mut notes = Vec::new();
    let mut id_skipped = Skipped::default();
    let id_map = build_id_map(&db, &mut id_skipped);
    push_skipped(&mut notes, "SruDbIdMapTable", &id_skipped);
    let mut out: Vec<(String, usize)> = Vec::new();
    for table in db.iter_tables()?.filter_map(|t| t.ok()) {
        let gname = table.name()?;
        if gname.starts_with("MSys")
            || gname == "SruDbCheckpointTable"
            || gname == "SruDbIdMapTable"
        {
            continue;
        }
        let cols: Vec<String> = table
            .iter_columns()?
            .filter_map(|c| c.ok())
            .filter_map(|c| c.name().ok())
            .collect();
        // 시그니처가 같은 테이블이 둘일 수 있다(예: EnergyUsage와 장기 집계인
        // {GUID}LT). 같은 출력 이름을 쓰면 뒤 테이블이 앞 테이블을 DROP하고
        // 덮어써 행이 유실되므로 이름을 반드시 구분한다.
        let mut name = friendly_name(&gname, &cols);
        if gname.ends_with("LT") {
            name.push_str("LT");
        }
        while out.iter().any(|(existing, _)| *existing == name) {
            name.push('_');
        }
        let mut skipped = Skipped::default();
        let n = dump_table_stream(&table, &id_map, &source, out_db, &name, &mut skipped)?;
        push_skipped(&mut notes, &gname, &skipped);
        out.push((name, n));
    }
    Ok(SrumParse { tables: out, skipped: notes })
}

fn push_skipped(notes: &mut Vec<String>, table: &str, skipped: &Skipped) {
    if skipped.records > 0 || skipped.values > 0 {
        notes.push(format!(
            "{table}: 읽기 실패 레코드 {}건, 값 {}건",
            skipped.records, skipped.values
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_filetime_columns_are_formatted_durations_are_not() {
        let ft = Value::I64(134_285_780_749_171_136);
        let text = filetime_column("ConnectStartTime", &ft).unwrap();
        assert!(text.starts_with("2026-"), "{text}");
        assert_eq!(filetime_column("ConnectedTime", &Value::I64(852_265)), None);
        assert_eq!(filetime_column("EndTime", &Value::I64(0)).as_deref(), Some(""));
    }
}
