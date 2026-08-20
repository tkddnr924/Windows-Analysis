//! Registry hive parser (via `notatin`, which applies transaction logs / dirty
//! hive recovery natively). Produces the same uniform dump schema as the Python
//! parser: last_write | key_path | value_name | value_type | value_data.
use std::path::{Path, PathBuf};

use anyhow::Result;
use notatin::cell_key_value::CellKeyValue;
use notatin::cell_value::CellValue;
use notatin::parser::ParserIterator;
use notatin::parser_builder::ParserBuilder;

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_kst;

pub const REG_TABLE: &str = "Registry";
pub const REG_FILENAMES: &[&str] = &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
pub const REG_SUFFIXES: &[&str] = &["NTUSER.DAT", "USRCLASS.DAT"];
pub const REG_FIELD_ORDER: &[&str] =
    &["last_write", "key_path", "value_name", "value_type", "value_data", "_recovery", "_source_file"];

fn has_control(s: &str) -> bool {
    s.chars().any(|c| c == '\u{0}' || ((c as u32) < 32 && c != '\t' && c != '\n' && c != '\r'))
}
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
/// Mirror the Python `_clean` for a decoded string: strip a trailing NUL, and
/// if control bytes remain, hex-encode (latin-1) instead of storing a BLOB.
fn clean_str(s: &str) -> String {
    let s = s.trim_end_matches('\u{0}');
    if has_control(s) {
        let bytes: Vec<u8> = s.chars().map(|c| if (c as u32) <= 255 { c as u8 } else { b'?' }).collect();
        hex_lower(&bytes)
    } else {
        s.to_string()
    }
}
/// json.dumps(list, ensure_ascii=False) — ["a", "b"] with a space after commas.
fn json_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", parts.join(", "))
}
fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn type_name(value: &CellKeyValue) -> String {
    // notatin's variant names match regipy's REG_* strings except 0x03
    // (notatin REG_BIN -> regipy REG_BINARY). For a type notatin doesn't map
    // (REG_UNKNOWN=999) regipy surfaces the raw numeric type instead — SAM
    // abuses the type field to store a RID (500, 1000, ...), so keep the raw
    // number to stay 1:1 with regipy (and preserve that RID).
    let s = format!("{:?}", value.data_type);
    match s.as_str() {
        "REG_BIN" => "REG_BINARY".to_string(),
        "REG_UNKNOWN" => value.detail.data_type_raw().to_string(),
        _ => s,
    }
}

fn render_value(cv: &CellValue) -> String {
    match cv {
        CellValue::String(s) => clean_str(s),
        CellValue::Binary(b) => hex_lower(b),
        CellValue::MultiString(v) => json_list(v),
        CellValue::U32(v) => v.to_string(),
        CellValue::I32(v) => v.to_string(),
        CellValue::U64(v) => v.to_string(),
        CellValue::I64(v) => v.to_string(),
        _ => String::new(),
    }
}

/// Sibling transaction logs (.LOG1/.LOG2) next to a primary hive.
pub fn sibling_logs(primary: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    if let Some(dir) = primary.parent() {
        let name = primary.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                let up = fname.to_uppercase();
                if up == format!("{}.LOG1", name).to_uppercase() || up == format!("{}.LOG2", name).to_uppercase() {
                    logs.push(e.path());
                }
            }
        }
    }
    logs.sort();
    logs
}

/// "live" for an allocated cell, else notatin's deleted/recovered state name
/// (DeletedPrimaryFile, DeletedPrimaryFileSlack, DeletedTransactionLog, ...).
fn recovery_label(key: &notatin::cell_key_node::CellKeyNode, value_deleted: Option<&notatin::cell_key_value::CellKeyValue>) -> String {
    if let Some(v) = value_deleted {
        if v.cell_state.is_deleted() { return format!("{:?}", v.cell_state); }
    }
    if key.cell_state.is_deleted() { return format!("{:?}", key.cell_state); }
    "live".to_string()
}

pub fn parse_hive_stream(primary: &Path, out: &Path) -> Result<usize> {
    let source = primary.to_string_lossy().to_string();
    let mut builder = ParserBuilder::from_path(primary.to_path_buf());
    for log in sibling_logs(primary) {
        builder.with_transaction_log(log);
    }
    builder.recover_deleted(true); // recover deleted keys/values (+ txlog versions)
    let parser = builder.build()?;

    let mut writer = StreamWriter::create(out, REG_TABLE, REG_FIELD_ORDER, REG_FIELD_ORDER)?;
    for key in ParserIterator::new(&parser) {
        if crate::pipeline::cancelled() { break; }
        let last_write = fmt_kst(key.last_key_written_date_and_time());
        let path = key.path.clone();
        let mut had_value = false;
        for value in key.value_iter() {
            had_value = true;
            let (cv, _logs) = value.get_content();
            let name = value.get_pretty_name();
            let name = if name.is_empty() { "(default)".to_string() } else { clean_str(&name) };
            let mut row = Row::new();
            row.insert("last_write".into(), last_write.clone());
            row.insert("key_path".into(), path.clone());
            row.insert("value_name".into(), name);
            row.insert("value_type".into(), type_name(&value));
            row.insert("value_data".into(), render_value(&cv));
            row.insert("_recovery".into(), recovery_label(&key, Some(&value)));
            row.insert("_source_file".into(), source.clone());
            writer.push(row)?;
        }
        if !had_value {
            let mut row = Row::new();
            row.insert("last_write".into(), last_write);
            row.insert("key_path".into(), path);
            row.insert("value_name".into(), String::new());
            row.insert("value_type".into(), String::new());
            row.insert("value_data".into(), String::new());
            row.insert("_recovery".into(), recovery_label(&key, None));
            row.insert("_source_file".into(), source.clone());
            writer.push(row)?;
        }
    }
    writer.finish()
}
