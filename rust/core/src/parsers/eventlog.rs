//! Windows Event Log (.evtx) parser via the `evtx` crate (omerbenamram) — the
//! same engine the Python `evtx` binding wraps, so the JSON structure matches.
//! One table per source log; schema identical to the Python parser, including
//! the EventData column serialized json.dumps-style (spaces after `,`/`:`,
//! insertion-ordered keys via serde_json's preserve_order).
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use serde::Serialize;
use serde_json::Value;

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_kst;


/// The IR-relevant .evtx to parse (exact filenames, case-insensitive), matching
/// the Python parser's allowlist. "%4" is the on-disk escaping for "/".
pub const ALLOWLIST: &[&str] = &[
    "Security.evtx", "System.evtx", "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx", "Windows PowerShell.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx", "Microsoft-Windows-SMBServer%4Audit.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx", "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
];

pub const EVENT_COLUMNS: &[&str] = &[
    "timestamp", "Channel", "EventID", "LevelName", "Level", "Provider",
    "Computer", "EventRecordID", "ProcessID", "ThreadID", "UserID",
    "EventData", "_record_key", "_status", "_error", "_source_file",
];

fn level_name(level: Option<&str>) -> String {
    match level {
        Some("0") | Some("4") => "Information".into(),
        Some("1") => "Critical".into(),
        Some("2") => "Error".into(),
        Some("3") => "Warning".into(),
        Some("5") => "Verbose".into(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// json.dumps(v, ensure_ascii=False): compact but with a space after every
/// ',' and ':'. serde_json's preserve_order keeps the evtx crate's key order.
struct PyFmt;
impl serde_json::ser::Formatter for PyFmt {
    fn begin_array_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W, first: bool) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(&mut self, w: &mut W, first: bool) -> std::io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        w.write_all(b": ")
    }
}
fn py_json(v: &Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PyFmt);
    v.serialize(&mut ser).ok();
    String::from_utf8(buf).unwrap_or_default()
}

fn get<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    if cur.is_null() { None } else { Some(cur) }
}
/// Legacy events wrap a scalar as {"#attributes": ..., "#text": N}; unwrap it.
fn scalar(v: Option<&Value>) -> Option<&Value> {
    match v {
        Some(Value::Object(m)) if m.contains_key("#text") => m.get("#text"),
        other => other,
    }
}
fn cell(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(if *b { "true" } else { "false" }.into()),
        Some(other) => Some(py_json(other)),
    }
}

fn fmt_ts(system_time: Option<&Value>, record_ts: DateTime<Utc>) -> String {
    if let Some(Value::String(s)) = system_time {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return fmt_kst(dt.with_timezone(&Utc));
        }
    }
    fmt_kst(record_ts)
}

pub fn parse_evtx_stream(path: &Path, out: &Path, table: &str) -> Result<usize> {
    let src = path.to_string_lossy().to_string();
    let fname = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut parser = EvtxParser::from_path(path)?;
    let mut writer = StreamWriter::create(out, table, EVENT_COLUMNS, EVENT_COLUMNS)?;

    for rec in parser.records_json_value() {
        if crate::pipeline::cancelled() { break; }
        match rec {
            Err(e) => {
                let mut row = Row::new();
                row.insert("timestamp".into(), String::new());
                row.insert("_status".into(), "corrupted_chunk".into());
                row.insert("_error".into(), e.to_string());
                row.insert("_source_file".into(), src.clone());
                writer.push(row)?;
            }
            Ok(r) => {
                let data = &r.data;
                let system = get(data, &["Event", "System"]);
                let sys = system.unwrap_or(&Value::Null);
                let payload = get(data, &["Event", "EventData"]).or_else(|| get(data, &["Event", "UserData"]));

                let level = cell(scalar(sys.get("Level")));
                let mut row = Row::new();
                row.insert("timestamp".into(), fmt_ts(get(sys, &["TimeCreated", "#attributes", "SystemTime"]), r.timestamp));
                if let Some(v) = cell(sys.get("Channel")) { row.insert("Channel".into(), v); }
                if let Some(v) = cell(scalar(sys.get("EventID"))) { row.insert("EventID".into(), v); }
                row.insert("LevelName".into(), level_name(level.as_deref()));
                if let Some(v) = level { row.insert("Level".into(), v); }
                if let Some(v) = cell(get(sys, &["Provider", "#attributes", "Name"])) { row.insert("Provider".into(), v); }
                if let Some(v) = cell(sys.get("Computer")) { row.insert("Computer".into(), v); }
                let erid = cell(sys.get("EventRecordID"));
                if let Some(v) = &erid { row.insert("EventRecordID".into(), v.clone()); }
                if let Some(v) = cell(get(sys, &["Execution", "#attributes", "ProcessID"])) { row.insert("ProcessID".into(), v); }
                if let Some(v) = cell(get(sys, &["Execution", "#attributes", "ThreadID"])) { row.insert("ThreadID".into(), v); }
                if let Some(v) = cell(get(sys, &["Security", "#attributes", "UserID"])) { row.insert("UserID".into(), v); }
                row.insert("EventData".into(), match payload { Some(p) => py_json(p), None => String::new() });
                row.insert("_status".into(), "ok".into());
                row.insert("_error".into(), String::new());
                row.insert("_record_key".into(), format!("{}::{}", fname, erid.unwrap_or_default()));
                row.insert("_source_file".into(), src.clone());
                writer.push(row)?;
            }
        }
    }
    writer.finish()
}
