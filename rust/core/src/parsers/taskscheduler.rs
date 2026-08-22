//! Task Scheduler per-task XML parser. Files have no extension and arbitrary
//! names; they're located by the task XML namespace in their content (like the
//! Python parser). One row per task, mirroring the Python field extraction.
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use rayon::prelude::*;
use walkdir::WalkDir;

use crate::sqlite::Row;
use crate::time::kst_offset;

pub const TASK_TABLE: &str = "TaskScheduler_Tasks";
pub const TASK_NAMESPACE: &str = "schemas.microsoft.com/windows/2004/02/mit/task";
pub const TASK_FIELD_ORDER: &[&str] = &[
    "timestamp", "task_name", "enabled", "hidden", "run_as", "run_level",
    "actions", "trigger_types", "trigger_start", "author", "description",
    "logon_type", "uri", "_source_file",
];

/// format_timestamp(value, source_tz=KST): honour an embedded offset/Z, else
/// assume KST; output KST "YYYY-MM-DD HH:MM:SS.fff". Empty in -> empty out.
fn fmt_task_time(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let kst = kst_offset();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.with_timezone(&kst).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            let dt: DateTime<FixedOffset> = kst.from_local_datetime(&ndt).single().unwrap_or_else(|| DateTime::from_naive_utc_and_offset(ndt, kst));
            return dt.with_timezone(&kst).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        }
    }
    s.to_string() // unparseable -> str(value), like Python
}

fn leaf(uri: &str) -> String {
    uri.trim_end_matches('\\').rsplit('\\').next().unwrap_or("").to_string()
}

// First descendant (document order, self included) with this local tag name.
fn find<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.descendants().find(|n| n.is_element() && n.tag_name().name() == name)
}
fn text(node: roxmltree::Node, name: &str) -> String {
    find(node, name).and_then(|n| n.text()).unwrap_or("").trim().to_string()
}

/// Decode a task file to a UTF-8 string (task XML is usually UTF-16LE w/ BOM).
fn read_text(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let u: Vec<u16> = raw[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let u: Vec<u16> = raw[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        let s = String::from_utf8_lossy(raw);
        s.strip_prefix('\u{feff}').map(|x| x.to_string()).unwrap_or_else(|| s.into_owned())
    }
}

fn parse_task(path: &Path) -> Result<Row> {
    let raw = std::fs::read(path)?;
    let mut content = read_text(&raw);
    // roxmltree takes UTF-8; drop an `encoding="UTF-16"` XML declaration so it
    // doesn't reject the (now UTF-8) string.
    if content.starts_with("<?xml") {
        if let Some(end) = content.find("?>") {
            content.replace_range(..end + 2, "");
        }
    }
    let content = content.trim_start();
    let doc = roxmltree::Document::parse(content)?;
    let root = doc.root_element();

    let reg = find(root, "RegistrationInfo");
    let settings = find(root, "Settings");
    let principals = find(root, "Principals");
    let actions_el = find(root, "Actions");
    let triggers_el = find(root, "Triggers");

    let uri = reg.map(|r| text(r, "URI")).unwrap_or_default();
    let date = reg.map(|r| text(r, "Date")).unwrap_or_default();
    let author = reg.map(|r| text(r, "Author")).unwrap_or_default();
    let description = reg.map(|r| text(r, "Description")).unwrap_or_default();
    let enabled = settings.map(|s| text(s, "Enabled")).unwrap_or_default();
    let hidden = settings.map(|s| text(s, "Hidden")).unwrap_or_default();

    let (mut run_as, mut run_level, mut logon_type) = (String::new(), String::new(), String::new());
    if let Some(pr) = principals.and_then(|p| find(p, "Principal")) {
        run_as = { let u = text(pr, "UserId"); if u.is_empty() { text(pr, "GroupId") } else { u } };
        run_level = text(pr, "RunLevel");
        logon_type = text(pr, "LogonType");
    }

    let mut action_parts: Vec<String> = Vec::new();
    if let Some(ae) = actions_el {
        for act in ae.children().filter(|c| c.is_element()) {
            match act.tag_name().name() {
                "Exec" => {
                    let cmd = text(act, "Command");
                    let args = text(act, "Arguments");
                    action_parts.push(format!("{} {}", cmd, args).trim().to_string());
                }
                "ComHandler" => action_parts.push(format!("COM:{}", text(act, "ClassId"))),
                other if !other.is_empty() => action_parts.push(other.to_string()),
                _ => {}
            }
        }
    }

    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    if let Some(te) = triggers_el {
        for trig in te.children().filter(|c| c.is_element()) {
            trigger_types.push(trig.tag_name().name().to_string());
            if trigger_start.is_empty() {
                let sb = text(trig, "StartBoundary");
                if !sb.is_empty() { trigger_start = sb; }
            }
        }
    }

    let task_name = { let l = leaf(&uri); if l.is_empty() { path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default() } else { l } };

    let mut row = Row::new();
    row.insert("timestamp".into(), fmt_task_time(&date));
    row.insert("task_name".into(), task_name);
    row.insert("enabled".into(), enabled);
    row.insert("hidden".into(), hidden);
    row.insert("run_as".into(), run_as);
    row.insert("run_level".into(), run_level);
    row.insert("actions".into(), action_parts.iter().filter(|p| !p.is_empty()).cloned().collect::<Vec<_>>().join(" | "));
    row.insert("trigger_types".into(), trigger_types.join(", "));
    row.insert("trigger_start".into(), fmt_task_time(&trigger_start));
    row.insert("author".into(), author);
    row.insert("description".into(), description);
    row.insert("logon_type".into(), logon_type);
    row.insert("uri".into(), uri);
    row.insert("_source_file".into(), path.to_string_lossy().to_string());
    Ok(row)
}

/// Walk `root`, parse every file whose content carries the task XML namespace.
pub fn parse_tasks(root: &Path) -> Result<Vec<Row>> {
    let paths: Vec<_> = WalkDir::new(root).into_iter().filter_map(|e| e.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect();
    let utf8 = TASK_NAMESPACE.as_bytes().to_vec();
    let utf16: Vec<u8> = TASK_NAMESPACE.bytes().flat_map(|b| [b, 0]).collect();
    Ok(paths.par_iter().filter_map(|path| {
        // Read only the first 4 KB to test for the task namespace — never the
        // whole file. A target can hold huge unrelated files (images, dumps);
        // slurping each one just to check its header made discovery crawl.
        let mut head = Vec::new();
        match std::fs::File::open(path) {
            Ok(f) => {
                use std::io::Read;
                if std::io::Read::take(f, 4096).read_to_end(&mut head).is_err() { return None; }
            }
            Err(_) => return None,
        }
        let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
        if !(has(&utf8) || has(&utf16)) { return None; }
        match parse_task(path) {
            Ok(r) => Some(r),
            Err(e) => {
                let mut row = Row::new();
                row.insert("timestamp".into(), String::new());
                row.insert("task_name".into(), path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
                row.insert("_source_file".into(), path.to_string_lossy().to_string());
                row.insert("_status".into(), "unreadable_file".into());
                row.insert("_error".into(), e.to_string());
                Some(row)
            }
        }
    }).collect())
}
