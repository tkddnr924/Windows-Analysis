//! PowerShell console history — the PSReadLine `ConsoleHost_history.txt` file,
//! one typed command per line in execution order. No timestamps exist in the
//! file (PSReadLine stores only the command text), so order is the only
//! temporal signal, preserved as `line_number`. Port of
//! parsers/powershell_history_parser.py.
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::sqlite::Row;

pub const PS_TABLE: &str = "PowerShell_ConsoleHistory";
pub const PS_FIELD_ORDER: &[&str] = &["line_number", "command", "user", "_source_file"];

const SKIP: &[&str] = &["psreadline", "powershell", "windows", "microsoft", "roaming", "appdata", "local"];

/// Best-effort account name: walk up the parents, skipping the known PSReadLine
/// path segments, and take the first remaining folder name.
fn user_from_path(path: &Path) -> String {
    for parent in path.ancestors().skip(1) {
        match parent.file_name() {
            Some(n) => {
                let name = n.to_string_lossy().to_string();
                if !SKIP.contains(&name.to_lowercase().as_str()) { return name; }
            }
            None => break, // reached the root (no file name component)
        }
    }
    String::new()
}

/// Match Python `str.splitlines()` for the common line boundaries (\r\n, \r,
/// \n): split into lines without a spurious trailing empty from a final EOL.
fn splitlines(text: &str) -> Vec<String> {
    if text.is_empty() { return Vec::new(); }
    let norm = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut parts: Vec<&str> = norm.split('\n').collect();
    if norm.ends_with('\n') { parts.pop(); }
    parts.into_iter().map(|s| s.to_string()).collect()
}

pub fn parse_console_history(paths: &[PathBuf]) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for path in paths {
        let source = path.to_string_lossy().to_string();
        let user = user_from_path(path);
        let text = match std::fs::read(path) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                let mut r = Row::new();
                r.insert("line_number".into(), String::new());
                r.insert("command".into(), String::new());
                r.insert("user".into(), user.clone());
                r.insert("_source_file".into(), source.clone());
                r.insert("_status".into(), "unreadable_file".into());
                r.insert("_error".into(), e.to_string());
                rows.push(r);
                continue;
            }
        };
        for (i, line) in splitlines(&text).into_iter().enumerate() {
            if line.is_empty() { continue; }
            let mut r = Row::new();
            r.insert("line_number".into(), (i + 1).to_string());
            r.insert("command".into(), line);
            r.insert("user".into(), user.clone());
            r.insert("_source_file".into(), source.clone());
            rows.push(r);
        }
    }
    Ok(rows)
}
