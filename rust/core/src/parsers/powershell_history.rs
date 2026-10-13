//! Preserve PSReadLine physical lines, including continuation markers and blanks.
//! Derived generation reconstructs commands while retaining every source line.
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::sqlite::Row;

pub const PS_TABLE: &str = "PowerShell_ConsoleHistory";
pub const PS_FIELD_ORDER: &[&str] = &["line_number", "command", "user", "_source_file"];

const SKIP: &[&str] = &[
    "psreadline",
    "powershell",
    "windows",
    "microsoft",
    "roaming",
    "appdata",
    "local",
];

/// Best-effort account name: walk up the parents, skipping the known PSReadLine
/// path segments, and take the first remaining folder name.
fn user_from_path(path: &Path) -> String {
    for parent in path.ancestors().skip(1) {
        match parent.file_name() {
            Some(n) => {
                let name = n.to_string_lossy().to_string();
                if !SKIP.contains(&name.to_lowercase().as_str()) {
                    return name;
                }
            }
            None => break, // reached the root (no file name component)
        }
    }
    String::new()
}

/// Match Python `str.splitlines()` for the common line boundaries (\r\n, \r,
/// \n): split into lines without a spurious trailing empty from a final EOL.
fn splitlines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let norm = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut parts: Vec<&str> = norm.split('\n').collect();
    if norm.ends_with('\n') {
        parts.pop();
    }
    parts.into_iter().map(|s| s.to_string()).collect()
}

/// Parsed lines plus files that could not be read (path, reason).
pub struct ConsoleHistory {
    pub rows: Vec<Row>,
    pub unreadable: Vec<(PathBuf, String)>,
}

pub fn parse_console_history(paths: &[PathBuf]) -> Result<ConsoleHistory> {
    let mut rows = Vec::new();
    let mut unreadable = Vec::new();
    for path in paths {
        let source = path.to_string_lossy().to_string();
        let user = user_from_path(path);
        let text = match std::fs::read(path) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                unreadable.push((path.clone(), e.to_string()));
                continue;
            }
        };
        for (i, line) in splitlines(&text).into_iter().enumerate() {
            let mut r = Row::new();
            r.insert("line_number".into(), (i + 1).to_string());
            r.insert("command".into(), line);
            r.insert("user".into(), user.clone());
            r.insert("_source_file".into(), source.clone());
            rows.push(r);
        }
    }
    Ok(ConsoleHistory { rows, unreadable })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_file_is_reported_not_an_empty_row() {
        let missing = std::env::temp_dir().join("wina-ps-missing-dir/ConsoleHost_history.txt");
        let parsed = parse_console_history(std::slice::from_ref(&missing)).unwrap();
        assert!(parsed.rows.is_empty());
        assert_eq!(parsed.unreadable.len(), 1);
        assert_eq!(parsed.unreadable[0].0, missing);
    }
}
