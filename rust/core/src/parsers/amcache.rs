//! Amcache.hve parser. Amcache is a registry hive, so it reuses notatin.
//! Emits Amcache_Programs (Root\InventoryApplication / legacy Root\Programs)
//! and Amcache_Files (Root\InventoryApplicationFile / legacy Root\File).
//! Files use the same snake_case column names + sha1/file_id handling as the
//! Python parser (regipy's AmCachePlugin) so it feeds the execution-history
//! overview identically.
use std::path::Path;

use anyhow::Result;
use notatin::cell_value::CellValue;
use notatin::parser::ParserIterator;
use notatin::parser_builder::ParserBuilder;
use crate::parsers::registry::sibling_logs;

use crate::sqlite::Row;
use crate::time::fmt_kst;

pub const PROGRAMS_TABLE: &str = "Amcache_Programs";
pub const FILES_TABLE: &str = "Amcache_Files";
pub const PROGRAMS_FIELD_ORDER: &[&str] = &[
    "timestamp", "InstallDate", "MsiInstallDate", "Name", "Version", "Publisher",
    "ProgramId", "ProgramInstanceId", "Source", "RootDirPath", "UninstallString", "_recovery", "_source_file",
];
pub const FILES_FIELD_ORDER: &[&str] = &[
    "timestamp", "link_date", "name", "lower_case_long_path", "original_file_name",
    "publisher", "product_name", "version", "product_version", "bin_file_version",
    "bin_product_version", "size", "SHA1", "program_id", "file_id", "binary_type", "language", "_recovery", "_source_file",
];

// Legacy Win8 \Root\Programs numeric value-name mapping (high-confidence subset).
fn map_legacy_program(name: &str) -> &str {
    match name {
        "0" => "Name",
        "1" => "Version",
        "2" => "Publisher",
        "3" => "Language",
        other => other,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}
fn render(cv: &CellValue) -> String {
    match cv {
        CellValue::String(s) => s.trim_end_matches('\u{0}').to_string(),
        CellValue::Binary(b) => hex_lower(b),
        CellValue::MultiString(v) => v.join(","),
        CellValue::U32(v) => v.to_string(),
        CellValue::I32(v) => v.to_string(),
        CellValue::U64(v) => v.to_string(),
        CellValue::I64(v) => v.to_string(),
        _ => String::new(),
    }
}

/// inflection.underscore — CamelCase -> snake_case (matches regipy's plugin).
fn underscore(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::new();
    for i in 0..ch.len() {
        let c = ch[i];
        if i > 0 && c.is_ascii_uppercase() {
            let prev = ch[i - 1];
            let next_lower = ch.get(i + 1).map_or(false, |n| n.is_ascii_lowercase());
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() || (prev.is_ascii_uppercase() && next_lower) {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out.replace('-', "_")
}

/// Path segments after the hive's "\...\Root\" prefix, or None.
fn after_root(path: &str) -> Option<Vec<&str>> {
    let low = path.to_ascii_lowercase();
    let idx = low.find("\\root\\")?;
    Some(path[idx + 6..].split('\\').collect())
}

fn recovery_label(key: &notatin::cell_key_node::CellKeyNode) -> String {
    if key.cell_state.is_deleted() { format!("{:?}", key.cell_state) } else { "live".to_string() }
}

pub fn parse_amcache(hive: &Path) -> Result<(Vec<Row>, Vec<Row>)> {
    let source = hive.to_string_lossy().to_string();
    let mut builder = ParserBuilder::from_path(hive.to_path_buf());
    for log in sibling_logs(hive) { builder.with_transaction_log(log); }
    builder.recover_deleted(true);
    let parser = builder.build()?;
    let mut programs: Vec<Row> = Vec::new();
    let mut files: Vec<Row> = Vec::new();

    for key in ParserIterator::new(&parser) {
        let segs = match after_root(&key.path) { Some(s) => s, None => continue };
        let ts = fmt_kst(key.last_key_written_date_and_time());

        // programs: Root\InventoryApplication\<id> (modern) or Root\Programs\<id> (legacy)
        let is_prog_modern = segs.len() == 2 && segs[0] == "InventoryApplication";
        let is_prog_legacy = segs.len() == 2 && segs[0] == "Programs";
        // files: Root\InventoryApplicationFile\<id> (modern) or Root\File\<vol>\<fileid> (legacy)
        let is_file_modern = segs.len() == 2 && segs[0] == "InventoryApplicationFile";
        let is_file_legacy = segs.len() == 3 && segs[0] == "File";

        if is_prog_modern || is_prog_legacy {
            let mut row = Row::new();
            for v in key.value_iter() {
                let (cv, _) = v.get_content();
                let name = v.get_pretty_name();
                let name = if is_prog_legacy { map_legacy_program(&name).to_string() } else { name };
                row.insert(name, render(&cv));
            }
            row.insert("timestamp".into(), ts);
            row.insert("_recovery".into(), recovery_label(&key));
            row.insert("_source_file".into(), source.clone());
            programs.push(row);
        } else if is_file_modern || is_file_legacy {
            let mut row = Row::new();
            for v in key.value_iter() {
                let (cv, _) = v.get_content();
                row.insert(underscore(&v.get_pretty_name()), render(&cv));
            }
            // regipy AmCachePlugin post-processing: strip the 4-char prefix on
            // file_id / program_id, derive sha1 from file_id, size hex->int.
            if let Some(fid) = row.get("file_id").cloned() {
                if fid != "0" && fid.len() > 4 {
                    let stripped = fid[4..].to_string();
                    row.insert("file_id".into(), stripped.clone());
                    row.entry("sha1".into()).or_insert(stripped);
                }
            }
            if let Some(sha) = row.get("sha1").cloned() {
                let s = if sha.len() > 4 && row.get("file_id").map_or(true, |f| *f != sha) { sha[4..].to_string() } else { sha };
                row.insert("sha1".into(), s);
            }
            if let Some(pid) = row.get("program_id").cloned() {
                if pid.len() > 4 { row.insert("program_id".into(), pid[4..].to_string()); }
            }
            if let Some(sz) = row.get("size").cloned() {
                if let Ok(n) = i64::from_str_radix(sz.trim_start_matches("0x"), 16) { row.insert("size".into(), n.to_string()); }
            }
            // rename sha1 -> SHA1 (Python column name)
            if let Some(s) = row.remove("sha1") { row.insert("SHA1".into(), s); }
            row.insert("timestamp".into(), ts);
            row.insert("_recovery".into(), recovery_label(&key));
            row.insert("_source_file".into(), source.clone());
            files.push(row);
        }
    }
    Ok((programs, files))
}
