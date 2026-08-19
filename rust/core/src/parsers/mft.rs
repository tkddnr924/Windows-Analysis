//! NTFS $MFT parser (via the `mft` crate), streaming. Two passes over the file:
//! pass 1 builds a lightweight entry->(name,parent) index for path resolution;
//! pass 2 re-reads each record, builds its row, and pushes it to a batched
//! SQLite writer. Memory stays bounded (index + one batch) regardless of record
//! count — the old approach held every row (~3 GB for ~1M records).
use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::MftAttributeContent;
use mft::MftParser;

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_kst_ft;

pub const MFT_TABLE: &str = "MFT_Records";
pub const MFT_FIELD_ORDER: &[&str] = &[
    "path", "file_name", "extension", "is_directory", "in_use", "file_size",
    "entry", "seq", "parent_entry",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "_source_file",
];

const ROOT_ENTRY: u64 = 5;

/// Best $FILE_NAME (Python namespace priority) + the $STANDARD_INFORMATION
/// timestamps, in a single attribute pass.
fn extract(entry: &mft::MftEntry) -> (Option<FileNameAttr>, Option<[String; 4]>) {
    let mut si: Option<[String; 4]> = None;
    let mut best: Option<FileNameAttr> = None;
    let mut best_prio: i32 = -1;
    for attr in entry.iter_attributes().filter_map(|a| a.ok()) {
        match attr.data {
            MftAttributeContent::AttrX10(s) => {
                si = Some([
                    fmt_kst_ft(s.created), fmt_kst_ft(s.modified),
                    fmt_kst_ft(s.mft_modified), fmt_kst_ft(s.accessed),
                ]);
            }
            MftAttributeContent::AttrX30(f) => {
                let prio = match f.namespace {
                    FileNamespace::Win32 | FileNamespace::Win32AndDos => 3,
                    FileNamespace::POSIX => 2,
                    FileNamespace::DOS => 1,
                };
                if prio > best_prio { best_prio = prio; best = Some(f); }
            }
            _ => {}
        }
    }
    (best, si)
}

/// Resolve a full path from parent references (memoized; identical algorithm to
/// the Python parser). `index`: entry -> (name, parent).
fn resolve(entry: u64, index: &HashMap<u64, (String, u64)>, cache: &mut HashMap<u64, String>, guard: &mut HashSet<u64>) -> String {
    if let Some(p) = cache.get(&entry) { return p.clone(); }
    let node = match index.get(&entry) { Some(n) => n, None => return "\\$Orphan".to_string() };
    if guard.contains(&entry) { return "\\$Orphan".to_string(); }
    guard.insert(entry);
    let (name, parent) = node;
    let base = if *parent == entry { "\\$Orphan".to_string() } else { resolve(*parent, index, cache, guard) };
    let full = if name.is_empty() { base } else { format!("{}\\{}", base, name) };
    cache.insert(entry, full.clone());
    full
}

pub fn parse_mft_stream(mft_path: &Path, out: &Path) -> Result<usize> {
    // pass 1: entry -> (name, parent) index for path resolution.
    let mut index: HashMap<u64, (String, u64)> = HashMap::new();
    {
        let mut parser = MftParser::from_path(mft_path)?;
        for entry in parser.iter_entries() {
            let entry = match entry { Ok(e) => e, Err(_) => continue };
            if let (Some(f), _) = extract(&entry) {
                index.insert(entry.header.record_number, (f.name.clone(), f.parent.entry));
            }
        }
    }

    let mut cache: HashMap<u64, String> = HashMap::new();
    cache.insert(ROOT_ENTRY, String::new());
    let src = mft_path.to_string_lossy().to_string();
    let mut writer = StreamWriter::create(out, MFT_TABLE, MFT_FIELD_ORDER, MFT_FIELD_ORDER)?;

    // pass 2: build + stream each row.
    let mut parser = MftParser::from_path(mft_path)?;
    for entry in parser.iter_entries() {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let hdr = &entry.header;
        let in_use = hdr.flags.bits() & 0x01 != 0;
        let is_dir = hdr.flags.bits() & 0x02 != 0;
        let (best, si) = extract(&entry);
        if best.is_none() && si.is_none() { continue; }

        let (name, parent, size, fn_t) = match &best {
            Some(f) => (f.name.clone(), f.parent.entry, f.physical_size, [
                fmt_kst_ft(f.created), fmt_kst_ft(f.modified), fmt_kst_ft(f.mft_modified), fmt_kst_ft(f.accessed),
            ]),
            None => (String::new(), u64::MAX, 0, [String::new(), String::new(), String::new(), String::new()]),
        };

        let e = hdr.record_number;
        let path = if e == ROOT_ENTRY || name == "." {
            "\\".to_string()
        } else {
            let mut guard = HashSet::new();
            let parent_path = resolve(parent, &index, &mut cache, &mut guard);
            let p = if name.is_empty() { parent_path } else { format!("{}\\{}", parent_path, name) };
            if p.is_empty() { "\\".to_string() } else { p }
        };

        let ext = if !is_dir {
            match name.rfind('.') { Some(d) if d > 0 => name[d + 1..].to_lowercase(), _ => String::new() }
        } else { String::new() };

        let si = si.unwrap_or([String::new(), String::new(), String::new(), String::new()]);
        let mut row = Row::new();
        row.insert("path".into(), path);
        row.insert("file_name".into(), name);
        row.insert("extension".into(), ext);
        row.insert("is_directory".into(), if is_dir { "Y" } else { "N" }.into());
        row.insert("in_use".into(), if in_use { "Y" } else { "N" }.into());
        row.insert("file_size".into(), if is_dir { "0".into() } else { size.to_string() });
        row.insert("entry".into(), e.to_string());
        row.insert("seq".into(), hdr.sequence.to_string());
        row.insert("parent_entry".into(), if parent == u64::MAX { "-1".into() } else { parent.to_string() });
        row.insert("si_created".into(), si[0].clone());
        row.insert("si_modified".into(), si[1].clone());
        row.insert("si_mft_modified".into(), si[2].clone());
        row.insert("si_accessed".into(), si[3].clone());
        row.insert("fn_created".into(), fn_t[0].clone());
        row.insert("fn_modified".into(), fn_t[1].clone());
        row.insert("fn_mft_modified".into(), fn_t[2].clone());
        row.insert("fn_accessed".into(), fn_t[3].clone());
        row.insert("_source_file".into(), src.clone());
        writer.push(row)?;
    }
    writer.finish()
}
