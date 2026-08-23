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
    "path",
    "file_name",
    "extension",
    "is_directory",
    "in_use",
    "file_size",
    "entry",
    "seq",
    "parent_entry",
    "si_created",
    "si_modified",
    "si_mft_modified",
    "si_accessed",
    "owner_id",
    "security_id",
    "fn_created",
    "fn_modified",
    "fn_mft_modified",
    "fn_accessed",
    "_source_file",
];

const ROOT_ENTRY: u64 = 5;

/// Best $FILE_NAME (Python namespace priority), the $STANDARD_INFORMATION
/// timestamps, and the real data size, in a single attribute pass.
///
/// The size comes from the unnamed $DATA (0x80) attribute — non-resident:
/// its `file_size`; resident (small files stored inline): its `data_size`.
/// The $FILE_NAME size fields are NOT authoritative: NTFS only refreshes them
/// when the filename attribute itself is rewritten, so for most files they sit
/// at 0 (or a stale value) even though the file has data. Reading them was why
/// real files showed as 0 bytes. Named $DATA streams are alternate data streams
/// and are skipped, so the size stays the file's own.
struct StandardInfo {
    timestamps: [String; 4],
    owner_id: u32,
    security_id: u32,
}

fn extract(entry: &mft::MftEntry) -> (Option<FileNameAttr>, Option<StandardInfo>, Option<u64>) {
    use mft::attribute::header::ResidentialHeader;
    use mft::attribute::MftAttributeType;

    let mut si: Option<StandardInfo> = None;
    let mut best: Option<FileNameAttr> = None;
    let mut best_prio: i32 = -1;
    let mut data_size: Option<u64> = None;

    for attr in entry.iter_attributes().filter_map(|a| a.ok()) {
        if attr.header.type_code == MftAttributeType::DATA && attr.header.name.is_empty() {
            match &attr.header.residential_header {
                ResidentialHeader::NonResident(nr) => data_size = Some(nr.file_size),
                ResidentialHeader::Resident(r) => data_size = Some(r.data_size as u64),
            }
        }
        match attr.data {
            MftAttributeContent::AttrX10(s) => {
                si = Some(StandardInfo {
                    timestamps: [
                        fmt_kst_ft(s.created),
                        fmt_kst_ft(s.modified),
                        fmt_kst_ft(s.mft_modified),
                        fmt_kst_ft(s.accessed),
                    ],
                    owner_id: s.owner_id,
                    security_id: s.security_id,
                });
            }
            MftAttributeContent::AttrX30(f) => {
                let prio = match f.namespace {
                    FileNamespace::Win32 | FileNamespace::Win32AndDos => 3,
                    FileNamespace::POSIX => 2,
                    FileNamespace::DOS => 1,
                };
                if prio > best_prio {
                    best_prio = prio;
                    best = Some(f);
                }
            }
            _ => {}
        }
    }
    (best, si, data_size)
}

/// Resolve a full path from parent references (memoized; identical algorithm to
/// the Python parser). `index`: entry -> (name, parent).
fn resolve(
    entry: u64,
    index: &HashMap<u64, (String, u64)>,
    cache: &mut HashMap<u64, String>,
    guard: &mut HashSet<u64>,
) -> String {
    if let Some(p) = cache.get(&entry) {
        return p.clone();
    }
    let node = match index.get(&entry) {
        Some(n) => n,
        None => return "\\$Orphan".to_string(),
    };
    if guard.contains(&entry) {
        return "\\$Orphan".to_string();
    }
    guard.insert(entry);
    let (name, parent) = node;
    let base = if *parent == entry {
        "\\$Orphan".to_string()
    } else {
        resolve(*parent, index, cache, guard)
    };
    let full = if name.is_empty() {
        base
    } else {
        format!("{}\\{}", base, name)
    };
    cache.insert(entry, full.clone());
    full
}

pub fn parse_mft_stream(mft_path: &Path, out: &Path) -> Result<usize> {
    // pass 1: entry -> (name, parent) index for path resolution.
    let mut index: HashMap<u64, (String, u64)> = HashMap::new();
    {
        let mut parser = MftParser::from_path(mft_path)?;
        for entry in parser.iter_entries() {
            if crate::pipeline::cancelled() {
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let (Some(f), _, _) = extract(&entry) {
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
        if crate::pipeline::cancelled() {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let hdr = &entry.header;
        let in_use = hdr.flags.bits() & 0x01 != 0;
        let is_dir = hdr.flags.bits() & 0x02 != 0;
        let (best, si, data_size) = extract(&entry);
        if best.is_none() && si.is_none() {
            continue;
        }

        let (name, parent, fn_size, fn_t) = match &best {
            Some(f) => (
                f.name.clone(),
                f.parent.entry,
                f.physical_size,
                [
                    fmt_kst_ft(f.created),
                    fmt_kst_ft(f.modified),
                    fmt_kst_ft(f.mft_modified),
                    fmt_kst_ft(f.accessed),
                ],
            ),
            None => (
                String::new(),
                u64::MAX,
                0,
                [String::new(), String::new(), String::new(), String::new()],
            ),
        };
        // $DATA is authoritative; fall back to $FILE_NAME only when there's no
        // $DATA attribute at all (e.g. a directory, or a record whose data
        // attribute lives in an extension record).
        let size = data_size.unwrap_or(fn_size);

        let e = hdr.record_number;
        let path = if e == ROOT_ENTRY || name == "." {
            "\\".to_string()
        } else {
            let mut guard = HashSet::new();
            let parent_path = resolve(parent, &index, &mut cache, &mut guard);
            let p = if name.is_empty() {
                parent_path
            } else {
                format!("{}\\{}", parent_path, name)
            };
            if p.is_empty() {
                "\\".to_string()
            } else {
                p
            }
        };

        let ext = if !is_dir {
            match name.rfind('.') {
                Some(d) if d > 0 => name[d + 1..].to_lowercase(),
                _ => String::new(),
            }
        } else {
            String::new()
        };

        let (si_times, owner_id, security_id) = match si {
            Some(info) => (info.timestamps, Some(info.owner_id), Some(info.security_id)),
            None => (
                [String::new(), String::new(), String::new(), String::new()],
                None,
                None,
            ),
        };
        let mut row = Row::new();
        row.insert("path".into(), path);
        row.insert("file_name".into(), name);
        row.insert("extension".into(), ext);
        row.insert("is_directory".into(), if is_dir { "Y" } else { "N" }.into());
        row.insert("in_use".into(), if in_use { "Y" } else { "N" }.into());
        row.insert(
            "file_size".into(),
            if is_dir { "0".into() } else { size.to_string() },
        );
        row.insert("entry".into(), e.to_string());
        row.insert("seq".into(), hdr.sequence.to_string());
        row.insert(
            "parent_entry".into(),
            if parent == u64::MAX {
                "-1".into()
            } else {
                parent.to_string()
            },
        );
        row.insert("si_created".into(), si_times[0].clone());
        row.insert("si_modified".into(), si_times[1].clone());
        row.insert("si_mft_modified".into(), si_times[2].clone());
        row.insert("si_accessed".into(), si_times[3].clone());
        // NTFS $STANDARD_INFORMATION owner/security IDs are numeric metadata,
        // not account names. Preserve them verbatim; do not resolve them to a
        // SID or a user account here.
        row.insert(
            "owner_id".into(),
            owner_id.map_or_else(String::new, |value| value.to_string()),
        );
        row.insert(
            "security_id".into(),
            security_id.map_or_else(String::new, |value| value.to_string()),
        );
        row.insert("fn_created".into(), fn_t[0].clone());
        row.insert("fn_modified".into(), fn_t[1].clone());
        row.insert("fn_mft_modified".into(), fn_t[2].clone());
        row.insert("fn_accessed".into(), fn_t[3].clone());
        row.insert("_source_file".into(), src.clone());
        writer.push(row)?;
    }
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::MFT_FIELD_ORDER;

    #[test]
    fn standard_information_ids_are_persisted_in_mft_schema() {
        assert!(MFT_FIELD_ORDER.contains(&"owner_id"));
        assert!(MFT_FIELD_ORDER.contains(&"security_id"));
    }
}
