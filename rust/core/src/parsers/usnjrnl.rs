//! USN Change Journal ($UsnJrnl:$J) parser — one row per USN record. Manual
//! struct parsing (USN_RECORD_V2 64-bit refs / V3 128-bit refs), mirroring the
//! Python parser byte-for-byte, including exact FILETIME rounding.
use std::path::Path;

use anyhow::Result;

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_filetime;

pub const USN_TABLE: &str = "UsnJrnl_Records";
pub const USN_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "filename",
    "reason",
    "file_attributes",
    "mft_entry",
    "parent_mft_entry",
    "usn",
    "source_info",
    "security_id",
    "file_reference",
    "parent_file_reference",
    "_source_file",
];

const REASON_FLAGS: &[(u32, &str)] = &[
    (0x1, "DATA_OVERWRITE"),
    (0x2, "DATA_EXTEND"),
    (0x4, "DATA_TRUNCATION"),
    (0x10, "NAMED_DATA_OVERWRITE"),
    (0x20, "NAMED_DATA_EXTEND"),
    (0x40, "NAMED_DATA_TRUNCATION"),
    (0x100, "FILE_CREATE"),
    (0x200, "FILE_DELETE"),
    (0x400, "EA_CHANGE"),
    (0x800, "SECURITY_CHANGE"),
    (0x1000, "RENAME_OLD_NAME"),
    (0x2000, "RENAME_NEW_NAME"),
    (0x4000, "INDEXABLE_CHANGE"),
    (0x8000, "BASIC_INFO_CHANGE"),
    (0x10000, "HARD_LINK_CHANGE"),
    (0x20000, "COMPRESSION_CHANGE"),
    (0x40000, "ENCRYPTION_CHANGE"),
    (0x80000, "OBJECT_ID_CHANGE"),
    (0x100000, "REPARSE_POINT_CHANGE"),
    (0x200000, "STREAM_CHANGE"),
    (0x400000, "TRANSACTED_CHANGE"),
    (0x800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
];
const ATTR_FLAGS: &[(u32, &str)] = &[
    (0x1, "READONLY"),
    (0x2, "HIDDEN"),
    (0x4, "SYSTEM"),
    (0x10, "DIRECTORY"),
    (0x20, "ARCHIVE"),
    (0x80, "NORMAL"),
    (0x100, "TEMPORARY"),
    (0x200, "SPARSE_FILE"),
    (0x400, "REPARSE_POINT"),
    (0x800, "COMPRESSED"),
    (0x1000, "OFFLINE"),
    (0x4000, "ENCRYPTED"),
];
fn decode_flags(value: u32, table: &[(u32, &str)]) -> String {
    table
        .iter()
        .filter(|(b, _)| value & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join("|")
}

fn u16le(d: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([d[p], d[p + 1]])
}
fn u32le(d: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(d[p..p + 4].try_into().unwrap())
}
fn u64le(d: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(d[p..p + 8].try_into().unwrap())
}
fn u128le(d: &[u8], p: usize) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[p..p + 16]);
    u128::from_le_bytes(b)
}

pub fn parse_usn_stream(path: &Path, out: &Path) -> Result<usize> {
    let source = path.to_string_lossy().to_string();
    let data = std::fs::read(path)?;
    let n = data.len();
    let mut writer = StreamWriter::create(out, USN_TABLE, USN_FIELD_ORDER, USN_FIELD_ORDER)?;
    let mut pos = 0usize;
    while pos < n {
        if crate::pipeline::cancelled() {
            break;
        }
        if data[pos] == 0 {
            pos += 1;
            continue;
        }
        if pos + 4 > n {
            break;
        }
        let reclen = u32le(&data, pos) as usize;
        // A corrupt record length must not hide valid records that follow.
        // USN records are 8-byte aligned, so resynchronize conservatively.
        if reclen < 60 || reclen > n.saturating_sub(pos) {
            pos = (pos + 8).min(n);
            continue;
        }
        let major = u16le(&data, pos + 4);
        let advance = (reclen + 7) & !7;

        let (file_ref, parent_ref, hdr): (u128, u128, usize) = match major {
            2 => (
                u64le(&data, pos + 8) as u128,
                u64le(&data, pos + 16) as u128,
                pos + 24,
            ),
            3 => (u128le(&data, pos + 8), u128le(&data, pos + 24), pos + 40),
            _ => {
                pos += advance;
                continue;
            }
        };
        // <QQIIIIHH at hdr: usn, ts, reason, source_info, security_id, attrs, name_len, name_off
        if hdr > n || 40 > n.saturating_sub(hdr) {
            pos += advance.min(n - pos);
            continue;
        }
        let usn = u64le(&data, hdr);
        let ts = u64le(&data, hdr + 8) as i64;
        let reason = u32le(&data, hdr + 16);
        let source_info = u32le(&data, hdr + 20);
        let security_id = u32le(&data, hdr + 24);
        let attrs = u32le(&data, hdr + 28);
        let name_len = u16le(&data, hdr + 32) as usize;
        let name_off = u16le(&data, hdr + 34) as usize;
        let name = {
            let start = pos + name_off;
            let end = start + name_len;
            if end <= n {
                let u16s: Vec<u16> = data[start..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::new()
            }
        };

        let mut row = Row::new();
        row.insert("timestamp".into(), fmt_filetime(ts));
        row.insert("filename".into(), name);
        row.insert("reason".into(), decode_flags(reason, REASON_FLAGS));
        row.insert("file_attributes".into(), decode_flags(attrs, ATTR_FLAGS));
        row.insert(
            "mft_entry".into(),
            (file_ref & 0xFFFF_FFFF_FFFF).to_string(),
        );
        row.insert(
            "parent_mft_entry".into(),
            (parent_ref & 0xFFFF_FFFF_FFFF).to_string(),
        );
        row.insert("usn".into(), usn.to_string());
        row.insert("source_info".into(), source_info.to_string());
        row.insert("security_id".into(), security_id.to_string());
        row.insert("file_reference".into(), file_ref.to_string());
        row.insert("parent_file_reference".into(), parent_ref.to_string());
        row.insert("_source_file".into(), source.clone());
        writer.push(row)?;
        pos += advance;
    }
    writer.finish()
}
