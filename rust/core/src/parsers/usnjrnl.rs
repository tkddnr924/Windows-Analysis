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
        // 파일명 범위는 파일 끝이 아니라 "이 레코드"의 경계로 검증한다 —
        // 조작된 오프셋/길이가 다음 레코드나 슬랙 바이트를 이름으로 읽으면
        // 실제 USN·MFT 참조에 존재하지 않는 파일명을 결합한 허위 행이 되므로,
        // 위반 레코드는 통째로 손상으로 격리하고 다음 정렬 위치로 진행한다.
        let fixed_end = (hdr - pos) + 36;
        let Some(name_end) = name_off.checked_add(name_len) else {
            pos += advance;
            continue;
        };
        if name_len > 0 && (name_off < fixed_end || !name_len.is_multiple_of(2)) {
            pos += advance;
            continue;
        }
        if name_end > reclen {
            pos += advance;
            continue;
        }
        let name = {
            let start = pos + name_off;
            let end = pos + name_end;
            let u16s: Vec<u16> = data[start..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// V2 레코드: 60바이트 고정 헤더 + UTF-16LE 파일명. 이름 오프셋·길이는
    /// 인자로 조작할 수 있게 해 손상 케이스를 만든다.
    fn usn_v2(reclen: u32, usn: u64, name: &str, name_off: u16, name_len: u16) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = vec![0u8; 60];
        b[0..4].copy_from_slice(&reclen.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[24..32].copy_from_slice(&usn.to_le_bytes());
        b[56..58].copy_from_slice(&name_len.to_le_bytes());
        b[58..60].copy_from_slice(&name_off.to_le_bytes());
        b.extend(name_bytes);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        b
    }

    #[test]
    fn name_range_is_bounded_to_its_own_record() {
        let root = std::env::temp_dir().join(format!(
            "wina-usn-bounds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        // 레코드 A: reclen=60인데 이름 범위가 [60,76) — 자기 레코드 경계를
        // 넘어 다음 레코드(B)의 파일명 바이트를 가리키는 조작 케이스.
        // 레코드 B: 정상 (이름 "evil.exe" 포함, reclen=76).
        let mut data = usn_v2(60, 111, "", 60, 16);
        data.extend(usn_v2(76, 222, "evil.exe", 60, 16));
        let src = root.join("J");
        std::fs::write(&src, &data).unwrap();
        let out = root.join("usn.sqlite");
        let count = parse_usn_stream(&src, &out).unwrap();
        assert_eq!(count, 1, "경계를 넘는 레코드 A는 손상으로 격리되어야 한다");
        let conn = rusqlite::Connection::open(&out).unwrap();
        let (usn, name): (String, String) = conn
            .query_row(
                &format!("SELECT usn, filename FROM \"{}\"", USN_TABLE),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(usn, "222");
        assert_eq!(name, "evil.exe");
        let _ = std::fs::remove_dir_all(root);
    }
}
