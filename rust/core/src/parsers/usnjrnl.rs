//! USN Change Journal ($UsnJrnl:$J) parser — one row per USN record. Manual
//! struct parsing (USN_RECORD_V2 64-bit refs / V3 128-bit refs), mirroring the
//! Python parser byte-for-byte, including exact FILETIME rounding. Each row
//! also carries the record's absolute byte offset in its input file.
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
    "reason_mask",
    "record_version",
    "file_attributes_mask",
    "_source_file",
    // Absolute byte offset of this record header in the input file (decimal).
    "record_offset",
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
    use std::io::Read;
    let source = path.to_string_lossy().to_string();
    let mut writer = StreamWriter::create(out, USN_TABLE, USN_FIELD_ORDER, USN_FIELD_ORDER)?;
    let mut file = std::fs::File::open(path)?;
    // 수 GB짜리 $J를 통째로 메모리에 올리지 않는다 — 4 MiB 창을 굴리며
    // 레코드 단위로 해석하고, 창 끝에 걸린 레코드는 리필 후 이어서 본다.
    // 이름 오프셋·길이가 u16이라 유효 레코드는 128 KiB를 넘을 수 없다.
    const WINDOW: usize = 4 * 1024 * 1024;
    const MAX_RECLEN: usize = 128 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    // 리필용 읽기 버퍼는 한 번만 할당해 재사용한다 — 수 GB $J에서 리필마다
    // 4 MiB를 새로 할당·제로화하면 allocator 부하만 커진다.
    let mut chunk = vec![0u8; WINDOW];
    // Name decoding buffer, reused so each record costs no extra allocation.
    let mut name_units: Vec<u16> = Vec::new();
    let mut pos = 0usize;
    // Absolute file offset of buf[0]; grows by the bytes dropped on each drain.
    let mut base = 0u64;
    let mut eof = false;
    loop {
        if crate::pipeline::cancelled() {
            break;
        }
        if pos > buf.len() {
            pos = buf.len();
        }
        if !eof && buf.len() - pos < MAX_RECLEN {
            base += pos as u64;
            buf.drain(..pos);
            pos = 0;
            while buf.len() < WINDOW {
                let read = file.read(&mut chunk)?;
                if read == 0 {
                    eof = true;
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
            }
        }
        let data = buf.as_slice();
        let n = data.len();
        if pos >= n {
            if eof {
                break;
            }
            continue;
        }
        if pos + 4 > n {
            if eof {
                break;
            }
            continue;
        }
        let reclen = u32le(data, pos) as usize;
        // Skip padding and corrupt lengths without losing 8-byte alignment.
        if !(60..=MAX_RECLEN).contains(&reclen) {
            pos = (pos + 8).min(n);
            continue;
        }
        if reclen > n - pos {
            if eof {
                // 파일 끝에서 잘린 레코드 — 종전 동작대로 재동기화.
                pos = (pos + 8).min(n);
                continue;
            }
            // 창 끝에 걸린 레코드 — 리필 후 다시 본다.
            continue;
        }
        let major = u16le(data, pos + 4);
        let advance = (reclen + 7) & !7;

        let (file_ref, parent_ref, hdr): (u128, u128, usize) = match major {
            2 => (
                u64le(data, pos + 8) as u128,
                u64le(data, pos + 16) as u128,
                pos + 24,
            ),
            3 => (u128le(data, pos + 8), u128le(data, pos + 24), pos + 40),
            _ => {
                pos += advance;
                continue;
            }
        };
        // <QQIIIIHH at hdr: usn, ts, reason, source_info, security_id, attrs, name_len, name_off
        if 36 > reclen.saturating_sub(hdr - pos) {
            pos += advance.min(n - pos);
            continue;
        }
        let usn = u64le(data, hdr);
        let ts = u64le(data, hdr + 8) as i64;
        let reason = u32le(data, hdr + 16);
        let source_info = u32le(data, hdr + 20);
        let security_id = u32le(data, hdr + 24);
        let attrs = u32le(data, hdr + 28);
        let name_len = u16le(data, hdr + 32) as usize;
        let name_off = u16le(data, hdr + 34) as usize;
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
            name_units.clear();
            name_units.extend(
                data[start..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])),
            );
            String::from_utf16_lossy(&name_units)
        };

        let mut row = Row::new();
        row.insert("timestamp".into(), fmt_filetime(ts));
        row.insert("filename".into(), name);
        row.insert("reason".into(), decode_flags(reason, REASON_FLAGS));
        row.insert("file_attributes".into(), decode_flags(attrs, ATTR_FLAGS));
        row.insert("reason_mask".into(), reason.to_string());
        row.insert("record_version".into(), major.to_string());
        row.insert("file_attributes_mask".into(), attrs.to_string());
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
        row.insert("record_offset".into(), (base + pos as u64).to_string());
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
    fn zero_padding_preserves_following_record_alignment() {
        let root = std::env::temp_dir().join(format!("wina-usn-padding-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let long_name = "a".repeat(98);
        let mut data = vec![0; 16];
        data.extend(usn_v2(64, 111, "x", 60, 2));
        data.extend([0; 8]);
        data.extend(usn_v2(256, 222, &long_name, 60, 196));
        data.extend([0; 16]);
        let source = root.join("$J");
        let output = root.join("usn.sqlite");
        std::fs::write(&source, data).unwrap();
        assert_eq!(parse_usn_stream(&source, &output).unwrap(), 2);
        let db = rusqlite::Connection::open(&output).unwrap();
        let mut query = db.prepare("SELECT usn, filename FROM UsnJrnl_Records ORDER BY rowid").unwrap();
        let rows: Vec<(String, String)> = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![("111".into(), "x".into()), ("222".into(), long_name)]);
        drop(query);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn raw_reason_mask_preserves_unknown_flags_and_record_version() {
        let root = std::env::temp_dir().join(format!("wina-usn-mask-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut data = usn_v2(64, 999, "x", 60, 2);
        data[40..44].copy_from_slice(&0x01000001u32.to_le_bytes());
        data[52..56].copy_from_slice(&0x40000020u32.to_le_bytes());
        let source = root.join("$J");
        let output = root.join("usn.sqlite");
        std::fs::write(&source, data).unwrap();
        assert_eq!(parse_usn_stream(&source, &output).unwrap(), 1);
        let db = rusqlite::Connection::open(&output).unwrap();
        let actual: (String, String, String, String, String) = db.query_row(
            "SELECT reason, reason_mask, record_version, file_attributes, file_attributes_mask FROM UsnJrnl_Records", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
        assert_eq!(actual, ("DATA_OVERWRITE".into(), "16777217".into(), "2".into(), "ARCHIVE".into(), "1073741856".into()));
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zero_low_length_byte_is_not_padding_and_short_v3_is_rejected() {
        let root = std::env::temp_dir().join(format!("wina-usn-header-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let long_name = "a".repeat(98);
        let mut data = usn_v2(256, 111, &long_name, 60, 196);
        let mut short_v3 = usn_v2(60, 333, "", 0, 0);
        short_v3[4..6].copy_from_slice(&3u16.to_le_bytes());
        data.extend(short_v3);
        data.extend(usn_v2(64, 444, "x", 60, 2));
        let source = root.join("$J");
        let output = root.join("usn.sqlite");
        std::fs::write(&source, data).unwrap();
        assert_eq!(parse_usn_stream(&source, &output).unwrap(), 2);
        let db = rusqlite::Connection::open(&output).unwrap();
        let mut query = db.prepare("SELECT usn, filename FROM UsnJrnl_Records ORDER BY rowid").unwrap();
        let rows: Vec<(String, String)> = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![("111".into(), long_name), ("444".into(), "x".into())]);
        drop(query);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
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

    /// V3 record: 76-byte fixed header (128-bit references) + UTF-16LE name.
    fn usn_v3(usn: u64, file_ref: u128, parent_ref: u128, name: &str) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = vec![0u8; 76];
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[8..24].copy_from_slice(&file_ref.to_le_bytes());
        b[24..40].copy_from_slice(&parent_ref.to_le_bytes());
        b[40..48].copy_from_slice(&usn.to_le_bytes());
        b[72..74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        b[74..76].copy_from_slice(&76u16.to_le_bytes());
        b.extend(name_bytes);
        let reclen = b.len() as u32;
        b[0..4].copy_from_slice(&reclen.to_le_bytes());
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        b
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("wina-usn-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Parse `data` into a fresh DB and return (usn, record_offset) per row.
    fn offsets_of(root: &std::path::Path, name: &str, data: &[u8]) -> Vec<(String, String)> {
        let source = root.join(name);
        let output = root.join(format!("{name}.sqlite"));
        std::fs::write(&source, data).unwrap();
        parse_usn_stream(&source, &output).unwrap();
        let db = rusqlite::Connection::open(&output).unwrap();
        let mut query = db
            .prepare(&format!(
                "SELECT usn, record_offset FROM \"{}\" ORDER BY rowid",
                USN_TABLE
            ))
            .unwrap();
        let rows = query
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, String)>>>()
            .unwrap();
        drop(query);
        drop(db);
        rows
    }

    #[test]
    fn record_offset_is_absolute_across_window_refills() {
        let root = tmp_dir("offset-window");
        // First record at 0, then more than one 4 MiB window of zero padding so
        // the reader drains the buffer before reaching the second record.
        let mut data = usn_v2(64, 111, "x", 60, 2);
        data.resize(data.len() + 4 * 1024 * 1024 + 4096, 0);
        let second = data.len();
        data.extend(usn_v2(64, 222, "y", 60, 2));
        let rows = offsets_of(&root, "J", &data);
        assert_eq!(
            rows,
            vec![
                ("111".to_string(), "0".to_string()),
                ("222".to_string(), second.to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn record_offset_survives_padding_and_skipped_records() {
        let root = tmp_dir("offset-skip");
        let mut data = vec![0u8; 16];
        let first = data.len();
        data.extend(usn_v2(64, 111, "x", 60, 2));
        data.extend([0u8; 8]);
        // Unknown record version — skipped whole, must not shift later offsets.
        let mut unknown = usn_v2(64, 999, "x", 60, 2);
        unknown[4..6].copy_from_slice(&9u16.to_le_bytes());
        data.extend(unknown);
        let second = data.len();
        data.extend(usn_v2(64, 222, "y", 60, 2));
        // Corrupt length — resynchronised in 8-byte steps.
        data.extend([0xFFu8; 8]);
        let third = data.len();
        data.extend(usn_v2(64, 333, "z", 60, 2));
        let rows = offsets_of(&root, "J", &data);
        assert_eq!(
            rows,
            vec![
                ("111".to_string(), first.to_string()),
                ("222".to_string(), second.to_string()),
                ("333".to_string(), third.to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn large_usn_and_references_keep_full_precision_with_offsets() {
        let root = tmp_dir("offset-large");
        let mut v2 = usn_v2(64, u64::MAX, "x", 60, 2);
        v2[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        v2[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        let v3_at = v2.len();
        let v3 = usn_v3(u64::MAX - 1, u128::MAX, 1u128 << 64, "y");
        let mut data = v2;
        data.extend(v3);
        let source = root.join("J");
        let output = root.join("usn.sqlite");
        std::fs::write(&source, &data).unwrap();
        assert_eq!(parse_usn_stream(&source, &output).unwrap(), 2);
        let db = rusqlite::Connection::open(&output).unwrap();
        let mut query = db
            .prepare(&format!(
                "SELECT usn, file_reference, parent_file_reference, mft_entry, \
                 parent_mft_entry, record_version, record_offset FROM \"{}\" ORDER BY rowid",
                USN_TABLE
            ))
            .unwrap();
        let rows: Vec<(String, String, String, String, String, String, String)> = query
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "18446744073709551615".to_string(),
                    "18446744073709551615".to_string(),
                    "18446744073709551615".to_string(),
                    "281474976710655".to_string(),
                    "281474976710655".to_string(),
                    "2".to_string(),
                    "0".to_string(),
                ),
                (
                    "18446744073709551614".to_string(),
                    "340282366920938463463374607431768211455".to_string(),
                    "18446744073709551616".to_string(),
                    "281474976710655".to_string(),
                    "0".to_string(),
                    "3".to_string(),
                    v3_at.to_string(),
                ),
            ]
        );
        drop(query);
        drop(db);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn offsets_are_independent_per_input() {
        let root = tmp_dir("offset-inputs");
        let mut first = vec![0u8; 16];
        first.extend(usn_v2(64, 111, "x", 60, 2));
        let second = usn_v2(64, 222, "y", 60, 2);
        assert_eq!(
            offsets_of(&root, "J1", &first),
            vec![("111".to_string(), "16".to_string())]
        );
        assert_eq!(
            offsets_of(&root, "J2", &second),
            vec![("222".to_string(), "0".to_string())]
        );
        let db = rusqlite::Connection::open(root.join("J2.sqlite")).unwrap();
        let source_file: String = db
            .query_row(
                &format!("SELECT _source_file FROM \"{}\"", USN_TABLE),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source_file, root.join("J2").to_string_lossy());
        drop(db);
        let _ = std::fs::remove_dir_all(root);
    }
}
