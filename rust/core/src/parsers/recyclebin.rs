//! Windows Recycle Bin `$I` metadata. `$R` is stat-only, never read or traversed.
//! Header: u64 version at 0, size at 8, FILETIME at 16.
//! V1: 260 UTF-16LE units at 24. V2: u32 unit count at 24, path at 28.
//! Damaged inputs retain failure rows; collected folder names do not prove volume identity.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;
use walkdir::WalkDir;

use crate::time::fmt_filetime;

pub const TABLE: &str = "RecycleBin_Records";

const CREATE_SQL: &str = r#"
CREATE TABLE "RecycleBin_Records" (
  "format_version" INTEGER,
  "original_path" TEXT,
  "file_size" INTEGER,
  "deleted_time_raw" TEXT,
  "timestamp" TEXT,
  "account_sid" TEXT,
  "account" TEXT,
  "volume_id" TEXT,
  "original_drive_letter" TEXT,
  "recycle_name" TEXT,
  "r_exists" INTEGER,
  "_source_file" TEXT NOT NULL,
  "_status" TEXT,
  "_error" TEXT,
  CHECK (r_exists IS NULL OR (typeof(r_exists) = 'integer' AND r_exists IN (0,1))),
  CHECK (file_size IS NULL OR (typeof(file_size) = 'integer' AND file_size >= 0))
);
CREATE INDEX idx_recyclebin_time ON RecycleBin_Records(timestamp);
CREATE INDEX idx_recyclebin_volume_account ON RecycleBin_Records(volume_id, account_sid, timestamp);
"#;

const INSERT_SQL: &str = r#"INSERT INTO "RecycleBin_Records" (
  "format_version", "original_path", "file_size", "deleted_time_raw", "timestamp",
  "account_sid", "account", "volume_id", "original_drive_letter", "recycle_name",
  "r_exists", "_source_file", "_status", "_error"
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#;

const STATUS_OK: &str = "ok";
const STATUS_CORRUPTED: &str = "corrupted";
const STATUS_UNREADABLE: &str = "unreadable_file";

const V1_PATH_CHARS: usize = 260;
const V1_SIZE: usize = 24 + V1_PATH_CHARS * 2;

// Keep evidenced headers even when path decoding fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DollarIHeader {
    version: u64,
    file_size: u64,
    deleted_filetime: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DollarI {
    header: DollarIHeader,
    original_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DollarIError {
    header: Option<DollarIHeader>,
    message: String,
}

impl DollarIError {
    fn new(header: Option<DollarIHeader>, message: impl Into<String>) -> Self {
        Self { header, message: message.into() }
    }
}

fn u64le(b: &[u8], off: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(raw)
}

fn u32le(b: &[u8], off: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&b[off..off + 4]);
    u32::from_le_bytes(raw)
}

// Invalid UTF-16 is a failure, not an empty successful path.
fn decode_utf16le(bytes: &[u8]) -> Result<String, String> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    char::decode_utf16(units.into_iter())
        .collect::<Result<String, _>>()
        .map_err(|e| format!("invalid UTF-16LE in original path: {e}"))
}

fn parse_dollar_i(data: &[u8]) -> Result<DollarI, DollarIError> {
    if data.len() < 24 {
        return Err(DollarIError::new(
            None,
            format!("truncated $I: {} bytes, 24-byte header required", data.len()),
        ));
    }
    let header = DollarIHeader {
        version: u64le(data, 0),
        file_size: u64le(data, 8),
        deleted_filetime: u64le(data, 16),
    };
    let path_bytes: &[u8] = match header.version {
        1 => {
            let end = std::cmp::min(data.len(), V1_SIZE);
            let region = &data[24..end];
            let terminated = region
                .chunks_exact(2)
                .any(|c| u16::from_le_bytes([c[0], c[1]]) == 0);
            if !terminated {
                return Err(DollarIError::new(
                    Some(header),
                    "version 1 original path is not null-terminated".to_string(),
                ));
            }
            region
        }
        2 => {
            if data.len() < 28 {
                return Err(DollarIError::new(
                    Some(header),
                    format!(
                        "truncated $I version 2: {} bytes, 28-byte header required",
                        data.len()
                    ),
                ));
            }
            let chars = u32le(data, 24) as usize;
            if chars == 0 {
                return Err(DollarIError::new(
                    Some(header),
                    "version 2 original path length is 0".to_string(),
                ));
            }
            // The length counts UTF-16 units, not bytes.
            let need = chars
                .checked_mul(2)
                .and_then(|b| b.checked_add(28))
                .ok_or_else(|| {
                    DollarIError::new(
                        Some(header),
                        format!("version 2 original path length {chars} chars overflows"),
                    )
                })?;
            if need > data.len() {
                return Err(DollarIError::new(
                    Some(header),
                    format!(
                        "version 2 original path length {chars} chars exceeds file ({} bytes)",
                        data.len()
                    ),
                ));
            }
            let region = &data[28..need];
            let last = u16::from_le_bytes([region[region.len() - 2], region[region.len() - 1]]);
            if last != 0 {
                return Err(DollarIError::new(
                    Some(header),
                    "version 2 original path is not null-terminated".to_string(),
                ));
            }
            region
        }
        other => {
            return Err(DollarIError::new(
                Some(header),
                format!("unsupported $I format version {other}"),
            ))
        }
    };
    let original_path =
        decode_utf16le(path_bytes).map_err(|e| DollarIError::new(Some(header), e))?;
    if original_path.is_empty() {
        return Err(DollarIError::new(
            Some(header),
            "original path is empty".to_string(),
        ));
    }
    Ok(DollarI { header, original_path })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecycleBinRecord {
    format_version: Option<i64>,
    original_path: Option<String>,
    file_size: Option<i64>,
    deleted_time_raw: Option<String>,
    timestamp: Option<String>,
    account_sid: Option<String>,
    account: Option<String>,
    volume_id: Option<String>,
    original_drive_letter: Option<String>,
    recycle_name: Option<String>,
    r_exists: Option<i64>,
    source_file: String,
    status: String,
    error: Option<String>,
}

impl RecycleBinRecord {
    fn empty(source_file: String) -> Self {
        Self {
            format_version: None,
            original_path: None,
            file_size: None,
            deleted_time_raw: None,
            timestamp: None,
            account_sid: None,
            account: None,
            volume_id: None,
            original_drive_letter: None,
            recycle_name: None,
            r_exists: None,
            source_file,
            status: STATUS_OK.to_string(),
            error: None,
        }
    }
}

/// Evidence-backed context; never inferred from collection folder names.
#[derive(Debug, Default, Clone)]
pub struct RecycleBinContext {
    /// Verified internal volume identity, if available.
    pub volume_id: Option<String>,
    /// Confirmed target account names keyed by uppercase SID.
    pub accounts: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RecycleBinInput {
    pub path: PathBuf,
    /// Failed inputs also retain one row.
    pub rows: usize,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct RecycleBinReport {
    pub rows: usize,
    pub failed_rows: usize,
    pub inputs: Vec<RecycleBinInput>,
}

// $I30 is an NTFS index dump, not Recycle Bin metadata.
fn is_dollar_i_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("$i") && lower != "$i30"
}

fn is_dollar_r_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("$r") && lower != "$recycle.bin"
}

fn recycle_name_of(file_name: &str) -> Option<String> {
    let mut chars = file_name.chars();
    let (a, b) = (chars.next()?, chars.next()?);
    if a != '$' || (b != 'I' && b != 'i') {
        return None;
    }
    let rest = chars.as_str();
    (!rest.is_empty()).then(|| rest.to_string())
}

fn r_path_for(i_path: &Path) -> Option<PathBuf> {
    let file_name = i_path.file_name()?.to_string_lossy().to_string();
    let suffix = recycle_name_of(&file_name)?;
    let prefix = if file_name.starts_with("$I") { "$R" } else { "$r" };
    Some(i_path.with_file_name(format!("{prefix}{suffix}")))
}

// Stat only: 1 present, 0 absent, None inaccessible.
fn r_exists(r_path: &Path) -> Option<i64> {
    match std::fs::symlink_metadata(r_path) {
        Ok(_) => Some(1),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
        Err(_) => None,
    }
}

fn looks_like_sid(part: &str) -> bool {
    let upper = part.to_uppercase();
    let Some(rest) = upper.strip_prefix("S-1-") else {
        return false;
    };
    let mut groups = 0usize;
    for group in rest.split('-') {
        if group.is_empty() || !group.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        groups += 1;
    }
    groups >= 2
}

// Require the immediate $Recycle.Bin/SID/$I context.
fn account_sid_of(path: &Path) -> Option<String> {
    let dir = path.parent()?;
    let sid = dir.file_name()?.to_string_lossy().to_string();
    if !looks_like_sid(&sid) {
        return None;
    }
    let bin = dir.parent()?.file_name()?.to_string_lossy().to_string();
    bin.eq_ignore_ascii_case("$recycle.bin")
        .then(|| sid.to_uppercase())
}

// Original drive letter does not establish the collected volume's identity.
fn original_drive_letter(original_path: &str) -> Option<String> {
    let mut chars = original_path.chars();
    match (chars.next(), chars.next()) {
        (Some(c), Some(':')) if c.is_ascii_alphabetic() => {
            Some(c.to_ascii_uppercase().to_string())
        }
        _ => None,
    }
}

// Keep path-derived context even when the $I payload cannot be decoded.
fn record_for(path: &Path, ctx: &RecycleBinContext) -> RecycleBinRecord {
    let mut rec = RecycleBinRecord::empty(path.to_string_lossy().to_string());
    rec.account_sid = account_sid_of(path);
    rec.account = rec
        .account_sid
        .as_ref()
        .and_then(|sid| ctx.accounts.get(sid.as_str()).cloned())
        .filter(|name| !name.is_empty());
    rec.volume_id = ctx.volume_id.clone().filter(|v| !v.is_empty());
    let file_name = path.file_name().map(|n| n.to_string_lossy().to_string());
    rec.recycle_name = file_name.as_deref().and_then(recycle_name_of);
    if let Some(r) = r_path_for(path) {
        rec.r_exists = r_exists(&r);
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            rec.status = STATUS_UNREADABLE.to_string();
            rec.error = Some(e.to_string());
            return rec;
        }
    };
    match parse_dollar_i(&data) {
        Ok(parsed) => {
            apply_header(&mut rec, parsed.header);
            if rec.file_size.is_none() {
                rec.status = STATUS_CORRUPTED.to_string();
                rec.error = Some(format!(
                    "original size {} bytes out of representable range",
                    parsed.header.file_size
                ));
                return rec;
            }
            rec.original_drive_letter = original_drive_letter(&parsed.original_path);
            rec.original_path = Some(parsed.original_path);
        }
        Err(err) => {
            if let Some(header) = err.header {
                rec.format_version = Some(header.version as i64);
                if header.version == 1 || header.version == 2 {
                    apply_header(&mut rec, header);
                }
            }
            rec.status = STATUS_CORRUPTED.to_string();
            rec.error = Some(err.message);
        }
    }
    rec
}

fn apply_header(rec: &mut RecycleBinRecord, header: DollarIHeader) {
    rec.format_version = Some(header.version as i64);
    rec.file_size = i64::try_from(header.file_size).ok();
    rec.deleted_time_raw = Some(header.deleted_filetime.to_string());
    let display = i64::try_from(header.deleted_filetime)
        .map(fmt_filetime)
        .unwrap_or_default();
    rec.timestamp = (!display.is_empty()).then_some(display);
}

/// Discover $I inputs without descending into $R directories.
pub fn recyclebin_sources(root: &Path) -> crate::finder::Found {
    let mut found = crate::finder::Found::default();
    let walker = WalkDir::new(root).into_iter().filter_entry(|entry| {
        if entry.depth() == 0 || !entry.file_type().is_dir() {
            return true;
        }
        !is_dollar_r_name(&entry.file_name().to_string_lossy())
    });
    for entry in walker {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_file()
                    && is_dollar_i_name(&entry.file_name().to_string_lossy())
                {
                    found.paths.push(entry.into_path());
                }
            }
            Err(e) => {
                let at = e
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| root.display().to_string());
                found.errors.push(format!("{at}: {e}"));
            }
        }
    }
    found.paths.sort();
    found
}

fn open_db(out: &Path) -> Result<Connection> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let conn = Connection::open(out)
        .with_context(|| format!("open RecycleBin DB: {}", out.display()))?;
    conn.execute_batch(&format!(
        "DROP TABLE IF EXISTS {};
         DROP INDEX IF EXISTS idx_recyclebin_time;
         DROP INDEX IF EXISTS idx_recyclebin_volume_account;",
        crate::sqlite::quote_ident(TABLE)
    ))?;
    conn.pragma_update(None, "journal_mode", "OFF").ok();
    conn.pragma_update(None, "synchronous", "OFF").ok();
    conn.execute_batch(CREATE_SQL)
        .with_context(|| format!("create {TABLE}"))?;
    Ok(conn)
}

fn insert(stmt: &mut rusqlite::Statement<'_>, rec: &RecycleBinRecord) -> rusqlite::Result<()> {
    stmt.execute(rusqlite::params![
        rec.format_version,
        rec.original_path,
        rec.file_size,
        rec.deleted_time_raw,
        rec.timestamp,
        rec.account_sid,
        rec.account,
        rec.volume_id,
        rec.original_drive_letter,
        rec.recycle_name,
        rec.r_exists,
        rec.source_file,
        rec.status,
        rec.error,
    ])?;
    Ok(())
}

/// Retain per-input failures as rows; propagate storage failures.
pub fn parse_recyclebin(
    paths: &[PathBuf],
    out: &Path,
    ctx: &RecycleBinContext,
) -> Result<RecycleBinReport> {
    let mut report = RecycleBinReport::default();
    let mut conn = open_db(out)?;
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(INSERT_SQL)?;
        for path in paths {
            if crate::pipeline::cancelled() {
                break;
            }
            let rec = record_for(path, ctx);
            if rec.status != STATUS_OK {
                report.failed_rows += 1;
            }
            report.rows += 1;
            report.inputs.push(RecycleBinInput {
                path: path.clone(),
                rows: 1,
                error: rec.error.clone(),
            });
            insert(&mut stmt, &rec)?;
        }
    }
    tx.commit()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::types::ValueRef;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-recyclebin-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn v1(size: u64, ft: u64, path: &str) -> Vec<u8> {
        let mut b = Vec::with_capacity(V1_SIZE);
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&ft.to_le_bytes());
        b.extend_from_slice(&utf16(path));
        b.extend_from_slice(&[0, 0]);
        b.resize(V1_SIZE, 0);
        b
    }

    fn v2(size: u64, ft: u64, path: &str) -> Vec<u8> {
        let units = utf16(path);
        let chars = (units.len() / 2 + 1) as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&2u64.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&ft.to_le_bytes());
        b.extend_from_slice(&chars.to_le_bytes());
        b.extend_from_slice(&units);
        b.extend_from_slice(&[0, 0]);
        b
    }

    const FT: u64 = 132_000_000_000_012_345;

    fn ctx() -> RecycleBinContext {
        RecycleBinContext::default()
    }

    #[test]
    fn version_1_reads_size_filetime_and_unicode_path() {
        let parsed = parse_dollar_i(&v1(4096, FT, "C:\\Users\\유저\\보고서.hwp")).unwrap();
        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.header.file_size, 4096);
        assert_eq!(parsed.header.deleted_filetime, FT);
        assert_eq!(parsed.original_path, "C:\\Users\\유저\\보고서.hwp");
    }

    #[test]
    fn version_2_length_is_characters_not_bytes() {
        let path = "D:\\작업\\데이터 모음.xlsx";
        let bytes = v2(12, FT, path);
        assert_eq!(u32le(&bytes, 24) as usize, path.encode_utf16().count() + 1);
        let parsed = parse_dollar_i(&bytes).unwrap();
        assert_eq!(parsed.header.version, 2);
        assert_eq!(parsed.original_path, path);
        assert_eq!(parsed.header.file_size, 12);
    }

    #[test]
    fn version_2_ignores_trailing_slack_after_the_declared_path() {
        let mut bytes = v2(1, FT, "C:\\a.txt");
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(parse_dollar_i(&bytes).unwrap().original_path, "C:\\a.txt");
    }

    #[test]
    fn truncated_header_fails_without_inventing_values() {
        let err = parse_dollar_i(&[0u8; 16]).unwrap_err();
        assert!(err.header.is_none());
        assert!(err.message.contains("24-byte header"), "{}", err.message);

        let short_v2 = &v2(1, FT, "C:\\a.txt")[..26];
        let err = parse_dollar_i(short_v2).unwrap_err();
        assert_eq!(err.header.map(|h| h.version), Some(2));
        assert!(err.message.contains("28-byte header"), "{}", err.message);
    }

    #[test]
    fn version_2_path_length_beyond_file_bounds_fails() {
        let mut bytes = v2(1, FT, "C:\\a.txt");
        bytes[24..28].copy_from_slice(&9000u32.to_le_bytes());
        let err = parse_dollar_i(&bytes).unwrap_err();
        assert!(err.message.contains("exceeds file"), "{}", err.message);
        assert_eq!(err.header.map(|h| h.version), Some(2));

        let mut huge = v2(1, FT, "C:\\a.txt");
        huge[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_dollar_i(&huge).is_err());
    }

    #[test]
    fn version_2_without_null_terminator_fails() {
        let path = "C:\\a.txt";
        let units = utf16(path);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&FT.to_le_bytes());
        bytes.extend_from_slice(&((units.len() / 2) as u32).to_le_bytes());
        bytes.extend_from_slice(&units);
        let err = parse_dollar_i(&bytes).unwrap_err();
        assert!(err.message.contains("null-terminated"), "{}", err.message);
    }

    #[test]
    fn version_1_without_null_terminator_fails() {
        let mut bytes = v1(1, FT, "C:\\a.txt");
        for b in bytes[24..].iter_mut() {
            *b = 0x41;
        }
        let err = parse_dollar_i(&bytes).unwrap_err();
        assert!(err.message.contains("null-terminated"), "{}", err.message);
        assert_eq!(err.header.map(|h| h.version), Some(1));
    }

    #[test]
    fn unsupported_version_fails_but_keeps_the_version_it_read() {
        let mut bytes = v2(1, FT, "C:\\a.txt");
        bytes[0..8].copy_from_slice(&3u64.to_le_bytes());
        let err = parse_dollar_i(&bytes).unwrap_err();
        assert_eq!(err.header.map(|h| h.version), Some(3));
        assert!(err.message.contains("unsupported"), "{}", err.message);
    }

    #[test]
    fn broken_utf16_is_an_error_not_an_empty_path() {
        let mut bytes = v2(1, FT, "C:\\a.txt");
        bytes[28..30].copy_from_slice(&0xD800u16.to_le_bytes()); // lone surrogate
        let err = parse_dollar_i(&bytes).unwrap_err();
        assert!(err.message.contains("UTF-16"), "{}", err.message);

        let mut empty = v2(1, FT, "C:\\a.txt");
        empty[24..28].copy_from_slice(&1u32.to_le_bytes());
        empty[28..30].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse_dollar_i(&empty).unwrap_err().message.contains("empty"));
    }

    #[test]
    fn raw_filetime_keeps_100ns_precision_and_timestamp_is_kst_millis() {
        let dir = tmp("time");
        let src = dir.join("$IAAA111.txt");
        std::fs::write(&src, v2(10, FT, "C:\\a.txt")).unwrap();
        let rec = record_for(&src, &ctx());
        assert_eq!(rec.deleted_time_raw.as_deref(), Some("132000000000012345"));
        assert_eq!(rec.timestamp.as_deref(), Some(fmt_filetime(FT as i64).as_str()));
        assert_eq!(rec.status, STATUS_OK);

        let zero = dir.join("$IZERO.txt");
        std::fs::write(&zero, v2(0, 0, "C:\\z.txt")).unwrap();
        let rec = record_for(&zero, &ctx());
        assert_eq!(rec.deleted_time_raw.as_deref(), Some("0"));
        assert_eq!(rec.timestamp, None);
        assert_eq!(rec.file_size, Some(0));
    }

    #[test]
    fn r_pairing_replaces_only_the_first_prefix_and_keeps_the_full_suffix() {
        let dir = tmp("pair");
        let i = dir.join("$I$IAB12.txt");
        std::fs::write(&i, v2(1, FT, "C:\\$IAB12.txt")).unwrap();
        assert_eq!(
            r_path_for(&i).unwrap().file_name().unwrap().to_string_lossy(),
            "$R$IAB12.txt"
        );
        let rec = record_for(&i, &ctx());
        assert_eq!(rec.recycle_name.as_deref(), Some("$IAB12.txt"));
        assert_eq!(rec.r_exists, Some(0));

        std::fs::write(dir.join("$R$IAB12.txt"), b"").unwrap();
        assert_eq!(record_for(&i, &ctx()).r_exists, Some(1));
    }

    #[test]
    fn r_existence_covers_missing_zero_size_and_directories_without_recursion() {
        let dir = tmp("rexists");
        let missing = dir.join("$IMISS.txt");
        std::fs::write(&missing, v2(5, FT, "C:\\miss.txt")).unwrap();
        assert_eq!(record_for(&missing, &ctx()).r_exists, Some(0));

        let empty = dir.join("$IEMPTY.txt");
        std::fs::write(&empty, v2(7, FT, "C:\\empty.txt")).unwrap();
        std::fs::write(dir.join("$REMPTY.txt"), b"").unwrap();
        let rec = record_for(&empty, &ctx());
        assert_eq!(rec.r_exists, Some(1));
        // Collected $R size must not replace the original $I size.
        assert_eq!(rec.file_size, Some(7));

        let folder = dir.join("$IDIR");
        std::fs::write(&folder, v2(99, FT, "C:\\dir")).unwrap();
        let rdir = dir.join("$RDIR");
        std::fs::create_dir_all(rdir.join("sub")).unwrap();
        std::fs::write(rdir.join("sub").join("child.txt"), b"child").unwrap();
        let rec = record_for(&folder, &ctx());
        assert_eq!(rec.r_exists, Some(1));
        assert_eq!(rec.file_size, Some(99));
        assert_eq!(rec.status, STATUS_OK);
    }

    #[test]
    fn sid_comes_only_from_the_recycle_bin_sid_directory() {
        let dir = tmp("sid");
        let sid = "S-1-5-21-111-222-333-1001";
        let bin = dir.join("C").join("$Recycle.Bin").join(sid);
        std::fs::create_dir_all(&bin).unwrap();
        let src = bin.join("$ICTX01.docx");
        std::fs::write(&src, v2(3, FT, "D:\\Share\\report.docx")).unwrap();

        let mut context = ctx();
        context.accounts.insert(sid.to_string(), "Administrator".to_string());
        let rec = record_for(&src, &context);
        assert_eq!(rec.account_sid.as_deref(), Some(sid));
        assert_eq!(rec.account.as_deref(), Some("Administrator"));
        assert_eq!(rec.original_drive_letter.as_deref(), Some("D"));
        assert_eq!(rec.recycle_name.as_deref(), Some("CTX01.docx"));

        assert_eq!(record_for(&src, &ctx()).account, None);

        let stray = dir.join("export").join(sid).join("sub");
        std::fs::create_dir_all(&stray).unwrap();
        let stray_i = stray.join("$ISTRAY.txt");
        std::fs::write(&stray_i, v2(1, FT, "C:\\stray.txt")).unwrap();
        assert_eq!(record_for(&stray_i, &ctx()).account_sid, None);

        let flat = dir.join("$IFLAT.txt");
        std::fs::write(&flat, v1(1, FT, "\\\\server\\share\\x.txt")).unwrap();
        let rec = record_for(&flat, &ctx());
        assert_eq!(rec.account_sid, None);
        assert_eq!(rec.original_drive_letter, None);
        assert_eq!(rec.status, STATUS_OK);
    }

    #[test]
    fn volume_id_is_never_guessed_from_the_collection_folder_name() {
        let dir = tmp("volume");
        let bin = dir
            .join("Volume C")
            .join("$Recycle.Bin")
            .join("S-1-5-21-1-2-3-1004");
        std::fs::create_dir_all(&bin).unwrap();
        let src = bin.join("$IVOL01.txt");
        std::fs::write(&src, v2(1, FT, "C:\\vol.txt")).unwrap();
        assert_eq!(record_for(&src, &ctx()).volume_id, None);

        let context = RecycleBinContext {
            volume_id: Some("VOL-7".to_string()),
            ..RecycleBinContext::default()
        };
        assert_eq!(record_for(&src, &context).volume_id.as_deref(), Some("VOL-7"));
    }

    #[test]
    fn discovery_takes_dollar_i_files_only_and_never_descends_r_subtrees() {
        let dir = tmp("find");
        let bin = dir
            .join("C")
            .join("$Recycle.Bin")
            .join("S-1-5-21-9-9-9-1002");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("$IGOOD.txt"), v2(1, FT, "C:\\good.txt")).unwrap();
        std::fs::write(bin.join("$RGOOD.txt"), b"content").unwrap();
        let rdir = bin.join("$RDEEP");
        std::fs::create_dir_all(&rdir).unwrap();
        std::fs::write(rdir.join("$IHIDDEN.txt"), v2(1, FT, "C:\\hidden.txt")).unwrap();
        std::fs::write(dir.join("$ISOLO.doc"), v1(5, FT, "E:\\solo.doc")).unwrap();
        std::fs::write(dir.join("$I30"), vec![0u8; 600]).unwrap();
        std::fs::write(dir.join("isolated.bin"), v1(5, FT, "E:\\isolated.doc")).unwrap();

        let found = recyclebin_sources(&dir);
        let names: Vec<String> = found
            .paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"$IGOOD.txt".to_string()), "{names:?}");
        assert!(names.contains(&"$ISOLO.doc".to_string()), "{names:?}");
        assert!(!names.contains(&"$IHIDDEN.txt".to_string()), "{names:?}");
        assert!(!names.contains(&"$RGOOD.txt".to_string()), "{names:?}");
        assert!(!names.contains(&"$I30".to_string()), "{names:?}");
        assert!(!names.contains(&"isolated.bin".to_string()), "{names:?}");
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn all_inputs_land_in_one_typed_table_with_failures_isolated() {
        let dir = tmp("db");
        let sid = "S-1-5-21-5-6-7-1003";
        let bin = dir.join("D").join("$RECYCLE.BIN").join(sid);
        std::fs::create_dir_all(&bin).unwrap();
        let ok = bin.join("$IOK01.txt");
        std::fs::write(&ok, v1(2048, FT, "C:\\Users\\u\\문서.txt")).unwrap();
        std::fs::write(bin.join("$ROK01.txt"), b"body").unwrap();
        let bad = bin.join("$IBAD01.txt");
        std::fs::write(&bad, vec![0u8; 16]).unwrap();
        let unsupported = bin.join("$IBAD02.txt");
        let mut raw = v2(1, FT, "C:\\x.txt");
        raw[0..8].copy_from_slice(&7u64.to_le_bytes());
        std::fs::write(&unsupported, &raw).unwrap();

        let out = dir.join("RECYCLEBIN").join("RecycleBin_Records.sqlite");
        let mut context = ctx();
        context.accounts.insert(sid.to_string(), "user1".to_string());
        let report =
            parse_recyclebin(&[ok.clone(), bad.clone(), unsupported.clone()], &out, &context)
                .unwrap();
        assert_eq!((report.rows, report.failed_rows), (3, 2));
        assert_eq!(report.inputs.len(), 3);
        assert_eq!(report.inputs[0].path, ok);
        assert_eq!(report.inputs[0].rows, 1);
        assert_eq!(report.inputs[0].error, None);
        assert_eq!(report.inputs[1].path, bad);
        assert!(report.inputs[1].error.as_ref().unwrap().contains("24-byte header"));
        assert_eq!(report.inputs[2].path, unsupported);
        assert!(report.inputs[2].error.as_ref().unwrap().contains("unsupported"));

        let conn = Connection::open(&out).unwrap();
        let cols: Vec<String> = conn
            .prepare("SELECT * FROM RecycleBin_Records LIMIT 0")
            .unwrap()
            .column_names()
            .iter()
            .map(|c| c.to_string())
            .collect();
        assert_eq!(
            cols,
            vec![
                "format_version",
                "original_path",
                "file_size",
                "deleted_time_raw",
                "timestamp",
                "account_sid",
                "account",
                "volume_id",
                "original_drive_letter",
                "recycle_name",
                "r_exists",
                "_source_file",
                "_status",
                "_error",
            ]
        );

        let (fv, size, rex, path, acct, drive, rname, status, err): (
            i64,
            i64,
            i64,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT format_version, file_size, r_exists, original_path, account,
                        original_drive_letter, recycle_name, _status, _error
                 FROM RecycleBin_Records WHERE _source_file = ?1",
                rusqlite::params![ok.to_string_lossy().to_string()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!((fv, size, rex), (1, 2048, 1));
        assert_eq!(path, "C:\\Users\\u\\문서.txt");
        assert_eq!((acct.as_str(), drive.as_str()), ("user1", "C"));
        assert_eq!(rname, "OK01.txt");
        assert_eq!(status, STATUS_OK);
        assert_eq!(err, None);

        let kinds: Vec<String> = conn
            .query_row(
                "SELECT typeof(format_version), typeof(file_size), typeof(r_exists),
                        typeof(deleted_time_raw), typeof(volume_id)
                 FROM RecycleBin_Records WHERE _source_file = ?1",
                rusqlite::params![ok.to_string_lossy().to_string()],
                |r| Ok(vec![r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?]),
            )
            .unwrap();
        assert_eq!(kinds, vec!["integer", "integer", "integer", "text", "null"]);

        let mut stmt = conn
            .prepare(
                "SELECT format_version, original_path, file_size, deleted_time_raw, timestamp,
                        account_sid, _status, _error
                 FROM RecycleBin_Records WHERE _source_file = ?1",
            )
            .unwrap();
        let row = stmt
            .query_row(rusqlite::params![bad.to_string_lossy().to_string()], |r| {
                Ok((
                    matches!(r.get_ref(0)?, ValueRef::Null),
                    matches!(r.get_ref(1)?, ValueRef::Null),
                    matches!(r.get_ref(2)?, ValueRef::Null),
                    matches!(r.get_ref(3)?, ValueRef::Null),
                    matches!(r.get_ref(4)?, ValueRef::Null),
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .unwrap();
        assert_eq!((row.0, row.1, row.2, row.3, row.4), (true, true, true, true, true));
        assert_eq!(row.5, sid);
        assert_eq!(row.6, STATUS_CORRUPTED);

        let (version, status, path_null): (i64, String, bool) = conn
            .query_row(
                "SELECT format_version, _status, original_path IS NULL FROM RecycleBin_Records
                 WHERE _source_file = ?1",
                rusqlite::params![unsupported.to_string_lossy().to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((version, status.as_str(), path_null), (7, STATUS_CORRUPTED, true));

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM RecycleBin_Records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 3);
    }

    #[test]
    fn unreadable_input_becomes_a_row_while_storage_errors_propagate() {
        let dir = tmp("io");
        let missing = dir.join("$IGONE.txt");
        let out = dir.join("RecycleBin_Records.sqlite");
        let report = parse_recyclebin(&[missing.clone()], &out, &ctx()).unwrap();
        assert_eq!((report.rows, report.failed_rows), (1, 1));
        assert!(report.inputs[0].error.is_some());
        let conn = Connection::open(&out).unwrap();
        let (status, has_err): (String, bool) = conn
            .query_row(
                "SELECT _status, _error IS NOT NULL FROM RecycleBin_Records",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, STATUS_UNREADABLE);
        assert!(has_err);

        let bad_out = dir.join("as_dir.sqlite");
        std::fs::create_dir_all(&bad_out).unwrap();
        assert!(parse_recyclebin(&[], &bad_out, &ctx()).is_err());
    }
}
