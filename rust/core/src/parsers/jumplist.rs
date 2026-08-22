//! JumpList parser. AutomaticDestinations-ms are OLE compound files (`cfb`);
//! each stream (except DestList*) is a raw Shell Link parsed with `lnk`.
//! CustomDestinations-ms are a raw concatenation of LNKs found by signature.
//! One row per LNK entry; schema matches the Python parser.
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use encoding_rs::EUC_KR;
use lnk::ShellLink;
use walkdir::WalkDir;
use rayon::prelude::*;

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const JUMPLIST_TABLE: &str = "JumpList_Entries";
pub const JUMPLIST_FIELD_ORDER: &[&str] = &[
    "timestamp", "created_time", "modified_time", "app_id", "jumplist_type",
    "target_path", "arguments", "working_directory", "machine_id", "stream_id",
    "_status", "_error", "_source_file",
];

// Shell Link header: size 0x4C + CLSID 00021401-0000-0000-C000-000000000046.
const LNK_SIG: [u8; 20] = [
    0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const LNK_HEADER_SIZE: usize = 0x4c;
const HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const HAS_LINK_INFO: u32 = 0x0000_0002;

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset.checked_add(4)?)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Read a null-terminated UTF-16LE string without ever treating malformed
/// evidence as a parser-wide failure.  Shell Links store the Unicode path in
/// LinkInfo separately from the ANSI path; the `lnk` crate currently decodes
/// that field as UTF-8, which turns Korean file names into replacement chars.
fn read_utf16z(data: &[u8], offset: usize, limit: usize) -> Option<String> {
    if offset >= limit || limit > data.len() {
        return None;
    }

    let mut units = Vec::new();
    let mut pos = offset;
    while pos.checked_add(2)? <= limit {
        let unit = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        pos += 2;
    }
    if units.is_empty() {
        return Some(String::new());
    }
    Some(String::from_utf16_lossy(&units))
}

fn read_ansi_z(data: &[u8], offset: usize, limit: usize) -> Option<String> {
    if offset >= limit || limit > data.len() {
        return None;
    }
    let end = data[offset..limit]
        .iter()
        .position(|&byte| byte == 0)
        .map(|index| offset + index)
        .unwrap_or(limit);
    // Windows-949 is represented by the WHATWG EUC-KR decoder in encoding_rs.
    // It covers the CP949 extension set used by Korean Windows installations.
    Some(EUC_KR.decode_without_bom_handling(&data[offset..end]).0.into_owned())
}

fn link_info_bounds(data: &[u8]) -> Option<(usize, usize, usize)> {
    let flags = read_u32_le(data, 0x14)?;
    if flags & HAS_LINK_INFO == 0 {
        return None;
    }
    let mut link_info_offset = LNK_HEADER_SIZE;
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        let id_list_size = data.get(link_info_offset..link_info_offset + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_le_bytes)? as usize;
        link_info_offset = link_info_offset.checked_add(2 + id_list_size)?;
    }
    let link_info_size = read_u32_le(data, link_info_offset)? as usize;
    let link_info_end = link_info_offset.checked_add(link_info_size)?;
    if link_info_size < 0x1c || link_info_end > data.len() {
        return None;
    }
    let header_size = read_u32_le(data, link_info_offset + 4)? as usize;
    if header_size < 0x1c || header_size > link_info_size {
        return None;
    }
    Some((link_info_offset, link_info_end, header_size))
}

/// Extract the Unicode target path directly from an LNK LinkInfo block.
///
/// This deliberately uses bounds-checked offsets because JumpLists frequently
/// contain partially overwritten LNK streams. Returning `None` merely falls
/// back to the crate parser for that individual entry.
fn unicode_link_info_target(data: &[u8]) -> Option<String> {
    let (link_info_offset, link_info_end, header_size) = link_info_bounds(data)?;
    if header_size < 0x24 {
        return None;
    }

    let local_offset = read_u32_le(data, link_info_offset + 0x1c)? as usize;
    let suffix_offset = read_u32_le(data, link_info_offset + 0x20)? as usize;
    let local = if local_offset == 0 {
        String::new()
    } else {
        read_utf16z(data, link_info_offset.checked_add(local_offset)?, link_info_end)?
    };
    let suffix = if suffix_offset == 0 {
        String::new()
    } else {
        read_utf16z(data, link_info_offset.checked_add(suffix_offset)?, link_info_end)?
    };
    if local.is_empty() && suffix.is_empty() {
        return None;
    }
    if suffix.is_empty() || local.ends_with(&suffix) {
        Some(local)
    } else {
        Some(format!("{local}{suffix}"))
    }
}

fn ansi_link_info_target(data: &[u8]) -> Option<String> {
    let (link_info_offset, link_info_end, _) = link_info_bounds(data)?;
    let local_offset = read_u32_le(data, link_info_offset + 0x10)? as usize;
    let suffix_offset = read_u32_le(data, link_info_offset + 0x18)? as usize;
    let local = if local_offset == 0 {
        String::new()
    } else {
        read_ansi_z(data, link_info_offset.checked_add(local_offset)?, link_info_end)?
    };
    let suffix = if suffix_offset == 0 {
        String::new()
    } else {
        read_ansi_z(data, link_info_offset.checked_add(suffix_offset)?, link_info_end)?
    };
    if local.is_empty() && suffix.is_empty() {
        return None;
    }
    if suffix.is_empty() || local.ends_with(&suffix) {
        Some(local)
    } else {
        Some(format!("{local}{suffix}"))
    }
}

fn ft(ticks: u64) -> String {
    fmt_filetime(ticks as i64)
}

/// Parse a raw LNK byte blob via the `lnk` crate (which only reads from a
/// path), returning (target_path, created, modified, accessed, args, wdir).
/// The machine NetBIOS name from the DistributedLinkTracker extra block
/// (signature 0xA0000003), which the `lnk` crate doesn't expose.
fn extract_machine_id(data: &[u8]) -> String {
    let sig = [0x03u8, 0x00, 0x00, 0xA0];
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i..i + 4] == sig {
            let mid = i + 12; // block = i-4; MachineID at block+16 = i+12
            if mid + 16 <= data.len() {
                let raw = &data[mid..mid + 16];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                return String::from_utf8_lossy(&raw[..end]).to_string();
            }
        }
        i += 1;
    }
    String::new()
}

fn temp_lnk_path() -> std::path::PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("wina_lnk_{}_{}.tmp", std::process::id(), n))
}

/// `lnk` 0.5 only accepts a path, not a reader.  Reuse one temporary path for
/// every stream in a source JumpList: creating and unlinking a file per entry
/// dominated runtime on JumpLists with many links.
fn parse_lnk(data: &[u8], tmp: &Path) -> Result<(String, String, String, String, String, String, String)> {
    std::fs::File::create(tmp)?.write_all(data)?;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ShellLink::open(tmp)));
    let sl = match res {
        Ok(Ok(sl)) => sl,
        Ok(Err(e)) => return Err(anyhow::anyhow!("{:?}", e)),
        Err(_) => return Err(anyhow::anyhow!("lnk parse panicked (malformed shell link)")),
    };

    let h = sl.header();
    let created = ft(h.creation_time().into());
    let modified = ft(h.write_time().into());
    let accessed = ft(h.access_time().into());

    let target = unicode_link_info_target(data)
        .or_else(|| ansi_link_info_target(data))
        .unwrap_or_else(|| match sl.link_info() {
        Some(li) => li.local_base_path().as_ref().map(|p| format!("{}{}", p, li.common_path_suffix()))
            .unwrap_or_else(|| sl.relative_path().clone().unwrap_or_default()),
        _ => sl.relative_path().clone().unwrap_or_default(),
        });
    let args = sl.arguments().clone().unwrap_or_default();
    let wdir = sl.working_dir().clone().unwrap_or_default();
    let machine_id = extract_machine_id(data);
    Ok((target, created, modified, accessed, args, wdir, machine_id))
}

fn row_ok(target: String, created: String, modified: String, accessed: String, args: String, wdir: String, machine_id: String,
          app_id: &str, jl_type: &str, stream_id: &str, source: &str) -> Row {
    let mut r = Row::new();
    r.insert("timestamp".into(), accessed);
    r.insert("created_time".into(), created);
    r.insert("modified_time".into(), modified);
    r.insert("app_id".into(), app_id.into());
    r.insert("jumplist_type".into(), jl_type.into());
    r.insert("target_path".into(), target);
    r.insert("arguments".into(), args);
    r.insert("working_directory".into(), wdir);
    r.insert("machine_id".into(), machine_id);
    r.insert("stream_id".into(), stream_id.into());
    r.insert("_status".into(), "ok".into());
    r.insert("_error".into(), String::new());
    r.insert("_source_file".into(), source.into());
    r
}
fn row_err(app_id: &str, jl_type: &str, stream_id: &str, source: &str, err: String) -> Row {
    let mut r = Row::new();
    r.insert("timestamp".into(), String::new());
    r.insert("app_id".into(), app_id.into());
    r.insert("jumplist_type".into(), jl_type.into());
    r.insert("stream_id".into(), stream_id.into());
    r.insert("_status".into(), "corrupted".into());
    r.insert("_error".into(), err);
    r.insert("_source_file".into(), source.into());
    r
}

fn parse_automatic(path: &Path, rows: &mut Vec<Row>) {
    let app_id = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let source = path.to_string_lossy().to_string();
    let mut comp = match cfb::open(path) {
        Ok(c) => c,
        Err(e) => { rows.push(row_err(&app_id, "Automatic", "", &source, e.to_string())); return; }
    };
    let names: Vec<String> = comp.walk()
        .filter(|e| e.is_stream())
        .map(|e| e.name().to_string())
        .filter(|n| n != "DestList" && n != "DestListPropertyStore")
        .collect();
    let tmp = temp_lnk_path();
    for name in names {
        let mut buf = Vec::new();
        let ok = comp.open_stream(&name).and_then(|mut s| s.read_to_end(&mut buf).map(|_| ()));
        if let Err(e) = ok { rows.push(row_err(&app_id, "Automatic", &name, &source, e.to_string())); continue; }
        match parse_lnk(&buf, &tmp) {
            Ok((t, c, m, a, ar, w, mid)) => rows.push(row_ok(t, c, m, a, ar, w, mid, &app_id, "Automatic", &name, &source)),
            Err(e) => rows.push(row_err(&app_id, "Automatic", &name, &source, e.to_string())),
        }
    }
    let _ = std::fs::remove_file(tmp);
}

fn parse_custom(path: &Path, rows: &mut Vec<Row>) {
    let app_id = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let source = path.to_string_lossy().to_string();
    let data = match std::fs::read(path) { Ok(d) => d, Err(e) => { rows.push(row_err(&app_id, "Custom", "", &source, e.to_string())); return; } };
    let mut offsets: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i + LNK_SIG.len() <= data.len() {
        if data[i..i + LNK_SIG.len()] == LNK_SIG { offsets.push(i); i += LNK_SIG.len(); } else { i += 1; }
    }
    let tmp = temp_lnk_path();
    for (idx, &start) in offsets.iter().enumerate() {
        let end = offsets.get(idx + 1).copied().unwrap_or(data.len());
        match parse_lnk(&data[start..end], &tmp) {
            Ok((t, c, m, a, ar, w, mid)) => rows.push(row_ok(t, c, m, a, ar, w, mid, &app_id, "Custom", &idx.to_string(), &source)),
            Err(e) => rows.push(row_err(&app_id, "Custom", &idx.to_string(), &source, e.to_string())),
        }
    }
    let _ = std::fs::remove_file(tmp);
}

pub fn parse_jumplists(root: &Path) -> Result<Vec<Row>> {
    // The lnk crate panics on some malformed shell links; we catch those per
    // entry. Silence the default panic hook so caught panics don't flood the
    // log, then restore it.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let entries: Vec<_> = WalkDir::new(root).into_iter().filter_map(|e| e.ok()).collect();
    let rows: Vec<Row> = entries.into_par_iter().flat_map(|entry| {
        let mut local_rows = Vec::new();
        if entry.file_type().is_file() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".automaticdestinations-ms") {
                parse_automatic(entry.path(), &mut local_rows);
            } else if name.ends_with(".customdestinations-ms") {
                parse_custom(entry.path(), &mut local_rows);
            }
        }
        local_rows
    }).collect();
    std::panic::set_hook(prev_hook);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_utf16z(data: &mut [u8], offset: usize, value: &str) {
        let mut pos = offset;
        for unit in value.encode_utf16().chain(std::iter::once(0)) {
            data[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
            pos += 2;
        }
    }

    #[test]
    fn reads_korean_unicode_link_info_path() {
        let local = "C:\\Users\\분석가";
        let suffix = "\\문서\\보고서.pdf";
        let local_offset = 0x24usize;
        let suffix_offset = local_offset + (local.encode_utf16().count() + 1) * 2;
        let link_info_size = suffix_offset + (suffix.encode_utf16().count() + 1) * 2;
        let mut data = vec![0u8; LNK_HEADER_SIZE + link_info_size];
        write_u32(&mut data, 0x14, HAS_LINK_INFO);
        let base = LNK_HEADER_SIZE;
        write_u32(&mut data, base, link_info_size as u32);
        write_u32(&mut data, base + 4, 0x24);
        write_u32(&mut data, base + 0x1c, local_offset as u32);
        write_u32(&mut data, base + 0x20, suffix_offset as u32);
        write_utf16z(&mut data, base + local_offset, local);
        write_utf16z(&mut data, base + suffix_offset, suffix);

        assert_eq!(
            unicode_link_info_target(&data).as_deref(),
            Some("C:\\Users\\분석가\\문서\\보고서.pdf")
        );
    }

    #[test]
    fn ignores_truncated_link_info() {
        let mut data = vec![0u8; LNK_HEADER_SIZE + 0x24];
        write_u32(&mut data, 0x14, HAS_LINK_INFO);
        write_u32(&mut data, LNK_HEADER_SIZE, 0x80);
        write_u32(&mut data, LNK_HEADER_SIZE + 4, 0x24);
        assert_eq!(unicode_link_info_target(&data), None);
    }

    #[test]
    fn reads_korean_ansi_link_info_path() {
        let local = "G:\\문서";
        let suffix = "\\보고서.pdf";
        let (local_bytes, _, _) = EUC_KR.encode(local);
        let (suffix_bytes, _, _) = EUC_KR.encode(suffix);
        let local_offset = 0x1cusize;
        let suffix_offset = local_offset + local_bytes.len() + 1;
        let link_info_size = suffix_offset + suffix_bytes.len() + 1;
        let mut data = vec![0u8; LNK_HEADER_SIZE + link_info_size];
        write_u32(&mut data, 0x14, HAS_LINK_INFO);
        let base = LNK_HEADER_SIZE;
        write_u32(&mut data, base, link_info_size as u32);
        write_u32(&mut data, base + 4, 0x1c);
        write_u32(&mut data, base + 0x10, local_offset as u32);
        write_u32(&mut data, base + 0x18, suffix_offset as u32);
        data[base + local_offset..base + local_offset + local_bytes.len()].copy_from_slice(&local_bytes);
        data[base + suffix_offset..base + suffix_offset + suffix_bytes.len()].copy_from_slice(&suffix_bytes);

        assert_eq!(
            ansi_link_info_target(&data).as_deref(),
            Some("G:\\문서\\보고서.pdf")
        );
    }
}
