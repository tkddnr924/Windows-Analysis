//! JumpList parser. AutomaticDestinations-ms are OLE compound files (`cfb`);
//! each stream (except DestList*) is a raw Shell Link parsed with `lnk`.
//! CustomDestinations-ms are a raw concatenation of LNKs found by signature.
//! One row per LNK entry; schema matches the Python parser.
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use lnk::ShellLink;
use walkdir::WalkDir;

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

fn parse_lnk(data: &[u8]) -> Result<(String, String, String, String, String, String, String)> {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("wina_lnk_{}_{}.tmp", std::process::id(), n));
    std::fs::File::create(&tmp)?.write_all(data)?;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ShellLink::open(&tmp)));
    let _ = std::fs::remove_file(&tmp);
    let sl = match res {
        Ok(Ok(sl)) => sl,
        Ok(Err(e)) => return Err(anyhow::anyhow!("{:?}", e)),
        Err(_) => return Err(anyhow::anyhow!("lnk parse panicked (malformed shell link)")),
    };

    let h = sl.header();
    let created = ft(h.creation_time().into());
    let modified = ft(h.write_time().into());
    let accessed = ft(h.access_time().into());

    let target = match sl.link_info() {
        Some(li) if li.local_base_path().is_some() => {
            format!("{}{}", li.local_base_path().as_ref().unwrap(), li.common_path_suffix())
        }
        _ => sl.relative_path().clone().unwrap_or_default(),
    };
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
    for name in names {
        let mut buf = Vec::new();
        let ok = comp.open_stream(&name).and_then(|mut s| s.read_to_end(&mut buf).map(|_| ()));
        if let Err(e) = ok { rows.push(row_err(&app_id, "Automatic", &name, &source, e.to_string())); continue; }
        match parse_lnk(&buf) {
            Ok((t, c, m, a, ar, w, mid)) => rows.push(row_ok(t, c, m, a, ar, w, mid, &app_id, "Automatic", &name, &source)),
            Err(e) => rows.push(row_err(&app_id, "Automatic", &name, &source, e.to_string())),
        }
    }
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
    for (idx, &start) in offsets.iter().enumerate() {
        let end = offsets.get(idx + 1).copied().unwrap_or(data.len());
        match parse_lnk(&data[start..end]) {
            Ok((t, c, m, a, ar, w, mid)) => rows.push(row_ok(t, c, m, a, ar, w, mid, &app_id, "Custom", &idx.to_string(), &source)),
            Err(e) => rows.push(row_err(&app_id, "Custom", &idx.to_string(), &source, e.to_string())),
        }
    }
}

pub fn parse_jumplists(root: &Path) -> Result<Vec<Row>> {
    // The lnk crate panics on some malformed shell links; we catch those per
    // entry. Silence the default panic hook so caught panics don't flood the
    // log, then restore it.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut rows = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.ends_with(".automaticdestinations-ms") {
            parse_automatic(entry.path(), &mut rows);
        } else if name.ends_with(".customdestinations-ms") {
            parse_custom(entry.path(), &mut rows);
        }
    }
    std::panic::set_hook(prev_hook);
    Ok(rows)
}
