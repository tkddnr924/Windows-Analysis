//! Windows Prefetch (.pf) parser — port of parsers/prefetch_parser.py, which
//! uses pyscca (libscca). Here `prefetch-core` provides the MAM/Xpress-Huffman
//! decompression + SCCA v30/31 parsing (run count, last-8 run times, volume
//! info, loaded filenames); the prefetch hash is read from the decompressed
//! SCCA header (offset 0x4C) since the crate doesn't surface it.
//!
//! NOTE (blind port — no .pf in the current sample; validate when one is
//! collected): `prefetch-core` supports SCCA v30/31 (Win10/11) only, so older
//! formats (v17/23/26) yield a `corrupted` row like Python's parse-failure
//! fallback; and it does not expose per-file MFT references, so
//! `Prefetch_LoadedFiles.file_reference` is left blank for now.
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const EXEC_TABLE: &str = "Prefetch_Execution";
pub const LOADED_TABLE: &str = "Prefetch_LoadedFiles";
pub const EXEC_FIELD_ORDER: &[&str] = &[
    "last_run_time",
    "run_time_2",
    "run_time_3",
    "run_time_4",
    "run_time_5",
    "run_time_6",
    "run_time_7",
    "run_time_8",
    "executable_filename",
    "prefetch_hash",
    "run_count",
    "format_version",
    "volume_device_path",
    "volume_serial_number",
    "volume_creation_time",
    "_status",
    "_error",
    "_source_file",
];
pub const LOADED_FIELD_ORDER: &[&str] = &[
    "executable_filename",
    "prefetch_hash",
    "loaded_filename",
    "file_reference",
    "_source_file",
];

const RUN_TIME_COLS: &[&str] = &[
    "last_run_time",
    "run_time_2",
    "run_time_3",
    "run_time_4",
    "run_time_5",
    "run_time_6",
    "run_time_7",
    "run_time_8",
];

/// FILETIME (100 ns since 1601) -> KST display; "" for 0/unset.
fn fmt(ft: i64) -> String {
    if ft == 0 {
        String::new()
    } else {
        fmt_filetime(ft)
    }
}

fn parse_one(path: &Path, exec_rows: &mut Vec<Row>, loaded_rows: &mut Vec<Row>) -> Result<()> {
    let source = path.to_string_lossy().to_string();
    let raw = std::fs::read(path)?;
    // Decompress first so we can also read the header hash the crate omits.
    let scca = prefetch_core::decompress(&raw).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let info = prefetch_core::parse_decompressed(&scca).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    // Prefetch hash: u32 LE at SCCA header offset 0x4C (right after the 60-byte
    // executable-name field), formatted as 8 uppercase hex — matches pyscca's
    // get_prefetch_hash().
    let prefetch_hash = if scca.len() >= 80 {
        format!(
            "{:08X}",
            u32::from_le_bytes([scca[76], scca[77], scca[78], scca[79]])
        )
    } else {
        String::new()
    };

    let executable = info.executable.clone();
    let mut times = info.last_run_times.clone();
    times.resize(8, 0);

    let mut row = Row::new();
    for (i, col) in RUN_TIME_COLS.iter().enumerate() {
        row.insert((*col).to_string(), fmt(times[i]));
    }
    row.insert("executable_filename".into(), executable.clone());
    row.insert("prefetch_hash".into(), prefetch_hash.clone());
    row.insert("run_count".into(), info.run_count.to_string());
    row.insert("format_version".into(), info.version.to_string());
    let (dev, serial, vct) = match info.volumes.first() {
        Some(v) => (
            v.device_path.clone(),
            format!("{:08X}", v.serial),
            fmt(v.creation_time),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    row.insert("volume_device_path".into(), dev);
    row.insert("volume_serial_number".into(), serial);
    row.insert("volume_creation_time".into(), vct);
    row.insert("_status".into(), "ok".into());
    row.insert("_error".into(), String::new());
    row.insert("_source_file".into(), source.clone());
    exec_rows.push(row);

    for fname in &info.filenames {
        let mut lr = Row::new();
        lr.insert("executable_filename".into(), executable.clone());
        lr.insert("prefetch_hash".into(), prefetch_hash.clone());
        lr.insert("loaded_filename".into(), fname.clone());
        lr.insert("file_reference".into(), String::new()); // not exposed by prefetch-core
        lr.insert("_source_file".into(), source.clone());
        loaded_rows.push(lr);
    }
    Ok(())
}

/// Returns (execution_rows, loaded_file_rows).
pub fn parse_prefetch(paths: &[PathBuf]) -> (Vec<Row>, Vec<Row>) {
    let mut exec_rows = Vec::new();
    let mut loaded_rows = Vec::new();
    for path in paths {
        if let Err(e) = parse_one(path, &mut exec_rows, &mut loaded_rows) {
            let mut row = Row::new();
            row.insert("last_run_time".into(), String::new());
            row.insert("_status".into(), "corrupted".into());
            row.insert("_error".into(), e.to_string());
            row.insert("_source_file".into(), path.to_string_lossy().to_string());
            exec_rows.push(row);
        }
    }
    (exec_rows, loaded_rows)
}
