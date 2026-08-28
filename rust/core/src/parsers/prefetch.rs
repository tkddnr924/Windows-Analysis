//! Windows Prefetch (.pf) parser — port of parsers/prefetch_parser.py, which
//! uses pyscca (libscca). Here `prefetch-core` provides the MAM/Xpress-Huffman
//! decompression + SCCA v30/31 parsing (run count, last-8 run times, volume
//! info, loaded filenames); the prefetch hash is read from the decompressed
//! SCCA header (offset 0x4C) since the crate doesn't surface it.
//!
//! Version dispatch: v30/31 (Win10/11, MAM 압축) is handled by `prefetch-core`;
//! v17/23/26 (XP/Vista/7/8.1) are UNCOMPRESSED SCCA files parsed by the
//! in-house `parse_legacy_scca` below (fixed offsets per libscca docs).
//! `prefetch-core` does not expose per-file MFT references, so
//! `Prefetch_LoadedFiles.file_reference` is left blank.
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

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .and_then(|x| x.try_into().ok())
        .map(u32::from_le_bytes)
}
fn i64le(b: &[u8], off: usize) -> Option<i64> {
    b.get(off..off + 8)
        .and_then(|x| x.try_into().ok())
        .map(i64::from_le_bytes)
}
/// UTF-16LE, 널 종료(널이 없으면 범위 끝까지).
fn utf16z(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

struct LegacyPrefetch {
    version: u32,
    executable: String,
    hash: String,
    run_times: Vec<i64>,
    run_count: u32,
    filenames: Vec<String>,
    volume: Option<(String, u32, i64)>, // (device_path, serial, creation_time)
}

/// 비압축 SCCA v17(XP)/v23(Vista·7)/v26(8·8.1) 파서 — libscca 문서의 고정
/// 오프셋 그대로. Win10/11(v30/31)은 MAM 압축이라 prefetch-core가 담당한다.
fn parse_legacy_scca(data: &[u8]) -> Result<LegacyPrefetch> {
    if data.len() < 0x9C || &data[4..8] != b"SCCA" {
        anyhow::bail!("not an uncompressed SCCA prefetch");
    }
    let version = u32le(data, 0).unwrap_or(0);
    // (마지막 실행 시각 오프셋, 시각 개수, 실행 횟수 오프셋)
    let (times_off, times_n, count_off) = match version {
        17 => (0x78usize, 1usize, 0x90usize),
        23 => (0x80, 1, 0x98),
        26 => (0x80, 8, 0xD0),
        other => anyhow::bail!("unsupported SCCA version {other}"),
    };
    let executable = utf16z(&data[0x10..0x4C.min(data.len())]);
    let hash = u32le(data, 0x4C)
        .map(|h| format!("{:08X}", h))
        .unwrap_or_default();
    let mut run_times = Vec::with_capacity(times_n);
    for i in 0..times_n {
        run_times.push(i64le(data, times_off + i * 8).unwrap_or(0));
    }
    let run_count = u32le(data, count_off).unwrap_or(0);

    // 로드 파일 문자열: [offset, offset+size) 구간의 UTF-16LE 널 종료 나열.
    let mut filenames = Vec::new();
    let fn_off = u32le(data, 0x64).unwrap_or(0) as usize;
    let fn_size = u32le(data, 0x68).unwrap_or(0) as usize;
    if fn_off > 0 && fn_off < data.len() {
        let end = fn_off.saturating_add(fn_size).min(data.len());
        let mut units = Vec::new();
        for c in data[fn_off..end].chunks_exact(2) {
            let u = u16::from_le_bytes([c[0], c[1]]);
            if u == 0 {
                if !units.is_empty() {
                    filenames.push(String::from_utf16_lossy(&units));
                    units.clear();
                }
            } else {
                units.push(u);
            }
        }
        if !units.is_empty() {
            filenames.push(String::from_utf16_lossy(&units));
        }
    }

    // 볼륨 정보(첫 볼륨만 — 실행 행 스키마가 하나만 담는다).
    // 엔트리: devpath offset(볼륨 섹션 기준)@0, 문자 수@4, 생성 FILETIME@8,
    // 시리얼@0x10. v17 엔트리 40바이트, v23/26 104바이트(선두 배치는 동일).
    let mut volume = None;
    let vol_off = u32le(data, 0x6C).unwrap_or(0) as usize;
    let vol_n = u32le(data, 0x70).unwrap_or(0) as usize;
    if vol_n > 0 && vol_off > 0 && vol_off + 0x14 <= data.len() {
        let dev_rel = u32le(data, vol_off).unwrap_or(0) as usize;
        let dev_chars = u32le(data, vol_off + 4).unwrap_or(0) as usize;
        let creation = i64le(data, vol_off + 8).unwrap_or(0);
        let serial = u32le(data, vol_off + 0x10).unwrap_or(0);
        let dev_start = vol_off.saturating_add(dev_rel);
        let dev_end = dev_start.saturating_add(dev_chars * 2).min(data.len());
        let device_path = if dev_start < dev_end {
            utf16z(&data[dev_start..dev_end])
        } else {
            String::new()
        };
        volume = Some((device_path, serial, creation));
    }

    Ok(LegacyPrefetch {
        version,
        executable,
        hash,
        run_times,
        run_count,
        filenames,
        volume,
    })
}

fn parse_one(path: &Path, exec_rows: &mut Vec<Row>, loaded_rows: &mut Vec<Row>) -> Result<()> {
    let source = path.to_string_lossy().to_string();
    let raw = std::fs::read(path)?;

    // 비압축 SCCA면 버전으로 분기 — v17/23/26은 직접 구현한 파서를 쓴다.
    if raw.len() >= 8 && &raw[4..8] == b"SCCA" && matches!(u32le(&raw, 0).unwrap_or(0), 17 | 23 | 26)
    {
        {
            let legacy = parse_legacy_scca(&raw)?;
            let mut times = legacy.run_times.clone();
            times.resize(8, 0);
            let mut row = Row::new();
            for (i, col) in RUN_TIME_COLS.iter().enumerate() {
                row.insert((*col).to_string(), fmt(times[i]));
            }
            row.insert("executable_filename".into(), legacy.executable.clone());
            row.insert("prefetch_hash".into(), legacy.hash.clone());
            row.insert("run_count".into(), legacy.run_count.to_string());
            row.insert("format_version".into(), legacy.version.to_string());
            let (dev, serial, vct) = match &legacy.volume {
                Some((path, serial, creation)) => {
                    (path.clone(), format!("{:08X}", serial), fmt(*creation))
                }
                None => (String::new(), String::new(), String::new()),
            };
            row.insert("volume_device_path".into(), dev);
            row.insert("volume_serial_number".into(), serial);
            row.insert("volume_creation_time".into(), vct);
            row.insert("_status".into(), "ok".into());
            row.insert("_error".into(), String::new());
            row.insert("_source_file".into(), source.clone());
            exec_rows.push(row);
            for fname in &legacy.filenames {
                let mut lr = Row::new();
                lr.insert("executable_filename".into(), legacy.executable.clone());
                lr.insert("prefetch_hash".into(), legacy.hash.clone());
                lr.insert("loaded_filename".into(), fname.clone());
                lr.insert("file_reference".into(), String::new());
                lr.insert("_source_file".into(), source.clone());
                loaded_rows.push(lr);
            }
            return Ok(());
        }
    }

    // Win10/11 (v30/31, MAM 압축): 기존 prefetch-core 경로 그대로.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_i64(b: &mut [u8], off: usize, v: i64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_utf16(b: &mut [u8], off: usize, s: &str) {
        let mut pos = off;
        for u in s.encode_utf16() {
            b[pos..pos + 2].copy_from_slice(&u.to_le_bytes());
            pos += 2;
        }
    }

    fn synthetic(version: u32, times_off: usize, count_off: usize) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        put_u32(&mut b, 0, version);
        b[4..8].copy_from_slice(b"SCCA");
        put_utf16(&mut b, 0x10, "CALC.EXE");
        put_u32(&mut b, 0x4C, 0x7057_100A);
        // filename strings: two null-terminated UTF-16 entries at 0x100
        put_utf16(&mut b, 0x100, "\\WINDOWS\\CALC.EXE");
        put_utf16(&mut b, 0x130, "\\WINDOWS\\NTDLL.DLL");
        put_u32(&mut b, 0x64, 0x100);
        put_u32(&mut b, 0x68, 0x60);
        // one volume at 0x180: device path at +0x28, 2 chars, serial DEADBEEF
        put_u32(&mut b, 0x6C, 0x180);
        put_u32(&mut b, 0x70, 1);
        put_u32(&mut b, 0x180, 0x28);
        put_u32(&mut b, 0x184, 2);
        put_i64(&mut b, 0x188, 130_000_000_000_000_000);
        put_u32(&mut b, 0x190, 0xDEAD_BEEF);
        put_utf16(&mut b, 0x1A8, "C:");
        put_i64(&mut b, times_off, 131_500_000_000_000_000);
        put_u32(&mut b, count_off, 5);
        b
    }

    #[test]
    fn legacy_scca_v17_and_v26_parse_with_correct_offsets() {
        let v17 = parse_legacy_scca(&synthetic(17, 0x78, 0x90)).unwrap();
        assert_eq!(v17.version, 17);
        assert_eq!(v17.executable, "CALC.EXE");
        assert_eq!(v17.hash, "7057100A");
        assert_eq!(v17.run_count, 5);
        assert_eq!(v17.run_times.len(), 1);
        assert!(v17.run_times[0] > 0);
        assert_eq!(
            v17.filenames,
            vec!["\\WINDOWS\\CALC.EXE".to_string(), "\\WINDOWS\\NTDLL.DLL".to_string()]
        );
        let (device, serial, creation) = v17.volume.expect("volume");
        assert_eq!(device, "C:");
        assert_eq!(format!("{:08X}", serial), "DEADBEEF");
        assert!(creation > 0);

        let v26 = parse_legacy_scca(&synthetic(26, 0x80, 0xD0)).unwrap();
        assert_eq!(v26.version, 26);
        assert_eq!(v26.run_times.len(), 8);
        assert!(v26.run_times[0] > 0);
        assert_eq!(v26.run_count, 5);
    }

    #[test]
    fn compressed_or_unknown_versions_are_not_claimed_by_the_legacy_parser() {
        assert!(parse_legacy_scca(b"MAM\x04short").is_err());
        let v30 = synthetic(30, 0x80, 0xD0);
        assert!(parse_legacy_scca(&v30).is_err());
    }
}
