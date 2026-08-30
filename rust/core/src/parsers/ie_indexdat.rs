//! IE5~9 index.dat 파서 ("Client UrlCache MMF Ver 5.2", XP/Vista/Win7).
//! History.IE5/Content.IE5/Cookies의 URL/LEAK/REDR 레코드를 0x80 블록 단위로
//! 스캔해 IEIndexDat_Records 행으로 낸다. 해시 테이블은 신뢰하지 않고 레코드
//! 시그니처를 직접 훑는다(손상 파일에서도 살아남는 레코드를 회수).
//!
//! 주의: History.IE5 일별 컨테이너(MSHist01…)의 FILETIME은 로컬 시간으로
//! 저장되는 것으로 알려져 있으나, 여기서는 원시 FILETIME을 UTC로 간주해
//! 일괄 표기한다 — 컨테이너별 시간대 보정은 범위 밖(T2 문서 참조).
use std::path::Path;

use anyhow::Result;

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const TABLE: &str = "IEIndexDat_Records";
pub const FIELD_ORDER: &[&str] = &[
    "record_type",
    "accessed_time",
    "modified_time",
    "hits",
    "url",
    "filename",
    "container",
    "account",
    "_source_file",
];

const MAGIC_52: &[u8] = b"Client UrlCache MMF Ver 5.2\0";
const BLOCK: usize = 0x80;
/// URL/LEAK 레코드(v5.2)의 고정부 오프셋 — libmsiecf 문서 준거.
const OFF_MODIFIED: usize = 0x08; // FILETIME
const OFF_ACCESSED: usize = 0x10; // FILETIME
const OFF_URL: usize = 0x34; // u32, 레코드 기준 상대 오프셋
const OFF_FILENAME: usize = 0x3C; // u32, 레코드 기준 상대 오프셋
const OFF_HITS: usize = 0x54; // u32
const OFF_REDR_URL: usize = 0x10; // REDR: URL 문자열 시작

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn le_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// 레코드 내 NUL 종료 ASCII/CP1252 문자열 (URL·캐시 파일명은 ASCII 저장).
fn zstring(rec: &[u8], off: usize) -> String {
    if off == 0 || off >= rec.len() {
        return String::new();
    }
    let end = rec[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(rec.len());
    String::from_utf8_lossy(&rec[off..end]).into_owned()
}

fn ft(ticks: Option<u64>) -> String {
    match ticks {
        Some(t) if t > 0 && t <= i64::MAX as u64 => fmt_filetime(t as i64),
        _ => String::new(),
    }
}

/// 경로에서 컨테이너 라벨: MSHist… 폴더(일별/주별 히스토리)면 그 폴더명,
/// 아니면 History.IE5/Content.IE5/Cookies 중 일치하는 상위 폴더명.
fn container_label(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if let Some(parent) = parts.iter().rev().nth(1) {
        if parent.to_ascii_lowercase().starts_with("mshist") {
            return parent.clone();
        }
    }
    for part in parts.iter().rev() {
        let lower = part.to_ascii_lowercase();
        if lower == "history.ie5" || lower == "content.ie5" || lower == "cookies" {
            return part.clone();
        }
    }
    path.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// index.dat 하나를 파싱해 레코드 행을 콜백으로 스트리밍한다. 반환: 행 수.
/// v5.2가 아닌 매직(4.7 등)은 레이아웃 오독 위험이 있어 명시 오류로 격리한다
/// (T0 원칙 — 조용한 공백 금지).
///
/// 파일 전체를 메모리에 올리지 않는다 — 0x80 블록 정렬을 유지한 채 청크로
/// 읽고, 청크 끝에 걸친 레코드(최대 512블록 = 64KiB)는 이월해 다음 청크에서
/// 온전히 처리한다.
pub fn parse_index_dat(
    path: &Path,
    account: &str,
    push: &mut dyn FnMut(Row) -> Result<()>,
) -> Result<usize> {
    use std::io::Read;
    const CHUNK: usize = 4 * 1024 * 1024;
    const MAX_REC: usize = 512 * BLOCK;
    let mut file = std::fs::File::open(path)?;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + MAX_REC);
    let mut fill = |buf: &mut Vec<u8>| -> Result<bool> {
        let carry = buf.len();
        buf.resize(carry + CHUNK, 0);
        let mut filled = carry;
        loop {
            let read = file.read(&mut buf[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
            if filled == buf.len() {
                break;
            }
        }
        buf.truncate(filled);
        Ok(filled < carry + CHUNK)
    };
    let mut eof = fill(&mut buf)?;
    if !buf.starts_with(MAGIC_52) {
        let head = String::from_utf8_lossy(&buf[..buf.len().min(24)]).into_owned();
        anyhow::bail!("unsupported index.dat format (v5.2 아님): {head:?}");
    }
    let source = path.to_string_lossy().to_string();
    let container = container_label(path);
    let mut n = 0usize;
    let mut off = BLOCK;
    loop {
        while off + 8 <= buf.len() {
            if crate::pipeline::cancelled() {
                return Ok(n);
            }
            let data: &[u8] = &buf;
            let sig = &data[off..off + 4];
            let record_type = match sig {
                b"URL " => "URL",
                b"LEAK" => "LEAK",
                b"REDR" => "REDR",
                _ => {
                    off += BLOCK;
                    continue;
                }
            };
            let nblocks = le_u32(data, off + 4).unwrap_or(0) as usize;
            if nblocks == 0 || nblocks > 512 {
                off += BLOCK;
                continue;
            }
            if !eof && off + nblocks * BLOCK > data.len() {
                // 레코드가 청크 끝에 걸침 — 이월해 다음 청크에서 처리.
                break;
            }
            let rec_end = (off + nblocks * BLOCK).min(data.len());
            let rec = &data[off..rec_end];

        let mut row = Row::new();
        row.insert("record_type".into(), record_type.into());
        row.insert("container".into(), container.clone());
        row.insert("account".into(), account.to_string());
        row.insert("_source_file".into(), source.clone());
        let url = if record_type == "REDR" {
            zstring(rec, OFF_REDR_URL)
        } else {
            row.insert("modified_time".into(), ft(le_u64(rec, OFF_MODIFIED)));
            row.insert("accessed_time".into(), ft(le_u64(rec, OFF_ACCESSED)));
            row.insert(
                "hits".into(),
                le_u32(rec, OFF_HITS)
                    .map(|h| h.to_string())
                    .unwrap_or_default(),
            );
            let url_off = le_u32(rec, OFF_URL).unwrap_or(0) as usize;
            let fn_off = le_u32(rec, OFF_FILENAME).unwrap_or(0) as usize;
            row.insert("filename".into(), zstring(rec, fn_off));
            zstring(rec, url_off)
        };
            if url.is_empty() {
                // URL 없는 항목(빈 슬롯/부분 덮어쓰기)은 증거 가치가 없다 — skip.
                off += nblocks * BLOCK;
                continue;
            }
            row.insert("url".into(), url);
            push(row)?;
            n += 1;
            off += nblocks * BLOCK;
        }
        if eof {
            return Ok(n);
        }
        // 남은 꼬리(진행 중 오프셋 이후)를 앞으로 옮기고 다음 청크를 채운다 —
        // off는 항상 0x80의 배수라 블록 정렬이 유지된다.
        buf.copy_within(off.., 0);
        buf.truncate(buf.len() - off);
        off = 0;
        eof = fill(&mut buf)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// 합성 index.dat: 헤더(매직) + URL 레코드(2블록) + REDR 레코드(1블록).
    fn synthetic() -> Vec<u8> {
        let mut b = vec![0u8; BLOCK * 6];
        b[..MAGIC_52.len()].copy_from_slice(MAGIC_52);

        let r = BLOCK; // URL record, 2 blocks
        b[r..r + 4].copy_from_slice(b"URL ");
        put_u32(&mut b, r + 4, 2);
        put_u64(&mut b, r + OFF_MODIFIED, 129_600_000_000_000_000);
        put_u64(&mut b, r + OFF_ACCESSED, 129_600_000_000_000_001);
        put_u32(&mut b, r + OFF_URL, 0x68);
        put_u32(&mut b, r + OFF_FILENAME, 0x90);
        put_u32(&mut b, r + OFF_HITS, 7);
        let url = b"Visited: tester@http://example.com/a";
        b[r + 0x68..r + 0x68 + url.len()].copy_from_slice(url);
        let fname = b"cached[1].htm";
        b[r + 0x90..r + 0x90 + fname.len()].copy_from_slice(fname);

        let r2 = BLOCK * 3; // REDR record, 1 block
        b[r2..r2 + 4].copy_from_slice(b"REDR");
        put_u32(&mut b, r2 + 4, 1);
        let redr = b"http://redirect.example.com/";
        b[r2 + OFF_REDR_URL..r2 + OFF_REDR_URL + redr.len()].copy_from_slice(redr);
        b
    }

    #[test]
    fn parses_url_and_redr_records() {
        let dir = std::env::temp_dir().join(format!(
            "wina-indexdat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(dir.join("History.IE5")).unwrap();
        let file = dir.join("History.IE5").join("index.dat");
        std::fs::write(&file, synthetic()).unwrap();

        let mut rows: Vec<Row> = Vec::new();
        let count = parse_index_dat(&file, "tester", &mut |r| {
            rows.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
        let url_row = &rows[0];
        assert_eq!(url_row.get("record_type").map(String::as_str), Some("URL"));
        assert_eq!(
            url_row.get("url").map(String::as_str),
            Some("Visited: tester@http://example.com/a")
        );
        assert_eq!(url_row.get("filename").map(String::as_str), Some("cached[1].htm"));
        assert_eq!(url_row.get("hits").map(String::as_str), Some("7"));
        assert_eq!(url_row.get("container").map(String::as_str), Some("History.IE5"));
        assert!(!url_row.get("accessed_time").unwrap().is_empty());
        let redr_row = &rows[1];
        assert_eq!(redr_row.get("record_type").map(String::as_str), Some("REDR"));
        assert_eq!(
            redr_row.get("url").map(String::as_str),
            Some("http://redirect.example.com/")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn non_v52_magic_is_an_explicit_error() {
        let dir = std::env::temp_dir().join(format!(
            "wina-indexdat-47-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("index.dat");
        std::fs::write(&file, b"Client UrlCache MMF Ver 4.7\0rest").unwrap();
        let err = parse_index_dat(&file, "a", &mut |_| Ok(())).unwrap_err();
        assert!(err.to_string().contains("unsupported index.dat"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mshist_daily_container_label_uses_folder_name() {
        let p = PathBuf::from("/x/History.IE5/MSHist012026083020260831/index.dat");
        assert_eq!(container_label(&p), "MSHist012026083020260831");
        let c = PathBuf::from("/x/Content.IE5/index.dat");
        assert_eq!(container_label(&c), "Content.IE5");
    }
}
