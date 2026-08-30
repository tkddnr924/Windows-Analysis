//! IE10+/레거시 Edge WebCacheV01.dat (ESE) 파서 — SRUM과 동일한 libesedb
//! (libyal FFI, pyesedb와 같은 엔진)로 읽는다. Containers 마스터 테이블에서
//! 방문 기록(History/MSHist…)과 다운로드(iedownload) 컨테이너를 분류해 각
//! Container_<id> 테이블을 IEWebCache_History / IEWebCache_Downloads 행으로
//! 낸다. Content·Cookies·DOMStore 등 나머지 컨테이너는 1차 범위 밖
//! (agent/func/legacy_windows_support_tasks.md T2 참조).
use std::path::Path;

use anyhow::Result;
use libesedb::{EseDb, Value};

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const HISTORY_TABLE: &str = "IEWebCache_History";
pub const DOWNLOADS_TABLE: &str = "IEWebCache_Downloads";
pub const HISTORY_FIELD_ORDER: &[&str] = &[
    "accessed_time",
    "modified_time",
    "expiry_time",
    "access_count",
    "url",
    "container",
    "account",
    "_source_file",
];
pub const DOWNLOADS_FIELD_ORDER: &[&str] = &[
    "accessed_time",
    "modified_time",
    "url",
    "metadata",
    "container",
    "account",
    "_source_file",
];

/// 수집 경로에서 계정명 추정. 수집기 배치(BROWSER/<계정>/…)를 우선하고,
/// 원본 이미지 경로(Users\<계정>, Documents and Settings\<계정>)로 폴백,
/// 마지막엔 부모 폴더명.
pub fn ie_account(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("BROWSER") && i + 1 < parts.len() {
            return parts[i + 1].clone();
        }
    }
    for (i, part) in parts.iter().enumerate() {
        if (part.eq_ignore_ascii_case("Users") || part.eq_ignore_ascii_case("Documents and Settings"))
            && i + 1 < parts.len()
        {
            return parts[i + 1].clone();
        }
    }
    path.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "ie".into())
}

/// 텍스트 값 렌더 — long value(행 밖 저장)는 전용 API로 실제 내용을 가져온다
/// (srum.rs의 render_record_value와 같은 이유).
fn value_text(rec: &libesedb::Record, entry: i32, v: &Value) -> String {
    match v {
        Value::Text(s) | Value::LargeText(s) => s.trim_end_matches('\u{0}').to_string(),
        Value::Long => match rec.long(entry) {
            Ok(lv) => lv
                .utf8()
                .map(|s| s.trim_end_matches('\u{0}').to_string())
                .unwrap_or_default(),
            Err(_) => String::new(),
        },
        _ => String::new(),
    }
}

fn value_bytes(rec: &libesedb::Record, entry: i32, v: &Value) -> Vec<u8> {
    match v {
        Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) => b.clone(),
        Value::Long => match rec.long(entry) {
            Ok(lv) => lv.vec().unwrap_or_default(),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// FILETIME 정수 컬럼 → KST 표기. 0/음수/없음은 빈 값.
fn ft(ticks: Option<i64>) -> String {
    match ticks {
        Some(t) if t > 0 => fmt_filetime(t),
        _ => String::new(),
    }
}

/// 바이너리 블롭에서 UTF-16LE 출력 가능 문자열(min_chars 이상)을 추출한다 —
/// iedownload 컨테이너의 ResponseHeaders 블롭에 저장 경로·원본 URL 등이
/// UTF-16 문자열로 들어 있다(구조 문서화가 불충분해 문자열 추출로 대신한다).
fn utf16_strings(blob: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    for c in blob.chunks_exact(2) {
        let u = u16::from_le_bytes([c[0], c[1]]);
        if u >= 0x20 && u != 0x7F && u < 0xFFFE {
            cur.push(u);
        } else {
            if cur.len() >= min_chars {
                out.push(String::from_utf16_lossy(&cur));
            }
            cur.clear();
        }
    }
    if cur.len() >= min_chars {
        out.push(String::from_utf16_lossy(&cur));
    }
    out
}

pub struct WebCacheCounts {
    pub history: usize,
    pub downloads: usize,
}

/// 스트리밍 이벤트 — 방문 기록 컨테이너를 전부 처리한 뒤에야 다운로드 행이
/// 나온다(컨테이너 2단계 순회 보장). 호출자는 이 순서 보장 덕에 같은 SQLite
/// 파일에 writer를 순차로 열어 다운로드도 스트리밍 기록할 수 있다 — 다운로드
/// 행을 메모리 배열에 모으지 않는다.
pub enum WebCacheEvent {
    History(Row),
    Download(Row),
}

/// WebCacheV##.dat 하나를 파싱해 방문 기록/다운로드 행을 콜백으로 스트리밍한다.
/// 손상·dirty ESE는 open 단계에서 Err — 파이프라인이 해당 파일만 격리한다.
pub fn parse_webcache(
    path: &Path,
    account: &str,
    sink: &mut dyn FnMut(WebCacheEvent) -> Result<()>,
) -> Result<WebCacheCounts> {
    let source = path.to_string_lossy().to_string();
    let db = EseDb::open(path).map_err(|e| {
        anyhow::anyhow!(
            "WebCache ESE open failed (dirty shutdown이면 esentutl /r 필요). Original error: {}",
            e
        )
    })?;

    // Containers 마스터 테이블에서 대상 컨테이너(id, 이름, 다운로드 여부) 분류.
    let containers = db
        .table_by_name("Containers")
        .map_err(|e| anyhow::anyhow!("Containers table missing: {}", e))?;
    let cols: Vec<String> = containers
        .iter_columns()?
        .filter_map(|c| c.ok())
        .filter_map(|c| c.name().ok())
        .collect();
    let idx_of = |n: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(n)).map(|i| i as i32);
    let (id_i, name_i) = match (idx_of("ContainerId"), idx_of("Name")) {
        (Some(a), Some(b)) => (a, b),
        _ => anyhow::bail!("Containers schema unexpected: {:?}", cols),
    };
    let mut targets: Vec<(i64, String, bool)> = Vec::new();
    for rec in containers.iter_records()?.filter_map(|r| r.ok()) {
        let id = rec.value(id_i).ok().and_then(|v| v.to_i64());
        let name = rec
            .value(name_i)
            .ok()
            .map(|v| value_text(&rec, name_i, &v))
            .unwrap_or_default();
        let name = name.trim_matches('\u{0}').trim().to_string();
        let lower = name.to_ascii_lowercase();
        let is_history = lower == "history" || lower.starts_with("mshist");
        let is_download = lower == "iedownload";
        if let (Some(id), true) = (id, is_history || is_download) {
            targets.push((id, name, is_download));
        }
    }

    let mut counts = WebCacheCounts {
        history: 0,
        downloads: 0,
    };
    // 방문 기록 컨테이너 → 다운로드 컨테이너 2단계 순회 — 이벤트 순서 보장의
    // 근거다 (WebCacheEvent 문서 참조).
    targets.sort_by_key(|(_, _, is_download)| *is_download);
    for (id, container_name, is_download) in targets {
        if crate::pipeline::cancelled() {
            break;
        }
        // 컨테이너 행은 있는데 테이블이 없을 수 있다(정리된 컨테이너) — skip.
        let table = match db.table_by_name(&format!("Container_{id}")) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let tcols: Vec<String> = table
            .iter_columns()?
            .filter_map(|c| c.ok())
            .filter_map(|c| c.name().ok())
            .collect();
        let ci = |n: &str| {
            tcols
                .iter()
                .position(|c| c.eq_ignore_ascii_case(n))
                .map(|i| i as i32)
        };
        let url_i = ci("Url");
        let acc_i = ci("AccessedTime");
        let mod_i = ci("ModifiedTime");
        let exp_i = ci("ExpiryTime");
        let cnt_i = ci("AccessCount");
        let hdr_i = ci("ResponseHeaders");
        let url_i = match url_i {
            Some(i) => i,
            None => continue,
        };
        for rec in table.iter_records()?.filter_map(|r| r.ok()) {
            if crate::pipeline::cancelled() {
                break;
            }
            let url = match rec.value(url_i) {
                Ok(v) => value_text(&rec, url_i, &v),
                Err(_) => String::new(),
            };
            if url.is_empty() {
                continue;
            }
            let get_int = |i: Option<i32>| -> Option<i64> {
                i.and_then(|i| rec.value(i).ok()).and_then(|v| v.to_i64())
            };
            let mut row = Row::new();
            row.insert("accessed_time".into(), ft(get_int(acc_i)));
            row.insert("modified_time".into(), ft(get_int(mod_i)));
            row.insert("url".into(), url);
            row.insert("container".into(), container_name.clone());
            row.insert("account".into(), account.to_string());
            row.insert("_source_file".into(), source.clone());
            if is_download {
                let metadata = match hdr_i.and_then(|i| rec.value(i).ok().map(|v| (i, v))) {
                    Some((i, v)) => utf16_strings(&value_bytes(&rec, i, &v), 5).join(" | "),
                    None => String::new(),
                };
                row.insert("metadata".into(), metadata);
                sink(WebCacheEvent::Download(row))?;
                counts.downloads += 1;
            } else {
                row.insert("expiry_time".into(), ft(get_int(exp_i)));
                row.insert(
                    "access_count".into(),
                    get_int(cnt_i).map(|x| x.to_string()).unwrap_or_default(),
                );
                sink(WebCacheEvent::History(row))?;
                counts.history += 1;
            }
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn account_extraction_prefers_collector_layout_then_users() {
        let collected = PathBuf::from("/case/BROWSER/Administrator/IE/WebCacheV01.dat");
        assert_eq!(ie_account(&collected), "Administrator");
        let image = PathBuf::from(
            "/mnt/c/Users/tester/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
        );
        assert_eq!(ie_account(&image), "tester");
        let xp = PathBuf::from("/mnt/c/Documents and Settings/old/Local Settings/index.dat");
        assert_eq!(ie_account(&xp), "old");
        let bare = PathBuf::from("/tmp/WebCache/WebCacheV01.dat");
        assert_eq!(ie_account(&bare), "WebCache");
    }

    #[test]
    fn utf16_string_extraction_finds_paths_in_binary_blob() {
        let mut blob = vec![0u8, 0, 1, 0];
        blob.extend("C:\\Users\\a\\Downloads\\x.exe".encode_utf16().flat_map(u16::to_le_bytes));
        blob.extend([0u8, 0, 9, 0]);
        blob.extend("ab".encode_utf16().flat_map(u16::to_le_bytes)); // 너무 짧음 — 제외
        blob.extend([0u8, 0]);
        let found = utf16_strings(&blob, 5);
        assert_eq!(found, vec!["C:\\Users\\a\\Downloads\\x.exe".to_string()]);
    }
}
