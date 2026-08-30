//! WMI Repository (OBJECTS.DATA) 영속성 파서. 전체 CIM 파싱 없이
//! __EventFilter / __EventConsumer 계열 / __FilterToConsumerBinding 세 클래스의
//! 인스턴스만 시그니처 스캔으로 추출한다 (PyWMIPersistenceFinder 방식).
//! WMI 이벤트 구독은 레지스트리 Run 키·예약작업 어디에도 남지 않는 영속성
//! 통로라 별도 테이블로 낸다. 산출량이 적어 findings 형태에 적합.
//!
//! 판별 규칙 (실수집본으로 확인):
//! - 클래스 정의(스키마)는 `클래스명\0\0속성명` 뒤에 CIM 타입 토큰
//!   ("string"/"uint32"/"boolean"…)이 따라온다 → 건너뜀.
//! - 인스턴스는 클래스명 뒤 바이너리 헤더 다음에 실제 값 문자열이 온다.
//! - 각 레코드 끝에는 UTF-16 16진 해시(널 사이 1글자 토큰 연속)가 붙는다 —
//!   이를 레코드 경계로 삼아 이웃 레코드로의 오염을 막는다.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::finder;
use crate::sqlite::Row;

pub const WMI_TABLE: &str = "WMI_Persistence";
pub const WMI_FIELD_ORDER: &[&str] = &[
    "kind",
    "name",
    "consumer_type",
    "filter_name",
    "consumer_name",
    "query",
    "query_language",
    "namespace",
    "details",
    "_source_file",
];

/// 추적하는 표준 이벤트 컨슈머 클래스들.
const CONSUMER_CLASSES: &[&str] = &[
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "NTEventLogEventConsumer",
    "LogFileEventConsumer",
    "SMTPEventConsumer",
];

/// CIM 타입·한정자 토큰 — 클래스 정의(스키마·로캘 보정)에만 나타난다.
/// "description"은 정의의 한정자 이름: 로캘 보정 레코드는 뒤가 UTF-16이라
/// 이 토큰 하나만 남는 경우가 있어 (실수집본 확인) 반드시 포함한다.
const TYPE_TOKENS: &[&str] = &[
    "string", "uint8", "uint32", "uint64", "sint32", "boolean", "datetime", "AMENDMENT", "LOCALE",
    "NOT_NULL", "DEPRECATED", "description", "Description",
];

pub fn wmi_sources(target: &Path) -> finder::Found {
    finder::by_name(target, &["OBJECTS.DATA"])
}

/// `data[..search_end]`에서 시작하는 시그니처 위치만 찾는다 — 청크 경계에
/// 걸친 레코드는 다음 청크의 겹침 구간에서 온전한 창으로 다시 스캔되므로,
/// 경계 근처 시작점은 여기서 제외해 잘린 추출을 막는다.
fn find_all(data: &[u8], search_end: usize, sig: &[u8]) -> Vec<usize> {
    let end = search_end.min(data.len());
    let mut offs = Vec::new();
    let mut from = 0;
    while from + sig.len() <= end {
        match data[from..end].windows(sig.len()).position(|w| w == sig) {
            Some(rel) => {
                offs.push(from + rel);
                from += rel + 1;
            }
            None => break,
        }
    }
    offs
}

fn printable(token: &[u8]) -> bool {
    token.iter().all(|&b| (0x20..0x7f).contains(&b) || b == b'\t')
}

/// `start`부터 널 구분 ASCII 토큰을 모은다. 1글자 토큰이 8번 연속되면
/// 인스턴스 해시(레코드 끝)로 보고 중단한다. 바이너리 토큰은 건너뛴다.
fn tokens_from(data: &[u8], start: usize, window: usize) -> Vec<String> {
    let end = (start + window).min(data.len());
    let mut tokens = Vec::new();
    let mut i = start;
    let mut short_run = 0usize;
    while i < end && tokens.len() < 64 {
        // 다음 널까지가 한 토큰.
        let stop = data[i..end]
            .iter()
            .position(|&b| b == 0)
            .map(|p| i + p)
            .unwrap_or(end);
        let raw = &data[i..stop];
        i = stop + 1;
        if raw.is_empty() {
            continue;
        }
        if !printable(raw) {
            short_run = 0;
            continue;
        }
        if raw.len() == 1 {
            short_run += 1;
            if short_run >= 8 {
                break;
            }
            continue;
        }
        short_run = 0;
        tokens.push(String::from_utf8_lossy(raw).into_owned());
    }
    tokens
}

fn is_definition(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|t| TYPE_TOKENS.contains(&t.as_str()))
}

fn base_row(kind: &str, source: &str) -> Row {
    let mut row = Row::new();
    for field in WMI_FIELD_ORDER {
        row.insert((*field).into(), String::new());
    }
    row.insert("kind".into(), kind.into());
    row.insert("_source_file".into(), source.into());
    row
}

/// `<클래스명>.Name="<값>"` 패턴에서 (클래스명, 값)을 찾는다.
fn name_refs(window: &str, class_suffix: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let needle = format!("{class_suffix}.Name=\"");
    let mut from = 0;
    while let Some(rel) = window[from..].find(&needle) {
        let at = from + rel;
        // 앞쪽으로 클래스명(영숫자/밑줄) 확장.
        let head = &window[..at + class_suffix.len()];
        let start = head
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map(|p| p + 1)
            .unwrap_or(0);
        let class = head[start..].to_string();
        let value_at = at + needle.len();
        let value = window[value_at..]
            .split('"')
            .next()
            .unwrap_or("")
            .to_string();
        found.push((class, value));
        from = value_at;
    }
    found
}

fn scan_bindings(
    data: &[u8],
    search_end: usize,
    source: &str,
    push: &mut dyn FnMut(Row) -> Result<()>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    for off in find_all(data, search_end, b"__FilterToConsumerBinding\x00") {
        let end = (off + 1024).min(data.len());
        let window: String = data[off..end]
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '\0' })
            .collect();
        let consumers = name_refs(&window, "EventConsumer");
        let filters = name_refs(&window, "EventFilter");
        for (consumer_type, consumer_name) in &consumers {
            for (_, filter_name) in &filters {
                if consumer_name.is_empty() || filter_name.is_empty() {
                    continue;
                }
                let key = format!("B|{consumer_type}|{consumer_name}|{filter_name}");
                if !seen.insert(key) {
                    continue;
                }
                let mut row = base_row("바인딩", source);
                row.insert("name".into(), format!("{filter_name} → {consumer_name}"));
                row.insert("consumer_type".into(), consumer_type.clone());
                row.insert("consumer_name".into(), consumer_name.clone());
                row.insert("filter_name".into(), filter_name.clone());
                push(row)?;
            }
        }
    }
    Ok(())
}

fn scan_filters(
    data: &[u8],
    search_end: usize,
    source: &str,
    push: &mut dyn FnMut(Row) -> Result<()>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    for off in find_all(data, search_end, b"__EventFilter\x00") {
        let tokens = tokens_from(data, off + b"__EventFilter\x00".len(), 2048);
        if is_definition(&tokens) {
            continue;
        }
        // WQL 쿼리 토큰을 축으로 이름·네임스페이스·언어를 잡는다
        // (실데이터 순서: namespace, name, query, language).
        let Some(qi) = tokens
            .iter()
            .position(|t| t.trim_start().to_ascii_lowercase().starts_with("select"))
        else {
            continue;
        };
        let query = tokens[qi].clone();
        let name = if qi >= 1 { tokens[qi - 1].clone() } else { String::new() };
        let namespace = if qi >= 2 && tokens[qi - 2].to_ascii_lowercase().starts_with("root") {
            tokens[qi - 2].clone()
        } else {
            String::new()
        };
        let language = tokens
            .get(qi + 1)
            .filter(|t| t.len() <= 16)
            .cloned()
            .unwrap_or_default();
        let key = format!("F|{name}|{query}");
        if !seen.insert(key) {
            continue;
        }
        let mut row = base_row("이벤트 필터", source);
        row.insert("name".into(), name.clone());
        row.insert("filter_name".into(), name);
        row.insert("query".into(), query);
        row.insert("query_language".into(), language);
        row.insert("namespace".into(), namespace);
        push(row)?;
    }
    Ok(())
}

fn scan_consumers(
    data: &[u8],
    search_end: usize,
    source: &str,
    push: &mut dyn FnMut(Row) -> Result<()>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    for class in CONSUMER_CLASSES {
        let sig = format!("{class}\0");
        for off in find_all(data, search_end, sig.as_bytes()) {
            let tokens = tokens_from(data, off + sig.len(), 4096);
            if tokens.is_empty() || is_definition(&tokens) {
                continue;
            }
            // 컨슈머 "프로바이더 등록" 레코드 — 모든 시스템에 있는 표준
            // 등록 정보라 인스턴스가 아니다.
            if tokens[0].contains("__Win32Provider.Name=") {
                continue;
            }
            let name = tokens[0].chars().take(256).collect::<String>();
            let details = tokens[1..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" | ")
                .chars()
                .take(4000)
                .collect::<String>();
            let key = format!("C|{class}|{name}|{details}");
            if !seen.insert(key) {
                continue;
            }
            let mut row = base_row("이벤트 컨슈머", source);
            row.insert("name".into(), name.clone());
            row.insert("consumer_type".into(), (*class).into());
            row.insert("consumer_name".into(), name);
            row.insert("details".into(), details);
            push(row)?;
        }
    }
    Ok(())
}

/// 원본 파일 하나의 파싱 결과 — 읽기 실패가 "0건 성공"으로 보이지 않게
/// 사유를 파이프라인 보고서까지 가져간다.
pub struct WmiFileReport {
    pub path: PathBuf,
    pub rows: usize,
    pub error: Option<String>,
}

/// 청크 스캔 창 — 파일 전체를 메모리에 올리지 않는다. 겹침 구간은 시그니처
/// 최대 길이 + 레코드 창(4096) + 여유를 덮어, 경계에 걸친 레코드도 다음
/// 청크에서 온전히 추출된다 (중복은 내용 키 `seen`으로 제거).
const SCAN_CHUNK: usize = 4 * 1024 * 1024;
const SCAN_OVERLAP: usize = 8 * 1024;

/// 청크 스캔 콜백 — (버퍼, 시그니처 탐색 상한, 행 수신자).
type ChunkScan<'a> = &'a mut dyn FnMut(&[u8], usize, &mut dyn FnMut(Row) -> Result<()>) -> Result<()>;

/// 한 파일을 kind 하나에 대해 청크 단위로 스캔한다. kind별로 파일을 다시
/// 읽어(총 3회) "바인딩 → 필터 → 컨슈머" 표 순서를 유지한다.
fn scan_file_chunked(
    path: &Path,
    source: &str,
    scan: ChunkScan<'_>,
    push: &mut dyn FnMut(Row) -> Result<()>,
) -> std::result::Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + SCAN_OVERLAP);
    loop {
        let carry = buf.len();
        buf.resize(carry + SCAN_CHUNK, 0);
        let mut filled = carry;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..]).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        let eof = filled < carry + SCAN_CHUNK;
        // 경계에 걸친 시작점은 다음 청크의 겹침 구간에서 온전한 창으로 다시
        // 스캔된다 — 마지막 청크에서만 끝까지 탐색.
        let search_end = if eof {
            buf.len()
        } else {
            buf.len().saturating_sub(SCAN_OVERLAP)
        };
        scan(&buf, search_end, push).map_err(|e| e.to_string())?;
        let _ = source;
        if eof {
            return Ok(());
        }
        let keep_from = buf.len().saturating_sub(SCAN_OVERLAP);
        buf.copy_within(keep_from.., 0);
        buf.truncate(buf.len() - keep_from);
    }
}

/// 발견 행을 즉시 `push`로 넘긴다(스트리밍). 파일별 성공 행 수·실패 사유를
/// 반환해 파이프라인이 `parse_report.json`에 기록한다. 한 파일의 실패는 다른
/// 파일 파싱을 막지 않는다.
pub fn parse_wmi_stream(
    paths: &[PathBuf],
    push: &mut dyn FnMut(Row) -> Result<()>,
) -> Result<Vec<WmiFileReport>> {
    let mut reports = Vec::new();
    for path in paths {
        let source = path.to_string_lossy().into_owned();
        let mut seen = BTreeSet::new();
        let mut count = 0usize;
        let mut failed: Option<String> = None;
        // 바인딩 → 필터 → 컨슈머 순서로 쌓인다 (스캔 순서가 곧 표 순서).
        type ScanFn = fn(&[u8], usize, &str, &mut dyn FnMut(Row) -> Result<()>, &mut BTreeSet<String>) -> Result<()>;
        let passes: [ScanFn; 3] = [scan_bindings, scan_filters, scan_consumers];
        for pass in passes {
            let src = source.clone();
            let seen_ref = &mut seen;
            let counted = &mut count;
            let result = scan_file_chunked(
                path,
                &source,
                &mut |data, search_end, sink| pass(data, search_end, &src, sink, seen_ref),
                &mut |row| {
                    *counted += 1;
                    push(row)
                },
            );
            if let Err(error) = result {
                failed = Some(error);
                break;
            }
        }
        reports.push(WmiFileReport {
            path: path.clone(),
            rows: count,
            error: failed,
        });
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 테스트 편의: 스트림 결과를 모아 행 목록으로 돌려준다.
    fn parse_wmi_from(paths: &[PathBuf]) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        let reports = parse_wmi_stream(paths, &mut |row| {
            rows.push(row);
            Ok(())
        })?;
        for report in reports {
            assert!(report.error.is_none(), "unexpected file error: {:?}", report.error);
        }
        Ok(rows)
    }

fn blob(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    /// 레코드 끝 해시 흉내: 널 사이 1글자 토큰 연속.
    fn hash_tail() -> Vec<u8> {
        let mut out = Vec::new();
        for c in b"47C79E62C222" {
            out.push(*c);
            out.push(0);
        }
        out
    }

    #[test]
    fn binding_filter_and_consumer_instances_are_extracted() {
        let data = blob(&[
            // 바인딩 인스턴스
            b"__FilterToConsumerBinding\x00\x00CommandLineEventConsumer.Name=\"BadConsumer\"\x00junk\x00__EventFilter.Name=\"BadFilter\"\x00",
            &hash_tail(),
            // 필터 인스턴스 (namespace, name, query, language)
            b"__EventFilter\x00\x15\x01\x02\x00\x00root\\cimv2\x00\x00BadFilter\x00\x00select * from __InstanceModificationEvent\x00\x00WQL\x00",
            &hash_tail(),
            // 컨슈머 인스턴스
            b"CommandLineEventConsumer\x00\x00BadConsumer\x00cmd.exe /c evil.bat\x00",
            &hash_tail(),
            // 클래스 정의 — 건너뛰어야 한다
            b"CommandLineEventConsumer\x00\x00CommandLineTemplate\x00\x01\x02\x00string\x00\x00Template\x00",
        ]);
        let dir = std::env::temp_dir().join(format!("wina-wmi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("OBJECTS.DATA");
        std::fs::write(&path, &data).unwrap();

        let rows = parse_wmi_from(&[path]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str()).collect();
        assert_eq!(kinds, vec!["바인딩", "이벤트 필터", "이벤트 컨슈머"]);
        assert_eq!(rows[0]["consumer_name"], "BadConsumer");
        assert_eq!(rows[0]["filter_name"], "BadFilter");
        assert_eq!(rows[0]["consumer_type"], "CommandLineEventConsumer");
        assert_eq!(rows[1]["name"], "BadFilter");
        assert_eq!(rows[1]["query"], "select * from __InstanceModificationEvent");
        assert_eq!(rows[1]["query_language"], "WQL");
        assert_eq!(rows[1]["namespace"], "root\\cimv2");
        assert_eq!(rows[2]["name"], "BadConsumer");
        assert!(rows[2]["details"].contains("cmd.exe /c evil.bat"));
    }

    /// 청크 경계 회귀: 시그니처·레코드가 4MiB 청크 끝에 걸쳐도 겹침 재스캔으로
    /// 온전히 1건 추출된다 (중복 없이).
    #[test]
    fn record_across_chunk_boundary_is_extracted_once() {
        let mut data = vec![0u8; super::SCAN_CHUNK - 40];
        data.extend_from_slice(
            b"__EventFilter\x00\x15\x01\x02\x00\x00root\\cimv2\x00\x00EdgeFilter\x00\x00select * from __InstanceModificationEvent\x00\x00WQL\x00",
        );
        data.extend(hash_tail());
        let dir = std::env::temp_dir().join(format!("wina-wmi-edge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("OBJECTS.DATA");
        std::fs::write(&path, &data).unwrap();
        let rows = parse_wmi_from(&[path]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rows.len(), 1, "boundary record must appear exactly once: {rows:?}");
        assert_eq!(rows[0]["name"], "EdgeFilter");
    }

    /// 파일별 실패 보고: 읽지 못한 원본은 사유가 남고, 다른 파일은 계속 파싱된다.
    #[test]
    fn unreadable_source_is_reported_and_others_continue() {
        let dir = std::env::temp_dir().join(format!("wina-wmi-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("OBJECTS.DATA");
        let data = blob(&[
            b"CommandLineEventConsumer\x00\x00GoodConsumer\x00cmd.exe /c ok.bat\x00",
            &hash_tail(),
        ]);
        std::fs::write(&good, &data).unwrap();
        let missing = dir.join("no-such-dir").join("OBJECTS.DATA");
        let mut rows = Vec::new();
        let reports = parse_wmi_stream(&[missing.clone(), good.clone()], &mut |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports[0].error.is_some(), "missing file must carry a reason");
        assert_eq!(reports[0].rows, 0);
        assert!(reports[1].error.is_none());
        assert_eq!(reports[1].rows, 1);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn class_definitions_are_not_reported_as_instances() {
        let data = blob(&[
            b"ActiveScriptEventConsumer\x00\x00AMENDMENT\x00\x00LOCALE\x00\x00KillTimeout\x00\x01\x00uint32\x00",
            b"__EventFilter\x00\x00CreatorSID\x00\x01\x00string\x00\x00QueryLanguage\x00",
        ]);
        let dir = std::env::temp_dir().join(format!("wina-wmi-def-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("OBJECTS.DATA");
        std::fs::write(&path, &data).unwrap();
        let rows = parse_wmi_from(&[path]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(rows.is_empty(), "definitions must be skipped: {rows:?}");
    }
}
