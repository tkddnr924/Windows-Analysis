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

pub fn wmi_sources(target: &Path) -> Vec<PathBuf> {
    finder::by_name(target, &["OBJECTS.DATA"])
}

fn find_all(data: &[u8], sig: &[u8]) -> Vec<usize> {
    let mut offs = Vec::new();
    let mut from = 0;
    while from + sig.len() <= data.len() {
        match data[from..].windows(sig.len()).position(|w| w == sig) {
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

fn scan_bindings(data: &[u8], source: &str, rows: &mut Vec<Row>, seen: &mut BTreeSet<String>) {
    for off in find_all(data, b"__FilterToConsumerBinding\x00") {
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
                rows.push(row);
            }
        }
    }
}

fn scan_filters(data: &[u8], source: &str, rows: &mut Vec<Row>, seen: &mut BTreeSet<String>) {
    for off in find_all(data, b"__EventFilter\x00") {
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
        rows.push(row);
    }
}

fn scan_consumers(data: &[u8], source: &str, rows: &mut Vec<Row>, seen: &mut BTreeSet<String>) {
    for class in CONSUMER_CLASSES {
        let sig = format!("{class}\0");
        for off in find_all(data, sig.as_bytes()) {
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
            rows.push(row);
        }
    }
}

pub fn parse_wmi_from(paths: &[PathBuf]) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for path in paths {
        let data = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let source = path.to_string_lossy().into_owned();
        let mut seen = BTreeSet::new();
        // 바인딩 → 필터 → 컨슈머 순서로 쌓인다 (스캔 순서가 곧 표 순서).
        scan_bindings(&data, &source, &mut rows, &mut seen);
        scan_filters(&data, &source, &mut rows, &mut seen);
        scan_consumers(&data, &source, &mut rows, &mut seen);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

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
