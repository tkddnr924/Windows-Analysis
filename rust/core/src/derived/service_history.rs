//! Service Control Manager history and service-installation auditing.
//! Every recorded field keeps its original text; mappings that Windows does
//! not state (current configuration, execution, identity merges) are never
//! inferred here.
use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use rusqlite::{Connection, OpenFlags};

use super::schema::{ChildSpec, DbSpec};
use super::{int_opt, int_val, text, text_opt, Cell, Ctx, DerivedDb, SourceRef};
use crate::overview::{classify_path, jget, parse_eventdata, EventLogOverviewCache};

const SCM_PROVIDER: &str = "Service Control Manager";
const AUDIT_EVENT_ID: &str = "4697";
const TIMESTAMP_KIND: &str = "이벤트 기록 시각";
/// Logs that can hold service evidence; others are not inspected here.
const LOGS: &[&str] = &["System", "Security"];

// ---------------------------------------------------------------------------
// Event semantics
// ---------------------------------------------------------------------------

/// What the Service Control Manager message itself states. `result` repeats the
/// recorded outcome only; it is not a risk judgement, and an event we cannot
/// map stays unclassified instead of becoming a failure.
struct Sem {
    description: &'static str,
    result: Option<&'static str>,
    mapping: &'static str,
}

fn semantics(event_id: &str) -> Sem {
    let (description, result, mapping) = match event_id {
        "7000" => ("서비스 시작 실패", Some("실패"), "mapped"),
        "7001" => ("의존 서비스 시작 실패", Some("실패"), "mapped"),
        "7002" => ("의존 그룹 시작 실패", Some("실패"), "mapped"),
        "7003" => ("의존 서비스 미설치 가능성", Some("실패"), "mapped"),
        "7009" => ("서비스 연결 대기 시간 초과", Some("실패"), "mapped"),
        "7011" => ("서비스 응답 대기 시간 초과", Some("실패"), "mapped"),
        "7016" => ("잘못된 서비스 상태 보고", Some("실패"), "mapped"),
        "7022" => ("서비스 시작 중 중단", Some("실패"), "mapped"),
        "7023" => ("서비스 종료(오류)", Some("실패"), "mapped"),
        "7024" => ("서비스 종료(서비스 지정 오류)", Some("실패"), "mapped"),
        "7026" => ("부팅/시스템 시작 드라이버 로드 실패", Some("실패"), "mapped"),
        "7030" => ("대화형 서비스 표시", Some("정보"), "mapped"),
        "7031" => ("서비스 비정상 종료(복구 동작)", Some("실패"), "mapped"),
        "7032" => ("서비스 복구 조치 실패", Some("실패"), "mapped"),
        "7034" => ("서비스 비정상 종료", Some("실패"), "mapped"),
        "7035" => ("서비스 제어 요청 전송", Some("정보"), "mapped"),
        "7036" => ("서비스 상태 변경", Some("정보"), "mapped"),
        "7038" => ("서비스 계정 로그온 실패", Some("실패"), "mapped"),
        "7039" => ("다른 프로세스가 서비스에 연결", Some("실패"), "mapped"),
        "7040" => ("시작 유형 변경", Some("정보"), "mapped"),
        "7042" => ("서비스 중지 요청 처리", Some("정보"), "mapped"),
        "7043" => ("서비스 종료 처리 미완료", Some("실패"), "mapped"),
        "7045" => ("서비스 설치", Some("정보"), "mapped"),
        AUDIT_EVENT_ID => ("서비스 설치 감사", None, "mapped"),
        _ => ("", None, "unmapped"),
    };
    Sem { description, result, mapping }
}

/// Confirmed Win32 system error constants (winerror.h). Codes outside this set
/// keep only their recorded value.
const WIN32_ERRORS: &[(i64, &str)] = &[
    (2, "ERROR_FILE_NOT_FOUND"),
    (3, "ERROR_PATH_NOT_FOUND"),
    (5, "ERROR_ACCESS_DENIED"),
    (1053, "ERROR_SERVICE_REQUEST_TIMEOUT"),
    (1056, "ERROR_SERVICE_ALREADY_RUNNING"),
    (1058, "ERROR_SERVICE_DISABLED"),
    (1060, "ERROR_SERVICE_DOES_NOT_EXIST"),
    (1062, "ERROR_SERVICE_NOT_ACTIVE"),
    (1064, "ERROR_EXCEPTION_IN_SERVICE"),
    (1067, "ERROR_PROCESS_ABORTED"),
    (1068, "ERROR_SERVICE_DEPENDENCY_FAIL"),
    (1069, "ERROR_SERVICE_LOGON_FAILED"),
    (1070, "ERROR_SERVICE_START_HANG"),
    (1072, "ERROR_SERVICE_MARKED_FOR_DELETE"),
    (1075, "ERROR_SERVICE_DEPENDENCY_DELETED"),
    (1077, "ERROR_SERVICE_NEVER_STARTED"),
    (1079, "ERROR_DIFFERENT_SERVICE_ACCOUNT"),
    (1722, "RPC_S_SERVER_UNAVAILABLE"),
];

/// Documented SERVICE_*_START values used by the 4697 audit record.
fn audit_start_type(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "0" => Some("부팅 시작"),
        "1" => Some("시스템 시작"),
        "2" => Some("자동 시작"),
        "3" => Some("요청 시 시작"),
        "4" => Some("사용 안 함"),
        _ => None,
    }
}

/// Well-known service identities (Microsoft well-known SIDs). A name only
/// resolves when the host's metadata confirms the SID or the name is one of
/// the documented aliases of that SID.
const WELL_KNOWN_ACCOUNTS: &[(&str, &[&str])] = &[
    ("S-1-5-18", &["localsystem", "system", "nt authority\\system", ".\\localsystem"]),
    ("S-1-5-19", &["localservice", "local service", "nt authority\\localservice", "nt authority\\local service"]),
    ("S-1-5-20", &["networkservice", "network service", "nt authority\\networkservice", "nt authority\\network service"]),
];

// ---------------------------------------------------------------------------
// Payload access
// ---------------------------------------------------------------------------

/// A record's payload in the shape the parser produced: named EventData,
/// a nested EventXML object, or the legacy EVT insertion-string array.
struct Fields {
    named: serde_json::Map<String, serde_json::Value>,
    strings: Vec<String>,
    format: &'static str,
}

impl Fields {
    fn parse(raw: &str) -> Self {
        let mut named = parse_eventdata(raw);
        let mut format = if named.is_empty() { "absent" } else { "eventdata_named" };
        let nested = match named.get("EventXML") {
            Some(serde_json::Value::Object(inner)) => Some(inner.clone()),
            _ => None,
        };
        if let Some(inner) = nested {
            for (key, value) in inner {
                named.entry(key).or_insert(value);
            }
            format = "eventxml_nested";
        }
        let strings = match named.get("Strings") {
            Some(serde_json::Value::Array(items)) => {
                format = "evt_strings";
                items
                    .iter()
                    .map(|item| match item {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        Self { named, strings, format }
    }

    /// Message insertion string %n — paramN in EventData, position n-1 in EVT.
    fn param(&self, n: usize) -> String {
        if self.format == "evt_strings" {
            return self.strings.get(n - 1).cloned().unwrap_or_default();
        }
        jget(&self.named, &format!("param{n}"))
    }

    /// A named field, falling back to its confirmed position in the legacy
    /// message when the record only carries insertion strings.
    fn field(&self, name: &str, position: usize) -> String {
        if self.format == "evt_strings" {
            return self.strings.get(position - 1).cloned().unwrap_or_default();
        }
        jget(&self.named, name)
    }

    fn binary(&self) -> String {
        let evtx = jget(&self.named, "Binary");
        if evtx.is_empty() {
            jget(&self.named, "Data")
        } else {
            evtx
        }
    }

    /// Every payload member in storage order, so no recorded value depends on
    /// a mapping being present.
    fn enumerate(&self) -> Vec<(String, &'static str, Cell)> {
        let mut out = Vec::new();
        for (index, value) in self.strings.iter().enumerate() {
            // A recorded empty insertion string is not a missing one.
            out.push((format!("Strings[{index}]"), "positional", Cell::Text(value.clone())));
        }
        for (key, value) in &self.named {
            if key == "Strings" {
                continue;
            }
            let rendered = match value {
                serde_json::Value::String(text) => Cell::Text(text.clone()),
                serde_json::Value::Null => Cell::Null,
                other => Cell::Text(other.to_string()),
            };
            out.push((key.clone(), "named", rendered));
        }
        out
    }
}

/// Decode SCM binary data (UTF-16LE service identity) without guessing at
/// bytes that are not text.
fn decode_binary(hex: &str) -> (Option<String>, &'static str) {
    let hex = hex.trim();
    if hex.is_empty() {
        return (None, "absent");
    }
    if hex.len() % 4 != 0 {
        return (None, if hex.len() % 2 == 0 { "unaligned" } else { "odd_length" });
    }
    let mut units = Vec::with_capacity(hex.len() / 4);
    for chunk in hex.as_bytes().chunks(4) {
        let Ok(text) = std::str::from_utf8(chunk) else {
            return (None, "invalid_hex");
        };
        let Ok(value) = u16::from_str_radix(text, 16) else {
            return (None, "invalid_hex");
        };
        units.push(value.swap_bytes());
    }
    while units.last() == Some(&0) {
        units.pop();
    }
    let Ok(decoded) = String::from_utf16(&units) else {
        return (None, "not_utf16");
    };
    if decoded.chars().any(|c| c.is_control()) {
        return (None, "not_text");
    }
    if decoded.is_empty() {
        return (None, "empty");
    }
    (Some(decoded), "decoded")
}

/// 7036 records "<name>/<state code>" in its binary data; split only that
/// exact shape.
fn split_binary_token(decoded: &str, event_id: &str) -> (String, Option<String>) {
    if event_id != "7036" {
        return (decoded.to_string(), None);
    }
    match decoded.rsplit_once('/') {
        Some((name, code))
            if !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty() =>
        {
            (name.to_string(), Some(code.to_string()))
        }
        _ => (decoded.to_string(), None),
    }
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

fn norm(value: &str) -> String {
    value.trim().to_lowercase()
}

fn opt(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn resolved(ctx: &Ctx, raw: &str) -> Option<String> {
    match ctx.meta.resolve_path(raw, None) {
        Cell::Text(value) => Some(value),
        _ => None,
    }
}

/// Split a recorded command line only where the original text marks the
/// executable boundary; otherwise the split stays unknown.
fn split_command(raw: &str) -> (Option<String>, Option<String>, &'static str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None, "unrecorded");
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => {
                let args = rest[end + 1..].trim();
                (
                    opt(&rest[..end]).map(str::to_string),
                    opt(args).map(str::to_string),
                    "quoted",
                )
            }
            None => (None, None, "ambiguous"),
        };
    }
    if !trimmed.contains(' ') {
        return (Some(trimmed.to_string()), None, "single_token");
    }
    // Scan whole tokens: a lowercase copy can differ in byte length, so the
    // boundary is measured on the original text.
    const EXTENSIONS: &[&str] = &[".exe", ".sys", ".dll", ".bat", ".cmd", ".com", ".scr"];
    let mut cut = 0usize;
    for token in trimmed.split(' ') {
        cut += token.len();
        let token = token.to_lowercase();
        if EXTENSIONS.iter().any(|extension| token.ends_with(extension)) {
            let args = trimmed[cut..].trim();
            return (
                Some(trimmed[..cut].to_string()),
                opt(args).map(str::to_string),
                if cut == trimmed.len() { "single_token" } else { "extension_token" },
            );
        }
        cut += 1;
    }
    (None, None, "ambiguous")
}

struct ErrorCode {
    numeric: Option<i64>,
    hex: Option<String>,
    format: Option<&'static str>,
    symbol: Option<&'static str>,
}

/// Keep the recorded code; add a constant name only for a confirmed system
/// error, never for a service-specific code.
fn parse_error_code(raw: &str, scope: &str) -> ErrorCode {
    let Some(raw) = opt(raw) else {
        return ErrorCode { numeric: None, hex: None, format: None, symbol: None };
    };
    let (digits, format) = match raw.strip_prefix("%%") {
        Some(rest) => (rest, "message_reference"),
        None => match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            Some(rest) => (rest, "hex"),
            None => (raw, "decimal"),
        },
    };
    let numeric = if format == "hex" {
        i64::from_str_radix(digits, 16).ok()
    } else {
        digits.parse::<i64>().ok()
    };
    let symbol = match (scope, numeric) {
        ("system", Some(value)) => WIN32_ERRORS
            .iter()
            .find(|(code, _)| *code == value)
            .map(|(_, name)| *name),
        _ => None,
    };
    ErrorCode {
        numeric,
        hex: numeric.map(|value| format!("0x{value:X}")),
        format: Some(if numeric.is_some() { format } else { "text" }),
        symbol,
    }
}

/// Audit success/failure comes from the record's own keywords bits.
fn audit_outcome(keywords: &str) -> Option<&'static str> {
    let raw = keywords.trim();
    let digits = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    let value = u64::from_str_radix(digits, 16).ok()?;
    match (value & 0x0020_0000_0000_0000 != 0, value & 0x0010_0000_0000_0000 != 0) {
        (true, false) => Some("success"),
        (false, true) => Some("failure"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Span {
    first: String,
    last: String,
}

impl Span {
    fn observe(&mut self, time: &str) {
        if time.is_empty() {
            return;
        }
        if self.first.is_empty() || time < self.first.as_str() {
            self.first = time.to_string();
        }
        if time > self.last.as_str() {
            self.last = time.to_string();
        }
    }
}

#[derive(Default)]
struct PathStat {
    image: String,
    resolved: Option<String>,
    executable: Option<String>,
    arguments: Option<String>,
    basis: &'static str,
    count: i64,
    span: Span,
    first_record: String,
    last_record: String,
    source: Option<SourceRef>,
}

#[derive(Default)]
struct Identity {
    kind: &'static str,
    display: String,
    key: String,
    key_source: String,
    events: i64,
    failures: i64,
    installs: i64,
    span: Span,
    paths: BTreeMap<String, PathStat>,
    latest_path: Option<(String, String, String)>,
}

#[derive(Default)]
struct Coverage {
    provider: String,
    description: String,
    result: Option<&'static str>,
    mapping: &'static str,
    count: i64,
    span: Span,
}

#[derive(Default)]
struct AliasStat {
    display: String,
    key: String,
    count: i64,
    span: Span,
}

#[derive(Default)]
struct LogStat {
    rows: i64,
    service_rows: i64,
    corrupted: i64,
    untimed: i64,
    span: Span,
    source_file: String,
}

fn relevant_log(table: &str) -> bool {
    LOGS.iter().any(|log| {
        table.eq_ignore_ascii_case(log)
            || table
                .strip_prefix(&format!("{log}_"))
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

pub(super) fn build(ctx: &Ctx, events: &EventLogOverviewCache) -> Result<usize> {
    // 7040 records a display name and its short name together; a display name
    // with more than one candidate key stays unresolved.
    let mut aliases: BTreeMap<(String, String), AliasStat> = BTreeMap::new();
    for row in events.rows() {
        if row.get("Provider").map(String::as_str) != Some(SCM_PROVIDER)
            || row.get("EventID").map(String::as_str) != Some("7040")
        {
            continue;
        }
        let fields = Fields::parse(row.get("EventData").map(String::as_str).unwrap_or(""));
        let (display, key) = (fields.param(1), fields.param(4));
        let (Some(display), Some(key)) = (opt(&display), opt(&key)) else {
            continue;
        };
        let entry = aliases
            .entry((norm(display), norm(key)))
            .or_insert_with(|| AliasStat {
                display: display.to_string(),
                key: key.to_string(),
                ..AliasStat::default()
            });
        entry.count += 1;
        entry.span.observe(row.get("timestamp").map(String::as_str).unwrap_or(""));
    }
    let mut alias_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (display, key) in aliases.keys() {
        alias_keys.entry(display.clone()).or_default().push(key.clone());
    }

    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut identities: BTreeMap<String, Identity> = BTreeMap::new();
    let mut states: BTreeMap<(String, String, String), (i64, Span)> = BTreeMap::new();
    let mut coverage: BTreeMap<String, Coverage> = BTreeMap::new();
    let mut logs: BTreeMap<String, LogStat> = BTreeMap::new();
    let mut accounts: BTreeMap<String, ()> = BTreeMap::new();

    for row in events.rows() {
        let table = row
            .get("_record_key")
            .and_then(|key| key.split("::").next())
            .unwrap_or("");
        if relevant_log(table) {
            let stat = logs.entry(table.to_string()).or_default();
            if stat.source_file.is_empty() {
                stat.source_file = row.get("_source_file").cloned().unwrap_or_default();
            }
            if row.get("_status").map(String::as_str) == Some("corrupted_chunk") {
                stat.corrupted += 1;
            } else {
                stat.rows += 1;
                let time = row.get("timestamp").map(String::as_str).unwrap_or("");
                if time.is_empty() {
                    stat.untimed += 1;
                } else {
                    stat.span.observe(time);
                }
            }
        }

        let provider = row.get("Provider").map(String::as_str).unwrap_or("");
        let event_id = row.get("EventID").map(String::as_str).unwrap_or("");
        let is_audit =
            event_id == AUDIT_EVENT_ID && row.get("Channel").map(String::as_str) == Some("Security");
        if provider != SCM_PROVIDER && !is_audit {
            continue;
        }
        if relevant_log(table) {
            logs.entry(table.to_string()).or_default().service_rows += 1;
        }

        let time = row.get("timestamp").map(String::as_str).unwrap_or("");
        // SQL NULL arrives as an absent key; a recorded empty payload does not.
        let payload = row.get("EventData");
        let payload_raw = payload.map(String::as_str).unwrap_or("");
        let payload_state = match payload {
            None => "absent",
            Some(value) if value.is_empty() => "empty",
            Some(_) => "present",
        };
        let fields = Fields::parse(payload_raw);
        let sem = semantics(event_id);
        let description = if sem.mapping == "unmapped" {
            format!("서비스 관리자 이벤트 {event_id}")
        } else {
            sem.description.to_string()
        };

        let mut service_name = String::new();
        let mut name_source = "";
        let mut service_key = String::new();
        let mut key_source = "";
        let mut image_path = String::new();
        let mut service_account = String::new();
        let mut state = String::new();
        let mut start_before = String::new();
        let mut start_after = String::new();
        let mut start_after_raw = String::new();
        let mut service_type = String::new();
        let mut service_type_raw = String::new();
        let mut control_code = String::new();
        let mut stop_reason = String::new();
        let mut stop_reason_code = String::new();
        let mut stop_comment = String::new();
        let mut dependency_service = String::new();
        let mut dependency_group = String::new();
        let mut driver_list = String::new();
        let mut error_raw = String::new();
        let mut error_scope = "";
        let mut termination_raw = String::new();
        let mut delay_raw = String::new();
        let mut action_raw = String::new();
        let mut action_text = String::new();
        let mut timeout_raw = String::new();
        let mut subject_sid = String::new();
        let mut subject_name = String::new();
        let mut subject_domain = String::new();
        let mut subject_logon_id = String::new();

        match event_id {
            "7045" => {
                service_key = fields.field("ServiceName", 1);
                service_name = service_key.clone();
                name_source = "ServiceName";
                key_source = "ServiceName";
                image_path = fields.field("ImagePath", 2);
                service_type = fields.field("ServiceType", 3);
                start_after = fields.field("StartType", 4);
                service_account = fields.field("AccountName", 5);
            }
            AUDIT_EVENT_ID => {
                subject_sid = fields.field("SubjectUserSid", 1);
                subject_name = fields.field("SubjectUserName", 2);
                subject_domain = fields.field("SubjectDomainName", 3);
                subject_logon_id = fields.field("SubjectLogonId", 4);
                service_key = fields.field("ServiceName", 5);
                service_name = service_key.clone();
                name_source = "ServiceName";
                key_source = "ServiceName";
                image_path = fields.field("ServiceFileName", 6);
                // The audit record stores numeric type and start type; only the
                // documented start-type values have a confirmed meaning.
                service_type_raw = fields.field("ServiceType", 7);
                start_after_raw = fields.field("ServiceStartType", 8);
                start_after = audit_start_type(&start_after_raw).unwrap_or("").to_string();
                service_account = fields.field("ServiceAccount", 9);
            }
            "7040" => {
                service_name = fields.param(1);
                name_source = "param1";
                start_before = fields.param(2);
                start_after = fields.param(3);
                service_key = fields.param(4);
                key_source = "param4";
            }
            "7036" => {
                service_name = fields.param(1);
                name_source = "param1";
                state = fields.param(2);
            }
            "7035" => {
                service_name = fields.param(1);
                name_source = "param1";
                control_code = fields.param(2);
            }
            "7042" => {
                service_name = fields.param(1);
                name_source = "param1";
                control_code = fields.param(2);
                stop_reason = fields.param(3);
                stop_reason_code = fields.param(4);
                stop_comment = fields.param(5);
            }
            "7000" | "7023" => {
                service_name = fields.param(1);
                name_source = "param1";
                error_raw = fields.param(2);
                error_scope = "system";
            }
            "7024" => {
                service_name = fields.param(1);
                name_source = "param1";
                error_raw = fields.param(2);
                error_scope = "service_specific";
            }
            "7001" => {
                service_name = fields.param(1);
                name_source = "param1";
                dependency_service = fields.param(2);
                error_raw = fields.param(3);
                error_scope = "system";
            }
            "7002" => {
                service_name = fields.param(1);
                name_source = "param1";
                dependency_group = fields.param(2);
            }
            "7003" => {
                service_name = fields.param(1);
                name_source = "param1";
                dependency_service = fields.param(2);
            }
            "7009" | "7011" => {
                timeout_raw = fields.param(1);
                service_name = fields.param(2);
                name_source = "param2";
            }
            "7016" | "7022" | "7030" | "7039" | "7043" => {
                service_name = fields.param(1);
                name_source = "param1";
            }
            "7026" => {
                // A boot-driver report lists drivers, not one service identity.
                driver_list = fields.param(1);
            }
            "7031" => {
                service_name = fields.param(1);
                name_source = "param1";
                termination_raw = fields.param(2);
                delay_raw = fields.param(3);
                action_raw = fields.param(4);
                action_text = fields.param(5);
            }
            "7032" => {
                // EVENT_SERVICE_RECOVERY_FAILED inserts differ from 7031.
                service_name = fields.param(3);
                name_source = "param3";
                action_raw = fields.param(1);
                action_text = fields.param(2);
                error_raw = fields.param(4);
                error_scope = "system";
            }
            "7034" => {
                service_name = fields.param(1);
                name_source = "param1";
                termination_raw = fields.param(2);
            }
            "7038" => {
                service_name = fields.param(1);
                name_source = "param1";
                service_account = fields.param(2);
                error_raw = fields.param(3);
                error_scope = "system";
            }
            _ => {}
        }

        let detail = match event_id {
            "7026" => driver_list.replace(['\r', '\n'], " ").trim().to_string(),
            "7034" => match opt(&termination_raw) {
                Some(count) => format!("종료 횟수 {count}"),
                None => String::new(),
            },
            "7031" | "7032" => action_text.clone(),
            "7042" => stop_reason_code.clone(),
            "7000" | "7023" | "7024" | "7001" | "7016" => fields.param(2),
            "7038" => error_raw.clone(),
            _ => String::new(),
        };

        let mut record = ctx.record(&SPEC);
        record.timestamp(time, TIMESTAMP_KIND);
        record.set(
            "timestamp_state",
            text(if time.trim().is_empty() { "unrecorded" } else { "recorded" }),
        );
        record.set("event_type", text(&description));
        record.set("description", text(&description));
        record.set("record_context", text(if is_audit { "security_audit" } else { "scm" }));

        // The recording actor is the event's own security context, not an
        // assertion about who requested the change.
        let user_sid = row.get("UserID").map(String::as_str).unwrap_or("");
        let (actor_raw, actor_basis) = if is_audit {
            (subject_sid.as_str(), "audit_subject_sid")
        } else {
            (user_sid, "event_user_sid")
        };
        let actor_sid = opt(actor_raw).filter(|value| super::is_sid(value));
        let actor_name = actor_sid.and_then(|sid| ctx.meta.account_name(sid));
        let actor_fallback = opt(&subject_name).filter(|_| is_audit);
        record.set("account", text_opt(actor_name.as_deref().or(actor_fallback)));
        record.set("account_sid", text_opt(actor_sid));
        record.set("account_sid_raw", text(actor_raw));
        record.set(
            "account_basis",
            match (actor_sid, actor_fallback) {
                (Some(_), _) => text(actor_basis),
                (None, Some(_)) => text("audit_subject_name"),
                _ => Cell::Null,
            },
        );
        if let Some(sid) = actor_sid {
            accounts.insert(sid.to_lowercase(), ());
        }
        record.set("subject_user_sid", text(&subject_sid));
        record.set("subject_user_name", text(&subject_name));
        record.set("subject_domain", text(&subject_domain));
        record.set("subject_logon_id", text(&subject_logon_id));

        record.set("service_name", text(&service_name));
        record.set(
            "service_name_source",
            text(if service_name.trim().is_empty() { "" } else { name_source }),
        );
        record.set("service_key", text(&service_key));
        record.set(
            "service_key_source",
            text(if service_key.trim().is_empty() { "" } else { key_source }),
        );
        record.set("service_name_normalized", text(&norm(&service_name)));
        record.set("service_key_normalized", text(&norm(&service_key)));

        // Binary data carries the service identity the message text omits; it
        // stays a candidate beside the recorded fields.
        let binary_raw = fields.binary();
        let (binary_text, binary_state) = decode_binary(&binary_raw);
        let (binary_token, binary_state_code) = match binary_text.as_deref() {
            Some(decoded) => {
                let (token, code) = split_binary_token(decoded, event_id);
                (Some(token), code)
            }
            None => (None, None),
        };
        record.set("binary_data_raw", text(&binary_raw));
        record.set("binary_text", text_opt(binary_text.as_deref()));
        record.set("binary_name_token", text_opt(binary_token.as_deref()));
        record.set("binary_state_code", text_opt(binary_state_code.as_deref()));
        record.set("binary_decode_state", text(binary_state));

        let alias_key = (!service_key.trim().is_empty())
            .then(|| norm(&service_key))
            .or_else(|| match alias_keys.get(&norm(&service_name)) {
                Some(keys) if keys.len() == 1 && !service_name.trim().is_empty() => {
                    Some(keys[0].clone())
                }
                _ => None,
            });
        let (candidate, candidate_basis) = match (opt(&service_key), binary_token.as_deref()) {
            (Some(key), _) => (Some(key.to_string()), "recorded_field"),
            (None, Some(token)) => (Some(token.to_string()), "binary_data"),
            (None, None) => match &alias_key {
                Some(key) => (Some(key.clone()), "alias_7040"),
                None => (None, ""),
            },
        };
        record.set("service_key_candidate", text_opt(candidate.as_deref()));
        record.set("service_key_candidate_basis", text(candidate_basis));

        // Grouping follows the stored contract: recorded key, then a single
        // 7040 alias candidate, then the recorded name, then this record alone.
        let (group_key, group_kind) = if let Some(key) = opt(&service_key) {
            (norm(key), "service_key")
        } else if let Some(key) = alias_key.clone().filter(|_| opt(&service_name).is_some()) {
            (key, "alias_service_key")
        } else if let Some(name) = opt(&service_name) {
            (norm(name), "service_name")
        } else {
            (format!("record::{}", record.record_id), "record")
        };
        let group_display = opt(&service_name).or(opt(&service_key)).map(str::to_string);
        record.set("group_key", text(&group_key));
        record.set("group_key_kind", text(group_kind));
        record.set("group_display_name", text_opt(group_display.as_deref()));

        let (executable, arguments, exec_basis) = split_command(&image_path);
        let shape = executable.as_deref().map(classify_path);
        let image_resolved = resolved(ctx, &image_path);
        let exec_resolved = executable.as_deref().and_then(|path| resolved(ctx, path));
        record.set("image_path", super::text_raw(&image_path));
        record.set("image_path_resolved", text_opt(image_resolved.as_deref()));
        record.set(
            "image_path_state",
            text(if image_path.trim().is_empty() { "unrecorded" } else { "recorded" }),
        );
        record.set("executable_path", text_opt(executable.as_deref()));
        record.set("executable_path_resolved", text_opt(exec_resolved.as_deref()));
        record.set("executable_path_key", text_opt(shape.as_ref().map(|s| s.key.as_str())));
        record.set("executable_path_kind", text_opt(shape.as_ref().map(|s| s.kind)));
        record.set("executable_drive", text_opt(shape.as_ref().map(|s| s.drive.as_str())));
        record.set(
            "executable_basis",
            text(if exec_basis == "unrecorded" { "" } else { exec_basis }),
        );
        record.set("command_arguments", text_opt(arguments.as_deref()));

        // The service execution identity is independent of the recording actor.
        let (account_sid, account_sid_basis) = resolve_service_account(ctx, &service_account);
        let account_resolved = account_sid.as_deref().and_then(|sid| ctx.meta.account_name(sid));
        if let Some(sid) = account_sid.as_deref() {
            accounts.insert(sid.to_lowercase(), ());
        }
        record.set("service_account", text(&service_account));
        record.set("service_account_sid", text_opt(account_sid.as_deref()));
        record.set("service_account_sid_basis", text(account_sid_basis));
        record.set("service_account_name_resolved", text_opt(account_resolved.as_deref()));

        record.set("state", text(&state));
        record.set("start_type_before", text(&start_before));
        record.set("start_type_after", text(&start_after));
        record.set("start_type_before_raw", text(&start_before));
        record.set("start_type_after_raw", text(if is_audit { &start_after_raw } else { &start_after }));
        record.set("service_type", text(&service_type));
        record.set("service_type_raw", text(if is_audit { &service_type_raw } else { &service_type }));
        record.set("control_code", text(&control_code));
        record.set("stop_reason", text(&stop_reason));
        record.set("stop_reason_code", text(&stop_reason_code));
        record.set("stop_comment", text(&stop_comment));
        record.set("dependency_service", text(&dependency_service));
        record.set("dependency_group", text(&dependency_group));
        record.set("driver_list_raw", super::text_raw(&driver_list));
        record.set(
            "driver_count",
            if driver_list.trim().is_empty() {
                Cell::Null
            } else {
                int_val(
                    driver_list
                        .split(['\r', '\n'])
                        .filter(|part| !part.trim().is_empty())
                        .count() as i64,
                )
            },
        );

        let error = parse_error_code(&error_raw, error_scope);
        record.set("error_code_raw", text(&error_raw));
        record.set("error_code_numeric", int_opt(error.numeric));
        record.set("error_code_hex", text_opt(error.hex.as_deref()));
        record.set("error_code_format", text_opt(error.format));
        record.set(
            "error_code_scope",
            text(if error_raw.trim().is_empty() { "" } else { error_scope }),
        );
        record.set("error_code_symbol", text_opt(error.symbol));

        record.set("termination_count", int_opt(opt(&termination_raw).and_then(|v| v.parse().ok())));
        record.set("termination_count_raw", text(&termination_raw));
        record.set("recovery_delay_ms", int_opt(opt(&delay_raw).and_then(|v| v.parse().ok())));
        record.set("recovery_delay_raw", text(&delay_raw));
        record.set("recovery_action_code", int_opt(opt(&action_raw).and_then(|v| v.parse().ok())));
        record.set("recovery_action_raw", text(&action_raw));
        record.set("recovery_action_text", text(&action_text));
        record.set("timeout_ms", int_opt(opt(&timeout_raw).and_then(|v| v.parse().ok())));
        record.set("timeout_raw", text(&timeout_raw));
        record.set("detail", super::text_raw(&detail));

        let keywords = row.get("Keywords").map(String::as_str).unwrap_or("");
        let outcome = if is_audit { audit_outcome(keywords) } else { None };
        let result = if is_audit {
            outcome.map(|value| if value == "failure" { "실패" } else { "정보" })
        } else {
            sem.result
        };
        record.set("result", text_opt(result));
        record.set(
            "result_basis",
            match (result, is_audit) {
                (Some(_), true) => text("감사 결과"),
                (Some(_), false) => text("사건 의미"),
                (None, _) => Cell::Null,
            },
        );
        record.set("audit_outcome", text_opt(outcome));

        record.set("event_id", super::int(event_id));
        record.set("provider", text(provider));
        for (column, key) in [
            ("channel", "Channel"),
            ("computer", "Computer"),
            ("event_record_id", "EventRecordID"),
            ("level_name", "LevelName"),
            ("keywords_raw", "Keywords"),
            ("process_id", "ProcessID"),
            ("thread_id", "ThreadID"),
            ("facts_status", "_status"),
            ("facts_error", "_error"),
            ("record_key", "_record_key"),
            ("source_file", "_source_file"),
        ] {
            record.set(column, text(row.get(key).map(String::as_str).unwrap_or("")));
        }
        record.set("payload_format", text(fields.format));
        record.set("payload_state", text(payload_state));
        record.set("mapping_state", text(sem.mapping));
        record.set("event_data_raw", payload.cloned().map(Cell::Text).unwrap_or(Cell::Null));

        let mut search = vec![
            service_name.clone(),
            service_key.clone(),
            image_path.clone(),
            service_account.clone(),
            detail.clone(),
            state.clone(),
            start_before.clone(),
            start_after.clone(),
            service_type.clone(),
            dependency_service.clone(),
            dependency_group.clone(),
            driver_list.clone(),
            error_raw.clone(),
            action_text.clone(),
            description.clone(),
        ];
        search.extend(
            [
                image_resolved.clone(),
                executable.clone(),
                exec_resolved.clone(),
                account_sid.clone(),
                account_resolved.clone(),
                actor_name.clone(),
                actor_sid.map(str::to_string),
                binary_token.clone(),
                group_display.clone(),
            ]
            .into_iter()
            .flatten(),
        );
        search.retain(|value| !value.trim().is_empty());
        record.set("search_text", text(&search.join(" ")));

        for (name, origin, value) in fields.enumerate() {
            record.child("ServiceEventFields", vec![text(&name), text(origin), value]);
        }

        let record_key = row.get("_record_key").map(String::as_str).unwrap_or("");
        let source = ctx
            .facts
            .source_from_record_key(
                record_key,
                Some("EventData"),
                row.get("_source_file").map(String::as_str),
                Some(&description),
            )?
            .ok_or_else(|| anyhow!("서비스 이벤트의 원본 좌표를 찾지 못했습니다: {record_key}"))?;
        let record_id = record.record_id.clone();
        record.source(Some(source.clone()));

        let identity = identities.entry(group_key.clone()).or_insert_with(|| Identity {
            kind: group_kind,
            ..Identity::default()
        });
        identity.events += 1;
        if result == Some("실패") {
            identity.failures += 1;
        }
        if event_id == "7045" || is_audit {
            identity.installs += 1;
        }
        identity.span.observe(time);
        if identity.display.is_empty() {
            if let Some(display) = group_display.as_deref() {
                identity.display = display.to_string();
            }
        }
        if identity.key.is_empty() {
            if let Some(key) = opt(&service_key) {
                identity.key = key.to_string();
                identity.key_source = key_source.to_string();
            }
        }
        if let Some(path) = opt(&image_path) {
            let stat = identity.paths.entry(norm(path)).or_insert_with(|| PathStat {
                image: path.to_string(),
                resolved: image_resolved.clone(),
                executable: executable.clone(),
                arguments: arguments.clone(),
                basis: exec_basis,
                first_record: record_id.clone(),
                source: Some(source.clone()),
                ..PathStat::default()
            });
            stat.count += 1;
            stat.span.observe(time);
            stat.last_record = record_id.clone();
            // The representative path is the latest observation in this group.
            let newer = identity
                .latest_path
                .as_ref()
                .map(|(current, _, _)| current.as_str() <= time)
                .unwrap_or(true);
            if newer && !time.is_empty() {
                identity.latest_path = Some((time.to_string(), path.to_string(), record_id.clone()));
            }
        }
        if let Some(state_raw) = opt(&state) {
            let entry = states
                .entry((group_key.clone(), event_id.to_string(), state_raw.to_string()))
                .or_insert_with(|| (0, Span::default()));
            entry.0 += 1;
            entry.1.observe(time);
        }
        let seen = coverage.entry(event_id.to_string()).or_insert_with(|| Coverage {
            provider: provider.to_string(),
            description: description.clone(),
            result,
            mapping: sem.mapping,
            ..Coverage::default()
        });
        seen.count += 1;
        seen.span.observe(time);

        db.write(record)?;
    }

    write_identities(ctx, &mut db, &identities)?;
    write_states(ctx, &mut db, &states)?;
    write_aliases(ctx, &mut db, &aliases, &alias_keys)?;
    write_coverage(ctx, &mut db, &coverage)?;
    write_logs(ctx, &mut db, &logs)?;
    write_metadata_references(ctx, &mut db, &accounts)?;
    db.finish()
}

/// A service account name resolves through the host's metadata or a documented
/// well-known identity; anything else keeps the recorded text only.
fn resolve_service_account(ctx: &Ctx, raw: &str) -> (Option<String>, &'static str) {
    let Some(raw) = opt(raw) else {
        return (None, "");
    };
    if super::is_sid(raw) {
        return (Some(raw.to_string()), "raw_sid");
    }
    let lower = raw.to_lowercase();
    let bare = lower.rsplit('\\').next().unwrap_or(&lower).to_string();
    for (sid, aliases) in WELL_KNOWN_ACCOUNTS {
        if ctx
            .meta
            .account_name(sid)
            .is_some_and(|name| name.eq_ignore_ascii_case(raw) || name.eq_ignore_ascii_case(&bare))
        {
            return (Some((*sid).to_string()), "metadata_name");
        }
        if aliases.contains(&lower.as_str()) || aliases.contains(&bare.as_str()) {
            return (Some((*sid).to_string()), "well_known_alias");
        }
    }
    match ctx
        .meta
        .inner
        .sid_for_account_name(raw)
        .or_else(|| ctx.meta.inner.sid_for_account_name(&bare))
    {
        Some(sid) => (Some(sid.to_string()), "metadata_name"),
        None => (None, ""),
    }
}

fn write_identities(
    ctx: &Ctx,
    db: &mut DerivedDb,
    identities: &BTreeMap<String, Identity>,
) -> Result<()> {
    for (group_key, identity) in identities {
        let latest = identity.latest_path.as_ref();
        db.insert_child(
            "ServiceIdentities",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(group_key),
                text(identity.kind),
                text(&identity.display),
                text(&identity.key),
                text(&identity.key_source),
                int_val(identity.events),
                int_val(identity.failures),
                int_val(identity.installs),
                text(&identity.span.first),
                text(&identity.span.last),
                int_val(identity.paths.len() as i64),
                text_opt(latest.map(|(_, path, _)| path.as_str())),
                text_opt(latest.map(|(time, _, _)| time.as_str())),
                text_opt(latest.map(|(_, _, record)| record.as_str())),
                text(if latest.is_some() { "latest_observed" } else { "" }),
                // Absence of a path is an observation about this group only.
                text(if identity.paths.is_empty() { "unrecorded_in_group" } else { "recorded" }),
            ],
        )?;
        // Path history runs in observation order; unrecorded times stay last.
        let mut ordered: Vec<&PathStat> = identity.paths.values().collect();
        ordered.sort_by(|left, right| {
            (left.span.first.is_empty(), &left.span.first, &left.image)
                .cmp(&(right.span.first.is_empty(), &right.span.first, &right.image))
        });
        for (ordinal, stat) in ordered.into_iter().enumerate() {
            let shape = stat.executable.as_deref().map(classify_path);
            let source = stat.source.as_ref();
            db.insert_child(
                "ServicePaths",
                &[
                    text(&uuid::Uuid::new_v4().to_string()),
                    text(ctx.host_id),
                    text(ctx.dataset_id),
                    text(group_key),
                    int_val(ordinal as i64),
                    super::text_raw(&stat.image),
                    text_opt(stat.resolved.as_deref()),
                    text_opt(stat.executable.as_deref()),
                    text_opt(shape.as_ref().map(|s| s.key.as_str())),
                    text_opt(shape.as_ref().map(|s| s.kind)),
                    text_opt(shape.as_ref().map(|s| s.drive.as_str())),
                    text(stat.basis),
                    text_opt(stat.arguments.as_deref()),
                    int_val(stat.count),
                    text(&stat.span.first),
                    text(&stat.span.last),
                    text(&stat.first_record),
                    text(&stat.last_record),
                    text_opt(source.map(|s| s.dataset.as_str())),
                    text_opt(source.map(|s| s.db.as_str())),
                    text_opt(source.map(|s| s.table.as_str())),
                    int_opt(source.map(|s| s.rowid)),
                    text_opt(source.and_then(|s| s.file.as_deref())),
                ],
            )?;
        }
    }
    Ok(())
}

fn write_states(
    ctx: &Ctx,
    db: &mut DerivedDb,
    states: &BTreeMap<(String, String, String), (i64, Span)>,
) -> Result<()> {
    for ((group_key, event_id, state), (count, span)) in states {
        db.insert_child(
            "ServiceStateObservations",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(group_key),
                super::int(event_id),
                text(state),
                int_val(*count),
                text(&span.first),
                text(&span.last),
            ],
        )?;
    }
    Ok(())
}

fn write_aliases(
    ctx: &Ctx,
    db: &mut DerivedDb,
    aliases: &BTreeMap<(String, String), AliasStat>,
    alias_keys: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    for ((display_key, key_normalized), stat) in aliases {
        let candidates = alias_keys.get(display_key).map(Vec::len).unwrap_or(1) as i64;
        db.insert_child(
            "ServiceNameAliases",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(&stat.display),
                text(display_key),
                text(&stat.key),
                text(key_normalized),
                int_val(candidates),
                int_val(stat.count),
                text(if candidates == 1 { "single" } else { "ambiguous" }),
                text("7040 param1/param4"),
                text(&stat.span.first),
                text(&stat.span.last),
            ],
        )?;
    }
    Ok(())
}

fn write_coverage(
    ctx: &Ctx,
    db: &mut DerivedDb,
    coverage: &BTreeMap<String, Coverage>,
) -> Result<()> {
    for (event_id, seen) in coverage {
        db.insert_child(
            "ServiceEventCoverage",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(&seen.provider),
                super::int(event_id),
                text(&seen.description),
                text_opt(seen.result),
                text(seen.mapping),
                int_val(seen.count),
                text(&seen.span.first),
                text(&seen.span.last),
            ],
        )?;
    }
    Ok(())
}

/// Collection scope per log: an uncollected or empty log is not evidence that
/// the events never happened.
fn write_logs(ctx: &Ctx, db: &mut DerivedDb, logs: &BTreeMap<String, LogStat>) -> Result<()> {
    let inputs = ctx.out_dir.join("EVENTLOG/EventLogInputs.sqlite");
    let mut remaining: BTreeMap<&str, &LogStat> =
        logs.iter().map(|(name, stat)| (name.as_str(), stat)).collect();
    let mut discovered = false;
    let mut seen: Vec<String> = Vec::new();
    if inputs.is_file() {
        let conn = Connection::open_with_flags(&inputs, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        discovered = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM EventLogInputs WHERE status='discovery_complete')",
            [],
            |row| row.get(0),
        )?;
        let rows: Vec<(i64, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<String>)> = {
            let mut query = conn.prepare(
                "SELECT rowid,source_file,facts_db,facts_table,status,row_count,error FROM EventLogInputs
                 WHERE status<>'discovery_complete' ORDER BY rowid",
            )?;
            let mapped = query.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (rowid, file, facts_db, facts_table, status, row_count, error) in rows {
            let table = facts_table.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| {
                file.as_deref()
                    .unwrap_or("")
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or("")
                    .rsplit_once('.')
                    .map(|(stem, _)| stem)
                    .unwrap_or("")
                    .to_string()
            });
            if !relevant_log(&table) {
                continue;
            }
            seen.push(table.to_lowercase());
            let input_rows = row_count.and_then(|value| value.parse::<i64>().ok());
            let state = match (status.as_str(), input_rows) {
                ("read_failed", _) => "read_failed",
                ("parsed", Some(0)) => "collected_empty",
                ("parsed", Some(_)) => "collected",
                _ => "unknown",
            };
            let source = ctx
                .facts
                .source_from_row(
                    &inputs,
                    "EventLogInputs",
                    rowid,
                    file.as_deref(),
                    Some("collection_observation"),
                )?
                .ok_or_else(|| anyhow!("EventLogInputs 원본 좌표를 찾지 못했습니다"))?;
            let stat = remaining.remove(table.as_str());
            let parsed = status == "parsed";
            // A parsed log with no matching rows observed zero, not unknown.
            let counted = |value: Option<i64>| {
                if parsed { int_val(value.unwrap_or(0)) } else { Cell::Null }
            };
            let facts_generation = ctx.facts.by_stem(&table)
                .map(|facts| ctx.facts.generation(facts)).transpose()?;
            db.insert_child(
                "ServiceLogObservations",
                &[
                    text(&uuid::Uuid::new_v4().to_string()),
                    text(ctx.host_id),
                    text(ctx.dataset_id),
                    text(&table),
                    text_opt(file.as_deref()),
                    text_opt(facts_db.as_deref().filter(|s| !s.is_empty())),
                    text_opt(facts_table.as_deref().filter(|s| !s.is_empty())),
                    text_opt(facts_generation.as_deref()),
                    text(state),
                    int_opt(input_rows),
                    counted(stat.map(|s| s.rows)),
                    counted(stat.map(|s| s.service_rows)),
                    counted(stat.map(|s| s.corrupted)),
                    counted(stat.map(|s| s.untimed)),
                    text(stat.map(|s| s.span.first.as_str()).unwrap_or("")),
                    text(stat.map(|s| s.span.last.as_str()).unwrap_or("")),
                    text_opt(error.as_deref()),
                    text(&source.dataset),
                    text(&source.db),
                    text(&source.table),
                    int_val(source.rowid),
                ],
            )?;
        }
    }
    for (table, stat) in &remaining {
        seen.push(table.to_lowercase());
        let facts = ctx.facts.by_stem(table);
        let generation = facts.map(|db| ctx.facts.generation(db)).transpose()?;
        db.insert_child(
            "ServiceLogObservations",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(table),
                text(&stat.source_file),
                text_opt(facts.map(|db| db.relative.as_str())),
                text(table),
                text_opt(generation.as_deref()),
                text("unknown"),
                Cell::Null,
                int_val(stat.rows),
                int_val(stat.service_rows),
                int_val(stat.corrupted),
                int_val(stat.untimed),
                text(&stat.span.first),
                text(&stat.span.last),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
            ],
        )?;
    }
    for log in LOGS {
        if seen.iter().any(|name| name == &log.to_lowercase()) {
            continue;
        }
        db.insert_child(
            "ServiceLogObservations",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(log),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                text(if discovered { "not_collected" } else { "unknown" }),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
            ],
        )?;
    }
    Ok(())
}

fn write_metadata_references(
    ctx: &Ctx,
    db: &mut DerivedDb,
    accounts: &BTreeMap<String, ()>,
) -> Result<()> {
    for sid in accounts.keys() {
        let Some(metadata_id) = ctx.meta.metadata_id("account", "machine", sid) else {
            continue;
        };
        db.insert_child(
            "ServiceMetadataReferences",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(metadata_id),
                text("account"),
            ],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage contract
// ---------------------------------------------------------------------------

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "ServiceHistory" (
  "record_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "timestamp" TEXT,
  "overview_name" TEXT NOT NULL,
  "account" TEXT,
  "account_sid" TEXT,
  "timestamp_kind" TEXT,
  "event_type" TEXT,
  "description" TEXT,
  "timestamp_state" TEXT NOT NULL,
  "record_context" TEXT NOT NULL,
  "account_basis" TEXT,
  "account_sid_raw" TEXT,
  "subject_user_sid" TEXT,
  "subject_user_name" TEXT,
  "subject_domain" TEXT,
  "subject_logon_id" TEXT,
  "service_name" TEXT,
  "service_name_source" TEXT,
  "service_key" TEXT,
  "service_key_source" TEXT,
  "service_name_normalized" TEXT,
  "service_key_normalized" TEXT,
  "service_key_candidate" TEXT,
  "service_key_candidate_basis" TEXT,
  "group_key" TEXT NOT NULL,
  "group_key_kind" TEXT NOT NULL,
  "group_display_name" TEXT,
  "image_path" TEXT,
  "image_path_resolved" TEXT,
  "image_path_state" TEXT NOT NULL,
  "executable_path" TEXT,
  "executable_path_resolved" TEXT,
  "executable_path_key" TEXT,
  "executable_path_kind" TEXT,
  "executable_drive" TEXT,
  "executable_basis" TEXT,
  "command_arguments" TEXT,
  "service_account" TEXT,
  "service_account_sid" TEXT,
  "service_account_sid_basis" TEXT,
  "service_account_name_resolved" TEXT,
  "state" TEXT,
  "start_type_before" TEXT,
  "start_type_after" TEXT,
  "start_type_before_raw" TEXT,
  "start_type_after_raw" TEXT,
  "service_type" TEXT,
  "service_type_raw" TEXT,
  "control_code" TEXT,
  "stop_reason" TEXT,
  "stop_reason_code" TEXT,
  "stop_comment" TEXT,
  "dependency_service" TEXT,
  "dependency_group" TEXT,
  "driver_list_raw" TEXT,
  "driver_count" INTEGER,
  "error_code_raw" TEXT,
  "error_code_numeric" INTEGER,
  "error_code_hex" TEXT,
  "error_code_format" TEXT,
  "error_code_scope" TEXT,
  "error_code_symbol" TEXT,
  "termination_count" INTEGER,
  "termination_count_raw" TEXT,
  "recovery_delay_ms" INTEGER,
  "recovery_delay_raw" TEXT,
  "recovery_action_code" INTEGER,
  "recovery_action_raw" TEXT,
  "recovery_action_text" TEXT,
  "timeout_ms" INTEGER,
  "timeout_raw" TEXT,
  "detail" TEXT,
  "result" TEXT,
  "result_basis" TEXT,
  "audit_outcome" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  "channel" TEXT,
  "computer" TEXT,
  "event_record_id" TEXT,
  "level_name" TEXT,
  "keywords_raw" TEXT,
  "process_id" TEXT,
  "thread_id" TEXT,
  "payload_format" TEXT NOT NULL,
  "payload_state" TEXT NOT NULL,
  "mapping_state" TEXT NOT NULL,
  "event_data_raw" TEXT,
  "binary_data_raw" TEXT,
  "binary_text" TEXT,
  "binary_name_token" TEXT,
  "binary_state_code" TEXT,
  "binary_decode_state" TEXT NOT NULL,
  "facts_status" TEXT,
  "facts_error" TEXT,
  "record_key" TEXT,
  "source_file" TEXT,
  "search_text" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'ServiceHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(timestamp_state IN ('recorded','unrecorded')),
  CHECK(record_context IN ('scm','security_audit')),
  CHECK(mapping_state IN ('mapped','partial','unmapped')),
  CHECK(group_key_kind IN ('service_key','alias_service_key','service_name','record')),
  CHECK(image_path_state IN ('recorded','unrecorded')),
  CHECK(payload_state IN ('present','empty','absent'))
);
CREATE INDEX "idx_ServiceHistory_time" ON "ServiceHistory"(timestamp, record_id);
CREATE INDEX "idx_ServiceHistory_account" ON "ServiceHistory"(account_sid, timestamp);
CREATE INDEX "idx_ServiceHistory_group" ON "ServiceHistory"(group_key, timestamp, record_id);
CREATE INDEX "idx_ServiceHistory_event" ON "ServiceHistory"(event_id, timestamp);
CREATE TABLE "source_records" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_dataset_id" TEXT NOT NULL,
  "source_artifact" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_field" TEXT,
  "source_record_key" TEXT,
  "source_file" TEXT,
  "source_label" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "ServiceEventFields" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "field_name" TEXT NOT NULL,
  "field_origin" TEXT NOT NULL,
  "field_value" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(field_origin IN ('named','positional')),
  FOREIGN KEY(record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE "ServiceIdentities" (
  "identity_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "group_key" TEXT NOT NULL,
  "group_key_kind" TEXT NOT NULL,
  "display_name" TEXT,
  "service_key" TEXT,
  "service_key_source" TEXT,
  "event_count" INTEGER NOT NULL,
  "failure_count" INTEGER NOT NULL,
  "install_event_count" INTEGER NOT NULL,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "distinct_path_count" INTEGER NOT NULL,
  "latest_image_path" TEXT,
  "latest_image_path_time" TEXT,
  "latest_image_path_record_id" TEXT,
  "representative_basis" TEXT,
  "path_observation_state" TEXT NOT NULL,
  PRIMARY KEY(identity_id),
  UNIQUE(host_id, dataset_id, group_key),
  CHECK(path_observation_state IN ('recorded','unrecorded_in_group')),
  FOREIGN KEY(latest_image_path_record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE "ServicePaths" (
  "path_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "group_key" TEXT NOT NULL,
  "path_ordinal" INTEGER NOT NULL,
  "image_path" TEXT NOT NULL,
  "image_path_resolved" TEXT,
  "executable_path" TEXT,
  "executable_path_key" TEXT,
  "executable_path_kind" TEXT,
  "executable_drive" TEXT,
  "executable_basis" TEXT,
  "command_arguments" TEXT,
  "observation_count" INTEGER NOT NULL,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "first_record_id" TEXT NOT NULL,
  "last_record_id" TEXT NOT NULL,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(path_id),
  UNIQUE(host_id, dataset_id, group_key, path_ordinal),
  CHECK(path_ordinal >= 0),
  FOREIGN KEY(first_record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(last_record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_ServicePaths_key" ON "ServicePaths"(executable_path_key, group_key);
CREATE TABLE "ServiceStateObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "group_key" TEXT NOT NULL,
  "event_id" INTEGER,
  "state_raw" TEXT NOT NULL,
  "observation_count" INTEGER NOT NULL,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  PRIMARY KEY(observation_id),
  UNIQUE(host_id, dataset_id, group_key, event_id, state_raw)
);
CREATE TABLE "ServiceNameAliases" (
  "alias_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "display_name" TEXT NOT NULL,
  "display_name_key" TEXT NOT NULL,
  "service_key" TEXT NOT NULL,
  "service_key_normalized" TEXT NOT NULL,
  "candidate_count" INTEGER NOT NULL,
  "observation_count" INTEGER NOT NULL,
  "resolution_state" TEXT NOT NULL,
  "basis" TEXT NOT NULL,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  PRIMARY KEY(alias_id),
  UNIQUE(host_id, dataset_id, display_name_key, service_key_normalized),
  CHECK(resolution_state IN ('single','ambiguous'))
);
CREATE TABLE "ServiceEventCoverage" (
  "coverage_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "provider" TEXT NOT NULL,
  "event_id" INTEGER,
  "description" TEXT,
  "result" TEXT,
  "mapping_state" TEXT NOT NULL,
  "observed_count" INTEGER NOT NULL,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  PRIMARY KEY(coverage_id),
  UNIQUE(host_id, dataset_id, event_id),
  CHECK(mapping_state IN ('mapped','partial','unmapped'))
);
CREATE TABLE "ServiceLogObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "log_name" TEXT NOT NULL,
  "source_file" TEXT,
  "facts_db" TEXT,
  "facts_table" TEXT,
  "facts_generation" TEXT,
  "collection_state" TEXT NOT NULL,
  "input_row_count" INTEGER,
  "event_count" INTEGER,
  "service_event_count" INTEGER,
  "corrupted_count" INTEGER,
  "untimed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "error" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(observation_id),
  CHECK(collection_state IN ('collected','collected_empty','read_failed','not_collected','unknown'))
);
CREATE TABLE "ServiceMetadataReferences" (
  "reference_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "metadata_id" TEXT NOT NULL,
  "reference_kind" TEXT NOT NULL,
  PRIMARY KEY(reference_id),
  UNIQUE(host_id, dataset_id, metadata_id, reference_kind)
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1),('service_history',3);
"#;

const MAIN: &[&str] = &[
    "record_id",
    "host_id",
    "dataset_id",
    "timestamp",
    "overview_name",
    "account",
    "account_sid",
    "timestamp_kind",
    "event_type",
    "description",
    "timestamp_state",
    "record_context",
    "account_basis",
    "account_sid_raw",
    "subject_user_sid",
    "subject_user_name",
    "subject_domain",
    "subject_logon_id",
    "service_name",
    "service_name_source",
    "service_key",
    "service_key_source",
    "service_name_normalized",
    "service_key_normalized",
    "service_key_candidate",
    "service_key_candidate_basis",
    "group_key",
    "group_key_kind",
    "group_display_name",
    "image_path",
    "image_path_resolved",
    "image_path_state",
    "executable_path",
    "executable_path_resolved",
    "executable_path_key",
    "executable_path_kind",
    "executable_drive",
    "executable_basis",
    "command_arguments",
    "service_account",
    "service_account_sid",
    "service_account_sid_basis",
    "service_account_name_resolved",
    "state",
    "start_type_before",
    "start_type_after",
    "start_type_before_raw",
    "start_type_after_raw",
    "service_type",
    "service_type_raw",
    "control_code",
    "stop_reason",
    "stop_reason_code",
    "stop_comment",
    "dependency_service",
    "dependency_group",
    "driver_list_raw",
    "driver_count",
    "error_code_raw",
    "error_code_numeric",
    "error_code_hex",
    "error_code_format",
    "error_code_scope",
    "error_code_symbol",
    "termination_count",
    "termination_count_raw",
    "recovery_delay_ms",
    "recovery_delay_raw",
    "recovery_action_code",
    "recovery_action_raw",
    "recovery_action_text",
    "timeout_ms",
    "timeout_raw",
    "detail",
    "result",
    "result_basis",
    "audit_outcome",
    "event_id",
    "provider",
    "channel",
    "computer",
    "event_record_id",
    "level_name",
    "keywords_raw",
    "process_id",
    "thread_id",
    "payload_format",
    "payload_state",
    "mapping_state",
    "event_data_raw",
    "binary_data_raw",
    "binary_text",
    "binary_name_token",
    "binary_state_code",
    "binary_decode_state",
    "facts_status",
    "facts_error",
    "record_key",
    "source_file",
    "search_text",
];

const SOURCE_RECORDS: &[&str] = &[
    "record_id",
    "ordinal",
    "source_dataset_id",
    "source_artifact",
    "source_db",
    "source_table",
    "source_rowid",
    "source_field",
    "source_record_key",
    "source_file",
    "source_label",
];

const SERVICE_EVENT_FIELDS: &[&str] =
    &["record_id", "ordinal", "field_name", "field_origin", "field_value"];

const SERVICE_IDENTITIES: &[&str] = &[
    "identity_id",
    "host_id",
    "dataset_id",
    "group_key",
    "group_key_kind",
    "display_name",
    "service_key",
    "service_key_source",
    "event_count",
    "failure_count",
    "install_event_count",
    "first_observed_time",
    "last_observed_time",
    "distinct_path_count",
    "latest_image_path",
    "latest_image_path_time",
    "latest_image_path_record_id",
    "representative_basis",
    "path_observation_state",
];

const SERVICE_PATHS: &[&str] = &[
    "path_id",
    "host_id",
    "dataset_id",
    "group_key",
    "path_ordinal",
    "image_path",
    "image_path_resolved",
    "executable_path",
    "executable_path_key",
    "executable_path_kind",
    "executable_drive",
    "executable_basis",
    "command_arguments",
    "observation_count",
    "first_observed_time",
    "last_observed_time",
    "first_record_id",
    "last_record_id",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const SERVICE_STATE_OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "group_key",
    "event_id",
    "state_raw",
    "observation_count",
    "first_observed_time",
    "last_observed_time",
];

const SERVICE_NAME_ALIASES: &[&str] = &[
    "alias_id",
    "host_id",
    "dataset_id",
    "display_name",
    "display_name_key",
    "service_key",
    "service_key_normalized",
    "candidate_count",
    "observation_count",
    "resolution_state",
    "basis",
    "first_observed_time",
    "last_observed_time",
];

const SERVICE_EVENT_COVERAGE: &[&str] = &[
    "coverage_id",
    "host_id",
    "dataset_id",
    "provider",
    "event_id",
    "description",
    "result",
    "mapping_state",
    "observed_count",
    "first_observed_time",
    "last_observed_time",
];

const SERVICE_LOG_OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "log_name",
    "source_file",
    "facts_db",
    "facts_table",
    "facts_generation",
    "collection_state",
    "input_row_count",
    "event_count",
    "service_event_count",
    "corrupted_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

const SERVICE_METADATA_REFERENCES: &[&str] =
    &["reference_id", "host_id", "dataset_id", "metadata_id", "reference_kind"];

pub(super) const SPEC: DbSpec = DbSpec {
    name: "ServiceHistory",
    table: "ServiceHistory",
    columns: MAIN,
    children: &[
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
        ChildSpec { table: "ServiceEventFields", columns: SERVICE_EVENT_FIELDS },
        ChildSpec { table: "ServiceIdentities", columns: SERVICE_IDENTITIES },
        ChildSpec { table: "ServicePaths", columns: SERVICE_PATHS },
        ChildSpec { table: "ServiceStateObservations", columns: SERVICE_STATE_OBSERVATIONS },
        ChildSpec { table: "ServiceNameAliases", columns: SERVICE_NAME_ALIASES },
        ChildSpec { table: "ServiceEventCoverage", columns: SERVICE_EVENT_COVERAGE },
        ChildSpec { table: "ServiceLogObservations", columns: SERVICE_LOG_OBSERVATIONS },
        ChildSpec { table: "ServiceMetadataReferences", columns: SERVICE_METADATA_REFERENCES },
    ],
    ddl: DDL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::sqlite::Row;
    use std::path::PathBuf;

    struct Case {
        root: PathBuf,
    }

    impl Case {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("wina-svc-{name}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
            super::super::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
            Self { root }
        }

        /// Facts rows exist so provenance resolves to a real rowid.
        fn facts(&self, table: &str, rows: usize) {
            let path = self.root.join(format!("EVENTLOG/{table}.sqlite"));
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("CREATE TABLE \"{table}\"(EventData TEXT);")).unwrap();
            for _ in 0..rows {
                conn.execute(&format!("INSERT INTO \"{table}\"(EventData) VALUES('{{}}')"), []).unwrap();
            }
            drop(conn);
            stamp_facts_generation(&path, "facts-old").unwrap();
        }

        fn account(&self, sid: &str, name: &str) {
            let conn = Connection::open(self.root.join("_OVERVIEW/Metadata.sqlite")).unwrap();
            conn.execute(
                "INSERT INTO metadata(metadata_id,host_id,dataset_id,kind,scope,key,value,resolution_status,account_name,account_sid)
                 VALUES(?1,'host','new','account','machine',?2,?3,'resolved',?3,?4)",
                rusqlite::params![uuid::Uuid::new_v4().to_string(), sid.to_lowercase(), name, sid],
            ).unwrap();
        }

        fn run(&self, events: &EventLogOverviewCache) -> (usize, Connection) {
            let ctx = Ctx {
                out_dir: &self.root,
                target: &self.root,
                host_id: "host",
                dataset_id: "new",
                facts: FactsIndex::load(&self.root).unwrap(),
                meta: MetaLookup::load(&self.root).unwrap(),
            };
            let count = build(&ctx, events).unwrap();
            let db = Connection::open(self.root.join("_OVERVIEW/ServiceHistory.sqlite")).unwrap();
            (count, db)
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// One System-channel SCM facts row.
    fn scm(n: usize, event_id: &str, time: &str, data: &str) -> Row {
        event_row("System", "Service Control Manager", n, event_id, time, data, "")
    }

    fn event_row(table: &str, provider: &str, n: usize, event_id: &str, time: &str, data: &str, user: &str) -> Row {
        let mut row = Row::from([
            ("Provider".into(), provider.into()),
            ("Channel".into(), table.into()),
            ("Computer".into(), "WIN-TEST".into()),
            ("EventID".into(), event_id.into()),
            ("EventRecordID".into(), n.to_string()),
            ("LevelName".into(), "Information".into()),
            ("Keywords".into(), "0x8080000000000000".into()),
            ("timestamp".into(), time.into()),
            ("EventData".into(), data.into()),
            ("_record_key".into(), format!("{table}::{n}")),
            ("_source_file".into(), format!("C:/evidence/{table}.evtx")),
        ]);
        if !user.is_empty() {
            row.insert("UserID".into(), user.into());
        }
        row
    }

    /// A facts row whose EventData is SQL NULL: the key is absent entirely.
    fn absent_payload(n: usize, event_id: &str, time: &str) -> Row {
        let mut row = scm(n, event_id, time, "");
        row.remove("EventData");
        row
    }

    fn one<T: rusqlite::types::FromSql>(db: &Connection, sql: &str) -> T {
        db.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    // R02 · A08: every Service Control Manager record is stored, newly mapped
    // events keep their own meaning, and unknown ids are neither dropped nor
    // forced into a failure result.
    #[test]
    fn every_scm_event_is_stored_and_unknown_ids_stay_unmapped() {
        let case = Case::new("coverage");
        case.facts("System", 8);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7038", "2026-01-01 00:00:01.000", r#"{"param1":"wlidsvc","param2":"NT AUTHORITY\\SYSTEM","param3":"%%1722"}"#),
            scm(2, "7043", "2026-01-01 00:00:02.000", r#"{"param1":"WhiteDefenderServices"}"#),
            scm(3, "7030", "2026-01-01 00:00:03.000", r#"{"param1":"HelpuHostService"}"#),
            scm(4, "7024", "2026-01-01 00:00:04.000", r#"{"param1":"kpnclient","param2":"%%143"}"#),
            scm(5, "9999", "2026-01-01 00:00:05.000", r#"{"param1":"UnknownThing"}"#),
            event_row("System", "VfpExt", 6, "7036", "2026-01-01 00:00:06.000", r#"{"param1":"other"}"#, ""),
            // A recorded empty payload and a missing one are different facts.
            scm(7, "7035", "2026-01-01 00:00:07.000", ""),
            absent_payload(8, "7036", "2026-01-01 00:00:08.000"),
        ]);
        let (count, db) = case.run(&events);
        assert_eq!(count, 7, "non-SCM provider rows stay out, SCM rows all stored");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServiceHistory WHERE result='실패'"), 3);
        let empty: (String, String, String) = db
            .query_row("SELECT payload_state,payload_format,event_data_raw FROM ServiceHistory WHERE event_id=7035", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(empty, ("empty".into(), "absent".into(), String::new()));
        let missing: (String, Option<String>) = db
            .query_row("SELECT payload_state,event_data_raw FROM ServiceHistory WHERE event_id=7036", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(missing, ("absent".into(), None));
        assert_eq!(one::<String>(&db, "SELECT result FROM ServiceHistory WHERE event_id=7030"), "정보");
        let unknown: (String, Option<String>, String) = db
            .query_row("SELECT mapping_state,result,event_data_raw FROM ServiceHistory WHERE event_id=9999", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(unknown.0, "unmapped");
        assert_eq!(unknown.1, None, "an unmapped event is not classified");
        assert!(unknown.2.contains("UnknownThing"), "raw payload survives mapping gaps");
        assert_eq!(
            one::<i64>(&db, "SELECT observed_count FROM ServiceEventCoverage WHERE event_id=9999 AND mapping_state='unmapped'"),
            1
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServiceEventCoverage"), 7);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
        // R10: the collected evidence file reaches source_records.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_file IS NULL"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_dataset_id<>'facts-old'"), 0);
        // A08: the log observation describes the collection range, not absence of facts.
        assert_eq!(one::<i64>(&db, "SELECT service_event_count FROM ServiceLogObservations WHERE log_name='System'"), 7);
    }

    // R09 · A02: recovery counts, delays and codes survive with their raw text,
    // and only confirmed system error codes gain a symbol.
    #[test]
    fn recovery_and_error_fields_keep_raw_values_and_confirmed_symbols() {
        let case = Case::new("recovery");
        case.facts("System", 4);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7031", "2026-01-01 00:00:01.000", r#"{"param1":"UltraViewer Service","param2":"1","param3":"60000","param4":"1","param5":"서비스 다시 시작","Binary":"55006C00740072006100"}"#),
            scm(2, "7024", "2026-01-01 00:00:02.000", r#"{"param1":"kpnclient","param2":"%%143"}"#),
            scm(3, "7038", "2026-01-01 00:00:03.000", r#"{"param1":"wlidsvc","param2":"NT AUTHORITY\\SYSTEM","param3":"%%1722"}"#),
            scm(4, "7001", "2026-01-01 00:00:04.000", r#"{"param1":"Dependent","param2":"BaseSvc","param3":"%%1068"}"#),
        ]);
        let (_, db) = case.run(&events);
        let recovery: (i64, i64, i64, String, String) = db
            .query_row(
                "SELECT termination_count,recovery_delay_ms,recovery_action_code,recovery_action_text,recovery_delay_raw
                 FROM ServiceHistory WHERE event_id=7031",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(recovery, (1, 60000, 1, "서비스 다시 시작".into(), "60000".into()));
        let specific: (String, i64, String, Option<String>) = db
            .query_row(
                "SELECT error_code_raw,error_code_numeric,error_code_scope,error_code_symbol FROM ServiceHistory WHERE event_id=7024",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(specific, ("%%143".into(), 143, "service_specific".into(), None));
        let logon: (String, String, String) = db
            .query_row(
                "SELECT error_code_symbol,error_code_hex,service_account FROM ServiceHistory WHERE event_id=7038",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(logon, ("RPC_S_SERVER_UNAVAILABLE".into(), "0x6BA".into(), "NT AUTHORITY\\SYSTEM".into()));
        let dependency: (String, String) = db
            .query_row("SELECT dependency_service,error_code_symbol FROM ServiceHistory WHERE event_id=7001", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(dependency, ("BaseSvc".into(), "ERROR_SERVICE_DEPENDENCY_FAIL".into()));
        // A03: every payload field stays queryable without reading facts.
        assert_eq!(
            one::<String>(&db, "SELECT field_value FROM ServiceEventFields f JOIN ServiceHistory s USING(record_id) WHERE s.event_id=7031 AND f.field_name='param3'"),
            "60000"
        );
    }

    #[test]
    fn failed_recovery_uses_corrective_action_message_positions() {
        let case = Case::new("failed-recovery");
        case.facts("System", 2);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7032", "", r#"{"param1":"1","param2":"Restart the service","param3":"DNS Client","param4":"%%1056"}"#),
            scm(2, "7032", "", r#"{"Strings":["0","No action","LegacySvc","%%5"]}"#),
        ]);
        let (_, db) = case.run(&events);
        let rows: Vec<(String, String, i64, String, i64, Option<i64>)> = db
            .prepare("SELECT service_name,mapping_state,recovery_action_code,recovery_action_text,error_code_numeric,termination_count FROM ServiceHistory ORDER BY event_record_id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows, vec![
            ("DNS Client".into(), "mapped".into(), 1, "Restart the service".into(), 1056, None),
            ("LegacySvc".into(), "mapped".into(), 0, "No action".into(), 5, None),
        ]);
    }

    // R01 · A06: the recording actor and the service execution identity stay
    // separate, and names come only from confirmed metadata or well-known SIDs.
    #[test]
    fn actor_and_service_account_are_resolved_separately() {
        let case = Case::new("accounts");
        case.facts("System", 3);
        case.account("S-1-5-18", "LocalSystem");
        case.account("S-1-5-21-5-5-5-500", "Administrator");
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            event_row("System", "Service Control Manager", 1, "7045", "2026-01-01 00:00:01.000",
                r#"{"ServiceName":"Svc","ImagePath":"C:\\svc.exe","ServiceType":"사용자 모드 서비스","StartType":"자동 시작","AccountName":"LocalSystem"}"#,
                "S-1-5-21-5-5-5-500"),
            event_row("System", "Service Control Manager", 2, "7045", "2026-01-01 00:00:02.000",
                r#"{"ServiceName":"Drv","ImagePath":"system32\\drivers\\d.sys","ServiceType":"커널 모드 드라이버","StartType":"요청 시 시작","AccountName":""}"#,
                "S-1-5-18"),
            event_row("System", "Service Control Manager", 3, "7040", "2026-01-01 00:00:03.000",
                r#"{"param1":"Display","param2":"사용 안 함","param3":"자동 시작","param4":"Svc"}"#, ""),
        ]);
        let (_, db) = case.run(&events);
        let first: (String, String, String, String, String, String) = db
            .query_row(
                "SELECT account,account_sid,account_basis,service_account,service_account_sid,service_account_sid_basis
                 FROM ServiceHistory WHERE service_key='Svc' AND event_id=7045",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(first.0, "Administrator");
        assert_eq!(first.1, "S-1-5-21-5-5-5-500");
        assert_eq!(first.2, "event_user_sid");
        assert_eq!(first.3, "LocalSystem");
        assert_eq!(first.4, "S-1-5-18");
        assert_eq!(first.5, "metadata_name");
        // An unrecorded service account is NULL, never the recording actor.
        let second: (Option<String>, Option<String>, String) = db
            .query_row(
                "SELECT service_account,service_account_sid,account_sid FROM ServiceHistory WHERE service_key='Drv'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(second, (None, None, "S-1-5-18".into()));
        // An event without UserID keeps the common account NULL.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM ServiceHistory WHERE event_id=7040 AND account IS NULL AND account_sid IS NULL AND account_basis IS NULL"),
            1
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServiceMetadataReferences WHERE reference_kind='account'"), 2);
    }

    // R12 · A07: the command line stays whole, and the executable token is only
    // separated when the original text makes the boundary explicit.
    #[test]
    fn command_line_is_preserved_and_executable_token_has_a_basis() {
        let case = Case::new("paths");
        case.facts("System", 3);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7045", "2026-01-01 00:00:01.000",
                r#"{"ServiceName":"A","ImagePath":"\"C:\\Program Files\\App\\u.exe\" --system --service=update","StartType":"자동 시작"}"#),
            scm(2, "7045", "2026-01-01 00:00:02.000",
                r#"{"ServiceName":"B","ImagePath":"system32\\drivers\\wd\\KslD.sys"}"#),
            scm(3, "7045", "2026-01-01 00:00:03.000",
                r#"{"ServiceName":"C","ImagePath":"C:\\Program Files\\no quotes here"}"#),
        ]);
        let (_, db) = case.run(&events);
        let quoted: (String, String, String, String, String) = db
            .query_row(
                "SELECT image_path,executable_path,command_arguments,executable_basis,executable_path_kind
                 FROM ServiceHistory WHERE service_key='A'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(quoted.0, "\"C:\\Program Files\\App\\u.exe\" --system --service=update");
        assert_eq!(quoted.1, "C:\\Program Files\\App\\u.exe");
        assert_eq!(quoted.2, "--system --service=update");
        assert_eq!(quoted.3, "quoted");
        assert_eq!(quoted.4, "drive_absolute");
        let bare: (String, String, String) = db
            .query_row("SELECT executable_path,executable_basis,executable_path_kind FROM ServiceHistory WHERE service_key='B'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(bare, ("system32\\drivers\\wd\\KslD.sys".into(), "single_token".into(), "relative".into()));
        let ambiguous: (Option<String>, String, Option<String>) = db
            .query_row("SELECT executable_path,executable_basis,command_arguments FROM ServiceHistory WHERE service_key='C'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(ambiguous, (None, "ambiguous".into(), None), "an unquoted path with spaces is not split by guesswork");
    }

    // R03 · R04 · A04: comparison keys ignore case while the original text and
    // genuinely different candidates are kept apart; the representative path is
    // the latest observation, not the input order.
    #[test]
    fn grouping_is_case_insensitive_and_paths_keep_their_own_history() {
        let case = Case::new("grouping");
        case.facts("System", 6);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7045", "2026-02-01 00:00:00.000", r#"{"ServiceName":"Svc","ImagePath":"C:\\new.exe"}"#),
            scm(2, "7045", "2026-01-01 00:00:00.000", r#"{"ServiceName":"svc","ImagePath":"C:\\old.exe"}"#),
            scm(3, "7040", "2026-01-01 01:00:00.000", r#"{"param1":"Shared Display","param2":"사용 안 함","param3":"자동 시작","param4":"Svc"}"#),
            scm(4, "7036", "2026-01-01 02:00:00.000", r#"{"param1":"Shared Display","param2":"실행","Binary":"5300760063002F0034000000"}"#),
            scm(5, "7040", "2026-01-01 03:00:00.000", r#"{"param1":"Ambiguous","param2":"사용 안 함","param3":"자동 시작","param4":"KeyOne"}"#),
            scm(6, "7040", "2026-01-01 04:00:00.000", r#"{"param1":"ambiguous","param2":"사용 안 함","param3":"자동 시작","param4":"KeyTwo"}"#),
        ]);
        let (_, db) = case.run(&events);
        // Case-only differences compare equal but the recorded text is intact.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(DISTINCT group_key) FROM ServiceHistory WHERE event_id=7045"), 1);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(DISTINCT service_key) FROM ServiceHistory WHERE event_id=7045"), 2);
        // A single 7040 candidate links the display name to its key.
        assert_eq!(
            one::<String>(&db, "SELECT resolution_state FROM ServiceNameAliases WHERE display_name='Shared Display'"),
            "single"
        );
        assert_eq!(one::<String>(&db, "SELECT group_key_kind FROM ServiceHistory WHERE event_id=7036"), "alias_service_key");
        // Two different keys for one display name stay unmerged.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServiceNameAliases WHERE display_name_key='ambiguous' AND resolution_state='ambiguous'"), 2);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(DISTINCT group_key) FROM ServiceHistory WHERE service_key IN ('KeyOne','KeyTwo')"), 2);
        // A04: both install paths are stored; the representative is the latest.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServicePaths WHERE group_key='svc'"), 2);
        let identity: (String, String, i64, String) = db
            .query_row(
                "SELECT latest_image_path,latest_image_path_time,distinct_path_count,representative_basis
                 FROM ServiceIdentities WHERE group_key='svc'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(identity.0, "C:\\new.exe");
        assert_eq!(identity.1, "2026-02-01 00:00:00.000");
        assert_eq!(identity.2, 2);
        assert_eq!(identity.3, "latest_observed");
        // A05: raw state text is counted inside the observed range only.
        let state: (i64, String, String) = db
            .query_row(
                "SELECT observation_count,first_observed_time,last_observed_time FROM ServiceStateObservations WHERE state_raw='실행'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, (1, "2026-01-01 02:00:00.000".into(), "2026-01-01 02:00:00.000".into()));
    }

    // R13 · R14 · R08: unnamed driver-load records stay independent, never
    // expose the internal group key as a service name, and unrecorded times or
    // paths are stored as observations rather than absence.
    #[test]
    fn unnamed_driver_records_and_unrecorded_values_stay_distinguishable() {
        let case = Case::new("boundary");
        case.facts("System", 3);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7026", "2026-01-01 00:00:01.000", "{\"param1\":\"\\r\\ndam\"}"),
            scm(2, "7026", "", "{\"param1\":\"\\r\\ndam\"}"),
            scm(3, "7034", "2026-01-01 00:00:03.000", r#"{"param1":"GlassWire Control Service","param2":"1","Binary":"47006C00"}"#),
        ]);
        let (_, db) = case.run(&events);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(DISTINCT group_key) FROM ServiceHistory WHERE event_id=7026"), 2);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM ServiceHistory WHERE event_id=7026 AND service_name IS NULL AND service_key IS NULL AND group_display_name IS NULL AND group_key_kind='record'"),
            2
        );
        assert_eq!(one::<String>(&db, "SELECT driver_list_raw FROM ServiceHistory WHERE event_id=7026 AND timestamp IS NOT NULL"), "\r\ndam");
        let untimed: (Option<String>, String, Option<String>) = db
            .query_row("SELECT timestamp,timestamp_state,timestamp_kind FROM ServiceHistory WHERE event_id=7026 AND timestamp IS NULL", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(untimed, (None, "unrecorded".into(), None));
        // R14: a card without a recorded path says so for its own scope.
        assert_eq!(
            one::<String>(&db, "SELECT path_observation_state FROM ServiceIdentities WHERE group_key_kind='record' LIMIT 1"),
            "unrecorded_in_group"
        );
        assert_eq!(one::<i64>(&db, "SELECT untimed_count FROM ServiceLogObservations WHERE log_name='System'"), 1);
        // Binary evidence is decoded as a candidate, not as the recorded key.
        let binary: (String, Option<String>, String) = db
            .query_row("SELECT binary_name_token,service_key,service_key_candidate_basis FROM ServiceHistory WHERE event_id=7034", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(binary, ("Gl".into(), None, "binary_data".into()));
    }

    // R15: legacy EVT records carry positional strings; the documented message
    // order supplies the fields and the original payload is preserved.
    #[test]
    fn legacy_evt_strings_map_by_message_position() {
        let case = Case::new("evt");
        case.facts("System", 2);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7045", "2026-01-01 00:00:01.000",
                r#"{"Strings":["EvtSvc","C:\\evt.exe","사용자 모드 서비스","자동 시작","LocalSystem"],"EventType":4,"Category":0,"Data":"4500760074005300760063000000"}"#),
            scm(2, "7036", "2026-01-01 00:00:02.000",
                r#"{"Strings":["Legacy Display","실행"],"EventType":4,"Category":0}"#),
        ]);
        let (_, db) = case.run(&events);
        let install: (String, String, String, String, String, String) = db
            .query_row(
                "SELECT service_key,image_path,service_type,start_type_after,service_account,payload_format
                 FROM ServiceHistory WHERE event_id=7045",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(install, ("EvtSvc".into(), "C:\\evt.exe".into(), "사용자 모드 서비스".into(), "자동 시작".into(), "LocalSystem".into(), "evt_strings".into()));
        assert_eq!(one::<String>(&db, "SELECT binary_name_token FROM ServiceHistory WHERE event_id=7045"), "EvtSvc");
        assert_eq!(one::<String>(&db, "SELECT state FROM ServiceHistory WHERE event_id=7036"), "실행");
        assert_eq!(
            one::<String>(&db, "SELECT field_name FROM ServiceEventFields f JOIN ServiceHistory s USING(record_id) WHERE s.event_id=7036 AND f.ordinal=1"),
            "Strings[1]"
        );
    }

    // A01: service installation auditing is its own record context and is never
    // folded into a 7045 by matching time and name.
    #[test]
    fn security_install_audit_is_kept_beside_the_scm_record() {
        let case = Case::new("audit");
        case.facts("System", 1);
        case.facts("Security", 1);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7045", "2026-01-01 00:00:01.000", r#"{"ServiceName":"Dup","ImagePath":"C:\\dup.exe","StartType":"자동 시작"}"#),
            event_row("Security", "Microsoft-Windows-Security-Auditing", 1, "4697", "2026-01-01 00:00:01.000",
                r#"{"SubjectUserSid":"S-1-5-21-5-5-5-500","SubjectUserName":"Administrator","SubjectDomainName":"WIN-TEST","SubjectLogonId":"0x3e7","ServiceName":"Dup","ServiceFileName":"C:\\dup.exe","ServiceType":"0x10","ServiceStartType":"2","ServiceAccount":"LocalSystem"}"#,
                ""),
        ]);
        let (count, db) = case.run(&events);
        assert_eq!(count, 2, "the audit record and the SCM record both remain");
        let audit: (String, String, String, String, String, String) = db
            .query_row(
                "SELECT record_context,subject_user_sid,subject_logon_id,start_type_after_raw,start_type_after,service_type_raw
                 FROM ServiceHistory WHERE event_id=4697",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(audit.0, "security_audit");
        assert_eq!(audit.1, "S-1-5-21-5-5-5-500");
        assert_eq!(audit.2, "0x3e7");
        assert_eq!(audit.3, "2");
        assert_eq!(audit.4, "자동 시작");
        assert_eq!(audit.5, "0x10");
        assert_eq!(one::<String>(&db, "SELECT record_context FROM ServiceHistory WHERE event_id=7045"), "scm");
        // R05: the search column reaches identity, path, account and detail text.
        assert!(one::<String>(&db, "SELECT search_text FROM ServiceHistory WHERE event_id=4697").contains("LocalSystem"));
        assert!(one::<String>(&db, "SELECT search_text FROM ServiceHistory WHERE event_id=7045").contains("C:\\dup.exe"));
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM ServiceLogObservations WHERE log_name='Security'"), 1);
    }
}
