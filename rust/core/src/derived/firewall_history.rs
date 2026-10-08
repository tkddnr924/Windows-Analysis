//! Firewall rule, setting, profile and service evidence.
//! Raw provider values, confirmed labels and label certainty are stored apart;
//! unknown events keep every payload field instead of being dropped.
use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::schema::{ChildSpec, DbSpec};
use super::{Cell, Ctx, DerivedDb, Record};
use crate::overview::EventLogOverviewCache;
use crate::sqlite::Row;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{Map, Value};

const FIREWALL_PROVIDER: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";
const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";
const FIREWALL_LOG: &str = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall";
const LOGS: &[&str] = &[FIREWALL_LOG, "Security"];

/// Filtering-platform connection audits are a different evidence class
/// (A05): counted as observation scope, never stored as a rule event.
const CONNECTION_AUDIT_IDS: &[i64] = &[
    5146, 5147, 5148, 5149, 5150, 5151, 5152, 5153, 5154, 5155, 5156, 5157, 5158, 5159,
];

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

fn value(raw: &str) -> Cell {
    if raw.is_empty() {
        Cell::Null
    } else {
        Cell::Text(raw.to_string())
    }
}

fn opt(raw: Option<&str>) -> Cell {
    raw.map(value).unwrap_or(Cell::Null)
}

fn number(value: Option<i64>) -> Cell {
    value.map(Cell::Int).unwrap_or(Cell::Null)
}

fn rf<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// Only an actual integer becomes an integer; text stays in the raw column.
fn int_of(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::String(text) => {
            let text = text.trim();
            match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => text.parse().ok(),
            }
        }
        _ => None,
    }
}

/// Nested EventXML wins over the flat payload, matching the other builders.
fn lookup<'a>(payload: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    if let Some(Value::Object(inner)) = payload.get("EventXML") {
        if let Some(found) = inner.get(name) {
            return Some(found);
        }
    }
    payload.get(name)
}

/// First present field, including fields recorded as an empty string.
fn field_of<'a>(
    payload: &'a Map<String, Value>,
    names: &[&'static str],
) -> Option<(&'static str, &'a Value)> {
    names
        .iter()
        .find_map(|name| lookup(payload, name).map(|value| (*name, value)))
}

fn text_of(payload: &Map<String, Value>, names: &[&'static str]) -> Option<(&'static str, String)> {
    field_of(payload, names).map(|(name, value)| (name, scalar_text(value)))
}

fn present(payload: &Map<String, Value>, names: &[&'static str]) -> Option<String> {
    text_of(payload, names)
        .map(|(_, text)| text)
        .filter(|text| !text.is_empty())
}

/// One row per payload field, including fields this view has no column for.
fn flatten(payload: &Map<String, Value>) -> Vec<(String, String, String, &'static str)> {
    let mut fields = Vec::new();
    for (name, value) in payload {
        if name == "EventXML" {
            if let Value::Object(inner) = value {
                for (key, nested) in inner {
                    fields.push((
                        key.clone(),
                        format!("EventXML.{key}"),
                        scalar_text(nested),
                        kind_of(nested),
                    ));
                }
                continue;
            }
        }
        fields.push((
            name.clone(),
            name.clone(),
            scalar_text(value),
            kind_of(value),
        ));
    }
    fields
}

// ---------------------------------------------------------------------------
// Confirmed label tables
// ---------------------------------------------------------------------------

// MS-FASP FW_DIRECTION.
fn direction_label(value: i64) -> Option<&'static str> {
    match value {
        1 => Some("인바운드"),
        2 => Some("아웃바운드"),
        _ => None,
    }
}

// MS-FASP FW_RULE_ACTION.
fn action_label(value: i64) -> Option<&'static str> {
    match value {
        1 => Some("보안 허용"),
        2 => Some("차단"),
        3 => Some("허용"),
        _ => None,
    }
}

// IANA protocol numbers only; 256 (any) keeps its number without a name.
fn protocol_label(value: i64) -> Option<&'static str> {
    match value {
        1 => Some("ICMP"),
        2 => Some("IGMP"),
        6 => Some("TCP"),
        17 => Some("UDP"),
        41 => Some("IPv6"),
        47 => Some("GRE"),
        50 => Some("ESP"),
        51 => Some("AH"),
        58 => Some("ICMPv6"),
        89 => Some("OSPF"),
        132 => Some("SCTP"),
        _ => None,
    }
}

const PROFILE_BITS: &[(i64, &str)] = &[(1, "도메인"), (2, "개인"), (4, "공용")];

fn profile_label(mask: i64) -> Option<String> {
    let names: Vec<&str> = PROFILE_BITS
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

/// Bits outside the confirmed three are preserved, never discarded.
fn profile_unmapped(mask: i64) -> i64 {
    mask & !0b111
}

struct Definition {
    event_type: String,
    description: String,
    state: &'static str,
    basis: &'static str,
}

/// Microsoft-documented firewall audit events (Audit MPSSVC Rule-Level Policy
/// Change, Audit Other System Events, Audit Filtering Platform Connection).
fn documented_audit(event_id: i64) -> Option<(&'static str, &'static str)> {
    Some(match event_id {
        4944 => ("시작 시 활성 정책", "Windows 방화벽 시작 시 활성 정책 기록"),
        4945 => ("시작 시 규칙 나열", "Windows 방화벽 시작 시 규칙 나열"),
        4946 => ("규칙 추가 (감사)", "방화벽 예외 목록에 규칙 추가"),
        4947 => ("규칙 수정 (감사)", "방화벽 예외 목록의 규칙 수정"),
        4948 => ("규칙 삭제 (감사)", "방화벽 예외 목록의 규칙 삭제"),
        4949 => ("설정 기본값 복원", "방화벽 설정을 기본값으로 복원"),
        4950 => ("설정 변경 (감사)", "방화벽 설정 변경"),
        4951 => ("규칙 무시 — 주 버전", "주 버전 미인식으로 규칙 무시"),
        4952 => ("규칙 일부 무시 — 부 버전", "부 버전 미인식으로 규칙 일부 무시"),
        4953 => ("규칙 무시 — 구문 분석 실패", "규칙 구문 분석 실패로 무시"),
        4954 => ("그룹 정책 설정 적용", "방화벽 그룹 정책 설정 변경 적용"),
        4956 => ("활성 프로필 변경", "방화벽 활성 프로필 변경"),
        4957 => ("규칙 미적용", "방화벽이 규칙을 적용하지 않음"),
        4958 => (
            "규칙 미적용 — 미구성 항목",
            "구성되지 않은 항목을 참조해 규칙 미적용",
        ),
        5024 => ("방화벽 서비스 시작", "Windows 방화벽 서비스 시작 성공"),
        5025 => ("방화벽 서비스 중지", "Windows 방화벽 서비스 중지"),
        5027 => (
            "정책 읽기 실패",
            "로컬 저장소에서 정책을 가져오지 못함 — 현재 정책 유지",
        ),
        5028 => (
            "정책 구문 분석 실패",
            "새 정책 구문 분석 실패 — 현재 정책 유지",
        ),
        5029 => ("드라이버 초기화 실패", "서비스가 드라이버 초기화 실패"),
        5030 => ("방화벽 서비스 시작 실패", "Windows 방화벽 서비스 시작 실패"),
        5031 => ("인바운드 수신 차단", "응용 프로그램의 인바운드 수신 차단"),
        5032 => ("차단 알림 실패", "차단 사실을 사용자에게 알리지 못함"),
        5033 => ("방화벽 드라이버 시작", "Windows 방화벽 드라이버 시작 성공"),
        5034 => ("방화벽 드라이버 중지", "Windows 방화벽 드라이버 중지"),
        5035 => ("방화벽 드라이버 시작 실패", "Windows 방화벽 드라이버 시작 실패"),
        5037 => (
            "방화벽 드라이버 런타임 오류",
            "드라이버가 심각한 런타임 오류로 종료",
        ),
        _ => return None,
    })
}

/// Labels that existed in the approved view before provider definitions were
/// checked. They are kept, but never presented as confirmed.
fn legacy_channel_label(event_id: i64) -> Option<&'static str> {
    match event_id {
        2004 => Some("규칙 추가"),
        2005 => Some("규칙 변경"),
        2006 => Some("규칙 삭제"),
        2033 => Some("모든 규칙 삭제"),
        2002 | 2003 => Some("설정 변경"),
        2011 => Some("수신 차단 알림"),
        _ => None,
    }
}

fn classify(provider: &str, event_id: Option<i64>, raw_id: &str, family: &'static str) -> Definition {
    if provider == SECURITY_PROVIDER {
        if let Some((event_type, description)) = event_id.and_then(documented_audit) {
            return Definition {
                event_type: event_type.to_string(),
                description: description.to_string(),
                state: "confirmed_documented",
                basis: "Microsoft 감사 문서(MPSSVC 규칙 수준 정책 변경·기타 시스템 이벤트·필터링 플랫폼 연결)",
            };
        }
    }
    // 2010 carries InterfaceGuid/InterfaceName/OldProfile/NewProfile: the
    // event's subject is confirmed by its own schema, the values are not.
    if event_id == Some(2010) {
        return Definition {
            event_type: "프로필 전환".into(),
            description: "인터페이스별 적용 프로필 값 기록(Old/New 원문 보존)".into(),
            state: "confirmed_schema",
            basis: "payload 필드 InterfaceGuid/InterfaceName/OldProfile/NewProfile",
        };
    }
    if let Some(label) = event_id.and_then(legacy_channel_label) {
        return Definition {
            event_type: label.to_string(),
            description: format!("기존 확정 뷰 라벨 유지 — 기록된 필드군: {family}"),
            state: "legacy_label_unconfirmed",
            basis: "기존 뷰 라벨 유지 — 수집 증거에 제공자 메시지·스키마 없음",
        };
    }
    Definition {
        event_type: if raw_id.is_empty() {
            "방화벽 이벤트".into()
        } else {
            format!("방화벽 이벤트 {raw_id}")
        },
        description: format!("제공자 정의 미확인 — 기록된 필드군: {family}"),
        state: "unconfirmed",
        basis: "수집 증거에 제공자 메시지·스키마 없음",
    }
}

/// Family of the payload as observed, never as assumed semantics.
fn payload_family(payload: &Map<String, Value>) -> &'static str {
    let has = |name: &str| lookup(payload, name).is_some();
    if payload.is_empty() {
        return "none";
    }
    if has("RuleId") || has("RuleName") {
        if has("Direction") || has("Protocol") || has("LocalPorts") || has("Action") {
            return "rule_definition";
        }
        return "rule_reference";
    }
    if has("SettingType") || has("SettingValue") || has("SettingValueString") {
        return "setting_change";
    }
    if has("Store Type") || has("StoreType") {
        return "store_operation";
    }
    if has("PolicyChange") {
        return "policy_change";
    }
    if has("NewProfile") || has("OldProfile") || has("InterfaceGuid") {
        return "profile_change";
    }
    "other"
}

// ---------------------------------------------------------------------------
// Address and port entries
// ---------------------------------------------------------------------------

fn looks_like_address(entry: &str) -> bool {
    !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%'))
}

fn address_kind(entry: &str) -> &'static str {
    if entry == "*" {
        return "any";
    }
    if entry.contains('/') {
        return "subnet";
    }
    if let Some((start, end)) = entry.split_once('-') {
        if looks_like_address(start.trim()) && looks_like_address(end.trim()) {
            return "range";
        }
    }
    if looks_like_address(entry) {
        return "address";
    }
    "keyword"
}

fn port_entry(entry: &str) -> (&'static str, Option<i64>, Option<i64>) {
    if entry == "*" {
        return ("any", None, None);
    }
    if let Some((start, end)) = entry.split_once('-') {
        if let (Ok(start), Ok(end)) = (start.trim().parse::<i64>(), end.trim().parse::<i64>()) {
            return ("range", Some(start), Some(end));
        }
    }
    match entry.parse::<i64>() {
        Ok(port) => ("single", Some(port), Some(port)),
        Err(_) => ("keyword", None, None),
    }
}

fn entries(raw: &str) -> Vec<&str> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

fn path_kind(raw: &str) -> &'static str {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "empty";
    }
    if trimmed.contains('%') {
        return "environment_variable";
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("\\device\\") || lower.starts_with("\\\\?\\") || lower.starts_with("\\??\\") {
        return "device";
    }
    if trimmed.starts_with("\\\\") {
        return "unc";
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return "drive_absolute";
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        return "relative";
    }
    "bare_name"
}

/// Expand only what the evidence asks to expand. A literal path needs no
/// resolution, so it stays NULL as `literal`; `unresolved` means an
/// environment variable was present but no stored value established it.
/// Firewall payloads never state the user context of a recorded path, so the
/// expansion is machine-scoped and never borrows the change subject's SID.
fn resolve(ctx: &Ctx, raw: &str) -> (Cell, &'static str) {
    if !raw.contains('%') {
        return (Cell::Null, "literal");
    }
    let resolved = ctx.meta.resolve_path(raw, None);
    let basis = if matches!(resolved, Cell::Text(_)) {
        "metadata_machine_environment"
    } else {
        "unresolved"
    };
    (resolved, basis)
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

struct Parsed<'a> {
    row: &'a Row,
    payload: Map<String, Value>,
    fields: Vec<(String, String, String, &'static str)>,
    family: &'static str,
    payload_state: &'static str,
    rule_id: Option<String>,
    timestamp: String,
}

fn set_pair(
    record: &mut Record,
    payload: &Map<String, Value>,
    raw_column: &str,
    int_column: &str,
    names: &[&'static str],
) -> Option<i64> {
    let Some((_, found)) = field_of(payload, names) else {
        return None;
    };
    record.set(raw_column, value(&scalar_text(found)));
    let parsed = int_of(found);
    record.set(int_column, number(parsed));
    parsed
}

fn record(ctx: &Ctx, parsed: &Parsed<'_>) -> Result<Record> {
    let row = parsed.row;
    let payload = &parsed.payload;
    let provider = rf(row, "Provider");
    let raw_id = rf(row, "EventID");
    let event_id = raw_id.parse::<i64>().ok();
    let definition = classify(provider, event_id, raw_id, parsed.family);

    let mut record = ctx.record(&SPEC);
    record.timestamp(&parsed.timestamp, "이벤트 기록 시각");
    record.set(
        "timestamp_state",
        value(if parsed.timestamp.is_empty() {
            "unrecorded"
        } else {
            "recorded"
        }),
    );
    record.set("event_type", value(&definition.event_type));
    record.set("description", value(&definition.description));
    record.set("event_definition_state", value(definition.state));
    record.set("event_definition_basis", value(definition.basis));
    record.set(
        "event_family",
        value(if provider == SECURITY_PROVIDER {
            "security_audit"
        } else {
            "firewall_channel"
        }),
    );
    record.set("payload_family", value(parsed.family));
    record.set("payload_state", value(parsed.payload_state));

    // R05: the explicit change subject, never the recording service SID.
    let subject = present(payload, &["ModifyingUser"])
        .map(|text| ("modifying_user", "ModifyingUser", text))
        .or_else(|| {
            present(payload, &["SubjectUserSid"])
                .map(|text| ("audit_subject", "SubjectUserSid", text))
        })
        .or_else(|| {
            present(payload, &["SubjectUserName"])
                .map(|text| ("audit_subject", "SubjectUserName", text))
        });
    if let Some((role, basis, raw)) = &subject {
        record.account(raw, &ctx.meta);
        record.set("account_role", value(role));
        record.set("account_basis", value(basis));
    }
    // The change subject is the changer, not the user context of a recorded
    // application path: firewall payloads never state whose environment the
    // path belongs to, so expansion stays machine-scoped (see `resolve`).

    let modifying_user = text_of(payload, &["ModifyingUser"]).map(|(_, text)| text);
    record.set("modifying_user_raw", opt(modifying_user.as_deref()));
    if let Some(sid) = modifying_user.as_deref().filter(|raw| super::is_sid(raw)) {
        record.set("modifying_user_sid", value(sid));
        record.set("modifying_user_name", opt(ctx.meta.account_name(sid).as_deref()));
    }
    for (column, names) in [
        ("subject_user_sid", &["SubjectUserSid"][..]),
        ("subject_user_name", &["SubjectUserName"][..]),
        ("subject_domain", &["SubjectDomainName"][..]),
        ("subject_logon_id", &["SubjectLogonId"][..]),
    ] {
        record.set(column, opt(present(payload, names).as_deref()));
    }
    record.set("system_user_sid", value(rf(row, "UserID")));

    // Rule identity and the registered rule body (A01).
    let rule_id = parsed.rule_id.clone();
    record.set("rule_id", opt(rule_id.as_deref()));
    record.set("rule_name", opt(present(payload, &["RuleName"]).as_deref()));
    record.set("service", opt(present(payload, &["ServiceName"]).as_deref()));
    for (column, names) in [
        ("embedded_context", &["EmbeddedContext"][..]),
        ("policy_app_id", &["PolicyAppId"][..]),
        (
            "remote_machine_authorization_list",
            &["RemoteMachineAuthorizationList"][..],
        ),
        (
            "remote_user_authorization_list",
            &["RemoteUserAuthorizationList"][..],
        ),
        ("interface_name", &["InterfaceName"][..]),
        ("interface_guid", &["InterfaceGuid"][..]),
        ("setting_value_string", &["SettingValueString"][..]),
        ("detail", &["Reason", "Message", "Description"][..]),
    ] {
        record.set(column, opt(present(payload, names).as_deref()));
    }
    for (raw_column, int_column, names) in [
        ("origin_raw", "origin", &["Origin"][..]),
        ("rule_status_raw", "rule_status", &["RuleStatus"][..]),
        ("error_code_raw", "error_code", &["ErrorCode"][..]),
        ("schema_version_raw", "schema_version", &["SchemaVersion"][..]),
        ("rule_active_raw", "rule_active", &["Active"][..]),
        ("rule_flags_raw", "rule_flags", &["Flags"][..]),
        ("edge_traversal_raw", "edge_traversal", &["EdgeTraversal"][..]),
        (
            "loose_source_mapped_raw",
            "loose_source_mapped",
            &["LooseSourceMapped"][..],
        ),
        (
            "local_only_mapped_raw",
            "local_only_mapped",
            &["LocalOnlyMapped"][..],
        ),
        ("security_options_raw", "security_options", &["SecurityOptions"][..]),
        ("setting_type_raw", "setting_type", &["SettingType", "Type"][..]),
        (
            "setting_value_size_raw",
            "setting_value_size",
            &["SettingValueSize"][..],
        ),
        ("store_type_raw", "store_type", &["Store Type", "StoreType"][..]),
        ("policy_change_raw", "policy_change", &["PolicyChange"][..]),
    ] {
        set_pair(&mut record, payload, raw_column, int_column, names);
    }
    // R07: the raw setting bytes stay exactly as recorded.
    record.set(
        "setting_value_raw",
        opt(text_of(payload, &["SettingValue", "Value"])
            .map(|(_, text)| text)
            .as_deref()),
    );

    // R02: original text, confirmed number and confirmed name are separate.
    let direction = set_pair(&mut record, payload, "direction_raw", "direction_value", &["Direction"]);
    record.set("direction", opt(direction.and_then(direction_label)));
    let action = set_pair(&mut record, payload, "action_raw", "action_value", &["Action"]);
    record.set("action", opt(action.and_then(action_label)));
    let protocol = set_pair(&mut record, payload, "protocol_raw", "protocol_number", &["Protocol"]);
    record.set("protocol", opt(protocol.and_then(protocol_label)));

    // R06: mask, confirmed bits and unmapped bits all survive.
    for (raw_column, mask_column, label_column, unmapped_column, names) in [
        (
            "profiles_raw",
            "profiles_mask",
            "profiles",
            "profiles_unmapped_bits",
            &["Profiles", "Profile", "ProfileChanged"][..],
        ),
        (
            "old_profile_raw",
            "old_profile_mask",
            "old_profile",
            "old_profile_unmapped_bits",
            &["OldProfile"][..],
        ),
        (
            "new_profile_raw",
            "new_profile_mask",
            "new_profile",
            "new_profile_unmapped_bits",
            &["NewProfile"][..],
        ),
    ] {
        let mask = set_pair(&mut record, payload, raw_column, mask_column, names);
        record.set(label_column, opt(mask.and_then(profile_label).as_deref()));
        record.set(unmapped_column, number(mask.map(profile_unmapped)));
    }

    // R03/R14: rule lists and single observed values are different columns.
    let local_addresses = present(payload, &["LocalAddresses"]);
    let remote_addresses = present(payload, &["RemoteAddresses"]);
    record.set("local_addresses", opt(local_addresses.as_deref()));
    record.set("remote_addresses", opt(remote_addresses.as_deref()));
    let single_address = text_of(payload, &["LocalAddress", "RemoteAddress", "RemoteIp", "IpAddress"]);
    record.set(
        "local_address",
        opt(present(payload, &["LocalAddress"]).as_deref()),
    );
    record.set(
        "remote_address",
        opt(present(payload, &["RemoteAddress", "RemoteIp", "IpAddress"]).as_deref()),
    );
    record.set(
        "single_address_basis",
        opt(single_address.as_ref().map(|(name, _)| *name)),
    );
    let attribution = match (
        local_addresses.is_some() || remote_addresses.is_some(),
        single_address.is_some(),
    ) {
        (true, _) => Some("rule_definition"),
        (false, true) => Some("observed_connection"),
        (false, false) => None,
    };
    record.set("address_attribution", opt(attribution));

    let local_ports = present(payload, &["LocalPorts"]);
    let remote_ports = present(payload, &["RemotePorts"]);
    record.set("local_ports", opt(local_ports.as_deref()));
    record.set("remote_ports", opt(remote_ports.as_deref()));
    let local_single = text_of(payload, &["LocalPort", "Port"]);
    let remote_single = text_of(payload, &["RemotePort"]);
    record.set(
        "local_port_raw",
        opt(local_single
            .as_ref()
            .map(|(_, text)| text.as_str())
            .filter(|text| !text.is_empty())),
    );
    record.set(
        "remote_port_raw",
        opt(remote_single
            .as_ref()
            .map(|(_, text)| text.as_str())
            .filter(|text| !text.is_empty())),
    );
    record.set(
        "local_port",
        number(local_single.as_ref().and_then(|(_, text)| text.trim().parse().ok())),
    );
    record.set(
        "remote_port",
        number(remote_single.as_ref().and_then(|(_, text)| text.trim().parse().ok())),
    );
    record.set(
        "single_port_basis",
        opt(local_single
            .as_ref()
            .or(remote_single.as_ref())
            .map(|(name, _)| *name)),
    );

    // R13/A07: target application and modifying application stay apart.
    let app = text_of(payload, &["ApplicationPath", "Application", "Application Path"]);
    record.set(
        "app_path_state",
        value(match app.as_ref().map(|(_, text)| text.as_str()) {
            None => "absent",
            Some("") => "empty",
            Some(_) => "recorded",
        }),
    );
    let app_path = app
        .as_ref()
        .map(|(_, text)| text.clone())
        .filter(|text| !text.is_empty());
    record.set("app_path", opt(app_path.as_deref()));
    let modifying_app = present(payload, &["ModifyingApplication"]);
    record.set("modifying_app", opt(modifying_app.as_deref()));
    for (column, raw) in [
        ("app_path_resolved", app_path.as_deref()),
        ("modifying_app_resolved", modifying_app.as_deref()),
    ] {
        let resolved = raw.map(|raw| resolve(ctx, raw).0).unwrap_or(Cell::Null);
        record.set(column, resolved);
    }

    record.set("event_id", number(event_id));
    for (column, key) in [
        ("provider", "Provider"),
        ("channel", "Channel"),
        ("computer", "Computer"),
        ("event_record_id", "EventRecordID"),
        ("level_name", "LevelName"),
        ("keywords_raw", "Keywords"),
        ("process_id", "ProcessID"),
        ("thread_id", "ThreadID"),
        ("activity_id", "ActivityID"),
        ("related_activity_id", "RelatedActivityID"),
        ("facts_status", "_status"),
        ("facts_error", "_error"),
        ("record_key", "_record_key"),
        ("source_file", "_source_file"),
    ] {
        record.set(column, value(rf(row, key)));
    }
    // A recorded but empty payload is evidence: facts keep SQL NULL as an
    // absent key, so only a missing key becomes NULL here.
    record.set(
        "event_data_raw",
        row.get("EventData")
            .cloned()
            .map(Cell::Text)
            .unwrap_or(Cell::Null),
    );

    // R10: every contract field, rule_id and account_sid included.
    let mut search: Vec<String> = vec![definition.event_type.clone(), definition.description.clone()];
    for cell in [
        record.get("rule_name"),
        record.get("rule_id"),
        record.get("app_path"),
        record.get("app_path_resolved"),
        record.get("service"),
        record.get("local_ports"),
        record.get("remote_ports"),
        record.get("local_addresses"),
        record.get("remote_addresses"),
        record.get("local_address"),
        record.get("remote_address"),
        record.get("profiles"),
        record.get("modifying_app"),
        record.get("modifying_app_resolved"),
        record.get("modifying_user_raw"),
        record.get("account"),
        record.get("account_sid"),
        record.get("interface_name"),
        record.get("interface_guid"),
        record.get("setting_value_string"),
        record.get("detail"),
        record.get("provider"),
    ]
    .into_iter()
    .flatten()
    {
        if let Cell::Text(text) = cell {
            search.push(text.clone());
        }
    }
    if !raw_id.is_empty() {
        search.push(raw_id.to_string());
    }
    record.set("search_text", Cell::Text(search.join(" ")));

    // Children: payload fields, addresses, ports and application paths.
    for (name, path, raw, kind) in &parsed.fields {
        record.child(
            "FirewallEventFields",
            vec![value(name), value(path), value(raw), value(kind)],
        );
    }
    for (role, raw, attribution) in [
        ("local", local_addresses.clone(), "rule_definition"),
        ("remote", remote_addresses.clone(), "rule_definition"),
        (
            "local",
            present(payload, &["LocalAddress"]),
            "observed_connection",
        ),
        (
            "remote",
            present(payload, &["RemoteAddress", "RemoteIp", "IpAddress"]),
            "observed_connection",
        ),
    ] {
        let Some(raw) = raw else { continue };
        for entry in entries(&raw) {
            record.child(
                "FirewallAddresses",
                vec![
                    value(role),
                    value(entry),
                    value(address_kind(entry)),
                    value(attribution),
                ],
            );
        }
    }
    for (role, raw, attribution) in [
        ("local", local_ports.clone(), "rule_definition"),
        ("remote", remote_ports.clone(), "rule_definition"),
        (
            "local",
            local_single
                .as_ref()
                .map(|(_, text)| text.clone())
                .filter(|text| !text.is_empty()),
            "observed_connection",
        ),
        (
            "remote",
            remote_single
                .as_ref()
                .map(|(_, text)| text.clone())
                .filter(|text| !text.is_empty()),
            "observed_connection",
        ),
    ] {
        let Some(raw) = raw else { continue };
        for entry in entries(&raw) {
            let (kind, start, end) = port_entry(entry);
            record.child(
                "FirewallPorts",
                vec![
                    value(role),
                    value(entry),
                    value(kind),
                    number(start),
                    number(end),
                    value(attribution),
                ],
            );
        }
    }
    for (role, raw) in [
        ("target_app", app_path.as_deref()),
        ("modifying_app", modifying_app.as_deref()),
    ] {
        let Some(raw) = raw else { continue };
        let (resolved, basis) = resolve(ctx, raw);
        record.child(
            "FirewallAppPaths",
            vec![
                value(role),
                value(raw),
                resolved,
                value(basis),
                value(path_kind(raw)),
                Cell::Null,
            ],
        );
    }

    let source = ctx
        .facts
        .source_from_record_key(
            rf(row, "_record_key"),
            Some("EventData"),
            Some(rf(row, "_source_file")),
            Some(definition.event_type.as_str()),
        )?
        .ok_or_else(|| {
            anyhow!(
                "방화벽 이벤트의 facts 출처를 찾지 못했습니다: {}",
                rf(row, "_record_key")
            )
        })?;
    record.source(Some(source));
    Ok(record)
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

#[derive(Default)]
struct LogScope {
    count: i64,
    corrupt: i64,
    untimed: i64,
    firewall: i64,
    connection: i64,
    first: Option<String>,
    last: Option<String>,
    source_file: Option<String>,
}

fn relevant_log(name: &str) -> bool {
    LOGS.iter().any(|log| name.eq_ignore_ascii_case(log))
        || name
            .strip_prefix("Security_")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
        || name
            .to_ascii_lowercase()
            .starts_with(&FIREWALL_LOG.to_ascii_lowercase())
}

pub(super) fn build(ctx: &Ctx, cache: &EventLogOverviewCache) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut scope: BTreeMap<String, LogScope> = BTreeMap::new();
    let mut parsed: Vec<Parsed<'_>> = Vec::new();

    for row in cache.rows() {
        let table = rf(row, "_record_key")
            .split("::")
            .next()
            .unwrap_or("")
            .to_string();
        let provider = rf(row, "Provider");
        let channel = rf(row, "Channel");
        let raw_id = rf(row, "EventID");
        let event_id = raw_id.parse::<i64>().ok();
        let corrupted = rf(row, "_status") == "corrupted_chunk";
        let timestamp = rf(row, "timestamp").to_string();
        let tracked = relevant_log(&table);
        if tracked {
            let entry = scope.entry(table.clone()).or_default();
            if entry.source_file.is_none() {
                entry.source_file =
                    Some(rf(row, "_source_file").to_string()).filter(|file| !file.is_empty());
            }
            if corrupted {
                entry.corrupt += 1;
            } else {
                entry.count += 1;
                if timestamp.is_empty() {
                    entry.untimed += 1;
                } else {
                    entry.first = Some(match entry.first.take() {
                        Some(first) if first <= timestamp => first,
                        _ => timestamp.clone(),
                    });
                    entry.last = Some(match entry.last.take() {
                        Some(last) if last >= timestamp => last,
                        _ => timestamp.clone(),
                    });
                }
                if event_id.is_some_and(|id| CONNECTION_AUDIT_IDS.contains(&id)) {
                    entry.connection += 1;
                }
            }
        }

        // Every event of the firewall channel is kept, known or not.
        let from_channel = provider == FIREWALL_PROVIDER || channel.starts_with(FIREWALL_PROVIDER);
        let keep = from_channel
            || (provider == SECURITY_PROVIDER
                && event_id.is_some_and(|id| documented_audit(id).is_some()));
        if !keep {
            continue;
        }
        if tracked && !corrupted {
            scope.entry(table).or_default().firewall += 1;
        }
        let raw_payload = row.get("EventData");
        let payload =
            crate::overview::parse_eventdata(raw_payload.map(String::as_str).unwrap_or(""));
        // Facts drop a SQL NULL column, so an absent key and a recorded but
        // empty payload are different observations.
        let payload_state = match raw_payload.map(|raw| raw.trim().is_empty()) {
            None => "absent",
            Some(true) => "empty",
            Some(false) if payload.is_empty() => "unparsed",
            Some(false) => "recorded",
        };
        parsed.push(Parsed {
            row,
            fields: flatten(&payload),
            family: payload_family(&payload),
            rule_id: present(&payload, &["RuleId"]),
            payload_state,
            payload,
            timestamp,
        });
    }

    let mut records = parsed
        .iter()
        .map(|event| record(ctx, event))
        .collect::<Result<Vec<_>>>()?;

    // A01: rule event order and the observed differences of the same RuleId.
    let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, event) in parsed.iter().enumerate() {
        if let Some(rule_id) = event.rule_id.as_deref() {
            groups.entry(rule_id).or_default().push(index);
        }
    }
    for indexes in groups.values() {
        let mut ordered = indexes.clone();
        ordered.sort_by(|left, right| {
            let first = &parsed[*left];
            let second = &parsed[*right];
            (first.timestamp.is_empty(), &first.timestamp, *left).cmp(&(
                second.timestamp.is_empty(),
                &second.timestamp,
                *right,
            ))
        });
        let total = ordered.len() as i64;
        let mut previous: Option<usize> = None;
        for (sequence, index) in ordered.iter().enumerate() {
            records[*index].set("rule_event_sequence", Cell::Int(sequence as i64));
            records[*index].set("rule_event_count", Cell::Int(total));
            if parsed[*index].family != "rule_definition" {
                continue;
            }
            if let Some(previous) = previous {
                let before = field_values(&parsed[previous].fields);
                let after = field_values(&parsed[*index].fields);
                let previous_id = records[previous].record_id.clone();
                let names: BTreeSet<&str> = before.keys().chain(after.keys()).copied().collect();
                for name in names {
                    let (old, new) = (before.get(name), after.get(name));
                    if old == new {
                        continue;
                    }
                    records[*index].child(
                        "FirewallRuleChanges",
                        vec![
                            value(name),
                            opt(old.copied()),
                            opt(new.copied()),
                            value(&previous_id),
                            value("same_rule_id_previous_rule_definition_event"),
                        ],
                    );
                }
            }
            previous = Some(*index);
        }
    }

    // Same order as the rule sequence above, so a difference row never
    // references a parent row that has not been written yet.
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by(|left, right| {
        let first = &parsed[*left];
        let second = &parsed[*right];
        (first.timestamp.is_empty(), &first.timestamp, *left).cmp(&(
            second.timestamp.is_empty(),
            &second.timestamp,
            *right,
        ))
    });
    let mut pending: Vec<Option<Record>> = records.into_iter().map(Some).collect();
    for index in order {
        if let Some(record) = pending[index].take() {
            db.write(record)?;
        }
    }
    observations(ctx, &db, scope)?;
    policy_snapshot(ctx, &db)?;
    db.finish()
}

fn field_values<'a>(fields: &'a [(String, String, String, &'static str)]) -> BTreeMap<&'a str, &'a str> {
    fields
        .iter()
        .map(|(name, _, raw, _)| (name.as_str(), raw.as_str()))
        .collect()
}

// ---------------------------------------------------------------------------
// Observation scope (A04/A05/A08)
// ---------------------------------------------------------------------------

fn observations(ctx: &Ctx, db: &DerivedDb, mut scope: BTreeMap<String, LogScope>) -> Result<()> {
    let path = ctx.out_dir.join("EVENTLOG/EventLogInputs.sqlite");
    let mut discovered = false;
    let mut seen: HashSet<String> = HashSet::new();
    if path.exists() {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        discovered = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM EventLogInputs WHERE status='discovery_complete')",
            [],
            |row| row.get(0),
        )?;
        let mut query = conn.prepare(
            "SELECT rowid,source_file,facts_db,facts_table,status,row_count,error FROM EventLogInputs
             WHERE status<>'discovery_complete' ORDER BY rowid",
        )?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let file: Option<String> = row.get(1)?;
            let table: String = row
                .get::<_, Option<String>>(3)?
                .filter(|table| !table.is_empty())
                .unwrap_or_else(|| {
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
            seen.insert(table.to_ascii_lowercase());
            let status: String = row.get(4)?;
            let input_rows = row
                .get::<_, Option<String>>(5)?
                .and_then(|count| count.parse::<i64>().ok());
            let state = match (status.as_str(), input_rows) {
                ("read_failed", _) => "read_failed",
                ("parsed", Some(0)) => "collected_empty",
                ("parsed", Some(_)) => "collected",
                _ => "unknown",
            };
            let source = ctx
                .facts
                .source_from_row(
                    &path,
                    "EventLogInputs",
                    row.get(0)?,
                    file.as_deref(),
                    Some("collection_observation"),
                )?
                .ok_or_else(|| anyhow!("EventLogInputs 출처를 찾지 못했습니다"))?;
            let stats = scope.remove(table.as_str()).unwrap_or_default();
            let parsed = status == "parsed";
            insert_observation(
                ctx,
                db,
                &table,
                file.as_deref(),
                row.get::<_, Option<String>>(2)?
                    .filter(|value| !value.is_empty())
                    .as_deref(),
                row.get::<_, Option<String>>(3)?
                    .filter(|value| !value.is_empty())
                    .as_deref(),
                state,
                input_rows,
                parsed.then_some(&stats),
                row.get::<_, Option<String>>(6)?.as_deref(),
                Some((
                    source.dataset.as_str(),
                    source.db.as_str(),
                    source.table.as_str(),
                    source.rowid,
                )),
            )?;
        }
    }
    for (table, stats) in &scope {
        seen.insert(table.to_ascii_lowercase());
        let facts = ctx.facts.by_stem(table);
        insert_observation(
            ctx,
            db,
            table,
            stats.source_file.as_deref(),
            facts.map(|facts| facts.relative.as_str()),
            Some(table.as_str()),
            "unknown",
            None,
            Some(stats),
            None,
            None,
        )?;
    }
    for log in LOGS {
        if seen.contains(&log.to_ascii_lowercase()) {
            continue;
        }
        insert_observation(
            ctx,
            db,
            log,
            None,
            None,
            None,
            if discovered { "not_collected" } else { "unknown" },
            None,
            None,
            None,
            None,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_observation(
    ctx: &Ctx,
    db: &DerivedDb,
    log: &str,
    source_file: Option<&str>,
    facts_db: Option<&str>,
    facts_table: Option<&str>,
    state: &str,
    input_rows: Option<i64>,
    stats: Option<&LogScope>,
    error: Option<&str>,
    source: Option<(&str, &str, &str, i64)>,
) -> Result<()> {
    // Side evidence either carries all four source coordinates or none.
    let (dataset, source_db, source_table, source_rowid) = match source {
        Some((dataset, db, table, rowid)) => {
            (Some(dataset), Some(db), Some(table), Some(rowid))
        }
        None => (None, None, None, None),
    };
    let facts_generation = ctx.facts.by_stem(log)
        .map(|facts| ctx.facts.generation(facts)).transpose()?;
    db.conn().execute(
        "INSERT INTO FirewallObservations(observation_id,host_id,dataset_id,log_name,source_file,facts_db,facts_table,
         collection_state,input_row_count,event_count,firewall_event_count,connection_audit_event_count,
         corrupted_count,untimed_count,first_observed_time,last_observed_time,audit_setting_state,error,
         source_dataset_id,source_db,source_table,source_rowid,facts_generation)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'unknown',?17,?18,?19,?20,?21,?22)",
        params![
            uuid::Uuid::new_v4().to_string(),
            ctx.host_id,
            ctx.dataset_id,
            log,
            source_file,
            facts_db,
            facts_table,
            state,
            input_rows,
            stats.map(|stats| stats.count),
            stats.map(|stats| stats.firewall),
            stats.map(|stats| stats.connection),
            stats.map(|stats| stats.corrupt),
            stats.map(|stats| stats.untimed),
            stats.and_then(|stats| stats.first.clone()),
            stats.and_then(|stats| stats.last.clone()),
            error,
            dataset,
            source_db,
            source_table,
            source_rowid,
            facts_generation,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry policy snapshot (A06)
// ---------------------------------------------------------------------------

/// Snapshot rows are present-state evidence; they never become past events.
fn policy_snapshot(ctx: &Ctx, db: &DerivedDb) -> Result<()> {
    let directory = ctx.out_dir.join("REGISTRY");
    let mut paths = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("");
                path.extension().is_some_and(|ext| ext == "sqlite")
                    && (stem.eq_ignore_ascii_case("SYSTEM")
                        || stem.strip_prefix("SYSTEM_").is_some_and(|rest| {
                            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
                        }))
            })
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    paths.sort();
    for path in paths {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let active = {
            let mut query = conn.prepare(
                "SELECT DISTINCT value_data FROM Registry WHERE lower(key_path) LIKE '%\\select' AND lower(value_name)='current'",
            )?;
            let current = query
                .query_map([], |row| row.get::<_, Option<String>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if current.len() == 1 {
                current[0]
                    .as_deref()
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|value| *value > 0)
                    .map(|value| format!("controlset{value:03}"))
            } else {
                None
            }
        };
        let mut query = conn.prepare(
            "SELECT rowid,last_write,key_path,value_name,value_type,value_data,value_data_hex,entry_kind,_source_file
             FROM Registry WHERE lower(key_path) LIKE '%firewallpolicy%' ORDER BY rowid",
        )?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(2)?;
            let parts: Vec<&str> = key.split('\\').collect();
            let lower = key.to_ascii_lowercase();
            let control_set = lower
                .split('\\')
                .find(|part| part.starts_with("controlset"))
                .map(str::to_string);
            let status = match (control_set.as_deref(), active.as_deref()) {
                (Some(found), Some(selected)) if found == selected => "active",
                (Some(_), Some(_)) => "inactive",
                _ => "unknown",
            };
            let policy_index = parts
                .iter()
                .position(|part| part.eq_ignore_ascii_case("FirewallPolicy"));
            let store_scope = policy_index
                .filter(|index| *index > 0)
                .and_then(|index| parts.get(index - 1))
                .copied();
            let profile_scope = policy_index.and_then(|index| {
                parts[index + 1..]
                    .iter()
                    .find(|part| part.to_ascii_lowercase().ends_with("profile"))
                    .copied()
            });
            let file: Option<String> = row.get(8)?;
            let source = ctx
                .facts
                .source_from_row(
                    &path,
                    "Registry",
                    row.get(0)?,
                    file.as_deref(),
                    Some("firewall_policy_snapshot"),
                )?
                .ok_or_else(|| {
                    anyhow!("방화벽 정책 스냅샷 출처를 찾지 못했습니다: {}", path.display())
                })?;
            db.conn().execute(
                "INSERT INTO FirewallPolicySnapshot(snapshot_id,host_id,dataset_id,key_path,value_name,value_type,
                 value_data,value_data_hex,entry_kind,last_write,control_set,control_set_status,store_scope,profile_scope,
                 source_dataset_id,source_db,source_table,source_rowid,source_file)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    ctx.host_id,
                    ctx.dataset_id,
                    key,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(1)?.filter(|v| !v.is_empty()),
                    control_set,
                    status,
                    store_scope,
                    profile_scope,
                    source.dataset,
                    source.db,
                    source.table,
                    source.rowid,
                    source.file,
                ],
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE FirewallHistory (
  record_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  timestamp TEXT,
  overview_name TEXT NOT NULL,
  account TEXT,
  account_sid TEXT,
  timestamp_kind TEXT,
  event_type TEXT,
  description TEXT,
  event_family TEXT,
  payload_family TEXT,
  event_definition_state TEXT,
  event_definition_basis TEXT,
  timestamp_state TEXT,
  payload_state TEXT,
  account_role TEXT,
  account_basis TEXT,
  rule_id TEXT,
  rule_name TEXT,
  rule_event_sequence INTEGER,
  rule_event_count INTEGER,
  app_path TEXT,
  app_path_resolved TEXT,
  app_path_state TEXT,
  service TEXT,
  direction_raw TEXT,
  direction_value INTEGER,
  direction TEXT,
  action_raw TEXT,
  action_value INTEGER,
  action TEXT,
  protocol_raw TEXT,
  protocol_number INTEGER,
  protocol TEXT,
  local_addresses TEXT,
  remote_addresses TEXT,
  local_address TEXT,
  remote_address TEXT,
  single_address_basis TEXT,
  address_attribution TEXT,
  local_ports TEXT,
  remote_ports TEXT,
  local_port INTEGER,
  remote_port INTEGER,
  local_port_raw TEXT,
  remote_port_raw TEXT,
  single_port_basis TEXT,
  profiles_raw TEXT,
  profiles_mask INTEGER,
  profiles TEXT,
  profiles_unmapped_bits INTEGER,
  old_profile_raw TEXT,
  old_profile_mask INTEGER,
  old_profile TEXT,
  old_profile_unmapped_bits INTEGER,
  new_profile_raw TEXT,
  new_profile_mask INTEGER,
  new_profile TEXT,
  new_profile_unmapped_bits INTEGER,
  interface_name TEXT,
  interface_guid TEXT,
  setting_type_raw TEXT,
  setting_type INTEGER,
  setting_value_raw TEXT,
  setting_value_size_raw TEXT,
  setting_value_size INTEGER,
  setting_value_string TEXT,
  store_type_raw TEXT,
  store_type INTEGER,
  policy_change_raw TEXT,
  policy_change INTEGER,
  origin_raw TEXT,
  origin INTEGER,
  rule_status_raw TEXT,
  rule_status INTEGER,
  error_code_raw TEXT,
  error_code INTEGER,
  schema_version_raw TEXT,
  schema_version INTEGER,
  rule_active_raw TEXT,
  rule_active INTEGER,
  rule_flags_raw TEXT,
  rule_flags INTEGER,
  edge_traversal_raw TEXT,
  edge_traversal INTEGER,
  loose_source_mapped_raw TEXT,
  loose_source_mapped INTEGER,
  local_only_mapped_raw TEXT,
  local_only_mapped INTEGER,
  security_options_raw TEXT,
  security_options INTEGER,
  embedded_context TEXT,
  policy_app_id TEXT,
  remote_machine_authorization_list TEXT,
  remote_user_authorization_list TEXT,
  modifying_user_raw TEXT,
  modifying_user_sid TEXT,
  modifying_user_name TEXT,
  modifying_app TEXT,
  modifying_app_resolved TEXT,
  subject_user_sid TEXT,
  subject_user_name TEXT,
  subject_domain TEXT,
  subject_logon_id TEXT,
  system_user_sid TEXT,
  detail TEXT,
  event_id INTEGER,
  provider TEXT,
  channel TEXT,
  computer TEXT,
  event_record_id TEXT,
  level_name TEXT,
  keywords_raw TEXT,
  process_id TEXT,
  thread_id TEXT,
  activity_id TEXT,
  related_activity_id TEXT,
  facts_status TEXT,
  facts_error TEXT,
  record_key TEXT,
  source_file TEXT,
  event_data_raw TEXT,
  search_text TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'FirewallHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX idx_FirewallHistory_time ON FirewallHistory(timestamp, record_id);
CREATE INDEX idx_FirewallHistory_order ON FirewallHistory((timestamp IS NULL), timestamp, record_id);
CREATE INDEX idx_FirewallHistory_account ON FirewallHistory(account_sid, timestamp);
CREATE INDEX idx_FirewallHistory_rule ON FirewallHistory(rule_id, timestamp, record_id);
CREATE INDEX idx_FirewallHistory_event ON FirewallHistory(event_id, timestamp, record_id);
CREATE TABLE FirewallEventFields (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  field_name TEXT NOT NULL,
  field_path TEXT NOT NULL,
  value_raw TEXT,
  value_kind TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_FirewallEventFields_name ON FirewallEventFields(field_name, value_raw);
CREATE TABLE FirewallAddresses (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  role TEXT NOT NULL,
  entry_raw TEXT NOT NULL,
  entry_kind TEXT NOT NULL,
  attribution TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(role IN ('local','remote')),
  CHECK(attribution IN ('rule_definition','observed_connection')),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE TABLE FirewallPorts (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  role TEXT NOT NULL,
  entry_raw TEXT NOT NULL,
  entry_kind TEXT NOT NULL,
  port_start INTEGER,
  port_end INTEGER,
  attribution TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(role IN ('local','remote')),
  CHECK(attribution IN ('rule_definition','observed_connection')),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE TABLE FirewallAppPaths (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  role TEXT NOT NULL,
  path_raw TEXT NOT NULL,
  path_resolved TEXT,
  resolution_basis TEXT NOT NULL,
  path_kind TEXT NOT NULL,
  account_sid_scope TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(role IN ('target_app','modifying_app')),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_FirewallAppPaths_path ON FirewallAppPaths(path_raw, role);
CREATE TABLE FirewallRuleChanges (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  field_name TEXT NOT NULL,
  previous_value TEXT,
  new_value TEXT,
  previous_record_id TEXT NOT NULL,
  basis TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE,
  FOREIGN KEY(previous_record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE TABLE FirewallObservations (
  observation_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  log_name TEXT NOT NULL,
  source_file TEXT,
  facts_db TEXT,
  facts_table TEXT,
  facts_generation TEXT,
  collection_state TEXT NOT NULL,
  input_row_count INTEGER,
  event_count INTEGER,
  firewall_event_count INTEGER,
  connection_audit_event_count INTEGER,
  corrupted_count INTEGER,
  untimed_count INTEGER,
  first_observed_time TEXT,
  last_observed_time TEXT,
  audit_setting_state TEXT NOT NULL,
  error TEXT,
  source_dataset_id TEXT,
  source_db TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  PRIMARY KEY(observation_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
        OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL
            AND source_table IS NOT NULL AND source_rowid IS NOT NULL))
);
CREATE TABLE FirewallPolicySnapshot (
  snapshot_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  key_path TEXT NOT NULL,
  value_name TEXT,
  value_type TEXT,
  value_data TEXT,
  value_data_hex TEXT,
  entry_kind TEXT,
  last_write TEXT,
  control_set TEXT,
  control_set_status TEXT NOT NULL,
  store_scope TEXT,
  profile_scope TEXT,
  source_dataset_id TEXT NOT NULL,
  source_db TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_rowid INTEGER NOT NULL,
  source_file TEXT,
  PRIMARY KEY(snapshot_id)
);
CREATE INDEX idx_FirewallPolicySnapshot_value ON FirewallPolicySnapshot(value_name, control_set_status);
CREATE TABLE source_records (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  source_dataset_id TEXT NOT NULL,
  source_artifact TEXT NOT NULL,
  source_db TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_rowid INTEGER NOT NULL,
  source_field TEXT,
  source_record_key TEXT,
  source_file TEXT,
  source_label TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE _wina_derived_version(name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version VALUES('overview_contract',1),('firewall_history',2);
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
    "event_family",
    "payload_family",
    "event_definition_state",
    "event_definition_basis",
    "timestamp_state",
    "payload_state",
    "account_role",
    "account_basis",
    "rule_id",
    "rule_name",
    "rule_event_sequence",
    "rule_event_count",
    "app_path",
    "app_path_resolved",
    "app_path_state",
    "service",
    "direction_raw",
    "direction_value",
    "direction",
    "action_raw",
    "action_value",
    "action",
    "protocol_raw",
    "protocol_number",
    "protocol",
    "local_addresses",
    "remote_addresses",
    "local_address",
    "remote_address",
    "single_address_basis",
    "address_attribution",
    "local_ports",
    "remote_ports",
    "local_port",
    "remote_port",
    "local_port_raw",
    "remote_port_raw",
    "single_port_basis",
    "profiles_raw",
    "profiles_mask",
    "profiles",
    "profiles_unmapped_bits",
    "old_profile_raw",
    "old_profile_mask",
    "old_profile",
    "old_profile_unmapped_bits",
    "new_profile_raw",
    "new_profile_mask",
    "new_profile",
    "new_profile_unmapped_bits",
    "interface_name",
    "interface_guid",
    "setting_type_raw",
    "setting_type",
    "setting_value_raw",
    "setting_value_size_raw",
    "setting_value_size",
    "setting_value_string",
    "store_type_raw",
    "store_type",
    "policy_change_raw",
    "policy_change",
    "origin_raw",
    "origin",
    "rule_status_raw",
    "rule_status",
    "error_code_raw",
    "error_code",
    "schema_version_raw",
    "schema_version",
    "rule_active_raw",
    "rule_active",
    "rule_flags_raw",
    "rule_flags",
    "edge_traversal_raw",
    "edge_traversal",
    "loose_source_mapped_raw",
    "loose_source_mapped",
    "local_only_mapped_raw",
    "local_only_mapped",
    "security_options_raw",
    "security_options",
    "embedded_context",
    "policy_app_id",
    "remote_machine_authorization_list",
    "remote_user_authorization_list",
    "modifying_user_raw",
    "modifying_user_sid",
    "modifying_user_name",
    "modifying_app",
    "modifying_app_resolved",
    "subject_user_sid",
    "subject_user_name",
    "subject_domain",
    "subject_logon_id",
    "system_user_sid",
    "detail",
    "event_id",
    "provider",
    "channel",
    "computer",
    "event_record_id",
    "level_name",
    "keywords_raw",
    "process_id",
    "thread_id",
    "activity_id",
    "related_activity_id",
    "facts_status",
    "facts_error",
    "record_key",
    "source_file",
    "event_data_raw",
    "search_text",
];

const EVENT_FIELDS: &[&str] = &[
    "record_id",
    "ordinal",
    "field_name",
    "field_path",
    "value_raw",
    "value_kind",
];

const ADDRESSES: &[&str] = &[
    "record_id",
    "ordinal",
    "role",
    "entry_raw",
    "entry_kind",
    "attribution",
];

const PORTS: &[&str] = &[
    "record_id",
    "ordinal",
    "role",
    "entry_raw",
    "entry_kind",
    "port_start",
    "port_end",
    "attribution",
];

const APP_PATHS: &[&str] = &[
    "record_id",
    "ordinal",
    "role",
    "path_raw",
    "path_resolved",
    "resolution_basis",
    "path_kind",
    "account_sid_scope",
];

const RULE_CHANGES: &[&str] = &[
    "record_id",
    "ordinal",
    "field_name",
    "previous_value",
    "new_value",
    "previous_record_id",
    "basis",
];

const OBSERVATIONS: &[&str] = &[
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
    "firewall_event_count",
    "connection_audit_event_count",
    "corrupted_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "audit_setting_state",
    "error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

const POLICY_SNAPSHOT: &[&str] = &[
    "snapshot_id",
    "host_id",
    "dataset_id",
    "key_path",
    "value_name",
    "value_type",
    "value_data",
    "value_data_hex",
    "entry_kind",
    "last_write",
    "control_set",
    "control_set_status",
    "store_scope",
    "profile_scope",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
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

pub(super) const SPEC: DbSpec = DbSpec {
    name: "FirewallHistory",
    table: "FirewallHistory",
    columns: MAIN,
    children: &[
        ChildSpec { table: "FirewallEventFields", columns: EVENT_FIELDS },
        ChildSpec { table: "FirewallAddresses", columns: ADDRESSES },
        ChildSpec { table: "FirewallPorts", columns: PORTS },
        ChildSpec { table: "FirewallAppPaths", columns: APP_PATHS },
        ChildSpec { table: "FirewallRuleChanges", columns: RULE_CHANGES },
        ChildSpec { table: "FirewallObservations", columns: OBSERVATIONS },
        ChildSpec { table: "FirewallPolicySnapshot", columns: POLICY_SNAPSHOT },
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
    ],
    ddl: DDL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::sqlite::Row;
    use rusqlite::Connection;

    const FW_STEM: &str = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall";
    const FW_PROVIDER: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";
    const SEC_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";

    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("wina-firewall-{name}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
            Self { root }
        }

        /// Real facts rows so every stored source reference resolves.
        fn facts(&self, stem: &str, rows: usize) -> &Self {
            let path = self.root.join("EVENTLOG").join(format!("{stem}.sqlite"));
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE \"{stem}\"(EventData TEXT);",
                stem = stem.replace('"', "\"\"")
            ))
            .unwrap();
            for _ in 0..rows {
                conn.execute(
                    &format!(
                        "INSERT INTO \"{stem}\"(EventData) VALUES('{{}}')",
                        stem = stem.replace('"', "\"\"")
                    ),
                    [],
                )
                .unwrap();
            }
            drop(conn);
            stamp_facts_generation(&path, "facts-old").unwrap();
            self
        }

        fn run(&self, rows: Vec<Row>) -> Connection {
            crate::derived::create_database(&self.root.join("_OVERVIEW"), "Metadata").unwrap();
            let ctx = Ctx {
                out_dir: &self.root,
                target: &self.root,
                host_id: "host",
                dataset_id: "new",
                facts: FactsIndex::load(&self.root).unwrap(),
                meta: MetaLookup::load(&self.root).unwrap(),
            };
            build(&ctx, &EventLogOverviewCache::from_rows_for_tests(rows)).unwrap();
            let conn = Connection::open(ctx.overview_dir().join("FirewallHistory.sqlite")).unwrap();
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
            conn
        }
    }

    fn event(stem: &str, provider: &str, n: usize, eid: &str, ts: &str, payload: &str, user: &str) -> Row {
        Row::from([
            ("Provider".to_string(), provider.to_string()),
            ("Channel".to_string(), format!("{provider}/Firewall")),
            ("Computer".to_string(), "WIN-TEST".to_string()),
            ("EventID".to_string(), eid.to_string()),
            ("EventRecordID".to_string(), n.to_string()),
            ("LevelName".to_string(), "Information".to_string()),
            ("Keywords".to_string(), "0x8000000000000000".to_string()),
            ("ProcessID".to_string(), "4".to_string()),
            ("ThreadID".to_string(), "8".to_string()),
            ("UserID".to_string(), user.to_string()),
            ("timestamp".to_string(), ts.to_string()),
            ("EventData".to_string(), payload.to_string()),
            ("_record_key".to_string(), format!("{stem}::{n}")),
            ("_source_file".to_string(), format!("{stem}.evtx")),
            ("_status".to_string(), "ok".to_string()),
        ])
    }

    fn fw(n: usize, eid: &str, ts: &str, payload: &str) -> Row {
        event(FW_STEM, FW_PROVIDER, n, eid, ts, payload, "S-1-5-19")
    }

    fn sec(n: usize, eid: &str, ts: &str, payload: &str) -> Row {
        event("Security", SEC_PROVIDER, n, eid, ts, payload, "")
    }

    fn text(conn: &Connection, sql: &str) -> Option<String> {
        conn.query_row(sql, [], |r| r.get::<_, Option<String>>(0)).unwrap()
    }

    fn number(conn: &Connection, sql: &str) -> Option<i64> {
        conn.query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).unwrap()
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap()
    }

    const RULE_A: &str = r#"{"RuleId":"{A}","RuleName":"HelpUServer","Origin":1,"ApplicationPath":"","ServiceName":"","Direction":1,"Protocol":6,"LocalPorts":"2500","RemotePorts":"*","Action":3,"Profiles":2147483647,"LocalAddresses":"*","RemoteAddresses":"*","Flags":1,"Active":1,"EdgeTraversal":0,"LooseSourceMapped":0,"SecurityOptions":0,"ModifyingUser":"S-1-5-18","ModifyingApplication":"C:\\Tools\\srv.exe","SchemaVersion":545,"RuleStatus":65536,"LocalOnlyMapped":0,"PolicyAppId":"","ErrorCode":0}"#;
    const RULE_A2: &str = r#"{"RuleId":"{A}","RuleName":"HelpUServer","Origin":1,"ApplicationPath":"","ServiceName":"","Direction":1,"Protocol":6,"LocalPorts":"2501","RemotePorts":"*","Action":3,"Profiles":2147483647,"LocalAddresses":"*","RemoteAddresses":"*","Flags":1,"Active":1,"EdgeTraversal":0,"LooseSourceMapped":0,"SecurityOptions":0,"ModifyingUser":"S-1-5-18","ModifyingApplication":"C:\\Tools\\srv.exe","SchemaVersion":545,"RuleStatus":65536,"LocalOnlyMapped":0,"PolicyAppId":"","ErrorCode":0}"#;

    // R01/A01/A03: unknown provider definitions stay unlabeled, repeated RuleId
    // is never collapsed, and every payload field survives verbatim.
    #[test]
    fn unconfirmed_event_families_keep_every_field_and_repeated_rule_ids() {
        let fx = Fixture::new("unconfirmed");
        fx.facts(FW_STEM, 4);
        let conn = fx.run(vec![
            fw(1, "2097", "2026-01-01 00:00:01.000", RULE_A),
            fw(2, "2097", "2026-01-01 00:00:02.000", RULE_A2),
            fw(3, "2052", "2026-01-01 00:00:03.000", r#"{"RuleId":"{A}","RuleName":"HelpUServer","ModifyingUser":"S-1-5-18","ModifyingApplication":"C:\\Tools\\setup.exe","ErrorCode":0}"#),
            fw(4, "2051", "2026-01-01 00:00:04.000", r#"{"ErrorCode":0,"PolicyChange":0}"#),
        ]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 4);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE rule_id='{A}'"), 3);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE event_definition_state='unconfirmed'"),
            4
        );
        assert_eq!(
            text(&conn, "SELECT event_type FROM FirewallHistory WHERE event_id=2097 LIMIT 1"),
            Some("방화벽 이벤트 2097".into())
        );
        assert_eq!(
            text(&conn, "SELECT payload_family FROM FirewallHistory WHERE event_id=2097 LIMIT 1"),
            Some("rule_definition".into())
        );
        assert_eq!(
            text(&conn, "SELECT payload_family FROM FirewallHistory WHERE event_id=2052"),
            Some("rule_reference".into())
        );
        assert_eq!(
            text(&conn, "SELECT payload_family FROM FirewallHistory WHERE event_id=2051"),
            Some("policy_change".into())
        );
        // No add/change/delete wording may be produced for unconfirmed events.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallHistory WHERE event_definition_state='unconfirmed'
                 AND (ifnull(description,'') LIKE '%추가%' OR ifnull(description,'') LIKE '%삭제%'
                      OR ifnull(description,'') LIKE '%변경%' OR ifnull(event_type,'') LIKE '%추가%'
                      OR ifnull(event_type,'') LIKE '%삭제%')"
            ),
            0
        );
        // Every payload key is preserved, including unknown ones.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id) WHERE h.event_id=2051"
            ),
            2
        );
        assert_eq!(
            text(
                &conn,
                "SELECT value_raw FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=2051 AND f.field_name='PolicyChange'"
            ),
            Some("0".into())
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id) WHERE h.event_id=2097"
            ),
            25 * 2
        );
        // A01: the per-rule sequence and the observed difference, nothing more.
        let seq: Vec<i64> = conn
            .prepare("SELECT rule_event_sequence FROM FirewallHistory WHERE event_id=2097 ORDER BY timestamp")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(seq, vec![0, 1]);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallRuleChanges"), 1);
        let change: (String, Option<String>, Option<String>, String) = conn
            .query_row(
                "SELECT field_name, previous_value, new_value, basis FROM FirewallRuleChanges",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(change.0, "LocalPorts");
        assert_eq!(change.1.as_deref(), Some("2500"));
        assert_eq!(change.2.as_deref(), Some("2501"));
        assert_eq!(change.3, "same_rule_id_previous_rule_definition_event");
        // R09: real facts coordinates and the original generation survive.
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM source_records WHERE source_dataset_id='facts-old' AND source_file LIKE '%.evtx'"),
            4
        );
        // R10: contract fields are searchable, rule_id and account_sid included.
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE search_text LIKE '%{A}%'"), 3);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE search_text LIKE '%S-1-5-18%'"),
            3
        );
    }

    // R02/R03/R14: raw protocol, address and port text is never replaced and
    // ranges are never forced into a single integer.
    #[test]
    fn protocol_address_and_port_originals_are_kept_beside_typed_values() {
        let fx = Fixture::new("wire");
        fx.facts(FW_STEM, 2);
        let conn = fx.run(vec![
            fw(1, "2097", "2026-01-01 00:00:01.000", r#"{"RuleId":"{B}","RuleName":"r","Direction":1,"Protocol":6,"LocalPorts":"5353,5354","RemotePorts":"1024-65535","LocalAddresses":"10.0.0.1-10.0.0.9,192.168.0.0/24","RemoteAddresses":"*","Action":3,"Profiles":4}"#),
            fw(2, "2097", "2026-01-01 00:00:02.000", r#"{"RuleId":"{C}","RuleName":"r2","Direction":99,"Protocol":256,"LocalPorts":"RPC","RemotePorts":"*","LocalAddresses":"LocalSubnet","RemoteAddresses":"*","Action":7,"Profiles":4}"#),
        ]);

        let first = "SELECT %s FROM FirewallHistory WHERE rule_id='{B}'";
        assert_eq!(number(&conn, &first.replace("%s", "protocol_number")), Some(6));
        assert_eq!(text(&conn, &first.replace("%s", "protocol")), Some("TCP".into()));
        assert_eq!(text(&conn, &first.replace("%s", "protocol_raw")), Some("6".into()));
        assert_eq!(text(&conn, &first.replace("%s", "direction")), Some("인바운드".into()));
        assert_eq!(text(&conn, &first.replace("%s", "action")), Some("허용".into()));
        assert_eq!(text(&conn, &first.replace("%s", "local_ports")), Some("5353,5354".into()));
        assert_eq!(text(&conn, &first.replace("%s", "remote_ports")), Some("1024-65535".into()));
        assert_eq!(number(&conn, &first.replace("%s", "local_port")), None);
        assert_eq!(text(&conn, &first.replace("%s", "address_attribution")), Some("rule_definition".into()));

        // Unmapped enum values keep the original number without a made-up name.
        let second = "SELECT %s FROM FirewallHistory WHERE rule_id='{C}'";
        assert_eq!(number(&conn, &second.replace("%s", "protocol_number")), Some(256));
        assert_eq!(text(&conn, &second.replace("%s", "protocol")), None);
        assert_eq!(number(&conn, &second.replace("%s", "direction_value")), Some(99));
        assert_eq!(text(&conn, &second.replace("%s", "direction")), None);
        assert_eq!(text(&conn, &second.replace("%s", "action")), None);
        assert_eq!(text(&conn, &second.replace("%s", "local_ports")), Some("RPC".into()));

        let ports: Vec<(String, String, Option<i64>, Option<i64>)> = conn
            .prepare(
                "SELECT role, entry_kind, port_start, port_end FROM FirewallPorts p
                 JOIN FirewallHistory h USING(record_id) WHERE h.rule_id='{B}' ORDER BY p.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            ports,
            vec![
                ("local".into(), "single".into(), Some(5353), Some(5353)),
                ("local".into(), "single".into(), Some(5354), Some(5354)),
                ("remote".into(), "range".into(), Some(1024), Some(65535)),
            ]
        );
        let keyword: (String, Option<i64>) = conn
            .query_row(
                "SELECT entry_kind, port_start FROM FirewallPorts p JOIN FirewallHistory h USING(record_id)
                 WHERE h.rule_id='{C}' AND p.role='local'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(keyword, ("keyword".into(), None));

        let addresses: Vec<(String, String, String, String)> = conn
            .prepare(
                "SELECT role, entry_raw, entry_kind, attribution FROM FirewallAddresses a
                 JOIN FirewallHistory h USING(record_id) WHERE h.rule_id='{B}' ORDER BY a.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            addresses,
            vec![
                ("local".into(), "10.0.0.1-10.0.0.9".into(), "range".into(), "rule_definition".into()),
                ("local".into(), "192.168.0.0/24".into(), "subnet".into(), "rule_definition".into()),
                ("remote".into(), "*".into(), "any".into(), "rule_definition".into()),
            ]
        );
    }

    // R04/R05/R06/R08: SID roles stay apart, service SIDs never become the
    // operator, and profile masks keep their unmapped bits.
    #[test]
    fn sid_roles_and_profile_masks_stay_separate() {
        let fx = Fixture::new("roles");
        fx.facts(FW_STEM, 2);
        let conn = fx.run(vec![
            fw(1, "2010", "2026-01-01 00:00:01.000", r#"{"InterfaceGuid":"{G}","InterfaceName":"ethernet_32770","OldProfile":2147483649,"NewProfile":4}"#),
            fw(2, "2097", "2026-01-01 00:00:02.000", RULE_A),
        ]);

        let profile = "SELECT %s FROM FirewallHistory WHERE event_id=2010";
        assert_eq!(text(&conn, &profile.replace("%s", "account")), None);
        assert_eq!(text(&conn, &profile.replace("%s", "account_sid")), None);
        assert_eq!(text(&conn, &profile.replace("%s", "account_role")), None);
        assert_eq!(text(&conn, &profile.replace("%s", "system_user_sid")), Some("S-1-5-19".into()));
        assert_eq!(text(&conn, &profile.replace("%s", "event_type")), Some("프로필 전환".into()));
        assert_eq!(
            text(&conn, &profile.replace("%s", "event_definition_state")),
            Some("confirmed_schema".into())
        );
        assert_eq!(number(&conn, &profile.replace("%s", "old_profile_mask")), Some(2147483649));
        assert_eq!(text(&conn, &profile.replace("%s", "old_profile")), Some("도메인".into()));
        assert_eq!(
            number(&conn, &profile.replace("%s", "old_profile_unmapped_bits")),
            Some(2147483648)
        );
        assert_eq!(text(&conn, &profile.replace("%s", "new_profile")), Some("공용".into()));
        assert_eq!(number(&conn, &profile.replace("%s", "new_profile_unmapped_bits")), Some(0));
        assert_eq!(text(&conn, &profile.replace("%s", "interface_name")), Some("ethernet_32770".into()));
        assert_eq!(text(&conn, &profile.replace("%s", "interface_guid")), Some("{G}".into()));

        let rule = "SELECT %s FROM FirewallHistory WHERE event_id=2097";
        assert_eq!(text(&conn, &rule.replace("%s", "account_sid")), Some("S-1-5-18".into()));
        assert_eq!(text(&conn, &rule.replace("%s", "account_role")), Some("modifying_user".into()));
        assert_eq!(text(&conn, &rule.replace("%s", "account_basis")), Some("ModifyingUser".into()));
        assert_eq!(text(&conn, &rule.replace("%s", "system_user_sid")), Some("S-1-5-19".into()));
        // 0x7FFFFFFF keeps its unmapped bits instead of becoming "all profiles".
        assert_eq!(number(&conn, &rule.replace("%s", "profiles_mask")), Some(2147483647));
        assert_eq!(text(&conn, &rule.replace("%s", "profiles")), Some("도메인, 개인, 공용".into()));
        assert_eq!(number(&conn, &rule.replace("%s", "profiles_unmapped_bits")), Some(2147483640));
    }

    // R07/R15/A02/A07: settings keep raw bytes and the provider reading, an
    // empty payload is reported as such, and app paths keep role and basis.
    #[test]
    fn settings_empty_payload_and_app_paths_are_explicit() {
        let fx = Fixture::new("settings");
        fx.facts(FW_STEM, 4);
        let conn = fx.run(vec![
            fw(1, "2082", "2026-01-01 00:00:01.000", r#"{"Profiles":4,"SettingType":3,"SettingValueSize":4,"SettingValue":"00000000","SettingValueString":"아니요","Origin":1,"ModifyingUser":"S-1-5-18","ModifyingApplication":"C:\\Program Files (x86)\\GlassWire\\GWCtlSrv.exe","ErrorCode":0}"#),
            fw(2, "2011", "", ""),
            fw(3, "2097", "2026-01-01 00:00:03.000", RULE_A),
            // Facts omit the column entirely when the payload is SQL NULL.
            {
                let mut absent = fw(4, "2059", "2026-01-01 00:00:04.000", "");
                absent.remove("EventData");
                absent
            },
        ]);

        let setting = "SELECT %s FROM FirewallHistory WHERE event_id=2082";
        assert_eq!(number(&conn, &setting.replace("%s", "setting_type")), Some(3));
        assert_eq!(text(&conn, &setting.replace("%s", "setting_value_raw")), Some("00000000".into()));
        assert_eq!(number(&conn, &setting.replace("%s", "setting_value_size")), Some(4));
        assert_eq!(text(&conn, &setting.replace("%s", "setting_value_string")), Some("아니요".into()));
        assert_eq!(text(&conn, &setting.replace("%s", "payload_family")), Some("setting_change".into()));
        assert_eq!(number(&conn, &setting.replace("%s", "error_code")), Some(0));
        assert_eq!(text(&conn, &setting.replace("%s", "app_path_state")), Some("absent".into()));

        // R15: an empty provider payload is recorded, not invented.
        let blocked = "SELECT %s FROM FirewallHistory WHERE event_id=2011";
        assert_eq!(text(&conn, &blocked.replace("%s", "payload_state")), Some("empty".into()));
        assert_eq!(text(&conn, &blocked.replace("%s", "timestamp")), None);
        assert_eq!(text(&conn, &blocked.replace("%s", "timestamp_kind")), None);
        assert_eq!(text(&conn, &blocked.replace("%s", "timestamp_state")), Some("unrecorded".into()));
        assert_eq!(text(&conn, &blocked.replace("%s", "local_address")), None);
        assert_eq!(text(&conn, &blocked.replace("%s", "remote_port_raw")), None);
        assert_eq!(text(&conn, &blocked.replace("%s", "address_attribution")), None);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id) WHERE h.event_id=2011"),
            0
        );
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM source_records s JOIN FirewallHistory h USING(record_id) WHERE h.event_id=2011"),
            1
        );
        // A recorded empty payload keeps its empty TEXT; only a missing
        // column is NULL and 'absent'.
        assert_eq!(
            text(&conn, &blocked.replace("%s", "event_data_raw")),
            Some(String::new())
        );
        let absent = "SELECT %s FROM FirewallHistory WHERE event_id=2059";
        assert_eq!(text(&conn, &absent.replace("%s", "payload_state")), Some("absent".into()));
        assert_eq!(text(&conn, &absent.replace("%s", "event_data_raw")), None);

        // Recorded-but-empty differs from an absent field.
        assert_eq!(
            text(&conn, "SELECT app_path_state FROM FirewallHistory WHERE event_id=2097"),
            Some("empty".into())
        );
        let apps: Vec<(String, String, String, String, Option<String>, Option<String>)> = conn
            .prepare(
                "SELECT role, path_raw, path_kind, resolution_basis, path_resolved, account_sid_scope
                 FROM FirewallAppPaths a JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=2082 ORDER BY a.ordinal",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        // A literal path asks for no expansion: NULL resolved value, basis
        // 'literal', and the change subject's SID is never borrowed as the
        // path's user context.
        assert_eq!(
            apps,
            vec![(
                "modifying_app".into(),
                "C:\\Program Files (x86)\\GlassWire\\GWCtlSrv.exe".into(),
                "drive_absolute".into(),
                "literal".into(),
                None,
                None
            )]
        );
    }

    // A07 boundary: a user environment variable in a target application path
    // is not resolved with the changing account's SID.
    #[test]
    fn user_variable_target_path_is_not_resolved_from_the_changer_sid() {
        let fx = Fixture::new("pathscope");
        fx.facts(FW_STEM, 1);
        let conn = fx.run(vec![fw(
            1,
            "2097",
            "2026-01-01 00:00:01.000",
            r#"{"RuleId":"{E}","RuleName":"r","Direction":1,"Protocol":6,"LocalPorts":"*","RemotePorts":"*","Action":3,"Profiles":4,"ApplicationPath":"%USERPROFILE%\\app\\x.exe","ModifyingUser":"S-1-5-21-1-2-3-500","ModifyingApplication":"C:\\Windows\\System32\\svchost.exe"}"#,
        )]);

        assert_eq!(
            text(&conn, "SELECT account_sid FROM FirewallHistory"),
            Some("S-1-5-21-1-2-3-500".into())
        );
        assert_eq!(text(&conn, "SELECT app_path_resolved FROM FirewallHistory"), None);
        let target: (String, Option<String>, String, Option<String>) = conn
            .query_row(
                "SELECT path_kind, path_resolved, resolution_basis, account_sid_scope
                 FROM FirewallAppPaths WHERE role='target_app'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            target,
            ("environment_variable".into(), None, "unresolved".into(), None)
        );
        assert_eq!(
            text(&conn, "SELECT resolution_basis FROM FirewallAppPaths WHERE role='modifying_app'"),
            Some("literal".into())
        );
    }

    // A03/A04/A05/A08: documented audit events are labeled, connection audit
    // events stay out of the rule view but are counted as observation scope.
    #[test]
    fn documented_audit_events_and_observation_scope() {
        let fx = Fixture::new("audit");
        fx.facts("Security", 4);
        let conn = fx.run(vec![
            sec(1, "5024", "2026-01-01 00:00:01.000", ""),
            sec(2, "5033", "2026-01-01 00:00:02.000", ""),
            sec(3, "4946", "2026-01-01 00:00:03.000", r#"{"RuleId":"{D}","RuleName":"audit rule","ProfileChanged":"모든","SubjectUserSid":"S-1-5-21-1-2-3-500","SubjectUserName":"Administrator","SubjectDomainName":"WIN","SubjectLogonId":"0x3e7"}"#),
            sec(4, "5156", "2026-01-01 00:00:04.000", r#"{"Application":"\\device\\harddiskvolume3\\x.exe"}"#),
        ]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 3);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE event_id=5156"), 0);
        assert_eq!(
            text(&conn, "SELECT event_type FROM FirewallHistory WHERE event_id=5024"),
            Some("방화벽 서비스 시작".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_definition_state FROM FirewallHistory WHERE event_id=5024"),
            Some("confirmed_documented".into())
        );
        assert_eq!(
            text(&conn, "SELECT payload_state FROM FirewallHistory WHERE event_id=5033"),
            Some("empty".into())
        );
        assert_eq!(text(&conn, "SELECT account_sid FROM FirewallHistory WHERE event_id=5033"), None);
        assert_eq!(
            text(&conn, "SELECT account_role FROM FirewallHistory WHERE event_id=4946"),
            Some("audit_subject".into())
        );
        assert_eq!(
            text(&conn, "SELECT subject_logon_id FROM FirewallHistory WHERE event_id=4946"),
            Some("0x3e7".into())
        );

        let scope: (String, Option<i64>, Option<i64>, Option<i64>, String) = conn
            .query_row(
                "SELECT collection_state, event_count, firewall_event_count, connection_audit_event_count, audit_setting_state
                 FROM FirewallObservations WHERE log_name='Security'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(scope, ("unknown".into(), Some(4), Some(3), Some(1), "unknown".into()));
        // The firewall channel was never collected here: that is not zero events.
        assert_eq!(
            text(&conn, &format!("SELECT collection_state FROM FirewallObservations WHERE log_name='{FW_STEM}'")),
            Some("unknown".into())
        );
        assert_eq!(
            number(&conn, &format!("SELECT event_count FROM FirewallObservations WHERE log_name='{FW_STEM}'")),
            None
        );
    }

    // A06: the registry policy snapshot is separate evidence, RegBack excluded.
    #[test]
    fn registry_policy_snapshot_marks_active_control_set_and_skips_regback() {
        let fx = Fixture::new("registry");
        fx.facts(FW_STEM, 1);
        std::fs::create_dir_all(fx.root.join("REGISTRY")).unwrap();
        for (name, rules) in [("SYSTEM", "live rule"), ("SYSTEM_RegBack", "backup rule")] {
            let path = fx.root.join("REGISTRY").join(format!("{name}.sqlite"));
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
                INSERT INTO Registry VALUES('2026-01-01','\ROOT\Select','Current','RegDword','1',NULL,'value','SYSTEM');
                INSERT INTO Registry VALUES('2026-01-02','\ROOT\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile','EnableFirewall','RegDword','1',NULL,'value','SYSTEM');
                INSERT INTO Registry VALUES('2026-01-03','\ROOT\ControlSet002\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile','EnableFirewall','RegDword','0',NULL,'value','SYSTEM');
                INSERT INTO Registry VALUES('2026-01-04','\ROOT\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{rules}','RegSz','v2.33|Action=Allow|Dir=In|',NULL,'value','SYSTEM');"#
            ))
            .unwrap();
            drop(conn);
            stamp_facts_generation(&path, "registry-old").unwrap();
        }
        let conn = fx.run(vec![fw(1, "2051", "2026-01-01 00:00:01.000", r#"{"ErrorCode":0,"PolicyChange":0}"#)]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallPolicySnapshot WHERE value_name='backup rule'"), 0);
        let active: (String, String, Option<String>, String) = conn
            .query_row(
                "SELECT control_set, control_set_status, profile_scope, source_dataset_id FROM FirewallPolicySnapshot
                 WHERE value_name='EnableFirewall' AND value_data='1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            active,
            ("controlset001".into(), "active".into(), Some("PublicProfile".into()), "registry-old".into())
        );
        assert_eq!(
            text(&conn, "SELECT control_set_status FROM FirewallPolicySnapshot WHERE value_name='EnableFirewall' AND value_data='0'"),
            Some("inactive".into())
        );
        let rule_row: (String, Option<String>) = conn
            .query_row(
                "SELECT store_scope, value_data FROM FirewallPolicySnapshot WHERE value_name='live rule'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rule_row.0, "Parameters");
        assert_eq!(rule_row.1.as_deref(), Some("v2.33|Action=Allow|Dir=In|"));
        // The snapshot never becomes a firewall event row.
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 1);
    }
}
