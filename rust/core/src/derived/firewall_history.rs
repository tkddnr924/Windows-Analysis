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
/// Provider GUID of the mpssvc.dll manifest that defines the firewall
/// channels; facts carry it from System/Provider/@Guid when available.
const FIREWALL_PROVIDER_GUID: &str = "d1bc9aff-2abf-4d71-9146-ecb2a986eb85";
const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";
const WFP_PROVIDER: &str = "Microsoft-Windows-WFP";
const IKE_PROVIDER: &str = "Microsoft-Windows-IKE";
const FIREWALL_LOG: &str = "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall";
const CONNECTION_SECURITY_LOG: &str =
    "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity";
const FIREWALL_DIAGNOSTICS_LOG: &str =
    "Microsoft-Windows-Windows Firewall With Advanced Security%4FirewallDiagnostics";
const WFP_LOG: &str = "Microsoft-Windows-WFP%4Operational";
const IKE_LOG: &str = "Microsoft-Windows-IKE%4Operational";
const SECURITY_LOG: &str = "Security";
const LOGS: &[&str] = &[
    FIREWALL_LOG,
    CONNECTION_SECURITY_LOG,
    FIREWALL_DIAGNOSTICS_LOG,
    WFP_LOG,
    IKE_LOG,
    SECURITY_LOG,
];

/// Filtering-platform connection audits (A05). They are stored as their own
/// evidence family — never as rule events — and counted as observation scope.
const CONNECTION_AUDIT_IDS: &[i64] = &[
    5146, 5147, 5148, 5149, 5150, 5151, 5152, 5153, 5154, 5155, 5156, 5157, 5158, 5159,
];

/// Wrapper the facts layer uses when the provider could not decode a record
/// and the EVTX carries `<ProcessingErrorData>` instead of `<EventData>`.
const PROCESSING_ERROR: &str = "ProcessingErrorData";

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
/// The provider's own decoding failure (`ProcessingErrorData`) is preserved
/// under its node path so it can never be read as a normal payload field.
fn flatten(payload: &Map<String, Value>) -> Vec<(String, String, String, &'static str)> {
    let mut fields = Vec::new();
    for (name, value) in payload {
        if name == "EventXML" || name == PROCESSING_ERROR {
            if let Value::Object(inner) = value {
                for (key, nested) in inner {
                    fields.push((
                        key.clone(),
                        format!("{name}.{key}"),
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
    /// Evidence family of the event, so rule policy, connection audits and
    /// IPsec security associations stay queryable apart from each other.
    scope: &'static str,
    /// Microsoft audit subcategory, only for documented Security events.
    subcategory: Option<&'static str>,
}

const MPSSVC_POLICY: &str = "Audit MPSSVC Rule-Level Policy Change";
const OTHER_SYSTEM: &str = "Audit Other System Events";
const FP_CONNECTION: &str = "Audit Filtering Platform Connection";
const FP_PACKET_DROP: &str = "Audit Filtering Platform Packet Drop";
const FP_POLICY: &str = "Audit Filtering Platform Policy Change";
const IPSEC_MAIN: &str = "Audit IPsec Main Mode";
const IPSEC_QUICK: &str = "Audit IPsec Quick Mode";
const IPSEC_EXTENDED: &str = "Audit IPsec Extended Mode";
const IPSEC_DRIVER: &str = "Audit IPsec Driver";

/// 5447 and the DoS-mitigation events are filtering-platform evidence but
/// Microsoft files them under different audit subcategories.
const OTHER_POLICY: &str = "Audit Other Policy Change Events";
const OTHER_OBJECT_ACCESS: &str = "Audit Other Object Access Events";

/// Microsoft-documented Security-channel audits that belong to this view:
/// title and owning subcategory come from the published subcategory pages of
/// the Windows 10 audit reference. `scope` is the evidence family, not a
/// claim about what happened on the wire.
fn documented_audit(event_id: i64) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    Some(match event_id {
        // Audit MPSSVC Rule-Level Policy Change.
        4944 => ("시작 시 활성 정책", "Windows 방화벽 시작 시 활성 정책 기록", "rule_policy_audit", MPSSVC_POLICY),
        4945 => ("시작 시 규칙 나열", "Windows 방화벽 시작 시 규칙 나열", "rule_policy_audit", MPSSVC_POLICY),
        4946 => ("규칙 추가 (감사)", "방화벽 예외 목록에 규칙 추가", "rule_policy_audit", MPSSVC_POLICY),
        4947 => ("규칙 수정 (감사)", "방화벽 예외 목록의 규칙 수정", "rule_policy_audit", MPSSVC_POLICY),
        4948 => ("규칙 삭제 (감사)", "방화벽 예외 목록의 규칙 삭제", "rule_policy_audit", MPSSVC_POLICY),
        4949 => ("설정 기본값 복원", "방화벽 설정을 기본값으로 복원", "rule_policy_audit", MPSSVC_POLICY),
        4950 => ("설정 변경 (감사)", "방화벽 설정 변경", "rule_policy_audit", MPSSVC_POLICY),
        4951 => ("규칙 무시 — 주 버전", "주 버전 미인식으로 규칙 무시", "rule_policy_audit", MPSSVC_POLICY),
        4952 => ("규칙 일부 무시 — 부 버전", "부 버전 미인식으로 규칙 일부 무시", "rule_policy_audit", MPSSVC_POLICY),
        4953 => ("규칙 무시 — 구문 분석 실패", "규칙 구문 분석 실패로 무시", "rule_policy_audit", MPSSVC_POLICY),
        4954 => ("그룹 정책 설정 적용", "방화벽 그룹 정책 설정 변경 적용", "rule_policy_audit", MPSSVC_POLICY),
        4956 => ("활성 프로필 변경", "방화벽 활성 프로필 변경", "rule_policy_audit", MPSSVC_POLICY),
        4957 => ("규칙 미적용", "방화벽이 규칙을 적용하지 않음", "rule_policy_audit", MPSSVC_POLICY),
        4958 => (
            "규칙 미적용 — 미구성 항목",
            "구성되지 않은 항목을 참조해 규칙 미적용",
            "rule_policy_audit",
            MPSSVC_POLICY,
        ),
        // Audit Other System Events — firewall service and driver lifecycle.
        5024 => ("방화벽 서비스 시작", "Windows 방화벽 서비스 시작 성공", "service_lifecycle_audit", OTHER_SYSTEM),
        5025 => ("방화벽 서비스 중지", "Windows 방화벽 서비스 중지", "service_lifecycle_audit", OTHER_SYSTEM),
        5027 => (
            "정책 읽기 실패",
            "로컬 저장소에서 정책을 가져오지 못함 — 현재 정책 유지",
            "service_lifecycle_audit",
            OTHER_SYSTEM,
        ),
        5028 => (
            "정책 구문 분석 실패",
            "새 정책 구문 분석 실패 — 현재 정책 유지",
            "service_lifecycle_audit",
            OTHER_SYSTEM,
        ),
        5029 => ("드라이버 초기화 실패", "서비스가 드라이버 초기화 실패", "service_lifecycle_audit", OTHER_SYSTEM),
        5030 => ("방화벽 서비스 시작 실패", "Windows 방화벽 서비스 시작 실패", "service_lifecycle_audit", OTHER_SYSTEM),
        5032 => ("차단 알림 실패", "차단 사실을 사용자에게 알리지 못함", "service_lifecycle_audit", OTHER_SYSTEM),
        5033 => ("방화벽 드라이버 시작", "Windows 방화벽 드라이버 시작 성공", "service_lifecycle_audit", OTHER_SYSTEM),
        5034 => ("방화벽 드라이버 중지", "Windows 방화벽 드라이버 중지", "service_lifecycle_audit", OTHER_SYSTEM),
        5035 => ("방화벽 드라이버 시작 실패", "Windows 방화벽 드라이버 시작 실패", "service_lifecycle_audit", OTHER_SYSTEM),
        5037 => (
            "방화벽 드라이버 런타임 오류",
            "드라이버가 심각한 런타임 오류로 종료",
            "service_lifecycle_audit",
            OTHER_SYSTEM,
        ),
        // Audit Filtering Platform Connection. These are per-packet/per-call
        // permission audits: an allowed connection is not a transfer.
        5031 => (
            "인바운드 수신 차단",
            "방화벽 서비스가 응용 프로그램의 인바운드 수신을 차단함",
            "connection_audit",
            FP_CONNECTION,
        ),
        5150 => ("패킷 차단 (WFP·연결 감사)", "Windows 필터링 플랫폼이 패킷을 차단함", "connection_audit", FP_CONNECTION),
        5151 => (
            "패킷 차단 (제한적 WFP 필터·연결 감사)",
            "더 제한적인 Windows 필터링 플랫폼 필터가 패킷을 차단함",
            "connection_audit",
            FP_CONNECTION,
        ),
        5154 => (
            "포트 수신 허용 (WFP)",
            "Windows 필터링 플랫폼이 응용 프로그램·서비스의 포트 수신 대기를 허용함",
            "listen_bind_audit",
            FP_CONNECTION,
        ),
        5155 => (
            "포트 수신 차단 (WFP)",
            "Windows 필터링 플랫폼이 응용 프로그램·서비스의 포트 수신 대기를 차단함",
            "listen_bind_audit",
            FP_CONNECTION,
        ),
        5156 => (
            "연결 허용 (WFP)",
            "Windows 필터링 플랫폼이 연결을 허용함 — 허용 감사이며 실제 데이터 교환을 뜻하지 않음",
            "connection_audit",
            FP_CONNECTION,
        ),
        5157 => (
            "연결 차단 (WFP)",
            "Windows 필터링 플랫폼이 연결을 차단함",
            "connection_audit",
            FP_CONNECTION,
        ),
        5158 => (
            "로컬 포트 바인드 허용 (WFP)",
            "Windows 필터링 플랫폼이 로컬 포트 바인드를 허용함",
            "listen_bind_audit",
            FP_CONNECTION,
        ),
        5159 => (
            "로컬 포트 바인드 차단 (WFP)",
            "Windows 필터링 플랫폼이 로컬 포트 바인드를 차단함",
            "listen_bind_audit",
            FP_CONNECTION,
        ),
        // Audit Filtering Platform Packet Drop.
        5152 => (
            "패킷 차단 (WFP·패킷 삭제 감사)",
            "Windows 필터링 플랫폼이 패킷을 차단함",
            "packet_drop_audit",
            FP_PACKET_DROP,
        ),
        5153 => (
            "패킷 차단 (제한적 WFP 필터·패킷 삭제 감사)",
            "더 제한적인 Windows 필터링 플랫폼 필터가 패킷을 차단함",
            "packet_drop_audit",
            FP_PACKET_DROP,
        ),
        // Audit Other Object Access Events — filtering platform DoS defence.
        5148 => (
            "DoS 공격 감지 — 방어 모드 진입 (WFP)",
            "Windows 필터링 플랫폼이 DoS 공격을 감지해 방어 모드로 전환하고 관련 패킷을 버림",
            "dos_mitigation_audit",
            OTHER_OBJECT_ACCESS,
        ),
        5149 => (
            "DoS 공격 완화 — 정상 처리 재개 (WFP)",
            "DoS 공격이 가라앉아 정상 처리가 재개됨",
            "dos_mitigation_audit",
            OTHER_OBJECT_ACCESS,
        ),
        // Audit IPsec Main Mode.
        4646 => ("IPsec 주 모드 보안 ID 기록", "IPsec 주 모드 협상의 보안 ID 기록", "ipsec_main_mode", IPSEC_MAIN),
        4650 => (
            "IPsec 주 모드 SA 설정 — 확장 모드 미사용·인증서 미사용",
            "IPsec 주 모드 보안 연결(SA)이 설정됨",
            "ipsec_main_mode",
            IPSEC_MAIN,
        ),
        4651 => (
            "IPsec 주 모드 SA 설정 — 확장 모드 미사용·인증서 인증",
            "IPsec 주 모드 보안 연결(SA)이 인증서 인증으로 설정됨",
            "ipsec_main_mode",
            IPSEC_MAIN,
        ),
        4652 | 4653 => ("IPsec 주 모드 협상 실패", "IPsec 주 모드 협상이 실패함", "ipsec_main_mode", IPSEC_MAIN),
        4655 => ("IPsec 주 모드 SA 종료", "IPsec 주 모드 보안 연결(SA)이 종료됨", "ipsec_main_mode", IPSEC_MAIN),
        4976 => (
            "IPsec 주 모드 잘못된 협상 패킷",
            "주 모드 협상 중 유효하지 않은 협상 패킷을 수신함",
            "ipsec_main_mode",
            IPSEC_MAIN,
        ),
        5049 => ("IPsec 보안 연결(SA) 삭제", "IPsec 보안 연결이 삭제됨", "ipsec_main_mode", IPSEC_MAIN),
        5453 => (
            "IPsec 협상 실패 — IKEEXT 서비스 미시작",
            "IKE/AuthIP 키 모듈(IKEEXT) 서비스가 시작되지 않아 협상 실패",
            "ipsec_main_mode",
            IPSEC_MAIN,
        ),
        // Audit IPsec Quick Mode.
        4977 => (
            "IPsec 빠른 모드 잘못된 협상 패킷",
            "빠른 모드 협상 중 유효하지 않은 협상 패킷을 수신함",
            "ipsec_quick_mode",
            IPSEC_QUICK,
        ),
        5451 => ("IPsec 빠른 모드 SA 설정", "IPsec 빠른 모드 보안 연결(SA)이 설정됨", "ipsec_quick_mode", IPSEC_QUICK),
        5452 => ("IPsec 빠른 모드 SA 종료", "IPsec 빠른 모드 보안 연결(SA)이 종료됨", "ipsec_quick_mode", IPSEC_QUICK),
        // Audit IPsec Extended Mode.
        4978 => (
            "IPsec 확장 모드 잘못된 협상 패킷",
            "확장 모드 협상 중 유효하지 않은 협상 패킷을 수신함",
            "ipsec_extended_mode",
            IPSEC_EXTENDED,
        ),
        4979..=4982 => (
            "IPsec 주 모드·확장 모드 SA 설정",
            "IPsec 주 모드와 확장 모드 보안 연결(SA)이 설정됨",
            "ipsec_extended_mode",
            IPSEC_EXTENDED,
        ),
        4983 | 4984 => (
            "IPsec 확장 모드 협상 실패",
            "확장 모드 협상 실패로 대응 주 모드 보안 연결이 삭제됨",
            "ipsec_extended_mode",
            IPSEC_EXTENDED,
        ),
        // Audit IPsec Driver.
        4960 => (
            "IPsec 인바운드 패킷 삭제 — 무결성 검사 실패",
            "무결성 검사에 실패한 인바운드 패킷을 IPsec이 삭제함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        4961 => (
            "IPsec 인바운드 패킷 삭제 — 재생 검사 실패",
            "재생 검사에 실패한 인바운드 패킷을 IPsec이 삭제함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        4962 => (
            "IPsec 인바운드 패킷 삭제 — 일련번호 과소",
            "일련번호가 낮아 재생 여부를 보장할 수 없는 패킷을 삭제함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        4963 => (
            "IPsec 평문 인바운드 패킷 삭제",
            "보호돼야 할 평문 인바운드 패킷을 IPsec이 삭제함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        4965 => (
            "IPsec SPI 불일치 패킷 수신",
            "잘못된 보안 매개 변수 인덱스(SPI)를 가진 패킷을 수신함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        5478 => ("IPsec 서비스 시작", "IPsec 서비스가 시작됨", "ipsec_driver", IPSEC_DRIVER),
        5479 => ("IPsec 서비스 종료", "IPsec 서비스가 종료됨", "ipsec_driver", IPSEC_DRIVER),
        5480 => (
            "IPsec 네트워크 인터페이스 목록 조회 실패",
            "IPsec 서비스가 전체 네트워크 인터페이스 목록을 가져오지 못함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        5483 => (
            "IPsec RPC 서버 초기화 실패",
            "IPsec 서비스가 RPC 서버 초기화에 실패해 시작하지 못함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        5484 => (
            "IPsec 서비스 심각한 오류 종료",
            "IPsec 서비스가 심각한 오류로 종료됨",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        5485 => (
            "IPsec PnP 필터 처리 실패",
            "네트워크 인터페이스 PnP 이벤트에서 일부 IPsec 필터를 처리하지 못함",
            "ipsec_driver",
            IPSEC_DRIVER,
        ),
        // Audit Filtering Platform Policy Change — IPsec policy objects.
        4709 => ("IPsec 서비스 시작됨", "IPsec 서비스가 시작됨", "ipsec_policy_change", FP_POLICY),
        4710 => ("IPsec 서비스 사용 안 함", "IPsec 서비스가 사용 안 함으로 설정됨", "ipsec_policy_change", FP_POLICY),
        4711 => (
            "IPsec 정책 엔진 동작",
            "PAStore 엔진 동작 중 하나가 기록됨 — 세부 동작은 payload 원문으로 확인",
            "ipsec_policy_change",
            FP_POLICY,
        ),
        4712 => (
            "IPsec 서비스 오류 가능성",
            "IPsec 서비스가 심각할 수 있는 오류를 만남",
            "ipsec_policy_change",
            FP_POLICY,
        ),
        5040 => ("IPsec 인증 집합 추가", "IPsec 설정 변경 — 인증 집합 추가", "ipsec_policy_change", FP_POLICY),
        5041 => ("IPsec 인증 집합 수정", "IPsec 설정 변경 — 인증 집합 수정", "ipsec_policy_change", FP_POLICY),
        5042 => ("IPsec 인증 집합 삭제", "IPsec 설정 변경 — 인증 집합 삭제", "ipsec_policy_change", FP_POLICY),
        5043 => ("연결 보안 규칙 추가", "IPsec 설정 변경 — 연결 보안 규칙 추가", "ipsec_policy_change", FP_POLICY),
        5044 => ("연결 보안 규칙 수정", "IPsec 설정 변경 — 연결 보안 규칙 수정", "ipsec_policy_change", FP_POLICY),
        5045 => ("연결 보안 규칙 삭제", "IPsec 설정 변경 — 연결 보안 규칙 삭제", "ipsec_policy_change", FP_POLICY),
        5046 => ("IPsec 암호화 집합 추가", "IPsec 설정 변경 — 암호화 집합 추가", "ipsec_policy_change", FP_POLICY),
        5047 => ("IPsec 암호화 집합 수정", "IPsec 설정 변경 — 암호화 집합 수정", "ipsec_policy_change", FP_POLICY),
        5048 => ("IPsec 암호화 집합 삭제", "IPsec 설정 변경 — 암호화 집합 삭제", "ipsec_policy_change", FP_POLICY),
        // Audit Filtering Platform Policy Change — WFP objects and PAStore.
        5440 => (
            "BFE 시작 시 콜아웃 존재",
            "기본 필터링 엔진 시작 시 존재한 콜아웃 기록",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5441 => (
            "BFE 시작 시 필터 존재",
            "기본 필터링 엔진 시작 시 존재한 필터 기록",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5442 => (
            "BFE 시작 시 공급자 존재",
            "기본 필터링 엔진 시작 시 존재한 공급자 기록",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5443 => (
            "BFE 시작 시 공급자 컨텍스트 존재",
            "기본 필터링 엔진 시작 시 존재한 공급자 컨텍스트 기록",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5444 => (
            "BFE 시작 시 하위 계층 존재",
            "기본 필터링 엔진 시작 시 존재한 하위 계층 기록",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5446 => ("WFP 콜아웃 변경", "Windows 필터링 플랫폼 콜아웃이 변경됨", "filtering_platform_policy_change", FP_POLICY),
        5447 => ("WFP 필터 변경", "Windows 필터링 플랫폼 필터가 변경됨", "filtering_platform_policy_change", OTHER_POLICY),
        5448 => ("WFP 공급자 변경", "Windows 필터링 플랫폼 공급자가 변경됨", "filtering_platform_policy_change", FP_POLICY),
        5449 => (
            "WFP 공급자 컨텍스트 변경",
            "Windows 필터링 플랫폼 공급자 컨텍스트가 변경됨",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5450 => (
            "WFP 하위 계층 변경",
            "Windows 필터링 플랫폼 하위 계층이 변경됨",
            "filtering_platform_policy_change",
            FP_POLICY,
        ),
        5456 => ("AD IPsec 정책 적용", "PAStore 엔진이 Active Directory IPsec 정책을 적용함", "filtering_platform_policy_change", FP_POLICY),
        5457 => ("AD IPsec 정책 적용 실패", "PAStore 엔진이 Active Directory IPsec 정책 적용에 실패함", "filtering_platform_policy_change", FP_POLICY),
        5458 => ("캐시된 AD IPsec 정책 적용", "PAStore 엔진이 로컬 캐시된 AD IPsec 정책을 적용함", "filtering_platform_policy_change", FP_POLICY),
        5459 => ("캐시된 AD IPsec 정책 적용 실패", "PAStore 엔진이 로컬 캐시된 AD IPsec 정책 적용에 실패함", "filtering_platform_policy_change", FP_POLICY),
        5460 => ("로컬 레지스트리 IPsec 정책 적용", "PAStore 엔진이 로컬 레지스트리 IPsec 정책을 적용함", "filtering_platform_policy_change", FP_POLICY),
        5461 => ("로컬 레지스트리 IPsec 정책 적용 실패", "PAStore 엔진이 로컬 레지스트리 IPsec 정책 적용에 실패함", "filtering_platform_policy_change", FP_POLICY),
        5462 => ("일부 IPsec 규칙 적용 실패", "PAStore 엔진이 활성 IPsec 정책의 일부 규칙을 적용하지 못함", "filtering_platform_policy_change", FP_POLICY),
        5463 => ("IPsec 정책 변경 없음 확인", "PAStore 엔진이 활성 IPsec 정책 변경을 조회해 변경 없음을 확인함", "filtering_platform_policy_change", FP_POLICY),
        5464 => ("IPsec 정책 변경 적용", "PAStore 엔진이 활성 IPsec 정책 변경을 조회해 적용함", "filtering_platform_policy_change", FP_POLICY),
        5465 => ("IPsec 정책 강제 다시 로드", "PAStore 엔진이 IPsec 정책 강제 다시 로드 제어를 처리함", "filtering_platform_policy_change", FP_POLICY),
        5466 => ("AD 접근 불가 — 캐시 정책 사용", "AD에 접근할 수 없어 캐시된 AD IPsec 정책을 사용함", "filtering_platform_policy_change", FP_POLICY),
        5467 => ("AD 접근 가능 — 변경 없음", "AD에 접근 가능하며 IPsec 정책 변경이 없어 캐시 사용을 중단함", "filtering_platform_policy_change", FP_POLICY),
        5468 => ("AD 접근 가능 — 변경 적용", "AD에 접근 가능하며 IPsec 정책 변경을 적용하고 캐시 사용을 중단함", "filtering_platform_policy_change", FP_POLICY),
        5471 => ("로컬 저장소 IPsec 정책 로드", "PAStore 엔진이 로컬 저장소 IPsec 정책을 로드함", "filtering_platform_policy_change", FP_POLICY),
        5472 => ("로컬 저장소 IPsec 정책 로드 실패", "PAStore 엔진이 로컬 저장소 IPsec 정책 로드에 실패함", "filtering_platform_policy_change", FP_POLICY),
        5473 => ("디렉터리 저장소 IPsec 정책 로드", "PAStore 엔진이 디렉터리 저장소 IPsec 정책을 로드함", "filtering_platform_policy_change", FP_POLICY),
        5474 => ("디렉터리 저장소 IPsec 정책 로드 실패", "PAStore 엔진이 디렉터리 저장소 IPsec 정책 로드에 실패함", "filtering_platform_policy_change", FP_POLICY),
        5477 => ("빠른 모드 필터 추가 실패", "PAStore 엔진이 빠른 모드 필터를 추가하지 못함", "filtering_platform_policy_change", FP_POLICY),
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

/// Where the row came from: provider, provider GUID and channel — never
/// inferred from the fields. The GUID is the manifest's own identity and
/// wins over the display name when facts carry it.
fn event_family(provider: &str, provider_guid: &str, channel: &str) -> &'static str {
    let guid = provider_guid.trim_matches(|c| c == '{' || c == '}');
    if guid.eq_ignore_ascii_case(FIREWALL_PROVIDER_GUID)
        || provider == FIREWALL_PROVIDER
        || channel.starts_with(FIREWALL_PROVIDER)
    {
        return match channel.rsplit('/').next().unwrap_or("") {
            "Firewall" => "firewall_channel",
            "ConnectionSecurity" => "connection_security_channel",
            "FirewallDiagnostics" => "firewall_diagnostics_channel",
            "FirewallVerbose" => "firewall_verbose_channel",
            "ConnectionSecurityVerbose" => "connection_security_verbose_channel",
            _ => "firewall_provider_channel",
        };
    }
    if provider == SECURITY_PROVIDER {
        return "security_audit";
    }
    if provider == WFP_PROVIDER {
        return "wfp_operational";
    }
    if provider == IKE_PROVIDER {
        return "ike_operational";
    }
    "other_provider"
}

fn channel_scope(family: &str) -> &'static str {
    match family {
        "firewall_channel" | "firewall_verbose_channel" => "firewall_policy_channel",
        "connection_security_channel" | "connection_security_verbose_channel" => {
            "connection_security_channel"
        }
        "firewall_diagnostics_channel" => "firewall_diagnostics_channel",
        "wfp_operational" | "ike_operational" => "provider_operational",
        _ => "unknown",
    }
}

/// Template family an event's payload follows, taken from the provider
/// manifests — never from the field names of the record in hand.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Firewall rule, setting, profile and service payloads.
    Rule,
    /// Filtering-platform per-packet / per-call audits.
    Packet,
    /// Filtering-platform denial-of-service defence audits.
    Dos,
    /// IPsec main/extended/quick mode and IPsec driver payloads.
    Ipsec,
    /// IPsec policy objects (authentication/crypto set, connection security rule).
    IpsecPolicy,
    /// Windows Filtering Platform object add/change audits.
    WfpObject,
    /// PAStore engine policy load/apply audits.
    PaStore,
    /// No manifest template is available: nothing is mapped.
    None,
}

const MPSSVC_MANIFEST: &str = "mpssvc.dll 10.0.26100.9549 WEVT_TEMPLATE";
const AUDIT_MANIFEST: &str =
    "Microsoft-Windows-Security-Auditing 매니페스트 {54849625-5478-4994-a5ba-3e3b0328c30d} (Windows 10 17134 덤프)";

/// Template family and template version of a Security-channel event as the
/// Microsoft-Windows-Security-Auditing manifest declares them.
fn audit_shape(event_id: i64) -> Option<(Shape, i64)> {
    Some(match event_id {
        4944..=4958 | 5024 | 5025 | 5027..=5037 => (Shape::Rule, 0),
        5146 | 5147 | 5150..=5155 | 5158 | 5159 => (Shape::Packet, 0),
        5156 | 5157 => (Shape::Packet, 1),
        5148 | 5149 => (Shape::Dos, 0),
        4646 | 4650..=4653 | 4655 | 4960..=4963 | 4965 | 4976..=4984 | 5453 | 5478..=5480
        | 5483..=5485 => (Shape::Ipsec, 0),
        5451 | 5452 => (Shape::Ipsec, 1),
        4709..=4712 | 5040..=5048 | 5049 => (Shape::IpsecPolicy, 0),
        5440..=5444 | 5446..=5450 => (Shape::WfpObject, 0),
        5456..=5468 | 5471..=5474 | 5477 => (Shape::PaStore, 0),
        _ => return None,
    })
}

/// Shape plus the manifest template version to guard against, if any.
fn schema_shape(family: &str, event_id: Option<i64>) -> (Shape, Option<i64>) {
    if family == "security_audit" {
        return match event_id.and_then(audit_shape) {
            Some((shape, version)) => (shape, Some(version)),
            None => (Shape::None, None),
        };
    }
    // The mpssvc.dll manifest declares version 0 for all 111 of its event
    // definitions, so a record that says otherwise is a build difference.
    match family {
        "firewall_channel"
        | "firewall_verbose_channel"
        | "firewall_diagnostics_channel"
        | "firewall_provider_channel"
        | "connection_security_channel"
        | "connection_security_verbose_channel" => (Shape::Rule, Some(0)),
        _ => (Shape::None, None),
    }
}

/// Where the meaning of the stored field names comes from. Without a
/// manifest template nothing is mapped and the names survive only in
/// `FirewallEventFields`.
fn field_schema_basis(family: &str, shape: Shape) -> &'static str {
    if shape == Shape::None {
        return "undocumented_fields_preserved";
    }
    if family == "security_audit" {
        "provider_manifest_security_auditing"
    } else {
        "provider_manifest_mpssvc"
    }
}

fn field_schema_source(family: &str, shape: Shape) -> Option<&'static str> {
    match (shape, family) {
        (Shape::None, _) => None,
        (_, "security_audit") => Some(AUDIT_MANIFEST),
        _ => Some(MPSSVC_MANIFEST),
    }
}

/// The manifest was read from one Windows build; the record carries its own
/// template version. Mapping is by field name, so a difference is recorded
/// instead of silently trusted.
fn schema_version_state(manifest: Option<i64>, event: Option<i64>) -> &'static str {
    match (manifest, event) {
        (None, _) => "not_applicable",
        (Some(_), None) => "event_version_unrecorded",
        (Some(manifest), Some(event)) if manifest == event => "match",
        _ => "event_version_differs",
    }
}

/// IPsec negotiation stage of an event, from its documented subcategory.
fn ipsec_mode(scope: &str) -> Option<&'static str> {
    match scope {
        "ipsec_main_mode" => Some("main_mode"),
        "ipsec_quick_mode" => Some("quick_mode"),
        "ipsec_extended_mode" => Some("extended_mode"),
        "ipsec_driver" => Some("driver"),
        _ => None,
    }
}

/// Which IPsec policy object a 5040~5049 record names, by the manifest's own
/// field names.
fn policy_object(payload: &Map<String, Value>) -> Option<(&'static str, &'static str, &'static str)> {
    for entry in [
        ("authentication_set", "AuthenticationSetId", "AuthenticationSetName"),
        (
            "connection_security_rule",
            "ConnectionSecurityRuleId",
            "ConnectionSecurityRuleName",
        ),
        ("cryptographic_set", "CryptographicSetId", "CryptographicSetName"),
        (
            "security_association",
            "IpSecSecurityAssociationId",
            "IpSecSecurityAssociationName",
        ),
    ] {
        if lookup(payload, entry.1).is_some() || lookup(payload, entry.2).is_some() {
            return Some(entry);
        }
    }
    None
}

/// Which Windows Filtering Platform object a 5440~5450 record describes.
fn wfp_object(payload: &Map<String, Value>) -> Option<(&'static str, &'static str, &'static str, &'static str, &'static str)> {
    for entry in [
        ("filter", "FilterKey", "FilterName", "FilterType", "FilterId"),
        ("callout", "CalloutKey", "CalloutName", "CalloutType", "CalloutId"),
        (
            "provider_context",
            "ProviderContextKey",
            "ProviderContextName",
            "ProviderContextType",
            "",
        ),
        ("sublayer", "SubLayerKey", "SubLayerName", "SubLayerType", ""),
        ("provider", "ProviderKey", "ProviderName", "ProviderType", ""),
    ] {
        if lookup(payload, entry.1).is_some() {
            return Some(entry);
        }
    }
    None
}

fn classify(
    family: &'static str,
    event_id: Option<i64>,
    raw_id: &str,
    payload_family: &'static str,
) -> Definition {
    if family == "security_audit" {
        if let Some((event_type, description, scope, subcategory)) =
            event_id.and_then(documented_audit)
        {
            return Definition {
                event_type: event_type.to_string(),
                description: description.to_string(),
                state: "confirmed_documented",
                basis: "Microsoft 감사 하위 범주 문서(MPSSVC 규칙 수준 정책 변경·기타 시스템 이벤트·필터링 플랫폼 연결/패킷 삭제/정책 변경·IPsec 주/빠른/확장 모드·IPsec 드라이버)",
                scope,
                subcategory: Some(subcategory),
            };
        }
    }
    // 2010 carries InterfaceGuid/InterfaceName/OldProfile/NewProfile: the
    // event's subject is confirmed by its own schema, the values are not.
    if family == "firewall_channel" && event_id == Some(2010) {
        return Definition {
            event_type: "프로필 전환".into(),
            description: "인터페이스별 적용 프로필 값 기록(Old/New 원문 보존)".into(),
            state: "confirmed_schema",
            basis: "payload 필드 InterfaceGuid/InterfaceName/OldProfile/NewProfile",
            scope: "firewall_policy_channel",
            subcategory: None,
        };
    }
    if family == "firewall_channel" {
        if let Some(label) = event_id.and_then(legacy_channel_label) {
            return Definition {
                event_type: label.to_string(),
                description: format!("기존 확정 뷰 라벨 유지 — 기록된 필드군: {payload_family}"),
                state: "legacy_label_unconfirmed",
                basis: "기존 뷰 라벨 유지 — 수집 증거에 제공자 메시지 문자열 없음",
                scope: "firewall_policy_channel",
                subcategory: None,
            };
        }
    }
    Definition {
        event_type: if raw_id.is_empty() {
            "방화벽 이벤트".into()
        } else {
            format!("방화벽 이벤트 {raw_id}")
        },
        description: format!("제공자 정의 미확인 — 기록된 필드군: {payload_family}"),
        state: "unconfirmed",
        basis: match family {
            "security_audit" => "Microsoft 감사 하위 범주 문서에 정의가 없는 이벤트 — 의미 미확인",
            "firewall_channel"
            | "firewall_verbose_channel"
            | "firewall_diagnostics_channel"
            | "firewall_provider_channel"
            | "connection_security_channel"
            | "connection_security_verbose_channel" => {
                "제공자 매니페스트(mpssvc.dll WEVT_TEMPLATE)에 이벤트·템플릿 정의는 있으나 메시지 문자열은 언어 리소스 mpssvc.dll.mui에만 있어 의미 미확인"
            }
            // Both channels belong to the Microsoft-Windows-WFP publisher.
            "wfp_operational" | "ike_operational" => {
                "제공자 정의·메시지 리소스(%WinDir%\\system32\\drivers\\fwpkclnt.sys)를 수집 증거에서 확인하지 못함"
            }
            _ => "수집 증거에 제공자 메시지·스키마 없음",
        },
        scope: if family == "security_audit" {
            "unknown"
        } else {
            channel_scope(family)
        },
        subcategory: None,
    }
}

/// Family of the payload as observed, never as assumed semantics.
fn payload_family(payload: &Map<String, Value>) -> &'static str {
    let has = |name: &str| lookup(payload, name).is_some();
    if payload.is_empty() {
        return "none";
    }
    if payload.contains_key(PROCESSING_ERROR) {
        return "processing_error";
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
    if has("FilterRTID") || has("LayerRTID") || has("LayerName") {
        return "filtering_platform_audit";
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
    /// Provider/channel origin, decided before any field is read.
    event_family: &'static str,
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

fn int_field(payload: &Map<String, Value>, names: &[&'static str]) -> Option<i64> {
    field_of(payload, names).and_then(|(_, value)| int_of(value))
}

/// R02: original text, confirmed number and confirmed name stay apart.
fn set_direction(record: &mut Record, payload: &Map<String, Value>) {
    let direction = set_pair(record, payload, "direction_raw", "direction_value", &["Direction"]);
    let name = direction.and_then(direction_label);
    record.set("direction", opt(name));
    let raw = record.get("direction_raw").and_then(|cell| match cell {
        Cell::Text(text) => Some(text.clone()),
        _ => None,
    });
    record.set(
        "direction_basis",
        opt(match (raw.as_deref(), name) {
            (Some(_), Some(_)) => Some("fw_direction_enum"),
            // Filtering-platform audits record a message constant such as
            // %%14592. Its string lives in msobjs.dll, the provider's
            // parameter file, which is not part of the collection, so the
            // value stays raw instead of being named from memory.
            (Some(raw), None) if raw.trim_start().starts_with("%%") => {
                Some("audit_message_constant_unresolved")
            }
            (Some(_), None) => Some("unmapped_value"),
            (None, _) => None,
        }),
    );
}

fn set_protocol(record: &mut Record, payload: &Map<String, Value>, names: &[&'static str]) {
    let protocol = set_pair(record, payload, "protocol_raw", "protocol_number", names);
    record.set("protocol", opt(protocol.and_then(protocol_label)));
}

/// R06: mask, confirmed bits and unmapped bits all survive.
fn set_profiles(record: &mut Record, payload: &Map<String, Value>) {
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
        let mask = set_pair(record, payload, raw_column, mask_column, names);
        record.set(label_column, opt(mask.and_then(profile_label).as_deref()));
        record.set(unmapped_column, number(mask.map(profile_unmapped)));
    }
}

fn set_single_ports(
    record: &mut Record,
    local: &Option<(&'static str, String)>,
    remote: &Option<(&'static str, String)>,
) {
    record.set(
        "local_port_raw",
        opt(local
            .as_ref()
            .map(|(_, text)| text.as_str())
            .filter(|text| !text.is_empty())),
    );
    record.set(
        "remote_port_raw",
        opt(remote
            .as_ref()
            .map(|(_, text)| text.as_str())
            .filter(|text| !text.is_empty())),
    );
    record.set(
        "local_port",
        number(local.as_ref().and_then(|(_, text)| text.trim().parse().ok())),
    );
    record.set(
        "remote_port",
        number(remote.as_ref().and_then(|(_, text)| text.trim().parse().ok())),
    );
    record.set(
        "single_port_basis",
        opt(local.as_ref().or(remote.as_ref()).map(|(name, _)| *name)),
    );
}

fn text_cell(payload: &Map<String, Value>, names: &[&'static str]) -> Cell {
    opt(present(payload, names).as_deref())
}

fn int_cell(payload: &Map<String, Value>, names: &[&'static str]) -> Cell {
    number(int_field(payload, names))
}

/// Everything the IPsec templates name beyond the endpoints: certificates,
/// negotiated algorithms, lifetimes, filter/SA ids and SPIs. One row per
/// record, written only when the record actually carries such a value.
fn ipsec_details(record: &mut Record, payload: &Map<String, Value>) {
    let text = |names: &[&'static str]| text_cell(payload, names);
    let num = |names: &[&'static str]| int_cell(payload, names);
    let values = vec![
        text(&["LocalMMCertHash", "LocalEMCertHash"]),
        text(&["LocalMMIssuingCA", "LocalEMIssuingCA"]),
        text(&["LocalMMRootCA", "LocalEMRootCA"]),
        text(&["RemoteMMCertHash", "RemoteEMCertHash"]),
        text(&["RemoteMMIssuingCA", "RemoteEMIssuingCA"]),
        text(&["RemoteMMRootCA", "RemoteEMRootCA"]),
        text(&["MMAuthMethod"]),
        text(&["EMAuthMethod"]),
        text(&["MMCipherAlg"]),
        text(&["MMIntegrityAlg"]),
        text(&["DHGroup"]),
        num(&["MMLifetime"]),
        num(&["QMLimit"]),
        text(&["Role"]),
        text(&["MMImpersonationState"]),
        text(&["EMImpersonationState"]),
        num(&["MMFilterID"]),
        num(&["QMFilterID"]),
        num(&["TransportFilterId"]),
        num(&["InboundSpi"]),
        num(&["OutboundSpi"]),
        num(&["SPI"]),
        num(&["TunnelId"]),
        num(&["TrafficSelectorId"]),
        text(&["LocalTunnelEndpoint"]),
        text(&["RemoteTunnelEndpoint"]),
        text(&["PeerPrivateAddress"]),
        text(&["LocalAddressMask"]),
        text(&["RemoteAddressMask"]),
        text(&["AhAuthType"]),
        text(&["EspAuthType"]),
        text(&["CipherType"]),
        text(&["Mode"]),
        num(&["LifetimeSeconds"]),
        num(&["LifetimeKilobytes"]),
        num(&["LifetimePackets"]),
        text(&["InitiatorCookie"]),
        text(&["ResponderCookie"]),
    ];
    if values.iter().all(|cell| matches!(cell, Cell::Null)) {
        return;
    }
    record.child("FirewallIpsecDetails", values);
}

/// The filtering-platform object a 5440~5450 record describes, with the key,
/// name, type and id the manifest defines for that object kind.
fn wfp_object_change(record: &mut Record, payload: &Map<String, Value>) {
    let Some((kind, key, name, type_name, id)) = wfp_object(payload) else {
        return;
    };
    let values = vec![
        value(kind),
        opt(present(payload, &[key]).as_deref()),
        opt(present(payload, &[name]).as_deref()),
        opt(present(payload, &[type_name]).as_deref()),
        if id.is_empty() {
            Cell::Null
        } else {
            number(int_field(payload, &[id]))
        },
        opt(present(payload, &["ChangeType"]).as_deref()),
        number(int_field(payload, &["Weight"])),
        opt(present(payload, &["Conditions"]).as_deref()),
        opt(present(payload, &["Action"]).as_deref()),
        opt(present(payload, &["ProviderKey"]).as_deref()),
        opt(present(payload, &["ProviderName"]).as_deref()),
        opt(present(payload, &["CalloutKey"]).as_deref()),
        opt(present(payload, &["CalloutName"]).as_deref()),
        opt(present(payload, &["LayerKey"]).as_deref()),
        number(int_field(payload, &["LayerId"])),
    ];
    record.child("FirewallFilterChanges", values);
}

fn record(ctx: &Ctx, parsed: &Parsed<'_>) -> Result<Record> {
    let row = parsed.row;
    let payload = &parsed.payload;
    let raw_id = rf(row, "EventID");
    let event_id = raw_id.parse::<i64>().ok();
    let family = parsed.event_family;
    let definition = classify(family, event_id, raw_id, parsed.family);

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
    record.set("event_family", value(family));
    record.set("event_scope", value(definition.scope));
    record.set("audit_subcategory", opt(definition.subcategory));
    let (shape, manifest_version) = schema_shape(family, event_id);
    let event_version = rf(row, "Version").parse::<i64>().ok();
    record.set("field_schema_basis", value(field_schema_basis(family, shape)));
    record.set("field_schema_source", opt(field_schema_source(family, shape)));
    record.set("field_schema_version", number(manifest_version));
    record.set(
        "field_schema_version_state",
        value(schema_version_state(manifest_version, event_version)),
    );
    record.set("payload_family", value(parsed.family));
    record.set("payload_state", value(parsed.payload_state));
    record.set("event_version", number(event_version));
    record.set("provider_guid", value(rf(row, "ProviderGuid")));

    // The provider's own decoding failure is evidence, not a payload: the
    // failed item name and the undecoded bytes stay in their own columns.
    if let Some(Value::Object(error)) = payload.get(PROCESSING_ERROR) {
        let code = error.get("ErrorCode");
        record.set(
            "processing_error_code_raw",
            opt(code.map(scalar_text).as_deref()),
        );
        record.set("processing_error_code", number(code.and_then(int_of)));
        record.set(
            "processing_error_item",
            opt(error.get("DataItemName").map(scalar_text).as_deref()),
        );
        record.set(
            "processing_error_payload",
            opt(error.get("EventPayload").map(scalar_text).as_deref()),
        );
    }

    // R05: the explicit change subject, never the recording service SID.
    // The Security-Auditing manifest names the operator of a filtering
    // platform object change `UserSid`/`UserName` (5446~5450), so those are
    // change subjects too — and nothing else in this view uses those names.
    let subject = present(payload, &["ModifyingUser"])
        .map(|text| ("modifying_user", "ModifyingUser", text))
        .or_else(|| {
            present(payload, &["SubjectUserSid"])
                .map(|text| ("audit_subject", "SubjectUserSid", text))
        })
        .or_else(|| present(payload, &["UserSid"]).map(|text| ("audit_subject", "UserSid", text)))
        .or_else(|| {
            present(payload, &["SubjectUserName"])
                .map(|text| ("audit_subject", "SubjectUserName", text))
        })
        .or_else(|| present(payload, &["UserName"]).map(|text| ("audit_subject", "UserName", text)));
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
        ("subject_user_sid", &["SubjectUserSid", "UserSid"][..]),
        ("subject_user_name", &["SubjectUserName", "UserName"][..]),
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
        ("setting_type_raw", "setting_type", &["SettingType"][..]),
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
    // R07/A02: the raw setting bytes stay exactly as recorded, and the
    // notation is only named when the recorded size proves it.
    let setting_value = text_of(payload, &["SettingValue"]).map(|(_, text)| text);
    record.set("setting_value_raw", opt(setting_value.as_deref()));
    if let Some(raw) = setting_value.as_deref().filter(|text| !text.is_empty()) {
        let size = record.get("setting_value_size").and_then(|cell| match cell {
            Cell::Int(size) => Some(*size),
            _ => None,
        });
        let hex = raw.len() % 2 == 0 && raw.chars().all(|c| c.is_ascii_hexdigit());
        record.set(
            "setting_value_encoding",
            value(if hex && size == Some((raw.len() / 2) as i64) {
                "hex_bytes"
            } else {
                "unknown"
            }),
        );
    }

    // Only what a provider manifest names is mapped into a typed column.
    // `Shape::None` means no template was available for this event id: then
    // nothing is mapped and every recorded name survives in
    // `FirewallEventFields` instead of being guessed into a meaning.
    let packet_audit = matches!(
        definition.scope,
        "connection_audit" | "packet_drop_audit" | "listen_bind_audit"
    );
    let app_role = if packet_audit { "connection_app" } else { "target_app" };

    let mut local_addresses: Option<String> = None;
    let mut remote_addresses: Option<String> = None;
    let mut local_ports: Option<String> = None;
    let mut remote_ports: Option<String> = None;
    let mut local_single: Option<(&'static str, String)> = None;
    let mut remote_single: Option<(&'static str, String)> = None;
    let mut single_local: Option<String> = None;
    let mut single_remote: Option<String> = None;
    let mut single_attribution = "observed_connection";
    let mut source_address: Option<String> = None;
    let mut dest_address: Option<String> = None;
    let mut source_port: Option<String> = None;
    let mut dest_port: Option<String> = None;
    let mut app_path: Option<String> = None;
    let mut modifying_app: Option<String> = None;

    match shape {
        Shape::Rule => {
            set_direction(&mut record, payload);
            let action = set_pair(&mut record, payload, "action_raw", "action_value", &["Action"]);
            record.set("action", opt(action.and_then(action_label)));
            set_protocol(&mut record, payload, &["Protocol"]);
            set_profiles(&mut record, payload);
            for (column, names) in [
                ("rule_attribute", &["RuleAttr"][..]),
                ("rejection_reason", &["ReasonForRejection"][..]),
                ("active_profile", &["ActiveProfile"][..]),
            ] {
                record.set(column, opt(present(payload, names).as_deref()));
            }

            // R03/R14: rule lists and single observed values are different
            // columns.
            local_addresses = present(payload, &["LocalAddresses"]);
            remote_addresses = present(payload, &["RemoteAddresses"]);
            record.set("local_addresses", opt(local_addresses.as_deref()));
            record.set("remote_addresses", opt(remote_addresses.as_deref()));
            let single_address =
                text_of(payload, &["LocalAddress", "RemoteAddress", "RemoteIp", "IpAddress"]);
            single_local = present(payload, &["LocalAddress"]);
            single_remote = present(payload, &["RemoteAddress", "RemoteIp", "IpAddress"]);
            record.set("local_address", opt(single_local.as_deref()));
            record.set("remote_address", opt(single_remote.as_deref()));
            record.set(
                "single_address_basis",
                opt(single_address.as_ref().map(|(name, _)| *name)),
            );
            record.set(
                "address_attribution",
                opt(match (
                    local_addresses.is_some() || remote_addresses.is_some(),
                    single_address.is_some(),
                ) {
                    (true, _) => Some("rule_definition"),
                    (false, true) => Some("observed_connection"),
                    (false, false) => None,
                }),
            );

            local_ports = present(payload, &["LocalPorts"]);
            remote_ports = present(payload, &["RemotePorts"]);
            record.set("local_ports", opt(local_ports.as_deref()));
            record.set("remote_ports", opt(remote_ports.as_deref()));
            local_single = text_of(payload, &["LocalPort", "Port"]);
            remote_single = text_of(payload, &["RemotePort"]);
            set_single_ports(&mut record, &local_single, &remote_single);
        }
        Shape::Packet => {
            set_direction(&mut record, payload);
            set_protocol(&mut record, payload, &["Protocol"]);
            source_address = present(payload, &["SourceAddress"]);
            dest_address = present(payload, &["DestAddress"]);
            source_port = present(payload, &["SourcePort"]);
            dest_port = present(payload, &["DestPort"]);
            record.set("source_address", opt(source_address.as_deref()));
            record.set("dest_address", opt(dest_address.as_deref()));
            record.set("source_port_raw", opt(source_port.as_deref()));
            record.set("dest_port_raw", opt(dest_port.as_deref()));
            record.set(
                "source_port",
                number(source_port.as_deref().and_then(|text| text.trim().parse().ok())),
            );
            record.set(
                "dest_port",
                number(dest_port.as_deref().and_then(|text| text.trim().parse().ok())),
            );
            record.set(
                "endpoint_attribution",
                opt((source_address.is_some()
                    || dest_address.is_some()
                    || source_port.is_some()
                    || dest_port.is_some())
                .then_some("observed_packet_endpoint")),
            );
            set_pair(
                &mut record,
                payload,
                "filter_run_time_id_raw",
                "filter_run_time_id",
                &["FilterRTID"],
            );
            set_pair(
                &mut record,
                payload,
                "layer_run_time_id_raw",
                "layer_run_time_id",
                &["LayerRTID"],
            );
            record.set("layer_name_raw", opt(present(payload, &["LayerName"]).as_deref()));
            // The audited process, never the service that wrote the record.
            set_pair(
                &mut record,
                payload,
                "payload_process_id_raw",
                "payload_process_id",
                &["ProcessID", "ProcessId"],
            );
            // A remote identity is evidence about the peer, not an operator.
            record.set(
                "remote_user_sid",
                opt(present(payload, &["RemoteUserID"]).as_deref()),
            );
            record.set(
                "remote_machine_sid",
                opt(present(payload, &["RemoteMachineID"]).as_deref()),
            );
            // Layer-2 audits (5146/5147/5150/5151) carry the frame context.
            for (column, names) in [
                ("ether_type_raw", &["EtherType"][..]),
                ("vlan_tag_raw", &["VlanTag"][..]),
                ("media_type", &["MediaType"][..]),
                ("interface_type", &["InterfaceType"][..]),
                ("vswitch_id", &["vSwitchID"][..]),
            ] {
                record.set(column, opt(present(payload, names).as_deref()));
            }
            record.set(
                "source_vswitch_port",
                number(int_field(payload, &["SourcevSwitchPort"])),
            );
            record.set(
                "dest_vswitch_port",
                number(int_field(payload, &["DestinationvSwitchPort"])),
            );
        }
        Shape::Dos => {
            record.set("dos_type", opt(present(payload, &["Type"]).as_deref()));
            record.set(
                "packets_discarded",
                number(int_field(payload, &["PacketsDiscarded"])),
            );
        }
        Shape::Ipsec => {
            record.set("ipsec_mode", opt(ipsec_mode(definition.scope)));
            // The security association's own endpoints: neither a rule
            // address nor an observed packet endpoint.
            single_local = present(payload, &["LocalAddress"]);
            single_remote = present(payload, &["RemoteAddress"]);
            single_attribution = "observed_security_association";
            record.set("local_address", opt(single_local.as_deref()));
            record.set("remote_address", opt(single_remote.as_deref()));
            record.set(
                "single_address_basis",
                opt(field_of(payload, &["LocalAddress", "RemoteAddress"]).map(|(name, _)| name)),
            );
            if single_local.is_some() || single_remote.is_some() {
                record.set("address_attribution", value(single_attribution));
            }
            local_single = text_of(payload, &["LocalPort", "LocalKeyModPort"]);
            remote_single = text_of(payload, &["RemotePort", "RemoteKeyModPort"]);
            set_single_ports(&mut record, &local_single, &remote_single);
            set_protocol(&mut record, payload, &["IpProtocol"]);
            for (column, names) in [
                (
                    "local_principal",
                    &["LocalMMPrincipalName", "LocalEMPrincipalName"][..],
                ),
                (
                    "remote_principal",
                    &["RemoteMMPrincipalName", "RemoteEMPrincipalName"][..],
                ),
                ("keying_module", &["KeyModName", "KeyingModuleName"][..]),
                ("failure_point", &["FailurePoint"][..]),
                ("failure_reason", &["FailureReason"][..]),
                ("negotiation_state", &["State"][..]),
            ] {
                record.set(column, opt(present(payload, names).as_deref()));
            }
            record.set(
                "main_mode_sa_id",
                number(int_field(payload, &["MMSAID", "MainModeSaId"])),
            );
            record.set("quick_mode_sa_id", number(int_field(payload, &["QuickModeSaId"])));
            // 5483/5484 name the failure `Error`, not `ErrorCode`.
            set_pair(&mut record, payload, "error_code_raw", "error_code", &["Error"]);
            ipsec_details(&mut record, payload);
        }
        Shape::IpsecPolicy => {
            set_profiles(&mut record, payload);
            if let Some((kind, id, name)) = policy_object(payload) {
                record.set("policy_object_kind", value(kind));
                record.set("policy_object_id", opt(present(payload, &[id]).as_deref()));
                record.set("policy_object_name", opt(present(payload, &[name]).as_deref()));
            }
        }
        Shape::WfpObject => {
            set_pair(
                &mut record,
                payload,
                "payload_process_id_raw",
                "payload_process_id",
                &["ProcessId"],
            );
            record.set("layer_name_raw", opt(present(payload, &["LayerName"]).as_deref()));
            wfp_object_change(&mut record, payload);
        }
        Shape::PaStore => {
            record.set("pastore_policy", opt(present(payload, &["Policy"]).as_deref()));
            record.set(
                "quick_mode_filter",
                opt(present(payload, &["QuickModeFilter"]).as_deref()),
            );
            set_pair(&mut record, payload, "error_code_raw", "error_code", &["Error"]);
        }
        Shape::None => {}
    }

    // R13/A07: target application and modifying application stay apart.
    if matches!(shape, Shape::Rule | Shape::Packet) {
        let app = text_of(payload, &["ApplicationPath", "Application", "Application Path"]);
        record.set(
            "app_path_state",
            value(match app.as_ref().map(|(_, text)| text.as_str()) {
                None => "absent",
                Some("") => "empty",
                Some(_) => "recorded",
            }),
        );
        app_path = app
            .as_ref()
            .map(|(_, text)| text.clone())
            .filter(|text| !text.is_empty());
        record.set("app_path", opt(app_path.as_deref()));
        record.set(
            "app_path_attribution",
            opt(app_path.as_ref().map(|_| {
                if packet_audit {
                    "observed_connection_process"
                } else {
                    "rule_target"
                }
            })),
        );
        modifying_app = present(payload, &["ModifyingApplication"]);
        record.set("modifying_app", opt(modifying_app.as_deref()));
        for (column, raw) in [
            ("app_path_resolved", app_path.as_deref()),
            ("modifying_app_resolved", modifying_app.as_deref()),
        ] {
            let resolved = raw.map(|raw| resolve(ctx, raw).0).unwrap_or(Cell::Null);
            record.set(column, resolved);
        }
    } else {
        record.set("app_path_state", value("not_mapped"));
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
        record.get("source_address"),
        record.get("dest_address"),
        record.get("remote_user_sid"),
        record.get("remote_machine_sid"),
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
        ("local", single_local.clone(), single_attribution),
        ("remote", single_remote.clone(), single_attribution),
        ("source", source_address.clone(), "observed_packet_endpoint"),
        (
            "destination",
            dest_address.clone(),
            "observed_packet_endpoint",
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
            single_attribution,
        ),
        (
            "remote",
            remote_single
                .as_ref()
                .map(|(_, text)| text.clone())
                .filter(|text| !text.is_empty()),
            single_attribution,
        ),
        ("source", source_port.clone(), "observed_packet_endpoint"),
        ("destination", dest_port.clone(), "observed_packet_endpoint"),
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
        (app_role, app_path.as_deref()),
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
    ipsec: i64,
    first: Option<String>,
    last: Option<String>,
    source_file: Option<String>,
}

/// The Security log, including its rotated copies.
fn security_log(name: &str) -> bool {
    name.eq_ignore_ascii_case(SECURITY_LOG) || rotated_of(name, SECURITY_LOG)
}

fn starts_ci(name: &str, prefix: &str) -> bool {
    name.len() >= prefix.len()
        && name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// A rotated copy keeps the stem and adds `_<digits>`.
fn rotated_of(name: &str, log: &str) -> bool {
    let bytes = name.as_bytes();
    starts_ci(name, log)
        && bytes.len() > log.len() + 1
        && bytes[log.len()] == b'_'
        && bytes[log.len() + 1..].iter().all(|b| b.is_ascii_digit())
}

fn relevant_log(name: &str) -> bool {
    // Every channel of the firewall provider, whatever the collection named it.
    starts_ci(name, FIREWALL_PROVIDER)
        || LOGS
            .iter()
            .any(|log| name.eq_ignore_ascii_case(log) || rotated_of(name, log))
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
        let family = event_family(provider, rf(row, "ProviderGuid"), channel);
        let audit_scope = (family == "security_audit")
            .then(|| event_id.and_then(documented_audit))
            .flatten()
            .map(|(_, _, scope, _)| scope);
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
                if audit_scope.is_some_and(|scope| scope.starts_with("ipsec")) {
                    entry.ipsec += 1;
                }
            }
        }

        // Every event of every firewall-provider channel is kept, known or
        // not; so is every event of the dedicated WFP/IKE channels. From the
        // Security log only the documented firewall, filtering platform and
        // IPsec audits are taken, plus the filtering-platform connection ids
        // that Microsoft lists without an own page.
        let firewall_provider_event = !matches!(
            family,
            "security_audit" | "wfp_operational" | "ike_operational" | "other_provider"
        );
        let security_keep = family == "security_audit"
            && event_id.is_some_and(|id| {
                documented_audit(id).is_some() || CONNECTION_AUDIT_IDS.contains(&id)
            });
        let keep = firewall_provider_event || (tracked && !security_log(&table)) || security_keep;
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
        // empty payload are different observations. A record the provider
        // itself could not decode is a third, distinct state.
        let payload_state = match raw_payload.map(|raw| raw.trim().is_empty()) {
            None => "absent",
            Some(true) => "empty",
            Some(false) if payload.contains_key(PROCESSING_ERROR) => "processing_error",
            Some(false) if payload.is_empty() => "unparsed",
            Some(false) => "recorded",
        };
        parsed.push(Parsed {
            row,
            fields: flatten(&payload),
            family: payload_family(&payload),
            event_family: family,
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
    // A rule id is only comparable inside the channel that defined it, so a
    // firewall rule and a connection security rule never chain together.
    let mut groups: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for (index, event) in parsed.iter().enumerate() {
        if let Some(rule_id) = event.rule_id.as_deref() {
            groups
                .entry((event.event_family, rule_id))
                .or_default()
                .push(index);
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
         collection_state,input_row_count,event_count,firewall_event_count,connection_audit_event_count,ipsec_event_count,
         corrupted_count,untimed_count,first_observed_time,last_observed_time,audit_setting_state,error,
         source_dataset_id,source_db,source_table,source_rowid,facts_generation)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,'unknown',?18,?19,?20,?21,?22,?23)",
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
            stats.map(|stats| stats.ipsec),
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
  event_scope TEXT,
  audit_subcategory TEXT,
  field_schema_basis TEXT,
  field_schema_source TEXT,
  field_schema_version INTEGER,
  field_schema_version_state TEXT,
  event_version INTEGER,
  provider_guid TEXT,
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
  app_path_attribution TEXT,
  service TEXT,
  direction_raw TEXT,
  direction_value INTEGER,
  direction TEXT,
  direction_basis TEXT,
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
  source_address TEXT,
  dest_address TEXT,
  source_port_raw TEXT,
  dest_port_raw TEXT,
  source_port INTEGER,
  dest_port INTEGER,
  endpoint_attribution TEXT,
  filter_run_time_id_raw TEXT,
  filter_run_time_id INTEGER,
  layer_name_raw TEXT,
  layer_run_time_id_raw TEXT,
  layer_run_time_id INTEGER,
  payload_process_id_raw TEXT,
  payload_process_id INTEGER,
  remote_user_sid TEXT,
  remote_machine_sid TEXT,
  processing_error_code_raw TEXT,
  processing_error_code INTEGER,
  processing_error_item TEXT,
  processing_error_payload TEXT,
  setting_value_encoding TEXT,
  ipsec_mode TEXT,
  local_principal TEXT,
  remote_principal TEXT,
  keying_module TEXT,
  main_mode_sa_id INTEGER,
  quick_mode_sa_id INTEGER,
  failure_point TEXT,
  failure_reason TEXT,
  negotiation_state TEXT,
  ether_type_raw TEXT,
  vlan_tag_raw TEXT,
  media_type TEXT,
  interface_type TEXT,
  vswitch_id TEXT,
  source_vswitch_port INTEGER,
  dest_vswitch_port INTEGER,
  dos_type TEXT,
  packets_discarded INTEGER,
  policy_object_kind TEXT,
  policy_object_id TEXT,
  policy_object_name TEXT,
  pastore_policy TEXT,
  quick_mode_filter TEXT,
  rule_attribute TEXT,
  rejection_reason TEXT,
  active_profile TEXT,
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
CREATE INDEX idx_FirewallHistory_scope ON FirewallHistory(event_scope, timestamp, record_id);
CREATE INDEX idx_FirewallHistory_family ON FirewallHistory(event_family, event_id, timestamp);
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
  CHECK(role IN ('local','remote','source','destination')),
  CHECK(attribution IN ('rule_definition','observed_connection','observed_packet_endpoint','observed_security_association')),
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
  CHECK(role IN ('local','remote','source','destination')),
  CHECK(attribution IN ('rule_definition','observed_connection','observed_packet_endpoint','observed_security_association')),
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
  CHECK(role IN ('target_app','modifying_app','connection_app')),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_FirewallAppPaths_path ON FirewallAppPaths(path_raw, role);
CREATE TABLE FirewallIpsecDetails (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  local_cert_thumbprint TEXT,
  local_cert_issuing_ca TEXT,
  local_cert_root_ca TEXT,
  remote_cert_thumbprint TEXT,
  remote_cert_issuing_ca TEXT,
  remote_cert_root_ca TEXT,
  main_mode_auth_method TEXT,
  extended_mode_auth_method TEXT,
  cipher_algorithm TEXT,
  integrity_algorithm TEXT,
  dh_group TEXT,
  main_mode_lifetime_minutes INTEGER,
  quick_mode_limit INTEGER,
  sa_role TEXT,
  main_mode_impersonation_state TEXT,
  extended_mode_impersonation_state TEXT,
  main_mode_filter_id INTEGER,
  quick_mode_filter_id INTEGER,
  transport_filter_id INTEGER,
  inbound_spi INTEGER,
  outbound_spi INTEGER,
  driver_spi INTEGER,
  tunnel_id INTEGER,
  traffic_selector_id INTEGER,
  local_tunnel_endpoint TEXT,
  remote_tunnel_endpoint TEXT,
  peer_private_address TEXT,
  local_address_mask TEXT,
  remote_address_mask TEXT,
  ah_auth_type TEXT,
  esp_auth_type TEXT,
  cipher_type TEXT,
  quick_mode_sa_mode TEXT,
  quick_mode_lifetime_seconds INTEGER,
  quick_mode_lifetime_kilobytes INTEGER,
  quick_mode_lifetime_packets INTEGER,
  initiator_cookie TEXT,
  responder_cookie TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
CREATE TABLE FirewallFilterChanges (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  object_kind TEXT NOT NULL,
  object_key TEXT,
  object_name TEXT,
  object_type TEXT,
  object_id INTEGER,
  change_type TEXT,
  weight INTEGER,
  conditions TEXT,
  action TEXT,
  provider_key TEXT,
  provider_name TEXT,
  callout_key TEXT,
  callout_name TEXT,
  layer_key TEXT,
  layer_id INTEGER,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(object_kind IN ('filter','callout','provider','provider_context','sublayer')),
  FOREIGN KEY(record_id) REFERENCES FirewallHistory(record_id) ON DELETE CASCADE
);
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
  ipsec_event_count INTEGER,
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
INSERT INTO _wina_derived_version VALUES('overview_contract',1),('firewall_history',3);
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
    "event_scope",
    "audit_subcategory",
    "field_schema_basis",
    "field_schema_source",
    "field_schema_version",
    "field_schema_version_state",
    "event_version",
    "provider_guid",
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
    "app_path_attribution",
    "service",
    "direction_raw",
    "direction_value",
    "direction",
    "direction_basis",
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
    "source_address",
    "dest_address",
    "source_port_raw",
    "dest_port_raw",
    "source_port",
    "dest_port",
    "endpoint_attribution",
    "filter_run_time_id_raw",
    "filter_run_time_id",
    "layer_name_raw",
    "layer_run_time_id_raw",
    "layer_run_time_id",
    "payload_process_id_raw",
    "payload_process_id",
    "remote_user_sid",
    "remote_machine_sid",
    "processing_error_code_raw",
    "processing_error_code",
    "processing_error_item",
    "processing_error_payload",
    "setting_value_encoding",
    "ipsec_mode",
    "local_principal",
    "remote_principal",
    "keying_module",
    "main_mode_sa_id",
    "quick_mode_sa_id",
    "failure_point",
    "failure_reason",
    "negotiation_state",
    "ether_type_raw",
    "vlan_tag_raw",
    "media_type",
    "interface_type",
    "vswitch_id",
    "source_vswitch_port",
    "dest_vswitch_port",
    "dos_type",
    "packets_discarded",
    "policy_object_kind",
    "policy_object_id",
    "policy_object_name",
    "pastore_policy",
    "quick_mode_filter",
    "rule_attribute",
    "rejection_reason",
    "active_profile",
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

const IPSEC_DETAILS: &[&str] = &[
    "record_id",
    "ordinal",
    "local_cert_thumbprint",
    "local_cert_issuing_ca",
    "local_cert_root_ca",
    "remote_cert_thumbprint",
    "remote_cert_issuing_ca",
    "remote_cert_root_ca",
    "main_mode_auth_method",
    "extended_mode_auth_method",
    "cipher_algorithm",
    "integrity_algorithm",
    "dh_group",
    "main_mode_lifetime_minutes",
    "quick_mode_limit",
    "sa_role",
    "main_mode_impersonation_state",
    "extended_mode_impersonation_state",
    "main_mode_filter_id",
    "quick_mode_filter_id",
    "transport_filter_id",
    "inbound_spi",
    "outbound_spi",
    "driver_spi",
    "tunnel_id",
    "traffic_selector_id",
    "local_tunnel_endpoint",
    "remote_tunnel_endpoint",
    "peer_private_address",
    "local_address_mask",
    "remote_address_mask",
    "ah_auth_type",
    "esp_auth_type",
    "cipher_type",
    "quick_mode_sa_mode",
    "quick_mode_lifetime_seconds",
    "quick_mode_lifetime_kilobytes",
    "quick_mode_lifetime_packets",
    "initiator_cookie",
    "responder_cookie",
];

const FILTER_CHANGES: &[&str] = &[
    "record_id",
    "ordinal",
    "object_kind",
    "object_key",
    "object_name",
    "object_type",
    "object_id",
    "change_type",
    "weight",
    "conditions",
    "action",
    "provider_key",
    "provider_name",
    "callout_key",
    "callout_name",
    "layer_key",
    "layer_id",
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
    "ipsec_event_count",
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
        ChildSpec { table: "FirewallIpsecDetails", columns: IPSEC_DETAILS },
        ChildSpec { table: "FirewallFilterChanges", columns: FILTER_CHANGES },
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
    const CS_STEM: &str =
        "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity";
    const FW_PROVIDER_GUID: &str = "d1bc9aff-2abf-4d71-9146-ecb2a986eb85";

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

    fn cs(n: usize, eid: &str, ts: &str, payload: &str) -> Row {
        let mut row = event(CS_STEM, FW_PROVIDER, n, eid, ts, payload, "S-1-5-19");
        row.insert(
            "Channel".to_string(),
            format!("{FW_PROVIDER}/ConnectionSecurity"),
        );
        row
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

    // A03/A04/A05/A08: documented audit events are labeled; a connection
    // audit is kept as its own family instead of being dropped, and the
    // observation scope still counts it separately.
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

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 4);
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5156"),
            Some("connection_audit".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5024"),
            Some("service_lifecycle_audit".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=4946"),
            Some("rule_policy_audit".into())
        );
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
        assert_eq!(scope, ("unknown".into(), Some(4), Some(4), Some(1), "unknown".into()));
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

    // A05: Windows Filtering Platform connection audits are stored as their
    // own evidence family with typed packet endpoints — never as rule events,
    // and never as proof that data was transferred.
    #[test]
    fn wfp_connection_audits_are_a_separate_typed_family() {
        let fx = Fixture::new("wfp");
        fx.facts("Security", 5);
        let conn = fx.run(vec![
            sec(1, "5156", "2026-01-01 00:00:01.000", r#"{"ProcessID":"4556","Application":"\\device\\harddiskvolume2\\documents\\listener.exe","Direction":"%%14592","SourceAddress":"10.0.0.10","SourcePort":"3333","DestAddress":"10.0.0.100","DestPort":"49278","Protocol":6,"FilterRTID":70201,"LayerName":"%%14610","LayerRTID":44,"RemoteUserID":"S-1-0-0","RemoteMachineID":"S-1-0-0"}"#),
            sec(2, "5157", "2026-01-01 00:00:02.000", r#"{"ProcessID":"0","Application":"System","Direction":"%%14593","SourceAddress":"fe80::1","SourcePort":"0","DestAddress":"ff02::16","DestPort":"0","Protocol":58,"FilterRTID":0,"LayerName":"%%14611","LayerRTID":48}"#),
            sec(3, "5152", "2026-01-01 00:00:03.000", r#"{"ProcessId":"4","Application":"System","Direction":"%%14592","SourceAddress":"10.0.0.9","SourcePort":"137","DestAddress":"10.0.0.255","DestPort":"137","Protocol":17,"FilterRTID":66,"LayerName":"%%14597","LayerRTID":13}"#),
            sec(4, "5154", "2026-01-01 00:00:04.000", r#"{"ProcessId":"900","Application":"\\device\\harddiskvolume3\\windows\\system32\\svchost.exe","SourceAddress":"0.0.0.0","SourcePort":"135","Protocol":6,"FilterRTID":69,"LayerName":"%%14608","LayerRTID":36}"#),
            sec(5, "5158", "2026-01-01 00:00:05.000", r#"{"ProcessId":"900","Application":"\\device\\harddiskvolume3\\windows\\system32\\svchost.exe","SourceAddress":"0.0.0.0","SourcePort":"49664","Protocol":6,"FilterRTID":69,"LayerName":"%%14608","LayerRTID":36}"#),
        ]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 5);
        let allowed = "SELECT %s FROM FirewallHistory WHERE event_id=5156";
        assert_eq!(
            text(&conn, &allowed.replace("%s", "event_type")),
            Some("연결 허용 (WFP)".into())
        );
        assert_eq!(
            text(&conn, &allowed.replace("%s", "event_definition_state")),
            Some("confirmed_documented".into())
        );
        assert_eq!(
            text(&conn, &allowed.replace("%s", "event_scope")),
            Some("connection_audit".into())
        );
        assert_eq!(
            text(&conn, &allowed.replace("%s", "audit_subcategory")),
            Some("Audit Filtering Platform Connection".into())
        );
        assert_eq!(
            text(&conn, &allowed.replace("%s", "field_schema_basis")),
            Some("provider_manifest_security_auditing".into())
        );
        // An allowed-connection audit must never be worded as a transfer or
        // as a completed/successful session.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallHistory WHERE event_scope IN ('connection_audit','packet_drop_audit','listen_bind_audit')
                 AND (ifnull(description,'') LIKE '%전송%' OR ifnull(description,'') LIKE '%성공%'
                      OR ifnull(event_type,'') LIKE '%전송%')"
            ),
            0
        );
        // Packet endpoints are their own columns: they are not rule addresses
        // and not local/remote attribution.
        assert_eq!(text(&conn, &allowed.replace("%s", "source_address")), Some("10.0.0.10".into()));
        assert_eq!(number(&conn, &allowed.replace("%s", "source_port")), Some(3333));
        assert_eq!(text(&conn, &allowed.replace("%s", "dest_address")), Some("10.0.0.100".into()));
        assert_eq!(number(&conn, &allowed.replace("%s", "dest_port")), Some(49278));
        assert_eq!(
            text(&conn, &allowed.replace("%s", "endpoint_attribution")),
            Some("observed_packet_endpoint".into())
        );
        assert_eq!(text(&conn, &allowed.replace("%s", "local_address")), None);
        assert_eq!(text(&conn, &allowed.replace("%s", "remote_address")), None);
        assert_eq!(text(&conn, &allowed.replace("%s", "address_attribution")), None);
        assert_eq!(text(&conn, &allowed.replace("%s", "rule_id")), None);
        assert_eq!(number(&conn, &allowed.replace("%s", "protocol_number")), Some(6));
        assert_eq!(text(&conn, &allowed.replace("%s", "protocol")), Some("TCP".into()));
        // The WFP process id is the audited process, not the logging service.
        assert_eq!(number(&conn, &allowed.replace("%s", "payload_process_id")), Some(4556));
        assert_eq!(text(&conn, &allowed.replace("%s", "process_id")), Some("4".into()));
        assert_eq!(number(&conn, &allowed.replace("%s", "filter_run_time_id")), Some(70201));
        assert_eq!(number(&conn, &allowed.replace("%s", "layer_run_time_id")), Some(44));
        assert_eq!(text(&conn, &allowed.replace("%s", "layer_name_raw")), Some("%%14610".into()));
        // The %% constants live in msobjs.dll; without it they stay unresolved.
        assert_eq!(text(&conn, &allowed.replace("%s", "direction_raw")), Some("%%14592".into()));
        assert_eq!(number(&conn, &allowed.replace("%s", "direction_value")), None);
        assert_eq!(text(&conn, &allowed.replace("%s", "direction")), None);
        assert_eq!(
            text(&conn, &allowed.replace("%s", "direction_basis")),
            Some("audit_message_constant_unresolved".into())
        );
        // A remote identity is never the acting account of the record.
        assert_eq!(text(&conn, &allowed.replace("%s", "remote_user_sid")), Some("S-1-0-0".into()));
        assert_eq!(text(&conn, &allowed.replace("%s", "remote_machine_sid")), Some("S-1-0-0".into()));
        assert_eq!(text(&conn, &allowed.replace("%s", "account_sid")), None);
        assert_eq!(text(&conn, &allowed.replace("%s", "account_role")), None);

        let endpoints: Vec<(String, String, String)> = conn
            .prepare(
                "SELECT role, entry_raw, attribution FROM FirewallAddresses a
                 JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5156 ORDER BY a.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            endpoints,
            vec![
                ("source".into(), "10.0.0.10".into(), "observed_packet_endpoint".into()),
                ("destination".into(), "10.0.0.100".into(), "observed_packet_endpoint".into()),
            ]
        );
        let ports: Vec<(String, Option<i64>, String)> = conn
            .prepare(
                "SELECT role, port_start, attribution FROM FirewallPorts p
                 JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5156 ORDER BY p.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            ports,
            vec![
                ("source".into(), Some(3333), "observed_packet_endpoint".into()),
                ("destination".into(), Some(49278), "observed_packet_endpoint".into()),
            ]
        );
        let app: (String, String, String) = conn
            .query_row(
                "SELECT role, path_raw, path_kind FROM FirewallAppPaths a
                 JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5156",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            app,
            (
                "connection_app".into(),
                "\\device\\harddiskvolume2\\documents\\listener.exe".into(),
                "device".into()
            )
        );
        assert_eq!(
            text(&conn, &allowed.replace("%s", "app_path_attribution")),
            Some("observed_connection_process".into())
        );

        // The remaining families are separable by one column.
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5152"),
            Some("packet_drop_audit".into())
        );
        assert_eq!(
            text(&conn, "SELECT audit_subcategory FROM FirewallHistory WHERE event_id=5152"),
            Some("Audit Filtering Platform Packet Drop".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5154"),
            Some("listen_bind_audit".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5158"),
            Some("listen_bind_audit".into())
        );
        // A listen/bind audit records one endpoint only: no destination.
        assert_eq!(
            text(&conn, "SELECT dest_address FROM FirewallHistory WHERE event_id=5154"),
            None
        );
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallObservations WHERE log_name='Security' AND connection_audit_event_count=5"),
            1
        );
    }

    // A05: IPsec audits are typed from the Microsoft-Windows-Security-
    // Auditing manifest templates — main/extended/quick mode endpoints,
    // principals, certificates, algorithms, lifetimes, filter/SA ids and
    // SPIs — while every recorded name still survives verbatim.
    #[test]
    fn ipsec_audits_are_typed_from_the_security_auditing_manifest() {
        let fx = Fixture::new("ipsec");
        fx.facts("Security", 5);
        let conn = fx.run(vec![
            sec(1, "4651", "2026-01-01 00:00:01.000", r#"{"LocalMMPrincipalName":"WIN$","LocalMMCertHash":"AA11","LocalMMIssuingCA":"CN=Issuer","LocalMMRootCA":"CN=Root","RemoteMMPrincipalName":"PEER$","RemoteMMCertHash":"BB22","RemoteMMIssuingCA":"CN=Issuer2","RemoteMMRootCA":"CN=Root2","LocalAddress":"10.0.0.5","LocalKeyModPort":500,"RemoteAddress":"10.0.0.9","RemoteKeyModPort":500,"KeyModName":"IKEv1","MMAuthMethod":"Certificate","MMCipherAlg":"AES-CBC 256","MMIntegrityAlg":"SHA-256","DHGroup":"DH Group 14","MMLifetime":480,"QMLimit":0,"Role":"Initiator","MMImpersonationState":"Not enabled","MMFilterID":66,"MMSAID":12}"#),
            sec(2, "5451", "2026-01-01 00:00:02.000", r#"{"LocalAddress":"10.0.0.5","LocalAddressMask":"255.255.255.255","LocalPort":445,"LocalTunnelEndpoint":"-","RemoteAddress":"10.0.0.9","RemoteAddressMask":"255.255.255.255","RemotePort":0,"PeerPrivateAddress":"-","RemoteTunnelEndpoint":"-","IpProtocol":6,"KeyingModuleName":"IKEv1","AhAuthType":"None","EspAuthType":"SHA-256","CipherType":"AES-GCM 128","LifetimeSeconds":3600,"LifetimeKilobytes":100000,"LifetimePackets":0,"Mode":"Transport","Role":"Initiator","TransportFilterId":77,"MainModeSaId":12,"QuickModeSaId":44,"InboundSpi":1111,"OutboundSpi":2222,"TunnelId":0,"TrafficSelectorId":0}"#),
            sec(3, "4652", "2026-01-01 00:00:03.000", r#"{"LocalAddress":"10.0.0.5","RemoteAddress":"10.0.0.9","KeyModName":"AuthIP","FailurePoint":"Local computer","FailureReason":"No policy configured","State":"Sent first (SA) payload","Role":"Initiator","InitiatorCookie":"01","ResponderCookie":"02"}"#),
            sec(4, "4960", "2026-01-01 00:00:04.000", r#"{"RemoteAddress":"10.0.0.9","SPI":4919}"#),
            sec(5, "5043", "2026-01-01 00:00:05.000", r#"{"ProfileChanged":"Domain","ConnectionSecurityRuleId":"{CS}","ConnectionSecurityRuleName":"csrule","SubjectUserSid":"S-1-5-21-1-2-3-500"}"#),
        ]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 5);
        for (event_id, scope, subcategory) in [
            (4651, "ipsec_main_mode", "Audit IPsec Main Mode"),
            (5451, "ipsec_quick_mode", "Audit IPsec Quick Mode"),
            (4652, "ipsec_main_mode", "Audit IPsec Main Mode"),
            (4960, "ipsec_driver", "Audit IPsec Driver"),
            (5043, "ipsec_policy_change", "Audit Filtering Platform Policy Change"),
        ] {
            assert_eq!(
                text(&conn, &format!("SELECT event_scope FROM FirewallHistory WHERE event_id={event_id}")),
                Some(scope.into()),
                "scope of {event_id}"
            );
            assert_eq!(
                text(&conn, &format!("SELECT audit_subcategory FROM FirewallHistory WHERE event_id={event_id}")),
                Some(subcategory.into()),
                "subcategory of {event_id}"
            );
            assert_eq!(
                text(&conn, &format!("SELECT event_definition_state FROM FirewallHistory WHERE event_id={event_id}")),
                Some("confirmed_documented".into()),
                "state of {event_id}"
            );
            assert_eq!(
                text(&conn, &format!("SELECT field_schema_basis FROM FirewallHistory WHERE event_id={event_id}")),
                Some("provider_manifest_security_auditing".into()),
                "schema basis of {event_id}"
            );
        }
        assert_eq!(
            text(&conn, "SELECT event_type FROM FirewallHistory WHERE event_id=5043"),
            Some("연결 보안 규칙 추가".into())
        );

        // Main mode: endpoints are the security association's own, never a
        // rule address and never a packet endpoint.
        let main = "SELECT %s FROM FirewallHistory WHERE event_id=4651";
        assert_eq!(text(&conn, &main.replace("%s", "ipsec_mode")), Some("main_mode".into()));
        assert_eq!(text(&conn, &main.replace("%s", "local_address")), Some("10.0.0.5".into()));
        assert_eq!(text(&conn, &main.replace("%s", "remote_address")), Some("10.0.0.9".into()));
        assert_eq!(
            text(&conn, &main.replace("%s", "address_attribution")),
            Some("observed_security_association".into())
        );
        assert_eq!(text(&conn, &main.replace("%s", "source_address")), None);
        assert_eq!(text(&conn, &main.replace("%s", "local_addresses")), None);
        assert_eq!(number(&conn, &main.replace("%s", "local_port")), Some(500));
        assert_eq!(
            text(&conn, &main.replace("%s", "single_port_basis")),
            Some("LocalKeyModPort".into())
        );
        assert_eq!(text(&conn, &main.replace("%s", "keying_module")), Some("IKEv1".into()));
        assert_eq!(text(&conn, &main.replace("%s", "local_principal")), Some("WIN$".into()));
        assert_eq!(text(&conn, &main.replace("%s", "remote_principal")), Some("PEER$".into()));
        assert_eq!(number(&conn, &main.replace("%s", "main_mode_sa_id")), Some(12));
        let certs: (Option<String>, Option<String>, Option<String>, Option<String>, Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT local_cert_thumbprint, remote_cert_thumbprint, cipher_algorithm, dh_group,
                        main_mode_lifetime_minutes, main_mode_filter_id
                 FROM FirewallIpsecDetails d JOIN FirewallHistory h USING(record_id) WHERE h.event_id=4651",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(
            certs,
            (
                Some("AA11".into()),
                Some("BB22".into()),
                Some("AES-CBC 256".into()),
                Some("DH Group 14".into()),
                Some(480),
                Some(66)
            )
        );

        // Quick mode: lifetimes, SPIs and the negotiated transforms.
        let quick = "SELECT %s FROM FirewallHistory WHERE event_id=5451";
        assert_eq!(text(&conn, &quick.replace("%s", "ipsec_mode")), Some("quick_mode".into()));
        assert_eq!(number(&conn, &quick.replace("%s", "quick_mode_sa_id")), Some(44));
        assert_eq!(number(&conn, &quick.replace("%s", "main_mode_sa_id")), Some(12));
        assert_eq!(number(&conn, &quick.replace("%s", "protocol_number")), Some(6));
        assert_eq!(text(&conn, &quick.replace("%s", "protocol")), Some("TCP".into()));
        assert_eq!(number(&conn, &quick.replace("%s", "local_port")), Some(445));
        assert_eq!(
            text(&conn, &quick.replace("%s", "field_schema_version_state")),
            Some("event_version_unrecorded".into())
        );
        assert_eq!(number(&conn, &quick.replace("%s", "field_schema_version")), Some(1));
        let quick_sa: (Option<i64>, Option<i64>, Option<i64>, Option<i64>, Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT quick_mode_lifetime_seconds, quick_mode_lifetime_kilobytes, inbound_spi, outbound_spi,
                        esp_auth_type, cipher_type, quick_mode_sa_mode
                 FROM FirewallIpsecDetails d JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5451",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(
            quick_sa,
            (
                Some(3600),
                Some(100000),
                Some(1111),
                Some(2222),
                Some("SHA-256".into()),
                Some("AES-GCM 128".into()),
                Some("Transport".into())
            )
        );

        // A failed negotiation keeps the failure point/reason and cookies.
        let failed = "SELECT %s FROM FirewallHistory WHERE event_id=4652";
        assert_eq!(
            text(&conn, &failed.replace("%s", "failure_point")),
            Some("Local computer".into())
        );
        assert_eq!(
            text(&conn, &failed.replace("%s", "failure_reason")),
            Some("No policy configured".into())
        );
        assert_eq!(
            text(&conn, &failed.replace("%s", "negotiation_state")),
            Some("Sent first (SA) payload".into())
        );
        assert_eq!(
            text(
                &conn,
                "SELECT initiator_cookie FROM FirewallIpsecDetails d JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=4652"
            ),
            Some("01".into())
        );
        // A failure audit is never described as a success.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallHistory WHERE event_id IN (4652,4983,4984)
                 AND ifnull(description,'') LIKE '%성공%'"
            ),
            0
        );

        // The driver SPI is the driver's, not a quick mode SPI.
        assert_eq!(text(&conn, "SELECT ipsec_mode FROM FirewallHistory WHERE event_id=4960"), Some("driver".into()));
        let driver: (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT driver_spi, inbound_spi FROM FirewallIpsecDetails d
                 JOIN FirewallHistory h USING(record_id) WHERE h.event_id=4960",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(driver, (Some(4919), None));

        // A policy object event names the object, and does not pretend to be
        // a firewall rule definition.
        let policy = "SELECT %s FROM FirewallHistory WHERE event_id=5043";
        assert_eq!(
            text(&conn, &policy.replace("%s", "policy_object_kind")),
            Some("connection_security_rule".into())
        );
        assert_eq!(text(&conn, &policy.replace("%s", "policy_object_id")), Some("{CS}".into()));
        assert_eq!(
            text(&conn, &policy.replace("%s", "policy_object_name")),
            Some("csrule".into())
        );
        assert_eq!(text(&conn, &policy.replace("%s", "profiles_raw")), Some("Domain".into()));
        assert_eq!(number(&conn, &policy.replace("%s", "profiles_mask")), None);
        assert_eq!(text(&conn, &policy.replace("%s", "rule_id")), None);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallRuleChanges"), 0);
        assert_eq!(text(&conn, &policy.replace("%s", "ipsec_mode")), None);
        // A connection security rule event keeps its audit subject.
        assert_eq!(
            text(&conn, &policy.replace("%s", "account_sid")),
            Some("S-1-5-21-1-2-3-500".into())
        );
        // Nothing is dropped: the recorded names still exist verbatim.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=4651"
            ),
            23
        );
        assert_eq!(
            number(&conn, "SELECT ipsec_event_count FROM FirewallObservations WHERE log_name='Security'"),
            Some(5)
        );
    }

    // The ConnectionSecurity channel is its own family: collected-but-empty is
    // not "no events", and a same-named rule id never chains across channels.
    #[test]
    fn connection_security_channel_is_kept_as_its_own_family() {
        let fx = Fixture::new("connsec");
        fx.facts(FW_STEM, 2);
        fx.facts(CS_STEM, 2);
        let conn = fx.run(vec![
            fw(1, "2097", "2026-01-01 00:00:01.000", RULE_A),
            fw(2, "2097", "2026-01-01 00:00:02.000", RULE_A2),
            cs(1, "2035", "2026-01-01 00:00:03.000", r#"{"RuleId":"{A}","RuleName":"HelpUServer","Direction":1,"Protocol":6,"LocalPorts":"2500","Action":3,"Profiles":4,"ModifyingUser":"S-1-5-18"}"#),
            cs(2, "2036", "2026-01-01 00:00:04.000", r#"{"RuleId":"{A}","Endpoint1":"10.0.0.5","Endpoint2":"10.0.0.9","AuthenticationSet":"{AUTH}"}"#),
        ]);

        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 4);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE event_family='connection_security_channel'"),
            2
        );
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=2035"),
            Some("connection_security_channel".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_definition_state FROM FirewallHistory WHERE event_id=2035"),
            Some("unconfirmed".into())
        );
        assert_eq!(
            text(&conn, "SELECT event_family FROM FirewallHistory WHERE event_id=2097 LIMIT 1"),
            Some("firewall_channel".into())
        );
        // Unknown fields of an unknown connection security event survive.
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=2036 AND f.field_name IN ('Endpoint1','Endpoint2','AuthenticationSet')"
            ),
            3
        );
        // The rule difference chain stays inside one channel.
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallRuleChanges"), 1);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM FirewallRuleChanges c JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_family='connection_security_channel'"
            ),
            0
        );
        // Both channels are reported as collected scope, separately.
        assert_eq!(
            count(&conn, &format!("SELECT COUNT(*) FROM FirewallObservations WHERE log_name='{CS_STEM}'")),
            1
        );
    }

    // An event whose payload could not be decoded by the provider is evidence:
    // the error node is preserved, and it is never read as a rule payload.
    #[test]
    fn processing_error_payload_is_preserved_without_being_interpreted() {
        let fx = Fixture::new("procerr");
        fx.facts(FW_STEM, 1);
        let conn = fx.run(vec![fw(
            1,
            "2011",
            "2026-01-01 00:00:01.000",
            r#"{"ProcessingErrorData": {"ErrorCode": 13, "DataItemName": "ModifyingUser", "EventPayload": "QAAAAEMAOgBc"}}"#,
        )]);

        let row = "SELECT %s FROM FirewallHistory WHERE event_id=2011";
        assert_eq!(text(&conn, &row.replace("%s", "payload_state")), Some("processing_error".into()));
        assert_eq!(text(&conn, &row.replace("%s", "payload_family")), Some("processing_error".into()));
        assert_eq!(number(&conn, &row.replace("%s", "processing_error_code")), Some(13));
        assert_eq!(
            text(&conn, &row.replace("%s", "processing_error_item")),
            Some("ModifyingUser".into())
        );
        assert_eq!(
            text(&conn, &row.replace("%s", "processing_error_payload")),
            Some("QAAAAEMAOgBc".into())
        );
        // The failed item name must not become a modifying user, and the
        // undecoded payload must not become an application path.
        assert_eq!(text(&conn, &row.replace("%s", "modifying_user_raw")), None);
        assert_eq!(text(&conn, &row.replace("%s", "account_sid")), None);
        assert_eq!(text(&conn, &row.replace("%s", "app_path")), None);
        assert_eq!(text(&conn, &row.replace("%s", "app_path_state")), Some("absent".into()));
        // Preservation keeps the error node path explicit.
        let fields: Vec<(String, String)> = conn
            .prepare("SELECT field_name, field_path FROM FirewallEventFields ORDER BY ordinal")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            fields,
            vec![
                ("ErrorCode".into(), "ProcessingErrorData.ErrorCode".into()),
                ("DataItemName".into(), "ProcessingErrorData.DataItemName".into()),
                ("EventPayload".into(), "ProcessingErrorData.EventPayload".into()),
            ]
        );
    }

    // A Security audit id that belongs to no documented firewall subcategory
    // is still kept, but nothing about it is labeled.
    #[test]
    fn undocumented_filtering_platform_ids_are_kept_as_unknown() {
        let fx = Fixture::new("unknownaudit");
        fx.facts("Security", 3);
        let conn = fx.run(vec![
            sec(1, "5146", "2026-01-01 00:00:01.000", r#"{"FilterRTID":1,"LayerName":"%%14595","LayerRTID":10}"#),
            sec(2, "4624", "2026-01-01 00:00:02.000", r#"{"TargetUserName":"alice"}"#),
            sec(3, "5156", "2026-01-01 00:00:03.000", r#"{"ProcessID":"1","Application":"x","Protocol":6}"#),
        ]);
        // 5146 has no Microsoft subcategory page: kept, but unlabeled.
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory"), 2);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM FirewallHistory WHERE event_id=4624"), 0);
        let unknown = "SELECT %s FROM FirewallHistory WHERE event_id=5146";
        assert_eq!(text(&conn, &unknown.replace("%s", "event_type")), Some("방화벽 이벤트 5146".into()));
        assert_eq!(
            text(&conn, &unknown.replace("%s", "event_definition_state")),
            Some("unconfirmed".into())
        );
        assert_eq!(text(&conn, &unknown.replace("%s", "event_scope")), Some("unknown".into()));
        assert_eq!(text(&conn, &unknown.replace("%s", "audit_subcategory")), None);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM FirewallEventFields f JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5146"),
            3
        );
    }

    // The new channels report their own collection scope, and the schema
    // discriminators of the manifest are preserved when facts carry them.
    #[test]
    fn new_channels_and_schema_discriminators_are_recorded() {
        let fx = Fixture::new("scope");
        fx.facts(FW_STEM, 1);
        let mut row = fw(1, "2097", "2026-01-01 00:00:01.000", RULE_A);
        row.insert("Version".into(), "1".into());
        row.insert("ProviderGuid".into(), FW_PROVIDER_GUID.into());
        let conn = fx.run(vec![row]);

        assert_eq!(number(&conn, "SELECT event_version FROM FirewallHistory"), Some(1));
        assert_eq!(
            text(&conn, "SELECT provider_guid FROM FirewallHistory"),
            Some(FW_PROVIDER_GUID.into())
        );
        assert_eq!(
            text(&conn, "SELECT field_schema_basis FROM FirewallHistory"),
            Some("provider_manifest_mpssvc".into())
        );
        // The manifest read for this parser declares version 0, so a record
        // that says otherwise is flagged instead of silently trusted.
        assert_eq!(number(&conn, "SELECT field_schema_version FROM FirewallHistory"), Some(0));
        assert_eq!(
            text(&conn, "SELECT field_schema_version_state FROM FirewallHistory"),
            Some("event_version_differs".into())
        );
        assert_eq!(
            text(&conn, "SELECT field_schema_source FROM FirewallHistory"),
            Some("mpssvc.dll 10.0.26100.9549 WEVT_TEMPLATE".into())
        );
        // Every supported log is accounted for, and a log that was never
        // collected is not reported as zero events.
        for log in [CS_STEM, "Microsoft-Windows-WFP%4Operational", "Microsoft-Windows-IKE%4Operational", "Security"] {
            assert_eq!(
                text(&conn, &format!("SELECT collection_state FROM FirewallObservations WHERE log_name='{log}'")),
                Some("unknown".into()),
                "state of {log}"
            );
            assert_eq!(
                number(&conn, &format!("SELECT event_count FROM FirewallObservations WHERE log_name='{log}'")),
                None,
                "count of {log}"
            );
        }
    }

    // R07/A02: the raw setting bytes keep their recorded notation and the
    // notation is only named when the recorded size proves it.
    #[test]
    fn setting_value_encoding_is_named_only_when_the_size_proves_it() {
        let fx = Fixture::new("encoding");
        fx.facts(FW_STEM, 2);
        let conn = fx.run(vec![
            fw(1, "2082", "2026-01-01 00:00:01.000", r#"{"Profiles":4,"SettingType":3,"SettingValueSize":4,"SettingValue":"00000000","SettingValueString":"아니요"}"#),
            fw(2, "2082", "2026-01-01 00:00:02.000", r#"{"Profiles":4,"SettingType":3,"SettingValueSize":8,"SettingValue":"00000000","SettingValueString":"아니요"}"#),
        ]);
        assert_eq!(
            text(&conn, "SELECT setting_value_encoding FROM FirewallHistory WHERE setting_value_size=4"),
            Some("hex_bytes".into())
        );
        assert_eq!(
            text(&conn, "SELECT setting_value_raw FROM FirewallHistory WHERE setting_value_size=4"),
            Some("00000000".into())
        );
        assert_eq!(
            text(&conn, "SELECT setting_value_encoding FROM FirewallHistory WHERE setting_value_size=8"),
            Some("unknown".into())
        );
    }

    // A filtering-platform object change is typed from the manifest, and the
    // filter's own `Action` is never read as a firewall rule action.
    #[test]
    fn wfp_object_changes_and_layer2_packets_are_typed_from_the_manifest() {
        let fx = Fixture::new("wfpobject");
        fx.facts("Security", 3);
        let conn = fx.run(vec![
            sec(1, "5447", "2026-01-01 00:00:01.000", r#"{"ProcessId":4,"UserSid":"S-1-5-18","UserName":"SYSTEM","ProviderKey":"{P}","ProviderName":"MS Firewall","ChangeType":"%%16386","FilterKey":"{F}","FilterName":"Allow 445","FilterType":"%%16400","FilterId":70201,"LayerKey":"{L}","LayerName":"%%14610","LayerId":44,"Weight":9,"Conditions":"2","Action":"%%16393","CalloutKey":"{C}","CalloutName":"cal"}"#),
            sec(2, "5146", "2026-01-01 00:00:02.000", r#"{"Direction":"%%14592","SourceAddress":"00-11-22-33-44-55","DestAddress":"66-77-88-99-AA-BB","EtherType":"0x800","VlanTag":"0x0","vSwitchID":"{V}","SourcevSwitchPort":3,"DestinationvSwitchPort":4,"FilterRTID":66,"LayerName":"%%14595","LayerRTID":13}"#),
            sec(3, "5149", "2026-01-01 00:00:03.000", r#"{"Type":"%%14608","PacketsDiscarded":120}"#),
        ]);

        // 5447: the object is named by its own key/name/type/id.
        let object: (String, Option<String>, Option<String>, Option<i64>, Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT object_kind, object_key, object_name, object_id, change_type, weight, c.action
                 FROM FirewallFilterChanges c JOIN FirewallHistory h USING(record_id) WHERE h.event_id=5447",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(
            object,
            (
                "filter".into(),
                Some("{F}".into()),
                Some("Allow 445".into()),
                Some(70201),
                Some("%%16386".into()),
                Some(9),
                Some("%%16393".into())
            )
        );
        let wfp = "SELECT %s FROM FirewallHistory WHERE event_id=5447";
        // The filter action is not a FW_RULE_ACTION value.
        assert_eq!(text(&conn, &wfp.replace("%s", "action")), None);
        assert_eq!(text(&conn, &wfp.replace("%s", "action_raw")), None);
        assert_eq!(number(&conn, &wfp.replace("%s", "payload_process_id")), Some(4));
        assert_eq!(text(&conn, &wfp.replace("%s", "layer_name_raw")), Some("%%14610".into()));
        // UserSid is the operator of a policy change, so it is the account.
        assert_eq!(text(&conn, &wfp.replace("%s", "account_sid")), Some("S-1-5-18".into()));
        assert_eq!(text(&conn, &wfp.replace("%s", "account_basis")), Some("UserSid".into()));
        assert_eq!(
            text(&conn, &wfp.replace("%s", "event_scope")),
            Some("filtering_platform_policy_change".into())
        );
        assert_eq!(
            text(&conn, &wfp.replace("%s", "audit_subcategory")),
            Some("Audit Other Policy Change Events".into())
        );

        // 5146 has no Microsoft page, but the manifest names its fields: the
        // frame context is typed while the meaning stays unconfirmed.
        let frame = "SELECT %s FROM FirewallHistory WHERE event_id=5146";
        assert_eq!(
            text(&conn, &frame.replace("%s", "event_definition_state")),
            Some("unconfirmed".into())
        );
        assert_eq!(text(&conn, &frame.replace("%s", "event_scope")), Some("unknown".into()));
        assert_eq!(
            text(&conn, &frame.replace("%s", "field_schema_basis")),
            Some("provider_manifest_security_auditing".into())
        );
        assert_eq!(text(&conn, &frame.replace("%s", "ether_type_raw")), Some("0x800".into()));
        assert_eq!(text(&conn, &frame.replace("%s", "vswitch_id")), Some("{V}".into()));
        assert_eq!(number(&conn, &frame.replace("%s", "source_vswitch_port")), Some(3));
        assert_eq!(number(&conn, &frame.replace("%s", "dest_vswitch_port")), Some(4));
        assert_eq!(number(&conn, &frame.replace("%s", "filter_run_time_id")), Some(66));
        assert_eq!(
            text(&conn, &frame.replace("%s", "endpoint_attribution")),
            Some("observed_packet_endpoint".into())
        );
        // A MAC endpoint is not forced into an IP address kind.
        assert_eq!(
            text(
                &conn,
                "SELECT entry_kind FROM FirewallAddresses a JOIN FirewallHistory h USING(record_id)
                 WHERE h.event_id=5146 AND a.role='source'"
            ),
            Some("keyword".into())
        );

        // 5149 keeps the discarded packet count as a number.
        assert_eq!(
            text(&conn, "SELECT event_scope FROM FirewallHistory WHERE event_id=5149"),
            Some("dos_mitigation_audit".into())
        );
        assert_eq!(
            number(&conn, "SELECT packets_discarded FROM FirewallHistory WHERE event_id=5149"),
            Some(120)
        );
        assert_eq!(
            text(&conn, "SELECT dos_type FROM FirewallHistory WHERE event_id=5149"),
            Some("%%14608".into())
        );
        // The DoS `Type` field is not a firewall setting type.
        assert_eq!(
            text(&conn, "SELECT setting_type_raw FROM FirewallHistory WHERE event_id=5149"),
            None
        );
    }
}
