//! Typed Microsoft Defender storage: one row per attributed evidence record.
//! Events are never merged into a synthetic detection, results come from the
//! event's own evidence, and unknown values stay NULL (뷰어13 R01~R20·A01~A08).
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::Result;
use serde_json::{Map, Value};

use super::defender_protection as protection;
use super::defender_protection::Observation;
use super::defender_support as support;
use super::eventlog_inputs::LogInputs;
use super::schema::{ChildSpec, DbSpec};
use super::{Cell, Ctx, DerivedDb, Record, SourceRef};
use crate::overview::EventLogOverviewCache;
use crate::sqlite::Row;

/// Only this provider's events are Defender evidence; a file name is not.
const PROVIDER: &str = "Microsoft-Windows-Windows Defender";
/// Provider GUID from the registered manifest; corroboration for the name.
const PROVIDER_GUID: &str = "11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78";
const TIME_KIND_EVENT: &str = "이벤트 기록 시각";
const TIME_KIND_DETECTION: &str = "탐지 기록 시각";
const SOURCE_EVENTLOG: &str = "EventLog";
const SOURCE_MPDETECTION: &str = "MPDetection";
const SOURCE_LABEL_EVENTLOG: &str = "Defender 이벤트 로그";
const SOURCE_LABEL_MPDETECTION: &str = "Defender 탐지 로그(MPDetection)";
/// The two channels the provider manifest declares.
const OPERATIONAL_CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";
const WHC_CHANNEL: &str = "Microsoft-Windows-Windows Defender/WHC";
/// Defender event logs this build knows about, so a log that was never
/// collected is distinguishable from one collected with zero events.
const EXPECTED_LOGS: &[&str] = &[
    "Microsoft-Windows-Windows Defender%4Operational",
    "Microsoft-Windows-Windows Defender%4WHC",
];

/// Documented event semantics. Every mapping is keyed by channel because the
/// manifest declares each event on one channel only: an id seen on the other
/// channel is not the same event (뷰어13 A01).
/// `support_state` says whether the meaning is published, `support_source`
/// says which authority published it, so an unmapped event stays visible
/// instead of being guessed.
struct Kind {
    id: i64,
    section: &'static str,
    event_type: &'static str,
    title: &'static str,
    description: &'static str,
    support_state: &'static str,
    support_source: &'static str,
}

const fn kind(
    id: i64,
    section: &'static str,
    event_type: &'static str,
    title: &'static str,
    description: &'static str,
    support_state: &'static str,
    support_source: &'static str,
) -> Kind {
    Kind { id, section, event_type, title, description, support_state, support_source }
}

const DOC: &str = "documented";
const PAYLOAD_ONLY: &str = "payload_only";
/// Event id, channel and message template taken from the registered provider
/// manifest of `MpEvMsg.dll` (Microsoft-Windows-Windows Defender,
/// {11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}).
const SRC_MANIFEST: &str = "provider_manifest";
/// Microsoft Learn documentation where the manifest dump has no entry.
const SRC_MSDOCS: &str = "microsoft_docs";
/// Field names observed in collected payloads with no published template.
const SRC_PAYLOAD: &str = "observed_payload";

/// Sections of the Operational channel.
const SECTION_THREAT: &str = "threat";
const SECTION_THREAT_ACTION: &str = "threat_action";
const SECTION_SCAN: &str = "scan";
const SECTION_SIGNATURE: &str = "signature";
const SECTION_TAMPERING: &str = "tampering";
const SECTION_HEALTH: &str = "health";
const SECTION_FAILURE: &str = "failure";
const SECTION_HISTORY: &str = "history";
const SECTION_ASR: &str = "asr";
const SECTION_FOLDER_GUARD: &str = "folder_guard";
const SECTION_NETWORK: &str = "network_protection";
const SECTION_DEVICE_CONTROL: &str = "device_control";
/// WHC channel section; the health state value itself stays raw.
const SECTION_WHC_STATE: &str = "whc_state";

const OPERATIONAL_KINDS: &[Kind] = &[
    kind(1000, SECTION_SCAN, "scan_started", "검사 시작", "맬웨어 방지 검사를 시작함", DOC, SRC_MANIFEST),
    kind(1001, SECTION_SCAN, "scan_completed", "검사 완료", "맬웨어 방지 검사를 완료함", DOC, SRC_MANIFEST),
    kind(1002, SECTION_SCAN, "scan_cancelled", "검사 중지", "검사가 완료 전에 중지됨", DOC, SRC_MANIFEST),
    kind(1003, SECTION_SCAN, "scan_paused", "검사 일시 중지", "검사가 일시 중지됨", DOC, SRC_MANIFEST),
    kind(1004, SECTION_SCAN, "scan_resumed", "검사 재개", "일시 중지된 검사가 재개됨", DOC, SRC_MANIFEST),
    kind(1005, SECTION_SCAN, "scan_error", "검사 오류 종료", "검사가 오류를 만나 종료됨", DOC, SRC_MANIFEST),
    kind(1006, SECTION_THREAT, "threat_detected", "위협 탐지", "맬웨어 또는 원치 않는 소프트웨어를 탐지함", DOC, SRC_MANIFEST),
    kind(1007, SECTION_THREAT_ACTION, "threat_action_taken", "조치 수행", "탐지 항목에 조치를 수행함", DOC, SRC_MANIFEST),
    kind(1008, SECTION_THREAT_ACTION, "threat_action_failed", "조치 실패", "탐지 항목 조치가 실패함", DOC, SRC_MANIFEST),
    kind(1009, SECTION_THREAT_ACTION, "quarantine_restored", "격리 복원", "격리에서 항목을 복원함", DOC, SRC_MANIFEST),
    kind(1010, SECTION_THREAT_ACTION, "quarantine_restore_failed", "격리 복원 실패", "격리 항목 복원이 실패함", DOC, SRC_MANIFEST),
    kind(1011, SECTION_THREAT_ACTION, "quarantine_deleted", "격리 삭제", "격리 항목을 삭제함", DOC, SRC_MANIFEST),
    kind(1012, SECTION_THREAT_ACTION, "quarantine_delete_failed", "격리 삭제 실패", "격리 항목 삭제가 실패함", DOC, SRC_MANIFEST),
    kind(1013, SECTION_HISTORY, "history_cleared", "기록 삭제", "맬웨어·검사 기록을 삭제함", DOC, SRC_MANIFEST),
    kind(1014, SECTION_HISTORY, "history_clear_failed", "기록 삭제 실패", "맬웨어·검사 기록 삭제가 실패함", DOC, SRC_MANIFEST),
    kind(1015, SECTION_THREAT, "behavior_detected", "동작 탐지", "의심스러운 동작을 탐지함", DOC, SRC_MANIFEST),
    kind(1116, SECTION_THREAT, "threat_detected", "위협 탐지", "맬웨어 또는 원치 않는 소프트웨어를 탐지함", DOC, SRC_MANIFEST),
    kind(1117, SECTION_THREAT_ACTION, "threat_action_taken", "조치 수행", "탐지 항목에 조치를 수행함", DOC, SRC_MANIFEST),
    kind(1118, SECTION_THREAT_ACTION, "threat_action_failed", "조치 실패", "탐지 항목 조치가 실패함(비치명적)", DOC, SRC_MANIFEST),
    kind(1119, SECTION_THREAT_ACTION, "threat_action_critically_failed", "조치 치명적 실패", "탐지 항목 조치가 치명적 오류로 실패함", DOC, SRC_MANIFEST),
    kind(1120, SECTION_THREAT, "threat_hash_logged", "탐지 해시 기록", "탐지 리소스의 해시를 기록함", DOC, SRC_MANIFEST),
    // ASR·CFA·네트워크 보호는 차단과 감사를 이벤트 자체로 구분한다.
    kind(1121, SECTION_ASR, "asr_rule_blocked", "ASR 규칙 차단", "공격 표면 축소 규칙이 차단 모드로 작업을 차단함", DOC, SRC_MANIFEST),
    kind(1122, SECTION_ASR, "asr_rule_audited", "ASR 규칙 감사", "공격 표면 축소 규칙이 감사 모드로 작업을 기록함(차단 아님)", DOC, SRC_MANIFEST),
    kind(1123, SECTION_FOLDER_GUARD, "cfa_blocked", "폴더 액세스 차단", "제어된 폴더 액세스가 신뢰되지 않은 프로세스의 변경을 차단함", DOC, SRC_MANIFEST),
    kind(1124, SECTION_FOLDER_GUARD, "cfa_audited", "폴더 액세스 감사", "제어된 폴더 액세스가 감사 모드로 변경 시도를 기록함(차단 아님)", DOC, SRC_MANIFEST),
    kind(1125, SECTION_NETWORK, "network_connection_audited", "네트워크 연결 감사", "네트워크 보호가 감사 모드로 연결을 기록함(차단 아님)", DOC, SRC_MANIFEST),
    kind(1126, SECTION_NETWORK, "network_connection_blocked", "네트워크 연결 차단", "네트워크 보호가 위험한 연결을 차단함", DOC, SRC_MANIFEST),
    kind(1127, SECTION_FOLDER_GUARD, "cfa_sector_write_blocked", "디스크 섹터 쓰기 차단", "제어된 폴더 액세스가 신뢰되지 않은 프로세스의 디스크 섹터·메모리 변경을 차단함", DOC, SRC_MANIFEST),
    kind(1128, SECTION_FOLDER_GUARD, "cfa_sector_write_audited", "디스크 섹터 쓰기 감사", "제어된 폴더 액세스가 감사 모드로 디스크 섹터·메모리 변경 시도를 기록함(차단 아님)", DOC, SRC_MANIFEST),
    kind(1129, SECTION_ASR, "asr_rule_warn_overridden", "ASR 경고 재정의", "사용자가 경고 모드의 차단을 재정의함", DOC, SRC_MSDOCS),
    kind(1133, SECTION_DEVICE_CONTROL, "device_control_blocked", "정책 작업 차단", "정책이 허용하지 않는 작업을 차단함", DOC, SRC_MANIFEST),
    kind(1134, SECTION_DEVICE_CONTROL, "device_control_audited", "정책 작업 감사", "정책 작업을 감사 기록함(차단 아님)", DOC, SRC_MANIFEST),
    kind(1150, SECTION_HEALTH, "service_healthy", "서비스 정상", "서비스가 정상 상태로 보고됨", DOC, SRC_MANIFEST),
    kind(1151, SECTION_HEALTH, "health_report", "상태 보고", "클라이언트 상태를 보고함", DOC, SRC_MANIFEST),
    kind(1160, SECTION_THREAT, "pua_detected", "PUA 탐지", "원치 않는 응용 프로그램(PUA)을 탐지함", DOC, SRC_MANIFEST),
    kind(2000, SECTION_SIGNATURE, "signature_updated", "정의 업데이트", "보안 인텔리전스를 업데이트함", DOC, SRC_MANIFEST),
    kind(2001, SECTION_SIGNATURE, "signature_update_failed", "정의 업데이트 실패", "보안 인텔리전스 업데이트가 실패함", DOC, SRC_MANIFEST),
    kind(2002, SECTION_SIGNATURE, "engine_updated", "엔진 업데이트", "엔진을 업데이트함", DOC, SRC_MANIFEST),
    kind(2003, SECTION_SIGNATURE, "engine_update_failed", "엔진 업데이트 실패", "엔진 업데이트가 실패함", DOC, SRC_MANIFEST),
    kind(2004, SECTION_SIGNATURE, "signature_load_failed", "정의 로드 실패", "정의를 로드하지 못해 이전 정의로 되돌림", DOC, SRC_MANIFEST),
    kind(2005, SECTION_SIGNATURE, "engine_load_platform_outdated", "플랫폼 버전 부족", "플랫폼 버전이 낮아 엔진을 로드하지 못함", DOC, SRC_MANIFEST),
    kind(2006, SECTION_SIGNATURE, "platform_update_failed", "플랫폼 업데이트 실패", "플랫폼 업데이트가 실패함", DOC, SRC_MANIFEST),
    kind(2007, SECTION_HEALTH, "platform_almost_outdated", "플랫폼 만료 예정", "플랫폼이 곧 만료됨", DOC, SRC_MANIFEST),
    kind(2010, SECTION_SIGNATURE, "cloud_intelligence_received", "클라우드 인텔리전스 수신", "클라우드 보호로 추가 인텔리전스를 받음", DOC, SRC_MANIFEST),
    kind(2011, SECTION_SIGNATURE, "dynamic_signature_deleted", "동적 정의 삭제", "만료된 동적 정의를 삭제함", DOC, SRC_MANIFEST),
    kind(2012, SECTION_SIGNATURE, "dynamic_signature_failed", "동적 정의 오류", "동적 정의 사용 중 오류가 발생함", DOC, SRC_MANIFEST),
    kind(2013, SECTION_SIGNATURE, "dynamic_signatures_deleted_all", "동적 정의 전체 삭제", "모든 동적 정의를 삭제함", DOC, SRC_MANIFEST),
    kind(2020, SECTION_SIGNATURE, "clean_file_downloaded", "정상 파일 수신", "분석용 정상 파일을 내려받음", DOC, SRC_MANIFEST),
    kind(2021, SECTION_SIGNATURE, "clean_file_download_failed", "정상 파일 수신 실패", "정상 파일 내려받기가 실패함", DOC, SRC_MANIFEST),
    kind(2030, SECTION_SCAN, "offline_scan_installed", "오프라인 검사 구성", "다음 재시작에 오프라인 검사를 실행하도록 구성됨", DOC, SRC_MANIFEST),
    kind(2031, SECTION_SCAN, "offline_scan_install_failed", "오프라인 검사 구성 실패", "오프라인 검사 구성이 실패함", DOC, SRC_MANIFEST),
    kind(2040, SECTION_HEALTH, "os_support_expiring", "OS 지원 종료 예정", "이 운영체제 버전의 지원이 곧 종료됨", DOC, SRC_MANIFEST),
    kind(2041, SECTION_HEALTH, "os_support_ended", "OS 지원 종료", "이 운영체제 버전의 지원이 종료됨", DOC, SRC_MANIFEST),
    kind(2042, SECTION_HEALTH, "protection_support_ended", "보호 지원 종료", "엔진이 이 운영체제를 더 이상 보호하지 않음", DOC, SRC_MANIFEST),
    kind(2050, SECTION_THREAT, "sample_submitted", "샘플 제출", "분석용 샘플 파일을 제출함", DOC, SRC_MANIFEST),
    kind(2051, SECTION_THREAT, "sample_submit_failed", "샘플 제출 실패", "분석용 샘플 파일 제출이 실패함", DOC, SRC_MANIFEST),
    kind(3002, SECTION_FAILURE, "realtime_protection_feature_failure", "실시간 보호 기능 실패", "실시간 보호 기능이 오류로 실패함", DOC, SRC_MANIFEST),
    kind(3007, SECTION_FAILURE, "realtime_protection_feature_recovered", "실시간 보호 기능 복구", "실시간 보호 기능이 복구됨", DOC, SRC_MANIFEST),
    kind(5000, SECTION_TAMPERING, "realtime_protection_enabled", "실시간 보호 사용", "실시간 보호가 사용 상태로 기록됨", DOC, SRC_MANIFEST),
    kind(5001, SECTION_TAMPERING, "realtime_protection_disabled", "실시간 보호 해제", "실시간 보호가 사용 안 함으로 기록됨", DOC, SRC_MANIFEST),
    kind(5004, SECTION_TAMPERING, "realtime_protection_config_changed", "실시간 보호 구성 변경", "실시간 보호 구성이 변경됨", DOC, SRC_MANIFEST),
    kind(5007, SECTION_TAMPERING, "configuration_changed", "보호 구성 변경", "보호 구성 값이 변경됨", DOC, SRC_MANIFEST),
    kind(5008, SECTION_FAILURE, "engine_failure", "엔진 오류", "엔진이 예기치 않은 오류로 종료됨", DOC, SRC_MANIFEST),
    kind(5009, SECTION_TAMPERING, "malware_scanning_enabled", "맬웨어 검사 사용", "맬웨어·원치 않는 소프트웨어 검사가 사용 상태로 기록됨", DOC, SRC_MANIFEST),
    kind(5010, SECTION_TAMPERING, "malware_scanning_disabled", "맬웨어 검사 해제", "맬웨어·원치 않는 소프트웨어 검사가 사용 안 함으로 기록됨", DOC, SRC_MANIFEST),
    kind(5011, SECTION_TAMPERING, "virus_scanning_enabled", "바이러스 검사 사용", "바이러스 검사가 사용 상태로 기록됨", DOC, SRC_MANIFEST),
    kind(5012, SECTION_TAMPERING, "virus_scanning_disabled", "바이러스 검사 해제", "바이러스 검사가 사용 안 함으로 기록됨", DOC, SRC_MANIFEST),
    kind(5013, SECTION_TAMPERING, "tamper_protection_blocked_change", "변조 방지 차단", "변조 방지가 설정 변경을 차단함", DOC, SRC_MSDOCS),
    kind(5017, SECTION_FAILURE, "feature_configuration_failure", "기능 구성 실패", "기능 구성에 실패한 사유가 기록됨", PAYLOAD_ONLY, SRC_PAYLOAD),
    kind(5100, SECTION_HEALTH, "platform_expiring", "보호 만료 예정", "보호 플랫폼이 곧 만료됨", DOC, SRC_MANIFEST),
    kind(5101, SECTION_HEALTH, "platform_expired", "보호 만료", "보호 플랫폼이 만료되어 보호가 중지됨", DOC, SRC_MANIFEST),
];

/// The manifest declares a single event on the WHC channel. Its state code is
/// an unlabelled number, so only the fact of a state update is stated and the
/// code itself stays raw.
const WHC_KINDS: &[Kind] = &[kind(
    101,
    SECTION_WHC_STATE,
    "whc_state_updated",
    "Defender 상태 갱신",
    "Defender 바이러스 백신 상태가 갱신됨(상태 코드 원문 보존, 의미 미확인)",
    DOC,
    SRC_MANIFEST,
)];

/// Channel-keyed lookup: an Operational meaning is never applied to another
/// channel just because the event number matches.
fn kind_of(channel: &str, event_id: Option<i64>) -> Option<&'static Kind> {
    let id = event_id?;
    let table = if channel.eq_ignore_ascii_case(OPERATIONAL_CHANNEL) {
        OPERATIONAL_KINDS
    } else if channel.eq_ignore_ascii_case(WHC_CHANNEL) {
        WHC_KINDS
    } else {
        return None;
    };
    table.iter().find(|kind| kind.id == id)
}

fn section_label(section: &str) -> &'static str {
    match section {
        SECTION_THREAT => "탐지",
        SECTION_THREAT_ACTION => "조치",
        SECTION_SCAN => "검사",
        SECTION_TAMPERING => "보호 설정",
        SECTION_HEALTH => "상태 보고",
        SECTION_FAILURE => "오류",
        SECTION_HISTORY => "기록 삭제",
        SECTION_ASR => "공격 표면 축소",
        SECTION_FOLDER_GUARD => "폴더 액세스 보호",
        SECTION_NETWORK => "네트워크 보호",
        SECTION_DEVICE_CONTROL => "장치·정책 제어",
        SECTION_WHC_STATE => "상태 갱신(WHC)",
        _ => "기타",
    }
}

/// Protection feature and enforcement mode, both from the event's own
/// documented meaning. Audit events never become blocks and block events
/// never become successful remediations.
const MODE_BLOCK: &str = "block";
const MODE_AUDIT: &str = "audit";
const MODE_WARN_OVERRIDE: &str = "warn_override";

fn protection_of(section: &str, event_type: &str) -> Option<(&'static str, &'static str)> {
    let feature = match section {
        SECTION_ASR => "attack_surface_reduction",
        SECTION_FOLDER_GUARD => "controlled_folder_access",
        SECTION_NETWORK => "network_protection",
        SECTION_DEVICE_CONTROL => "device_control",
        _ => return None,
    };
    let mode = match event_type {
        "asr_rule_blocked" | "cfa_blocked" | "cfa_sector_write_blocked"
        | "network_connection_blocked" | "device_control_blocked" => MODE_BLOCK,
        "asr_rule_audited" | "cfa_audited" | "cfa_sector_write_audited"
        | "network_connection_audited" | "device_control_audited" => MODE_AUDIT,
        "asr_rule_warn_overridden" => MODE_WARN_OVERRIDE,
        _ => return None,
    };
    Some((feature, mode))
}

/// Attack surface reduction rule GUIDs and their published names. An unlisted
/// GUID keeps the raw value with no invented name.
const ASR_RULES: &[(&str, &str)] = &[
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands"),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools"),
    ("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware"),
];

fn asr_rule_name(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    ASR_RULES
        .iter()
        .find(|(guid, _)| guid.eq_ignore_ascii_case(trimmed))
        .map(|(_, name)| *name)
}

/// Registry value names whose change directly concerns protection features.
const PROTECTION_SETTINGS: &[&str] = &[
    "DisableAntiSpyware",
    "DisableAntiVirus",
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableIOAVProtection",
    "DisableOnAccessProtection",
    "DisableScanOnRealtimeEnable",
    "DisableScriptScanning",
    "DisableBlockAtFirstSeen",
    "PUAProtection",
    "TamperProtection",
];

fn value(raw: &str) -> Cell {
    if raw.is_empty() {
        Cell::Null
    } else {
        Cell::Text(raw.to_string())
    }
}

fn opt_value(raw: Option<&str>) -> Cell {
    raw.map(value).unwrap_or(Cell::Null)
}

fn int_text(raw: &str) -> Cell {
    match raw.trim().parse::<i64>() {
        Ok(parsed) => Cell::Int(parsed),
        Err(_) => Cell::Null,
    }
}

/// Payload instant as KST (`parse_log_time` rule) plus the written value in
/// `<column>_raw`. FILETIME zero (1601-01-01 UTC) is "never", not a time.
fn set_payload_time(record: &mut Record, column: &str, raw: &str) {
    let parsed = support::parse_log_time(raw)
        .map(|parsed| parsed.display)
        .filter(|display| display != "1601-01-01 09:00:00.000");
    record.set(column, opt_value(parsed.as_deref()));
    record.set(&format!("{column}_raw"), value(raw));
}

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

// --- payload access ---------------------------------------------------------

/// Flat EventData and nested EventXML share one access rule; an unreadable
/// payload is recorded as such rather than becoming an empty normal row.
struct Payload {
    map: Map<String, Value>,
    nested: Option<Map<String, Value>>,
    shape: &'static str,
    count: usize,
}

fn flatten(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// A missing EventData column and a stored empty payload are different facts.
fn payload_of(raw: Option<&str>) -> Payload {
    let Some(raw) = raw else {
        return Payload { map: Map::new(), nested: None, shape: "absent", count: 0 };
    };
    if raw.trim().is_empty() {
        return Payload { map: Map::new(), nested: None, shape: "empty", count: 0 };
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => {
            let nested = match map.get("EventXML") {
                Some(Value::Object(inner)) => Some(inner.clone()),
                _ => None,
            };
            let count = nested.as_ref().map(Map::len).unwrap_or_else(|| map.len());
            // A record the parser could only keep as ProcessingErrorData has
            // no readable field template; it is not an empty normal payload.
            let shape = if nested.is_some() {
                "nested"
            } else if map.contains_key("ProcessingErrorData") {
                "processing_error"
            } else {
                "flat"
            };
            Payload { map, nested, shape, count }
        }
        _ => Payload { map: Map::new(), nested: None, shape: "invalid", count: 0 },
    }
}

impl Payload {
    fn get(&self, name: &str) -> String {
        if let Some(inner) = &self.nested {
            if let Some(found) = inner.get(name) {
                let text = flatten(found);
                if !text.is_empty() {
                    return text;
                }
            }
        }
        self.map.get(name).map(flatten).unwrap_or_default()
    }

    /// Documented label variants differ per event id; the first present wins.
    fn first(&self, names: &[&str]) -> String {
        for name in names {
            let found = self.get(name);
            if !found.is_empty() {
                return found;
            }
        }
        String::new()
    }

    fn entries(&self) -> Vec<(String, String, &'static str)> {
        let mut rows = Vec::with_capacity(self.map.len() + self.count);
        if let Some(inner) = &self.nested {
            for (name, found) in inner {
                rows.push((name.clone(), flatten(found), "EventXML"));
            }
        }
        for (name, found) in &self.map {
            if name == "EventXML" && self.nested.is_some() {
                continue;
            }
            rows.push((name.clone(), flatten(found), "EventData"));
        }
        rows
    }
}

// --- field parsing ----------------------------------------------------------

struct Resource {
    raw: String,
    kind: Option<String>,
    path: String,
}

/// Defender writes several resources in one field, separated by ';'.
fn resources_of(raw: &str) -> Vec<Resource> {
    raw.split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once(":_") {
            Some((kind, path)) if !kind.contains('\\') && !kind.contains('/') => Resource {
                raw: part.to_string(),
                kind: Some(kind.to_string()),
                path: path.to_string(),
            },
            _ => Resource { raw: part.to_string(), kind: None, path: part.to_string() },
        })
        .collect()
}

struct ConfigValue {
    raw: String,
    target: String,
    value: String,
    state: &'static str,
}

/// `<scope>\<name> = <value>`; evtx trims the trailing space of empty values,
/// so a recorded-but-empty value differs from a value that was never written.
fn config_value(raw: &str) -> ConfigValue {
    if raw.is_empty() {
        return ConfigValue { raw: String::new(), target: String::new(), value: String::new(), state: "absent" };
    }
    if let Some((target, found)) = raw.split_once(" = ") {
        let state = if found.is_empty() { "empty" } else { "value" };
        return ConfigValue {
            raw: raw.to_string(),
            target: target.to_string(),
            value: found.to_string(),
            state,
        };
    }
    if let Some(target) = raw.strip_suffix(" =") {
        return ConfigValue {
            raw: raw.to_string(),
            target: target.to_string(),
            value: String::new(),
            state: "empty",
        };
    }
    ConfigValue { raw: raw.to_string(), target: String::new(), value: String::new(), state: "unparsed" }
}

fn change_kind(old: &ConfigValue, new: &ConfigValue) -> &'static str {
    match (old.state, new.state) {
        ("absent", "absent") => "unknown",
        ("absent", _) => "added",
        (_, "absent") => "removed",
        ("unparsed", _) | (_, "unparsed") => "unknown",
        _ if old.value == new.value && old.target == new.target => "unchanged",
        _ => "changed",
    }
}

/// `...\Exclusions\<kind>\<value>` identifies a scan exclusion entry.
fn exclusion_of(target: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = target.split('\\').collect();
    let index = parts.iter().position(|part| part.eq_ignore_ascii_case("Exclusions"))?;
    let kind = parts.get(index + 1)?.to_string();
    let rest = parts.get(index + 2..).map(|rest| rest.join("\\")).unwrap_or_default();
    Some((kind, rest))
}

fn protection_setting(target: &str) -> Option<String> {
    let last = target.rsplit('\\').next()?;
    PROTECTION_SETTINGS
        .iter()
        .find(|name| name.eq_ignore_ascii_case(last))
        .map(|_| last.to_string())
}

/// Disable* values that switch a tracked feature; DWORD 1 disables it and 0
/// enables it. Other values, a removal or another setting stay unknown/none.
const SETTING_FEATURES: &[(&str, &str)] = &[
    ("DisableRealtimeMonitoring", protection::FEATURE_REALTIME),
    ("DisableOnAccessProtection", protection::FEATURE_ON_ACCESS),
    ("DisableIOAVProtection", protection::FEATURE_IOAV),
    ("DisableBehaviorMonitoring", protection::FEATURE_BEHAVIOR),
];

fn setting_state(target: &str, new: &ConfigValue) -> Option<(&'static str, &'static str)> {
    let last = target.rsplit('\\').next()?;
    let feature = SETTING_FEATURES.iter().find(|(name, _)| name.eq_ignore_ascii_case(last))?.1;
    let raw = new.value.trim();
    let number = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => raw.parse::<u64>().ok(),
    };
    let state = match (new.state, number) {
        ("value", Some(1)) => protection::STATE_OFF,
        ("value", Some(0)) => protection::STATE_ON,
        _ => protection::STATE_UNKNOWN,
    };
    Some((feature, state))
}

fn is_zero(code: &str) -> bool {
    let trimmed = code.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    !digits.is_empty() && digits.chars().all(|c| c == '0')
}

/// Results come from the event's own semantics or its error code, never from
/// an action name's wording.
fn result_of(event_type: &str, error_code: &str) -> (Option<&'static str>, Option<&'static str>) {
    let failed = !error_code.is_empty() && !is_zero(error_code);
    match event_type {
        "threat_action_taken" | "quarantine_restored" | "quarantine_deleted" => {
            if failed {
                (Some("failure"), Some("payload:error_code"))
            } else {
                (Some("success"), Some("event:action_taken"))
            }
        }
        "threat_action_failed"
        | "threat_action_critically_failed"
        | "quarantine_restore_failed"
        | "quarantine_delete_failed" => (Some("failure"), Some("event:action_failed")),
        "offline_scan_install_failed"
        | "history_clear_failed"
        | "engine_failure"
        | "scan_error"
        | "sample_submit_failed"
        | "realtime_protection_feature_failure"
        | "feature_configuration_failure" => (Some("failure"), Some("event:reported_failure")),
        "scan_completed" => (Some("success"), Some("event:scan_completed")),
        "scan_cancelled" => (Some("unknown"), Some("event:scan_cancelled")),
        "scan_paused" | "scan_resumed" => (Some("unknown"), Some("event:scan_state_only")),
        "threat_detected" | "behavior_detected" | "pua_detected" => {
            (Some("unknown"), Some("event:detection_without_action"))
        }
        // Enforcement events state what the engine did, not that a threat was
        // removed: an audit event is explicitly not a block.
        "asr_rule_blocked" | "cfa_blocked" | "cfa_sector_write_blocked"
        | "network_connection_blocked" | "device_control_blocked" => {
            (Some("blocked"), Some("event:block_mode_enforced"))
        }
        "asr_rule_audited" | "cfa_audited" | "cfa_sector_write_audited"
        | "network_connection_audited" | "device_control_audited" => {
            (Some("audited"), Some("event:audit_mode_only"))
        }
        "asr_rule_warn_overridden" => {
            (Some("warn_overridden"), Some("event:user_override_in_warn_mode"))
        }
        "tamper_protection_blocked_change" => {
            (Some("blocked"), Some("event:tamper_protection_blocked"))
        }
        _ => (None, None),
    }
}

/// Network protection writes one endpoint string. Only its syntax is read:
/// no category, reputation or direction is invented.
#[derive(Default)]
struct Destination {
    kind: &'static str,
    scheme: String,
    host: String,
    ip: String,
    port: Option<i64>,
}

fn destination_of(raw: &str) -> Option<Destination> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() && !scheme.contains(['/', '.', ' ']) => {
            (scheme.to_string(), rest)
        }
        _ => (String::new(), trimmed),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Userinfo stays out of the host; the raw value keeps it.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|_| authority.find(']')) {
        let host = &authority[1..end];
        let port = authority[end + 1..].strip_prefix(':').and_then(|port| port.parse::<i64>().ok());
        (host.to_string(), port)
    } else if authority.matches(':').count() > 1 {
        // A bracketless IPv6 literal has no port to split off.
        (authority.to_string(), None)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                (host.to_string(), port.parse::<i64>().ok())
            }
            _ => (authority.to_string(), None),
        }
    };
    let ip = host.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string());
    let kind = if !scheme.is_empty() {
        "url"
    } else if ip.is_some() {
        "ip"
    } else if !host.is_empty() && host.contains('.') {
        "hostname"
    } else if host.is_empty() {
        "unparsed"
    } else {
        "host_label"
    };
    Some(Destination {
        kind,
        scheme,
        host,
        ip: ip.unwrap_or_default(),
        port,
    })
}

fn feature_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "사용" | "enabled" | "on" | "1" => protection::STATE_ON,
        "사용 안 함" | "사용안함" | "disabled" | "off" | "0" => protection::STATE_OFF,
        _ => protection::STATE_UNKNOWN,
    }
}

// --- stored row bookkeeping -------------------------------------------------

struct ScanFacts {
    scan_id: String,
    scan_type: String,
    scan_parameters: String,
    duration_raw: String,
    duration_seconds: Option<i64>,
    user_raw: String,
    user_sid: String,
}

struct Stored {
    record_id: String,
    section: String,
    event_type: String,
    event_id: Option<i64>,
    event_record_id: Option<i64>,
    timestamp: Option<String>,
    detection_id: String,
    /// Detection instant as stored (KST): the payload `Detection Time` of an
    /// EVTX event, the line time of an MPDetection record.
    detection_time: Option<String>,
    threat_name: String,
    action: String,
    action_performer: String,
    result: Option<String>,
    result_basis: Option<String>,
    scan: Option<ScanFacts>,
}

#[derive(Default)]
struct LogStats {
    source_file: String,
    attributed: i64,
    foreign: i64,
    unmapped: i64,
    corrupted: i64,
    untimed: i64,
    first: Option<String>,
    last: Option<String>,
}

// --- build ------------------------------------------------------------------

/// Materialize MPDetection evidence before the overview references it.
pub(super) fn prepare_inputs(out_dir: &Path, target: &Path, dataset_id: &str) -> Result<Vec<String>> {
    support::prepare_inputs(out_dir, target, dataset_id)
}

pub(super) fn build(ctx: &Ctx, cache: &EventLogOverviewCache) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut stats: BTreeMap<String, LogStats> = BTreeMap::new();
    let mut stored: Vec<Stored> = Vec::new();
    let mut observations: Vec<Observation> = Vec::new();
    // Health reports wait until the protection changes are known.
    let mut pending: Vec<(Record, Stored)> = Vec::new();

    for row in cache.rows() {
        let table = g(row, "_record_key").split("::").next().unwrap_or("").to_string();
        let provider = g(row, "Provider");
        let from_defender_file = std::path::Path::new(g(row, "_source_file"))
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_lowercase().contains("defender"))
            .unwrap_or(false);
        if provider != PROVIDER {
            if from_defender_file {
                let entry = stats.entry(table).or_default();
                entry.source_file = g(row, "_source_file").to_string();
                if g(row, "_status") == "corrupted_chunk" {
                    entry.corrupted += 1;
                } else {
                    entry.foreign += 1;
                }
            }
            continue;
        }
        let entry = stats.entry(table).or_default();
        entry.source_file = g(row, "_source_file").to_string();
        if g(row, "_status") == "corrupted_chunk" {
            entry.corrupted += 1;
        }
        entry.attributed += 1;
        let timestamp = g(row, "timestamp");
        if timestamp.is_empty() {
            entry.untimed += 1;
        } else {
            entry.first = Some(match entry.first.take() {
                Some(current) if current <= timestamp.to_string() => current,
                _ => timestamp.to_string(),
            });
            entry.last = Some(match entry.last.take() {
                Some(current) if current >= timestamp.to_string() => current,
                _ => timestamp.to_string(),
            });
        }
        let event_id = g(row, "EventID").trim().parse::<i64>().ok();
        // Each documented meaning belongs to one channel; the same number on
        // the other channel is a different event and stays raw.
        let channel = g(row, "Channel");
        let known_channel = channel.eq_ignore_ascii_case(OPERATIONAL_CHANNEL)
            || channel.eq_ignore_ascii_case(WHC_CHANNEL);
        let found = kind_of(channel, event_id);
        if found.is_none() {
            entry.unmapped += 1;
        }
        let (record, facts, keep) = event_record(ctx, row, event_id, found, known_channel, &mut observations)?;
        match keep {
            Keep::Store => {
                stored.push(facts);
                db.write(record)?;
            }
            Keep::IfChanged => pending.push((record, facts)),
            Keep::Drop => {}
        }
    }
    let changed = protection::changed_records(&observations);
    for (record, facts) in pending {
        if changed.contains(&facts.record_id) {
            stored.push(facts);
            db.write(record)?;
        }
    }

    let mpdetection = mpdetection_rows(ctx, &mut db, &mut stored)?;
    detections(ctx, &mut db, &stored)?;
    scans(ctx, &mut db, &stored)?;
    let kept: HashSet<String> = stored.iter().map(|row| row.record_id.clone()).collect();
    protection::populate(ctx, &mut db, &observations, &kept)?;
    summaries(ctx, &mut db, &stored)?;
    candidates(ctx, &mut db, &stored)?;
    input_observations(ctx, &mut db, stats, &mpdetection)?;
    db.finish()
}

/// Whether a source event becomes an `_OVERVIEW` row (user decision 2026-10-14).
enum Keep {
    Store,
    /// Health report: stored only when it carries a protection change.
    IfChanged,
    /// Definition-version section, routine heartbeat or periodic history purge.
    Drop,
}

/// Periodic history purge: SYSTEM deletes history older than a whole number
/// of days (`ScanPurgeItemsAfterDelay`, default 15) before the event time.
fn periodic_purge(account_sid: &str, user_raw: &str, event_time: &str, cleared_raw: &str) -> bool {
    let system = if super::is_sid(account_sid) {
        account_sid == "S-1-5-18"
    } else {
        user_raw.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM")
    };
    let Some(cleared) = support::parse_log_time(cleared_raw) else {
        return false;
    };
    const DAY: i64 = 86_400;
    const TOLERANCE: i64 = 2;
    match protection::gap(&cleared.display, event_time) {
        Cell::Int(seconds) => system && seconds >= DAY - TOLERANCE && (seconds + TOLERANCE) % DAY <= 2 * TOLERANCE,
        _ => false,
    }
}

/// One stored row per source event; no field is borrowed from another event.
fn event_record(
    ctx: &Ctx,
    row: &Row,
    event_id: Option<i64>,
    found: Option<&'static Kind>,
    known_channel: bool,
    observations: &mut Vec<Observation>,
) -> Result<(Record, Stored, Keep)> {
    let payload = payload_of(row.get("EventData").map(String::as_str));
    let mut record = ctx.record(&SPEC);
    let record_id = record.record_id.clone();
    let timestamp = g(row, "timestamp");
    let channel = g(row, "Channel");
    let operational = channel.eq_ignore_ascii_case(OPERATIONAL_CHANNEL);
    let whc = channel.eq_ignore_ascii_case(WHC_CHANNEL);
    debug_assert_eq!(known_channel, operational || whc);
    let section = found.map(|kind| kind.section).unwrap_or("other");
    let event_type = found
        .map(|kind| kind.event_type.to_string())
        .unwrap_or_else(|| format!("defender_event_{}", g(row, "EventID")));
    let description = found.map(|kind| kind.description.to_string()).unwrap_or_else(|| {
        if operational {
            "지원 매핑이 없는 Defender 이벤트 원문".to_string()
        } else if whc {
            "WHC 채널에서 매핑되지 않은 이벤트 원문 — 확인된 의미 없음".to_string()
        } else {
            "매니페스트에 없는 Defender 채널 이벤트 원문 — 확인된 의미 없음".to_string()
        }
    });

    record.timestamp(timestamp, TIME_KIND_EVENT);
    record.set("timestamp_state", value(if timestamp.is_empty() { "unrecorded" } else { "recorded" }));
    record.set("event_type", value(&event_type));
    record.set("description", value(&description));
    record.set("section", value(section));
    record.set("section_label", value(section_label(section)));
    record.set("source", value(SOURCE_EVENTLOG));
    record.set("source_label", value(SOURCE_LABEL_EVENTLOG));
    record.set(
        "support_state",
        value(found.map(|kind| kind.support_state).unwrap_or({
            if operational {
                "unmapped"
            } else {
                "unmapped_channel"
            }
        })),
    );
    record.set("support_source", opt_value(found.map(|kind| kind.support_source)));
    record.set(
        "channel_state",
        value(if operational {
            "manifest_operational"
        } else if whc {
            "manifest_whc"
        } else {
            "unknown_channel"
        }),
    );
    record.set("title", opt_value(found.map(|kind| kind.title)));

    // Threat and action fields, each from this event only.
    let threat_name = payload.first(&["Threat Name", "Name"]);
    let detection_id = payload.first(&["Detection ID"]);
    let path = payload.first(&["Path", "Threat Resource Path", "Resource", "Target File Name", "File Name", "Filename"]);
    let parsed = resources_of(&path);
    // `ID` is the threat id in antimalware events and the rule GUID in ASR
    // events, so the family of this event decides who may read it.
    let generic_id = payload.get("ID");
    let antimalware = matches!(
        section,
        SECTION_THREAT | SECTION_THREAT_ACTION | SECTION_SCAN | SECTION_HISTORY
    );
    let threat_id = match payload.get("Threat ID") {
        stored if !stored.is_empty() => stored,
        _ if antimalware => generic_id.clone(),
        _ => String::new(),
    };
    record.set("threat_name", value(&threat_name));
    record.set("threat_id", value(&threat_id));
    record.set("severity", value(&payload.first(&["Severity Name", "Severity"])));
    record.set("severity_id", int_text(&payload.first(&["Severity ID"])));
    record.set("category", value(&payload.first(&["Category Name", "Category"])));
    record.set("category_id", int_text(&payload.first(&["Category ID"])));
    record.set("resources_raw", value(&path));
    record.set("resource_count", if path.is_empty() { Cell::Null } else { Cell::Int(parsed.len() as i64) });
    record.set(
        "target_path",
        if parsed.len() == 1 { value(&parsed[0].path) } else { Cell::Null },
    );
    for resource in &parsed {
        record.child(
            "DefenderResources",
            vec![value(&resource.raw), opt_value(resource.kind.as_deref()), value(&resource.path)],
        );
    }
    record.set("detection_id", value(&detection_id));
    record.set("detection_id_state", value(if detection_id.is_empty() { "absent" } else { "present" }));
    record.set("detection_type", value(&payload.first(&["Type Name", "Detection Type"])));
    record.set("detection_origin", value(&payload.first(&["Origin Name", "Detection Origin"])));
    record.set("detection_source", value(&payload.first(&["Source Name", "Detection Source"])));
    let detection_user = payload.first(&["Detection User"]);
    record.set("detection_user", value(&detection_user));
    let process = payload.first(&["Process Name"]);
    record.set("process", value(&process));
    let action = payload.first(&["Action Name", "Action"]);
    record.set("action", value(&action));
    record.set("action_id", int_text(&payload.first(&["Action ID"])));
    // The action time is this event's own time, never another event's.
    record.set(
        "action_time",
        if section == "threat_action" { value(timestamp) } else { Cell::Null },
    );
    record.set("additional_actions", value(&payload.first(&["Additional Actions String"])));
    record.set("additional_actions_id", int_text(&payload.first(&["Additional Actions ID"])));
    let remediation_user = payload.first(&["Remediation User"]);
    record.set("remediation_user", value(&remediation_user));
    // 1116/1117 template field; Pre Execution/Post Clean Status stay in the
    // field child. No template has `Status` or `Action Status`.
    record.set("status_raw", value(&payload.first(&["Status Code"])));
    let error_code = payload.first(&["Error Code"]);
    let error_description = payload.first(&["Error Description"]);
    record.set("error_code", value(&error_code));
    record.set("error_description", value(&error_description));
    let (result, result_basis) = result_of(&event_type, &error_code);
    record.set("result", opt_value(result));
    record.set("result_basis", opt_value(result_basis));

    // Attack surface reduction, controlled folder access, network protection
    // and policy enforcement. The feature and the enforcement mode come from
    // the event's documented meaning, never from a payload wording.
    let protection = protection_of(section, &event_type);
    record.set("protection_feature", opt_value(protection.map(|(feature, _)| feature)));
    record.set("protection_mode", opt_value(protection.map(|(_, mode)| mode)));
    let asr_rule_id = if section == SECTION_ASR { generic_id.clone() } else { String::new() };
    let asr_name = asr_rule_name(&asr_rule_id);
    record.set("asr_rule_id", value(&asr_rule_id));
    record.set("asr_rule_name", opt_value(asr_name));
    record.set(
        "asr_rule_name_source",
        if asr_rule_id.is_empty() {
            Cell::Null
        } else {
            value(if asr_name.is_some() { "microsoft_docs" } else { "unknown_guid" })
        },
    );
    // One endpoint string; its syntax is parsed and the raw value is kept.
    let destination_raw = payload.get("Destination");
    let destination = destination_of(&destination_raw);
    record.set("network_destination_raw", value(&destination_raw));
    record.set("network_destination_kind", opt_value(destination.as_ref().map(|found| found.kind)));
    record.set(
        "network_destination_scheme",
        destination.as_ref().map(|found| value(&found.scheme)).unwrap_or(Cell::Null),
    );
    record.set(
        "network_destination_host",
        destination.as_ref().map(|found| value(&found.host)).unwrap_or(Cell::Null),
    );
    record.set(
        "network_destination_ip",
        destination.as_ref().map(|found| value(&found.ip)).unwrap_or(Cell::Null),
    );
    record.set(
        "network_destination_port",
        destination.as_ref().and_then(|found| found.port).map(Cell::Int).unwrap_or(Cell::Null),
    );
    // Enforcement events carry their own detection instant; the source zone
    // is recorded and an unzoned value follows the documented UTC rule.
    let detection_time_raw = payload.first(&["Detection Time", "Detection time"]);
    let detection_time = support::parse_log_time(&detection_time_raw);
    record.set("detection_time_raw", value(&detection_time_raw));
    record.set(
        "detection_time",
        detection_time.as_ref().map(|parsed| value(&parsed.display)).unwrap_or(Cell::Null),
    );
    record.set(
        "detection_time_state",
        if detection_time_raw.is_empty() {
            Cell::Null
        } else {
            value(detection_time.as_ref().map(|parsed| parsed.state()).unwrap_or("unparsed"))
        },
    );
    record.set(
        "detection_time_zone_source",
        opt_value(detection_time.as_ref().map(|parsed| parsed.zone)),
    );
    // Policy enforcement fields with published names only; the remaining
    // template parameters have no published name and stay in the field child.
    record.set("policy_version", value(&payload.get("Policy Version")));
    record.set("policy_rule_id", value(&payload.get("Policy Rule Id")));
    record.set("policy_enforcement_level", value(&payload.get("Enforcement Level")));
    record.set("policy_action_type", value(&payload.get("Action Type")));
    record.set("policy_audit_reason", value(&payload.get("Audit Reason")));
    record.set("policy_event_timestamp_raw", value(&payload.get("Event Timestamp")));
    // WHC state update: the numeric state code has no published enumeration,
    // so it is stored as written and nothing is derived from it.
    let whc_state = payload.get("hc_stateid");
    record.set("whc_state_raw", if whc { value(&whc_state) } else { Cell::Null });
    record.set("whc_state_id", if whc { int_text(&whc_state) } else { Cell::Null });

    // Scan evidence.
    let scan_id = payload.first(&["Scan ID"]);
    let scan_type = payload.first(&["Scan Type"]);
    let scan_parameters = payload.first(&["Scan Parameters"]);
    let (hours, minutes, seconds) = (
        payload.get("Scan Time Hours"),
        payload.get("Scan Time Minutes"),
        payload.get("Scan Time Seconds"),
    );
    let duration_raw = if hours.is_empty() && minutes.is_empty() && seconds.is_empty() {
        payload.get("Scan Time")
    } else {
        format!("{hours}:{minutes}:{seconds}")
    };
    let duration_seconds = match (
        hours.trim().parse::<i64>(),
        minutes.trim().parse::<i64>(),
        seconds.trim().parse::<i64>(),
    ) {
        (Ok(hours), Ok(minutes), Ok(seconds)) => Some(hours * 3600 + minutes * 60 + seconds),
        _ => None,
    };
    record.set("scan_id", value(&scan_id));
    record.set("scan_type", value(&scan_type));
    record.set("scan_type_index", int_text(&payload.get("Scan Type Index")));
    record.set("scan_parameters", value(&scan_parameters));
    record.set("scan_parameters_index", int_text(&payload.get("Scan Parameters Index")));
    record.set("scan_trigger", value(&payload.get("Scan Trigger")));
    record.set("scan_trigger_index", int_text(&payload.get("Scan Trigger Index")));
    record.set("scan_resources", value(&payload.get("Scan Resources")));
    record.set("scan_duration_raw", value(&duration_raw));
    record.set("scan_duration_seconds", duration_seconds.map(Cell::Int).unwrap_or(Cell::Null));

    // Definition, engine and platform versions.
    record.set("signature_version_current", value(&payload.first(&["Current security intelligence Version", "Current Signature Version", "New security intelligence version"])));
    record.set("signature_version_previous", value(&payload.first(&["Previous security intelligence Version", "Previous Signature Version", "Previous security intelligence version"])));
    record.set("engine_version_current", value(&payload.first(&["Current Engine Version", "New Engine Version"])));
    record.set("engine_version_previous", value(&payload.first(&["Previous Engine Version"])));
    record.set("signature_type", value(&payload.first(&["Security intelligence Type", "Signature Type"])));
    record.set("signature_type_index", int_text(&payload.first(&["Security intelligence Type Index", "Signature Type Index"])));
    record.set("update_type", value(&payload.first(&["Update Type"])));
    record.set("update_stage", value(&payload.first(&["Update State", "Update Stage"])));
    record.set("update_source", value(&payload.first(&["Update Source"])));
    record.set("update_source_path", value(&payload.first(&["Source Path"])));
    record.set("cloud_intelligence_type", value(&payload.first(&["Cloud protection intelligence Type", "Dynamic Signature Type"])));
    record.set("cloud_intelligence_version", value(&payload.first(&["Cloud protection intelligence Version", "Dynamic Signature Version"])));
    record.set("persistence_path", value(&payload.first(&["Persistence Path"])));
    record.set("product_name", value(&payload.first(&["Product Name"])));
    record.set("product_version", value(&payload.first(&["Product Version"])));
    record.set("platform_version", value(&payload.first(&["Platform version", "Current Platform Version", "Platform Version"])));
    record.set("engine_version", value(&payload.first(&["Engine version", "Engine Version"])));
    record.set("signature_version", value(&payload.first(&["Security intelligence version", "Signature Version"])));

    // Health report state, kept as the reported raw values.
    let rtp = payload.get("RTP state");
    let oa = payload.get("OA state");
    let ioav = payload.get("IOAV state");
    let bm = payload.get("BM state");
    record.set("rtp_state_raw", value(&rtp));
    record.set("oa_state_raw", value(&oa));
    record.set("ioav_state_raw", value(&ioav));
    record.set("bm_state_raw", value(&bm));
    record.set("product_status", value(&payload.get("Product status")));
    record.set("engine_up_to_date", value(&payload.get("Engine up-to-date")));
    record.set("platform_up_to_date", value(&payload.get("Platform up-to-date")));
    record.set("av_signature_version", value(&payload.get("AV security intelligence version")));
    record.set("as_signature_version", value(&payload.get("AS security intelligence version")));
    record.set("av_signature_age_raw", value(&payload.get("Last AV security intelligence age")));
    record.set("as_signature_age_raw", value(&payload.get("Last AS security intelligence age")));
    set_payload_time(&mut record, "av_signature_created", &payload.get("AV security intelligence creation time"));
    set_payload_time(&mut record, "as_signature_created", &payload.get("AS security intelligence creation time"));
    record.set("last_quick_scan_age_raw", value(&payload.get("Last quick scan age")));
    set_payload_time(&mut record, "last_quick_scan_start", &payload.get("Last quick scan start time"));
    set_payload_time(&mut record, "last_quick_scan_end", &payload.get("Last quick scan end time"));
    record.set("last_quick_scan_source", value(&payload.get("Last quick scan source")));
    record.set("last_full_scan_age_raw", value(&payload.get("Last full scan age")));
    set_payload_time(&mut record, "last_full_scan_start", &payload.get("Last full scan start time"));
    set_payload_time(&mut record, "last_full_scan_end", &payload.get("Last full scan end time"));
    record.set("last_full_scan_source", value(&payload.get("Last full scan source")));
    record.set("latest_engine_version", value(&payload.get("Latest engine version")));
    record.set("latest_platform_version", value(&payload.get("Latest platform version")));

    // Failure evidence.
    let feature_name = payload.first(&["Feature Name", "Feature"]);
    let failure_reason = payload.first(&["Failure Reason", "Reason"]);
    record.set("feature_name", value(&feature_name));
    record.set("failure_type", value(&payload.first(&["Failure Type"])));
    record.set("failure_type_index", int_text(&payload.first(&["Failure Type Index"])));
    record.set("failure_id", value(&payload.first(&["Failure Id"])));
    record.set("failure_reason", value(&failure_reason));
    record.set("recommendation", value(&payload.first(&["Recommendation"])));
    record.set("exception_code", value(&payload.first(&["Exception Code"])));
    record.set("engine_code", value(&payload.first(&["Engine Code"])));

    // Configuration change evidence.
    let old_config = config_value(&payload.get("Old Value"));
    let new_config = config_value(&payload.get("New Value"));
    let has_config = old_config.state != "absent" || new_config.state != "absent";
    let target = if !new_config.target.is_empty() { new_config.target.clone() } else { old_config.target.clone() };
    record.set("config_old_raw", value(&old_config.raw));
    record.set("config_old_value", value(&old_config.value));
    record.set("config_old_state", if has_config { value(old_config.state) } else { Cell::Null });
    record.set("config_new_raw", value(&new_config.raw));
    record.set("config_new_value", value(&new_config.value));
    record.set("config_new_state", if has_config { value(new_config.state) } else { Cell::Null });
    record.set("config_target_raw", if has_config { value(&format!("{}|{}", old_config.raw, new_config.raw)) } else { Cell::Null });
    record.set("config_target", value(&target));
    record.set("config_scope", value(target.split('\\').next().unwrap_or("")));
    record.set("config_change_kind", if has_config { value(change_kind(&old_config, &new_config)) } else { Cell::Null });
    match exclusion_of(&target) {
        Some((kind, entry)) => {
            record.set("config_exclusion_kind", value(&kind));
            record.set("config_exclusion_value", value(&entry));
        }
        None => {
            record.set("config_exclusion_kind", Cell::Null);
            record.set("config_exclusion_value", Cell::Null);
        }
    }
    record.set("config_protection_setting", opt_value(protection_setting(&target).as_deref()));
    set_payload_time(&mut record, "history_cleared_time", &payload.first(&["Timestamp", "Time"]));

    // Account roles: the payload user, the detection subject, the performer
    // and the event's security context stay separate.
    let domain = payload.get("Domain");
    let user = payload.get("User");
    let sid = payload.get("SID");
    // ASR/CFA/network events write one combined `User`; the stored domain and
    // name come from that one value instead of leaving the pair empty.
    let (domain, user) = match (domain.is_empty(), user.split_once('\\')) {
        (true, Some((found_domain, found_name))) => {
            (found_domain.to_string(), found_name.to_string())
        }
        _ => (domain, user),
    };
    let user_raw = match (domain.is_empty(), user.is_empty()) {
        (true, true) => String::new(),
        (true, false) => user.clone(),
        (false, true) => domain.clone(),
        (false, false) => format!("{domain}\\{user}"),
    };
    let system_sid = g(row, "UserID");
    let mut account_role = "";
    let mut account_name_source = "";
    if super::is_sid(&sid) {
        record.set("account_sid", value(&sid));
        match ctx.meta.account_name(&sid) {
            Some(name) => {
                record.set("account", value(&name));
                account_name_source = "metadata";
            }
            None if !user.is_empty() => {
                record.set("account", value(&user));
                account_name_source = "payload";
            }
            None => {}
        }
        account_role = "event_user";
    } else if !user_raw.is_empty() {
        record.set("account", value(&user_raw));
        account_name_source = "payload";
        account_role = "event_user";
    }
    record.set("account_role", value(account_role));
    record.set("account_name_source", value(account_name_source));
    record.set("event_user_raw", value(&user_raw));
    record.set("event_user_domain", value(&domain));
    record.set("event_user_name", value(&user));
    record.set("event_user_sid", if super::is_sid(&sid) { value(&sid) } else { Cell::Null });
    record.set("system_user_sid", if super::is_sid(system_sid) { value(system_sid) } else { Cell::Null });
    if !user_raw.is_empty() || super::is_sid(&sid) {
        account_role_child(&mut record, ctx, "event_user", &user_raw, &domain, &user, &sid);
    }
    if !detection_user.is_empty() {
        let (detection_domain, detection_name) = split_account(&detection_user);
        account_role_child(&mut record, ctx, "detection_user", &detection_user, &detection_domain, &detection_name, "");
    }
    if !remediation_user.is_empty() {
        let (performer_domain, performer_name) = split_account(&remediation_user);
        account_role_child(&mut record, ctx, "remediation_user", &remediation_user, &performer_domain, &performer_name, "");
    }
    if super::is_sid(system_sid) {
        account_role_child(&mut record, ctx, "security_context", system_sid, "", "", system_sid);
    }

    // Event identity and the exact parser payload.
    record.set("event_id", event_id.map(Cell::Int).unwrap_or(Cell::Null));
    record.set("provider", value(g(row, "Provider")));
    record.set("channel", value(channel));
    // Manifest discriminators kept next to the name; NULL in older facts.
    let provider_guid = g(row, "ProviderGuid");
    let normalized_guid = provider_guid.trim().trim_start_matches('{').trim_end_matches('}');
    record.set("provider_guid", value(provider_guid));
    record.set(
        "provider_guid_state",
        value(if provider_guid.trim().is_empty() {
            "absent"
        } else if normalized_guid.eq_ignore_ascii_case(PROVIDER_GUID) {
            "matched_manifest"
        } else {
            "other_guid"
        }),
    );
    record.set("schema_version", int_text(g(row, "Version")));
    record.set("computer", value(g(row, "Computer")));
    record.set("event_record_id", value(g(row, "EventRecordID")));
    record.set("level_name", value(g(row, "LevelName")));
    record.set("keywords_raw", value(g(row, "Keywords")));
    record.set("process_id", value(g(row, "ProcessID")));
    record.set("thread_id", value(g(row, "ThreadID")));
    record.set("activity_id", value(g(row, "ActivityID")));
    record.set("related_activity_id", value(g(row, "RelatedActivityID")));
    record.set("facts_status", value(g(row, "_status")));
    record.set("facts_error", value(g(row, "_error")));
    record.set("payload_shape", value(payload.shape));
    record.set("payload_field_count", Cell::Int(payload.count as i64));
    // Keep a stored empty payload distinct from a missing EventData column.
    record.set(
        "event_data_raw",
        row.get("EventData").cloned().map(Cell::Text).unwrap_or(Cell::Null),
    );
    record.set("record_key", value(g(row, "_record_key")));
    record.set("source_file", value(g(row, "_source_file")));
    for (name, found, scope) in payload.entries() {
        record.child("DefenderEventFields", vec![value(&name), value(&found), value(scope)]);
    }

    let detail = payload.first(&["Error Description", "Failure Reason", "Recommendation"]);
    record.set("detail", value(&detail));
    let account_text = record
        .get("account")
        .and_then(|cell| match cell {
            Cell::Text(text) => Some(text.clone()),
            _ => None,
        })
        .unwrap_or_default();
    record.set(
        "search_text",
        Cell::Text(search_text(&[
            threat_name.as_str(),
            path.as_str(),
            found.map(|kind| kind.title).unwrap_or(""),
            detail.as_str(),
            process.as_str(),
            detection_user.as_str(),
            remediation_user.as_str(),
            account_text.as_str(),
            sid.as_str(),
            system_sid,
            user_raw.as_str(),
            scan_id.as_str(),
            target.as_str(),
            feature_name.as_str(),
            failure_reason.as_str(),
            error_code.as_str(),
            asr_rule_id.as_str(),
            asr_name.unwrap_or(""),
            destination_raw.as_str(),
            destination.as_ref().map(|found| found.host.as_str()).unwrap_or(""),
            event_type.as_str(),
            section,
        ])),
    );

    record.source(Some(
        ctx.facts
            .source_from_record_key(
                g(row, "_record_key"),
                Some("EventData"),
                Some(g(row, "_source_file")),
                Some(&event_type),
            )?
            .ok_or_else(|| {
                anyhow::anyhow!("Defender 이벤트의 facts 출처가 없습니다: {}", g(row, "_record_key"))
            })?,
    ));

    // Feature states observed by this event. Only an event whose meaning is
    // confirmed contributes a protection state.
    for (feature, raw) in [
        (protection::FEATURE_REALTIME, &rtp),
        (protection::FEATURE_ON_ACCESS, &oa),
        (protection::FEATURE_IOAV, &ioav),
        (protection::FEATURE_BEHAVIOR, &bm),
    ] {
        if raw.is_empty() || found.is_none() {
            continue;
        }
        observations.push(Observation {
            record_id: record_id.clone(),
            feature,
            state: feature_state(raw),
            state_raw: Some(raw.clone()),
            basis: protection::BASIS_HEALTH,
            timestamp: (!timestamp.is_empty()).then(|| timestamp.to_string()),
            timestamp_kind: (!timestamp.is_empty()).then_some(TIME_KIND_EVENT),
            event_id,
            event_record_id: g(row, "EventRecordID").trim().parse::<i64>().ok(),
            order: observations.len(),
        });
    }
    if let Some((feature, state, basis, state_raw)) = match event_type.as_str() {
        "realtime_protection_enabled" => Some((protection::FEATURE_REALTIME, protection::STATE_ON, protection::BASIS_STATE_EVENT, None)),
        "realtime_protection_disabled" => Some((protection::FEATURE_REALTIME, protection::STATE_OFF, protection::BASIS_STATE_EVENT, None)),
        "realtime_protection_config_changed" => Some((protection::FEATURE_REALTIME, protection::STATE_UNKNOWN, protection::BASIS_CONFIG_CHANGE, None)),
        "malware_scanning_enabled" => Some((protection::FEATURE_MALWARE_SCANNING, protection::STATE_ON, protection::BASIS_STATE_EVENT, None)),
        "malware_scanning_disabled" => Some((protection::FEATURE_MALWARE_SCANNING, protection::STATE_OFF, protection::BASIS_STATE_EVENT, None)),
        "virus_scanning_enabled" => Some((protection::FEATURE_VIRUS_SCANNING, protection::STATE_ON, protection::BASIS_STATE_EVENT, None)),
        "virus_scanning_disabled" => Some((protection::FEATURE_VIRUS_SCANNING, protection::STATE_OFF, protection::BASIS_STATE_EVENT, None)),
        "configuration_changed" => setting_state(&target, &new_config).map(|(feature, state)| {
            (feature, state, protection::BASIS_CONFIG_CHANGE, (!new_config.value.is_empty()).then(|| new_config.value.clone()))
        }),
        _ => None,
    } {
        observations.push(Observation {
            record_id: record_id.clone(),
            feature,
            state,
            state_raw,
            basis,
            timestamp: (!timestamp.is_empty()).then(|| timestamp.to_string()),
            timestamp_kind: (!timestamp.is_empty()).then_some(TIME_KIND_EVENT),
            event_id,
            event_record_id: g(row, "EventRecordID").trim().parse::<i64>().ok(),
            order: observations.len(),
        });
    }

    let keep = match event_type.as_str() {
        _ if section == SECTION_SIGNATURE => Keep::Drop,
        // Routine quick scans and events without a supported meaning (user decision 2026-10-14).
        _ if found.is_none() => Keep::Drop,
        _ if section == SECTION_SCAN
            && ["Quick Scan", "빠른 검사"].iter().any(|quick| scan_parameters.trim().eq_ignore_ascii_case(quick)) =>
        {
            Keep::Drop
        }
        // Only scan exclusions and protection settings carry meaning.
        "configuration_changed"
            if !target.is_empty() && exclusion_of(&target).is_none() && protection_setting(&target).is_none() =>
        {
            Keep::Drop
        }
        "service_healthy" => Keep::Drop,
        "health_report" => Keep::IfChanged,
        "history_cleared" => {
            // Payload account first; the security context only when it is absent.
            let account_sid = if super::is_sid(&sid) {
                sid.as_str()
            } else if user_raw.is_empty() {
                system_sid
            } else {
                ""
            };
            if periodic_purge(account_sid, &user_raw, timestamp, &payload.first(&["Timestamp", "Time"])) {
                Keep::Drop
            } else {
                Keep::Store
            }
        }
        _ => Keep::Store,
    };
    let facts = Stored {
        record_id,
        section: section.to_string(),
        event_type,
        event_id,
        event_record_id: g(row, "EventRecordID").trim().parse::<i64>().ok(),
        timestamp: (!timestamp.is_empty()).then(|| timestamp.to_string()),
        detection_id,
        detection_time: detection_time.map(|parsed| parsed.display),
        threat_name,
        action,
        action_performer: remediation_user,
        result: result.map(str::to_string),
        result_basis: result_basis.map(str::to_string),
        scan: (!scan_id.is_empty() || section == "scan").then(|| ScanFacts {
            scan_id,
            scan_type,
            scan_parameters,
            duration_raw,
            duration_seconds,
            user_raw,
            user_sid: if super::is_sid(&sid) { sid } else { String::new() },
        }),
    };
    Ok((record, facts, keep))
}

fn split_account(raw: &str) -> (String, String) {
    match raw.split_once('\\') {
        Some((domain, name)) => (domain.to_string(), name.to_string()),
        None => (String::new(), raw.to_string()),
    }
}

fn account_role_child(
    record: &mut Record,
    ctx: &Ctx,
    role: &str,
    raw: &str,
    domain: &str,
    name: &str,
    sid: &str,
) {
    let resolved = super::is_sid(sid).then(|| ctx.meta.account_name(sid)).flatten();
    let (display, source) = match (&resolved, name.is_empty()) {
        (Some(found), _) => (found.clone(), "metadata"),
        (None, false) => (name.to_string(), "payload"),
        (None, true) => (String::new(), ""),
    };
    record.child(
        "DefenderAccountRoles",
        vec![
            value(role),
            value(raw),
            value(domain),
            value(&display),
            if super::is_sid(sid) { value(sid) } else { Cell::Null },
            value(source),
        ],
    );
}

fn search_text(parts: &[&str]) -> String {
    let mut out = String::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() || out.contains(part) {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(part);
    }
    out
}

// --- MPDetection rows -------------------------------------------------------

struct MpFile {
    row: support::FileRow,
}

fn mpdetection_rows(ctx: &Ctx, db: &mut DerivedDb, stored: &mut Vec<Stored>) -> Result<Vec<MpFile>> {
    let files = support::read_files(ctx.out_dir)?;
    let detections = support::read_detections(ctx.out_dir)?;
    let path = support::support_path(ctx.out_dir);
    for detection in detections {
        let mut record = ctx.record(&SPEC);
        let record_id = record.record_id.clone();
        let timestamp = detection.timestamp.clone().unwrap_or_default();
        record.timestamp(&timestamp, TIME_KIND_DETECTION);
        record.set(
            "timestamp_state",
            value(match detection.timestamp_state.as_str() {
                parsed if parsed.starts_with("parsed_") => "recorded",
                other => other,
            }),
        );
        record.set("timestamp_raw", value(&detection.timestamp_raw));
        // The zone the stored instant came from, never an assumed shift.
        record.set("timestamp_zone_source", opt_value(detection.source_timezone.as_deref()));
        record.set("timestamp_parse_state", value(&detection.timestamp_state));
        record.set("event_type", value("mpdetection_detection"));
        record.set(
            "description",
            value(if detection.parse_state == "parsed" {
                "MPDetection 로그의 DETECTION 기록"
            } else {
                "MPDetection DETECTION 행을 해석하지 못함(원문 보존)"
            }),
        );
        record.set("section", value(SECTION_THREAT));
        record.set("section_label", value(section_label(SECTION_THREAT)));
        record.set("source", value(SOURCE_MPDETECTION));
        record.set("source_label", value(SOURCE_LABEL_MPDETECTION));
        record.set("support_state", value(&detection.parse_state));
        record.set("support_source", value(SRC_PAYLOAD));
        record.set("title", value("탐지 기록(MPDetection)"));
        record.set("threat_name", opt_value(detection.threat_name.as_deref()));
        record.set("detection_id_state", value("absent"));
        let resource = detection.resource_raw.clone().unwrap_or_default();
        let parsed = resources_of(&resource);
        record.set("detail", value(&resource));
        record.set("resources_raw", value(&resource));
        record.set(
            "resource_count",
            if resource.is_empty() { Cell::Null } else { Cell::Int(parsed.len() as i64) },
        );
        record.set("target_path", if parsed.len() == 1 { value(&parsed[0].path) } else { Cell::Null });
        for item in &parsed {
            record.child(
                "DefenderResources",
                vec![value(&item.raw), opt_value(item.kind.as_deref()), value(&item.path)],
            );
        }
        record.set("raw_line", Cell::Text(detection.raw_line.clone()));
        record.set("line_number", Cell::Int(detection.line_number));
        record.set("source_file", value(&detection.source_file));
        record.set("result", value("unknown"));
        record.set("result_basis", value("source:mpdetection_has_no_action_record"));
        record.set(
            "search_text",
            Cell::Text(search_text(&[
                detection.threat_name.as_deref().unwrap_or(""),
                resource.as_str(),
                detection.raw_line.as_str(),
                "mpdetection_detection",
            ])),
        );
        let mut source = ctx
            .facts
            .source_from_row(
                &path,
                support::RECORDS_TABLE,
                detection.rowid,
                Some(&detection.source_file),
                Some("MPDetection DETECTION 행"),
            )?
            .ok_or_else(|| anyhow::anyhow!("MPDetection facts 출처가 없습니다"))?;
        source.artifact = support::ARTIFACT.to_string();
        record.source(Some(source));
        stored.push(Stored {
            record_id,
            section: "threat".to_string(),
            event_type: "mpdetection_detection".to_string(),
            event_id: None,
            event_record_id: None,
            timestamp: detection.timestamp.clone(),
            detection_id: String::new(),
            detection_time: detection.timestamp.clone(),
            threat_name: detection.threat_name.clone().unwrap_or_default(),
            action: String::new(),
            action_performer: String::new(),
            result: Some("unknown".to_string()),
            result_basis: Some("source:mpdetection_has_no_action_record".to_string()),
            scan: None,
        });
        db.write(record)?;
    }
    Ok(files.into_iter().map(|row| MpFile { row }).collect())
}

// --- detections -------------------------------------------------------------

fn detections(ctx: &Ctx, db: &mut DerivedDb, stored: &[Stored]) -> Result<()> {
    let mut keys: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, row) in stored.iter().enumerate() {
        if row.section != "threat" && row.section != "threat_action" {
            continue;
        }
        // A trusted Detection ID is the only reason to group two events.
        let key = if row.detection_id.is_empty() {
            row.record_id.clone()
        } else {
            row.detection_id.clone()
        };
        if !groups.contains_key(&key) {
            keys.push(key.clone());
        }
        groups.entry(key).or_default().push(index);
    }

    for key in keys {
        let members = &groups[&key];
        let detection_key = uuid::Uuid::new_v4().to_string();
        let identity = if stored[members[0]].detection_id.is_empty() { "record" } else { "detection_id" };
        let detection_members: Vec<&Stored> = members.iter().map(|index| &stored[*index]).collect();
        let detection_event = detection_members
            .iter()
            .copied()
            .filter(|row| row.section == "threat")
            .min_by(|a, b| order_key(a).cmp(&order_key(b)));
        let representative = detection_event
            .or_else(|| detection_members.iter().copied().min_by(|a, b| order_key(a).cmp(&order_key(b))));
        let action_event = detection_members
            .iter()
            .copied()
            .filter(|row| row.section == "threat_action")
            .min_by(|a, b| order_key(a).cmp(&order_key(b)));
        let times: Vec<&String> = detection_members.iter().filter_map(|row| row.timestamp.as_ref()).collect();
        db.insert_child(
            "DefenderDetections",
            &[
                value(&detection_key),
                value(ctx.host_id),
                value(ctx.dataset_id),
                value(&stored[members[0]].detection_id),
                value(identity),
                opt_value(
                    detection_members
                        .iter()
                        .map(|row| row.threat_name.as_str())
                        .find(|name| !name.is_empty()),
                ),
                opt_value(times.iter().min().map(|time| time.as_str())),
                opt_value(times.iter().max().map(|time| time.as_str())),
                Cell::Int(detection_members.len() as i64),
                Cell::Int(detection_members.iter().filter(|row| row.section == "threat").count() as i64),
                Cell::Int(detection_members.iter().filter(|row| row.section == "threat_action").count() as i64),
                Cell::Int(
                    detection_members
                        .iter()
                        .filter(|row| row.result.as_deref() == Some("failure"))
                        .count() as i64,
                ),
                Cell::Int(detection_members.iter().filter(|row| row.timestamp.is_none()).count() as i64),
                opt_value(representative.map(|row| row.record_id.as_str())),
                value(if detection_event.is_some() {
                    "earliest_recorded_detection_event"
                } else {
                    "earliest_recorded_member"
                }),
                opt_value(action_event.map(|row| row.record_id.as_str())),
                opt_value(action_event.and_then(|row| row.timestamp.as_deref())),
                opt_value(action_event.map(|row| row.action.as_str())),
                opt_value(action_event.map(|row| row.action_performer.as_str())),
                opt_value(action_event.and_then(|row| row.result.as_deref())),
                opt_value(action_event.and_then(|row| row.result_basis.as_deref())),
                value("earliest_recorded_action_event(tie:event_record_id)"),
            ],
        )?;
        for (ordinal, member) in detection_members.iter().enumerate() {
            db.insert_child(
                "DefenderDetectionMembers",
                &[
                    value(&detection_key),
                    Cell::Int(ordinal as i64),
                    value(&member.record_id),
                    value(match member.section.as_str() {
                        "threat_action" => "action",
                        _ if member.event_type == "mpdetection_detection" => "mpdetection",
                        _ => "detection",
                    }),
                    member.event_id.map(Cell::Int).unwrap_or(Cell::Null),
                    opt_value(member.timestamp.as_deref()),
                ],
            )?;
        }
    }
    Ok(())
}

/// Recorded time first, then the event record id; untimed rows stay last.
fn order_key(row: &Stored) -> (bool, String, i64) {
    (
        row.timestamp.is_none(),
        row.timestamp.clone().unwrap_or_default(),
        row.event_record_id.unwrap_or(i64::MAX),
    )
}

// --- scans ------------------------------------------------------------------
/// The earliest recorded event of one kind inside a scan group.
fn pick<'a>(members: &[&'a Stored], event_type: &str) -> Option<&'a Stored> {
    members
        .iter()
        .copied()
        .filter(|row| row.event_type == event_type)
        .min_by(|a, b| order_key(a).cmp(&order_key(b)))
}

/// Scan lifecycle kinds; offline-scan configuration (2030/2031) is no scan.
const SCAN_LIFECYCLE: &[&str] =
    &["scan_started", "scan_completed", "scan_cancelled", "scan_paused", "scan_resumed", "scan_error"];

/// The first non-empty value of one scan fact across the ordered members.
fn first_fact<'a>(facts: &[&'a ScanFacts], field: impl Fn(&'a ScanFacts) -> &'a str) -> Option<&'a str> {
    facts.iter().map(|facts| field(facts)).find(|found| !found.is_empty())
}

fn scans(ctx: &Ctx, db: &mut DerivedDb, stored: &[Stored]) -> Result<()> {
    let mut keys: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, row) in stored.iter().enumerate() {
        let Some(scan) = &row.scan else { continue };
        if !SCAN_LIFECYCLE.contains(&row.event_type.as_str()) {
            continue;
        }
        let key = if scan.scan_id.is_empty() { row.record_id.clone() } else { scan.scan_id.clone() };
        if !groups.contains_key(&key) {
            keys.push(key.clone());
        }
        groups.entry(key).or_default().push(index);
    }
    for key in keys {
        let members: Vec<&Stored> = groups[&key].iter().map(|index| &stored[*index]).collect();
        let start = pick(&members, "scan_started");
        let completion = pick(&members, "scan_completed");
        let cancel = pick(&members, "scan_cancelled");
        let error = pick(&members, "scan_error");
        let pauses = members.iter().filter(|row| row.event_type == "scan_paused").count() as i64;
        let resumes = members.iter().filter(|row| row.event_type == "scan_resumed").count() as i64;
        // Lifecycle facts first, then the other members in log order; the
        // Scan ID is the group key and survives a rotated-out start.
        let mut ordered: Vec<&Stored> = [start, completion, cancel, error].into_iter().flatten().collect();
        let mut rest: Vec<&Stored> = members
            .iter()
            .copied()
            .filter(|row| !ordered.iter().any(|picked| std::ptr::eq(*picked, *row)))
            .collect();
        rest.sort_by_key(|row| order_key(row));
        ordered.extend(rest);
        let facts: Vec<&ScanFacts> = ordered.iter().filter_map(|row| row.scan.as_ref()).collect();
        let scan_id = first_fact(&facts, |facts| facts.scan_id.as_str()).unwrap_or("");
        let scan_type = first_fact(&facts, |facts| facts.scan_type.as_str());
        let scan_parameters = first_fact(&facts, |facts| facts.scan_parameters.as_str());
        let user = facts.iter().find(|facts| !facts.user_raw.is_empty() || !facts.user_sid.is_empty());
        // Only an observed pair states a pairing; a missing partner is not a stop.
        let pairing = match (start.is_some(), completion.is_some(), cancel.is_some(), error.is_some()) {
            (true, true, _, _) => "start_and_completion",
            (true, false, true, _) => "start_and_cancel",
            (true, false, false, true) => "start_and_error",
            (true, false, false, false) => "start_only",
            (false, true, _, _) => "completion_only",
            (false, false, true, _) => "cancel_only",
            (false, false, false, true) => "error_only",
            _ => "unknown",
        };
        let elapsed = match (start.and_then(|row| row.timestamp.as_deref()), completion.and_then(|row| row.timestamp.as_deref())) {
            (Some(from), Some(to)) => protection::gap(from, to),
            _ => Cell::Null,
        };
        let duration = completion.and_then(|row| row.scan.as_ref());
        db.insert_child(
            "DefenderScans",
            &[
                value(&uuid::Uuid::new_v4().to_string()),
                value(ctx.host_id),
                value(ctx.dataset_id),
                value(scan_id),
                value(if scan_id.is_empty() { "absent" } else { "present" }),
                opt_value(scan_type),
                opt_value(scan_parameters),
                value(if start.is_some() {
                    "start_event"
                } else if completion.is_some() {
                    "completion_event"
                } else if cancel.is_some() {
                    "cancel_event"
                } else if error.is_some() {
                    "error_event"
                } else {
                    "member_event"
                }),
                opt_value(start.map(|row| row.record_id.as_str())),
                opt_value(start.and_then(|row| row.timestamp.as_deref())),
                opt_value(completion.map(|row| row.record_id.as_str())),
                opt_value(completion.and_then(|row| row.timestamp.as_deref())),
                opt_value(cancel.map(|row| row.record_id.as_str())),
                opt_value(cancel.and_then(|row| row.timestamp.as_deref())),
                opt_value(error.map(|row| row.record_id.as_str())),
                opt_value(error.and_then(|row| row.timestamp.as_deref())),
                Cell::Int(pauses),
                Cell::Int(resumes),
                opt_value(duration.map(|facts| facts.duration_raw.as_str())),
                duration.and_then(|facts| facts.duration_seconds).map(Cell::Int).unwrap_or(Cell::Null),
                elapsed,
                value(pairing),
                value("observed_scan_id_events"),
                Cell::Int(members.len() as i64),
                opt_value(user.map(|facts| facts.user_sid.as_str())),
                opt_value(user.map(|facts| facts.user_raw.as_str())),
            ],
        )?;
    }
    Ok(())
}

// --- summaries and candidates ----------------------------------------------

fn summaries(ctx: &Ctx, db: &mut DerivedDb, stored: &[Stored]) -> Result<()> {
    let mut kinds: BTreeMap<&str, Vec<&Stored>> = BTreeMap::new();
    for row in stored {
        kinds.entry(row.event_type.as_str()).or_default().push(row);
    }
    for (event_type, rows) in kinds {
        let times: Vec<&String> = rows.iter().filter_map(|row| row.timestamp.as_ref()).collect();
        let mut distinct: Vec<&str> = rows
            .iter()
            .filter_map(|row| match (&row.scan, row.detection_id.as_str()) {
                (Some(scan), _) if !scan.scan_id.is_empty() => Some(scan.scan_id.as_str()),
                (_, detection) if !detection.is_empty() => Some(detection),
                _ => None,
            })
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        db.insert_child(
            "DefenderActivitySummaries",
            &[
                value(&uuid::Uuid::new_v4().to_string()),
                value(ctx.host_id),
                value(ctx.dataset_id),
                value(event_type),
                value(&rows[0].section),
                // Period-scoped counts come from the stored rows themselves.
                value("observed_all"),
                Cell::Int(rows.len() as i64),
                Cell::Int(rows.iter().filter(|row| row.timestamp.is_none()).count() as i64),
                opt_value(times.iter().min().map(|time| time.as_str())),
                opt_value(times.iter().max().map(|time| time.as_str())),
                Cell::Int(distinct.len() as i64),
            ],
        )?;
    }
    Ok(())
}

/// Equal threat name and detection instant across the two sources is a
/// candidate only; duplicates stay as two records (A06). The EVTX record time
/// is when the event was written, not when the threat was detected.
fn candidates(ctx: &Ctx, db: &mut DerivedDb, stored: &[Stored]) -> Result<()> {
    let events: Vec<&Stored> = stored
        .iter()
        .filter(|row| row.event_type != "mpdetection_detection" && row.section == "threat")
        .collect();
    for row in stored.iter().filter(|row| row.event_type == "mpdetection_detection") {
        let Some(detected) = row.detection_time.as_deref() else { continue };
        if row.threat_name.is_empty() {
            continue;
        }
        for event in &events {
            if event.threat_name != row.threat_name || event.detection_time.as_deref() != Some(detected) {
                continue;
            }
            db.insert_child(
                "DefenderSourceCandidates",
                &[
                    value(&uuid::Uuid::new_v4().to_string()),
                    value(ctx.host_id),
                    value(ctx.dataset_id),
                    value(&event.record_id),
                    value(&row.record_id),
                    value("candidate"),
                    value("same_threat_name_and_detection_time"),
                    value(&row.threat_name),
                    value(detected),
                ],
            )?;
        }
    }
    Ok(())
}

// --- observation range ------------------------------------------------------

fn input_observations(
    ctx: &Ctx,
    db: &mut DerivedDb,
    mut stats: BTreeMap<String, LogStats>,
    files: &[MpFile],
) -> Result<()> {
    let inputs = LogInputs::read(ctx, |name| name.to_lowercase().contains("defender"))?;
    let mut seen: Vec<String> = Vec::new();
    for input in &inputs.logs {
        let name = input.log_name.as_str();
        let source = inputs.source(ctx, input)?;
        let found = stats.remove(name).unwrap_or_default();
        seen.push(name.to_lowercase());
        eventlog_observation(
            ctx, db, name, input.source_file.as_deref().unwrap_or(""), input.facts_db.as_deref().unwrap_or(""),
            input.facts_table.as_deref().unwrap_or(""), input.collection_state(), input.input_rows, &found,
            input.error.as_deref(), Some(&source),
        )?;
    }
    let remaining: Vec<(String, LogStats)> = stats.into_iter().collect();
    for (table, found) in remaining {
        let facts = ctx.facts.by_stem(&table);
        seen.push(table.to_lowercase());
        eventlog_observation(
            ctx,
            db,
            &table,
            &found.source_file.clone(),
            facts.map(|facts| facts.relative.as_str()).unwrap_or(""),
            &table,
            "unknown",
            None,
            &found,
            None,
            None,
        )?;
    }
    // A Defender log that was never collected is not a log with zero events.
    for log in EXPECTED_LOGS {
        if seen.iter().any(|name| name == &log.to_lowercase()) {
            continue;
        }
        // Existing facts without a manifest entry stay unknown, not absent.
        let facts = ctx.facts.by_stem(log);
        let mut values = vec![
            value(&uuid::Uuid::new_v4().to_string()),
            value(ctx.host_id),
            value(ctx.dataset_id),
            value("eventlog"),
            value(log),
            Cell::Null,
            opt_value(facts.map(|facts| facts.relative.as_str())),
            opt_value(facts.map(|_| *log)),
            value(if facts.is_none() { inputs.absent_state() } else { "unknown" }),
        ];
        values.extend(std::iter::repeat(Cell::Null).take(INPUT_OBSERVATIONS.len() - values.len()));
        db.insert_child("DefenderInputObservations", &values)?;
    }

    let support_db = support::support_path(ctx.out_dir);
    for file in files {
        let row = &file.row;
        let source = ctx
            .facts
            .source_from_row(
                &support_db,
                support::FILES_TABLE,
                row.rowid,
                Some(&row.source_file),
                Some("mpdetection_input"),
            )?
            .map(|mut source| {
                source.artifact = support::ARTIFACT.to_string();
                source
            })
            .ok_or_else(|| anyhow::anyhow!("MPDetection 입력 출처가 없습니다"))?;
        db.insert_child(
            "DefenderInputObservations",
            &[
                value(&uuid::Uuid::new_v4().to_string()),
                value(ctx.host_id),
                value(ctx.dataset_id),
                value("mpdetection"),
                value("MPDetection"),
                value(&row.source_file),
                value(support::SUPPORT_DB),
                value(support::FILES_TABLE),
                value(if row.decode_state == support::READ_FAILED {
                    "read_failed"
                } else if row.decode_state == support::UNSUPPORTED_ENCODING {
                    "unsupported_encoding"
                } else if row.decode_state == support::UNDETERMINED_ENCODING {
                    "undetermined_encoding"
                } else {
                    "collected"
                }),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                opt_value(row.encoding.as_deref()),
                opt_value(row.bom.as_deref()),
                value(&row.decode_state),
                opt_value(row.decode_error.as_deref()),
                row.byte_count.map(Cell::Int).unwrap_or(Cell::Null),
                row.line_count.map(Cell::Int).unwrap_or(Cell::Null),
                row.detection_line_count.map(Cell::Int).unwrap_or(Cell::Null),
                row.other_line_count.map(Cell::Int).unwrap_or(Cell::Null),
                row.unparsed_time_count.map(Cell::Int).unwrap_or(Cell::Null),
                row.incomplete_detection_count.map(Cell::Int).unwrap_or(Cell::Null),
                Cell::Null,
                value(&source.dataset),
                value(&source.db),
                value(&source.table),
                Cell::Int(source.rowid),
            ],
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn eventlog_observation(
    ctx: &Ctx,
    db: &mut DerivedDb,
    log_name: &str,
    source_file: &str,
    facts_db: &str,
    facts_table: &str,
    state: &str,
    input_rows: Option<i64>,
    stats: &LogStats,
    error: Option<&str>,
    source: Option<&SourceRef>,
) -> Result<()> {
    db.insert_child(
        "DefenderInputObservations",
        &[
            value(&uuid::Uuid::new_v4().to_string()),
            value(ctx.host_id),
            value(ctx.dataset_id),
            value("eventlog"),
            value(log_name),
            value(if source_file.is_empty() { stats.source_file.as_str() } else { source_file }),
            value(facts_db),
            value(facts_table),
            value(state),
            input_rows.map(Cell::Int).unwrap_or(Cell::Null),
            Cell::Int(stats.attributed + stats.foreign),
            Cell::Int(stats.attributed),
            Cell::Int(stats.foreign),
            Cell::Int(stats.unmapped),
            Cell::Int(stats.corrupted),
            Cell::Int(stats.untimed),
            opt_value(stats.first.as_deref()),
            opt_value(stats.last.as_deref()),
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
            opt_value(error),
            opt_value(source.map(|source| source.dataset.as_str())),
            opt_value(source.map(|source| source.db.as_str())),
            opt_value(source.map(|source| source.table.as_str())),
            source.map(|source| Cell::Int(source.rowid)).unwrap_or(Cell::Null),
        ],
    )
}

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "Defender" (
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
  "section" TEXT,
  "section_label" TEXT,
  "source" TEXT,
  "source_label" TEXT,
  "support_state" TEXT,
  "support_source" TEXT,
  "channel_state" TEXT,
  "title" TEXT,
  "detail" TEXT,
  "severity" TEXT,
  "severity_id" INTEGER,
  "category" TEXT,
  "category_id" INTEGER,
  "threat_name" TEXT,
  "threat_id" TEXT,
  "target_path" TEXT,
  "resources_raw" TEXT,
  "resource_count" INTEGER,
  "detection_id" TEXT,
  "detection_id_state" TEXT,
  "detection_type" TEXT,
  "detection_origin" TEXT,
  "detection_source" TEXT,
  "detection_user" TEXT,
  "process" TEXT,
  "action" TEXT,
  "action_id" INTEGER,
  "action_time" TEXT,
  "additional_actions" TEXT,
  "additional_actions_id" INTEGER,
  "remediation_user" TEXT,
  "status_raw" TEXT,
  "error_code" TEXT,
  "error_description" TEXT,
  "result" TEXT,
  "result_basis" TEXT,
  "protection_feature" TEXT,
  "protection_mode" TEXT,
  "asr_rule_id" TEXT,
  "asr_rule_name" TEXT,
  "asr_rule_name_source" TEXT,
  "network_destination_raw" TEXT,
  "network_destination_kind" TEXT,
  "network_destination_scheme" TEXT,
  "network_destination_host" TEXT,
  "network_destination_ip" TEXT,
  "network_destination_port" INTEGER,
  "detection_time_raw" TEXT,
  "detection_time" TEXT,
  "detection_time_state" TEXT,
  "detection_time_zone_source" TEXT,
  "policy_version" TEXT,
  "policy_rule_id" TEXT,
  "policy_enforcement_level" TEXT,
  "policy_action_type" TEXT,
  "policy_audit_reason" TEXT,
  "policy_event_timestamp_raw" TEXT,
  "whc_state_raw" TEXT,
  "whc_state_id" INTEGER,
  "scan_id" TEXT,
  "scan_type" TEXT,
  "scan_type_index" INTEGER,
  "scan_parameters" TEXT,
  "scan_parameters_index" INTEGER,
  "scan_trigger" TEXT,
  "scan_trigger_index" INTEGER,
  "scan_resources" TEXT,
  "scan_duration_raw" TEXT,
  "scan_duration_seconds" INTEGER,
  "signature_version_current" TEXT,
  "signature_version_previous" TEXT,
  "engine_version_current" TEXT,
  "engine_version_previous" TEXT,
  "signature_type" TEXT,
  "signature_type_index" INTEGER,
  "update_type" TEXT,
  "update_stage" TEXT,
  "update_source" TEXT,
  "update_source_path" TEXT,
  "cloud_intelligence_type" TEXT,
  "cloud_intelligence_version" TEXT,
  "persistence_path" TEXT,
  "product_name" TEXT,
  "product_version" TEXT,
  "platform_version" TEXT,
  "engine_version" TEXT,
  "signature_version" TEXT,
  "rtp_state_raw" TEXT,
  "oa_state_raw" TEXT,
  "ioav_state_raw" TEXT,
  "bm_state_raw" TEXT,
  "product_status" TEXT,
  "engine_up_to_date" TEXT,
  "platform_up_to_date" TEXT,
  "av_signature_version" TEXT,
  "as_signature_version" TEXT,
  "av_signature_age_raw" TEXT,
  "as_signature_age_raw" TEXT,
  "av_signature_created" TEXT,
  "av_signature_created_raw" TEXT,
  "as_signature_created" TEXT,
  "as_signature_created_raw" TEXT,
  "last_quick_scan_age_raw" TEXT,
  "last_quick_scan_start" TEXT,
  "last_quick_scan_start_raw" TEXT,
  "last_quick_scan_end" TEXT,
  "last_quick_scan_end_raw" TEXT,
  "last_quick_scan_source" TEXT,
  "last_full_scan_age_raw" TEXT,
  "last_full_scan_start" TEXT,
  "last_full_scan_start_raw" TEXT,
  "last_full_scan_end" TEXT,
  "last_full_scan_end_raw" TEXT,
  "last_full_scan_source" TEXT,
  "latest_engine_version" TEXT,
  "latest_platform_version" TEXT,
  "feature_name" TEXT,
  "failure_type" TEXT,
  "failure_type_index" INTEGER,
  "failure_id" TEXT,
  "failure_reason" TEXT,
  "recommendation" TEXT,
  "exception_code" TEXT,
  "engine_code" TEXT,
  "config_target_raw" TEXT,
  "config_target" TEXT,
  "config_scope" TEXT,
  "config_old_raw" TEXT,
  "config_old_value" TEXT,
  "config_old_state" TEXT,
  "config_new_raw" TEXT,
  "config_new_value" TEXT,
  "config_new_state" TEXT,
  "config_change_kind" TEXT,
  "config_exclusion_kind" TEXT,
  "config_exclusion_value" TEXT,
  "config_protection_setting" TEXT,
  "history_cleared_time" TEXT,
  "history_cleared_time_raw" TEXT,
  "account_role" TEXT,
  "account_name_source" TEXT,
  "event_user_raw" TEXT,
  "event_user_domain" TEXT,
  "event_user_name" TEXT,
  "event_user_sid" TEXT,
  "system_user_sid" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  "channel" TEXT,
  "provider_guid" TEXT,
  "provider_guid_state" TEXT,
  "schema_version" INTEGER,
  "computer" TEXT,
  "event_record_id" TEXT,
  "level_name" TEXT,
  "keywords_raw" TEXT,
  "process_id" TEXT,
  "thread_id" TEXT,
  "activity_id" TEXT,
  "related_activity_id" TEXT,
  "facts_status" TEXT,
  "facts_error" TEXT,
  "payload_shape" TEXT,
  "payload_field_count" INTEGER,
  "event_data_raw" TEXT,
  "record_key" TEXT,
  "source_file" TEXT,
  "line_number" INTEGER,
  "raw_line" TEXT,
  "timestamp_raw" TEXT,
  "timestamp_state" TEXT,
  "timestamp_zone_source" TEXT,
  "timestamp_parse_state" TEXT,
  "search_text" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'Defender'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_Defender_time" ON "Defender"(timestamp, record_id);
CREATE INDEX "idx_Defender_account" ON "Defender"(account_sid, timestamp);
CREATE INDEX "idx_Defender_section" ON "Defender"(section, timestamp);
CREATE INDEX "idx_Defender_event" ON "Defender"(event_id, timestamp);
CREATE TABLE "DefenderEventFields" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "field_name" TEXT,
  "field_value" TEXT,
  "field_scope" TEXT,
  PRIMARY KEY(record_id, ordinal),
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_DefenderEventFields_name" ON "DefenderEventFields"(field_name);
CREATE TABLE "DefenderResources" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "resource_raw" TEXT,
  "resource_kind" TEXT,
  "resource_value" TEXT,
  PRIMARY KEY(record_id, ordinal),
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderAccountRoles" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "role" TEXT NOT NULL,
  "raw_value" TEXT,
  "domain" TEXT,
  "name" TEXT,
  "sid" TEXT,
  "name_source" TEXT,
  PRIMARY KEY(record_id, ordinal),
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderDetections" (
  "detection_key" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "detection_id" TEXT,
  "identity_basis" TEXT NOT NULL,
  "threat_name" TEXT,
  "first_timestamp" TEXT,
  "last_timestamp" TEXT,
  "event_count" INTEGER,
  "detection_event_count" INTEGER,
  "action_event_count" INTEGER,
  "failed_action_count" INTEGER,
  "untimed_count" INTEGER,
  "representative_record_id" TEXT,
  "representative_basis" TEXT,
  "action_record_id" TEXT,
  "action_time" TEXT,
  "action" TEXT,
  "action_performer" TEXT,
  "action_result" TEXT,
  "action_result_basis" TEXT,
  "action_selection_rule" TEXT,
  PRIMARY KEY(detection_key),
  FOREIGN KEY(representative_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(action_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderDetectionMembers" (
  "detection_key" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "record_id" TEXT NOT NULL,
  "member_role" TEXT NOT NULL,
  "event_id" INTEGER,
  "timestamp" TEXT,
  PRIMARY KEY(detection_key, ordinal),
  FOREIGN KEY(detection_key) REFERENCES "DefenderDetections"("detection_key") ON DELETE CASCADE,
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderScans" (
  "scan_entry_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "scan_id" TEXT,
  "scan_id_state" TEXT NOT NULL,
  "scan_type" TEXT,
  "scan_parameters" TEXT,
  "type_basis" TEXT,
  "start_record_id" TEXT,
  "start_time" TEXT,
  "completion_record_id" TEXT,
  "completion_time" TEXT,
  "cancel_record_id" TEXT,
  "cancel_time" TEXT,
  "error_record_id" TEXT,
  "error_time" TEXT,
  "pause_count" INTEGER,
  "resume_count" INTEGER,
  "reported_duration_raw" TEXT,
  "reported_duration_seconds" INTEGER,
  "elapsed_seconds" INTEGER,
  "pairing_state" TEXT NOT NULL,
  "pairing_basis" TEXT,
  "event_count" INTEGER,
  "user_sid" TEXT,
  "user_raw" TEXT,
  PRIMARY KEY(scan_entry_id),
  FOREIGN KEY(start_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(completion_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(cancel_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(error_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderProtectionStates" (
  "state_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "feature" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "state_raw" TEXT,
  "state_basis" TEXT NOT NULL,
  "timestamp" TEXT,
  "timestamp_kind" TEXT,
  "record_id" TEXT NOT NULL,
  "event_id" INTEGER,
  "event_record_id" INTEGER,
  "observation_ordinal" INTEGER,
  "previous_state" TEXT,
  "change_kind" TEXT,
  "order_ambiguous" INTEGER,
  "same_time_count" INTEGER,
  "gap_seconds" INTEGER,
  "certainty" TEXT,
  PRIMARY KEY(state_id),
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_DefenderProtectionStates_feature" ON "DefenderProtectionStates"(feature, timestamp);
CREATE TABLE "DefenderProtectionIntervals" (
  "interval_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "feature" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "run_kind" TEXT,
  "run_start_time" TEXT,
  "run_start_record_id" TEXT,
  "run_end_time" TEXT,
  "run_end_record_id" TEXT,
  "observation_count" INTEGER,
  "next_state" TEXT,
  "next_observation_time" TEXT,
  "next_record_id" TEXT,
  "boundary_gap_seconds" INTEGER,
  "boundary_kind" TEXT,
  "prior_gap_seconds" INTEGER,
  "order_ambiguous" INTEGER,
  "claim" TEXT NOT NULL,
  PRIMARY KEY(interval_id),
  CHECK(claim = 'observed_endpoints_only'),
  FOREIGN KEY(run_start_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(run_end_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderProtectionLatest" (
  "latest_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "feature" TEXT NOT NULL,
  "state" TEXT,
  "certainty" TEXT NOT NULL,
  "tie_count" INTEGER,
  "record_id" TEXT,
  "state_basis" TEXT,
  "observation_count" INTEGER,
  "untimed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "scope" TEXT NOT NULL,
  PRIMARY KEY(latest_id),
  CHECK(state IS NOT NULL OR certainty <> 'confirmed'),
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderActivitySummaries" (
  "summary_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "summary_kind" TEXT NOT NULL,
  "section" TEXT,
  "scope" TEXT NOT NULL,
  "event_count" INTEGER,
  "untimed_count" INTEGER,
  "first_time" TEXT,
  "last_time" TEXT,
  "distinct_key_count" INTEGER,
  PRIMARY KEY(summary_id)
);
CREATE TABLE "DefenderSourceCandidates" (
  "candidate_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "primary_record_id" TEXT NOT NULL,
  "candidate_record_id" TEXT NOT NULL,
  "relation" TEXT NOT NULL,
  "match_basis" TEXT NOT NULL,
  "threat_name" TEXT,
  "timestamp" TEXT,
  PRIMARY KEY(candidate_id),
  CHECK(relation = 'candidate'),
  FOREIGN KEY(primary_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(candidate_record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE TABLE "DefenderInputObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "input_kind" TEXT NOT NULL,
  "log_name" TEXT,
  "source_file" TEXT,
  "facts_db" TEXT,
  "facts_table" TEXT,
  "collection_state" TEXT NOT NULL,
  "input_row_count" INTEGER,
  "event_count" INTEGER,
  "attributed_count" INTEGER,
  "foreign_provider_count" INTEGER,
  "unmapped_event_count" INTEGER,
  "corrupted_count" INTEGER,
  "untimed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "encoding" TEXT,
  "bom" TEXT,
  "decode_state" TEXT,
  "decode_error" TEXT,
  "byte_count" INTEGER,
  "line_count" INTEGER,
  "detection_line_count" INTEGER,
  "other_line_count" INTEGER,
  "unparsed_time_count" INTEGER,
  "incomplete_detection_count" INTEGER,
  "error" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(observation_id)
);
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
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1),('defender',5);
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
    "section",
    "section_label",
    "source",
    "source_label",
    "support_state",
    "support_source",
    "channel_state",
    "title",
    "detail",
    "severity",
    "severity_id",
    "category",
    "category_id",
    "threat_name",
    "threat_id",
    "target_path",
    "resources_raw",
    "resource_count",
    "detection_id",
    "detection_id_state",
    "detection_type",
    "detection_origin",
    "detection_source",
    "detection_user",
    "process",
    "action",
    "action_id",
    "action_time",
    "additional_actions",
    "additional_actions_id",
    "remediation_user",
    "status_raw",
    "error_code",
    "error_description",
    "result",
    "result_basis",
    "protection_feature",
    "protection_mode",
    "asr_rule_id",
    "asr_rule_name",
    "asr_rule_name_source",
    "network_destination_raw",
    "network_destination_kind",
    "network_destination_scheme",
    "network_destination_host",
    "network_destination_ip",
    "network_destination_port",
    "detection_time_raw",
    "detection_time",
    "detection_time_state",
    "detection_time_zone_source",
    "policy_version",
    "policy_rule_id",
    "policy_enforcement_level",
    "policy_action_type",
    "policy_audit_reason",
    "policy_event_timestamp_raw",
    "whc_state_raw",
    "whc_state_id",
    "scan_id",
    "scan_type",
    "scan_type_index",
    "scan_parameters",
    "scan_parameters_index",
    "scan_trigger",
    "scan_trigger_index",
    "scan_resources",
    "scan_duration_raw",
    "scan_duration_seconds",
    "signature_version_current",
    "signature_version_previous",
    "engine_version_current",
    "engine_version_previous",
    "signature_type",
    "signature_type_index",
    "update_type",
    "update_stage",
    "update_source",
    "update_source_path",
    "cloud_intelligence_type",
    "cloud_intelligence_version",
    "persistence_path",
    "product_name",
    "product_version",
    "platform_version",
    "engine_version",
    "signature_version",
    "rtp_state_raw",
    "oa_state_raw",
    "ioav_state_raw",
    "bm_state_raw",
    "product_status",
    "engine_up_to_date",
    "platform_up_to_date",
    "av_signature_version",
    "as_signature_version",
    "av_signature_age_raw",
    "as_signature_age_raw",
    "av_signature_created",
    "av_signature_created_raw",
    "as_signature_created",
    "as_signature_created_raw",
    "last_quick_scan_age_raw",
    "last_quick_scan_start",
    "last_quick_scan_start_raw",
    "last_quick_scan_end",
    "last_quick_scan_end_raw",
    "last_quick_scan_source",
    "last_full_scan_age_raw",
    "last_full_scan_start",
    "last_full_scan_start_raw",
    "last_full_scan_end",
    "last_full_scan_end_raw",
    "last_full_scan_source",
    "latest_engine_version",
    "latest_platform_version",
    "feature_name",
    "failure_type",
    "failure_type_index",
    "failure_id",
    "failure_reason",
    "recommendation",
    "exception_code",
    "engine_code",
    "config_target_raw",
    "config_target",
    "config_scope",
    "config_old_raw",
    "config_old_value",
    "config_old_state",
    "config_new_raw",
    "config_new_value",
    "config_new_state",
    "config_change_kind",
    "config_exclusion_kind",
    "config_exclusion_value",
    "config_protection_setting",
    "history_cleared_time",
    "history_cleared_time_raw",
    "account_role",
    "account_name_source",
    "event_user_raw",
    "event_user_domain",
    "event_user_name",
    "event_user_sid",
    "system_user_sid",
    "event_id",
    "provider",
    "channel",
    "provider_guid",
    "provider_guid_state",
    "schema_version",
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
    "payload_shape",
    "payload_field_count",
    "event_data_raw",
    "record_key",
    "source_file",
    "line_number",
    "raw_line",
    "timestamp_raw",
    "timestamp_state",
    "timestamp_zone_source",
    "timestamp_parse_state",
    "search_text",
];

const EVENT_FIELDS: &[&str] = &["record_id", "ordinal", "field_name", "field_value", "field_scope"];

const RESOURCES: &[&str] = &["record_id", "ordinal", "resource_raw", "resource_kind", "resource_value"];

const ACCOUNT_ROLES: &[&str] = &[
    "record_id",
    "ordinal",
    "role",
    "raw_value",
    "domain",
    "name",
    "sid",
    "name_source",
];

const DETECTIONS: &[&str] = &[
    "detection_key",
    "host_id",
    "dataset_id",
    "detection_id",
    "identity_basis",
    "threat_name",
    "first_timestamp",
    "last_timestamp",
    "event_count",
    "detection_event_count",
    "action_event_count",
    "failed_action_count",
    "untimed_count",
    "representative_record_id",
    "representative_basis",
    "action_record_id",
    "action_time",
    "action",
    "action_performer",
    "action_result",
    "action_result_basis",
    "action_selection_rule",
];

const DETECTION_MEMBERS: &[&str] = &[
    "detection_key",
    "ordinal",
    "record_id",
    "member_role",
    "event_id",
    "timestamp",
];

const SCANS: &[&str] = &[
    "scan_entry_id",
    "host_id",
    "dataset_id",
    "scan_id",
    "scan_id_state",
    "scan_type",
    "scan_parameters",
    "type_basis",
    "start_record_id",
    "start_time",
    "completion_record_id",
    "completion_time",
    "cancel_record_id",
    "cancel_time",
    "error_record_id",
    "error_time",
    "pause_count",
    "resume_count",
    "reported_duration_raw",
    "reported_duration_seconds",
    "elapsed_seconds",
    "pairing_state",
    "pairing_basis",
    "event_count",
    "user_sid",
    "user_raw",
];

const PROTECTION_STATES: &[&str] = &[
    "state_id",
    "host_id",
    "dataset_id",
    "feature",
    "state",
    "state_raw",
    "state_basis",
    "timestamp",
    "timestamp_kind",
    "record_id",
    "event_id",
    "event_record_id",
    "observation_ordinal",
    "previous_state",
    "change_kind",
    "order_ambiguous",
    "same_time_count",
    "gap_seconds",
    "certainty",
];

const PROTECTION_INTERVALS: &[&str] = &[
    "interval_id",
    "host_id",
    "dataset_id",
    "feature",
    "state",
    "run_kind",
    "run_start_time",
    "run_start_record_id",
    "run_end_time",
    "run_end_record_id",
    "observation_count",
    "next_state",
    "next_observation_time",
    "next_record_id",
    "boundary_gap_seconds",
    "boundary_kind",
    "prior_gap_seconds",
    "order_ambiguous",
    "claim",
];

const PROTECTION_LATEST: &[&str] = &[
    "latest_id",
    "host_id",
    "dataset_id",
    "feature",
    "state",
    "certainty",
    "tie_count",
    "record_id",
    "state_basis",
    "observation_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "scope",
];

const SUMMARIES: &[&str] = &[
    "summary_id",
    "host_id",
    "dataset_id",
    "summary_kind",
    "section",
    "scope",
    "event_count",
    "untimed_count",
    "first_time",
    "last_time",
    "distinct_key_count",
];

const SOURCE_CANDIDATES: &[&str] = &[
    "candidate_id",
    "host_id",
    "dataset_id",
    "primary_record_id",
    "candidate_record_id",
    "relation",
    "match_basis",
    "threat_name",
    "timestamp",
];

const INPUT_OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "input_kind",
    "log_name",
    "source_file",
    "facts_db",
    "facts_table",
    "collection_state",
    "input_row_count",
    "event_count",
    "attributed_count",
    "foreign_provider_count",
    "unmapped_event_count",
    "corrupted_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "encoding",
    "bom",
    "decode_state",
    "decode_error",
    "byte_count",
    "line_count",
    "detection_line_count",
    "other_line_count",
    "unparsed_time_count",
    "incomplete_detection_count",
    "error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
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
    name: "Defender",
    table: "Defender",
    columns: MAIN,
    children: &[
        ChildSpec { table: "DefenderEventFields", columns: EVENT_FIELDS },
        ChildSpec { table: "DefenderResources", columns: RESOURCES },
        ChildSpec { table: "DefenderAccountRoles", columns: ACCOUNT_ROLES },
        ChildSpec { table: "DefenderDetections", columns: DETECTIONS },
        ChildSpec { table: "DefenderDetectionMembers", columns: DETECTION_MEMBERS },
        ChildSpec { table: "DefenderScans", columns: SCANS },
        ChildSpec { table: "DefenderProtectionStates", columns: PROTECTION_STATES },
        ChildSpec { table: "DefenderProtectionIntervals", columns: PROTECTION_INTERVALS },
        ChildSpec { table: "DefenderProtectionLatest", columns: PROTECTION_LATEST },
        ChildSpec { table: "DefenderActivitySummaries", columns: SUMMARIES },
        ChildSpec { table: "DefenderSourceCandidates", columns: SOURCE_CANDIDATES },
        ChildSpec { table: "DefenderInputObservations", columns: INPUT_OBSERVATIONS },
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

    const TABLE: &str = "Microsoft-Windows-Windows Defender%4Operational";
    const LOG: &str = "/evidence/Microsoft-Windows-Windows Defender%4Operational.evtx";

    struct Case {
        root: std::path::PathBuf,
    }

    impl Case {
        /// Facts rows must exist so every stored source coordinate is real.
        fn new(rows: usize) -> Self {
            let root = std::env::temp_dir().join(format!("wina-defender-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
            let facts = root.join(format!("EVENTLOG/{TABLE}.sqlite"));
            let conn = Connection::open(&facts).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE \"{TABLE}\"(EventData TEXT);
                 WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<{rows})
                 INSERT INTO \"{TABLE}\" SELECT '{{}}' FROM n;"
            ))
            .unwrap();
            drop(conn);
            stamp_facts_generation(&facts, "facts-old").unwrap();
            super::super::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
            Self { root }
        }

        fn build(&self, rows: Vec<Row>) -> Connection {
            let ctx = Ctx {
                out_dir: &self.root,
                target: &self.root,
                host_id: "host",
                dataset_id: "new",
                facts: FactsIndex::load(&self.root).unwrap(),
                meta: MetaLookup::load(&self.root).unwrap(),
            };
            build(&ctx, &EventLogOverviewCache::from_rows_for_tests(rows)).unwrap();
            Connection::open(self.root.join("_OVERVIEW/Defender.sqlite")).unwrap()
        }

        fn prepare(&self) {
            prepare_inputs(&self.root, &self.root, "facts-new").unwrap();
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn event(id: &str, ordinal: usize, time: &str, payload: &str) -> Row {
        Row::from([
            (
                "Provider".to_string(),
                "Microsoft-Windows-Windows Defender".to_string(),
            ),
            (
                "Channel".to_string(),
                "Microsoft-Windows-Windows Defender/Operational".to_string(),
            ),
            ("Computer".to_string(), "WIN-HOST".to_string()),
            ("EventID".to_string(), id.to_string()),
            ("EventRecordID".to_string(), ordinal.to_string()),
            ("LevelName".to_string(), "Information".to_string()),
            ("Keywords".to_string(), "0x8000000000000000".to_string()),
            ("UserID".to_string(), "S-1-5-18".to_string()),
            ("timestamp".to_string(), time.to_string()),
            ("EventData".to_string(), payload.to_string()),
            ("_record_key".to_string(), format!("{TABLE}::{ordinal}")),
            ("_source_file".to_string(), LOG.to_string()),
        ])
    }

    fn one<T: rusqlite::types::FromSql>(db: &Connection, sql: &str) -> T {
        db.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    // R01/R06/R07/R19 + A02: every documented event is a queryable row with
    // period-capable aggregates and separated account roles.
    #[test]
    fn documented_events_store_rows_roles_and_period_inputs() {
        let case = Case::new(4);
        let db = case.build(vec![
            event(
                "1013",
                1,
                "2026-03-02 10:00:00.000",
                r#"{"Timestamp":"2026-03-02T00:30:00Z","Domain":"WIN-HOST","User":"Administrator","SID":"S-1-5-21-1-2-3-500"}"#,
            ),
            event(
                "1000",
                2,
                "2026-03-02 11:00:00.000",
                r#"{"Scan ID":"{AAA}","Scan Type":"맬웨어 방지","Scan Parameters":"전체 검사","Domain":"NT AUTHORITY","User":"SYSTEM","SID":"S-1-5-18"}"#,
            ),
            event(
                "1001",
                3,
                "2026-03-02 11:00:10.000",
                r#"{"Scan ID":"{AAA}","Scan Type":"맬웨어 방지","Scan Parameters":"전체 검사","Scan Time Hours":"0","Scan Time Minutes":"00","Scan Time Seconds":"10","Domain":"NT AUTHORITY","User":"SYSTEM","SID":"S-1-5-18"}"#,
            ),
            event(
                "1013",
                4,
                "2026-03-05 09:00:00.000",
                r#"{"Timestamp":"2026-03-05T00:00:00Z","Domain":"NT AUTHORITY","User":"SYSTEM","SID":"S-1-5-18"}"#,
            ),
        ]);

        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender"), 4);
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(event_type) FROM (SELECT event_type FROM Defender WHERE event_id=1013 ORDER BY event_record_id)"),
            "history_cleared,history_cleared"
        );
        // Payload SID is the account; the security context stays separate.
        let (sid, system, role): (String, String, String) = db
            .query_row(
                "SELECT account_sid,system_user_sid,account_role FROM Defender WHERE event_record_id='1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(sid, "S-1-5-21-1-2-3-500");
        assert_eq!(system, "S-1-5-18");
        assert_eq!(role, "event_user");
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT COUNT(*) FROM DefenderAccountRoles WHERE role='security_context'"
            ),
            4
        );
        // R06: per-kind totals with first/last stay queryable per period.
        let (count, first, last): (i64, String, String) = db
            .query_row(
                "SELECT event_count,first_time,last_time FROM DefenderActivitySummaries WHERE summary_kind='scan_started'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!((count, first.as_str(), last.as_str()), (1, "2026-03-02 11:00:00.000", "2026-03-02 11:00:00.000"));
        // A02: Scan ID pairs the start and completion, duration from payload.
        let (state, secs, elapsed): (String, i64, i64) = db
            .query_row(
                "SELECT pairing_state,reported_duration_seconds,elapsed_seconds FROM DefenderScans WHERE scan_id='{AAA}'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!((state.as_str(), secs, elapsed), ("start_and_completion", 10, 10));
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_dataset_id<>'facts-old'"),
            0
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // RD-01: payload UTC instants are stored as KST like every other time;
    // the written value stays in a _raw column and FILETIME zero is no time.
    #[test]
    fn payload_utc_times_are_stored_as_kst_with_raw_kept() {
        let case = Case::new(2);
        let db = case.build(vec![
            event(
                "1013",
                1,
                "2026-08-23 07:34:59.772",
                r#"{"Timestamp":"2026-08-21T22:34:59Z","Domain":"WIN-HOST","User":"analyst"}"#,
            ),
            event(
                "1151",
                2,
                "2026-08-23 00:45:13.838",
                r#"{"RTP state":"사용 안 함","AV security intelligence creation time":"2026-08-22T07:31:42Z","AS security intelligence creation time":"2026-08-22T07:31:42Z","Last quick scan start time":"2026-08-21T22:35:00Z","Last quick scan end time":"2026-08-21T22:36:46Z","Last full scan start time":"1601-01-01T00:00:00Z","Last full scan end time":"1601-01-01T00:00:00Z"}"#,
            ),
        ]);
        let (cleared, cleared_raw): (String, String) = db
            .query_row(
                "SELECT history_cleared_time,history_cleared_time_raw FROM Defender WHERE event_id=1013",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(cleared, "2026-08-22 07:34:59.000");
        assert_eq!(cleared_raw, "2026-08-21T22:34:59Z");
        let health: (String, String, String, String, String) = db
            .query_row(
                "SELECT av_signature_created,as_signature_created,last_quick_scan_start,last_quick_scan_end,last_quick_scan_start_raw FROM Defender WHERE event_id=1151",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            health,
            (
                "2026-08-22 16:31:42.000".to_string(),
                "2026-08-22 16:31:42.000".to_string(),
                "2026-08-22 07:35:00.000".to_string(),
                "2026-08-22 07:36:46.000".to_string(),
                "2026-08-21T22:35:00Z".to_string(),
            )
        );
        let (full_start, full_start_raw): (Option<String>, String) = db
            .query_row(
                "SELECT last_full_scan_start,last_full_scan_start_raw FROM Defender WHERE event_id=1151",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(full_start, None);
        assert_eq!(full_start_raw, "1601-01-01T00:00:00Z");
    }

    // R03/R04/R05: actions keep their own rows; identity never comes from
    // similar time/name/path.
    #[test]
    fn detections_keep_action_history_and_never_merge_without_id() {
        let case = Case::new(4);
        let db = case.build(vec![
            event("1116", 1, "2026-04-01 01:00:00.000", r#"{"Detection ID":"{D1}","Threat Name":"Trojan:Win32/X","Severity Name":"심각","Category Name":"트로이 목마","Path":"file:_C:\\tmp\\a.exe","Process Name":"C:\\x.exe","Detection User":"WIN-HOST\\admin"}"#),
            event("1117", 2, "2026-04-01 01:00:05.000", r#"{"Detection ID":"{D1}","Threat Name":"Trojan:Win32/X","Action Name":"격리","Remediation User":"NT AUTHORITY\\SYSTEM","Additional Actions String":"재부팅 필요"}"#),
            event("1116", 3, "2026-04-02 02:00:00.000", r#"{"Threat Name":"Trojan:Win32/Y","Path":"file:_C:\\tmp\\b.exe"}"#),
            event("1116", 4, "2026-04-02 02:00:00.000", r#"{"Threat Name":"Trojan:Win32/Y","Path":"file:_C:\\tmp\\b.exe"}"#),
        ]);

        // Four source events stay four rows.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender"), 4);
        // The detection row keeps no borrowed action fields.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE event_id=1116 AND (action IS NOT NULL OR remediation_user IS NOT NULL)"),
            0
        );
        // One grouped detection for the trusted ID, two independent records.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetections"), 3);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetections WHERE identity_basis='record'"),
            2
        );
        let (action, performer, rule): (String, String, String) = db
            .query_row(
                "SELECT action,action_performer,action_selection_rule FROM DefenderDetections WHERE detection_id='{D1}'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(action, "격리");
        assert_eq!(performer, "NT AUTHORITY\\SYSTEM");
        assert!(rule.contains("earliest"));
        // Both members are linked back as evidence.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetectionMembers m JOIN DefenderDetections d ON d.detection_key=m.detection_key WHERE d.detection_id='{D1}'"),
            2
        );
    }

    // R08/R09/R14: resources, remediation user and results stay evidence-bound.
    #[test]
    fn resources_results_and_remediation_stay_separate() {
        let case = Case::new(3);
        let db = case.build(vec![
            event("1117", 1, "2026-04-03 03:00:00.000", r#"{"Detection ID":"{D2}","Threat Name":"T","Path":"file:_C:\\a.exe;file:_C:\\b.exe","Action Name":"제거","Remediation User":"WIN-HOST\\admin"}"#),
            event("1118", 2, "2026-04-03 03:10:00.000", r#"{"Detection ID":"{D3}","Threat Name":"T2","Action Name":"제거","Error Code":"0x80508023","Error Description":"실패"}"#),
            event("1116", 3, "2026-04-03 03:20:00.000", r#"{"Detection ID":"{D4}","Threat Name":"T3","Path":"file:_C:\\c.exe"}"#),
        ]);

        // Multiple resources keep the raw string and each target.
        let (path, raw, count): (Option<String>, String, i64) = db
            .query_row(
                "SELECT target_path,resources_raw,resource_count FROM Defender WHERE event_id=1117",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(path, None);
        assert!(raw.contains("b.exe"));
        assert_eq!(count, 2);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderResources WHERE resource_value='C:\\b.exe' AND resource_kind='file'"),
            1
        );
        // Action taken is reported success; the performer is not a result.
        let (result, basis, performer): (String, String, Option<String>) = db
            .query_row("SELECT result,result_basis,remediation_user FROM Defender WHERE event_id=1117", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(result, "success");
        assert!(basis.starts_with("event:"));
        assert_eq!(performer.as_deref(), Some("WIN-HOST\\admin"));
        assert_eq!(
            one::<String>(&db, "SELECT result FROM Defender WHERE event_id=1118"),
            "failure"
        );
        // Detection without a recorded action is unknown, never success.
        assert_eq!(
            one::<String>(&db, "SELECT result FROM Defender WHERE event_id=1116"),
            "unknown"
        );
    }

    // R02/R13/A04: per-feature states, boundaries and ties.
    #[test]
    fn protection_states_keep_boundaries_and_uncertainty() {
        let case = Case::new(5);
        let db = case.build(vec![
            event("1151", 1, "2026-08-01 00:00:00.000", r#"{"RTP state":"사용","OA state":"사용","IOAV state":"사용","BM state":"사용"}"#),
            event("5001", 2, "2026-08-14 03:15:12.000", "{}"),
            event("1151", 3, "2026-08-20 00:00:00.000", r#"{"RTP state":"사용 안 함","OA state":"사용 안 함","IOAV state":"사용 안 함","BM state":"사용 안 함"}"#),
            event("5000", 4, "2026-09-28 21:46:55.000", "{}"),
            event("5004", 5, "2026-09-29 00:00:00.000", "{}"),
        ]);

        // The routine first report (all on) is not stored; the off report, the
        // two explicit state events and the configuration change remain.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionStates WHERE feature='realtime_protection'"),
            4
        );
        // A configuration change is not an on/off state.
        assert_eq!(
            one::<String>(&db, "SELECT state FROM DefenderProtectionStates WHERE event_id=5004"),
            "unknown"
        );
        let (state, certainty): (String, String) = db
            .query_row("SELECT state,certainty FROM DefenderProtectionLatest WHERE feature='realtime_protection'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((state.as_str(), certainty.as_str()), ("on", "confirmed"));
        // The off run ends at its last observation; the gap is explicit.
        let (start, end, gap, kind): (String, String, i64, String) = db
            .query_row(
                "SELECT run_start_time,run_end_time,boundary_gap_seconds,boundary_kind FROM DefenderProtectionIntervals \
                 WHERE feature='realtime_protection' AND state='off'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(start, "2026-08-14 03:15:12.000");
        assert_eq!(end, "2026-08-20 00:00:00.000");
        assert_eq!(kind, "state_change");
        assert!(gap > 0);
        let (run_kind, start_record): (String, Option<String>) = db
            .query_row(
                "SELECT run_kind,run_start_record_id FROM DefenderProtectionIntervals WHERE feature='on_access' AND state='on' AND run_start_time='2026-08-01 00:00:00.000'",
                [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(run_kind, "initial_observation");
        // Its record was not stored, so no reference points at it.
        assert_eq!(start_record, None);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // 2026-10-14 user decision: routine heartbeats, unchanged health reports
    // and periodic history purges are not brought into _OVERVIEW.
    #[test]
    fn routine_reports_and_periodic_purges_are_not_stored() {
        let case = Case::new(10);
        let on = r#"{"RTP state":"사용","OA state":"사용"}"#;
        let db = case.build(vec![
            event("1150", 1, "2026-08-01 00:00:00.000", "{}"),
            event("1151", 2, "2026-08-01 00:00:00.100", on),
            event("1151", 3, "2026-08-01 01:00:00.000", on),
            event("1151", 4, "2026-08-01 02:00:00.000", r#"{"RTP state":"사용 안 함","OA state":"사용"}"#),
            event("1151", 5, "2026-08-01 03:00:00.000", r#"{"RTP state":"사용 안 함","OA state":"사용"}"#),
            event("1151", 6, "2026-08-01 04:00:00.000", on),
            event("1151", 7, "2026-08-01 05:00:00.000", on),
            // SYSTEM purge of history older than 15 days: periodic.
            event("1013", 8, "2026-08-16 09:00:00.500", r#"{"Timestamp":"2026-08-01T00:00:00Z","Domain":"NT AUTHORITY","User":"SYSTEM"}"#),
            // Not a whole-day cutoff, or not SYSTEM: kept.
            event("1013", 9, "2026-08-16 09:00:00.000", r#"{"Timestamp":"2026-08-16T00:00:00Z","Domain":"NT AUTHORITY","User":"SYSTEM"}"#),
            event("1013", 10, "2026-08-16 09:00:00.000", r#"{"Timestamp":"2026-08-01T00:00:00Z","Domain":"WIN-HOST","User":"analyst"}"#),
        ]);

        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE event_id=1150"), 0);
        // Only the off and back-on reports remain.
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(event_record_id) FROM (SELECT event_record_id FROM Defender WHERE event_id=1151 ORDER BY timestamp)"),
            "4,6"
        );
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(event_record_id) FROM (SELECT event_record_id FROM Defender WHERE event_id=1013 ORDER BY CAST(event_record_id AS INTEGER))"),
            "9,10"
        );
        // The latest state still uses every observation; its record is gone.
        let latest: (String, Option<String>, i64, String) = db
            .query_row(
                "SELECT state,record_id,observation_count,last_observed_time FROM DefenderProtectionLatest WHERE feature='realtime_protection'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(latest, ("on".to_string(), None, 6, "2026-08-01 05:00:00.000".to_string()));
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(change_kind) FROM (SELECT change_kind FROM DefenderProtectionStates WHERE feature='realtime_protection' ORDER BY timestamp)"),
            "transition,transition"
        );
        // on_access never changed: only its observations on stored records
        // remain (unchanged), and the latest state still exists.
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(change_kind) FROM DefenderProtectionStates WHERE feature='on_access'"),
            "unchanged,unchanged"
        );
        assert_eq!(one::<String>(&db, "SELECT state FROM DefenderProtectionLatest WHERE feature='on_access'"), "on");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // 2026-10-14 user decision: quick scans are not brought into _OVERVIEW.
    #[test]
    fn quick_scans_are_not_stored() {
        let case = Case::new(4);
        let db = case.build(vec![
            event("1000", 1, "2026-08-01 00:00:00.000", r#"{"Scan ID":"{Q}","Scan Parameters":"빠른 검사"}"#),
            event("1001", 2, "2026-08-01 00:00:19.000", r#"{"Scan ID":"{Q}","Scan Parameters":"빠른 검사"}"#),
            event("1000", 3, "2026-08-01 01:00:00.000", r#"{"Scan ID":"{E}","Scan Parameters":"Quick Scan"}"#),
            event("1000", 4, "2026-08-01 02:00:00.000", r#"{"Scan ID":"{F}","Scan Parameters":"전체 검사"}"#),
        ]);
        assert_eq!(one::<String>(&db, "SELECT group_concat(event_record_id) FROM Defender"), "4");
        assert_eq!(one::<String>(&db, "SELECT group_concat(scan_id) FROM DefenderScans"), "{F}");
    }

    // 2026-10-14 user decision: the definition-version section (updates,
    // failures, cloud intelligence) is not brought into _OVERVIEW.
    #[test]
    fn definition_version_section_is_not_stored() {
        let case = Case::new(5);
        let db = case.build(vec![
            event("2000", 1, "2026-08-01 00:00:00.000", r#"{"Current security intelligence Version":"1.2","Previous security intelligence Version":"1.1"}"#),
            event("2001", 2, "2026-08-01 01:00:00.000", r#"{"Error Code":"0x80240022"}"#),
            event("2002", 3, "2026-08-01 02:00:00.000", r#"{"Current Engine Version":"1.1.2","Previous Engine Version":"1.1.1"}"#),
            event("2010", 4, "2026-08-01 03:00:00.000", "{}"),
            event("1000", 5, "2026-08-01 04:00:00.000", r#"{"Scan ID":"{B}"}"#),
        ]);
        assert_eq!(one::<String>(&db, "SELECT group_concat(event_id) FROM Defender"), "1000");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderActivitySummaries WHERE section='signature'"), 0);
        // Still recognised Defender events, not counted as unmapped.
        assert_eq!(
            one::<i64>(&db, "SELECT unmapped_event_count FROM DefenderInputObservations WHERE input_kind='eventlog' AND event_count IS NOT NULL"),
            0
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // 2026-10-14 user decision: only scan exclusions and protection settings
    // stay among configuration changes; unreadable targets are kept.
    #[test]
    fn unrelated_configuration_changes_are_not_stored() {
        let case = Case::new(5);
        let db = case.build(vec![
            event("5007", 1, "2026-05-01 00:00:00.000", r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x7A257414","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\WdConfigHash = 0x57C0580F"}"#),
            event("5007", 2, "2026-05-01 00:01:00.000", r#"{"Old Value":"","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\Controls\\104 = 0x1"}"#),
            event("5007", 3, "2026-05-01 00:02:00.000", r#"{"Old Value":"","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\tmp = 0x0"}"#),
            event("5007", 4, "2026-05-01 00:03:00.000", r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x0","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"}"#),
            event("5007", 5, "2026-05-01 00:04:00.000", r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection = 0x5","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection = 0x4"}"#),
        ]);
        assert_eq!(
            one::<String>(&db, "SELECT group_concat(event_record_id) FROM (SELECT event_record_id FROM Defender ORDER BY event_record_id)"),
            "3,4,5"
        );
        assert_eq!(one::<String>(&db, "SELECT state FROM DefenderProtectionLatest WHERE feature='realtime_protection'"), "off");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // R02/R17: same-time conflicts never become a decided latest state.
    #[test]
    fn same_time_conflicts_stay_undetermined() {
        let case = Case::new(2);
        let db = case.build(vec![
            event("5000", 1, "2026-09-01 00:00:00.000", "{}"),
            event("5001", 2, "2026-09-01 00:00:00.000", "{}"),
        ]);
        let (state, certainty, ties): (Option<String>, String, i64) = db
            .query_row(
                "SELECT state,certainty,tie_count FROM DefenderProtectionLatest WHERE feature='realtime_protection'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(state, None);
        assert_eq!(certainty, "ambiguous_tie");
        assert_eq!(ties, 2);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionStates WHERE order_ambiguous=1"),
            2
        );
    }

    // A03: configuration changes keep the raw values and distinguish states.
    #[test]
    fn configuration_changes_distinguish_added_removed_and_unparsed() {
        let case = Case::new(4);
        let db = case.build(vec![
            event("5007", 1, "2026-05-01 00:00:00.000", r#"{"Old Value":"","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\tmp = 0x0"}"#),
            event("5007", 2, "2026-05-01 00:01:00.000", r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\tmp = 0x0","New Value":""}"#),
            event("5007", 3, "2026-05-01 00:02:00.000", r#"{"Old Value":"Default\\DisableRealtimeMonitoring = 0x0","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\DisableRealtimeMonitoring = 0x1"}"#),
            event("5007", 4, "2026-05-01 00:03:00.000", r#"{"Old Value":"N/A\\Exclusions\\Paths\\C:\\x =","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\x"}"#),
        ]);

        let kind = |n: i64| -> String {
            db.query_row(
                "SELECT config_change_kind FROM Defender WHERE event_record_id=?1",
                [n.to_string()],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(kind(1), "added");
        assert_eq!(kind(2), "removed");
        assert_eq!(kind(3), "changed");
        assert_eq!(
            one::<String>(&db, "SELECT config_exclusion_kind FROM Defender WHERE event_record_id='1'"),
            "Paths"
        );
        assert_eq!(
            one::<String>(&db, "SELECT config_protection_setting FROM Defender WHERE event_record_id='3'"),
            "DisableRealtimeMonitoring"
        );
        // Recorded-but-empty differs from a value that is missing entirely.
        let (old_state, new_state): (String, String) = db
            .query_row("SELECT config_old_state,config_new_state FROM Defender WHERE event_record_id='4'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(old_state, "empty");
        assert_eq!(new_state, "unparsed");
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE event_id=5007 AND config_new_raw IS NULL AND event_record_id IN ('1','3','4')"),
            0
        );
    }

    // R11/R12 + A01: provider attribution, nested payloads and unmapped events.
    #[test]
    fn foreign_providers_excluded_and_payload_shapes_preserved() {
        let case = Case::new(7);
        let mut foreign = event("1116", 1, "2026-06-01 00:00:00.000", r#"{"Threat Name":"X"}"#);
        foreign.insert(
            "Provider".to_string(),
            "Microsoft-Windows-Kernel-General".to_string(),
        );
        let mut nested = event("1151", 2, "2026-06-01 01:00:00.000", "");
        nested.insert(
            "EventData".to_string(),
            r#"{"EventXML":{"RTP state":"사용 안 함","OA state":"사용"}}"#.to_string(),
        );
        // A stored empty payload and a missing EventData column differ.
        let stored_empty = event("5000", 5, "2026-06-01 04:00:00.000", "");
        let mut absent = event("5001", 6, "2026-06-01 05:00:00.000", "");
        absent.remove("EventData");
        // Another Defender channel: the id's Operational meaning is not proven,
        // so it is not stored and contributes no state or scan.
        let mut other_channel = event("1000", 7, "2026-06-01 06:00:00.000", r#"{"RTP state":"사용","Scan ID":"{W}"}"#);
        other_channel.insert(
            "Channel".to_string(),
            "Microsoft-Windows-Windows Defender/WHC".to_string(),
        );
        let db = case.build(vec![
            foreign,
            nested,
            event("2014", 3, "2026-06-01 02:00:00.000", r#"{"Product Name":"Microsoft Defender"}"#),
            event("5007", 4, "2026-06-01 03:00:00.000", "not json"),
            stored_empty,
            absent,
            other_channel,
        ]);

        let payload = |id: i64| -> (String, Option<String>) {
            db.query_row(
                "SELECT payload_shape,event_data_raw FROM Defender WHERE event_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        assert_eq!(payload(5000), ("empty".to_string(), Some(String::new())));
        assert_eq!(payload(5001), ("absent".to_string(), None));

        // Unmapped events (2014, the WHC-channel 1000) are not stored.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender"), 4);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE event_id IN (1000,2014)"), 0);
        assert_eq!(one::<i64>(&db,
            "SELECT COUNT(*) FROM DefenderProtectionStates s JOIN Defender d USING(record_id)
             WHERE d.channel='Microsoft-Windows-Windows Defender/WHC'"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderScans"), 0);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE provider<>'Microsoft-Windows-Windows Defender'"),
            0
        );
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT foreign_provider_count FROM DefenderInputObservations WHERE input_kind='eventlog' AND event_count IS NOT NULL"
            ),
            1
        );
        assert_eq!(
            one::<String>(&db, "SELECT payload_shape FROM Defender WHERE event_id=1151"),
            "nested"
        );
        assert_eq!(
            one::<String>(&db, "SELECT rtp_state_raw FROM Defender WHERE event_id=1151"),
            "사용 안 함"
        );
        // Invalid payloads stay visible, never blank rows.
        let (shape, raw): (String, String) = db
            .query_row("SELECT payload_shape,event_data_raw FROM Defender WHERE event_id=5007", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(shape, "invalid");
        assert_eq!(raw, "not json");
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT unmapped_event_count FROM DefenderInputObservations WHERE input_kind='eventlog' AND event_count IS NOT NULL"
            ),
            2
        );
        // A Defender log that was never collected keeps its own state.
        assert_eq!(
            one::<String>(
                &db,
                "SELECT collection_state FROM DefenderInputObservations WHERE log_name='Microsoft-Windows-Windows Defender%4WHC'"
            ),
            "unknown"
        );
    }

    // A06/A07: MPDetection keeps raw lines, encoding and parse failures.
    #[test]
    fn mpdetection_inputs_separate_zero_detections_from_failures() {
        let case = Case::new(1);
        let support = case.root.join("VACCINE/WINDEFENDER/Support");
        std::fs::create_dir_all(&support).unwrap();
        let utf16 = |text: &str| {
            let mut bytes = vec![0xFF, 0xFE];
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        };
        std::fs::write(
            support.join("MPDetection-20260401-000000.log"),
            utf16(
                "2026-04-01T01:00:00.000 Service started - Microsoft Defender\r\n\
                 2026-04-01T01:00:00.000 DETECTION Trojan:Win32/X file:_C:\\tmp\\a.exe\r\n\
                 NOT-A-TIME DETECTION Trojan:Win32/Y file:_C:\\tmp\\b.exe\r\n",
            ),
        )
        .unwrap();
        // UTF-16BE carries the same standard signature and now decodes.
        let mut be = vec![0xFE, 0xFF];
        for unit in "2026-04-01T02:00:00.000Z DETECTION Z res".encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        std::fs::write(support.join("MPDetection-20260402-000000.log"), be).unwrap();
        // A BOM-less UTF-16 stream is byte-wise valid UTF-8; it must not look
        // like a healthy file with zero detections.
        let mut headless = Vec::new();
        for unit in "2026-04-01T03:00:00.000 DETECTION Q res".encode_utf16() {
            headless.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(support.join("MPDetection-20260403-000000.log"), headless).unwrap();
        case.prepare();

        // RD-14: the EVTX record is written after the detection instant; the
        // match uses the payload Detection Time, not the record time.
        let db = case.build(vec![event(
            "1116",
            1,
            "2026-04-01 10:00:00.218",
            r#"{"Threat Name":"Trojan:Win32/X","Path":"file:_C:\\tmp\\a.exe","Detection Time":"2026-04-01T01:00:00.000Z"}"#,
        )]);

        // One EVTX row plus the little-endian lines and the big-endian line.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE source='MPDetection'"), 3);
        let (ts, raw, state, line): (Option<String>, String, String, i64) = db
            .query_row(
                "SELECT timestamp,timestamp_raw,timestamp_state,line_number FROM Defender \
                 WHERE source='MPDetection' AND threat_name='Trojan:Win32/Y'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap();
        assert_eq!(ts, None);
        assert_eq!(raw, "NOT-A-TIME");
        assert_eq!(state, "unparsed");
        assert_eq!(line, 3);
        // Documented UTC rule for an unzoned value, kept as evidence.
        let (time, zone, parse_state): (String, String, String) = db
            .query_row(
                "SELECT timestamp,timestamp_zone_source,timestamp_parse_state FROM Defender \
                 WHERE source='MPDetection' AND threat_name='Trojan:Win32/X'",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(time, "2026-04-01 10:00:00.000");
        assert_eq!(zone, support::ZONE_UTC_DOCUMENTED);
        assert_eq!(parse_state, "parsed_utc_documented");
        assert_eq!(
            one::<String>(&db, "SELECT raw_line FROM Defender WHERE source='MPDetection' AND threat_name='Trojan:Win32/X'"),
            "2026-04-01T01:00:00.000 DETECTION Trojan:Win32/X file:_C:\\tmp\\a.exe"
        );
        // The explicit Z of the big-endian line is recorded as such.
        let (be_time, be_zone): (String, String) = db
            .query_row(
                "SELECT timestamp,timestamp_zone_source FROM Defender \
                 WHERE source='MPDetection' AND threat_name='Z'",
                [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(be_time, "2026-04-01 11:00:00.000");
        assert_eq!(be_zone, support::ZONE_UTC_EXPLICIT);
        let observation = |pattern: &str| -> (String, Option<i64>, Option<i64>) {
            db.query_row(
                "SELECT decode_state,detection_line_count,line_count FROM DefenderInputObservations \
                 WHERE input_kind='mpdetection' AND source_file LIKE ?1",
                [pattern],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(observation("%20260402%"), ("decoded_utf16be_bom".to_string(), Some(1), Some(1)));
        // An undetermined encoding is not a healthy zero-detection file.
        assert_eq!(
            observation("%20260403%"),
            ("undetermined_encoding".to_string(), None, None)
        );
        assert_eq!(
            one::<String>(
                &db,
                "SELECT collection_state FROM DefenderInputObservations WHERE source_file LIKE '%20260403%'"
            ),
            "undetermined_encoding"
        );
        assert_eq!(observation("%20260401%").2, Some(3));
        // A06: equal threat and detection time is a candidate, never a merged
        // detection.
        let (basis, relation, time): (String, String, String) = db
            .query_row("SELECT match_basis,relation,timestamp FROM DefenderSourceCandidates", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(relation, "candidate");
        assert_eq!(basis, "same_threat_name_and_detection_time");
        assert_eq!(time, "2026-04-01 10:00:00.000");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetections"), 4);
        // MPDetection rows point at their own preserved facts rows.
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT COUNT(*) FROM source_records WHERE source_artifact='MPDetection' AND source_table='Defender_MPDetection_Records'"
            ),
            3
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // R15/R17/A08: untimed events, search text and ordering keys.
    #[test]
    fn untimed_rows_keep_null_time_and_searchable_text() {
        let case = Case::new(2);
        let db = case.build(vec![
            event("1116", 1, "", r#"{"Threat Name":"Trojan:Win32/Q","Path":"file:_C:\\tmp\\q.exe","Process Name":"C:\\p.exe","Detection User":"WIN-HOST\\admin"}"#),
            event("1000", 2, "2026-07-01 00:00:00.000", r#"{"Scan ID":"{B}","Domain":"NT AUTHORITY","User":"SYSTEM","SID":"S-1-5-18"}"#),
        ]);

        let (ts, kind, state): (Option<String>, Option<String>, String) = db
            .query_row("SELECT timestamp,timestamp_kind,timestamp_state FROM Defender WHERE event_id=1116", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        assert_eq!(ts, None);
        assert_eq!(kind, None);
        assert_eq!(state, "unrecorded");
        let search: String = one(&db, "SELECT search_text FROM Defender WHERE event_id=1116");
        for needle in ["Trojan:Win32/Q", "q.exe", "C:\\p.exe", "WIN-HOST\\admin"] {
            assert!(search.contains(needle), "missing {needle} in {search}");
        }
        let scan_search: String = one(&db, "SELECT search_text FROM Defender WHERE event_id=1000");
        assert!(scan_search.contains("S-1-5-18"));
        assert_eq!(
            one::<i64>(&db, "SELECT untimed_count FROM DefenderActivitySummaries WHERE summary_kind='threat_detected'"),
            1
        );
        // Observation range only covers recorded times.
        assert_eq!(
            one::<String>(&db, "SELECT first_observed_time FROM DefenderInputObservations WHERE input_kind='eventlog' AND event_count IS NOT NULL"),
            "2026-07-01 00:00:00.000"
        );
    }

    // A01: a Defender log collected with zero events is not a log that was
    // never collected (real WHC evtx is a valid empty log).
    #[test]
    fn collected_empty_log_differs_from_never_collected() {
        let case = Case::new(1);
        // The Operational log is not part of this collection at all.
        std::fs::remove_file(case.root.join("EVENTLOG/Microsoft-Windows-Windows Defender%4Operational.sqlite")).unwrap();
        let manifest = case.root.join("EVENTLOG/EventLogInputs.sqlite");
        let conn = Connection::open(&manifest).unwrap();
        conn.execute_batch(
            "CREATE TABLE EventLogInputs(source_file TEXT,facts_db TEXT,facts_table TEXT,status TEXT,row_count TEXT,error TEXT);
             INSERT INTO EventLogInputs VALUES('','','','discovery_complete','2',NULL);
             INSERT INTO EventLogInputs VALUES('/evidence/Microsoft-Windows-Windows Defender%4WHC.evtx',
               'EVENTLOG/Microsoft-Windows-Windows Defender%4WHC.sqlite','Microsoft-Windows-Windows Defender%4WHC','parsed','0',NULL);",
        )
        .unwrap();
        drop(conn);
        stamp_facts_generation(&manifest, "facts-old").unwrap();

        let db = case.build(Vec::new());
        let state = |log: &str| -> (String, Option<i64>, Option<i64>) {
            db.query_row(
                "SELECT collection_state,input_row_count,event_count FROM DefenderInputObservations WHERE log_name=?1",
                [log],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(
            state("Microsoft-Windows-Windows Defender%4WHC"),
            ("collected_empty".to_string(), Some(0), Some(0))
        );
        assert_eq!(
            state("Microsoft-Windows-Windows Defender%4Operational"),
            ("not_collected".to_string(), None, None)
        );
        // No events means no invented semantics anywhere.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM Defender"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionLatest"), 0);
    }

    /// The same event row seen on another channel of the same provider.
    fn on_channel(mut row: Row, channel: &str) -> Row {
        row.insert("Channel".to_string(), channel.to_string());
        row
    }

    // A01/R12: the WHC channel has its own single documented event; an
    // Operational id seen there keeps no Operational meaning.
    #[test]
    fn whc_channel_maps_only_its_own_manifest_event() {
        let case = Case::new(4);
        let db = case.build(vec![
            on_channel(
                event("101", 1, "2026-08-01 00:00:00.000", r#"{"hc_stateid":"4"}"#),
                WHC_CHANNEL,
            ),
            // An ASR block id on the WHC channel is not an ASR block event.
            on_channel(
                event("1121", 2, "2026-08-01 00:01:00.000", r#"{"ID":"{c1db55ab-c21a-4637-bb3f-a12568109d35}"}"#),
                WHC_CHANNEL,
            ),
            // The WHC id on the Operational channel is equally unmapped.
            event("101", 3, "2026-08-01 00:02:00.000", r#"{"hc_stateid":"4"}"#),
            on_channel(
                event("1150", 4, "2026-08-01 00:03:00.000", "{}"),
                "Microsoft-Windows-Windows Defender/Unknown",
            ),
        ]);

        let row = |record: i64, column: &str| -> Option<String> {
            db.query_row(
                &format!("SELECT {column} FROM Defender WHERE event_record_id=?1"),
                [record.to_string()],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(row(1, "event_type").as_deref(), Some("whc_state_updated"));
        assert_eq!(row(1, "section").as_deref(), Some(SECTION_WHC_STATE));
        assert_eq!(row(1, "support_state").as_deref(), Some(DOC));
        assert_eq!(row(1, "support_source").as_deref(), Some(SRC_MANIFEST));
        assert_eq!(row(1, "channel_state").as_deref(), Some("manifest_whc"));
        // The state code stays raw and keeps no invented meaning.
        assert_eq!(row(1, "whc_state_raw").as_deref(), Some("4"));
        assert_eq!(
            one::<i64>(&db, "SELECT whc_state_id FROM Defender WHERE event_record_id='1'"),
            4
        );
        // Unmapped ids on either channel are not stored.
        assert_eq!(one::<String>(&db, "SELECT group_concat(event_record_id) FROM Defender"), "1");
        // No protection state, scan or detection is created from any of them.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionStates"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderScans"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetections"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // A01: block, audit and warn-override stay distinct, the rule GUID is not
    // a threat id, and the endpoint keeps its raw value next to its parts.
    #[test]
    fn asr_network_and_folder_events_keep_mode_rule_and_endpoint() {
        let case = Case::new(6);
        let db = case.build(vec![
            event(
                "1121",
                1,
                "2026-08-02 10:00:00.000",
                r#"{"ID":"{c1db55ab-c21a-4637-bb3f-a12568109d35}","Detection Time":"2026-08-02T01:00:00.000Z","User":"WIN-HOST\\admin","Path":"C:\\tmp\\a.docx","Process Name":"C:\\Office\\winword.exe","Signature Version":"1.443.1.0","Product Version":"4.18.25110.6"}"#,
            ),
            event(
                "1122",
                2,
                "2026-08-02 10:01:00.000",
                r#"{"ID":"{00000000-0000-0000-0000-000000000001}","Detection Time":"2026-08-02T01:01:00.000Z","User":"WIN-HOST\\admin","Path":"C:\\tmp\\b.docx","Process Name":"C:\\Office\\excel.exe"}"#,
            ),
            event(
                "1129",
                3,
                "2026-08-02 10:02:00.000",
                r#"{"ID":"{c1db55ab-c21a-4637-bb3f-a12568109d35}","User":"WIN-HOST\\admin","Path":"C:\\tmp\\c.docx"}"#,
            ),
            event(
                "1125",
                4,
                "2026-08-02 10:03:00.000",
                r#"{"Detection Time":"2026-08-02T01:03:00Z","User":"WIN-HOST\\admin","Destination":"https://example.test:8443/path?q=1","Process Name":"C:\\Windows\\explorer.exe"}"#,
            ),
            event(
                "1126",
                5,
                "2026-08-02 10:04:00.000",
                r#"{"Detection Time":"NOT-A-TIME","User":"WIN-HOST\\admin","Destination":"203.0.113.5:443","Process Name":"C:\\Windows\\explorer.exe"}"#,
            ),
            event(
                "1127",
                6,
                "2026-08-02 10:05:00.000",
                r#"{"Detection Time":"2026-08-02T01:05:00.000Z","User":"WIN-HOST\\admin","Path":"\\Device\\HarddiskVolume3","Process Name":"C:\\tmp\\x.exe"}"#,
            ),
        ]);

        let text = |record: i64, column: &str| -> Option<String> {
            db.query_row(
                &format!("SELECT {column} FROM Defender WHERE event_record_id=?1"),
                [record.to_string()],
                |r| r.get(0),
            )
            .unwrap()
        };
        // Block and audit are different results; neither is a success.
        assert_eq!(text(1, "result").as_deref(), Some("blocked"));
        assert_eq!(text(1, "protection_mode").as_deref(), Some(MODE_BLOCK));
        assert_eq!(text(1, "protection_feature").as_deref(), Some("attack_surface_reduction"));
        assert_eq!(text(2, "result").as_deref(), Some("audited"));
        assert_eq!(text(2, "protection_mode").as_deref(), Some(MODE_AUDIT));
        assert_eq!(text(3, "result").as_deref(), Some("warn_overridden"));
        assert_eq!(text(3, "protection_mode").as_deref(), Some(MODE_WARN_OVERRIDE));
        assert_eq!(text(4, "protection_mode").as_deref(), Some(MODE_AUDIT));
        assert_eq!(text(5, "protection_mode").as_deref(), Some(MODE_BLOCK));
        assert_eq!(text(6, "protection_feature").as_deref(), Some("controlled_folder_access"));
        assert_eq!(text(6, "event_type").as_deref(), Some("cfa_sector_write_blocked"));
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM Defender WHERE result='success'"),
            0
        );
        // The rule GUID is a rule, never the threat id of a detection.
        assert_eq!(
            text(1, "asr_rule_id").as_deref(),
            Some("{c1db55ab-c21a-4637-bb3f-a12568109d35}")
        );
        assert_eq!(text(1, "asr_rule_name").as_deref(), Some("Use advanced protection against ransomware"));
        assert_eq!(text(1, "asr_rule_name_source").as_deref(), Some("microsoft_docs"));
        assert_eq!(text(1, "threat_id"), None);
        assert_eq!(text(2, "asr_rule_name"), None);
        assert_eq!(text(2, "asr_rule_name_source").as_deref(), Some("unknown_guid"));
        assert_eq!(text(4, "asr_rule_id"), None);
        // Path, process and the combined user are typed and still raw.
        assert_eq!(text(1, "target_path").as_deref(), Some("C:\\tmp\\a.docx"));
        assert_eq!(text(1, "process").as_deref(), Some("C:\\Office\\winword.exe"));
        assert_eq!(text(1, "event_user_raw").as_deref(), Some("WIN-HOST\\admin"));
        assert_eq!(text(1, "event_user_domain").as_deref(), Some("WIN-HOST"));
        assert_eq!(text(1, "event_user_name").as_deref(), Some("admin"));
        assert_eq!(text(6, "target_path").as_deref(), Some("\\Device\\HarddiskVolume3"));
        // Endpoint parts come from the syntax only; the raw stays untouched.
        assert_eq!(text(4, "network_destination_raw").as_deref(), Some("https://example.test:8443/path?q=1"));
        assert_eq!(text(4, "network_destination_kind").as_deref(), Some("url"));
        assert_eq!(text(4, "network_destination_scheme").as_deref(), Some("https"));
        assert_eq!(text(4, "network_destination_host").as_deref(), Some("example.test"));
        assert_eq!(text(4, "network_destination_ip"), None);
        assert_eq!(
            one::<i64>(&db, "SELECT network_destination_port FROM Defender WHERE event_record_id='4'"),
            8443
        );
        assert_eq!(text(5, "network_destination_kind").as_deref(), Some("ip"));
        assert_eq!(text(5, "network_destination_ip").as_deref(), Some("203.0.113.5"));
        assert_eq!(text(1, "network_destination_raw"), None);
        // The payload detection instant keeps its zone evidence.
        assert_eq!(text(1, "detection_time").as_deref(), Some("2026-08-02 10:00:00.000"));
        assert_eq!(text(1, "detection_time_state").as_deref(), Some("parsed_utc_explicit"));
        assert_eq!(text(1, "detection_time_zone_source").as_deref(), Some(support::ZONE_UTC_EXPLICIT));
        assert_eq!(text(5, "detection_time"), None);
        assert_eq!(text(5, "detection_time_raw").as_deref(), Some("NOT-A-TIME"));
        assert_eq!(text(5, "detection_time_state").as_deref(), Some("unparsed"));
        assert_eq!(text(3, "detection_time_state"), None);
        // Enforcement events are not detections and change no feature state.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderDetections"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionStates"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionLatest"), 0);
        // Every event keeps one summary row per documented kind.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderActivitySummaries WHERE section IN ('asr','network_protection','folder_guard')"),
            6
        );
        let search: String = one(&db, "SELECT search_text FROM Defender WHERE event_record_id='4'");
        assert!(search.contains("example.test"), "{search}");
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // A01/A02: policy enforcement fields and the full scan lifecycle.
    #[test]
    fn policy_events_and_scan_lifecycle_keep_their_own_evidence() {
        let case = Case::new(6);
        let db = case.build(vec![
            event(
                "1133",
                1,
                "2026-08-03 09:00:00.000",
                r#"{"Policy Version":"1","Policy Rule Id":"{RULE-1}","Enforcement Level":"Deny","Action Type":"Write","Event Timestamp":"2026-08-03T00:00:00Z"}"#,
            ),
            event(
                "1134",
                2,
                "2026-08-03 09:01:00.000",
                r#"{"Policy Version":"1","Policy Rule Id":"{RULE-2}","Enforcement Level":"Audit","Audit Reason":"AllowedByPolicy","Action Type":"Read"}"#,
            ),
            event("1000", 3, "2026-08-03 10:00:00.000", r#"{"Scan ID":"{S1}","Scan Type":"빠른 검사"}"#),
            event("1003", 4, "2026-08-03 10:01:00.000", r#"{"Scan ID":"{S1}"}"#),
            event("1004", 5, "2026-08-03 10:02:00.000", r#"{"Scan ID":"{S1}"}"#),
            event(
                "1005",
                6,
                "2026-08-03 10:03:00.000",
                r#"{"Scan ID":"{S1}","Error Code":"0x80508023","Error Description":"항목을 찾을 수 없습니다"}"#,
            ),
        ]);

        let text = |record: i64, column: &str| -> Option<String> {
            db.query_row(
                &format!("SELECT {column} FROM Defender WHERE event_record_id=?1"),
                [record.to_string()],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(text(1, "protection_feature").as_deref(), Some("device_control"));
        assert_eq!(text(1, "policy_rule_id").as_deref(), Some("{RULE-1}"));
        assert_eq!(text(1, "policy_enforcement_level").as_deref(), Some("Deny"));
        assert_eq!(text(1, "policy_event_timestamp_raw").as_deref(), Some("2026-08-03T00:00:00Z"));
        assert_eq!(text(1, "result").as_deref(), Some("blocked"));
        assert_eq!(text(2, "result").as_deref(), Some("audited"));
        assert_eq!(text(2, "policy_audit_reason").as_deref(), Some("AllowedByPolicy"));
        assert_eq!(text(1, "policy_audit_reason"), None);
        // A started scan that errors is never reported as completed.
        let (pairing, pauses, resumes): (String, i64, i64) = db
            .query_row(
                "SELECT pairing_state,pause_count,resume_count FROM DefenderScans",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(pairing, "start_and_error");
        assert_eq!((pauses, resumes), (1, 1));
        assert_eq!(
            one::<String>(&db, "SELECT error_time FROM DefenderScans"),
            "2026-08-03 10:03:00.000"
        );
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM DefenderScans WHERE completion_record_id IS NOT NULL OR elapsed_seconds IS NOT NULL"),
            0
        );
        assert_eq!(text(6, "result").as_deref(), Some("failure"));
        assert_eq!(text(4, "result").as_deref(), Some("unknown"));
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    // The manifest discriminators are stored when the facts carry them and
    // stay NULL for older facts instead of being assumed.
    #[test]
    fn provider_guid_and_schema_version_are_stored_or_null() {
        let case = Case::new(3);
        let mut matched = event("5000", 1, "2026-08-04 00:00:00.000", "{}");
        matched.insert("ProviderGuid".to_string(), format!("{{{PROVIDER_GUID}}}"));
        matched.insert("Version".to_string(), "0".to_string());
        let mut other = event("5000", 2, "2026-08-04 00:01:00.000", "{}");
        other.insert(
            "ProviderGuid".to_string(),
            "{00000000-0000-0000-0000-000000000000}".to_string(),
        );
        other.insert("Version".to_string(), "2".to_string());
        let legacy = event("5000", 3, "2026-08-04 00:02:00.000", "{}");
        let db = case.build(vec![matched, other, legacy]);

        let state = |record: i64| -> (String, Option<i64>, Option<String>) {
            db.query_row(
                "SELECT provider_guid_state,schema_version,provider_guid FROM Defender WHERE event_record_id=?1",
                [record.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(state(1).0, "matched_manifest");
        assert_eq!(state(1).1, Some(0));
        assert_eq!(state(2).0, "other_guid");
        assert_eq!(state(2).1, Some(2));
        assert_eq!(state(3), ("absent".to_string(), None, None));
    }

    // RD-11: 1116/1117 write `Status Code`; there is no `Status` or
    // `Action Status` template field, so no column claims one.
    #[test]
    fn threat_status_comes_from_the_manifest_status_code() {
        let case = Case::new(1);
        let db = case.build(vec![event(
            "1117",
            1,
            "2026-09-08 01:49:54.328",
            r#"{"Detection ID":"{D9}","Threat Name":"T","Status Code":"3","Status Description":"","Pre Execution Status":"3","Post Clean Status":"0","Action Name":"격리","Additional Actions String":"No additional actions required"}"#,
        )]);
        assert_eq!(one::<String>(&db, "SELECT status_raw FROM Defender WHERE event_id=1117"), "3");
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM pragma_table_info('Defender') WHERE name='action_status'"),
            0
        );
    }

    // RD-12: a 5007 change of a Disable* protection value is a config-change
    // observation; 0x1 is off, 0x0 is on, a removed value stays unknown.
    #[test]
    fn protection_setting_changes_become_config_observations() {
        let case = Case::new(4);
        let db = case.build(vec![
            event(
                "5007",
                1,
                "2026-09-01 00:00:00.000",
                r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x0","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"}"#,
            ),
            event(
                "5007",
                2,
                "2026-09-01 00:01:00.000",
                r#"{"Old Value":"","New Value":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring = 0x0"}"#,
            ),
            event(
                "5007",
                3,
                "2026-09-01 00:02:00.000",
                r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection = 0x1","New Value":""}"#,
            ),
            event(
                "5007",
                4,
                "2026-09-01 00:03:00.000",
                r#"{"Old Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection = 0x4","New Value":"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection = 0x5"}"#,
            ),
        ]);
        let observed = |feature: &str| -> (String, Option<String>, String, i64) {
            db.query_row(
                "SELECT state,state_raw,state_basis,event_id FROM DefenderProtectionStates WHERE feature=?1",
                [feature],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
        };
        assert_eq!(observed("realtime_protection"), ("off".to_string(), Some("0x1".to_string()), "config_change".to_string(), 5007));
        assert_eq!(observed("behavior_monitoring"), ("on".to_string(), Some("0x0".to_string()), "config_change".to_string(), 5007));
        assert_eq!(observed("ioav"), ("unknown".to_string(), None, "config_change".to_string(), 5007));
        // No published on/off meaning for this value: no observation.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderProtectionStates"), 3);
        assert_eq!(
            one::<String>(&db, "SELECT state FROM DefenderProtectionLatest WHERE feature='realtime_protection'"),
            "off"
        );
    }

    // RD-13: the Scan ID group key survives rotation of the lifecycle events,
    // and offline-scan configuration events are not scans.
    #[test]
    fn scan_id_survives_pause_only_groups_and_offline_config_is_no_scan() {
        let case = Case::new(3);
        let db = case.build(vec![
            event(
                "1003",
                1,
                "2026-08-05 10:01:00.000",
                r#"{"Scan ID":"{S2}","Scan Type":"빠른 검사","Scan Parameters":"검사 매개변수","Domain":"NT AUTHORITY","User":"SYSTEM","SID":"S-1-5-18"}"#,
            ),
            event("1004", 2, "2026-08-05 10:02:00.000", r#"{"Scan ID":"{S2}"}"#),
            event("2030", 3, "2026-08-05 11:00:00.000", "{}"),
        ]);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM DefenderScans"), 1);
        let scan: (String, String, String, String, String, String, i64, i64) = db
            .query_row(
                "SELECT scan_id,scan_id_state,scan_type,scan_parameters,user_sid,pairing_state,pause_count,resume_count FROM DefenderScans",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )
            .unwrap();
        assert_eq!(
            scan,
            (
                "{S2}".to_string(),
                "present".to_string(),
                "빠른 검사".to_string(),
                "검사 매개변수".to_string(),
                "S-1-5-18".to_string(),
                "unknown".to_string(),
                1,
                1
            )
        );
        assert_eq!(one::<String>(&db, "SELECT user_raw FROM DefenderScans"), "NT AUTHORITY\\SYSTEM");
    }

    // RD-15: a read_failed Defender log is named from its file stem and is
    // not reported a second time as never collected.
    #[test]
    fn read_failed_log_keeps_its_name_and_is_not_also_uncollected() {
        let case = Case::new(1);
        std::fs::remove_file(case.root.join("EVENTLOG/Microsoft-Windows-Windows Defender%4Operational.sqlite")).unwrap();
        let manifest = case.root.join("EVENTLOG/EventLogInputs.sqlite");
        let conn = Connection::open(&manifest).unwrap();
        conn.execute_batch(
            "CREATE TABLE EventLogInputs(source_file TEXT,facts_db TEXT,facts_table TEXT,status TEXT,row_count TEXT,error TEXT);
             INSERT INTO EventLogInputs VALUES('','','','discovery_complete','1',NULL);
             INSERT INTO EventLogInputs VALUES('C:\\evidence\\Microsoft-Windows-Windows Defender%4Operational.evtx',
               '','','read_failed',NULL,'access denied');",
        )
        .unwrap();
        drop(conn);
        stamp_facts_generation(&manifest, "facts-old").unwrap();

        let db = case.build(Vec::new());
        let rows: Vec<(Option<String>, String)> = db
            .prepare(
                "SELECT log_name,collection_state FROM DefenderInputObservations \
                 WHERE input_kind='eventlog' AND (log_name IS NULL OR log_name LIKE '%Operational') ORDER BY 1",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            rows,
            vec![(Some("Microsoft-Windows-Windows Defender%4Operational".to_string()), "read_failed".to_string())]
        );
    }
}
