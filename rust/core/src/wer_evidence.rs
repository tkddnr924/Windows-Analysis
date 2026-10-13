//! Windows Error Reporting evidence: Report.wer files and the application
//! error/hang/report events. Every source keeps its own record; identifiers
//! relate records without merging them, and a signature position is only
//! interpreted for layouts confirmed by the collected evidence.
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::overview::{basename_win, jget, parse_eventdata, read_table_with_rowid, EventLogOverviewCache};
use crate::sqlite::Row;
use crate::time::fmt_filetime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    ReportFile,
    Reporting1001,
    AppError1000,
    AppHang1002,
}

impl Origin {
    pub fn key(self) -> &'static str {
        match self {
            Origin::ReportFile => "report_file",
            Origin::Reporting1001 => "eventlog_1001",
            Origin::AppError1000 => "eventlog_1000",
            Origin::AppHang1002 => "eventlog_1002",
        }
    }

    /// Reporting stage of this record. The stages of one report are separate
    /// records: a repeated identifier is evidence, not a parser duplicate.
    pub fn stage(self) -> &'static str {
        match self {
            Origin::ReportFile => "report_written",
            Origin::Reporting1001 => "report_generated",
            Origin::AppError1000 => "app_error_event",
            Origin::AppHang1002 => "app_hang_event",
        }
    }

    pub fn source_label(self) -> &'static str {
        match self {
            Origin::ReportFile => "Report.wer",
            _ => "EventLog",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Origin::ReportFile => "오류 보고서 파일",
            Origin::Reporting1001 => "Windows 오류 보고 생성 기록",
            Origin::AppError1000 => "응용 프로그램 오류 이벤트",
            Origin::AppHang1002 => "응용 프로그램 중단 이벤트",
        }
    }

    pub fn timestamp_kind(self) -> &'static str {
        match self {
            Origin::ReportFile => "보고 시각",
            _ => "이벤트 기록 시각",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Report.wer family (Sig/DynamicSig/State/OsInfo/UI/LoadedModule) or "P".
    pub family: String,
    /// Index as written in the source (`DynamicSig[1]` stays 1).
    pub original_index: Option<i64>,
    /// Position inside the report JSON array, which renumbers from 0.
    pub array_position: Option<i64>,
    pub label: Option<String>,
    pub label_field: Option<&'static str>,
    pub value: Option<String>,
    pub value_present: bool,
    pub role: Option<&'static str>,
    pub p_field: Option<String>,
    pub basis: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEntry {
    pub role: &'static str,
    pub raw: String,
    pub basis: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    pub role: &'static str,
    pub value: String,
}

pub struct WerRecord {
    pub origin: Origin,
    pub timestamp: String,
    pub fields: BTreeMap<&'static str, String>,
    pub signatures: Vec<Signature>,
    pub paths: Vec<PathEntry>,
    pub identifiers: Vec<Identifier>,
    pub record_key: String,
    pub source_file: String,
    pub source_rowid: Option<i64>,
}

impl WerRecord {
    fn new(origin: Origin) -> Self {
        let mut record = Self {
            origin,
            timestamp: String::new(),
            fields: BTreeMap::new(),
            signatures: Vec::new(),
            paths: Vec::new(),
            identifiers: Vec::new(),
            record_key: String::new(),
            source_file: String::new(),
            source_rowid: None,
        };
        record.set("origin", origin.key());
        record.set("reporting_stage", origin.stage());
        record.set("source", origin.source_label());
        record.set("description", origin.description());
        record
    }

    pub fn get(&self, column: &str) -> &str {
        self.fields.get(column).map(String::as_str).unwrap_or("")
    }

    /// Empty evidence stays absent so the storage can keep it NULL.
    pub(crate) fn set(&mut self, column: &'static str, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.fields.insert(column, value);
        }
    }

    fn identifier(&mut self, role: &'static str, value: &str) {
        let value = value.trim();
        if !value.is_empty() {
            self.identifiers.push(Identifier {
                role,
                value: value.to_string(),
            });
        }
    }

    fn path(&mut self, role: &'static str, raw: &str, basis: &'static str) {
        let raw = raw.trim();
        if !raw.is_empty() {
            self.paths.push(PathEntry {
                role,
                raw: raw.to_string(),
                basis,
            });
        }
    }

    /// Text for list search; the full bodies stay in their own columns and are
    /// never truncated into this field.
    pub fn search_text(&self) -> String {
        const SEARCHED: &[&str] = &[
            "error_type", "error_class", "friendly_event_name", "consent_key",
            "app_name", "signature_app_name", "ns_app_name", "original_filename",
            "app_path", "app_path_resolved", "module_name", "module_path",
            "exception_code", "exception_offset", "hang_signature", "hang_type_text",
            "install_status", "install_source", "hresult", "client_app_id",
            "report_identifier", "integrator_report_identifier", "report_id", "integrator_report_id",
            "store_path", "target_app_id", "account", "account_sid",
            "record_subject_sid", "computer", "provider", "parse_status",
        ];
        let mut parts: Vec<&str> = Vec::new();
        for column in SEARCHED {
            let value = self.get(column);
            if !value.is_empty() && !parts.contains(&value) {
                parts.push(value);
            }
        }
        for signature in &self.signatures {
            for text in [signature.label.as_deref(), signature.value.as_deref()] {
                if let Some(text) = text.filter(|t| !t.is_empty()) {
                    parts.push(text);
                }
            }
        }
        for path in &self.paths {
            parts.push(&path.raw);
        }
        parts.join(" ")
    }
}

/// A signature layout confirmed by this collection: Report.wer `Sig[i].Name`
/// labels and, for the crash families, the named Application Error/1000
/// payload of the same report. Unlisted event types keep every value but get
/// no positional meaning.
struct Schema {
    id: &'static str,
    class: &'static str,
    roles: &'static [&'static str],
}

// APPCRASH/CriticalProcessFault2: 1000 AppName/ModuleName/ExceptionCode/
// FaultingOffset match P1/P4/P7/P8 of the same ReportId.
const CRASH_ROLES: &[&str] = &[
    "app_name", "app_version", "app_timestamp", "module_name", "module_version",
    "module_timestamp", "exception_code", "exception_offset",
];
// BEX64: the same cross-check shows P7 is the offset and P8 the code.
const BEX64_ROLES: &[&str] = &[
    "app_name", "app_version", "app_timestamp", "module_name", "module_version",
    "module_timestamp", "exception_offset", "exception_code", "exception_data",
];
// AppHang*: Report.wer labels "Hang Signature"/"Hang Type".
const HANG_ROLES: &[&str] = &[
    "app_name", "app_version", "app_timestamp", "hang_signature", "hang_type",
];
const HANG_XPROC_ROLES: &[&str] = &[
    "app_name", "app_version", "app_timestamp", "hang_signature", "hang_type",
    "waiting_app_name", "waiting_app_version",
];
// crashpad_log: Report.wer labels ApplicationName/ApplicationVersion/Source/
// InstallStatus — an installer diagnostic, not a crash dump.
const CRASHPAD_ROLES: &[&str] = &[
    "app_name", "app_version", "install_source", "install_status",
];
// StoreAgent*: Report.wer labels ClientAppId/HResult/OSVersion/OSRevision/
// DeviceClass/ProductHash.
const STORE_AGENT_ROLES: &[&str] = &[
    "client_app_id", "hresult", "os_version", "os_revision", "device_class",
    "product_hash",
];

fn schema_for(event_type: &str) -> Option<Schema> {
    Some(match event_type {
        "APPCRASH" | "CriticalProcessFault2" => Schema {
            id: "appcrash_p",
            class: "crash",
            roles: CRASH_ROLES,
        },
        "BEX64" => Schema {
            id: "bex64_p",
            class: "crash",
            roles: BEX64_ROLES,
        },
        "AppHangB1" => Schema {
            id: "apphang_b1",
            class: "hang",
            roles: HANG_ROLES,
        },
        "AppHangXProcB1" => Schema {
            id: "apphang_xproc_b1",
            class: "hang",
            roles: HANG_XPROC_ROLES,
        },
        "crashpad_log" => Schema {
            id: "crashpad_log",
            class: "install_diagnostic",
            roles: CRASHPAD_ROLES,
        },
        "StoreAgentSearchUpdatePackagesFailure1" | "StoreAgentScanForUpdatesFailure0" => Schema {
            id: "store_agent",
            class: "store_update_failure",
            roles: STORE_AGENT_ROLES,
        },
        _ => return None,
    })
}

/// Signature roles and typed columns are separate vocabularies: the binary
/// name in a signature is not the report's display application name.
fn role_column(role: &str) -> &'static str {
    match role {
        "app_name" => "signature_app_name",
        "app_version" => "app_version",
        "app_timestamp" => "app_timestamp",
        "module_name" => "module_name",
        "module_version" => "module_version",
        "module_timestamp" => "module_timestamp",
        "exception_code" => "exception_code",
        "exception_offset" => "exception_offset",
        "exception_data" => "exception_data",
        "hang_signature" => "hang_signature",
        "hang_type" => "hang_type_raw",
        "waiting_app_name" => "waiting_app_name",
        "waiting_app_version" => "waiting_app_version",
        "install_status" => "install_status",
        "install_source" => "install_source",
        "client_app_id" => "client_app_id",
        "hresult" => "hresult",
        "os_version" => "os_version_raw",
        "os_revision" => "os_revision",
        "device_class" => "device_class",
        "product_hash" => "product_hash",
        other => unreachable!("undeclared signature role: {other}"),
    }
}

fn hex_u64(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// `0x1dcd22aeaf5e3d1` is a FILETIME written as a hexadecimal number — not the
/// little-endian byte order used by the AppSessionGuid trailer.
fn filetime_from_hex_number(raw: &str) -> String {
    match hex_u64(raw).and_then(|value| i64::try_from(value).ok()) {
        Some(ticks) => fmt_filetime(ticks),
        None => String::new(),
    }
}

/// AppSessionGuid "PPPPPPPP-BBBB-CCCC-DDDD-EEEEEEEEEEEE": the first group is
/// the PID and the last two groups hold the process creation FILETIME as
/// little-endian bytes.
pub fn guid_pid_and_start(guid: &str) -> Option<(u32, String)> {
    let parts: Vec<&str> = guid.trim().split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let pid = u32::from_str_radix(parts[0], 16).ok()?;
    let data4 = format!("{}{}", parts[3], parts[4]);
    if data4.len() != 16 || !data4.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut ticks: u64 = 0;
    for index in (0..16).step_by(2) {
        let byte = u64::from_str_radix(&data4[index..index + 2], 16).ok()?;
        ticks |= byte << (8 * (index / 2));
    }
    let start = fmt_filetime(i64::try_from(ticks).ok()?);
    if start.is_empty() {
        return None;
    }
    Some((pid, start))
}

/// Generated display text for start → report elapsed time. It is produced
/// here, not read from the evidence, and says nothing about termination.
pub fn duration_kr(start: &str, end: &str) -> String {
    let fmt = "%Y-%m-%d %H:%M:%S%.3f";
    let (Ok(start), Ok(end)) = (
        chrono::NaiveDateTime::parse_from_str(start.trim(), fmt),
        chrono::NaiveDateTime::parse_from_str(end.trim(), fmt),
    ) else {
        return String::new();
    };
    let secs = (end - start).num_seconds();
    if secs < 0 {
        return String::new();
    }
    let mut parts = Vec::new();
    for (value, unit) in [
        (secs / 86400, "일"),
        ((secs % 86400) / 3600, "시간"),
        ((secs % 3600) / 60, "분"),
    ] {
        if value > 0 {
            parts.push(format!("{value}{unit}"));
        }
    }
    if parts.is_empty() {
        parts.push(format!("{}초", secs % 60));
    }
    parts.join(" ")
}

/// The WER store is the folder holding the report folder. Only that one
/// component is compared, so folder names elsewhere in the path (such as the
/// analyst's collection root) never classify the store.
fn store_location(report_dir: &str) -> &'static str {
    let mut components = report_dir
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .rev();
    components.next();
    match components.next() {
        Some(store) if store.eq_ignore_ascii_case("ReportQueue") => "ReportQueue",
        Some(store) if store.eq_ignore_ascii_case("ReportArchive") => "ReportArchive",
        _ => "unknown",
    }
}

fn text_of(row: &Row, key: &str) -> String {
    row.get(key).cloned().unwrap_or_default()
}

// --- Report.wer records -----------------------------------------------------

/// Scalars promoted to typed columns. Everything else stays in the report
/// body, the raw entry list and the structured signature rows.
const REPORT_SCALARS: &[(&str, &str)] = &[
    ("Version", "report_version_raw"),
    ("EventType", "error_type"),
    ("EventTime", "event_time_raw"),
    ("ReportType", "report_type_raw"),
    ("Consent", "consent_raw"),
    ("UploadTime", "upload_time_raw"),
    ("ReportStatus", "report_status_raw"),
    ("ReportIdentifier", "report_identifier"),
    ("IntegratorReportIdentifier", "integrator_report_identifier"),
    ("Wow64Host", "wow64_host"),
    ("Wow64Guest", "wow64_guest"),
    ("NsAppName", "ns_app_name"),
    ("NsPartner", "ns_partner"),
    ("NsGroup", "ns_group"),
    ("OriginalFilename", "original_filename"),
    ("AppSessionGuid", "app_session_guid"),
    ("TargetAppId", "target_app_id"),
    ("TargetAppVer", "target_app_ver"),
    ("BootId", "boot_id"),
    ("TargetAsId", "target_as_id"),
    ("IsFatal", "is_fatal_raw"),
    ("EtwNonCollectReason", "etw_non_collect_reason"),
    ("Response.BucketId", "response_bucket_id"),
    ("Response.BucketTable", "response_bucket_table"),
    ("Response.LegacyBucketId", "response_legacy_bucket_id"),
    ("Response.type", "response_type"),
    ("FriendlyEventName", "friendly_event_name"),
    ("ConsentKey", "consent_key"),
    ("AppName", "app_name"),
    ("AppPath", "app_path"),
    ("ReportDescription", "report_description"),
    ("ApplicationIdentity", "application_identity"),
    ("MetadataHash", "metadata_hash"),
];

/// Families whose elements are `Key=`/`Value=` pairs rather than `Name=`.
fn label_field_of(family: &str) -> &'static str {
    match family {
        "State" | "OsInfo" => "Key",
        _ => "Name",
    }
}

/// Build signature rows from the preserved raw entries so that the original
/// `Sig[0]`/`DynamicSig[1]` numbering survives the JSON array renumbering.
fn signatures_from_entries(entries: &str, schema: Option<&Schema>) -> Option<Vec<Signature>> {
    let parsed: Value = serde_json::from_str(entries).ok()?;
    let entries = parsed.as_array()?;
    let mut order: Vec<(String, i64)> = Vec::new();
    let mut slots: BTreeMap<(String, i64), Signature> = BTreeMap::new();
    for entry in entries {
        let (Some(family), Some(index)) = (
            entry.get("family").and_then(Value::as_str),
            entry.get("index").and_then(Value::as_i64),
        ) else {
            continue;
        };
        let key = (family.to_string(), index);
        if !slots.contains_key(&key) {
            order.push(key.clone());
            slots.insert(
                key.clone(),
                Signature {
                    family: family.to_string(),
                    original_index: Some(index),
                    array_position: None,
                    label: None,
                    label_field: None,
                    value: None,
                    value_present: false,
                    role: None,
                    p_field: None,
                    basis: "report_entry",
                },
            );
        }
        let slot = slots.get_mut(&key).expect("slot inserted above");
        let value = entry
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        match entry.get("sub").and_then(Value::as_str) {
            Some("Name") | Some("Key") => {
                slot.label = Some(value);
                slot.label_field = Some(label_field_of(family));
            }
            Some("Value") => {
                slot.value = Some(value);
                slot.value_present = true;
            }
            Some(_) => {}
            None => {
                slot.value = Some(value);
                slot.value_present = true;
            }
        }
    }
    // Array position follows the ascending index order of the report JSON.
    let mut families: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for (family, index) in &order {
        families.entry(family.as_str()).or_default().push(*index);
    }
    for indices in families.values_mut() {
        indices.sort_unstable();
    }
    let mut out = Vec::with_capacity(order.len());
    for key in &order {
        let mut signature = slots.remove(key).expect("ordered slot");
        signature.array_position = families
            .get(key.0.as_str())
            .and_then(|indices| indices.iter().position(|index| *index == key.1))
            .map(|position| position as i64);
        if signature.family == "Sig" {
            signature.role = schema
                .and_then(|schema| usize::try_from(key.1).ok().and_then(|i| schema.roles.get(i)))
                .copied();
        }
        out.push(signature);
    }
    Some(out)
}

/// Results written before the complete raw text, entry list and read status
/// were preserved cannot be presented as fully preserved evidence.
pub fn reparse_required(detail: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "WER/WER_Reports.sqlite: {detail} — 이 결과는 원문·원문 인덱스·읽기 상태를 \
         보존하기 전 저장본입니다. WER를 다시 파싱해야 오류 보고 저장을 생성할 수 있습니다"
    )
}

pub fn from_report_row(row: &Row, rowid: i64) -> anyhow::Result<WerRecord> {
    let mut record = WerRecord::new(Origin::ReportFile);
    record.source_rowid = Some(rowid);
    record.source_file = text_of(row, "_source_file");
    record.record_key = format!("WER_Reports::WER_Reports::{rowid}");
    record.set("source_file", record.source_file.clone());
    record.set("record_key", record.record_key.clone());
    let status = match row.get("_status").map(String::as_str) {
        Some(status) if !status.is_empty() => status.to_string(),
        _ => return Err(reparse_required(&format!("rowid {rowid}: _status 없음"))),
    };
    record.set("parse_status", status.clone());
    record.set("parse_error", text_of(row, "_error"));
    record.set("report_encoding", text_of(row, "encoding"));
    record.set("report_decode_status", text_of(row, "decode_status"));
    record.set("report_decode_error", text_of(row, "decode_error"));
    record.set("report_byte_size", text_of(row, "byte_size"));
    record.set("report_line_count", text_of(row, "line_count"));
    record.set("report_entry_count", text_of(row, "entry_count"));
    record.set(
        "report_unparsed_line_count",
        text_of(row, "unparsed_line_count"),
    );
    // An empty report file and a missing body are different facts.
    record.set(
        "payload_state",
        match row.get("report_text") {
            None => "absent",
            Some(value) if value.is_empty() => "present_empty",
            Some(_) => "present",
        },
    );
    record.set("report_text", text_of(row, "report_text"));
    record.set("report_entries_json", text_of(row, "entries_json"));
    record.set("report", text_of(row, "report"));
    record.set("payload_format", "report_file");
    if status != "parsed" {
        // A failed read keeps its row and no invented values.
        record.set("app_path_status", "not_recorded");
        return Ok(record);
    }

    record.timestamp = text_of(row, "timestamp");
    // The parser always writes the body of a parsed row; a body that no longer
    // parses is damaged facts, not a report without values.
    let report: Value = serde_json::from_str(record.get("report")).map_err(|error| {
        reparse_required(&format!("rowid {rowid}: report 해석 실패 ({error})"))
    })?;
    for &(key, column) in REPORT_SCALARS {
        if let Some(value) = report.get(key).and_then(Value::as_str) {
            record.set(column, value);
        }
    }
    // The promoted facts columns stay authoritative for the scalars the
    // parser lifted.
    for (key, column) in [
        ("EventType", "error_type"),
        ("AppName", "app_name"),
        ("AppPath", "app_path"),
        ("TargetAppId", "target_app_id"),
        ("ReportIdentifier", "report_identifier"),
    ] {
        record.set(column, text_of(row, key));
    }
    let error_type = record.get("error_type").to_string();
    let schema = schema_for(&error_type);
    record.set("event_time_source", "EventTime");
    record.set("event_time_precision", "filetime_100ns");
    record.set("app_name_field", "AppName");
    if let Some(upload) = record
        .get("upload_time_raw")
        .parse::<i64>()
        .ok()
        .map(fmt_filetime)
    {
        record.set("upload_time", upload);
    }

    let entries = row
        .get("entries_json")
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| reparse_required(&format!("rowid {rowid}: entries_json 없음")))?;
    record.signatures = signatures_from_entries(entries, schema.as_ref())
        .ok_or_else(|| reparse_required(&format!("rowid {rowid}: entries_json 해석 실패")))?;
    record.set("signature_index_source", "raw_entries");
    apply_schema(&mut record, schema, "event_type");

    // Loaded modules are recorded paths of the faulting process image set.
    let modules: Vec<String> = record
        .signatures
        .iter()
        .filter(|signature| signature.family == "LoadedModule")
        .filter_map(|signature| signature.value.clone())
        .collect();
    for module in modules {
        record.path("loaded_module", &module, "report_entry");
    }
    let app_path = record.get("app_path").to_string();
    record.set(
        "app_path_status",
        if app_path.is_empty() {
            "not_recorded"
        } else {
            "recorded"
        },
    );
    record.path("app_path", &app_path, "report_scalar");
    let source_file = record.source_file.clone();
    if !source_file.is_empty() {
        record.path("report_file", &source_file, "collected_file_location");
        // The collected file location is not a host path, so store_path stays
        // for the 1001 StorePath; only the store folder name is read here.
        let folder = Path::new(&source_file)
            .parent()
            .map(|parent| parent.to_string_lossy().to_string())
            .unwrap_or_default();
        record.set("store_location", store_location(&folder));
        record.set("store_location_basis", "report_file_location");
    }

    if let Some((pid, start)) = guid_pid_and_start(record.get("app_session_guid")) {
        record.set("app_pid", pid.to_string());
        record.set("app_start_time", start);
        record.set("app_start_time_raw", record.get("app_session_guid").to_string());
        record.set("app_start_time_source", "AppSessionGuid");
    }
    finish_times(&mut record);

    let identifiers = [
        ("report_identifier", record.get("report_identifier").to_string()),
        (
            "integrator_report_identifier",
            record.get("integrator_report_identifier").to_string(),
        ),
    ];
    for (role, value) in identifiers {
        record.identifier(role, &value);
    }
    Ok(record)
}

// --- EventLog records -------------------------------------------------------

/// Payload keys lifted to typed columns per provider.
const EVENT_1001_SCALARS: &[(&str, &str)] = &[
    ("EventName", "error_type"),
    ("Bucket", "bucket"),
    ("BucketType", "bucket_type"),
    ("HashedBucket", "hashed_bucket"),
    ("Response", "response_text"),
    ("CabId", "cab_id"),
    ("CabGuid", "cab_guid"),
    ("AnalysisSymbol", "analysis_symbol"),
    ("Rechecking", "rechecking_raw"),
    ("ReportId", "report_id"),
    ("ReportStatus", "report_status_raw"),
    ("StorePath", "store_path"),
];

const EVENT_1000_SCALARS: &[(&str, &str)] = &[
    ("AppName", "app_name"),
    ("AppVersion", "app_version"),
    ("AppTimeStamp", "app_timestamp"),
    ("ModuleName", "module_name"),
    ("ModuleVersion", "module_version"),
    ("ModuleTimeStamp", "module_timestamp"),
    ("ExceptionCode", "exception_code"),
    ("FaultingOffset", "exception_offset"),
    ("ProcessId", "app_pid_raw"),
    ("ProcessCreationTime", "app_start_time_raw"),
    ("AppPath", "app_path"),
    ("ModulePath", "module_path"),
    ("IntegratorReportId", "integrator_report_id"),
    ("PackageFullName", "package_full_name"),
    ("PackageRelativeAppId", "package_relative_app_id"),
];

const EVENT_1002_SCALARS: &[(&str, &str)] = &[
    ("AppName", "app_name"),
    ("AppVersion", "app_version"),
    ("ProcessId", "app_pid_raw"),
    ("StartTime", "app_start_time_raw"),
    ("TerminationTime", "termination_time_raw"),
    ("ExeFileName", "app_path"),
    ("ReportId", "report_id"),
    ("HangType", "hang_type_text"),
    ("PackageFullName", "package_full_name"),
    ("PackageRelativeAppId", "package_relative_app_id"),
];

/// Template insert order (%1..%n) of each provider's message; an unnamed
/// `Data.#text` payload carries the values in exactly this order.
const EVENT_1001_ORDER: &[&str] = &[
    "Bucket", "BucketType", "EventName", "Response", "CabId", "P1", "P2", "P3", "P4", "P5",
    "P6", "P7", "P8", "P9", "P10", "AttachedFiles", "StorePath", "AnalysisSymbol", "Rechecking",
    "ReportId", "ReportStatus", "HashedBucket", "CabGuid",
];
const EVENT_1000_ORDER: &[&str] = &[
    "AppName", "AppVersion", "AppTimeStamp", "ModuleName", "ModuleVersion", "ModuleTimeStamp",
    "ExceptionCode", "FaultingOffset", "ProcessId", "ProcessCreationTime", "AppPath", "ModulePath",
    "IntegratorReportId", "PackageFullName", "PackageRelativeAppId",
];
const EVENT_1002_ORDER: &[&str] = &[
    "AppName", "AppVersion", "ProcessId", "StartTime", "TerminationTime", "ExeFileName", "ReportId",
    "PackageFullName", "PackageRelativeAppId", "HangType",
];

/// Normalize the payload shape without hiding which shape was stored.
fn event_payload(raw: &str, order: &[&str]) -> (serde_json::Map<String, Value>, &'static str) {
    let mut map = parse_eventdata(raw);
    let mut format = "named";
    if let Some(Value::Object(inner)) = map.get("EventXML").cloned() {
        map = inner;
        format = "nested_eventxml";
    }
    if !order.iter().any(|key| map.contains_key(*key)) {
        let array = map
            .get("Data")
            .and_then(|value| value.get("#text"))
            .and_then(Value::as_array)
            .cloned();
        if let Some(array) = array {
            for (key, value) in order.iter().zip(array.iter()) {
                let text = match value {
                    Value::String(text) => text.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                map.insert((*key).to_string(), Value::String(text));
            }
            format = "unnamed_data_array";
        }
    }
    (map, format)
}

/// `basis` names the type field the schema was chosen from.
fn apply_schema(record: &mut WerRecord, schema: Option<Schema>, basis: &'static str) {
    match schema {
        Some(schema) => {
            record.set("signature_schema", schema.id);
            record.set("signature_schema_status", "mapped");
            record.set("error_class", schema.class);
            record.set("error_class_basis", basis);
            let mapped: Vec<(&'static str, String)> = record
                .signatures
                .iter()
                .filter_map(|signature| {
                    let role = signature.role?;
                    let value = signature.value.clone()?;
                    (!value.is_empty()).then_some((role_column(role), value))
                })
                .collect();
            for (column, value) in mapped {
                record.set(column, value);
            }
        }
        None => {
            record.set("signature_schema_status", "unmapped");
            if record.get("error_class").is_empty() {
                record.set("error_class", "unclassified");
                record.set("error_class_basis", "unverified_type");
            }
        }
    }
}

/// Elapsed milliseconds between two stored KST timestamps.
fn elapsed_ms(start: &str, end: &str) -> Option<i64> {
    let fmt = "%Y-%m-%d %H:%M:%S%.f";
    let start = chrono::NaiveDateTime::parse_from_str(start.trim(), fmt).ok()?;
    let end = chrono::NaiveDateTime::parse_from_str(end.trim(), fmt).ok()?;
    let delta = end.signed_duration_since(start).num_milliseconds();
    (delta >= 0).then_some(delta)
}

fn finish_times(record: &mut WerRecord) {
    let start = record.get("app_start_time").to_string();
    let report = record.timestamp.clone();
    if !start.is_empty() && !report.is_empty() {
        let uptime = duration_kr(&start, &report);
        if !uptime.is_empty() {
            record.set("app_uptime", uptime);
        }
        // The computed span is start → report; the report is not an exit.
        record.set("app_uptime_basis", "start_to_report");
        if let Some(ms) = elapsed_ms(&start, &report) {
            record.set("app_uptime_ms", ms.to_string());
        }
    }
}

pub fn from_event_row(row: &Row) -> Option<WerRecord> {
    let provider = row.get("Provider").map(String::as_str).unwrap_or_default();
    let event_id = row.get("EventID").map(String::as_str).unwrap_or_default();
    let origin = match (provider, event_id) {
        ("Windows Error Reporting", "1001") => Origin::Reporting1001,
        ("Application Error", "1000") => Origin::AppError1000,
        ("Application Hang", "1002") => Origin::AppHang1002,
        _ => return None,
    };
    let mut record = WerRecord::new(origin);
    record.timestamp = text_of(row, "timestamp");
    record.record_key = text_of(row, "_record_key");
    record.source_file = text_of(row, "_source_file");
    record.set("record_key", record.record_key.clone());
    record.set("source_file", record.source_file.clone());
    record.set("provider", provider);
    record.set("event_id", event_id);
    for (key, column) in [
        ("Channel", "channel"),
        ("Computer", "computer"),
        ("EventRecordID", "event_record_id"),
        ("LevelName", "level_name"),
        ("Keywords", "keywords_raw"),
        ("ProcessID", "logging_process_id"),
        ("ThreadID", "logging_thread_id"),
        ("ActivityID", "activity_id"),
        ("RelatedActivityID", "related_activity_id"),
        ("_status", "facts_status"),
        ("_error", "facts_error"),
    ] {
        record.set(column, text_of(row, key));
    }
    // The event row's own read status; a corrupted chunk keeps its state.
    record.set(
        "parse_status",
        match record.get("facts_status") {
            "" => "parsed".to_string(),
            status => status.to_string(),
        },
    );
    // The EVTX subject writes the record; it is not the application's owner.
    let subject = text_of(row, "UserID");
    if !subject.is_empty() {
        record.set("record_subject_sid", subject);
        record.set("account_role", "record_subject");
    }
    record.set("app_account_status", "unknown");
    record.set("event_time_source", "EVTX SystemTime");
    record.set("event_time_precision", "millisecond");
    // A stored empty payload and a missing payload are different facts.
    record.set(
        "payload_state",
        match row.get("EventData") {
            None => "absent",
            Some(value) if value.is_empty() => "present_empty",
            Some(_) => "present",
        },
    );
    let raw = text_of(row, "EventData");
    record.set("event_data_raw", raw.clone());
    let order = match origin {
        Origin::Reporting1001 => EVENT_1001_ORDER,
        Origin::AppError1000 => EVENT_1000_ORDER,
        Origin::AppHang1002 => EVENT_1002_ORDER,
        Origin::ReportFile => unreachable!("report files are built from facts rows"),
    };
    let (payload, format) = event_payload(&raw, order);
    record.set("payload_format", format);

    let scalars = match origin {
        Origin::Reporting1001 => EVENT_1001_SCALARS,
        Origin::AppError1000 => EVENT_1000_SCALARS,
        Origin::AppHang1002 => EVENT_1002_SCALARS,
        Origin::ReportFile => unreachable!("report files are built from facts rows"),
    };
    for &(key, column) in scalars {
        record.set(column, jget(&payload, key));
    }

    match origin {
        Origin::Reporting1001 => {
            let error_type = record.get("error_type").to_string();
            let schema = schema_for(&error_type);
            for index in 1..=10usize {
                let field = format!("P{index}");
                let Some(value) = payload.get(&field) else {
                    continue;
                };
                let value = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                record.signatures.push(Signature {
                    family: "P".into(),
                    original_index: Some(index as i64),
                    array_position: None,
                    label: None,
                    label_field: None,
                    value: Some(value),
                    value_present: true,
                    role: schema
                        .as_ref()
                        .and_then(|schema| schema.roles.get(index - 1))
                        .copied(),
                    p_field: Some(field),
                    basis: "event_p_field",
                });
            }
            // P1 names the application only in a confirmed layout whose first
            // role is the application; otherwise it stays a signature value.
            let p1_is_app = schema
                .as_ref()
                .is_some_and(|schema| schema.roles.first() == Some(&"app_name"));
            apply_schema(&mut record, schema, "event_name");
            // The 1001 payload records no application path; a module path is
            // never promoted into app_path.
            record.set("app_path_status", "not_recorded");
            if p1_is_app {
                record.set("app_name", jget(&payload, "P1"));
                if !record.get("app_name").is_empty() {
                    record.set("app_name_field", "P1");
                }
            }
            let store = record.get("store_path").to_string();
            if !store.is_empty() {
                record.set("store_location", store_location(&store));
                record.set("store_location_basis", "event_store_path");
                record.path("store_path", &store, "event_payload");
            }
            for attached in jget(&payload, "AttachedFiles")
                .split(['\r', '\n'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
            {
                record.path("attached_file", &attached, "event_payload");
            }
            record.set("attached_files_raw", jget(&payload, "AttachedFiles"));
            record.identifier("report_id", &record.get("report_id").to_string());
        }
        Origin::AppError1000 | Origin::AppHang1002 => {
            // The provider itself states the event meaning; no position guess.
            record.set(
                "error_class",
                if origin == Origin::AppError1000 {
                    "crash"
                } else {
                    "hang"
                },
            );
            record.set("error_class_basis", "provider_event");
            record.set("error_type", provider);
            record.set("signature_schema_status", "named_payload");
            record.set("app_name_field", "AppName");
            let app_path = record.get("app_path").to_string();
            record.set(
                "app_path_status",
                if app_path.is_empty() {
                    "not_recorded"
                } else {
                    "recorded"
                },
            );
            record.path("app_path", &app_path, "event_payload");
            let module_path = record.get("module_path").to_string();
            record.path("module_path", &module_path, "event_payload");
            let start_raw = record.get("app_start_time_raw").to_string();
            let start = filetime_from_hex_number(&start_raw);
            if !start.is_empty() {
                record.set("app_start_time", start);
                record.set(
                    "app_start_time_source",
                    if origin == Origin::AppError1000 {
                        "ProcessCreationTime"
                    } else {
                        "StartTime"
                    },
                );
            }
            if let Some(pid) = hex_u64(record.get("app_pid_raw")) {
                record.set("app_pid", pid.to_string());
            }
            if origin == Origin::AppError1000 {
                record.identifier(
                    "integrator_report_id",
                    &record.get("integrator_report_id").to_string(),
                );
            } else {
                record.identifier("report_id", &record.get("report_id").to_string());
            }
        }
        Origin::ReportFile => unreachable!("report files are built from facts rows"),
    }
    finish_times(&mut record);
    Some(record)
}

/// Every WER record of this result, report files first and then events, in
/// the order their sources were read. Facts written before the complete raw
/// preservation fail here instead of looking fully preserved.
pub fn collect(out_dir: &Path, events: &EventLogOverviewCache) -> anyhow::Result<Vec<WerRecord>> {
    let facts = out_dir.join("WER").join("WER_Reports.sqlite");
    let mut records = Vec::new();
    for row in read_table_with_rowid(&facts, "WER_Reports")? {
        let rowid = row
            .get("__source_rowid")
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or_else(|| reparse_required("원본 rowid를 읽지 못했습니다"))?;
        records.push(from_report_row(&row, rowid)?);
    }
    records.extend(events.rows().iter().filter_map(from_event_row));
    Ok(records)
}

/// Execution evidence for ExecutionHistory: a decoded process creation time
/// from the report's own session value. Reporting time is not an exit time.
/// It reads the records already collected for WerReports, so both overviews
/// share one collection.
pub fn execution_start_evidence(records: &[WerRecord]) -> Vec<Row> {
    records
        .iter()
        .filter(|record| record.get("app_start_time_source") == "AppSessionGuid")
        .filter_map(|record| {
            let path = record.get("app_path").to_string();
            let name = match record.get("app_name") {
                "" => basename_win(&path),
                name => name.to_string(),
            };
            if name.is_empty() {
                return None;
            }
            Some(Row::from([
                ("timestamp".to_string(), record.get("app_start_time").to_string()),
                ("program_name".to_string(), name),
                ("program_path".to_string(), path),
                ("user".to_string(), String::new()),
                ("source_artifact".to_string(), "WER".to_string()),
                ("record_key".to_string(), record.record_key.clone()),
            ]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::Row;

    fn report_row(event_type: &str, extra: &str, entries: &str) -> Row {
        let report = format!(
            r#"{{"Version": "1", "EventType": "{event_type}", "EventTime": "134350754916815872", "ReportIdentifier": "11111111-1111-1111-1111-111111111111"{extra}}}"#
        );
        Row::from([
            ("timestamp".into(), "2026-09-28 22:24:51.681".into()),
            ("EventType".into(), event_type.into()),
            ("AppName".into(), "UltraViewer".into()),
            ("AppPath".into(), "C:\\Program Files\\UltraViewer\\app.exe".into()),
            ("ReportIdentifier".into(), "11111111-1111-1111-1111-111111111111".into()),
            ("report".into(), report),
            ("entries_json".into(), entries.into()),
            ("report_text".into(), "EventType=x\r\n".into()),
            ("encoding".into(), "utf-16le-bom".into()),
            ("decode_status".into(), "ok".into()),
            ("_status".into(), "parsed".into()),
            (
                "_source_file".into(),
                "/case/WER/ReportArchive/Critical_app_1/Report.wer".into(),
            ),
        ])
    }

    fn event_row(provider: &str, id: &str, payload: &str) -> Row {
        Row::from([
            ("Provider".into(), provider.into()),
            ("EventID".into(), id.into()),
            ("Channel".into(), "Application".into()),
            ("Computer".into(), "HOST".into()),
            ("EventRecordID".into(), "42".into()),
            ("UserID".into(), "S-1-5-18".into()),
            ("ProcessID".into(), "1234".into()),
            ("timestamp".into(), "2026-09-28 22:24:51.822".into()),
            ("EventData".into(), payload.into()),
            ("_record_key".into(), "Application::7".into()),
            ("_source_file".into(), "Application.evtx".into()),
        ])
    }

    /// R01/R04/A05: confirmed hang layout, original Sig/DynamicSig indices and
    /// the label text all survive; nothing lands in the crash columns.
    #[test]
    fn report_file_keeps_original_indices_roles_and_labels() {
        let entries = r#"[
            {"line":1,"key":"Sig[0].Name","family":"Sig","index":0,"sub":"Name","value":"Application Name"},
            {"line":2,"key":"Sig[0].Value","family":"Sig","index":0,"sub":"Value","value":"app.exe"},
            {"line":3,"key":"Sig[3].Name","family":"Sig","index":3,"sub":"Name","value":"Hang Signature"},
            {"line":4,"key":"Sig[3].Value","family":"Sig","index":3,"sub":"Value","value":"7ef1"},
            {"line":5,"key":"Sig[4].Name","family":"Sig","index":4,"sub":"Name","value":"Hang Type"},
            {"line":6,"key":"Sig[4].Value","family":"Sig","index":4,"sub":"Value","value":"67246080"},
            {"line":7,"key":"DynamicSig[1].Name","family":"DynamicSig","index":1,"sub":"Name","value":"OS 버전"},
            {"line":8,"key":"DynamicSig[1].Value","family":"DynamicSig","index":1,"sub":"Value","value":"10.0"},
            {"line":9,"key":"OsInfo[30].Key","family":"OsInfo","index":30,"sub":"Key","value":"buildflightid"},
            {"line":10,"key":"LoadedModule[0]","family":"LoadedModule","index":0,"value":"C:\\WINDOWS\\ntdll.dll"}
        ]"#;
        let record = from_report_row(&report_row("AppHangB1", "", entries), 7).unwrap();
        assert_eq!(record.origin, Origin::ReportFile);
        assert_eq!(record.get("signature_schema"), "apphang_b1");
        assert_eq!(record.get("signature_schema_status"), "mapped");
        assert_eq!(record.get("hang_signature"), "7ef1");
        assert_eq!(record.get("hang_type_raw"), "67246080");
        assert_eq!(record.get("module_name"), "");
        assert_eq!(record.get("exception_code"), "");
        assert_eq!(record.get("error_class"), "hang");
        let dynamic: Vec<_> = record
            .signatures
            .iter()
            .filter(|s| s.family == "DynamicSig")
            .map(|s| (s.original_index, s.array_position, s.label.clone()))
            .collect();
        assert_eq!(dynamic, vec![(Some(1), Some(0), Some("OS 버전".into()))]);
        let flight = record
            .signatures
            .iter()
            .find(|s| s.label.as_deref() == Some("buildflightid"))
            .unwrap();
        assert_eq!((flight.original_index, flight.value_present), (Some(30), false));
        let module = record
            .signatures
            .iter()
            .find(|s| s.family == "LoadedModule")
            .unwrap();
        assert_eq!(module.value.as_deref(), Some("C:\\WINDOWS\\ntdll.dll"));
        assert_eq!(module.role, None);
        // The report file location is the store folder; it is not a claim
        // about any collected file.
        assert_eq!(record.get("store_location"), "ReportArchive");
        assert!(record.paths.iter().any(|p| p.role == "loaded_module"));
    }

    /// R01: an unverified signature layout keeps every value but refuses to
    /// guess which position means module or exception.
    #[test]
    fn unmapped_type_keeps_values_without_position_guesses() {
        let payload = r#"{"EventName":"CbsPackageServicingFailure2","P1":"10.0.26100.32131","P6":"80070005","P8":"Installed","ReportId":"22222222-2222-2222-2222-222222222222"}"#;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(record.get("signature_schema"), "");
        assert_eq!(record.get("signature_schema_status"), "unmapped");
        assert_eq!(record.get("error_class"), "unclassified");
        assert_eq!(record.get("error_class_basis"), "unverified_type");
        assert_eq!(record.get("module_name"), "");
        assert_eq!(record.get("exception_code"), "");
        assert_eq!(record.get("hresult"), "");
        let p6 = record
            .signatures
            .iter()
            .find(|s| s.p_field.as_deref() == Some("P6"))
            .unwrap();
        assert_eq!((p6.value.as_deref(), p6.role), (Some("80070005"), None));
    }

    /// R01/A04: BEX64 keeps the offset out of the exception code column.
    #[test]
    fn bex64_offset_is_not_stored_as_the_exception_code() {
        let payload = r#"{"EventName":"BEX64","P1":"WSCAgent.exe","P2":"2022.9.0.1","P3":"69733389","P4":"WSCAgent.exe","P5":"2022.9.0.1","P6":"69733389","P7":"000000000005eb94","P8":"c0000409","P9":"0000000000000007","ReportId":"33333333-3333-3333-3333-333333333333","StorePath":"\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_WSCAgent"}"#;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(record.get("exception_code"), "c0000409");
        assert_eq!(record.get("exception_offset"), "000000000005eb94");
        assert_eq!(record.get("exception_data"), "0000000000000007");
        assert_eq!(record.get("module_name"), "WSCAgent.exe");
        assert_eq!(record.get("error_class"), "crash");
        assert_eq!(record.get("store_location"), "ReportArchive");
    }

    /// R01/A04: StoreAgent failures are an update-failure family; OSRevision
    /// and HResult keep their own roles instead of becoming module/exception.
    #[test]
    fn store_agent_keeps_hresult_and_os_revision_in_their_own_roles() {
        let payload = r#"{"EventName":"StoreAgentScanForUpdatesFailure0","P1":"Update;","P2":"80070005","P3":"26100","P4":"32230","P5":"Windows.Server","ReportId":"44444444-4444-4444-4444-444444444444","ReportStatus":4,"StorePath":"\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\NonCritical_Update"}"#;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(record.get("hresult"), "80070005");
        assert_eq!(record.get("os_revision"), "32230");
        assert_eq!(record.get("client_app_id"), "Update;");
        assert_eq!(record.get("module_name"), "");
        assert_eq!(record.get("exception_code"), "");
        assert_eq!(record.get("error_class"), "store_update_failure");
        assert_eq!(record.get("store_location"), "ReportQueue");
        assert_eq!(record.get("report_status_raw"), "4");
    }

    /// R02: the 1001 payload carries no application path; a module path is
    /// never promoted into app_path.
    #[test]
    fn eventlog_1001_leaves_app_path_empty() {
        let payload = r#"{"EventName":"APPCRASH","P1":"app.exe","P4":"C:\\WINDOWS\\SYSTEM32\\ntdll.dll","P7":"c00000fd","P8":"00029787","ReportId":"55555555-5555-5555-5555-555555555555"}"#;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(record.get("app_path"), "");
        assert_eq!(record.get("app_path_status"), "not_recorded");
        assert_eq!(record.get("module_name"), "C:\\WINDOWS\\SYSTEM32\\ntdll.dll");
        assert_eq!(record.get("app_name"), "app.exe");
        assert_eq!(record.get("app_name_field"), "P1");
        assert!(!record.paths.iter().any(|p| p.role == "app_path"));
    }

    /// A01/A06: hex FILETIME numbers decode as numbers; the AppSessionGuid
    /// trailer decodes as little-endian bytes. The two never share a decoder.
    #[test]
    fn hex_filetime_and_session_guid_use_separate_decoders() {
        let payload = r#"{"AppName":"UltraViewer_Desktop.exe","ProcessId":"0x23db8","StartTime":"0x1dd4f4c6a044dcb","TerminationTime":4294967295,"ExeFileName":"C:\\Program Files (x86)\\UltraViewer\\UltraViewer_Desktop.exe","ReportId":"8fbe709e-2057-499d-b338-1a8a3d2b1c15","HangType":"Top level window is idle"}"#;
        let hang = from_event_row(&event_row("Application Hang", "1002", payload)).unwrap();
        assert_eq!(hang.get("app_start_time_source"), "StartTime");
        assert_eq!(hang.get("app_start_time"), crate::time::fmt_filetime(0x1dd4f4c6a044dcb));
        assert_eq!(hang.get("app_pid"), "146872");
        assert_eq!(hang.get("app_pid_raw"), "0x23db8");
        // 4294967295 is not a time; it stays raw and never becomes a flag.
        assert_eq!(hang.get("termination_time_raw"), "4294967295");
        assert_eq!(hang.get("hang_type_text"), "Top level window is idle");
        assert_eq!(hang.get("error_class"), "hang");
        assert_eq!(hang.get("app_path"), "C:\\Program Files (x86)\\UltraViewer\\UltraViewer_Desktop.exe");

        let entries = "[]";
        let guid = r#", "AppSessionGuid": "000011e8-0000-000a-6189-bef9f6f7dc01""#;
        let report = from_report_row(&report_row("APPCRASH", guid, entries), 3).unwrap();
        assert_eq!(guid_pid_and_start("000011e8-0000-000a-6189-bef9f6f7dc01").unwrap().0, 4584);
        assert_eq!(report.get("app_pid"), "4584");
        assert_eq!(report.get("app_start_time_source"), "AppSessionGuid");
        assert_eq!(report.get("app_uptime_basis"), "start_to_report");
        assert_ne!(report.get("app_uptime_ms"), "");
    }

    /// R05: the recording subject SID is not the application's owner.
    #[test]
    fn subject_sid_is_kept_in_its_own_role() {
        let payload = r#"{"AppName":"UltraViewer_Desktop.exe","ModuleName":"ntdll.dll","ExceptionCode":"c00000fd","FaultingOffset":"00029787","ProcessId":"0x15c0","ProcessCreationTime":"0x1dcd22aeaf5e3d1","AppPath":"C:\\app.exe","ModulePath":"C:\\WINDOWS\\SYSTEM32\\ntdll.dll","IntegratorReportId":"097b6cfe-1eb1-4297-a3c7-9b9f090ae496"}"#;
        let record = from_event_row(&event_row("Application Error", "1000", payload)).unwrap();
        assert_eq!(record.get("record_subject_sid"), "S-1-5-18");
        assert_eq!(record.get("account_role"), "record_subject");
        assert_eq!(record.get("app_account_status"), "unknown");
        assert_eq!(record.get("module_path"), "C:\\WINDOWS\\SYSTEM32\\ntdll.dll");
        assert_eq!(record.get("app_path"), "C:\\app.exe");
        assert_eq!(record.get("exception_offset"), "00029787");
        assert_eq!(record.get("app_start_time_source"), "ProcessCreationTime");
        assert_eq!(
            record.identifiers,
            vec![Identifier {
                role: "integrator_report_id",
                value: "097b6cfe-1eb1-4297-a3c7-9b9f090ae496".into()
            }]
        );
        assert_eq!(record.get("error_class_basis"), "provider_event");
        // A machine-wide report file has no account evidence at all.
        let report = from_report_row(&report_row("APPCRASH", "", "[]"), 1).unwrap();
        assert_eq!(report.get("record_subject_sid"), "");
        assert_eq!(report.get("account_role"), "");
    }

    /// R16: a failed read stays a record with its status and no invented data.
    #[test]
    fn unreadable_report_row_keeps_failure_state() {
        let row = Row::from([
            ("timestamp".into(), String::new()),
            ("_status".into(), "unreadable_file".into()),
            ("_error".into(), "permission denied".into()),
            ("_source_file".into(), "/case/WER/ReportQueue/x/Report.wer".into()),
        ]);
        let record = from_report_row(&row, 9).unwrap();
        assert_eq!(record.get("parse_status"), "unreadable_file");
        assert_eq!(record.get("parse_error"), "permission denied");
        assert_eq!(record.get("error_type"), "");
        assert!(record.signatures.is_empty() && record.identifiers.is_empty());
        assert_eq!(record.timestamp, "");
    }

    /// R16: facts written before raw preservation fail with a reparse
    /// instruction instead of looking fully preserved.
    #[test]
    fn legacy_facts_require_reparse() {
        let mut row = report_row("APPCRASH", "", "[]");
        row.remove("_status");
        let error = from_report_row(&row, 4).err().expect("legacy facts must require reparse").to_string();
        assert!(error.contains("다시 파싱"), "{error}");
        let mut row = report_row("APPCRASH", "", "[]");
        row.insert("entries_json".into(), String::new());
        assert!(from_report_row(&row, 5).is_err());
    }

    /// R03: the synthetic unnamed EventData layout is normalized but labelled,
    /// and the real named layout is left untouched.
    #[test]
    fn unnamed_eventdata_is_normalized_and_labelled() {
        let payload = r##"{"Data":{"#text":["0","0","APPCRASH","x","y","app.exe","1.0","abc","ntdll.dll"]}}"##;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(record.get("payload_format"), "unnamed_data_array");
        assert_eq!(record.get("error_type"), "APPCRASH");
        assert_eq!(record.get("app_name"), "app.exe");
        assert_eq!(record.get("module_name"), "ntdll.dll");
        assert_eq!(record.get("event_data_raw"), payload);
        let named = from_event_row(&event_row(
            "Windows Error Reporting",
            "1001",
            r#"{"EventName":"APPCRASH","P1":"app.exe"}"#,
        ))
        .unwrap();
        assert_eq!(named.get("payload_format"), "named");
    }

    /// Real unnamed `Data.#text` payloads map by each provider's template
    /// order (message inserts %1..%n), not by the 1001 P-field layout.
    #[test]
    fn unnamed_payloads_follow_the_provider_template_order() {
        let crash = r##"{"Data": {"#text": ["mc3504.exe", "0.0.0.0", "6aa7950a", "mc3504.exe", "0.0.0.0", "6aa7950a", "c00000fd", "00000000000049f2", "588", "01dd446c6b8359f5", "C:\\Windows\\TEMP\\mc3504.exe", "C:\\Windows\\TEMP\\mc3504.exe", "d91d8a2b-0278-4b88-bc1a-5df632a50437", "", ""]}, "Binary": null}"##;
        let record = from_event_row(&event_row("Application Error", "1000", crash)).unwrap();
        assert_eq!(record.get("payload_format"), "unnamed_data_array");
        assert_eq!(record.get("app_name"), "mc3504.exe");
        assert_eq!(record.get("module_name"), "mc3504.exe");
        assert_eq!(record.get("exception_code"), "c00000fd");
        assert_eq!(record.get("exception_offset"), "00000000000049f2");
        assert_eq!(record.get("app_pid"), "1416");
        assert_eq!(record.get("app_path"), "C:\\Windows\\TEMP\\mc3504.exe");
        assert_eq!(record.get("module_path"), "C:\\Windows\\TEMP\\mc3504.exe");
        assert_eq!(record.get("integrator_report_id"), "d91d8a2b-0278-4b88-bc1a-5df632a50437");
        assert_eq!(record.get("app_start_time_source"), "ProcessCreationTime");
        assert_eq!(record.get("package_full_name"), "");

        let report = r##"{"Data": {"#text": ["", "0", "MoAppCrash", "사용할 수 없음", "0", "Microsoft.Windows.Search_1.14.18.19041_neutral_neutral_cw5n1h2txyewy", "praid:CortanaUI", "10.0.19041.6282", "87634c04", "StackHash12_8b8", "0.0.0.0", "00000000", "8000ffff", "0", "", "", "\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\AppCrash_x", "", "0", "52b483f6-56c6-4c90-ab83-4f27efd26075", "6", "", "0"]}, "Binary": null}"##;
        let record = from_event_row(&event_row("Windows Error Reporting", "1001", report)).unwrap();
        assert_eq!(record.get("error_type"), "MoAppCrash");
        assert_eq!(record.get("bucket_type"), "0");
        assert_eq!(record.get("response_text"), "사용할 수 없음");
        // MoAppCrash is unmapped: P1 (a package name) stays a signature value.
        assert_eq!(record.get("app_name"), "");
        let p1 = record.signatures.iter().find(|s| s.p_field.as_deref() == Some("P1")).unwrap();
        assert_eq!(p1.value.as_deref(), Some("Microsoft.Windows.Search_1.14.18.19041_neutral_neutral_cw5n1h2txyewy"));
        assert_eq!(record.get("store_path"), "\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\AppCrash_x");
        assert_eq!(record.get("report_id"), "52b483f6-56c6-4c90-ab83-4f27efd26075");
        assert_eq!(record.get("report_status_raw"), "6");
        assert_eq!(record.get("cab_guid"), "0");
        assert_eq!(record.signatures.iter().filter(|s| s.family == "P").count(), 10);

        let hang = r##"{"Data": {"#text": ["app.exe", "1.0", "1a2b", "01dd446c6b8359f5", "4294967295", "C:\\app.exe", "11111111-2222-3333-4444-555555555555", "", "", "Unknown"]}}"##;
        let record = from_event_row(&event_row("Application Hang", "1002", hang)).unwrap();
        assert_eq!(record.get("app_name"), "app.exe");
        assert_eq!(record.get("app_path"), "C:\\app.exe");
        assert_eq!(record.get("report_id"), "11111111-2222-3333-4444-555555555555");
        assert_eq!(record.get("termination_time_raw"), "4294967295");
        assert_eq!(record.get("hang_type_text"), "Unknown");
    }

    /// A stored empty payload is not a missing payload.
    #[test]
    fn empty_payload_is_distinct_from_a_missing_one() {
        let mut row = event_row("Windows Error Reporting", "1001", "");
        assert_eq!(
            from_event_row(&row).unwrap().get("payload_state"),
            "present_empty"
        );
        row.remove("EventData");
        assert_eq!(from_event_row(&row).unwrap().get("payload_state"), "absent");
        assert_eq!(
            from_event_row(&event_row("Application Hang", "1002", "{}"))
                .unwrap()
                .get("payload_state"),
            "present"
        );
    }

    /// Only the approved providers become report records.
    #[test]
    fn unrelated_providers_are_not_error_reports() {
        assert!(from_event_row(&event_row(".NET Runtime", "1000", "{}")).is_none());
        assert!(from_event_row(&event_row("Microsoft-Windows-Winlogon", "1002", "{}")).is_none());
        assert!(from_event_row(&event_row(
            "Microsoft-Windows-WER-PayloadHealth",
            "1",
            "{}"
        ))
        .is_none());
    }

    /// A parsed facts row whose report body no longer parses is damaged facts,
    /// not a report without values.
    #[test]
    fn unparsable_report_body_requires_reparse() {
        let mut row = report_row("APPCRASH", "", "[]");
        row.insert("report".into(), "{\"EventType\": \"APPCRASH\"".into());
        let error = from_report_row(&row, 6).err().expect("damaged body must not pass").to_string();
        assert!(error.contains("다시 파싱"), "{error}");
    }

    /// The collected file location is not the host store path, and the store
    /// is the folder holding the report folder — never a substring of the
    /// analyst's collection path.
    #[test]
    fn store_location_comes_from_the_report_folder_parent() {
        let mut row = report_row("APPCRASH", "", "[]");
        row.insert(
            "_source_file".into(),
            "/cases/ReportQueue_export/WER/ReportArchive/AppCrash_app_1/Report.wer".into(),
        );
        let report = from_report_row(&row, 2).unwrap();
        assert_eq!(report.get("store_path"), "");
        assert_eq!(report.get("store_location"), "ReportArchive");
        assert_eq!(report.get("store_location_basis"), "report_file_location");
        assert!(!report.paths.iter().any(|p| p.role == "store_path"));
        assert!(report.paths.iter().any(|p| p.role == "report_file"));

        let payload = r#"{"EventName":"APPCRASH","P1":"app.exe","StorePath":"\\\\?\\C:\\ReportQueueTools\\WER\\ReportArchive\\AppCrash_app"}"#;
        let event = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(event.get("store_location"), "ReportArchive");
        let payload = r#"{"EventName":"APPCRASH","P1":"app.exe","StorePath":"C:\\Temp\\ReportArchive_copy"}"#;
        let event = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(event.get("store_location"), "unknown");
    }

    /// The class basis names the field the schema was chosen from.
    #[test]
    fn error_class_basis_names_the_type_field() {
        let report = from_report_row(&report_row("APPCRASH", "", "[]"), 1).unwrap();
        assert_eq!(report.get("error_class_basis"), "event_type");
        let payload = r#"{"EventName":"APPCRASH","P1":"app.exe"}"#;
        let event = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
        assert_eq!(event.get("error_class_basis"), "event_name");
    }

    /// 1001 P1 is an application name only for a confirmed layout whose first
    /// role is the application; codes never land in app_name.
    #[test]
    fn eventlog_1001_app_name_needs_a_confirmed_app_role() {
        for payload in [
            r#"{"EventName":"LiveKernelEvent","P1":"144","P2":"3"}"#,
            r#"{"EventName":"AppxDeploymentFailureBlue","P1":"80070057"}"#,
            r#"{"EventName":"StoreAgentScanForUpdatesFailure0","P1":"Update;","P2":"80070005"}"#,
        ] {
            let record = from_event_row(&event_row("Windows Error Reporting", "1001", payload)).unwrap();
            assert_eq!(record.get("app_name"), "", "{payload}");
            assert_eq!(record.get("app_name_field"), "", "{payload}");
        }
        let record = from_event_row(&event_row(
            "Windows Error Reporting",
            "1001",
            r#"{"EventName":"APPCRASH","P1":"app.exe"}"#,
        ))
        .unwrap();
        assert_eq!((record.get("app_name"), record.get("app_name_field")), ("app.exe", "P1"));
    }

    /// ExecutionHistory reads the already collected records; it never runs a
    /// second collection.
    #[test]
    fn execution_start_evidence_uses_collected_records() {
        let guid = r#", "AppSessionGuid": "000011e8-0000-000a-6189-bef9f6f7dc01""#;
        let mut row = report_row("APPCRASH", guid, "[]");
        row.insert("AppName".into(), String::new());
        let records = vec![
            from_report_row(&row, 3).unwrap(),
            from_report_row(&report_row("APPCRASH", "", "[]"), 4).unwrap(),
        ];
        let rows = execution_start_evidence(&records);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["program_name"], "app.exe");
        assert_eq!(rows[0]["record_key"], "WER_Reports::WER_Reports::3");
    }
}
