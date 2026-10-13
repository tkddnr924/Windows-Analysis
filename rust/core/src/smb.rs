//! SMB access history classification — viewer09 R01~R15 / A01~A05.
//!
//! Reads the shared EventLog facts cache and emits one typed event per
//! selected record. Interpretation only: every value comes from the record it
//! was read from, the original facts `Row` stays attached, and nothing here
//! invents a protocol, a result, a device, a share or a session.
//!
//! Boundaries this module keeps:
//!
//! * A Security type 3 logon is *network* authentication with an unspecified
//!   protocol. It is never promoted to SMB and never re-labelled as RDP.
//! * Share audit records (5140/5145/5168) are SMB-confirmed evidence, but an
//!   allowed access check is a *requested* access check, not a completed read,
//!   write, copy or exfiltration.
//! * SMBServer/SMBClient records are classified only for event IDs with
//!   verified published meaning. An unverified ID is retained with an unknown
//!   result — never forced to failure — and `Status` 0 never proves success.
//! * Success/failure of audited Security events comes from the record's
//!   `Keywords` audit mask, not from the event ID or level.
//! * 4634/4672 are context evidence of the same logon instance, not extra
//!   connections; a 4672 is kept only when its logon ID belongs to a selected
//!   direct event of the same log and computer (see `relations` for the
//!   bounded-instance and measured pre-logon rules). 4776 is authentication
//!   context that stays unlinked: it is never matched to a logon by time or
//!   account name.
//!
//! Published references for the semantics encoded below:
//!
//! * 5140 — <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140>
//! * 5145 (+ access token table) — <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145>
//! * 5168 — <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5168>
//! * 4625 (logon types, failure codes, NTLM package fields) — <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625>
//! * NTSTATUS values — <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55>
//! * ETW keyword bitmask layout — <https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events>
//! * SMBClient 31017/31018/31022 and SMBServer 3023 — <https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3>
//! * SMBServer/Audit 3000 (SMB1 access auditing) — <https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3>

mod relations;

use serde_json::{Map, Value};

use crate::overview::{jget, parse_eventdata, EventLogOverviewCache};
use crate::sqlite::Row;

const SEC: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";
const SMB_SERVER: &str = "Microsoft-Windows-SMBServer";
const SMB_CLIENT: &str = "Microsoft-Windows-SMBClient";

/// Microsoft-defined audit keywords in the top 16 bits of the ETW keyword
/// bitmask (`winmeta.xml`); Security records carry them verbatim, e.g.
/// `0x8020000000000000` on 5145 success and `0x8010000000000000` on 5168.
const KEYWORD_AUDIT_SUCCESS: u64 = 0x0020_0000_0000_0000;
const KEYWORD_AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;

/// Which side of the view an event belongs to. Context evidence is retained
/// and searchable but is never counted as a connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SmbRole {
    Direct,
    Context,
}

/// A definite link between one direct event and one context event. Both
/// indices address [`SmbClassification::events`] by position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmbRelation {
    pub main_index: usize,
    pub context_index: usize,
    /// `logon_instance_end` | `special_privileges`
    pub kind: &'static str,
    /// How the link was proven. Only `same_logon_id_bounded_instance` exists:
    /// an explicit logon ID inside one source log, computer and boundary
    /// generation. Never time or name proximity.
    pub basis: &'static str,
    pub logon_instance: String,
    pub logon_id: String,
}

/// One classified record. `source` is the original facts row, so the writer
/// can persist exact raw provenance (payload JSON, record key, file) without
/// this module normalising it.
#[derive(Clone, Debug)]
pub struct SmbEvent<'a> {
    pub source: &'a Row,
    /// Position in [`SmbClassification::events`].
    pub index: usize,

    // --- provenance (verbatim facts values) ---
    pub timestamp: &'a str,
    pub timestamp_kind: &'static str,
    pub provider: &'a str,
    pub channel: &'a str,
    pub computer: &'a str,
    pub event_id: &'a str,
    pub event_record_id: &'a str,
    pub level_name: &'a str,
    /// Raw `System/Keywords` value — the audit outcome evidence.
    pub keywords_raw: &'a str,
    pub process_id: &'a str,
    pub thread_id: &'a str,
    /// Principal that wrote the record, never the audited account.
    pub system_user_sid: &'a str,
    pub activity_id: &'a str,
    pub related_activity_id: &'a str,
    pub record_key: &'a str,
    pub source_file: &'a str,
    pub event_data_raw: &'a str,
    pub facts_status: &'a str,
    pub facts_error: &'a str,
    /// Collected-log identity (`_record_key` table part): one ID namespace.
    pub source_scope: String,

    // --- classification ---
    pub role: SmbRole,
    pub event_kind: &'static str,
    pub description: &'static str,
    pub direction: &'static str,
    pub direction_basis: &'static str,
    pub peer_role: &'static str,
    pub protocol: &'static str,
    pub protocol_basis: &'static str,
    pub result: &'static str,
    pub result_basis: &'static str,
    pub audit_outcome: &'static str,
    pub access_semantics: &'static str,
    pub boundary_kind: &'static str,

    // --- identity ---
    pub account_raw: String,
    pub account_domain: String,
    pub account_name: String,
    pub account_upn: String,
    pub account_sid: String,
    pub account_key: String,
    pub account_display: String,
    /// S-1-0-0 is recorded evidence, never a confirmed account.
    pub account_sid_is_placeholder: bool,
    pub subject_user_sid: String,
    pub subject_user_name: String,
    pub subject_domain: String,
    pub subject_logon_id: String,
    pub target_user_sid: String,
    pub target_user_name: String,
    pub target_domain: String,
    pub target_logon_id: String,
    /// Representative logon ID of this record (target for logon events,
    /// subject for share/privilege events).
    pub logon_id: String,
    pub logon_type: String,
    pub logon_process: String,
    pub authentication_package: String,
    pub lm_package_name: String,
    pub key_length: String,
    /// Self-reported name, not a confirmed device.
    pub workstation_name: String,
    pub transmitted_services: String,

    // --- peer ---
    pub remote_address: String,
    pub remote_address_raw: String,
    pub remote_port_raw: String,
    /// Parsed port; `Some(0)` is a recorded zero, `None` is no value.
    pub remote_port: Option<i64>,
    /// Reported peer name (SMB payloads). A name is not an address.
    pub peer_name_raw: String,
    /// `recorded` | `unrecorded` — addressless events are kept either way.
    pub address_state: &'static str,

    // --- share / requested access ---
    pub share_name: String,
    pub share_path: String,
    pub target_file: String,
    pub object_type: String,
    pub access_mask: String,
    pub access_list: String,
    pub access_reason: String,
    /// Published token interpretation only.
    pub access_rights: String,
    /// Tokens with no published meaning, kept verbatim.
    pub access_rights_unmapped: String,

    // --- status / failure evidence ---
    pub status_raw: String,
    pub sub_status_raw: String,
    pub failure_reason_raw: String,
    pub status_format: &'static str,
    pub sub_status_format: &'static str,
    pub status_meaning: &'static str,
    pub sub_status_meaning: &'static str,
    pub reason_raw: String,
    pub server_name_raw: String,
    pub object_name_raw: String,
    pub session_id: String,
    pub spn_name: String,
    pub server_names_raw: String,
    pub configured_names_raw: String,
    pub ip_addresses_raw: String,
    pub privilege_list: String,

    // --- correlation ---
    /// `scope|computer|generation|logon id`, empty when no bounded instance.
    pub logon_instance: String,
}

/// Classifier output in facts order.
#[derive(Clone, Debug)]
pub struct SmbClassification<'a> {
    pub events: Vec<SmbEvent<'a>>,
    pub relations: Vec<SmbRelation>,
}

impl<'a> SmbEvent<'a> {
    /// `index` is assigned once the retained set is final.
    fn new(src: &'a Row) -> Self {
        let record_key = g(src, "_record_key");
        SmbEvent {
            source: src,
            index: 0,
            timestamp: g(src, "timestamp"),
            timestamp_kind: "이벤트 기록 시각",
            provider: g(src, "Provider"),
            channel: g(src, "Channel"),
            computer: g(src, "Computer"),
            event_id: g(src, "EventID"),
            event_record_id: g(src, "EventRecordID"),
            level_name: g(src, "LevelName"),
            keywords_raw: g(src, "Keywords"),
            process_id: g(src, "ProcessID"),
            thread_id: g(src, "ThreadID"),
            system_user_sid: g(src, "UserID"),
            activity_id: g(src, "ActivityID"),
            related_activity_id: g(src, "RelatedActivityID"),
            record_key,
            source_file: g(src, "_source_file"),
            event_data_raw: g(src, "EventData"),
            facts_status: g(src, "_status"),
            facts_error: g(src, "_error"),
            source_scope: record_key
                .rsplit_once("::")
                .map(|(table, _)| table)
                .unwrap_or(record_key)
                .to_string(),
            role: SmbRole::Direct,
            event_kind: "",
            description: "",
            direction: "unknown",
            direction_basis: "",
            peer_role: "unknown",
            protocol: "unknown",
            protocol_basis: "",
            result: "미확인",
            result_basis: "unclassified_event",
            audit_outcome: "unrecorded",
            access_semantics: "",
            boundary_kind: "",
            account_raw: String::new(),
            account_domain: String::new(),
            account_name: String::new(),
            account_upn: String::new(),
            account_sid: String::new(),
            account_key: String::new(),
            account_display: String::new(),
            account_sid_is_placeholder: false,
            subject_user_sid: String::new(),
            subject_user_name: String::new(),
            subject_domain: String::new(),
            subject_logon_id: String::new(),
            target_user_sid: String::new(),
            target_user_name: String::new(),
            target_domain: String::new(),
            target_logon_id: String::new(),
            logon_id: String::new(),
            logon_type: String::new(),
            logon_process: String::new(),
            authentication_package: String::new(),
            lm_package_name: String::new(),
            key_length: String::new(),
            workstation_name: String::new(),
            transmitted_services: String::new(),
            remote_address: String::new(),
            remote_address_raw: String::new(),
            remote_port_raw: String::new(),
            remote_port: None,
            peer_name_raw: String::new(),
            address_state: "unrecorded",
            share_name: String::new(),
            share_path: String::new(),
            target_file: String::new(),
            object_type: String::new(),
            access_mask: String::new(),
            access_list: String::new(),
            access_reason: String::new(),
            access_rights: String::new(),
            access_rights_unmapped: String::new(),
            status_raw: String::new(),
            sub_status_raw: String::new(),
            failure_reason_raw: String::new(),
            status_format: "",
            sub_status_format: "",
            status_meaning: "",
            sub_status_meaning: "",
            reason_raw: String::new(),
            server_name_raw: String::new(),
            object_name_raw: String::new(),
            session_id: String::new(),
            spn_name: String::new(),
            server_names_raw: String::new(),
            configured_names_raw: String::new(),
            ip_addresses_raw: String::new(),
            privilege_list: String::new(),
            logon_instance: String::new(),
        }
    }

    /// Everything the view searches: address, share, path, file, requested
    /// rights, raw account/domain/UPN/SID, failure codes, description and ID.
    pub fn search_text(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(28);
        for value in [
            self.event_id,
            self.provider,
            self.channel,
            self.description,
            self.event_kind,
        ] {
            if !value.is_empty() {
                parts.push(value);
            }
        }
        for value in [
            &self.account_raw,
            &self.account_domain,
            &self.account_name,
            &self.account_upn,
            &self.account_sid,
            &self.account_key,
            &self.logon_id,
            &self.workstation_name,
            &self.remote_address,
            &self.remote_address_raw,
            &self.peer_name_raw,
            &self.remote_port_raw,
            &self.share_name,
            &self.share_path,
            &self.target_file,
            &self.access_mask,
            &self.access_list,
            &self.access_rights,
            &self.access_rights_unmapped,
            &self.status_raw,
            &self.sub_status_raw,
            &self.failure_reason_raw,
            &self.server_name_raw,
            &self.server_names_raw,
            &self.spn_name,
        ] {
            if !value.is_empty() {
                parts.push(value.as_str());
            }
        }
        parts.join(" ")
    }
}

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(|s| s.as_str()).unwrap_or("")
}

/// Windows uses "-" for absent payload fields; retain other text verbatim.
fn clean(value: String) -> String {
    if value.trim() == "-" {
        String::new()
    } else {
        value
    }
}

/// Payloads are flat EventData, or wrapped in `EventXML` / a nested
/// `EventData` object (SMBServer/SMBClient shape). First non-empty match wins;
/// numeric 0 stays "0".
fn field(ed: &Map<String, Value>, names: &[&str]) -> String {
    let nested = ["EventXML", "EventData"]
        .into_iter()
        .filter_map(|key| ed.get(key).and_then(Value::as_object));
    for src in nested.chain(std::iter::once(ed)) {
        for name in names {
            let value = jget(src, name);
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::new()
}

fn f(ed: &Map<String, Value>, names: &[&str]) -> String {
    clean(field(ed, names))
}

/// How a recorded code was written down (R06: decimal and hex are different
/// notations of the evidence and both must stay distinguishable).
fn code_format(raw: &str) -> &'static str {
    if raw.is_empty() {
        ""
    } else if raw.len() > 2
        && (raw.starts_with("0x") || raw.starts_with("0X"))
        && raw[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        "hex"
    } else if raw.chars().all(|c| c.is_ascii_digit()) {
        "decimal"
    } else {
        "other"
    }
}

fn code_value(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    }
}

/// Published NTSTATUS meanings only (MS-ERREF and the 4625 monitoring table).
/// An unmapped code keeps its raw value and gets no interpretation; a zero
/// status is named, never turned into a generic "success" result.
fn ntstatus_meaning(raw: &str) -> &'static str {
    match code_value(raw) {
        Some(0x0000_0000) => "STATUS_SUCCESS",
        Some(0xC000_0022) => "STATUS_ACCESS_DENIED",
        Some(0xC000_005E) => "There are currently no logon servers available to service the logon request.",
        Some(0xC000_0064) => "User logon with misspelled or bad user account",
        Some(0xC000_006A) => "User logon with misspelled or bad password",
        Some(0xC000_006D) => "This is either due to a bad username or authentication information",
        Some(0xC000_006F) => "User logon outside authorized hours",
        Some(0xC000_0070) => "User logon from unauthorized workstation",
        Some(0xC000_0072) => "User logon to account disabled by administrator",
        Some(0xC000_015B) => "The user has not been granted the requested logon type (aka logon right) at this machine",
        Some(0xC000_0192) => "An attempt was made to logon, but the Netlogon service was not started",
        Some(0xC000_0193) => "User logon with expired account",
        Some(0xC000_0234) => "Account locked out",
        Some(0xC000_0413) => "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine",
        _ => "",
    }
}

/// Audit outcome from the record's own keyword mask. Missing keywords are
/// unrecorded evidence, not a success.
fn audit_outcome(keywords: &str) -> &'static str {
    if keywords.trim().is_empty() {
        return "unrecorded";
    }
    match code_value(keywords) {
        Some(mask) => {
            let success = mask & KEYWORD_AUDIT_SUCCESS != 0;
            let failure = mask & KEYWORD_AUDIT_FAILURE != 0;
            match (success, failure) {
                (true, false) => "success",
                (false, true) => "failure",
                _ => "unknown",
            }
        }
        None => "unknown",
    }
}

/// Published access token names for 5140/5145 `AccessList` entries.
fn access_token_name(token: &str) -> Option<&'static str> {
    Some(match token {
        "%%1537" => "DELETE",
        "%%1538" => "READ_CONTROL",
        "%%1539" => "WRITE_DAC",
        "%%1540" => "WRITE_OWNER",
        "%%1541" => "SYNCHRONIZE",
        "%%1542" => "ACCESS_SYS_SEC",
        "%%4416" => "ReadData (or ListDirectory)",
        "%%4417" => "WriteData (or AddFile)",
        "%%4418" => "AppendData (or AddSubdirectory or CreatePipeInstance)",
        "%%4419" => "ReadEA",
        "%%4420" => "WriteEA",
        "%%4421" => "Execute/Traverse",
        "%%4422" => "DeleteChild",
        "%%4423" => "ReadAttributes",
        "%%4424" => "WriteAttributes",
        _ => return None,
    })
}

/// (interpreted rights, tokens with no published meaning). Requested access
/// only — never evidence that the operation completed.
fn interpret_access_list(list: &str) -> (String, String) {
    let mut known: Vec<&str> = Vec::new();
    let mut unknown: Vec<&str> = Vec::new();
    for token in list.split_whitespace() {
        match access_token_name(token) {
            Some(name) => known.push(name),
            None => unknown.push(token),
        }
    }
    (known.join(", "), unknown.join(" "))
}

/// Leading UNC backslashes and a trailing share path are not part of the peer
/// name; the original token stays in `remote_address_raw`.
fn peer_token(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('\\')
        .split('\\')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// A reported name only becomes an address when it is a literal IP address.
fn ip_literal(value: &str) -> bool {
    let value = value.trim();
    let bare = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    bare.parse::<std::net::IpAddr>().is_ok()
}

fn is_sid(value: &str) -> bool {
    crate::derived::is_sid(value)
}

/// Identity fields. The short display name, the raw payload value and the
/// identity key are separate: two domains with the same short name never
/// collapse, and the S-1-0-0 placeholder never becomes an identity.
fn apply_account(event: &mut SmbEvent<'_>, raw: &str, domain: &str, sid: &str) {
    event.account_raw = raw.to_string();
    event.account_domain = domain.to_string();
    let (local, upn) = match raw.split_once('@') {
        Some((head, tail)) if !head.is_empty() && !tail.is_empty() => {
            (head.to_string(), raw.to_string())
        }
        _ => (raw.to_string(), String::new()),
    };
    event.account_name = local.clone();
    event.account_upn = upn.clone();
    event.account_sid = sid.to_string();
    let placeholder = sid.eq_ignore_ascii_case("S-1-0-0");
    event.account_sid_is_placeholder = placeholder;
    let confirmed_sid = is_sid(sid) && !placeholder;
    event.account_key = if confirmed_sid {
        sid.to_ascii_uppercase()
    } else if !upn.is_empty() {
        upn.trim().to_lowercase()
    } else if !domain.trim().is_empty() && !local.trim().is_empty() {
        format!("{}\\{}", domain.trim().to_lowercase(), local.trim().to_lowercase())
    } else {
        local.trim().to_lowercase()
    };
    event.account_display = if !raw.is_empty() {
        raw.to_string()
    } else if confirmed_sid {
        sid.to_string()
    } else {
        String::new()
    };
}

fn apply_status(event: &mut SmbEvent<'_>, status: String, sub_status: String) {
    event.status_format = code_format(&status);
    event.status_meaning = ntstatus_meaning(&status);
    event.sub_status_format = code_format(&sub_status);
    event.sub_status_meaning = ntstatus_meaning(&sub_status);
    event.status_raw = status;
    event.sub_status_raw = sub_status;
}

fn apply_port(event: &mut SmbEvent<'_>, raw: String) {
    event.remote_port = raw.parse::<i64>().ok();
    event.remote_port_raw = raw;
}

fn apply_address(event: &mut SmbEvent<'_>, raw: &str, address: String) {
    event.remote_address_raw = raw.to_string();
    if !address.is_empty() {
        event.address_state = "recorded";
        event.remote_address = address;
    }
}

/// Per-event semantics. `result` is resolved after the payload is read, so
/// audited events can take their outcome from the keyword mask.
struct Spec {
    role: SmbRole,
    event_kind: &'static str,
    description: &'static str,
    direction: &'static str,
    direction_basis: &'static str,
    peer_role: &'static str,
    protocol: &'static str,
    protocol_basis: &'static str,
    access_semantics: &'static str,
    boundary_kind: &'static str,
    result: ResultRule,
}

enum ResultRule {
    /// Result follows the published meaning of the event itself.
    Fixed(&'static str),
    /// Result follows the record's audit keyword; the fallback applies only
    /// when the event is published as single-outcome.
    Keyword(Option<&'static str>),
    /// No verified meaning: unknown, never success and never failure.
    Unclassified,
}

fn security_spec(eid: &str) -> Option<Spec> {
    let spec = |role,
                event_kind,
                description,
                direction,
                direction_basis,
                peer_role,
                protocol,
                protocol_basis,
                access_semantics,
                boundary_kind,
                result| {
        Some(Spec {
            role,
            event_kind,
            description,
            direction,
            direction_basis,
            peer_role,
            protocol,
            protocol_basis,
            access_semantics,
            boundary_kind,
            result,
        })
    };
    match eid {
        // Network (type 3) authentication. SMB is one possible consumer of a
        // type 3 logon, not a fact recorded here.
        "4624" => spec(
            SmbRole::Direct,
            "network_logon_success",
            "네트워크 로그온 성공(LogonType 3)",
            "inbound",
            "network_logon_target_host",
            "client",
            "unknown",
            "network_logon_type3_unspecified",
            "",
            "",
            ResultRule::Fixed("성공"),
        ),
        "4625" => spec(
            SmbRole::Direct,
            "network_logon_failure",
            "네트워크 로그온 실패(LogonType 3)",
            "inbound",
            "network_logon_target_host",
            "client",
            "unknown",
            "network_logon_type3_unspecified",
            "",
            "",
            ResultRule::Fixed("실패"),
        ),
        // Ends the logon instance — not an SMB share session end (A02).
        "4634" => spec(
            SmbRole::Context,
            "logon_instance_end",
            "로그온 인스턴스 종료",
            "unknown",
            "context_event",
            "unknown",
            "unknown",
            "context_event",
            "",
            "",
            ResultRule::Fixed("정보"),
        ),
        // Special privileges are not evidence of C$/ADMIN$ access (A02).
        "4672" => spec(
            SmbRole::Context,
            "special_privileges_assigned",
            "특수 권한 할당",
            "unknown",
            "context_event",
            "unknown",
            "unknown",
            "context_event",
            "",
            "",
            ResultRule::Fixed("정보"),
        ),
        // NTLM credential validation: no target share, no bound logon (A03).
        "4776" => spec(
            SmbRole::Context,
            "ntlm_credential_validation",
            "NTLM 자격 증명 검증",
            "unknown",
            "context_event",
            "unknown",
            "unknown",
            "context_event",
            "",
            "",
            ResultRule::Keyword(None),
        ),
        // Share access, logged once per session on first access attempt.
        "5140" => spec(
            SmbRole::Direct,
            "share_access",
            "네트워크 공유 접근",
            "inbound",
            "share_server_audit",
            "client",
            "smb",
            "network_share_audit",
            "share_access_first_use",
            "",
            ResultRule::Keyword(None),
        ),
        // Requested-access check. Failure means share-level denial; NTFS-level
        // denials do not generate it, and success is not a completed transfer.
        "5145" => spec(
            SmbRole::Direct,
            "share_access_check",
            "네트워크 공유 요청 권한 검사",
            "inbound",
            "share_server_audit",
            "client",
            "smb",
            "network_share_audit",
            "requested_access_check",
            "",
            ResultRule::Keyword(None),
        ),
        // Published as failure-only; the keyword still decides when present.
        "5168" => spec(
            SmbRole::Direct,
            "smb_spn_check_failure",
            "SMB/SMB2 SPN 검사 실패",
            "inbound",
            "share_server_audit",
            "client",
            "smb",
            "smb_spn_check",
            "",
            "",
            ResultRule::Keyword(Some("실패")),
        ),
        // Boundaries and audit-configuration observations (A03/A04).
        "4608" => spec(
            SmbRole::Context,
            "system_start",
            "시스템 시작",
            "unknown",
            "context_event",
            "unknown",
            "unknown",
            "context_event",
            "",
            "system_start",
            ResultRule::Fixed("정보"),
        ),
        "4719" => spec(
            SmbRole::Context,
            "audit_policy_change",
            "시스템 감사 정책 변경",
            "unknown",
            "context_event",
            "unknown",
            "unknown",
            "context_event",
            "",
            "audit_policy_change",
            ResultRule::Fixed("정보"),
        ),
        _ => None,
    }
}

/// SMBServer/SMBClient records. The provider tells which role this host had;
/// only published event meanings are classified.
fn smb_provider_spec(server: bool, eid: &str) -> Spec {
    let (direction, direction_basis, peer_role) = if server {
        ("inbound", "provider_server_role", "client")
    } else {
        ("outbound", "provider_client_role", "server")
    };
    let mut spec = Spec {
        role: SmbRole::Direct,
        event_kind: "smb_channel_event_unclassified",
        description: "SMB 로그 이벤트",
        direction,
        direction_basis,
        peer_role,
        protocol: "smb",
        protocol_basis: "smb_provider_channel",
        access_semantics: "",
        boundary_kind: "",
        result: ResultRule::Unclassified,
    };
    match (server, eid) {
        // SMB1 access auditing (Set-SmbServerConfiguration -AuditSmb1Access).
        (true, "3000") => {
            spec.event_kind = "smb1_access_audit";
            spec.description = "SMB1 접근 감사 기록";
            spec.result = ResultRule::Fixed("정보");
        }
        // Published as "The SMB client was logged on as Guest account".
        (true, "3023") => {
            spec.event_kind = "insecure_guest_logon_server";
            spec.description = "SMB 클라이언트가 Guest 계정으로 로그온됨";
            spec.result = ResultRule::Fixed("정보");
        }
        // "Rejected an insecure guest logon... The server denied the connection."
        (false, "31017") => {
            spec.event_kind = "rejected_insecure_guest_logon";
            spec.description = "안전하지 않은 Guest 로그온 거부";
            spec.result = ResultRule::Fixed("실패");
        }
        // Configuration change, not a connection.
        (false, "31018") => {
            spec.role = SmbRole::Context;
            spec.event_kind = "insecure_guest_auth_enabled";
            spec.description = "AllowInsecureGuestAuth 사용 설정됨";
            spec.direction = "unknown";
            spec.direction_basis = "context_event";
            spec.peer_role = "unknown";
            spec.result = ResultRule::Fixed("정보");
        }
        // "Allowed an insecure guest logon" — the client allowed it; the
        // record does not state what the session then did.
        (false, "31022") => {
            spec.event_kind = "allowed_insecure_guest_logon";
            spec.description = "안전하지 않은 Guest 로그온 허용";
            spec.result = ResultRule::Fixed("정보");
        }
        _ => {}
    }
    spec
}

fn log_cleared_spec() -> Spec {
    Spec {
        role: SmbRole::Context,
        event_kind: "log_cleared",
        description: "감사 로그 삭제",
        direction: "unknown",
        direction_basis: "context_event",
        peer_role: "unknown",
        protocol: "unknown",
        protocol_basis: "context_event",
        access_semantics: "",
        boundary_kind: "log_cleared",
        result: ResultRule::Fixed("정보"),
    }
}

/// `audited`: the record carries Security audit keywords. SMBServer/SMBClient
/// keywords are provider keywords, so no audit outcome is issued for them.
fn apply_spec(event: &mut SmbEvent<'_>, spec: &Spec, audited: bool) {
    event.role = spec.role;
    event.event_kind = spec.event_kind;
    event.description = spec.description;
    event.direction = spec.direction;
    event.direction_basis = spec.direction_basis;
    event.peer_role = spec.peer_role;
    event.protocol = spec.protocol;
    event.protocol_basis = spec.protocol_basis;
    event.access_semantics = spec.access_semantics;
    event.boundary_kind = spec.boundary_kind;
    event.audit_outcome = if audited { audit_outcome(event.keywords_raw) } else { "" };
    match spec.result {
        ResultRule::Fixed(result) => {
            event.result = result;
            event.result_basis = "event_semantics";
        }
        ResultRule::Keyword(fallback) => match event.audit_outcome {
            "success" => {
                event.result = "성공";
                event.result_basis = "audit_keyword";
            }
            "failure" => {
                event.result = "실패";
                event.result_basis = "audit_keyword";
            }
            _ => match fallback {
                Some(result) => {
                    event.result = result;
                    event.result_basis = "event_semantics";
                }
                None => {
                    event.result = "미확인";
                    event.result_basis = "audit_keyword_unavailable";
                }
            },
        },
        ResultRule::Unclassified => {
            event.result = "미확인";
            event.result_basis = "unclassified_event";
        }
    }
}

fn fill_security(event: &mut SmbEvent<'_>, eid: &str, ed: &Map<String, Value>) {
    event.subject_user_sid = f(ed, &["SubjectUserSid"]);
    event.subject_user_name = f(ed, &["SubjectUserName"]);
    event.subject_domain = f(ed, &["SubjectDomainName"]);
    event.subject_logon_id = f(ed, &["SubjectLogonId"]);
    match eid {
        "4624" | "4625" | "4634" => {
            event.target_user_sid = f(ed, &["TargetUserSid"]);
            event.target_user_name = f(ed, &["TargetUserName"]);
            event.target_domain = f(ed, &["TargetDomainName"]);
            event.target_logon_id = f(ed, &["TargetLogonId"]);
            event.logon_id = event.target_logon_id.clone();
            event.logon_type = f(ed, &["LogonType"]);
            event.logon_process = f(ed, &["LogonProcessName"]);
            event.authentication_package = f(ed, &["AuthenticationPackageName"]);
            event.lm_package_name = f(ed, &["LmPackageName"]);
            event.key_length = f(ed, &["KeyLength"]);
            event.workstation_name = f(ed, &["WorkstationName"]);
            event.transmitted_services = f(ed, &["TransmittedServices", "TransitedServices"]);
            let name = event.target_user_name.clone();
            let domain = event.target_domain.clone();
            let sid = event.target_user_sid.clone();
            apply_account(event, &name, &domain, &sid);
            let address = f(ed, &["IpAddress"]);
            apply_address(event, &address.clone(), address);
            apply_port(event, f(ed, &["IpPort"]));
            apply_status(event, f(ed, &["Status"]), f(ed, &["SubStatus"]));
            event.failure_reason_raw = f(ed, &["FailureReason"]);
        }
        "4672" => {
            event.logon_id = event.subject_logon_id.clone();
            event.privilege_list = f(ed, &["PrivilegeList"]);
            let name = event.subject_user_name.clone();
            let domain = event.subject_domain.clone();
            let sid = event.subject_user_sid.clone();
            apply_account(event, &name, &domain, &sid);
        }
        "4776" => {
            // The validating computer records the account and the reported
            // workstation only; there is no logon ID and no peer address.
            event.authentication_package = f(ed, &["PackageName"]);
            event.workstation_name = f(ed, &["Workstation"]);
            let name = f(ed, &["TargetUserName"]);
            apply_account(event, &name, "", "");
            apply_status(event, f(ed, &["Status"]), String::new());
        }
        "5140" | "5145" => {
            event.logon_id = event.subject_logon_id.clone();
            event.object_type = f(ed, &["ObjectType"]);
            event.share_name = f(ed, &["ShareName"]);
            event.share_path = f(ed, &["ShareLocalPath"]);
            event.target_file = f(ed, &["RelativeTargetName"]);
            event.access_mask = f(ed, &["AccessMask"]);
            event.access_list = f(ed, &["AccessList"]);
            event.access_reason = f(ed, &["AccessReason"]);
            let (rights, unmapped) = interpret_access_list(&event.access_list);
            event.access_rights = rights;
            event.access_rights_unmapped = unmapped;
            let name = event.subject_user_name.clone();
            let domain = event.subject_domain.clone();
            let sid = event.subject_user_sid.clone();
            apply_account(event, &name, &domain, &sid);
            let address = f(ed, &["IpAddress"]);
            apply_address(event, &address.clone(), address);
            apply_port(event, f(ed, &["IpPort"]));
        }
        "5168" => {
            event.logon_id = event.subject_logon_id.clone();
            event.spn_name = f(ed, &["SpnName"]);
            // ServerNames / IpAddresses list this host's own names, so they
            // never become a peer address.
            event.server_names_raw = f(ed, &["ServerNames"]);
            event.configured_names_raw = f(ed, &["ConfiguredNames"]);
            event.ip_addresses_raw = f(ed, &["IpAddresses"]);
            let name = event.subject_user_name.clone();
            let domain = event.subject_domain.clone();
            let sid = event.subject_user_sid.clone();
            apply_account(event, &name, &domain, &sid);
            apply_status(event, f(ed, &["ErrorCode"]), String::new());
        }
        _ => {}
    }
}

fn fill_smb_provider(event: &mut SmbEvent<'_>, ed: &Map<String, Value>, server: bool) {
    event.share_name = f(ed, &["ShareName"]);
    event.server_name_raw = f(ed, &["ServerName"]);
    event.object_name_raw = f(ed, &["ObjectName"]);
    event.session_id = f(ed, &["SessionId", "SessionID"]);
    event.reason_raw = f(ed, &["Reason"]);
    apply_status(event, f(ed, &["Status"]), String::new());
    let user = f(ed, &["UserName"]);
    if !user.is_empty() {
        let (domain, name) = match user.split_once('\\') {
            Some((domain, name)) => (domain.to_string(), name.to_string()),
            None => (String::new(), user.clone()),
        };
        apply_account(event, &name, &domain, "");
        event.account_raw = user;
    }
    // Peer evidence: ClientName on the server side (ServerName is this host),
    // the target server or the share's host on the client side. A reported
    // name stays a name; a wildcard host is not a peer.
    let candidates = if server {
        [f(ed, &["ClientName"]), String::new()]
    } else {
        [event.server_name_raw.clone(), event.share_name.clone()]
    };
    let peer = candidates.into_iter().find_map(|raw| {
        let token = peer_token(&raw);
        (!token.is_empty() && !token.contains(['*', '?'])).then_some((raw, token))
    });
    if let Some((raw_peer, token)) = peer {
        event.peer_name_raw = token.clone();
        let address = if ip_literal(&token) { token } else { String::new() };
        apply_address(event, &raw_peer, address);
    }
}

fn classify_row<'a>(src: &'a Row) -> Option<SmbEvent<'a>> {
    let provider = g(src, "Provider");
    let eid = g(src, "EventID");
    let security = provider == SEC;
    let server = provider.eq_ignore_ascii_case(SMB_SERVER);
    let client = provider.eq_ignore_ascii_case(SMB_CLIENT);
    let eventlog = provider.eq_ignore_ascii_case(EVENTLOG);
    if !(security || server || client || (eventlog && eid == "1102")) {
        return None;
    }
    let ed = parse_eventdata(g(src, "EventData"));
    let spec = if security {
        let spec = security_spec(eid)?;
        // Only network (type 3) logons belong to this view; another logon type
        // is different evidence and is left to its own view.
        if matches!(eid, "4624" | "4625" | "4634") && f(&ed, &["LogonType"]) != "3" {
            return None;
        }
        spec
    } else if eventlog {
        log_cleared_spec()
    } else {
        smb_provider_spec(server, eid)
    };
    let mut event = SmbEvent::new(src);
    apply_spec(&mut event, &spec, !(server || client));
    if security {
        fill_security(&mut event, eid, &ed);
    } else if server || client {
        fill_smb_provider(&mut event, &ed, server);
    }
    Some(event)
}

/// One typed event per selected record, in facts order, plus the definite
/// context links. Records are never dropped for a missing address or a missing
/// timestamp.
pub fn classify<'a>(cache: &'a EventLogOverviewCache) -> SmbClassification<'a> {
    let mut events: Vec<SmbEvent<'a>> = Vec::new();
    for src in cache.rows() {
        if let Some(event) = classify_row(src) {
            events.push(event);
        }
    }
    // A02 scope: a special-privileges record is SMB context only when it
    // carries the logon ID of a selected direct event from the same collected
    // log and computer. Local and service privilege records are unrelated
    // evidence and never enter this view.
    let selected: std::collections::HashSet<(&str, &str, String)> = events
        .iter()
        .filter(|event| event.role == SmbRole::Direct)
        .filter_map(|event| {
            let logon_id = crate::derived::normalize_logon_id(&event.logon_id);
            if logon_id.is_empty() {
                return None;
            }
            Some((event.source_scope.as_str(), event.computer, logon_id))
        })
        .collect();
    let mut keep = events
        .iter()
        .map(|event| {
            if event.event_kind != "special_privileges_assigned" {
                return true;
            }
            let logon_id = crate::derived::normalize_logon_id(&event.logon_id);
            !logon_id.is_empty()
                && selected.contains(&(event.source_scope.as_str(), event.computer, logon_id))
        })
        .collect::<Vec<bool>>()
        .into_iter();
    drop(selected);
    events.retain(|_| keep.next().unwrap_or(true));
    for (index, event) in events.iter_mut().enumerate() {
        event.index = index;
    }
    let relations = relations::link(&mut events);
    SmbClassification { events, relations }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overview::EventLogOverviewCache;
    use crate::sqlite::Row;

    const EVTLOG: &str = "Microsoft-Windows-Eventlog";
    const SRV: &str = "Microsoft-Windows-SMBServer";
    const CLI: &str = "Microsoft-Windows-SMBClient";

    const AUDIT_SUCCESS: &str = "0x8020000000000000";
    const AUDIT_FAILURE: &str = "0x8010000000000000";

    fn ev(pairs: &[(&str, &str)]) -> Row {
        let mut row = Row::new();
        for (k, v) in pairs {
            row.insert((*k).into(), (*v).into());
        }
        row
    }

    /// Security facts row as the EVTX parser writes it (Keywords included).
    fn sec(eid: &str, keywords: &str, data: &str, ts: &str, key: &str) -> Row {
        ev(&[
            ("timestamp", ts),
            ("Provider", SEC),
            ("Channel", "Security"),
            ("Computer", "DESKTOP-A"),
            ("EventID", eid),
            ("Keywords", keywords),
            ("EventRecordID", "100"),
            ("EventData", data),
            ("_record_key", key),
            ("_source_file", "C:\\evidence\\Security.evtx"),
            ("_status", "ok"),
        ])
    }

    fn smb_row(provider: &str, channel: &str, eid: &str, data: &str, key: &str) -> Row {
        ev(&[
            ("timestamp", "2026-01-27 09:00:00.000"),
            ("Provider", provider),
            ("Channel", channel),
            ("Computer", "DESKTOP-A"),
            ("EventID", eid),
            ("EventData", data),
            ("_record_key", key),
            ("_source_file", "C:\\evidence\\SmbClient.evtx"),
            ("_status", "ok"),
        ])
    }

    /// Owned projection of one classified event so assertions do not fight the
    /// borrow of the cache.
    struct Seen {
        event_kind: String,
        role: String,
        direction: String,
        direction_basis: String,
        peer_role: String,
        protocol: String,
        protocol_basis: String,
        result: String,
        result_basis: String,
        audit_outcome: String,
        access_semantics: String,
        boundary_kind: String,
        account_raw: String,
        account_domain: String,
        account_name: String,
        account_upn: String,
        account_sid: String,
        account_key: String,
        account_display: String,
        account_sid_is_placeholder: bool,
        logon_id: String,
        logon_type: String,
        authentication_package: String,
        lm_package_name: String,
        workstation_name: String,
        remote_address: String,
        remote_address_raw: String,
        remote_port_raw: String,
        remote_port: Option<i64>,
        peer_name_raw: String,
        address_state: String,
        share_name: String,
        share_path: String,
        target_file: String,
        access_mask: String,
        access_list: String,
        access_rights: String,
        access_rights_unmapped: String,
        status_raw: String,
        status_format: String,
        status_meaning: String,
        sub_status_raw: String,
        failure_reason_raw: String,
        spn_name: String,
        server_names_raw: String,
        logon_instance: String,
        event_id: String,
        keywords_raw: String,
        source_file: String,
        record_key: String,
        timestamp: String,
        search_text: String,
    }

    fn seen(e: &SmbEvent<'_>) -> Seen {
        Seen {
            event_kind: e.event_kind.into(),
            role: match e.role {
                SmbRole::Direct => "direct".to_string(),
                SmbRole::Context => "context".to_string(),
            },
            direction: e.direction.into(),
            direction_basis: e.direction_basis.into(),
            peer_role: e.peer_role.into(),
            protocol: e.protocol.into(),
            protocol_basis: e.protocol_basis.into(),
            result: e.result.into(),
            result_basis: e.result_basis.into(),
            audit_outcome: e.audit_outcome.into(),
            access_semantics: e.access_semantics.into(),
            boundary_kind: e.boundary_kind.into(),
            account_raw: e.account_raw.clone(),
            account_domain: e.account_domain.clone(),
            account_name: e.account_name.clone(),
            account_upn: e.account_upn.clone(),
            account_sid: e.account_sid.clone(),
            account_key: e.account_key.clone(),
            account_display: e.account_display.clone(),
            account_sid_is_placeholder: e.account_sid_is_placeholder,
            logon_id: e.logon_id.clone(),
            logon_type: e.logon_type.clone(),
            authentication_package: e.authentication_package.clone(),
            lm_package_name: e.lm_package_name.clone(),
            workstation_name: e.workstation_name.clone(),
            remote_address: e.remote_address.clone(),
            remote_address_raw: e.remote_address_raw.clone(),
            remote_port_raw: e.remote_port_raw.clone(),
            remote_port: e.remote_port,
            peer_name_raw: e.peer_name_raw.clone(),
            address_state: e.address_state.into(),
            share_name: e.share_name.clone(),
            share_path: e.share_path.clone(),
            target_file: e.target_file.clone(),
            access_mask: e.access_mask.clone(),
            access_list: e.access_list.clone(),
            access_rights: e.access_rights.clone(),
            access_rights_unmapped: e.access_rights_unmapped.clone(),
            status_raw: e.status_raw.clone(),
            status_format: e.status_format.into(),
            status_meaning: e.status_meaning.into(),
            sub_status_raw: e.sub_status_raw.clone(),
            failure_reason_raw: e.failure_reason_raw.clone(),
            spn_name: e.spn_name.clone(),
            server_names_raw: e.server_names_raw.clone(),
            logon_instance: e.logon_instance.clone(),
            event_id: e.event_id.into(),
            keywords_raw: e.keywords_raw.into(),
            source_file: e.source_file.into(),
            record_key: e.record_key.into(),
            timestamp: e.timestamp.into(),
            search_text: e.search_text(),
        }
    }

    fn classify_owned(rows: Vec<Row>) -> (Vec<Seen>, Vec<(usize, usize, String, String)>) {
        let cache = EventLogOverviewCache::from_rows_for_tests(rows);
        let out = classify(&cache);
        let events = out.events.iter().map(seen).collect();
        let relations = out
            .relations
            .iter()
            .map(|r| {
                (
                    r.main_index,
                    r.context_index,
                    r.kind.to_string(),
                    r.basis.to_string(),
                )
            })
            .collect();
        (events, relations)
    }

    /// R01/R02/R03: a type 3 logon is network authentication with an
    /// unspecified protocol — never asserted to be SMB — and every raw
    /// identity/package/port value survives.
    #[test]
    fn type3_logon_success_is_protocol_unspecified_and_keeps_raw_identity() {
        let data = r#"{"SubjectUserSid":"S-1-0-0","TargetUserSid":"S-1-5-21-1-2-3-1001",
            "TargetUserName":"su3592@naver.com","TargetDomainName":"NAVER","TargetLogonId":"0x7a3f21",
            "LogonType":3,"LogonProcessName":"NtLmSsp ","AuthenticationPackageName":"NTLM",
            "LmPackageName":"NTLM V2","KeyLength":"128","WorkstationName":"WIN-CLIENT",
            "IpAddress":"59.19.252.187","IpPort":"0","TransmittedServices":"-"}"#;
        let (events, _) = classify_owned(vec![sec(
            "4624",
            AUDIT_SUCCESS,
            data,
            "2026-01-27 09:00:00.000",
            "Security::1",
        )]);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.role, "direct");
        assert_eq!(e.event_kind, "network_logon_success");
        assert_eq!(e.protocol, "unknown");
        assert_eq!(e.protocol_basis, "network_logon_type3_unspecified");
        assert_eq!(e.result, "성공");
        assert_eq!(e.result_basis, "event_semantics");
        assert_eq!(e.direction, "inbound");
        assert_eq!(e.peer_role, "client");
        // Raw payload values stay verbatim, including the numeric logon type
        // and the recorded "0" port (which is not NULL).
        assert_eq!(e.logon_type, "3");
        assert_eq!(e.authentication_package, "NTLM");
        assert_eq!(e.lm_package_name, "NTLM V2");
        assert_eq!(e.workstation_name, "WIN-CLIENT");
        assert_eq!(e.remote_port_raw, "0");
        assert_eq!(e.remote_port, Some(0));
        assert_eq!(e.address_state, "recorded");
        assert_eq!(e.remote_address, "59.19.252.187");
        assert_eq!(e.logon_id, "0x7a3f21");
        // UPN survives; display name and identity key are separate values.
        assert_eq!(e.account_raw, "su3592@naver.com");
        assert_eq!(e.account_upn, "su3592@naver.com");
        assert_eq!(e.account_name, "su3592");
        assert_eq!(e.account_domain, "NAVER");
        assert_eq!(e.account_sid, "S-1-5-21-1-2-3-1001");
        assert_eq!(e.account_key, "S-1-5-21-1-2-3-1001");
        assert_eq!(e.account_display, "su3592@naver.com");
        assert!(!e.account_sid_is_placeholder);
        // Provenance for the writer.
        assert_eq!(e.source_file, "C:\\evidence\\Security.evtx");
        assert_eq!(e.record_key, "Security::1");
        assert_eq!(e.event_id, "4624");
        assert_eq!(e.keywords_raw, AUDIT_SUCCESS);
        assert_eq!(e.audit_outcome, "success");
    }

    /// R02/R03/R06: S-1-0-0 is a placeholder, so the key falls back to the
    /// domain-qualified name, and every raw failure code is kept with its
    /// recorded notation and published meaning.
    #[test]
    fn failed_logon_keeps_placeholder_sid_apart_and_raw_failure_codes() {
        let data = r#"{"TargetUserSid":"S-1-0-0","TargetUserName":"alice","TargetDomainName":"CORP",
            "TargetLogonId":"0x0","LogonType":"3","Status":"0xc000006d","SubStatus":"0xc000006a",
            "FailureReason":"%%2313","AuthenticationPackageName":"NTLM","WorkstationName":"OTHERPC",
            "IpAddress":"-","IpPort":"-"}"#;
        let (events, _) = classify_owned(vec![sec(
            "4625",
            AUDIT_FAILURE,
            data,
            "2026-01-27 09:01:00.000",
            "Security::2",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "network_logon_failure");
        assert_eq!(e.result, "실패");
        assert_eq!(e.account_sid, "S-1-0-0");
        assert!(e.account_sid_is_placeholder);
        assert_eq!(e.account_key, "corp\\alice");
        assert_eq!(e.status_raw, "0xc000006d");
        assert_eq!(e.status_format, "hex");
        assert_eq!(
            e.status_meaning,
            "This is either due to a bad username or authentication information"
        );
        assert_eq!(e.sub_status_raw, "0xc000006a");
        // The resource token is preserved, never translated.
        assert_eq!(e.failure_reason_raw, "%%2313");
        // R07: "-" is no value, and the event is still retained.
        assert_eq!(e.remote_address, "");
        assert_eq!(e.remote_port_raw, "");
        assert_eq!(e.remote_port, None);
        assert_eq!(e.address_state, "unrecorded");
    }

    /// Different domains with the same short name must not collapse into one
    /// identity key (R03).
    #[test]
    fn same_name_in_two_domains_keeps_separate_keys() {
        let mk = |domain: &str, key: &str| {
            let data = format!(
                r#"{{"TargetUserName":"alice","TargetDomainName":"{domain}","LogonType":"3","TargetLogonId":"0x1"}}"#
            );
            sec("4624", AUDIT_SUCCESS, &data, "2026-01-27 09:00:00.000", key)
        };
        let (events, _) = classify_owned(vec![mk("CORP", "Security::1"), mk("LAB", "Security::2")]);
        assert_eq!(events[0].account_key, "corp\\alice");
        assert_eq!(events[1].account_key, "lab\\alice");
    }

    #[test]
    fn upn_realms_do_not_collapse_under_the_same_reported_domain() {
        let rows = ["Alice@ONE.test", "alice@TWO.test", "alice@one.TEST"]
            .iter().enumerate().map(|(i,name)| {
                let payload = format!(r#"{{"LogonType":3,"TargetUserName":"{name}","TargetDomainName":"CORP"}}"#);
                sec("4624", AUDIT_SUCCESS, &payload, "2026-01-27 09:00:00.000", &format!("Security::{}",i+1))
            }).collect();
        let (events,_) = classify_owned(rows);
        assert_ne!(events[0].account_key,events[1].account_key);
        assert_eq!(events[0].account_key,events[2].account_key);
        assert_eq!(events[0].account_raw,"Alice@ONE.test");
    }

    /// Only type 3 belongs to this view: a RemoteInteractive logon is not
    /// network-share evidence and must not be re-labelled.
    #[test]
    fn non_type3_logons_are_not_classified() {
        let data = r#"{"TargetUserName":"alice","LogonType":"10","TargetLogonId":"0x55"}"#;
        let (events, _) = classify_owned(vec![sec(
            "4624",
            AUDIT_SUCCESS,
            data,
            "2026-01-27 09:00:00.000",
            "Security::1",
        )]);
        assert!(events.is_empty());
    }

    /// A01: 5145 is a requested-access check. The audit outcome comes from the
    /// Keywords mask, documented access tokens are resolved and unknown tokens
    /// are kept raw rather than guessed.
    #[test]
    fn share_access_check_uses_keywords_and_documented_access_tokens() {
        let data = r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1104","SubjectUserName":"dadmin",
            "SubjectDomainName":"CONTOSO","SubjectLogonId":"0x38d34","ObjectType":"File",
            "IpAddress":"10.0.0.100","IpPort":"56926","ShareName":"\\\\*\\Documents",
            "ShareLocalPath":"\\??\\C:\\Documents","RelativeTargetName":"Bginfo.exe",
            "AccessMask":"0x100081","AccessList":"%%1541 %%4416 %%9999",
            "AccessReason":"%%1541: %%1801 D:(A;;FA;;;WD)"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5145",
            AUDIT_SUCCESS,
            data,
            "2026-01-27 09:02:00.000",
            "Security::3",
        )]);
        let e = &events[0];
        assert_eq!(e.role, "direct");
        assert_eq!(e.event_kind, "share_access_check");
        assert_eq!(e.protocol, "smb");
        assert_eq!(e.protocol_basis, "network_share_audit");
        assert_eq!(e.result, "성공");
        assert_eq!(e.result_basis, "audit_keyword");
        assert_eq!(e.audit_outcome, "success");
        // Requested access only — never a completed read/write.
        assert_eq!(e.access_semantics, "requested_access_check");
        assert_eq!(e.share_name, "\\\\*\\Documents");
        assert_eq!(e.share_path, "\\??\\C:\\Documents");
        assert_eq!(e.target_file, "Bginfo.exe");
        assert_eq!(e.access_mask, "0x100081");
        assert_eq!(e.access_list, "%%1541 %%4416 %%9999");
        assert_eq!(e.access_rights, "SYNCHRONIZE, ReadData (or ListDirectory)");
        assert_eq!(e.access_rights_unmapped, "%%9999");
        assert_eq!(e.account_sid, "S-1-5-21-1-2-3-1104");
        assert_eq!(e.account_domain, "CONTOSO");
        assert_eq!(e.logon_id, "0x38d34");
        assert_eq!(e.remote_address, "10.0.0.100");
        assert_eq!(e.remote_port, Some(56926));
        assert_eq!(e.direction, "inbound");
        assert_eq!(e.peer_role, "client");
    }

    /// The same event ID with an Audit Failure mask is a share-level denial,
    /// so ID/Level alone must not fix the result.
    #[test]
    fn share_access_check_failure_mask_is_a_failure() {
        let data = r#"{"ShareName":"\\\\*\\IPC$","AccessMask":"0x1","AccessList":"%%4416"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5145",
            AUDIT_FAILURE,
            data,
            "2026-01-27 09:03:00.000",
            "Security::4",
        )]);
        assert_eq!(events[0].result, "실패");
        assert_eq!(events[0].audit_outcome, "failure");
        assert_eq!(events[0].result_basis, "audit_keyword");
    }

    /// Without the Keywords evidence the outcome stays unknown — not success.
    #[test]
    fn share_access_check_without_keywords_is_unknown_result() {
        let data = r#"{"ShareName":"\\\\*\\Documents"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5145",
            "",
            data,
            "2026-01-27 09:04:00.000",
            "Security::5",
        )]);
        assert_eq!(events[0].result, "미확인");
        assert_eq!(events[0].result_basis, "audit_keyword_unavailable");
        assert_eq!(events[0].audit_outcome, "unrecorded");
    }

    /// 5140 fires once per session on first access; port 0 is a recorded value.
    #[test]
    fn share_access_event_marks_first_use_and_keeps_port_zero() {
        let data = r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1104","SubjectLogonId":"0x541f35",
            "ShareName":"\\\\*\\Documents","ShareLocalPath":"\\??\\C:\\Documents",
            "IpAddress":"::1","IpPort":"0","AccessMask":"0x1","AccessList":"%%4416"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5140",
            AUDIT_SUCCESS,
            data,
            "2026-01-27 09:05:00.000",
            "Security::6",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "share_access");
        assert_eq!(e.access_semantics, "share_access_first_use");
        assert_eq!(e.remote_port_raw, "0");
        assert_eq!(e.remote_port, Some(0));
        assert_eq!(e.address_state, "recorded");
        assert_eq!(e.access_rights, "ReadData (or ListDirectory)");
    }

    /// 5168 is documented as SMB/SMB2 SPN check failure; its ServerNames /
    /// IpAddresses lists describe this host, so they never become a peer
    /// address.
    #[test]
    fn spn_check_failure_is_smb_evidence_without_a_peer_address() {
        let data = r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1104","SubjectUserName":"dadmin",
            "SubjectDomainName":"CONTOSO","SubjectLogonId":"0xd0cd4","SpnName":"N/A",
            "ErrorCode":"0xc0000022","ServerNames":"CONTOSO;DC01;","ConfiguredNames":"N/A",
            "IpAddresses":"127.0.0.1;::1;"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5168",
            AUDIT_FAILURE,
            data,
            "2026-01-27 09:06:00.000",
            "Security::7",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "smb_spn_check_failure");
        assert_eq!(e.protocol, "smb");
        assert_eq!(e.protocol_basis, "smb_spn_check");
        assert_eq!(e.result, "실패");
        assert_eq!(e.status_raw, "0xc0000022");
        assert_eq!(e.status_meaning, "STATUS_ACCESS_DENIED");
        assert_eq!(e.spn_name, "N/A");
        assert_eq!(e.server_names_raw, "CONTOSO;DC01;");
        assert_eq!(e.remote_address, "");
        assert_eq!(e.address_state, "unrecorded");
    }

    /// R05: an SMB channel event with no verified meaning stays unknown —
    /// neither failure nor success — and Status 0 proves nothing.
    #[test]
    fn unverified_smb_client_event_is_unknown_not_failure() {
        let data =
            r#"{"ServerName":"fileserver01","Status":"0","ShareName":"\\\\fileserver01\\data"}"#;
        let (events, _) = classify_owned(vec![smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "99999",
            data,
            "SmbClientSecurity::1",
        )]);
        let e = &events[0];
        assert_eq!(e.role, "direct");
        assert_eq!(e.event_kind, "smb_channel_event_unclassified");
        assert_eq!(e.result, "미확인");
        assert_eq!(e.result_basis, "unclassified_event");
        assert_eq!(e.protocol, "smb");
        assert_eq!(e.protocol_basis, "smb_provider_channel");
        assert_eq!(e.direction, "outbound");
        assert_eq!(e.peer_role, "server");
        assert_eq!(e.direction_basis, "provider_client_role");
        // Raw target evidence is kept, but a reported name is not an address.
        assert_eq!(e.share_name, "\\\\fileserver01\\data");
        assert_eq!(e.peer_name_raw, "fileserver01");
        assert_eq!(e.remote_address, "");
        assert_eq!(e.address_state, "unrecorded");
        assert_eq!(e.status_raw, "0");
        assert_eq!(e.status_format, "decimal");
        assert_eq!(e.status_meaning, "STATUS_SUCCESS");
    }

    /// 31017 is documented: the server denied an insecure guest logon.
    #[test]
    fn rejected_insecure_guest_logon_is_a_documented_client_failure() {
        let data = r#"{"UserName":"Guest","ServerName":"192.168.10.199","ShareName":"\\\\192.168.10.199\\dbbackup"}"#;
        let (events, _) = classify_owned(vec![smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "31017",
            data,
            "SmbClientSecurity::2",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "rejected_insecure_guest_logon");
        assert_eq!(e.result, "실패");
        assert_eq!(e.result_basis, "event_semantics");
        assert_eq!(e.direction, "outbound");
        // A literal address in the reported target may be used as an address.
        assert_eq!(e.remote_address, "192.168.10.199");
        assert_eq!(e.address_state, "recorded");
        assert_eq!(e.share_name, "\\\\192.168.10.199\\dbbackup");
        assert_eq!(e.account_raw, "Guest");
    }

    /// 31018 records a configuration change, not a connection.
    #[test]
    fn insecure_guest_auth_enabled_is_context_not_a_connection() {
        let (events, _) = classify_owned(vec![smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "31018",
            "{}",
            "SmbClientSecurity::3",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "insecure_guest_auth_enabled");
        assert_eq!(e.role, "context");
        assert_eq!(e.result, "정보");
        assert_eq!(e.direction, "unknown");
    }

    /// RD-33: the time meaning uses the shared Korean vocabulary.
    #[test]
    fn timestamp_kind_uses_event_recorded_vocabulary() {
        let cache = EventLogOverviewCache::from_rows_for_tests(vec![smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "31018",
            "{}",
            "SmbClientSecurity::3",
        )]);
        assert_eq!(classify(&cache).events[0].timestamp_kind, "이벤트 기록 시각");
    }

    /// RD-67: provider keywords are not audit keywords; no audit outcome is
    /// issued for SMBClient/SMBServer records.
    #[test]
    fn provider_records_carry_no_audit_outcome() {
        let mut row = smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "31018",
            "{}",
            "SmbClientSecurity::3",
        );
        row.insert("Keywords".into(), "0x200000000000080".into());
        let (events, _) = classify_owned(vec![row]);
        assert_eq!(events[0].audit_outcome, "");
    }

    /// RD-34: on the server side only ClientName names the peer; the server's
    /// own name is never the peer.
    #[test]
    fn server_side_peer_comes_only_from_client_name() {
        let data = r#"{"EventData":{"ServerName":"10.0.0.5","ShareName":"\\\\10.0.0.5\\IPC$"}}"#;
        let (events, _) = classify_owned(vec![smb_row(
            SRV,
            "Microsoft-Windows-SMBServer/Security",
            "551",
            data,
            "SMBServerSecurity::1",
        )]);
        let e = &events[0];
        assert_eq!(e.peer_name_raw, "");
        assert_eq!(e.remote_address, "");
        assert_eq!(e.address_state, "unrecorded");
    }

    /// RD-34: a wildcard share host is not a peer.
    #[test]
    fn wildcard_share_host_is_not_a_peer() {
        let data = r#"{"EventData":{"ShareName":"\\\\*\\IPC$"}}"#;
        let (events, _) = classify_owned(vec![smb_row(
            CLI,
            "Microsoft-Windows-SmbClient/Security",
            "31017",
            data,
            "SmbClientSecurity::1",
        )]);
        let e = &events[0];
        assert_eq!(e.peer_name_raw, "");
        assert_eq!(e.remote_address_raw, "");
        assert_eq!(e.address_state, "unrecorded");
    }

    /// R07: an addressless SMBServer record is retained with its account and
    /// raw status, flagged as address-unrecorded.
    #[test]
    fn addressless_smb_server_event_is_retained() {
        let data = r#"{"EventData":{"UserName":"backup","Status":"3221225506","SessionId":"0x12"}}"#;
        let (events, _) = classify_owned(vec![smb_row(
            SRV,
            "Microsoft-Windows-SMBServer/Security",
            "551",
            data,
            "SMBServerSecurity::1",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "smb_channel_event_unclassified");
        assert_eq!(e.result, "미확인");
        assert_eq!(e.direction, "inbound");
        assert_eq!(e.peer_role, "client");
        assert_eq!(e.direction_basis, "provider_server_role");
        assert_eq!(e.account_raw, "backup");
        assert_eq!(e.status_raw, "3221225506");
        assert_eq!(e.status_format, "decimal");
        assert_eq!(e.status_meaning, "STATUS_ACCESS_DENIED");
        assert_eq!(e.address_state, "unrecorded");
    }

    /// SMB1 access auditing is documented for Microsoft-Windows-SMBServer/Audit
    /// event 3000 — informational evidence, not a failure.
    #[test]
    fn smb1_audit_event_is_informational_smb_evidence() {
        let data = r#"{"EventData":{"ClientName":"\\\\10.0.0.9"}}"#;
        let (events, _) = classify_owned(vec![smb_row(
            SRV,
            "Microsoft-Windows-SMBServer/Audit",
            "3000",
            data,
            "SMBServerAudit::1",
        )]);
        let e = &events[0];
        assert_eq!(e.event_kind, "smb1_access_audit");
        assert_eq!(e.result, "정보");
        assert_eq!(e.protocol, "smb");
        assert_eq!(e.remote_address, "10.0.0.9");
        assert_eq!(e.remote_address_raw, "\\\\10.0.0.9");
    }

    /// A02: 4634 and 4672 of the same logon instance are context evidence
    /// linked to the direct logon — never extra connections.
    #[test]
    fn logoff_and_special_privileges_link_to_the_same_logon_instance() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetDomainName":"CORP","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let priv_ev = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"alice","SubjectDomainName":"CORP","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:00:00.100",
            "Security::2",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetDomainName":"CORP","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security::3",
        );
        let (events, relations) = classify_owned(vec![logon, priv_ev, logoff]);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].role, "direct");
        assert_eq!(events[1].role, "context");
        assert_eq!(events[1].event_kind, "special_privileges_assigned");
        assert_eq!(events[2].role, "context");
        assert_eq!(events[2].event_kind, "logon_instance_end");
        // One connection, two related context records.
        assert_eq!(
            events.iter().filter(|e| e.role == "direct").count(),
            1,
            "context events must not become connections"
        );
        assert_eq!(relations.len(), 2);
        assert_eq!(
            relations[0],
            (
                0,
                1,
                "special_privileges".into(),
                "same_logon_id_bounded_instance".into()
            )
        );
        assert_eq!(
            relations[1],
            (
                0,
                2,
                "logon_instance_end".into(),
                "same_logon_id_bounded_instance".into()
            )
        );
        assert_eq!(events[0].logon_instance, events[2].logon_instance);
        assert!(!events[0].logon_instance.is_empty());
    }

    /// A02 scope: the Security log carries thousands of 4672 records for
    /// local and service logons. Only a special-privileges record whose logon
    /// ID belongs to a selected direct event enters this view; the rest are
    /// not SMB context at all.
    #[test]
    fn special_privileges_without_a_selected_logon_id_is_excluded() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        // Same logon ID as the selected network logon, written in the other
        // hex case — one identity, kept as context.
        let related = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"alice","SubjectLogonId":"0x7A3F21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:00:00.100",
            "Security::2",
        );
        // A service logon's privileges: no selected event carries this ID.
        let unrelated = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"SYSTEM","SubjectLogonId":"0x3e7","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:00:00.200",
            "Security::3",
        );
        // Same ID as the logon, but recorded in a different collected log.
        let other_log = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"alice","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:00:00.300",
            "Security_2::9",
        );
        let (events, relations) = classify_owned(vec![logon, related, unrelated, other_log]);
        assert_eq!(events.len(), 2, "only the in-scope 4672 is retained");
        assert_eq!(events[1].event_kind, "special_privileges_assigned");
        assert_eq!(events[1].account_raw, "alice");
        // Indices are reassigned after the scope filter, so relations address
        // the returned vector.
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].0, 0);
        assert_eq!(relations[0].1, 1);
    }

    /// A restart between the logon and the logoff makes the ID a different
    /// instance, so nothing is linked.
    #[test]
    fn logon_id_reuse_across_a_restart_is_not_linked() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let boot = sec(
            "4608",
            AUDIT_SUCCESS,
            "{}",
            "2026-01-27 09:05:00.000",
            "Security::2",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security::3",
        );
        let (events, relations) = classify_owned(vec![logon, boot, logoff]);
        assert_eq!(events[1].event_kind, "system_start");
        assert_eq!(events[1].boundary_kind, "system_start");
        assert_eq!(events[1].role, "context");
        assert!(
            relations.is_empty(),
            "a reused ID across a restart is not one instance"
        );
        assert_ne!(events[0].logon_instance, events[2].logon_instance);
    }

    /// A cleared log is the same kind of boundary as a restart.
    #[test]
    fn log_clear_is_a_boundary_and_breaks_linking() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x99","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let mut cleared = sec(
            "1102",
            AUDIT_SUCCESS,
            "{}",
            "2026-01-27 09:05:00.000",
            "Security::2",
        );
        cleared.insert("Provider".into(), EVTLOG.into());
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x99","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security::3",
        );
        let (events, relations) = classify_owned(vec![logon, cleared, logoff]);
        assert_eq!(events[1].boundary_kind, "log_cleared");
        assert!(relations.is_empty());
    }

    /// Two collected logs are two ID namespaces: the same number is not the
    /// same logon instance.
    #[test]
    fn same_logon_id_in_another_source_log_is_not_linked() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x55","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x55","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security_2::1",
        );
        let (_, relations) = classify_owned(vec![logon, logoff]);
        assert!(relations.is_empty());
    }

    /// A placeholder logon ID identifies no instance.
    #[test]
    fn placeholder_logon_id_never_forms_an_instance() {
        let logon = sec(
            "4625",
            AUDIT_FAILURE,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x0","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x0","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![logon, logoff]);
        assert_eq!(events[0].logon_instance, "");
        assert!(relations.is_empty());
    }

    /// Ambiguous instances stay unlinked context (defensive: two primaries
    /// claiming one ID inside one boundary).
    #[test]
    fn ambiguous_instance_leaves_context_unlinked() {
        let mk_logon = |key: &str, ts: &str| {
            sec(
                "4624",
                AUDIT_SUCCESS,
                r#"{"TargetUserName":"alice","TargetLogonId":"0x77","LogonType":"3"}"#,
                ts,
                key,
            )
        };
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x77","LogonType":"3"}"#,
            "2026-01-27 09:10:00.000",
            "Security::3",
        );
        let (_, relations) = classify_owned(vec![
            mk_logon("Security::1", "2026-01-27 09:00:00.000"),
            mk_logon("Security::2", "2026-01-27 09:01:00.000"),
            logoff,
        ]);
        assert!(relations.is_empty());
    }

    /// A logoff recorded before any logon of that ID closes nothing: the
    /// later logon must not swallow it as its own end.
    #[test]
    fn logoff_before_its_logon_is_not_linked() {
        let early_logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:05:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![early_logoff, logon]);
        assert_eq!(events.len(), 2, "the logoff stays as context");
        assert!(relations.is_empty());
        assert_eq!(events[0].logon_instance, "");
    }

    /// Context after the instance already closed belongs to no instance.
    #[test]
    fn special_privileges_after_the_logoff_is_not_linked() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        let late_priv = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"alice","SubjectLogonId":"0x7a","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:30:00.000",
            "Security::3",
        );
        let (events, relations) = classify_owned(vec![logon, logoff, late_priv]);
        assert_eq!(events.len(), 3, "the late privilege record is retained");
        assert_eq!(relations.len(), 1, "only the logoff of the open instance");
        assert_eq!(relations[0].1, 1);
        assert_eq!(events[2].logon_instance, "");
    }

    /// The same ID used again after a clean close is a second instance, each
    /// with its own end — not one ambiguous blob.
    #[test]
    fn reused_logon_id_after_a_close_forms_two_instances() {
        let logon_a = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff_a = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        let logon_b = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:02:00.000",
            "Security::3",
        );
        let logoff_b = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:03:00.000",
            "Security::4",
        );
        let (events, relations) = classify_owned(vec![logon_a, logoff_a, logon_b, logoff_b]);
        assert_eq!(relations.len(), 2);
        assert_eq!((relations[0].0, relations[0].1), (0, 1));
        assert_eq!((relations[1].0, relations[1].1), (2, 3));
        assert_eq!(events[0].logon_instance, events[1].logon_instance);
        assert_eq!(events[2].logon_instance, events[3].logon_instance);
        assert_ne!(events[0].logon_instance, events[2].logon_instance);
    }

    /// A failed logon proves no logon lifetime, so it never opens an instance
    /// for a later logoff to close.
    #[test]
    fn failed_logon_does_not_open_an_instance() {
        let failure = sec(
            "4625",
            AUDIT_FAILURE,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![failure, logoff]);
        assert_eq!(events.len(), 2);
        assert!(relations.is_empty());
        assert_eq!(events[0].logon_instance, "");
        assert_eq!(events[1].logon_instance, "");
    }

    /// Without a recorded computer the instance has no boundary at all, so the
    /// records are kept but nothing is attributed.
    #[test]
    fn missing_computer_cannot_bound_an_instance() {
        let mut logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let mut logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        logon.remove("Computer");
        logoff.remove("Computer");
        let (events, relations) = classify_owned(vec![logon, logoff]);
        assert_eq!(events.len(), 2);
        assert!(relations.is_empty());
        assert_eq!(events[0].logon_instance, "");
    }

    /// A record with no collected-log identity cannot be bounded either.
    #[test]
    fn missing_source_scope_cannot_bound_an_instance() {
        let mut logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let mut logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        logon.remove("_record_key");
        logoff.remove("_record_key");
        let (events, relations) = classify_owned(vec![logon, logoff]);
        assert_eq!(events.len(), 2);
        assert!(relations.is_empty());
    }

    /// Two confirmed, different SIDs on one logon ID are two principals: the
    /// context is retained but never attributed.
    #[test]
    fn conflicting_confirmed_sids_block_the_link() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-2002","TargetUserName":"bob","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![logon, logoff]);
        assert_eq!(events.len(), 2, "the conflicting logoff is still kept");
        assert!(relations.is_empty());
    }

    /// Measured shape of the real Security log: the 4672 of a network logon
    /// is written *before* its 4624 (lower EventRecordID, sometimes 1 ms
    /// earlier). The same logon ID and the same confirmed SID make that a
    /// definite link, with its own basis.
    #[test]
    fn privilege_recorded_before_its_logon_links_on_id_and_sid() {
        let privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1001","SubjectUserName":"alice","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 08:59:59.999",
            "Security::1",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetDomainName":"CORP","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![privileges, logon]);
        assert_eq!(relations.len(), 1);
        assert_eq!(
            relations[0],
            (
                1,
                0,
                "special_privileges".into(),
                "same_logon_id_sid_prelogon_privileges".into()
            )
        );
        assert_eq!(events[0].logon_instance, events[1].logon_instance);
        assert!(!events[0].logon_instance.is_empty());
    }

    /// Same recorded second: the collected order (EventRecordID / facts
    /// order) still puts the privilege record first, and it still links.
    #[test]
    fn privilege_with_the_same_timestamp_as_its_logon_links() {
        let privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1001","SubjectUserName":"alice","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::2",
        );
        let (_, relations) = classify_owned(vec![privileges, logon]);
        assert_eq!(relations.len(), 1);
        assert_eq!((relations[0].0, relations[0].1), (1, 0));
        assert_eq!(relations[0].3, "same_logon_id_sid_prelogon_privileges");
    }

    /// A pre-logon privilege record only links on a *confirmed, equal* SID:
    /// a different SID is a different principal.
    #[test]
    fn pre_logon_privilege_with_another_sid_is_not_linked() {
        let privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserSid":"S-1-5-21-1-2-3-2002","SubjectUserName":"bob","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 08:59:59.999",
            "Security::1",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![privileges, logon]);
        assert_eq!(events.len(), 2, "the privilege record is still retained");
        assert!(relations.is_empty());
        assert_eq!(events[0].logon_instance, "");
    }

    /// No confirmed SID on either side means no proven principal: the ID
    /// alone does not make a pre-logon link.
    #[test]
    fn pre_logon_privilege_without_a_confirmed_sid_is_not_linked() {
        let privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserName":"alice","SubjectLogonId":"0x7a3f21","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 08:59:59.999",
            "Security::1",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a3f21","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![privileges, logon]);
        assert_eq!(events.len(), 2);
        assert!(relations.is_empty());
    }

    /// Once an ID has already been opened and closed, a later privilege
    /// record is never carried forward into the next reuse of that ID.
    #[test]
    fn privilege_after_a_closed_instance_is_not_carried_into_the_reuse() {
        let logon_a = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let logoff_a = sec(
            "4634",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:01:00.000",
            "Security::2",
        );
        let orphan_privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1001","SubjectUserName":"alice","SubjectLogonId":"0x7a","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 09:02:00.000",
            "Security::3",
        );
        let logon_b = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:03:00.000",
            "Security::4",
        );
        let (events, relations) = classify_owned(vec![
            logon_a,
            logoff_a,
            orphan_privileges,
            logon_b,
        ]);
        assert_eq!(events.len(), 4, "the orphan privilege record is retained");
        assert_eq!(relations.len(), 1, "only the first instance's logoff");
        assert_eq!((relations[0].0, relations[0].1), (0, 1));
        assert_eq!(events[2].logon_instance, "");
    }

    /// A restart discards pending pre-logon evidence: the ID after the
    /// boundary is a different instance.
    #[test]
    fn pending_privilege_is_dropped_at_a_restart() {
        let privileges = sec(
            "4672",
            AUDIT_SUCCESS,
            r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1001","SubjectUserName":"alice","SubjectLogonId":"0x7a","PrivilegeList":"SeTcbPrivilege"}"#,
            "2026-01-27 08:59:00.000",
            "Security::1",
        );
        let boot = sec(
            "4608",
            AUDIT_SUCCESS,
            "{}",
            "2026-01-27 08:59:30.000",
            "Security::2",
        );
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserSid":"S-1-5-21-1-2-3-1001","TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::3",
        );
        let (events, relations) = classify_owned(vec![privileges, boot, logon]);
        assert_eq!(events.len(), 3);
        assert!(relations.is_empty());
        assert_eq!(events[0].logon_instance, "");
    }

    /// A03: 4776 is kept as authentication context and is never matched to a
    /// logon by time or account name.
    #[test]
    fn ntlm_validation_is_unlinked_context() {
        let logon = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetDomainName":"CORP","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let ntlm = sec(
            "4776",
            AUDIT_SUCCESS,
            r#"{"PackageName":"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0","TargetUserName":"alice","Workstation":"OTHERPC","Status":"0x0"}"#,
            "2026-01-27 09:00:00.100",
            "Security::2",
        );
        let (events, relations) = classify_owned(vec![logon, ntlm]);
        let e = &events[1];
        assert_eq!(e.role, "context");
        assert_eq!(e.event_kind, "ntlm_credential_validation");
        assert_eq!(e.account_raw, "alice");
        assert_eq!(e.workstation_name, "OTHERPC");
        assert_eq!(
            e.authentication_package,
            "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
        );
        assert_eq!(e.status_raw, "0x0");
        assert_eq!(e.logon_instance, "");
        assert!(
            relations.is_empty(),
            "4776 must not be matched by time or name"
        );
    }

    /// 4719 is an audit-configuration observation, kept as context only.
    #[test]
    fn audit_policy_change_is_context_observation() {
        let (events, _) = classify_owned(vec![sec(
            "4719",
            AUDIT_SUCCESS,
            r#"{"CategoryId":"%%8272","SubcategoryId":"%%14081"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        )]);
        let e = &events[0];
        assert_eq!(e.role, "context");
        assert_eq!(e.boundary_kind, "audit_policy_change");
        assert_eq!(e.event_kind, "audit_policy_change");
    }

    /// R13: an event with no timestamp is kept — never dropped — and never
    /// joins an instance, because it cannot be placed between boundaries.
    #[test]
    fn untimed_record_is_retained_and_forms_no_instance() {
        let timed = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7a","LogonType":"3"}"#,
            "2026-01-27 09:00:00.000",
            "Security::1",
        );
        let untimed = sec(
            "4624",
            AUDIT_SUCCESS,
            r#"{"TargetUserName":"alice","TargetLogonId":"0x7b","LogonType":"3"}"#,
            "",
            "Security::2",
        );
        let (events, _) = classify_owned(vec![timed, untimed]);
        assert_eq!(events.len(), 2, "an untimed record is never dropped");
        assert_eq!(events[1].timestamp, "");
        assert_eq!(events[1].logon_instance, "");
    }

    /// R10: the searchable text carries share, path, file, rights, raw account
    /// values, SID and the event ID.
    #[test]
    fn search_text_covers_contract_fields() {
        let data = r#"{"SubjectUserSid":"S-1-5-21-1-2-3-1104","SubjectUserName":"dadmin",
            "SubjectDomainName":"CONTOSO","SubjectLogonId":"0x38d34","ShareName":"\\\\*\\Documents",
            "ShareLocalPath":"\\??\\C:\\Documents","RelativeTargetName":"Bginfo.exe",
            "AccessMask":"0x100081","AccessList":"%%4416","IpAddress":"10.0.0.100"}"#;
        let (events, _) = classify_owned(vec![sec(
            "5145",
            AUDIT_SUCCESS,
            data,
            "2026-01-27 09:02:00.000",
            "Security::3",
        )]);
        let text = &events[0].search_text;
        for needle in [
            "\\\\*\\Documents",
            "C:\\Documents",
            "Bginfo.exe",
            "ReadData",
            "S-1-5-21-1-2-3-1104",
            "CONTOSO",
            "dadmin",
            "10.0.0.100",
            "5145",
        ] {
            assert!(text.contains(needle), "search text missing {needle}: {text}");
        }
    }

    /// Unrelated providers stay out of the view entirely.
    #[test]
    fn unrelated_events_are_dropped() {
        let other = ev(&[
            ("timestamp", "2026-01-27 09:00:00.000"),
            ("Provider", "Microsoft-Windows-Bits-Client"),
            ("EventID", "3"),
            ("EventData", "{}"),
            ("_record_key", "Bits::1"),
        ]);
        let (events, _) = classify_owned(vec![other]);
        assert!(events.is_empty());
    }
}
