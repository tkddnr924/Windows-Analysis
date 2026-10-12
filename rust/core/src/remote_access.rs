//! Remote access (RDP) event classification — viewer08 R01~R17 / A01~A05.
//! Reads the shared EventLog facts cache and emits one row per selected event.
//! Interpretation only: no session invention, no cross-event carry (that is
//! `relations`), no fabricated identities.

pub(crate) mod relations;

use serde_json::{Map, Value};

use crate::overview::{jget, parse_eventdata, EventLogOverviewCache};
use crate::sqlite::Row;

const SEC: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";
const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
const AX: &str = "Microsoft-Windows-TerminalServices-ClientActiveXCore";
const CORE: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";

/// Windows audit payloads write "-" where a field has no value.
fn clean(value: String) -> String {
    if value == "-" {
        String::new()
    } else {
        value
    }
}

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(|s| s.as_str()).unwrap_or("")
}

/// Absent and empty are the same thing: no key is written for a missing value.
fn set(row: &mut Row, key: &str, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() {
        row.insert(key.into(), value);
    }
}

/// Payloads are either flat EventData or wrapped in an `EventXML` object.
/// Returns the first non-empty match; numeric 0 stays "0".
fn field(ed: &Map<String, Value>, names: &[&str]) -> String {
    for src in ed
        .get("EventXML")
        .and_then(Value::as_object)
        .into_iter()
        .chain(std::iter::once(ed))
    {
        for name in names {
            let value = jget(src, name);
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::new()
}

/// "ip:port", "[ipv6]:port" or a bare address. A bare IPv6 (several colons,
/// no brackets) keeps every colon.
fn split_host_port(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let port = rest[end + 1..].strip_prefix(':').unwrap_or("");
            return (rest[..end].to_string(), port.to_string());
        }
    }
    if raw.matches(':').count() == 1 {
        if let Some((host, port)) = raw.split_once(':') {
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                return (host.to_string(), port.to_string());
            }
        }
    }
    (raw.to_string(), String::new())
}

struct Spec {
    direction: &'static str,
    result: &'static str,
    stage: &'static str,
    description: &'static str,
}

/// Selected remote-access events only. Everything else stays out of the view:
/// an unselected ID is not evidence of a session.
fn spec_for(provider: &str, eid: &str) -> Option<Spec> {
    let s = |direction, result, stage, description| {
        Some(Spec {
            direction,
            result,
            stage,
            description,
        })
    };
    match (provider, eid) {
        // Transport layer: ClientIP carries the source address before auth.
        (CORE, "131") => s("inbound", "성공", "transport", "RDP 전송 계층 연결 수립"),
        // UDP fallback diagnostics — information, never a session failure.
        (CORE, "135") => s(
            "inbound",
            "정보",
            "transport_warning",
            "RDP 전송 방식 경고",
        ),
        // Raw connection state transition incl. the provider's error code.
        (CORE, "226") => s(
            "inbound",
            "정보",
            "error_transition",
            "RDP 연결 상태 전이",
        ),
        (SEC, "4624") => s("inbound", "성공", "logon", "RDP 로그온 성공(LogonType 10)"),
        (SEC, "4625") => s("inbound", "실패", "logon", "RDP 로그온 실패(LogonType 10)"),
        // Ends the logon instance, not necessarily the desktop session.
        (SEC, "4634") => s(
            "inbound",
            "정보",
            "logoff",
            "RDP 로그온 인스턴스 종료(LogonType 10)",
        ),
        // Candidate: carries no remote evidence of its own.
        (SEC, "4647") => s("unknown", "정보", "logoff", "사용자 시작 로그오프"),
        (SEC, "4778") => s(
            "inbound",
            "정보",
            "reconnect",
            "세션 재연결(Window Station)",
        ),
        (SEC, "4779") => s(
            "inbound",
            "정보",
            "disconnect",
            "세션 연결 끊김(Window Station)",
        ),
        // Network authentication only; not proof of a desktop session.
        (RCM, "1149") => s(
            "inbound",
            "성공",
            "authentication",
            "RDP 네트워크 인증 성공",
        ),
        (LSM, "21") => s("inbound", "성공", "logon", "RDP 세션 로그온"),
        (LSM, "22") => s("inbound", "정보", "shell", "RDP 셸 시작"),
        (LSM, "23") => s("inbound", "정보", "logoff", "RDP 세션 로그오프"),
        (LSM, "24") => s("inbound", "정보", "disconnect", "RDP 세션 연결 끊김"),
        (LSM, "25") => s("inbound", "성공", "reconnect", "RDP 세션 재연결"),
        (LSM, "39") => s(
            "inbound",
            "정보",
            "disconnect",
            "RDP 세션 연결 끊김(다른 세션에 의해)",
        ),
        (LSM, "40") => s("inbound", "정보", "disconnect", "RDP 세션 연결 끊김"),
        (AX, "1024") => s("outbound", "정보", "transport", "RDP 아웃바운드 연결 시도"),
        (AX, "1025") => s("outbound", "성공", "transport", "RDP 아웃바운드 연결됨"),
        (AX, "1026") => s("outbound", "정보", "disconnect", "RDP 아웃바운드 연결 끊김"),
        (AX, "1102") => s("outbound", "정보", "transport", "RDP 아웃바운드 서버 주소"),
        _ => None,
    }
}

/// ID-reuse boundary evidence (A03). Never a remote access event.
fn control_kind(provider: &str, eid: &str) -> Option<&'static str> {
    match (provider, eid) {
        (SEC, "4608") => Some("system_start"),
        (EVENTLOG, "1102") => Some("log_cleared"),
        _ => None,
    }
}

/// Facts columns every classified row keeps verbatim.
fn common(src: &Row) -> Row {
    let mut row = Row::new();
    for (dst, key) in [
        ("timestamp", "timestamp"),
        ("event_id", "EventID"),
        ("provider", "Provider"),
        ("channel", "Channel"),
        ("computer", "Computer"),
        ("event_record_id", "EventRecordID"),
        ("process_id", "ProcessID"),
        ("thread_id", "ThreadID"),
        // The service principal that logged the record, never the target user.
        ("system_user_sid", "UserID"),
        ("activity_id", "ActivityID"),
        ("related_activity_id", "RelatedActivityID"),
        ("record_key", "_record_key"),
        ("event_data", "EventData"),
        ("facts_status", "_status"),
        ("facts_error", "_error"),
    ] {
        set(&mut row, dst, g(src, key));
    }
    // Originals stay verbatim; only a genuine (non all-zero) GUID is offered
    // as a correlation identifier.
    for (dst, key) in [
        ("correlation_activity_id", "ActivityID"),
        ("correlation_related_activity_id", "RelatedActivityID"),
    ] {
        let value = g(src, key);
        if genuine_guid(value) {
            set(&mut row, dst, value);
        }
    }
    let source_file = g(src, "_source_file");
    set(&mut row, "source_file", source_file);
    set(&mut row, "_source_file", source_file);
    let key = g(src, "_record_key");
    set(
        &mut row,
        "source_scope",
        key.rsplit_once("::").map(|(t, _)| t).unwrap_or(key),
    );
    row
}

/// Placeholder GUIDs (all zeroes, with or without braces) identify nothing.
fn genuine_guid(value: &str) -> bool {
    uuid::Uuid::parse_str(value.trim()).is_ok_and(|id| !id.is_nil())
}

/// Identity fields. `target_user_sid` must already be set when known: a
/// confirmed SID outranks the name for the identity key.
fn set_account(row: &mut Row, raw: &str, domain: &str, name: &str) {
    set(row, "account_raw", raw);
    set(row, "account_domain", domain);
    let (local, upn) = match name.split_once('@') {
        Some((head, tail)) if !head.is_empty() && !tail.is_empty() => {
            (head.to_string(), name.to_string())
        }
        _ => (name.to_string(), String::new()),
    };
    set(row, "account_upn", upn.as_str());
    set(row, "account_name", local.as_str());
    // Short display name; metadata confirmation is a separate step.
    set(row, "account", local.as_str());
    let sid = g(row, "target_user_sid");
    // S-1-0-0 is the null SID — raw evidence, never an identity.
    let key = if crate::derived::is_sid(sid) && !sid.eq_ignore_ascii_case("S-1-0-0") {
        sid.to_ascii_uppercase()
    } else if !domain.is_empty() && !local.is_empty() {
        format!("{}\\{}", domain.to_lowercase(), local.to_lowercase())
    } else if !upn.is_empty() {
        upn.to_lowercase()
    } else {
        local.to_lowercase()
    };
    set(row, "account_key", key);
}

/// LOCAL/console is kept as evidence but never becomes a remote address, and
/// a local record must not assert an inbound remote direction (R01). Provider,
/// stage and result stay as recorded.
fn set_scope_address(row: &mut Row, address: &str, console: bool) {
    set(row, "remote_address_raw", address);
    if address.eq_ignore_ascii_case("LOCAL") || console {
        row.insert("access_scope".into(), "local".into());
        row.insert("direction".into(), "unknown".into());
    } else if !address.is_empty() {
        row.insert("access_scope".into(), "remote".into());
        set(row, "remote_address", address);
    }
}

fn fill_security(row: &mut Row, eid: &str, ed: &Map<String, Value>) {
    if eid == "4778" || eid == "4779" {
        set(row, "logon_id", clean(field(ed, &["LogonID", "LogonId"])));
        let session_name = clean(field(ed, &["SessionName"]));
        set(row, "session_name", session_name.as_str());
        let domain = clean(field(ed, &["AccountDomain"]));
        let name = clean(field(ed, &["AccountName"]));
        if !name.is_empty() || !domain.is_empty() {
            set_account(row, &name, &domain, &name);
        }
        let address = clean(field(ed, &["ClientAddress"]));
        let console = session_name
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("console"));
        set_scope_address(row, &address, console);
        if g(row, "access_scope") != "local"
            && !session_name
                .get(..4)
                .is_some_and(|s| s.eq_ignore_ascii_case("rdp-"))
        {
            set(row, "access_scope", "unknown");
            set(row, "direction", "unknown");
        }
        if g(row, "access_scope") != "local" {
            set(row, "remote_computer", clean(field(ed, &["ClientName"])));
        }
        return;
    }
    set(row, "target_user_sid", clean(field(ed, &["TargetUserSid"])));
    let domain = clean(field(ed, &["TargetDomainName"]));
    let name = clean(field(ed, &["TargetUserName"]));
    if !name.is_empty() || !domain.is_empty() || !g(row, "target_user_sid").is_empty() {
        set_account(row, &name, &domain, &name);
    }
    set(row, "logon_id", clean(field(ed, &["TargetLogonId"])));
    set(row, "logon_type", clean(field(ed, &["LogonType"])));
    // The audited workstation name is the recording host for User32 logons,
    // so it is not a peer computer.
    set(
        row,
        "workstation_name",
        clean(field(ed, &["WorkstationName"])),
    );
    set(
        row,
        "authentication_package",
        clean(field(ed, &["AuthenticationPackageName"])),
    );
    set(
        row,
        "logon_process",
        clean(field(ed, &["LogonProcessName"])),
    );
    set(row, "status", clean(field(ed, &["Status"])));
    set(row, "sub_status", clean(field(ed, &["SubStatus"])));
    set(row, "failure_reason", clean(field(ed, &["FailureReason"])));
    set(
        row,
        "subject_user_sid",
        clean(field(ed, &["SubjectUserSid"])),
    );
    set(
        row,
        "subject_user_name",
        clean(field(ed, &["SubjectUserName"])),
    );
    set(
        row,
        "subject_domain",
        clean(field(ed, &["SubjectDomainName"])),
    );
    set(
        row,
        "subject_logon_id",
        clean(field(ed, &["SubjectLogonId"])),
    );
    if eid == "4647" {
        // Remote linkage is unproven until correlation matches a remote
        // logon instance from the same source.
        row.insert("_exclude".into(), "1".into());
        row.insert("exclude_reason".into(), "unconfirmed_4647".into());
        return;
    }
    // 4624/4625/4634 reach here only with LogonType 10.
    row.insert("access_scope".into(), "remote".into());
    let address = clean(field(ed, &["IpAddress"]));
    set(row, "remote_address_raw", address.as_str());
    set(row, "remote_address", address);
    // Port 0 is a recorded value, "-" is no value.
    set(row, "remote_port", clean(field(ed, &["IpPort"])));
}

fn fill_lsm(row: &mut Row, ed: &Map<String, Value>) {
    let user = clean(field(ed, &["User"]));
    if !user.is_empty() {
        let (domain, name) = match user.split_once('\\') {
            Some((domain, name)) => (domain, name),
            None => ("", user.as_str()),
        };
        set_account(row, &user, domain, name);
    }
    // LSM SessionID is a Terminal Services session, not a Security LogonId.
    set(
        row,
        "session_id",
        clean(field(ed, &["SessionID", "Session", "TargetSession"])),
    );
    set(row, "reason", clean(field(ed, &["Reason"])));
    set(row, "source_session", clean(field(ed, &["Source"])));
    set_scope_address(row, &clean(field(ed, &["Address"])), false);
}

fn fill_rcm(row: &mut Row, ed: &Map<String, Value>) {
    let name = clean(field(ed, &["Param1"]));
    let domain = clean(field(ed, &["Param2"]));
    if !name.is_empty() || !domain.is_empty() {
        set_account(row, &name, &domain, &name);
    }
    set_scope_address(row, &clean(field(ed, &["Param3"])), false);
}

fn fill_core(row: &mut Row, eid: &str, ed: &Map<String, Value>) {
    match eid {
        "131" => {
            set(row, "conn_type", clean(field(ed, &["ConnType"])));
            let raw = clean(field(ed, &["ClientIP"]));
            set(row, "remote_address_raw", raw.as_str());
            let (host, port) = split_host_port(&raw);
            if !host.is_empty() {
                row.insert("access_scope".into(), "remote".into());
                set(row, "remote_address", host);
                set(row, "remote_port", port);
            }
        }
        "135" => {
            set(row, "tunnel_id", clean(field(ed, &["TunnelID"])));
            set(row, "transport_type", clean(field(ed, &["TransportType"])));
        }
        "226" => {
            set(
                row,
                "state_transition",
                clean(field(ed, &["StateTransition"])),
            );
            set(row, "previous_state", clean(field(ed, &["PreviousState"])));
            set(
                row,
                "previous_state_name",
                clean(field(ed, &["PreviousStateName"])),
            );
            set(row, "new_state", clean(field(ed, &["NewState"])));
            set(row, "new_state_name", clean(field(ed, &["NewStateName"])));
            set(row, "transition_event", clean(field(ed, &["Event"])));
            set(
                row,
                "transition_event_name",
                clean(field(ed, &["EventName"])),
            );
            set(row, "error_code", clean(field(ed, &["ErrorCode"])));
        }
        _ => {}
    }
}

fn fill_outbound(row: &mut Row, eid: &str, ed: &Map<String, Value>) {
    // Only the address-bearing client events record a server address; the
    // others get nothing at classify time.
    if eid == "1024" || eid == "1102" {
        set_scope_address(row, &clean(field(ed, &["Value"])), false);
    }
}

/// One row per selected event, in facts order. The returned index is the
/// stable event identity the correlation step and the parent writer use.
pub(crate) fn classify(events: &EventLogOverviewCache) -> Vec<Row> {
    let mut out: Vec<Row> = Vec::new();
    for src in events.rows() {
        let provider = g(src, "Provider");
        let eid = g(src, "EventID");
        if let Some(kind) = control_kind(provider, eid) {
            let mut row = common(src);
            row.insert("control_kind".into(), kind.into());
            row.insert("_exclude".into(), "1".into());
            row.insert("exclude_reason".into(), "control_event".into());
            out.push(row);
            continue;
        }
        let spec = match spec_for(provider, eid) {
            Some(spec) => spec,
            None => continue,
        };
        let ed = parse_eventdata(g(src, "EventData"));
        // Only RemoteInteractive logons belong to the remote access view.
        if matches!(eid, "4624" | "4625" | "4634")
            && provider == SEC
            && field(&ed, &["LogonType"]) != "10"
        {
            continue;
        }
        let mut row = common(src);
        row.insert("direction".into(), spec.direction.into());
        row.insert("result".into(), spec.result.into());
        row.insert("stage".into(), spec.stage.into());
        row.insert("description".into(), spec.description.into());
        row.insert("access_scope".into(), "unknown".into());
        match provider {
            SEC => fill_security(&mut row, eid, &ed),
            LSM => fill_lsm(&mut row, &ed),
            RCM => fill_rcm(&mut row, &ed),
            CORE => fill_core(&mut row, eid, &ed),
            AX => fill_outbound(&mut row, eid, &ed),
            _ => {}
        }
        out.push(row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overview::EventLogOverviewCache;
    use crate::sqlite::Row;

    /// Build a facts row the way the EVTX parser writes it.
    fn ev(pairs: &[(&str, &str)]) -> Row {
        let mut row = Row::new();
        for (k, v) in pairs {
            row.insert((*k).into(), (*v).into());
        }
        row
    }

    fn classify_rows(rows: Vec<Row>) -> Vec<Row> {
        classify(&EventLogOverviewCache::from_rows_for_tests(rows))
    }

    fn g<'a>(row: &'a Row, key: &str) -> &'a str {
        row.get(key).map(|s| s.as_str()).unwrap_or("")
    }

    const SEC: &str = "Microsoft-Windows-Security-Auditing";
    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
    const CORE: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";
    const AX: &str = "Microsoft-Windows-TerminalServices-ClientActiveXCore";
    const EVTLOG: &str = "Microsoft-Windows-Eventlog";

    /// Actual LSM 21 payload shape (BrowserAiParserSmoke_20261008).
    fn lsm(eid: &str, data: &str, rowid: &str) -> Row {
        ev(&[
            ("timestamp", "2026-01-27 09:19:40.232"),
            ("Provider", LSM),
            (
                "Channel",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            ),
            ("Computer", "WIN-GGCIBKR6A2I"),
            ("EventID", eid),
            ("EventRecordID", "10"),
            ("ProcessID", "1100"),
            ("ThreadID", "2204"),
            ("UserID", "S-1-5-18"),
            ("EventData", data),
            ("_record_key", &format!("LSMTABLE::{rowid}")),
            ("_source_file", "/case/EVENTLOG/Logs/LSM.evtx"),
        ])
    }

    fn sec(eid: &str, data: &str) -> Row {
        ev(&[
            ("timestamp", "2026-09-10 02:58:59.941"),
            ("Provider", SEC),
            ("Channel", "Security"),
            ("Computer", "WIN-GGCIBKR6A2I"),
            ("EventID", eid),
            ("EventRecordID", "212210"),
            ("ProcessID", "1016"),
            ("ThreadID", "147108"),
            ("EventData", data),
            ("_record_key", "Security::4924"),
            ("_source_file", "/case/EVENTLOG/Logs/Security.evtx"),
        ])
    }

    // --- common fields -----------------------------------------------------

    #[test]
    fn common_fields_come_from_facts_and_source_scope_is_the_table_prefix() {
        let rows = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "WIN-GGCIBKR6A2I\\Administrator", "SessionID": 1, "Address": "LOCAL"}}"#,
            "7",
        )]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(g(r, "timestamp"), "2026-01-27 09:19:40.232");
        assert_eq!(g(r, "event_id"), "21");
        assert_eq!(g(r, "provider"), LSM);
        assert_eq!(
            g(r, "channel"),
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        );
        assert_eq!(g(r, "computer"), "WIN-GGCIBKR6A2I");
        assert_eq!(g(r, "event_record_id"), "10");
        assert_eq!(g(r, "process_id"), "1100");
        assert_eq!(g(r, "thread_id"), "2204");
        // System/Security UserID stays the service principal, never the target.
        assert_eq!(g(r, "system_user_sid"), "S-1-5-18");
        assert_eq!(g(r, "target_user_sid"), "");
        assert_eq!(g(r, "record_key"), "LSMTABLE::7");
        assert_eq!(g(r, "source_file"), "/case/EVENTLOG/Logs/LSM.evtx");
        assert_eq!(g(r, "_source_file"), "/case/EVENTLOG/Logs/LSM.evtx");
        assert_eq!(g(r, "source_scope"), "LSMTABLE");
        assert_eq!(
            g(r, "event_data"),
            r#"{"EventXML": {"User": "WIN-GGCIBKR6A2I\\Administrator", "SessionID": 1, "Address": "LOCAL"}}"#
        );
    }

    #[test]
    fn correlation_ids_are_preserved_when_present_and_absent_otherwise() {
        let mut with = lsm("21", r#"{"EventXML": {"SessionID": 1}}"#, "1");
        with.insert(
            "ActivityID".into(),
            "{11111111-2222-3333-4444-555555555555}".into(),
        );
        with.insert(
            "RelatedActivityID".into(),
            "{99999999-8888-7777-6666-555555555555}".into(),
        );
        let without = lsm("21", r#"{"EventXML": {"SessionID": 2}}"#, "2");
        let rows = classify_rows(vec![with, without]);
        assert_eq!(
            g(&rows[0], "activity_id"),
            "{11111111-2222-3333-4444-555555555555}"
        );
        assert_eq!(
            g(&rows[0], "related_activity_id"),
            "{99999999-8888-7777-6666-555555555555}"
        );
        assert_eq!(
            g(&rows[0], "correlation_activity_id"),
            "{11111111-2222-3333-4444-555555555555}"
        );
        assert!(!rows[1].contains_key("activity_id"));
        assert!(!rows[1].contains_key("related_activity_id"));
        assert!(!rows[1].contains_key("correlation_activity_id"));
    }

    #[test]
    fn all_zero_activity_guids_are_kept_raw_but_are_not_correlation_ids() {
        let mut braced = lsm("21", r#"{"EventXML": {"SessionID": 1}}"#, "1");
        braced.insert(
            "ActivityID".into(),
            "{00000000-0000-0000-0000-000000000000}".into(),
        );
        let mut bare = lsm("21", r#"{"EventXML": {"SessionID": 1}}"#, "2");
        bare.insert(
            "ActivityID".into(),
            "00000000-0000-0000-0000-000000000000".into(),
        );
        bare.insert(
            "RelatedActivityID".into(),
            "00000000-0000-0000-0000-000000000000".into(),
        );
        let rows = classify_rows(vec![braced, bare]);
        for r in &rows {
            assert!(r.get("activity_id").unwrap().contains("00000000"));
            assert!(!r.contains_key("correlation_activity_id"));
            assert!(!r.contains_key("correlation_related_activity_id"));
        }
    }

    #[test]
    fn empty_or_invalid_payload_still_emits_the_row_without_invented_fields() {
        let rows = classify_rows(vec![lsm("40", "", "3"), lsm("40", "not json", "4")]);
        assert_eq!(rows.len(), 2);
        assert!(!rows[0].contains_key("event_data"));
        assert_eq!(g(&rows[1], "event_data"), "not json");
        for r in &rows {
            assert!(!r.contains_key("session_id"));
            assert!(!r.contains_key("remote_address"));
            assert!(!r.contains_key("account_name"));
            assert_eq!(g(r, "access_scope"), "unknown");
        }
    }

    #[test]
    fn rows_keep_input_order_and_unknown_providers_are_dropped() {
        let rows = classify_rows(vec![
            lsm("21", r#"{"EventXML": {"SessionID": 1}}"#, "1"),
            ev(&[
                ("Provider", "Microsoft-Windows-Kernel-General"),
                ("EventID", "12"),
            ]),
            lsm("23", r#"{"EventXML": {"SessionID": 1}}"#, "2"),
        ]);
        assert_eq!(rows.len(), 2);
        assert_eq!(g(&rows[0], "event_id"), "21");
        assert_eq!(g(&rows[1], "event_id"), "23");
    }

    #[test]
    fn rows_without_timestamp_are_retained() {
        let mut row = lsm("21", r#"{"EventXML": {"SessionID": 1}}"#, "1");
        row.remove("timestamp");
        let rows = classify_rows(vec![row]);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].contains_key("timestamp"));
    }

    // --- LSM ---------------------------------------------------------------

    #[test]
    fn lsm_local_address_is_local_scope_and_never_a_remote_address() {
        let rows = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "WIN-GGCIBKR6A2I\\Administrator", "SessionID": 1, "Address": "LOCAL"}}"#,
            "1",
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "access_scope"), "local");
        // R01: a LOCAL record never asserts an inbound remote direction,
        // while stage/result stay exactly as the provider recorded them.
        assert_eq!(g(r, "direction"), "unknown");
        assert_eq!(g(r, "stage"), "logon");
        assert_eq!(g(r, "result"), "성공");
        assert!(!r.contains_key("remote_address"));
        assert_eq!(g(r, "remote_address_raw"), "LOCAL");
        assert_eq!(g(r, "session_id"), "1");
        assert_eq!(g(r, "account_raw"), "WIN-GGCIBKR6A2I\\Administrator");
        assert_eq!(g(r, "account_name"), "Administrator");
        assert_eq!(g(r, "account_domain"), "WIN-GGCIBKR6A2I");
        assert_eq!(g(r, "account"), "Administrator");
        assert_eq!(g(r, "account_key"), "win-ggcibkr6a2i\\administrator");
        assert!(!r.contains_key("logon_id"));
    }

    #[test]
    fn lsm_remote_address_is_remote_scope() {
        let rows = classify_rows(vec![lsm(
            "25",
            r#"{"EventXML": {"User": "WIN-GGCIBKR6A2I\\Administrator", "SessionID": 1, "Address": "59.19.252.187"}}"#,
            "1",
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "access_scope"), "remote");
        assert_eq!(g(r, "stage"), "reconnect");
        assert_eq!(g(r, "remote_address"), "59.19.252.187");
        assert_eq!(g(r, "remote_address_raw"), "59.19.252.187");
        assert!(!r.contains_key("remote_port"));
    }

    #[test]
    fn lsm_stage_map_covers_every_selected_event() {
        let want = [
            ("21", "logon", "성공"),
            ("22", "shell", "정보"),
            ("23", "logoff", "정보"),
            ("24", "disconnect", "정보"),
            ("25", "reconnect", "성공"),
            ("39", "disconnect", "정보"),
            ("40", "disconnect", "정보"),
        ];
        for (eid, stage, result) in want {
            let rows = classify_rows(vec![lsm(eid, r#"{"EventXML": {"SessionID": 1}}"#, "1")]);
            assert_eq!(rows.len(), 1, "event {eid}");
            assert_eq!(g(&rows[0], "stage"), stage, "event {eid}");
            assert_eq!(g(&rows[0], "result"), result, "event {eid}");
            assert_eq!(g(&rows[0], "direction"), "inbound", "event {eid}");
        }
    }

    #[test]
    fn lsm_40_uses_session_and_keeps_reason_without_identity() {
        let rows = classify_rows(vec![lsm(
            "40",
            r#"{"EventXML": {"Session": 1, "Reason": 5}}"#,
            "1",
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "session_id"), "1");
        assert_eq!(g(r, "reason"), "5");
        assert!(!r.contains_key("account_name"));
        assert!(!r.contains_key("account_key"));
        assert_eq!(g(r, "access_scope"), "unknown");
    }

    #[test]
    fn lsm_39_keeps_source_session_separately_from_session_id() {
        let rows = classify_rows(vec![lsm(
            "39",
            r#"{"EventXML": {"Session": 2, "Source": 1}}"#,
            "1",
        )]);
        assert_eq!(g(&rows[0], "session_id"), "2");
        assert_eq!(g(&rows[0], "source_session"), "1");
    }

    #[test]
    fn lsm_reason_zero_is_preserved() {
        let rows = classify_rows(vec![lsm(
            "40",
            r#"{"EventXML": {"Session": 2, "Reason": 0}}"#,
            "1",
        )]);
        assert_eq!(g(&rows[0], "reason"), "0");
    }

    // --- Security ----------------------------------------------------------

    const S4624_T10: &str = r#"{"SubjectUserSid": "S-1-5-18", "SubjectUserName": "WIN-GGCIBKR6A2I$", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7", "TargetUserSid": "S-1-5-21-1112784034-420110452-3239019016-500", "TargetUserName": "Administrator", "TargetDomainName": "WIN-GGCIBKR6A2I", "TargetLogonId": "0x1ecee532d", "LogonType": 10, "LogonProcessName": "User32", "AuthenticationPackageName": "Negotiate", "WorkstationName": "WIN-GGCIBKR6A2I", "ProcessId": "0xa68", "ProcessName": "C:\\Windows\\System32\\svchost.exe", "IpAddress": "59.19.252.187", "IpPort": "0"}"#;

    #[test]
    fn security_4624_type10_keeps_identity_and_separates_subject_from_target() {
        let rows = classify_rows(vec![sec("4624", S4624_T10)]);
        let r = &rows[0];
        assert_eq!(g(r, "direction"), "inbound");
        assert_eq!(g(r, "access_scope"), "remote");
        assert_eq!(g(r, "stage"), "logon");
        assert_eq!(g(r, "result"), "성공");
        assert_eq!(g(r, "logon_type"), "10");
        assert_eq!(g(r, "logon_id"), "0x1ecee532d");
        assert_eq!(
            g(r, "target_user_sid"),
            "S-1-5-21-1112784034-420110452-3239019016-500"
        );
        assert_eq!(g(r, "account_name"), "Administrator");
        assert_eq!(g(r, "account_domain"), "WIN-GGCIBKR6A2I");
        assert_eq!(g(r, "account_raw"), "Administrator");
        // Confirmed SID wins the identity key.
        assert_eq!(
            g(r, "account_key"),
            "S-1-5-21-1112784034-420110452-3239019016-500"
        );
        assert_eq!(g(r, "subject_user_sid"), "S-1-5-18");
        assert_eq!(g(r, "subject_user_name"), "WIN-GGCIBKR6A2I$");
        assert_eq!(g(r, "subject_domain"), "WORKGROUP");
        assert_eq!(g(r, "subject_logon_id"), "0x3e7");
        assert_eq!(g(r, "authentication_package"), "Negotiate");
        assert_eq!(g(r, "logon_process"), "User32");
        assert_eq!(g(r, "remote_address"), "59.19.252.187");
        // Actual 0 survives; it is not NULL.
        assert_eq!(g(r, "remote_port"), "0");
        // WorkstationName is the collected host itself for User32 logons.
        assert_eq!(g(r, "workstation_name"), "WIN-GGCIBKR6A2I");
        assert!(!r.contains_key("remote_computer"));
        assert!(!r.contains_key("session_id"));
        assert!(!r.contains_key("local_address"));
    }

    #[test]
    fn security_logon_events_require_logon_type_10() {
        let t3 = S4624_T10.replace("\"LogonType\": 10", "\"LogonType\": 3");
        let rows = classify_rows(vec![
            sec("4624", &t3),
            sec("4625", &t3),
            sec("4634", r#"{"TargetLogonId": "0x1", "LogonType": 2}"#),
        ]);
        assert!(rows.is_empty());
    }

    #[test]
    fn security_logon_type_missing_is_not_treated_as_remote() {
        let rows = classify_rows(vec![sec("4624", r#"{"TargetUserName": "a"}"#)]);
        assert!(rows.is_empty());
    }

    #[test]
    fn security_4625_type10_keeps_failure_detail() {
        let data = r#"{"TargetUserSid": "S-1-0-0", "TargetUserName": "Administrator", "TargetDomainName": "WIN-GGCIBKR6A2I", "Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": "0xc0000064", "LogonType": 10, "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM", "IpAddress": "59.19.252.187", "IpPort": "0"}"#;
        let rows = classify_rows(vec![sec("4625", data)]);
        let r = &rows[0];
        assert_eq!(g(r, "result"), "실패");
        assert_eq!(g(r, "stage"), "logon");
        assert_eq!(g(r, "status"), "0xc000006d");
        assert_eq!(g(r, "sub_status"), "0xc0000064");
        assert_eq!(g(r, "failure_reason"), "%%2313");
        // S-1-0-0 is the null SID: keep it raw but never key identity on it.
        assert_eq!(g(r, "target_user_sid"), "S-1-0-0");
        assert_eq!(g(r, "account_key"), "win-ggcibkr6a2i\\administrator");
    }

    #[test]
    fn security_4634_type10_is_a_logon_instance_end() {
        let rows = classify_rows(vec![sec(
            "4634",
            r#"{"TargetUserSid": "S-1-5-21-1112784034-420110452-3239019016-500", "TargetUserName": "Administrator", "TargetDomainName": "WIN-GGCIBKR6A2I", "TargetLogonId": "0x1ecee532d", "LogonType": 10}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "stage"), "logoff");
        assert_eq!(g(r, "result"), "정보");
        assert_eq!(g(r, "access_scope"), "remote");
        assert_eq!(g(r, "logon_id"), "0x1ecee532d");
        assert!(!r.contains_key("_exclude"));
        // The description must not claim the desktop session ended.
        assert!(g(r, "description").contains("로그온"));
    }

    #[test]
    fn security_4647_is_emitted_but_pre_excluded_until_correlation_confirms() {
        let rows = classify_rows(vec![sec(
            "4647",
            r#"{"TargetUserSid": "S-1-5-21-1112784034-420110452-3239019016-500", "TargetUserName": "Administrator", "TargetDomainName": "WIN-GGCIBKR6A2I", "TargetLogonId": "0x5e7873"}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "event_id"), "4647");
        assert_eq!(g(r, "logon_id"), "0x5e7873");
        assert_eq!(g(r, "stage"), "logoff");
        assert_eq!(g(r, "_exclude"), "1");
        assert_eq!(g(r, "exclude_reason"), "unconfirmed_4647");
        // Direction/scope stay unknown: 4647 carries no remote evidence.
        assert_eq!(g(r, "direction"), "unknown");
        assert_eq!(g(r, "access_scope"), "unknown");
        assert!(!r.contains_key("logon_type"));
    }

    #[test]
    fn security_4778_4779_split_remote_from_console() {
        let remote = r#"{"AccountName": "Administrator", "AccountDomain": "WIN-GGCIBKR6A2I", "LogonID": "0x1ecee532d", "SessionName": "RDP-Tcp#3", "ClientName": "DESKTOP-8UPEUU3", "ClientAddress": "59.19.252.187"}"#;
        let console = r#"{"AccountName": "Administrator", "AccountDomain": "WIN-GGCIBKR6A2I", "LogonID": "0x3e7", "SessionName": "Console", "ClientName": "-", "ClientAddress": "LOCAL"}"#;
        let rows = classify_rows(vec![sec("4778", remote), sec("4779", console)]);
        let a = &rows[0];
        assert_eq!(a.get("stage").unwrap(), "reconnect");
        assert_eq!(g(a, "access_scope"), "remote");
        assert_eq!(g(a, "remote_address"), "59.19.252.187");
        assert_eq!(g(a, "remote_computer"), "DESKTOP-8UPEUU3");
        assert_eq!(g(a, "session_name"), "RDP-Tcp#3");
        assert_eq!(g(a, "logon_id"), "0x1ecee532d");
        // SessionName is a name, never the LSM numeric session id.
        assert!(!a.contains_key("session_id"));
        let b = &rows[1];
        assert_eq!(g(b, "stage"), "disconnect");
        assert_eq!(g(b, "access_scope"), "local");
        assert_eq!(g(b, "direction"), "unknown");
        assert!(!b.contains_key("remote_address"));
        assert_eq!(g(b, "remote_address_raw"), "LOCAL");
        assert!(!b.contains_key("remote_computer"));
    }

    #[test]
    fn control_events_are_excluded_and_carry_no_remote_interpretation() {
        let mut clear = sec("1102", "");
        clear.insert("Provider".into(), EVTLOG.into());
        let rows = classify_rows(vec![sec("4608", ""), clear]);
        assert_eq!(rows.len(), 2);
        for (r, kind) in rows.iter().zip(["system_start", "log_cleared"]) {
            assert_eq!(g(r, "control_kind"), kind);
            assert_eq!(g(r, "_exclude"), "1");
            assert_eq!(g(r, "exclude_reason"), "control_event");
            assert!(!r.contains_key("direction"));
            assert!(!r.contains_key("stage"));
            assert!(!r.contains_key("access_scope"));
            assert!(!r.contains_key("result"));
            assert_eq!(g(r, "source_scope"), "Security");
        }
    }

    #[test]
    fn eventlog_1102_from_another_provider_is_not_a_control_row() {
        let rows = classify_rows(vec![sec("1102", "")]);
        assert!(rows.is_empty());
    }

    // --- RCM / RdpCoreTS ---------------------------------------------------

    fn rcm(eid: &str, data: &str) -> Row {
        ev(&[
            ("timestamp", "2026-06-11 14:20:24.176"),
            ("Provider", RCM),
            (
                "Channel",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            ),
            ("Computer", "WIN-GGCIBKR6A2I"),
            ("EventID", eid),
            ("EventRecordID", "1"),
            ("UserID", "S-1-5-20"),
            ("EventData", data),
            ("_record_key", "RCM::1"),
            ("_source_file", "/case/EVENTLOG/Logs/RCM.evtx"),
        ])
    }

    #[test]
    fn rcm_1149_is_authentication_only_and_not_a_logon_proof() {
        let rows = classify_rows(vec![rcm(
            "1149",
            r#"{"EventXML": {"Param1": "administrator", "Param2": "DESKTOP-8UPEUU3", "Param3": "59.19.252.187"}}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "stage"), "authentication");
        assert_eq!(g(r, "result"), "성공");
        assert_eq!(g(r, "direction"), "inbound");
        assert_eq!(g(r, "access_scope"), "remote");
        assert_eq!(g(r, "account_name"), "administrator");
        assert_eq!(g(r, "account_domain"), "DESKTOP-8UPEUU3");
        assert_eq!(g(r, "remote_address"), "59.19.252.187");
        assert!(!r.contains_key("session_id"));
        assert!(!r.contains_key("logon_id"));
        // R08: 1149 must not be described as desktop/login-screen arrival.
        let desc = g(r, "description");
        assert!(!desc.contains("로그인 화면"));
        assert!(!desc.contains("데스크톱"));
    }

    #[test]
    fn rcm_1149_without_domain_keeps_an_undomained_account_key() {
        let rows = classify_rows(vec![rcm(
            "1149",
            r#"{"EventXML": {"Param1": "administrator", "Param2": "", "Param3": "59.19.252.187"}}"#,
        )]);
        let r = &rows[0];
        assert!(!r.contains_key("account_domain"));
        assert!(!r.contains_key("remote_computer"));
        assert_eq!(g(r, "account_key"), "administrator");
    }

    #[test]
    fn account_keys_never_collapse_different_domains_or_bare_names() {
        let a = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "DOMA\\user", "SessionID": 1}}"#,
            "1",
        )]);
        let b = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "DOMB\\user", "SessionID": 1}}"#,
            "1",
        )]);
        let bare = classify_rows(vec![rcm("1149", r#"{"EventXML": {"Param1": "user"}}"#)]);
        assert_eq!(g(&a[0], "account_key"), "doma\\user");
        assert_eq!(g(&b[0], "account_key"), "domb\\user");
        assert_eq!(g(&bare[0], "account_key"), "user");
        assert_ne!(g(&a[0], "account_key"), g(&b[0], "account_key"));
        assert_ne!(g(&a[0], "account_key"), g(&bare[0], "account_key"));
    }

    #[test]
    fn case_variants_of_the_same_account_share_one_key() {
        let a = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "WIN-X\\Administrator", "SessionID": 1}}"#,
            "1",
        )]);
        let b = classify_rows(vec![lsm(
            "21",
            r#"{"EventXML": {"User": "win-x\\administrator", "SessionID": 1}}"#,
            "1",
        )]);
        assert_eq!(g(&a[0], "account_key"), g(&b[0], "account_key"));
        // Display and raw keep the original casing.
        assert_eq!(g(&a[0], "account"), "Administrator");
        assert_eq!(g(&a[0], "account_raw"), "WIN-X\\Administrator");
    }

    #[test]
    fn upn_accounts_keep_the_upn_and_do_not_invent_a_domain() {
        let rows = classify_rows(vec![sec(
            "4625",
            r#"{"TargetUserSid": "S-1-0-0", "TargetUserName": "su3592@naver.com", "TargetDomainName": "-", "LogonType": 10, "Status": "0xc000006d"}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "account_upn"), "su3592@naver.com");
        assert_eq!(g(r, "account_name"), "su3592");
        assert!(!r.contains_key("account_domain"));
        assert_eq!(g(r, "account_key"), "su3592@naver.com");
    }

    fn core(eid: &str, data: &str) -> Row {
        ev(&[
            ("timestamp", "2026-09-16 16:06:59.923"),
            ("Provider", CORE),
            (
                "Channel",
                "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
            ),
            ("Computer", "WIN-GGCIBKR6A2I"),
            ("EventID", eid),
            ("EventRecordID", "3984"),
            ("ProcessID", "1396"),
            ("ThreadID", "2204"),
            ("UserID", "S-1-5-20"),
            ("EventData", data),
            ("_record_key", "Core::44"),
            ("_source_file", "/case/EVENTLOG/Logs/Core.evtx"),
        ])
    }

    #[test]
    fn core_131_splits_client_ip_and_port_but_keeps_the_raw_token() {
        let rows = classify_rows(vec![core(
            "131",
            r#"{"ConnType": "TCP", "ClientIP": "59.19.252.187:60963"}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "stage"), "transport");
        assert_eq!(g(r, "direction"), "inbound");
        assert_eq!(g(r, "access_scope"), "remote");
        assert_eq!(g(r, "remote_address"), "59.19.252.187");
        assert_eq!(g(r, "remote_port"), "60963");
        assert_eq!(g(r, "remote_address_raw"), "59.19.252.187:60963");
        assert_eq!(g(r, "conn_type"), "TCP");
    }

    #[test]
    fn core_131_handles_bracketed_ipv6_and_portless_values() {
        let rows = classify_rows(vec![
            core("131", r#"{"ClientIP": "[fe80::1]:3389"}"#),
            core("131", r#"{"ClientIP": "fe80::1"}"#),
            core("131", r#"{"ClientIP": "10.0.0.5"}"#),
        ]);
        assert_eq!(g(&rows[0], "remote_address"), "fe80::1");
        assert_eq!(g(&rows[0], "remote_port"), "3389");
        assert_eq!(g(&rows[1], "remote_address"), "fe80::1");
        assert!(!rows[1].contains_key("remote_port"));
        assert_eq!(g(&rows[2], "remote_address"), "10.0.0.5");
        assert!(!rows[2].contains_key("remote_port"));
    }

    #[test]
    fn core_135_is_a_transport_warning_not_an_rdp_failure() {
        let rows = classify_rows(vec![core(
            "135",
            r#"{"TunnelID": 1, "TransportType": "TCP: Reason Code: 3 (No UDP Packets Received)"}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "stage"), "transport_warning");
        // Information only: the UDP problem is not a whole-session failure.
        assert_eq!(g(r, "result"), "정보");
        assert_eq!(g(r, "direction"), "inbound");
        assert_eq!(g(r, "access_scope"), "unknown");
        assert_eq!(g(r, "tunnel_id"), "1");
        assert_eq!(
            g(r, "transport_type"),
            "TCP: Reason Code: 3 (No UDP Packets Received)"
        );
        assert!(!r.contains_key("remote_address"));
        assert!(!r.contains_key("session_id"));
    }

    #[test]
    fn core_226_keeps_the_raw_error_transition() {
        let rows = classify_rows(vec![core(
            "226",
            r#"{"StateTransition": "RDP_TCP", "PreviousState": 23, "PreviousStateName": "StateUnknown", "NewState": 21, "NewStateName": "StateDisconnected", "Event": 43, "EventName": "Event_Disconnect", "ErrorCode": "0x80070040"}"#,
        )]);
        let r = &rows[0];
        assert_eq!(g(r, "stage"), "error_transition");
        assert_eq!(g(r, "result"), "정보");
        assert_eq!(g(r, "state_transition"), "RDP_TCP");
        assert_eq!(g(r, "previous_state"), "23");
        assert_eq!(g(r, "previous_state_name"), "StateUnknown");
        assert_eq!(g(r, "new_state"), "21");
        assert_eq!(g(r, "new_state_name"), "StateDisconnected");
        assert_eq!(g(r, "transition_event"), "43");
        assert_eq!(g(r, "transition_event_name"), "Event_Disconnect");
        assert_eq!(g(r, "error_code"), "0x80070040");
        // No proven start/end comes out of a state transition.
        assert!(!r.contains_key("session_id"));
        assert!(!r.contains_key("logon_id"));
    }

    #[test]
    fn rdpcore_unselected_ids_stay_out_of_the_event_set() {
        let rows = classify_rows(vec![
            core(
                "101",
                r#"{"ReasonString": "Reason Code: 2(Server Configuration)."}"#,
            ),
            core("103", r#"{"ReasonCode": 5}"#),
            core("66", r#"{"ConnectionName": "RDP-Tcp#0", "SessionID": 3}"#),
        ]);
        assert!(rows.is_empty());
    }

    #[test]
    fn facts_status_and_error_are_preserved() {
        let mut row = core("131", r#"{"ClientIP": "10.0.0.5"}"#);
        row.insert("_status".into(), "ok".into());
        row.insert("_error".into(), String::new());
        let rows = classify_rows(vec![row]);
        assert_eq!(g(&rows[0], "facts_status"), "ok");
        assert!(!rows[0].contains_key("facts_error"));
    }

    // --- outbound ----------------------------------------------------------

    fn ax(eid: &str, data: &str) -> Row {
        ev(&[
            ("timestamp", "2026-02-02 10:00:00.000"),
            ("Provider", AX),
            (
                "Channel",
                "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            ),
            ("Computer", "WIN-GGCIBKR6A2I"),
            ("EventID", eid),
            ("EventRecordID", "1"),
            ("ProcessID", "4242"),
            ("EventData", data),
            ("_record_key", "RDPClient::1"),
            ("_source_file", "/case/EVENTLOG/Logs/RDPClient.evtx"),
        ])
    }

    #[test]
    fn outbound_events_keep_direction_and_their_own_address_only() {
        let rows = classify_rows(vec![
            ax("1024", r#"{"Name": "ServerName", "Value": "10.1.1.9"}"#),
            ax("1025", ""),
            ax("1026", ""),
            ax("1102", r#"{"Name": "ServerAddress", "Value": "10.1.1.9"}"#),
        ]);
        assert_eq!(rows.len(), 4);
        for r in &rows {
            assert_eq!(g(r, "direction"), "outbound");
        }
        assert_eq!(g(&rows[0], "remote_address"), "10.1.1.9");
        assert_eq!(g(&rows[0], "access_scope"), "remote");
        assert_eq!(g(&rows[0], "stage"), "transport");
        // No address evidence of its own: nothing is borrowed at classify time.
        assert!(!rows[1].contains_key("remote_address"));
        assert_eq!(g(&rows[1], "access_scope"), "unknown");
        assert_eq!(g(&rows[2], "stage"), "disconnect");
        assert_eq!(g(&rows[3], "remote_address"), "10.1.1.9");
        // Process scope is available for correlation; no connection id exists.
        assert_eq!(g(&rows[0], "process_id"), "4242");
        assert!(!rows[0].contains_key("connection_id"));
    }

    #[test]
    fn invalid_activity_cannot_join_connections_and_sid_needs_no_name() {
        let mut source = ax("1025", "");
        source.insert("ActivityID".into(), "not-a-guid".into());
        let rows = classify_rows(vec![
            source,
            sec(
                "4624",
                r#"{"LogonType":10,"TargetUserSid":"S-1-5-21-1-2-3-1001"}"#,
            ),
        ]);
        assert_eq!(g(&rows[0], "activity_id"), "not-a-guid");
        assert!(!rows[0].contains_key("correlation_activity_id"));
        assert_eq!(g(&rows[1], "account_key"), "S-1-5-21-1-2-3-1001");
        assert!(!rows[1].contains_key("account_name"));
    }

    #[test]
    fn authentication_domain_is_not_a_peer_computer() {
        let rows = classify_rows(vec![rcm(
            "1149",
            r#"{"EventXML":{"Param1":"alice","Param2":"CORP","Param3":"10.0.0.9"}}"#,
        )]);
        assert_eq!(g(&rows[0], "account_domain"), "CORP");
        assert_eq!(g(&rows[0], "account_key"), r"corp\alice");
        assert!(!rows[0].contains_key("remote_computer"));
    }

    #[test]
    fn enhanced_session_is_not_proof_of_a_remote_rdp_connection() {
        let rows = classify_rows(vec![sec(
            "4778",
            r#"{"AccountName":"alice","AccountDomain":"CORP","LogonID":"0x1","SessionName":"31C5CE94259D4006A9E4#3","ClientAddress":"127.0.0.1","ClientName":"HOST"}"#,
        )]);
        assert_eq!(g(&rows[0], "access_scope"), "unknown");
        assert_eq!(g(&rows[0], "direction"), "unknown");
        assert_eq!(g(&rows[0], "remote_address"), "127.0.0.1");
        assert_eq!(g(&rows[0], "logon_id"), "0x1");
    }
}
