//! Source-scoped correlation for classified remote access events.
//!
//! Rows are grouped only inside one collected log (`source_scope`) plus
//! provider/channel/computer and one ID namespace, and identity is carried
//! forward only inside a proven instance of that ID. Nothing here groups by
//! time proximity, infers a reboot, merges different account domains, or turns
//! observed bounds into a proven start/end or a dwell duration. Rows are never
//! reordered or removed; the only mutations are `segment_key`, lifting the
//! classifier's fail-closed 4647 exclusion once it is confirmed, and effective
//! fields that each get a relation row.

use crate::sqlite::Row;
use std::collections::HashMap;

/// Correlation output. Indices in `segments`/`relations` are zero-based
/// decimal strings into the original classify vector.
#[derive(Debug, Default)]
pub(crate) struct Correlation {
    pub segments: Vec<Row>,
    pub relations: Vec<Row>,
}

/// Account identity is read as one atomic bundle so a domain from one event
/// can never be paired with a name from another. `account_raw` is part of the
/// bundle for detection only — it is the original payload value and is never
/// written back.
const ACCOUNT_FIELDS: [&str; 6] = [
    "account",
    "account_raw",
    "account_name",
    "account_domain",
    "account_upn",
    "account_key",
];

/// Segment-level fields aggregated from direct (pre-carry) member evidence.
const AGG_FIELDS: [&str; 16] = [
    "direction",
    "access_scope",
    "session_id",
    "logon_id",
    "session_name",
    "target_user_sid",
    "logon_type",
    "account",
    "account_raw",
    "account_name",
    "account_domain",
    "account_upn",
    "account_key",
    "remote_address",
    "remote_port",
    "remote_computer",
];

/// The classifier marks 4647 excluded up front; correlation lifts it only for
/// a confirmed logon instance.
const UNCONFIRMED_4647: &str = "unconfirmed_4647";

/// Console (LOCAL) logons are not remote access and are not stored
/// (2026-10-14 user decision).
pub(crate) const CONSOLE_SESSION: &str = "console_session";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IdSpace {
    LsmSession,
    SecurityLogon,
    RdpClientConnection,
}

impl IdSpace {
    fn as_str(self) -> &'static str {
        match self {
            IdSpace::LsmSession => "lsm_session",
            IdSpace::SecurityLogon => "security_logon",
            IdSpace::RdpClientConnection => "rdp_client_connection",
        }
    }
}

/// Everything that makes two IDs the same ID. Different source logs, channels,
/// providers, computers or namespaces are different IDs even when the number
/// is identical (an LSM SessionID is not a Security LogonId).
#[derive(Clone)]
struct ScopeMeta {
    source_scope: String,
    channel: String,
    provider: String,
    computer: String,
    space: IdSpace,
    id: String,
    /// Extra scope component; process id for outbound client connections.
    extra: String,
}

impl ScopeMeta {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.source_scope,
            self.channel,
            self.provider,
            self.computer,
            self.space.as_str(),
            self.id,
            self.extra
        )
    }
}

struct Scope {
    meta: ScopeMeta,
    /// Members with a usable timestamp, sorted by (timestamp, original index).
    timed: Vec<usize>,
    /// Members without a timestamp — retained, but never ordered nor carried.
    untimed: Vec<usize>,
}

/// Real restart / log-clear evidence. Only ever splits segments.
struct Control {
    index: usize,
    kind: &'static str,
    time: String,
    computer: String,
    source_scope: String,
}

/// Last direct evidence inside the current instance.
#[derive(Default)]
struct Carry {
    address: Option<(usize, String)>,
    /// remote/local, kept apart from the address because LOCAL sessions have
    /// no address at all.
    access_scope: Option<(usize, String)>,
    /// (evidence index, ACCOUNT_FIELDS values)
    account: Option<(usize, Vec<String>)>,
    sid: Option<(usize, String)>,
    /// Principal of the instance, recorded once from the first direct
    /// evidence that carries it.
    principal_sid: String,
    principal_name: String,
    principal_domain: String,
}

struct SegmentBuild {
    key: String,
    meta: ScopeMeta,
    instance: String,
    split_reason: &'static str,
    time_unknown: bool,
    members: Vec<usize>,
    /// Direct (pre-carry) AGG_FIELDS of each member, parallel to `members`.
    direct: Vec<Row>,
    /// (index, event_id, timestamp, start_kind) of a proven start event.
    start: Option<(usize, String, String, &'static str)>,
    /// (index, event_id, timestamp, end_kind) of a proven end event.
    end: Option<(usize, String, String, &'static str)>,
    truncated: Option<(usize, &'static str)>,
    reconnects: usize,
    disconnects: usize,
    /// Per AGG_FIELDS: (first direct value, saw a different direct value).
    agg: Vec<(String, bool)>,
}

impl SegmentBuild {
    fn new(meta: ScopeMeta, instance: String, split_reason: &'static str) -> Self {
        let key = format!("{}|{}", meta.key(), instance);
        Self {
            key,
            meta,
            instance,
            split_reason,
            time_unknown: false,
            members: Vec::new(),
            direct: Vec::new(),
            start: None,
            end: None,
            truncated: None,
            reconnects: 0,
            disconnects: 0,
            agg: vec![(String::new(), false); AGG_FIELDS.len()],
        }
    }

    /// Record direct evidence of a member. Must run before any effective fill
    /// so a carried value is never echoed back as direct evidence.
    fn observe_direct(&mut self, row: &Row) {
        let mut snapshot = Row::new();
        for name in AGG_FIELDS {
            put(&mut snapshot, name, field(row, name));
        }
        self.absorb(&snapshot);
        self.direct.push(snapshot);
    }

    fn absorb(&mut self, row: &Row) {
        for (slot, name) in AGG_FIELDS.iter().enumerate() {
            let value = field(row, name);
            if value.is_empty()
                || (matches!(*name, "direction" | "access_scope") && value == "unknown")
            {
                continue;
            }
            if self.agg[slot].0.is_empty() {
                self.agg[slot].0 = value.to_string();
            } else if self.agg[slot].0 != value {
                self.agg[slot].1 = true;
            }
        }
    }

    /// Reconnect/disconnect are counted, never turned into a dwell duration.
    fn count_stage(&mut self, row: &Row) {
        match field(row, "stage") {
            "reconnect" => self.reconnects += 1,
            "disconnect" => self.disconnects += 1,
            _ => {}
        }
    }

    /// Drop console members (already marked excluded) and rebuild every
    /// aggregate from the remaining ones. False when nothing remains.
    fn drop_console(&mut self, rows: &[Row]) -> bool {
        let gone = |index: usize| field(&rows[index], "exclude_reason") == CONSOLE_SESSION;
        if !self.members.iter().any(|&index| gone(index)) {
            return true;
        }
        let kept: Vec<(usize, Row)> = self
            .members
            .drain(..)
            .zip(self.direct.drain(..))
            .filter(|(index, _)| !gone(*index))
            .collect();
        self.agg = vec![(String::new(), false); AGG_FIELDS.len()];
        self.reconnects = 0;
        self.disconnects = 0;
        for (index, snapshot) in kept {
            self.absorb(&snapshot);
            self.count_stage(&rows[index]);
            self.members.push(index);
            self.direct.push(snapshot);
        }
        if self.start.as_ref().is_some_and(|(index, ..)| gone(*index)) {
            self.start = None;
        }
        if self.end.as_ref().is_some_and(|(index, ..)| gone(*index)) {
            self.end = None;
        }
        if self.truncated.as_ref().is_some_and(|(index, _)| gone(*index)) {
            self.truncated = None;
        }
        !self.members.is_empty()
    }

    fn emit(&self, rows: &[Row]) -> Row {
        let mut r = Row::new();
        put(&mut r, "segment_key", &self.key);
        put(&mut r, "source_scope", &self.meta.source_scope);
        put(&mut r, "provider", &self.meta.provider);
        put(&mut r, "channel", &self.meta.channel);
        put(&mut r, "computer", &self.meta.computer);
        put(&mut r, "id_space", self.meta.space.as_str());
        put(&mut r, "id_value", &self.meta.id);
        if self.meta.space == IdSpace::RdpClientConnection {
            put(&mut r, "scope_process_id", &self.meta.extra);
        }
        put(&mut r, "instance_index", &self.instance);
        put(
            &mut r,
            "time_unknown",
            if self.time_unknown { "1" } else { "0" },
        );
        put(&mut r, "split_reason", self.split_reason);

        let ordered = &self.members;
        r.insert("event_count".into(), ordered.len().to_string());
        if let Some(&first) = ordered.first() {
            put(&mut r, "first_event_index", &first.to_string());
        }
        if let Some(&last) = ordered.last() {
            put(&mut r, "last_event_index", &last.to_string());
        }

        // Observed bounds are what this log happens to show, never a proven
        // session span.
        if let Some(&first) = ordered.first() {
            put(
                &mut r,
                "first_observed_time",
                field(&rows[first], "timestamp"),
            );
        }
        if let Some(&last) = ordered.last() {
            put(
                &mut r,
                "last_observed_time",
                field(&rows[last], "timestamp"),
            );
        }

        match &self.start {
            Some((index, eid, time, kind)) => {
                put(&mut r, "start_bound", "proven");
                put(&mut r, "start_time", time);
                put(&mut r, "start_event_index", &index.to_string());
                put(&mut r, "start_event_id", eid);
                put(&mut r, "start_kind", kind);
            }
            None => put(&mut r, "start_bound", "unobserved"),
        }
        match &self.end {
            Some((index, eid, time, kind)) => {
                put(&mut r, "end_bound", "proven");
                put(&mut r, "end_time", time);
                put(&mut r, "end_event_index", &index.to_string());
                put(&mut r, "end_event_id", eid);
                put(&mut r, "end_kind", kind);
            }
            None => put(&mut r, "end_bound", "unobserved"),
        }
        if let Some((index, kind)) = &self.truncated {
            put(&mut r, "truncated_by", kind);
            put(&mut r, "truncated_by_index", &index.to_string());
        }
        r.insert("reconnect_count".into(), self.reconnects.to_string());
        r.insert("disconnect_count".into(), self.disconnects.to_string());

        let mut varied: Vec<&str> = Vec::new();
        for (slot, name) in AGG_FIELDS.iter().enumerate() {
            let value = if matches!(*name, "direction" | "access_scope")
                && (self.agg[slot].0.is_empty() || self.agg[slot].1)
            {
                "unknown"
            } else {
                &self.agg[slot].0
            };
            put(&mut r, name, value);
            if self.agg[slot].1 {
                varied.push(*name);
            }
        }
        // A console/LOCAL segment is never an inbound remote connection.
        if field(&r, "access_scope") == "local" {
            put(&mut r, "direction", "unknown");
        }
        if !varied.is_empty() {
            put(&mut r, "identity_varied", &varied.join(","));
        }
        r
    }
}

fn field<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn set(row: &mut Row, key: &str, value: &str) {
    row.insert(key.to_string(), value.to_string());
}

/// Missing values stay absent — only real evidence is written.
fn put(row: &mut Row, key: &str, value: &str) {
    if !value.is_empty() {
        row.insert(key.to_string(), value.to_string());
    }
}

fn connection_key(value: &str) -> String {
    uuid::Uuid::parse_str(value.trim())
        .map(|id| id.hyphenated().to_string())
        .unwrap_or_else(|_| value.to_string())
}

/// ID namespace of one row, or None when nothing identifies it. Outbound needs
/// a real activity id plus process scope — a PID alone or a time window must
/// never link client events.
fn id_namespace(row: &Row) -> Option<(IdSpace, String, String)> {
    if field(row, "direction") == "outbound" {
        // correlation_activity_id is the classifier's genuine-GUID-only
        // field; a process id alone never groups anything.
        let id = field(row, "correlation_activity_id");
        let process = field(row, "process_id");
        if id.is_empty() || process.is_empty() {
            return None;
        }
        return Some((
            IdSpace::RdpClientConnection,
            connection_key(id),
            process.to_string(),
        ));
    }
    let session = field(row, "session_id");
    if !session.is_empty() {
        return Some((IdSpace::LsmSession, session.to_string(), String::new()));
    }
    let logon = crate::derived::normalize_logon_id(field(row, "logon_id"));
    if !logon.is_empty() {
        return Some((IdSpace::SecurityLogon, logon, String::new()));
    }
    None
}

/// Reconnection does not prove an initial logon. An outbound connection starts
/// at its attempt (1024) or, without one, at the established event (1025).
fn start_kind(space: IdSpace, eid: &str) -> Option<&'static str> {
    match (space, eid) {
        (IdSpace::LsmSession, "21") => Some("session_logon"),
        (IdSpace::SecurityLogon, "4624") => Some("logon_instance_start"),
        (IdSpace::RdpClientConnection, "1024") => Some("client_connection_attempt"),
        (IdSpace::RdpClientConnection, "1025") => Some("client_connection_established"),
        _ => None,
    }
}

/// Events that open a new instance when one is already in progress. 1025
/// completes the attempt it follows, so it never splits.
fn opens_instance(space: IdSpace, eid: &str) -> bool {
    match space {
        IdSpace::RdpClientConnection => eid == "1024",
        _ => start_kind(space, eid).is_some(),
    }
}

/// Events that prove an instance end. Security ends the logon instance, which
/// is not the same thing as a desktop session ending. An LSM disconnect
/// (24/39/40) leaves the session open for a reconnect (25), so only the
/// logoff (23) ends it.
fn end_kind(space: IdSpace, eid: &str) -> Option<&'static str> {
    match (space, eid) {
        (IdSpace::LsmSession, "23") => Some("session_logoff"),
        (IdSpace::SecurityLogon, "4634") => Some("logon_instance_end"),
        (IdSpace::RdpClientConnection, "1026") => Some("client_disconnect"),
        _ => None,
    }
}

/// A restart invalidates every ID on that computer; a log clear only breaks
/// continuity of the log it happened in.
fn control_applies(control: &Control, meta: &ScopeMeta) -> bool {
    match control.kind {
        "system_start" => !meta.computer.is_empty() && control.computer == meta.computer,
        "log_cleared" => control.source_scope == meta.source_scope,
        _ => false,
    }
}

/// A row the classifier excluded stays out of correlation, except the
/// fail-closed 4647 candidate which is exactly what correlation decides.
fn is_correlatable(row: &Row) -> bool {
    if !field(row, "control_kind").is_empty() {
        return false;
    }
    field(row, "_exclude") != "1" || field(row, "exclude_reason") == UNCONFIRMED_4647
}

fn relation_row(
    from: usize,
    to: usize,
    field_name: &str,
    kind: &str,
    value: &str,
    segment_key: &str,
) -> Row {
    let mut r = Row::new();
    r.insert("from_index".into(), from.to_string());
    r.insert("to_index".into(), to.to_string());
    r.insert("field".into(), field_name.to_string());
    r.insert("relation_kind".into(), kind.to_string());
    put(&mut r, "value", value);
    r.insert("segment_key".into(), segment_key.to_string());
    r
}

/// Does this row prove a different principal than the open instance? A known
/// SID on both sides decides; otherwise the recorded name, plus the domain
/// when both sides have one. Account keys are built differently per event
/// (SID-based for 4624, domain/name for 4778), so unequal key strings alone
/// prove nothing. An unknown principal never proves equality, so it never
/// splits either.
fn principal_conflict(carry: &Carry, row: &Row) -> bool {
    let sid = field(row, "target_user_sid");
    if crate::derived::is_sid(sid)
        && !sid.eq_ignore_ascii_case("S-1-0-0")
        && !carry.principal_sid.is_empty()
    {
        return !sid.eq_ignore_ascii_case(&carry.principal_sid);
    }
    let name = field(row, "account_name");
    if name.is_empty() || carry.principal_name.is_empty() {
        return false;
    }
    if !name.eq_ignore_ascii_case(&carry.principal_name) {
        return true;
    }
    let domain = field(row, "account_domain");
    !domain.is_empty()
        && !carry.principal_domain.is_empty()
        && !domain.eq_ignore_ascii_case(&carry.principal_domain)
}

fn collect_controls(rows: &[Row]) -> Vec<Control> {
    let mut out = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let kind = match field(row, "control_kind") {
            "system_start" => "system_start",
            "log_cleared" => "log_cleared",
            _ => continue,
        };
        out.push(Control {
            index,
            kind,
            time: field(row, "timestamp").to_string(),
            computer: field(row, "computer").to_string(),
            source_scope: field(row, "source_scope").to_string(),
        });
    }
    out.sort_by(|a, b| a.time.cmp(&b.time).then(a.index.cmp(&b.index)));
    out
}

fn collect_scopes(rows: &[Row]) -> (Vec<String>, HashMap<String, Scope>) {
    let mut order: Vec<String> = Vec::new();
    let mut scopes: HashMap<String, Scope> = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        if !is_correlatable(row) {
            continue;
        }
        // Without a source we cannot prove two rows come from the same log.
        let source_scope = field(row, "source_scope");
        if source_scope.is_empty() {
            continue;
        }
        let Some((space, id, extra)) = id_namespace(row) else {
            continue;
        };
        let meta = ScopeMeta {
            source_scope: source_scope.to_string(),
            channel: field(row, "channel").to_string(),
            provider: field(row, "provider").to_string(),
            computer: field(row, "computer").to_string(),
            space,
            id,
            extra,
        };
        let key = meta.key();
        if !scopes.contains_key(&key) {
            order.push(key.clone());
            scopes.insert(
                key.clone(),
                Scope {
                    meta,
                    timed: Vec::new(),
                    untimed: Vec::new(),
                },
            );
        }
        let scope = scopes.get_mut(&key).expect("scope inserted above");
        if field(row, "timestamp").is_empty() {
            scope.untimed.push(index);
        } else {
            scope.timed.push(index);
        }
    }
    (order, scopes)
}

/// Fill empty effective fields from the instance's last direct evidence and
/// record one relation per filled field. Raw identity fields stay untouched.
fn carry_into(
    rows: &mut [Row],
    index: usize,
    segment_key: &str,
    carry: &mut Carry,
    relations: &mut Vec<Row>,
) {
    let own_address = field(&rows[index], "remote_address").to_string();
    if field(&rows[index], "access_scope") == "local" {
        carry.address = None;
    } else if own_address.is_empty() {
        if let Some((from, address)) = carry.address.as_ref() {
            set(&mut rows[index], "remote_address", &address);
            relations.push(relation_row(
                *from,
                index,
                "remote_address",
                "carry_forward",
                &address,
                segment_key,
            ));
        }
    } else {
        carry.address = Some((index, own_address));
    }

    // remote vs LOCAL/console travels on its own because a LOCAL session has
    // an access_scope but no address.
    let own_scope = field(&rows[index], "access_scope").to_string();
    if own_scope.is_empty() || own_scope == "unknown" {
        if let Some((from, scope)) = carry.access_scope.as_ref() {
            set(&mut rows[index], "access_scope", &scope);
            relations.push(relation_row(
                *from,
                index,
                "access_scope",
                "carry_forward",
                &scope,
                segment_key,
            ));
            // Evidenced LOCAL/console access must not stay an inbound remote
            // success for direction-based consumers.
            if scope == "local" && field(&rows[index], "direction") != "unknown" {
                set(&mut rows[index], "direction", "unknown");
                relations.push(relation_row(
                    *from,
                    index,
                    "direction",
                    "local_scope_direction",
                    "unknown",
                    segment_key,
                ));
            }
            // LSM records only this host's sessions: proven remote scope of the
            // same session instance is what makes an unaddressed one inbound.
            if scope == "remote"
                && field(&rows[index], "provider") == super::LSM
                && field(&rows[index], "direction") == "unknown"
            {
                set(&mut rows[index], "direction", "inbound");
                relations.push(relation_row(
                    *from,
                    index,
                    "direction",
                    "remote_scope_direction",
                    "inbound",
                    segment_key,
                ));
            }
        }
    } else {
        carry.access_scope = Some((index, own_scope));
    }

    // Console rows are not stored, so they never donate identity to the
    // remote rows that survive.
    let console = field(&rows[index], "access_scope") == "local";
    let own_account: Vec<String> = ACCOUNT_FIELDS
        .iter()
        .map(|name| field(&rows[index], name).to_string())
        .collect();
    if own_account.iter().all(String::is_empty) {
        if let Some((from, bundle)) = carry.account.as_ref() {
            for (name, value) in ACCOUNT_FIELDS.iter().zip(bundle.iter()) {
                // account_raw stays exactly as the payload recorded it.
                if value.is_empty()
                    || *name == "account_raw"
                    || (*name == "account_key" && carry.sid.is_some())
                {
                    continue;
                }
                set(&mut rows[index], name, value);
                relations.push(relation_row(
                    *from,
                    index,
                    name,
                    "carry_forward",
                    value,
                    segment_key,
                ));
            }
        }
    } else {
        if carry.principal_name.is_empty() {
            carry.principal_name.clone_from(&own_account[2]);
        }
        if carry.principal_domain.is_empty() {
            carry.principal_domain.clone_from(&own_account[3]);
        }
        if !console {
            carry.account = Some((index, own_account));
        }
    }

    let own_sid = field(&rows[index], "target_user_sid").to_string();
    if own_sid.is_empty() {
        if let Some((from, sid)) = carry.sid.as_ref() {
            set(&mut rows[index], "target_user_sid", &sid);
            relations.push(relation_row(
                *from,
                index,
                "target_user_sid",
                "carry_forward",
                &sid,
                segment_key,
            ));
            let key = sid.to_ascii_uppercase();
            if field(&rows[index], "account_key") != key {
                set(&mut rows[index], "account_key", &key);
                relations.push(relation_row(
                    *from,
                    index,
                    "account_key",
                    "carry_forward",
                    &key,
                    segment_key,
                ));
            }
        }
    } else if crate::derived::is_sid(&own_sid) && !own_sid.eq_ignore_ascii_case("S-1-0-0") {
        if carry.principal_sid.is_empty() {
            carry.principal_sid.clone_from(&own_sid);
        }
        if !console {
            carry.sid = Some((index, own_sid));
        }
    }
}

fn walk_scope(
    rows: &mut [Row],
    scope: &Scope,
    controls: &[Control],
    builds: &mut Vec<SegmentBuild>,
    relations: &mut Vec<Row>,
) {
    let mut current: Option<(SegmentBuild, Carry)> = None;
    let mut next_instance = 1usize;
    let mut pending: &'static str = "";
    let mut prev_time = String::new();

    for &index in &scope.timed {
        let time = field(&rows[index], "timestamp").to_string();
        let eid = field(&rows[index], "event_id").to_string();

        // Actual restart / log-clear evidence closes the open instance so a
        // reused ID is never linked across the boundary.
        if current.is_some() {
            let hit = controls.iter().find(|c| {
                !c.time.is_empty()
                    && c.time.as_str() > prev_time.as_str()
                    && c.time <= time
                    && control_applies(c, &scope.meta)
            });
            if let Some(control) = hit {
                let (mut build, _) = current.take().expect("instance open");
                build.truncated = Some((control.index, control.kind));
                builds.push(build);
                pending = "after_control_boundary";
            }
        }

        let starts = start_kind(scope.meta.space, &eid);
        let opens = opens_instance(scope.meta.space, &eid);
        let conflicts = current
            .as_ref()
            .is_some_and(|(_, carry)| principal_conflict(carry, &rows[index]));
        let starts_new = conflicts
            || current
                .as_ref()
                .is_some_and(|(build, _)| opens && !build.members.is_empty());

        // 4647 arrives excluded. It is confirmed only by a still-open, proven
        // remote logon instance with this LogonId in this same log; an
        // arbitrary earlier matching ID is not evidence.
        if scope.meta.space == IdSpace::SecurityLogon && eid == "4647" {
            let confirmed = !starts_new
                && current
                    .as_ref()
                    .is_some_and(|(build, _)| build.start.is_some());
            if !confirmed {
                set(&mut rows[index], "_exclude", "1");
                set(&mut rows[index], "exclude_reason", UNCONFIRMED_4647);
                continue;
            }
            rows[index].remove("_exclude");
            rows[index].remove("exclude_reason");
        }

        if starts_new {
            let (build, _) = current.take().expect("instance open");
            builds.push(build);
            pending = if conflicts {
                "principal_conflict"
            } else {
                "new_start"
            };
        }
        if current.is_none() {
            let instance = next_instance.to_string();
            next_instance += 1;
            current = Some((
                SegmentBuild::new(scope.meta.clone(), instance, pending),
                Carry::default(),
            ));
            pending = "";
        }

        let ends = end_kind(scope.meta.space, &eid);
        {
            let (build, carry) = current.as_mut().expect("instance open");
            build.observe_direct(&rows[index]);
            build.members.push(index);
            let key = build.key.clone();
            set(&mut rows[index], "segment_key", &key);
            carry_into(rows, index, &key, carry, relations);
            build.count_stage(&rows[index]);
            if let Some(kind) = starts {
                if build.start.is_none() {
                    build.start = Some((index, eid.clone(), time.clone(), kind));
                }
            }
            if let Some(kind) = ends {
                build.end = Some((index, eid.clone(), time.clone(), kind));
            }
            if scope.meta.space == IdSpace::SecurityLogon && (ends.is_some() || eid == "4647") {
                if let Some((start_index, _, _, _)) = &build.start {
                    let relation = if eid == "4647" {
                        "confirmed_remote_logoff"
                    } else {
                        "logon_instance_end"
                    };
                    let logon_id = field(&rows[index], "logon_id").to_string();
                    relations.push(relation_row(
                        index,
                        *start_index,
                        "logon_id",
                        relation,
                        &logon_id,
                        &key,
                    ));
                }
            }
        }
        if ends.is_some() {
            let (build, _) = current.take().expect("instance open");
            builds.push(build);
            pending = "after_end";
        }
        prev_time = time;
    }
    if let Some((mut build, _)) = current.take() {
        if let Some(control) = controls
            .iter()
            .find(|c| c.time > prev_time && control_applies(c, &scope.meta))
        {
            build.truncated = Some((control.index, control.kind));
        }
        builds.push(build);
    }

    // Rows without a timestamp cannot be ordered, so no instance can be
    // established for them: each keeps its own single-row segment with the ID
    // provenance, and they neither give nor receive carry.
    for &index in &scope.untimed {
        if field(&rows[index], "_exclude") == "1" {
            continue;
        }
        let mut build = SegmentBuild::new(scope.meta.clone(), format!("u{index}"), "");
        build.time_unknown = true;
        build.observe_direct(&rows[index]);
        build.members.push(index);
        let key = build.key.clone();
        set(&mut rows[index], "segment_key", &key);
        build.count_stage(&rows[index]);
        builds.push(build);
    }
}

pub(crate) fn correlate(rows: &mut [Row]) -> Correlation {
    let controls = collect_controls(rows);
    let (order, mut scopes) = collect_scopes(rows);
    for key in &order {
        let scope = scopes.get_mut(key).expect("scope key was registered");
        // Same timestamp keeps original record order.
        scope.timed.sort_by(|&a, &b| {
            field(&rows[a], "timestamp")
                .cmp(field(&rows[b], "timestamp"))
                .then(a.cmp(&b))
        });
    }

    let mut builds: Vec<SegmentBuild> = Vec::new();
    let mut relations: Vec<Row> = Vec::new();
    for key in &order {
        let scope = scopes.get(key).expect("scope key was registered");
        walk_scope(rows, scope, &controls, &mut builds, &mut relations);
    }

    // Exclusion runs after carry so the session's logoff/shell rows that only
    // inherit LOCAL scope go too; segments keep their remote members only.
    for row in rows.iter_mut() {
        if field(row, "access_scope") == "local" && field(row, "_exclude") != "1" {
            set(row, "_exclude", "1");
            set(row, "exclude_reason", CONSOLE_SESSION);
        }
    }
    builds.retain_mut(|build| build.drop_console(rows));
    relations.retain(|relation| {
        ["from_index", "to_index"].iter().all(|key| {
            field(relation, key)
                .parse::<usize>()
                .map_or(true, |index| field(&rows[index], "exclude_reason") != CONSOLE_SESSION)
        })
    });
    let mut segments: Vec<Row> = builds.iter().map(|build| build.emit(rows)).collect();
    segments.sort_by(|a, b| {
        let first = |r: &Row| {
            field(r, "first_event_index")
                .parse::<usize>()
                .unwrap_or(usize::MAX)
        };
        first(a)
            .cmp(&first(b))
            .then_with(|| field(a, "segment_key").cmp(field(b, "segment_key")))
    });
    relations.sort_by(|a, b| {
        let num = |r: &Row, k: &str| field(r, k).parse::<usize>().unwrap_or(usize::MAX);
        num(a, "to_index")
            .cmp(&num(b, "to_index"))
            .then_with(|| num(a, "from_index").cmp(&num(b, "from_index")))
            .then_with(|| field(a, "field").cmp(field(b, "field")))
            .then_with(|| field(a, "relation_kind").cmp(field(b, "relation_kind")))
    });
    Correlation {
        segments,
        relations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    const LSM_CH: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    const SEC: &str = "Microsoft-Windows-Security-Auditing";
    // Same `dataset::db::table` form the derived builder assigns.
    const SRC_LSM: &str = "ds::EVENTLOG/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.sqlite::Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational";
    const SRC_SEC: &str = "ds::EVENTLOG/Security.sqlite::Security";
    const SRC_CLIENT: &str = "ds::EVENTLOG/Microsoft-Windows-TerminalServices-RDPClient%4Operational.sqlite::Microsoft-Windows-TerminalServices-RDPClient%4Operational";

    fn ev(pairs: &[(&str, &str)]) -> Row {
        pairs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// `domain\name` as the classifier splits it; a bare name has no domain.
    fn split_account(account: &str) -> (&str, &str) {
        match account.split_once('\\') {
            Some((domain, name)) => (domain, name),
            None => ("", account),
        }
    }

    /// LSM row as the classifier emits it: an empty address means unknown, and
    /// a LOCAL session has access_scope=local with no address at all.
    fn lsm(time: &str, eid: &str, session: &str, address: &str, account: &str) -> Row {
        let stage = match eid {
            "21" => "logon",
            "22" => "shell",
            "23" => "logoff",
            "24" | "39" | "40" => "disconnect",
            "25" => "reconnect",
            _ => "",
        };
        let (domain, name) = split_account(account);
        ev(&[
            ("timestamp", time),
            ("event_id", eid),
            ("provider", LSM),
            ("channel", LSM_CH),
            ("computer", "PC1"),
            ("source_scope", SRC_LSM),
            // Classifier rule: LSM is inbound only with remote address evidence.
            ("direction", if address.is_empty() { "unknown" } else { "inbound" }),
            ("stage", stage),
            ("result", "성공"),
            (
                "access_scope",
                if address.is_empty() {
                    "unknown"
                } else {
                    "remote"
                },
            ),
            ("session_id", session),
            ("remote_address", address),
            ("account", name),
            ("account_name", name),
            ("account_domain", domain),
            ("account_key", account),
        ])
    }

    /// Direct LOCAL evidence: the classifier already neutralises direction.
    fn lsm_local(time: &str, eid: &str, session: &str, account: &str) -> Row {
        let mut row = lsm(time, eid, session, "", account);
        row.insert("access_scope".into(), "local".into());
        row.insert("direction".into(), "unknown".into());
        row.insert("remote_address_raw".into(), "LOCAL".into());
        row
    }

    fn security(time: &str, eid: &str, logon_id: &str, account: &str) -> Row {
        let stage = match eid {
            "4624" => "logon",
            "4625" => "logon",
            "4634" | "4647" => "logoff",
            _ => "",
        };
        let (domain, name) = split_account(account);
        ev(&[
            ("timestamp", time),
            ("event_id", eid),
            ("provider", SEC),
            ("channel", "Security"),
            ("computer", "PC1"),
            ("source_scope", SRC_SEC),
            ("direction", "inbound"),
            ("stage", stage),
            ("access_scope", "remote"),
            ("logon_id", logon_id),
            ("logon_type", "10"),
            ("account", name),
            ("account_name", name),
            ("account_domain", domain),
            ("account_key", account),
        ])
    }

    /// The classifier ships 4647 already excluded (fail-closed).
    fn candidate_4647(time: &str, logon_id: &str) -> Row {
        let mut row = security(time, "4647", logon_id, "");
        row.insert("_exclude".into(), "1".into());
        row.insert("exclude_reason".into(), UNCONFIRMED_4647.into());
        row
    }

    #[test]
    fn a_sid_key_and_a_name_key_for_the_same_principal_do_not_split() {
        const SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        // 4624 keys the principal by SID; 4778 only ever records domain/name.
        let logon = || {
            let mut row = security("2026-09-29 00:10:00", "4624", "0x33", "corp\\alice");
            row.insert("target_user_sid".into(), SID.into());
            row.insert("account_key".into(), SID.into());
            row
        };
        let mut reconnect = security("2026-09-29 00:20:00", "4778", "0x33", "CORP\\Alice");
        reconnect.insert("stage".into(), "reconnect".into());
        reconnect.insert("session_name".into(), "RDP-Tcp#0".into());
        let mut rows = vec![logon(), reconnect];
        let c = correlate(&mut rows);
        assert_eq!(
            c.segments.len(),
            1,
            "differently built account keys are not a different principal"
        );
        assert_eq!(rows[0]["segment_key"], rows[1]["segment_key"]);
        assert_eq!(rows[1]["target_user_sid"], SID, "the known SID carries");
        assert_eq!(field(&c.segments[0], "reconnect_count"), "1");

        // A different SID on the same LogonId is a genuine conflict.
        let mut other = security("2026-09-29 00:30:00", "4634", "0x33", "corp\\bob");
        other.insert(
            "target_user_sid".into(),
            "S-1-5-21-1111111111-2222222222-3333333333-1002".into(),
        );
        let mut rows = vec![logon(), other];
        let c = correlate(&mut rows);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(field(&c.segments[1], "split_reason"), "principal_conflict");
    }

    fn control(time: &str, eid: &str, kind: &str, source_scope: &str) -> Row {
        ev(&[
            ("timestamp", time),
            ("event_id", eid),
            (
                "provider",
                if kind == "log_cleared" {
                    "Microsoft-Windows-Eventlog"
                } else {
                    SEC
                },
            ),
            ("channel", "Security"),
            ("computer", "PC1"),
            ("source_scope", source_scope),
            ("control_kind", kind),
            ("_exclude", "1"),
            ("exclude_reason", "control_event"),
        ])
    }

    fn has_carry(c: &Correlation, from: usize, to: usize, name: &str) -> bool {
        c.relations.iter().any(|r| {
            field(r, "relation_kind") == "carry_forward"
                && field(r, "field") == name
                && field(r, "from_index") == from.to_string()
                && field(r, "to_index") == to.to_string()
        })
    }

    #[test]
    fn forward_carry_inside_one_proven_session() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:20:00", "23", "3", "", ""),
        ];
        rows[0].insert("account_raw".into(), "CORP\\Alice".into());
        rows[0].insert("account_name".into(), "Alice".into());
        rows[0].insert("account_domain".into(), "CORP".into());
        let c = correlate(&mut rows);
        assert_eq!(rows[1]["remote_address"], "10.0.0.5");
        assert_eq!(rows[1]["account_key"], "corp\\alice");
        assert_eq!(rows[1]["account_name"], "Alice");
        assert_eq!(rows[1]["account_domain"], "CORP");
        assert_eq!(rows[1]["access_scope"], "remote");
        assert_eq!(
            rows[1].get("account_raw"),
            None,
            "raw payload values are never filled by correlation"
        );
        assert_eq!(rows[0]["account_raw"], "CORP\\Alice", "original untouched");
        assert!(has_carry(&c, 0, 1, "remote_address"));
        assert!(has_carry(&c, 0, 1, "account_key"));
        assert!(has_carry(&c, 0, 1, "account_name"));
        assert!(!has_carry(&c, 0, 1, "account_raw"));
        assert!(has_carry(&c, 0, 1, "access_scope"));
        assert_eq!(c.segments.len(), 1);
        let s = &c.segments[0];
        assert_eq!(field(s, "start_bound"), "proven");
        assert_eq!(field(s, "start_kind"), "session_logon");
        assert_eq!(field(s, "start_time"), "2026-09-29 00:10:00");
        assert_eq!(field(s, "end_bound"), "proven");
        assert_eq!(field(s, "end_kind"), "session_logoff");
        assert_eq!(field(s, "first_observed_time"), "2026-09-29 00:10:00");
        assert_eq!(field(s, "last_observed_time"), "2026-09-29 00:20:00");
        assert!(
            s.keys()
                .all(|k| !k.contains("duration") && !k.contains("dwell")),
            "observed bounds must never become a dwell duration"
        );
    }

    #[test]
    fn new_logon21_splits_before_carry() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:11:00", "25", "3", "", ""),
            lsm("2026-09-29 00:30:00", "21", "3", "", ""),
            lsm("2026-09-29 00:31:00", "23", "3", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1]["remote_address"], "10.0.0.5");
        assert_eq!(rows[2].get("remote_address"), None, "new 21 resets carry");
        assert_eq!(rows[3].get("remote_address"), None);
        assert_eq!(c.segments.len(), 2);
        assert_ne!(rows[1]["segment_key"], rows[2]["segment_key"]);
        assert_eq!(field(&c.segments[1], "split_reason"), "new_start");
        assert_eq!(field(&c.segments[0], "reconnect_count"), "1");
        assert_eq!(field(&c.segments[0], "disconnect_count"), "0");
        assert_eq!(field(&c.segments[0], "end_bound"), "unobserved");
        assert_eq!(field(&c.segments[1], "start_bound"), "proven");
    }

    #[test]
    fn principal_conflict_splits_and_keeps_domains_apart() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:12:00", "25", "3", "", "lab\\alice"),
            lsm("2026-09-29 00:13:00", "24", "3", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(field(&c.segments[1], "split_reason"), "principal_conflict");
        assert_eq!(rows[1]["account_key"], "lab\\alice", "domain is not merged");
        assert_eq!(
            rows[1].get("remote_address"),
            None,
            "a conflicting principal must not inherit the previous address"
        );
        assert_eq!(rows[2].get("remote_address"), None);
        assert_eq!(field(&c.segments[1], "account_key"), "lab\\alice");
    }

    #[test]
    fn disconnect_keeps_the_session_instance_open_and_logoff_ends_it() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:20:00", "24", "3", "", ""),
            lsm("2026-09-29 00:20:00", "39", "3", "", ""),
            lsm("2026-09-29 00:20:00", "40", "3", "", ""),
            lsm("2026-09-29 00:40:00", "25", "3", "", ""),
            lsm("2026-09-29 00:50:00", "23", "3", "", ""),
            lsm("2026-09-29 00:50:01", "24", "3", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(c.segments.len(), 2);
        // Reconnect after a disconnect is the same session instance.
        assert_eq!(rows[4]["remote_address"], "10.0.0.5");
        assert_eq!(rows[4]["account_key"], "corp\\alice");
        assert_eq!(rows[0]["segment_key"], rows[5]["segment_key"]);
        let session = &c.segments[0];
        assert_eq!(field(session, "start_kind"), "session_logon");
        assert_eq!(field(session, "end_kind"), "session_logoff");
        assert_eq!(field(session, "end_event_id"), "23");
        assert_eq!(field(session, "disconnect_count"), "3");
        assert_eq!(field(session, "reconnect_count"), "1");
        assert_eq!(field(session, "event_count"), "6");
        // State is dropped after the logoff row.
        assert_eq!(rows[6].get("remote_address"), None);
        assert_eq!(field(&c.segments[1], "split_reason"), "after_end");
        assert_eq!(field(&c.segments[1], "start_bound"), "unobserved");
        assert_eq!(field(&c.segments[1], "end_bound"), "unobserved");
    }

    // Remote logon, console reattach (25 LOCAL), then remote again in one
    // session: only remote members and their counts survive.
    #[test]
    fn console_members_leave_a_remote_session_with_remote_counts_only() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:20:00", "24", "3", "", ""),
            lsm_local("2026-09-29 00:30:00", "25", "3", "corp\\alice"),
            lsm("2026-09-29 00:40:00", "24", "3", "", ""),
            lsm("2026-09-29 00:50:00", "25", "3", "10.0.0.6", "corp\\alice"),
            lsm("2026-09-29 01:00:00", "23", "3", "", ""),
        ];
        let c = correlate(&mut rows);
        let console: Vec<usize> = (0..rows.len())
            .filter(|&i| field(&rows[i], "exclude_reason") == CONSOLE_SESSION)
            .collect();
        assert!(console.contains(&2));
        assert_eq!(c.segments.len(), 1);
        let session = &c.segments[0];
        let survivors = rows.len() - console.len();
        assert_eq!(field(session, "event_count"), survivors.to_string());
        assert_eq!(field(session, "access_scope"), "remote");
        assert_eq!(field(session, "start_event_index"), "0");
        for (key, stage) in [("reconnect_count", "reconnect"), ("disconnect_count", "disconnect")] {
            let expected = (0..rows.len())
                .filter(|i| !console.contains(i) && field(&rows[*i], "stage") == stage)
                .count();
            assert_eq!(field(session, key), expected.to_string(), "{key}");
        }
        assert!(c.relations.iter().all(|r| {
            [field(r, "from_index"), field(r, "to_index")]
                .iter()
                .all(|i| !console.contains(&i.parse().unwrap()))
        }));
    }

    #[test]
    fn all_console_session_leaves_no_segment_or_relation() {
        let mut rows = vec![
            lsm_local("2026-09-29 00:10:00", "21", "1", "corp\\alice"),
            lsm("2026-09-29 00:10:01", "22", "1", "", ""),
            lsm("2026-09-29 09:00:00", "23", "1", "", ""),
        ];
        let c = correlate(&mut rows);
        assert!(rows.iter().all(|r| field(r, "exclude_reason") == CONSOLE_SESSION));
        assert!(c.segments.is_empty());
        assert!(c.relations.is_empty());
    }

    // A surviving remote row never takes identity from a removed console row.
    #[test]
    fn console_rows_never_donate_identity_to_remote_rows() {
        let mut rows = vec![
            lsm_local("2026-09-29 00:10:00", "21", "3", "corp\\bob"),
            lsm("2026-09-29 00:20:00", "25", "3", "10.0.0.6", ""),
            lsm("2026-09-29 00:30:00", "21", "4", "10.0.0.5", "corp\\alice"),
            lsm_local("2026-09-29 00:40:00", "25", "4", "corp\\alice"),
            lsm("2026-09-29 00:50:00", "25", "4", "10.0.0.6", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1].get("account_key"), None);
        assert_eq!(rows[4]["account_key"], "corp\\alice");
        let cited = |to: &str| -> Vec<String> {
            c.relations
                .iter()
                .filter(|r| field(r, "to_index") == to && field(r, "field") == "account_key")
                .map(|r| field(r, "from_index").to_string())
                .collect()
        };
        assert!(cited("1").is_empty());
        assert_eq!(cited("4"), vec!["2".to_string()]);
    }

    #[test]
    fn client_connection_start_is_the_attempt_or_the_established_event() {
        let id = "11111111-2222-3333-4444-555555555555";
        let mut rows = vec![
            client("2026-09-29 00:10:00", "1024", id, "10.0.0.9"),
            client("2026-09-29 00:10:01", "1026", id, ""),
            client("2026-09-29 00:10:02", "1102", id, "10.0.0.9"),
            client("2026-09-29 00:10:03", "1025", id, ""),
            client("2026-09-29 00:20:00", "1026", id, ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(c.segments.len(), 2);
        let attempt = &c.segments[0];
        assert_eq!(field(attempt, "start_bound"), "proven");
        assert_eq!(field(attempt, "start_kind"), "client_connection_attempt");
        assert_eq!(field(attempt, "start_event_id"), "1024");
        assert_eq!(field(attempt, "end_kind"), "client_disconnect");
        // 1025 marks the established connection without splitting the instance.
        let connected = &c.segments[1];
        assert_eq!(field(connected, "event_count"), "3");
        assert_eq!(field(connected, "start_kind"), "client_connection_established");
        assert_eq!(field(connected, "start_event_id"), "1025");
        assert_eq!(field(connected, "end_event_id"), "1026");
    }

    #[test]
    fn interleaved_sessions_do_not_cross_fill() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "1", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:11:00", "21", "2", "", ""),
            lsm("2026-09-29 00:12:00", "25", "1", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(
            rows[1].get("remote_address"),
            None,
            "session 2 stays unknown"
        );
        assert_eq!(rows[2]["remote_address"], "10.0.0.5");
        assert!(has_carry(&c, 0, 2, "remote_address"));
        assert_eq!(c.segments.len(), 2);
    }

    #[test]
    fn same_session_id_in_another_source_is_another_id() {
        let mut other = lsm("2026-09-29 00:20:00", "23", "3", "", "");
        other.insert(
            "source_scope".into(),
            "ds::EVENTLOG/Second%4Operational.sqlite::Second%4Operational".into(),
        );
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "3", "10.0.0.5", "corp\\alice"),
            other,
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1].get("remote_address"), None);
        assert_eq!(rows[1].get("account_key"), None);
        assert_eq!(c.segments.len(), 2);
        assert_ne!(rows[0]["segment_key"], rows[1]["segment_key"]);
    }

    #[test]
    fn lsm_session_id_is_not_a_security_logon_id() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "2", "10.0.0.5", "corp\\alice"),
            security("2026-09-29 00:11:00", "4634", "2", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1].get("remote_address"), None);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(field(&c.segments[0], "id_space"), "lsm_session");
        assert_eq!(field(&c.segments[1], "id_space"), "security_logon");
    }

    // RD-05: an LSM record without its own address becomes inbound only when
    // the same session instance carries proven remote scope.
    #[test]
    fn remote_session_scope_makes_unaddressed_lsm_inbound() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "6", "10.0.0.5", "corp\\alice"),
            lsm("2026-09-29 00:20:00", "40", "6", "", ""),
            lsm("2026-09-29 00:30:00", "40", "7", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1]["access_scope"], "remote");
        assert_eq!(rows[1]["direction"], "inbound");
        assert!(c.relations.iter().any(|r| {
            field(r, "relation_kind") == "remote_scope_direction"
                && field(r, "field") == "direction"
                && field(r, "from_index") == "0"
                && field(r, "to_index") == "1"
        }));
        // No scope evidence in its own session: stays unknown.
        assert_eq!(rows[2]["direction"], "unknown");
        assert_eq!(rows[2]["access_scope"], "unknown");
    }

    #[test]
    fn untimed_rows_are_kept_but_never_carry_or_share_an_instance() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "5", "10.0.0.5", "corp\\alice"),
            lsm("", "23", "5", "", ""),
            lsm("2026-09-29 00:30:00", "25", "5", "", ""),
            lsm("", "21", "5", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(
            rows[1].get("remote_address"),
            None,
            "no usable order means no carry"
        );
        assert!(rows[1].contains_key("segment_key"), "still findable");
        assert_eq!(rows[2]["remote_address"], "10.0.0.5");
        assert!(!has_carry(&c, 1, 2, "remote_address"));
        let untimed: Vec<&Row> = c
            .segments
            .iter()
            .filter(|s| field(s, "time_unknown") == "1")
            .collect();
        assert_eq!(untimed.len(), 2, "an unknown instance is never shared");
        assert_ne!(
            rows[1]["segment_key"], rows[3]["segment_key"],
            "same reused id, but no provable same instance"
        );
        assert_eq!(field(untimed[0], "instance_index"), "u1");
        assert_eq!(field(untimed[0], "event_count"), "1");
        assert_eq!(field(untimed[0], "start_bound"), "unobserved");
        assert_eq!(field(untimed[0], "end_bound"), "unobserved");
        assert_eq!(field(untimed[0], "first_observed_time"), "");
        assert_ne!(rows[0]["segment_key"], rows[1]["segment_key"]);
    }

    #[test]
    fn unconfirmed_4647_stays_excluded_in_place() {
        let mut rows = vec![candidate_4647("2026-09-29 00:16:29.663", "0x5e7873")];
        let c = correlate(&mut rows);
        assert_eq!(rows[0]["_exclude"], "1");
        assert_eq!(rows[0]["exclude_reason"], UNCONFIRMED_4647);
        assert_eq!(rows[0].get("segment_key"), None);
        assert!(c.segments.is_empty());
        assert!(c.relations.is_empty());
    }

    #[test]
    fn confirmed_4647_links_to_its_own_logon_instance() {
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4624", "0x5e7873", "corp\\alice"),
            candidate_4647("2026-09-29 00:16:29.663", "0x5e7873"),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1].get("_exclude"), None, "exclusion is lifted");
        assert_eq!(rows[1].get("exclude_reason"), None);
        assert_eq!(rows[0]["segment_key"], rows[1]["segment_key"]);
        assert!(c.relations.iter().any(|r| {
            field(r, "relation_kind") == "confirmed_remote_logoff"
                && field(r, "from_index") == "1"
                && field(r, "to_index") == "0"
                && field(r, "field") == "logon_id"
                && field(r, "value") == "0x5e7873"
        }));
    }

    #[test]
    fn logoff_4647_after_the_instance_ended_stays_unconfirmed() {
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4624", "0x11", "corp\\alice"),
            security("2026-09-29 00:11:00", "4634", "0x11", ""),
            candidate_4647("2026-09-29 00:12:00", "0x11"),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[2]["exclude_reason"], UNCONFIRMED_4647);
        assert_eq!(rows[2].get("segment_key"), None);
        assert_eq!(c.segments.len(), 1);
        assert!(c.relations.iter().any(|r| {
            field(r, "relation_kind") == "logon_instance_end"
                && field(r, "from_index") == "1"
                && field(r, "to_index") == "0"
        }));
    }

    #[test]
    fn logon_id_zero_never_groups_rows() {
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4625", "0x0", "corp\\alice"),
            security("2026-09-29 00:11:00", "4625", "0x0", ""),
        ];
        let c = correlate(&mut rows);
        assert!(c.segments.is_empty());
        assert_eq!(rows[1].get("account_key"), None);
    }

    #[test]
    fn information_rows_without_identity_join_nothing() {
        let core = |time: &str, stage: &str, eid: &str| {
            ev(&[
                ("timestamp", time),
                ("event_id", eid),
                (
                    "provider",
                    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
                ),
                (
                    "channel",
                    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
                ),
                ("computer", "PC1"),
                (
                    "source_scope",
                    "ds::EVENTLOG/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.sqlite::Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational",
                ),
                ("direction", "inbound"),
                ("access_scope", "unknown"),
                ("stage", stage),
            ])
        };
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "9", "10.0.0.5", "corp\\alice"),
            core("2026-09-29 00:11:00", "transport_warning", "135"),
            core("2026-09-29 00:12:00", "error_transition", "226"),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[1].get("segment_key"), None);
        assert_eq!(rows[2].get("segment_key"), None);
        assert_eq!(rows[1].get("remote_address"), None);
        assert_eq!(c.segments.len(), 1);
        assert_eq!(field(&c.segments[0], "event_count"), "1");
    }

    #[test]
    fn outbound_needs_a_real_activity_id_and_process_scope() {
        const ID: &str = "11111111-2222-3333-4444-555555555555";
        let base = |time: &str, pid: &str, activity: &str, address: &str| {
            ev(&[
                ("timestamp", time),
                ("event_id", "1024"),
                (
                    "provider",
                    "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                ),
                (
                    "channel",
                    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                ),
                ("computer", "PC1"),
                ("source_scope", SRC_CLIENT),
                ("direction", "outbound"),
                ("access_scope", "remote"),
                ("stage", "transport"),
                ("process_id", pid),
                ("correlation_activity_id", activity),
                ("remote_address", address),
            ])
        };
        let mut rows = vec![
            base("2026-09-29 00:10:00", "100", ID, "10.0.0.9"),
            base("2026-09-29 00:10:30", "200", ID, ""),
            base("2026-09-29 00:10:40", "100", ID, ""),
            base("2026-09-29 00:10:50", "100", "", ""),
        ];
        rows[2].insert("event_id".into(), "1025".into());
        let c = correlate(&mut rows);
        assert_eq!(
            rows[1].get("remote_address"),
            None,
            "another process is another connection scope"
        );
        assert_eq!(rows[2]["remote_address"], "10.0.0.9");
        assert_eq!(
            rows[3].get("remote_address"),
            None,
            "no activity id, no carry"
        );
        assert_eq!(rows[3].get("segment_key"), None);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(field(&c.segments[0], "scope_process_id"), "100");
        assert_eq!(field(&c.segments[0], "start_kind"), "client_connection_attempt");
    }

    #[test]
    fn placeholder_guid_is_not_a_connection_identifier() {
        let zero = |time: &str, address: &str| {
            ev(&[
                ("timestamp", time),
                ("event_id", "1024"),
                (
                    "provider",
                    "Microsoft-Windows-TerminalServices-ClientActiveXCore",
                ),
                (
                    "channel",
                    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
                ),
                ("computer", "PC1"),
                ("source_scope", SRC_CLIENT),
                ("direction", "outbound"),
                ("access_scope", "remote"),
                ("stage", "transport"),
                ("process_id", "100"),
                ("activity_id", "{00000000-0000-0000-0000-000000000000}"),
                ("remote_address", address),
            ])
        };
        let mut rows = vec![
            zero("2026-09-29 00:10:00", "10.0.0.9"),
            zero("2026-09-29 00:10:10", ""),
        ];
        let c = correlate(&mut rows);
        assert!(c.segments.is_empty(), "an all-zero GUID identifies nothing");
        assert_eq!(rows[1].get("remote_address"), None);
        assert_eq!(
            rows[0]["activity_id"], "{00000000-0000-0000-0000-000000000000}",
            "the original id is preserved untouched"
        );
    }

    #[test]
    fn system_start_evidence_breaks_id_reuse() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "25", "6", "10.0.0.5", "corp\\alice"),
            control("2026-09-29 00:15:00", "4608", "system_start", SRC_SEC),
            lsm("2026-09-29 00:20:00", "24", "6", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[2].get("remote_address"), None);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(field(&c.segments[0], "truncated_by"), "system_start");
        assert_eq!(field(&c.segments[0], "truncated_by_index"), "1");
        assert_eq!(field(&c.segments[0], "end_bound"), "unobserved");
        assert_eq!(
            field(&c.segments[1], "split_reason"),
            "after_control_boundary"
        );
    }

    #[test]
    fn log_clear_only_breaks_its_own_log() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "25", "7", "10.0.0.5", "corp\\alice"),
            control("2026-09-29 00:15:00", "1102", "log_cleared", SRC_SEC),
            lsm("2026-09-29 00:20:00", "24", "7", "", ""),
        ];
        let c = correlate(&mut rows);
        assert_eq!(rows[2]["remote_address"], "10.0.0.5");
        assert_eq!(c.segments.len(), 1);
        assert_eq!(c.segments[0].get("truncated_by"), None);

        let mut same_log = vec![
            lsm("2026-09-29 00:10:00", "25", "7", "10.0.0.5", "corp\\alice"),
            control("2026-09-29 00:15:00", "1102", "log_cleared", SRC_LSM),
            lsm("2026-09-29 00:20:00", "24", "7", "", ""),
        ];
        let c = correlate(&mut same_log);
        assert_eq!(same_log[2].get("remote_address"), None);
        assert_eq!(field(&c.segments[0], "truncated_by"), "log_cleared");
    }

    #[test]
    fn rows_are_never_reordered_or_removed() {
        let mut rows = vec![
            lsm("2026-09-29 00:30:00", "23", "8", "", ""),
            lsm("2026-09-29 00:10:00", "21", "8", "10.0.0.5", "corp\\alice"),
            ev(&[("event_id", "131"), ("provider", "x")]),
        ];
        let before: Vec<String> = rows
            .iter()
            .map(|r| field(r, "event_id").to_string())
            .collect();
        let c = correlate(&mut rows);
        let after: Vec<String> = rows
            .iter()
            .map(|r| field(r, "event_id").to_string())
            .collect();
        assert_eq!(before, after);
        assert_eq!(rows.len(), 3);
        // Evidence order, not row order, drives the carry.
        assert_eq!(rows[0]["remote_address"], "10.0.0.5");
        assert!(has_carry(&c, 1, 0, "remote_address"));
        assert_eq!(
            rows[2].get("segment_key"),
            None,
            "a row with no source and no id is never grouped"
        );
        assert_eq!(field(&c.segments[0], "start_event_index"), "1");
        assert_eq!(field(&c.segments[0], "end_event_index"), "0");
    }

    #[test]
    fn logoff_initiation_does_not_prove_termination() {
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4624", "0x11", "corp\\alice"),
            candidate_4647("2026-09-29 00:11:00", "0x11"),
        ];
        let initiated = correlate(&mut rows);
        assert_eq!(field(&initiated.segments[0], "end_bound"), "unobserved");
        rows.push(security("2026-09-29 00:12:00", "4634", "0x11", ""));
        let ended = correlate(&mut rows);
        assert_eq!(ended.segments.len(), 1);
        assert_eq!(field(&ended.segments[0], "end_event_id"), "4634");
        assert_eq!(rows[1]["segment_key"], rows[2]["segment_key"]);
    }

    #[test]
    fn untimed_logoff_candidate_cannot_create_a_visible_segment() {
        let mut rows = vec![candidate_4647("", "0x11")];
        let result = correlate(&mut rows);
        assert!(result.segments.is_empty());
        assert!(!rows[0].contains_key("segment_key"));
    }

    #[test]
    fn local_evidence_stops_remote_address_carry() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "1", "10.0.0.5", "corp\\alice"),
            lsm_local("2026-09-29 00:11:00", "22", "1", "corp\\alice"),
            lsm("2026-09-29 00:12:00", "23", "1", "", ""),
        ];
        correlate(&mut rows);
        assert!(!rows[1].contains_key("remote_address"));
        assert!(!rows[2].contains_key("remote_address"));
        assert_eq!(rows[2]["access_scope"], "local");
    }

    #[test]
    fn observed_record_bounds_follow_time_not_input_position() {
        let mut rows = vec![
            lsm("2026-09-29 00:30:00", "23", "8", "", ""),
            lsm("2026-09-29 00:10:00", "21", "8", "10.0.0.5", "corp\\alice"),
        ];
        let result = correlate(&mut rows);
        let segment = &result.segments[0];
        for (index, time) in [
            ("first_event_index", "first_observed_time"),
            ("last_event_index", "last_observed_time"),
        ] {
            let member = field(segment, index).parse::<usize>().unwrap();
            assert_eq!(rows[member]["timestamp"], segment[time]);
        }
    }

    fn client(time: &str, eid: &str, activity: &str, address: &str) -> Row {
        ev(&[
            ("timestamp", time),
            ("event_id", eid),
            ("direction", "outbound"),
            ("source_scope", SRC_CLIENT),
            ("provider", "ClientActiveXCore"),
            ("channel", "RDPClient"),
            ("computer", "PC1"),
            ("process_id", "100"),
            ("correlation_activity_id", activity),
            ("remote_address", address),
        ])
    }

    #[test]
    fn client_connection_boundaries_stop_address_carry() {
        let id = "11111111-2222-3333-4444-555555555555";
        let mut rows = vec![
            client("2026-09-29 00:10:00", "1024", id, "10.0.0.9"),
            client("2026-09-29 00:11:00", "1026", id, ""),
            client("2026-09-29 00:12:00", "1025", id, ""),
            client("2026-09-29 00:13:00", "1102", id, "10.0.0.8"),
            client("2026-09-29 00:14:00", "1024", id, ""),
        ];
        correlate(&mut rows);
        assert_eq!(rows[1]["remote_address"], "10.0.0.9");
        assert!(!rows[2].contains_key("remote_address"));
        assert!(!rows[4].contains_key("remote_address"));
    }

    #[test]
    fn identifier_encodings_do_not_split_the_same_instance() {
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4624", "0x00AB", "corp\\alice"),
            security("2026-09-29 00:11:00", "4634", "0xab", ""),
            client(
                "2026-09-29 00:10:00",
                "1024",
                "{AAAAAAAA-2222-3333-4444-555555555555}",
                "10.0.0.9",
            ),
            client(
                "2026-09-29 00:11:00",
                "1025",
                "aaaaaaaa-2222-3333-4444-555555555555",
                "",
            ),
        ];
        correlate(&mut rows);
        assert_eq!(rows[0]["segment_key"], rows[1]["segment_key"]);
        assert_eq!(rows[2]["segment_key"], rows[3]["segment_key"]);
        assert_eq!(rows[3]["remote_address"], "10.0.0.9");
        assert_eq!(rows[0]["logon_id"], "0x00AB");
    }

    #[test]
    fn restart_after_the_last_member_keeps_boundary_evidence() {
        let mut rows = vec![
            lsm("2026-09-29 00:10:00", "21", "1", "10.0.0.5", "corp\\alice"),
            control("2026-09-29 00:20:00", "4608", "system_start", SRC_SEC),
        ];
        let result = correlate(&mut rows);
        assert_eq!(field(&result.segments[0], "truncated_by"), "system_start");
        assert_eq!(field(&result.segments[0], "end_bound"), "unobserved");
    }

    #[test]
    fn null_sid_does_not_replace_known_identity_and_carried_sid_controls_the_key() {
        let sid = "S-1-5-21-1-2-3-1001";
        let mut rows = vec![
            security("2026-09-29 00:10:00", "4624", "0x11", "corp\\alice"),
            security("2026-09-29 00:11:00", "4778", "0x11", "corp\\alice"),
            security("2026-09-29 00:12:00", "4779", "0x11", "corp\\alice"),
            security("2026-09-29 00:13:00", "4634", "0x11", "corp\\alice"),
        ];
        rows[0].insert("target_user_sid".into(), sid.into());
        rows[0].insert("account_key".into(), sid.into());
        rows[2].insert("target_user_sid".into(), "S-1-0-0".into());
        let result = correlate(&mut rows);
        assert_eq!(result.segments.len(), 1);
        assert_eq!(rows[1]["account_key"], sid);
        assert_eq!(rows[2]["target_user_sid"], "S-1-0-0");
        assert_eq!(rows[3]["target_user_sid"], sid);
        assert!(has_carry(&result, 0, 1, "account_key"));
    }
}
