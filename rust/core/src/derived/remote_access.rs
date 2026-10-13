//! Evidence-scoped remote access events, relationships and observed bounds.
use super::schema::{ChildSpec, DbSpec};
use super::{int, text_raw, Cell, Ctx, DerivedDb, Record, SourceRef};
use crate::overview::EventLogOverviewCache;
use crate::sqlite::Row;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE RemoteAccessBoundaries (
  boundary_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  timestamp TEXT,
  control_kind TEXT NOT NULL,
  event_id INTEGER,
  provider TEXT,
  channel TEXT,
  computer TEXT,
  event_record_id TEXT,
  event_data TEXT,
  source_dataset_id TEXT NOT NULL,
  source_db TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_rowid INTEGER NOT NULL,
  source_file TEXT,
  PRIMARY KEY(boundary_id)
);
CREATE TABLE RemoteAccessObservations (
  observation_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  source_dataset_id TEXT NOT NULL,
  source_db TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_file TEXT,
  provider TEXT,
  channel TEXT,
  computer TEXT,
  row_count INTEGER,
  first_observed_time TEXT,
  last_observed_time TEXT,
  untimed_count INTEGER,
  selected_count INTEGER,
  remote_count INTEGER,
  local_count INTEGER,
  unknown_count INTEGER,
  PRIMARY KEY(observation_id)
);
CREATE TABLE RemoteAccessSegments (
  segment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  source_scope TEXT,
  provider TEXT,
  channel TEXT,
  computer TEXT,
  id_space TEXT,
  id_value TEXT,
  scope_process_id TEXT,
  instance_index TEXT,
  time_unknown INTEGER,
  split_reason TEXT,
  direction TEXT,
  access_scope TEXT,
  event_count INTEGER,
  first_observed_time TEXT,
  last_observed_time TEXT,
  start_bound TEXT,
  start_time TEXT,
  start_event_id INTEGER,
  end_bound TEXT,
  end_time TEXT,
  end_event_id INTEGER,
  end_kind TEXT,
  reconnect_count INTEGER,
  disconnect_count INTEGER,
  first_record_id TEXT,
  last_record_id TEXT,
  start_record_id TEXT,
  end_record_id TEXT,
  truncated_by TEXT,
  boundary_id TEXT,
  start_kind TEXT,
  identity_varied TEXT,
  session_id TEXT,
  logon_id TEXT,
  session_name TEXT,
  target_user_sid TEXT,
  logon_type INTEGER,
  account TEXT,
  account_raw TEXT,
  account_name TEXT,
  account_domain TEXT,
  account_upn TEXT,
  account_key TEXT,
  remote_address TEXT,
  remote_port INTEGER,
  remote_computer TEXT,
  PRIMARY KEY(segment_id),
  FOREIGN KEY(first_record_id) REFERENCES RemoteDesktopHistory(record_id),
  FOREIGN KEY(last_record_id) REFERENCES RemoteDesktopHistory(record_id),
  FOREIGN KEY(start_record_id) REFERENCES RemoteDesktopHistory(record_id),
  FOREIGN KEY(end_record_id) REFERENCES RemoteDesktopHistory(record_id),
  FOREIGN KEY(boundary_id) REFERENCES RemoteAccessBoundaries(boundary_id)
);
CREATE TABLE RemoteDesktopHistory (
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
  direction TEXT NOT NULL,
  event_id INTEGER,
  provider TEXT,
  remote_address TEXT,
  remote_computer TEXT,
  remote_port INTEGER,
  logon_type INTEGER,
  session_id TEXT,
  logon_id TEXT,
  result TEXT,
  start_time TEXT,
  end_time TEXT,
  access_scope TEXT NOT NULL,
  stage TEXT,
  account_raw TEXT,
  account_name TEXT,
  account_domain TEXT,
  account_upn TEXT,
  account_key TEXT,
  system_user_sid TEXT,
  target_user_sid TEXT,
  channel TEXT,
  computer TEXT,
  event_record_id TEXT,
  process_id TEXT,
  thread_id TEXT,
  activity_id TEXT,
  related_activity_id TEXT,
  remote_address_raw TEXT,
  status TEXT,
  sub_status TEXT,
  failure_reason TEXT,
  reason TEXT,
  authentication_package TEXT,
  logon_process TEXT,
  source_scope TEXT,
  segment_id TEXT,
  observation_id TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name='RemoteDesktopHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(direction IN ('inbound','outbound','unknown')),
  CHECK(access_scope IN ('remote','local','unknown')),
  FOREIGN KEY(segment_id) REFERENCES RemoteAccessSegments(segment_id),
  FOREIGN KEY(observation_id) REFERENCES RemoteAccessObservations(observation_id)
);
CREATE TABLE RemoteAccessDetails (
  record_id TEXT NOT NULL,
  event_data TEXT,
  source_file TEXT,
  record_key TEXT,
  facts_status TEXT,
  facts_error TEXT,
  subject_user_sid TEXT,
  subject_user_name TEXT,
  subject_domain TEXT,
  subject_logon_id TEXT,
  workstation_name TEXT,
  session_name TEXT,
  source_session TEXT,
  conn_type TEXT,
  tunnel_id TEXT,
  transport_type TEXT,
  state_transition TEXT,
  previous_state INTEGER,
  new_state INTEGER,
  transition_event INTEGER,
  previous_state_name TEXT,
  new_state_name TEXT,
  transition_event_name TEXT,
  error_code TEXT,
  PRIMARY KEY(record_id),
  FOREIGN KEY(record_id) REFERENCES RemoteDesktopHistory(record_id) ON DELETE CASCADE
);
CREATE TABLE RemoteAccessRelations (
  record_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  related_record_id TEXT NOT NULL,
  field TEXT,
  relation_kind TEXT NOT NULL,
  value TEXT,
  segment_id TEXT,
  PRIMARY KEY(record_id,ordinal),
  CHECK(ordinal>=0),
  FOREIGN KEY(record_id) REFERENCES RemoteDesktopHistory(record_id) ON DELETE CASCADE,
  FOREIGN KEY(related_record_id) REFERENCES RemoteDesktopHistory(record_id),
  FOREIGN KEY(segment_id) REFERENCES RemoteAccessSegments(segment_id)
);
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
  PRIMARY KEY(record_id,ordinal),
  CHECK(ordinal>=0),
  FOREIGN KEY(record_id) REFERENCES RemoteDesktopHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_RemoteDesktopHistory_time ON RemoteDesktopHistory(timestamp,record_id);
CREATE INDEX idx_RemoteDesktopHistory_account ON RemoteDesktopHistory(account_key,timestamp);
CREATE INDEX idx_RemoteDesktopHistory_filter ON RemoteDesktopHistory(access_scope,direction,result,logon_type);
CREATE INDEX idx_RemoteDesktopHistory_segment ON RemoteDesktopHistory(segment_id,timestamp,record_id);
CREATE INDEX idx_source_lookup ON source_records(source_db,source_table,source_rowid,source_field);
CREATE TABLE _wina_derived_version(name TEXT NOT NULL PRIMARY KEY,version INTEGER NOT NULL);
INSERT INTO _wina_derived_version VALUES('overview_contract',1),('remote_desktop_history',4);
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
    "direction",
    "event_id",
    "provider",
    "remote_address",
    "remote_computer",
    "remote_port",
    "logon_type",
    "session_id",
    "logon_id",
    "result",
    "start_time",
    "end_time",
    "access_scope",
    "stage",
    "account_raw",
    "account_name",
    "account_domain",
    "account_upn",
    "account_key",
    "system_user_sid",
    "target_user_sid",
    "channel",
    "computer",
    "event_record_id",
    "process_id",
    "thread_id",
    "activity_id",
    "related_activity_id",
    "remote_address_raw",
    "status",
    "sub_status",
    "failure_reason",
    "reason",
    "authentication_package",
    "logon_process",
    "source_scope",
    "segment_id",
    "observation_id",
];

const DETAILS: &[&str] = &[
    "record_id",
    "event_data",
    "source_file",
    "record_key",
    "facts_status",
    "facts_error",
    "subject_user_sid",
    "subject_user_name",
    "subject_domain",
    "subject_logon_id",
    "workstation_name",
    "session_name",
    "source_session",
    "conn_type",
    "tunnel_id",
    "transport_type",
    "state_transition",
    "previous_state",
    "new_state",
    "transition_event",
    "previous_state_name",
    "new_state_name",
    "transition_event_name",
    "error_code",
];

const RELATIONS: &[&str] = &[
    "record_id",
    "ordinal",
    "related_record_id",
    "field",
    "relation_kind",
    "value",
    "segment_id",
];

const SEGMENTS: &[&str] = &[
    "segment_id",
    "host_id",
    "dataset_id",
    "source_scope",
    "provider",
    "channel",
    "computer",
    "id_space",
    "id_value",
    "scope_process_id",
    "instance_index",
    "time_unknown",
    "split_reason",
    "direction",
    "access_scope",
    "event_count",
    "first_observed_time",
    "last_observed_time",
    "start_bound",
    "start_time",
    "start_event_id",
    "end_bound",
    "end_time",
    "end_event_id",
    "end_kind",
    "reconnect_count",
    "disconnect_count",
    "first_record_id",
    "last_record_id",
    "start_record_id",
    "end_record_id",
    "truncated_by",
    "boundary_id",
    "start_kind",
    "identity_varied",
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

const OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_file",
    "provider",
    "channel",
    "computer",
    "row_count",
    "first_observed_time",
    "last_observed_time",
    "untimed_count",
    "selected_count",
    "remote_count",
    "local_count",
    "unknown_count",
];

const BOUNDARIES: &[&str] = &[
    "boundary_id",
    "host_id",
    "dataset_id",
    "timestamp",
    "control_kind",
    "event_id",
    "provider",
    "channel",
    "computer",
    "event_record_id",
    "event_data",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const SOURCES: &[&str] = &[
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

const CHILDREN: &[ChildSpec] = &[
    ChildSpec {
        table: "RemoteAccessDetails",
        columns: DETAILS,
    },
    ChildSpec {
        table: "RemoteAccessRelations",
        columns: RELATIONS,
    },
    ChildSpec {
        table: "RemoteAccessSegments",
        columns: SEGMENTS,
    },
    ChildSpec {
        table: "RemoteAccessObservations",
        columns: OBSERVATIONS,
    },
    ChildSpec {
        table: "RemoteAccessBoundaries",
        columns: BOUNDARIES,
    },
    ChildSpec {
        table: "source_records",
        columns: SOURCES,
    },
];
pub(super) const SPEC: DbSpec = DbSpec {
    name: "RemoteDesktopHistory",
    table: "RemoteDesktopHistory",
    columns: MAIN,
    children: CHILDREN,
    ddl: DDL,
};

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn cell(row: &Row, key: &str) -> Cell {
    match key {
        "event_id" | "remote_port" | "logon_type" | "time_unknown" | "event_count"
        | "start_event_id" | "end_event_id" | "reconnect_count" | "disconnect_count"
        | "row_count" | "untimed_count" | "selected_count" | "remote_count" | "previous_state"
        | "new_state" | "transition_event" | "local_count" | "unknown_count" | "source_rowid" => {
            int(g(row, key))
        }
        _ => text_raw(g(row, key)),
    }
}

fn values(row: &Row, columns: &[&str]) -> Vec<Cell> {
    columns.iter().map(|column| cell(row, column)).collect()
}

fn scoped_source(source: &SourceRef) -> String {
    format!("{}::{}::{}", source.dataset, source.db, source.table)
}

fn observation_key(row: &Row) -> (&str, &str, &str, &str) {
    let scope = g(row, "record_key")
        .rsplit_once("::")
        .map(|(scope, _)| scope)
        .unwrap_or("");
    (
        scope,
        g(row, "provider"),
        g(row, "channel"),
        g(row, "computer"),
    )
}

fn remote_provider(provider: &str) -> bool {
    matches!(
        provider,
        "Microsoft-Windows-Security-Auditing"
            | "Microsoft-Windows-TerminalServices-LocalSessionManager"
            | "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
            | "Microsoft-Windows-TerminalServices-ClientActiveXCore"
            | "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
    )
}

struct Observation {
    row: Row,
    total: i64,
    untimed: i64,
    selected: i64,
    remote: i64,
    local: i64,
    unknown: i64,
}

fn source_row(ctx: &Ctx, source: &SourceRef) -> Row {
    Row::from([
        ("host_id".into(), ctx.host_id.into()),
        ("dataset_id".into(), ctx.dataset_id.into()),
        ("source_dataset_id".into(), source.dataset.clone()),
        ("source_db".into(), source.db.clone()),
        ("source_table".into(), source.table.clone()),
        ("source_rowid".into(), source.rowid.to_string()),
        (
            "source_file".into(),
            source.file.clone().unwrap_or_default(),
        ),
    ])
}

pub(super) fn build(ctx: &Ctx, cache: &EventLogOverviewCache) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut events = crate::remote_access::classify(cache);
    let mut sources = Vec::with_capacity(events.len());
    for row in &mut events {
        let source = ctx.source_of(row, g(row, "description"))?.ok_or_else(|| {
            anyhow!(
                "remote access event has no facts source: {}",
                g(row, "record_key")
            )
        })?;
        row.insert("source_scope".into(), scoped_source(&source));
        sources.push(source);
    }
    let correlated = crate::remote_access::relations::correlate(&mut events);
    let mut observations: HashMap<(&str, &str, &str, &str), Observation> = HashMap::new();
    let mut source_cache: HashMap<&str, SourceRef> = HashMap::new();
    for row in cache.rows() {
        if !remote_provider(g(row, "Provider")) && g(row, "Channel") != "Security" {
            continue;
        }
        let key = g(row, "_record_key");
        let Some((scope, _)) = key.rsplit_once("::") else {
            continue;
        };
        if !source_cache.contains_key(scope) {
            let Some(source) = ctx.facts.source_from_record_key(
                key,
                None,
                row.get("_source_file").map(String::as_str),
                None,
            )?
            else {
                continue;
            };
            source_cache.insert(scope, source);
        }
        let source = &source_cache[scope];
        let key = (
            scope,
            g(row, "Provider"),
            g(row, "Channel"),
            g(row, "Computer"),
        );
        let observation = observations.entry(key).or_insert_with(|| {
            let mut fields = source_row(ctx, source);
            fields.insert("observation_id".into(), uuid::Uuid::new_v4().to_string());
            for (to, from) in [
                ("provider", "Provider"),
                ("channel", "Channel"),
                ("computer", "Computer"),
            ] {
                fields.insert(to.into(), g(row, from).into());
            }
            Observation {
                row: fields,
                total: 0,
                untimed: 0,
                selected: 0,
                remote: 0,
                local: 0,
                unknown: 0,
            }
        });
        observation.total += 1;
        let time = g(row, "timestamp");
        if time.is_empty() {
            observation.untimed += 1;
        } else {
            for (field, earlier) in [("first_observed_time", true), ("last_observed_time", false)] {
                let current = g(&observation.row, field);
                if current.is_empty() || (earlier && time < current) || (!earlier && time > current)
                {
                    observation.row.insert(field.into(), time.into());
                }
            }
        }
    }
    // One source row per (recipient, donor): every carried field of a donor
    // cites the same facts row, so the fields share one label.
    let mut carried: HashMap<usize, Vec<(usize, Vec<&str>)>> = HashMap::new();
    for relation in &correlated.relations {
        if matches!(
            g(relation, "relation_kind"),
            "carry_forward" | "local_scope_direction" | "remote_scope_direction"
        ) {
            let recipient = relation_index(relation, "to_index", events.len())?;
            let donor = relation_index(relation, "from_index", events.len())?;
            let donors = carried.entry(recipient).or_default();
            match donors.iter_mut().find(|(index, _)| *index == donor) {
                Some((_, fields)) => fields.push(g(relation, "field")),
                None => donors.push((donor, vec![g(relation, "field")])),
            }
        }
    }
    let mut records: Vec<Option<Record>> = events
        .iter()
        .map(|row| (g(row, "_exclude") != "1").then(|| ctx.record(&SPEC)))
        .collect();
    let record_ids: Vec<Option<String>> = records
        .iter()
        .map(|record| record.as_ref().map(|record| record.record_id.clone()))
        .collect();
    let mut boundary_ids = HashMap::new();
    for (index, row) in events.iter().enumerate() {
        if g(row, "control_kind").is_empty() {
            continue;
        }
        let mut fields = source_row(ctx, &sources[index]);
        let id = uuid::Uuid::new_v4().to_string();
        fields.insert("boundary_id".into(), id.clone());
        for key in [
            "timestamp",
            "control_kind",
            "event_id",
            "provider",
            "channel",
            "computer",
            "event_record_id",
            "event_data",
        ] {
            fields.insert(key.into(), g(row, key).into());
        }
        db.insert_child("RemoteAccessBoundaries", &values(&fields, BOUNDARIES))?;
        boundary_ids.insert(index, id);
    }
    let mut segment_ids = HashMap::new();
    for segment in &correlated.segments {
        let mut fields = segment.clone();
        let id = uuid::Uuid::new_v4().to_string();
        fields.insert("segment_id".into(), id.clone());
        fields.insert("host_id".into(), ctx.host_id.into());
        fields.insert("dataset_id".into(), ctx.dataset_id.into());
        if let Some(boundary) = g(segment, "truncated_by_index")
            .parse::<usize>()
            .ok()
            .and_then(|i| boundary_ids.get(&i))
        {
            fields.insert("boundary_id".into(), boundary.clone());
        }
        db.insert_child("RemoteAccessSegments", &values(&fields, SEGMENTS))?;
        segment_ids.insert(g(segment, "segment_key").to_string(), id);
    }
    for row in &events {
        if g(row, "_exclude") == "1" {
            continue;
        }
        let key = observation_key(row);
        if let Some(observation) = observations.get_mut(&key) {
            observation.selected += 1;
            match g(row, "access_scope") {
                "remote" => observation.remote += 1,
                "local" => observation.local += 1,
                _ => observation.unknown += 1,
            }
        }
    }
    for observation in observations.values_mut() {
        for (key, value) in [
            ("row_count", observation.total),
            ("untimed_count", observation.untimed),
            ("selected_count", observation.selected),
            ("remote_count", observation.remote),
            ("local_count", observation.local),
            ("unknown_count", observation.unknown),
        ] {
            observation.row.insert(key.into(), value.to_string());
        }
        db.insert_child(
            "RemoteAccessObservations",
            &values(&observation.row, OBSERVATIONS),
        )?;
    }
    for (index, row) in events.iter().enumerate() {
        let Some(mut record) = records[index].take() else {
            continue;
        };
        for &column in &MAIN[10..] {
            if !matches!(column, "segment_id" | "observation_id") {
                record.set(column, cell(row, column));
            }
        }
        record.timestamp(g(row, "timestamp"), "이벤트 기록 시각");
        record.set("event_type", text_raw(g(row, "stage")));
        record.set("description", text_raw(g(row, "description")));
        let sid = g(row, "target_user_sid");
        let known_sid = super::is_sid(sid) && sid != "S-1-0-0";
        record.set(
            "account_sid",
            if known_sid { text_raw(sid) } else { Cell::Null },
        );
        let account = if known_sid {
            ctx.meta.account_name(sid)
        } else {
            None
        };
        record.set(
            "account",
            text_raw(account.as_deref().unwrap_or(g(row, "account_name"))),
        );
        if let Some(id) = segment_ids.get(g(row, "segment_key")) {
            record.set("segment_id", text_raw(id));
        }
        let key = observation_key(row);
        if let Some(observation) = observations.get(&key) {
            record.set(
                "observation_id",
                text_raw(g(&observation.row, "observation_id")),
            );
        }
        record.source(Some(sources[index].clone()));
        for (donor, fields) in carried.get(&index).into_iter().flatten() {
            let mut source = sources[*donor].clone();
            source.field = Some("EventData".into());
            source.label = Some(format!("same-instance carry: {}", fields.join(", ")));
            record.source(Some(source));
        }
        let id = record.record_id.clone();
        db.write(record)?;
        let mut details = values(row, DETAILS);
        details[0] = Cell::Text(id);
        db.insert_child("RemoteAccessDetails", &details)?;
    }
    let lookup_record = |row: &Row, key: &str| -> Result<Cell> {
        if g(row, key).is_empty() {
            return Ok(Cell::Null);
        }
        let index = relation_index(row, key, record_ids.len())?;
        record_ids[index]
            .as_ref()
            .map(|id| text_raw(id))
            .ok_or_else(|| anyhow!("segment references excluded event: {index}"))
    };
    for segment in &correlated.segments {
        let id = &segment_ids[g(segment, "segment_key")];
        db.conn().execute(
            "UPDATE RemoteAccessSegments SET first_record_id=?1,last_record_id=?2,
            start_record_id=?3,end_record_id=?4 WHERE segment_id=?5",
            rusqlite::params![
                lookup_record(segment, "first_event_index")?,
                lookup_record(segment, "last_event_index")?,
                lookup_record(segment, "start_event_index")?,
                lookup_record(segment, "end_event_index")?,
                id
            ],
        )?;
    }
    let mut ordinals: HashMap<usize, i64> = HashMap::new();
    for relation in &correlated.relations {
        let from = relation_index(relation, "from_index", record_ids.len())?;
        let to = relation_index(relation, "to_index", record_ids.len())?;
        let (parent, related) = if matches!(
            g(relation, "relation_kind"),
            "carry_forward" | "local_scope_direction" | "remote_scope_direction"
        ) {
            (to, from)
        } else {
            (from, to)
        };
        let parent_id = record_ids[parent]
            .as_ref()
            .ok_or_else(|| anyhow!("excluded relation parent"))?;
        let related_id = record_ids[related]
            .as_ref()
            .ok_or_else(|| anyhow!("excluded relation target"))?;
        let ordinal = ordinals.entry(parent).or_default();
        db.insert_child(
            "RemoteAccessRelations",
            &[
                text_raw(parent_id),
                Cell::Int(*ordinal),
                text_raw(related_id),
                text_raw(g(relation, "field")),
                text_raw(g(relation, "relation_kind")),
                text_raw(g(relation, "value")),
                segment_ids
                    .get(g(relation, "segment_key"))
                    .map(|id| text_raw(id))
                    .unwrap_or(Cell::Null),
            ],
        )?;
        *ordinal += 1;
    }
    db.finish()
}

fn relation_index(row: &Row, key: &str, count: usize) -> Result<usize> {
    g(row, key)
        .parse::<usize>()
        .ok()
        .filter(|index| *index < count)
        .ok_or_else(|| anyhow!("invalid remote evidence index: {key}={}", g(row, key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use rusqlite::Connection;

    const LSM_STEM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational";
    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";

    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Fixture {
        fn new(rows: usize) -> Self {
            let root = std::env::temp_dir()
                .join(format!("wina-remote-access-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
            let path = root.join("EVENTLOG").join(format!("{LSM_STEM}.sqlite"));
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!("CREATE TABLE \"{LSM_STEM}\"(EventData TEXT);"))
                .unwrap();
            for _ in 0..rows {
                conn.execute(&format!("INSERT INTO \"{LSM_STEM}\"(EventData) VALUES('{{}}')"), [])
                    .unwrap();
            }
            drop(conn);
            stamp_facts_generation(&path, "facts-old").unwrap();
            Self { root }
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
            Connection::open(ctx.overview_dir().join("RemoteDesktopHistory.sqlite")).unwrap()
        }
    }

    fn lsm(n: usize, eid: &str, ts: &str, payload: &str) -> Row {
        Row::from([
            ("Provider".to_string(), LSM.to_string()),
            ("Channel".to_string(), format!("{LSM}/Operational")),
            ("Computer".to_string(), "WIN-TEST".to_string()),
            ("EventID".to_string(), eid.to_string()),
            ("EventRecordID".to_string(), n.to_string()),
            ("timestamp".to_string(), ts.to_string()),
            ("EventData".to_string(), payload.to_string()),
            ("_record_key".to_string(), format!("{LSM_STEM}::{n}")),
            ("_source_file".to_string(), format!("{LSM_STEM}.evtx")),
            ("_status".to_string(), "ok".to_string()),
        ])
    }

    #[test]
    fn carried_fields_cite_each_donor_facts_row_once() {
        let fixture = Fixture::new(2);
        let conn = fixture.run(vec![
            lsm(
                1,
                "21",
                "2026-01-01 00:00:00.000",
                r#"{"EventXML":{"User":"CORP\\alice","SessionID":3,"Address":"10.0.0.5"}}"#,
            ),
            lsm(2, "40", "2026-01-01 00:01:00.000", r#"{"EventXML":{"Session":3,"Reason":5}}"#),
        ]);
        let carried: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM RemoteAccessRelations r JOIN RemoteDesktopHistory h
                 ON h.record_id=r.record_id WHERE h.event_id=40",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(carried > 1, "fixture must carry several fields");
        let (rows, distinct, label): (i64, i64, String) = conn
            .query_row(
                "SELECT COUNT(*),
                        COUNT(DISTINCT source_db||'|'||source_table||'|'||source_rowid||'|'||ifnull(source_field,'')),
                        max(CASE WHEN source_rowid=1 THEN source_label END)
                 FROM source_records s JOIN RemoteDesktopHistory h ON h.record_id=s.record_id
                 WHERE h.event_id=40",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(rows, 2, "own row plus one donor row");
        assert_eq!(distinct, rows);
        assert!(label.contains("account_name") && label.contains("remote_address"));
    }
}
