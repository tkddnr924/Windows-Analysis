//! Direct SMB/network authentication evidence and separately counted context.
use super::schema::{ChildSpec, DbSpec};
use super::{Cell, Ctx, DerivedDb, SourceRef};
use crate::overview::EventLogOverviewCache;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OpenFlags};

fn value(raw: &str) -> Cell { if raw.is_empty() { Cell::Null } else { Cell::Text(raw.to_string()) } }

fn record(ctx: &Ctx, event: &crate::smb::SmbEvent<'_>) -> super::Record {
    let mut record = ctx.record(&SPEC);
    record.timestamp(event.timestamp, event.timestamp_kind);
    record.set("timestamp_state",value(if event.timestamp.is_empty() { "unrecorded" } else { "recorded" }));
    record.set("event_type",value(event.event_kind));
    record.set("description",value(event.description));
    record.set("account",value(&event.account_display));
    record.set("account_sid",if super::is_sid(&event.account_sid) && !event.account_sid_is_placeholder {
        value(&event.account_sid)
    } else { Cell::Null });
    record.set("account_sid_is_placeholder",Cell::Int(i64::from(event.account_sid_is_placeholder)));
    record.set("remote_port_raw",value(&event.remote_port_raw));
    record.set("remote_port",super::int_opt(event.remote_port));
    record.set("event_id",super::int(event.event_id));
    record.set("logon_type",super::int(&event.logon_type));
    record.set("event_data_raw",event.source.get("EventData").map(|_|Cell::Text(event.event_data_raw.to_string())).unwrap_or(Cell::Null));
    record.set("search_text",Cell::Text(event.search_text()));
    for (column, raw) in [
        ("provider", event.provider.as_ref()),
        ("channel", event.channel.as_ref()),
        ("computer", event.computer.as_ref()),
        ("event_record_id", event.event_record_id.as_ref()),
        ("level_name", event.level_name.as_ref()),
        ("keywords_raw", event.keywords_raw.as_ref()),
        ("process_id", event.process_id.as_ref()),
        ("thread_id", event.thread_id.as_ref()),
        ("system_user_sid", event.system_user_sid.as_ref()),
        ("activity_id", event.activity_id.as_ref()),
        ("related_activity_id", event.related_activity_id.as_ref()),
        ("source_scope", event.source_scope.as_ref()),
        ("facts_status", event.facts_status.as_ref()),
        ("facts_error", event.facts_error.as_ref()),
        ("account_raw", event.account_raw.as_ref()),
        ("account_domain", event.account_domain.as_ref()),
        ("account_name", event.account_name.as_ref()),
        ("account_upn", event.account_upn.as_ref()),
        ("account_key", event.account_key.as_ref()),
        ("subject_user_sid", event.subject_user_sid.as_ref()),
        ("subject_user_name", event.subject_user_name.as_ref()),
        ("subject_domain", event.subject_domain.as_ref()),
        ("subject_logon_id", event.subject_logon_id.as_ref()),
        ("target_user_sid", event.target_user_sid.as_ref()),
        ("target_user_name", event.target_user_name.as_ref()),
        ("target_domain", event.target_domain.as_ref()),
        ("target_logon_id", event.target_logon_id.as_ref()),
        ("logon_id", event.logon_id.as_ref()),
        ("logon_process", event.logon_process.as_ref()),
        ("authentication_package", event.authentication_package.as_ref()),
        ("lm_package_name", event.lm_package_name.as_ref()),
        ("key_length", event.key_length.as_ref()),
        ("workstation_name", event.workstation_name.as_ref()),
        ("transmitted_services", event.transmitted_services.as_ref()),
        ("remote_address", event.remote_address.as_ref()),
        ("remote_address_raw", event.remote_address_raw.as_ref()),
        ("peer_name_raw", event.peer_name_raw.as_ref()),
        ("address_state", event.address_state.as_ref()),
        ("share_name", event.share_name.as_ref()),
        ("share_path", event.share_path.as_ref()),
        ("target_file", event.target_file.as_ref()),
        ("object_type", event.object_type.as_ref()),
        ("access_mask", event.access_mask.as_ref()),
        ("access_list", event.access_list.as_ref()),
        ("access_reason", event.access_reason.as_ref()),
        ("access_rights", event.access_rights.as_ref()),
        ("access_rights_unmapped", event.access_rights_unmapped.as_ref()),
        ("status_raw", event.status_raw.as_ref()),
        ("sub_status_raw", event.sub_status_raw.as_ref()),
        ("failure_reason_raw", event.failure_reason_raw.as_ref()),
        ("status_format", event.status_format.as_ref()),
        ("sub_status_format", event.sub_status_format.as_ref()),
        ("status_meaning", event.status_meaning.as_ref()),
        ("sub_status_meaning", event.sub_status_meaning.as_ref()),
        ("reason_raw", event.reason_raw.as_ref()),
        ("server_name_raw", event.server_name_raw.as_ref()),
        ("object_name_raw", event.object_name_raw.as_ref()),
        ("session_id", event.session_id.as_ref()),
        ("spn_name", event.spn_name.as_ref()),
        ("server_names_raw", event.server_names_raw.as_ref()),
        ("configured_names_raw", event.configured_names_raw.as_ref()),
        ("ip_addresses_raw", event.ip_addresses_raw.as_ref()),
        ("privilege_list", event.privilege_list.as_ref()),
        ("logon_instance", event.logon_instance.as_ref()),
        ("record_key", event.record_key.as_ref()),
        ("source_file", event.source_file.as_ref()),
        ("direction", event.direction.as_ref()),
        ("direction_basis", event.direction_basis.as_ref()),
        ("peer_role", event.peer_role.as_ref()),
        ("protocol", event.protocol.as_ref()),
        ("protocol_basis", event.protocol_basis.as_ref()),
        ("result", event.result.as_ref()),
        ("result_basis", event.result_basis.as_ref()),
        ("audit_outcome", event.audit_outcome.as_ref()),
        ("access_semantics", event.access_semantics.as_ref()),
        ("boundary_kind", event.boundary_kind.as_ref()),
    ] { record.set(column,value(raw)); }
    record
}

fn source(ctx: &Ctx, event: &crate::smb::SmbEvent<'_>) -> Result<SourceRef> {
    ctx.facts.source_from_record_key(event.record_key,Some("EventData"),Some(event.source_file),Some(event.event_kind))?
        .ok_or_else(||anyhow!("SMB event missing facts provenance: {}",event.record_key))
}

pub(super) fn build(ctx: &Ctx, cache: &EventLogOverviewCache) -> Result<usize> {
    let classified = crate::smb::classify(cache);
    let mut db = DerivedDb::create(&ctx.overview_dir(),SPEC.name)?;
    let mut ids = Vec::with_capacity(classified.events.len());
    let sources = classified.events.iter().map(|event|source(ctx,event)).collect::<Result<Vec<_>>>()?;
    let mut linked = classified.relations.iter().peekable();
    for (index,event) in classified.events.iter().enumerate() {
        let mut record = record(ctx,event);
        ids.push(record.record_id.clone());
        if event.role == crate::smb::SmbRole::Direct {
            record.source(Some(sources[index].clone()));
            while linked.peek().is_some_and(|relation| relation.main_index == index) {
                let relation = linked.next().unwrap();
                let mut donor = sources.get(relation.context_index).ok_or_else(||anyhow!("invalid SMB context index"))?.clone();
                donor.label = Some(format!("{}: {}",relation.kind,relation.basis));
                record.source(Some(donor));
            }
            db.write(record)?;
        } else {
            let source = &sources[index];
            let mut cells = record.values;
            cells.extend([value(&source.dataset),value(&source.db),value(&source.table),Cell::Int(source.rowid)]);
            db.insert_child("SmbContext",&cells)?;
        }
    }
    let mut ordinals = vec![0i64; ids.len()];
    for relation in &classified.relations {
        let parent = ids.get(relation.main_index).ok_or_else(||anyhow!("invalid SMB relation parent"))?;
        let context = ids.get(relation.context_index).ok_or_else(||anyhow!("invalid SMB relation context"))?;
        db.insert_child("SmbRelations",&[value(parent),Cell::Int(ordinals[relation.main_index]),value(context),
            value(relation.kind),value(relation.basis),value(&relation.logon_instance),value(&relation.logon_id)])?;
        ordinals[relation.main_index] += 1;
    }
    super::smb_observations::populate(ctx,&db,cache)?;
    super::smb_environment::populate(ctx,&db,cache)?;
    metadata_references(ctx,&db)?;
    db.finish()
}

fn metadata_references(ctx: &Ctx, db: &DerivedDb) -> Result<()> {
    let path = ctx.overview_dir().join("Metadata.sqlite");
    if !path.exists() { return Ok(()); }
    let metadata = Connection::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut query = metadata.prepare("SELECT metadata_id,kind FROM metadata WHERE host_id=?1 AND dataset_id=?2 AND kind IN ('host','network') ORDER BY metadata_id")?;
    let mut rows = query.query(params![ctx.host_id,ctx.dataset_id])?;
    while let Some(row) = rows.next()? {
        db.conn().execute("INSERT INTO SmbMetadataReferences(reference_id,host_id,dataset_id,metadata_id,reference_kind) VALUES(?1,?2,?3,?4,?5)",
            params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,row.get::<_,String>(0)?,row.get::<_,String>(1)?])?;
    }
    Ok(())
}


/// One column list builds both record tables and their column specs, so
/// SmbContext rows (MAIN values + source columns) keep MAIN's order.
macro_rules! smb_schema {
    ($($column:ident $kind:literal,)*) => {
        const MAIN: &[&str] = &[$(stringify!($column)),*];
        const SMBCONTEXT: &[&str] = &[$(stringify!($column),)* "source_dataset_id", "source_db", "source_table", "source_rowid"];
        const DDL: &str = concat!(
            "PRAGMA foreign_keys=ON;\nCREATE TABLE SmbHistory (\n",
            $("  ", stringify!($column), " ", $kind, ",\n",)*
            r#"  PRIMARY KEY(record_id),
  CHECK(overview_name='SmbHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(direction IN ('inbound','outbound','unknown')),
  CHECK(protocol IN ('smb','unknown'))
);
CREATE INDEX idx_SmbHistory_time ON SmbHistory(timestamp IS NULL,timestamp,record_id);
CREATE INDEX idx_SmbHistory_filters ON SmbHistory(account_sid,direction,result);
CREATE INDEX idx_SmbHistory_address ON SmbHistory(remote_address,timestamp,record_id);
CREATE TABLE SmbContext (
"#,
            $("  ", stringify!($column), " ", $kind, ",\n",)*
            r#"  source_dataset_id TEXT,
  source_db TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  PRIMARY KEY(record_id)
);
CREATE TABLE SmbRelations (
  record_id TEXT NOT NULL,
  ordinal INTEGER,
  context_id TEXT,
  relation_kind TEXT,
  basis TEXT,
  logon_instance TEXT,
  logon_id TEXT,
  PRIMARY KEY(record_id,ordinal),
  FOREIGN KEY(record_id) REFERENCES SmbHistory(record_id) ON DELETE CASCADE,
  FOREIGN KEY(context_id) REFERENCES SmbContext(record_id)
);
CREATE TABLE SmbLogObservations (
  observation_id TEXT,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  log_name TEXT,
  source_file TEXT,
  facts_db TEXT,
  facts_table TEXT,
  facts_generation TEXT,
  collection_state TEXT,
  input_row_count INTEGER,
  event_count INTEGER,
  corrupted_count INTEGER,
  untimed_count INTEGER,
  first_observed_time TEXT,
  last_observed_time TEXT,
  audit_setting_state TEXT,
  error TEXT,
  source_dataset_id TEXT,
  source_db TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  PRIMARY KEY(observation_id)
);
CREATE TABLE SmbEnvironment (
  environment_id TEXT,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  evidence_kind TEXT,
  timestamp TEXT,
  timestamp_kind TEXT,
  event_id INTEGER,
  provider TEXT,
  service_name TEXT,
  state TEXT,
  start_type_before TEXT,
  start_type_after TEXT,
  event_data TEXT,
  key_path TEXT,
  value_name TEXT,
  value_type TEXT,
  value_data TEXT,
  value_data_hex TEXT,
  entry_kind TEXT,
  control_set TEXT,
  control_set_status TEXT,
  source_dataset_id TEXT,
  source_db TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  source_file TEXT,
  PRIMARY KEY(environment_id)
);
CREATE TABLE SmbMetadataReferences (
  reference_id TEXT,
  host_id TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  metadata_id TEXT,
  reference_kind TEXT,
  PRIMARY KEY(reference_id)
);
CREATE TABLE source_records (
  record_id TEXT NOT NULL,
  ordinal INTEGER,
  source_dataset_id TEXT,
  source_artifact TEXT,
  source_db TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  source_field TEXT,
  source_record_key TEXT,
  source_file TEXT,
  source_label TEXT,
  PRIMARY KEY(record_id,ordinal),
  FOREIGN KEY(record_id) REFERENCES SmbHistory(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db,source_table,source_rowid,source_field);
CREATE TABLE _wina_derived_version(name TEXT NOT NULL PRIMARY KEY,version INTEGER NOT NULL);
INSERT INTO _wina_derived_version VALUES('overview_contract',1),('smb_history',5);
"#,
        );
    };
}

smb_schema! {
    record_id "TEXT NOT NULL",
    host_id "TEXT NOT NULL",
    dataset_id "TEXT NOT NULL",
    timestamp "TEXT",
    overview_name "TEXT NOT NULL",
    account "TEXT",
    account_sid "TEXT",
    timestamp_kind "TEXT",
    event_type "TEXT",
    description "TEXT",
    direction "TEXT",
    direction_basis "TEXT",
    peer_role "TEXT",
    protocol "TEXT",
    protocol_basis "TEXT",
    result "TEXT",
    result_basis "TEXT",
    audit_outcome "TEXT",
    access_semantics "TEXT",
    boundary_kind "TEXT",
    timestamp_state "TEXT",
    event_id "INTEGER",
    provider "TEXT",
    channel "TEXT",
    computer "TEXT",
    event_record_id "TEXT",
    level_name "TEXT",
    keywords_raw "TEXT",
    process_id "TEXT",
    thread_id "TEXT",
    system_user_sid "TEXT",
    activity_id "TEXT",
    related_activity_id "TEXT",
    source_scope "TEXT",
    facts_status "TEXT",
    facts_error "TEXT",
    account_raw "TEXT",
    account_domain "TEXT",
    account_name "TEXT",
    account_upn "TEXT",
    account_key "TEXT",
    account_sid_is_placeholder "INTEGER",
    subject_user_sid "TEXT",
    subject_user_name "TEXT",
    subject_domain "TEXT",
    subject_logon_id "TEXT",
    target_user_sid "TEXT",
    target_user_name "TEXT",
    target_domain "TEXT",
    target_logon_id "TEXT",
    logon_id "TEXT",
    logon_type "INTEGER",
    logon_process "TEXT",
    authentication_package "TEXT",
    lm_package_name "TEXT",
    key_length "TEXT",
    workstation_name "TEXT",
    transmitted_services "TEXT",
    remote_address "TEXT",
    remote_address_raw "TEXT",
    remote_port "INTEGER",
    remote_port_raw "TEXT",
    peer_name_raw "TEXT",
    address_state "TEXT",
    share_name "TEXT",
    share_path "TEXT",
    target_file "TEXT",
    object_type "TEXT",
    access_mask "TEXT",
    access_list "TEXT",
    access_reason "TEXT",
    access_rights "TEXT",
    access_rights_unmapped "TEXT",
    status_raw "TEXT",
    sub_status_raw "TEXT",
    failure_reason_raw "TEXT",
    status_format "TEXT",
    sub_status_format "TEXT",
    status_meaning "TEXT",
    sub_status_meaning "TEXT",
    reason_raw "TEXT",
    server_name_raw "TEXT",
    object_name_raw "TEXT",
    session_id "TEXT",
    spn_name "TEXT",
    server_names_raw "TEXT",
    configured_names_raw "TEXT",
    ip_addresses_raw "TEXT",
    privilege_list "TEXT",
    logon_instance "TEXT",
    event_data_raw "TEXT",
    record_key "TEXT",
    source_file "TEXT",
    search_text "TEXT",
}

const SMBRELATIONS: &[&str] = &[
    "record_id",
    "ordinal",
    "context_id",
    "relation_kind",
    "basis",
    "logon_instance",
    "logon_id",
];

const SMBLOGOBSERVATIONS: &[&str] = &[
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

const SMBENVIRONMENT: &[&str] = &[
    "environment_id",
    "host_id",
    "dataset_id",
    "evidence_kind",
    "timestamp",
    "timestamp_kind",
    "event_id",
    "provider",
    "service_name",
    "state",
    "start_type_before",
    "start_type_after",
    "event_data",
    "key_path",
    "value_name",
    "value_type",
    "value_data",
    "value_data_hex",
    "entry_kind",
    "control_set",
    "control_set_status",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const SMBMETADATAREFERENCES: &[&str] = &[
    "reference_id",
    "host_id",
    "dataset_id",
    "metadata_id",
    "reference_kind",
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
    name: "SmbHistory", table: "SmbHistory", columns: MAIN,
    children: &[
        ChildSpec { table: "SmbContext", columns: SMBCONTEXT },
        ChildSpec { table: "SmbRelations", columns: SMBRELATIONS },
        ChildSpec { table: "SmbLogObservations", columns: SMBLOGOBSERVATIONS },
        ChildSpec { table: "SmbEnvironment", columns: SMBENVIRONMENT },
        ChildSpec { table: "SmbMetadataReferences", columns: SMBMETADATAREFERENCES },
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
    ], ddl: DDL,
};


#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{FactsIndex, MetaLookup, stamp_facts_generation};
    use crate::sqlite::Row;

    #[test]
    fn storage_keeps_unknown_protocol_port_zero_upn_and_separate_context() {
        let root=std::env::temp_dir().join(format!("wina-smb-storage-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let facts=root.join("EVENTLOG/Security.sqlite");
        let conn=Connection::open(&facts).unwrap();
        conn.execute_batch("CREATE TABLE Security(EventData TEXT); INSERT INTO Security VALUES('{}'),('{}'),('{}');").unwrap();
        drop(conn);
        stamp_facts_generation(&facts,"facts-old").unwrap();
        let make=|id:&str,n:usize,time:&str,payload:&str|Row::from([
            ("Provider".into(),"Microsoft-Windows-Security-Auditing".into()),("Channel".into(),"Security".into()),
            ("Computer".into(),"HOST".into()),("EventID".into(),id.into()),("EventRecordID".into(),n.to_string()),
            ("timestamp".into(),time.into()),("EventData".into(),payload.into()),
            ("_record_key".into(),format!("Security::{n}")),("_source_file".into(),"Security.evtx".into()),
        ]);
        let events=EventLogOverviewCache::from_rows_for_tests(vec![
            make("4624",1,"2026-01-01 00:00:00.000",r#"{"LogonType":3,"TargetUserName":"a@example.test","TargetDomainName":"DOMAIN","TargetLogonId":"0x10","IpAddress":"10.0.0.1","IpPort":"0"}"#),
            make("4634",2,"2026-01-01 00:01:00.000",r#"{"LogonType":3,"TargetLogonId":"0x10"}"#),
            make("4625",3,"",r#"{"LogonType":3,"TargetUserSid":"S-1-0-0","Status":"0xc000006d"}"#),
        ]);
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx=Ctx{out_dir:&root,target:&root,host_id:"host",dataset_id:"new",facts:FactsIndex::load(&root).unwrap(),meta:MetaLookup::load(&root).unwrap()};
        assert_eq!(build(&ctx,&events).unwrap(),2);
        let db=Connection::open(ctx.overview_dir().join("SmbHistory.sqlite")).unwrap();
        let first:(String,i64,String,String)=db.query_row("SELECT protocol,remote_port,account_raw,account_key FROM SmbHistory WHERE event_id=4624",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(first.0,"unknown"); assert_eq!(first.1,0); assert_eq!(first.2,"a@example.test"); assert!(first.3.contains("example.test"));
        assert_eq!(db.query_row("SELECT COUNT(*) FROM SmbContext WHERE event_id=4634",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM SmbRelations",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        let unknown:(Option<String>,Option<String>,Option<String>,String)=db.query_row("SELECT timestamp,account_sid,remote_address,address_state FROM SmbHistory WHERE event_id=4625",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(unknown,(None,None,None,"unrecorded".into()));
        assert_eq!(db.query_row("SELECT COUNT(*) FROM source_records WHERE source_dataset_id<>'facts-old'",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        drop(db); std::fs::remove_dir_all(root).unwrap();
    }
}
