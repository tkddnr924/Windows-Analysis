//! Service and registry snapshots are environment evidence, not connections.
use super::{service_history, Ctx, DerivedDb};
use std::collections::BTreeMap;
use crate::overview::EventLogOverviewCache;
use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, events: &EventLogOverviewCache) -> Result<()> {
    let directory = ctx.out_dir.join("REGISTRY");
    let mut paths = match std::fs::read_dir(directory) {
        Ok(entries) => entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            p.extension().is_some_and(|e| e == "sqlite")
                && (stem.eq_ignore_ascii_case("SYSTEM")
                    || stem.strip_prefix("SYSTEM_").is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
        }).collect::<Vec<_>>(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    paths.sort();
    for path in paths {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut selection = conn.prepare("SELECT DISTINCT value_data FROM Registry WHERE lower(key_path) LIKE '%\\select' AND lower(value_name)='current'")?;
        let current = selection.query_map([], |r| r.get::<_, Option<String>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let current = if current.len() == 1 {
            current[0].as_deref().and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0)
        } else { None };
        let active = current.map(|v| format!("controlset{v:03}"));
        // Every row of the LanmanServer key and its subkeys is kept; a sibling
        // service such as LanmanServerX is not selected.
        let mut query = conn.prepare(
            "SELECT rowid,last_write,key_path,value_name,value_type,value_data,value_data_hex,entry_kind,_source_file
             FROM Registry WHERE lower(key_path) LIKE '%\\services\\lanmanserver'
             OR lower(key_path) LIKE '%\\services\\lanmanserver\\%'
             OR (lower(key_path) LIKE '%\\select' AND lower(value_name)='current') ORDER BY rowid")?;
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            let key: String = row.get(2)?;
            let name: Option<String> = row.get(3)?;
            let lower = key.to_ascii_lowercase();
            let kind = if lower.ends_with("\\select") {
                "control_set_selection"
            } else if lower.ends_with("\\services\\lanmanserver") {
                "service_configuration"
            } else if lower.ends_with("\\services\\lanmanserver\\parameters") {
                "share_configuration"
            } else if lower.ends_with("\\services\\lanmanserver\\shares")
                || lower.contains("\\services\\lanmanserver\\shares\\") {
                "share_definition"
            } else { "service_subkey" };
            let control_set = lower.split('\\').find(|part| part.starts_with("controlset"));
            let control_status = match (control_set, active.as_deref()) {
                (Some(value), Some(selected)) if value == selected => "active",
                (Some(_), Some(_)) => "inactive",
                _ => "unknown",
            };
            let file: Option<String> = row.get(8)?;
            let source = ctx.facts.source_from_row(&path, "Registry", row.get(0)?, file.as_deref(), Some(kind))?
                .ok_or_else(|| anyhow::anyhow!("missing SMB environment facts: {}", path.display()))?;
            db.conn().execute(
                "INSERT INTO SmbEnvironment(environment_id,host_id,dataset_id,evidence_kind,timestamp,timestamp_kind,
                 key_path,value_name,value_type,value_data,value_data_hex,entry_kind,control_set,control_set_status,
                 source_dataset_id,source_db,source_table,source_rowid,source_file)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,kind,
                    row.get::<_,Option<String>>(1)?.filter(|s|!s.is_empty()),"키 기록 시각",
                    key,name,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,
                    row.get::<_,Option<String>>(6)?,row.get::<_,Option<String>>(7)?,control_set,control_status,
                    source.dataset,source.db,source.table,source.rowid,source.file],
            )?;
        }
    }
    let is_scm = |row: &crate::sqlite::Row| row.get("Provider").map(String::as_str) == Some("Service Control Manager")
        && row.get("Channel").map(String::as_str) == Some("System");
    let payload_of = |row: &crate::sqlite::Row| row.get("EventData").and_then(|v| serde_json::from_str::<serde_json::Value>(v).ok());
    // 7040 records display name (param1) and short key (param4) together;
    // a display name with more than one key stays unresolved (ServiceHistory rule).
    let mut aliases: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for row in events.rows().iter().filter(|row| is_scm(row) && row.get("EventID").map(String::as_str) == Some("7040")) {
        let Some(payload) = payload_of(row) else { continue };
        let field = |key| payload.get(key).and_then(serde_json::Value::as_str).map(str::trim).filter(|s| !s.is_empty());
        if let (Some(display), Some(key)) = (field("param1"), field("param4")) {
            aliases.entry(display.to_lowercase()).or_default().entry(key.to_lowercase()).or_insert_with(|| key.to_string());
        }
    }
    for row in events.rows() {
        if !is_scm(row) { continue; }
        let Some(payload) = payload_of(row) else { continue };
        let field = |key| payload.get(key).and_then(serde_json::Value::as_str);
        let event_id = row.get("EventID").and_then(|s|s.parse::<i64>().ok());
        let (service,kind,state,before,after) = match event_id {
            // param1 is the display name; the key is the Binary "<key>/<code>"
            // token, else the single 7040 alias of that display name.
            Some(7036) => {
                let binary = field("Binary").filter(|s| !s.is_empty()).or(field("Data")).unwrap_or("");
                let token = service_history::decode_binary(binary).0
                    .map(|decoded| service_history::split_binary_token(&decoded, "7036").0);
                let alias = field("param1")
                    .and_then(|display| aliases.get(&display.trim().to_lowercase()))
                    .filter(|keys| keys.len() == 1)
                    .and_then(|keys| keys.values().next().cloned());
                (token.or(alias),"service_state",field("param2"),None,None)
            }
            Some(7040) => (field("param4").map(str::to_string),"service_start_type_change",None,field("param2"),field("param3")),
            // 7045 (service installation) is ServiceHistory evidence.
            _ => continue,
        };
        if !service.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("LanmanServer")) { continue; }
        let source = ctx.facts.source_from_record_key(
            row.get("_record_key").map(String::as_str).unwrap_or(""),Some("EventData"),
            row.get("_source_file").map(String::as_str),Some(kind))?
            .ok_or_else(||anyhow::anyhow!("missing LanmanServer event provenance"))?;
        db.conn().execute(
            "INSERT INTO SmbEnvironment(environment_id,host_id,dataset_id,evidence_kind,timestamp,timestamp_kind,
             event_id,provider,service_name,state,start_type_before,start_type_after,event_data,
             source_dataset_id,source_db,source_table,source_rowid,source_file)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,kind,
                row.get("timestamp").filter(|s|!s.is_empty()),"이벤트 기록 시각",event_id,row.get("Provider"),
                service,state,before,after,row.get("EventData"),source.dataset,source.db,source.table,source.rowid,source.file],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::sqlite::Row;

    #[test]
    fn settings_and_state_remain_separate_with_original_generation() {
        let root = std::env::temp_dir().join(format!("wina-smb-environment-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("REGISTRY")).unwrap();
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let registry = root.join("REGISTRY/SYSTEM.sqlite");
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
        INSERT INTO Registry VALUES('2026-01-01', '\ROOT\Select','Current','RegDword','2',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-02', '\ROOT\ControlSet001\Services\LanmanServer','Start','RegDword','4',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-03', '\ROOT\ControlSet002\Services\LanmanServer','Start','RegDword','2',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-04', '\ROOT\ControlSet002\Services\LanmanServer\Shares','Evidence','RegMultiSz','["Path=C:\\Evidence"]',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-04', '\ROOT\ControlSet002\Services\LanmanServer\Shares\Security','','', '',NULL,'key','SYSTEM');"#).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        let event_path = root.join("EVENTLOG/System.sqlite");
        let conn = Connection::open(&event_path).unwrap();
        conn.execute_batch("CREATE TABLE System(EventData TEXT); INSERT INTO System VALUES('{}');").unwrap();
        drop(conn);
        stamp_facts_generation(&event_path, "event-old").unwrap();
        let events = EventLogOverviewCache::from_rows_for_tests(vec![Row::from([
            ("Provider".into(), "Service Control Manager".into()),
            ("Channel".into(), "System".into()),
            ("EventID".into(), "7036".into()),
            ("EventData".into(), format!(r#"{{"param1":"Server","param2":"실행","Binary":"{}"}}"#, utf16_hex("LanmanServer/4"))),
            ("timestamp".into(), "2026-02-01".into()),
            ("_record_key".into(), "System::1".into()),
            ("_source_file".into(), "System.evtx".into()),
        ])]);
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx = Ctx { out_dir: &root, target: &root, host_id: "host", dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(), meta: MetaLookup::load(&root).unwrap() };
        let db = DerivedDb::create(&ctx.overview_dir(), "SmbHistory").unwrap();
        populate(&ctx, &db, &events).unwrap();
        let settings: Vec<(String,String,String)> = db.conn().prepare("SELECT value_data,control_set_status,source_dataset_id FROM SmbEnvironment WHERE value_name='Start' ORDER BY key_path").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(settings, vec![("4".into(),"inactive".into(),"registry-old".into()),("2".into(),"active".into(),"registry-old".into())]);
        let state: (String,String,Option<String>,String) = db.conn().query_row("SELECT evidence_kind,state,start_type_after,source_dataset_id FROM SmbEnvironment WHERE event_id=7036",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(state,("service_state".into(),"실행".into(),None,"event-old".into()));
        let empty_key: (String,String) = db.conn().query_row("SELECT entry_kind,value_data FROM SmbEnvironment WHERE key_path LIKE '%Shares\\Security'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(empty_key,("key".into(),String::new()));
        assert_eq!(db.conn().query_row("SELECT COUNT(*) FROM SmbHistory",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        db.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    fn utf16_hex(text: &str) -> String {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).map(|b| format!("{b:02X}")).collect()
    }

    // RD-03: 7036 param1 is the display name; LanmanServer is proven only by
    // the Binary "<key>/<code>" token or a single 7040 display→key alias.
    #[test]
    fn state_events_match_by_short_key_evidence_not_display_name() {
        let root = std::env::temp_dir().join(format!("wina-smb-environment-7036-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let event_path = root.join("EVENTLOG/System.sqlite");
        let conn = Connection::open(&event_path).unwrap();
        conn.execute_batch("CREATE TABLE System(EventData TEXT);").unwrap();
        for _ in 0..6 {
            conn.execute("INSERT INTO System VALUES('{}')", []).unwrap();
        }
        drop(conn);
        stamp_facts_generation(&event_path, "event-old").unwrap();
        let scm = |n: usize, id: &str, data: String| Row::from([
            ("Provider".into(), "Service Control Manager".into()),
            ("Channel".into(), "System".into()),
            ("EventID".into(), id.into()),
            ("EventData".into(), data),
            ("timestamp".into(), format!("2026-02-0{n}")),
            ("_record_key".into(), format!("System::{n}")),
            ("_source_file".into(), "System.evtx".into()),
        ]);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            // Display name with the short key in Binary.
            scm(1, "7036", format!(r#"{{"param1":"서버","param2":"실행","Binary":"{}"}}"#, utf16_hex("LanmanServer/4"))),
            // Another service whose display name is not the key.
            scm(2, "7036", format!(r#"{{"param1":"Workstation","param2":"실행","Binary":"{}"}}"#, utf16_hex("LanmanWorkstation/4"))),
            // 7040 records display name and key together.
            scm(3, "7040", r#"{"param1":"Server","param2":"사용 안 함","param3":"자동 시작","param4":"LanmanServer"}"#.into()),
            // No Binary: the single 7040 alias proves the key.
            scm(4, "7036", r#"{"param1":"Server","param2":"중지됨"}"#.into()),
            // A display name equal to the key text is still not a key.
            scm(5, "7036", r#"{"param1":"LanmanServer","param2":"실행"}"#.into()),
        ]);
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx = Ctx { out_dir: &root, target: &root, host_id: "host", dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(), meta: MetaLookup::load(&root).unwrap() };
        let db = DerivedDb::create(&ctx.overview_dir(), "SmbHistory").unwrap();
        populate(&ctx, &db, &events).unwrap();
        let states: Vec<(String,String,String)> = db.conn().prepare("SELECT service_name,state,source_rowid FROM SmbEnvironment WHERE event_id=7036 ORDER BY source_rowid").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get::<_,i64>(2)?.to_string()))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(states, vec![
            ("LanmanServer".into(),"실행".into(),"1".into()),
            ("LanmanServer".into(),"중지됨".into(),"4".into()),
        ]);
        db.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    // RD-24/33/55: every LanmanServer subkey row is kept, sibling services are
    // not selected, time meanings use the shared vocabulary, and 7045 is left
    // to ServiceHistory.
    #[test]
    fn every_lanmanserver_row_is_kept_with_shared_time_meanings() {
        let root = std::env::temp_dir().join(format!("wina-smb-environment-all-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("REGISTRY")).unwrap();
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let registry = root.join("REGISTRY/SYSTEM.sqlite");
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
        INSERT INTO Registry VALUES('2026-01-02', '\ROOT\ControlSet001\Services\LanmanServer','Start','RegDword','2',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-03', '\ROOT\ControlSet001\Services\LanmanServer\DefaultSecurity','SrvsvcShareAdminConnect','RegBinary',NULL,'0100','value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-03', '\ROOT\ControlSet001\Services\LanmanServer\Parameters\FsctlAllowlist','FSCTL_X','RegDword','1',NULL,'value','SYSTEM');
        INSERT INTO Registry VALUES('2026-01-03', '\ROOT\ControlSet001\Services\LanmanServerX','Start','RegDword','3',NULL,'value','SYSTEM');"#).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        let event_path = root.join("EVENTLOG/System.sqlite");
        let conn = Connection::open(&event_path).unwrap();
        conn.execute_batch("CREATE TABLE System(EventData TEXT); INSERT INTO System VALUES('{}'),('{}');").unwrap();
        drop(conn);
        stamp_facts_generation(&event_path, "event-old").unwrap();
        let scm = |n: usize, id: &str, data: String| Row::from([
            ("Provider".into(), "Service Control Manager".into()),
            ("Channel".into(), "System".into()),
            ("EventID".into(), id.into()),
            ("EventData".into(), data),
            ("timestamp".into(), format!("2026-02-0{n}")),
            ("_record_key".into(), format!("System::{n}")),
            ("_source_file".into(), "System.evtx".into()),
        ]);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            scm(1, "7036", format!(r#"{{"param1":"Server","param2":"실행","Binary":"{}"}}"#, utf16_hex("LanmanServer/4"))),
            scm(2, "7045", r#"{"ServiceName":"LanmanServer","StartType":"자동 시작"}"#.into()),
        ]);
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx = Ctx { out_dir: &root, target: &root, host_id: "host", dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(), meta: MetaLookup::load(&root).unwrap() };
        let db = DerivedDb::create(&ctx.overview_dir(), "SmbHistory").unwrap();
        populate(&ctx, &db, &events).unwrap();
        let rows: Vec<(String,Option<String>,String)> = db.conn().prepare("SELECT evidence_kind,value_name,timestamp_kind FROM SmbEnvironment ORDER BY timestamp,value_name").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![
            ("service_configuration".into(),Some("Start".into()),"키 기록 시각".into()),
            ("service_subkey".into(),Some("FSCTL_X".into()),"키 기록 시각".into()),
            ("service_subkey".into(),Some("SrvsvcShareAdminConnect".into()),"키 기록 시각".into()),
            ("service_state".into(),None,"이벤트 기록 시각".into()),
        ]);
        db.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
