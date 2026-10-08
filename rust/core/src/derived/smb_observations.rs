//! Per-log collection evidence; no absence-to-audit-policy inference.
use super::{Ctx, DerivedDb};
use crate::overview::EventLogOverviewCache;
use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};
use std::collections::{BTreeMap, HashSet};

const LOGS: &[&str] = &[
    "Security", "System", "Microsoft-Windows-SMBServer%4Security",
    "Microsoft-Windows-SMBServer%4Audit", "Microsoft-Windows-SmbClient%4Security",
];

#[derive(Default)]
struct Bounds<'a> {
    count: i64,
    corrupt: i64,
    untimed: i64,
    first: Option<&'a str>,
    last: Option<&'a str>,
    source_file: Option<&'a str>,
}

fn relevant(name: &str) -> bool {
    LOGS.iter().any(|log| name.eq_ignore_ascii_case(log))
        || name.to_ascii_lowercase().starts_with("microsoft-windows-smb")
        || name.strip_prefix("Security_").is_some_and(|s| s.bytes().all(|b|b.is_ascii_digit()))
        || name.strip_prefix("System_").is_some_and(|s| s.bytes().all(|b|b.is_ascii_digit()))
}

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, events: &EventLogOverviewCache) -> Result<()> {
    let mut bounds: BTreeMap<&str, Bounds<'_>> = BTreeMap::new();
    for row in events.rows() {
        let Some(table) = row.get("_record_key").and_then(|key|key.split("::").next()) else { continue };
        if !relevant(table) { continue; }
        let value = bounds.entry(table).or_default();
        value.source_file = row.get("_source_file").map(String::as_str).or(value.source_file);
        if row.get("_status").is_some_and(|s| s == "corrupted_chunk") {
            value.corrupt += 1;
            continue;
        }
        value.count += 1;
        if let Some(time) = row.get("timestamp").map(String::as_str).filter(|s|!s.is_empty()) {
            value.first = Some(value.first.map_or(time,|v|v.min(time)));
            value.last = Some(value.last.map_or(time,|v|v.max(time)));
        } else { value.untimed += 1; }
    }
    let path = ctx.out_dir.join("EVENTLOG/EventLogInputs.sqlite");
    let mut discovered = false;
    let mut seen = HashSet::new();
    if path.exists() {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        discovered = conn.query_row("SELECT EXISTS(SELECT 1 FROM EventLogInputs WHERE status='discovery_complete')",[],|r|r.get(0))?;
        let mut stmt = conn.prepare("SELECT rowid,source_file,facts_db,facts_table,status,row_count,error FROM EventLogInputs WHERE status<>'discovery_complete' ORDER BY rowid")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let file: Option<String> = row.get(1)?;
            let table: String = row.get::<_,Option<String>>(3)?.filter(|s|!s.is_empty()).unwrap_or_else(|| {
                file.as_deref().unwrap_or("").rsplit(['/', '\\']).next().unwrap_or("")
                    .rsplit_once('.').map(|(stem,_)|stem).unwrap_or("").to_string()
            });
            if !relevant(&table) { continue; }
            seen.insert(table.to_ascii_lowercase());
            let status: String = row.get(4)?;
            let count = row.get::<_,Option<String>>(5)?.and_then(|v|v.parse::<i64>().ok());
            let state = match (status.as_str(), count) {
                ("read_failed",_) => "read_failed",
                ("parsed",Some(0)) => "collected_empty",
                ("parsed",Some(_)) => "collected",
                _ => "unknown",
            };
            let source = ctx.facts.source_from_row(&path,"EventLogInputs",row.get(0)?,file.as_deref(),Some("collection_observation"))?
                .ok_or_else(||anyhow::anyhow!("missing EventLogInputs provenance"))?;
            let stats = bounds.remove(table.as_str()).unwrap_or_default();
            let parsed = status == "parsed";
            db.conn().execute(
                "INSERT INTO SmbLogObservations(observation_id,host_id,dataset_id,log_name,source_file,facts_db,facts_table,
                 collection_state,input_row_count,event_count,corrupted_count,untimed_count,first_observed_time,last_observed_time,
                 audit_setting_state,error,source_dataset_id,source_db,source_table,source_rowid)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'unknown',?15,?16,?17,?18,?19)",
                params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,table,file,
                    row.get::<_,Option<String>>(2)?.filter(|s|!s.is_empty()),
                    row.get::<_,Option<String>>(3)?.filter(|s|!s.is_empty()),state,count,
                    parsed.then_some(stats.count),parsed.then_some(stats.corrupt),parsed.then_some(stats.untimed),
                    stats.first,stats.last,row.get::<_,Option<String>>(6)?,source.dataset,source.db,source.table,source.rowid],
            )?;
        }
    }
    for (table,stats) in bounds {
        seen.insert(table.to_ascii_lowercase());
        let facts = ctx.facts.by_stem(table);
        let generation = facts.map(|f|ctx.facts.generation(f)).transpose()?;
        db.conn().execute(
            "INSERT INTO SmbLogObservations(observation_id,host_id,dataset_id,log_name,source_file,facts_db,facts_table,
             collection_state,event_count,corrupted_count,untimed_count,first_observed_time,last_observed_time,
             audit_setting_state,source_dataset_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,'unknown',?8,?9,?10,?11,?12,'unknown',?13)",
            params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,table,stats.source_file,
                facts.map(|f|f.relative.as_str()),table,stats.count,stats.corrupt,stats.untimed,stats.first,stats.last,generation],
        )?;
    }
    for log in LOGS {
        if seen.contains(&log.to_ascii_lowercase()) { continue; }
        db.conn().execute(
            "INSERT INTO SmbLogObservations(observation_id,host_id,dataset_id,log_name,collection_state,audit_setting_state)
             VALUES(?1,?2,?3,?4,?5,'unknown')",
            params![uuid::Uuid::new_v4().to_string(),ctx.host_id,ctx.dataset_id,log,
                if discovered { "not_collected" } else { "unknown" }],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{FactsIndex, MetaLookup, stamp_facts_generation};
    #[test]
    fn empty_failed_missing_and_unobserved_are_distinct() {
        let root = std::env::temp_dir().join(format!("wina-smb-logs-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        let path=root.join("EVENTLOG/EventLogInputs.sqlite");
        let conn=Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE EventLogInputs(source_file TEXT,facts_db TEXT,facts_table TEXT,status TEXT,row_count TEXT,error TEXT);
        INSERT INTO EventLogInputs VALUES('','','','discovery_complete','2',NULL);
        INSERT INTO EventLogInputs VALUES('Security.evtx','EVENTLOG/Security.sqlite','Security','parsed','0',NULL);
        INSERT INTO EventLogInputs VALUES('Microsoft-Windows-SMBServer%4Audit.evtx','','','read_failed','0','bad header');").unwrap();
        drop(conn);
        stamp_facts_generation(&path,"old-facts").unwrap();
        super::super::create_database(&root.join("_OVERVIEW"),"Metadata").unwrap();
        let ctx=Ctx {out_dir:&root,target:&root,host_id:"host",dataset_id:"new",facts:FactsIndex::load(&root).unwrap(),meta:MetaLookup::load(&root).unwrap()};
        let db=DerivedDb::create(&ctx.overview_dir(),"SmbHistory").unwrap();
        populate(&ctx,&db,&EventLogOverviewCache::from_rows_for_tests(Vec::new())).unwrap();
        let get=|log:&str| db.conn().query_row("SELECT collection_state,event_count,audit_setting_state FROM SmbLogObservations WHERE log_name=?1",[log],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<i64>>(1)?,r.get::<_,String>(2)?))).unwrap();
        assert_eq!(get("Security"),("collected_empty".into(),Some(0),"unknown".into()));
        assert_eq!(get("Microsoft-Windows-SMBServer%4Audit"),("read_failed".into(),None,"unknown".into()));
        assert_eq!(get("Microsoft-Windows-SmbClient%4Security"),("not_collected".into(),None,"unknown".into()));
        db.finish().unwrap();
        std::fs::remove_file(path).unwrap();
        let ctx=Ctx {out_dir:&root,target:&root,host_id:"host",dataset_id:"new",facts:FactsIndex::load(&root).unwrap(),meta:MetaLookup::load(&root).unwrap()};
        let db=DerivedDb::create(&ctx.overview_dir(),"SmbHistory").unwrap();
        populate(&ctx,&db,&EventLogOverviewCache::from_rows_for_tests(Vec::new())).unwrap();
        assert_eq!(db.conn().query_row("SELECT COUNT(*) FROM SmbLogObservations WHERE collection_state<>'unknown' OR event_count IS NOT NULL",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        db.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
