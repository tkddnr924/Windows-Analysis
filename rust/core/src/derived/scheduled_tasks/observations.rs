//! What was actually collected for this view (A07, R12).
//!
//! Zero events is not proof that nothing ran: a log can be missing from the
//! collection, present but empty, or unreadable. Those states are stored
//! separately and never inferred from an empty result.
use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};

use crate::derived::{Ctx, DerivedDb};
use crate::overview::EventLogOverviewCache;

/// Logs that carry scheduled-task evidence. Maintenance is listed because the
/// collection can contain it even when the parser's allowlist does not read it
/// — "not parsed" must not look like "no events".
const LOGS: &[&str] = &[
    "Microsoft-Windows-TaskScheduler%4Operational",
    "Microsoft-Windows-TaskScheduler%4Maintenance",
    "Security",
];

const DEFINITION_FACTS_STEM: &str = "TaskScheduler_Tasks";

#[derive(Default)]
struct Bounds {
    count: i64,
    task_count: i64,
    corrupt: i64,
    untimed: i64,
    first: Option<String>,
    last: Option<String>,
    source_file: Option<String>,
}

fn relevant(name: &str) -> bool {
    LOGS.iter().any(|log| name.eq_ignore_ascii_case(log))
        || name.to_ascii_lowercase().contains("taskscheduler")
        || name
            .strip_prefix("Security_")
            .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_task_evidence(row: &crate::sqlite::Row) -> bool {
    let provider = row.get("Provider").map(String::as_str).unwrap_or("");
    if provider == "Microsoft-Windows-TaskScheduler" {
        return true;
    }
    provider == "Microsoft-Windows-Security-Auditing"
        && matches!(
            row.get("EventID").map(String::as_str).unwrap_or(""),
            "4698" | "4699" | "4700" | "4701" | "4702"
        )
}

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, events: &EventLogOverviewCache) -> Result<()> {
    let mut bounds: BTreeMap<String, Bounds> = BTreeMap::new();
    for row in events.rows() {
        let Some(table) = row
            .get("_record_key")
            .and_then(|key| key.split("::").next())
            .map(str::to_string)
        else {
            continue;
        };
        if !relevant(&table) {
            continue;
        }
        let entry = bounds.entry(table).or_default();
        if entry.source_file.is_none() {
            entry.source_file = row.get("_source_file").cloned();
        }
        if row.get("_status").is_some_and(|status| status == "corrupted_chunk") {
            entry.corrupt += 1;
            continue;
        }
        entry.count += 1;
        if is_task_evidence(row) {
            entry.task_count += 1;
        }
        match row.get("timestamp").filter(|value| !value.is_empty()) {
            Some(time) => {
                entry.first = Some(match entry.first.take() {
                    Some(current) => current.min(time.clone()),
                    None => time.clone(),
                });
                entry.last = Some(match entry.last.take() {
                    Some(current) => current.max(time.clone()),
                    None => time.clone(),
                });
            }
            None => entry.untimed += 1,
        }
    }

    let inputs = ctx.out_dir.join("EVENTLOG/EventLogInputs.sqlite");
    let mut discovered = false;
    let mut seen: Vec<String> = Vec::new();
    if inputs.exists() {
        let conn = Connection::open_with_flags(&inputs, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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
                .filter(|value| !value.is_empty())
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
            if !relevant(&table) {
                continue;
            }
            seen.push(table.to_ascii_lowercase());
            let status: String = row.get(4)?;
            let count = row
                .get::<_, Option<String>>(5)?
                .and_then(|value| value.parse::<i64>().ok());
            let state = match (status.as_str(), count) {
                ("read_failed", _) => "read_failed",
                ("parsed", Some(0)) => "collected_empty",
                ("parsed", Some(_)) => "collected",
                _ => "unknown",
            };
            let source = ctx
                .facts
                .source_from_row(&inputs, "EventLogInputs", row.get(0)?, file.as_deref(), Some("collection_observation"))?
                .ok_or_else(|| anyhow::anyhow!("EventLogInputs 출처를 확인하지 못했습니다"))?;
            let stats = bounds.remove(&table).unwrap_or_default();
            let parsed = status == "parsed";
            let facts_generation = ctx.facts.by_stem(&table)
                .map(|facts| ctx.facts.generation(facts)).transpose()?;
            db.conn().execute(
                "INSERT INTO TaskLogObservations(observation_id,host_id,dataset_id,observation_kind,log_name,source_file,
                 facts_db,facts_table,collection_state,input_row_count,event_count,task_event_count,corrupted_count,
                 untimed_count,first_observed_time,last_observed_time,error,source_dataset_id,source_db,source_table,source_rowid,facts_generation)
                 VALUES(?1,?2,?3,'event_log',?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    ctx.host_id,
                    ctx.dataset_id,
                    table,
                    file,
                    row.get::<_, Option<String>>(2)?.filter(|value| !value.is_empty()),
                    row.get::<_, Option<String>>(3)?.filter(|value| !value.is_empty()),
                    state,
                    count,
                    parsed.then_some(stats.count),
                    parsed.then_some(stats.task_count),
                    parsed.then_some(stats.corrupt),
                    parsed.then_some(stats.untimed),
                    stats.first,
                    stats.last,
                    row.get::<_, Option<String>>(6)?,
                    source.dataset,
                    source.db,
                    source.table,
                    source.rowid,
                    facts_generation,
                ],
            )?;
        }
    }

    // Logs that produced rows without an input manifest entry.
    for (table, stats) in bounds {
        seen.push(table.to_ascii_lowercase());
        let facts = ctx.facts.by_stem(&table);
        let generation = facts.map(|facts| ctx.facts.generation(facts)).transpose()?;
        db.conn().execute(
            "INSERT INTO TaskLogObservations(observation_id,host_id,dataset_id,observation_kind,log_name,source_file,
             facts_db,facts_table,collection_state,event_count,task_event_count,corrupted_count,untimed_count,
             first_observed_time,last_observed_time,facts_generation)
             VALUES(?1,?2,?3,'event_log',?4,?5,?6,?7,'unknown',?8,?9,?10,?11,?12,?13,?14)",
            params![
                uuid::Uuid::new_v4().to_string(),
                ctx.host_id,
                ctx.dataset_id,
                table,
                stats.source_file,
                facts.map(|facts| facts.relative.as_str()),
                table,
                stats.count,
                stats.task_count,
                stats.corrupt,
                stats.untimed,
                stats.first,
                stats.last,
                generation,
            ],
        )?;
    }

    // Expected logs that never appeared in this collection.
    for log in LOGS {
        if seen.iter().any(|name| name == &log.to_ascii_lowercase()) {
            continue;
        }
        db.conn().execute(
            "INSERT INTO TaskLogObservations(observation_id,host_id,dataset_id,observation_kind,log_name,collection_state)
             VALUES(?1,?2,?3,'event_log',?4,?5)",
            params![
                uuid::Uuid::new_v4().to_string(),
                ctx.host_id,
                ctx.dataset_id,
                log,
                if discovered { "not_collected" } else { "unknown" },
            ],
        )?;
    }

    // Collected task definition files.
    let definitions = ctx.facts.by_stem(DEFINITION_FACTS_STEM);
    let (state, rows, generation, relative) = match definitions {
        Some(facts) => {
            let rows: Option<i64> =
                Connection::open_with_flags(&facts.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .and_then(|conn| {
                        conn.query_row(
                            &format!(
                                "SELECT COUNT(*) FROM {}",
                                crate::sqlite::quote_ident(DEFINITION_FACTS_STEM)
                            ),
                            [],
                            |row| row.get(0),
                        )
                    })
                    .ok();
            (
                match rows {
                    Some(0) => "collected_empty",
                    Some(_) => "collected",
                    None => "read_failed",
                },
                rows,
                Some(ctx.facts.generation(facts)?),
                Some(facts.relative.clone()),
            )
        }
        None => ("not_collected", None, None, None),
    };
    db.conn().execute(
        "INSERT INTO TaskLogObservations(observation_id,host_id,dataset_id,observation_kind,log_name,facts_db,
         facts_table,collection_state,input_row_count,facts_generation)
         VALUES(?1,?2,?3,'task_definition_input',?4,?5,?6,?7,?8,?9)",
        params![
            uuid::Uuid::new_v4().to_string(),
            ctx.host_id,
            ctx.dataset_id,
            DEFINITION_FACTS_STEM,
            relative,
            DEFINITION_FACTS_STEM,
            state,
            rows,
            generation,
        ],
    )?;

    super::supplemental::input_observations(ctx, db)
}
