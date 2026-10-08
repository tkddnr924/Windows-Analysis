//! Collector-reported live tasks and collected executable copies (A05, A06).
//!
//! The collector's `Volatile/tasks.json` is a *report made at collection time*
//! and its `Signature` column is the collector's own measurement — never the
//! Windows task definition and never a signature verification performed here.
//! Collected `TASKS_SYSTEM32/Exec` copies are files the collector picked up by
//! name; a name match to a task command is a comparison, not an identity.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use super::{normalize_task_path, DefinitionIndex};
use crate::derived::{ancillary, stamp_facts_generation, Ctx, DerivedDb};
use crate::overview;
use crate::parsers::taskscheduler::{decode_text, sha256_file};

/// Host-relative supplemental evidence database owned by this view.
pub(crate) const SUPPLEMENTAL_DB: &str = "SUPPLEMENTAL/ScheduledTask_Supplemental.sqlite";
const DB_STEM: &str = "ScheduledTask_Supplemental";
pub(crate) const LIVE_TABLE: &str = "TaskLive_Records";
pub(crate) const EXEC_TABLE: &str = "TaskExecCopy_Records";
pub(crate) const INPUT_TABLE: &str = "TaskSupplementalInputs";
const LIVE_ARTIFACT: &str = "CollectorTasksJson";
const EXEC_ARTIFACT: &str = "CollectedTaskExecutable";
const INPUT_ARTIFACT: &str = "ScheduledTaskSupplementalInput";

const CREATE_SQL: &str = r#"
CREATE TABLE "TaskLive_Records" (
  "entry_index" INTEGER,
  "entry_key" TEXT,
  "name" TEXT,
  "description" TEXT,
  "command" TEXT,
  "triggers" TEXT,
  "account" TEXT,
  "signature" TEXT,
  "signer" TEXT,
  "sign_timestamp" TEXT,
  "signer2" TEXT,
  "sign_timestamp2" TEXT,
  "raw_json" TEXT,
  "encoding" TEXT,
  "_source_file" TEXT NOT NULL
);
CREATE TABLE "TaskExecCopy_Records" (
  "collected_path" TEXT NOT NULL,
  "file_name" TEXT,
  "size" INTEGER,
  "sha256" TEXT,
  "_source_file" TEXT NOT NULL
);
CREATE TABLE "TaskSupplementalInputs" (
  "input_kind" TEXT NOT NULL,
  "input_path" TEXT,
  "status" TEXT NOT NULL,
  "item_count" INTEGER,
  "error" TEXT,
  "_source_file" TEXT NOT NULL
);
"#;

/// Collector snapshot inputs are materialised as facts before the overview is
/// derived, exactly like the other supplemental evidence.
///
/// Returns the host-relative database paths that must be sealed. The database
/// is always written (even with zero live entries) because the input
/// observations themselves are evidence of what was collected.
pub(crate) fn prepare_inputs(out_dir: &Path, target: &Path, dataset_id: &str) -> Result<Vec<String>> {
    let dir = out_dir.join(ancillary::ANCILLARY_CATEGORY);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("보조 증거 폴더 생성: {}", dir.display()))?;
    let path = dir.join(format!("{DB_STEM}.sqlite"));
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 작업 보조 증거 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("작업 보조 증거 DB 생성: {}", path.display()))?;
    conn.execute_batch(CREATE_SQL)?;
    conn.execute_batch("BEGIN")?;

    let mut inputs: Vec<(String, String, String, Option<i64>, Option<String>, String)> = Vec::new();

    // --- Volatile/tasks.json -------------------------------------------------
    let found = crate::finder::by_name(target, &["tasks.json"]);
    if found.paths.is_empty() {
        inputs.push((
            "collector_tasks_json".into(),
            String::new(),
            "not_collected".into(),
            None,
            None,
            target.to_string_lossy().to_string(),
        ));
    }
    for source in &found.paths {
        let display = source.to_string_lossy().to_string();
        let raw = match std::fs::read(source) {
            Ok(raw) => raw,
            Err(error) => {
                inputs.push((
                    "collector_tasks_json".into(),
                    display.clone(),
                    "read_failed".into(),
                    None,
                    Some(error.to_string()),
                    display,
                ));
                continue;
            }
        };
        let decoded = decode_text(&raw);
        let parsed: serde_json::Value = match serde_json::from_str(decoded.text.trim()) {
            Ok(value) => value,
            Err(error) => {
                inputs.push((
                    "collector_tasks_json".into(),
                    display.clone(),
                    "parse_failed".into(),
                    None,
                    Some(error.to_string()),
                    display,
                ));
                continue;
            }
        };
        let serde_json::Value::Object(map) = parsed else {
            inputs.push((
                "collector_tasks_json".into(),
                display.clone(),
                "parse_failed".into(),
                None,
                Some("최상위 JSON이 객체가 아닙니다".into()),
                display,
            ));
            continue;
        };
        // "title" holds the column names; every other key is one live task.
        let titles: Vec<String> = map
            .get("title")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default();
        let column = |row: &serde_json::Value, name: &str| -> Option<String> {
            let index = titles.iter().position(|title| title == name)?;
            row.get(index)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .filter(|value| !value.is_empty())
        };
        let mut statement = conn.prepare(
            "INSERT INTO \"TaskLive_Records\" (entry_index, entry_key, name, description, command, triggers,
             account, signature, signer, sign_timestamp, signer2, sign_timestamp2, raw_json, encoding, _source_file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        )?;
        let mut count = 0i64;
        for (key, row) in &map {
            if key == "title" {
                continue;
            }
            count += statement.execute(params![
                key.parse::<i64>().ok(),
                key,
                column(row, "Name"),
                column(row, "Description"),
                column(row, "Command"),
                column(row, "Triggers"),
                column(row, "Account"),
                column(row, "Signature"),
                column(row, "Signer"),
                column(row, "SignTimeStamp"),
                column(row, "Signer2"),
                column(row, "SignTimeStamp2"),
                row.to_string(),
                decoded.encoding,
                &display,
            ])? as i64;
        }
        drop(statement);
        inputs.push((
            "collector_tasks_json".into(),
            display.clone(),
            "collected".into(),
            Some(count),
            None,
            display,
        ));
    }

    // --- Collected task executables (TASKS*/Exec) ----------------------------
    let exec_dirs = collected_exec_dirs(target);
    if exec_dirs.is_empty() {
        inputs.push((
            "collected_task_executables".into(),
            String::new(),
            "not_collected".into(),
            None,
            None,
            target.to_string_lossy().to_string(),
        ));
    }
    for dir in exec_dirs {
        let display = dir.to_string_lossy().to_string();
        let (files, errors) = crate::finder::walk_files(&dir);
        let mut statement = conn.prepare(
            "INSERT INTO \"TaskExecCopy_Records\" (collected_path, file_name, size, sha256, _source_file)
             VALUES (?1,?2,?3,?4,?5)",
        )?;
        let mut count = 0i64;
        let mut failures: Vec<String> = errors;
        for file in files {
            // Stream the file: a collected executable must not be slurped into
            // memory just to be measured and hashed.
            match sha256_file(&file) {
                Ok((size, digest)) => {
                    count += statement.execute(params![
                        file.to_string_lossy(),
                        file.file_name().map(|name| name.to_string_lossy().to_string()),
                        size as i64,
                        digest,
                        file.to_string_lossy(),
                    ])? as i64;
                }
                Err(error) => failures.push(format!("{}: {error}", file.display())),
            }
        }
        drop(statement);
        inputs.push((
            "collected_task_executables".into(),
            display.clone(),
            if failures.is_empty() {
                "collected".into()
            } else {
                "collected_with_errors".to_string()
            },
            Some(count),
            (!failures.is_empty()).then(|| failures.join(" | ")),
            display,
        ));
    }

    {
        let mut statement = conn.prepare(
            "INSERT INTO \"TaskSupplementalInputs\" (input_kind, input_path, status, item_count, error, _source_file)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )?;
        for (kind, input_path, status, count, error, file) in &inputs {
            statement.execute(params![
                kind,
                (!input_path.is_empty()).then_some(input_path),
                status,
                count,
                error,
                file
            ])?;
        }
    }
    conn.execute_batch("COMMIT")?;
    drop(conn);
    stamp_facts_generation(&path, dataset_id)?;
    Ok(vec![SUPPLEMENTAL_DB.to_string()])
}

/// Directories the collector uses for task executable copies: an `Exec` folder
/// directly under a `TASKS*` collection root.
fn collected_exec_dirs(target: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(target)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.eq_ignore_ascii_case("Exec") {
            continue;
        }
        let parent = entry
            .path()
            .parent()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().to_ascii_uppercase())
            .unwrap_or_default();
        if parent.starts_with("TASKS") {
            found.push(entry.path().to_path_buf());
        }
    }
    found.sort();
    found
}

fn text(row: &crate::sqlite::Row, key: &str) -> Option<String> {
    row.get(key).filter(|value| !value.is_empty()).cloned()
}

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, index: &DefinitionIndex) -> Result<()> {
    let path = ctx.out_dir.join(SUPPLEMENTAL_DB);
    if !path.exists() {
        return Ok(());
    }

    for row in overview::read_table_with_rowid(&path, LIVE_TABLE) {
        let rowid: i64 = row
            .get("__source_rowid")
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        let source = ctx
            .facts
            .source_from_row(&path, LIVE_TABLE, rowid, text(&row, "_source_file").as_deref(), Some(LIVE_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("작업 보조 스냅샷 출처를 확인하지 못했습니다"))?;
        let name = row.get("name").cloned().unwrap_or_default();
        let normalized = (!name.is_empty()).then(|| normalize_task_path(&name));
        let (matched, status) = match &normalized {
            Some(path) => super::match_definition(index, path),
            None => (None, "name_missing".to_string()),
        };
        db.conn().execute(
            "INSERT INTO TaskLiveSnapshot(snapshot_id,host_id,dataset_id,entry_index,name,task_path_normalized,
             task_description,command,triggers_text,account_reported,signature_reported,signer,sign_timestamp,
             signer2,sign_timestamp2,raw_json,matched_record_id,match_status,match_basis,
             source_dataset_id,source_db,source_table,source_rowid,source_file)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
            params![
                uuid::Uuid::new_v4().to_string(),
                ctx.host_id,
                ctx.dataset_id,
                row.get("entry_index").and_then(|value| value.parse::<i64>().ok()),
                text(&row, "name"),
                normalized,
                text(&row, "description"),
                text(&row, "command"),
                text(&row, "triggers"),
                text(&row, "account"),
                text(&row, "signature"),
                text(&row, "signer"),
                text(&row, "sign_timestamp"),
                text(&row, "signer2"),
                text(&row, "sign_timestamp2"),
                text(&row, "raw_json"),
                matched,
                status,
                "collector_task_name_vs_definition_path",
                source.dataset,
                source.db,
                source.table,
                source.rowid,
                source.file,
            ],
        )?;
    }

    // Collected executable copies compared to action commands by file name.
    let mut by_name: BTreeMap<String, Vec<(usize, &(String, i64, String, Option<String>))>> =
        BTreeMap::new();
    for (position, command) in index.commands().iter().enumerate() {
        let resolved = command.3.clone().unwrap_or_else(|| command.2.clone());
        by_name
            .entry(super::command_leaf(&resolved))
            .or_default()
            .push((position, command));
    }
    for row in overview::read_table_with_rowid(&path, EXEC_TABLE) {
        let rowid: i64 = row
            .get("__source_rowid")
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        let source = ctx
            .facts
            .source_from_row(&path, EXEC_TABLE, rowid, text(&row, "collected_path").as_deref(), Some(EXEC_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("수집 실행 파일 사본 출처를 확인하지 못했습니다"))?;
        let file_name = row.get("file_name").cloned().unwrap_or_default();
        let matches = by_name
            .get(&file_name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        let insert = |record_id: Option<&str>,
                          action_ordinal: Option<i64>,
                          command_raw: Option<&str>,
                          command_resolved: Option<&str>,
                          status: &str,
                          basis: &str|
         -> Result<()> {
            db.conn().execute(
                "INSERT INTO TaskFileEvidence(evidence_id,host_id,dataset_id,record_id,action_ordinal,evidence_kind,
                 collected_path,collected_name,collected_size,collected_sha256,command_raw,command_resolved,
                 match_status,match_basis,source_dataset_id,source_db,source_table,source_rowid,source_file)
                 VALUES(?1,?2,?3,?4,?5,'collected_exec_copy',?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    ctx.host_id,
                    ctx.dataset_id,
                    record_id,
                    action_ordinal,
                    text(&row, "collected_path"),
                    text(&row, "file_name"),
                    row.get("size").and_then(|value| value.parse::<i64>().ok()),
                    text(&row, "sha256"),
                    command_raw,
                    command_resolved,
                    status,
                    basis,
                    source.dataset,
                    source.db,
                    source.table,
                    source.rowid,
                    source.file,
                ],
            )?;
            Ok(())
        };
        if matches.is_empty() {
            insert(
                None,
                None,
                None,
                None,
                "no_matching_action",
                "collected executable file name matches no task action command",
            )?;
            continue;
        }
        for (_, command) in matches {
            insert(
                Some(&command.0),
                Some(command.1),
                Some(&command.2),
                command.3.as_deref(),
                "file_name_match_only",
                "collected executable file name equals the action command file name; volume, time and content identity are not established",
            )?;
        }
    }
    Ok(())
}

/// Input-level observations for the view's collection scope.
pub(super) fn input_observations(ctx: &Ctx, db: &DerivedDb) -> Result<()> {
    let path = ctx.out_dir.join(SUPPLEMENTAL_DB);
    if !path.exists() {
        return Ok(());
    }
    for row in overview::read_table_with_rowid(&path, INPUT_TABLE) {
        let rowid: i64 = row
            .get("__source_rowid")
            .and_then(|value| value.parse().ok())
            .unwrap_or_default();
        let source = ctx
            .facts
            .source_from_row(&path, INPUT_TABLE, rowid, text(&row, "_source_file").as_deref(), Some(INPUT_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("작업 보조 입력 관측 출처를 확인하지 못했습니다"))?;
        db.conn().execute(
            "INSERT INTO TaskLogObservations(observation_id,host_id,dataset_id,observation_kind,log_name,source_file,
             collection_state,input_row_count,error,source_dataset_id,source_db,source_table,source_rowid)
             VALUES(?1,?2,?3,'supplemental_input',?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                uuid::Uuid::new_v4().to_string(),
                ctx.host_id,
                ctx.dataset_id,
                text(&row, "input_kind"),
                text(&row, "input_path"),
                row.get("status").cloned().unwrap_or_else(|| "unknown".into()),
                row.get("item_count").and_then(|value| value.parse::<i64>().ok()),
                text(&row, "error"),
                source.dataset,
                source.db,
                source.table,
                source.rowid,
            ],
        )?;
    }
    Ok(())
}
