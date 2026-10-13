//! Direct BITS queue (qmgr) evidence: discovery, facts and typed snapshots.
//!
//! The queue holds the *state of the transfer queue at collection time*. A job
//! or file record is never an execution or a completed transfer, and records
//! are never merged with Bits-Client events by name — the typed rows stay in
//! their own tables so a snapshot can not be read as an event.
//!
//! `prepare_inputs` materialises the parsed records as facts
//! (`SUPPLEMENTAL/Bits_Queue.sqlite`) before the overview is derived, and
//! `populate` converts those facts — and nothing else — into the typed
//! `BitsQueueEvidence` / `BitsQueueJobs` / `BitsQueueFiles` tables with their
//! real facts coordinates.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags};

use super::{opt, t};
use crate::derived::{ancillary, int_opt, stamp_facts_generation, Cell, Ctx, DerivedDb};
use crate::parsers::bits_queue::{
    self, job_priority_name, job_state_name, job_type_name, notify_flags, ParsedQueue, QueueJob,
};
use crate::time::fmt_filetime;

/// Host-relative facts database owned by this view.
pub(crate) const QUEUE_DB: &str = "SUPPLEMENTAL/Bits_Queue.sqlite";
const DB_STEM: &str = "Bits_Queue";
pub(crate) const INPUT_TABLE: &str = "BitsQueue_Inputs";
pub(crate) const JOB_TABLE: &str = "BitsQueue_Jobs";
pub(crate) const FILE_TABLE: &str = "BitsQueue_Files";
const INPUT_ARTIFACT: &str = "BitsQueueInput";
const JOB_ARTIFACT: &str = "BitsQueueJob";
const FILE_ARTIFACT: &str = "BitsQueueFile";

const JOB_BASIS: &str =
    "qmgr 큐의 작업 레코드 스냅샷(수집 시점 큐 상태). 전송 실행·완료 사실이 아니다";
const FILE_BASIS: &str =
    "qmgr 큐의 파일 레코드 스냅샷(수집 시점 큐 상태). 다운로드 완료 증거가 아니다";
/// A record found past an undocumented trailer is a candidate: its boundary is
/// not established by the format, so the row says so instead of claiming it.
const FILE_BASIS_HEURISTIC: &str =
    "qmgr 큐의 파일 레코드 후보(수집 시점 큐 상태). 앞 레코드와의 경계가 문서화되지 않아 \
     재동기화로 찾았으며 경계는 증명되지 않았다. 다운로드 완료 증거가 아니다";

const CREATE_SQL: &str = r#"
CREATE TABLE "BitsQueue_Inputs" (
  "input_kind" TEXT NOT NULL,
  "search_pattern" TEXT,
  "search_root" TEXT,
  "input_path" TEXT,
  "relative_path" TEXT,
  "file_size" INTEGER,
  "format" TEXT,
  "format_detail" TEXT,
  "status" TEXT NOT NULL,
  "collection_state" TEXT NOT NULL,
  "declared_job_count" INTEGER,
  "job_record_count" INTEGER,
  "file_record_count" INTEGER,
  "failed_record_count" INTEGER,
  "job_delimiter" TEXT,
  "job_delimiter_id" INTEGER,
  "error" TEXT,
  "note" TEXT,
  "_source_file" TEXT NOT NULL
);
CREATE TABLE "BitsQueue_Jobs" (
  "input_path" TEXT NOT NULL,
  "record_index" INTEGER NOT NULL,
  "container_format" TEXT,
  "container_table" TEXT,
  "container_record_index" INTEGER,
  "record_offset" INTEGER,
  "record_length" INTEGER,
  "container_record_id" TEXT,
  "blob_prefix_hex" TEXT,
  "job_type_raw" INTEGER,
  "priority_raw" INTEGER,
  "state_raw" INTEGER,
  "control_reserved_raw" INTEGER,
  "job_id" TEXT,
  "job_name" TEXT,
  "job_description" TEXT,
  "notify_command" TEXT,
  "notify_arguments" TEXT,
  "owner_sid" TEXT,
  "notify_flags_raw" INTEGER,
  "access_token_offset" INTEGER,
  "access_token_length" INTEGER,
  "transfer_section_kind" TEXT,
  "declared_file_count" INTEGER,
  "parsed_file_count" INTEGER,
  "file_reference_guids" TEXT,
  "error_count" INTEGER,
  "errors_json" TEXT,
  "transient_error_count" INTEGER,
  "retry_delay_raw" INTEGER,
  "timeout_raw" INTEGER,
  "created_raw" TEXT,
  "modified_raw" TEXT,
  "other_time0_raw" TEXT,
  "other_time1_raw" TEXT,
  "other_time2_raw" TEXT,
  "metadata_padding_hex" TEXT,
  "metadata_state" TEXT NOT NULL,
  "transfer_trailing_length" INTEGER,
  "metadata_trailing_length" INTEGER,
  "parse_status" TEXT NOT NULL,
  "parse_method" TEXT,
  "parse_error" TEXT,
  "record_blob" BLOB,
  "_source_file" TEXT NOT NULL
);
CREATE TABLE "BitsQueue_Files" (
  "input_path" TEXT NOT NULL,
  "record_index" INTEGER NOT NULL,
  "container_format" TEXT,
  "container_table" TEXT,
  "container_record_index" INTEGER,
  "record_offset" INTEGER,
  "record_length" INTEGER,
  "container_record_id" TEXT,
  "blob_prefix_hex" TEXT,
  "job_record_index" INTEGER,
  "job_id" TEXT,
  "link_basis" TEXT NOT NULL,
  "file_index_in_job" INTEGER,
  "dest_file" TEXT,
  "source_url" TEXT,
  "tmp_file" TEXT,
  "download_size_raw" TEXT,
  "transfer_size_raw" TEXT,
  "reserved_byte" INTEGER,
  "drive" TEXT,
  "volume_guid" TEXT,
  "trailing_filetime_raw" TEXT,
  "trailing_length" INTEGER,
  "parse_status" TEXT NOT NULL,
  "parse_method" TEXT,
  "parse_error" TEXT,
  "record_blob" BLOB,
  "_source_file" TEXT NOT NULL
);
CREATE INDEX "idx_BitsQueue_Files_candidates"
  ON "BitsQueue_Files" ("input_path", "job_record_index")
  WHERE "parse_status" = 'heuristic_boundary';
"#;

// ---------------------------------------------------------------------------
// facts
// ---------------------------------------------------------------------------

/// Discover and parse the queue inputs once, before the overview is derived.
///
/// Returns the host-relative facts database when it holds at least one row.
/// The schema is written in every case so a later run sees a real empty
/// result instead of a missing database.
pub(crate) fn prepare_inputs(out_dir: &Path, target: &Path, dataset_id: &str) -> Result<Vec<String>> {
    let dir = out_dir.join(ancillary::ANCILLARY_CATEGORY);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("보조 증거 폴더 생성: {}", dir.display()))?;
    let path = dir.join(format!("{DB_STEM}.sqlite"));
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 BITS 큐 증거 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("BITS 큐 증거 DB 생성: {}", path.display()))?;
    conn.execute_batch(CREATE_SQL)?;
    conn.execute_batch("BEGIN")?;

    let root = target.to_string_lossy().to_string();
    let available = target.is_dir();
    let (files, walk_errors) = if available {
        crate::finder::walk_files(target)
    } else {
        (Vec::new(), Vec::new())
    };
    let walk_error = walk_errors.first().cloned();
    let mut rows = 0usize;

    for input in bits_queue::discover_inputs(&files) {
        let note = match &walk_error {
            Some(error) => format!("{} / 탐색 경고: {error}", input.note),
            None => input.note.to_string(),
        };
        let Some(path_found) = input.path.clone() else {
            conn.execute(
                &insert_input_sql(),
                params![
                    input.kind,
                    input.pattern,
                    &root,
                    Option::<String>::None,
                    Option::<String>::None,
                    Option::<i64>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    "not_collected",
                    if available { "not_collected" } else { "target_unavailable" },
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<String>::None,
                    Option::<i64>::None,
                    Option::<String>::None,
                    note,
                    &root,
                ],
            )?;
            rows += 1;
            continue;
        };
        let display = path_found.to_string_lossy().to_string();
        let relative = path_found
            .strip_prefix(target)
            .unwrap_or(&path_found)
            .to_string_lossy()
            .to_string();
        if input.directory_only {
            conn.execute(
                &insert_input_sql(),
                params![
                    input.kind,
                    input.pattern,
                    &root,
                    &display,
                    &relative,
                    Option::<i64>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    "directory_collected",
                    "collected",
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<i64>::None,
                    Option::<String>::None,
                    Option::<i64>::None,
                    Option::<String>::None,
                    note,
                    &display,
                ],
            )?;
            rows += 1;
            continue;
        }

        let size = std::fs::metadata(&path_found).ok().map(|meta| meta.len() as i64);
        let parsed = bits_queue::parse_queue_file(&path_found);
        conn.execute(
            &insert_input_sql(),
            params![
                input.kind,
                input.pattern,
                &root,
                &display,
                &relative,
                size,
                parsed.format.as_str(),
                &parsed.format_detail,
                parsed.status,
                "collected",
                parsed.declared_job_count.map(i64::from),
                parsed.jobs.len() as i64,
                parsed.file_record_count(),
                parsed.failed_record_count(),
                &parsed.job_delimiter,
                parsed.job_delimiter_id,
                &parsed.error,
                note,
                &display,
            ],
        )?;
        rows += 1;
        rows += write_records(&conn, &display, &parsed)?;
    }

    conn.execute_batch("COMMIT")?;
    drop(conn);
    stamp_facts_generation(&path, dataset_id)?;
    Ok(if rows == 0 {
        Vec::new()
    } else {
        vec![QUEUE_DB.to_string()]
    })
}

fn insert_input_sql() -> String {
    format!(
        "INSERT INTO \"{INPUT_TABLE}\" (input_kind,search_pattern,search_root,input_path,relative_path,
         file_size,format,format_detail,status,collection_state,declared_job_count,job_record_count,
         file_record_count,failed_record_count,job_delimiter,job_delimiter_id,error,note,_source_file)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)"
    )
}

fn write_records(conn: &Connection, display: &str, parsed: &ParsedQueue) -> Result<usize> {
    let format = parsed.format.as_str();
    let mut written = 0usize;
    let mut job_statement = conn.prepare(&format!(
        "INSERT INTO \"{JOB_TABLE}\" (input_path,record_index,container_format,container_table,
         container_record_index,record_offset,record_length,container_record_id,blob_prefix_hex,
         job_type_raw,priority_raw,state_raw,control_reserved_raw,job_id,job_name,job_description,
         notify_command,notify_arguments,owner_sid,notify_flags_raw,access_token_offset,
         access_token_length,transfer_section_kind,declared_file_count,parsed_file_count,
         file_reference_guids,error_count,errors_json,transient_error_count,retry_delay_raw,
         timeout_raw,created_raw,modified_raw,other_time0_raw,other_time1_raw,other_time2_raw,
         metadata_padding_hex,metadata_state,transfer_trailing_length,metadata_trailing_length,
         parse_status,parse_method,parse_error,record_blob,_source_file)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,
         ?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,?42,?43,?44,?45)"
    ))?;
    for job in &parsed.jobs {
        job_statement.execute(params![
            display,
            job.record_index,
            format,
            &job.container_table,
            job.container_record_index,
            job.record_offset,
            job.record_length,
            &job.container_record_id,
            &job.blob_prefix_hex,
            job.job_type_raw.map(i64::from),
            job.priority_raw.map(i64::from),
            job.state_raw.map(i64::from),
            job.control_reserved_raw.map(i64::from),
            &job.job_id,
            &job.name,
            &job.description,
            &job.notify_command,
            &job.notify_arguments,
            &job.owner_sid,
            job.notify_flags_raw.map(i64::from),
            job.access_token_offset,
            job.access_token_length,
            job.transfer_section_kind,
            job.declared_file_count.map(i64::from),
            parsed_file_count(job),
            guid_list(&job.file_reference_guids),
            job.error_count.map(i64::from),
            errors_json(job),
            job.transient_error_count.map(i64::from),
            job.retry_delay_raw.map(i64::from),
            job.timeout_raw.map(i64::from),
            job.created_raw.map(|value| value.to_string()),
            job.modified_raw.map(|value| value.to_string()),
            job.other_time0_raw.map(|value| value.to_string()),
            job.other_time1_raw.map(|value| value.to_string()),
            job.other_time2_raw.map(|value| value.to_string()),
            &job.metadata_padding_hex,
            job.metadata_state,
            job.transfer_trailing_length,
            job.metadata_trailing_length,
            job.parse_status,
            job.parse_method,
            &job.parse_error,
            &job.blob,
            display,
        ])?;
        written += 1;
    }
    drop(job_statement);

    let mut file_statement = conn.prepare(&format!(
        "INSERT INTO \"{FILE_TABLE}\" (input_path,record_index,container_format,container_table,
         container_record_index,record_offset,record_length,container_record_id,blob_prefix_hex,
         job_record_index,job_id,link_basis,file_index_in_job,dest_file,source_url,tmp_file,
         download_size_raw,transfer_size_raw,reserved_byte,drive,volume_guid,trailing_filetime_raw,
         trailing_length,parse_status,parse_method,parse_error,record_blob,_source_file)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,
         ?24,?25,?26,?27,?28)"
    ))?;
    let mut sequence = 0i64;
    let nested = parsed.jobs.iter().flat_map(|job| job.files.iter());
    for file in nested.chain(parsed.files.iter()) {
        file_statement.execute(params![
            display,
            sequence,
            format,
            &file.container_table,
            file.container_record_index,
            file.record_offset,
            file.record_length,
            &file.container_record_id,
            &file.blob_prefix_hex,
            file.job_record_index,
            &file.job_id,
            file.link_basis,
            file.file_index_in_job,
            &file.dest_file,
            &file.source_url,
            &file.tmp_file,
            file.download_size.map(|value| value.to_string()),
            file.transfer_size.map(|value| value.to_string()),
            file.reserved_byte.map(i64::from),
            &file.drive,
            &file.volume_guid,
            file.trailing_filetime.map(|value| value.to_string()),
            file.trailing_length,
            file.parse_status,
            file.parse_method,
            &file.parse_error,
            &file.blob,
            display,
        ])?;
        sequence += 1;
        written += 1;
    }
    Ok(written)
}

/// A legacy job carries its file records; an ESE job carries the GUIDs of the
/// `Files` rows it references. Both are the files this record accounts for.
fn parsed_file_count(job: &QueueJob) -> i64 {
    match job.transfer_section_kind {
        Some("file_reference_guids") => job.file_reference_guids.len() as i64,
        // Rows that could not be read are evidence, not recovered files.
        _ => job
            .files
            .iter()
            .filter(|file| file.parse_status != "failed")
            .count() as i64,
    }
}

fn guid_list(values: &[String]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    serde_json::to_string(values).ok()
}

fn errors_json(job: &QueueJob) -> Option<String> {
    if job.errors.is_empty() {
        return None;
    }
    let items: Vec<serde_json::Value> = job
        .errors
        .iter()
        .map(|error| {
            serde_json::json!({
                "code": error.code.to_string(),
                "code_hex": format!("0x{:016X}", error.code),
                "stat1": error.stat1,
                "stat2": error.stat2,
                "stat3": error.stat3,
                "stat4": error.stat4,
                "reserved": error.reserved,
            })
        })
        .collect();
    serde_json::to_string(&items).ok()
}

// ---------------------------------------------------------------------------
// typed rows
// ---------------------------------------------------------------------------

struct InputRow {
    rowid: i64,
    kind: Option<String>,
    pattern: Option<String>,
    root: Option<String>,
    path: Option<String>,
    relative: Option<String>,
    size: Option<i64>,
    format: Option<String>,
    format_detail: Option<String>,
    status: String,
    collection_state: String,
    declared_job_count: Option<i64>,
    job_record_count: Option<i64>,
    file_record_count: Option<i64>,
    failed_record_count: Option<i64>,
    delimiter: Option<String>,
    delimiter_id: Option<i64>,
    error: Option<String>,
    note: Option<String>,
}

/// Write the queue evidence of this result: one row per discovered (or
/// missing) input plus the typed job and file snapshots of every input that
/// parsed.
pub(super) fn populate(ctx: &Ctx, db: &mut DerivedDb) -> Result<()> {
    let path = ctx.out_dir.join(QUEUE_DB);
    if !path.exists() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("BITS 큐 증거 읽기: {}", path.display()))?;

    let mut inputs: Vec<InputRow> = Vec::new();
    {
        let mut statement = conn.prepare(&format!(
            "SELECT rowid,input_kind,search_pattern,search_root,input_path,relative_path,file_size,
             format,format_detail,status,collection_state,declared_job_count,job_record_count,
             file_record_count,failed_record_count,job_delimiter,job_delimiter_id,error,note
             FROM \"{INPUT_TABLE}\" ORDER BY rowid"
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            inputs.push(InputRow {
                rowid: row.get(0)?,
                kind: row.get(1)?,
                pattern: row.get(2)?,
                root: row.get(3)?,
                path: row.get(4)?,
                relative: row.get(5)?,
                size: row.get(6)?,
                format: row.get(7)?,
                format_detail: row.get(8)?,
                status: row.get(9)?,
                collection_state: row.get(10)?,
                declared_job_count: row.get(11)?,
                job_record_count: row.get(12)?,
                file_record_count: row.get(13)?,
                failed_record_count: row.get(14)?,
                delimiter: row.get(15)?,
                delimiter_id: row.get(16)?,
                error: row.get(17)?,
                note: row.get(18)?,
            });
        }
    }

    let mut evidence_by_path: BTreeMap<String, String> = BTreeMap::new();
    for input in &inputs {
        let evidence_id = uuid::Uuid::new_v4().to_string();
        let source = ctx
            .facts
            .source_from_row(&path, INPUT_TABLE, input.rowid, input.path.as_deref(), Some(INPUT_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("BITS 큐 입력 출처를 확인하지 못했습니다"))?;
        db.insert_child(
            "BitsQueueEvidence",
            &[
                t(&evidence_id),
                t(ctx.host_id),
                t(ctx.dataset_id),
                opt(input.kind.as_deref()),
                opt(input.pattern.as_deref()),
                opt(input.root.as_deref()),
                opt(input.relative.as_deref()),
                opt(input.path.as_deref()),
                int_opt(input.size),
                t(&input.collection_state),
                t(parse_support(&input.status)),
                opt(input.note.as_deref()),
                opt(input.format.as_deref()),
                opt(input.format_detail.as_deref()),
                t(&input.status),
                int_opt(input.declared_job_count),
                int_opt(input.job_record_count),
                int_opt(input.file_record_count),
                int_opt(input.failed_record_count),
                opt(input.delimiter.as_deref()),
                int_opt(input.delimiter_id),
                opt(input.error.as_deref()),
                t(&source.dataset),
                t(&source.db),
                t(&source.table),
                Cell::Int(source.rowid),
            ],
        )?;
        if let Some(file) = &input.path {
            evidence_by_path.insert(file.clone(), evidence_id);
        }
    }

    let jobs = write_jobs(ctx, db, &conn, &path, &evidence_by_path)?;
    write_files(ctx, db, &conn, &path, &evidence_by_path, &jobs)?;
    Ok(())
}

/// Collection and support state stay separate: `parse_support` answers whether
/// this build can read the input, never whether it held data.
fn parse_support(status: &str) -> &'static str {
    match status {
        "parsed" => "parsed",
        "parsed_with_errors" => "parsed_with_errors",
        "truncated" => "truncated",
        "unsupported_format" => "unsupported_format",
        "open_failed" => "open_failed",
        "read_failed" => "read_failed",
        "directory_collected" => "not_applicable",
        _ => "not_collected",
    }
}

fn write_jobs(
    ctx: &Ctx,
    db: &mut DerivedDb,
    conn: &Connection,
    facts: &Path,
    evidence: &BTreeMap<String, String>,
) -> Result<BTreeMap<(String, i64), JobLink>> {
    let mut statement = conn.prepare(&format!(
        "SELECT rowid,input_path,record_index,container_format,container_table,container_record_index,
         record_offset,record_length,container_record_id,blob_prefix_hex,job_type_raw,priority_raw,
         state_raw,control_reserved_raw,job_id,job_name,job_description,notify_command,
         notify_arguments,owner_sid,notify_flags_raw,access_token_offset,access_token_length,
         transfer_section_kind,declared_file_count,parsed_file_count,file_reference_guids,error_count,
         errors_json,transient_error_count,retry_delay_raw,timeout_raw,created_raw,modified_raw,
         other_time0_raw,other_time1_raw,other_time2_raw,metadata_padding_hex,metadata_state,
         transfer_trailing_length,metadata_trailing_length,parse_status,parse_method,parse_error,
         record_blob
         FROM \"{JOB_TABLE}\" ORDER BY rowid"
    ))?;
    let mut candidate_count = conn.prepare(&format!(
        "SELECT COUNT(*) FROM \"{FILE_TABLE}\" WHERE input_path=?1 AND job_record_index=?2
         AND parse_status='heuristic_boundary'"
    ))?;
    let mut rows = statement.query([])?;
    let mut index: BTreeMap<(String, i64), JobLink> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let input_path: String = row.get(1)?;
        let record_index: i64 = row.get(2)?;
        let queue_job_id = uuid::Uuid::new_v4().to_string();
        let source = ctx
            .facts
            .source_from_row(facts, JOB_TABLE, rowid, Some(input_path.as_str()), Some(JOB_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("BITS 큐 작업 출처를 확인하지 못했습니다"))?;

        let job_type_raw: Option<i64> = row.get(10)?;
        let priority_raw: Option<i64> = row.get(11)?;
        let state_raw: Option<i64> = row.get(12)?;
        let job_id: Option<String> = row.get(14)?;
        let owner_sid: Option<String> = row.get(19)?;
        let flags_raw: Option<i64> = row.get(20)?;
        let (flag_names, unmapped) = match flags_raw {
            Some(value) if (0..=i64::from(u32::MAX)).contains(&value) => {
                let (names, rest) = notify_flags(value as u32);
                (
                    (!names.is_empty())
                        .then(|| serde_json::to_string(&names).unwrap_or_default()),
                    Some(i64::from(rest)),
                )
            }
            _ => (None, None),
        };
        let command: Option<String> = row.get(17)?;
        let command_resolved = command
            .as_deref()
            .map(|raw| ctx.meta.resolve_path(raw, owner_sid.as_deref()))
            .unwrap_or(Cell::Null);
        let declared: Option<i64> = row.get(24)?;
        let parsed_files: Option<i64> = row.get(25)?;
        // Records recovered past an undocumented trailer keep the count from
        // being presented as an established file list.
        let candidates: i64 = candidate_count.query_row(
            params![&input_path, record_index],
            |row| row.get(0),
        )?;
        let created_raw: Option<String> = row.get(32)?;
        let modified_raw: Option<String> = row.get(33)?;
        let other0_raw: Option<String> = row.get(34)?;
        let other1_raw: Option<String> = row.get(35)?;
        let other2_raw: Option<String> = row.get(36)?;
        let owner_name = owner_sid
            .as_deref()
            .and_then(|sid| ctx.meta.account_name(sid));
        let relative = relative_of(&input_path, ctx.target);

        db.insert_child(
            "BitsQueueJobs",
            &[
                t(&queue_job_id),
                t(ctx.host_id),
                t(ctx.dataset_id),
                opt(evidence.get(&input_path).map(String::as_str)),
                t(&input_path),
                opt(relative.as_deref()),
                opt(row.get::<_, Option<String>>(3)?.as_deref()),
                opt(row.get::<_, Option<String>>(4)?.as_deref()),
                int_opt(row.get(5)?),
                int_opt(row.get(6)?),
                int_opt(row.get(7)?),
                opt(row.get::<_, Option<String>>(8)?.as_deref()),
                opt(row.get::<_, Option<String>>(9)?.as_deref()),
                opt(job_id.as_deref()),
                t(if job_id.is_some() { "recorded" } else { "unrecorded" }),
                int_opt(job_type_raw),
                opt(enum_name(job_type_raw, job_type_name)),
                int_opt(priority_raw),
                opt(enum_name(priority_raw, job_priority_name)),
                int_opt(state_raw),
                opt(enum_name(state_raw, job_state_name)),
                int_opt(row.get(13)?),
                opt(row.get::<_, Option<String>>(15)?.as_deref()),
                opt(row.get::<_, Option<String>>(16)?.as_deref()),
                opt(command.as_deref()),
                command_resolved,
                opt(row.get::<_, Option<String>>(18)?.as_deref()),
                int_opt(flags_raw),
                opt(flag_names.as_deref()),
                int_opt(unmapped),
                opt(owner_sid.as_deref()),
                t(match owner_sid.as_deref() {
                    Some(value) if crate::derived::is_sid(value) => "recorded",
                    Some("") | None => "unrecorded",
                    Some(_) => "uninterpretable",
                }),
                opt(owner_name.as_deref()),
                t(if owner_name.is_some() {
                    "metadata_account_sid"
                } else {
                    "unresolved"
                }),
                int_opt(row.get(21)?),
                int_opt(row.get(22)?),
                opt(row.get::<_, Option<String>>(23)?.as_deref()),
                int_opt(declared),
                int_opt(parsed_files),
                t(count_state(declared, parsed_files, candidates)),
                opt(row.get::<_, Option<String>>(26)?.as_deref()),
                int_opt(row.get(27)?),
                opt(row.get::<_, Option<String>>(28)?.as_deref()),
                int_opt(row.get(29)?),
                int_opt(row.get(30)?),
                int_opt(row.get(31)?),
                filetime_cell(created_raw.as_deref()),
                opt(created_raw.as_deref()),
                filetime_cell(modified_raw.as_deref()),
                opt(modified_raw.as_deref()),
                filetime_cell(other0_raw.as_deref()),
                opt(other0_raw.as_deref()),
                filetime_cell(other1_raw.as_deref()),
                opt(other1_raw.as_deref()),
                filetime_cell(other2_raw.as_deref()),
                opt(other2_raw.as_deref()),
                opt(row.get::<_, Option<String>>(37)?.as_deref()),
                opt(row.get::<_, Option<String>>(38)?.as_deref()),
                int_opt(row.get(39)?),
                int_opt(row.get(40)?),
                opt(row.get::<_, Option<String>>(41)?.as_deref()),
                opt(row.get::<_, Option<String>>(42)?.as_deref()),
                opt(row.get::<_, Option<String>>(43)?.as_deref()),
                blob_cell(row.get::<_, Option<Vec<u8>>>(44)?),
                t(JOB_BASIS),
                t(&source.dataset),
                t(&source.db),
                t(&source.table),
                Cell::Int(source.rowid),
                opt(source.file.as_deref()),
            ],
        )?;
        index.insert(
            (input_path, record_index),
            JobLink { queue_job_id, owner_sid },
        );
    }
    Ok(index)
}

fn write_files(
    ctx: &Ctx,
    db: &mut DerivedDb,
    conn: &Connection,
    facts: &Path,
    evidence: &BTreeMap<String, String>,
    jobs: &BTreeMap<(String, i64), JobLink>,
) -> Result<()> {
    let mut statement = conn.prepare(&format!(
        "SELECT rowid,input_path,record_index,container_format,container_table,container_record_index,
         record_offset,record_length,container_record_id,blob_prefix_hex,job_record_index,job_id,
         link_basis,file_index_in_job,dest_file,source_url,tmp_file,download_size_raw,
         transfer_size_raw,reserved_byte,drive,volume_guid,trailing_filetime_raw,trailing_length,
         parse_status,parse_method,parse_error,record_blob
         FROM \"{FILE_TABLE}\" ORDER BY rowid"
    ))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let input_path: String = row.get(1)?;
        let source = ctx
            .facts
            .source_from_row(facts, FILE_TABLE, rowid, Some(input_path.as_str()), Some(FILE_ARTIFACT))?
            .ok_or_else(|| anyhow::anyhow!("BITS 큐 파일 출처를 확인하지 못했습니다"))?;
        let job_record_index: Option<i64> = row.get(10)?;
        let link = job_record_index.and_then(|index| jobs.get(&(input_path.clone(), index)));
        let queue_job_id = link.map(|link| link.queue_job_id.clone());
        let dest: Option<String> = row.get(14)?;
        let tmp: Option<String> = row.get(16)?;
        // A file record carries no owner of its own; only its job does.
        let owner = link.and_then(|link| link.owner_sid.clone());
        let dest_resolved = dest
            .as_deref()
            .map(|raw| ctx.meta.resolve_path(raw, owner.as_deref()))
            .unwrap_or(Cell::Null);
        let tmp_resolved = tmp
            .as_deref()
            .map(|raw| ctx.meta.resolve_path(raw, owner.as_deref()))
            .unwrap_or(Cell::Null);
        let parse_status: Option<String> = row.get(24)?;
        let download_raw: Option<String> = row.get(17)?;
        let transfer_raw: Option<String> = row.get(18)?;
        let trailing_raw: Option<String> = row.get(22)?;
        let relative = relative_of(&input_path, ctx.target);

        db.insert_child(
            "BitsQueueFiles",
            &[
                t(&uuid::Uuid::new_v4().to_string()),
                t(ctx.host_id),
                t(ctx.dataset_id),
                opt(evidence.get(&input_path).map(String::as_str)),
                opt(queue_job_id.as_deref()),
                t(&input_path),
                opt(relative.as_deref()),
                opt(row.get::<_, Option<String>>(3)?.as_deref()),
                opt(row.get::<_, Option<String>>(4)?.as_deref()),
                int_opt(row.get(5)?),
                int_opt(row.get(6)?),
                int_opt(row.get(7)?),
                opt(row.get::<_, Option<String>>(8)?.as_deref()),
                opt(row.get::<_, Option<String>>(9)?.as_deref()),
                int_opt(job_record_index),
                opt(row.get::<_, Option<String>>(11)?.as_deref()),
                opt(row.get::<_, Option<String>>(12)?.as_deref()),
                int_opt(row.get(13)?),
                opt(row.get::<_, Option<String>>(15)?.as_deref()),
                opt(dest.as_deref()),
                dest_resolved.clone(),
                super::path_state(dest.as_deref(), &dest_resolved),
                opt(tmp.as_deref()),
                tmp_resolved,
                opt(row.get::<_, Option<String>>(20)?.as_deref()),
                opt(row.get::<_, Option<String>>(21)?.as_deref()),
                size_value(download_raw.as_deref()),
                opt(download_raw.as_deref()),
                t(size_state(download_raw.as_deref())),
                size_value(transfer_raw.as_deref()),
                opt(transfer_raw.as_deref()),
                t(size_state(transfer_raw.as_deref())),
                int_opt(row.get(19)?),
                filetime_cell(trailing_raw.as_deref()),
                opt(trailing_raw.as_deref()),
                t(trailing_state(trailing_raw.as_deref())),
                int_opt(row.get(23)?),
                opt(parse_status.as_deref()),
                opt(row.get::<_, Option<String>>(25)?.as_deref()),
                opt(row.get::<_, Option<String>>(26)?.as_deref()),
                blob_cell(row.get::<_, Option<Vec<u8>>>(27)?),
                t(match parse_status.as_deref() {
                    Some("heuristic_boundary") => FILE_BASIS_HEURISTIC,
                    _ => FILE_BASIS,
                }),
                t(&source.dataset),
                t(&source.db),
                t(&source.table),
                Cell::Int(source.rowid),
                opt(source.file.as_deref()),
            ],
        )?;
    }
    Ok(())
}

/// The job row a file record belongs to, with the owner recorded on that job.
struct JobLink {
    queue_job_id: String,
    owner_sid: Option<String>,
}

fn relative_of(path: &str, target: &Path) -> Option<String> {
    let full = Path::new(path);
    full.strip_prefix(target)
        .ok()
        .map(|value| value.to_string_lossy().to_string())
}

fn enum_name(raw: Option<i64>, lookup: fn(u32) -> Option<&'static str>) -> Option<&'static str> {
    let raw = raw?;
    if !(0..=i64::from(u32::MAX)).contains(&raw) {
        return None;
    }
    lookup(raw as u32)
}

fn count_state(declared: Option<i64>, parsed: Option<i64>, candidates: i64) -> &'static str {
    match (declared, parsed) {
        (Some(declared), Some(parsed)) if declared == parsed && candidates > 0 => {
            "matches_with_unproven_boundary"
        }
        (Some(declared), Some(parsed)) if declared == parsed => "matches",
        (Some(_), Some(_)) => "mismatch",
        _ => "unknown",
    }
}

fn filetime_cell(raw: Option<&str>) -> Cell {
    let Some(raw) = raw else {
        return Cell::Null;
    };
    let Ok(value) = raw.parse::<u64>() else {
        return Cell::Null;
    };
    if value == 0 || value > i64::MAX as u64 {
        return Cell::Null;
    }
    match fmt_filetime(value as i64) {
        formatted if formatted.is_empty() => Cell::Null,
        formatted => Cell::Text(formatted),
    }
}

fn size_value(raw: Option<&str>) -> Cell {
    match raw.and_then(|raw| raw.parse::<u64>().ok()) {
        Some(value) if value == bits_queue::SIZE_UNKNOWN => Cell::Null,
        Some(value) if value <= i64::MAX as u64 => Cell::Int(value as i64),
        _ => Cell::Null,
    }
}

/// `BG_SIZE_UNKNOWN` means "not known yet", never a real size.
fn size_state(raw: Option<&str>) -> &'static str {
    match raw.map(|raw| raw.parse::<u64>()) {
        None => "unrecorded",
        Some(Ok(value)) if value == bits_queue::SIZE_UNKNOWN => "unknown_sentinel",
        Some(Ok(value)) if value <= i64::MAX as u64 => "recorded",
        _ => "uninterpretable",
    }
}

/// The FILETIME that follows an ESE file record has no documented meaning; it
/// is preserved, not named.
fn trailing_state(raw: Option<&str>) -> &'static str {
    match raw.map(|raw| raw.parse::<u64>()) {
        None => "absent",
        Some(Ok(0)) => "zero",
        Some(Ok(_)) => "recorded_meaning_unverified",
        _ => "uninterpretable",
    }
}

fn blob_cell(value: Option<Vec<u8>>) -> Cell {
    match value {
        Some(bytes) => Cell::Blob(bytes),
        None => Cell::Null,
    }
}

