//! Typed error reporting storage: report files and the application error,
//! hang and reporting events, each kept as its own record with its own
//! signature rows, recorded paths, identifier relations and read status.
use std::collections::BTreeMap;

use anyhow::{anyhow, Result};

use super::schema::{ChildSpec, DbSpec};
use super::{int, is_sid, nz, text, text_raw, Cell, Ctx, DerivedDb, Record, SourceRef};
use crate::overview::EventLogOverviewCache;
use crate::wer_evidence::{self, Origin, WerRecord};

/// Counts and sizes are stored as INTEGER so a real 0 differs from NULL.
const INT_COLUMNS: &[&str] = &[
    "app_pid", "app_uptime_ms", "report_status_raw", "event_id", "report_byte_size",
    "report_line_count", "report_entry_count", "report_unparsed_line_count",
];

/// Evidence bodies keep their own whitespace.
const RAW_COLUMNS: &[&str] = &[
    "report", "report_text", "report_entries_json", "event_data_raw", "attached_files_raw",
];

fn cell_for(column: &str, value: &str) -> Cell {
    if INT_COLUMNS.contains(&column) {
        int(value)
    } else if RAW_COLUMNS.contains(&column) {
        text_raw(value)
    } else {
        text(value)
    }
}

/// `\\?\` only tells the Win32 API to skip path parsing; the rest is the
/// recorded path. Nothing else is rewritten.
fn normalize_path(raw: &str) -> String {
    raw.strip_prefix("\\\\?\\").unwrap_or(raw).to_string()
}

fn file_name_of(path: &str) -> String {
    path.replace('/', "\\")
        .rsplit('\\')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The recording subject of an event is stored in its own role; it is never
/// promoted to the application's owner.
fn resolve_account(ctx: &Ctx, item: &mut WerRecord) {
    let sid = item.get("record_subject_sid").to_string();
    if !is_sid(&sid) {
        return;
    }
    item.set("account_sid", sid.clone());
    if let Some(name) = ctx.meta.account_name(&sid) {
        item.set("account", name.clone());
        item.set("record_subject_account", name);
    }
}

fn order_key(item: &WerRecord) -> (bool, &str, &'static str, &str) {
    (
        item.timestamp.is_empty(),
        item.timestamp.as_str(),
        item.origin.key(),
        item.record_key.as_str(),
    )
}

fn source(ctx: &Ctx, item: &WerRecord) -> Result<SourceRef> {
    let label = item.origin.description();
    let file = nz(&item.source_file);
    let found = match item.source_rowid {
        Some(rowid) => ctx.facts.source_from_row(
            &ctx.out_dir.join("WER").join("WER_Reports.sqlite"),
            "WER_Reports",
            rowid,
            file,
            Some(label),
        )?,
        None => {
            ctx.facts
                .source_from_record_key(&item.record_key, Some("EventData"), file, Some(label))?
        }
    };
    found.ok_or_else(|| {
        anyhow!(
            "오류 보고 레코드의 원본 근거를 찾지 못했습니다: {}",
            item.record_key
        )
    })
}

fn record(ctx: &Ctx, item: &WerRecord) -> Result<Record> {
    let mut record = ctx.record(&SPEC);
    record.timestamp(&item.timestamp, item.origin.timestamp_kind());
    record.set("event_type", text(item.origin.stage()));
    for (column, value) in &item.fields {
        record.set(column, cell_for(column, value));
    }
    // A stored empty payload stays an empty TEXT; only a missing one is NULL.
    if item.get("payload_state") == "present_empty" {
        let column = match item.origin {
            Origin::ReportFile => "report_text",
            _ => "event_data_raw",
        };
        record.set(column, Cell::Text(String::new()));
    }
    record.set(
        "app_path_resolved",
        ctx.meta.resolve_path(item.get("app_path"), None),
    );
    record.set(
        "module_path_resolved",
        ctx.meta.resolve_path(item.get("module_path"), None),
    );
    if let Some(store) = nz(item.get("store_path")) {
        record.set("store_path_normalized", text(&normalize_path(store)));
    }
    // Raw status value plus its hexadecimal form; no meaning is invented.
    if let Ok(status) = item.get("report_status_raw").trim().parse::<i64>() {
        record.set("report_status_hex", text(&format!("0x{status:x}")));
    }
    record.set("signature_count", Cell::Int(item.signatures.len() as i64));
    record.set("path_count", Cell::Int(item.paths.len() as i64));
    record.set("search_text", Cell::Text(item.search_text()));
    for signature in &item.signatures {
        record.child(
            "WerSignatures",
            vec![
                Cell::Text(signature.family.clone()),
                signature.original_index.map(Cell::Int).unwrap_or(Cell::Null),
                signature.array_position.map(Cell::Int).unwrap_or(Cell::Null),
                signature
                    .label
                    .clone()
                    .map(Cell::Text)
                    .unwrap_or(Cell::Null),
                signature
                    .label_field
                    .map(|field| Cell::Text(field.to_string()))
                    .unwrap_or(Cell::Null),
                signature
                    .value
                    .clone()
                    .map(Cell::Text)
                    .unwrap_or(Cell::Null),
                Cell::Int(i64::from(signature.value_present)),
                signature
                    .role
                    .map(|role| Cell::Text(role.to_string()))
                    .unwrap_or(Cell::Null),
                signature
                    .p_field
                    .clone()
                    .map(Cell::Text)
                    .unwrap_or(Cell::Null),
                Cell::Text(signature.basis.to_string()),
            ],
        );
    }
    for path in &item.paths {
        let normalized = normalize_path(&path.raw);
        let resolved = ctx.meta.resolve_path(&path.raw, None);
        let status = match (&resolved, path.raw.contains('%')) {
            (Cell::Text(_), _) => "resolved",
            (_, true) => "unresolved",
            _ => "literal",
        };
        record.child(
            "WerPaths",
            vec![
                Cell::Text(path.role.to_string()),
                Cell::Text(path.raw.clone()),
                Cell::Text(normalized.clone()),
                text(&file_name_of(&normalized)),
                text(&file_name_of(&normalized).to_lowercase()),
                resolved,
                Cell::Text(status.to_string()),
                Cell::Text(path.basis.to_string()),
            ],
        );
    }
    record.source(Some(source(ctx, item)?));
    Ok(record)
}

/// Records that share an identifier value are related, not merged: the same
/// identifier appearing in several stages is evidence of those stages.
fn relations(items: &[WerRecord], records: &[Record]) -> (Vec<Vec<Cell>>, Vec<i64>) {
    let mut groups: BTreeMap<String, Vec<(usize, &'static str, String)>> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        for identifier in &item.identifiers {
            groups
                .entry(identifier.value.to_lowercase())
                .or_default()
                .push((index, identifier.role, identifier.value.clone()));
        }
    }
    let mut ordinals = vec![0i64; items.len()];
    let mut rows = Vec::new();
    for members in groups.values() {
        for (index, role, value) in members {
            for (other, other_role, _) in members {
                if other == index {
                    continue;
                }
                rows.push(vec![
                    Cell::Text(records[*index].record_id.clone()),
                    Cell::Int(ordinals[*index]),
                    Cell::Text(records[*other].record_id.clone()),
                    Cell::Text("identifier_match".to_string()),
                    Cell::Text((*role).to_string()),
                    Cell::Text((*other_role).to_string()),
                    Cell::Text(value.clone()),
                    Cell::Text(items[*other].origin.key().to_string()),
                    Cell::Text(items[*other].origin.stage().to_string()),
                    text(&items[*other].timestamp),
                ]);
                ordinals[*index] += 1;
            }
        }
    }
    (rows, ordinals)
}

#[derive(Default)]
struct LogCounts {
    total: i64,
    reporting: i64,
    app_error: i64,
    app_hang: i64,
    first: Option<String>,
    last: Option<String>,
}

impl LogCounts {
    fn observe(&mut self, item: &WerRecord) {
        self.total += 1;
        match item.origin {
            Origin::Reporting1001 => self.reporting += 1,
            Origin::AppError1000 => self.app_error += 1,
            Origin::AppHang1002 => self.app_hang += 1,
            Origin::ReportFile => {}
        }
        if !item.timestamp.is_empty() {
            let time = item.timestamp.clone();
            self.first = Some(match self.first.take() {
                Some(current) => current.min(time.clone()),
                None => time.clone(),
            });
            self.last = Some(match self.last.take() {
                Some(current) => current.max(time),
                None => time,
            });
        }
    }
}

/// Collection evidence so that a missing source, an empty source and an empty
/// query result stay distinguishable.
fn observations(ctx: &Ctx, db: &mut DerivedDb, items: &[WerRecord]) -> Result<()> {
    let facts = ctx.out_dir.join("WER").join("WER_Reports.sqlite");
    let found = ctx.facts.by_path(&facts);
    let generation = found.map(|db| ctx.facts.generation(db)).transpose()?;
    let mut reports = LogCounts::default();
    let mut failed = 0i64;
    for item in items.iter().filter(|item| item.origin == Origin::ReportFile) {
        reports.observe(item);
        if item.get("parse_status") != "parsed" {
            failed += 1;
        }
    }
    let state = match (found.is_some(), reports.total) {
        (false, _) => "not_collected",
        (true, 0) => "collected_empty",
        _ => "collected",
    };
    db.insert_child(
        "WerObservations",
        &[
            Cell::Text(uuid::Uuid::new_v4().to_string()),
            Cell::Text(ctx.host_id.to_string()),
            Cell::Text(ctx.dataset_id.to_string()),
            Cell::Text("report_file".to_string()),
            Cell::Text("WER_Reports".to_string()),
            found
                .map(|db| Cell::Text(db.relative.clone()))
                .unwrap_or(Cell::Null),
            found.map(|_| Cell::Text("WER_Reports".to_string())).unwrap_or(Cell::Null),
            generation.map(Cell::Text).unwrap_or(Cell::Null),
            Cell::Text(state.to_string()),
            Cell::Int(reports.total),
            Cell::Int(reports.total - failed),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Int(failed),
            reports.first.map(Cell::Text).unwrap_or(Cell::Null),
            reports.last.map(Cell::Text).unwrap_or(Cell::Null),
            Cell::Text(
                "입력은 확장자가 .wer인 파일 전부이며, 읽기 실패 보고서도 행으로 남습니다"
                    .to_string(),
            ),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
        ],
    )?;

    let mut logs: BTreeMap<String, LogCounts> = BTreeMap::new();
    for item in items.iter().filter(|item| item.origin != Origin::ReportFile) {
        let table = item
            .record_key
            .split("::")
            .next()
            .unwrap_or_default()
            .to_string();
        logs.entry(table).or_default().observe(item);
    }
    if logs.is_empty() {
        logs.insert("Application".to_string(), LogCounts::default());
    }
    for (table, counts) in logs {
        let found = ctx.facts.by_stem(&table);
        let generation = found.map(|db| ctx.facts.generation(db)).transpose()?;
        let state = match (found.is_some(), counts.total) {
            (false, _) => "not_collected",
            (true, 0) => "collected_empty",
            _ => "collected",
        };
        db.insert_child(
            "WerObservations",
            &[
                Cell::Text(uuid::Uuid::new_v4().to_string()),
                Cell::Text(ctx.host_id.to_string()),
                Cell::Text(ctx.dataset_id.to_string()),
                Cell::Text("eventlog".to_string()),
                Cell::Text(table.clone()),
                found
                    .map(|db| Cell::Text(db.relative.clone()))
                    .unwrap_or(Cell::Null),
                found.map(|_| Cell::Text(table.clone())).unwrap_or(Cell::Null),
                generation.map(Cell::Text).unwrap_or(Cell::Null),
                Cell::Text(state.to_string()),
                Cell::Int(counts.total),
                Cell::Null,
                Cell::Int(counts.reporting),
                Cell::Int(counts.app_error),
                Cell::Int(counts.app_hang),
                Cell::Null,
                counts.first.map(Cell::Text).unwrap_or(Cell::Null),
                counts.last.map(Cell::Text).unwrap_or(Cell::Null),
                Cell::Text(
                    "Windows 오류 보고/1001·응용 프로그램 오류/1000·중단/1002만 편입하며, \
                     WER 채널의 업로드 상태 기록은 보고서가 아니므로 원본 로그로만 남습니다"
                        .to_string(),
                ),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn build(ctx: &Ctx, events: &EventLogOverviewCache) -> Result<usize> {
    let mut items = wer_evidence::collect(ctx.out_dir, events)?;
    for item in items.iter_mut() {
        resolve_account(ctx, item);
    }
    // Stable order: time, then source kind and the original row key.
    items.sort_by(|left, right| order_key(left).cmp(&order_key(right)));
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut records = Vec::with_capacity(items.len());
    for item in &items {
        records.push(record(ctx, item)?);
    }
    let (relation_rows, counts) = relations(&items, &records);
    for (index, mut record) in records.into_iter().enumerate() {
        record.set("relation_count", Cell::Int(counts[index]));
        db.write(record)?;
    }
    for row in relation_rows {
        db.insert_child("WerRelations", &row)?;
    }
    observations(ctx, &mut db, &items)?;
    db.finish()
}

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "WerReports" (
  "record_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "timestamp" TEXT,
  "overview_name" TEXT NOT NULL,
  "account" TEXT,
  "account_sid" TEXT,
  "timestamp_kind" TEXT,
  "event_type" TEXT,
  "description" TEXT,
  "origin" TEXT NOT NULL,
  "reporting_stage" TEXT NOT NULL,
  "source" TEXT NOT NULL,
  "error_type" TEXT,
  "error_class" TEXT,
  "error_class_basis" TEXT,
  "signature_schema" TEXT,
  "signature_schema_status" TEXT,
  "signature_index_source" TEXT,
  "payload_format" TEXT,
  "payload_state" TEXT,
  "friendly_event_name" TEXT,
  "consent_key" TEXT,
  "report_description" TEXT,
  "app_name" TEXT,
  "app_name_field" TEXT,
  "signature_app_name" TEXT,
  "app_version" TEXT,
  "app_timestamp" TEXT,
  "app_path" TEXT,
  "app_path_resolved" TEXT,
  "app_path_status" TEXT,
  "original_filename" TEXT,
  "ns_app_name" TEXT,
  "ns_partner" TEXT,
  "ns_group" TEXT,
  "target_app_id" TEXT,
  "target_app_ver" TEXT,
  "target_as_id" TEXT,
  "application_identity" TEXT,
  "metadata_hash" TEXT,
  "module_name" TEXT,
  "module_version" TEXT,
  "module_timestamp" TEXT,
  "module_path" TEXT,
  "module_path_resolved" TEXT,
  "exception_code" TEXT,
  "exception_offset" TEXT,
  "exception_data" TEXT,
  "hang_signature" TEXT,
  "hang_type_raw" TEXT,
  "hang_type_text" TEXT,
  "waiting_app_name" TEXT,
  "waiting_app_version" TEXT,
  "install_status" TEXT,
  "install_source" TEXT,
  "hresult" TEXT,
  "client_app_id" TEXT,
  "os_version_raw" TEXT,
  "os_revision" TEXT,
  "device_class" TEXT,
  "product_hash" TEXT,
  "report_identifier" TEXT,
  "integrator_report_identifier" TEXT,
  "report_id" TEXT,
  "integrator_report_id" TEXT,
  "app_pid" INTEGER,
  "app_pid_raw" TEXT,
  "app_session_guid" TEXT,
  "app_start_time" TEXT,
  "app_start_time_raw" TEXT,
  "app_start_time_source" TEXT,
  "app_uptime" TEXT,
  "app_uptime_ms" INTEGER,
  "app_uptime_basis" TEXT,
  "termination_time_raw" TEXT,
  "event_time_raw" TEXT,
  "event_time_source" TEXT,
  "event_time_precision" TEXT,
  "upload_time" TEXT,
  "upload_time_raw" TEXT,
  "report_status_raw" INTEGER,
  "report_status_hex" TEXT,
  "store_path" TEXT,
  "store_path_normalized" TEXT,
  "store_location" TEXT,
  "store_location_basis" TEXT,
  "consent_raw" TEXT,
  "bucket" TEXT,
  "bucket_type" TEXT,
  "hashed_bucket" TEXT,
  "response_text" TEXT,
  "response_bucket_id" TEXT,
  "response_bucket_table" TEXT,
  "response_legacy_bucket_id" TEXT,
  "response_type" TEXT,
  "cab_id" TEXT,
  "cab_guid" TEXT,
  "rechecking_raw" TEXT,
  "analysis_symbol" TEXT,
  "attached_files_raw" TEXT,
  "is_fatal_raw" TEXT,
  "boot_id" TEXT,
  "wow64_host" TEXT,
  "wow64_guest" TEXT,
  "etw_non_collect_reason" TEXT,
  "report_version_raw" TEXT,
  "report_type_raw" TEXT,
  "package_full_name" TEXT,
  "package_relative_app_id" TEXT,
  "provider" TEXT,
  "channel" TEXT,
  "computer" TEXT,
  "event_id" INTEGER,
  "event_record_id" TEXT,
  "level_name" TEXT,
  "keywords_raw" TEXT,
  "logging_process_id" TEXT,
  "logging_thread_id" TEXT,
  "activity_id" TEXT,
  "related_activity_id" TEXT,
  "record_subject_sid" TEXT,
  "record_subject_account" TEXT,
  "account_role" TEXT,
  "app_account_status" TEXT,
  "facts_status" TEXT,
  "facts_error" TEXT,
  "event_data_raw" TEXT,
  "report" TEXT,
  "report_text" TEXT,
  "report_entries_json" TEXT,
  "report_encoding" TEXT,
  "report_decode_status" TEXT,
  "report_decode_error" TEXT,
  "report_byte_size" INTEGER,
  "report_line_count" INTEGER,
  "report_entry_count" INTEGER,
  "report_unparsed_line_count" INTEGER,
  "parse_status" TEXT NOT NULL,
  "parse_error" TEXT,
  "signature_count" INTEGER NOT NULL,
  "path_count" INTEGER NOT NULL,
  "relation_count" INTEGER NOT NULL,
  "record_key" TEXT,
  "source_file" TEXT,
  "search_text" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'WerReports'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(origin IN ('report_file','eventlog_1001','eventlog_1000','eventlog_1002')),
  CHECK(app_path_status IS NULL OR app_path_status IN ('recorded','not_recorded')),
  CHECK(signature_schema IS NULL OR signature_schema_status = 'mapped')
);
CREATE INDEX "idx_WerReports_time" ON "WerReports"(timestamp, record_id);
CREATE INDEX "idx_WerReports_account" ON "WerReports"(account_sid, timestamp);
CREATE INDEX "idx_WerReports_type" ON "WerReports"(error_type, timestamp);
CREATE INDEX "idx_WerReports_report_identifier" ON "WerReports"(report_identifier);
CREATE INDEX "idx_WerReports_report_id" ON "WerReports"(report_id);
CREATE TABLE "source_records" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_dataset_id" TEXT NOT NULL,
  "source_artifact" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_field" TEXT,
  "source_record_key" TEXT,
  "source_file" TEXT,
  "source_label" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "WerReports"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "WerSignatures" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "family" TEXT NOT NULL,
  "original_index" INTEGER,
  "array_position" INTEGER,
  "label" TEXT,
  "label_field" TEXT,
  "value" TEXT,
  "value_present" INTEGER NOT NULL CHECK(value_present IN (0,1)),
  "role" TEXT,
  "p_field" TEXT,
  "basis" TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(basis IN ('report_entry','event_p_field')),
  FOREIGN KEY(record_id) REFERENCES "WerReports"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_WerSignatures_role" ON "WerSignatures"(role, value);
CREATE TABLE "WerPaths" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "path_role" TEXT NOT NULL,
  "path_raw" TEXT NOT NULL,
  "path_normalized" TEXT NOT NULL,
  "file_name" TEXT,
  "file_name_lower" TEXT,
  "path_resolved" TEXT,
  "resolution_status" TEXT NOT NULL,
  "path_basis" TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(path_role IN ('app_path','module_path','loaded_module','store_path','attached_file','report_file')),
  CHECK(resolution_status IN ('resolved','literal','unresolved')),
  CHECK(path_basis IN ('report_scalar','report_entry','event_payload','collected_file_location')),
  FOREIGN KEY(record_id) REFERENCES "WerReports"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_WerPaths_name" ON "WerPaths"(file_name_lower, path_role);
CREATE TABLE "WerRelations" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "related_record_id" TEXT NOT NULL,
  "relation_kind" TEXT NOT NULL,
  "self_field" TEXT NOT NULL,
  "related_field" TEXT NOT NULL,
  "matched_value" TEXT NOT NULL,
  "related_origin" TEXT NOT NULL,
  "related_stage" TEXT NOT NULL,
  "related_timestamp" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(relation_kind = 'identifier_match'),
  CHECK(record_id <> related_record_id),
  FOREIGN KEY(record_id) REFERENCES "WerReports"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(related_record_id) REFERENCES "WerReports"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_WerRelations_value" ON "WerRelations"(matched_value);
CREATE TABLE "WerObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "source_name" TEXT NOT NULL,
  "facts_db" TEXT,
  "facts_table" TEXT,
  "facts_generation" TEXT,
  "collection_state" TEXT NOT NULL,
  "record_count" INTEGER,
  "report_count" INTEGER,
  "event_1001_count" INTEGER,
  "event_1000_count" INTEGER,
  "event_1002_count" INTEGER,
  "failed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "note" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(observation_id),
  CHECK(scope IN ('report_file','eventlog')),
  CHECK(collection_state IN ('collected','collected_empty','not_collected')),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL))
);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('wer_reports',3);
"#;

const MAIN: &[&str] = &[
    "record_id", "host_id", "dataset_id", "timestamp", "overview_name", "account",
    "account_sid", "timestamp_kind", "event_type", "description",
    "origin", "reporting_stage", "source", "error_type", "error_class", "error_class_basis",
    "signature_schema", "signature_schema_status", "signature_index_source", "payload_format",
    "payload_state",
    "friendly_event_name", "consent_key", "report_description",
    "app_name", "app_name_field", "signature_app_name", "app_version", "app_timestamp",
    "app_path", "app_path_resolved", "app_path_status",
    "original_filename", "ns_app_name", "ns_partner", "ns_group",
    "target_app_id", "target_app_ver", "target_as_id", "application_identity", "metadata_hash",
    "module_name", "module_version", "module_timestamp", "module_path", "module_path_resolved",
    "exception_code", "exception_offset", "exception_data",
    "hang_signature", "hang_type_raw", "hang_type_text", "waiting_app_name", "waiting_app_version",
    "install_status", "install_source", "hresult", "client_app_id", "os_version_raw",
    "os_revision", "device_class", "product_hash",
    "report_identifier", "integrator_report_identifier", "report_id", "integrator_report_id",
    "app_pid", "app_pid_raw", "app_session_guid",
    "app_start_time", "app_start_time_raw", "app_start_time_source",
    "app_uptime", "app_uptime_ms", "app_uptime_basis", "termination_time_raw",
    "event_time_raw", "event_time_source", "event_time_precision",
    "upload_time", "upload_time_raw",
    "report_status_raw", "report_status_hex",
    "store_path", "store_path_normalized", "store_location", "store_location_basis",
    "consent_raw", "bucket", "bucket_type", "hashed_bucket", "response_text",
    "response_bucket_id", "response_bucket_table", "response_legacy_bucket_id", "response_type",
    "cab_id", "cab_guid", "rechecking_raw", "analysis_symbol", "attached_files_raw",
    "is_fatal_raw", "boot_id", "wow64_host", "wow64_guest", "etw_non_collect_reason",
    "report_version_raw", "report_type_raw", "package_full_name", "package_relative_app_id",
    "provider", "channel", "computer", "event_id", "event_record_id", "level_name",
    "keywords_raw", "logging_process_id", "logging_thread_id", "activity_id",
    "related_activity_id",
    "record_subject_sid", "record_subject_account", "account_role", "app_account_status",
    "facts_status", "facts_error",
    "event_data_raw", "report", "report_text", "report_entries_json",
    "report_encoding", "report_decode_status", "report_decode_error",
    "report_byte_size", "report_line_count", "report_entry_count", "report_unparsed_line_count",
    "parse_status", "parse_error",
    "signature_count", "path_count", "relation_count",
    "record_key", "source_file", "search_text",
];

const SOURCE_RECORDS: &[&str] = &[
    "record_id", "ordinal", "source_dataset_id", "source_artifact", "source_db",
    "source_table", "source_rowid", "source_field", "source_record_key", "source_file",
    "source_label",
];

const WER_SIGNATURES: &[&str] = &[
    "record_id", "ordinal", "family", "original_index", "array_position", "label",
    "label_field", "value", "value_present", "role", "p_field", "basis",
];

const WER_PATHS: &[&str] = &[
    "record_id", "ordinal", "path_role", "path_raw", "path_normalized", "file_name",
    "file_name_lower", "path_resolved", "resolution_status", "path_basis",
];

const WER_RELATIONS: &[&str] = &[
    "record_id", "ordinal", "related_record_id", "relation_kind", "self_field",
    "related_field", "matched_value", "related_origin", "related_stage", "related_timestamp",
];

const WER_OBSERVATIONS: &[&str] = &[
    "observation_id", "host_id", "dataset_id", "scope", "source_name", "facts_db",
    "facts_table", "facts_generation", "collection_state", "record_count", "report_count",
    "event_1001_count", "event_1000_count", "event_1002_count", "failed_count",
    "first_observed_time", "last_observed_time", "note", "source_dataset_id", "source_db",
    "source_table", "source_rowid",
];

pub(super) const SPEC: DbSpec = DbSpec {
    name: "WerReports",
    table: "WerReports",
    columns: MAIN,
    children: &[
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
        ChildSpec { table: "WerSignatures", columns: WER_SIGNATURES },
        ChildSpec { table: "WerPaths", columns: WER_PATHS },
        ChildSpec { table: "WerRelations", columns: WER_RELATIONS },
        ChildSpec { table: "WerObservations", columns: WER_OBSERVATIONS },
    ],
    ddl: DDL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::sqlite::Row;
    use rusqlite::Connection;

    const APPCRASH_ENTRIES: &str = r#"[
        {"line":1,"key":"Sig[0].Name","family":"Sig","index":0,"sub":"Name","value":"응용 프로그램 이름"},
        {"line":2,"key":"Sig[0].Value","family":"Sig","index":0,"sub":"Value","value":"app.exe"},
        {"line":3,"key":"Sig[3].Name","family":"Sig","index":3,"sub":"Name","value":"오류 모듈 이름"},
        {"line":4,"key":"Sig[3].Value","family":"Sig","index":3,"sub":"Value","value":"ntdll.dll"},
        {"line":5,"key":"Sig[6].Name","family":"Sig","index":6,"sub":"Name","value":"예외 코드"},
        {"line":6,"key":"Sig[6].Value","family":"Sig","index":6,"sub":"Value","value":"c00000fd"},
        {"line":7,"key":"Sig[7].Name","family":"Sig","index":7,"sub":"Name","value":"예외 오프셋"},
        {"line":8,"key":"Sig[7].Value","family":"Sig","index":7,"sub":"Value","value":"00029787"},
        {"line":9,"key":"DynamicSig[1].Name","family":"DynamicSig","index":1,"sub":"Name","value":"OS 버전"},
        {"line":10,"key":"DynamicSig[1].Value","family":"DynamicSig","index":1,"sub":"Value","value":"10.0"},
        {"line":11,"key":"LoadedModule[0]","family":"LoadedModule","index":0,"value":"C:\\WINDOWS\\ntdll.dll"}
    ]"#;

    const STORE_AGENT_ENTRIES: &str = r#"[
        {"line":1,"key":"Sig[0].Name","family":"Sig","index":0,"sub":"Name","value":"ClientAppId"},
        {"line":2,"key":"Sig[0].Value","family":"Sig","index":0,"sub":"Value","value":"Update;"},
        {"line":3,"key":"Sig[1].Name","family":"Sig","index":1,"sub":"Name","value":"HResult"},
        {"line":4,"key":"Sig[1].Value","family":"Sig","index":1,"sub":"Value","value":"80070005"},
        {"line":5,"key":"Sig[2].Name","family":"Sig","index":2,"sub":"Name","value":"OSVersion"},
        {"line":6,"key":"Sig[2].Value","family":"Sig","index":2,"sub":"Value","value":"26100"},
        {"line":7,"key":"Sig[3].Name","family":"Sig","index":3,"sub":"Name","value":"OSRevision"},
        {"line":8,"key":"Sig[3].Value","family":"Sig","index":3,"sub":"Value","value":"32230"}
    ]"#;

    fn facts_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("wina-wer-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("WER")).unwrap();
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        root
    }

    fn write_report_facts(root: &std::path::Path, rows: &[(&str, &str, &str, &str, &str, &str)]) {
        let path = root.join("WER/WER_Reports.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE WER_Reports(timestamp TEXT,EventType TEXT,AppName TEXT,AppPath TEXT,
             TargetAppId TEXT,ReportIdentifier TEXT,report TEXT,report_text TEXT,entries_json TEXT,
             encoding TEXT,decode_status TEXT,decode_error TEXT,byte_size TEXT,line_count TEXT,
             entry_count TEXT,unparsed_line_count TEXT,_status TEXT,_error TEXT,_source_file TEXT);",
        )
        .unwrap();
        for (timestamp, event_type, identifier, report, entries, source) in rows {
            let status = if report.is_empty() {
                "unreadable_file"
            } else {
                "parsed"
            };
            let error = if report.is_empty() { "permission denied" } else { "" };
            conn.execute(
                "INSERT INTO WER_Reports VALUES(?1,?2,'App','C:\\Program Files\\app.exe','W:app',?3,?4,
                 'EventType=x',?5,'utf-16le-bom','ok',NULL,'4096','120','118','2',?6,?7,?8)",
                rusqlite::params![timestamp, event_type, identifier, report, entries, status, error, source],
            )
            .unwrap();
        }
        drop(conn);
        stamp_facts_generation(&path, "facts-old").unwrap();
    }

    fn write_event_facts(root: &std::path::Path) {
        let path = root.join("EVENTLOG/Application.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Application(EventData TEXT);
             INSERT INTO Application VALUES('{}'),('{}'),('{}'),('{}');",
        )
        .unwrap();
        drop(conn);
        stamp_facts_generation(&path, "facts-old").unwrap();
    }

    fn event(provider: &str, id: &str, rowid: usize, timestamp: &str, payload: &str) -> Row {
        Row::from([
            ("Provider".into(), provider.into()),
            ("EventID".into(), id.into()),
            ("Channel".into(), "Application".into()),
            ("Computer".into(), "HOST".into()),
            ("EventRecordID".into(), rowid.to_string()),
            ("UserID".into(), "S-1-5-18".into()),
            ("timestamp".into(), timestamp.into()),
            ("EventData".into(), payload.into()),
            ("_record_key".into(), format!("Application::{rowid}")),
            ("_source_file".into(), "Application.evtx".into()),
        ])
    }

    fn open(root: &std::path::Path) -> Connection {
        Connection::open(root.join("_OVERVIEW/WerReports.sqlite")).unwrap()
    }

    #[test]
    fn storage_keeps_types_stages_relations_paths_and_failures() {
        let root = facts_root("storage");
        write_report_facts(
            &root,
            &[
                (
                    "2026-06-24 05:34:15.200",
                    "APPCRASH",
                    "aaaaaaaa-0000-0000-0000-000000000001",
                    r#"{"EventType":"APPCRASH","EventTime":"134350746553097144","ReportIdentifier":"aaaaaaaa-0000-0000-0000-000000000001","IntegratorReportIdentifier":"bbbbbbbb-0000-0000-0000-000000000002","AppName":"App","AppPath":"C:\\Program Files\\app.exe","UploadTime":"134350746688309602","ReportStatus":"268435456","IsFatal":"4294967295","AppSessionGuid":"000011e8-0000-000a-6189-bef9f6f7dc01","FriendlyEventName":"작동이 중지됨"}"#,
                    APPCRASH_ENTRIES,
                    "/case/WER/ReportArchive/AppCrash_app_1/Report.wer",
                ),
                (
                    "2026-06-24 05:35:00.000",
                    "StoreAgentScanForUpdatesFailure0",
                    "cccccccc-0000-0000-0000-000000000003",
                    r#"{"EventType":"StoreAgentScanForUpdatesFailure0","ReportIdentifier":"cccccccc-0000-0000-0000-000000000003","ReportStatus":"4","Sig":[{"Name":"ClientAppId","Value":"Update;"},{"Name":"HResult","Value":"80070005"},{"Name":"OSVersion","Value":"26100"},{"Name":"OSRevision","Value":"32230"}]}"#,
                    STORE_AGENT_ENTRIES,
                    "/case/WER/ReportQueue/NonCritical_Update_1/Report.wer",
                ),
                ("", "", "", "", "", "/case/WER/ReportQueue/broken/Report.wer"),
            ],
        );
        write_event_facts(&root);
        let events = crate::overview::EventLogOverviewCache::from_rows_for_tests(vec![
            event(
                "Windows Error Reporting",
                "1001",
                1,
                "2026-06-24 05:34:15.516",
                r#"{"EventName":"APPCRASH","P1":"app.exe","P4":"ntdll.dll","P7":"c00000fd","P8":"00029787","ReportId":"aaaaaaaa-0000-0000-0000-000000000001","ReportStatus":268435456,"StorePath":"\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\AppCrash_app","AttachedFiles":"\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER.a.tmp.dmp\r\n\\\\?\\C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\WER.b.tmp.xml","Rechecking":0}"#,
            ),
            event(
                "Application Error",
                "1000",
                2,
                "2026-06-24 05:34:15.516",
                r#"{"AppName":"app.exe","ModuleName":"ntdll.dll","ExceptionCode":"c00000fd","FaultingOffset":"00029787","ProcessId":"0x15c0","ProcessCreationTime":"0x1dcd22aeaf5e3d1","AppPath":"C:\\Program Files\\app.exe","ModulePath":"C:\\WINDOWS\\SYSTEM32\\ntdll.dll","IntegratorReportId":"aaaaaaaa-0000-0000-0000-000000000001"}"#,
            ),
            event(
                "Application Hang",
                "1002",
                3,
                "2026-09-28 22:24:51.822",
                r#"{"AppName":"hang.exe","ProcessId":"0x23db8","StartTime":"0x1dd4f4c6a044dcb","TerminationTime":4294967295,"ExeFileName":"C:\\hang.exe","ReportId":"bbbbbbbb-0000-0000-0000-000000000002","HangType":"Top level window is idle"}"#,
            ),
            event(
                "Microsoft-Windows-WER-PayloadHealth",
                "1",
                4,
                "2026-09-28 22:25:00.000",
                r#"{"Stage":"s1event"}"#,
            ),
        ]);
        crate::derived::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        let ctx = Ctx {
            out_dir: &root,
            target: &root,
            host_id: "host",
            dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(),
            meta: MetaLookup::load(&root).unwrap(),
        };
        // Upload telemetry is not a report: four report rows plus two events.
        assert_eq!(build(&ctx, &events).unwrap(), 6);
        let db = open(&root);

        // R01/A04: each family keeps its own role; no merged exception column.
        let crash: (String, String, String, String, Option<String>) = db
            .query_row(
                "SELECT signature_schema,module_name,exception_code,exception_offset,hang_signature
                 FROM WerReports WHERE origin='report_file' AND error_type='APPCRASH'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            crash,
            (
                "appcrash_p".into(),
                "ntdll.dll".into(),
                "c00000fd".into(),
                "00029787".into(),
                None
            )
        );
        let store: (Option<String>, Option<String>, String, String, i64) = db
            .query_row(
                "SELECT module_name,exception_code,hresult,os_revision,report_status_raw
                 FROM WerReports WHERE error_type='StoreAgentScanForUpdatesFailure0'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            store,
            (None, None, "80070005".into(), "32230".into(), 4)
        );
        // Every StoreAgent signature keeps its own label, index and role.
        let store_roles: Vec<(i64, String, Option<String>)> = db
            .prepare(
                "SELECT s.original_index,s.label,s.role FROM WerSignatures s
                 JOIN WerReports w USING(record_id)
                 WHERE w.error_type='StoreAgentScanForUpdatesFailure0' ORDER BY s.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            store_roles,
            vec![
                (0, "ClientAppId".to_string(), Some("client_app_id".to_string())),
                (1, "HResult".to_string(), Some("hresult".to_string())),
                (2, "OSVersion".to_string(), Some("os_version".to_string())),
                (3, "OSRevision".to_string(), Some("os_revision".to_string())),
            ]
        );

        // R04/A05: original Sig/DynamicSig indices and labels survive.
        let dynamic: (i64, i64, String) = db
            .query_row(
                "SELECT original_index,array_position,label FROM WerSignatures
                 WHERE family='DynamicSig' AND basis='report_entry'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(dynamic, (1, 0, "OS 버전".into()));
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM WerSignatures WHERE family='P' AND p_field IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            4
        );

        // R02: the 1001 payload has no application path.
        let reporting: (Option<String>, String, String, String) = db
            .query_row(
                "SELECT app_path,app_path_status,module_name,store_location
                 FROM WerReports WHERE origin='eventlog_1001'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            reporting,
            (None, "not_recorded".into(), "ntdll.dll".into(), "ReportArchive".into())
        );

        // A01/A06: hang start time comes from the hex FILETIME, and the
        // reporting time is never recorded as an exit time.
        let hang: (String, String, i64, String, Option<i64>) = db
            .query_row(
                "SELECT app_start_time_source,termination_time_raw,app_pid,app_uptime_basis,app_uptime_ms
                 FROM WerReports WHERE origin='eventlog_1002'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(hang.0, "StartTime");
        assert_eq!(hang.1, "4294967295");
        assert_eq!(hang.2, 146872);
        assert_eq!(hang.3, "start_to_report");
        assert!(hang.4.unwrap() > 0);

        // A02/A07: identifier matches relate the stages of one report in both
        // directions without merging or deleting any record.
        let relations: Vec<(String, String, String, String)> = db
            .prepare(
                "SELECT w.origin,r.related_origin,r.self_field,r.related_field
                 FROM WerRelations r JOIN WerReports w USING(record_id)
                 ORDER BY w.origin,r.related_origin,r.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            relations,
            vec![
                (
                    "eventlog_1000".into(),
                    "eventlog_1001".into(),
                    "integrator_report_id".into(),
                    "report_id".into()
                ),
                (
                    "eventlog_1000".into(),
                    "report_file".into(),
                    "integrator_report_id".into(),
                    "report_identifier".into()
                ),
                (
                    "eventlog_1001".into(),
                    "eventlog_1000".into(),
                    "report_id".into(),
                    "integrator_report_id".into()
                ),
                (
                    "eventlog_1001".into(),
                    "report_file".into(),
                    "report_id".into(),
                    "report_identifier".into()
                ),
                (
                    "eventlog_1002".into(),
                    "report_file".into(),
                    "report_id".into(),
                    "integrator_report_identifier".into()
                ),
                (
                    "report_file".into(),
                    "eventlog_1000".into(),
                    "report_identifier".into(),
                    "integrator_report_id".into()
                ),
                (
                    "report_file".into(),
                    "eventlog_1001".into(),
                    "report_identifier".into(),
                    "report_id".into()
                ),
                (
                    "report_file".into(),
                    "eventlog_1002".into(),
                    "integrator_report_identifier".into(),
                    "report_id".into()
                ),
            ]
        );

        // A08: every recorded path keeps its role; nothing claims the file was
        // collected or executed.
        let paths: Vec<(String, String)> = db
            .prepare(
                "SELECT path_role,path_normalized FROM WerPaths p JOIN WerReports w USING(record_id)
                 WHERE w.origin='eventlog_1001' ORDER BY p.ordinal",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0].0, "store_path");
        assert!(!paths[0].1.starts_with("\\\\?\\"));
        assert_eq!(paths[1].0, "attached_file");

        // R16: the unreadable report keeps its own row and status.
        let failed: (String, String, Option<String>, Option<String>) = db
            .query_row(
                "SELECT parse_status,parse_error,error_type,report FROM WerReports
                 WHERE parse_status='unreadable_file'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(failed.0, "unreadable_file");
        assert_eq!(failed.1, "permission denied");
        assert_eq!((failed.2, failed.3), (None, None));

        // R05: the EVTX subject is stored in its own role.
        let account: (Option<String>, Option<String>, Option<String>, String) = db
            .query_row(
                "SELECT account,account_sid,account_role,app_account_status FROM WerReports
                 WHERE origin='eventlog_1000'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(account.1.as_deref(), Some("S-1-5-18"));
        assert_eq!(account.2.as_deref(), Some("record_subject"));
        assert_eq!(account.3, "unknown");
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM WerReports WHERE origin='report_file' AND account_sid IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );

        // R07/R12: typed identifiers and modules are searchable, and the body
        // stays complete instead of a truncated search copy.
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM WerReports WHERE search_text LIKE '%aaaaaaaa-0000-0000-0000-000000000001%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM WerReports WHERE report LIKE '%AppSessionGuid%'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );

        // R09/R11: collection evidence distinguishes sources from empty results.
        let observation: (String, i64, i64) = db
            .query_row(
                "SELECT collection_state,record_count,failed_count FROM WerObservations
                 WHERE scope='report_file'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(observation, ("collected".into(), 3, 1));
        let logs: (String, i64, i64, i64) = db
            .query_row(
                "SELECT collection_state,event_1001_count,event_1000_count,event_1002_count
                 FROM WerObservations WHERE scope='eventlog'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(logs, ("collected".into(), 1, 1, 1));

        // Provenance keeps the real facts generation and rows.
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM source_records WHERE source_dataset_id<>'facts-old'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        // R10: equal timestamps stay ordered by record_id without loss.
        assert_eq!(
            db.query_row(
                "SELECT count(DISTINCT record_id) FROM WerReports WHERE timestamp='2026-06-24 05:34:15.516'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// R11: a missing source and an empty result are different states.
    #[test]
    fn missing_sources_are_distinct_from_zero_rows() {
        let root = facts_root("empty");
        crate::derived::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        let events = crate::overview::EventLogOverviewCache::from_rows_for_tests(Vec::new());
        let ctx = Ctx {
            out_dir: &root,
            target: &root,
            host_id: "host",
            dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(),
            meta: MetaLookup::load(&root).unwrap(),
        };
        assert_eq!(build(&ctx, &events).unwrap(), 0);
        let db = open(&root);
        let states: Vec<(String, String)> = db
            .prepare("SELECT scope,collection_state FROM WerObservations ORDER BY scope")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            states,
            vec![
                ("eventlog".to_string(), "not_collected".to_string()),
                ("report_file".to_string(), "not_collected".to_string()),
            ]
        );
        drop(db);

        write_report_facts(&root, &[]);
        write_event_facts(&root);
        let ctx = Ctx {
            out_dir: &root,
            target: &root,
            host_id: "host",
            dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(),
            meta: MetaLookup::load(&root).unwrap(),
        };
        assert_eq!(build(&ctx, &events).unwrap(), 0);
        let db = open(&root);
        assert_eq!(
            db.query_row(
                "SELECT collection_state FROM WerObservations WHERE scope='report_file'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "collected_empty"
        );
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A recorded empty payload stays an empty TEXT; only a missing payload
    /// becomes NULL.
    #[test]
    fn empty_payload_is_stored_as_empty_text() {
        let root = facts_root("empty-payload");
        write_event_facts(&root);
        crate::derived::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        let mut absent = event("Application Hang", "1002", 2, "2026-01-01 00:00:01.000", "");
        absent.remove("EventData");
        let events = crate::overview::EventLogOverviewCache::from_rows_for_tests(vec![
            event("Windows Error Reporting", "1001", 1, "2026-01-01 00:00:00.000", ""),
            absent,
        ]);
        let ctx = Ctx {
            out_dir: &root,
            target: &root,
            host_id: "host",
            dataset_id: "new",
            facts: FactsIndex::load(&root).unwrap(),
            meta: MetaLookup::load(&root).unwrap(),
        };
        assert_eq!(build(&ctx, &events).unwrap(), 2);
        let db = open(&root);
        let stored: Vec<(String, String, Option<String>)> = db
            .prepare(
                "SELECT payload_state,typeof(event_data_raw),event_data_raw FROM WerReports
                 ORDER BY timestamp",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            stored,
            vec![
                ("present_empty".to_string(), "text".to_string(), Some(String::new())),
                ("absent".to_string(), "null".to_string(), None),
            ]
        );
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}
