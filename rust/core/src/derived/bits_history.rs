//! BITS job/file transfer evidence: every Bits-Client record is stored as its
//! own typed event. Job state, URL transfer and job-file records keep separate
//! scopes; results come from recorded hr/error codes only, never from a job
//! start. Direct queue (qmgr) evidence is a snapshot of the service queue and
//! stays in its own tables: a queue record never becomes an event and is never
//! merged with an event by job name or URL.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection, OpenFlags};

mod queue;

use super::schema::{ChildSpec, DbSpec};
use super::{int_opt, Cell, Ctx, DerivedDb, SourceRef};
use crate::overview::EventLogOverviewCache;
use crate::sqlite::Row;

pub(super) use queue::prepare_inputs;

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "BitsHistory" (
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
  "timestamp_state" TEXT,
  "status" TEXT,
  "event_scope" TEXT,
  "result" TEXT,
  "result_scope" TEXT,
  "result_basis" TEXT,
  "result_state" TEXT,
  "job_id" TEXT,
  "job_id_state" TEXT,
  "job_group_key" TEXT,
  "job_name" TEXT,
  "job_name_source" TEXT,
  "transfer_id" TEXT,
  "transfer_id_state" TEXT,
  "url" TEXT,
  "url_source" TEXT,
  "local_path" TEXT,
  "local_path_resolved" TEXT,
  "local_path_source" TEXT,
  "path_resolution_state" TEXT,
  "bytes_scope" TEXT,
  "bytes_transferred" INTEGER,
  "bytes_transferred_raw" TEXT,
  "bytes_total" INTEGER,
  "bytes_total_raw" TEXT,
  "bytes_total_state" TEXT,
  "bytes_transferred_from_peer" INTEGER,
  "file_length" INTEGER,
  "file_count" INTEGER,
  "file_time_raw" TEXT,
  "file_time_kind" TEXT,
  "hr_raw" TEXT,
  "hr_value" INTEGER,
  "hr_hex" TEXT,
  "hr_state" TEXT,
  "hr_severity" TEXT,
  "additional_info_hr_raw" TEXT,
  "additional_info_hr_value" INTEGER,
  "error_code_raw" TEXT,
  "error_code_value" INTEGER,
  "error_code_hex" TEXT,
  "error_code_source" TEXT,
  "owner_raw" TEXT,
  "owner_domain" TEXT,
  "owner_name" TEXT,
  "owner_sid" TEXT,
  "owner_sid_state" TEXT,
  "owner_sid_candidate" TEXT,
  "owner_sid_candidate_basis" TEXT,
  "account_state" TEXT,
  "user_raw" TEXT,
  "user_domain" TEXT,
  "user_name" TEXT,
  "process" TEXT,
  "process_resolved" TEXT,
  "process_source" TEXT,
  "command_line" TEXT,
  "requester_process_id" INTEGER,
  "client_process_start_key" TEXT,
  "system_process_id" INTEGER,
  "system_thread_id" INTEGER,
  "system_user_sid" TEXT,
  "peer_raw" TEXT,
  "proxy_raw" TEXT,
  "peer_protocol_flags_raw" TEXT,
  "peer_context_info_raw" TEXT,
  "bandwidth_limit" INTEGER,
  "bandwidth_limit_raw" TEXT,
  "bandwidth_limit_state" TEXT,
  "ignore_bandwidth_limits_on_lan_raw" TEXT,
  "event_id" INTEGER,
  "event_id_raw" TEXT,
  "provider" TEXT,
  "channel" TEXT,
  "computer" TEXT,
  "event_record_id" TEXT,
  "level_name" TEXT,
  "level" INTEGER,
  "keywords_raw" TEXT,
  "activity_id" TEXT,
  "related_activity_id" TEXT,
  "payload_state" TEXT,
  "event_data_raw" TEXT,
  "facts_status" TEXT,
  "facts_error" TEXT,
  "record_key" TEXT,
  "source_file" TEXT,
  "search_text" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'BitsHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_BitsHistory_time" ON "BitsHistory"(timestamp, record_id);
CREATE INDEX "idx_BitsHistory_account" ON "BitsHistory"(account_sid, timestamp);
CREATE INDEX "idx_BitsHistory_job" ON "BitsHistory"(job_group_key, timestamp, record_id);
CREATE INDEX "idx_BitsHistory_job_id" ON "BitsHistory"(job_id);
CREATE INDEX "idx_BitsHistory_url" ON "BitsHistory"(url);
CREATE INDEX "idx_BitsHistory_local_path" ON "BitsHistory"(local_path);
CREATE INDEX "idx_BitsHistory_status" ON "BitsHistory"(status, timestamp);
CREATE INDEX "idx_BitsHistory_event" ON "BitsHistory"(event_id, timestamp);
CREATE TABLE "BitsFiles" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "job_key" TEXT,
  "entry_kind" TEXT,
  "url" TEXT,
  "url_source" TEXT,
  "local_path" TEXT,
  "local_path_resolved" TEXT,
  "local_path_source" TEXT,
  "path_resolution_state" TEXT,
  "transfer_id" TEXT,
  "bytes_transferred" INTEGER,
  "bytes_total" INTEGER,
  "bytes_total_state" TEXT,
  "file_length" INTEGER,
  "file_time_raw" TEXT,
  "declared_file_count" INTEGER,
  "evidence_basis" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "BitsHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BitsFiles_job" ON "BitsFiles"(job_key);
CREATE INDEX "idx_BitsFiles_url" ON "BitsFiles"(url);
CREATE INDEX "idx_BitsFiles_path" ON "BitsFiles"(local_path);
CREATE TABLE "BitsJobs" (
  "job_key" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "job_id" TEXT,
  "job_id_state" TEXT,
  "first_event_time" TEXT,
  "last_event_time" TEXT,
  "event_count" INTEGER,
  "untimed_event_count" INTEGER,
  "job_created_count" INTEGER,
  "job_completed_count" INTEGER,
  "job_cancelled_count" INTEGER,
  "job_command_count" INTEGER,
  "job_file_count" INTEGER,
  "transfer_started_count" INTEGER,
  "transfer_completed_count" INTEGER,
  "transfer_error_count" INTEGER,
  "other_event_count" INTEGER,
  "success_result_count" INTEGER,
  "failure_result_count" INTEGER,
  "unknown_result_count" INTEGER,
  "file_child_count" INTEGER,
  "distinct_url_count" INTEGER,
  "distinct_local_path_count" INTEGER,
  "distinct_transfer_id_count" INTEGER,
  "declared_file_count_max" INTEGER,
  "job_names_json" TEXT,
  "owners_json" TEXT,
  "processes_json" TEXT,
  "creation_observed" INTEGER,
  "termination_observed" INTEGER,
  "window_state" TEXT,
  PRIMARY KEY(job_key)
);
CREATE INDEX "idx_BitsJobs_time" ON "BitsJobs"(first_event_time, job_key);
CREATE TABLE "BitsObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "log_name" TEXT,
  "source_file" TEXT,
  "facts_db" TEXT,
  "facts_table" TEXT,
  "collection_state" TEXT,
  "input_row_count" INTEGER,
  "event_count" INTEGER,
  "incorporated_count" INTEGER,
  "corrupted_count" INTEGER,
  "untimed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "error" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(observation_id)
);
CREATE TABLE "BitsEventCoverage" (
  "coverage_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "log_name" TEXT,
  "event_id" INTEGER,
  "event_id_raw" TEXT,
  "status" TEXT,
  "event_count" INTEGER,
  "incorporated_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "observation_state" TEXT,
  PRIMARY KEY(coverage_id)
);
CREATE INDEX "idx_BitsEventCoverage_event" ON "BitsEventCoverage"(event_id);
CREATE TABLE "BitsQueueEvidence" (
  "evidence_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "evidence_kind" TEXT,
  "search_pattern" TEXT,
  "search_root" TEXT,
  "relative_path" TEXT,
  "source_file" TEXT,
  "file_size" INTEGER,
  "collection_state" TEXT,
  "parse_support" TEXT,
  "note" TEXT,
  "format" TEXT,
  "format_detail" TEXT,
  "parse_status" TEXT,
  "declared_job_count" INTEGER,
  "job_record_count" INTEGER,
  "file_record_count" INTEGER,
  "failed_record_count" INTEGER,
  "job_delimiter" TEXT,
  "job_delimiter_id" INTEGER,
  "parse_error" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(evidence_id)
);
CREATE TABLE "BitsQueueJobs" (
  "queue_job_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "evidence_id" TEXT,
  "input_path" TEXT,
  "relative_path" TEXT,
  "container_format" TEXT,
  "container_table" TEXT,
  "container_record_index" INTEGER,
  "record_offset" INTEGER,
  "record_length" INTEGER,
  "container_record_id" TEXT,
  "blob_prefix_hex" TEXT,
  "job_id" TEXT,
  "job_id_state" TEXT,
  "job_type_raw" INTEGER,
  "job_type" TEXT,
  "priority_raw" INTEGER,
  "priority" TEXT,
  "state_raw" INTEGER,
  "state" TEXT,
  "control_reserved_raw" INTEGER,
  "job_name" TEXT,
  "job_description" TEXT,
  "notify_command" TEXT,
  "notify_command_resolved" TEXT,
  "notify_arguments" TEXT,
  "notify_flags_raw" INTEGER,
  "notify_flags" TEXT,
  "notify_flags_unmapped" INTEGER,
  "owner_sid" TEXT,
  "owner_sid_state" TEXT,
  "owner_name" TEXT,
  "owner_name_basis" TEXT,
  "access_token_offset" INTEGER,
  "access_token_length" INTEGER,
  "transfer_section_kind" TEXT,
  "declared_file_count" INTEGER,
  "parsed_file_count" INTEGER,
  "file_count_state" TEXT,
  "file_reference_guids" TEXT,
  "error_count" INTEGER,
  "errors_json" TEXT,
  "transient_error_count" INTEGER,
  "retry_delay_raw" INTEGER,
  "timeout_raw" INTEGER,
  "created_time" TEXT,
  "created_time_raw" TEXT,
  "modified_time" TEXT,
  "modified_time_raw" TEXT,
  "other_time0" TEXT,
  "other_time0_raw" TEXT,
  "other_time1" TEXT,
  "other_time1_raw" TEXT,
  "other_time2" TEXT,
  "other_time2_raw" TEXT,
  "metadata_padding_hex" TEXT,
  "metadata_state" TEXT,
  "trailing_length" INTEGER,
  "parse_status" TEXT,
  "parse_method" TEXT,
  "parse_error" TEXT,
  "record_blob" BLOB,
  "evidence_basis" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(queue_job_id),
  FOREIGN KEY(evidence_id) REFERENCES "BitsQueueEvidence"("evidence_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BitsQueueJobs_job" ON "BitsQueueJobs"(job_id);
CREATE INDEX "idx_BitsQueueJobs_state" ON "BitsQueueJobs"(state, queue_job_id);
CREATE INDEX "idx_BitsQueueJobs_owner" ON "BitsQueueJobs"(owner_sid);
CREATE TABLE "BitsQueueFiles" (
  "queue_file_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "evidence_id" TEXT,
  "queue_job_id" TEXT,
  "input_path" TEXT,
  "relative_path" TEXT,
  "container_format" TEXT,
  "container_table" TEXT,
  "container_record_index" INTEGER,
  "record_offset" INTEGER,
  "record_length" INTEGER,
  "container_record_id" TEXT,
  "blob_prefix_hex" TEXT,
  "job_record_index" INTEGER,
  "job_id" TEXT,
  "link_basis" TEXT,
  "file_index_in_job" INTEGER,
  "source_url" TEXT,
  "dest_file" TEXT,
  "dest_file_resolved" TEXT,
  "dest_path_resolution_state" TEXT,
  "tmp_file" TEXT,
  "tmp_file_resolved" TEXT,
  "drive" TEXT,
  "volume_guid" TEXT,
  "download_size" INTEGER,
  "download_size_raw" TEXT,
  "download_size_state" TEXT,
  "transfer_size" INTEGER,
  "transfer_size_raw" TEXT,
  "transfer_size_state" TEXT,
  "reserved_byte" INTEGER,
  "trailing_filetime" TEXT,
  "trailing_filetime_raw" TEXT,
  "trailing_filetime_state" TEXT,
  "trailing_length" INTEGER,
  "parse_status" TEXT,
  "parse_method" TEXT,
  "parse_error" TEXT,
  "record_blob" BLOB,
  "evidence_basis" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(queue_file_id),
  FOREIGN KEY(evidence_id) REFERENCES "BitsQueueEvidence"("evidence_id") ON DELETE CASCADE,
  FOREIGN KEY(queue_job_id) REFERENCES "BitsQueueJobs"("queue_job_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BitsQueueFiles_job" ON "BitsQueueFiles"(queue_job_id);
CREATE INDEX "idx_BitsQueueFiles_url" ON "BitsQueueFiles"(source_url);
CREATE INDEX "idx_BitsQueueFiles_path" ON "BitsQueueFiles"(dest_file);
CREATE TABLE "BitsMetadataReferences" (
  "reference_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "metadata_id" TEXT NOT NULL,
  "reference_kind" TEXT,
  "reference_key" TEXT,
  PRIMARY KEY(reference_id)
);
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
  FOREIGN KEY(record_id) REFERENCES "BitsHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1),('bits_history',3);
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
    "timestamp_state",
    "status",
    "event_scope",
    "result",
    "result_scope",
    "result_basis",
    "result_state",
    "job_id",
    "job_id_state",
    "job_group_key",
    "job_name",
    "job_name_source",
    "transfer_id",
    "transfer_id_state",
    "url",
    "url_source",
    "local_path",
    "local_path_resolved",
    "local_path_source",
    "path_resolution_state",
    "bytes_scope",
    "bytes_transferred",
    "bytes_transferred_raw",
    "bytes_total",
    "bytes_total_raw",
    "bytes_total_state",
    "bytes_transferred_from_peer",
    "file_length",
    "file_count",
    "file_time_raw",
    "file_time_kind",
    "hr_raw",
    "hr_value",
    "hr_hex",
    "hr_state",
    "hr_severity",
    "additional_info_hr_raw",
    "additional_info_hr_value",
    "error_code_raw",
    "error_code_value",
    "error_code_hex",
    "error_code_source",
    "owner_raw",
    "owner_domain",
    "owner_name",
    "owner_sid",
    "owner_sid_state",
    "owner_sid_candidate",
    "owner_sid_candidate_basis",
    "account_state",
    "user_raw",
    "user_domain",
    "user_name",
    "process",
    "process_resolved",
    "process_source",
    "command_line",
    "requester_process_id",
    "client_process_start_key",
    "system_process_id",
    "system_thread_id",
    "system_user_sid",
    "peer_raw",
    "proxy_raw",
    "peer_protocol_flags_raw",
    "peer_context_info_raw",
    "bandwidth_limit",
    "bandwidth_limit_raw",
    "bandwidth_limit_state",
    "ignore_bandwidth_limits_on_lan_raw",
    "event_id",
    "event_id_raw",
    "provider",
    "channel",
    "computer",
    "event_record_id",
    "level_name",
    "level",
    "keywords_raw",
    "activity_id",
    "related_activity_id",
    "payload_state",
    "event_data_raw",
    "facts_status",
    "facts_error",
    "record_key",
    "source_file",
    "search_text",
];

const FILES: &[&str] = &[
    "record_id",
    "ordinal",
    "job_key",
    "entry_kind",
    "url",
    "url_source",
    "local_path",
    "local_path_resolved",
    "local_path_source",
    "path_resolution_state",
    "transfer_id",
    "bytes_transferred",
    "bytes_total",
    "bytes_total_state",
    "file_length",
    "file_time_raw",
    "declared_file_count",
    "evidence_basis",
];

const JOBS: &[&str] = &[
    "job_key",
    "host_id",
    "dataset_id",
    "job_id",
    "job_id_state",
    "first_event_time",
    "last_event_time",
    "event_count",
    "untimed_event_count",
    "job_created_count",
    "job_completed_count",
    "job_cancelled_count",
    "job_command_count",
    "job_file_count",
    "transfer_started_count",
    "transfer_completed_count",
    "transfer_error_count",
    "other_event_count",
    "success_result_count",
    "failure_result_count",
    "unknown_result_count",
    "file_child_count",
    "distinct_url_count",
    "distinct_local_path_count",
    "distinct_transfer_id_count",
    "declared_file_count_max",
    "job_names_json",
    "owners_json",
    "processes_json",
    "creation_observed",
    "termination_observed",
    "window_state",
];

const OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "log_name",
    "source_file",
    "facts_db",
    "facts_table",
    "collection_state",
    "input_row_count",
    "event_count",
    "incorporated_count",
    "corrupted_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

const COVERAGE: &[&str] = &[
    "coverage_id",
    "host_id",
    "dataset_id",
    "log_name",
    "event_id",
    "event_id_raw",
    "status",
    "event_count",
    "incorporated_count",
    "first_observed_time",
    "last_observed_time",
    "observation_state",
];

const QUEUE_EVIDENCE: &[&str] = &[
    "evidence_id",
    "host_id",
    "dataset_id",
    "evidence_kind",
    "search_pattern",
    "search_root",
    "relative_path",
    "source_file",
    "file_size",
    "collection_state",
    "parse_support",
    "note",
    "format",
    "format_detail",
    "parse_status",
    "declared_job_count",
    "job_record_count",
    "file_record_count",
    "failed_record_count",
    "job_delimiter",
    "job_delimiter_id",
    "parse_error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

const QUEUE_JOBS: &[&str] = &[
    "queue_job_id",
    "host_id",
    "dataset_id",
    "evidence_id",
    "input_path",
    "relative_path",
    "container_format",
    "container_table",
    "container_record_index",
    "record_offset",
    "record_length",
    "container_record_id",
    "blob_prefix_hex",
    "job_id",
    "job_id_state",
    "job_type_raw",
    "job_type",
    "priority_raw",
    "priority",
    "state_raw",
    "state",
    "control_reserved_raw",
    "job_name",
    "job_description",
    "notify_command",
    "notify_command_resolved",
    "notify_arguments",
    "notify_flags_raw",
    "notify_flags",
    "notify_flags_unmapped",
    "owner_sid",
    "owner_sid_state",
    "owner_name",
    "owner_name_basis",
    "access_token_offset",
    "access_token_length",
    "transfer_section_kind",
    "declared_file_count",
    "parsed_file_count",
    "file_count_state",
    "file_reference_guids",
    "error_count",
    "errors_json",
    "transient_error_count",
    "retry_delay_raw",
    "timeout_raw",
    "created_time",
    "created_time_raw",
    "modified_time",
    "modified_time_raw",
    "other_time0",
    "other_time0_raw",
    "other_time1",
    "other_time1_raw",
    "other_time2",
    "other_time2_raw",
    "metadata_padding_hex",
    "metadata_state",
    "trailing_length",
    "parse_status",
    "parse_method",
    "parse_error",
    "record_blob",
    "evidence_basis",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const QUEUE_FILES: &[&str] = &[
    "queue_file_id",
    "host_id",
    "dataset_id",
    "evidence_id",
    "queue_job_id",
    "input_path",
    "relative_path",
    "container_format",
    "container_table",
    "container_record_index",
    "record_offset",
    "record_length",
    "container_record_id",
    "blob_prefix_hex",
    "job_record_index",
    "job_id",
    "link_basis",
    "file_index_in_job",
    "source_url",
    "dest_file",
    "dest_file_resolved",
    "dest_path_resolution_state",
    "tmp_file",
    "tmp_file_resolved",
    "drive",
    "volume_guid",
    "download_size",
    "download_size_raw",
    "download_size_state",
    "transfer_size",
    "transfer_size_raw",
    "transfer_size_state",
    "reserved_byte",
    "trailing_filetime",
    "trailing_filetime_raw",
    "trailing_filetime_state",
    "trailing_length",
    "parse_status",
    "parse_method",
    "parse_error",
    "record_blob",
    "evidence_basis",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const METADATA_REFERENCES: &[&str] = &[
    "reference_id",
    "host_id",
    "dataset_id",
    "metadata_id",
    "reference_kind",
    "reference_key",
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
    name: "BitsHistory",
    table: "BitsHistory",
    columns: MAIN,
    children: &[
        ChildSpec { table: "BitsFiles", columns: FILES },
        ChildSpec { table: "BitsJobs", columns: JOBS },
        ChildSpec { table: "BitsObservations", columns: OBSERVATIONS },
        ChildSpec { table: "BitsEventCoverage", columns: COVERAGE },
        ChildSpec { table: "BitsQueueEvidence", columns: QUEUE_EVIDENCE },
        ChildSpec { table: "BitsQueueJobs", columns: QUEUE_JOBS },
        ChildSpec { table: "BitsQueueFiles", columns: QUEUE_FILES },
        ChildSpec { table: "BitsMetadataReferences", columns: METADATA_REFERENCES },
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
    ],
    ddl: DDL,
};

// ---------------------------------------------------------------------------
// Payload and value access
// ---------------------------------------------------------------------------

type Payload = serde_json::Map<String, serde_json::Value>;

const BITS_PROVIDER: &str = "Microsoft-Windows-Bits-Client";
const CANONICAL_LOG: &str = "Microsoft-Windows-Bits-Client%4Operational";
/// u64::MAX means "size not known yet" in BITS payloads, not a real size.
const UNKNOWN_SIZE: &str = "18446744073709551615";
const KNOWN_EVENT_IDS: &[&str] = &["3", "4", "5", "6", "59", "60", "61", "306", "310", "16403"];

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn starts_bits(value: &str) -> bool {
    value
        .get(..BITS_PROVIDER.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(BITS_PROVIDER))
}

/// Provider, channel or facts table are each sufficient evidence of this log.
fn is_bits(row: &Row) -> bool {
    g(row, "Provider").eq_ignore_ascii_case(BITS_PROVIDER)
        || starts_bits(g(row, "Channel"))
        || starts_bits(log_of(row))
}

fn log_of(row: &Row) -> &str {
    row.get("_record_key")
        .and_then(|key| key.split("::").next())
        .unwrap_or("")
}

fn lookup<'a>(map: &'a Payload, key: &str) -> Option<&'a serde_json::Value> {
    if let Some(serde_json::Value::Object(inner)) = map.get("EventXML") {
        if let Some(value) = inner.get(key).filter(|value| !value.is_null()) {
            return Some(value);
        }
    }
    map.get(key).filter(|value| !value.is_null())
}

fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// Recorded-but-empty payload values stay distinct from absent ones.
fn field(map: &Payload, key: &str) -> Option<String> {
    lookup(map, key).map(render)
}

fn first<'a>(map: &Payload, keys: &[&'a str]) -> Option<(&'a str, String)> {
    keys.iter().find_map(|key| {
        field(map, key)
            .filter(|value| !value.is_empty())
            .map(|value| (*key, value))
    })
}

/// Named fields first; positional slots only where the provider records them.
fn pick(
    map: &Payload,
    named: &[&str],
    positional: Option<(&'static str, &'static str)>,
) -> (Option<String>, Option<String>) {
    if let Some((key, value)) = first(map, named) {
        return (Some(value), Some(key.to_string()));
    }
    if let Some((key, label)) = positional {
        if let Some((_, value)) = first(map, &[key]) {
            return (Some(value), Some(label.to_string()));
        }
    }
    (None, None)
}

fn t(value: &str) -> Cell {
    Cell::Text(value.to_string())
}

fn opt(value: Option<&str>) -> Cell {
    match value {
        Some(value) => Cell::Text(value.to_string()),
        None => Cell::Null,
    }
}

fn parse_i64(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    raw.parse::<i64>().ok().or_else(|| {
        raw.parse::<u64>()
            .ok()
            .filter(|value| *value <= i64::MAX as u64)
            .map(|value| value as i64)
    })
}

fn num(value: Option<&str>) -> Cell {
    match value.and_then(parse_i64) {
        Some(value) => Cell::Int(value),
        None => Cell::Null,
    }
}

/// 32-bit status codes: hex, unsigned decimal and signed decimal all occur.
fn parse_code(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    let value = raw.parse::<i64>().ok()?;
    if (0..=i64::from(u32::MAX)).contains(&value) {
        return Some(value as u32);
    }
    if (i64::from(i32::MIN)..0).contains(&value) {
        return Some(value as i32 as u32);
    }
    None
}

struct Code {
    raw: Option<String>,
    value: Option<u32>,
    state: &'static str,
}

fn code_of(raw: Option<String>) -> Code {
    match raw {
        None => Code { raw: None, value: None, state: "unrecorded" },
        Some(raw) => {
            let value = parse_code(&raw);
            let state = if value.is_some() { "recorded" } else { "uninterpretable" };
            Code { raw: Some(raw), value, state }
        }
    }
}

impl Code {
    fn int(&self) -> Cell {
        self.value.map(|value| Cell::Int(i64::from(value))).unwrap_or(Cell::Null)
    }

    fn hex(&self) -> Cell {
        self.value
            .map(|value| Cell::Text(format!("0x{value:08X}")))
            .unwrap_or(Cell::Null)
    }

    /// Only the HRESULT severity bit is provider independent ([MS-ERREF] 2.1);
    /// the specific facility/code meaning needs the provider definition.
    fn severity(&self) -> Cell {
        match self.value {
            Some(value) if value & 0x8000_0000 != 0 => t("failure"),
            Some(_) => t("success"),
            None => Cell::Null,
        }
    }
}

struct Size {
    raw: Option<String>,
    value: Cell,
    state: &'static str,
}

fn size_of(raw: Option<String>) -> Size {
    match raw {
        None => Size { raw: None, value: Cell::Null, state: "unrecorded" },
        Some(raw) if raw.trim() == UNKNOWN_SIZE => {
            Size { raw: Some(raw), value: Cell::Null, state: "unknown_sentinel" }
        }
        Some(raw) => match parse_i64(&raw) {
            Some(value) => Size { raw: Some(raw), value: Cell::Int(value), state: "recorded" },
            None => Size { raw: Some(raw), value: Cell::Null, state: "uninterpretable" },
        },
    }
}

/// Literal paths have no resolution; only variable paths can stay unresolved.
fn path_state(raw: Option<&str>, resolved: &Cell) -> Cell {
    match raw {
        None => Cell::Null,
        Some(raw) if raw.is_empty() => t("unrecorded"),
        Some(raw) if !raw.contains('%') => t("literal"),
        Some(_) => t(if matches!(resolved, Cell::Text(_)) { "resolved" } else { "unresolved" }),
    }
}

fn split_principal(raw: &str) -> (Option<&str>, Option<&str>) {
    match raw.rsplit_once('\\') {
        Some((domain, name)) => (
            Some(domain).filter(|value| !value.is_empty()),
            Some(name).filter(|value| !value.is_empty()),
        ),
        None => (None, Some(raw).filter(|value| !value.is_empty())),
    }
}

/// A unique metadata account of this host may be a candidate for a recorded
/// owner name; it never becomes the record's confirmed SID.
fn owner_candidate(ctx: &Ctx, domain: Option<&str>, name: &str) -> Option<(String, &'static str)> {
    let sid = ctx.meta.inner.sid_for_account_name(name)?.to_string();
    let Some(domain) = domain else {
        return Some((sid, "metadata_unique_account_name"));
    };
    let entry_domain = ctx
        .meta
        .inner
        .account_entry(&sid)
        .and_then(|entry| entry.domain.clone());
    let host_domain = ctx.meta.inner.computer_name().unwrap_or("");
    let matches = entry_domain
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(domain))
        || host_domain.eq_ignore_ascii_case(domain);
    matches.then_some((sid, "metadata_unique_account_name_host_domain"))
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

struct Kind {
    status: &'static str,
    scope: &'static str,
    event_type: &'static str,
    description: &'static str,
}

fn kind_of(event_id: &str) -> Kind {
    let (status, scope, event_type, description) = match event_id {
        "3" => ("job_created", "job", "BITS 전송 작업 생성", "작업 생성 기록"),
        "4" => ("job_completed", "job", "BITS 전송 작업 완료", "작업 완료 기록"),
        "5" => ("job_cancelled", "job", "BITS 전송 작업 취소", "작업 취소 기록"),
        "6" => (
            "job_command",
            "job",
            "BITS 작업 명령 기록",
            "작업 관련 명령 원문 기록(실행 결과는 기록되지 않음)",
        ),
        "59" => ("transfer_started", "transfer", "BITS URL 전송 시작", "URL 전송 시작 기록"),
        "60" => ("transfer_completed", "transfer", "BITS URL 전송 종료", "URL 전송 종료 기록"),
        "61" => ("transfer_error", "transfer", "BITS URL 전송 오류", "URL 전송 오류 기록"),
        "306" => (
            "detail_unrecorded",
            "channel",
            "BITS 상세 기록",
            "페이로드가 기록되지 않은 상세 기록",
        ),
        "310" => ("channel_warning", "channel", "BITS 경고", "작업 ID 없는 경고 기록"),
        "16403" => (
            "job_file_added",
            "file",
            "BITS 작업 파일 기록",
            "작업 파일 등록(원격·로컬 경로 기록, 전송 완료 아님)",
        ),
        _ => ("unclassified", "unknown", "BITS 기타 이벤트", "분류되지 않은 BITS 이벤트"),
    };
    Kind { status, scope, event_type, description }
}

struct Outcome {
    result: &'static str,
    scope: Option<&'static str>,
    basis: String,
    state: &'static str,
}

/// Results come from recorded evidence only: a job start is never a transfer
/// result and a missing hr is never success.
fn outcome_of(event_id: &str, hr: &Code) -> Outcome {
    let make = |result, scope, basis: &str, state| Outcome {
        result,
        scope: Some(scope),
        basis: basis.to_string(),
        state,
    };
    match event_id {
        "3" => make("정보", "job", "작업 생성 이벤트(3)", "confirmed"),
        "4" => make("성공", "job", "작업 완료 이벤트(4)", "confirmed"),
        "5" => make("정보", "job", "작업 취소 이벤트(5)", "confirmed"),
        "6" => make("정보", "job", "작업 명령 기록(6) — 실행 결과 미기록", "confirmed"),
        "16403" => make("정보", "file", "작업 파일 기록(16403) — 전송 완료 아님", "confirmed"),
        "59" => make("정보", "transfer", "전송 시작 이벤트(59)", "confirmed"),
        "61" => make("실패", "transfer", "전송 오류 이벤트(61)", "confirmed"),
        "306" => make("미확인", "channel", "페이로드 미기록(306)", "unrecorded"),
        "310" => make("미확인", "channel", "작업 ID 없는 경고(310)", "unattributed"),
        "60" => match (hr.state, hr.value) {
            ("recorded", Some(value)) if value & 0x8000_0000 != 0 => Outcome {
                result: "실패",
                scope: Some("transfer"),
                basis: format!("hr 실패 심각도 0x{value:08X}"),
                state: "confirmed",
            },
            ("recorded", Some(value)) => Outcome {
                result: "성공",
                scope: Some("transfer"),
                basis: format!("hr 성공 심각도 0x{value:08X}"),
                state: "confirmed",
            },
            ("uninterpretable", _) => Outcome {
                result: "미확인",
                scope: Some("transfer"),
                basis: format!("hr 해석 불가({})", hr.raw.clone().unwrap_or_default()),
                state: "uninterpretable",
            },
            _ => make("미확인", "transfer", "hr 미기록", "unrecorded"),
        },
        _ => Outcome {
            result: "미확인",
            scope: None,
            basis: "미분류 BITS 이벤트".to_string(),
            state: "unclassified",
        },
    }
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

#[derive(Default)]
struct JobAgg {
    job_id: Option<String>,
    first: Option<String>,
    last: Option<String>,
    events: i64,
    untimed: i64,
    created: i64,
    completed: i64,
    cancelled: i64,
    command: i64,
    files: i64,
    started: i64,
    finished: i64,
    errors: i64,
    other: i64,
    success: i64,
    failure: i64,
    unknown: i64,
    children: i64,
    urls: BTreeSet<String>,
    paths: BTreeSet<String>,
    transfers: BTreeSet<String>,
    declared_max: Option<i64>,
    names: BTreeSet<String>,
    owners: BTreeSet<String>,
    processes: BTreeSet<String>,
}

#[derive(Default)]
struct LogStats {
    rows: i64,
    incorporated: i64,
    corrupted: i64,
    untimed: i64,
    first: Option<String>,
    last: Option<String>,
    source_file: Option<String>,
}

#[derive(Default)]
struct Coverage {
    count: i64,
    incorporated: i64,
    first: Option<String>,
    last: Option<String>,
}

fn observe(first: &mut Option<String>, last: &mut Option<String>, time: &str) {
    if time.is_empty() {
        return;
    }
    if first.as_deref().map_or(true, |value| time < value) {
        *first = Some(time.to_string());
    }
    if last.as_deref().map_or(true, |value| time > value) {
        *last = Some(time.to_string());
    }
}

fn json_list(values: &BTreeSet<String>) -> Cell {
    if values.is_empty() {
        return Cell::Null;
    }
    Cell::Text(serde_json::Value::from(values.iter().cloned().collect::<Vec<_>>()).to_string())
}

fn count(value: i64) -> Cell {
    Cell::Int(value)
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

fn source(ctx: &Ctx, row: &Row, label: &str, payload_recorded: bool) -> Result<SourceRef> {
    ctx.facts
        .source_from_record_key(
            g(row, "_record_key"),
            payload_recorded.then_some("EventData"),
            Some(g(row, "_source_file")),
            Some(label),
        )?
        .ok_or_else(|| {
            anyhow!(
                "BITS 이벤트의 원본 facts 행을 찾지 못했습니다: {}",
                g(row, "_record_key")
            )
        })
}

pub(super) fn build(ctx: &Ctx, events: &EventLogOverviewCache) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut jobs: BTreeMap<String, JobAgg> = BTreeMap::new();
    let mut logs: BTreeMap<String, LogStats> = BTreeMap::new();
    let mut coverage: BTreeMap<(String, String), Coverage> = BTreeMap::new();
    let mut account_sids: BTreeSet<String> = BTreeSet::new();

    for row in events.rows() {
        if !is_bits(row) {
            continue;
        }
        let log = {
            let name = log_of(row);
            if name.is_empty() { CANONICAL_LOG.to_string() } else { name.to_string() }
        };
        let event_id = g(row, "EventID").to_string();
        let time = g(row, "timestamp");
        // A ProcessingErrorData payload is the event decoder's failure, not
        // job data: its values are never read as BITS fields and its error
        // code is never a transfer result. The raw wrapper stays recorded.
        let (map, payload_state) = match g(row, "EventData").trim() {
            "" => (Payload::new(), "unrecorded"),
            raw => match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(serde_json::Value::Object(map)) if map.contains_key("ProcessingErrorData") => {
                    (Payload::new(), "processing_error")
                }
                Ok(serde_json::Value::Object(map)) => (map, "recorded"),
                _ => (Payload::new(), "unparsed"),
            },
        };
        let kind = kind_of(&event_id);

        let hr = code_of(field(&map, "hr"));
        let additional_hr = code_of(field(&map, "AdditionalInfoHr"));
        let (error_code, error_source) = match first(&map, &["error", "ErrorCode"]) {
            Some((key, value)) => (code_of(Some(value)), Some(key)),
            None => (code_of(None), None),
        };
        let outcome = outcome_of(&event_id, &hr);

        let job_id = first(&map, &["jobId", "Id"]).map(|(_, value)| value);
        let positional = (event_id == "3").then_some(("string", "positional_string"));
        let (job_name, job_name_source) = pick(&map, &["jobTitle", "name"], positional);
        let (owner_raw, _) = pick(
            &map,
            &["jobOwner"],
            (event_id == "3").then_some(("string2", "positional_string2")),
        );
        let (process, process_source) = pick(
            &map,
            &["processPath", "program"],
            (event_id == "3").then_some(("string3", "positional_string3")),
        );
        let (url, url_source) = pick(&map, &["url", "RemoteName"], None);
        let (local_path, local_path_source) = pick(&map, &["LocalName"], None);
        let transfer_id = field(&map, "transferId").filter(|value| !value.is_empty());
        let user_raw = field(&map, "User").filter(|value| !value.is_empty());
        let command_line = field(&map, "parameters");

        let transferred = size_of(field(&map, "bytesTransferred"));
        let total = size_of(field(&map, "bytesTotal"));
        let bandwidth = size_of(field(&map, "bandwidthLimit"));
        let bytes_scope = if transferred.raw.is_some() || total.raw.is_some() {
            match event_id.as_str() {
                "4" | "5" => Some("job"),
                "59" | "60" | "61" => Some("transfer"),
                _ => Some("unknown"),
            }
        } else {
            None
        };

        let local_resolved = ctx.meta.resolve_path(local_path.as_deref().unwrap_or(""), None);
        let process_resolved = ctx.meta.resolve_path(process.as_deref().unwrap_or(""), None);

        let (owner_domain, owner_name) = owner_raw
            .as_deref()
            .map(split_principal)
            .unwrap_or((None, None));
        let owner_is_sid = owner_raw.as_deref().is_some_and(super::is_sid);
        let candidate = match (owner_is_sid, owner_name) {
            (false, Some(name)) => owner_candidate(ctx, owner_domain, name),
            _ => None,
        };
        let owner_sid_state = match (owner_is_sid, owner_name) {
            (true, _) => "recorded",
            (false, Some(_)) => "name_only",
            _ => "unrecorded",
        };
        let (account, account_state) = if owner_is_sid {
            (
                ctx.meta.account_name(owner_raw.as_deref().unwrap_or("")),
                "sid_recorded",
            )
        } else if let Some((sid, _)) = &candidate {
            (
                ctx.meta
                    .account_name(sid)
                    .or_else(|| owner_name.map(str::to_string)),
                "metadata_confirmed_name",
            )
        } else if let Some(name) = owner_name {
            (Some(name.to_string()), "event_name_only")
        } else {
            (None, "unrecorded")
        };
        if let Some((sid, _)) = &candidate {
            account_sids.insert(sid.to_uppercase());
        }
        if owner_is_sid {
            if let Some(sid) = owner_raw.as_deref() {
                account_sids.insert(sid.to_uppercase());
            }
        }
        let (user_domain, user_name) = user_raw
            .as_deref()
            .map(split_principal)
            .unwrap_or((None, None));

        let mut rec = ctx.record(&SPEC);
        let job_key = match &job_id {
            Some(id) => format!("job:{}", id.to_uppercase()),
            None => format!("record:{}", rec.record_id),
        };

        rec.timestamp(time, "이벤트 기록 시각");
        rec.set("timestamp_state", t(if time.trim().is_empty() { "unrecorded" } else { "recorded" }));
        rec.set("event_type", t(kind.event_type));
        rec.set("description", t(kind.description));
        rec.set("status", t(kind.status));
        rec.set("event_scope", t(kind.scope));
        rec.set("result", t(outcome.result));
        rec.set("result_scope", opt(outcome.scope));
        rec.set("result_basis", t(&outcome.basis));
        rec.set("result_state", t(outcome.state));
        rec.set("account", opt(account.as_deref()));
        rec.set(
            "account_sid",
            if owner_is_sid { opt(owner_raw.as_deref()) } else { Cell::Null },
        );
        rec.set("account_state", t(account_state));
        rec.set("job_id", opt(job_id.as_deref()));
        rec.set("job_id_state", t(if job_id.is_some() { "confirmed" } else { "unrecorded" }));
        rec.set("job_group_key", t(&job_key));
        rec.set("job_name", opt(job_name.as_deref()));
        rec.set("job_name_source", opt(job_name_source.as_deref()));
        rec.set("transfer_id", opt(transfer_id.as_deref()));
        rec.set(
            "transfer_id_state",
            t(if transfer_id.is_some() { "recorded" } else { "unrecorded" }),
        );
        rec.set("url", opt(url.as_deref()));
        rec.set("url_source", opt(url_source.as_deref()));
        rec.set("local_path", opt(local_path.as_deref()));
        rec.set("local_path_resolved", local_resolved.clone());
        rec.set("local_path_source", opt(local_path_source.as_deref()));
        rec.set(
            "path_resolution_state",
            path_state(local_path.as_deref(), &local_resolved),
        );
        rec.set("bytes_scope", opt(bytes_scope));
        rec.set("bytes_transferred", transferred.value.clone());
        rec.set("bytes_transferred_raw", opt(transferred.raw.as_deref()));
        rec.set("bytes_total", total.value.clone());
        rec.set("bytes_total_raw", opt(total.raw.as_deref()));
        rec.set("bytes_total_state", t(total.state));
        rec.set(
            "bytes_transferred_from_peer",
            num(field(&map, "bytesTransferredFromPeer").as_deref()),
        );
        rec.set("file_length", num(field(&map, "fileLength").as_deref()));
        rec.set("file_count", num(field(&map, "fileCount").as_deref()));
        let file_time = field(&map, "fileTime");
        rec.set("file_time_raw", opt(file_time.as_deref()));
        rec.set(
            "file_time_kind",
            if file_time.is_some() {
                t("원본 기록 파일 시각(다운로드 실행 시각 아님)")
            } else {
                Cell::Null
            },
        );
        rec.set("hr_raw", opt(hr.raw.as_deref()));
        rec.set("hr_value", hr.int());
        rec.set("hr_hex", hr.hex());
        rec.set("hr_state", t(hr.state));
        rec.set("hr_severity", hr.severity());
        rec.set("additional_info_hr_raw", opt(additional_hr.raw.as_deref()));
        rec.set("additional_info_hr_value", additional_hr.int());
        rec.set("error_code_raw", opt(error_code.raw.as_deref()));
        rec.set("error_code_value", error_code.int());
        rec.set("error_code_hex", error_code.hex());
        rec.set("error_code_source", opt(error_source));
        rec.set("owner_raw", opt(owner_raw.as_deref()));
        rec.set("owner_domain", opt(owner_domain));
        rec.set("owner_name", opt(owner_name));
        rec.set(
            "owner_sid",
            if owner_is_sid { opt(owner_raw.as_deref()) } else { Cell::Null },
        );
        rec.set("owner_sid_state", t(owner_sid_state));
        rec.set(
            "owner_sid_candidate",
            opt(candidate.as_ref().map(|(sid, _)| sid.as_str())),
        );
        rec.set(
            "owner_sid_candidate_basis",
            opt(candidate.as_ref().map(|(_, basis)| *basis)),
        );
        rec.set("user_raw", opt(user_raw.as_deref()));
        rec.set("user_domain", opt(user_domain));
        rec.set("user_name", opt(user_name));
        rec.set("process", opt(process.as_deref()));
        rec.set("process_resolved", process_resolved);
        rec.set("process_source", opt(process_source.as_deref()));
        rec.set("command_line", opt(command_line.as_deref()));
        rec.set("requester_process_id", num(field(&map, "processId").as_deref()));
        rec.set(
            "client_process_start_key",
            opt(field(&map, "ClientProcessStartKey").as_deref()),
        );
        rec.set("system_process_id", num(Some(g(row, "ProcessID"))));
        rec.set("system_thread_id", num(Some(g(row, "ThreadID"))));
        rec.set("system_user_sid", super::text(g(row, "UserID")));
        rec.set("peer_raw", opt(field(&map, "peer").as_deref()));
        rec.set("proxy_raw", opt(field(&map, "proxy").as_deref()));
        rec.set(
            "peer_protocol_flags_raw",
            opt(field(&map, "peerProtocolFlags").as_deref()),
        );
        rec.set(
            "peer_context_info_raw",
            opt(field(&map, "PeerContextInfo").as_deref()),
        );
        rec.set("bandwidth_limit", bandwidth.value.clone());
        rec.set("bandwidth_limit_raw", opt(bandwidth.raw.as_deref()));
        rec.set("bandwidth_limit_state", t(bandwidth.state));
        rec.set(
            "ignore_bandwidth_limits_on_lan_raw",
            opt(field(&map, "ignoreBandwidthLimitsOnLan").as_deref()),
        );
        rec.set("event_id", num(Some(event_id.as_str())));
        rec.set("event_id_raw", super::text(&event_id));
        rec.set("provider", super::text(g(row, "Provider")));
        rec.set("channel", super::text(g(row, "Channel")));
        rec.set("computer", super::text(g(row, "Computer")));
        rec.set("event_record_id", super::text(g(row, "EventRecordID")));
        rec.set("level_name", super::text(g(row, "LevelName")));
        rec.set("level", num(Some(g(row, "Level"))));
        rec.set("keywords_raw", super::text(g(row, "Keywords")));
        rec.set("activity_id", super::text(g(row, "ActivityID")));
        rec.set("related_activity_id", super::text(g(row, "RelatedActivityID")));
        rec.set("payload_state", t(payload_state));
        // Exact payload bytes: a recorded empty string is not an absent value.
        rec.set(
            "event_data_raw",
            row.get("EventData")
                .cloned()
                .map(Cell::Text)
                .unwrap_or(Cell::Null),
        );
        rec.set("facts_status", super::text(g(row, "_status")));
        rec.set("facts_error", super::text(g(row, "_error")));
        rec.set("record_key", super::text(g(row, "_record_key")));
        rec.set("source_file", super::text_raw(g(row, "_source_file")));

        let searchable = [
            job_name.as_deref(),
            job_id.as_deref(),
            transfer_id.as_deref(),
            url.as_deref(),
            local_path.as_deref(),
            match &local_resolved {
                Cell::Text(value) => Some(value.as_str()),
                _ => None,
            },
            process.as_deref(),
            command_line.as_deref(),
            owner_raw.as_deref(),
            user_raw.as_deref(),
            account.as_deref(),
            candidate.as_ref().map(|(sid, _)| sid.as_str()),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
        rec.set("search_text", super::text(&searchable));

        // Only file-scoped and transfer-scoped events carry evidenced children.
        let has_child = matches!(event_id.as_str(), "16403" | "59" | "60" | "61")
            && (url.is_some() || local_path.is_some());
        if has_child {
            let basis = format!(
                "EID {event_id} {}",
                [url_source.as_deref(), local_path_source.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("/")
            );
            rec.child(
                "BitsFiles",
                vec![
                    t(&job_key),
                    t(if event_id == "16403" { "job_file" } else { "transfer_target" }),
                    opt(url.as_deref()),
                    opt(url_source.as_deref()),
                    opt(local_path.as_deref()),
                    local_resolved.clone(),
                    opt(local_path_source.as_deref()),
                    path_state(local_path.as_deref(), &local_resolved),
                    opt(transfer_id.as_deref()),
                    transferred.value.clone(),
                    total.value.clone(),
                    t(total.state),
                    num(field(&map, "fileLength").as_deref()),
                    opt(file_time.as_deref()),
                    num(field(&map, "fileCount").as_deref()),
                    t(&basis),
                ],
            );
        }

        rec.source(Some(source(ctx, row, kind.event_type, payload_state == "recorded")?));
        db.write(rec)?;

        let job = jobs.entry(job_key).or_default();
        if job.job_id.is_none() {
            job.job_id = job_id.clone();
        }
        job.events += 1;
        observe(&mut job.first, &mut job.last, time);
        if time.trim().is_empty() {
            job.untimed += 1;
        }
        match kind.status {
            "job_created" => job.created += 1,
            "job_completed" => job.completed += 1,
            "job_cancelled" => job.cancelled += 1,
            "job_command" => job.command += 1,
            "job_file_added" => job.files += 1,
            "transfer_started" => job.started += 1,
            "transfer_completed" => job.finished += 1,
            "transfer_error" => job.errors += 1,
            _ => job.other += 1,
        }
        match outcome.result {
            "성공" => job.success += 1,
            "실패" => job.failure += 1,
            "미확인" => job.unknown += 1,
            _ => {}
        }
        if has_child {
            job.children += 1;
        }
        if let Some(value) = url.clone() {
            job.urls.insert(value);
        }
        if let Some(value) = local_path.clone() {
            job.paths.insert(value);
        }
        if let Some(value) = transfer_id.clone() {
            job.transfers.insert(value);
        }
        if let Some(value) = field(&map, "fileCount").as_deref().and_then(parse_i64) {
            job.declared_max = Some(job.declared_max.map_or(value, |current| current.max(value)));
        }
        if let Some(value) = job_name.clone() {
            job.names.insert(value);
        }
        if let Some(value) = owner_raw.clone() {
            job.owners.insert(value);
        }
        if let Some(value) = process.clone() {
            job.processes.insert(value);
        }

        let stats = logs.entry(log.clone()).or_default();
        stats.rows += 1;
        stats.incorporated += 1;
        if g(row, "_status") == "corrupted_chunk" {
            stats.corrupted += 1;
        }
        if time.trim().is_empty() {
            stats.untimed += 1;
        }
        observe(&mut stats.first, &mut stats.last, time);
        if stats.source_file.is_none() {
            let file = g(row, "_source_file");
            if !file.is_empty() {
                stats.source_file = Some(file.to_string());
            }
        }

        let seen = coverage.entry((log, event_id)).or_default();
        seen.count += 1;
        seen.incorporated += 1;
        observe(&mut seen.first, &mut seen.last, time);
    }

    write_jobs(ctx, &mut db, jobs)?;
    write_observations(ctx, &mut db, logs)?;
    write_coverage(ctx, &mut db, coverage)?;
    queue::populate(ctx, &mut db)?;
    write_metadata_references(ctx, &mut db, &account_sids)?;
    db.finish()
}

fn write_jobs(ctx: &Ctx, db: &mut DerivedDb, jobs: BTreeMap<String, JobAgg>) -> Result<()> {
    for (job_key, job) in jobs {
        let creation = job.created > 0;
        let termination = job.completed + job.cancelled > 0;
        let window = match (creation, termination) {
            (true, true) => "creation_and_termination_observed",
            (true, false) => "termination_unobserved",
            (false, true) => "creation_unobserved",
            (false, false) => "creation_and_termination_unobserved",
        };
        db.insert_child(
            "BitsJobs",
            &[
                t(&job_key),
                t(ctx.host_id),
                t(ctx.dataset_id),
                opt(job.job_id.as_deref()),
                t(if job.job_id.is_some() { "confirmed" } else { "unrecorded" }),
                opt(job.first.as_deref()),
                opt(job.last.as_deref()),
                count(job.events),
                count(job.untimed),
                count(job.created),
                count(job.completed),
                count(job.cancelled),
                count(job.command),
                count(job.files),
                count(job.started),
                count(job.finished),
                count(job.errors),
                count(job.other),
                count(job.success),
                count(job.failure),
                count(job.unknown),
                count(job.children),
                count(job.urls.len() as i64),
                count(job.paths.len() as i64),
                count(job.transfers.len() as i64),
                int_opt(job.declared_max),
                json_list(&job.names),
                json_list(&job.owners),
                json_list(&job.processes),
                count(i64::from(creation)),
                count(i64::from(termination)),
                t(window),
            ],
        )?;
    }
    Ok(())
}

/// Collection state comes from the real input manifest; an empty log, a failed
/// read and an uncollected log stay distinct.
fn write_observations(
    ctx: &Ctx,
    db: &mut DerivedDb,
    mut logs: BTreeMap<String, LogStats>,
) -> Result<()> {
    let path = ctx.out_dir.join("EVENTLOG/EventLogInputs.sqlite");
    let mut discovered = false;
    let mut manifest_logs = false;
    if path.exists() {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        discovered = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM EventLogInputs WHERE status='discovery_complete')",
            [],
            |row| row.get(0),
        )?;
        let mut rows = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT rowid,source_file,facts_db,facts_table,status,row_count,error \
                 FROM EventLogInputs WHERE status<>'discovery_complete' ORDER BY rowid",
            )?;
            let mut cursor = stmt.query([])?;
            while let Some(row) = cursor.next()? {
                rows.push((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ));
            }
        }
        for (rowid, file, facts_db, facts_table, status, row_count, error) in rows {
            let table = facts_table.clone().filter(|value| !value.is_empty()).unwrap_or_else(|| {
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
            if !starts_bits(&table) {
                continue;
            }
            manifest_logs = true;
            let input_rows = row_count.as_deref().and_then(parse_i64);
            let state = match (status.as_str(), input_rows) {
                ("read_failed", _) => "read_failed",
                ("parsed", Some(0)) => "collected_empty",
                ("parsed", Some(_)) => "collected",
                _ => "unknown",
            };
            let reference = ctx
                .facts
                .source_from_row(&path, "EventLogInputs", rowid, file.as_deref(), Some("수집 관측"))?
                .ok_or_else(|| anyhow!("EventLogInputs 원본 참조를 찾지 못했습니다"))?;
            let stats = logs.remove(&table).unwrap_or_default();
            let parsed = status == "parsed";
            db.insert_child(
                "BitsObservations",
                &[
                    t(&uuid::Uuid::new_v4().to_string()),
                    t(ctx.host_id),
                    t(ctx.dataset_id),
                    t(&table),
                    opt(file.as_deref()),
                    opt(facts_db.as_deref()),
                    opt(facts_table.as_deref()),
                    t(state),
                    int_opt(input_rows),
                    int_opt(parsed.then_some(stats.rows)),
                    int_opt(parsed.then_some(stats.incorporated)),
                    int_opt(parsed.then_some(stats.corrupted)),
                    int_opt(parsed.then_some(stats.untimed)),
                    opt(stats.first.as_deref()),
                    opt(stats.last.as_deref()),
                    opt(error.as_deref()),
                    t(&reference.dataset),
                    t(&reference.db),
                    t(&reference.table),
                    Cell::Int(reference.rowid),
                ],
            )?;
        }
    }
    for (table, stats) in logs {
        manifest_logs = true;
        // Without a manifest row these coordinates are unknown; all four stay
        // NULL together rather than carrying a partial reference.
        let facts = ctx.facts.by_stem(&table);
        db.insert_child(
            "BitsObservations",
            &[
                t(&uuid::Uuid::new_v4().to_string()),
                t(ctx.host_id),
                t(ctx.dataset_id),
                t(&table),
                opt(stats.source_file.as_deref()),
                opt(facts.map(|db| db.relative.as_str())),
                t(&table),
                t("unknown"),
                Cell::Null,
                count(stats.rows),
                count(stats.incorporated),
                count(stats.corrupted),
                count(stats.untimed),
                opt(stats.first.as_deref()),
                opt(stats.last.as_deref()),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
            ],
        )?;
    }
    if !manifest_logs {
        db.insert_child(
            "BitsObservations",
            &[
                t(&uuid::Uuid::new_v4().to_string()),
                t(ctx.host_id),
                t(ctx.dataset_id),
                t(CANONICAL_LOG),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                t(if discovered { "not_collected" } else { "unknown" }),
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
                Cell::Null,
            ],
        )?;
    }
    Ok(())
}

/// Observed ids keep their counts; contract ids with no record stay explicitly
/// unobserved instead of silently missing.
fn write_coverage(
    ctx: &Ctx,
    db: &mut DerivedDb,
    coverage: BTreeMap<(String, String), Coverage>,
) -> Result<()> {
    let mut observed_logs: BTreeSet<String> = BTreeSet::new();
    for ((log, event_id), seen) in &coverage {
        observed_logs.insert(log.clone());
        db.insert_child(
            "BitsEventCoverage",
            &[
                t(&uuid::Uuid::new_v4().to_string()),
                t(ctx.host_id),
                t(ctx.dataset_id),
                t(log),
                num(Some(event_id.as_str())),
                t(event_id),
                t(kind_of(event_id).status),
                count(seen.count),
                count(seen.incorporated),
                opt(seen.first.as_deref()),
                opt(seen.last.as_deref()),
                t("observed"),
            ],
        )?;
    }
    for log in observed_logs {
        for event_id in KNOWN_EVENT_IDS {
            if coverage.contains_key(&(log.clone(), (*event_id).to_string())) {
                continue;
            }
            db.insert_child(
                "BitsEventCoverage",
                &[
                    t(&uuid::Uuid::new_v4().to_string()),
                    t(ctx.host_id),
                    t(ctx.dataset_id),
                    t(&log),
                    num(Some(*event_id)),
                    t(event_id),
                    t(kind_of(event_id).status),
                    count(0),
                    count(0),
                    Cell::Null,
                    Cell::Null,
                    t("unobserved"),
                ],
            )?;
        }
    }
    Ok(())
}


/// Host and network metadata plus only the account entries this result used.
fn write_metadata_references(
    ctx: &Ctx,
    db: &mut DerivedDb,
    sids: &BTreeSet<String>,
) -> Result<()> {
    let path = ctx.overview_dir().join("Metadata.sqlite");
    if !path.exists() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut selected = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT metadata_id,kind,key,account_sid FROM metadata \
             WHERE host_id=?1 AND dataset_id=?2 ORDER BY metadata_id",
        )?;
        let mut rows = stmt.query(params![ctx.host_id, ctx.dataset_id])?;
        while let Some(row) = rows.next()? {
            let metadata_id: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let key: Option<String> = row.get(2)?;
            let sid: Option<String> = row.get(3)?;
            let keep = match kind.as_str() {
                "host" | "network" => true,
                "account" => sid
                    .as_deref()
                    .or(key.as_deref())
                    .is_some_and(|value| sids.contains(&value.to_uppercase())),
                _ => false,
            };
            if keep {
                selected.push((metadata_id, kind, key));
            }
        }
    }
    for (metadata_id, kind, key) in selected {
        db.insert_child(
            "BitsMetadataReferences",
            &[
                t(&uuid::Uuid::new_v4().to_string()),
                t(ctx.host_id),
                t(ctx.dataset_id),
                t(&metadata_id),
                t(&kind),
                opt(key.as_deref()),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};

    const LOG: &str = "Microsoft-Windows-Bits-Client%4Operational";
    const EVTX: &str = "/evidence/NonVolatile/EVENTLOG/Logs/Microsoft-Windows-Bits-Client%4Operational.evtx";

    struct Fixture {
        root: std::path::PathBuf,
        target: std::path::PathBuf,
    }

    impl Fixture {
        fn new(rows: usize) -> Self {
            let root = std::env::temp_dir().join(format!("wina-bits-{}", uuid::Uuid::new_v4()));
            let target = root.join("target");
            std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
            std::fs::create_dir_all(&target).unwrap();
            let facts = root.join("EVENTLOG").join(format!("{LOG}.sqlite"));
            let conn = Connection::open(&facts).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE \"{LOG}\" (EventData TEXT);
                 {}",
                (0..rows)
                    .map(|_| format!("INSERT INTO \"{LOG}\" VALUES('{{}}');"))
                    .collect::<String>()
            ))
            .unwrap();
            drop(conn);
            stamp_facts_generation(&facts, "facts-old").unwrap();
            super::super::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
            Self { root, target }
        }

        fn inputs(&self, row_count: i64) {
            let path = self.root.join("EVENTLOG/EventLogInputs.sqlite");
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE EventLogInputs (source_file TEXT, facts_db TEXT, facts_table TEXT, status TEXT, row_count TEXT, error TEXT);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO EventLogInputs VALUES(?1,?2,?3,'parsed',?4,NULL)",
                params![EVTX, format!("EVENTLOG/{LOG}.sqlite"), LOG, row_count.to_string()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO EventLogInputs VALUES(NULL,NULL,NULL,'discovery_complete','1',NULL)",
                [],
            )
            .unwrap();
            drop(conn);
            stamp_facts_generation(&path, "facts-old").unwrap();
        }

        fn account(&self, sid: &str, name: &str, domain: &str, computer: &str) {
            let conn = Connection::open(self.root.join("_OVERVIEW/Metadata.sqlite")).unwrap();
            conn.execute(
                "INSERT INTO metadata(metadata_id,host_id,dataset_id,kind,scope,key,value,resolution_status,account_name,account_sid,domain)
                 VALUES(?1,'host','new','account','machine',?2,?3,'resolved',?3,?4,?5)",
                params![uuid::Uuid::new_v4().to_string(), sid.to_lowercase(), name, sid, domain],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO metadata(metadata_id,host_id,dataset_id,kind,scope,key,value,resolution_status)
                 VALUES(?1,'host','new','host','host','computer_name',?2,'resolved')",
                params![uuid::Uuid::new_v4().to_string(), computer],
            )
            .unwrap();
        }

        /// Mirrors the pipeline: queue facts are materialised before the
        /// overview is derived, and the overview only reads those facts.
        fn run(&self, rows: Vec<Row>) -> (usize, Connection) {
            prepare_inputs(&self.root, &self.target, "new").unwrap();
            let ctx = Ctx {
                out_dir: &self.root,
                target: &self.target,
                host_id: "host",
                dataset_id: "new",
                facts: FactsIndex::load(&self.root).unwrap(),
                meta: MetaLookup::load(&self.root).unwrap(),
            };
            let written =
                build(&ctx, &EventLogOverviewCache::from_rows_for_tests(rows)).unwrap();
            let db = Connection::open(ctx.overview_dir().join("BitsHistory.sqlite")).unwrap();
            (written, db)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn event(n: usize, eid: &str, time: &str, payload: Option<&str>) -> Row {
        let mut row = Row::from([
            ("Provider".into(), "Microsoft-Windows-Bits-Client".into()),
            ("Channel".into(), "Microsoft-Windows-Bits-Client/Operational".into()),
            ("Computer".into(), "WIN-TEST".into()),
            ("EventID".into(), eid.into()),
            ("EventRecordID".into(), n.to_string()),
            ("LevelName".into(), "Information".into()),
            ("Level".into(), "4".into()),
            ("Keywords".into(), "0x4000000000000000".into()),
            ("ProcessID".into(), "12544".into()),
            ("ThreadID".into(), "7212".into()),
            ("UserID".into(), "S-1-5-18".into()),
            ("timestamp".into(), time.into()),
            ("_record_key".into(), format!("{LOG}::{n}")),
            ("_source_file".into(), EVTX.into()),
            ("_status".into(), "ok".into()),
        ]);
        if let Some(payload) = payload {
            row.insert("EventData".into(), payload.into());
        }
        row
    }

    fn one<T: rusqlite::types::FromSql>(db: &Connection, sql: &str) -> T {
        db.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// Real-collection shapes: job state, job file (16403) and URL transfer are
    /// separate events with their own scope; a job start never becomes a
    /// transfer result, and 16403 keeps RemoteName/LocalName verbatim.
    #[test]
    fn job_file_and_transfer_events_keep_separate_scopes_and_paths() {
        let fx = Fixture::new(9);
        let job = "6356091E-6B09-4189-8B7C-C4B0E324D69E";
        let rows = vec![
            event(1, "3", "2026-09-19 20:55:28.905", Some(&format!(
                r#"{{"jobTitle":"Chrome Component Updater","jobId":"{job}","jobOwner":"WIN-TEST\\Administrator","processPath":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","processId":15812,"ClientProcessStartKey":2814749767152643}}"#
            ))),
            event(2, "16403", "2026-09-19 20:55:28.912", Some(&format!(
                r#"{{"User":"WIN-TEST\\Administrator","jobTitle":"Chrome Component Updater","jobId":"{job}","jobOwner":"WIN-TEST\\Administrator","fileCount":1,"RemoteName":"http://edgedl.me.gvt1.com/edgedl/a","LocalName":"C:\\WINDOWS\\SystemTemp\\chrome_BITS_15812\\a","processId":15812,"ClientProcessStartKey":2814749767152643}}"#
            ))),
            event(3, "59", "2026-09-19 20:55:28.985", Some(&format!(
                r#"{{"transferId":"C6FB7FB5-0F4E-4CD8-85A6-40D59F2301E4","name":"Chrome Component Updater","Id":"{job}","url":"http://edgedl.me.gvt1.com/edgedl/a","peer":"","fileTime":"2026-09-19T07:49:42.000000Z","fileLength":1533,"bytesTotal":1533,"bytesTransferred":0,"bytesTransferredFromPeer":0}}"#
            ))),
            event(4, "60", "2026-09-19 20:55:34.475", Some(&format!(
                r#"{{"transferId":"C6FB7FB5-0F4E-4CD8-85A6-40D59F2301E4","name":"Chrome Component Updater","Id":"{job}","url":"http://edgedl.me.gvt1.com/edgedl/a","peer":"","hr":0,"fileTime":"2026-09-19T07:49:42.000000Z","fileLength":1533,"bytesTotal":1533,"bytesTransferred":1533,"proxy":"","peerProtocolFlags":0,"bytesTransferredFromPeer":0,"AdditionalInfoHr":0,"PeerContextInfo":0,"bandwidthLimit":18446744073709551615,"ignoreBandwidthLimitsOnLan":false}}"#
            ))),
            event(5, "4", "2026-09-19 20:55:36.915", Some(&format!(
                r#"{{"User":"WIN-TEST\\Administrator","jobTitle":"Chrome Component Updater","jobId":"{job}","jobOwner":"WIN-TEST\\Administrator","fileCount":1,"bytesTransferred":1533,"bytesTransferredFromPeer":0}}"#
            ))),
            event(6, "6", "2026-09-23 21:12:43.478", Some(
                r#"{"jobId":"F6B4F927-5BE7-462C-8E77-0F4CCEDC1B0D","jobOwner":"NT AUTHORITY\\SYSTEM","program":"C:\\WINDOWS\\system32\\directxdatabaseupdater.exe","parameters":"C:\\WINDOWS\\system32\\directxdatabaseupdater.exe -DatabaseComplete {F6B4F927-5BE7-462C-8E77-0F4CCEDC1B0D}"}"#,
            )),
            event(7, "5", "2026-09-29 03:28:33.510", Some(
                r#"{"User":"WIN-TEST\\Administrator","jobTitle":"Edge Component Updater","jobId":"3DDCD559-A66D-4220-9315-DFC9E15C299C","jobOwner":"WIN-TEST\\Administrator","fileCount":1,"processId":13796}"#,
            )),
            event(8, "310", "2026-09-19 20:55:28.983", Some(r#"{"ErrorCode":2147942450}"#)),
            // The real collection records EID 306 with an empty payload string.
            event(9, "306", "2026-09-20 06:55:29.828", Some("")),
        ];
        let (written, db) = fx.run(rows);
        assert_eq!(written, 9, "every Bits-Client record is incorporated");

        // 16403: own event, verbatim local path, literal paths resolve to NULL.
        let file: (String, String, String, Option<String>, String, String, String) = db
            .query_row(
                "SELECT status,event_scope,local_path,local_path_resolved,path_resolution_state,url_source,result_scope
                 FROM BitsHistory WHERE event_id=16403",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(file.0, "job_file_added");
        assert_eq!(file.1, "file");
        assert_eq!(file.2, "C:\\WINDOWS\\SystemTemp\\chrome_BITS_15812\\a");
        assert_eq!(file.3, None);
        assert_eq!(file.4, "literal");
        assert_eq!(file.5, "RemoteName");
        assert_eq!(file.6, "file");

        // Job start carries no transfer result; job completion stays job-scoped.
        let start: (String, String, Option<i64>, String) = db
            .query_row(
                "SELECT result,result_scope,bytes_transferred,result_state FROM BitsHistory WHERE event_id=3",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(start, ("정보".into(), "job".into(), None, "confirmed".into()));
        assert_eq!(one::<String>(&db, "SELECT bytes_scope FROM BitsHistory WHERE event_id=4"), "job");
        assert_eq!(one::<i64>(&db, "SELECT bytes_transferred FROM BitsHistory WHERE event_id=4"), 1533);
        assert_eq!(one::<i64>(&db, "SELECT file_count FROM BitsHistory WHERE event_id=4"), 1);

        // 60: hr=0 is the only evidence of transfer success; sentinels stay NULL.
        let done: (String, String, i64, String, String, Option<i64>, String) = db
            .query_row(
                "SELECT result,result_scope,hr_value,hr_hex,hr_severity,bandwidth_limit,bandwidth_limit_state
                 FROM BitsHistory WHERE event_id=60",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(done.0, "성공");
        assert_eq!(done.1, "transfer");
        assert_eq!(done.2, 0);
        assert_eq!(done.3, "0x00000000");
        assert_eq!(done.4, "success");
        assert_eq!(done.5, None);
        assert_eq!(done.6, "unknown_sentinel");
        assert_eq!(
            one::<String>(&db, "SELECT bandwidth_limit_raw FROM BitsHistory WHERE event_id=60"),
            "18446744073709551615"
        );
        // Recorded-but-empty values stay distinct from unrecorded ones.
        assert_eq!(one::<String>(&db, "SELECT peer_raw FROM BitsHistory WHERE event_id=60"), "");
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsHistory WHERE event_id=59 AND proxy_raw IS NULL"),
            1
        );
        assert_eq!(one::<i64>(&db, "SELECT bytes_transferred FROM BitsHistory WHERE event_id=59"), 0);

        // EID 6 keeps the command verbatim and claims no execution result.
        let command: (String, String, String) = db
            .query_row(
                "SELECT command_line,process,result FROM BitsHistory WHERE event_id=6",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(command.0.ends_with("-DatabaseComplete {F6B4F927-5BE7-462C-8E77-0F4CCEDC1B0D}"));
        assert_eq!(command.1, "C:\\WINDOWS\\system32\\directxdatabaseupdater.exe");
        assert_eq!(command.2, "정보");

        // 310 has no job attribution; 306 has no payload at all.
        let warn: (Option<String>, String, String, i64, String) = db
            .query_row(
                "SELECT job_id,job_id_state,job_group_key,error_code_value,result FROM BitsHistory WHERE event_id=310",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(warn.0, None);
        assert_eq!(warn.1, "unrecorded");
        assert!(warn.2.starts_with("record:"));
        assert_eq!(warn.3, 2_147_942_450);
        assert_eq!(warn.4, "미확인");
        let verbose: (String, Option<String>, String) = db
            .query_row(
                "SELECT payload_state,event_data_raw,result_state FROM BitsHistory WHERE event_id=306",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            verbose,
            ("unrecorded".into(), Some(String::new()), "unrecorded".into()),
            "an empty payload string is stored verbatim, not as NULL"
        );

        // Children exist only for evidenced file/transfer rows.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsFiles"), 3);
        let child: (String, String, String) = db
            .query_row(
                "SELECT entry_kind,url,local_path FROM BitsFiles WHERE entry_kind='job_file'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(child.0, "job_file");
        assert_eq!(child.1, "http://edgedl.me.gvt1.com/edgedl/a");
        assert_eq!(child.2, "C:\\WINDOWS\\SystemTemp\\chrome_BITS_15812\\a");

        // Job grouping: one confirmed job plus separate unidentified records.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsJobs WHERE job_id_state='confirmed'"),
            3
        );
        let grouped: (i64, i64, i64, i64, String) = db
            .query_row(
                &format!(
                    "SELECT event_count,job_created_count,transfer_completed_count,file_child_count,window_state
                     FROM BitsJobs WHERE job_id='{job}'"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(grouped.0, 5);
        assert_eq!(grouped.1, 1);
        assert_eq!(grouped.2, 1);
        assert_eq!(grouped.3, 3);
        assert_eq!(grouped.4, "creation_and_termination_observed");
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsJobs WHERE job_id_state='unrecorded'"),
            2
        );
        // The cancelled job has no creation event in this window.
        assert_eq!(
            one::<String>(
                &db,
                "SELECT window_state FROM BitsJobs WHERE job_id='3DDCD559-A66D-4220-9315-DFC9E15C299C'"
            ),
            "creation_unobserved"
        );

        // Provenance: one real facts row per event, original file carried through.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM source_records"), 9);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_dataset_id<>'facts-old'"),
            0
        );
        assert_eq!(
            one::<i64>(&db, &format!("SELECT COUNT(*) FROM BitsHistory WHERE source_file='{EVTX}'")),
            9
        );
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_field='EventData'"),
            8
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    /// A recorded empty payload and an absent payload are different evidence
    /// states; the raw bytes stay exactly as the facts row holds them.
    #[test]
    fn present_empty_and_absent_payload_stay_distinct() {
        let fx = Fixture::new(2);
        let (written, db) = fx.run(vec![
            event(1, "306", "2026-01-01 00:00:00.000", Some("")),
            event(2, "306", "2026-01-01 00:01:00.000", None),
        ]);
        assert_eq!(written, 2);
        let empty: (Option<String>, String) = db
            .query_row(
                "SELECT event_data_raw,payload_state FROM BitsHistory WHERE event_record_id='1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(empty, (Some(String::new()), "unrecorded".into()));
        let absent: (Option<String>, String) = db
            .query_row(
                "SELECT event_data_raw,payload_state FROM BitsHistory WHERE event_record_id='2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(absent, (None, "unrecorded".into()));
        // Neither row points at an EventData field that holds no evidence.
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM source_records WHERE source_field IS NOT NULL"),
            0
        );
    }

    /// R03: identical job names never merge; only a recorded job id groups.
    #[test]
    fn same_name_without_job_id_stays_separate() {
        let fx = Fixture::new(2);
        let payload = r#"{"jobTitle":"Updater","jobOwner":"WIN-TEST\\Administrator"}"#;
        let (written, db) = fx.run(vec![
            event(1, "3", "2026-01-01 00:00:00.000", Some(payload)),
            event(2, "3", "2026-01-02 00:00:00.000", Some(payload)),
        ]);
        assert_eq!(written, 2);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(DISTINCT job_group_key) FROM BitsHistory"), 2);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsJobs"), 2);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsJobs WHERE job_id_state='unrecorded' AND job_id IS NULL"),
            2
        );
    }

    /// R02/R07: unrecorded, sentinel and real zero values stay distinguishable.
    #[test]
    fn unrecorded_sentinel_and_zero_values_stay_distinct() {
        let fx = Fixture::new(4);
        let (written, db) = fx.run(vec![
            event(1, "60", "2026-01-01 00:00:00.000", Some(
                r#"{"Id":"A","url":"http://x/1","bytesTotal":18446744073709551615,"bytesTransferred":0}"#,
            )),
            event(2, "60", "2026-01-01 00:01:00.000", Some(
                r#"{"Id":"A","url":"http://x/2","hr":"0x80190194","bytesTotal":0,"bytesTransferred":0}"#,
            )),
            event(3, "61", "2026-01-01 00:02:00.000", Some(
                r#"{"Id":"A","url":"http://x/3","error":"0x80072ee2"}"#,
            )),
            event(4, "60", "", Some(r#"{"Id":"A","url":"http://x/4","hr":"not-a-code"}"#)),
        ]);
        assert_eq!(written, 4);

        let missing: (String, String, Option<i64>, String, String, Option<i64>) = db
            .query_row(
                "SELECT result,result_state,hr_value,hr_state,bytes_total_state,bytes_total
                 FROM BitsHistory WHERE url='http://x/1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(missing.0, "미확인", "missing hr must not become success");
        assert_eq!(missing.1, "unrecorded");
        assert_eq!(missing.2, None);
        assert_eq!(missing.3, "unrecorded");
        assert_eq!(missing.4, "unknown_sentinel");
        assert_eq!(missing.5, None);
        assert_eq!(
            one::<i64>(&db, "SELECT bytes_transferred FROM BitsHistory WHERE url='http://x/1'"),
            0
        );

        let failed: (String, i64, String, String, i64) = db
            .query_row(
                "SELECT result,hr_value,hr_severity,bytes_total_state,bytes_total
                 FROM BitsHistory WHERE url='http://x/2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(failed.0, "실패");
        assert_eq!(failed.1, 0x8019_0194);
        assert_eq!(failed.2, "failure");
        assert_eq!(failed.3, "recorded");
        assert_eq!(failed.4, 0, "a recorded zero total is not an unknown size");

        let error: (String, i64, String, String) = db
            .query_row(
                "SELECT result,error_code_value,error_code_hex,error_code_source
                 FROM BitsHistory WHERE url='http://x/3'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(error.0, "실패");
        assert_eq!(error.1, 0x8007_2ee2);
        assert_eq!(error.2, "0x80072EE2");
        assert_eq!(error.3, "error");

        let broken: (String, String, Option<String>, Option<String>, String) = db
            .query_row(
                "SELECT hr_state,hr_raw,hr_hex,timestamp,timestamp_state
                 FROM BitsHistory WHERE url='http://x/4'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(broken.0, "uninterpretable");
        assert_eq!(broken.1, "not-a-code");
        assert_eq!(broken.2, None);
        assert_eq!(broken.3, None);
        assert_eq!(broken.4, "unrecorded");
    }

    /// R08/A05/A08: positional job creation, owner identity and record context.
    #[test]
    fn positional_creation_and_owner_identity_stay_separate() {
        let fx = Fixture::new(2);
        fx.account("S-1-5-21-99-99-99-500", "Administrator", "WIN-TEST", "WIN-TEST");
        let (written, db) = fx.run(vec![
            event(1, "3", "2026-01-01 00:00:00.000", Some(
                r#"{"string":"Legacy Job","string2":"WIN-TEST\\Administrator","string3":"C:\\tools\\dl.exe"}"#,
            )),
            event(2, "3", "2026-01-01 00:01:00.000", Some(
                r#"{"jobTitle":"Named Job","jobId":"B","jobOwner":"NT AUTHORITY\\SYSTEM","processPath":"C:\\WINDOWS\\x.exe","processId":4321,"ClientProcessStartKey":2814749767152643}"#,
            )),
        ]);
        assert_eq!(written, 2);

        let legacy: (String, String, String, String) = db
            .query_row(
                "SELECT job_name,job_name_source,process,process_source FROM BitsHistory WHERE event_record_id='1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(legacy, (
            "Legacy Job".into(),
            "positional_string".into(),
            "C:\\tools\\dl.exe".into(),
            "positional_string3".into(),
        ));

        let owner: (String, String, String, Option<String>, String, String, String) = db
            .query_row(
                "SELECT owner_raw,owner_domain,owner_name,account_sid,owner_sid_state,owner_sid_candidate,account_state
                 FROM BitsHistory WHERE event_record_id='1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(owner.0, "WIN-TEST\\Administrator");
        assert_eq!(owner.1, "WIN-TEST");
        assert_eq!(owner.2, "Administrator");
        assert_eq!(owner.3, None, "a name alone never produces a confirmed SID");
        assert_eq!(owner.4, "name_only");
        assert_eq!(owner.5, "S-1-5-21-99-99-99-500");
        assert_eq!(owner.6, "metadata_confirmed_name");

        // System context is never promoted to the job owner's identity.
        let context: (String, i64, i64, Option<String>, i64, String) = db
            .query_row(
                "SELECT system_user_sid,system_process_id,system_thread_id,owner_sid_candidate,requester_process_id,client_process_start_key
                 FROM BitsHistory WHERE event_record_id='2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(context.0, "S-1-5-18");
        assert_eq!(context.1, 12544);
        assert_eq!(context.2, 7212);
        assert_eq!(context.3, None, "NT AUTHORITY\\SYSTEM has no confirmed metadata name");
        assert_eq!(context.4, 4321);
        assert_eq!(context.5, "2814749767152643");
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsHistory WHERE account_sid IS NOT NULL"),
            0
        );
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsMetadataReferences WHERE reference_kind='account'"),
            1
        );
    }

    /// R05: search text covers job id, url, path, process and owner.
    #[test]
    fn search_text_covers_parent_and_child_fields() {
        let fx = Fixture::new(1);
        let (_, db) = fx.run(vec![event(1, "16403", "2026-01-01 00:00:00.000", Some(
            r#"{"jobTitle":"Updater","jobId":"JOB-1","jobOwner":"WIN-TEST\\Administrator","RemoteName":"http://host/file.bin","LocalName":"C:\\temp\\file.bin","fileCount":2}"#,
        ))]);
        let text: String = one(&db, "SELECT search_text FROM BitsHistory");
        for needle in ["JOB-1", "http://host/file.bin", "C:\\temp\\file.bin", "WIN-TEST\\Administrator", "Updater"] {
            assert!(text.contains(needle), "search text missing {needle}");
        }
        assert_eq!(one::<i64>(&db, "SELECT declared_file_count FROM BitsFiles"), 2);
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsHistory h WHERE EXISTS(SELECT 1 FROM BitsFiles f WHERE f.record_id=h.record_id AND f.local_path LIKE 'C:\\temp%')"),
            1
        );
    }

    /// A02/A08/R14: observed and unobserved event ids are separate states.
    #[test]
    fn observations_and_coverage_separate_unobserved_ids() {
        let fx = Fixture::new(2);
        fx.inputs(2);
        let (_, db) = fx.run(vec![
            event(1, "59", "2026-01-01 00:00:00.000", Some(r#"{"Id":"A","url":"http://x/1"}"#)),
            event(2, "60", "", Some(r#"{"Id":"A","url":"http://x/1","hr":0}"#)),
        ]);
        let observation: (String, i64, i64, i64, String, String) = db
            .query_row(
                "SELECT collection_state,input_row_count,event_count,untimed_count,source_db,source_dataset_id FROM BitsObservations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(observation.0, "collected");
        assert_eq!(observation.1, 2);
        assert_eq!(observation.2, 2);
        assert_eq!(observation.3, 1);
        assert_eq!(observation.4, "EVENTLOG/EventLogInputs.sqlite");
        assert_eq!(observation.5, "facts-old");
        assert_eq!(
            one::<i64>(&db, "SELECT event_count FROM BitsEventCoverage WHERE event_id=59"),
            1
        );
        let unobserved: (i64, String) = db
            .query_row(
                "SELECT event_count,observation_state FROM BitsEventCoverage WHERE event_id=61",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(unobserved, (0, "unobserved".into()));
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsEventCoverage WHERE observation_state='observed'"),
            2
        );
    }

    /// A ProcessingErrorData payload is the event decoder's failure: its
    /// values are not job data and its error code is not a transfer result.
    #[test]
    fn processing_error_payload_is_not_read_as_job_data() {
        let fx = Fixture::new(1);
        let payload =
            r#"{"ProcessingErrorData":{"ErrorCode":15005,"DataItemName":"hr","EventPayload":"0100"}}"#;
        let (written, db) = fx.run(vec![event(1, "60", "2026-01-01 00:00:00.000", Some(payload))]);
        assert_eq!(written, 1);
        let row: (String, Option<String>, Option<String>, String, Option<i64>, Option<String>) = db
            .query_row(
                "SELECT payload_state,event_data_raw,hr_raw,hr_state,error_code_value,url
                 FROM BitsHistory",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(row.0, "processing_error");
        assert_eq!(row.1.as_deref(), Some(payload), "the raw wrapper stays verbatim");
        assert_eq!(row.2, None);
        assert_eq!(row.3, "unrecorded");
        assert_eq!(row.4, None, "a decoding error code is not a BITS error code");
        assert_eq!(row.5, None);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsFiles"), 0);
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT COUNT(*) FROM source_records WHERE source_field='EventData'"
            ),
            0
        );
    }

    /// A07: every reviewed queue input keeps its collection state even when
    /// nothing was collected; nothing is invented from the absence.
    #[test]
    fn queue_evidence_records_collection_state_of_every_pattern() {
        let fx = Fixture::new(0);
        let (_, db) = fx.run(Vec::new());
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueEvidence WHERE collection_state='not_collected'"),
            crate::parsers::bits_queue::INPUT_PATTERNS.len() as i64
        );
        assert_eq!(
            one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueEvidence WHERE parse_support='not_collected'"),
            crate::parsers::bits_queue::INPUT_PATTERNS.len() as i64
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueJobs"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueFiles"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsHistory"), 0);
    }

    /// A collected queue is parsed into typed job and file snapshots with
    /// their facts coordinates. The snapshot never becomes an event row.
    #[test]
    fn legacy_queue_input_becomes_typed_job_and_file_snapshots() {
        use crate::parsers::bits_queue::fixtures::{file_record, legacy_job, legacy_queue, JobSpec};
        use crate::parsers::bits_queue::{JOB_DELIMITERS, SIZE_UNKNOWN};

        let fx = Fixture::new(0);
        fx.account("S-1-5-21-1-2-3-1001", "Administrator", "WIN-TEST", "WIN-TEST");
        let dir = fx
            .target
            .join("NonVolatile/BITS/ProgramData/Microsoft/Network/Downloader");
        std::fs::create_dir_all(&dir).unwrap();
        let files = vec![
            file_record(
                r"C:\Users\a\Downloads\patch.exe",
                "https://host.test/patch.exe",
                r"C:\Users\a\AppData\Local\Temp\BIT1.tmp",
                4096,
                8192,
            ),
            file_record(
                r"C:\Users\a\Downloads\second.bin",
                "https://host.test/second.bin",
                r"C:\Users\a\AppData\Local\Temp\BIT2.tmp",
                0,
                SIZE_UNKNOWN,
            ),
        ];
        let job = legacy_job(
            &JobSpec {
                name: "WindowsUpdate",
                description: "job description",
                command: r"C:\Windows\System32\cmd.exe",
                arguments: "/c echo done",
                sid: "S-1-5-21-1-2-3-1001",
                flags: 0x0003,
                state: 4,
                ..JobSpec::default()
            },
            &files,
        );
        std::fs::write(
            dir.join("qmgr0.dat"),
            legacy_queue(&[job], JOB_DELIMITERS[2].1, 1),
        )
        .unwrap();

        let (written, db) = fx.run(Vec::new());
        assert_eq!(written, 0);
        let evidence: (String, String, String, i64, i64, i64, i64, i64, String) = db
            .query_row(
                "SELECT collection_state,parse_support,format,declared_job_count,job_record_count,
                        file_record_count,failed_record_count,job_delimiter_id,source_dataset_id
                 FROM BitsQueueEvidence WHERE search_pattern='qmgr0.dat'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .unwrap();
        // Two file records are present, but only the first has a proven
        // boundary: the job and the input report the unproven candidate.
        assert_eq!(
            evidence,
            (
                "collected".into(),
                "parsed_with_errors".into(),
                "legacy_qmgr_queue".into(),
                1,
                1,
                2,
                2,
                3,
                "new".into()
            )
        );

        let job_row: (String, String, String, String, String, String, String, i64, String, String, String, i64, i64, String) = db
            .query_row(
                "SELECT job_id,job_type,priority,state,job_name,job_description,notify_command,
                        notify_flags_unmapped,notify_flags,owner_sid,owner_name,declared_file_count,
                        parsed_file_count,file_count_state
                 FROM BitsQueueJobs",
                [],
                |r| {
                    Ok((
                        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                        r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?, r.get(13)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(job_row.0, "12345678-1234-5678-9abc-def011223344");
        assert_eq!(job_row.1, "BG_JOB_TYPE_DOWNLOAD");
        assert_eq!(job_row.2, "BG_JOB_PRIORITY_NORMAL");
        assert_eq!(job_row.3, "BG_JOB_STATE_ERROR");
        assert_eq!(job_row.4, "WindowsUpdate");
        assert_eq!(job_row.5, "job description");
        assert_eq!(job_row.6, r"C:\Windows\System32\cmd.exe");
        assert_eq!(job_row.7, 0);
        assert!(job_row.8.contains("BG_NOTIFY_JOB_TRANSFERRED"));
        assert!(job_row.8.contains("BG_NOTIFY_JOB_ERROR"));
        assert_eq!(job_row.9, "S-1-5-21-1-2-3-1001");
        assert_eq!(job_row.10, "Administrator");
        assert_eq!((job_row.11, job_row.12), (2, 2));
        assert_eq!(one::<String>(&db, "SELECT parse_status FROM BitsQueueJobs"), "partial");
        assert!(one::<String>(&db, "SELECT parse_error FROM BitsQueueJobs").contains("증명되지"));
        assert_eq!(job_row.13, "matches_with_unproven_boundary");

        let created: String = one(&db, "SELECT created_time FROM BitsQueueJobs");
        assert_eq!(created, crate::time::fmt_filetime(132_000_000_000_000_000));
        let created_raw: String = one(&db, "SELECT created_time_raw FROM BitsQueueJobs");
        assert_eq!(created_raw, "132000000000000000");
        let errors: String = one(&db, "SELECT errors_json FROM BitsQueueJobs");
        assert!(errors.contains("0x0000000080070005"));
        assert_eq!(one::<i64>(&db, "SELECT transient_error_count FROM BitsQueueJobs"), 2);
        assert_eq!(one::<i64>(&db, "SELECT retry_delay_raw FROM BitsQueueJobs"), 600);
        assert_eq!(one::<i64>(&db, "SELECT timeout_raw FROM BitsQueueJobs"), 1_209_600);
        assert_eq!(one::<String>(&db, "SELECT metadata_state FROM BitsQueueJobs"), "parsed");
        assert!(one::<i64>(&db, "SELECT LENGTH(record_blob) FROM BitsQueueJobs") > 0);
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT COUNT(*) FROM BitsQueueJobs j JOIN BitsQueueEvidence e ON e.evidence_id=j.evidence_id
                 WHERE j.source_dataset_id='new' AND j.source_db='SUPPLEMENTAL/Bits_Queue.sqlite'
                   AND j.source_table='BitsQueue_Jobs' AND j.source_rowid>0"
            ),
            1
        );

        let first: (String, String, String, i64, i64, String, String, String) = db
            .query_row(
                "SELECT source_url,dest_file,tmp_file,download_size,transfer_size,download_size_state,
                        link_basis,dest_path_resolution_state
                 FROM BitsQueueFiles WHERE file_index_in_job=0",
                [],
                |r| {
                    Ok((
                        r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(first.0, "https://host.test/patch.exe");
        assert_eq!(first.1, r"C:\Users\a\Downloads\patch.exe");
        assert_eq!(first.2, r"C:\Users\a\AppData\Local\Temp\BIT1.tmp");
        assert_eq!((first.3, first.4), (4096, 8192));
        assert_eq!(first.5, "recorded");
        assert_eq!(first.6, "legacy_job_transfer_section");
        assert_eq!(first.7, "literal");

        // BG_SIZE_UNKNOWN stays a sentinel, never a size.
        let second: (Option<i64>, String, String) = db
            .query_row(
                "SELECT transfer_size,transfer_size_raw,transfer_size_state FROM BitsQueueFiles
                 WHERE file_index_in_job=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(second, (None, "18446744073709551615".into(), "unknown_sentinel".into()));
        // The second record was recovered past an undocumented trailer: the
        // row says the boundary is unproven and keeps its bytes.
        let candidate: (String, String, String, i64) = db
            .query_row(
                "SELECT parse_status,parse_method,evidence_basis,LENGTH(record_blob)
                 FROM BitsQueueFiles WHERE file_index_in_job=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(candidate.0, "heuristic_boundary");
        assert_eq!(candidate.1, "heuristic_resync");
        assert!(candidate.2.contains("증명되지"));
        assert!(candidate.3 > 0);
        assert_eq!(
            one::<String>(&db, "SELECT parse_status FROM BitsQueueFiles WHERE file_index_in_job=0"),
            "parsed"
        );
        assert_eq!(
            one::<i64>(
                &db,
                "SELECT COUNT(*) FROM BitsQueueFiles f JOIN BitsQueueJobs j ON j.queue_job_id=f.queue_job_id"
            ),
            2
        );
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueFiles WHERE drive='C:'"), 2);
        // A queue snapshot is not an event and not a transfer result.
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsHistory"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsFiles"), 0);
        let violations: i64 = db
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(violations, 0);
    }

    /// Unreadable, foreign and truncated inputs keep an explicit failure; an
    /// empty valid result would hide them.
    #[test]
    fn unsupported_and_truncated_queue_inputs_keep_their_errors() {
        use crate::parsers::bits_queue::fixtures::{legacy_job, legacy_queue, JobSpec};
        use crate::parsers::bits_queue::JOB_DELIMITERS;

        let fx = Fixture::new(0);
        let dir = fx.target.join("NonVolatile/BITS/Downloader");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("qmgr.db"), b"SQLite format 3\0 not an ESE database").unwrap();
        let complete = legacy_queue(&[legacy_job(&JobSpec::default(), &[])], JOB_DELIMITERS[0].1, 1);
        std::fs::write(dir.join("qmgr0.dat"), &complete[..complete.len() - 40]).unwrap();

        let (_, db) = fx.run(Vec::new());
        let database: (String, String, String, Option<String>) = db
            .query_row(
                "SELECT parse_support,parse_status,format,parse_error FROM BitsQueueEvidence
                 WHERE search_pattern='qmgr.db'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(database.0, "unsupported_format");
        assert_eq!(database.1, "unsupported_format");
        assert_eq!(database.2, "unknown");
        assert!(database.3.is_some());
        let legacy: (String, String, Option<String>, Option<String>) = db
            .query_row(
                "SELECT parse_support,parse_status,parse_error,format_detail FROM BitsQueueEvidence
                 WHERE search_pattern='qmgr0.dat'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(legacy.0, "truncated");
        assert_eq!(legacy.1, "truncated");
        assert!(legacy.2.is_some());
        assert!(legacy.3.is_some());
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueJobs"), 0);
        assert_eq!(one::<i64>(&db, "SELECT COUNT(*) FROM BitsQueueFiles"), 0);
    }

    /// A record that stops short keeps the values it did yield, its raw bytes
    /// and the reason it is incomplete.
    #[test]
    fn partial_queue_record_keeps_values_raw_bytes_and_reason() {
        use crate::parsers::bits_queue::fixtures::{control, file_record, legacy_queue, JobSpec};
        use crate::parsers::bits_queue::{JOB_DELIMITERS, XFER_HEADER};

        let fx = Fixture::new(0);
        let dir = fx.target.join("NonVolatile/BITS/Downloader");
        std::fs::create_dir_all(&dir).unwrap();
        let spec = JobSpec { name: "truncated-job", ..JobSpec::default() };
        let mut job = control(&spec);
        job.extend_from_slice(&XFER_HEADER);
        job.extend_from_slice(&1u32.to_le_bytes());
        job.extend(file_record(r"C:\a\x.bin", "http://host.test/x.bin", r"C:\a\x.tmp", 7, 9));
        std::fs::write(
            dir.join("qmgr1.dat"),
            legacy_queue(&[job.clone()], JOB_DELIMITERS[4].1, 1),
        )
        .unwrap();

        let (_, db) = fx.run(Vec::new());
        let row: (String, String, Option<String>, Option<String>, i64) = db
            .query_row(
                "SELECT parse_status,metadata_state,parse_error,created_time,LENGTH(record_blob)
                 FROM BitsQueueJobs",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(row.0, "partial");
        assert_eq!(row.1, "absent");
        assert!(row.2.is_some());
        assert!(row.3.is_none());
        assert_eq!(row.4, job.len() as i64);
        assert_eq!(one::<String>(&db, "SELECT job_name FROM BitsQueueJobs"), "truncated-job");
        assert_eq!(
            one::<String>(&db, "SELECT source_url FROM BitsQueueFiles"),
            "http://host.test/x.bin"
        );
        assert_eq!(
            one::<i64>(&db, "SELECT failed_record_count FROM BitsQueueEvidence WHERE search_pattern='qmgr1.dat'"),
            1
        );
        assert_eq!(
            one::<String>(&db, "SELECT parse_support FROM BitsQueueEvidence WHERE search_pattern='qmgr1.dat'"),
            "parsed_with_errors"
        );
    }
}
