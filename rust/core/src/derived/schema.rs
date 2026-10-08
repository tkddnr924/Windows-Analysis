//! Canonical overview DDL and storage-order column definitions.

pub struct ChildSpec {
    pub table: &'static str,
    pub columns: &'static [&'static str],
}

pub struct DbSpec {
    pub name: &'static str,
    pub table: &'static str,
    pub columns: &'static [&'static str],
    pub children: &'static [ChildSpec],
    pub ddl: &'static str,
}

impl DbSpec {
    pub fn index_of(&self, column: &str) -> Option<usize> {
        self.columns.iter().position(|c| *c == column)
    }

    pub fn child(&self, table: &str) -> Option<&ChildSpec> {
        self.children.iter().find(|c| c.table == table)
    }
}

// Common columns for all 20 event overviews; metadata has its own contract.
pub const COMMON_COLUMNS: &[&str] = &[
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
];

pub const SOURCE_RECORDS_TABLE: &str = "source_records";
pub const SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const METADATA_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "metadata" (
  "metadata_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "key" TEXT NOT NULL,
  "value" TEXT,
  "raw_value" TEXT,
  "resolution_status" TEXT NOT NULL,
  "observed_at" TEXT,
  "account_name" TEXT,
  "account_sid" TEXT,
  "full_name" TEXT,
  "domain" TEXT,
  "account_kind" TEXT,
  "name_source" TEXT,
  "rid" INTEGER,
  "rid_sam" INTEGER,
  "home_directory" TEXT,
  "profile_path" TEXT,
  "profile_path_resolved" TEXT,
  "created" TEXT,
  "last_login" TEXT,
  "password_last_set" TEXT,
  "last_failed_login" TEXT,
  "login_count" INTEGER,
  "failed_login_count" INTEGER,
  "disabled" INTEGER CHECK ("disabled" IN (0,1)),
  "special_account" INTEGER CHECK ("special_account" IN (0,1)),
  "account_flags" TEXT,
  "interface_id" TEXT,
  "interface_name" TEXT,
  "mac_address" TEXT,
  "network_profile" TEXT,
  "dhcp_enabled" INTEGER CHECK ("dhcp_enabled" IN (0,1)),
  "dhcp_server" TEXT,
  "lease_obtained" TEXT,
  "lease_terminates" TEXT,
  "env_name" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  "selection_reason" TEXT,
  PRIMARY KEY(metadata_id),
  UNIQUE(kind, scope, key),
  CHECK(kind IN ('host','account','network','env')),
  CHECK(resolution_status IN ('resolved','missing','conflict','unresolved')),
  CHECK(kind <> 'account' OR (account_sid IS NOT NULL AND key = lower(account_sid)))
);
CREATE INDEX idx_metadata_account ON metadata(account_sid) WHERE kind = 'account';
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
  FOREIGN KEY(record_id) REFERENCES "metadata"("metadata_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "MetadataAddresses" (
  "metadata_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "address" TEXT,
  "family" INTEGER,
  "prefix_length" INTEGER,
  "subnet_mask" TEXT,
  PRIMARY KEY ("metadata_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("metadata_id") REFERENCES "metadata"("metadata_id") ON DELETE CASCADE
);
CREATE TABLE "MetadataGateways" (
  "metadata_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "address" TEXT,
  "metric" INTEGER,
  PRIMARY KEY ("metadata_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("metadata_id") REFERENCES "metadata"("metadata_id") ON DELETE CASCADE
);
CREATE TABLE "MetadataDnsServers" (
  "metadata_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "address" TEXT,
  PRIMARY KEY ("metadata_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("metadata_id") REFERENCES "metadata"("metadata_id") ON DELETE CASCADE
);
CREATE TABLE "MetadataGroups" (
  "metadata_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "group_sid" TEXT,
  "group_name" TEXT,
  PRIMARY KEY ("metadata_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("metadata_id") REFERENCES "metadata"("metadata_id") ON DELETE CASCADE
);
CREATE TABLE "MetadataCandidates" (
  "metadata_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "candidate_value" TEXT,
  "source_ordinal" INTEGER,
  "reason" TEXT,
  PRIMARY KEY ("metadata_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("metadata_id") REFERENCES "metadata"("metadata_id") ON DELETE CASCADE,
  FOREIGN KEY (metadata_id, source_ordinal) REFERENCES source_records(record_id, ordinal)
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const METADATA_COLUMNS: &[&str] = &[
    "metadata_id",
    "host_id",
    "dataset_id",
    "kind",
    "scope",
    "key",
    "value",
    "raw_value",
    "resolution_status",
    "observed_at",
    "account_name",
    "account_sid",
    "full_name",
    "domain",
    "account_kind",
    "name_source",
    "rid",
    "rid_sam",
    "home_directory",
    "profile_path",
    "profile_path_resolved",
    "created",
    "last_login",
    "password_last_set",
    "last_failed_login",
    "login_count",
    "failed_login_count",
    "disabled",
    "special_account",
    "account_flags",
    "interface_id",
    "interface_name",
    "mac_address",
    "network_profile",
    "dhcp_enabled",
    "dhcp_server",
    "lease_obtained",
    "lease_terminates",
    "env_name",
    "details_json",
    "selection_reason",
];

const METADATA_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const METADATA_METADATA_ADDRESSES_COLUMNS: &[&str] = &[
    "metadata_id",
    "ordinal",
    "address",
    "family",
    "prefix_length",
    "subnet_mask",
];

const METADATA_METADATA_GATEWAYS_COLUMNS: &[&str] = &[
    "metadata_id",
    "ordinal",
    "address",
    "metric",
];

const METADATA_METADATA_DNS_SERVERS_COLUMNS: &[&str] = &[
    "metadata_id",
    "ordinal",
    "address",
];

const METADATA_METADATA_GROUPS_COLUMNS: &[&str] = &[
    "metadata_id",
    "ordinal",
    "group_sid",
    "group_name",
];

const METADATA_METADATA_CANDIDATES_COLUMNS: &[&str] = &[
    "metadata_id",
    "ordinal",
    "candidate_value",
    "source_ordinal",
    "reason",
];

const METADATA_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: METADATA_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "MetadataAddresses", columns: METADATA_METADATA_ADDRESSES_COLUMNS },
    ChildSpec { table: "MetadataGateways", columns: METADATA_METADATA_GATEWAYS_COLUMNS },
    ChildSpec { table: "MetadataDnsServers", columns: METADATA_METADATA_DNS_SERVERS_COLUMNS },
    ChildSpec { table: "MetadataGroups", columns: METADATA_METADATA_GROUPS_COLUMNS },
    ChildSpec { table: "MetadataCandidates", columns: METADATA_METADATA_CANDIDATES_COLUMNS },
];


const EXECUTION_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "ExecutionHistory" (
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
  "program_name" TEXT,
  "program_path" TEXT,
  "program_path_resolved" TEXT,
  "run_count" INTEGER,
  "focus_count" INTEGER,
  "focus_time_ms" INTEGER,
  "publisher" TEXT,
  "sha1" TEXT,
  "prefetch_hash" TEXT,
  "command_line" TEXT,
  "process_id" TEXT,
  "parent_process_id" TEXT,
  "parent_process_path" TEXT,
  "account_role" TEXT,
  "subject_user_sid" TEXT,
  "subject_user_name" TEXT,
  "subject_domain_name" TEXT,
  "subject_logon_id" TEXT,
  "target_user_sid" TEXT,
  "target_user_name" TEXT,
  "target_domain_name" TEXT,
  "target_logon_id" TEXT,
  "event_id" INTEGER,
  "event_provider" TEXT,
  "event_channel" TEXT,
  "event_record_id" TEXT,
  "event_process_id" TEXT,
  "event_thread_id" TEXT,
  "event_user_sid" TEXT,
  "event_computer" TEXT,
  "event_data" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'ExecutionHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_ExecutionHistory_time" ON "ExecutionHistory"(timestamp, record_id);
CREATE INDEX "idx_ExecutionHistory_account" ON "ExecutionHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "ExecutionHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "ExecutionTimes" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "execution_time" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ExecutionHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE "ExecutionVolumes" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "device_path" TEXT,
  "serial_number" TEXT,
  "created_at" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ExecutionHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('execution_history',3);
"#;

const EXECUTION_HISTORY_COLUMNS: &[&str] = &[
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
    "program_name",
    "program_path",
    "program_path_resolved",
    "run_count",
    "focus_count",
    "focus_time_ms",
    "publisher",
    "sha1",
    "prefetch_hash",
    "command_line",
    "process_id",
    "parent_process_id",
    "parent_process_path",
    "account_role",
    "subject_user_sid",
    "subject_user_name",
    "subject_domain_name",
    "subject_logon_id",
    "target_user_sid",
    "target_user_name",
    "target_domain_name",
    "target_logon_id",
    "event_id",
    "event_provider",
    "event_channel",
    "event_record_id",
    "event_process_id",
    "event_thread_id",
    "event_user_sid",
    "event_computer",
    "event_data",
];

const EXECUTION_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const EXECUTION_HISTORY_EXECUTION_TIMES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "execution_time",
];

const EXECUTION_HISTORY_EXECUTION_VOLUMES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "device_path",
    "serial_number",
    "created_at",
];

const EXECUTION_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: EXECUTION_HISTORY_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "ExecutionTimes", columns: EXECUTION_HISTORY_EXECUTION_TIMES_COLUMNS },
    ChildSpec { table: "ExecutionVolumes", columns: EXECUTION_HISTORY_EXECUTION_VOLUMES_COLUMNS },
];


const POWER_SHELL_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "PowerShellHistory" (
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
  "process" TEXT,
  "process_id" INTEGER,
  "command" TEXT,
  "script_block" TEXT,
  "host_application" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  "script_path" TEXT,
  "script_path_resolved" TEXT,
  "line_number" INTEGER,
  "session_id" TEXT,
  "script_block_id" TEXT,
  "runspace_id" TEXT,
  "context_info" TEXT,
  "error_message" TEXT,
  "event_data" TEXT,
  "event_channel" TEXT,
  "event_record_id" TEXT,
  "event_level" INTEGER,
  "script_block_status" TEXT,
  "script_block_expected_parts" INTEGER,
  "script_block_observed_parts" INTEGER,
  "script_block_missing" TEXT,
  "script_block_conflicts" TEXT,
  "script_block_anomalies" TEXT,
  "console_history_status" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'PowerShellHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_PowerShellHistory_time" ON "PowerShellHistory"(timestamp, record_id);
CREATE INDEX "idx_PowerShellHistory_account" ON "PowerShellHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "PowerShellHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "PowerShellScriptParts" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_ordinal" INTEGER NOT NULL,
  "timestamp" TEXT,
  "message_number" INTEGER,
  "message_total" INTEGER,
  "script_block" TEXT,
  "event_data" TEXT,
  "event_record_id" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "PowerShellHistory"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(record_id, source_ordinal) REFERENCES "source_records"("record_id", "ordinal")
);
CREATE TABLE "PowerShellEncodedCommands" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_field" TEXT NOT NULL,
  "encoded_command" TEXT NOT NULL,
  "decoded_command" TEXT,
  "decode_method" TEXT NOT NULL,
  "decode_status" TEXT NOT NULL,
  "decode_error" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(source_field IN ('command', 'host_application')),
  FOREIGN KEY(record_id) REFERENCES "PowerShellHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE "PowerShellConsoleLines" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_ordinal" INTEGER NOT NULL,
  "line_number" INTEGER,
  "command" TEXT NOT NULL,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "PowerShellHistory"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(record_id, source_ordinal) REFERENCES "source_records"("record_id", "ordinal")
);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('powershell_history',3);
"#;

const POWER_SHELL_HISTORY_COLUMNS: &[&str] = &[
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
    "process",
    "process_id",
    "command",
    "script_block",
    "host_application",
    "event_id",
    "provider",
    "script_path",
    "script_path_resolved",
    "line_number",
    "session_id",
    "script_block_id",
    "runspace_id",
    "context_info",
    "error_message",
    "event_data",
    "event_channel",
    "event_record_id",
    "event_level",
    "script_block_status",
    "script_block_expected_parts",
    "script_block_observed_parts",
    "script_block_missing",
    "script_block_conflicts",
    "script_block_anomalies",
    "console_history_status",
];

const POWER_SHELL_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const POWER_SHELL_SCRIPT_PARTS_COLUMNS: &[&str] = &[
    "record_id", "ordinal", "source_ordinal", "timestamp", "message_number",
    "message_total", "script_block", "event_data", "event_record_id",
];

const POWER_SHELL_ENCODED_COMMANDS_COLUMNS: &[&str] = &[
    "record_id", "ordinal", "source_field", "encoded_command", "decoded_command",
    "decode_method", "decode_status", "decode_error",
];

const POWER_SHELL_CONSOLE_LINES_COLUMNS: &[&str] = &[
    "record_id", "ordinal", "source_ordinal", "line_number", "command",
];

const POWER_SHELL_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: POWER_SHELL_HISTORY_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "PowerShellScriptParts", columns: POWER_SHELL_SCRIPT_PARTS_COLUMNS },
    ChildSpec { table: "PowerShellEncodedCommands", columns: POWER_SHELL_ENCODED_COMMANDS_COLUMNS },
    ChildSpec { table: "PowerShellConsoleLines", columns: POWER_SHELL_CONSOLE_LINES_COLUMNS },
];


const BROWSER_ACTIVITY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "BrowserActivity" (
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
  "browser" TEXT,
  "profile" TEXT,
  "title" TEXT,
  "url" TEXT,
  "url_raw" TEXT,
  "visit_count" INTEGER,
  "typed_count" INTEGER,
  "detail" TEXT,
  "size" TEXT,
  "size_bytes" INTEGER,
  "mime" TEXT,
  "danger" TEXT,
  "source_url" TEXT,
  "status" TEXT,
  "http_status" INTEGER,
  "cache_key" TEXT,
  "cache_body_recovered" INTEGER CHECK ("cache_body_recovered" IN (0,1)),
  "download_path" TEXT,
  "download_path_resolved" TEXT,
  "response_headers" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'BrowserActivity'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_BrowserActivity_time" ON "BrowserActivity"(timestamp, record_id);
CREATE INDEX "idx_BrowserActivity_account" ON "BrowserActivity"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "BrowserActivity"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const BROWSER_ACTIVITY_COLUMNS: &[&str] = &[
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
    "browser",
    "profile",
    "title",
    "url",
    "url_raw",
    "visit_count",
    "typed_count",
    "detail",
    "size",
    "size_bytes",
    "mime",
    "danger",
    "source_url",
    "status",
    "http_status",
    "cache_key",
    "cache_body_recovered",
    "download_path",
    "download_path_resolved",
    "response_headers",
];

const BROWSER_ACTIVITY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const BROWSER_ACTIVITY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: BROWSER_ACTIVITY_SOURCE_RECORDS_COLUMNS },
];


const AI_CONVERSATIONS_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "AiConversations" (
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
  "provider" TEXT,
  "conversation_id" TEXT,
  "service_account" TEXT,
  "title" TEXT,
  "created_at" TEXT,
  "updated_at" TEXT,
  "url" TEXT,
  "raw_json" TEXT CHECK ("raw_json" IS NULL OR json_valid("raw_json")),
  "message_count" INTEGER,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'AiConversations'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_AiConversations_time" ON "AiConversations"(timestamp, record_id);
CREATE INDEX "idx_AiConversations_account" ON "AiConversations"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "AiConversations"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "AiMessages" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "message_id" TEXT,
  "role" TEXT,
  "content" TEXT,
  "created_at" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "AiConversations"("record_id") ON DELETE CASCADE
);
CREATE TABLE "AiAttachments" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "message_ordinal" INTEGER,
  "url" TEXT,
  "file_name" TEXT,
  "mime" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "AiConversations"("record_id") ON DELETE CASCADE,
  FOREIGN KEY (record_id, message_ordinal) REFERENCES AiMessages(record_id, ordinal)
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const AI_CONVERSATIONS_COLUMNS: &[&str] = &[
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
    "provider",
    "conversation_id",
    "service_account",
    "title",
    "created_at",
    "updated_at",
    "url",
    "raw_json",
    "message_count",
];

const AI_CONVERSATIONS_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const AI_CONVERSATIONS_AI_MESSAGES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "message_id",
    "role",
    "content",
    "created_at",
];

const AI_CONVERSATIONS_AI_ATTACHMENTS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "message_ordinal",
    "url",
    "file_name",
    "mime",
];

const AI_CONVERSATIONS_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: AI_CONVERSATIONS_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "AiMessages", columns: AI_CONVERSATIONS_AI_MESSAGES_COLUMNS },
    ChildSpec { table: "AiAttachments", columns: AI_CONVERSATIONS_AI_ATTACHMENTS_COLUMNS },
];


const REGISTRY_FINDINGS_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "RegistryFindings" (
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
  "category" TEXT,
  "name" TEXT,
  "value" TEXT,
  "value_type" TEXT,
  "status" TEXT,
  "detail" TEXT,
  "key_path" TEXT,
  "source" TEXT,
  "command" TEXT,
  "command_resolved" TEXT,
  "subtype" TEXT,
  "properties" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'RegistryFindings'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_RegistryFindings_time" ON "RegistryFindings"(timestamp, record_id);
CREATE INDEX "idx_RegistryFindings_account" ON "RegistryFindings"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "RegistryFindings"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const REGISTRY_FINDINGS_COLUMNS: &[&str] = &[
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
    "category",
    "name",
    "value",
    "value_type",
    "status",
    "detail",
    "key_path",
    "source",
    "command",
    "command_resolved",
    "subtype",
    "properties",
];

const REGISTRY_FINDINGS_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const REGISTRY_FINDINGS_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: REGISTRY_FINDINGS_SOURCE_RECORDS_COLUMNS },
];


const REMOTE_DESKTOP_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "RemoteDesktopHistory" (
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
  "direction" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  "remote_address" TEXT,
  "remote_computer" TEXT,
  "remote_port" INTEGER,
  "local_address" TEXT,
  "logon_type" INTEGER,
  "session_id" TEXT,
  "logon_id" TEXT,
  "result" TEXT,
  "start_time" TEXT,
  "end_time" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'RemoteDesktopHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_RemoteDesktopHistory_time" ON "RemoteDesktopHistory"(timestamp, record_id);
CREATE INDEX "idx_RemoteDesktopHistory_account" ON "RemoteDesktopHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "RemoteDesktopHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const REMOTE_DESKTOP_HISTORY_COLUMNS: &[&str] = &[
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
    "local_address",
    "logon_type",
    "session_id",
    "logon_id",
    "result",
    "start_time",
    "end_time",
];

const REMOTE_DESKTOP_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const REMOTE_DESKTOP_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: REMOTE_DESKTOP_HISTORY_SOURCE_RECORDS_COLUMNS },
];


const SMB_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "SmbHistory" (
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
  "direction" TEXT,
  "remote_address" TEXT,
  "remote_port" INTEGER,
  "share_name" TEXT,
  "share_path" TEXT,
  "target_file" TEXT,
  "access_mask" TEXT,
  "access_rights" TEXT,
  "result" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'SmbHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_SmbHistory_time" ON "SmbHistory"(timestamp, record_id);
CREATE INDEX "idx_SmbHistory_account" ON "SmbHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "SmbHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const SMB_HISTORY_COLUMNS: &[&str] = &[
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
    "remote_address",
    "remote_port",
    "share_name",
    "share_path",
    "target_file",
    "access_mask",
    "access_rights",
    "result",
    "event_id",
    "provider",
];

const SMB_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const SMB_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: SMB_HISTORY_SOURCE_RECORDS_COLUMNS },
];


const SCHEDULED_TASKS_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "ScheduledTasks" (
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
  "task_name" TEXT,
  "task_path" TEXT,
  "is_microsoft" INTEGER CHECK ("is_microsoft" IN (0,1)),
  "run_as" TEXT,
  "run_as_sid" TEXT,
  "run_level" TEXT,
  "logon_type" TEXT,
  "enabled" INTEGER CHECK ("enabled" IN (0,1)),
  "hidden" INTEGER CHECK ("hidden" IN (0,1)),
  "author" TEXT,
  "task_description" TEXT,
  "uri" TEXT,
  "result" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'ScheduledTasks'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_ScheduledTasks_time" ON "ScheduledTasks"(timestamp, record_id);
CREATE INDEX "idx_ScheduledTasks_account" ON "ScheduledTasks"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "TaskActions" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "action_type" TEXT,
  "command" TEXT,
  "command_resolved" TEXT,
  "arguments" TEXT,
  "working_directory" TEXT,
  "raw_action" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE TABLE "TaskTriggers" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "trigger_type" TEXT,
  "start_time" TEXT,
  "end_time" TEXT,
  "enabled" INTEGER CHECK ("enabled" IN (0,1)),
  "raw_trigger" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const SCHEDULED_TASKS_COLUMNS: &[&str] = &[
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
    "task_name",
    "task_path",
    "is_microsoft",
    "run_as",
    "run_as_sid",
    "run_level",
    "logon_type",
    "enabled",
    "hidden",
    "author",
    "task_description",
    "uri",
    "result",
    "event_id",
    "provider",
];

const SCHEDULED_TASKS_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const SCHEDULED_TASKS_TASK_ACTIONS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "action_type",
    "command",
    "command_resolved",
    "arguments",
    "working_directory",
    "raw_action",
];

const SCHEDULED_TASKS_TASK_TRIGGERS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "trigger_type",
    "start_time",
    "end_time",
    "enabled",
    "raw_trigger",
];

const SCHEDULED_TASKS_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: SCHEDULED_TASKS_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "TaskActions", columns: SCHEDULED_TASKS_TASK_ACTIONS_COLUMNS },
    ChildSpec { table: "TaskTriggers", columns: SCHEDULED_TASKS_TASK_TRIGGERS_COLUMNS },
];


const SERVICE_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "ServiceHistory" (
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
  "service_name" TEXT,
  "service_key" TEXT,
  "image_path" TEXT,
  "image_path_resolved" TEXT,
  "service_account" TEXT,
  "service_account_sid" TEXT,
  "state" TEXT,
  "start_type_before" TEXT,
  "start_type_after" TEXT,
  "service_type" TEXT,
  "detail" TEXT,
  "result" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'ServiceHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_ServiceHistory_time" ON "ServiceHistory"(timestamp, record_id);
CREATE INDEX "idx_ServiceHistory_account" ON "ServiceHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "ServiceHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const SERVICE_HISTORY_COLUMNS: &[&str] = &[
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
    "service_name",
    "service_key",
    "image_path",
    "image_path_resolved",
    "service_account",
    "service_account_sid",
    "state",
    "start_type_before",
    "start_type_after",
    "service_type",
    "detail",
    "result",
    "event_id",
    "provider",
];

const SERVICE_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const SERVICE_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: SERVICE_HISTORY_SOURCE_RECORDS_COLUMNS },
];


const DEFENDER_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "Defender" (
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
  "section" TEXT,
  "event_id" INTEGER,
  "title" TEXT,
  "detail" TEXT,
  "severity" TEXT,
  "category" TEXT,
  "threat_name" TEXT,
  "target_path" TEXT,
  "detection_type" TEXT,
  "action" TEXT,
  "action_time" TEXT,
  "process" TEXT,
  "source" TEXT,
  "remediation" TEXT,
  "additional_actions" TEXT,
  "origin" TEXT,
  "detection_user" TEXT,
  "raw_line" TEXT,
  "result" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'Defender'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_Defender_time" ON "Defender"(timestamp, record_id);
CREATE INDEX "idx_Defender_account" ON "Defender"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "Defender"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const DEFENDER_COLUMNS: &[&str] = &[
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
    "section",
    "event_id",
    "title",
    "detail",
    "severity",
    "category",
    "threat_name",
    "target_path",
    "detection_type",
    "action",
    "action_time",
    "process",
    "source",
    "remediation",
    "additional_actions",
    "origin",
    "detection_user",
    "raw_line",
    "result",
];

const DEFENDER_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const DEFENDER_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: DEFENDER_SOURCE_RECORDS_COLUMNS },
];


const FIREWALL_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "FirewallHistory" (
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
  "rule_name" TEXT,
  "rule_id" TEXT,
  "app_path" TEXT,
  "app_path_resolved" TEXT,
  "service" TEXT,
  "direction" TEXT,
  "action" TEXT,
  "protocol" TEXT,
  "protocol_number" INTEGER,
  "local_address" TEXT,
  "remote_address" TEXT,
  "local_ports" TEXT,
  "remote_ports" TEXT,
  "local_port" INTEGER,
  "remote_port" INTEGER,
  "profiles" TEXT,
  "modifying_app" TEXT,
  "detail" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'FirewallHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_FirewallHistory_time" ON "FirewallHistory"(timestamp, record_id);
CREATE INDEX "idx_FirewallHistory_account" ON "FirewallHistory"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "FirewallHistory"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const FIREWALL_HISTORY_COLUMNS: &[&str] = &[
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
    "rule_name",
    "rule_id",
    "app_path",
    "app_path_resolved",
    "service",
    "direction",
    "action",
    "protocol",
    "protocol_number",
    "local_address",
    "remote_address",
    "local_ports",
    "remote_ports",
    "local_port",
    "remote_port",
    "profiles",
    "modifying_app",
    "detail",
    "event_id",
    "provider",
];

const FIREWALL_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const FIREWALL_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: FIREWALL_HISTORY_SOURCE_RECORDS_COLUMNS },
];


const BITS_HISTORY_DDL: &str = r#"PRAGMA foreign_keys=ON;
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
  "job_name" TEXT,
  "job_id" TEXT,
  "url" TEXT,
  "local_path" TEXT,
  "local_path_resolved" TEXT,
  "process" TEXT,
  "bytes_transferred" INTEGER,
  "bytes_total" INTEGER,
  "status" TEXT,
  "result" TEXT,
  "event_id" INTEGER,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'BitsHistory'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_BitsHistory_time" ON "BitsHistory"(timestamp, record_id);
CREATE INDEX "idx_BitsHistory_account" ON "BitsHistory"(account_sid, timestamp);
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
CREATE TABLE "BitsFiles" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "url" TEXT,
  "local_path" TEXT,
  "local_path_resolved" TEXT,
  "bytes_transferred" INTEGER,
  "bytes_total" INTEGER,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "BitsHistory"("record_id") ON DELETE CASCADE
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const BITS_HISTORY_COLUMNS: &[&str] = &[
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
    "job_name",
    "job_id",
    "url",
    "local_path",
    "local_path_resolved",
    "process",
    "bytes_transferred",
    "bytes_total",
    "status",
    "result",
    "event_id",
];

const BITS_HISTORY_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const BITS_HISTORY_BITS_FILES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "url",
    "local_path",
    "local_path_resolved",
    "bytes_transferred",
    "bytes_total",
];

const BITS_HISTORY_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: BITS_HISTORY_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "BitsFiles", columns: BITS_HISTORY_BITS_FILES_COLUMNS },
];


const WER_REPORTS_DDL: &str = r#"PRAGMA foreign_keys=ON;
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
  "error_type" TEXT,
  "app_name" TEXT,
  "app_path" TEXT,
  "app_path_resolved" TEXT,
  "target_app_id" TEXT,
  "report_identifier" TEXT,
  "app_pid" INTEGER,
  "app_start_time" TEXT,
  "app_uptime" TEXT,
  "app_uptime_ms" INTEGER,
  "fault_module" TEXT,
  "exception_code" TEXT,
  "report" TEXT,
  "source" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'WerReports'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_WerReports_time" ON "WerReports"(timestamp, record_id);
CREATE INDEX "idx_WerReports_account" ON "WerReports"(account_sid, timestamp);
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

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const WER_REPORTS_COLUMNS: &[&str] = &[
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
    "error_type",
    "app_name",
    "app_path",
    "app_path_resolved",
    "target_app_id",
    "report_identifier",
    "app_pid",
    "app_start_time",
    "app_uptime",
    "app_uptime_ms",
    "fault_module",
    "exception_code",
    "report",
    "source",
];

const WER_REPORTS_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const WER_REPORTS_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: WER_REPORTS_SOURCE_RECORDS_COLUMNS },
];


const RDP_CACHE_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "RdpCache" (
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
  "source_file" TEXT,
  "fragment_index" INTEGER,
  "tile_count" INTEGER,
  "width" INTEGER,
  "height" INTEGER,
  "rows" INTEGER,
  "cols" INTEGER,
  "image" TEXT,
  "status" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'RdpCache'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_RdpCache_time" ON "RdpCache"(timestamp, record_id);
CREATE INDEX "idx_RdpCache_account" ON "RdpCache"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "RdpCache"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const RDP_CACHE_COLUMNS: &[&str] = &[
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
    "source_file",
    "fragment_index",
    "tile_count",
    "width",
    "height",
    "rows",
    "cols",
    "image",
    "status",
];

const RDP_CACHE_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const RDP_CACHE_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: RDP_CACHE_SOURCE_RECORDS_COLUMNS },
];


const TARGET_INFO_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "TargetInfo" (
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
  "metadata_id" TEXT,
  "category" TEXT,
  "name" TEXT,
  "value" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'TargetInfo'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_TargetInfo_time" ON "TargetInfo"(timestamp, record_id);
CREATE INDEX "idx_TargetInfo_account" ON "TargetInfo"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "TargetInfo"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "TargetAccountEvents" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_ordinal" INTEGER NOT NULL,
  "timestamp" TEXT,
  "channel" TEXT,
  "event_id" INTEGER,
  "level_name" TEXT,
  "level" INTEGER,
  "provider" TEXT,
  "computer" TEXT,
  "event_record_id" INTEGER,
  "process_id" INTEGER,
  "thread_id" INTEGER,
  "user_id" TEXT,
  "event_data" TEXT,
  "parse_status" TEXT,
  "parse_error" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  CHECK (source_ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "TargetInfo"("record_id") ON DELETE CASCADE,
  FOREIGN KEY ("record_id", "source_ordinal") REFERENCES "source_records"("record_id", "ordinal") ON DELETE CASCADE
);
CREATE INDEX "idx_TargetAccountEvents_time" ON "TargetAccountEvents"(record_id, timestamp, ordinal);
CREATE UNIQUE INDEX "idx_TargetAccountEvents_source" ON "TargetAccountEvents"(record_id, source_ordinal);
CREATE TABLE "TargetAccountEventMatches" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "event_ordinal" INTEGER NOT NULL,
  "role" TEXT NOT NULL,
  "match_kind" TEXT NOT NULL,
  "field" TEXT,
  "value" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  CHECK (event_ordinal >= 0),
  CHECK (match_kind IN ('sid', 'name')),
  FOREIGN KEY ("record_id") REFERENCES "TargetInfo"("record_id") ON DELETE CASCADE,
  FOREIGN KEY ("record_id", "event_ordinal") REFERENCES "TargetAccountEvents"("record_id", "ordinal") ON DELETE CASCADE
);
CREATE INDEX "idx_TargetAccountEventMatches_event" ON "TargetAccountEventMatches"(record_id, event_ordinal);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('target_info',2);
"#;

const TARGET_INFO_COLUMNS: &[&str] = &[
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
    "metadata_id",
    "category",
    "name",
    "value",
];

const TARGET_INFO_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

pub const TARGET_ACCOUNT_EVENTS_TABLE: &str = "TargetAccountEvents";
const TARGET_INFO_ACCOUNT_EVENTS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "source_ordinal",
    "timestamp",
    "channel",
    "event_id",
    "level_name",
    "level",
    "provider",
    "computer",
    "event_record_id",
    "process_id",
    "thread_id",
    "user_id",
    "event_data",
    "parse_status",
    "parse_error",
];

pub const TARGET_ACCOUNT_EVENT_MATCHES_TABLE: &str = "TargetAccountEventMatches";
const TARGET_INFO_ACCOUNT_EVENT_MATCHES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "event_ordinal",
    "role",
    "match_kind",
    "field",
    "value",
];

const TARGET_INFO_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: TARGET_INFO_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: TARGET_ACCOUNT_EVENTS_TABLE, columns: TARGET_INFO_ACCOUNT_EVENTS_COLUMNS },
    ChildSpec {
        table: TARGET_ACCOUNT_EVENT_MATCHES_TABLE,
        columns: TARGET_INFO_ACCOUNT_EVENT_MATCHES_COLUMNS,
    },
];


const WMI_SUBSCRIPTIONS_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "WmiSubscriptions" (
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
  "object_type" TEXT,
  "namespace" TEXT,
  "object_path" TEXT,
  "filter_name" TEXT,
  "query" TEXT,
  "query_language" TEXT,
  "event_namespace" TEXT,
  "consumer_name" TEXT,
  "consumer_type" TEXT,
  "command" TEXT,
  "command_resolved" TEXT,
  "script_text" TEXT,
  "script_engine" TEXT,
  "filter_ref" TEXT,
  "consumer_ref" TEXT,
  "creator_sid" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'WmiSubscriptions'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_WmiSubscriptions_time" ON "WmiSubscriptions"(timestamp, record_id);
CREATE INDEX "idx_WmiSubscriptions_account" ON "WmiSubscriptions"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "WmiSubscriptions"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const WMI_SUBSCRIPTIONS_COLUMNS: &[&str] = &[
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
    "object_type",
    "namespace",
    "object_path",
    "filter_name",
    "query",
    "query_language",
    "event_namespace",
    "consumer_name",
    "consumer_type",
    "command",
    "command_resolved",
    "script_text",
    "script_engine",
    "filter_ref",
    "consumer_ref",
    "creator_sid",
];

const WMI_SUBSCRIPTIONS_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const WMI_SUBSCRIPTIONS_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: WMI_SUBSCRIPTIONS_SOURCE_RECORDS_COLUMNS },
];


const FILE_SYSTEM_ENTRIES_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "FileSystemEntries" (
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
  "path" TEXT,
  "file_name" TEXT,
  "extension" TEXT,
  "is_directory" INTEGER CHECK ("is_directory" IN (0,1)),
  "in_use" INTEGER CHECK ("in_use" IN (0,1)),
  "file_size" INTEGER,
  "data" BLOB CHECK ("data" IS NULL OR typeof("data") = 'blob'),
  "volume_id" TEXT,
  "volume_label" TEXT,
  "volume_serial" TEXT,
  "drive_letter" TEXT,
  "ntfs_major_version" INTEGER,
  "ntfs_minor_version" INTEGER,
  "volume_flags" TEXT,
  "entry" INTEGER,
  "seq" INTEGER,
  "parent_entry" INTEGER,
  "parent_seq" INTEGER,
  "si_created" TEXT,
  "si_modified" TEXT,
  "si_mft_modified" TEXT,
  "si_accessed" TEXT,
  "owner_id" INTEGER,
  "security_id" INTEGER,
  "fn_created" TEXT,
  "fn_modified" TEXT,
  "fn_mft_modified" TEXT,
  "fn_accessed" TEXT,
  "parent_status" TEXT,
  "path_status" TEXT,
  "data_status" TEXT,
  "source_file" TEXT,
  "source_relative" TEXT,
  "input_name" TEXT,
  "path_key" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'FileSystemEntries'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_FileSystemEntries_time" ON "FileSystemEntries"(timestamp, record_id);
CREATE INDEX "idx_FileSystemEntries_account" ON "FileSystemEntries"(account_sid, timestamp);
CREATE INDEX "idx_FileSystemEntries_entry" ON "FileSystemEntries"(volume_id, entry, seq);
CREATE INDEX "idx_FileSystemEntries_children" ON "FileSystemEntries"(volume_id, parent_entry, parent_seq, parent_status, is_directory, file_name COLLATE NOCASE);
CREATE INDEX "idx_FileSystemEntries_path" ON "FileSystemEntries"(path_key, volume_id);
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
  FOREIGN KEY(record_id) REFERENCES "FileSystemEntries"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('file_system_entries',2);
"#;

const FILE_SYSTEM_ENTRIES_COLUMNS: &[&str] = &[
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
    "path",
    "file_name",
    "extension",
    "is_directory",
    "in_use",
    "file_size",
    "data",
    "volume_id",
    "volume_label",
    "volume_serial",
    "drive_letter",
    "ntfs_major_version",
    "ntfs_minor_version",
    "volume_flags",
    "entry",
    "seq",
    "parent_entry",
    "parent_seq",
    "si_created",
    "si_modified",
    "si_mft_modified",
    "si_accessed",
    "owner_id",
    "security_id",
    "fn_created",
    "fn_modified",
    "fn_mft_modified",
    "fn_accessed",
    "parent_status",
    "path_status",
    "data_status",
    "source_file",
    "source_relative",
    "input_name",
    "path_key",
];

const FILE_SYSTEM_ENTRIES_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const FILE_SYSTEM_ENTRIES_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: FILE_SYSTEM_ENTRIES_SOURCE_RECORDS_COLUMNS },
];


const USN_JOURNAL_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "UsnJournal" (
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
  "file_name" TEXT,
  "path" TEXT,
  "volume_id" TEXT,
  "journal_id" TEXT,
  "usn" TEXT,
  "record_version" INTEGER,
  "file_reference" TEXT,
  "parent_reference" TEXT,
  "reason_mask" TEXT,
  "reason" TEXT,
  "source_info" TEXT,
  "security_id" INTEGER,
  "file_attributes" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'UsnJournal'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_UsnJournal_time" ON "UsnJournal"(timestamp, record_id);
CREATE INDEX "idx_UsnJournal_account" ON "UsnJournal"(account_sid, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const USN_JOURNAL_COLUMNS: &[&str] = &[
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
    "file_name",
    "path",
    "volume_id",
    "journal_id",
    "usn",
    "record_version",
    "file_reference",
    "parent_reference",
    "reason_mask",
    "reason",
    "source_info",
    "security_id",
    "file_attributes",
];

const USN_JOURNAL_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const USN_JOURNAL_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: USN_JOURNAL_SOURCE_RECORDS_COLUMNS },
];


const PATH_REFERENCES_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "PathReferences" (
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
  "path" TEXT,
  "label" TEXT,
  "target_path" TEXT,
  "target_path_resolved" TEXT,
  "app_id" TEXT,
  "jumplist_type" TEXT,
  "arguments" TEXT,
  "working_directory" TEXT,
  "machine_id" TEXT,
  "created_time" TEXT,
  "modified_time" TEXT,
  "access_count" INTEGER,
  "lnk_accessed" TEXT,
  "hostname" TEXT,
  "destlist_accessed" TEXT,
  "timestamp_source" TEXT,
  "target_drive_letter" TEXT,
  "path_kind" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'PathReferences'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_PathReferences_time" ON "PathReferences"(timestamp, record_id);
CREATE INDEX "idx_PathReferences_account" ON "PathReferences"(account_sid, timestamp);
CREATE INDEX "idx_PathReferences_path" ON "PathReferences"(path, record_id);
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
  FOREIGN KEY(record_id) REFERENCES "PathReferences"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "PathReferenceCandidates" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "file_record_id" TEXT NOT NULL,
  "volume_id" TEXT NOT NULL,
  "match_basis" TEXT NOT NULL CHECK (match_basis IN ('path','path_and_drive')),
  PRIMARY KEY(record_id, ordinal),
  UNIQUE(record_id, file_record_id),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES PathReferences(record_id) ON DELETE CASCADE
);
CREATE INDEX "idx_PathReferenceCandidates_file" ON "PathReferenceCandidates"(volume_id, file_record_id);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('path_references',2);
"#;

const PATH_REFERENCES_COLUMNS: &[&str] = &[
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
    "path",
    "label",
    "target_path",
    "target_path_resolved",
    "app_id",
    "jumplist_type",
    "arguments",
    "working_directory",
    "machine_id",
    "created_time",
    "modified_time",
    "access_count",
    "lnk_accessed",
    "hostname",
    "destlist_accessed",
    "timestamp_source",
    "target_drive_letter",
    "path_kind",
];

const PATH_REFERENCES_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const PATH_REFERENCES_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: PATH_REFERENCES_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "PathReferenceCandidates", columns: &[
        "record_id", "ordinal", "file_record_id", "volume_id", "match_basis",
    ] },
];


const RECYCLE_BIN_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "RecycleBin" (
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
  "format_version" INTEGER,
  "original_path" TEXT,
  "original_drive_letter" TEXT,
  "file_size" INTEGER,
  "deleted_time_raw" TEXT,
  "volume_id" TEXT,
  "recycle_name" TEXT,
  "r_exists" INTEGER CHECK ("r_exists" IN (0,1)),
  "status" TEXT,
  "error" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'RecycleBin'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL)
);
CREATE INDEX "idx_RecycleBin_time" ON "RecycleBin"(timestamp, record_id);
CREATE INDEX "idx_RecycleBin_account" ON "RecycleBin"(account_sid, timestamp);
CREATE INDEX "idx_RecycleBin_name" ON "RecycleBin"(volume_id, account_sid, recycle_name);
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
  FOREIGN KEY(record_id) REFERENCES "RecycleBin"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const RECYCLE_BIN_COLUMNS: &[&str] = &[
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
    "format_version",
    "original_path",
    "original_drive_letter",
    "file_size",
    "deleted_time_raw",
    "volume_id",
    "recycle_name",
    "r_exists",
    "status",
    "error",
];

const RECYCLE_BIN_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const RECYCLE_BIN_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: RECYCLE_BIN_SOURCE_RECORDS_COLUMNS },
];


// Canonical generation and reporting order.
pub const SPECS: &[DbSpec] = &[
    DbSpec {
        name: "Metadata",
        table: "metadata",
        columns: METADATA_COLUMNS,
        children: METADATA_CHILDREN,
        ddl: METADATA_DDL,
    },
    DbSpec {
        name: "ExecutionHistory",
        table: "ExecutionHistory",
        columns: EXECUTION_HISTORY_COLUMNS,
        children: EXECUTION_HISTORY_CHILDREN,
        ddl: EXECUTION_HISTORY_DDL,
    },
    DbSpec {
        name: "PowerShellHistory",
        table: "PowerShellHistory",
        columns: POWER_SHELL_HISTORY_COLUMNS,
        children: POWER_SHELL_HISTORY_CHILDREN,
        ddl: POWER_SHELL_HISTORY_DDL,
    },
    DbSpec {
        name: "BrowserActivity",
        table: "BrowserActivity",
        columns: BROWSER_ACTIVITY_COLUMNS,
        children: BROWSER_ACTIVITY_CHILDREN,
        ddl: BROWSER_ACTIVITY_DDL,
    },
    DbSpec {
        name: "AiConversations",
        table: "AiConversations",
        columns: AI_CONVERSATIONS_COLUMNS,
        children: AI_CONVERSATIONS_CHILDREN,
        ddl: AI_CONVERSATIONS_DDL,
    },
    DbSpec {
        name: "RegistryFindings",
        table: "RegistryFindings",
        columns: REGISTRY_FINDINGS_COLUMNS,
        children: REGISTRY_FINDINGS_CHILDREN,
        ddl: REGISTRY_FINDINGS_DDL,
    },
    DbSpec {
        name: "RemoteDesktopHistory",
        table: "RemoteDesktopHistory",
        columns: REMOTE_DESKTOP_HISTORY_COLUMNS,
        children: REMOTE_DESKTOP_HISTORY_CHILDREN,
        ddl: REMOTE_DESKTOP_HISTORY_DDL,
    },
    DbSpec {
        name: "SmbHistory",
        table: "SmbHistory",
        columns: SMB_HISTORY_COLUMNS,
        children: SMB_HISTORY_CHILDREN,
        ddl: SMB_HISTORY_DDL,
    },
    DbSpec {
        name: "ScheduledTasks",
        table: "ScheduledTasks",
        columns: SCHEDULED_TASKS_COLUMNS,
        children: SCHEDULED_TASKS_CHILDREN,
        ddl: SCHEDULED_TASKS_DDL,
    },
    DbSpec {
        name: "ServiceHistory",
        table: "ServiceHistory",
        columns: SERVICE_HISTORY_COLUMNS,
        children: SERVICE_HISTORY_CHILDREN,
        ddl: SERVICE_HISTORY_DDL,
    },
    DbSpec {
        name: "Defender",
        table: "Defender",
        columns: DEFENDER_COLUMNS,
        children: DEFENDER_CHILDREN,
        ddl: DEFENDER_DDL,
    },
    DbSpec {
        name: "FirewallHistory",
        table: "FirewallHistory",
        columns: FIREWALL_HISTORY_COLUMNS,
        children: FIREWALL_HISTORY_CHILDREN,
        ddl: FIREWALL_HISTORY_DDL,
    },
    DbSpec {
        name: "BitsHistory",
        table: "BitsHistory",
        columns: BITS_HISTORY_COLUMNS,
        children: BITS_HISTORY_CHILDREN,
        ddl: BITS_HISTORY_DDL,
    },
    DbSpec {
        name: "WerReports",
        table: "WerReports",
        columns: WER_REPORTS_COLUMNS,
        children: WER_REPORTS_CHILDREN,
        ddl: WER_REPORTS_DDL,
    },
    DbSpec {
        name: "RdpCache",
        table: "RdpCache",
        columns: RDP_CACHE_COLUMNS,
        children: RDP_CACHE_CHILDREN,
        ddl: RDP_CACHE_DDL,
    },
    DbSpec {
        name: "TargetInfo",
        table: "TargetInfo",
        columns: TARGET_INFO_COLUMNS,
        children: TARGET_INFO_CHILDREN,
        ddl: TARGET_INFO_DDL,
    },
    DbSpec {
        name: "WmiSubscriptions",
        table: "WmiSubscriptions",
        columns: WMI_SUBSCRIPTIONS_COLUMNS,
        children: WMI_SUBSCRIPTIONS_CHILDREN,
        ddl: WMI_SUBSCRIPTIONS_DDL,
    },
    DbSpec {
        name: "FileSystemEntries",
        table: "FileSystemEntries",
        columns: FILE_SYSTEM_ENTRIES_COLUMNS,
        children: FILE_SYSTEM_ENTRIES_CHILDREN,
        ddl: FILE_SYSTEM_ENTRIES_DDL,
    },
    DbSpec {
        name: "UsnJournal",
        table: "UsnJournal",
        columns: USN_JOURNAL_COLUMNS,
        children: USN_JOURNAL_CHILDREN,
        ddl: USN_JOURNAL_DDL,
    },
    DbSpec {
        name: "PathReferences",
        table: "PathReferences",
        columns: PATH_REFERENCES_COLUMNS,
        children: PATH_REFERENCES_CHILDREN,
        ddl: PATH_REFERENCES_DDL,
    },
    DbSpec {
        name: "RecycleBin",
        table: "RecycleBin",
        columns: RECYCLE_BIN_COLUMNS,
        children: RECYCLE_BIN_CHILDREN,
        ddl: RECYCLE_BIN_DDL,
    },
];

pub fn spec(name: &str) -> Option<&'static DbSpec> {
    SPECS.iter().find(|s| s.name == name)
}
