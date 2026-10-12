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
  CHECK(kind IN ('host','account','virtual_account','network','env')),
  CHECK(resolution_status IN ('resolved','missing','conflict','unresolved')),
  CHECK(kind NOT IN ('account','virtual_account') OR (account_sid IS NOT NULL AND key = lower(account_sid)))
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
INSERT INTO _wina_derived_version(name,version) VALUES ('execution_history',5);
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


// Full hive inventory and typed key/value evidence, separate from selected findings.
const REGISTRY_EXPLORER_DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "RegistryHives" (
  "hive_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "hive_name" TEXT NOT NULL,
  "source_file" TEXT,
  "facts_db" TEXT,
  "facts_dataset_id" TEXT,
  "inventory_source" TEXT NOT NULL,
  "input_status" TEXT,
  "load_status" TEXT NOT NULL,
  "load_error" TEXT,
  "input_error" TEXT,
  "facts_row_count" INTEGER,
  "logs_discovered" INTEGER,
  "logs_applied" INTEGER,
  "log_error" TEXT,
  "is_regback" INTEGER NOT NULL CHECK ("is_regback" IN (0,1)),
  "key_count" INTEGER NOT NULL,
  "value_count" INTEGER NOT NULL,
  "root_count" INTEGER NOT NULL,
  PRIMARY KEY("hive_id"),
  UNIQUE("ordinal"),
  CHECK("inventory_source" IN ('manifest','facts_scan')),
  CHECK("load_status" IN ('loaded','not_parsed','facts_missing','facts_unreadable')),
  CHECK("load_status" <> 'loaded' OR "facts_dataset_id" IS NOT NULL),
  CHECK("load_status" = 'loaded' OR ("key_count" = 0 AND "value_count" = 0)),
  CHECK("key_count" >= 0 AND "value_count" >= 0 AND "root_count" >= 0)
);
CREATE INDEX "idx_RegistryHives_name" ON "RegistryHives"("hive_name","ordinal");
CREATE INDEX "idx_RegistryHives_facts" ON "RegistryHives"("facts_db");
CREATE TABLE "RegistryExplorer" (
  "record_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "hive_id" TEXT NOT NULL,
  "entry_kind" TEXT NOT NULL,
  "key_record_id" TEXT,
  "parent_record_id" TEXT,
  "parent_status" TEXT,
  "key_offset" TEXT,
  "parent_key_offset" TEXT,
  "key_name" TEXT,
  "key_path" TEXT,
  "key_path_lower" TEXT,
  "key_depth" INTEGER,
  "key_last_write" TEXT,
  "key_subkey_count" INTEGER,
  "key_value_count" INTEGER,
  "stored_subkey_count" INTEGER,
  "stored_value_count" INTEGER,
  "key_read_status" TEXT,
  "key_read_error" TEXT,
  "value_offset" TEXT,
  "value_name" TEXT,
  "value_name_lower" TEXT,
  "value_is_default" INTEGER,
  "value_display_name" TEXT,
  "value_type_code" INTEGER,
  "value_type_code_raw" TEXT,
  "value_type_name" TEXT,
  "value_data" BLOB,
  "value_data_hex" TEXT,
  "value_data_length" INTEGER,
  "value_data_text" TEXT,
  "value_read_status" TEXT,
  "value_read_error" TEXT,
  "recovery" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  PRIMARY KEY("record_id"),
  FOREIGN KEY("hive_id") REFERENCES "RegistryHives"("hive_id") ON DELETE CASCADE,
  FOREIGN KEY("key_record_id") REFERENCES "RegistryExplorer"("record_id") ON DELETE CASCADE,
  FOREIGN KEY("parent_record_id") REFERENCES "RegistryExplorer"("record_id") ON DELETE CASCADE,
  CHECK("entry_kind" IN ('key','value')),
  CHECK(("entry_kind" = 'key') = ("key_path" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("key_offset" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("key_path_lower" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("key_depth" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("key_read_status" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("parent_status" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("stored_subkey_count" IS NOT NULL)),
  CHECK(("entry_kind" = 'key') = ("stored_value_count" IS NOT NULL)),
  CHECK("parent_record_id" IS NULL OR "entry_kind" = 'key'),
  CHECK("key_read_status" IS NULL OR "key_read_status" IN ('ok','partial')),
  CHECK("parent_status" IS NULL OR "parent_status" IN ('root','linked','unresolved')),
  CHECK("parent_status" <> 'root' OR ("parent_key_offset" IS NULL AND "key_depth" = 0)),
  CHECK("parent_status" <> 'linked' OR "parent_record_id" IS NOT NULL),
  CHECK("key_depth" IS NULL OR "key_depth" >= 0),
  CHECK(("entry_kind" = 'value') = ("key_record_id" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_name" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_name_lower" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_is_default" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_read_status" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_data_hex" IS NOT NULL)),
  CHECK(("entry_kind" = 'value') = ("value_data_length" IS NOT NULL)),
  CHECK("value_read_status" IS NULL OR "value_read_status" IN ('ok','empty','error','partial')),
  CHECK("value_is_default" IS NULL OR "value_is_default" IN (0,1)),
  CHECK("value_is_default" IS NULL OR ("value_is_default" = 1) = ("value_name" = '')),
  CHECK("value_data_length" IS NULL OR "value_data_length" >= 0),
  CHECK("value_data" IS NULL OR length("value_data") = "value_data_length"),
  CHECK("value_data" IS NULL OR "value_data_hex" IS NULL
        OR length("value_data_hex") = 2 * length("value_data")),
  CHECK("source_rowid" > 0)
);
CREATE INDEX "idx_RegistryExplorer_hive_path" ON "RegistryExplorer"("hive_id","key_path_lower")
  WHERE "entry_kind" = 'key';
CREATE INDEX "idx_RegistryExplorer_path" ON "RegistryExplorer"("key_path_lower","hive_id")
  WHERE "entry_kind" = 'key';
CREATE INDEX "idx_RegistryExplorer_children" ON "RegistryExplorer"("parent_record_id","key_path_lower")
  WHERE "entry_kind" = 'key';
CREATE INDEX "idx_RegistryExplorer_key_offset" ON "RegistryExplorer"("hive_id","key_offset")
  WHERE "entry_kind" = 'key';
CREATE INDEX "idx_RegistryExplorer_key_source" ON "RegistryExplorer"("hive_id","source_rowid")
  WHERE "entry_kind" = 'key';
CREATE UNIQUE INDEX "idx_RegistryExplorer_value_source" ON "RegistryExplorer"("hive_id","source_rowid")
  WHERE "entry_kind" = 'value';
CREATE INDEX "idx_RegistryExplorer_values" ON "RegistryExplorer"("key_record_id","source_rowid")
  WHERE "entry_kind" = 'value';
CREATE INDEX "idx_RegistryExplorer_value_name" ON "RegistryExplorer"("value_name_lower","record_id")
  WHERE "entry_kind" = 'value';
CREATE INDEX "idx_RegistryExplorer_value_type" ON "RegistryExplorer"("value_type_code","record_id")
  WHERE "entry_kind" = 'value';
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
  FOREIGN KEY(record_id) REFERENCES "RegistryExplorer"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "RegistryQuickTargets" (
  "finding_record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "resolution" TEXT NOT NULL,
  "basis" TEXT NOT NULL,
  "target_record_id" TEXT,
  "target_kind" TEXT,
  "target_key_path" TEXT,
  "hive_id" TEXT,
  "finding_source_db" TEXT,
  "finding_source_rowid" INTEGER,
  "finding_hive_name" TEXT,
  "finding_key_path" TEXT,
  "candidate_count" INTEGER NOT NULL,
  PRIMARY KEY("finding_record_id","ordinal"),
  CHECK("ordinal" >= 0),
  CHECK("candidate_count" >= 0),
  CHECK("basis" IN ('source_records','key_path')),
  CHECK("resolution" IN ('exact_value','exact_key','parent_key','ancestor_key','ambiguous',
                         'unresolved','unavailable','missing_hive')),
  CHECK(("resolution" IN ('exact_value','exact_key','parent_key','ancestor_key'))
        = ("target_record_id" IS NOT NULL)),
  CHECK(("target_record_id" IS NULL) = ("target_kind" IS NULL)),
  CHECK("target_kind" IS NULL OR "target_kind" IN ('key','value')),
  -- Keep requested paths separate from verified target paths.
  CHECK("target_key_path" IS NULL OR "resolution" IN ('parent_key','ancestor_key')),
  CHECK("resolution" <> 'ancestor_key' OR "target_key_path" IS NOT NULL),
  FOREIGN KEY("target_record_id") REFERENCES "RegistryExplorer"("record_id") ON DELETE CASCADE,
  FOREIGN KEY("hive_id") REFERENCES "RegistryHives"("hive_id") ON DELETE CASCADE
);
CREATE INDEX "idx_RegistryQuickTargets_target" ON "RegistryQuickTargets"("target_record_id");

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('registry_explorer',1);
"#;

pub const REGISTRY_HIVES_TABLE: &str = "RegistryHives";
pub const REGISTRY_QUICK_TARGETS_TABLE: &str = "RegistryQuickTargets";

const REGISTRY_EXPLORER_COLUMNS: &[&str] = &[
    "record_id",
    "host_id",
    "dataset_id",
    "hive_id",
    "entry_kind",
    "key_record_id",
    "parent_record_id",
    "parent_status",
    "key_offset",
    "parent_key_offset",
    "key_name",
    "key_path",
    "key_path_lower",
    "key_depth",
    "key_last_write",
    "key_subkey_count",
    "key_value_count",
    "stored_subkey_count",
    "stored_value_count",
    "key_read_status",
    "key_read_error",
    "value_offset",
    "value_name",
    "value_name_lower",
    "value_is_default",
    "value_display_name",
    "value_type_code",
    "value_type_code_raw",
    "value_type_name",
    "value_data",
    "value_data_hex",
    "value_data_length",
    "value_data_text",
    "value_read_status",
    "value_read_error",
    "recovery",
    "source_rowid",
];

const REGISTRY_EXPLORER_HIVES_COLUMNS: &[&str] = &[
    "hive_id",
    "ordinal",
    "host_id",
    "dataset_id",
    "hive_name",
    "source_file",
    "facts_db",
    "facts_dataset_id",
    "inventory_source",
    "input_status",
    "load_status",
    "load_error",
    "input_error",
    "facts_row_count",
    "logs_discovered",
    "logs_applied",
    "log_error",
    "is_regback",
    "key_count",
    "value_count",
    "root_count",
];

const REGISTRY_EXPLORER_QUICK_TARGETS_COLUMNS: &[&str] = &[
    "finding_record_id",
    "ordinal",
    "resolution",
    "basis",
    "target_record_id",
    "target_kind",
    "target_key_path",
    "hive_id",
    "finding_source_db",
    "finding_source_rowid",
    "finding_hive_name",
    "finding_key_path",
    "candidate_count",
];

const REGISTRY_EXPLORER_SOURCE_RECORDS_COLUMNS: &[&str] = &[
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

const REGISTRY_EXPLORER_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: REGISTRY_HIVES_TABLE, columns: REGISTRY_EXPLORER_HIVES_COLUMNS },
    ChildSpec { table: "source_records", columns: REGISTRY_EXPLORER_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: REGISTRY_QUICK_TARGETS_TABLE, columns: REGISTRY_EXPLORER_QUICK_TARGETS_COLUMNS },
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
CREATE TABLE "UsnChangeGroups" (
  "group_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "input_id" TEXT NOT NULL,
  "input_name" TEXT,
  "source_file" TEXT,
  "source_relative" TEXT,
  "record_version" INTEGER,
  "file_reference" TEXT,
  "file_reference_sort" TEXT,
  "first_parent_reference" TEXT,
  "last_parent_reference" TEXT,
  "first_file_name" TEXT,
  "last_file_name" TEXT,
  "distinct_file_name_count" INTEGER,
  "first_timestamp" TEXT,
  "last_timestamp" TEXT,
  "first_usn" TEXT,
  "first_usn_sort" TEXT,
  "last_usn" TEXT,
  "last_usn_sort" TEXT,
  "first_input_sequence" INTEGER,
  "last_input_sequence" INTEGER,
  "member_count" INTEGER,
  "event_type" TEXT,
  "reason_union_mask" TEXT,
  "reason_union" TEXT,
  "unknown_reason_mask" TEXT,
  "has_unknown_reason" INTEGER CHECK ("has_unknown_reason" IN (0,1)),
  "group_scope" TEXT NOT NULL,
  "grouping_basis" TEXT NOT NULL,
  "boundary_reason" TEXT,
  "close_observed" INTEGER CHECK ("close_observed" IN (0,1)),
  "is_display_summary" INTEGER NOT NULL CHECK ("is_display_summary" = 1),
  "operation_confirmed" INTEGER NOT NULL CHECK ("operation_confirmed" = 0),
  PRIMARY KEY(group_id)
);
CREATE INDEX "idx_UsnChangeGroups_input" ON "UsnChangeGroups"(input_id, first_input_sequence);
CREATE INDEX "idx_UsnChangeGroups_reference" ON "UsnChangeGroups"(input_id, record_version, file_reference_sort);
CREATE INDEX "idx_UsnChangeGroups_time" ON "UsnChangeGroups"(first_timestamp, group_id);
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
  "input_id" TEXT NOT NULL,
  "input_name" TEXT,
  "source_file" TEXT,
  "source_relative" TEXT,
  "record_offset" TEXT,
  "input_sequence" INTEGER,
  "usn_sort" TEXT,
  "file_reference_sort" TEXT,
  "parent_reference_sort" TEXT,
  "group_id" TEXT,
  "group_ordinal" INTEGER,
  "rename_role" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'UsnJournal'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(group_ordinal IS NULL OR group_ordinal >= 0),
  CHECK(rename_role IS NULL OR rename_role IN ('old','new','both')),
  FOREIGN KEY(group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE
);
CREATE INDEX "idx_UsnJournal_time" ON "UsnJournal"(timestamp, record_id);
CREATE INDEX "idx_UsnJournal_account" ON "UsnJournal"(account_sid, timestamp);
CREATE INDEX "idx_UsnJournal_input" ON "UsnJournal"(input_id, input_sequence);
CREATE INDEX "idx_UsnJournal_usn" ON "UsnJournal"(input_id, usn_sort, record_id);
CREATE INDEX "idx_UsnJournal_reference" ON "UsnJournal"(input_id, record_version, file_reference_sort, usn_sort);
CREATE INDEX "idx_UsnJournal_group" ON "UsnJournal"(group_id, group_ordinal);
CREATE INDEX "idx_UsnJournal_name" ON "UsnJournal"(file_name COLLATE NOCASE, timestamp);
CREATE INDEX "idx_UsnJournal_rename" ON "UsnJournal"(input_id, record_version, file_reference, usn_sort) WHERE rename_role IS NOT NULL;
CREATE TABLE "UsnGroupMembers" (
  "group_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "record_id" TEXT NOT NULL,
  "input_id" TEXT NOT NULL,
  "input_sequence" INTEGER,
  "record_offset" TEXT,
  "timestamp" TEXT,
  "file_name" TEXT,
  "event_type" TEXT,
  "reason" TEXT,
  "reason_mask" TEXT,
  "usn" TEXT,
  "usn_sort" TEXT,
  PRIMARY KEY(group_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE,
  FOREIGN KEY(record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX "idx_UsnGroupMembers_record" ON "UsnGroupMembers"(record_id);
CREATE INDEX "idx_UsnGroupMembers_name" ON "UsnGroupMembers"(file_name COLLATE NOCASE, group_id);
CREATE TABLE "UsnReasonFlags" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "group_id" TEXT NOT NULL,
  "reason_flag" TEXT NOT NULL,
  "flag_bit" TEXT NOT NULL,
  "is_unknown" INTEGER NOT NULL CHECK ("is_unknown" IN (0,1)),
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE
);
CREATE INDEX "idx_UsnReasonFlags_flag" ON "UsnReasonFlags"(reason_flag, group_id);
CREATE INDEX "idx_UsnReasonFlags_group" ON "UsnReasonFlags"(group_id, reason_flag);
CREATE TABLE "UsnRenameEvents" (
  "rename_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "input_id" TEXT NOT NULL,
  "input_name" TEXT,
  "record_version" INTEGER,
  "file_reference" TEXT,
  "file_reference_sort" TEXT,
  "status" TEXT NOT NULL,
  "ambiguity_reason" TEXT,
  "matching_basis" TEXT NOT NULL,
  "old_record_id" TEXT,
  "new_record_id" TEXT,
  "old_group_id" TEXT,
  "new_group_id" TEXT,
  "old_file_name" TEXT,
  "new_file_name" TEXT,
  "old_usn" TEXT,
  "old_usn_sort" TEXT,
  "new_usn" TEXT,
  "new_usn_sort" TEXT,
  "old_timestamp" TEXT,
  "new_timestamp" TEXT,
  "old_candidate_count" INTEGER NOT NULL,
  "new_candidate_count" INTEGER NOT NULL,
  PRIMARY KEY(rename_id),
  CHECK(status IN ('paired','missing_old','missing_new','ambiguous')),
  CHECK(status <> 'paired' OR (old_record_id IS NOT NULL AND new_record_id IS NOT NULL)),
  FOREIGN KEY(old_record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(new_record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(old_group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE,
  FOREIGN KEY(new_group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE
);
CREATE INDEX "idx_UsnRenameEvents_reference" ON "UsnRenameEvents"(input_id, record_version, file_reference);
CREATE INDEX "idx_UsnRenameEvents_status" ON "UsnRenameEvents"(status, input_id);
CREATE INDEX "idx_UsnRenameEvents_new_name" ON "UsnRenameEvents"(new_file_name COLLATE NOCASE);
CREATE INDEX "idx_UsnRenameEvents_old_name" ON "UsnRenameEvents"(old_file_name COLLATE NOCASE);
CREATE TABLE "UsnRenameCandidates" (
  "rename_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "record_id" TEXT NOT NULL,
  "group_id" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "file_name" TEXT,
  "usn" TEXT,
  "usn_sort" TEXT,
  "timestamp" TEXT,
  "record_offset" TEXT,
  "input_sequence" INTEGER,
  "reason_mask" TEXT,
  PRIMARY KEY(rename_id, ordinal),
  CHECK(ordinal >= 0),
  CHECK(role IN ('old','new','both')),
  FOREIGN KEY(rename_id) REFERENCES "UsnRenameEvents"("rename_id") ON DELETE CASCADE,
  FOREIGN KEY(record_id) REFERENCES "UsnJournal"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(group_id) REFERENCES "UsnChangeGroups"("group_id") ON DELETE CASCADE
);
CREATE INDEX "idx_UsnRenameCandidates_record" ON "UsnRenameCandidates"(record_id);
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
INSERT INTO _wina_derived_version(name,version) VALUES ('usn_journal',2);
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
    "input_id",
    "input_name",
    "source_file",
    "source_relative",
    "record_offset",
    "input_sequence",
    "usn_sort",
    "file_reference_sort",
    "parent_reference_sort",
    "group_id",
    "group_ordinal",
    "rename_role",
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

pub const USN_CHANGE_GROUPS_COLUMNS: &[&str] = &[
    "group_id",
    "host_id",
    "dataset_id",
    "input_id",
    "input_name",
    "source_file",
    "source_relative",
    "record_version",
    "file_reference",
    "file_reference_sort",
    "first_parent_reference",
    "last_parent_reference",
    "first_file_name",
    "last_file_name",
    "distinct_file_name_count",
    "first_timestamp",
    "last_timestamp",
    "first_usn",
    "first_usn_sort",
    "last_usn",
    "last_usn_sort",
    "first_input_sequence",
    "last_input_sequence",
    "member_count",
    "event_type",
    "reason_union_mask",
    "reason_union",
    "unknown_reason_mask",
    "has_unknown_reason",
    "group_scope",
    "grouping_basis",
    "boundary_reason",
    "close_observed",
    "is_display_summary",
    "operation_confirmed",
];

pub const USN_GROUP_MEMBERS_COLUMNS: &[&str] = &[
    "group_id",
    "ordinal",
    "record_id",
    "input_id",
    "input_sequence",
    "record_offset",
    "timestamp",
    "file_name",
    "event_type",
    "reason",
    "reason_mask",
    "usn",
    "usn_sort",
];

pub const USN_REASON_FLAGS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "group_id",
    "reason_flag",
    "flag_bit",
    "is_unknown",
];

pub const USN_RENAME_EVENTS_COLUMNS: &[&str] = &[
    "rename_id",
    "host_id",
    "dataset_id",
    "input_id",
    "input_name",
    "record_version",
    "file_reference",
    "file_reference_sort",
    "status",
    "ambiguity_reason",
    "matching_basis",
    "old_record_id",
    "new_record_id",
    "old_group_id",
    "new_group_id",
    "old_file_name",
    "new_file_name",
    "old_usn",
    "old_usn_sort",
    "new_usn",
    "new_usn_sort",
    "old_timestamp",
    "new_timestamp",
    "old_candidate_count",
    "new_candidate_count",
];

pub const USN_RENAME_CANDIDATES_COLUMNS: &[&str] = &[
    "rename_id",
    "ordinal",
    "record_id",
    "group_id",
    "role",
    "file_name",
    "usn",
    "usn_sort",
    "timestamp",
    "record_offset",
    "input_sequence",
    "reason_mask",
];

const USN_JOURNAL_CHILDREN: &[ChildSpec] = &[
    ChildSpec { table: "source_records", columns: USN_JOURNAL_SOURCE_RECORDS_COLUMNS },
    ChildSpec { table: "UsnChangeGroups", columns: USN_CHANGE_GROUPS_COLUMNS },
    ChildSpec { table: "UsnGroupMembers", columns: USN_GROUP_MEMBERS_COLUMNS },
    ChildSpec { table: "UsnReasonFlags", columns: USN_REASON_FLAGS_COLUMNS },
    ChildSpec { table: "UsnRenameEvents", columns: USN_RENAME_EVENTS_COLUMNS },
    ChildSpec { table: "UsnRenameCandidates", columns: USN_RENAME_CANDIDATES_COLUMNS },
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
CREATE TABLE "PathReferenceOrigins" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL CHECK(ordinal >= 0),
  "origin_db" TEXT NOT NULL,
  "origin_table" TEXT NOT NULL,
  "origin_record_id" TEXT NOT NULL,
  "origin_child_table" TEXT,
  "origin_ordinal" INTEGER,
  "origin_field" TEXT,
  "role" TEXT NOT NULL,
  "raw_input" TEXT,
  "resolution_basis" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK((origin_child_table IS NULL AND origin_ordinal IS NULL)
     OR (origin_child_table IS NOT NULL AND origin_ordinal IS NOT NULL AND origin_ordinal >= 0)),
  FOREIGN KEY(record_id) REFERENCES PathReferences(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_PathReferenceOrigins_origin
  ON PathReferenceOrigins(origin_db, origin_table, origin_record_id);
CREATE TABLE "PathReferenceExecutionCandidates" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL CHECK(ordinal >= 0),
  "execution_record_id" TEXT NOT NULL,
  "match_basis" TEXT NOT NULL CHECK(match_basis = 'same_host_dataset_drive_path'),
  PRIMARY KEY(record_id, ordinal),
  UNIQUE(record_id, execution_record_id),
  FOREIGN KEY(record_id) REFERENCES PathReferences(record_id) ON DELETE CASCADE
);
CREATE INDEX idx_PathReferenceExecutionCandidates_execution
  ON PathReferenceExecutionCandidates(execution_record_id);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('path_references',3);
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
    ChildSpec { table: "PathReferenceOrigins", columns: &[
        "record_id", "ordinal", "origin_db", "origin_table", "origin_record_id",
        "origin_child_table", "origin_ordinal", "origin_field", "role",
        "raw_input", "resolution_basis",
    ] },
    ChildSpec { table: "PathReferenceExecutionCandidates", columns: &[
        "record_id", "ordinal", "execution_record_id", "match_basis",
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
    super::browser_activity::SPEC,
    super::ai_conversations::SPEC,
    DbSpec {
        name: "RegistryFindings",
        table: "RegistryFindings",
        columns: REGISTRY_FINDINGS_COLUMNS,
        children: REGISTRY_FINDINGS_CHILDREN,
        ddl: REGISTRY_FINDINGS_DDL,
    },
    // 선별 판정 뒤에 생성한다 — 퀵 접근 관계가 RegistryFindings 좌표를 읽는다.
    DbSpec {
        name: "RegistryExplorer",
        table: "RegistryExplorer",
        columns: REGISTRY_EXPLORER_COLUMNS,
        children: REGISTRY_EXPLORER_CHILDREN,
        ddl: REGISTRY_EXPLORER_DDL,
    },
    super::remote_access::SPEC,
    super::smb_history::SPEC,
    super::scheduled_tasks::SPEC,
    super::service_history::SPEC,
    super::defender::SPEC,
    super::firewall_history::SPEC,
    super::bits_history::SPEC,
    super::wer_reports::SPEC,
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
