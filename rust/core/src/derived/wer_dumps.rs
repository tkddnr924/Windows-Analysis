//! Collected crash dump evidence for the error reporting overview.
//!
//! Dump files found in the collection are parsed once into their own facts
//! database (`SUPPLEMENTAL/Wer_Dump_Files.sqlite`) and the overview records are
//! built from those stored rows — the original bytes are read exactly once.
//!
//! A dump is its own record. It is related to a report only when the collected
//! dump file sits inside the very directory that holds that `Report.wer`; a
//! matching process name is never treated as a relation, and dumps collected
//! elsewhere (for example `%LOCALAPPDATA%\CrashDumps`) stay standalone
//! evidence. Memory contents, credentials and executable behaviour are out of
//! scope: only documented container metadata is stored.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

use super::{text, text_opt, Cell, Ctx, Record, SourceRef};
use crate::overview::basename_win;
use crate::parsers::wer_dump::{self, Dump, MODULE_LOADED, MODULE_UNLOADED};
use crate::time::{fmt_filetime, fmt_unix};

pub(super) const DUMP_CATEGORY: &str = "SUPPLEMENTAL";
pub(super) const DUMP_FILE: &str = "Wer_Dump_Files.sqlite";
/// Host-relative evidence database.
pub(super) const DUMP_DB: &str = "SUPPLEMENTAL/Wer_Dump_Files.sqlite";
pub(super) const FILES_TABLE: &str = "Wer_Dump_Files";
pub(super) const STREAMS_TABLE: &str = "Wer_Dump_Streams";
pub(super) const THREADS_TABLE: &str = "Wer_Dump_Threads";
pub(super) const MODULES_TABLE: &str = "Wer_Dump_Modules";
pub(super) const REGIONS_TABLE: &str = "Wer_Dump_Memory_Regions";
pub(super) const COUNTERS_TABLE: &str = "Wer_Dump_Counters";
pub(super) const DISCOVERY_ERRORS_TABLE: &str = "Wer_Dump_Discovery_Errors";
pub(super) const ARTIFACT: &str = "WerCrashDump";

/// Whole-file hashing stays bounded; larger dumps keep their size only.
const HASH_LIMIT: u64 = 512 * 1024 * 1024;

const CREATE_SQL: &str = r#"
CREATE TABLE "Wer_Dump_Files" (
  "_source_file" TEXT NOT NULL,
  "file_name" TEXT NOT NULL,
  "collected_directory" TEXT NOT NULL,
  "location_role" TEXT NOT NULL,
  "report_file" TEXT,
  "report_lookup_state" TEXT NOT NULL,
  "report_lookup_error" TEXT,
  "byte_count" INTEGER,
  "sha256" TEXT,
  "hash_state" TEXT NOT NULL,
  "format" TEXT NOT NULL,
  "parse_status" TEXT NOT NULL,
  "parse_error" TEXT,
  "signature_ascii" TEXT,
  "signature_hex" TEXT,
  "version_raw" INTEGER,
  "version_low" INTEGER,
  "version_high" INTEGER,
  "checksum" INTEGER,
  "time_date_stamp" INTEGER,
  "time_date_stamp_kst" TEXT,
  "flags" INTEGER,
  "flags_hex" TEXT,
  "stream_count" INTEGER,
  "stream_directory_rva" INTEGER,
  "directory_state" TEXT,
  "issue_count" INTEGER,
  "issues" TEXT,
  "processor_architecture" INTEGER,
  "processor_architecture_name" TEXT,
  "processor_level" INTEGER,
  "processor_revision" INTEGER,
  "number_of_processors" INTEGER,
  "product_type" INTEGER,
  "product_type_name" TEXT,
  "os_major_version" INTEGER,
  "os_minor_version" INTEGER,
  "os_build_number" INTEGER,
  "platform_id" INTEGER,
  "platform_name" TEXT,
  "suite_mask" INTEGER,
  "csd_version" TEXT,
  "csd_state" TEXT,
  "misc_size" INTEGER,
  "misc_revision" INTEGER,
  "misc_flags" INTEGER,
  "misc_flag_names" TEXT,
  "misc_unknown_flag_bits" INTEGER,
  "process_id" INTEGER,
  "process_create_time" INTEGER,
  "process_create_time_kst" TEXT,
  "process_user_time" INTEGER,
  "process_kernel_time" INTEGER,
  "process_integrity_level" INTEGER,
  "process_execute_flags" INTEGER,
  "protected_process" INTEGER,
  "time_zone_id" INTEGER,
  "build_string" TEXT,
  "debug_build_string" TEXT,
  "exception_present" INTEGER NOT NULL,
  "exception_thread_id" INTEGER,
  "exception_code" INTEGER,
  "exception_code_hex" TEXT,
  "exception_code_name" TEXT,
  "exception_flags" INTEGER,
  "exception_record_address_hex" TEXT,
  "exception_address_hex" TEXT,
  "exception_parameter_count" INTEGER,
  "exception_parameters" TEXT,
  "exception_context_rva" INTEGER,
  "exception_context_size" INTEGER,
  "exception_thread_in_list" INTEGER,
  "first_module_path" TEXT,
  "first_module_name" TEXT,
  "thread_count" INTEGER,
  "module_count" INTEGER,
  "unloaded_module_count" INTEGER,
  "memory_region_count" INTEGER,
  "stream_typed_count" INTEGER,
  "stream_unknown_count" INTEGER,
  "counter_count" INTEGER
);
CREATE TABLE "Wer_Dump_Streams" (
  "_source_file" TEXT NOT NULL,
  "stream_index" INTEGER NOT NULL,
  "stream_type" INTEGER NOT NULL,
  "stream_type_name" TEXT,
  "data_size" INTEGER NOT NULL,
  "stream_rva" INTEGER NOT NULL,
  "range_state" TEXT NOT NULL,
  "parse_state" TEXT NOT NULL,
  "overlaps" INTEGER NOT NULL,
  "header_size" INTEGER,
  "entry_size" INTEGER,
  "declared_entries" INTEGER,
  "stored_entries" INTEGER,
  "sha256" TEXT,
  "prefix_hex" TEXT,
  "text_value" TEXT,
  "note" TEXT
);
CREATE TABLE "Wer_Dump_Threads" (
  "_source_file" TEXT NOT NULL,
  "thread_index" INTEGER NOT NULL,
  "source_stream" TEXT NOT NULL,
  "thread_id" INTEGER NOT NULL,
  "suspend_count" INTEGER,
  "priority_class" INTEGER,
  "priority" INTEGER,
  "teb" INTEGER,
  "teb_hex" TEXT,
  "stack_start" INTEGER,
  "stack_start_hex" TEXT,
  "stack_size" INTEGER,
  "stack_rva" INTEGER,
  "context_rva" INTEGER,
  "context_size" INTEGER,
  "thread_name" TEXT,
  "is_exception_thread" INTEGER NOT NULL,
  "dump_flags" INTEGER,
  "dump_error" INTEGER,
  "exit_status" INTEGER,
  "create_time_raw" INTEGER,
  "create_time" TEXT,
  "exit_time_raw" INTEGER,
  "exit_time" TEXT,
  "kernel_time_100ns" INTEGER,
  "user_time_100ns" INTEGER,
  "start_address_hex" TEXT,
  "affinity_hex" TEXT
);
CREATE TABLE "Wer_Dump_Modules" (
  "_source_file" TEXT NOT NULL,
  "module_index" INTEGER NOT NULL,
  "module_kind" TEXT NOT NULL,
  "base_of_image" INTEGER,
  "base_of_image_hex" TEXT,
  "size_of_image" INTEGER,
  "checksum" INTEGER,
  "time_date_stamp" INTEGER,
  "time_date_stamp_kst" TEXT,
  "module_path" TEXT,
  "module_path_state" TEXT NOT NULL,
  "file_name" TEXT,
  "file_name_lower" TEXT,
  "file_version" TEXT,
  "product_version" TEXT,
  "file_flags" INTEGER,
  "file_os" INTEGER,
  "file_type" INTEGER,
  "file_subtype" INTEGER,
  "cv_signature" TEXT,
  "cv_guid" TEXT,
  "cv_age" INTEGER,
  "pdb_file_name" TEXT,
  "cv_state" TEXT
);
CREATE TABLE "Wer_Dump_Memory_Regions" (
  "_source_file" TEXT NOT NULL,
  "region_index" INTEGER NOT NULL,
  "source_stream" TEXT NOT NULL,
  "base_address" INTEGER,
  "base_address_hex" TEXT NOT NULL,
  "allocation_base" INTEGER,
  "allocation_base_hex" TEXT,
  "allocation_protect" INTEGER,
  "region_size" INTEGER,
  "state" INTEGER,
  "state_name" TEXT,
  "protect" INTEGER,
  "protect_name" TEXT,
  "region_type" INTEGER,
  "region_type_name" TEXT,
  "stored_data_size" INTEGER
);
CREATE TABLE "Wer_Dump_Counters" (
  "_source_file" TEXT NOT NULL,
  "stream_type" INTEGER NOT NULL,
  "struct_name" TEXT NOT NULL,
  "field_name" TEXT NOT NULL,
  "value" INTEGER,
  "value_hex" TEXT NOT NULL
);
CREATE TABLE "Wer_Dump_Discovery_Errors" (
  "error" TEXT NOT NULL
);
"#;

// --- discovery --------------------------------------------------------------

/// Extensions Windows uses for minidump output. Other containers are still
/// read and classified; only the discovery filter lives here.
const DUMP_EXTENSIONS: &[&str] = &["dmp", "mdmp", "hdmp"];

pub(super) const LOCATION_REPORT_DIR: &str = "wer_report_directory";
pub(super) const LOCATION_CRASH_DUMPS: &str = "crash_dumps_directory";
pub(super) const LOCATION_WER_TEMP: &str = "wer_temp_directory";
pub(super) const LOCATION_WER_TREE: &str = "wer_directory";
pub(super) const LOCATION_OTHER: &str = "other_collected_location";

pub(super) const LOOKUP_FOUND: &str = "found";
pub(super) const LOOKUP_ABSENT: &str = "absent";
pub(super) const LOOKUP_UNREADABLE: &str = "unreadable";

struct Collected {
    path: PathBuf,
    directory: String,
    location_role: &'static str,
    /// The `Report.wer` collected in the same directory, by its real path.
    report_file: Option<String>,
    report_lookup_state: &'static str,
    report_lookup_error: Option<String>,
}

fn has_component(path: &Path, name: &str) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(name)
    })
}

/// Outcome of checking a dump's directory for its `Report.wer`.
#[derive(Clone)]
struct ReportLookup {
    state: &'static str,
    report: Option<PathBuf>,
    error: Option<String>,
}

/// A report file collected in the same directory, found by reading the
/// directory itself rather than by assuming a file name case. A directory or
/// entry that cannot be read is "unreadable", never "absent".
fn report_lookup(directory: &Path) -> ReportLookup {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            return ReportLookup {
                state: LOOKUP_UNREADABLE,
                report: None,
                error: Some(format!("{}: {error}", directory.display())),
            }
        }
    };
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        if !entry.file_name().to_string_lossy().eq_ignore_ascii_case("Report.wer") {
            continue;
        }
        let path = entry.path();
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => found.push(path),
            Ok(_) => {}
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    found.sort();
    match found.into_iter().next() {
        Some(report) => ReportLookup {
            state: LOOKUP_FOUND,
            report: Some(report),
            error: None,
        },
        None if errors.is_empty() => ReportLookup {
            state: LOOKUP_ABSENT,
            report: None,
            error: None,
        },
        None => ReportLookup {
            state: LOOKUP_UNREADABLE,
            report: None,
            error: Some(errors.join(" | ")),
        },
    }
}

/// Collected dumps plus the walk failures met while searching for them.
fn collected_dumps(target: &Path) -> (Vec<Collected>, Vec<String>) {
    let (files, errors) = crate::finder::walk_files(target);
    let mut files: Vec<PathBuf> = files
        .into_iter()
        .filter(|path| {
            path.extension()
                .map(|ext| {
                    let ext = ext.to_string_lossy().to_lowercase();
                    DUMP_EXTENSIONS.contains(&ext.as_str())
                })
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    let mut lookups: BTreeMap<PathBuf, ReportLookup> = BTreeMap::new();
    let collected = files
        .into_iter()
        .map(|path| {
            let directory = path.parent().map(Path::to_path_buf).unwrap_or_default();
            let lookup = lookups
                .entry(directory.clone())
                .or_insert_with(|| report_lookup(&directory))
                .clone();
            // Roles read the path inside the collection, never the folders
            // above it on the analyst's machine.
            let relative = directory.strip_prefix(target).unwrap_or(&directory);
            let parent_name = relative
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            let location_role = if lookup.report.is_some() {
                LOCATION_REPORT_DIR
            } else if parent_name.eq_ignore_ascii_case("CrashDumps") {
                LOCATION_CRASH_DUMPS
            } else if parent_name.eq_ignore_ascii_case("Temp") && has_component(relative, "WER") {
                LOCATION_WER_TEMP
            } else if has_component(relative, "WER") {
                LOCATION_WER_TREE
            } else {
                LOCATION_OTHER
            };
            Collected {
                path,
                directory: directory.display().to_string(),
                location_role,
                report_file: lookup.report.map(|path| path.display().to_string()),
                report_lookup_state: lookup.state,
                report_lookup_error: lookup.error,
            }
        })
        .collect();
    (collected, errors)
}

// --- helpers ----------------------------------------------------------------

fn int_u64(value: u64) -> Option<i64> {
    i64::try_from(value).ok()
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

/// Hash the collected file as a whole so the stored evidence can be tied back
/// to the original bytes. Oversized files keep their size only.
fn file_hash(path: &Path, byte_count: u64) -> (Option<String>, &'static str) {
    if byte_count > HASH_LIMIT {
        return (None, "skipped_over_limit");
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return (None, "read_failed");
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        match std::io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(_) => return (None, "read_failed"),
        }
    }
    (Some(crate::hex::hex_lower(&hasher.finalize())), "computed")
}

// --- facts ------------------------------------------------------------------

pub(super) fn dump_path(out_dir: &Path) -> PathBuf {
    out_dir.join(DUMP_CATEGORY).join(DUMP_FILE)
}

/// Materialize collected dump evidence before the overview references it.
pub(super) fn prepare_inputs(
    out_dir: &Path,
    target: &Path,
    dataset_id: &str,
) -> Result<Vec<String>> {
    let dir = out_dir.join(DUMP_CATEGORY);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("크래시 덤프 보조 증거 폴더 생성: {}", dir.display()))?;
    let path = dump_path(out_dir);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 크래시 덤프 증거 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("크래시 덤프 증거 DB 생성: {}", path.display()))?;
    conn.execute_batch(CREATE_SQL)?;
    conn.execute_batch("BEGIN")?;
    let mut rows = 0usize;
    let (collected, errors) = collected_dumps(target);
    for collected in collected {
        let dump = wer_dump::parse_file(&collected.path);
        rows += insert_dump(&conn, &collected, &dump)?;
    }
    // A directory that could not be searched is evidence of an incomplete
    // search, not of an absent dump.
    for error in errors {
        rows += conn.execute(
            &format!("INSERT INTO \"{DISCOVERY_ERRORS_TABLE}\" (error) VALUES (?1)"),
            [error],
        )?;
    }
    conn.execute_batch("COMMIT")?;
    drop(conn);
    super::stamp_facts_generation(&path, dataset_id)?;
    Ok(if rows == 0 {
        Vec::new()
    } else {
        vec![DUMP_DB.to_string()]
    })
}

fn insert_dump(conn: &Connection, collected: &Collected, dump: &Dump) -> Result<usize> {
    let source_file = collected.path.display().to_string();
    let (sha256, hash_state) = file_hash(&collected.path, dump.byte_count);
    let system = dump.system.clone();
    let misc = dump.misc.clone();
    let exception = dump.exception.clone();
    let first_module = dump.first_loaded_module().cloned();
    let first_module_path = first_module.as_ref().and_then(|module| module.name.clone());
    let exception_thread_in_list = exception.as_ref().map(|exception| {
        i64::from(
            dump.threads
                .iter()
                .any(|thread| thread.thread_id == exception.thread_id),
        )
    });
    let loaded = dump
        .modules
        .iter()
        .filter(|module| module.kind == MODULE_LOADED)
        .count() as i64;
    let unloaded = dump
        .modules
        .iter()
        .filter(|module| module.kind == MODULE_UNLOADED)
        .count() as i64;
    let typed_streams = dump
        .streams
        .iter()
        .filter(|stream| stream.parse_state == wer_dump::STREAM_TYPED)
        .count() as i64;
    let unknown_streams = dump
        .streams
        .iter()
        .filter(|stream| stream.parse_state == wer_dump::STREAM_UNKNOWN_TYPE)
        .count() as i64;
    conn.execute(
        &format!(
            "INSERT INTO \"{FILES_TABLE}\" (_source_file, file_name, collected_directory, \
             location_role, report_file, report_lookup_state, report_lookup_error, byte_count, \
             sha256, hash_state, format, parse_status, \
             parse_error, signature_ascii, signature_hex, version_raw, version_low, version_high, \
             checksum, time_date_stamp, time_date_stamp_kst, flags, flags_hex, stream_count, \
             stream_directory_rva, directory_state, issue_count, issues, processor_architecture, \
             processor_architecture_name, processor_level, processor_revision, \
             number_of_processors, product_type, product_type_name, os_major_version, \
             os_minor_version, os_build_number, platform_id, platform_name, suite_mask, \
             csd_version, csd_state, misc_size, misc_revision, misc_flags, misc_flag_names, \
             misc_unknown_flag_bits, process_id, process_create_time, process_create_time_kst, \
             process_user_time, process_kernel_time, process_integrity_level, \
             process_execute_flags, protected_process, time_zone_id, build_string, \
             debug_build_string, exception_present, exception_thread_id, exception_code, \
             exception_code_hex, exception_code_name, exception_flags, \
             exception_record_address_hex, exception_address_hex, exception_parameter_count, \
             exception_parameters, exception_context_rva, exception_context_size, \
             exception_thread_in_list, first_module_path, first_module_name, thread_count, module_count, \
             unloaded_module_count, memory_region_count, stream_typed_count, \
             stream_unknown_count, counter_count) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
             ?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,?42,\
             ?43,?44,?45,?46,?47,?48,?49,?50,?51,?52,?53,?54,?55,?56,?57,?58,?59,?60,?61,?62,?63,\
             ?64,?65,?66,?67,?68,?69,?70,?71,?72,?73,?74,?75,?76,?77,?78,?79,?80,?81)"
        ),
        rusqlite::params![
            source_file,
            basename_win(&source_file),
            collected.directory,
            collected.location_role,
            collected.report_file,
            collected.report_lookup_state,
            collected.report_lookup_error,
            int_u64(dump.byte_count),
            sha256,
            hash_state,
            dump.format,
            dump.parse_status,
            dump.parse_error,
            dump.signature_ascii,
            dump.signature_hex,
            dump.version_raw.map(i64::from),
            dump.version_low.map(i64::from),
            dump.version_high.map(i64::from),
            dump.checksum.map(i64::from),
            dump.time_date_stamp.map(i64::from),
            dump.time_date_stamp
                .map(|value| fmt_unix(i64::from(value)))
                .filter(|value| !value.is_empty()),
            dump.flags.and_then(int_u64),
            dump.flags.map(hex_u64),
            dump.stream_count.map(i64::from),
            dump.directory_rva.map(i64::from),
            dump.directory_state,
            dump.issues.len() as i64,
            dump.issues_text(),
            system.as_ref().map(|info| i64::from(info.processor_architecture)),
            system.as_ref().and_then(|info| info.architecture_name),
            system.as_ref().map(|info| i64::from(info.processor_level)),
            system.as_ref().map(|info| i64::from(info.processor_revision)),
            system.as_ref().map(|info| i64::from(info.number_of_processors)),
            system.as_ref().map(|info| i64::from(info.product_type)),
            system.as_ref().and_then(|info| info.product_type_name),
            system.as_ref().map(|info| i64::from(info.major_version)),
            system.as_ref().map(|info| i64::from(info.minor_version)),
            system.as_ref().map(|info| i64::from(info.build_number)),
            system.as_ref().map(|info| i64::from(info.platform_id)),
            system.as_ref().and_then(|info| info.platform_name),
            system.as_ref().map(|info| i64::from(info.suite_mask)),
            system.as_ref().and_then(|info| info.csd_version.clone()),
            system.as_ref().map(|info| info.csd_state),
            misc.as_ref().map(|info| i64::from(info.size_of_info)),
            misc.as_ref().map(|info| i64::from(info.revision)),
            misc.as_ref().map(|info| i64::from(info.flags1)),
            misc.as_ref().and_then(|info| info.flag_names.clone()),
            misc.as_ref().and_then(|info| info.unknown_flag_bits.map(i64::from)),
            misc.as_ref().and_then(|info| info.process_id.map(i64::from)),
            misc.as_ref().and_then(|info| info.process_create_time.map(i64::from)),
            misc.as_ref()
                .and_then(|info| info.process_create_time)
                .map(|value| fmt_unix(i64::from(value)))
                .filter(|value| !value.is_empty()),
            misc.as_ref().and_then(|info| info.process_user_time.map(i64::from)),
            misc.as_ref().and_then(|info| info.process_kernel_time.map(i64::from)),
            misc.as_ref().and_then(|info| info.process_integrity_level.map(i64::from)),
            misc.as_ref().and_then(|info| info.process_execute_flags.map(i64::from)),
            misc.as_ref().and_then(|info| info.protected_process.map(i64::from)),
            misc.as_ref().and_then(|info| info.time_zone_id.map(i64::from)),
            misc.as_ref().and_then(|info| info.build_string.clone()),
            misc.as_ref().and_then(|info| info.debug_build_string.clone()),
            i64::from(exception.is_some()),
            exception.as_ref().map(|value| i64::from(value.thread_id)),
            exception.as_ref().map(|value| i64::from(value.code)),
            exception.as_ref().map(|value| format!("0x{:08x}", value.code)),
            exception.as_ref().and_then(|value| value.code_name),
            exception.as_ref().map(|value| i64::from(value.flags)),
            exception.as_ref().map(|value| hex_u64(value.nested_record_address)),
            exception.as_ref().map(|value| hex_u64(value.address)),
            exception.as_ref().map(|value| i64::from(value.number_parameters)),
            exception.as_ref().map(|value| {
                value
                    .parameters
                    .iter()
                    .map(|parameter| hex_u64(*parameter))
                    .collect::<Vec<_>>()
                    .join(",")
            }),
            exception.as_ref().map(|value| i64::from(value.context_rva)),
            exception.as_ref().map(|value| i64::from(value.context_size)),
            exception_thread_in_list,
            first_module_path.clone(),
            first_module_path.as_deref().map(basename_win),
            dump.threads.len() as i64,
            loaded,
            unloaded,
            dump.regions.len() as i64,
            typed_streams,
            unknown_streams,
            dump.counters.len() as i64,
        ],
    )?;
    let mut rows = 1usize;

    {
        let mut insert = conn.prepare(&format!(
            "INSERT INTO \"{STREAMS_TABLE}\" (_source_file, stream_index, stream_type, \
             stream_type_name, data_size, stream_rva, range_state, parse_state, overlaps, \
             header_size, entry_size, declared_entries, stored_entries, sha256, prefix_hex, \
             text_value, note) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)"
        ))?;
        for stream in &dump.streams {
            rows += insert.execute(rusqlite::params![
                source_file,
                i64::from(stream.index),
                i64::from(stream.type_code),
                stream.type_name,
                i64::from(stream.data_size),
                i64::from(stream.rva),
                stream.range_state,
                stream.parse_state,
                i64::from(stream.overlaps),
                stream.header_size.map(i64::from),
                stream.entry_size.map(i64::from),
                stream.declared_entries.and_then(int_u64),
                stream.stored_entries.and_then(int_u64),
                stream.sha256,
                stream.prefix_hex,
                stream.text,
                stream.note,
            ])?;
        }
    }

    {
        let exception_thread = dump.exception.as_ref().map(|value| value.thread_id);
        let mut insert = conn.prepare(&format!(
            "INSERT INTO \"{THREADS_TABLE}\" (_source_file, thread_index, source_stream, \
             thread_id, suspend_count, priority_class, priority, teb, teb_hex, stack_start, \
             stack_start_hex, stack_size, stack_rva, context_rva, context_size, thread_name, \
             is_exception_thread, dump_flags, dump_error, exit_status, create_time_raw, \
             create_time, exit_time_raw, exit_time, kernel_time_100ns, user_time_100ns, \
             start_address_hex, affinity_hex) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
             ?22,?23,?24,?25,?26,?27,?28)"
        ))?;
        for thread in &dump.threads {
            let info = thread.info.clone();
            rows += insert.execute(rusqlite::params![
                source_file,
                i64::from(thread.index),
                thread.source_stream,
                i64::from(thread.thread_id),
                thread.suspend_count.map(i64::from),
                thread.priority_class.map(i64::from),
                thread.priority.map(i64::from),
                thread.teb.and_then(int_u64),
                thread.teb.map(hex_u64),
                thread.stack_start.and_then(int_u64),
                thread.stack_start.map(hex_u64),
                thread.stack_size.map(i64::from),
                thread.stack_rva.map(i64::from),
                thread.context_rva.map(i64::from),
                thread.context_size.map(i64::from),
                thread.name,
                i64::from(exception_thread == Some(thread.thread_id)),
                info.as_ref().map(|info| i64::from(info.dump_flags)),
                info.as_ref().map(|info| i64::from(info.dump_error)),
                info.as_ref().map(|info| i64::from(info.exit_status)),
                info.as_ref().and_then(|info| int_u64(info.create_time)),
                info.as_ref()
                    .map(|info| fmt_filetime(info.create_time as i64))
                    .filter(|value| !value.is_empty()),
                info.as_ref().and_then(|info| int_u64(info.exit_time)),
                info.as_ref()
                    .map(|info| fmt_filetime(info.exit_time as i64))
                    .filter(|value| !value.is_empty()),
                info.as_ref().and_then(|info| int_u64(info.kernel_time)),
                info.as_ref().and_then(|info| int_u64(info.user_time)),
                info.as_ref().map(|info| hex_u64(info.start_address)),
                info.as_ref().map(|info| hex_u64(info.affinity)),
            ])?;
        }
    }

    {
        let mut insert = conn.prepare(&format!(
            "INSERT INTO \"{MODULES_TABLE}\" (_source_file, module_index, module_kind, \
             base_of_image, base_of_image_hex, size_of_image, checksum, time_date_stamp, \
             time_date_stamp_kst, module_path, module_path_state, file_name, file_name_lower, \
             file_version, product_version, file_flags, file_os, file_type, file_subtype, \
             cv_signature, cv_guid, cv_age, pdb_file_name, cv_state) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
             ?22,?23,?24)"
        ))?;
        for module in &dump.modules {
            let version = module.version.clone();
            let cv = module.cv.clone();
            let name = module.name.clone();
            rows += insert.execute(rusqlite::params![
                source_file,
                i64::from(module.index),
                module.kind,
                int_u64(module.base_of_image),
                hex_u64(module.base_of_image),
                i64::from(module.size_of_image),
                i64::from(module.checksum),
                i64::from(module.time_date_stamp),
                Some(fmt_unix(i64::from(module.time_date_stamp)))
                    .filter(|value| !value.is_empty()),
                name,
                module.name_state,
                module.name.as_deref().map(basename_win),
                module
                    .name
                    .as_deref()
                    .map(|name| basename_win(name).to_lowercase()),
                version.as_ref().map(|info| info.file_version.clone()),
                version.as_ref().map(|info| info.product_version.clone()),
                version.as_ref().map(|info| i64::from(info.file_flags)),
                version.as_ref().map(|info| i64::from(info.file_os)),
                version.as_ref().map(|info| i64::from(info.file_type)),
                version.as_ref().map(|info| i64::from(info.file_subtype)),
                cv.as_ref().map(|record| record.signature.clone()),
                cv.as_ref().and_then(|record| record.guid.clone()),
                cv.as_ref().and_then(|record| record.age.map(i64::from)),
                cv.as_ref().and_then(|record| record.pdb_file_name.clone()),
                cv.as_ref().map(|record| record.state),
            ])?;
        }
    }

    {
        let mut insert = conn.prepare(&format!(
            "INSERT INTO \"{REGIONS_TABLE}\" (_source_file, region_index, source_stream, \
             base_address, base_address_hex, allocation_base, allocation_base_hex, \
             allocation_protect, region_size, state, state_name, protect, protect_name, \
             region_type, region_type_name, stored_data_size) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"
        ))?;
        for region in &dump.regions {
            rows += insert.execute(rusqlite::params![
                source_file,
                i64::from(region.index),
                region.source_stream,
                int_u64(region.base_address),
                hex_u64(region.base_address),
                region.allocation_base.and_then(int_u64),
                region.allocation_base.map(hex_u64),
                region.allocation_protect.map(i64::from),
                int_u64(region.region_size),
                region.state.map(i64::from),
                region.state_name,
                region.protect.map(i64::from),
                region.protect_name,
                region.region_type.map(i64::from),
                region.region_type_name,
                region.data_size.and_then(int_u64),
            ])?;
        }
    }

    {
        let mut insert = conn.prepare(&format!(
            "INSERT INTO \"{COUNTERS_TABLE}\" (_source_file, stream_type, struct_name, \
             field_name, value, value_hex) VALUES (?1,?2,?3,?4,?5,?6)"
        ))?;
        for counter in &dump.counters {
            rows += insert.execute(rusqlite::params![
                source_file,
                i64::from(counter.stream_type),
                counter.group,
                counter.field,
                int_u64(counter.value),
                hex_u64(counter.value),
            ])?;
        }
    }
    Ok(rows)
}

// --- stored rows ------------------------------------------------------------

pub(super) struct FileRow {
    pub rowid: i64,
    pub source_file: String,
    pub file_name: String,
    pub collected_directory: String,
    pub location_role: String,
    pub report_file: Option<String>,
    pub values: BTreeMap<&'static str, Cell>,
    /// `MINIDUMP_MODULE_LIST` entry 0 — a loaded module, not a process identity.
    pub first_module_path: Option<String>,
    pub first_module_name: Option<String>,
    pub timestamp: Option<String>,
    pub search_values: Vec<String>,
}

fn open_facts(out_dir: &Path) -> Result<Option<Connection>> {
    let path = dump_path(out_dir);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?))
}

fn cell_int(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Cell> {
    Ok(row
        .get::<_, Option<i64>>(index)?
        .map(Cell::Int)
        .unwrap_or(Cell::Null))
}

fn cell_text(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Cell> {
    Ok(row
        .get::<_, Option<String>>(index)?
        .map(Cell::Text)
        .unwrap_or(Cell::Null))
}

/// Stored facts columns promoted to overview columns, by name.
const FILE_COLUMNS: &[(&str, &str, bool)] = &[
    ("format", "dump_format", false),
    ("parse_status", "dump_parse_status", false),
    ("report_lookup_state", "dump_report_lookup_state", false),
    ("report_lookup_error", "dump_report_lookup_error", false),
    ("parse_error", "dump_parse_error", false),
    ("signature_hex", "dump_signature_hex", false),
    ("version_raw", "dump_version_raw", true),
    ("flags_hex", "dump_flags_hex", false),
    ("byte_count", "dump_byte_count", true),
    ("sha256", "dump_sha256", false),
    ("hash_state", "dump_hash_state", false),
    ("stream_count", "dump_stream_count", true),
    ("stream_unknown_count", "dump_stream_unknown_count", true),
    ("thread_count", "dump_thread_count", true),
    ("module_count", "dump_module_count", true),
    ("unloaded_module_count", "dump_unloaded_module_count", true),
    ("memory_region_count", "dump_memory_region_count", true),
    ("issue_count", "dump_issue_count", true),
    ("issues", "dump_issues", false),
    ("time_date_stamp", "dump_time_date_stamp_raw", true),
    ("directory_state", "dump_directory_state", false),
    ("processor_architecture_name", "dump_architecture", false),
    ("number_of_processors", "dump_processor_count", true),
    ("product_type_name", "dump_product_type", false),
    ("platform_name", "dump_platform", false),
    ("os_build_number", "dump_os_build", true),
    ("build_string", "dump_build_string", false),
    ("misc_revision", "dump_misc_revision", true),
    ("process_id", "dump_process_id", true),
    ("process_create_time_kst", "dump_process_create_time", false),
    ("process_integrity_level", "dump_process_integrity_level", true),
    ("protected_process", "dump_protected_process", true),
    ("exception_thread_id", "dump_exception_thread_id", true),
    ("exception_code_hex", "dump_exception_code_hex", false),
    ("exception_code_name", "dump_exception_code_name", false),
    ("exception_address_hex", "dump_exception_address_hex", false),
    ("exception_parameters", "dump_exception_parameters", false),
    ("exception_thread_in_list", "dump_exception_thread_in_list", true),
    ("counter_count", "dump_counter_count", true),
];

fn read_files(conn: &Connection) -> Result<Vec<FileRow>> {
    let promoted: Vec<&str> = FILE_COLUMNS.iter().map(|(facts, _, _)| *facts).collect();
    let sql = format!(
        "SELECT rowid,_source_file,file_name,collected_directory,location_role,report_file,\
         first_module_path,first_module_name,time_date_stamp_kst,os_major_version,os_minor_version,{} \
         FROM \"{FILES_TABLE}\" ORDER BY rowid",
        promoted.join(",")
    );
    let mut query = conn.prepare(&sql)?;
    let rows = query.query_map([], |row| {
        let mut values: BTreeMap<&'static str, Cell> = BTreeMap::new();
        for (index, (_, column, is_int)) in FILE_COLUMNS.iter().enumerate() {
            let cell = if *is_int {
                cell_int(row, 11 + index)?
            } else {
                cell_text(row, 11 + index)?
            };
            values.insert(*column, cell);
        }
        let major: Option<i64> = row.get(9)?;
        let minor: Option<i64> = row.get(10)?;
        let build: Option<i64> = match values.get("dump_os_build") {
            Some(Cell::Int(value)) => Some(*value),
            _ => None,
        };
        if let (Some(major), Some(minor), Some(build)) = (major, minor, build) {
            values.insert(
                "dump_os_version",
                Cell::Text(format!("{major}.{minor}.{build}")),
            );
        }
        let first_module_path: Option<String> = row.get(6)?;
        let first_module_name: Option<String> = row.get(7)?;
        let timestamp: Option<String> = row.get(8)?;
        let file_name: String = row.get(2)?;
        let source_file: String = row.get(1)?;
        let mut search_values = vec![file_name.clone(), source_file.clone()];
        for value in [first_module_path.clone(), first_module_name.clone()] {
            if let Some(value) = value {
                search_values.push(value);
            }
        }
        for column in [
            "dump_exception_code_name",
            "dump_exception_code_hex",
            "dump_format",
            "dump_parse_status",
            "dump_build_string",
        ] {
            if let Some(Cell::Text(value)) = values.get(column) {
                search_values.push(value.clone());
            }
        }
        Ok(FileRow {
            rowid: row.get(0)?,
            source_file,
            file_name,
            collected_directory: row.get(3)?,
            location_role: row.get(4)?,
            report_file: row.get(5)?,
            values,
            first_module_path,
            first_module_name,
            timestamp,
            search_values,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Facts child tables and the overview child tables they fill, in output
/// order. Columns are selected by the overview child's own column names, so a
/// renamed or missing column fails the query instead of shifting values.
const CHILD_TABLES: &[(&str, &str)] = &[
    (STREAMS_TABLE, "WerDumpStreams"),
    (THREADS_TABLE, "WerDumpThreads"),
    (MODULES_TABLE, "WerDumpModules"),
    (REGIONS_TABLE, "WerDumpMemoryRegions"),
    (COUNTERS_TABLE, "WerDumpCounters"),
];

/// Every child row of one dump as (overview child table, values); each value
/// keeps the storage type it was written with.
fn read_children(conn: &Connection, source_file: &str) -> Result<Vec<(&'static str, Vec<Cell>)>> {
    let mut children = Vec::new();
    for &(facts_table, child_table) in CHILD_TABLES {
        // record_id and ordinal are assigned by the overview record.
        let columns = super::wer_reports::SPEC
            .child(child_table)
            .and_then(|spec| spec.columns.strip_prefix(&["record_id", "ordinal"][..]))
            .ok_or_else(|| anyhow::anyhow!("{child_table} 자식 테이블 정의가 없습니다"))?;
        let selected: Vec<String> = columns.iter().map(|column| format!("\"{column}\"")).collect();
        let mut query = conn.prepare(&format!(
            "SELECT {} FROM \"{facts_table}\" WHERE _source_file=?1 ORDER BY rowid",
            selected.join(",")
        ))?;
        let mut rows = query.query([source_file])?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                values.push(match row.get_ref(index)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Int(value),
                    ValueRef::Text(bytes) => Cell::Text(std::str::from_utf8(bytes)?.to_string()),
                    ValueRef::Blob(bytes) => Cell::Blob(bytes.to_vec()),
                    ValueRef::Real(_) => anyhow::bail!(
                        "{facts_table}.{}: 실수 값은 저장하지 않습니다",
                        columns[index]
                    ),
                });
            }
            children.push((child_table, values));
        }
    }
    Ok(children)
}

// --- overview records -------------------------------------------------------

/// A built dump record plus the collected locations needed to relate it.
pub(super) struct DumpRecord {
    pub record: Record,
    /// The `Wer_Dump_Files` row this record was built from.
    pub rowid: i64,
    pub collected_directory: String,
    pub report_file: Option<String>,
}

pub(super) const STAGE: &str = "collected_dump";
pub(super) const ORIGIN: &str = "crash_dump";
pub(super) const EVENT_TYPE: &str = "crash_dump_collected";
pub(super) const TIMESTAMP_KIND: &str = "덤프 작성 시각";

/// Build one overview record per stored dump file.
pub(super) fn build(ctx: &Ctx) -> Result<Vec<DumpRecord>> {
    let Some(conn) = open_facts(ctx.out_dir)? else {
        return Ok(Vec::new());
    };
    let facts_path = dump_path(ctx.out_dir);
    let mut built = Vec::new();
    for file in read_files(&conn)? {
        let children = read_children(&conn, &file.source_file)?;
        let mut record = ctx.record(&super::wer_reports::SPEC);
        if let Some(timestamp) = file.timestamp.as_deref().filter(|value| !value.is_empty()) {
            record.timestamp(timestamp, TIMESTAMP_KIND);
        }
        record.set("origin", text(ORIGIN));
        record.set("reporting_stage", text(STAGE));
        record.set("source", text("CrashDump"));
        record.set("event_type", text(EVENT_TYPE));
        record.set("error_type", text(EVENT_TYPE));
        record.set("description", text(&description(&file)));
        record.set("record_key", text(&file.source_file));
        record.set("source_file", text(&file.source_file));
        record.set("dump_location_role", text(&file.location_role));
        record.set("dump_collected_directory", text(&file.collected_directory));
        record.set("dump_report_file", text_opt(file.report_file.as_deref()));
        record.set("dump_file_name", text(&file.file_name));
        record.set(
            "dump_first_module_path",
            text_opt(file.first_module_path.as_deref()),
        );
        record.set(
            "dump_first_module_name",
            text_opt(file.first_module_name.as_deref()),
        );
        for (column, cell) in &file.values {
            record.set(column, cell.clone());
        }
        // The dump's own parse state is this record's parse state.
        let parse_status = match file.values.get("dump_parse_status") {
            Some(Cell::Text(value)) => value.clone(),
            _ => wer_dump::STATUS_READ_FAILED.to_string(),
        };
        record.set("parse_status", Cell::Text(parse_status));
        record.set(
            "parse_error",
            file.values
                .get("dump_parse_error")
                .cloned()
                .unwrap_or(Cell::Null),
        );
        if let Some(Cell::Int(process_id)) = file.values.get("dump_process_id") {
            record.set("app_pid", Cell::Int(*process_id));
            record.set("app_pid_raw", text(&process_id.to_string()));
        }
        if let Some(Cell::Text(start)) = file.values.get("dump_process_create_time") {
            record.set("app_start_time", Cell::Text(start.clone()));
            record.set("app_start_time_source", text("minidump_misc_info"));
        }
        // `MINIDUMP_MODULE_LIST` is documented as an array of loaded modules;
        // entry 0 is not a documented process-image guarantee, so it never
        // fills the common application identity columns.
        record.set("signature_count", Cell::Int(0));
        record.set("relation_count", Cell::Int(0));
        record.set("search_text", Cell::Text(file.search_values.join("\n")));

        for (table, values) in children {
            record.child(table, values);
        }
        paths(&mut record, &file);
        record.set(
            "path_count",
            Cell::Int(record.child_count("WerPaths") as i64),
        );

        let mut source = ctx
            .facts
            .source_from_row(
                &facts_path,
                FILES_TABLE,
                file.rowid,
                Some(file.source_file.as_str()),
                Some("수집된 크래시 덤프"),
            )?
            .ok_or_else(|| anyhow::anyhow!("크래시 덤프 facts 출처가 없습니다"))?;
        source.artifact = ARTIFACT.to_string();
        record.source(Some(source));

        built.push(DumpRecord {
            record,
            rowid: file.rowid,
            collected_directory: file.collected_directory.clone(),
            report_file: file.report_file.clone(),
        });
    }
    Ok(built)
}

/// Display text built here from stored values; it names the collected file and
/// where it was collected, never what a process did.
fn description(file: &FileRow) -> String {
    let mut parts = vec![file.file_name.clone()];
    if let Some(Cell::Text(format)) = file.values.get("dump_format") {
        parts.push(format.clone());
    }
    if let Some(Cell::Text(code)) = file.values.get("dump_exception_code_name") {
        parts.push(code.clone());
    } else if let Some(Cell::Text(code)) = file.values.get("dump_exception_code_hex") {
        parts.push(code.clone());
    }
    parts.push(file.location_role.clone());
    parts.join(" · ")
}

/// Recorded paths of a dump record: the collected file itself and the module
/// path stored at `MINIDUMP_MODULE_LIST` index 0.
fn paths(record: &mut Record, file: &FileRow) {
    record.child(
        "WerPaths",
        vec![
            Cell::Text("dump_file".to_string()),
            Cell::Text(file.source_file.clone()),
            Cell::Text(file.source_file.clone()),
            text(&file.file_name),
            text(&file.file_name.to_lowercase()),
            Cell::Null,
            Cell::Text("literal".to_string()),
            Cell::Text("collected_file_location".to_string()),
        ],
    );
    if let Some(path) = file.first_module_path.as_deref() {
        let name = basename_win(path);
        record.child(
            "WerPaths",
            vec![
                Cell::Text("dump_first_module_path".to_string()),
                Cell::Text(path.to_string()),
                Cell::Text(path.to_string()),
                text(&name),
                text(&name.to_lowercase()),
                Cell::Null,
                Cell::Text("literal".to_string()),
                Cell::Text("module_list_index_0".to_string()),
            ],
        );
    }
}

/// One dump ↔ report relation, by the collected report file's own path.
pub(super) struct DumpLink {
    pub dump_index: usize,
    pub report_source_file: String,
    pub directory: String,
}

/// Dumps relate to the report collected in the same directory. Nothing is
/// matched by process name, bucket or time.
pub(super) fn links(dumps: &[DumpRecord]) -> Vec<DumpLink> {
    dumps
        .iter()
        .enumerate()
        .filter_map(|(index, dump)| {
            dump.report_file.as_ref().map(|report| DumpLink {
                dump_index: index,
                report_source_file: report.clone(),
                directory: dump.collected_directory.clone(),
            })
        })
        .collect()
}

/// Collection evidence for the dump scope.
pub(super) struct Observation {
    pub source_name: &'static str,
    pub facts_db: Option<String>,
    pub facts_table: Option<String>,
    pub facts_generation: Option<String>,
    pub collection_state: &'static str,
    pub record_count: i64,
    pub failed_count: i64,
    pub note: String,
    pub source: Option<SourceRef>,
}

/// Distinguish "no dump collected" from "dumps collected but unreadable".
pub(super) fn observation(ctx: &Ctx, dumps: &[DumpRecord]) -> Result<Observation> {
    let facts_path = dump_path(ctx.out_dir);
    let found = ctx.facts.by_path(&facts_path);
    // Only a dump whose bytes could not be read fails; an identified
    // non-minidump container or version was read successfully.
    let failed = dumps
        .iter()
        .filter(|dump| {
            matches!(
                dump.record.get("dump_parse_status"),
                Some(Cell::Text(status))
                    if status.as_str() == wer_dump::STATUS_READ_FAILED
                        || status.as_str() == wer_dump::STATUS_TRUNCATED
            )
        })
        .count() as i64;
    let unsupported = dumps
        .iter()
        .filter(|dump| {
            matches!(
                dump.record.get("dump_format"),
                Some(Cell::Text(format)) if format.as_str() != wer_dump::FORMAT_MINIDUMP
            )
        })
        .count();
    let lookup_failed = dumps
        .iter()
        .filter(|dump| {
            matches!(
                dump.record.get("dump_report_lookup_state"),
                Some(Cell::Text(state)) if state.as_str() == LOOKUP_UNREADABLE
            )
        })
        .count();
    let discovery_errors: i64 = match (found, open_facts(ctx.out_dir)?) {
        (Some(_), Some(conn)) => conn.query_row(
            &format!("SELECT COUNT(*) FROM \"{DISCOVERY_ERRORS_TABLE}\""),
            [],
            |row| row.get(0),
        )?,
        _ => 0,
    };
    let (collection_state, facts_db, facts_table, facts_generation, source) = match found {
        Some(db) if !dumps.is_empty() => {
            let generation = ctx.facts.generation(db)?;
            let mut source = ctx
                .facts
                .source_from_row(&facts_path, FILES_TABLE, dumps[0].rowid, None, None)?;
            if let Some(source) = source.as_mut() {
                source.artifact = ARTIFACT.to_string();
            }
            (
                "collected",
                Some(db.relative.clone()),
                Some(FILES_TABLE.to_string()),
                Some(generation),
                source,
            )
        }
        Some(db) => {
            let generation = ctx.facts.generation(db)?;
            (
                "collected_empty",
                Some(db.relative.clone()),
                Some(FILES_TABLE.to_string()),
                Some(generation),
                None,
            )
        }
        None => ("not_collected", None, None, None, None),
    };
    Ok(Observation {
        source_name: "CrashDump",
        facts_db,
        facts_table,
        facts_generation,
        collection_state,
        record_count: dumps.len() as i64,
        failed_count: failed,
        note: format!(
            "수집 덤프 {}개, 미니덤프가 아닌 컨테이너 {}개, 보고서 확인 실패 {}개, 탐색 실패 {}건",
            dumps.len(),
            unsupported,
            lookup_failed,
            discovery_errors
        ),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn location_roles_follow_the_collected_directory() {
        let base = std::env::temp_dir().join(format!("wina-dumps-{}", uuid::Uuid::new_v4()));
        let report_dir = base.join("WER/ReportQueue/abc");
        let crash_dir = base.join("Users/u/AppData/Local/CrashDumps");
        let temp_dir = base.join("WER/Temp");
        let other = base.join("Other");
        for dir in [&report_dir, &crash_dir, &temp_dir, &other] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(report_dir.join("Report.wer"), b"Version=1").unwrap();
        std::fs::write(report_dir.join("memory.hdmp"), b"").unwrap();
        std::fs::write(crash_dir.join("app.exe.1.dmp"), b"").unwrap();
        std::fs::write(temp_dir.join("WER1.tmp.dmp"), b"").unwrap();
        std::fs::write(other.join("x.mdmp"), b"").unwrap();

        let (found, errors) = collected_dumps(&base);
        assert!(errors.is_empty());
        let roles: BTreeMap<String, &'static str> = found
            .iter()
            .map(|dump| {
                (
                    dump.path.file_name().unwrap().to_string_lossy().to_string(),
                    dump.location_role,
                )
            })
            .collect();
        assert_eq!(roles["memory.hdmp"], LOCATION_REPORT_DIR);
        assert_eq!(roles["app.exe.1.dmp"], LOCATION_CRASH_DUMPS);
        assert_eq!(roles["WER1.tmp.dmp"], LOCATION_WER_TEMP);
        assert_eq!(roles["x.mdmp"], LOCATION_OTHER);
        let report = found
            .iter()
            .find(|dump| dump.location_role == LOCATION_REPORT_DIR)
            .unwrap();
        assert_eq!(
            report.report_file.as_deref(),
            Some(report_dir.join("Report.wer").display().to_string().as_str())
        );
        // A dump outside that directory is never tied to the report.
        let crash = found
            .iter()
            .find(|dump| dump.location_role == LOCATION_CRASH_DUMPS)
            .unwrap();
        assert_eq!(crash.report_file, None);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A directory that cannot be read is neither "no report" nor silently
    /// skipped: walk failures and report lookup failures stay recorded.
    #[cfg(unix)]
    #[test]
    fn unreadable_locations_are_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("wina-dumps-locked-{}", uuid::Uuid::new_v4()));
        let target = base.join("target");
        let out = base.join("out");
        let report_dir = target.join("WER/ReportQueue/abc");
        let locked = target.join("WER/ReportArchive/locked");
        std::fs::create_dir_all(&report_dir).unwrap();
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(report_dir.join("Report.wer"), b"Version=1").unwrap();
        std::fs::write(report_dir.join("memory.hdmp"), b"").unwrap();
        std::fs::write(locked.join("hidden.dmp"), b"").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let published = prepare_inputs(&out, &target, "facts");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        published.unwrap();
        let conn = Connection::open(dump_path(&out)).unwrap();
        let errors: Vec<String> = conn
            .prepare("SELECT error FROM Wer_Dump_Discovery_Errors")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("locked"), "{errors:?}");
        let state: String = conn
            .query_row(
                "SELECT report_lookup_state FROM Wer_Dump_Files WHERE file_name='memory.hdmp'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "found");
        drop(conn);

        let lookup = report_lookup(&target.join("WER/ReportQueue/missing"));
        assert_eq!(lookup.state, LOOKUP_UNREADABLE);
        assert!(lookup.report.is_none() && lookup.error.is_some());
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Location roles read the path inside the collection, not the folders
    /// above it on the analyst's machine.
    #[test]
    fn location_roles_ignore_the_collection_root() {
        let base = std::env::temp_dir().join(format!("wina-dumps-root-{}", uuid::Uuid::new_v4()));
        let target = base.join("WER");
        let other = target.join("Other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("x.mdmp"), b"").unwrap();
        let (found, errors) = collected_dumps(&target);
        assert!(errors.is_empty());
        assert_eq!(found[0].location_role, LOCATION_OTHER);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
