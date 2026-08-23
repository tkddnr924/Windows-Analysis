//! Parse-stage orchestration, mirroring main.py run_host: locate each
//! artifact's files under the target, parse, and write per-source SQLite into
//! CATEGORY/<name>.sqlite. Streaming parsers write directly; smaller ones use
//! write_table. Overview builders are a separate (later) stage.
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Result;
use serde::Serialize;

use crate::case_store::{self};
use crate::finder;
use crate::overview;
use crate::parsers::{
    amcache, browser_cache, browser_history, eventlog, jumplist, mft, powershell_history, prefetch,
    rdpcache, registry, srum, taskscheduler, usnjrnl, wer,
};
use crate::sqlite::{write_table, write_table_cols, Row};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

// Global progress sink (Send). When set (by the GUI), progress lines route here
// instead of stdout; unset (CLI) prints to stdout. Global + Send so worker
// threads (parallel registry parsing) reach the same sink.
static LOG_SINK: Mutex<Option<Box<dyn FnMut(&str) + Send>>> = Mutex::new(None);

/// Immutable per-run text logs are retained outside artifact output folders so
/// a full reparse can clear derived SQLite without erasing prior diagnostics.
pub const PARSE_LOG_DIRECTORY: &str = "parse_logs";
const PARSE_STAGING_DIRECTORY: &str = ".parse-staging";
/// Sealed copies of individual artifact outputs.  They live only inside a
/// staging run and make partial publication independent from files a later
/// artifact may share or modify (for example Browser History and Cache).
const PARSE_COMMITTED_DIRECTORY: &str = ".artifact-committed";

static PERSISTENT_LOG: Mutex<Option<File>> = Mutex::new(None);
static PARSE_RUN_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

/// A filesystem-safe ID for correlating GUI supervision records with a worker
/// process. The local sequence keeps IDs unique even if the same GUI process
/// starts more than one run inside a millisecond.
pub fn new_parse_run_id() -> String {
    format!(
        "{}_{:05}_{:04}",
        chrono::Local::now().format("%Y%m%d_%H%M%S_%3f"),
        std::process::id(),
        PARSE_RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

fn safe_run_id(run_id: &str) -> String {
    let value: String = run_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(96)
        .collect();
    if value.is_empty() {
        new_parse_run_id()
    } else {
        value
    }
}

pub fn parse_run_log_path(host_dir: &Path, run_id: &str) -> std::path::PathBuf {
    host_dir
        .join(PARSE_LOG_DIRECTORY)
        .join(format!("{}.txt", safe_run_id(run_id)))
}

fn artifact_output_categories(only: Option<&HashSet<String>>) -> HashSet<&'static str> {
    let Some(only) = only else {
        return HashSet::new();
    };
    let mut categories = HashSet::new();
    for artifact in only {
        match artifact.as_str() {
            "Amcache" => {
                categories.insert("AMCACHE");
            }
            "EventLog" => {
                categories.insert("EVENTLOG");
            }
            "Registry" => {
                categories.insert("REGISTRY");
            }
            "UsnJrnl" => {
                categories.insert("FILESYSTEM");
            }
            "MFT" => {
                categories.insert("_OVERVIEW");
            }
            "JumpList" => {
                categories.insert("JUMPLIST");
            }
            "SRUM" => {
                categories.insert("SRUM");
            }
            "TaskScheduler" => {
                categories.insert("TASKSCHEDULER");
            }
            "RdpCache" => {
                categories.insert("RDPCACHE");
            }
            "BrowserHistory" | "BrowserCache" => {
                categories.insert("BROWSER");
            }
            "Prefetch" => {
                categories.insert("PREFETCH");
            }
            "PowerShell" => {
                categories.insert("POWERSHELL");
            }
            "WER" => {
                categories.insert("WER");
            }
            _ => {}
        }
    }
    // Overview builders replace files in this directory even during a scoped
    // run, so it must never be hard-linked to the published output.
    categories.insert("_OVERVIEW");
    categories
}

fn copy_tree(source: &Path, destination: &Path, copy_data: bool) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path, copy_data)?;
        } else if copy_data {
            std::fs::copy(&source_path, &destination_path)?;
        } else if std::fs::hard_link(&source_path, &destination_path).is_err() {
            // Cross-volume evidence folders cannot be linked.  Copying is
            // slower but keeps the staged run isolated from published data.
            std::fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}

/// Build an isolated output tree.  A failed/cancelled parser can therefore
/// never expose a half-written SQLite database to the analysis views.
fn prepare_staging_output(
    live_dir: &Path,
    run_id: &str,
    only: Option<&HashSet<String>>,
) -> Result<PathBuf> {
    let stage = live_dir
        .join(PARSE_STAGING_DIRECTORY)
        .join(safe_run_id(run_id));
    if stage.exists() {
        std::fs::remove_dir_all(&stage)?;
    }
    std::fs::create_dir_all(&stage)?;
    if only.is_none() {
        return Ok(stage);
    }
    let copied_data = artifact_output_categories(only);
    for entry in std::fs::read_dir(live_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !entry.path().is_dir()
            || name == PARSE_LOG_DIRECTORY
            || name == PARSE_STAGING_DIRECTORY
            || name == PARSE_COMMITTED_DIRECTORY
        {
            continue;
        }
        copy_tree(
            &entry.path(),
            &stage.join(name.as_ref()),
            copied_data.contains(name.as_ref()),
        )?;
    }
    Ok(stage)
}

/// Publish staged category directories with rename operations only after every
/// artifact and overview succeeded.  Directory replacement is atomic on the
/// same volume, and the small rollback path retains the prior output on an
/// individual rename failure.
fn publish_staging_output(live_dir: &Path, stage: &Path, run_id: &str) -> Result<()> {
    let backup = live_dir
        .join(PARSE_STAGING_DIRECTORY)
        .join(format!("{}.previous", safe_run_id(run_id)));
    if backup.exists() {
        std::fs::remove_dir_all(&backup)?;
    }
    std::fs::create_dir_all(&backup)?;
    let mut published: Vec<(PathBuf, PathBuf)> = Vec::new();
    let entries: Vec<_> = std::fs::read_dir(stage)?.collect::<std::result::Result<_, _>>()?;
    for entry in entries {
        let source = entry.path();
        let name = entry.file_name();
        if name == PARSE_COMMITTED_DIRECTORY {
            continue;
        }
        let destination = live_dir.join(&name);
        let previous = backup.join(&name);
        if destination.exists() {
            std::fs::rename(&destination, &previous)?;
        }
        if let Err(error) = std::fs::rename(&source, &destination) {
            if previous.exists() {
                let _ = std::fs::rename(&previous, &destination);
            }
            for (published_destination, published_previous) in published.into_iter().rev() {
                let rollback_source =
                    stage.join(published_destination.file_name().unwrap_or_default());
                let _ = std::fs::rename(&published_destination, rollback_source);
                if published_previous.exists() {
                    let _ = std::fs::rename(published_previous, published_destination);
                }
            }
            return Err(error.into());
        }
        published.push((destination, previous));
    }
    let _ = std::fs::remove_dir_all(&backup);
    let _ = std::fs::remove_dir_all(stage);
    Ok(())
}

type OutputSignature = (u64, u128);

fn staged_file_signatures(root: &Path) -> std::collections::HashMap<PathBuf, OutputSignature> {
    fn visit(
        root: &Path,
        current: &Path,
        out: &mut std::collections::HashMap<PathBuf, OutputSignature>,
    ) {
        let Ok(entries) = std::fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|name| name == PARSE_COMMITTED_DIRECTORY)
                {
                    continue;
                }
                visit(root, &path, out);
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            if let Ok(relative) = path.strip_prefix(root) {
                if relative
                    .components()
                    .next()
                    .is_some_and(|component| component.as_os_str() == PARSE_COMMITTED_DIRECTORY)
                {
                    continue;
                }
                out.insert(relative.to_path_buf(), (metadata.len(), modified));
            }
        }
    }
    let mut out = std::collections::HashMap::new();
    visit(root, root, &mut out);
    out
}

/// A sealed output is copied immediately after one artifact finishes.  The
/// partial-run publisher reads this immutable snapshot rather than the shared
/// staging category, which prevents a later failing artifact from leaking a
/// half-written SQLite file into an earlier successful artifact's publish.
#[derive(Clone, Debug)]
struct SealedArtifactOutput {
    artifact: String,
    relative: PathBuf,
}

fn seal_artifact_outputs(
    stage: &Path,
    artifact: &str,
    outputs: &[String],
) -> Result<Vec<SealedArtifactOutput>> {
    let artifact_root = stage
        .join(PARSE_COMMITTED_DIRECTORY)
        .join(artifact.replace(|character: char| !character.is_ascii_alphanumeric(), "_"));
    let mut sealed = Vec::new();
    for output in outputs {
        let relative = PathBuf::from(output);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            anyhow::bail!("invalid staged artifact output path");
        }
        let source = stage.join(&relative);
        if !source.is_file() {
            continue;
        }
        let destination = artifact_root.join(&relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&source, &destination)?;
        sealed.push(SealedArtifactOutput {
            artifact: artifact.to_string(),
            relative,
        });
    }
    Ok(sealed)
}

fn changed_staged_outputs(
    before: &std::collections::HashMap<PathBuf, OutputSignature>,
    root: &Path,
) -> Vec<String> {
    let after = staged_file_signatures(root);
    let mut changed: Vec<String> = after
        .iter()
        .filter_map(|(path, signature)| {
            (before.get(path) != Some(signature)).then(|| path.to_string_lossy().to_string())
        })
        .collect();
    changed.sort();
    changed
}

/// Publish only complete files belonging to artifacts that completed in this
/// invocation. Each SQLite file is built in the isolated stage then renamed,
/// so a failed sibling artifact can never expose its partial database or erase
/// the prior committed result.
fn publish_staged_artifact_files(
    live_dir: &Path,
    stage: &Path,
    run_id: &str,
    outputs: &[SealedArtifactOutput],
) -> Result<()> {
    let backup = live_dir
        .join(PARSE_STAGING_DIRECTORY)
        .join(format!("{}.partial-previous", safe_run_id(run_id)));
    if backup.exists() {
        std::fs::remove_dir_all(&backup)?;
    }
    std::fs::create_dir_all(&backup)?;
    let mut published: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();
    // A later successful artifact may intentionally add a table to the same
    // SQLite file (Browser History + Cache).  Last successful writer wins,
    // matching normal parse order while failures still publish none of their
    // changed files.
    let mut unique = std::collections::BTreeMap::<PathBuf, String>::new();
    for output in outputs {
        unique.insert(output.relative.clone(), output.artifact.clone());
    }
    for (relative, artifact) in unique {
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            anyhow::bail!("invalid staged artifact output path");
        }
        let source = stage
            .join(PARSE_COMMITTED_DIRECTORY)
            .join(artifact.replace(|character: char| !character.is_ascii_alphanumeric(), "_"))
            .join(&relative);
        if !source.is_file() {
            continue;
        }
        let destination = live_dir.join(&relative);
        let previous = backup.join(&relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if destination.exists() {
            if let Some(parent) = previous.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&destination, &previous)?;
        }
        if let Err(error) = std::fs::rename(&source, &destination) {
            if previous.exists() {
                let _ = std::fs::rename(&previous, &destination);
            }
            for (published_destination, published_previous, published_source) in
                published.into_iter().rev()
            {
                let _ = std::fs::rename(&published_destination, published_source);
                if published_previous.exists() {
                    let _ = std::fs::rename(published_previous, published_destination);
                }
            }
            return Err(error.into());
        }
        published.push((destination, previous, source));
    }
    let _ = std::fs::remove_dir_all(backup);
    Ok(())
}

fn log_timestamp() -> String {
    chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

fn normalize_log_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Append a timestamped parse lifecycle or supervisor event. This deliberately
/// never fails the parser: forensic output must continue even when a disk log
/// is temporarily unavailable.
pub fn append_parse_log_event(log_path: &Path, message: &str) {
    let Some(parent) = log_path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) else {
        return;
    };
    if writeln!(
        file,
        "{} {}",
        log_timestamp(),
        normalize_log_message(message)
    )
    .is_ok()
    {
        let _ = file.sync_data();
    }
}

fn append_current_log_output(message: &str) {
    let Ok(mut guard) = PERSISTENT_LOG.lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    if writeln!(
        file,
        "{} [OUTPUT] {}",
        log_timestamp(),
        normalize_log_message(message)
    )
    .is_ok()
    {
        let _ = file.sync_data();
    }
}

fn append_current_log_lifecycle(message: &str) {
    let Ok(mut guard) = PERSISTENT_LOG.lock() else {
        return;
    };
    let Some(file) = guard.as_mut() else {
        return;
    };
    if writeln!(
        file,
        "{} [LIFECYCLE] {}",
        log_timestamp(),
        normalize_log_message(message)
    )
    .is_ok()
    {
        let _ = file.sync_data();
    }
}

struct PersistentRunLog {
    active: bool,
    finished: bool,
}

impl PersistentRunLog {
    fn begin(
        out_dir: &Path,
        run_id: &str,
        case_id: &str,
        host_id: &str,
        only: Option<&HashSet<String>>,
    ) -> Self {
        let path = parse_run_log_path(out_dir, run_id);
        let Some(parent) = path.parent() else {
            return Self {
                active: false,
                finished: false,
            };
        };
        if std::fs::create_dir_all(parent).is_err() {
            return Self {
                active: false,
                finished: false,
            };
        }
        let Ok(file) = OpenOptions::new().create(true).append(true).open(path) else {
            return Self {
                active: false,
                finished: false,
            };
        };
        let active = PERSISTENT_LOG
            .lock()
            .map(|mut guard| {
                *guard = Some(file);
                true
            })
            .unwrap_or(false);
        let logger = Self {
            active,
            finished: false,
        };
        if logger.active {
            let scope = only
                .map(|items| items.len().to_string())
                .unwrap_or_else(|| "all".to_string());
            append_current_log_lifecycle(&format!(
                "run_started case={} host={} scope={}",
                case_id, host_id, scope
            ));
        }
        logger
    }

    fn finish(&mut self, status: &str, detail: &str) {
        if !self.active || self.finished {
            return;
        }
        append_current_log_lifecycle(&format!("run_finished status={} {}", status, detail));
        if let Ok(mut guard) = PERSISTENT_LOG.lock() {
            *guard = None;
        }
        self.finished = true;
    }
}

impl Drop for PersistentRunLog {
    fn drop(&mut self) {
        if self.active && !self.finished {
            append_current_log_lifecycle("run_interrupted reason=no_terminal_record");
            if let Ok(mut guard) = PERSISTENT_LOG.lock() {
                *guard = None;
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseReport {
    run_id: String,
    run_at: String,
    status: String,
    duration_ms: u128,
    published: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    registry_hives: Vec<RegistryHiveReport>,
    /// Explicit run-wide Registry recovery contract.  This prevents a fast
    /// live-only run from being mistaken for one that applied deleted cells or
    /// transaction logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_recovery: Option<RegistryRecoveryReport>,
    /// Parser stages that reached a terminal successful state. This does not
    /// mean their output was made visible in the live host directory.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    completed_artifacts: Vec<String>,
    /// Artifacts with one or more outputs actually published by this run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    published_artifacts: Vec<String>,
    /// Host-relative files actually published by this run. This is the source
    /// of truth for UI result availability, rather than parser completion.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    published_outputs: Vec<String>,
    artifacts: Vec<ParseArtifactReport>,
    overview: Vec<OverviewTableReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryHiveReport {
    source_path: String,
    status: String,
    row_count: usize,
    /// Logs discovered beside the hive. In temporary live-only mode they are
    /// recorded as provenance but deliberately not applied.
    recovery_logs_discovered: usize,
    recovery_log_count: usize,
    /// Whether deleted-cell recovery and transaction-log application ran.
    recovery_enabled: bool,
    recovered_row_count: usize,
    recovery_permit_wait_ms: u128,
    build_recovery_ms: u128,
    iteration_and_sqlite_write_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryRecoveryReport {
    /// "disabled" for the temporary live-only parser mode.
    mode: String,
    deleted_cell_recovery_applied: bool,
    transaction_logs_applied: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseArtifactReport {
    name: String,
    status: String,
    /// Whether this parser performed a source discovery pass. This is kept
    /// apart from rows/outputs: an existing file can validly yield zero rows.
    input_discovery_checked: bool,
    /// True when the discovery pass (or a parser-provided source row) found at
    /// least one evidence file.  `no_input` is valid only after a checked,
    /// empty discovery pass.
    evidence_discovered: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    outputs: Vec<String>,
    /// Outputs from this artifact that were actually copied into the live
    /// result directory. A completed artifact can deliberately have none when
    /// a sibling failed and the output belongs to withheld derived overview.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    published_outputs: Vec<String>,
    /// published | withheld | not_published. Kept separate from parser status
    /// so a dashboard never mistakes a sealed staging file for live evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    publication_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    inputs: Vec<ParseInputReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseInputReport {
    name: String,
    source_path: String,
    record_count: usize,
    recovery_log: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OverviewTableReport {
    name: String,
    row_count: usize,
}

/// Persist a terminal report without exposing staged artifact data. The
/// per-run manifest is immutable; `parse_report.json` is only a pointer to
/// the most recent lifecycle outcome for dashboard/status consumers.
fn write_terminal_report(live_dir: &Path, run_id: &str, report: &ParseReport) -> Result<()> {
    let payload = serde_json::to_vec_pretty(report)?;
    std::fs::write(
        parse_run_log_path(live_dir, run_id).with_extension("json"),
        &payload,
    )?;
    let temporary = live_dir.join("parse_report.json.staging");
    std::fs::write(&temporary, payload)?;
    std::fs::rename(temporary, live_dir.join("parse_report.json"))?;
    Ok(())
}

/// Install (or clear) the progress sink.
pub fn set_log_sink(sink: Option<Box<dyn FnMut(&str) + Send>>) {
    *LOG_SINK.lock().unwrap() = sink;
}

fn emit(msg: &str) {
    if let Ok(mut g) = LOG_SINK.lock() {
        match g.as_mut() {
            Some(f) => f(msg),
            None => println!("{}", msg),
        }
    }
    append_current_log_output(msg);
}

/// Cooperative cancel flag: `run_host` clears it at start and checks it before
/// each artifact; `cancel` (from the GUI) sets it to stop the remaining work.
/// Parsers poll `cancelled()` inside their row loops so a long single artifact
/// (e.g. a big registry hive) stops promptly too, not only between artifacts.
pub static CANCEL: AtomicBool = AtomicBool::new(false);

/// True once the user requested cancel. Parsers should break out of their
/// row/entry loops when this returns true.
pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}

/// Every artifact the pipeline knows how to parse, in run order.
pub const ARTIFACT_NAMES: &[&str] = &[
    "Amcache",
    "EventLog",
    "Registry",
    "UsnJrnl",
    "MFT",
    "JumpList",
    "SRUM",
    "TaskScheduler",
    "RdpCache",
    "BrowserHistory",
    "BrowserCache",
    "PowerShell",
    "Prefetch",
    "WER",
];

fn announce(name: &str) {
    emit(&format!("=== {} ===", name));
}
fn found(paths: &[std::path::PathBuf]) {
    if paths.is_empty() {
        emit(&format!("[!] no matching files found"));
    } else if paths.len() <= 20 {
        for p in paths {
            emit(&format!("[*] found: {}", p.display()));
        }
    } else {
        emit(&format!("[*] found: {} files", paths.len()));
    }
}

fn record_inputs(report: &mut ParseReport, artifact: &str, paths: &[std::path::PathBuf]) {
    if let Some(entry) = report
        .artifacts
        .iter_mut()
        .rev()
        .find(|entry| entry.name == artifact)
    {
        entry.input_discovery_checked = true;
        entry.evidence_discovered |= !paths.is_empty();
    }
    for path in paths {
        record_input(report, artifact, path, false);
        if artifact == "Amcache" {
            for log in registry::sibling_logs(path) {
                record_input(report, artifact, &log, true);
            }
        }
    }
}

/// An artifact can be validly attempted without its evidence file being
/// present.  This is distinct from a parser failure: no output exists, and a
/// retry cannot produce one until the missing evidence is supplied.
fn mark_artifact_no_input(report: &mut ParseReport, artifact: &str) {
    if let Some(entry) = report
        .artifacts
        .iter_mut()
        .rev()
        .find(|entry| entry.name == artifact)
    {
        entry.status = "no_input".to_string();
        entry.publication_status = Some("not_published".to_string());
    }
}

/// A parser section with neither discovered evidence nor staged output is not
/// a successful empty parse.  Treat it consistently as an evidence-missing
/// state so the report/UI never says "completed" for an artifact that was
/// never able to run.  Parsers may still explicitly mark this earlier (MFT
/// does so to provide a more specific log line).
fn artifact_has_no_input(entry: &ParseArtifactReport, outputs: &[String]) -> bool {
    entry.status == "no_input"
        || (entry.input_discovery_checked && !entry.evidence_discovered && outputs.is_empty())
}

fn record_published_outputs(report: &mut ParseReport, outputs: &[SealedArtifactOutput]) {
    let mut by_artifact = std::collections::BTreeMap::<String, Vec<String>>::new();
    for output in outputs {
        by_artifact
            .entry(output.artifact.clone())
            .or_default()
            .push(output.relative.to_string_lossy().to_string());
    }
    for paths in by_artifact.values_mut() {
        paths.sort();
        paths.dedup();
    }
    report.published_artifacts = by_artifact.keys().cloned().collect();
    report.published_outputs = by_artifact.values().flatten().cloned().collect();
    report.published_outputs.sort();
    report.published_outputs.dedup();

    for artifact in &mut report.artifacts {
        let published = by_artifact.remove(&artifact.name).unwrap_or_default();
        artifact.published_outputs = published;
        artifact.publication_status = Some(if artifact.published_outputs.is_empty() {
            if artifact.status == "completed" && !artifact.outputs.is_empty() {
                "withheld"
            } else {
                "not_published"
            }
            .to_string()
        } else {
            "published".to_string()
        });
    }
}

fn record_input(report: &mut ParseReport, artifact: &str, path: &Path, recovery_log: bool) {
    let Some(entry) = report
        .artifacts
        .iter_mut()
        .rev()
        .find(|entry| entry.name == artifact)
    else {
        return;
    };
    entry.input_discovery_checked = true;
    entry.evidence_discovered = true;
    let source_path = path.to_string_lossy().to_string();
    if entry
        .inputs
        .iter()
        .any(|input| input.source_path == source_path)
    {
        return;
    }
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| source_path.clone());
    entry.inputs.push(ParseInputReport {
        name,
        source_path,
        record_count: 0,
        recovery_log,
    });
}

fn record_input_count(report: &mut ParseReport, artifact: &str, path: &Path, record_count: usize) {
    record_input(report, artifact, path, false);
    let source_path = path.to_string_lossy();
    if let Some(entry) = report
        .artifacts
        .iter_mut()
        .rev()
        .find(|entry| entry.name == artifact)
    {
        if let Some(input) = entry
            .inputs
            .iter_mut()
            .find(|input| input.source_path == source_path.as_ref())
        {
            input.record_count = record_count;
        }
    }
}

fn record_rows_by_source(report: &mut ParseReport, artifact: &str, rows: &[Row]) {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for row in rows {
        if let Some(source) = row.get("_source_file").filter(|source| !source.is_empty()) {
            *counts.entry(source.clone()).or_default() += 1;
        }
    }
    for (source, count) in counts {
        record_input_count(report, artifact, Path::new(&source), count);
    }
}

fn add_rows_by_source(report: &mut ParseReport, artifact: &str, rows: &[Row]) {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for row in rows {
        if let Some(source) = row.get("_source_file").filter(|source| !source.is_empty()) {
            *counts.entry(source.clone()).or_default() += 1;
        }
    }
    for (source, count) in counts {
        record_input(report, artifact, Path::new(&source), false);
        if let Some(entry) = report
            .artifacts
            .iter_mut()
            .rev()
            .find(|entry| entry.name == artifact)
        {
            if let Some(input) = entry
                .inputs
                .iter_mut()
                .find(|input| input.source_path == source)
            {
                input.record_count = input.record_count.saturating_add(count);
            }
        }
    }
}

fn panic_details(payload: Box<dyn std::any::Any + Send>) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|value| (*value).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    // Keep the durable report/log actionable without turning a parser panic
    // into an unbounded dump of local paths or stack frames.
    let compact_trace = backtrace.lines().take(24).collect::<Vec<_>>().join(" | ");
    let combined = if compact_trace.is_empty() {
        message
    } else {
        format!("{message}; backtrace={compact_trace}")
    };
    combined.chars().take(4_000).collect()
}

fn uniq_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_string()) {
        return base.to_string();
    }
    let mut i = 2;
    loop {
        let n = format!("{}_{}", base, i);
        if taken.insert(n.clone()) {
            return n;
        }
        i += 1;
    }
}

pub fn run_host(
    case_id: &str,
    host_id: &str,
    cases_dir: &Path,
    only: Option<HashSet<String>>,
) -> Result<()> {
    run_host_with_log_id(case_id, host_id, cases_dir, only, None)
}

pub fn run_host_with_log_id(
    case_id: &str,
    host_id: &str,
    cases_dir: &Path,
    only: Option<HashSet<String>>,
    run_id: Option<&str>,
) -> Result<()> {
    let host = case_store::load_host(case_id, host_id, cases_dir)?;
    let live_dir = case_store::host_dir(cases_dir, case_id, host_id);
    let target = std::path::PathBuf::from(&host.target_dir);
    CANCEL.store(false, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let run_id = run_id.map(safe_run_id).unwrap_or_else(new_parse_run_id);
    let mut persistent_log =
        PersistentRunLog::begin(&live_dir, &run_id, case_id, host_id, only.as_ref());
    let mut report = ParseReport {
        run_id: run_id.clone(),
        run_at: String::new(),
        status: "running".to_string(),
        duration_ms: 0,
        published: false,
        errors: Vec::new(),
        registry_hives: Vec::new(),
        registry_recovery: None,
        completed_artifacts: Vec::new(),
        published_artifacts: Vec::new(),
        published_outputs: Vec::new(),
        artifacts: Vec::new(),
        overview: Vec::new(),
    };
    let out_dir = match prepare_staging_output(&live_dir, &run_id, only.as_ref()) {
        Ok(stage) => stage,
        Err(error) => {
            let run_at = chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string();
            report.run_at = run_at.clone();
            report.status = "error".to_string();
            report.duration_ms = started.elapsed().as_millis();
            report.errors.push(format!("staging: {error}"));
            if let Err(report_error) = write_terminal_report(&live_dir, &run_id, &report) {
                append_current_log_lifecycle(&format!(
                    "terminal_report_failed error={report_error}"
                ));
            }
            if let Err(status_error) = case_store::update_host_status(
                case_id,
                host_id,
                cases_dir,
                &run_at,
                "error",
                Vec::new(),
                Some(started.elapsed().as_secs_f64()),
            ) {
                append_current_log_lifecycle(&format!("host_status_failed error={status_error}"));
            }
            persistent_log.finish("error", &format!("stage_prepare_failed error={error}"));
            return Err(error);
        }
    };
    append_current_log_lifecycle(&format!("staging_started path={}", out_dir.display()));
    let want = |n: &str| only.as_ref().map_or(true, |o| o.contains(n));
    let mut artifacts_run: Vec<String> = Vec::new();
    let mut sealed_outputs: Vec<SealedArtifactOutput> = Vec::new();
    let mut had_error = false;
    let cat = |c: &str| out_dir.join(c);

    // Each artifact is isolated: an Err is logged and skipped, and a *panic*
    // (e.g. a malformed structure that trips an index) is caught too, so one
    // bad artifact can never stop the ones after it or the _OVERVIEW stage.
    macro_rules! guard { ($name:expr, $body:block) => {{
        report.artifacts.push(ParseArtifactReport { name: $name.to_string(), status: "running".to_string(), input_discovery_checked: false, evidence_discovered: false, outputs: Vec::new(), published_outputs: Vec::new(), publication_status: None, error: None, inputs: Vec::new() });
        append_current_log_lifecycle(&format!("artifact_started name={}", $name));
        if !CANCEL.load(Ordering::Relaxed) {
            let output_before = staged_file_signatures(&out_dir);
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> { $body Ok(()) }));
            match res {
                Ok(Ok(())) => {
                    let outputs = changed_staged_outputs(&output_before, &out_dir);
                    let no_input = report
                        .artifacts
                        .last()
                        .is_some_and(|entry| artifact_has_no_input(entry, &outputs));
                    if no_input {
                        // Most artifact sections only know that there was no
                        // evidence after their finder returns.  Centralising
                        // the terminal state here keeps Prefetch and every
                        // future artifact truthful without relying on each
                        // parser branch to remember a special case.
                        mark_artifact_no_input(&mut report, $name);
                        append_current_log_lifecycle(&format!(
                            "artifact_finished name={} status=no_input",
                            $name
                        ));
                    } else { match seal_artifact_outputs(&out_dir, $name, &outputs) {
                        Ok(sealed) => {
                            if let Some(entry) = report.artifacts.last_mut() {
                                entry.status = "completed".to_string();
                                entry.outputs = outputs;
                            }
                            sealed_outputs.extend(sealed);
                            report.completed_artifacts.push($name.to_string());
                            append_current_log_lifecycle(&format!(
                                "artifact_finished name={} status=completed",
                                $name
                            ));
                        }
                        Err(error) => {
                            let error = format!("sealed output: {error}");
                            emit(&format!("[!] {} failed: {}", $name, error));
                            had_error = true;
                            report.errors.push(format!("{}: {}", $name, error));
                            if let Some(entry) = report.artifacts.last_mut() {
                                entry.status = "failed".to_string();
                                entry.error = Some(error.clone());
                            }
                            append_current_log_lifecycle(&format!(
                                "artifact_finished name={} status=failed error={}",
                                $name, error
                            ));
                        }
                    }}
                }
                Ok(Err(error)) => {
                    emit(&format!("[!] {} failed: {}", $name, error));
                    had_error = true;
                    let error = error.to_string();
                    report.errors.push(format!("{}: {}", $name, error));
                    if let Some(entry) = report.artifacts.last_mut() {
                        entry.status = "failed".to_string();
                        entry.error = Some(error.clone());
                    }
                    append_current_log_lifecycle(&format!(
                        "artifact_finished name={} status=failed error={}",
                        $name, error
                    ));
                }
                Err(payload) => {
                    let error = panic_details(payload);
                    emit(&format!("[!] {} panicked — skipped: {}", $name, error));
                    had_error = true;
                    report.errors.push(format!("{}: panic: {}", $name, error));
                    if let Some(entry) = report.artifacts.last_mut() {
                        entry.status = "failed".to_string();
                        entry.error = Some(format!("panic: {}", error));
                    }
                    append_current_log_lifecycle(&format!(
                        "artifact_finished name={} status=failed panic={}",
                        $name, error
                    ));
                }
            }
        } else if let Some(entry) = report.artifacts.last_mut() { entry.status = "cancelled".to_string(); append_current_log_lifecycle(&format!("artifact_finished name={} status=cancelled", $name)); }
        artifacts_run.push($name.to_string());
    }}; }

    // --- Amcache (AMCACHE/<stem>.sqlite: Amcache_Programs + Amcache_Files) ---
    if want("Amcache") {
        announce("Amcache");
        guard!("Amcache", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["Amcache.hve"]));
            found(&paths);
            record_inputs(&mut report, "Amcache", &paths);
            let mut taken = HashSet::new();
            for p in &paths {
                let base = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Amcache".into());
                let name = uniq_name(&base, &mut taken);
                let out = cat("AMCACHE").join(format!("{}.sqlite", name));
                let (progs, files) = amcache::parse_amcache(p)?;
                write_table(
                    &out,
                    amcache::PROGRAMS_TABLE,
                    &progs,
                    amcache::PROGRAMS_FIELD_ORDER,
                )?;
                write_table(
                    &out,
                    amcache::FILES_TABLE,
                    &files,
                    amcache::FILES_FIELD_ORDER,
                )?;
                record_input_count(&mut report, "Amcache", p, progs.len() + files.len());
                emit(&format!(
                    "[+] {} programs, {} files -> {}",
                    progs.len(),
                    files.len(),
                    out.display()
                ));
            }
        });
    }

    // --- EventLog (EVENTLOG/<stem>.sqlite) ---
    if want("EventLog") {
        announce("EventLog");
        guard!("EventLog", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, eventlog::ALLOWLIST));
            found(&paths);
            record_inputs(&mut report, "EventLog", &paths);
            let mut taken = HashSet::new();
            for p in &paths {
                let base = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "EventLog".into());
                let name = uniq_name(&base, &mut taken);
                let out = cat("EVENTLOG").join(format!("{}.sqlite", name));
                let n = eventlog::parse_evtx_stream(p, &out, &name)?;
                record_input_count(&mut report, "EventLog", p, n);
                if n > 0 {
                    emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), name));
                }
            }
        });
    }

    // --- Registry (REGISTRY/<filename>.sqlite, table Registry) ---
    if want("Registry") {
        announce("Registry");
        guard!("Registry", {
            let mut all = finder::by_name(&target, registry::REG_FILENAMES);
            all.extend(finder::by_suffix(&target, registry::REG_SUFFIXES));
            // drop a RegBack copy when the live hive of the same name is present
            let live: HashSet<String> = all
                .iter()
                .filter(|p| {
                    !p.components().any(|c| {
                        c.as_os_str()
                            .to_string_lossy()
                            .eq_ignore_ascii_case("regback")
                    })
                })
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_uppercase()))
                .collect();
            all.retain(|p| {
                let is_regback = p.components().any(|c| {
                    c.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("regback")
                });
                let nm = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_uppercase())
                    .unwrap_or_default();
                !is_regback || !live.contains(&nm)
            });
            let paths = finder::dedupe_by_content(all);
            found(&paths);
            record_inputs(&mut report, "Registry", &paths);
            if registry::registry_recovery_disabled() {
                report.registry_recovery = Some(RegistryRecoveryReport {
                    mode: "disabled".to_string(),
                    deleted_cell_recovery_applied: false,
                    transaction_logs_applied: false,
                });
                emit("[*] Registry recovery disabled temporarily: deleted cells and transaction logs were not applied; parsing allocated live hive records only");
            } else {
                report.registry_recovery = Some(RegistryRecoveryReport {
                    mode: "enabled".to_string(),
                    deleted_cell_recovery_applied: true,
                    transaction_logs_applied: true,
                });
            }
            // Assign each hive a unique output name, then parse hives in
            // parallel. Every worker writes its own SQLite output, so normal
            // allocated-record parsing remains isolated in live-only mode.
            let mut taken = HashSet::new();
            let mut jobs: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
            for p in &paths {
                let base = p
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "hive".into());
                let name = uniq_name(&base, &mut taken);
                jobs.push((p.clone(), cat("REGISTRY").join(format!("{}.sqlite", name))));
            }
            // Keep Registry hive work bounded at two workers. If temporary
            // recovery is later re-enabled, the parser's process-wide permits
            // continue to cap the expensive builder/recovery stage as well.
            let workers = registry::registry_recovery_worker_count(jobs.len());
            let next = AtomicUsize::new(0);
            let parsed_counts = Mutex::new(
                Vec::<(std::path::PathBuf, registry::HiveParseMetrics)>::with_capacity(jobs.len()),
            );
            let source_failures = Mutex::new(Vec::<String>::new());
            std::thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| loop {
                        if CANCEL.load(Ordering::Relaxed) {
                            break;
                        } // stop starting new hives
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= jobs.len() {
                            break;
                        }
                        let (src, out) = &jobs[i];
                        if CANCEL.load(Ordering::Relaxed) {
                            break;
                        }
                        match registry::parse_hive_stream_with_metrics(src, out) {
                            Ok(metrics) => {
                                if let Ok(mut counts) = parsed_counts.lock() {
                                    counts.push((src.clone(), metrics.clone()));
                                }
                                emit(&format!(
                                    "[+] {} rows -> {} [Registry]",
                                    metrics.row_count,
                                    out.display()
                                ));
                            }
                            Err(e) => {
                                emit(&format!("[!] {} failed: {}", out.display(), e));
                                if let Ok(mut failures) = source_failures.lock() {
                                    failures.push(format!("{}: {}", src.display(), e));
                                }
                            }
                        }
                    });
                }
            });
            if let Ok(counts) = parsed_counts.into_inner() {
                for (source, metrics) in counts {
                    record_input_count(&mut report, "Registry", &source, metrics.row_count);
                    report.registry_hives.push(RegistryHiveReport {
                        source_path: source.to_string_lossy().to_string(),
                        status: "completed".to_string(),
                        row_count: metrics.row_count,
                        recovery_logs_discovered: metrics.recovery_logs_discovered,
                        recovery_log_count: metrics.recovery_log_count,
                        recovery_enabled: metrics.recovery_enabled,
                        recovered_row_count: metrics.recovered_row_count,
                        recovery_permit_wait_ms: metrics.recovery_permit_wait_ms,
                        build_recovery_ms: metrics.build_recovery_ms,
                        iteration_and_sqlite_write_ms: metrics.iteration_and_sqlite_write_ms,
                        error: None,
                    });
                }
            }
            let failures = source_failures.into_inner().unwrap_or_default();
            if !failures.is_empty() {
                report.registry_hives.extend(failures.iter().map(|failure| {
                    RegistryHiveReport {
                        source_path: failure
                            .split_once(": ")
                            .map(|(path, _)| path)
                            .unwrap_or(failure)
                            .to_string(),
                        status: "failed".to_string(),
                        row_count: 0,
                        recovery_logs_discovered: 0,
                        recovery_log_count: 0,
                        recovery_enabled: !registry::registry_recovery_disabled(),
                        recovered_row_count: 0,
                        recovery_permit_wait_ms: 0,
                        build_recovery_ms: 0,
                        iteration_and_sqlite_write_ms: 0,
                        error: Some(failure.clone()),
                    }
                }));
                anyhow::bail!(
                    "{} Registry source(s) failed: {}",
                    failures.len(),
                    failures.join("; ")
                );
            }
        });
    }

    // --- UsnJrnl (FILESYSTEM/UsnJrnl_Records.sqlite) ---
    if want("UsnJrnl") {
        announce("UsnJrnl");
        guard!("UsnJrnl", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["$J"]));
            found(&paths);
            record_inputs(&mut report, "UsnJrnl", &paths);
            if let Some(p) = paths.first() {
                let out = cat("FILESYSTEM").join("UsnJrnl_Records.sqlite");
                let n = usnjrnl::parse_usn_stream(p, &out)?;
                record_input_count(&mut report, "UsnJrnl", p, n);
                emit(&format!("[+] {} rows -> {}", n, out.display()));
            }
        });
    }

    // --- MFT (_OVERVIEW/MFT_Records.sqlite) ---
    if want("MFT") {
        announce("MFT");
        guard!("MFT", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["$MFT"]));
            found(&paths);
            record_inputs(&mut report, "MFT", &paths);
            if let Some(p) = paths.first() {
                let out = cat("_OVERVIEW").join("MFT_Records.sqlite");
                let n = mft::parse_mft_stream(p, &out)?;
                record_input_count(&mut report, "MFT", p, n);
                emit(&format!("[+] {} rows -> {}", n, out.display()));
            } else {
                mark_artifact_no_input(&mut report, "MFT");
                emit("[*] MFT 원본이 없어 이번 실행에서 MFT 결과를 만들지 않았습니다");
            }
        });
    }

    // --- SRUM (SRUM/<stem>.sqlite, table per provider) ---
    if want("SRUM") {
        announce("SRUM");
        guard!("SRUM", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["SRUDB.dat"]));
            found(&paths);
            record_inputs(&mut report, "SRUM", &paths);
            let mut taken = HashSet::new();
            let mut source_failures = Vec::new();
            for p in &paths {
                let base = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "SRUDB".into());
                let name = uniq_name(&base, &mut taken);
                let out = cat("SRUM").join(format!("{}.sqlite", name));
                match srum::parse_srum_stream(p, &out) {
                    Ok(tables) => {
                        let record_count = tables.iter().map(|(_, count)| *count).sum();
                        record_input_count(&mut report, "SRUM", p, record_count);
                        for (t, n) in tables {
                            emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), t));
                        }
                    }
                    Err(e) => {
                        emit(&format!("[!] SRUM failed for {}: {}", p.display(), e));
                        source_failures.push(format!("{}: {}", p.display(), e));
                    }
                }
            }
            if !source_failures.is_empty() {
                anyhow::bail!(
                    "{} SRUM source(s) failed: {}",
                    source_failures.len(),
                    source_failures.join("; ")
                );
            }
        });
    }

    // --- JumpList (JUMPLIST/JumpList_Entries.sqlite) ---
    if want("JumpList") {
        announce("JumpList");
        guard!("JumpList", {
            let (sources, rows) = jumplist::parse_jumplists_with_sources(&target)?;
            record_inputs(&mut report, "JumpList", &sources);
            record_rows_by_source(&mut report, "JumpList", &rows);
            if !rows.is_empty() {
                let out = cat("JUMPLIST").join("JumpList_Entries.sqlite");
                write_table(
                    &out,
                    jumplist::JUMPLIST_TABLE,
                    &rows,
                    jumplist::JUMPLIST_FIELD_ORDER,
                )?;
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            } else {
                emit(&format!("[!] no matching files found"));
            }
        });
    }

    // --- TaskScheduler (TASKSCHEDULER/TaskScheduler_Tasks.sqlite) ---
    if want("TaskScheduler") {
        announce("TaskScheduler");
        guard!("TaskScheduler", {
            let (sources, rows) = taskscheduler::parse_tasks_with_sources(&target)?;
            record_inputs(&mut report, "TaskScheduler", &sources);
            record_rows_by_source(&mut report, "TaskScheduler", &rows);
            if !rows.is_empty() {
                let out = cat("TASKSCHEDULER").join("TaskScheduler_Tasks.sqlite");
                write_table(
                    &out,
                    taskscheduler::TASK_TABLE,
                    &rows,
                    taskscheduler::TASK_FIELD_ORDER,
                )?;
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            } else {
                emit(&format!("[!] no matching files found"));
            }
        });
    }

    // --- RdpCache (RDPCACHE/RdpBitmapCache.sqlite) ---
    if want("RdpCache") {
        announce("RdpCache");
        guard!("RdpCache", {
            let (sources, rows) = rdpcache::parse_rdpcache_with_sources(&target)?;
            record_inputs(&mut report, "RdpCache", &sources);
            record_rows_by_source(&mut report, "RdpCache", &rows);
            if !rows.is_empty() {
                let out = cat("RDPCACHE").join("RdpBitmapCache.sqlite");
                write_table(&out, rdpcache::RDP_TABLE, &rows, rdpcache::RDP_FIELD_ORDER)?;
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            } else {
                emit(&format!("[!] no matching files found"));
            }
        });
    }

    // --- WER (WER/WER_Reports.sqlite) ---
    if want("WER") {
        announce("WER");
        guard!("WER", {
            let (sources, rows) = wer::parse_wer_with_sources(&target)?;
            record_inputs(&mut report, "WER", &sources);
            record_rows_by_source(&mut report, "WER", &rows);
            if !rows.is_empty() {
                let out = cat("WER").join("WER_Reports.sqlite");
                write_table(&out, wer::WER_TABLE, &rows, wer::WER_FIELD_ORDER)?;
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            } else {
                emit(&format!("[!] no matching files found"));
            }
        });
    }

    // --- BrowserHistory (BROWSER/<account>.sqlite, table per source table) ---
    if want("BrowserHistory") {
        announce("BrowserHistory");
        guard!("BrowserHistory", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["History"]));
            found(&paths);
            record_inputs(&mut report, "BrowserHistory", &paths);
            let mut taken = HashSet::new();
            for p in &paths {
                let acct = browser_account(p);
                let name = uniq_name(&acct, &mut taken);
                let out = cat("BROWSER").join(format!("{}.sqlite", name));
                let tables = browser_history::parse_history(p)?;
                let record_count = tables.iter().map(|(_, _, rows)| rows.len()).sum();
                record_input_count(&mut report, "BrowserHistory", p, record_count);
                for (t, cols, rows) in &tables {
                    write_table_cols(&out, t, rows, cols, &[])?;
                    emit(&format!(
                        "[+] {} rows -> {} [{}]",
                        rows.len(),
                        out.display(),
                        t
                    ));
                }
            }
        });
    }

    // --- BrowserCache (BROWSER/<account>_Chrome_Cache.sqlite — shared with BrowserHistory) ---
    if want("BrowserCache") {
        announce("BrowserCache");
        guard!("BrowserCache", {
            let paths = finder::dedupe_by_content(finder::by_name(&target, &["index"]));
            found(&paths);
            record_inputs(&mut report, "BrowserCache", &paths);
            for (name, source, rows) in browser_cache::parse_caches(&paths) {
                let out = cat("BROWSER").join(format!("{}.sqlite", name));
                write_table(
                    &out,
                    browser_cache::CACHE_TABLE,
                    &rows,
                    browser_cache::CACHE_FIELD_ORDER,
                )?;
                record_input_count(&mut report, "BrowserCache", &source, rows.len());
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            }
        });
    }

    // --- Prefetch (PREFETCH/Prefetch_Execution.sqlite + Prefetch_LoadedFiles.sqlite) ---
    if want("Prefetch") {
        announce("Prefetch");
        guard!("Prefetch", {
            let paths = finder::dedupe_by_content(finder::by_extension(&target, &[".pf"]));
            found(&paths);
            record_inputs(&mut report, "Prefetch", &paths);
            if !paths.is_empty() {
                let (exec_rows, loaded_rows) = prefetch::parse_prefetch(&paths);
                record_rows_by_source(&mut report, "Prefetch", &exec_rows);
                add_rows_by_source(&mut report, "Prefetch", &loaded_rows);
                let ex = cat("PREFETCH").join(format!("{}.sqlite", prefetch::EXEC_TABLE));
                write_table(
                    &ex,
                    prefetch::EXEC_TABLE,
                    &exec_rows,
                    prefetch::EXEC_FIELD_ORDER,
                )?;
                emit(&format!("[+] {} rows -> {}", exec_rows.len(), ex.display()));
                let lf = cat("PREFETCH").join(format!("{}.sqlite", prefetch::LOADED_TABLE));
                write_table(
                    &lf,
                    prefetch::LOADED_TABLE,
                    &loaded_rows,
                    prefetch::LOADED_FIELD_ORDER,
                )?;
                emit(&format!(
                    "[+] {} rows -> {}",
                    loaded_rows.len(),
                    lf.display()
                ));
            }
        });
    }

    // --- PowerShell console history (POWERSHELL/PowerShell_ConsoleHistory.sqlite) ---
    if want("PowerShell") {
        announce("PowerShell");
        guard!("PowerShell", {
            let paths =
                finder::dedupe_by_content(finder::by_name(&target, &["ConsoleHost_history.txt"]));
            found(&paths);
            record_inputs(&mut report, "PowerShell", &paths);
            if !paths.is_empty() {
                let rows = powershell_history::parse_console_history(&paths)?;
                record_rows_by_source(&mut report, "PowerShell", &rows);
                let out =
                    cat("POWERSHELL").join(format!("{}.sqlite", powershell_history::PS_TABLE));
                write_table(
                    &out,
                    powershell_history::PS_TABLE,
                    &rows,
                    powershell_history::PS_FIELD_ORDER,
                )?;
                emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            }
        });
    }

    // Skip the correlation stage entirely if the run was cancelled.
    // Derived views are published only after every requested raw artifact
    // completed. A partial raw run may still commit its completed source DBs,
    // but must retain the prior overview rather than derive a new view from a
    // mixture of current and failed artifact data.
    if !cancelled() && !had_error {
        emit(&format!("=== _OVERVIEW ==="));
        append_current_log_lifecycle("overview_started");
        let ov = out_dir.join("_OVERVIEW");
        // TargetInfo, BAM execution history, and RegistryFindings all inspect
        // the same recovered Registry SQLite rows.  Keep one in-memory cache
        // for this overview pass only, preserving rowids/source identities.
        let registry_overview = overview::RegistryOverviewCache::load(&out_dir);
        let mut write_ov = |name: &str, rows: Vec<Row>, skip_empty: bool| -> Result<()> {
            if rows.is_empty() && skip_empty {
                return Ok(());
            }
            let out = ov.join(format!("{}.sqlite", name));
            write_table(&out, name, &rows, &[])?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            report.overview.push(OverviewTableReport {
                name: name.to_string(),
                row_count: rows.len(),
            });
            Ok(())
        };
        let overview_result = (|| -> Result<()> {
            write_ov(
                "ScheduledTasks",
                overview::build_scheduled_tasks(&out_dir),
                true,
            )?;
            write_ov("RdpCache", overview::build_rdp_cache(&out_dir), true)?;
            write_ov("Defender", overview::build_defender(&out_dir), false)?;
            write_ov(
                "RemoteDesktopHistory",
                overview::build_remote_desktop_history(&out_dir),
                false,
            )?;
            write_ov("SmbHistory", overview::build_smb_history(&out_dir), true)?;
            write_ov(
                "PowerShellHistory",
                overview::build_powershell_history(&out_dir),
                false,
            )?;
            write_ov(
                "BrowserActivity",
                overview::build_browser_history(&out_dir),
                false,
            )?;
            write_ov(
                "TargetInfo",
                overview::build_target_info_with_registry(&registry_overview),
                false,
            )?;
            write_ov(
                "ExecutionHistory",
                overview::build_execution_history_with_registry(&out_dir, &registry_overview),
                false,
            )?;
            write_ov(
                "RegistryFindings",
                overview::build_registry_findings_with_registry(&registry_overview),
                false,
            )?;
            Ok(())
        })();
        match overview_result {
            Ok(()) => append_current_log_lifecycle("overview_finished status=completed"),
            Err(error) => {
                had_error = true;
                report.errors.push(format!("_OVERVIEW: {error}"));
                emit(&format!("[!] _OVERVIEW failed: {error}"));
                append_current_log_lifecycle(&format!(
                    "overview_finished status=failed error={error}"
                ));
            }
        }
    } else if cancelled() {
        emit(&format!("=== 취소됨 — 종합 분석 건너뜀 ==="));
        append_current_log_lifecycle("overview_finished status=cancelled");
    } else {
        emit(&format!("=== 일부 아티팩트 실패 — 종합 분석 유지 ==="));
        append_current_log_lifecycle(
            "overview_finished status=skipped reason=raw_artifact_failure",
        );
    }

    let run_at = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();
    let mut status = if cancelled() {
        "cancelled"
    } else if had_error {
        "partial"
    } else {
        "ok"
    };
    report.run_at = run_at.clone();
    report.status = status.to_string();
    report.duration_ms = started.elapsed().as_millis();

    // The latest terminal lifecycle report is safe to publish even when the
    // staged evidence was rejected: it contains no derived rows and makes the
    // failure/cancel state visible without exposing half-written SQLite files.
    if status == "ok" {
        match publish_staging_output(&live_dir, &out_dir, &run_id) {
            Ok(()) => {
                record_published_outputs(&mut report, &sealed_outputs);
                report.published = !report.published_outputs.is_empty();
                append_current_log_lifecycle("staging_published status=completed");
            }
            Err(error) => {
                status = "error";
                report.status = status.to_string();
                report.errors.push(format!("publish: {error}"));
                let _ = std::fs::remove_dir_all(&out_dir);
                emit(&format!("[!] publish failed: {error}"));
                append_current_log_lifecycle(&format!("staging_publish_failed error={error}"));
            }
        }
    }
    if status == "partial" {
        let outputs: Vec<SealedArtifactOutput> = sealed_outputs
            .into_iter()
            // `_OVERVIEW` contains derived tables. The MFT raw table lives
            // there today, but it is retained from the last committed view on
            // a partial run rather than replacing the overview directory.
            .filter(|output| !output.relative.starts_with("_OVERVIEW"))
            .collect();
        if outputs.is_empty() {
            record_published_outputs(&mut report, &[]);
            append_current_log_lifecycle(
                "staging_discarded status=partial reason=no_completed_raw_outputs",
            );
        } else {
            match publish_staged_artifact_files(&live_dir, &out_dir, &run_id, &outputs) {
                Ok(()) => {
                    record_published_outputs(&mut report, &outputs);
                    report.published = !report.published_outputs.is_empty();
                    append_current_log_lifecycle(
                        "staging_published status=partial committed_raw_artifacts",
                    );
                }
                Err(error) => {
                    status = "error";
                    report.status = status.to_string();
                    report.errors.push(format!("partial_publish: {error}"));
                    emit(&format!("[!] partial publish failed: {error}"));
                    append_current_log_lifecycle(&format!(
                        "staging_partial_publish_failed error={error}"
                    ));
                }
            }
        }
    }
    if status != "ok" && status != "partial" {
        record_published_outputs(&mut report, &[]);
        let _ = std::fs::remove_dir_all(&out_dir);
        append_current_log_lifecycle(&format!("staging_discarded status={status}"));
    } else {
        let _ = std::fs::remove_dir_all(&out_dir);
    }
    // Keep a terminal lifecycle report even when the staged evidence was
    // rejected. A report-write failure is recorded but cannot skip host status
    // and persistent-log finalisation.
    if let Err(error) = write_terminal_report(&live_dir, &run_id, &report) {
        status = "error";
        report.status = status.to_string();
        append_current_log_lifecycle(&format!("terminal_report_failed error={error}"));
    }
    if let Err(error) = case_store::update_host_status(
        case_id,
        host_id,
        cases_dir,
        &run_at,
        status,
        artifacts_run,
        Some(started.elapsed().as_secs_f64()),
    ) {
        append_current_log_lifecycle(&format!("host_status_failed error={error}"));
        persistent_log.finish("error", &format!("duration_ms={}", report.duration_ms));
        return Err(error);
    }
    persistent_log.finish(status, &format!("duration_ms={}", report.duration_ms));
    if status == "error" || status == "partial" {
        anyhow::bail!("pipeline completed with failed artifacts or terminal output errors");
    }
    Ok(())
}

/// Account folder under BROWSER (…/BROWSER/<account>/CHROME/Default/History).
fn browser_account(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("BROWSER") && i + 1 < parts.len() {
            return parts[i + 1].clone();
        }
    }
    path.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "browser".into())
}

#[cfg(test)]
mod persistent_log_tests {
    use super::*;

    // These tests exercise the process-global worker log sink. The GUI runs
    // hosts in separate child processes, but unit tests share this process, so
    // serialize only this fixture to avoid cross-test log routing.
    static PIPELINE_LOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "wina-pipeline-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ))
    }

    #[test]
    fn report_serializes_temporary_registry_recovery_policy_explicitly() {
        let policy = RegistryRecoveryReport {
            mode: "disabled".to_string(),
            deleted_cell_recovery_applied: false,
            transaction_logs_applied: false,
        };
        let value = serde_json::to_value(policy).unwrap();
        assert_eq!(value["mode"], "disabled");
        assert_eq!(value["deletedCellRecoveryApplied"], false);
        assert_eq!(value["transactionLogsApplied"], false);
    }

    #[test]
    fn run_log_is_append_only_and_marks_unfinished_runs() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("log-test");
        std::fs::create_dir_all(&root).unwrap();
        let run_id = "20260823_010203_004_00001";
        let path = parse_run_log_path(&root, run_id);
        {
            let _run = PersistentRunLog::begin(&root, run_id, "case-a", "host-a", None);
            append_current_log_lifecycle("artifact_started name=Registry");
        }
        append_parse_log_event(
            &path,
            "[SUPERVISOR] termination status=forced reason=gui_cancel",
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("run_started case=case-a host=host-a scope=all"));
        assert!(text.contains("artifact_started name=Registry"));
        assert!(text.contains("run_interrupted reason=no_terminal_record"));
        assert!(text.contains("termination status=forced reason=gui_cancel"));
        assert!(text
            .lines()
            .all(|line| line.len() >= 23 && line.as_bytes().get(4) == Some(&b'-')));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn staged_output_is_invisible_until_publish_and_failure_discard_keeps_live_data() {
        let root = temporary_directory("staging");
        let live = root.join("host");
        let registry = live.join("REGISTRY");
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(registry.join("Registry.sqlite"), b"published-before").unwrap();
        let mut only = HashSet::new();
        only.insert("Registry".to_string());

        let failed_stage = prepare_staging_output(&live, "failed-run", Some(&only)).unwrap();
        std::fs::write(
            failed_stage.join("REGISTRY/Registry.sqlite"),
            b"partial-new",
        )
        .unwrap();
        std::fs::remove_dir_all(&failed_stage).unwrap();
        assert_eq!(
            std::fs::read(registry.join("Registry.sqlite")).unwrap(),
            b"published-before"
        );

        let success_stage = prepare_staging_output(&live, "success-run", Some(&only)).unwrap();
        std::fs::write(
            success_stage.join("REGISTRY/Registry.sqlite"),
            b"published-after",
        )
        .unwrap();
        publish_staging_output(&live, &success_stage, "success-run").unwrap();
        assert_eq!(
            std::fs::read(registry.join("Registry.sqlite")).unwrap(),
            b"published-after"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn partial_publish_uses_sealed_success_outputs_and_keeps_prior_overview() {
        let root = temporary_directory("partial-publish");
        let live = root.join("host");
        std::fs::create_dir_all(live.join("_OVERVIEW")).unwrap();
        std::fs::write(live.join("_OVERVIEW/MFT_Records.sqlite"), b"prior-overview").unwrap();

        let stage = prepare_staging_output(&live, "partial-run", None).unwrap();
        std::fs::create_dir_all(stage.join("REGISTRY")).unwrap();
        std::fs::create_dir_all(stage.join("_OVERVIEW")).unwrap();
        std::fs::write(
            stage.join("REGISTRY/Registry.sqlite"),
            b"successful-registry",
        )
        .unwrap();
        let registry_outputs = vec!["REGISTRY/Registry.sqlite".to_string()];
        let sealed = seal_artifact_outputs(&stage, "Registry", &registry_outputs).unwrap();

        // A failed later artifact can still leave a partial stage file, but it
        // has no seal and therefore cannot be published with Registry.
        std::fs::write(stage.join("_OVERVIEW/MFT_Records.sqlite"), b"partial-mft").unwrap();
        publish_staged_artifact_files(&live, &stage, "partial-run", &sealed).unwrap();

        assert_eq!(
            std::fs::read(live.join("REGISTRY/Registry.sqlite")).unwrap(),
            b"successful-registry"
        );
        assert_eq!(
            std::fs::read(live.join("_OVERVIEW/MFT_Records.sqlite")).unwrap(),
            b"prior-overview"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn partial_publish_does_not_leak_later_failed_shared_browser_write() {
        let root = temporary_directory("sealed-browser");
        let live = root.join("host");
        let stage = prepare_staging_output(&live, "browser-partial", None).unwrap();
        std::fs::create_dir_all(stage.join("BROWSER")).unwrap();
        let database = stage.join("BROWSER/analyst.sqlite");
        std::fs::write(&database, b"history-complete").unwrap();
        let outputs = vec!["BROWSER/analyst.sqlite".to_string()];
        let sealed_history = seal_artifact_outputs(&stage, "BrowserHistory", &outputs).unwrap();

        // BrowserCache uses the same SQLite file.  If it fails after writing,
        // its stage file must not alter BrowserHistory's already sealed copy.
        std::fs::write(&database, b"cache-partial").unwrap();
        publish_staged_artifact_files(&live, &stage, "browser-partial", &sealed_history).unwrap();
        assert_eq!(
            std::fs::read(live.join("BROWSER/analyst.sqlite")).unwrap(),
            b"history-complete"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn panic_details_retains_payload_and_bounds_backtrace() {
        let detail = panic_details(Box::new("malformed MFT record"));
        assert!(detail.contains("malformed MFT record"));
        assert!(detail.len() <= 4_000);
    }

    #[test]
    fn report_distinguishes_completed_staging_from_actual_publication_and_mft_no_input() {
        let mut report = ParseReport {
            run_id: "publication-state".to_string(),
            run_at: String::new(),
            status: "partial".to_string(),
            duration_ms: 0,
            published: false,
            errors: Vec::new(),
            registry_hives: Vec::new(),
            registry_recovery: None,
            completed_artifacts: vec!["Registry".to_string(), "MFT".to_string()],
            published_artifacts: Vec::new(),
            published_outputs: Vec::new(),
            artifacts: vec![
                ParseArtifactReport {
                    name: "Registry".to_string(),
                    status: "completed".to_string(),
                    input_discovery_checked: true,
                    evidence_discovered: true,
                    outputs: vec!["REGISTRY/Registry.sqlite".to_string()],
                    published_outputs: Vec::new(),
                    publication_status: None,
                    error: None,
                    inputs: Vec::new(),
                },
                ParseArtifactReport {
                    name: "MFT".to_string(),
                    status: "completed".to_string(),
                    input_discovery_checked: false,
                    evidence_discovered: false,
                    outputs: vec!["_OVERVIEW/MFT_Records.sqlite".to_string()],
                    published_outputs: Vec::new(),
                    publication_status: None,
                    error: None,
                    inputs: Vec::new(),
                },
            ],
            overview: Vec::new(),
        };
        let sealed = vec![SealedArtifactOutput {
            artifact: "Registry".to_string(),
            relative: PathBuf::from("REGISTRY/Registry.sqlite"),
        }];
        record_published_outputs(&mut report, &sealed);
        assert_eq!(
            report.completed_artifacts,
            vec!["Registry".to_string(), "MFT".to_string()]
        );
        assert_eq!(report.published_artifacts, vec!["Registry".to_string()]);
        assert_eq!(
            report.artifacts[0].publication_status.as_deref(),
            Some("published")
        );
        assert_eq!(
            report.artifacts[1].publication_status.as_deref(),
            Some("withheld")
        );

        mark_artifact_no_input(&mut report, "MFT");
        assert_eq!(report.artifacts[1].status, "no_input");
        assert_eq!(
            report.artifacts[1].publication_status.as_deref(),
            Some("not_published")
        );
    }

    #[test]
    fn artifact_without_discovered_evidence_or_output_is_no_input() {
        let empty = ParseArtifactReport {
            name: "Prefetch".to_string(),
            status: "running".to_string(),
            input_discovery_checked: true,
            evidence_discovered: false,
            outputs: Vec::new(),
            published_outputs: Vec::new(),
            publication_status: None,
            error: None,
            inputs: Vec::new(),
        };
        assert!(artifact_has_no_input(&empty, &[]));

        let with_input = ParseArtifactReport {
            evidence_discovered: true,
            inputs: vec![ParseInputReport {
                name: "Layout.ini".to_string(),
                source_path: "/evidence/Layout.ini".to_string(),
                record_count: 0,
                recovery_log: false,
            }],
            ..empty
        };
        assert!(!artifact_has_no_input(&with_input, &[]));
        assert!(!artifact_has_no_input(
            &with_input,
            &["PREFETCH/Prefetch.sqlite".to_string()]
        ));

        let untracked_zero_result = ParseArtifactReport {
            input_discovery_checked: false,
            evidence_discovered: false,
            inputs: Vec::new(),
            ..with_input
        };
        assert!(
            !artifact_has_no_input(&untracked_zero_result, &[]),
            "a parser without explicit source discovery must not relabel a zero-row result as no_input"
        );
    }

    #[test]
    fn discovered_zero_row_source_is_not_no_input() {
        let mut report = ParseReport {
            run_id: "zero-rows".to_string(),
            run_at: String::new(),
            status: "running".to_string(),
            duration_ms: 0,
            published: false,
            errors: Vec::new(),
            registry_hives: Vec::new(),
            registry_recovery: None,
            completed_artifacts: Vec::new(),
            published_artifacts: Vec::new(),
            published_outputs: Vec::new(),
            artifacts: vec![ParseArtifactReport {
                name: "BrowserCache".to_string(),
                status: "running".to_string(),
                input_discovery_checked: false,
                evidence_discovered: false,
                outputs: Vec::new(),
                published_outputs: Vec::new(),
                publication_status: None,
                error: None,
                inputs: Vec::new(),
            }],
            overview: Vec::new(),
        };
        record_inputs(
            &mut report,
            "BrowserCache",
            &[PathBuf::from("/evidence/Cache/index")],
        );
        let artifact = &report.artifacts[0];
        assert!(artifact.input_discovery_checked);
        assert!(artifact.evidence_discovered);
        assert!(
            !artifact_has_no_input(artifact, &[]),
            "an existing cache index may yield zero recoverable records but is still an input"
        );
    }

    #[test]
    fn empty_selected_artifact_persists_no_input_in_terminal_report() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("no-input");
        let cases_dir = root.join("cases");
        let target_dir = root.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        let case = case_store::create_case("case", "2026-08-23 01:02:03", &cases_dir).unwrap();
        let host = case_store::create_host(
            &case.id,
            "host",
            &target_dir.to_string_lossy(),
            "2026-08-23 01:02:03",
            &cases_dir,
        )
        .unwrap();
        let mut only = HashSet::new();
        only.insert("Prefetch".to_string());

        run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some("no-input")).unwrap();

        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        let prefetch = report["artifacts"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["name"] == "Prefetch"))
            .expect("Prefetch artifact report");
        assert_eq!(prefetch["status"], "no_input");
        assert_eq!(prefetch["inputDiscoveryChecked"], true);
        assert_eq!(prefetch["evidenceDiscovered"], false);
        assert_eq!(prefetch["publicationStatus"], "not_published");
        assert!(report["completedArtifacts"]
            .as_array()
            .is_none_or(|entries| !entries.iter().any(|entry| entry == "Prefetch")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn registry_and_srum_source_failures_mark_report_host_and_log_as_partial() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("source-errors");
        let cases_dir = root.join("cases");
        let target_dir = root.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        // The filename makes it a Registry candidate; the content is not a
        // hive, exercising a per-source parse error without aborting the run.
        std::fs::write(target_dir.join("SOFTWARE"), b"not a registry hive").unwrap();
        std::fs::write(target_dir.join("SRUDB.dat"), b"not an ESE database").unwrap();
        let case = case_store::create_case("case", "2026-08-23 01:02:03", &cases_dir).unwrap();
        let host = case_store::create_host(
            &case.id,
            "host",
            &target_dir.to_string_lossy(),
            "2026-08-23 01:02:03",
            &cases_dir,
        )
        .unwrap();
        let mut only = HashSet::new();
        only.insert("Registry".to_string());
        only.insert("SRUM".to_string());
        let run_id = "source-errors";

        let result = run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some(run_id));
        assert!(
            result.is_err(),
            "failed artifacts must produce a nonzero worker exit"
        );

        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        let artifacts = report["artifacts"].as_array().expect("artifact report");
        for artifact in ["Registry", "SRUM"] {
            assert!(
                artifacts
                    .iter()
                    .any(|entry| { entry["name"] == artifact && entry["status"] == "failed" }),
                "{artifact} source failure must make the artifact fail"
            );
        }
        assert!(report["registryHives"]
            .as_array()
            .is_some_and(|hives| hives.iter().any(|hive| hive["status"] == "failed")));
        assert_eq!(
            case_store::load_host(&case.id, &host.id, &cases_dir)
                .unwrap()
                .last_run_status
                .as_deref(),
            Some("partial")
        );
        assert_eq!(report["status"], "partial");
        assert_eq!(report["published"], false);
        let log = std::fs::read_to_string(parse_run_log_path(&host_dir, run_id)).unwrap();
        assert!(log.contains("artifact_finished name=Registry status=failed"));
        assert!(log.contains("artifact_finished name=SRUM status=failed"));
        assert!(log.contains("run_finished status=partial"));
        let _ = std::fs::remove_dir_all(root);
    }
}
