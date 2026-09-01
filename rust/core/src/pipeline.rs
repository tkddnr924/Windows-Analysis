//! Parse-stage orchestration, mirroring main.py run_host: locate each
//! artifact's files under the target, parse, and write per-source SQLite into
//! CATEGORY/<name>.sqlite. Streaming parsers write directly; smaller ones use
//! write_table. Overview builders are a separate (later) stage.
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::case_store::{self};
use crate::finder;
use crate::overview;
use crate::parsers::{
    amcache, browser_cache, browser_history, eventlog, ie_indexdat, ie_webcache, jumplist, mft,
    powershell_history, prefetch, rdpcache, registry, srum, taskscheduler, timeline, usnjrnl,
    wer, wmi_repository,
};
use crate::sqlite::{write_table, Row};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

// Global progress sink (Send). When set (by the GUI), progress lines route here
// instead of stdout; unset (CLI) prints to stdout. Global + Send so worker
// threads (parallel registry parsing) reach the same sink.
pub type LogSink = Box<dyn FnMut(&str) + Send>;
static LOG_SINK: Mutex<Option<LogSink>> = Mutex::new(None);

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
            "BrowserHistory" | "BrowserCache" | "IEWebCache" | "IEIndexDat" => {
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
            "WmiRepository" => {
                categories.insert("WMI");
            }
            "Timeline" => {
                categories.insert("TIMELINE");
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
/// 재파싱은 이전 결과를 보존하지 않는다(사용자 확정, 2026-08-30). 호스트의
/// 수집 데이터는 불변이므로 실패한 파싱은 다시 해도 실패한다 — 이전 실행
/// 결과를 남기면 서로 다른 시점의 facts와 _OVERVIEW가 섞여 화면 간 모순이
/// 생긴다. 전체 실행은 모든 결과 카테고리를, 범위 실행은 해당 아티팩트의
/// 카테고리(+항상 재생성되는 _OVERVIEW)만 지우고 이번 실행 산출물만 발행한다.
/// 취소된 실행은 발행 단계에 오지 않으므로 이전 결과가 유지된다.
fn clear_previous_results(live_dir: &Path, only: Option<&HashSet<String>>) -> Result<()> {
    let scoped = only.map(|only| artifact_output_categories(Some(only)));
    for entry in std::fs::read_dir(live_dir)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if name == PARSE_LOG_DIRECTORY
            || name == PARSE_STAGING_DIRECTORY
            || name == PARSE_COMMITTED_DIRECTORY
        {
            continue;
        }
        if let Some(scoped) = &scoped {
            if !scoped.contains(name.as_str()) {
                continue;
            }
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    // 통합 타임라인 캐시는 매 실행 재생성된다 — 지운 facts와 어긋난 이전
    // 캐시가 남지 않게 함께 제거한다.
    let _ = std::fs::remove_file(live_dir.join("_master_timeline.cache.json"));
    Ok(())
}

/// `_OVERVIEW` 안에 파서가 직접 기록하는 원본(raw) 산출물. write_ov 파생이
/// 아니므로 파생 리셋에서 지우면 안 된다 — status=="ok" 발행은 seal본
/// (`.artifact-committed`)을 건너뛰고 스테이징 트리를 그대로 발행하므로,
/// 여기서 지워진 파일은 어디서도 복구되지 않은 채 보고서에만 published로
/// 남는다(전체 실행에서 파일 시스템 뷰가 비는 실제 사고 원인).
const OVERVIEW_PARSER_OUTPUTS: &[&str] = &["MFT_Records.sqlite"];

/// 범위 재파싱 스테이지에는 이전 실행의 _OVERVIEW 복사본이 들어 있다.
/// 파생 생성 직전에 비워, 발행되는 파생은 항상 이번 실행 facts에서 만든
/// 것만 남긴다 (facts/derived 동일 시점 보장). 모든 write_ov 파생은 0건에도
/// 스키마와 함께 다시 쓰이므로 리셋 후 빈자리가 남지 않는다.
/// 단 파서 원본 산출물(OVERVIEW_PARSER_OUTPUTS)은 보존한다: 전체 실행에서는
/// 이번 실행 파서가 방금 쓴 파일이고, 범위 재파싱에서는 스테이지 준비가
/// 복사해 온 마지막 발행본이라 어느 쪽이든 facts와 같은 시점이다.
fn reset_stage_overview(ov: &Path) -> Result<()> {
    if ov.exists() {
        for entry in std::fs::read_dir(ov)? {
            let entry = entry?;
            let name = entry.file_name();
            if OVERVIEW_PARSER_OUTPUTS
                .iter()
                .any(|keep| name.to_string_lossy() == *keep)
            {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
    }
    std::fs::create_dir_all(ov)?;
    Ok(())
}

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    amcache_hives: Vec<AmcacheHiveReport>,
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
    /// 발견된 트랜잭션 로그를 적용하지 못해 기본 하이브만으로 폴백한 사유.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_log_apply_error: Option<String>,
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

/// Amcache 하이브별 트랜잭션 로그 처리 실적 — 실행이 끝난 뒤에도 결과가 로그
/// 정합본인지, 손상 로그 때문에 기본 하이브만으로 폴백한 것인지 구분할 수
/// 있게 parse_report.json에 남는다 (Registry의 registry_hives와 동형 목적).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AmcacheHiveReport {
    source_path: String,
    /// registry_hives와 같은 어휘 — "completed" 또는 "skipped_corrupted".
    /// 건너뛴 손상 하이브도 여기 남아야 0건 결과와 구분된다.
    status: String,
    logs_discovered: usize,
    logs_applied: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_apply_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
    /// 탐색(디렉터리 순회·내용 판별) 중 만난 접근·읽기 실패 — 발견 0건이
    /// 실제 무증거인지 접근 불가였는지 구분하는 근거.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    discovery_errors: Vec<String>,
    inputs: Vec<ParseInputReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseInputReport {
    name: String,
    source_path: String,
    record_count: usize,
    recovery_log: bool,
    /// 이 원본 파일을 읽거나 해석하지 못한 사유 — 0건 성공과 구분된다.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
pub fn set_log_sink(sink: Option<LogSink>) {
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
    "IEWebCache",
    "IEIndexDat",
    "PowerShell",
    "Prefetch",
    "WER",
    "WmiRepository",
    "Timeline",
];

/// A parser section with neither discovered evidence nor staged output is not
/// a successful empty parse.  Treat it consistently as an evidence-missing
/// state so the report/UI never says "completed" for an artifact that was
/// never able to run.
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

fn entry_record_input(entry: &mut ParseArtifactReport, path: &Path, recovery_log: bool) {
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
        error: None,
    });
}

/// 개별 원본 파일의 읽기·해석 실패 사유를 입력 항목에 남긴다 — 실패한
/// 파일이 "0건 성공"으로 보이지 않게 한다.
fn entry_record_input_error(entry: &mut ParseArtifactReport, path: &Path, reason: &str) {
    entry_record_input(entry, path, false);
    let source_path = path.to_string_lossy();
    if let Some(input) = entry
        .inputs
        .iter_mut()
        .find(|input| input.source_path == source_path.as_ref())
    {
        input.error = Some(reason.to_string());
    }
}

fn entry_record_inputs(entry: &mut ParseArtifactReport, paths: &[PathBuf]) {
    entry.input_discovery_checked = true;
    entry.evidence_discovered |= !paths.is_empty();
    for path in paths {
        entry_record_input(entry, path, false);
    }
}

fn entry_record_input_count(entry: &mut ParseArtifactReport, path: &Path, record_count: usize) {
    entry_record_input(entry, path, false);
    let source_path = path.to_string_lossy();
    if let Some(input) = entry
        .inputs
        .iter_mut()
        .find(|input| input.source_path == source_path.as_ref())
    {
        input.record_count = record_count;
    }
}

fn entry_record_rows_by_source(entry: &mut ParseArtifactReport, rows: &[Row]) {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for row in rows {
        if let Some(source) = row.get("_source_file").filter(|source| !source.is_empty()) {
            *counts.entry(source.clone()).or_default() += 1;
        }
    }
    for (source, count) in counts {
        entry_record_input_count(entry, Path::new(&source), count);
    }
}

/// 이미 기록된 입력의 레코드 수에 추가분을 더한다 (없으면 입력을 만들고 더함).
fn entry_add_input_count(entry: &mut ParseArtifactReport, source: &Path, count: usize) {
    entry_record_input(entry, source, false);
    let source = source.to_string_lossy().to_string();
    if let Some(input) = entry
        .inputs
        .iter_mut()
        .find(|input| input.source_path == source)
    {
        input.record_count = input.record_count.saturating_add(count);
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

/// One artifact's parse result: its report entry, sealed outputs, and (for
/// Registry) the per-hive extras. Each parallel worker fills exactly one of
/// these, so the shared `ParseReport` is only touched by the merge step.
struct ArtifactOutcome {
    entry: ParseArtifactReport,
    sealed: Vec<SealedArtifactOutput>,
    errors: Vec<String>,
    registry_hives: Vec<RegistryHiveReport>,
    amcache_hives: Vec<AmcacheHiveReport>,
    registry_recovery: Option<RegistryRecoveryReport>,
}

impl ArtifactOutcome {
    fn new(name: &str) -> Self {
        Self {
            entry: ParseArtifactReport {
                name: name.to_string(),
                status: "running".to_string(),
                input_discovery_checked: false,
                evidence_discovered: false,
                outputs: Vec::new(),
                published_outputs: Vec::new(),
                publication_status: None,
                error: None,
                discovery_errors: Vec::new(),
                inputs: Vec::new(),
            },
            sealed: Vec::new(),
            errors: Vec::new(),
            registry_hives: Vec::new(),
            amcache_hives: Vec::new(),
            registry_recovery: None,
        }
    }
}

/// Locate one artifact's evidence files under the target (path/content rules
/// unchanged from the sequential pipeline). 탐색 중 만난 접근·순회 실패도
/// 함께 반환된다 — 파이프라인이 아티팩트 보고서에 기록해 "발견 0건"과
/// 구분한다. RegBack 하이브도 별도 증거로 계획에 포함한다(출력명·파생 입력
/// 구분은 파싱/파생 단계 몫 — 2026-08-31 사용자 확정).
fn discover_artifact_files(name: &str, target: &Path) -> finder::Found {
    match name {
        "Amcache" => finder::by_name(target, &["Amcache.hve"]),
        "EventLog" => {
            let mut all = finder::by_name(target, eventlog::ALLOWLIST);
            // XP/2003 구형 .evt(SecEvent/SysEvent/AppEvent)도 같은 아티팩트로.
            let evt = finder::by_name(target, eventlog::EVT_ALLOWLIST);
            all.paths.extend(evt.paths);
            all.errors.extend(evt.errors);
            all
        }
        "Registry" => {
            let mut all = finder::by_name(target, registry::REG_FILENAMES);
            let suffixed = finder::by_suffix(target, registry::REG_SUFFIXES);
            all.paths.extend(suffixed.paths);
            all.errors.extend(suffixed.errors);
            all
        }
        "UsnJrnl" => finder::by_name(target, &["$J"]),
        "MFT" => finder::by_name(target, &["$MFT"]),
        "SRUM" => finder::by_name(target, &["SRUDB.dat"]),
        "JumpList" => jumplist::jumplist_sources(target),
        "TaskScheduler" => taskscheduler::task_sources(target),
        "RdpCache" => rdpcache::rdpcache_sources(target),
        "BrowserHistory" => finder::by_name(target, &["History"]),
        "BrowserCache" => finder::by_name(target, &["index"]),
        // WebCacheV##.dat — 버전 숫자는 빌드에 따라 다르다(01이 일반적).
        "IEWebCache" => finder::by_name(
            target,
            &[
                "WebCacheV01.dat",
                "WebCacheV02.dat",
                "WebCacheV16.dat",
                "WebCacheV24.dat",
            ],
        ),
        // 파일명만으로는 오탐 가능 — 매직("Client UrlCache MMF") 검사는 파서가 한다.
        "IEIndexDat" => finder::by_name(target, &["index.dat"]),
        "PowerShell" => finder::by_name(target, &["ConsoleHost_history.txt"]),
        "Prefetch" => finder::by_extension(target, &[".pf"]),
        "WER" => wer::wer_sources(target),
        "WmiRepository" => wmi_repository::wmi_sources(target),
        "Timeline" => timeline::timeline_sources(target),
        _ => finder::Found::default(),
    }
}

/// 디스크 부족·I/O 실패 같은 저장 환경 오류인지 판별한다. 이런 오류는 데이터
/// 손상이 아니므로 건너뛰지 않고 아티팩트 실패(partial)로 올린다.
/// 실행 환경(저장 공간·권한·장치 I/O) 문제인지 판별한다. 환경 오류는 증거
/// 손상이 아니므로 "손상 아티팩트 건너뜀"이 아니라 아티팩트 실패(partial)로
/// 올라가야 한다 — 권한 거부로 못 읽은 원본이 "손상된 하이브"로 표시되면
/// 분석가가 증거 상태를 오판한다. 포맷 해석 실패만 손상으로 남긴다.
fn is_storage_error(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind;
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            // ENOSPC — 저장 공간 부족.
            if io.raw_os_error() == Some(28) {
                return true;
            }
            if matches!(
                io.kind(),
                ErrorKind::PermissionDenied
                    | ErrorKind::Interrupted
                    | ErrorKind::TimedOut
                    | ErrorKind::WouldBlock
                    | ErrorKind::NotConnected
            ) {
                return true;
            }
        }
        if let Some(rusqlite::Error::SqliteFailure(failure, _)) =
            cause.downcast_ref::<rusqlite::Error>()
        {
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::SystemIoFailure
            ) {
                return true;
            }
        }
    }
    false
}

/// 파서가 잘 짜여 있다는 전제 하에, 파싱·저장 실패는 데이터 손상으로 판단하고
/// 해당 출력만 정리한 뒤 다음 단계로 넘어간다(Ok(None)). 유일한 예외는 저장
/// 환경 오류(디스크 부족 등) — 이는 손상이 아니므로 Err로 올려 아티팩트를
/// 실패(partial)로 처리한다. 실패·건너뜀 단위의 반쯤 쓰인 파일은 즉시
/// 삭제되어 발행될 수 없다.
fn run_unit_or_skip<T>(
    label: &str,
    outputs_to_clean: &[&Path],
    unit: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(unit));
    match result {
        Ok(Ok(value)) => Ok(Some(value)),
        Ok(Err(error)) => {
            for output in outputs_to_clean {
                let _ = std::fs::remove_file(output);
            }
            if is_storage_error(&error) {
                return Err(error);
            }
            emit(&format!("[*] 손상된 데이터 건너뜀: {} ({})", label, error));
            Ok(None)
        }
        Err(_) => {
            for output in outputs_to_clean {
                let _ = std::fs::remove_file(output);
            }
            emit(&format!("[*] 손상된 데이터 건너뜀: {}", label));
            Ok(None)
        }
    }
}

fn parse_amcache_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    entry_record_inputs(&mut outcome.entry, paths);
    // 하이브별 트랜잭션 로그 목록은 여기서 한 번만 확정한다(파싱 계획 고정) —
    // 입력 기록·logsDiscovered·실제 파서 입력이 전부 같은 스냅샷을 쓰므로,
    // 목록화 이후 디렉터리가 변해도 보고서와 실제 적용 로그가 어긋나지 않는다.
    let planned: Vec<(&PathBuf, Vec<PathBuf>)> = paths
        .iter()
        .map(|p| (p, registry::sibling_logs(p)))
        .collect();
    for (_, logs) in &planned {
        for log in logs {
            entry_record_input(&mut outcome.entry, log, true);
        }
    }
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // 하이브 하나가 손상돼도 그 하이브만 건너뛴다(파싱 실패 == 손상 아티팩트).
    for (p, logs) in &planned {
        let p = *p;
        let base = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Amcache".into());
        let name = uniq_name(&base, &mut taken);
        let relative = format!("AMCACHE/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let logs_discovered = logs.len();
        // 하이브 자체가 열리지 않는 손상은 사유를 보고서까지 가져가야 하므로
        // run_unit_or_skip이 삼키기 전에 클로저 안에서 가로챈다 — 저장 환경
        // 오류(디스크 부족 등)만 종전대로 Err로 올려 아티팩트를 partial 처리.
        enum AmcacheUnit {
            Parsed {
                programs: usize,
                files: usize,
                log_apply_error: Option<String>,
            },
            Skipped(String),
        }
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<AmcacheUnit> {
            let parsed = match amcache::parse_amcache(p, logs) {
                Ok(parsed) => parsed,
                Err(error) => {
                    if is_storage_error(&error) {
                        return Err(error);
                    }
                    return Ok(AmcacheUnit::Skipped(error.to_string()));
                }
            };
            write_table(
                &out,
                amcache::PROGRAMS_TABLE,
                &parsed.programs,
                amcache::PROGRAMS_FIELD_ORDER,
            )?;
            write_table(
                &out,
                amcache::FILES_TABLE,
                &parsed.files,
                amcache::FILES_FIELD_ORDER,
            )?;
            Ok(AmcacheUnit::Parsed {
                programs: parsed.programs.len(),
                files: parsed.files.len(),
                log_apply_error: parsed.log_apply_error,
            })
        })?;
        match unit {
            Some(AmcacheUnit::Parsed {
                programs: prog_count,
                files: file_count,
                log_apply_error,
            }) => {
                entry_record_input_count(&mut outcome.entry, p, prog_count + file_count);
                if let Some(reason) = &log_apply_error {
                    emit(&format!(
                        "[*] Amcache 로그 적용 실패 — 기본 하이브만 파싱: {} ({})",
                        p.display(),
                        reason
                    ));
                }
                // 폴백 여부는 실행 로그가 아니라 영구 보고서에 남아야, 실행이
                // 끝난 뒤에도 이 결과가 로그 정합본인지 구분할 수 있다.
                outcome.amcache_hives.push(AmcacheHiveReport {
                    source_path: p.to_string_lossy().to_string(),
                    status: "completed".to_string(),
                    logs_discovered,
                    logs_applied: if log_apply_error.is_none() {
                        logs_discovered
                    } else {
                        0
                    },
                    log_apply_error,
                    error: None,
                });
                emit(&format!(
                    "[+] {} programs, {} files -> {}",
                    prog_count,
                    file_count,
                    out.display()
                ));
                outputs.push(relative);
            }
            Some(AmcacheUnit::Skipped(reason)) => {
                emit(&format!(
                    "[*] 손상된 Amcache 하이브 건너뜀: {} ({})",
                    p.display(),
                    reason
                ));
                outcome.amcache_hives.push(AmcacheHiveReport {
                    source_path: p.to_string_lossy().to_string(),
                    status: "skipped_corrupted".to_string(),
                    logs_discovered,
                    logs_applied: 0,
                    log_apply_error: None,
                    error: Some(reason),
                });
            }
            // run_unit_or_skip이 삼킨 잔여 경로(패닉, 손상성 저장 오류) —
            // 사유 원문은 없지만 건너뛴 사실 자체는 보고서에 남긴다.
            None => {
                outcome.amcache_hives.push(AmcacheHiveReport {
                    source_path: p.to_string_lossy().to_string(),
                    status: "skipped_corrupted".to_string(),
                    logs_discovered,
                    logs_applied: 0,
                    log_apply_error: None,
                    error: Some("파싱이 중단됨 — 실행 로그 참조".to_string()),
                });
            }
        }
    }
    Ok(outputs)
}

fn parse_eventlog_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // 손상된 레코드는 파서가 corrupted_chunk 행으로 격리한다. 파일 자체가
    // 열리지 않는 로그는 그 파일만 건너뛰어, 나머지 로그의 저장 완료분이
    // 함께 폐기되지 않게 한다(파싱 실패 == 손상 아티팩트).
    for p in paths {
        let base = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "EventLog".into());
        let name = uniq_name(&base, &mut taken);
        let relative = format!("EVENTLOG/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let is_evt = p
            .extension()
            .map(|e| e.to_string_lossy().eq_ignore_ascii_case("evt"))
            .unwrap_or(false);
        if let Some(n) = run_unit_or_skip(&p.display().to_string(), &[&out], || {
            if is_evt {
                eventlog::parse_evt_stream(p, &out, &name)
            } else {
                eventlog::parse_evtx_stream(p, &out, &name)
            }
        })? {
            entry_record_input_count(entry, p, n);
            if n > 0 {
                emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), name));
            }
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_registry_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    entry_record_inputs(&mut outcome.entry, paths);
    // 트랜잭션 로그는 항상 조합해 최신 정합 상태를 파싱한다. 삭제 셀 복구는
    // 비용이 커서 임시로 끈 상태 — 보고서에 그대로 드러낸다.
    if registry::registry_recovery_disabled() {
        outcome.registry_recovery = Some(RegistryRecoveryReport {
            mode: "transaction_logs_only".to_string(),
            deleted_cell_recovery_applied: false,
            transaction_logs_applied: true,
        });
        emit("[*] 레지스트리: 트랜잭션 로그(.LOG1/.LOG2) 조합 적용 · 삭제 셀 복구는 수행하지 않음");
    } else {
        outcome.registry_recovery = Some(RegistryRecoveryReport {
            mode: "enabled".to_string(),
            deleted_cell_recovery_applied: true,
            transaction_logs_applied: true,
        });
    }
    // Assign each hive a unique output name, then parse hives in parallel.
    // Every worker writes its own SQLite output, so normal allocated-record
    // parsing remains isolated in live-only mode.
    //
    // RegBack 하이브도 별도 증거로 파싱하되 출력명에 `_RegBack`을 붙인다 —
    // facts에는 보존되고, 파생(_OVERVIEW) 단계는 이 접미로 라이브 하이브만
    // 입력으로 삼아 오래된 값의 이중 표시를 막는다 (2026-08-31 사용자 확정).
    //
    // 하이브별 트랜잭션 로그 목록은 여기서 한 번만 확정한다(파싱 계획 고정) —
    // 입력 기록·logsDiscovered·실제 파서 입력이 같은 스냅샷을 쓴다 (Amcache와
    // 동일). 각 로그는 복구 로그 입력으로 보고서에 남는다.
    let mut taken = HashSet::new();
    let mut jobs: Vec<(PathBuf, Vec<PathBuf>, PathBuf, String)> = Vec::new();
    for p in paths {
        let mut base = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "hive".into());
        let is_regback = p.components().any(|c| {
            c.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case("regback")
        });
        if is_regback {
            base = format!("{base}_RegBack");
        }
        let name = uniq_name(&base, &mut taken);
        let relative = format!("REGISTRY/{}.sqlite", name);
        let logs = registry::sibling_logs(p);
        for log in &logs {
            entry_record_input(&mut outcome.entry, log, true);
        }
        jobs.push((p.clone(), logs, out_dir.join(&relative), relative));
    }
    // Keep Registry hive work bounded at two workers. If temporary recovery is
    // later re-enabled, the parser's process-wide permits continue to cap the
    // expensive builder/recovery stage as well.
    let workers = registry::registry_recovery_worker_count(jobs.len());
    let next = AtomicUsize::new(0);
    let parsed_counts = Mutex::new(Vec::<(PathBuf, String, registry::HiveParseMetrics)>::with_capacity(jobs.len()));
    // (설명, 저장 환경 오류 여부) — 손상 하이브는 건너뛰고, 디스크 부족 같은
    // 저장 오류만 아티팩트 실패로 올린다.
    let source_failures = Mutex::new(Vec::<(String, bool)>::new());
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
                let (src, logs, out, relative) = &jobs[i];
                if CANCEL.load(Ordering::Relaxed) {
                    break;
                }
                match registry::parse_hive_stream_with_metrics(src, logs, out) {
                    Ok(metrics) => {
                        if let Ok(mut counts) = parsed_counts.lock() {
                            counts.push((src.clone(), relative.clone(), metrics.clone()));
                        }
                        emit(&format!(
                            "[+] {} rows -> {} [Registry]",
                            metrics.row_count,
                            out.display()
                        ));
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(out);
                        let storage = is_storage_error(&e);
                        if !storage {
                            emit(&format!("[*] 손상된 하이브 건너뜀: {} ({})", src.display(), e));
                        }
                        if let Ok(mut failures) = source_failures.lock() {
                            failures.push((format!("{}: {}", src.display(), e), storage));
                        }
                    }
                }
            });
        }
    });
    let mut outputs = Vec::new();
    let mut any_logs_applied = false;
    let mut any_log_apply_failed = false;
    if let Ok(counts) = parsed_counts.into_inner() {
        for (source, relative, metrics) in counts {
            entry_record_input_count(&mut outcome.entry, &source, metrics.row_count);
            any_logs_applied |= metrics.recovery_log_count > 0;
            if let Some(reason) = &metrics.recovery_log_apply_error {
                any_log_apply_failed = true;
                emit(&format!(
                    "[*] 레지스트리 로그 적용 실패 — 기본 하이브만 파싱: {} ({})",
                    source.display(),
                    reason
                ));
            }
            outcome.registry_hives.push(RegistryHiveReport {
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
                recovery_log_apply_error: metrics.recovery_log_apply_error.clone(),
                error: None,
            });
            outputs.push(relative);
        }
    }
    // 아티팩트 요약의 "로그 적용됨"은 선언이 아니라 실적이다 — 어떤 하이브도
    // 로그를 적용하지 못했거나(발견 0 포함) 적용 실패가 있으면 false.
    if let Some(recovery) = outcome.registry_recovery.as_mut() {
        recovery.transaction_logs_applied = any_logs_applied && !any_log_apply_failed;
    }
    // 손상된 하이브는 건너뛴 것으로 취급한다(파싱 실패 == 손상 아티팩트).
    // 성공한 하이브 출력은 그대로 발행되고, 건너뛴 사실은 보고서의
    // registry_hives에만 남는다. 디스크 부족 같은 저장 환경 오류만
    // 아티팩트 실패(partial)로 올린다.
    let failures = source_failures.into_inner().unwrap_or_default();
    outcome
        .registry_hives
        .extend(failures.iter().map(|(failure, storage)| RegistryHiveReport {
            source_path: failure
                .split_once(": ")
                .map(|(path, _)| path)
                .unwrap_or(failure)
                .to_string(),
            status: if *storage { "failed" } else { "skipped_corrupted" }.to_string(),
            row_count: 0,
            recovery_logs_discovered: 0,
            recovery_log_count: 0,
            recovery_enabled: !registry::registry_recovery_disabled(),
            recovered_row_count: 0,
            recovery_permit_wait_ms: 0,
            build_recovery_ms: 0,
            iteration_and_sqlite_write_ms: 0,
            recovery_log_apply_error: None,
            error: Some(failure.clone()),
        }));
    let storage_failures: Vec<&String> = failures
        .iter()
        .filter(|(_, storage)| *storage)
        .map(|(failure, _)| failure)
        .collect();
    if !storage_failures.is_empty() {
        anyhow::bail!(
            "{} Registry storage failure(s): {}",
            storage_failures.len(),
            storage_failures
                .iter()
                .map(|failure| failure.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    outputs.sort();
    Ok(outputs)
}

fn parse_usnjrnl_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    // 손상 레코드는 파서가 재동기화로 건너뛴다. 파일 열기/저장 실패만 여기서
    // 데이터 손상으로 판단해 건너뛴다.
    if let Some(p) = paths.first() {
        let relative = "FILESYSTEM/UsnJrnl_Records.sqlite".to_string();
        let out = out_dir.join(&relative);
        if let Some(n) = run_unit_or_skip(&p.display().to_string(), &[&out], || {
            usnjrnl::parse_usn_stream(p, &out)
        })? {
            entry_record_input_count(entry, p, n);
            emit(&format!("[+] {} rows -> {}", n, out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_mft_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    // 손상 엔트리는 파서가 레코드 단위로 건너뛴다. 파일 열기/저장 실패만
    // 여기서 데이터 손상으로 판단해 건너뛴다.
    if let Some(p) = paths.first() {
        let relative = "_OVERVIEW/MFT_Records.sqlite".to_string();
        let out = out_dir.join(&relative);
        if let Some(n) = run_unit_or_skip(&p.display().to_string(), &[&out], || {
            mft::parse_mft_stream(p, &out)
        })? {
            entry_record_input_count(entry, p, n);
            emit(&format!("[+] {} rows -> {}", n, out.display()));
            outputs.push(relative);
        }
    } else {
        emit("[*] MFT 원본이 없어 이번 실행에서 MFT 결과를 만들지 않았습니다");
    }
    Ok(outputs)
}

fn parse_srum_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // 손상된 SRUDB는 그 파일만 건너뛴다(파싱 실패 == 손상 아티팩트).
    for p in paths {
        let base = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "SRUDB".into());
        let name = uniq_name(&base, &mut taken);
        let relative = format!("SRUM/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || {
            srum::parse_srum_stream(p, &out)
        })?;
        if let Some(tables) = unit {
            let record_count = tables.iter().map(|(_, count)| *count).sum();
            entry_record_input_count(entry, p, record_count);
            for (t, n) in tables {
                emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), t));
            }
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_jumplist_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let rows = jumplist::parse_jumplists_from(paths);
    entry_record_rows_by_source(entry, &rows);
    let mut outputs = Vec::new();
    if !rows.is_empty() {
        let relative = "JUMPLIST/JumpList_Entries.sqlite".to_string();
        let out = out_dir.join(&relative);
        if run_unit_or_skip("JumpList", &[&out], || {
            write_table(
                &out,
                jumplist::JUMPLIST_TABLE,
                &rows,
                jumplist::JUMPLIST_FIELD_ORDER,
            )
        })?
        .is_some()
        {
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_taskscheduler_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let rows = taskscheduler::parse_tasks_from(paths);
    entry_record_rows_by_source(entry, &rows);
    let mut outputs = Vec::new();
    if !rows.is_empty() {
        let relative = "TASKSCHEDULER/TaskScheduler_Tasks.sqlite".to_string();
        let out = out_dir.join(&relative);
        if run_unit_or_skip("TaskScheduler", &[&out], || {
            write_table(
                &out,
                taskscheduler::TASK_TABLE,
                &rows,
                taskscheduler::TASK_FIELD_ORDER,
            )
        })?
        .is_some()
        {
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_rdpcache_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    if paths.is_empty() {
        return Ok(outputs);
    }
    // 타일·모자이크 PNG(base64)는 행마다 커서 전량 적재하지 않고, 파일 하나
    // 디코딩이 끝날 때마다 스트리밍으로 기록한다.
    let relative = "RDPCACHE/RdpBitmapCache.sqlite".to_string();
    let out = out_dir.join(&relative);
    let mut per_source = std::collections::HashMap::<String, usize>::new();
    let unit = run_unit_or_skip("RdpCache", &[&out], || -> Result<usize> {
        let mut writer = crate::sqlite::StreamWriter::create(
            &out,
            rdpcache::RDP_TABLE,
            rdpcache::RDP_FIELD_ORDER,
            rdpcache::RDP_FIELD_ORDER,
        )?;
        rdpcache::parse_rdpcache_into(paths, &mut |row| {
            if let Some(source) = row.get("_source_file").filter(|source| !source.is_empty()) {
                *per_source.entry(source.clone()).or_default() += 1;
            }
            writer.push(row)
        })?;
        writer.finish()
    })?;
    let Some(total) = unit else {
        return Ok(outputs);
    };
    for (source, count) in per_source {
        entry_record_input_count(entry, Path::new(&source), count);
    }
    if total == 0 {
        let _ = std::fs::remove_file(&out);
    } else {
        emit(&format!("[+] {} rows -> {}", total, out.display()));
        outputs.push(relative);
    }
    Ok(outputs)
}

fn parse_timeline_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    if paths.is_empty() {
        return Ok(outputs);
    }
    // WAL/SHM 보조 파일은 여기서 한 번만 확정한다(계획 고정) — 각 보조 파일은
    // 복구 로그 입력으로 보고서에 남고, 파서는 이 목록만 사용한다.
    let planned: Vec<(PathBuf, Vec<PathBuf>)> = paths
        .iter()
        .map(|p| (p.clone(), timeline::wal_siblings(p)))
        .collect();
    for (_, sides) in &planned {
        for side in sides {
            entry_record_input(entry, side, true);
        }
    }
    let relative = "TIMELINE/Timeline_Activities.sqlite".to_string();
    let out = out_dir.join(&relative);
    type Unit = (usize, Vec<timeline::TimelineFileReport>);
    let unit = run_unit_or_skip("Timeline", &[&out], || -> Result<Unit> {
        // 행을 읽는 즉시 스트리밍 기록 — 전체 행을 메모리에 모으지 않는다.
        let mut writer = crate::sqlite::StreamWriter::create(
            &out,
            timeline::TIMELINE_TABLE,
            timeline::TIMELINE_FIELD_ORDER,
            timeline::TIMELINE_FIELD_ORDER,
        )?;
        let reports = timeline::parse_timeline_stream(&planned, &mut |row| writer.push(row));
        let total = writer.finish()?;
        if total > 0 {
            // 표시 순서(계정 → 시각)는 저장 후 SQLite 정렬로 만든다 — 파서가
            // 전 행을 모아 정렬하던 방식을 대체하며 메모리 사용은 상수로 남는다.
            let conn = rusqlite::Connection::open(&out)?;
            let table = crate::sqlite::quote_ident(timeline::TIMELINE_TABLE);
            conn.execute_batch(&format!(
                "CREATE TABLE \"__wina_sorted\" AS SELECT * FROM {table} ORDER BY account, timestamp;\n                 DROP TABLE {table};\n                 ALTER TABLE \"__wina_sorted\" RENAME TO {table};"
            ))?;
        }
        Ok((total, reports))
    })?;
    if let Some((total, reports)) = unit {
        for report in reports {
            entry_record_input_count(entry, &report.path, report.rows);
            if let Some(reason) = &report.error {
                emit(&format!(
                    "[*] Timeline DB 파싱 실패 — 건너뜀: {} ({reason})",
                    report.path.display()
                ));
                entry_record_input_error(entry, &report.path, reason);
            } else if let Some(note) = &report.wal_note {
                emit(&format!("[*] {} — {note}", report.path.display()));
                entry_record_input_error(entry, &report.path, note);
            }
        }
        if total == 0 {
            let _ = std::fs::remove_file(&out);
        } else {
            emit(&format!("[+] {} rows -> {}", total, out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_wmi_repository_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    if paths.is_empty() {
        return Ok(outputs);
    }
    let relative = "WMI/WMI_Persistence.sqlite".to_string();
    let out = out_dir.join(&relative);
    // 발견 즉시 스트리밍 기록 — 원본 전체 바이트나 전체 행을 메모리에 두지
    // 않는다. 파일별 실패는 사유와 함께 보고서 입력에 남는다.
    type Unit = (usize, Vec<wmi_repository::WmiFileReport>);
    let unit = run_unit_or_skip("WmiRepository", &[&out], || -> Result<Unit> {
        let mut writer = crate::sqlite::StreamWriter::create(
            &out,
            wmi_repository::WMI_TABLE,
            wmi_repository::WMI_FIELD_ORDER,
            wmi_repository::WMI_FIELD_ORDER,
        )?;
        let reports = wmi_repository::parse_wmi_stream(paths, &mut |row| writer.push(row))?;
        Ok((writer.finish()?, reports))
    })?;
    if let Some((total, reports)) = unit {
        for report in reports {
            entry_record_input_count(entry, &report.path, report.rows);
            if let Some(reason) = report.error {
                emit(&format!(
                    "[*] WMI 저장소 읽기 실패 — 건너뜀: {} ({reason})",
                    report.path.display()
                ));
                entry_record_input_error(entry, &report.path, &reason);
            }
        }
        if total == 0 {
            let _ = std::fs::remove_file(&out);
        } else {
            emit(&format!("[+] {} rows -> {}", total, out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_wer_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let rows = wer::parse_wer_from(paths);
    entry_record_rows_by_source(entry, &rows);
    let mut outputs = Vec::new();
    if !rows.is_empty() {
        let relative = "WER/WER_Reports.sqlite".to_string();
        let out = out_dir.join(&relative);
        if run_unit_or_skip("WER", &[&out], || {
            write_table(&out, wer::WER_TABLE, &rows, wer::WER_FIELD_ORDER)
        })?
        .is_some()
        {
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

/// History 내용에서 브라우저를 판별한다 — 해당 브라우저만 만들 수 있는 내부
/// 스킴 방문(chrome:// · edge:// · whale://)이 정확히 한 종류 있을 때만 Some.
/// 경로에 단서가 없을 때의 2차 판별이며, 열기 실패·근거 혼재 시 None(미상).
fn history_content_browser(path: &Path) -> Option<&'static str> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .ok()?;
    let mut hits: Vec<&'static str> = Vec::new();
    for (scheme, browser) in [("chrome", "Chrome"), ("edge", "Edge"), ("whale", "Whale")] {
        let found: bool = conn
            .query_row(
                &format!("SELECT 1 FROM urls WHERE url LIKE '{scheme}://%' LIMIT 1"),
                [],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if found {
            hits.push(browser);
        }
    }
    match hits.as_slice() {
        [one] => Some(one),
        _ => None,
    }
}

fn parse_browser_history_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // 계정 하나의 History가 손상돼도 그 계정만 건너뛴다(파싱 실패 == 손상
    // 아티팩트). 이미 저장 완료된 다른 계정 결과는 그대로 발행된다.
    for p in paths {
        let acct = browser_account(p);
        // 브라우저 판별: 경로 세그먼트 → 내용(내부 스킴) → 미상. 미상이면
        // 브라우저를 주장하지 않고 종전처럼 계정명만 쓴다 — 같은 계정에
        // 여러 History가 있을 때 어느 브라우저인지 산출물 이름에 남기기
        // 위한 것(T8). 원본 경로는 parse_report 입력 목록에 보존된다.
        let base = match browser_cache::browser_of(p).or_else(|| history_content_browser(p)) {
            Some(browser) => format!("{}_{}", acct, browser),
            None => acct,
        };
        let name = uniq_name(&base, &mut taken);
        let relative = format!("BROWSER/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<(usize, bool)> {
            // 테이블 단위 스트리밍 기록 — 전체 행을 메모리에 쌓지 않는다.
            let (record_count, wrote) = browser_history::parse_history_stream(p, &out)?;
            if wrote {
                emit(&format!("[+] {} rows -> {}", record_count, out.display()));
            }
            Ok((record_count, wrote))
        })?;
        if let Some((record_count, wrote)) = unit {
            entry_record_input_count(entry, p, record_count);
            if wrote {
                // 결과 DB ↔ 수집 원본 경로 1:1 매핑을 산출물 안에 보존한다 —
                // 유입 흐름이 캐시 행의 프로필 루트와 대조해 같은 브라우저
                // 프로필의 History만 정확히 고를 근거 (다중 프로필 혼입 차단).
                if let Ok(conn) = rusqlite::Connection::open(&out) {
                    let _ = conn.execute_batch(
                        "DROP TABLE IF EXISTS \"_wina_source\";\n                         CREATE TABLE \"_wina_source\" (source_path TEXT);",
                    );
                    let _ = conn.execute(
                        "INSERT INTO \"_wina_source\" VALUES (?1)",
                        [p.to_string_lossy().to_string()],
                    );
                }
                outputs.push(relative);
            }
        }
    }
    Ok(outputs)
}

fn parse_browser_cache_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry.input_discovery_checked = true;
    let mut outputs = Vec::new();
    // 계정(수집된 사용자 프로필)별 캐시 index 하나 = 출력 SQLite 하나.
    // 엔트리를 파싱하는 즉시 스트리밍 기록하므로 전체 결과가 메모리에 남지
    // 않고, 손상된 캐시는 해당 계정만 건너뛴다(파싱 실패 == 손상 아티팩트).
    //
    // 입력 기록은 검증을 통과한 index와 거부된 index(사유 포함)만 남긴다 —
    // 이름만 같은 비대상 index(Code Cache 등 레이아웃 밖)는 증거 입력이
    // 아니므로 기록하지 않는다.
    let candidates = browser_cache::cache_outputs(paths);
    for (path, reason) in &candidates.rejected {
        entry_record_input_error(entry, path, reason);
        emit(&format!("[*] 손상된 캐시 index 건너뜀: {} ({reason})", path.display()));
    }
    for (name, index_path) in candidates.outputs {
        entry_record_input(entry, &index_path, false);
        let relative = format!("BROWSER/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&index_path.display().to_string(), &[&out], || -> Result<usize> {
            let mut writer = crate::sqlite::StreamWriter::create(
                &out,
                browser_cache::CACHE_TABLE,
                browser_cache::CACHE_FIELD_ORDER,
                browser_cache::CACHE_FIELD_ORDER,
            )?;
            browser_cache::parse_cache_index(&index_path, &mut |row| writer.push(row))?;
            writer.finish()
        })?;
        match unit {
            Some(0) => {
                let _ = std::fs::remove_file(&out);
            }
            Some(count) => {
                entry_record_input_count(entry, &index_path, count);
                emit(&format!("[+] {} rows -> {}", count, out.display()));
                outputs.push(relative);
            }
            None => {}
        }
    }
    Ok(outputs)
}

fn parse_ie_webcache_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // WebCache 파일 하나 = 출력 SQLite 하나(계정별). 손상/dirty ESE는 해당
    // 파일만 건너뛴다(파싱 실패 == 손상 아티팩트).
    for p in paths {
        let acct = ie_webcache::ie_account(p);
        let name = uniq_name(&format!("{acct}_IE_WebCache"), &mut taken);
        let relative = format!("BROWSER/{name}.sqlite");
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<usize> {
            // 파서가 방문 기록 → 다운로드 순서를 보장하므로(컨테이너 2단계
            // 순회), 같은 SQLite 파일에 writer를 순차로 열어 다운로드도
            // 스트리밍 기록한다 — 다운로드 행을 메모리 배열에 모으지 않는다.
            let mut history = Some(crate::sqlite::StreamWriter::create(
                &out,
                ie_webcache::HISTORY_TABLE,
                ie_webcache::HISTORY_FIELD_ORDER,
                ie_webcache::HISTORY_FIELD_ORDER,
            )?);
            let mut downloads: Option<crate::sqlite::StreamWriter> = None;
            let mut total = 0usize;
            ie_webcache::parse_webcache(p, &acct, &mut |event| match event {
                ie_webcache::WebCacheEvent::History(row) => history
                    .as_mut()
                    .expect("history rows arrive before downloads")
                    .push(row),
                ie_webcache::WebCacheEvent::Download(row) => {
                    if downloads.is_none() {
                        if let Some(writer) = history.take() {
                            total += writer.finish()?;
                        }
                        downloads = Some(crate::sqlite::StreamWriter::create(
                            &out,
                            ie_webcache::DOWNLOADS_TABLE,
                            ie_webcache::DOWNLOADS_FIELD_ORDER,
                            ie_webcache::DOWNLOADS_FIELD_ORDER,
                        )?);
                    }
                    downloads.as_mut().expect("writer opened above").push(row)
                }
            })?;
            if let Some(writer) = history.take() {
                total += writer.finish()?;
            }
            if let Some(writer) = downloads.take() {
                total += writer.finish()?;
            }
            Ok(total)
        })?;
        match unit {
            Some(0) => {
                let _ = std::fs::remove_file(&out);
            }
            Some(count) => {
                entry_record_input_count(entry, p, count);
                emit(&format!("[+] {} rows -> {}", count, out.display()));
                outputs.push(relative);
            }
            None => {}
        }
    }
    Ok(outputs)
}

fn parse_ie_indexdat_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    // 계정 하나에 index.dat가 여러 개(History.IE5/Content.IE5/Cookies/일별
    // 컨테이너) — 계정별 출력 SQLite 하나로 모은다. 미지원 버전·손상 파일은
    // 그 파일만 건너뛰고 경고를 남긴다.
    let mut by_account: std::collections::BTreeMap<String, Vec<&PathBuf>> =
        std::collections::BTreeMap::new();
    for p in paths {
        by_account
            .entry(ie_webcache::ie_account(p))
            .or_default()
            .push(p);
    }
    for (acct, files) in by_account {
        let relative = format!("BROWSER/{acct}_IE_IndexDat.sqlite");
        let out = out_dir.join(&relative);
        type Unit = (usize, Vec<(PathBuf, usize)>, Vec<(PathBuf, String)>);
        let unit = run_unit_or_skip(&format!("index.dat[{acct}]"), &[&out], || -> Result<Unit> {
            let mut writer = crate::sqlite::StreamWriter::create(
                &out,
                ie_indexdat::TABLE,
                ie_indexdat::FIELD_ORDER,
                ie_indexdat::FIELD_ORDER,
            )?;
            let mut per_source: Vec<(PathBuf, usize)> = Vec::new();
            let mut failures: Vec<(PathBuf, String)> = Vec::new();
            for p in &files {
                match ie_indexdat::parse_index_dat(p, &acct, &mut |row| writer.push(row)) {
                    Ok(nrows) => per_source.push(((*p).clone(), nrows)),
                    Err(error) => {
                        emit(&format!("[!] index.dat 건너뜀 {}: {}", p.display(), error));
                        failures.push(((*p).clone(), error.to_string()));
                    }
                }
            }
            Ok((writer.finish()?, per_source, failures))
        })?;
        if let Some((total, per_source, failures)) = unit {
            for (source, count) in per_source {
                entry_record_input_count(entry, &source, count);
            }
            // 실패한 파일은 사유와 함께 입력에 남는다 — 0건 성공과 구분.
            for (source, reason) in failures {
                entry_record_input_error(entry, &source, &reason);
            }
            if total == 0 {
                let _ = std::fs::remove_file(&out);
            } else {
                emit(&format!("[+] {} rows -> {}", total, out.display()));
                outputs.push(relative);
            }
        }
    }
    Ok(outputs)
}

fn parse_prefetch_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    if !paths.is_empty() {
        let exec_relative = format!("PREFETCH/{}.sqlite", prefetch::EXEC_TABLE);
        let loaded_relative = format!("PREFETCH/{}.sqlite", prefetch::LOADED_TABLE);
        let ex = out_dir.join(&exec_relative);
        let lf = out_dir.join(&loaded_relative);
        let unit = run_unit_or_skip("Prefetch", &[&ex, &lf], || -> Result<prefetch::PrefetchCounts> {
            // 파싱 즉시 스트리밍 기록 — 전체 행을 메모리에 쌓지 않는다.
            prefetch::parse_prefetch_stream(paths, &ex, &lf)
        })?;
        if let Some(counts) = unit {
            for (source, count) in &counts.exec_by_source {
                entry_record_input_count(entry, Path::new(source), *count);
            }
            for (source, count) in &counts.loaded_by_source {
                entry_record_input(entry, Path::new(source), false);
                entry_add_input_count(entry, Path::new(source), *count);
            }
            emit(&format!("[+] {} rows -> {}", counts.exec_rows, ex.display()));
            emit(&format!(
                "[+] {} rows -> {}",
                counts.loaded_rows,
                lf.display()
            ));
            outputs.push(exec_relative);
            outputs.push(loaded_relative);
        }
    }
    Ok(outputs)
}

fn parse_powershell_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    entry: &mut ParseArtifactReport,
) -> Result<Vec<String>> {
    entry_record_inputs(entry, paths);
    let mut outputs = Vec::new();
    if !paths.is_empty() {
        let relative = format!("POWERSHELL/{}.sqlite", powershell_history::PS_TABLE);
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip("PowerShell", &[&out], || -> Result<Vec<Row>> {
            let rows = powershell_history::parse_console_history(paths)?;
            write_table(
                &out,
                powershell_history::PS_TABLE,
                &rows,
                powershell_history::PS_FIELD_ORDER,
            )?;
            Ok(rows)
        })?;
        if let Some(rows) = unit {
            entry_record_rows_by_source(entry, &rows);
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            outputs.push(relative);
        }
    }
    Ok(outputs)
}

fn parse_artifact_sources(
    name: &str,
    paths: &[PathBuf],
    out_dir: &Path,
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    match name {
        "Amcache" => parse_amcache_artifact(paths, out_dir, outcome),
        "EventLog" => parse_eventlog_artifact(paths, out_dir, &mut outcome.entry),
        "Registry" => parse_registry_artifact(paths, out_dir, outcome),
        "UsnJrnl" => parse_usnjrnl_artifact(paths, out_dir, &mut outcome.entry),
        "MFT" => parse_mft_artifact(paths, out_dir, &mut outcome.entry),
        "SRUM" => parse_srum_artifact(paths, out_dir, &mut outcome.entry),
        "JumpList" => parse_jumplist_artifact(paths, out_dir, &mut outcome.entry),
        "TaskScheduler" => parse_taskscheduler_artifact(paths, out_dir, &mut outcome.entry),
        "RdpCache" => parse_rdpcache_artifact(paths, out_dir, &mut outcome.entry),
        "BrowserHistory" => parse_browser_history_artifact(paths, out_dir, &mut outcome.entry),
        "BrowserCache" => parse_browser_cache_artifact(paths, out_dir, &mut outcome.entry),
        "IEWebCache" => parse_ie_webcache_artifact(paths, out_dir, &mut outcome.entry),
        "IEIndexDat" => parse_ie_indexdat_artifact(paths, out_dir, &mut outcome.entry),
        "PowerShell" => parse_powershell_artifact(paths, out_dir, &mut outcome.entry),
        "Prefetch" => parse_prefetch_artifact(paths, out_dir, &mut outcome.entry),
        "WER" => parse_wer_artifact(paths, out_dir, &mut outcome.entry),
        "WmiRepository" => parse_wmi_repository_artifact(paths, out_dir, &mut outcome.entry),
        "Timeline" => parse_timeline_artifact(paths, out_dir, &mut outcome.entry),
        other => anyhow::bail!("unknown artifact {other}"),
    }
}

fn mark_artifact_failed(outcome: &mut ArtifactOutcome, name: &str, error: String) {
    outcome.errors.push(format!("{}: {}", name, error));
    outcome.entry.status = "failed".to_string();
    outcome.entry.error = Some(error.clone());
    append_current_log_lifecycle(&format!(
        "artifact_finished name={} status=failed error={}",
        name, error
    ));
}

/// Run one artifact end-to-end inside a worker thread: parse into the staging
/// tree, seal its outputs, and record the terminal state. An Err is logged and
/// isolated, and a *panic* (e.g. a malformed structure that trips an index) is
/// caught too, so one bad artifact can never stop the ones running beside it
/// or the _OVERVIEW stage.
fn run_artifact_job(
    name: &str,
    paths: &[PathBuf],
    discovery_errors: &[String],
    out_dir: &Path,
) -> ArtifactOutcome {
    let mut outcome = ArtifactOutcome::new(name);
    // 탐색 중 만난 접근·순회 실패는 이 아티팩트 보고서에 남는다 — 접근 불가
    // 하위 디렉터리의 "발견 0건"이 실제 무증거로 오인되지 않게.
    outcome.entry.discovery_errors = discovery_errors.to_vec();
    append_current_log_lifecycle(&format!("artifact_started name={}", name));
    if CANCEL.load(Ordering::Relaxed) {
        outcome.entry.status = "cancelled".to_string();
        append_current_log_lifecycle(&format!(
            "artifact_finished name={} status=cancelled",
            name
        ));
        return outcome;
    }
    emit(&format!("[시작] {}", name));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_artifact_sources(name, paths, out_dir, &mut outcome)
    }));
    match result {
        Ok(Ok(outputs)) => {
            if artifact_has_no_input(&outcome.entry, &outputs) {
                outcome.entry.status = "no_input".to_string();
                outcome.entry.publication_status = Some("not_published".to_string());
                emit(&format!("[완료] {} — 원본 없음", name));
                append_current_log_lifecycle(&format!(
                    "artifact_finished name={} status=no_input",
                    name
                ));
            } else {
                match seal_artifact_outputs(out_dir, name, &outputs) {
                    Ok(sealed) => {
                        outcome.entry.status = "completed".to_string();
                        outcome.entry.outputs = outputs;
                        outcome.sealed = sealed;
                        emit(&format!("[완료] {}", name));
                        append_current_log_lifecycle(&format!(
                            "artifact_finished name={} status=completed",
                            name
                        ));
                    }
                    Err(error) => {
                        let error = format!("sealed output: {error}");
                        emit(&format!("[!] {} failed: {}", name, error));
                        mark_artifact_failed(&mut outcome, name, error);
                    }
                }
            }
        }
        Ok(Err(error)) => {
            let error = error.to_string();
            emit(&format!("[!] {} failed: {}", name, error));
            mark_artifact_failed(&mut outcome, name, error);
        }
        Err(payload) => {
            let error = panic_details(payload);
            emit(&format!("[!] {} panicked — skipped: {}", name, error));
            outcome.errors.push(format!("{}: panic: {}", name, error));
            outcome.entry.status = "failed".to_string();
            outcome.entry.error = Some(format!("panic: {}", error));
            append_current_log_lifecycle(&format!(
                "artifact_finished name={} status=failed panic={}",
                name, error
            ));
        }
    }
    outcome
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
        amcache_hives: Vec::new(),
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
    let want = |n: &str| only.as_ref().is_none_or(|o| o.contains(n));
    let mut artifacts_run: Vec<String> = Vec::new();
    let mut sealed_outputs: Vec<SealedArtifactOutput> = Vec::new();
    let mut had_error = false;

    // ---- 1단계: 아티팩트별 원본 파일 확인(경로/내용 기준) 및 목록화 ----
    let wanted: Vec<&'static str> = ARTIFACT_NAMES
        .iter()
        .copied()
        .filter(|name| want(name))
        .collect();
    emit("=== 파일 확인 ===");
    append_current_log_lifecycle("discovery_started");
    let discovered: std::collections::HashMap<&'static str, finder::Found> = {
        let slots: Vec<Mutex<finder::Found>> = wanted
            .iter()
            .map(|_| Mutex::new(finder::Found::default()))
            .collect();
        let next = AtomicUsize::new(0);
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(wanted.len().max(1));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    if CANCEL.load(Ordering::Relaxed) {
                        break;
                    }
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= wanted.len() {
                        break;
                    }
                    let found = discover_artifact_files(wanted[index], &target);
                    if let Ok(mut slot) = slots[index].lock() {
                        *slot = found;
                    }
                });
            }
        });
        wanted
            .iter()
            .zip(slots)
            .map(|(name, slot)| (*name, slot.into_inner().unwrap_or_default()))
            .collect()
    };
    for &name in &wanted {
        let found = &discovered[name];
        emit(&format!("[파일] {}: {}개", name, found.paths.len()));
        if found.paths.len() <= 20 {
            for path in &found.paths {
                emit(&format!("[*] found: {}", path.display()));
            }
        }
        for error in &found.errors {
            emit(&format!("[!] 탐색 실패 ({name}): {error}"));
        }
    }
    append_current_log_lifecycle("discovery_finished");

    // ---- 2단계: 아티팩트 병렬 파싱 — 각 아티팩트의 원본 데이터베이스 저장 ----
    // BrowserHistory와 BrowserCache는 같은 BROWSER/<account>.sqlite 파일을
    // 공유할 수 있어 한 체인 안에서 순서대로 실행한다(마지막 성공 기록이
    // 남는 기존 규칙 유지). 나머지 아티팩트는 서로 독립적으로 병렬 실행된다.
    let mut chains: Vec<Vec<&'static str>> = Vec::new();
    for &name in &wanted {
        if name == "BrowserCache" {
            if let Some(chain) = chains
                .iter_mut()
                .find(|chain| chain.contains(&"BrowserHistory"))
            {
                chain.push(name);
                continue;
            }
        }
        chains.push(vec![name]);
    }
    emit("=== 파싱 ===");
    let outcomes: Mutex<Vec<ArtifactOutcome>> = Mutex::new(Vec::with_capacity(wanted.len()));
    {
        let next = AtomicUsize::new(0);
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(chains.len().max(1));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= chains.len() {
                        break;
                    }
                    for &name in &chains[index] {
                        let (paths, discovery_errors): (&[PathBuf], &[String]) = discovered
                            .get(name)
                            .map(|found| (found.paths.as_slice(), found.errors.as_slice()))
                            .unwrap_or((&[], &[]));
                        let outcome = run_artifact_job(name, paths, discovery_errors, &out_dir);
                        let mut collected = outcomes
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        collected.push(outcome);
                    }
                });
            }
        });
    }
    let mut outcomes = outcomes
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for &name in &wanted {
        let Some(position) = outcomes
            .iter()
            .position(|outcome| outcome.entry.name == name)
        else {
            continue;
        };
        let outcome = outcomes.remove(position);
        had_error |= !outcome.errors.is_empty();
        report.errors.extend(outcome.errors);
        if outcome.entry.status == "completed" {
            report.completed_artifacts.push(name.to_string());
        }
        report.registry_hives.extend(outcome.registry_hives);
        report.amcache_hives.extend(outcome.amcache_hives);
        if outcome.registry_recovery.is_some() {
            report.registry_recovery = outcome.registry_recovery;
        }
        sealed_outputs.extend(outcome.sealed);
        report.artifacts.push(outcome.entry);
        artifacts_run.push(name.to_string());
    }

    // The correlation overview is built from the staging tree, which always
    // holds the best-available picture: on a full run every succeeded artifact
    // is freshly staged; on a scoped re-run the untouched categories are copied
    // in from the last committed output. A single failed raw artifact (e.g. a
    // dirty SRUDB.dat that libesedb cannot open) therefore must NOT suppress the
    // overview — every integrated analysis tab is derived from it, so skipping
    // it would blank the whole host analysis even when the other artifacts
    // parsed cleanly. Only a cancel skips it, because a cancelled run may have
    // stopped mid-artifact and left the staging tree incomplete.
    if !cancelled() {
        emit("=== _OVERVIEW ===");
        append_current_log_lifecycle("overview_started");
        let ov = out_dir.join("_OVERVIEW");
        reset_stage_overview(&ov)?;
        // TargetInfo, BAM execution history, and RegistryFindings all inspect
        // the same recovered Registry SQLite rows.  Keep one in-memory cache
        // for this overview pass only, preserving rowids/source identities.
        let registry_overview = overview::RegistryOverviewCache::load(&out_dir);
        // columns: 0건에도 스키마를 만들 고정 컬럼 목록. 모든 개요 테이블은
        // 0건이어도 스키마와 함께 발행한다 — "해당 활동 없음"이 그 자체로
        // 확인 가능한 정보로 남는다 (2026-08-31 사용자 확정, 통일).
        // 스트리밍으로 쓰는 파생(write_ov 밖 경로)의 보고 항목 — report가
        // write_ov 클로저에 이미 가변 차용돼 있어 별도 목록에 모았다가 합친다.
        let mut extra_overview: Vec<OverviewTableReport> = Vec::new();
        let mut write_ov = |name: &str, rows: Vec<Row>, columns: &[&str]| -> Result<()> {
            let out = ov.join(format!("{}.sqlite", name));
            write_table(&out, name, &rows, columns)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            report.overview.push(OverviewTableReport {
                name: name.to_string(),
                row_count: rows.len(),
            });
            Ok(())
        };
        let overview_result = (|| -> Result<()> {
            // 이벤트 로그 행은 여러 빌더가 공유한다 — 한 번만 로드.
            let events = overview::EventLogOverviewCache::load(&out_dir);
            write_ov(
                "ScheduledTasks",
                overview::build_scheduled_tasks_with_events(&out_dir, &events),
                overview::ST_KEYS,
            )?;
            write_ov("RdpCache", overview::build_rdp_cache(&out_dir), overview::RC_KEYS)?;
            write_ov(
                "Defender",
                {
                    let mut defender_rows = overview::build_defender_with_events(&events);
                    // MPDetection-*.log의 DETECTION 라인 합류 (source=MPDetection).
                    defender_rows.extend(overview::defender_from_mpdetection(&target));
                    defender_rows
                },
                overview::DEF_KEYS,
            )?;
            write_ov(
                "RemoteDesktopHistory",
                overview::build_remote_desktop_history_with_events(&events),
                overview::RDP_KEYS,
            )?;
            write_ov(
                "SmbHistory",
                overview::build_smb_history_with_events(&events),
                overview::SMB_KEYS,
            )?;
            write_ov(
                "BitsHistory",
                overview::build_bits_history_with_events(&events),
                overview::BITS_KEYS,
            )?;
            write_ov(
                "FirewallHistory",
                overview::build_firewall_history_with_events(&out_dir, &events),
                overview::FW_KEYS,
            )?;
            write_ov(
                "PowerShellHistory",
                overview::build_powershell_history_with_events(&out_dir, &events),
                overview::PS_KEYS,
            )?;
            drop(events);
            write_ov(
                "BrowserActivity",
                overview::build_browser_history(&out_dir),
                overview::BH_KEYS,
            )?;
            write_ov(
                "TargetInfo",
                {
                    let mut ti_rows =
                        overview::build_target_info_with_registry(&registry_overview);
                    // hosts 파일 수동 등록 항목 합류 (유효 엔트리 없으면 0행).
                    ti_rows.extend(overview::ti_from_hosts_file(&target));
                    ti_rows
                },
                overview::TI_KEYS,
            )?;
            write_ov(
                "ExecutionHistory",
                overview::build_execution_history_with_registry(&out_dir, &registry_overview),
                overview::ROW_KEYS,
            )?;
            write_ov(
                "RegistryFindings",
                overview::build_registry_findings_with_registry(&registry_overview),
                overview::RF_KEYS,
            )?;
            write_ov(
                "PathReferences",
                overview::build_path_references(&out_dir, &registry_overview),
                overview::PR_KEYS,
            )?;
            // AI 대화 — 지원 브라우저 캐시 facts 전량 판별(상한 없음). 원문
            // JSON을 메모리에 모으지 않도록 스트리밍 기록하고, 표시 순서
            // (관찰 시각 내림차순 + URL)는 저장 후 SQLite 정렬로 만든다.
            // 뷰어는 이 파생 테이블만 기간·페이지 조건으로 조회한다.
            {
                let name = crate::ai_activity::AI_TABLE;
                let out = ov.join(format!("{}.sqlite", name));
                let mut writer = crate::sqlite::StreamWriter::create(
                    &out,
                    name,
                    crate::ai_activity::AI_KEYS,
                    crate::ai_activity::AI_KEYS,
                )?;
                crate::ai_activity::build_ai_conversations_stream(&out_dir, &mut |row| {
                    writer.push(row)
                })?;
                let total = writer.finish()?;
                if total > 0 {
                    let conn = rusqlite::Connection::open(&out)?;
                    let table = crate::sqlite::quote_ident(name);
                    conn.execute_batch(&format!(
                        "CREATE TABLE \"__wina_sorted\" AS SELECT * FROM {table} ORDER BY date DESC, url ASC;\n                         DROP TABLE {table};\n                         ALTER TABLE \"__wina_sorted\" RENAME TO {table};"
                    ))?;
                }
                emit(&format!("[+] {} rows -> {}", total, out.display()));
                extra_overview.push(OverviewTableReport {
                    name: name.to_string(),
                    row_count: total,
                });
            }
            Ok(())
        })();
        report.overview.append(&mut extra_overview);
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
        // Seal the freshly-built correlation tables so a partial run (some raw
        // artifact failed) still publishes them through the per-file path. On a
        // clean run they publish with the rest of the staging tree instead.
        let overview_outputs: Vec<String> = report
            .overview
            .iter()
            .map(|table| format!("_OVERVIEW/{}.sqlite", table.name))
            .collect();
        match seal_artifact_outputs(&out_dir, "_OVERVIEW", &overview_outputs) {
            Ok(sealed) => sealed_outputs.extend(sealed),
            Err(error) => emit(&format!("[!] _OVERVIEW seal failed: {error}")),
        }
    } else {
        emit("=== 취소됨 — 종합 분석 건너뜀 ===");
        append_current_log_lifecycle("overview_finished status=cancelled");
    }

    let run_at = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();

    // 가공의 마지막 단계: 통합 타임라인 캐시. run_at(=호스트의 lastRunAt)을
    // 키로 스테이징 루트에 기록하고, 발행 시 호스트 루트로 함께 이동한다.
    // 캐시 생성 실패는 치명적이지 않다 — 뷰어가 탭 열람 시 직접 다시 만든다.
    if !cancelled() {
        match crate::timeline_cache::build_master_timeline_cache(&out_dir, &live_dir, &run_at) {
            Ok(entry_count) => {
                emit(&format!("[+] {} rows -> 통합 타임라인", entry_count));
                append_current_log_lifecycle("timeline_cache_finished status=completed");
                match seal_artifact_outputs(
                    &out_dir,
                    "_OVERVIEW",
                    &["_master_timeline.cache.json".to_string()],
                ) {
                    Ok(sealed) => sealed_outputs.extend(sealed),
                    Err(error) => emit(&format!("[!] 통합 타임라인 캐시 seal 실패: {error}")),
                }
            }
            Err(error) => {
                emit(&format!("[!] 통합 타임라인 캐시 생성 실패: {error}"));
                append_current_log_lifecycle(&format!(
                    "timeline_cache_finished status=failed error={error}"
                ));
            }
        }
    }

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
        if let Err(error) = clear_previous_results(&live_dir, only.as_ref()) {
            report.errors.push(format!("clear previous results: {error}"));
        }
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
        // 실패 아티팩트의 이전 결과도 함께 지운다 — 남은 것은 항상 이번 실행
        // 한 시점의 산출물뿐이다(실패 = 손상·오수집 원본 판정, 보고서에 기록).
        if let Err(error) = clear_previous_results(&live_dir, only.as_ref()) {
            report.errors.push(format!("clear previous results: {error}"));
        }
        // Publish every sealed file, including the freshly-built `_OVERVIEW`
        // correlation tables and the MFT raw table. A partial run still derives
        // a valid overview from the artifacts that staged successfully, so the
        // analysis tabs stay populated instead of blanking when one raw
        // artifact (such as a dirty SRUM database) fails.
        let outputs: Vec<SealedArtifactOutput> = sealed_outputs;
        // A partial publish must carry at least one successful RAW artifact.
        // The _OVERVIEW tables can contain default findings derived from zero
        // evidence, so an overview-only seal (every selected source failed)
        // would otherwise publish and report `published=true` for a run that
        // produced nothing.
        let has_completed_raw = outputs
            .iter()
            .any(|output| output.artifact != "_OVERVIEW");
        if !has_completed_raw {
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
    fn environment_io_errors_escalate_but_format_errors_do_not() {
        // 권한 거부는 증거 손상이 아니라 실행 환경 문제 — partial로 승격.
        let denied = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert!(is_storage_error(&denied));
        let enospc = anyhow::Error::new(std::io::Error::from_raw_os_error(28));
        assert!(is_storage_error(&enospc));
        // 포맷 해석 실패는 손상 아티팩트로 건너뛴다.
        let format = anyhow::anyhow!("not a registry hive");
        assert!(!is_storage_error(&format));
        let not_found = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "gone",
        ));
        assert!(!is_storage_error(&not_found));
    }

    #[test]
    fn amcache_hive_report_serializes_log_fallback() {
        let fallback = AmcacheHiveReport {
            source_path: "C:\\Amcache.hve".to_string(),
            status: "completed".to_string(),
            logs_discovered: 2,
            logs_applied: 0,
            log_apply_error: Some("bad LOG1".to_string()),
            error: None,
        };
        let value = serde_json::to_value(&fallback).unwrap();
        assert_eq!(value["status"], "completed");
        assert_eq!(value["logsDiscovered"], 2);
        assert_eq!(value["logsApplied"], 0);
        assert_eq!(value["logApplyError"], "bad LOG1");
        assert!(value.get("error").is_none());
        let skipped = AmcacheHiveReport {
            source_path: "C:\\Amcache.hve".to_string(),
            status: "skipped_corrupted".to_string(),
            logs_discovered: 2,
            logs_applied: 0,
            log_apply_error: None,
            error: Some("not a hive".to_string()),
        };
        let value = serde_json::to_value(&skipped).unwrap();
        assert_eq!(value["status"], "skipped_corrupted");
        assert_eq!(value["error"], "not a hive");
        assert!(value.get("logApplyError").is_none());
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
    fn partial_publish_clears_prior_results_and_publishes_only_sealed_outputs() {
        let root = temporary_directory("partial-publish");
        let live = root.join("host");
        // 이전 실행의 파생 결과 — 재파싱은 이전 결과를 보존하지 않으므로
        // (수집 데이터 불변, 실패 파싱은 반복 실패) 발행 전에 지워져야 한다.
        std::fs::create_dir_all(live.join("_OVERVIEW")).unwrap();
        std::fs::write(live.join("_OVERVIEW/MFT_Records.sqlite"), b"prior-overview").unwrap();
        std::fs::write(live.join("_master_timeline.cache.json"), b"prior-cache").unwrap();

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
        clear_previous_results(&live, None).unwrap();
        publish_staged_artifact_files(&live, &stage, "partial-run", &sealed).unwrap();

        assert_eq!(
            std::fs::read(live.join("REGISTRY/Registry.sqlite")).unwrap(),
            b"successful-registry"
        );
        // 이전 파생 결과·타임라인 캐시는 남지 않는다 — "새 facts + 이전
        // derived" 혼재가 구조적으로 불가능해야 한다. 봉인되지 않은 실패
        // 아티팩트의 stage 파일도 발행되지 않는다.
        assert!(!live.join("_OVERVIEW/MFT_Records.sqlite").exists());
        assert!(!live.join("_master_timeline.cache.json").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// T8: 경로에 단서가 없는 History는 내부 스킴 방문으로 브라우저를
    /// 판별하고, 근거가 없거나 혼재하면 미상(None)으로 남긴다.
    #[test]
    fn history_content_browser_detects_only_unambiguous_internal_schemes() {
        let root = temporary_directory("history-content-browser");
        std::fs::create_dir_all(&root).unwrap();
        let make = |name: &str, urls: &[&str]| {
            let path = root.join(name);
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute("CREATE TABLE urls (url TEXT)", []).unwrap();
            for url in urls {
                conn.execute("INSERT INTO urls VALUES (?1)", rusqlite::params![url])
                    .unwrap();
            }
            path
        };
        let edge = make("edge.sqlite", &["https://x.test/", "edge://settings/profiles"]);
        let plain = make("plain.sqlite", &["https://x.test/"]);
        let mixed = make(
            "mixed.sqlite",
            &["chrome://version", "edge://settings", "https://x.test/"],
        );
        assert_eq!(history_content_browser(&edge), Some("Edge"));
        assert_eq!(history_content_browser(&plain), None);
        assert_eq!(history_content_browser(&mixed), None);
        // urls 테이블이 없거나 sqlite가 아니면 판별하지 않는다.
        std::fs::write(root.join("junk.sqlite"), b"not sqlite").unwrap();
        assert_eq!(history_content_browser(&root.join("junk.sqlite")), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stage_overview_reset_drops_copied_prior_derived_files() {
        let root = temporary_directory("stage-ov-reset");
        let live = root.join("host");
        // 범위 재파싱: 이전 실행의 파생 파일이 live에 있고, 스테이지 준비가
        // 이를 복사해 온다. 0건이 된 skip_empty 파생은 write_ov가 아무것도
        // 안 하므로, 리셋 없이는 이 복사본이 그대로 재발행된다.
        std::fs::create_dir_all(live.join("_OVERVIEW")).unwrap();
        std::fs::write(live.join("_OVERVIEW/ScheduledTasks.sqlite"), b"prior").unwrap();
        // 파서 원본 산출물은 파생이 아니다 — 범위 재파싱에서 복사돼 온
        // 마지막 발행본이 리셋에서 지워지면 어디서도 복구되지 않는다.
        std::fs::write(live.join("_OVERVIEW/MFT_Records.sqlite"), b"committed-mft").unwrap();
        let mut only = HashSet::new();
        only.insert("TaskScheduler".to_string());
        let stage = prepare_staging_output(&live, "scoped-ov", Some(&only)).unwrap();
        assert!(stage.join("_OVERVIEW/ScheduledTasks.sqlite").exists());
        reset_stage_overview(&stage.join("_OVERVIEW")).unwrap();
        assert!(!stage.join("_OVERVIEW/ScheduledTasks.sqlite").exists());
        assert!(stage.join("_OVERVIEW").exists());
        assert_eq!(
            std::fs::read(stage.join("_OVERVIEW/MFT_Records.sqlite")).unwrap(),
            b"committed-mft"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ok_publish_retains_parser_staged_mft_records_after_overview_reset() {
        let root = temporary_directory("ok-publish-mft");
        let live = root.join("host");
        // 이전 실행의 발행본 — ok 발행은 전부 이번 실행 결과로 대체한다.
        std::fs::create_dir_all(live.join("_OVERVIEW")).unwrap();
        std::fs::write(live.join("_OVERVIEW/MFT_Records.sqlite"), b"prior-mft").unwrap();
        std::fs::write(live.join("_OVERVIEW/TargetInfo.sqlite"), b"prior-derived").unwrap();

        // 전체 실행 재현: MFT 파서가 스테이징 _OVERVIEW에 기록·seal → 파생
        // 생성 직전 리셋 → 파생 기록 → ok 발행. 리셋이 파서 산출물을 지우면
        // ok 발행(publish_staging_output)은 seal본을 건너뛰므로 소실된다.
        let stage = prepare_staging_output(&live, "ok-run", None).unwrap();
        std::fs::create_dir_all(stage.join("_OVERVIEW")).unwrap();
        std::fs::write(stage.join("_OVERVIEW/MFT_Records.sqlite"), b"fresh-mft").unwrap();
        let mft_outputs = vec!["_OVERVIEW/MFT_Records.sqlite".to_string()];
        seal_artifact_outputs(&stage, "MFT", &mft_outputs).unwrap();

        reset_stage_overview(&stage.join("_OVERVIEW")).unwrap();
        std::fs::write(stage.join("_OVERVIEW/TargetInfo.sqlite"), b"fresh-derived").unwrap();

        clear_previous_results(&live, None).unwrap();
        publish_staging_output(&live, &stage, "ok-run").unwrap();

        assert_eq!(
            std::fs::read(live.join("_OVERVIEW/MFT_Records.sqlite")).unwrap(),
            b"fresh-mft"
        );
        assert_eq!(
            std::fs::read(live.join("_OVERVIEW/TargetInfo.sqlite")).unwrap(),
            b"fresh-derived"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scoped_clear_removes_only_target_categories() {
        let root = temporary_directory("scoped-clear");
        let live = root.join("host");
        std::fs::create_dir_all(live.join("REGISTRY")).unwrap();
        std::fs::create_dir_all(live.join("EVENTLOG")).unwrap();
        std::fs::create_dir_all(live.join("_OVERVIEW")).unwrap();
        std::fs::write(live.join("REGISTRY/Registry.sqlite"), b"old").unwrap();
        std::fs::write(live.join("EVENTLOG/Security.sqlite"), b"keep").unwrap();
        std::fs::write(live.join("_OVERVIEW/TargetInfo.sqlite"), b"old").unwrap();
        let mut only = HashSet::new();
        only.insert("Registry".to_string());
        clear_previous_results(&live, Some(&only)).unwrap();
        // 대상 아티팩트 카테고리와 항상 재생성되는 _OVERVIEW만 지워지고,
        // 범위 밖 카테고리는 유지된다.
        assert!(!live.join("REGISTRY").exists());
        assert!(!live.join("_OVERVIEW").exists());
        assert_eq!(
            std::fs::read(live.join("EVENTLOG/Security.sqlite")).unwrap(),
            b"keep"
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
            amcache_hives: Vec::new(),
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
                    discovery_errors: Vec::new(),
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
                    discovery_errors: Vec::new(),
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

        report.artifacts[1].status = "no_input".to_string();
        report.artifacts[1].publication_status = Some("not_published".to_string());
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
            discovery_errors: Vec::new(),
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
                error: None,
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
            discovery_errors: Vec::new(),
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
            amcache_hives: Vec::new(),
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
                discovery_errors: Vec::new(),
                inputs: Vec::new(),
            }],
            overview: Vec::new(),
        };
        entry_record_inputs(
            &mut report.artifacts[0],
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
    fn corrupted_registry_and_srum_sources_are_skipped_and_run_completes() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock().unwrap();
        let root = temporary_directory("source-errors");
        let cases_dir = root.join("cases");
        let target_dir = root.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        // The filename makes it a Registry candidate; the content is not a
        // hive. A corrupted source is skipped — it must not fail the artifact
        // or discard sibling results (파싱 실패 == 손상 아티팩트).
        std::fs::write(target_dir.join("SOFTWARE"), b"not a registry hive").unwrap();
        std::fs::write(target_dir.join("SRUDB.dat"), b"not an ESE database").unwrap();
        std::fs::write(target_dir.join("Amcache.hve"), b"not an amcache hive").unwrap();
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
        only.insert("Amcache".to_string());
        let run_id = "source-errors";

        run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some(run_id))
            .expect("skipped corrupted sources must not fail the run");

        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        let artifacts = report["artifacts"].as_array().expect("artifact report");
        for artifact in ["Registry", "SRUM", "Amcache"] {
            let entry = artifacts
                .iter()
                .find(|entry| entry["name"] == artifact)
                .expect("artifact entry");
            assert_eq!(
                entry["status"], "completed",
                "{artifact}: a skipped corrupted source completes with no output"
            );
            assert!(entry.get("outputs").is_none() || entry["outputs"].as_array().unwrap().is_empty());
        }
        // The skipped hive stays visible in the per-hive report data.
        assert!(report["registryHives"]
            .as_array()
            .is_some_and(|hives| hives.iter().any(|hive| hive["status"] == "skipped_corrupted")));
        // 손상 Amcache 건너뜀도 경로·오류와 함께 영구 보고서에 남아야
        // 0건 결과와 구분된다.
        let amcache_hive = report["amcacheHives"]
            .as_array()
            .and_then(|hives| {
                hives
                    .iter()
                    .find(|hive| hive["status"] == "skipped_corrupted")
            })
            .expect("skipped amcache hive report");
        assert!(amcache_hive["sourcePath"]
            .as_str()
            .is_some_and(|path| path.ends_with("Amcache.hve")));
        assert!(amcache_hive["error"].as_str().is_some_and(|e| !e.is_empty()));
        assert_eq!(report["status"], "ok");
        assert_eq!(
            case_store::load_host(&case.id, &host.id, &cases_dir)
                .unwrap()
                .last_run_status
                .as_deref(),
            Some("ok")
        );
        let log = std::fs::read_to_string(parse_run_log_path(&host_dir, run_id)).unwrap();
        assert!(log.contains("artifact_finished name=Registry status=completed"));
        assert!(log.contains("artifact_finished name=SRUM status=completed"));
        assert!(log.contains("run_finished status=ok"));
        let _ = std::fs::remove_dir_all(root);
    }
}
