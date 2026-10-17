//! Parse-stage orchestration, mirroring main.py run_host: locate each
//! artifact's files under the target, parse, and write per-source SQLite into
//! CATEGORY/<name>.sqlite. Streaming parsers write directly; smaller ones use
//! write_table. Overview builders are a separate (later) stage.
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::case_store::{self};
use crate::finder;
use crate::parsers::{
    amcache, browser_cache, browser_history, eventlog, ie_indexdat, ie_webcache, jumplist, mft,
    powershell_history, prefetch, rdpcache, recyclebin, registry, srum, taskscheduler, timeline, usnjrnl,
    wer,
};
use crate::sqlite::{write_fixed_table, write_table, Row};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

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

/// Raw output category of each parser. BROWSER is shared by four parsers;
/// MFT writes its raw table into `_OVERVIEW`, whose other files are derived.
fn artifact_category(artifact: &str) -> Option<&'static str> {
    Some(match artifact {
        "Amcache" => "AMCACHE",
        "EventLog" => "EVENTLOG",
        "Registry" => "REGISTRY",
        "UsnJrnl" => "FILESYSTEM",
        "MFT" => "_OVERVIEW",
        "JumpList" => "JUMPLIST",
        "SRUM" => "SRUM",
        "TaskScheduler" => "TASKSCHEDULER",
        "RdpCache" => "RDPCACHE",
        "BrowserHistory" | "BrowserCache" | "IEWebCache" | "IEIndexDat" => "BROWSER",
        "Prefetch" => "PREFETCH",
        "PowerShell" => "POWERSHELL",
        "WER" => "WER",
        "Timeline" => "TIMELINE",
        "RecycleBin" => "RECYCLEBIN",
        _ => return None,
    })
}

/// Categories every run rebuilds from the stage. Overview builders replace
/// files here even during a scoped run, so they are never hard-linked.
const RECOMPUTED_CATEGORIES: &[&str] = &["_OVERVIEW", "SUPPLEMENTAL"];

/// What a scoped run drops so its selected parsers start from no previous
/// outputs while unselected parsers keep theirs.
#[derive(Debug, Default)]
struct ScopedReset {
    /// Categories written only by selected parsers: staged empty, replaced live.
    owned: HashSet<&'static str>,
    /// Categories selected parsers share with unselected ones: staged as copies.
    shared: HashSet<&'static str>,
    /// Previous outputs of selected parsers inside `shared` categories.
    files: Vec<PathBuf>,
}

impl ScopedReset {
    /// Live category directories replaced wholesale by this run.
    fn clears(&self, category: &str) -> bool {
        self.owned.contains(category) || RECOMPUTED_CATEGORIES.contains(&category)
    }
}

fn scoped_reset(live_dir: &Path, only: &HashSet<String>) -> Result<ScopedReset> {
    let mut reset = ScopedReset::default();
    let mut owners = Vec::new();
    for &artifact in ARTIFACT_NAMES.iter().filter(|name| only.contains(**name)) {
        let Some(category) = artifact_category(artifact) else {
            continue;
        };
        let shared = ARTIFACT_NAMES.iter().any(|other| {
            !only.contains(*other) && artifact_category(other) == Some(category)
        });
        if !shared {
            reset.owned.insert(category);
            continue;
        }
        reset.shared.insert(category);
        // Nothing published in the category means nothing to attribute.
        let published = match std::fs::read_dir(live_dir.join(category)) {
            Ok(mut entries) => entries.next().is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if published {
            owners.push((artifact, category));
        }
    }
    if owners.is_empty() {
        return Ok(reset);
    }
    let previous = previous_artifact_outputs(live_dir)?;
    for (artifact, category) in owners {
        // Never guess ownership from file names: unknown means full reparse.
        let outputs = previous.get(artifact).with_context(|| {
            format!(
                "{artifact}: no published parse report records its previous {category} outputs; run a full reparse"
            )
        })?;
        for output in outputs {
            let relative = PathBuf::from(output);
            let mut parts = relative.components();
            let inside = matches!(parts.next(), Some(std::path::Component::Normal(first)) if first == category)
                && parts.next().is_some()
                && parts.all(|part| matches!(part, std::path::Component::Normal(_)));
            if !inside {
                anyhow::bail!(
                    "{artifact}: recorded output {output} is outside {category}; run a full reparse"
                );
            }
            reset.files.push(relative);
        }
    }
    Ok(reset)
}

/// Outputs each artifact had in the latest report that published (`ok` or
/// `partial`). Later scoped runs omit unselected artifacts, so every per-run
/// manifest is consulted, plus `parse_report.json` for older hosts.
fn previous_artifact_outputs(
    live_dir: &Path,
) -> Result<std::collections::HashMap<String, Vec<String>>> {
    let mut reports = Vec::new();
    match std::fs::read_dir(live_dir.join(PARSE_LOG_DIRECTORY)) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
                    reports.push(path);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    reports.push(live_dir.join("parse_report.json"));
    let mut latest = std::collections::HashMap::<String, (String, Vec<String>)>::new();
    for path in reports {
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let report: serde_json::Value = serde_json::from_slice(&raw)
            .with_context(|| format!("unreadable parse report {}", path.display()))?;
        if !matches!(report["status"].as_str(), Some("ok" | "partial")) {
            continue;
        }
        let run_at = report["runAt"].as_str().unwrap_or_default();
        for artifact in report["artifacts"].as_array().into_iter().flatten() {
            let Some(name) = artifact["name"].as_str() else {
                continue;
            };
            if latest.get(name).is_some_and(|(seen, _)| seen.as_str() >= run_at) {
                continue;
            }
            let mut outputs: Vec<String> = ["outputs", "publishedOutputs"]
                .iter()
                .flat_map(|key| artifact[*key].as_array().into_iter().flatten())
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect();
            outputs.sort();
            outputs.dedup();
            latest.insert(name.to_string(), (run_at.to_string(), outputs));
        }
    }
    Ok(latest
        .into_iter()
        .map(|(name, (_, outputs))| (name, outputs))
        .collect())
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
/// Scoped runs remove only the selected parsers' recorded files from
/// categories they share with unselected parsers (BROWSER).
/// 취소된 실행은 발행 단계에 오지 않으므로 이전 결과가 유지된다.
fn clear_previous_results(live_dir: &Path, scoped: Option<&ScopedReset>) -> Result<()> {
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
        if scoped.is_some_and(|scoped| !scoped.clears(&name)) {
            continue;
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    if let Some(scoped) = scoped {
        remove_recorded_outputs(live_dir, &scoped.files)?;
    }
    // v1.3.11 이하가 남긴 구 JSON 타임라인 캐시 — 더 이상 만들지도 읽지도
    // 않는다(통합 타임라인은 sqlite 단일 경로). 지운 facts와 어긋난 대용량
    // 산출물이 증거 폴더에 남지 않게 재파싱 때 함께 제거한다.
    let _ = std::fs::remove_file(live_dir.join("_master_timeline.cache.json"));
    // 스트리밍 빌드가 만드는 sqlite 타임라인도 함께 무효화한다(첫 열람 시 재빌드).
    let _ = std::fs::remove_file(live_dir.join("_master_timeline.sqlite"));
    Ok(())
}

fn remove_recorded_outputs(root: &Path, files: &[PathBuf]) -> Result<()> {
    for file in files {
        match std::fs::remove_file(root.join(file)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    Ok(())
}

/// `_OVERVIEW` 안에 파서가 직접 기록하는 원본(raw) 산출물. write_ov 파생이
/// 아니므로 파생 리셋에서 지우면 안 된다 — status=="ok" 발행은 seal본
/// (`.artifact-committed`)을 건너뛰고 스테이징 트리를 그대로 발행하므로,
/// 여기서 지워진 파일은 어디서도 복구되지 않은 채 보고서에만 published로
/// 남는다(전체 실행에서 파일 시스템 뷰가 비는 실제 사고 원인).
/// A scoped run that selects MFT stages `_OVERVIEW` empty instead (MFT owns
/// it alone; see `scoped_reset`), so no previous copy survives a re-run.
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
    scoped: Option<&ScopedReset>,
) -> Result<PathBuf> {
    let staging_root = live_dir.join(PARSE_STAGING_DIRECTORY);
    let stage = staging_root.join(safe_run_id(run_id));
    // One run per host (GUI scheduler): anything else here is an orphan of a
    // killed or crashed run, including `.previous`/`.partial-previous` backups.
    if staging_root.exists() {
        for entry in std::fs::read_dir(&staging_root)? {
            let path = entry?.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
    }
    std::fs::create_dir_all(&stage)?;
    let Some(scoped) = scoped else {
        return Ok(stage);
    };
    for entry in std::fs::read_dir(live_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Selected parsers start from an empty category of their own.
        if !entry.path().is_dir()
            || name == PARSE_LOG_DIRECTORY
            || name == PARSE_STAGING_DIRECTORY
            || name == PARSE_COMMITTED_DIRECTORY
            || scoped.owned.contains(name.as_ref())
        {
            continue;
        }
        copy_tree(
            &entry.path(),
            &stage.join(name.as_ref()),
            scoped.shared.contains(name.as_ref()) || RECOMPUTED_CATEGORIES.contains(&name.as_ref()),
        )?;
    }
    remove_recorded_outputs(&stage, &scoped.files)?;
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

pub(crate) fn append_current_log_lifecycle(message: &str) {
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

fn emit(msg: &str) {
    println!("{}", msg);
    append_current_log_output(msg);
}

/// GUI progress protocol for the overview phase ("[종합 분석 진행] done/total").
pub(crate) fn overview_progress(done: usize, total: usize) {
    emit(&format!("[종합 분석 진행] {done}/{total}"));
}

/// Set by the GUI supervisor: before _OVERVIEW the child announces
/// `OVERVIEW_READY_LINE` (freeing its parse slot) and waits for one stdin line
/// granting an overview slot. Without it (CLI) the build starts directly.
pub const OVERVIEW_GATE_ENV: &str = "WINA_OVERVIEW_GATE";
pub const OVERVIEW_READY_LINE: &str = "[GATE] overview_ready";

fn wait_for_overview_turn() {
    if std::env::var_os(OVERVIEW_GATE_ENV).is_none() {
        return;
    }
    emit("=== _OVERVIEW 대기 ===");
    append_current_log_lifecycle("overview_gate_waiting");
    println!("{OVERVIEW_READY_LINE}");
    // A closed pipe (supervisor gone) also ends the wait.
    let _ = std::io::stdin().read_line(&mut String::new());
    append_current_log_lifecycle("overview_gate_granted");
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
    "Timeline",
    "RecycleBin",
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

pub(crate) fn panic_details(payload: Box<dyn std::any::Any + Send>) -> String {
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

/// 산출물 이름의 중복 회피. 대소문자를 구분하지 않는 파일시스템(macOS·Windows)
/// 에서는 케이스만 다른 이름이 같은 파일이므로, 중복 판정 키를 소문자로 둔다 —
/// 그러지 않으면 `NTUSER.DAT`가 `ntuser.dat`에 조용히 덮여 증거가 사라진다.
fn uniq_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_lowercase()) {
        return base.to_string();
    }
    let mut i = 2;
    loop {
        let n = format!("{}_{}", base, i);
        if taken.insert(n.to_lowercase()) {
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

/// Every supported evidence file under the target, found with the same rules a
/// run would plan with. Parse eligibility (UI-01) reuses this instead of
/// duplicating the rules, so unsupported files never count as new data.
/// Paths and repeated traversal errors are deduplicated across artifacts.
pub fn discover_host_inputs(target: &Path) -> finder::Found {
    let mut found = finder::Found::default();
    let mut seen_paths = HashSet::new();
    let mut seen_errors = HashSet::new();
    for name in ARTIFACT_NAMES {
        let mut hit = discover_artifact_files(name, target);
        if *name == "BrowserCache" {
            // Match the inputs the parser records, not every file named index.
            let candidates = browser_cache::cache_outputs(&hit.paths);
            hit.paths = candidates.outputs.into_iter().map(|(_, path)| path)
                .chain(candidates.rejected.into_iter().map(|(path, _)| path))
                .collect();
        }
        for path in hit.paths {
            if seen_paths.insert(path.clone()) {
                found.paths.push(path);
            }
        }
        for error in hit.errors {
            if seen_errors.insert(error.clone()) {
                found.errors.push(error);
            }
        }
    }
    found
}

/// Only SYSTEM, SOFTWARE, SAM, SECURITY, Amcache.hve and user
/// NTUSER.DAT/UsrClass.dat are parsed; RegBack copies and every other hive are
/// skipped (user decision 2026-10-15).
fn discover_registry_hives(target: &Path) -> finder::Found {
    let (files, errors) = finder::walk_files(target);
    let mut found = finder::Found { paths: Vec::new(), errors };
    for path in files {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let regback = path.strip_prefix(target).unwrap_or(&path).components().any(|part| {
            part.as_os_str().to_string_lossy().eq_ignore_ascii_case("RegBack")
        });
        let known = registry::REG_FILENAMES.iter().chain(&["Amcache.hve"]).any(|n| name.eq_ignore_ascii_case(n))
            || registry::REG_SUFFIXES.iter().any(|suffix| {
                name.get(name.len().saturating_sub(suffix.len())..)
                    .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
            });
        if known && !regback {
            found.paths.push(path);
        }
    }
    found
}

/// Locate one artifact's evidence files under the target. 탐색 중 만난 접근·순회 실패도
/// 함께 반환된다 — 파이프라인이 아티팩트 보고서에 기록해 "발견 0건"과
/// 구분한다.
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
        "Registry" => discover_registry_hives(target),
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
        "Timeline" => timeline::timeline_sources(target),
        "RecycleBin" => recyclebin::recyclebin_sources(target),
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
    Ok(run_unit_or_skip_reason(label, outputs_to_clean, unit)?.ok())
}

/// run_unit_or_skip과 동일하되 건너뛴 사유 문자열을 돌려준다 — 호출자가
/// parse_report 입력 항목에 실패 사유를 남겨 "0건 성공"과 구분되게 한다.
fn run_unit_or_skip_reason<T>(
    label: &str,
    outputs_to_clean: &[&Path],
    unit: impl FnOnce() -> Result<T>,
) -> Result<std::result::Result<T, String>> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(unit));
    match result {
        Ok(Ok(value)) => Ok(Ok(value)),
        Ok(Err(error)) => {
            for output in outputs_to_clean {
                let _ = std::fs::remove_file(output);
            }
            if is_storage_error(&error) {
                return Err(error);
            }
            emit(&format!("[*] 손상된 데이터 건너뜀: {} ({})", label, error));
            Ok(Err(error.to_string()))
        }
        Err(_) => {
            for output in outputs_to_clean {
                let _ = std::fs::remove_file(output);
            }
            emit(&format!("[*] 손상된 데이터 건너뜀: {}", label));
            Ok(Err(format!("파싱 중 내부 오류: {label}")))
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
    // Scoped staging copies prior facts; this artifact owns the whole category.
    // 범위 재파싱에서 이번에 수집되지 않은 지난 실행의 로그가 그대로 발행되면
    // 분석가는 그것을 이번 수집본으로 읽는다.
    let eventlog_dir = out_dir.join("EVENTLOG");
    if eventlog_dir.exists() {
        std::fs::remove_dir_all(&eventlog_dir).with_context(|| {
            format!("이벤트 로그 이전 스테이지 정리: {}", eventlog_dir.display())
        })?;
    }
    let mut outputs = Vec::new();
    // 매니페스트 이름을 선점한다 — 같은 이름의 수집 로그는 EventLogInputs_2로
    // 발행되어 입력 기록이 facts에 덮이지 않는다.
    let mut taken = HashSet::from([eventlog::INPUTS_TABLE.to_lowercase()]);
    let mut input_rows: Vec<Row> = Vec::with_capacity(paths.len() + 1);
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
        let mut row = Row::new();
        row.insert("source_file".into(), p.to_string_lossy().into_owned());
        match run_unit_or_skip_reason(&p.display().to_string(), &[&out], || {
            if is_evt {
                eventlog::parse_evt_stream(p, &out, &name)
            } else {
                eventlog::parse_evtx_stream(p, &out, &name)
            }
        })? {
            Ok(n) => {
                entry_record_input_count(entry, p, n);
                if n > 0 {
                    emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), name));
                }
                outputs.push(relative.clone());
                row.insert("facts_db".into(), relative.clone());
                row.insert("facts_table".into(), name.clone());
                row.insert("status".into(), eventlog::INPUT_STATUS_PARSED.into());
                // corrupted_chunk 격리 행까지 포함한 저장 행 수 — 0건 수집과
                // 읽기 실패를 구분하는 근거다.
                row.insert("row_count".into(), n.to_string());
                row.insert("error".into(), String::new());
            }
            // 건너뛴 원본은 사유 원문과 함께 남긴다 — 실패를 추정하지 않고,
            // 출력이 지워졌으므로 facts 좌표는 비운다.
            Err(reason) => {
                entry_record_input_error(entry, p, &reason);
                row.insert("facts_db".into(), String::new());
                row.insert("facts_table".into(), String::new());
                row.insert("status".into(), eventlog::INPUT_STATUS_READ_FAILED.into());
                row.insert("row_count".into(), "0".into());
                row.insert("error".into(), reason);
            }
        }
        input_rows.push(row);
    }
    // 탐색이 끝났다는 사실 자체를 남긴다. 이 행이 있으면 목록에 없는 채널은
    // "미수집"이고, 매니페스트가 아예 없으면 "이번 결과에 이벤트 로그 실행
    // 기록 없음(알 수 없음)"이다 — 수집 0건에도 기록된다.
    let mut summary = Row::new();
    summary.insert("source_file".into(), String::new());
    summary.insert("facts_db".into(), String::new());
    summary.insert("facts_table".into(), String::new());
    summary.insert(
        "status".into(),
        eventlog::INPUT_STATUS_DISCOVERY_COMPLETE.into(),
    );
    summary.insert("row_count".into(), paths.len().to_string());
    summary.insert("error".into(), String::new());
    input_rows.push(summary);
    write_table(
        &out_dir.join(eventlog::INPUTS_RELATIVE),
        eventlog::INPUTS_TABLE,
        &input_rows,
        eventlog::INPUT_FIELDS,
    )?;
    outputs.push(eventlog::INPUTS_RELATIVE.to_string());
    outputs.sort();
    Ok(outputs)
}

fn parse_registry_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    entry_record_inputs(&mut outcome.entry, paths);
    // Scoped staging copies prior facts; this artifact owns the whole category.
    let registry_dir = out_dir.join("REGISTRY");
    if registry_dir.exists() {
        std::fs::remove_dir_all(&registry_dir)
            .with_context(|| format!("레지스트리 이전 스테이지 정리: {}", registry_dir.display()))?;
    }
    if paths.is_empty() {
        return Ok(Vec::new());
    }
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
    // RegBack and COMPONENTS are never discovered (2026-10-15).
    //
    // 하이브별 트랜잭션 로그 목록은 여기서 한 번만 확정한다(파싱 계획 고정) —
    // 입력 기록·logsDiscovered·실제 파서 입력이 같은 스냅샷을 쓴다 (Amcache와
    // 동일). 각 로그는 복구 로그 입력으로 보고서에 남는다.
    let mut taken = HashSet::from(["registryinputs".to_string()]);
    let mut jobs: Vec<(PathBuf, Vec<PathBuf>, PathBuf, String)> = Vec::new();
    for p in paths {
        // 사용자 하이브는 `<계정>_NTUSER.DAT` 꼴로 발행한다 — 계정마다 같은
        // 파일명이 오므로, 접두가 없으면 하이브끼리 이름이 겹치고 파생 계층도
        // 어느 계정의 값인지 복원하지 못한다.
        let base = registry::output_base_name(p);
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
    let source_failures = Mutex::new(Vec::<(PathBuf, String, bool)>::new());
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
                            failures.push((src.clone(), format!("{}: {}", src.display(), e), storage));
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
    // Corrupted inputs remain visible in both the report and exploration manifest.
    // Storage failures still fail the artifact.
    let failures = source_failures.into_inner().unwrap_or_default();
    outcome
        .registry_hives
        .extend(failures.iter().map(|(source, failure, storage)| RegistryHiveReport {
            source_path: source.to_string_lossy().to_string(),
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
        .filter(|(_, _, storage)| *storage)
        .map(|(_, failure, _)| failure)
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
    let mut input_rows = Vec::with_capacity(outcome.registry_hives.len());
    for (source, logs, _, relative) in &jobs {
        let source_text = source.to_string_lossy();
        let Some(report) = outcome.registry_hives.iter()
            .find(|report| report.source_path == source_text) else { continue };
        let mut row = Row::new();
        row.insert("source_file".into(), source_text.into_owned());
        row.insert("facts_db".into(), relative.clone());
        row.insert("hive_name".into(), source.file_name().unwrap_or_default().to_string_lossy().into_owned());
        row.insert("status".into(), report.status.clone());
        row.insert("row_count".into(), report.row_count.to_string());
        row.insert("error".into(), report.error.clone().unwrap_or_default());
        row.insert("logs_discovered".into(), logs.len().to_string());
        row.insert("logs_applied".into(), report.recovery_log_count.to_string());
        row.insert("log_error".into(), report.recovery_log_apply_error.clone().unwrap_or_default());
        input_rows.push(row);
    }
    const INPUT_FIELDS: &[&str] = &[
        "source_file", "facts_db", "hive_name", "status", "row_count",
        "error", "logs_discovered", "logs_applied", "log_error",
    ];
    let manifest = "REGISTRY/RegistryInputs.sqlite";
    write_table(&out_dir.join(manifest), "RegistryInputs", &input_rows, INPUT_FIELDS)?;
    outputs.push(manifest.to_string());
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
    for (index, p) in paths.iter().enumerate() {
        if cancelled() {
            break;
        }
        let relative = if index == 0 {
            "FILESYSTEM/UsnJrnl_Records.sqlite".to_string()
        } else {
            format!("FILESYSTEM/UsnJrnl_Records_{}.sqlite", index + 1)
        };
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
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    entry_record_inputs(&mut outcome.entry, paths);
    if paths.is_empty() {
        emit("[*] MFT 원본이 없어 이번 실행에서 MFT 결과를 만들지 않았습니다");
        return Ok(Vec::new());
    }
    let relative = "_OVERVIEW/MFT_Records.sqlite";
    let reports = mft::parse_mft_sources(paths, &out_dir.join(relative))?;
    let has_success = reports.iter().any(|source| source.error.is_none());
    let mut total = 0;
    for source in reports {
        total += source.record_count;
        entry_record_input_count(&mut outcome.entry, &source.source, source.record_count);
        if let Some(error) = source.error {
            entry_record_input_error(&mut outcome.entry, &source.source, &error);
            outcome.errors.push(format!("MFT {}: {error}", source.source.display()));
        }
    }
    emit(&format!("[+] {total} rows -> {relative}"));
    if has_success {
        Ok(vec![relative.to_string()])
    } else {
        std::fs::remove_file(out_dir.join(relative))?;
        Ok(Vec::new())
    }
}

fn parse_recyclebin_artifact(
    paths: &[PathBuf],
    out_dir: &Path,
    outcome: &mut ArtifactOutcome,
) -> Result<Vec<String>> {
    entry_record_inputs(&mut outcome.entry, paths);
    // Staged MFT facts: this run's MFT, or the copied prior one on a scoped run.
    let mft_db = out_dir.join("_OVERVIEW/MFT_Records.sqlite");
    let mft = if mft_db.is_file() {
        match recyclebin::mft_resident_sources(&mft_db) {
            Ok(items) => items,
            Err(error) => {
                outcome.errors.push(format!("RecycleBin MFT {}: {error:#}", mft_db.display()));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    if paths.is_empty() && mft.is_empty() {
        return Ok(Vec::new());
    }
    let relative = "RECYCLEBIN/RecycleBin_Records.sqlite";
    let parsed = recyclebin::parse_recyclebin(
        paths,
        &mft,
        &out_dir.join(relative),
        &recyclebin::RecycleBinContext {
            volume_id: None,
            accounts: crate::metadata::account_names_from_facts(out_dir)?,
        },
    )?;
    // One MFT feeds many rows: aggregate per input path.
    let mut per_input = std::collections::BTreeMap::<PathBuf, (usize, Vec<String>)>::new();
    for input in parsed.inputs {
        let slot = per_input.entry(input.path).or_default();
        slot.0 += input.rows;
        slot.1.extend(input.error);
    }
    for (path, (rows, errors)) in per_input {
        entry_record_input_count(&mut outcome.entry, &path, rows);
        if !errors.is_empty() {
            let error = errors.join("; ");
            entry_record_input_error(&mut outcome.entry, &path, &error);
            outcome.errors.push(format!("RecycleBin {}: {error}", path.display()));
        }
    }
    emit(&format!("[+] {} rows -> {}", parsed.rows, relative));
    Ok(vec![relative.to_string()])
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
        match run_unit_or_skip_reason(&p.display().to_string(), &[&out], || {
            srum::parse_srum_stream(p, &out)
        })? {
            Ok(parsed) => {
                let record_count = parsed.tables.iter().map(|(_, count)| *count).sum();
                entry_record_input_count(entry, p, record_count);
                for (t, n) in &parsed.tables {
                    emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), t));
                }
                if !parsed.skipped.is_empty() {
                    let reason = parsed.skipped.join("; ");
                    emit(&format!("[!] {}: {reason}", p.display()));
                    entry_record_input_error(entry, p, &reason);
                }
                outputs.push(relative);
            }
            Err(reason) => entry_record_input_error(entry, p, &reason),
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
        if let Some(count) = run_unit_or_skip("TaskScheduler", &[&out], || {
            write_fixed_table(
                &out,
                taskscheduler::TASK_TABLE,
                rows,
                taskscheduler::TASK_FIELD_ORDER,
            )
        })? {
            emit(&format!("[+] {} rows -> {}", count, out.display()));
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
        if let Some(count) = run_unit_or_skip("WER", &[&out], || {
            write_fixed_table(&out, wer::WER_TABLE, rows, wer::WER_FIELD_ORDER)
        })? {
            emit(&format!("[+] {} rows -> {}", count, out.display()));
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
    let planned: Vec<_> = paths.iter().map(|p| (p, timeline::wal_siblings(p))).collect();
    for (_, sides) in &planned {
        for side in sides {
            entry_record_input(entry, side, true);
        }
    }
    let mut outputs = Vec::new();
    let mut taken = HashSet::new();
    // 계정 하나의 History가 손상돼도 그 계정만 건너뛴다(파싱 실패 == 손상
    // 아티팩트). 이미 저장 완료된 다른 계정 결과는 그대로 발행된다.
    for (p, sides) in planned {
        let acct = Some(browser_cache::account_of(p))
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| "browser".into());
        // 브라우저 판별: 경로 세그먼트 → 내용(내부 스킴) → 미상. 미상이면
        // 브라우저를 주장하지 않고 종전처럼 계정명만 쓴다 — 같은 계정에
        // 여러 History가 있을 때 어느 브라우저인지 산출물 이름에 남기기
        // 위한 것(T8). 원본 경로는 parse_report 입력 목록에 보존된다.
        let browser = browser_cache::browser_of(p).or_else(|| history_content_browser(p));
        let base = match browser {
            Some(browser) => format!("{}_{}", acct, browser),
            None => acct,
        };
        let name = uniq_name(&base, &mut taken);
        let relative = format!("BROWSER/{}.sqlite", name);
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<browser_history::HistoryParse> {
            // 테이블 단위 스트리밍 기록 — 전체 행을 메모리에 쌓지 않는다.
            let parsed = browser_history::parse_history_stream(p, &sides, &out)?;
            if parsed.wrote {
                crate::browser_input::write_input(&out,
                    &crate::browser_input::BrowserInput::from_source(p, "history", browser))?;
                emit(&format!("[+] {} rows -> {}", parsed.rows, out.display()));
            }
            Ok(parsed)
        })?;
        if let Some(parsed) = unit {
            let wrote = parsed.wrote;
            entry_record_input_count(entry, p, parsed.rows);
            if !parsed.table_errors.is_empty() {
                let reason = format!("테이블 읽기 실패: {}", parsed.table_errors.join("; "));
                emit(&format!("[!] {}: {reason}", p.display()));
                entry_record_input_error(entry, p, &reason);
            }
            if wrote {
                if let Ok(conn) = rusqlite::Connection::open(&out) {
                    // 방문 이동 그래프의 요구식 조회(id·부모·자식·URL 탐색)용
                    // 인덱스 — idx_mft_children과 같은 파싱 시점 인덱스 선례.
                    // 대상 테이블이 없는 산출물(스키마 변형)에서는 실패해도
                    // 조회가 테이블 스캔으로 동작하므로 best-effort.
                    if let Err(error) = conn.execute_batch(
                        "CREATE INDEX IF NOT EXISTS idx_visits_id ON visits(id);\n                         CREATE INDEX IF NOT EXISTS idx_visits_from ON visits(from_visit);\n                         CREATE INDEX IF NOT EXISTS idx_visits_opener ON visits(opener_visit);\n                         CREATE INDEX IF NOT EXISTS idx_visits_url ON visits(url);\n                         CREATE INDEX IF NOT EXISTS idx_urls_id ON urls(id);\n                         CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(url);",
                    ) {
                        emit(&format!(
                            "[*] History 인덱스 생성 건너뜀 {}: {error}",
                            out.display()
                        ));
                    }
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
            let count = writer.finish()?;
            if count > 0 {
                crate::browser_input::write_input(&out,
                    &crate::browser_input::BrowserInput::from_source(&index_path, "cache", None))?;
            }
            Ok(count)
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
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<(usize, usize)> {
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
            let counts = ie_webcache::parse_webcache(p, &acct, &mut |event| match event {
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
            if total > 0 {
                crate::browser_input::write_input(&out,
                    &crate::browser_input::BrowserInput::from_source(p, "ie_webcache", Some("IE")))?;
            }
            Ok((total, counts.skipped_records))
        })?;
        if let Some((_, skipped)) = unit.filter(|(_, skipped)| *skipped > 0) {
            let reason = format!("읽기 실패 레코드 {skipped}건");
            emit(&format!("[!] {}: {reason}", p.display()));
            entry_record_input_error(entry, p, &reason);
        }
        match unit.map(|(count, _)| count) {
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
    let mut taken = HashSet::new();
    for p in paths {
        let acct = ie_webcache::ie_account(p);
        let name = uniq_name(&format!("{acct}_IE_IndexDat"), &mut taken);
        let relative = format!("BROWSER/{name}.sqlite");
        let out = out_dir.join(&relative);
        let unit = run_unit_or_skip(&p.display().to_string(), &[&out], || -> Result<usize> {
            let mut writer = crate::sqlite::StreamWriter::create(
                &out,
                ie_indexdat::TABLE,
                ie_indexdat::FIELD_ORDER,
                ie_indexdat::FIELD_ORDER,
            )?;
            ie_indexdat::parse_index_dat(p, &acct, &mut |row| writer.push(row))?;
            let count = writer.finish()?;
            if count > 0 {
                crate::browser_input::write_input(&out,
                    &crate::browser_input::BrowserInput::from_source(p, "ie_indexdat", Some("IE")))?;
            }
            Ok(count)
        })?;
        if let Some(count) = unit {
            entry_record_input_count(entry, p, count);
            if count == 0 {
                let _ = std::fs::remove_file(&out);
            } else {
                emit(&format!("[+] {} rows -> {}", count, out.display()));
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
        let unit = run_unit_or_skip("PowerShell", &[&out], || -> Result<powershell_history::ConsoleHistory> {
            let parsed = powershell_history::parse_console_history(paths)?;
            write_table(
                &out,
                powershell_history::PS_TABLE,
                &parsed.rows,
                powershell_history::PS_FIELD_ORDER,
            )?;
            Ok(parsed)
        })?;
        if let Some(parsed) = unit {
            entry_record_rows_by_source(entry, &parsed.rows);
            for (path, reason) in &parsed.unreadable {
                emit(&format!("[!] {}: 읽기 실패: {reason}", path.display()));
                entry_record_input_error(entry, path, &format!("읽기 실패: {reason}"));
            }
            emit(&format!("[+] {} rows -> {}", parsed.rows.len(), out.display()));
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
        "MFT" => parse_mft_artifact(paths, out_dir, outcome),
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
        "Timeline" => parse_timeline_artifact(paths, out_dir, &mut outcome.entry),
        "RecycleBin" => parse_recyclebin_artifact(paths, out_dir, outcome),
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
    dataset_id: &str,
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
        let outputs = parse_artifact_sources(name, paths, out_dir, &mut outcome)?;
        for output in &outputs {
            let path = out_dir.join(output);
            if path.extension().is_some_and(|extension| extension == "sqlite") {
                crate::derived::stamp_facts_generation(&path, dataset_id)?;
            }
        }
        Ok::<_, anyhow::Error>(outputs)
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
    let dataset_id = uuid::Uuid::new_v4().to_string();
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
    // Ownership is resolved before staging so an unknown owner fails safe.
    let staged = only
        .as_ref()
        .map(|only| scoped_reset(&live_dir, only))
        .transpose()
        .and_then(|scoped| {
            let stage = prepare_staging_output(&live_dir, &run_id, scoped.as_ref())?;
            Ok((stage, scoped))
        });
    let (out_dir, scoped) = match staged {
        Ok(staged) => staged,
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
    // Serialize shared browser DB writes. RecycleBin reads Registry SIDs and
    // staged MFT facts, so it runs after every other parser.
    let mut chains: Vec<Vec<&'static str>> = Vec::new();
    for &name in &wanted {
        if name == "RecycleBin" {
            continue;
        }
        let prerequisite = match name {
            "BrowserCache" => Some("BrowserHistory"),
            _ => None,
        };
        if let Some(prerequisite) = prerequisite {
            if let Some(chain) = chains
                .iter_mut()
                .find(|chain| chain.contains(&prerequisite))
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
                        let outcome = run_artifact_job(name, paths, discovery_errors, &out_dir, &dataset_id);
                        let mut collected = outcomes
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        collected.push(outcome);
                    }
                });
            }
        });
    }
    if wanted.contains(&"RecycleBin") {
        let (paths, discovery_errors): (&[PathBuf], &[String]) = discovered
            .get("RecycleBin")
            .map(|found| (found.paths.as_slice(), found.errors.as_slice()))
            .unwrap_or((&[], &[]));
        let outcome = run_artifact_job("RecycleBin", paths, discovery_errors, &out_dir, &dataset_id);
        outcomes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(outcome);
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
    let mut overview_reset_failed = false;
    if !cancelled() {
        wait_for_overview_turn();
        emit("=== _OVERVIEW ===");
        append_current_log_lifecycle("overview_started");
        let ov = out_dir.join("_OVERVIEW");
        // A stage that cannot be reset would mix generations: fail the run but
        // still write the terminal report, host status and cleanup below.
        let reset_result = reset_stage_overview(&ov);
        overview_reset_failed = reset_result.is_err();
        let overview_result = reset_result.and_then(|()| {
            let ancillary = crate::derived::prepare_ancillary_facts(&out_dir, &target, &dataset_id)?;
            sealed_outputs.extend(seal_artifact_outputs(&out_dir, "Supplemental", &ancillary)?);
            crate::derived::build_all(&out_dir, &target, host_id, &dataset_id)
        });
        match overview_result {
            Ok(build) => {
                for (name, row_count) in build.tables {
                    emit(&format!("[+] {row_count} rows -> {}", ov.join(format!("{name}.sqlite")).display()));
                    report.overview.push(OverviewTableReport { name, row_count });
                }
                // Skipped unreadable inputs keep the overview but make the run partial.
                for error in &build.input_errors {
                    had_error = true;
                    report.errors.push(format!("_OVERVIEW: {error}"));
                    emit(&format!("[!] _OVERVIEW input skipped: {error}"));
                }
                append_current_log_lifecycle(if build.input_errors.is_empty() {
                    "overview_finished status=completed"
                } else {
                    "overview_finished status=partial"
                });
            }
            Err(error) => {
                had_error = true;
                // `{:#}` keeps the cause chain; the outer context alone names only the task.
                report.errors.push(format!("_OVERVIEW: {error:#}"));
                emit(&format!("[!] _OVERVIEW failed: {error:#}"));
                append_current_log_lifecycle(&format!(
                    "overview_finished status=failed error={error:#}"
                ));
            }
        }
        // Seal the freshly-built correlation tables so a partial run (some raw
        // artifact failed) still publishes them through the per-file path. On a
        // clean run they publish with the rest of the staging tree instead.
        let mut overview_outputs: Vec<String> = report
            .overview
            .iter()
            .map(|table| format!("_OVERVIEW/{}.sqlite", table.name))
            .collect();
        if !wanted.contains(&"MFT") && ov.join("MFT_Records.sqlite").is_file() {
            overview_outputs.push("_OVERVIEW/MFT_Records.sqlite".to_string());
        }
        match seal_artifact_outputs(&out_dir, "_OVERVIEW", &overview_outputs) {
            Ok(sealed) => sealed_outputs.extend(sealed),
            Err(error) => {
                had_error = true;
                report.errors.push(format!("_OVERVIEW seal: {error}"));
                emit(&format!("[!] _OVERVIEW seal failed: {error}"));
            }
        }
    } else {
        emit("=== 취소됨 — 종합 분석 건너뜀 ===");
        append_current_log_lifecycle("overview_finished status=cancelled");
    }

    let run_at = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();

    let mut status = if cancelled() {
        "cancelled"
    } else if overview_reset_failed {
        "error"
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
    // 실패 아티팩트의 이전 결과도 함께 지운다 — 남은 것은 항상 이번 실행
    // 한 시점의 산출물뿐이다(실패 = 손상·오수집 원본 판정, 보고서에 기록).
    // A prior result that cannot be removed would mix generations under the
    // new status, so the run becomes an error and nothing is published.
    if status == "ok" || status == "partial" {
        if let Err(error) = clear_previous_results(&live_dir, scoped.as_ref()) {
            status = "error";
            report.status = status.to_string();
            report.errors.push(format!("clear previous results: {error}"));
            emit(&format!("[!] clear previous results failed: {error}"));
            append_current_log_lifecycle(&format!("clear_previous_results_failed error={error}"));
        }
    }
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

#[cfg(test)]
mod persistent_log_tests {
    use super::*;

    // These tests exercise the process-global worker log sink. The GUI runs
    // hosts in separate child processes, but unit tests share this process, so
    // serialize only this fixture to avoid cross-test log routing.
    static PIPELINE_LOG_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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
    fn indexdat_sources_with_the_same_account_remain_separate_inputs() {
        let _guard = PIPELINE_LOG_TEST_LOCK.lock();
        let root = temporary_directory("indexdat-inputs");
        let mut bytes = vec![0u8; 0x180];
        let magic = b"Client UrlCache MMF Ver 5.2\0";
        bytes[..magic.len()].copy_from_slice(magic);
        bytes[0x80..0x84].copy_from_slice(b"REDR");
        bytes[0x84..0x88].copy_from_slice(&1u32.to_le_bytes());
        let url = b"https://example.test/";
        bytes[0x90..0x90 + url.len()].copy_from_slice(url);
        let paths: Vec<_> = ["History.IE5", "Content.IE5"].iter()
            .map(|folder| root.join("BROWSER/analyst/IE").join(folder).join("index.dat"))
            .collect();
        for path in &paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &bytes).unwrap();
        }
        let out = root.join("output");
        let mut outcome = ArtifactOutcome::new("IEIndexDat");
        let outputs = parse_ie_indexdat_artifact(&paths, &out, &mut outcome.entry).unwrap();
        assert_eq!(outputs.len(), 2);
        for (relative, source) in outputs.iter().zip(&paths) {
            let conn = rusqlite::Connection::open(out.join(relative)).unwrap();
            let input = crate::browser_input::read_input(&conn).unwrap();
            assert_eq!(input.source_file.as_deref(), source.to_str());
            assert_eq!(input.account_label.as_deref(), Some("analyst"));
            assert_eq!(conn.query_row("SELECT count(*) FROM IEIndexDat_Records", [],
                |row| row.get::<_, i64>(0)).unwrap(), 1);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    /// 유효하지만 레코드가 하나도 없는 XP .evt — 0x30 헤더 + EOF(커서) 레코드.
    /// "수집은 됐지만 이벤트 0건"인 실제 입력을 만든다.
    fn empty_evt_bytes() -> Vec<u8> {
        fn put(buffer: &mut [u8], offset: usize, value: u32) {
            buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut data = vec![0u8; 0x30];
        put(&mut data, 0x00, 0x30);
        put(&mut data, 0x04, 0x654c_664c); // "LfLe"
        put(&mut data, 0x08, 1);
        put(&mut data, 0x0C, 1);
        put(&mut data, 0x10, 0x30); // StartOffset
        put(&mut data, 0x20, 0x58); // 파일 길이
        put(&mut data, 0x2C, 0x30);
        let mut eof = vec![0u8; 0x28];
        put(&mut eof, 0x00, 0x28);
        for (index, magic) in [0x1111_1111u32, 0x2222_2222, 0x3333_3333, 0x4444_4444]
            .iter()
            .enumerate()
        {
            put(&mut eof, 4 + index * 4, *magic);
        }
        put(&mut eof, 0x14, 0x30); // BeginRecord
        put(&mut eof, 0x24, 0x28);
        data.extend(eof);
        data
    }

    fn manifest_row(
        connection: &rusqlite::Connection,
        status: &str,
    ) -> (String, String, String, String, String) {
        connection
            .query_row(
                "SELECT source_file,facts_db,facts_table,row_count,error FROM EventLogInputs \
                 WHERE status=?1",
                [status],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap_or_else(|error| panic!("{status} manifest row: {error}"))
    }

    /// A04: 수집된 빈 로그·읽기 실패·미수집을 저장에서 구분할 수 있어야 한다.
    /// 0건으로 파싱된 입력은 facts 좌표와 함께 parsed, 열지 못한 입력은 사유
    /// 원문과 함께 read_failed, 목록에 없는 채널은 미수집으로 읽힌다.
    #[test]
    fn eventlog_manifest_separates_empty_logs_from_read_failures() {
        let _guard = PIPELINE_LOG_TEST_LOCK.lock();
        let root = temporary_directory("eventlog-manifest");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let empty = target.join("SysEvent.Evt");
        let unreadable = target.join("AppEvent.Evt");
        std::fs::write(&empty, empty_evt_bytes()).unwrap();
        std::fs::write(&unreadable, b"not an event log").unwrap();
        let out = root.join("output");
        let mut outcome = ArtifactOutcome::new("EventLog");

        let outputs = parse_eventlog_artifact(
            &[empty.clone(), unreadable.clone()],
            &out,
            &mut outcome.entry,
        )
        .unwrap();

        assert_eq!(
            outputs,
            vec![
                "EVENTLOG/EventLogInputs.sqlite".to_string(),
                "EVENTLOG/SysEvent.sqlite".to_string(),
            ],
            "읽지 못한 로그는 발행되지 않고, 매니페스트는 항상 발행된다"
        );
        assert!(!out.join("EVENTLOG/AppEvent.sqlite").exists());
        let manifest =
            rusqlite::Connection::open(out.join("EVENTLOG/EventLogInputs.sqlite")).unwrap();
        let parsed = manifest_row(&manifest, "parsed");
        assert_eq!(parsed.0, empty.to_string_lossy());
        assert_eq!(parsed.1, "EVENTLOG/SysEvent.sqlite");
        assert_eq!(parsed.2, "SysEvent");
        assert_eq!(parsed.3, "0", "수집된 빈 로그는 0건 파싱으로 남는다");
        assert_eq!(parsed.4, "");
        let failed = manifest_row(&manifest, "read_failed");
        assert_eq!(failed.0, unreadable.to_string_lossy());
        assert_eq!(failed.1, "");
        assert_eq!(failed.2, "");
        assert_eq!(failed.3, "0");
        assert!(
            !failed.4.is_empty(),
            "읽기 실패는 사유 원문을 잃지 않는다"
        );
        let discovery = manifest_row(&manifest, "discovery_complete");
        assert_eq!(
            (
                discovery.0.as_str(),
                discovery.1.as_str(),
                discovery.2.as_str()
            ),
            ("", "", "")
        );
        assert_eq!(discovery.3, "2", "요약 행은 발견한 입력 수를 남긴다");
        let listed: i64 = manifest
            .query_row(
                "SELECT COUNT(*) FROM EventLogInputs WHERE source_file LIKE '%Security.evtx'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(listed, 0, "수집되지 않은 채널은 매니페스트에 없다");
        drop(manifest);
        // 실패한 입력은 보고서에서도 "0건 성공"과 구분된다.
        let failed_input = outcome
            .entry
            .inputs
            .iter()
            .find(|input| input.source_path == unreadable.to_string_lossy())
            .expect("실패 입력 보고");
        assert!(failed_input.error.as_deref().is_some_and(|e| !e.is_empty()));
        // Keywords는 저장 스키마에 남는다(이벤트 0건이어도 컬럼은 존재).
        let facts = rusqlite::Connection::open(out.join("EVENTLOG/SysEvent.sqlite")).unwrap();
        assert!(
            facts.prepare("SELECT Keywords FROM SysEvent").is_ok(),
            "Keywords 컬럼이 저장 스키마에 있어야 한다"
        );
        drop(facts);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// 입력이 하나도 없어도 "이번 실행에서 탐색은 끝났다"는 근거를 남겨야
    /// 미수집과 미실행(매니페스트 없음)을 구분할 수 있다.
    #[test]
    fn eventlog_without_inputs_still_writes_a_discovery_manifest() {
        let _guard = PIPELINE_LOG_TEST_LOCK.lock();
        let root = temporary_directory("eventlog-no-input");
        let out = root.join("output");
        let mut outcome = ArtifactOutcome::new("EventLog");

        let outputs = parse_eventlog_artifact(&[], &out, &mut outcome.entry).unwrap();

        assert_eq!(outputs, vec!["EVENTLOG/EventLogInputs.sqlite".to_string()]);
        let manifest =
            rusqlite::Connection::open(out.join("EVENTLOG/EventLogInputs.sqlite")).unwrap();
        let rows: i64 = manifest
            .query_row("SELECT COUNT(*) FROM EventLogInputs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(manifest_row(&manifest, "discovery_complete").3, "0");
        drop(manifest);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// 매니페스트와 같은 이름의 로그가 수집돼도 입력 기록이 덮이지 않는다.
    #[test]
    fn eventlog_manifest_name_is_reserved_against_a_collected_log() {
        let _guard = PIPELINE_LOG_TEST_LOCK.lock();
        let root = temporary_directory("eventlog-reserved");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let collision = target.join("EventLogInputs.Evt");
        std::fs::write(&collision, empty_evt_bytes()).unwrap();
        let out = root.join("output");
        let mut outcome = ArtifactOutcome::new("EventLog");

        parse_eventlog_artifact(&[collision], &out, &mut outcome.entry).unwrap();

        let manifest =
            rusqlite::Connection::open(out.join("EVENTLOG/EventLogInputs.sqlite")).unwrap();
        let parsed = manifest_row(&manifest, "parsed");
        assert_eq!(parsed.1, "EVENTLOG/EventLogInputs_2.sqlite");
        assert_eq!(parsed.2, "EventLogInputs_2");
        drop(manifest);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registry_discovery_keeps_only_the_selected_hives() {
        let root = temporary_directory("registry-discovery");
        std::fs::create_dir_all(root.join("RegBack")).unwrap();
        std::fs::create_dir_all(root.join("Users/admin")).unwrap();
        let mut header = [0u8; 32];
        header[..4].copy_from_slice(b"regf");
        // Only SYSTEM/SOFTWARE/SAM/SECURITY and user hives (user decision 2026-10-15).
        for name in ["COMPONENTS", "DEFAULT", "DRIVERS", "BCD-Template", "ELAM", "BBI", "renamed-evidence.bin", "Amcache.hve",
                     "RegBack/SYSTEM", "SAM", "SECURITY", "SYSTEM", "Users/admin/NTUSER.DAT", "Users/admin/UsrClass.dat"] {
            std::fs::write(root.join(name), header).unwrap();
        }
        std::fs::write(root.join("SOFTWARE"), b"corrupt").unwrap();
        std::fs::write(root.join("unrelated.txt"), b"not a hive").unwrap();
        let found = discover_artifact_files("Registry", &root);
        let mut relative: Vec<_> = found.paths.iter().map(|p| p.strip_prefix(&root).unwrap().to_path_buf()).collect();
        relative.sort();
        let mut expected: Vec<_> = ["Amcache.hve", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "Users/admin/NTUSER.DAT", "Users/admin/UsrClass.dat"]
            .iter().map(PathBuf::from).collect();
        expected.sort();
        assert_eq!(relative, expected);
        assert!(found.errors.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_mft_inputs_leave_no_publishable_empty_database() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("failed-mft-inputs");
        std::fs::create_dir_all(&root).unwrap();
        let sources = [root.join("first-MFT"), root.join("second-MFT")];
        for source in &sources {
            std::fs::write(source, b"not an MFT").unwrap();
        }
        let output = root.join("output");
        let outcome = run_artifact_job("MFT", &sources, &[], &output, "fixture-generation");
        assert_eq!(outcome.errors.len(), 2);
        assert_eq!(outcome.entry.inputs.len(), 2);
        assert!(outcome.entry.inputs.iter().all(|input| input.error.is_some()));
        assert!(outcome.sealed.is_empty());
        assert!(!output.join("_OVERVIEW/MFT_Records.sqlite").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recyclebin_retains_valid_metadata_when_another_input_is_corrupt() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("recyclebin-inputs");
        std::fs::create_dir_all(&root).unwrap();
        let good = root.join("$Igood.txt");
        let bad = root.join("$Ibad.txt");
        let name: Vec<u16> = "C:\\temp\\file.txt\0".encode_utf16().collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&128u64.to_le_bytes());
        bytes.extend_from_slice(&133000000000000000u64.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        for value in name {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        std::fs::write(&good, bytes).unwrap();
        std::fs::write(&bad, b"broken").unwrap();
        let output = root.join("output");
        let outcome = run_artifact_job("RecycleBin", &[good.clone(), bad.clone()], &[], &output, "fixture-generation");
        assert!(!outcome.errors.is_empty());
        assert_eq!(outcome.sealed.len(), 1);
        let db = rusqlite::Connection::open(
            output.join("RECYCLEBIN/RecycleBin_Records.sqlite"),
        ).unwrap();
        let record: (String, i64, i64) = db.query_row(
            "SELECT original_path, file_size, r_exists FROM RecycleBin_Records WHERE _source_file=?1",
            [good.to_string_lossy().as_ref()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(record, ("C:\\temp\\file.txt".to_string(), 128, 0));
        let failed: String = db.query_row(
            "SELECT _status FROM RecycleBin_Records WHERE _source_file=?1",
            [bad.to_string_lossy().as_ref()], |row| row.get(0),
        ).unwrap();
        assert_eq!(failed, "corrupted");
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recyclebin_parses_resident_mft_dollar_i_without_collected_files() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("recyclebin-mft");
        let output = root.join("output");
        let mft_path = output.join("_OVERVIEW/MFT_Records.sqlite");
        mft::parse_mft_sources(&[], &mft_path).unwrap();
        let name: Vec<u16> = "C:\\temp\\file.txt\0".encode_utf16().collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&128u64.to_le_bytes());
        bytes.extend_from_slice(&133000000000000000u64.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        for value in name {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        rusqlite::Connection::open(&mft_path).unwrap().execute(
            "INSERT INTO MFT_Records(volume_id, path, file_name, is_directory, in_use, file_size, data, entry, seq, data_status, _source_file) \
             VALUES ('vol', '\\$Recycle.Bin\\S-1-5-21-1-2-3-500\\$IAB.txt', '$IAB.txt', 0, 1, ?1, ?2, 7, 1, 'resident', 'evidence-MFT')",
            rusqlite::params![bytes.len() as i64, bytes],
        ).unwrap();
        let outcome = run_artifact_job("RecycleBin", &[], &[], &output, "fixture-generation");
        assert_eq!(outcome.entry.status, "completed", "{:?}", outcome.errors);
        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.entry.inputs.len(), 1);
        assert_eq!(outcome.entry.inputs[0].source_path, "evidence-MFT");
        assert_eq!(outcome.entry.inputs[0].record_count, 1);
        let db = rusqlite::Connection::open(output.join("RECYCLEBIN/RecycleBin_Records.sqlite")).unwrap();
        let record: (String, i64) = db.query_row(
            "SELECT original_path, mft_entry FROM RecycleBin_Records", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(record, ("C:\\temp\\file.txt".to_string(), 7));
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// 대소문자를 구분하지 않는 파일시스템에서 케이스만 다른 산출물이 서로를
    /// 덮어쓰지 않아야 한다 — `NTUSER.DAT`/`ntuser.dat`가 한 파일로 합쳐지면
    /// 하이브 하나가 통째로 사라진다.
    #[test]
    fn output_names_do_not_collide_on_case_insensitive_filesystems() {
        let mut taken = HashSet::new();
        assert_eq!(uniq_name("NTUSER.DAT", &mut taken), "NTUSER.DAT");
        assert_eq!(uniq_name("ntuser.dat", &mut taken), "ntuser.dat_2");
        assert_eq!(uniq_name("NTUSER.DAT", &mut taken), "NTUSER.DAT_3");
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
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
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
        let only = HashSet::from(["Registry".to_string()]);
        let scoped = scoped_reset(&live, &only).unwrap();

        // Registry owns REGISTRY alone, so its stage starts empty.
        let failed_stage = prepare_staging_output(&live, "failed-run", Some(&scoped)).unwrap();
        assert!(!failed_stage.join("REGISTRY").exists());
        std::fs::create_dir_all(failed_stage.join("REGISTRY")).unwrap();
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

        let success_stage = prepare_staging_output(&live, "success-run", Some(&scoped)).unwrap();
        std::fs::create_dir_all(success_stage.join("REGISTRY")).unwrap();
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
    fn new_stage_sweeps_orphans_of_killed_runs() {
        let root = temporary_directory("staging-orphans");
        let live = root.join("host");
        let staging = live.join(PARSE_STAGING_DIRECTORY);
        std::fs::create_dir_all(staging.join("killed-run/_OVERVIEW")).unwrap();
        std::fs::create_dir_all(staging.join("killed-run.previous/REGISTRY")).unwrap();
        std::fs::create_dir_all(staging.join("killed-run.partial-previous")).unwrap();
        let stage = prepare_staging_output(&live, "next-run", None).unwrap();
        let left: Vec<_> = std::fs::read_dir(&staging)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let _ = std::fs::remove_dir_all(root);
        assert_eq!(left, vec![stage.file_name().unwrap().to_owned()]);
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
        let scoped = scoped_reset(&live, &only).unwrap();
        let stage = prepare_staging_output(&live, "scoped-ov", Some(&scoped)).unwrap();
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
        clear_previous_results(&live, Some(&scoped_reset(&live, &only).unwrap())).unwrap();
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
    fn scoped_partial_run_preserves_retained_mft_facts_and_generation() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("partial-retained-mft");
        let cases = root.join("cases");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("$IBROKEN.txt"), b"corrupt").unwrap();
        let case = case_store::create_case("case", "2026-10-07 00:00:00", &cases).unwrap();
        let host = case_store::create_host(&case.id, "host", &target.to_string_lossy(), "2026-10-07 00:00:00", &cases).unwrap();
        let live = case_store::host_dir(&cases, &case.id, &host.id);
        let mft_path = live.join("_OVERVIEW/MFT_Records.sqlite");
        mft::parse_mft_sources(&[], &mft_path).unwrap();
        let db = rusqlite::Connection::open(&mft_path).unwrap();
        db.execute(
            "INSERT INTO MFT_Records(volume_id, file_name, file_size, data, entry, seq, _source_file) VALUES ('volume', 'retained.txt', 0, X'', 42, 1, 'evidence-MFT')",
            [],
        ).unwrap();
        drop(db);
        crate::derived::stamp_facts_generation(&mft_path, "prior-generation").unwrap();
        let only = HashSet::from(["RecycleBin".to_string()]);
        assert!(run_host_with_log_id(&case.id, &host.id, &cases, Some(only), Some("partial-reparse")).is_err());
        assert!(mft_path.is_file(), "retained facts must survive partial publication");
        assert_eq!(crate::derived::facts_dataset_id(&mft_path).unwrap(), "prior-generation");
        let db = rusqlite::Connection::open(live.join("_OVERVIEW/FileSystemEntries.sqlite")).unwrap();
        let source: (String, i64) = db.query_row(
            "SELECT source_dataset_id, source_rowid FROM source_records", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(source, ("prior-generation".to_string(), 1));
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_selected_artifact_persists_no_input_in_terminal_report() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
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

    fn scoped_browser_fixture(label: &str) -> (PathBuf, String, String, PathBuf, PathBuf) {
        let root = temporary_directory(label);
        let cases_dir = root.join("cases");
        let profile = root.join("target/Users/alice/AppData/Local/Microsoft/Edge/User Data/Default");
        std::fs::create_dir_all(&profile).unwrap();
        let history = profile.join("History");
        rusqlite::Connection::open(&history)
            .unwrap()
            .execute_batch(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls VALUES (1, 'https://fresh.example/');",
            )
            .unwrap();
        let case = case_store::create_case("case", "2026-10-13 00:00:00", &cases_dir).unwrap();
        let host = case_store::create_host(
            &case.id,
            "host",
            &root.join("target").to_string_lossy(),
            "2026-10-13 00:00:00",
            &cases_dir,
        )
        .unwrap();
        let live = case_store::host_dir(&cases_dir, &case.id, &host.id);
        // Previous publication: this History's output carrying a table the
        // current parser no longer writes, an output whose History is gone,
        // and BrowserCache's own file in the same category.
        let name = format!(
            "{}_{}",
            browser_cache::account_of(&history),
            browser_cache::browser_of(&history).unwrap()
        );
        let browser = live.join("BROWSER");
        std::fs::create_dir_all(&browser).unwrap();
        rusqlite::Connection::open(browser.join(format!("{name}.sqlite")))
            .unwrap()
            .execute_batch(
                "CREATE TABLE urls (id TEXT, url TEXT);
                 INSERT INTO urls VALUES ('1', 'https://stale.example/');
                 CREATE TABLE _wina_source (source_file TEXT);",
            )
            .unwrap();
        let bob = browser.join("bob_Edge.sqlite");
        rusqlite::Connection::open(&bob)
            .unwrap()
            .execute_batch("CREATE TABLE urls (id TEXT, url TEXT);")
            .unwrap();
        crate::browser_input::write_input(
            &bob,
            &crate::browser_input::BrowserInput::from_source(
                Path::new("/evidence/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History"),
                "history",
                None,
            ),
        )
        .unwrap();
        let cache = browser.join("alice_Edge_Cache.sqlite");
        crate::sqlite::StreamWriter::create(
            &cache,
            browser_cache::CACHE_TABLE,
            browser_cache::CACHE_FIELD_ORDER,
            browser_cache::CACHE_FIELD_ORDER,
        )
        .unwrap()
        .finish()
        .unwrap();
        crate::browser_input::write_input(
            &cache,
            &crate::browser_input::BrowserInput::from_source(
                Path::new("/evidence/Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Cache/Cache_Data/index"),
                "cache",
                None,
            ),
        )
        .unwrap();
        crate::derived::stamp_facts_generation(&bob, "prior-generation").unwrap();
        crate::derived::stamp_facts_generation(&cache, "prior-generation").unwrap();
        (root, case.id, host.id, live, browser.join(format!("{name}.sqlite")))
    }

    #[test]
    fn scoped_browser_history_rerun_drops_only_its_previous_outputs() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let (root, case_id, host_id, live, current) = scoped_browser_fixture("scoped-browser-stale");
        let current_relative = format!(
            "BROWSER/{}",
            current.file_name().unwrap().to_string_lossy()
        );
        let previous = serde_json::json!({
            "runId": "previous", "runAt": "2026-10-13 16:13:18.000", "status": "ok",
            "published": true,
            "artifacts": [
                {"name": "BrowserHistory", "status": "completed",
                 "outputs": [current_relative, "BROWSER/bob_Edge.sqlite"],
                 "publishedOutputs": [current_relative, "BROWSER/bob_Edge.sqlite"]},
                {"name": "BrowserCache", "status": "completed",
                 "outputs": ["BROWSER/alice_Edge_Cache.sqlite"],
                 "publishedOutputs": ["BROWSER/alice_Edge_Cache.sqlite"]}
            ]
        });
        std::fs::write(live.join("parse_report.json"), previous.to_string()).unwrap();
        let cases_dir = root.join("cases");
        let only = HashSet::from(["BrowserHistory".to_string()]);

        let result = run_host_with_log_id(&case_id, &host_id, &cases_dir, Some(only), Some("scoped-browser"));
        let report = std::fs::read_to_string(live.join("parse_report.json")).unwrap();
        assert!(result.is_ok(), "{report}");

        let db = rusqlite::Connection::open(&current).unwrap();
        let tables: Vec<String> = db
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!tables.iter().any(|table| table == "_wina_source"), "{tables:?}");
        let urls: Vec<String> = db
            .prepare("SELECT url FROM urls")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(urls, ["https://fresh.example/"]);
        drop(db);
        assert!(!live.join("BROWSER/bob_Edge.sqlite").exists());
        assert!(live.join("BROWSER/alice_Edge_Cache.sqlite").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scoped_browser_rerun_without_ownership_record_fails_and_keeps_live() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let (root, case_id, host_id, live, current) = scoped_browser_fixture("scoped-browser-unknown");
        let cases_dir = root.join("cases");
        let only = HashSet::from(["BrowserHistory".to_string()]);

        let result = run_host_with_log_id(&case_id, &host_id, &cases_dir, Some(only), Some("scoped-unknown"));

        assert!(result.is_err());
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(live.join("parse_report.json")).unwrap()).unwrap();
        assert_eq!(report["status"], "error");
        assert!(report["errors"][0].as_str().unwrap().contains("BrowserHistory"), "{report}");
        // Nothing was guessed away from the published tree.
        assert!(current.is_file());
        assert!(live.join("BROWSER/bob_Edge.sqlite").is_file());
        assert!(live.join("BROWSER/alice_Edge_Cache.sqlite").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    /// An unreadable SRUM facts DB skipped by Metadata must surface in the
    /// terminal report and make the run partial, not silently `ok`.
    #[test]
    fn unreadable_srum_facts_db_makes_run_partial_with_reported_error() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("srum-metadata-error");
        let cases_dir = root.join("cases");
        let target_dir = root.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        let case = case_store::create_case("case", "2026-10-13 00:00:00", &cases_dir).unwrap();
        let host = case_store::create_host(
            &case.id,
            "host",
            &target_dir.to_string_lossy(),
            "2026-10-13 00:00:00",
            &cases_dir,
        )
        .unwrap();
        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        // Retained SRUM output copied into the scoped stage: the schema is
        // readable, but the user table's page is corrupt.
        let srum = host_dir.join("SRUM/SRUM_Corrupt.sqlite");
        std::fs::create_dir_all(srum.parent().unwrap()).unwrap();
        let db = rusqlite::Connection::open(&srum).unwrap();
        db.execute_batch("CREATE TABLE SRUM_Corrupt(user TEXT); INSERT INTO SRUM_Corrupt VALUES ('S-1-5-90-0-7');").unwrap();
        let page_size: usize = db.query_row("PRAGMA page_size", [], |row| row.get(0)).unwrap();
        drop(db);
        let mut bytes = std::fs::read(&srum).unwrap();
        bytes[page_size..2 * page_size].fill(0xFF);
        std::fs::write(&srum, bytes).unwrap();
        let only = HashSet::from(["Prefetch".to_string()]);

        let result = run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some("srum-metadata-error"));

        assert!(result.is_err(), "a skipped Metadata input must not report success");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap()).unwrap();
        assert_eq!(report["status"], "partial");
        let errors: Vec<&str> = report["errors"]
            .as_array()
            .map(|errors| errors.iter().filter_map(|e| e.as_str()).collect())
            .unwrap_or_default();
        assert!(
            errors.iter().any(|e| e.starts_with("_OVERVIEW: Metadata: ") && e.contains("SRUM/SRUM_Corrupt.sqlite")),
            "{errors:?}"
        );
        // The overview is still built from the remaining inputs.
        assert!(report["overview"]
            .as_array()
            .is_some_and(|tables| tables.iter().any(|t| t["name"] == "Metadata")));
        assert_eq!(
            case_store::load_host(&case.id, &host.id, &cases_dir).unwrap().last_run_status.as_deref(),
            Some("partial")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A prior result that cannot be removed must not be reported as `ok`:
    /// stale and fresh outputs would mix under a successful status.
    #[cfg(unix)]
    #[test]
    fn failed_clear_of_previous_results_is_an_error_not_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("clear-failure");
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
        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        // A prior PREFETCH result whose file cannot be unlinked.
        let locked = host_dir.join("PREFETCH/locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("Prefetch.sqlite"), b"prior").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let only = HashSet::from(["Prefetch".to_string()]);

        let result = run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some("clear-failure"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(result.is_err(), "a failed clear must fail the run");
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        assert_eq!(report["status"], "error");
        assert!(report["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|e| e.as_str().is_some_and(|e| e.contains("clear previous results")))));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupted_registry_and_srum_sources_are_skipped_and_run_completes() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
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
        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        let stale = host_dir.join("REGISTRY/RemovedInput.sqlite");
        let mut old_key: Row = registry::REG_FIELD_ORDER.iter()
            .map(|field| ((*field).to_string(), String::new())).collect();
        for (field, value) in [
            ("entry_kind", "key"), ("key_offset", "4128"), ("key_name", "ROOT"),
            ("key_path", "\\ROOT"), ("key_read_status", "ok"),
            ("key_subkey_count", "0"), ("key_value_count", "0"), ("_recovery", "live"),
            ("_source_file", "C:\\removed\\SOFTWARE"),
        ] {
            old_key.insert(field.into(), value.into());
        }
        write_table(&stale, "Registry", &[old_key], registry::REG_FIELD_ORDER).unwrap();
        crate::derived::stamp_facts_generation(&stale, "previous-registry-generation").unwrap();
        let mut only = HashSet::new();
        only.insert("Registry".to_string());
        only.insert("SRUM".to_string());
        only.insert("Amcache".to_string());
        let run_id = "source-errors";

        run_host_with_log_id(&case.id, &host.id, &cases_dir, Some(only), Some(run_id))
            .expect("skipped corrupted sources must not fail the run");

        assert!(!stale.exists(), "A removed input must not survive Registry reparsing");
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
                "{artifact}: a skipped corrupted source must not fail the run"
            );
            if artifact != "Registry" {
                assert!(entry.get("outputs").is_none() || entry["outputs"].as_array().unwrap().is_empty());
            }
        }
        // 통합 타임라인은 sqlite 단일 경로다 — 파싱은 구 JSON 캐시를 만들지
        // 않는다(대형 호스트에서 전량 적재·정렬·직렬화가 다시 일어나지 않음).
        assert!(!host_dir.join("_master_timeline.cache.json").exists());
        // 건너뛴 SRUM 원본은 입력 항목에 실패 사유가 남아 0건 성공과 구분된다.
        let srum_entry = artifacts
            .iter()
            .find(|entry| entry["name"] == "SRUM")
            .expect("srum entry");
        let srum_input = srum_entry["inputs"]
            .as_array()
            .and_then(|inputs| {
                inputs
                    .iter()
                    .find(|input| input["name"] == "SRUDB.dat")
            })
            .expect("srum input report");
        assert!(srum_input["error"].as_str().is_some_and(|e| !e.is_empty()));
        // The skipped hive stays visible in the per-hive report data.
        assert!(report["registryHives"]
            .as_array()
            .is_some_and(|hives| hives.iter().any(|hive| hive["status"] == "skipped_corrupted")));
        let inputs = rusqlite::Connection::open(
            host_dir.join("REGISTRY/RegistryInputs.sqlite"),
        ).unwrap();
        let failed_hive: (String, String, String, String) = inputs.query_row(
            "SELECT source_file,status,row_count,error FROM RegistryInputs WHERE hive_name='SOFTWARE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(failed_hive.0, target_dir.join("SOFTWARE").to_string_lossy());
        assert_eq!(failed_hive.1, "skipped_corrupted");
        assert_eq!(failed_hive.2, "0");
        assert!(!failed_hive.3.is_empty(), "Unreadable input must retain its error");
        drop(inputs);
        let explorer = rusqlite::Connection::open(host_dir.join("_OVERVIEW/RegistryExplorer.sqlite")).unwrap();
        let inventory: (i64, i64) = explorer.query_row(
            "SELECT COUNT(*),SUM(key_count) FROM RegistryHives", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        // SOFTWARE and Amcache.hve are both registry inputs, each unreadable.
        assert_eq!(inventory, (2, 0));
        drop(explorer);
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

    /// 범위 재파싱(EventLog만)은 이번 수집본만 발행해야 한다 — 지난 실행의
    /// 이벤트 로그 facts가 남아 현재 데이터처럼 보이면 안 되고, 범위 밖
    /// 카테고리는 그대로 유지돼야 한다.
    #[test]
    fn scoped_eventlog_rerun_drops_stale_facts_and_keeps_other_categories() {
        let _serial = PIPELINE_LOG_TEST_LOCK.lock();
        CANCEL.store(false, Ordering::Relaxed);
        let root = temporary_directory("eventlog-scoped");
        let cases_dir = root.join("cases");
        let target_dir = root.join("target");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(target_dir.join("SysEvent.Evt"), empty_evt_bytes()).unwrap();
        let case = case_store::create_case("case", "2026-10-09 00:00:00", &cases_dir).unwrap();
        let host = case_store::create_host(
            &case.id,
            "host",
            &target_dir.to_string_lossy(),
            "2026-10-09 00:00:00",
            &cases_dir,
        )
        .unwrap();
        let host_dir = case_store::host_dir(&cases_dir, &case.id, &host.id);
        // 지난 실행이 남긴, 이번에는 수집되지 않은 로그.
        let stale = host_dir.join("EVENTLOG/Security.sqlite");
        let mut stale_row: Row = eventlog::EVENT_COLUMNS
            .iter()
            .map(|field| ((*field).to_string(), String::new()))
            .collect();
        for (field, value) in [
            ("timestamp", "2026-10-01 00:00:00.000"),
            ("Channel", "Security"),
            ("EventID", "4624"),
            ("Keywords", "0x8020000000000000"),
            ("Provider", "Microsoft-Windows-Security-Auditing"),
            ("_record_key", "Security::1"),
            ("_status", "ok"),
            ("_source_file", "C:\\removed\\Security.evtx"),
        ] {
            stale_row.insert(field.into(), value.into());
        }
        write_table(&stale, "Security", &[stale_row], eventlog::EVENT_COLUMNS).unwrap();
        crate::derived::stamp_facts_generation(&stale, "previous-eventlog-generation").unwrap();
        // 범위 밖 카테고리의 지난 결과.
        let untouched = host_dir.join("PREFETCH/Prefetch.sqlite");
        std::fs::create_dir_all(untouched.parent().unwrap()).unwrap();
        std::fs::write(&untouched, b"keep").unwrap();
        let only = HashSet::from(["EventLog".to_string()]);

        run_host_with_log_id(
            &case.id,
            &host.id,
            &cases_dir,
            Some(only),
            Some("eventlog-scoped"),
        )
        .expect("EventLog 범위 재파싱");

        assert!(
            !stale.exists(),
            "이번에 수집되지 않은 지난 로그가 현재 수집본으로 남으면 안 된다"
        );
        assert!(host_dir.join("EVENTLOG/SysEvent.sqlite").is_file());
        assert_eq!(std::fs::read(&untouched).unwrap(), b"keep");
        let manifest =
            rusqlite::Connection::open(host_dir.join("EVENTLOG/EventLogInputs.sqlite")).unwrap();
        let discovered: (String, String) = manifest
            .query_row(
                "SELECT row_count,facts_db FROM EventLogInputs WHERE status='discovery_complete'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(discovered, ("1".to_string(), String::new()));
        let removed: i64 = manifest
            .query_row(
                "SELECT COUNT(*) FROM EventLogInputs WHERE facts_db='EVENTLOG/Security.sqlite'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(removed, 0);
        // 매니페스트도 이번 실행 facts 세대로 스탬프되어 발행된다.
        assert!(crate::derived::facts_generation(
            &host_dir.join("EVENTLOG/EventLogInputs.sqlite")
        )
        .unwrap()
        .is_some_and(|generation| generation != "previous-eventlog-generation"));
        drop(manifest);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        let entry = report["artifacts"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["name"] == "EventLog"))
            .expect("EventLog artifact report");
        assert_eq!(entry["status"], "completed");
        let _ = std::fs::remove_dir_all(root);
    }
}
