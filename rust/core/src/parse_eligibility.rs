//! UI-01: a host's `파싱` button is enabled only when new data was collected.
//!
//! The baseline comes from existing parser provenance, not a new metadata file:
//! every terminal report in `parse_logs/<run_id>.json` (plus `parse_report.json`
//! for hosts stored before per-run manifests) lists the evidence files that run
//! planned, in `artifacts[].inputs[].sourcePath`.
//!
//! Only runs that reached a verdict on the data (`ok`/`complete`/`partial`) form
//! the baseline. `cancelled` (aborted before publication) and `error` (storage or
//! publish failure) say nothing about the evidence, so they never lock a host.
//! Collected data is immutable and a failed parse fails again
//! ([[patterns/parsing]], 2026-08-30), so failure alone never re-enables parsing;
//! only a new or modified source file does.
//!
//! Every read failure is an error, never a silent "unchanged".
use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;

use crate::case_store;
use crate::pipeline;

/// Parse button state plus the Korean sentence shown next to it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseEligibility {
    pub can_parse: bool,
    pub reason: String,
}

impl ParseEligibility {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            can_parse: true,
            reason: reason.into(),
        }
    }

    fn block(reason: impl Into<String>) -> Self {
        Self {
            can_parse: false,
            reason: reason.into(),
        }
    }
}

fn is_verdict_status(status: &str) -> bool {
    matches!(status, "ok" | "complete" | "partial")
}

/// Separator-only normalisation. Case is preserved so distinct files on a
/// case-sensitive filesystem cannot collapse into one.
fn normalized(path: &str) -> String {
    let value = path.replace('\\', "/");
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        value
    } else {
        trimmed.to_string()
    }
}

/// Report `runAt` is local time; None for legacy shapes, which then compare by
/// path only instead of failing.
fn parse_run_at(value: &str) -> Option<SystemTime> {
    let naive = chrono::NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%d %H:%M:%S%.f").ok()?;
    let local = naive.and_local_timezone(chrono::Local).single()?;
    let seconds = local.timestamp();
    if seconds < 0 {
        return None;
    }
    Some(
        SystemTime::UNIX_EPOCH
            + std::time::Duration::new(seconds as u64, local.timestamp_subsec_nanos()),
    )
}

#[derive(Default)]
struct Baseline {
    /// Newest verdict run that read each input. Per input, not per host: a
    /// scoped rerun (MFT only) must not vouch for files it never looked at.
    inputs: HashMap<String, Option<SystemTime>>,
    parsed: bool,
}

impl Baseline {
    fn absorb(&mut self, report: &serde_json::Value) {
        let status = report
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !is_verdict_status(status) {
            return;
        }
        self.parsed = true;
        let run_at = report
            .get("runAt")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_run_at);
        let artifacts = report
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for artifact in artifacts {
            let inputs = artifact
                .get("inputs")
                .and_then(serde_json::Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            for input in inputs {
                let Some(source) = input.get("sourcePath").and_then(serde_json::Value::as_str)
                else {
                    continue;
                };
                let slot = self.inputs.entry(normalized(source)).or_insert(None);
                if let Some(run_at) = run_at {
                    if slot.is_none_or(|previous| run_at > previous) {
                        *slot = Some(run_at);
                    }
                }
            }
        }
    }
}

fn read_report(path: &Path) -> Result<Option<serde_json::Value>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow!(
                "파싱 기록을 읽지 못했습니다({}): {error}",
                path.display()
            ))
        }
    };
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("파싱 기록이 손상되었습니다({})", path.display()))?;
    Ok(Some(value))
}

fn baseline_of(live_dir: &Path) -> Result<Baseline> {
    let mut baseline = Baseline::default();
    let log_dir = live_dir.join(pipeline::PARSE_LOG_DIRECTORY);
    match std::fs::read_dir(&log_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|error| {
                    anyhow!(
                        "파싱 기록 폴더를 읽지 못했습니다({}): {error}",
                        log_dir.display()
                    )
                })?;
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                {
                    if let Some(report) = read_report(&path)? {
                        baseline.absorb(&report);
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => bail!(
            "파싱 기록 폴더를 읽지 못했습니다({}): {error}",
            log_dir.display()
        ),
    }
    // Hosts stored before per-run manifests only have the latest pointer.
    if let Some(report) = read_report(&live_dir.join("parse_report.json"))? {
        baseline.absorb(&report);
    }
    Ok(baseline)
}

/// Decide from the host result directory and its collection folder alone.
pub fn eligibility_for(live_dir: &Path, target: &Path) -> Result<ParseEligibility> {
    let baseline = baseline_of(live_dir)?;
    // A missing collection folder is a visible failure, never a silent allow.
    if !target.is_dir() {
        bail!("수집 폴더를 찾을 수 없습니다: {}", target.display());
    }
    if !baseline.parsed {
        return Ok(ParseEligibility::allow("아직 파싱하지 않은 호스트입니다."));
    }
    // Compare only files the pipeline itself would plan, so unsupported files
    // (collector notes) never count as new data.
    let found = pipeline::discover_host_inputs(target);
    if let Some(error) = found.errors.first() {
        bail!("수집 폴더를 읽지 못했습니다: {error}");
    }
    for path in &found.paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
        let Some(parsed_at) = baseline.inputs.get(&normalized(&path.to_string_lossy())) else {
            return Ok(ParseEligibility::allow(format!(
                "새 증거 파일이 있습니다: {name}"
            )));
        };
        let Some(parsed_at) = *parsed_at else {
            continue;
        };
        let modified = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .map_err(|error| anyhow!("원본 파일 상태를 읽지 못했습니다({name}): {error}"))?;
        if modified > parsed_at {
            return Ok(ParseEligibility::allow(format!(
                "마지막 파싱 이후 변경된 원본이 있습니다: {name}"
            )));
        }
    }
    Ok(ParseEligibility::block(
        "마지막 파싱 이후 새로 추가된 데이터가 없습니다.",
    ))
}

/// Case-store entry point. The parse command uses it too, so the button state
/// and what the backend actually allows cannot drift apart.
pub fn host_parse_eligibility(
    case_id: &str,
    host_id: &str,
    cases_dir: &Path,
) -> Result<ParseEligibility> {
    let host = case_store::load_host(case_id, host_id, cases_dir)
        .with_context(|| format!("호스트 정보를 읽지 못했습니다: {host_id}"))?;
    let live_dir = case_store::host_dir(cases_dir, case_id, host_id);
    eligibility_for(&live_dir, Path::new(&host.target_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "wina-eligibility-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn at(offset_secs: i64) -> String {
        (chrono::Local::now() + chrono::Duration::seconds(offset_secs))
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string()
    }

    /// Write an evidence file with an explicit age, so a test never depends on
    /// millisecond truncation of `runAt` versus the file's real mtime.
    fn evidence(path: &Path, age_secs: u64) {
        std::fs::write(path, b"evidence").unwrap();
        set_modified(path, SystemTime::now() - std::time::Duration::from_secs(age_secs));
    }

    fn set_modified(path: &Path, when: SystemTime) {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(when).unwrap();
    }

    /// One terminal manifest, as `write_terminal_report` stores it: a per-run
    /// file plus the overwritten latest pointer.
    fn write_manifest(live_dir: &Path, run_id: &str, status: &str, run_at: &str, inputs: &[&Path]) {
        let log_dir = live_dir.join(pipeline::PARSE_LOG_DIRECTORY);
        std::fs::create_dir_all(&log_dir).unwrap();
        let report = serde_json::json!({
            "runId": run_id,
            "runAt": run_at,
            "status": status,
            "published": status == "ok",
            "artifacts": [{
                "name": "Artifact",
                "status": "completed",
                "inputs": inputs.iter().map(|path| serde_json::json!({
                    "name": path.file_name().unwrap().to_string_lossy(),
                    "sourcePath": path.to_string_lossy(),
                    "recordCount": 1,
                    "recoveryLog": false,
                })).collect::<Vec<_>>(),
            }],
        });
        let payload = serde_json::to_vec_pretty(&report).unwrap();
        std::fs::write(log_dir.join(format!("{run_id}.json")), &payload).unwrap();
        std::fs::write(live_dir.join("parse_report.json"), &payload).unwrap();
    }

    /// Collection folder with one supported file and one unsupported file.
    fn seed_target(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = temporary_directory(label);
        let live = root.join("host");
        let target = root.join("evidence");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let hive = target.join("Amcache.hve");
        evidence(&hive, 3600);
        std::fs::write(target.join("collection-notes.txt"), b"collector log").unwrap();
        (live, target, hive)
    }

    #[test]
    fn non_target_browser_indexes_do_not_enable_reparsing() {
        let (live, target, hive) = seed_target("non-target-index");
        write_manifest(&live, "full", "ok", &at(-60), &[&hive]);
        for directory in ["EDGE/Default/Code Cache/js", "CHROME/Default/Code Cache/wasm", "unrelated"] {
            let directory = target.join(directory);
            std::fs::create_dir_all(&directory).unwrap();
            evidence(&directory.join("index"), 120);
        }
        assert!(!eligibility_for(&live, &target).unwrap().can_parse);
        std::fs::remove_dir_all(live.parent().unwrap()).unwrap();
    }

    #[test]
    fn new_supported_cache_index_is_detected_even_if_corrupt() {
        let (live, target, hive) = seed_target("supported-index");
        write_manifest(&live, "full", "ok", &at(-60), &[&hive]);
        let cache = target.join("EDGE/Default/Cache/Cache_Data");
        std::fs::create_dir_all(&cache).unwrap();
        let index = cache.join("index");
        evidence(&index, 120);
        assert!(eligibility_for(&live, &target).unwrap().can_parse);
        write_manifest(&live, "partial", "partial", &at(-30), &[&index]);
        assert!(!eligibility_for(&live, &target).unwrap().can_parse);
        std::fs::remove_dir_all(live.parent().unwrap()).unwrap();
    }

    #[test]
    fn never_parsed_host_is_parsable() {
        let (live, target, _) = seed_target("fresh");
        let state = eligibility_for(&live, &target).unwrap();
        assert!(state.can_parse, "{}", state.reason);
    }

    /// A never-parsed host with no collection folder must fail visibly instead
    /// of being offered as parsable.
    #[test]
    fn never_parsed_host_without_target_is_an_error() {
        let (live, target, _) = seed_target("fresh-missing-target");
        std::fs::remove_dir_all(&target).unwrap();
        assert!(eligibility_for(&live, &target).is_err());
    }

    #[test]
    fn unchanged_evidence_after_successful_run_is_blocked() {
        let (live, target, hive) = seed_target("unchanged");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        let state = eligibility_for(&live, &target).unwrap();
        assert!(!state.can_parse, "{}", state.reason);
        assert!(!state.reason.is_empty());
    }

    /// Collected data is immutable: a failed parse of unchanged input must not
    /// reopen the button.
    #[test]
    fn failed_run_without_new_evidence_stays_blocked() {
        let (live, target, hive) = seed_target("failed");
        write_manifest(&live, "run-1", "partial", &at(0), &[&hive]);
        let state = eligibility_for(&live, &target).unwrap();
        assert!(!state.can_parse, "{}", state.reason);
    }

    /// Cancelling is not a verdict on the evidence.
    #[test]
    fn cancelled_run_leaves_host_parsable() {
        let (live, target, hive) = seed_target("cancelled");
        write_manifest(&live, "run-1", "cancelled", &at(0), &[&hive]);
        let state = eligibility_for(&live, &target).unwrap();
        assert!(state.can_parse, "{}", state.reason);
    }

    #[test]
    fn newly_collected_supported_file_unlocks_parsing() {
        let (live, target, hive) = seed_target("new-file");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        std::fs::write(target.join("$MFT"), b"mft").unwrap();
        let state = eligibility_for(&live, &target).unwrap();
        assert!(state.can_parse, "{}", state.reason);
        assert!(state.reason.contains("$MFT"), "{}", state.reason);
    }

    /// Unsupported files are not evidence, so adding them changes nothing.
    #[test]
    fn unsupported_new_file_does_not_unlock_parsing() {
        let (live, target, hive) = seed_target("unsupported");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        std::fs::write(target.join("readme-2.txt"), b"not evidence").unwrap();
        let state = eligibility_for(&live, &target).unwrap();
        assert!(!state.can_parse, "{}", state.reason);
    }

    /// A scoped rerun records only its own artifact and overwrites the latest
    /// pointer; the full baseline still comes from the earlier manifest.
    #[test]
    fn scoped_retry_manifest_does_not_erase_full_baseline() {
        let (live, target, hive) = seed_target("scoped");
        let mft = target.join("$MFT");
        evidence(&mft, 3600);
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive, &mft]);
        write_manifest(&live, "run-2", "partial", &at(1), &[&mft]);
        let state = eligibility_for(&live, &target).unwrap();
        assert!(!state.can_parse, "{}", state.reason);
    }

    /// A later scoped rerun of another artifact must not vouch for a file it
    /// never read: the modified PowerShell history stays parsable.
    #[test]
    fn scoped_rerun_does_not_mask_a_file_modified_after_its_own_run() {
        let (live, target, _) = seed_target("scoped-mask");
        let history = target.join("ConsoleHost_history.txt");
        evidence(&history, 300);
        let mft = target.join("$MFT");
        evidence(&mft, 3600);
        let hive = target.join("Amcache.hve");
        // Full run, then the history changes, then an unrelated scoped rerun.
        write_manifest(&live, "run-1", "ok", &at(-600), &[&hive, &history, &mft]);
        // run-1 read the history; only run-2 (MFT only) is newer than its mtime.
        write_manifest(&live, "run-2", "partial", &at(0), &[&mft]);
        let state = eligibility_for(&live, &target).unwrap();
        assert!(state.can_parse, "{}", state.reason);
        assert!(
            state.reason.contains("ConsoleHost_history.txt"),
            "{}",
            state.reason
        );
    }

    #[test]
    fn modified_evidence_after_last_run_unlocks_parsing() {
        let (live, target, hive) = seed_target("modified");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        set_modified(&hive, SystemTime::now() + std::time::Duration::from_secs(120));
        let state = eligibility_for(&live, &target).unwrap();
        assert!(state.can_parse, "{}", state.reason);
        assert!(state.reason.contains("Amcache.hve"), "{}", state.reason);
    }

    /// An unreadable record is never read as "unchanged".
    #[test]
    fn unreadable_report_is_an_error_not_unchanged() {
        let (live, target, hive) = seed_target("corrupt");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        std::fs::write(
            live.join(pipeline::PARSE_LOG_DIRECTORY).join("run-1.json"),
            b"{ broken",
        )
        .unwrap();
        assert!(eligibility_for(&live, &target).is_err());
    }

    #[test]
    fn missing_target_directory_is_an_error() {
        let (live, target, hive) = seed_target("missing-target");
        write_manifest(&live, "run-1", "ok", &at(0), &[&hive]);
        std::fs::remove_dir_all(&target).unwrap();
        assert!(eligibility_for(&live, &target).is_err());
    }
}
