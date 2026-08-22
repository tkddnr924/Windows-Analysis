//! Parse-stage orchestration, mirroring main.py run_host: locate each
//! artifact's files under the target, parse, and write per-source SQLite into
//! CATEGORY/<name>.sqlite. Streaming parsers write directly; smaller ones use
//! write_table. Overview builders are a separate (later) stage.
use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::case_store::{self};
use crate::finder;
use crate::parsers::{amcache, browser_cache, browser_history, eventlog, powershell_history, prefetch, jumplist, mft, rdpcache, registry, srum, taskscheduler, usnjrnl, wer};
use crate::sqlite::{write_table, write_table_cols, Row};
use crate::overview;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

// Global progress sink (Send). When set (by the GUI), progress lines route here
// instead of stdout; unset (CLI) prints to stdout. Global + Send so worker
// threads (parallel registry parsing) reach the same sink.
static LOG_SINK: Mutex<Option<Box<dyn FnMut(&str) + Send>>> = Mutex::new(None);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseReport {
    run_at: String,
    artifacts: Vec<ParseArtifactReport>,
    overview: Vec<OverviewTableReport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseArtifactReport {
    name: String,
    status: String,
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

/// Install (or clear) the progress sink.
pub fn set_log_sink(sink: Option<Box<dyn FnMut(&str) + Send>>) {
    *LOG_SINK.lock().unwrap() = sink;
}

fn emit(msg: &str) {
    if let Ok(mut g) = LOG_SINK.lock() {
        match g.as_mut() { Some(f) => f(msg), None => println!("{}", msg) }
    }
}

/// Cooperative cancel flag: `run_host` clears it at start and checks it before
/// each artifact; `cancel` (from the GUI) sets it to stop the remaining work.
/// Parsers poll `cancelled()` inside their row loops so a long single artifact
/// (e.g. a big registry hive) stops promptly too, not only between artifacts.
pub static CANCEL: AtomicBool = AtomicBool::new(false);

/// True once the user requested cancel. Parsers should break out of their
/// row/entry loops when this returns true.
pub fn cancelled() -> bool { CANCEL.load(Ordering::Relaxed) }

/// Every artifact the pipeline knows how to parse, in run order.
pub const ARTIFACT_NAMES: &[&str] = &[
    "Amcache", "EventLog", "Registry", "UsnJrnl", "MFT", "JumpList", "SRUM",
    "TaskScheduler", "RdpCache", "BrowserHistory", "BrowserCache", "PowerShell", "Prefetch", "WER",
];

fn announce(name: &str) { emit(&format!("=== {} ===", name)); }
fn found(paths: &[std::path::PathBuf]) {
    if paths.is_empty() { emit(&format!("[!] no matching files found")); }
    else if paths.len() <= 20 { for p in paths { emit(&format!("[*] found: {}", p.display())); } }
    else { emit(&format!("[*] found: {} files", paths.len())); }
}

fn record_inputs(report: &mut ParseReport, artifact: &str, paths: &[std::path::PathBuf]) {
    for path in paths {
        record_input(report, artifact, path, false);
        if artifact == "Amcache" {
            for log in registry::sibling_logs(path) {
                record_input(report, artifact, &log, true);
            }
        }
    }
}

fn record_input(report: &mut ParseReport, artifact: &str, path: &Path, recovery_log: bool) {
    let Some(entry) = report.artifacts.iter_mut().rev().find(|entry| entry.name == artifact) else { return; };
    let source_path = path.to_string_lossy().to_string();
    if entry.inputs.iter().any(|input| input.source_path == source_path) { return; }
    let name = path.file_name().map(|value| value.to_string_lossy().to_string()).unwrap_or_else(|| source_path.clone());
    entry.inputs.push(ParseInputReport { name, source_path, record_count: 0, recovery_log });
}

fn record_input_count(report: &mut ParseReport, artifact: &str, path: &Path, record_count: usize) {
    record_input(report, artifact, path, false);
    let source_path = path.to_string_lossy();
    if let Some(entry) = report.artifacts.iter_mut().rev().find(|entry| entry.name == artifact) {
        if let Some(input) = entry.inputs.iter_mut().find(|input| input.source_path == source_path.as_ref()) {
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
        if let Some(entry) = report.artifacts.iter_mut().rev().find(|entry| entry.name == artifact) {
            if let Some(input) = entry.inputs.iter_mut().find(|input| input.source_path == source) {
                input.record_count = input.record_count.saturating_add(count);
            }
        }
    }
}
fn uniq_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_string()) { return base.to_string(); }
    let mut i = 2;
    loop { let n = format!("{}_{}", base, i); if taken.insert(n.clone()) { return n; } i += 1; }
}

pub fn run_host(case_id: &str, host_id: &str, cases_dir: &Path, only: Option<HashSet<String>>) -> Result<()> {
    let host = case_store::load_host(case_id, host_id, cases_dir)?;
    let out_dir = case_store::host_dir(cases_dir, case_id, host_id);
    let target = std::path::PathBuf::from(&host.target_dir);
    CANCEL.store(false, Ordering::Relaxed);
    let started = std::time::Instant::now();

    if only.is_none() {
        if let Ok(entries) = std::fs::read_dir(&out_dir) {
            for e in entries.flatten() { if e.path().is_dir() { let _ = std::fs::remove_dir_all(e.path()); } }
        }
    }
    let want = |n: &str| only.as_ref().map_or(true, |o| o.contains(n));
    let mut artifacts_run: Vec<String> = Vec::new();
    let mut had_error = false;
    let mut report = ParseReport { run_at: String::new(), artifacts: Vec::new(), overview: Vec::new() };
    let cat = |c: &str| out_dir.join(c);

    // Each artifact is isolated: an Err is logged and skipped, and a *panic*
    // (e.g. a malformed structure that trips an index) is caught too, so one
    // bad artifact can never stop the ones after it or the _OVERVIEW stage.
    macro_rules! guard { ($name:expr, $body:block) => {{
        report.artifacts.push(ParseArtifactReport { name: $name.to_string(), status: "running".to_string(), inputs: Vec::new() });
        if !CANCEL.load(Ordering::Relaxed) {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> { $body Ok(()) }));
            match res {
                Ok(Ok(())) => { if let Some(entry) = report.artifacts.last_mut() { entry.status = "completed".to_string(); } }
                Ok(Err(e)) => { emit(&format!("[!] {} failed: {}", $name, e)); had_error = true; if let Some(entry) = report.artifacts.last_mut() { entry.status = "failed".to_string(); } }
                Err(_) => { emit(&format!("[!] {} panicked — skipped", $name)); had_error = true; if let Some(entry) = report.artifacts.last_mut() { entry.status = "failed".to_string(); } }
            }
        } else if let Some(entry) = report.artifacts.last_mut() { entry.status = "cancelled".to_string(); }
        artifacts_run.push($name.to_string());
    }}; }

    // --- Amcache (AMCACHE/<stem>.sqlite: Amcache_Programs + Amcache_Files) ---
    if want("Amcache") { announce("Amcache"); guard!("Amcache", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["Amcache.hve"]));
        found(&paths); record_inputs(&mut report, "Amcache", &paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "Amcache".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("AMCACHE").join(format!("{}.sqlite", name));
            let (progs, files) = amcache::parse_amcache(p)?;
            write_table(&out, amcache::PROGRAMS_TABLE, &progs, amcache::PROGRAMS_FIELD_ORDER)?;
            write_table(&out, amcache::FILES_TABLE, &files, amcache::FILES_FIELD_ORDER)?;
            record_input_count(&mut report, "Amcache", p, progs.len() + files.len());
            emit(&format!("[+] {} programs, {} files -> {}", progs.len(), files.len(), out.display()));
        }
    }); }

    // --- EventLog (EVENTLOG/<stem>.sqlite) ---
    if want("EventLog") { announce("EventLog"); guard!("EventLog", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, eventlog::ALLOWLIST));
        found(&paths); record_inputs(&mut report, "EventLog", &paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "EventLog".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("EVENTLOG").join(format!("{}.sqlite", name));
            let n = eventlog::parse_evtx_stream(p, &out, &name)?;
            record_input_count(&mut report, "EventLog", p, n);
            if n > 0 { emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), name)); }
        }
    }); }

    // --- Registry (REGISTRY/<filename>.sqlite, table Registry) ---
    if want("Registry") { announce("Registry"); guard!("Registry", {
        let mut all = finder::by_name(&target, registry::REG_FILENAMES);
        all.extend(finder::by_suffix(&target, registry::REG_SUFFIXES));
        // drop a RegBack copy when the live hive of the same name is present
        let live: HashSet<String> = all.iter()
            .filter(|p| !p.components().any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("regback")))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_uppercase())).collect();
        all.retain(|p| {
            let is_regback = p.components().any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("regback"));
            let nm = p.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
            !is_regback || !live.contains(&nm)
        });
        let paths = finder::dedupe_by_content(all);
        found(&paths); record_inputs(&mut report, "Registry", &paths);
        // Assign each hive a unique output name (sequential), then parse hives
        // in parallel — each writes its own sqlite, so there's no shared state.
        // notatin's deleted-cell/transaction-log recovery is CPU-heavy and
        // dominates this step; spreading the hives across cores cuts wall time.
        let mut taken = HashSet::new();
        let mut jobs: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
        for p in &paths {
            let base = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "hive".into());
            let name = uniq_name(&base, &mut taken);
            jobs.push((p.clone(), cat("REGISTRY").join(format!("{}.sqlite", name))));
        }
        // Cap concurrency: each big hive's recovery can use hundreds of MB.
        let workers = std::thread::available_parallelism().map(|n| n.get().min(4)).unwrap_or(2);
        let next = AtomicUsize::new(0);
        let parsed_counts = Mutex::new(Vec::<(std::path::PathBuf, usize)>::with_capacity(jobs.len()));
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    if CANCEL.load(Ordering::Relaxed) { break; } // stop starting new hives
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= jobs.len() { break; }
                    let (src, out) = &jobs[i];
                    if CANCEL.load(Ordering::Relaxed) { break; }
                    match registry::parse_hive_stream(src, out) {
                        Ok(n) => {
                            if let Ok(mut counts) = parsed_counts.lock() { counts.push((src.clone(), n)); }
                            emit(&format!("[+] {} rows -> {} [Registry]", n, out.display()));
                        }
                        Err(e) => emit(&format!("[!] {} failed: {}", out.display(), e)),
                    }
                });
            }
        });
        if let Ok(counts) = parsed_counts.into_inner() {
            for (source, count) in counts { record_input_count(&mut report, "Registry", &source, count); }
        }
    }); }

    // --- UsnJrnl (FILESYSTEM/UsnJrnl_Records.sqlite) ---
    if want("UsnJrnl") { announce("UsnJrnl"); guard!("UsnJrnl", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["$J"]));
        found(&paths); record_inputs(&mut report, "UsnJrnl", &paths);
        if let Some(p) = paths.first() {
            let out = cat("FILESYSTEM").join("UsnJrnl_Records.sqlite");
            let n = usnjrnl::parse_usn_stream(p, &out)?;
            record_input_count(&mut report, "UsnJrnl", p, n);
            emit(&format!("[+] {} rows -> {}", n, out.display()));
        }
    }); }

    // --- MFT (_OVERVIEW/MFT_Records.sqlite) ---
    if want("MFT") { announce("MFT"); guard!("MFT", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["$MFT"]));
        found(&paths); record_inputs(&mut report, "MFT", &paths);
        if let Some(p) = paths.first() {
            let out = cat("_OVERVIEW").join("MFT_Records.sqlite");
            let n = mft::parse_mft_stream(p, &out)?;
            record_input_count(&mut report, "MFT", p, n);
            emit(&format!("[+] {} rows -> {}", n, out.display()));
        }
    }); }

    // --- SRUM (SRUM/<stem>.sqlite, table per provider) ---
    if want("SRUM") { announce("SRUM"); guard!("SRUM", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["SRUDB.dat"]));
        found(&paths); record_inputs(&mut report, "SRUM", &paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "SRUDB".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("SRUM").join(format!("{}.sqlite", name));
            match srum::parse_srum_stream(p, &out) {
                Ok(tables) => {
                    let record_count = tables.iter().map(|(_, count)| *count).sum();
                    record_input_count(&mut report, "SRUM", p, record_count);
                    for (t, n) in tables { emit(&format!("[+] {} rows -> {} [{}]", n, out.display(), t)); }
                }
                Err(e) => {
                    emit(&format!("[!] SRUM failed for {}: {}", p.display(), e));
                }
            }
        }
    }); }

    // --- JumpList (JUMPLIST/JumpList_Entries.sqlite) ---
    if want("JumpList") { announce("JumpList"); guard!("JumpList", {
        let rows = jumplist::parse_jumplists(&target)?;
        record_rows_by_source(&mut report, "JumpList", &rows);
        if !rows.is_empty() {
            let out = cat("JUMPLIST").join("JumpList_Entries.sqlite");
            write_table(&out, jumplist::JUMPLIST_TABLE, &rows, jumplist::JUMPLIST_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        } else { emit(&format!("[!] no matching files found")); }
    }); }

    // --- TaskScheduler (TASKSCHEDULER/TaskScheduler_Tasks.sqlite) ---
    if want("TaskScheduler") { announce("TaskScheduler"); guard!("TaskScheduler", {
        let rows = taskscheduler::parse_tasks(&target)?;
        record_rows_by_source(&mut report, "TaskScheduler", &rows);
        if !rows.is_empty() {
            let out = cat("TASKSCHEDULER").join("TaskScheduler_Tasks.sqlite");
            write_table(&out, taskscheduler::TASK_TABLE, &rows, taskscheduler::TASK_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        } else { emit(&format!("[!] no matching files found")); }
    }); }

    // --- RdpCache (RDPCACHE/RdpBitmapCache.sqlite) ---
    if want("RdpCache") { announce("RdpCache"); guard!("RdpCache", {
        let rows = rdpcache::parse_rdpcache(&target)?;
        record_rows_by_source(&mut report, "RdpCache", &rows);
        if !rows.is_empty() {
            let out = cat("RDPCACHE").join("RdpBitmapCache.sqlite");
            write_table(&out, rdpcache::RDP_TABLE, &rows, rdpcache::RDP_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        } else { emit(&format!("[!] no matching files found")); }
    }); }

    // --- WER (WER/WER_Reports.sqlite) ---
    if want("WER") { announce("WER"); guard!("WER", {
        let rows = wer::parse_wer(&target)?;
        record_rows_by_source(&mut report, "WER", &rows);
        if !rows.is_empty() {
            let out = cat("WER").join("WER_Reports.sqlite");
            write_table(&out, wer::WER_TABLE, &rows, wer::WER_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        } else { emit(&format!("[!] no matching files found")); }
    }); }

    // --- BrowserHistory (BROWSER/<account>.sqlite, table per source table) ---
    if want("BrowserHistory") { announce("BrowserHistory"); guard!("BrowserHistory", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["History"]));
        found(&paths); record_inputs(&mut report, "BrowserHistory", &paths);
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
                emit(&format!("[+] {} rows -> {} [{}]", rows.len(), out.display(), t));
            }
        }
    }); }

    // --- BrowserCache (BROWSER/<account>_Chrome_Cache.sqlite — shared with BrowserHistory) ---
    if want("BrowserCache") { announce("BrowserCache"); guard!("BrowserCache", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["index"]));
        found(&paths); record_inputs(&mut report, "BrowserCache", &paths);
        for (name, source, rows) in browser_cache::parse_caches(&paths) {
            let out = cat("BROWSER").join(format!("{}.sqlite", name));
            write_table(&out, browser_cache::CACHE_TABLE, &rows, browser_cache::CACHE_FIELD_ORDER)?;
            record_input_count(&mut report, "BrowserCache", &source, rows.len());
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        }
    }); }

    // --- Prefetch (PREFETCH/Prefetch_Execution.sqlite + Prefetch_LoadedFiles.sqlite) ---
    if want("Prefetch") { announce("Prefetch"); guard!("Prefetch", {
        let paths = finder::dedupe_by_content(finder::by_extension(&target, &[".pf"]));
        found(&paths); record_inputs(&mut report, "Prefetch", &paths);
        if !paths.is_empty() {
            let (exec_rows, loaded_rows) = prefetch::parse_prefetch(&paths);
            record_rows_by_source(&mut report, "Prefetch", &exec_rows);
            add_rows_by_source(&mut report, "Prefetch", &loaded_rows);
            let ex = cat("PREFETCH").join(format!("{}.sqlite", prefetch::EXEC_TABLE));
            write_table(&ex, prefetch::EXEC_TABLE, &exec_rows, prefetch::EXEC_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", exec_rows.len(), ex.display()));
            let lf = cat("PREFETCH").join(format!("{}.sqlite", prefetch::LOADED_TABLE));
            write_table(&lf, prefetch::LOADED_TABLE, &loaded_rows, prefetch::LOADED_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", loaded_rows.len(), lf.display()));
        }
    }); }

    // --- PowerShell console history (POWERSHELL/PowerShell_ConsoleHistory.sqlite) ---
    if want("PowerShell") { announce("PowerShell"); guard!("PowerShell", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["ConsoleHost_history.txt"]));
        found(&paths); record_inputs(&mut report, "PowerShell", &paths);
        if !paths.is_empty() {
            let rows = powershell_history::parse_console_history(&paths)?;
            record_rows_by_source(&mut report, "PowerShell", &rows);
            let out = cat("POWERSHELL").join(format!("{}.sqlite", powershell_history::PS_TABLE));
            write_table(&out, powershell_history::PS_TABLE, &rows, powershell_history::PS_FIELD_ORDER)?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
        }
    }); }

    // Skip the correlation stage entirely if the run was cancelled.
    if !cancelled() {
        emit(&format!("=== _OVERVIEW ==="));
        let ov = out_dir.join("_OVERVIEW");
        let mut write_ov = |name: &str, rows: Vec<Row>, skip_empty: bool| -> Result<()> {
            if rows.is_empty() && skip_empty { return Ok(()); }
            let out = ov.join(format!("{}.sqlite", name));
            write_table(&out, name, &rows, &[])?;
            emit(&format!("[+] {} rows -> {}", rows.len(), out.display()));
            report.overview.push(OverviewTableReport { name: name.to_string(), row_count: rows.len() });
            Ok(())
        };
        write_ov("ScheduledTasks", overview::build_scheduled_tasks(&out_dir), true)?;
        write_ov("RdpCache", overview::build_rdp_cache(&out_dir), true)?;
        write_ov("Defender", overview::build_defender(&out_dir), false)?;
        write_ov("RemoteDesktopHistory", overview::build_remote_desktop_history(&out_dir), false)?;
        write_ov("SmbHistory", overview::build_smb_history(&out_dir), true)?;
        write_ov("PowerShellHistory", overview::build_powershell_history(&out_dir), false)?;
        write_ov("BrowserActivity", overview::build_browser_history(&out_dir), false)?;
        write_ov("TargetInfo", overview::build_target_info(&out_dir), false)?;
        write_ov("ExecutionHistory", overview::build_execution_history(&out_dir), false)?;
        write_ov("RegistryFindings", overview::build_registry_findings(&out_dir), false)?;
    } else {
        emit(&format!("=== 취소됨 — 종합 분석 건너뜀 ==="));
    }

    let run_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    report.run_at = run_at.clone();
    std::fs::write(out_dir.join("parse_report.json"), serde_json::to_vec_pretty(&report)?)?;
    let status = if cancelled() { "cancelled" } else if had_error { "error" } else { "ok" };
    case_store::update_host_status(case_id, host_id, cases_dir,
        &run_at, status, artifacts_run,
        Some(started.elapsed().as_secs_f64()))?;
    Ok(())
}

/// Account folder under BROWSER (…/BROWSER/<account>/CHROME/Default/History).
fn browser_account(path: &Path) -> String {
    let parts: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("BROWSER") && i + 1 < parts.len() { return parts[i + 1].clone(); }
    }
    path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "browser".into())
}
