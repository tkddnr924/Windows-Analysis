//! Parse-stage orchestration, mirroring main.py run_host: locate each
//! artifact's files under the target, parse, and write per-source SQLite into
//! CATEGORY/<name>.sqlite. Streaming parsers write directly; smaller ones use
//! write_table. Overview builders are a separate (later) stage.
use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;

use crate::case_store::{self};
use crate::finder;
use crate::parsers::{amcache, browser_cache, browser_history, eventlog, powershell_history, prefetch, jumplist, mft, rdpcache, registry, srum, taskscheduler, usnjrnl, wer};
use crate::sqlite::{write_table, write_table_cols, Row};
use crate::overview;

fn announce(name: &str) { println!("=== {} ===", name); }
fn found(paths: &[std::path::PathBuf]) {
    if paths.is_empty() { println!("[!] no matching files found"); }
    else if paths.len() <= 20 { for p in paths { println!("[*] found: {}", p.display()); } }
    else { println!("[*] found: {} files", paths.len()); }
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

    if only.is_none() {
        if let Ok(entries) = std::fs::read_dir(&out_dir) {
            for e in entries.flatten() { if e.path().is_dir() { let _ = std::fs::remove_dir_all(e.path()); } }
        }
    }
    let want = |n: &str| only.as_ref().map_or(true, |o| o.contains(n));
    let mut artifacts_run: Vec<String> = Vec::new();
    let mut had_error = false;
    let cat = |c: &str| out_dir.join(c);

    macro_rules! guard { ($name:expr, $body:block) => {{
        let r: Result<()> = (|| { $body Ok(()) })();
        if let Err(e) = r { println!("[!] {} failed: {}", $name, e); had_error = true; }
        artifacts_run.push($name.to_string());
    }}; }

    // --- Amcache (AMCACHE/<stem>.sqlite: Amcache_Programs + Amcache_Files) ---
    if want("Amcache") { announce("Amcache"); guard!("Amcache", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["Amcache.hve"]));
        found(&paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "Amcache".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("AMCACHE").join(format!("{}.sqlite", name));
            let (progs, files) = amcache::parse_amcache(p)?;
            write_table(&out, amcache::PROGRAMS_TABLE, &progs, amcache::PROGRAMS_FIELD_ORDER)?;
            write_table(&out, amcache::FILES_TABLE, &files, amcache::FILES_FIELD_ORDER)?;
            println!("[+] {} programs, {} files -> {}", progs.len(), files.len(), out.display());
        }
    }); }

    // --- EventLog (EVENTLOG/<stem>.sqlite) ---
    if want("EventLog") { announce("EventLog"); guard!("EventLog", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, eventlog::ALLOWLIST));
        found(&paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "EventLog".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("EVENTLOG").join(format!("{}.sqlite", name));
            let n = eventlog::parse_evtx_stream(p, &out, &name)?;
            if n > 0 { println!("[+] {} rows -> {} [{}]", n, out.display(), name); }
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
        found(&paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "hive".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("REGISTRY").join(format!("{}.sqlite", name));
            let n = registry::parse_hive_stream(p, &out)?;
            println!("[+] {} rows -> {} [Registry]", n, out.display());
        }
    }); }

    // --- UsnJrnl (FILESYSTEM/UsnJrnl_Records.sqlite) ---
    if want("UsnJrnl") { announce("UsnJrnl"); guard!("UsnJrnl", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["$J"]));
        found(&paths);
        if let Some(p) = paths.first() {
            let out = cat("FILESYSTEM").join("UsnJrnl_Records.sqlite");
            let n = usnjrnl::parse_usn_stream(p, &out)?;
            println!("[+] {} rows -> {}", n, out.display());
        }
    }); }

    // --- MFT (_OVERVIEW/MFT_Records.sqlite) ---
    if want("MFT") { announce("MFT"); guard!("MFT", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["$MFT"]));
        found(&paths);
        if let Some(p) = paths.first() {
            let out = cat("_OVERVIEW").join("MFT_Records.sqlite");
            let n = mft::parse_mft_stream(p, &out)?;
            println!("[+] {} rows -> {}", n, out.display());
        }
    }); }

    // --- SRUM (SRUM/<stem>.sqlite, table per provider) ---
    if want("SRUM") { announce("SRUM"); guard!("SRUM", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["SRUDB.dat"]));
        found(&paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let base = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "SRUDB".into());
            let name = uniq_name(&base, &mut taken);
            let out = cat("SRUM").join(format!("{}.sqlite", name));
            let tables = srum::parse_srum_stream(p, &out)?;
            for (t, n) in tables { println!("[+] {} rows -> {} [{}]", n, out.display(), t); }
        }
    }); }

    // --- JumpList (JUMPLIST/JumpList_Entries.sqlite) ---
    if want("JumpList") { announce("JumpList"); guard!("JumpList", {
        let rows = jumplist::parse_jumplists(&target)?;
        if !rows.is_empty() {
            let out = cat("JUMPLIST").join("JumpList_Entries.sqlite");
            write_table(&out, jumplist::JUMPLIST_TABLE, &rows, jumplist::JUMPLIST_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        } else { println!("[!] no matching files found"); }
    }); }

    // --- TaskScheduler (TASKSCHEDULER/TaskScheduler_Tasks.sqlite) ---
    if want("TaskScheduler") { announce("TaskScheduler"); guard!("TaskScheduler", {
        let rows = taskscheduler::parse_tasks(&target)?;
        if !rows.is_empty() {
            let out = cat("TASKSCHEDULER").join("TaskScheduler_Tasks.sqlite");
            write_table(&out, taskscheduler::TASK_TABLE, &rows, taskscheduler::TASK_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        } else { println!("[!] no matching files found"); }
    }); }

    // --- RdpCache (RDPCACHE/RdpBitmapCache.sqlite) ---
    if want("RdpCache") { announce("RdpCache"); guard!("RdpCache", {
        let rows = rdpcache::parse_rdpcache(&target)?;
        if !rows.is_empty() {
            let out = cat("RDPCACHE").join("RdpBitmapCache.sqlite");
            write_table(&out, rdpcache::RDP_TABLE, &rows, rdpcache::RDP_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        } else { println!("[!] no matching files found"); }
    }); }

    // --- WER (WER/WER_Reports.sqlite) ---
    if want("WER") { announce("WER"); guard!("WER", {
        let rows = wer::parse_wer(&target)?;
        if !rows.is_empty() {
            let out = cat("WER").join("WER_Reports.sqlite");
            write_table(&out, wer::WER_TABLE, &rows, wer::WER_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        } else { println!("[!] no matching files found"); }
    }); }

    // --- BrowserHistory (BROWSER/<account>.sqlite, table per source table) ---
    if want("BrowserHistory") { announce("BrowserHistory"); guard!("BrowserHistory", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["History"]));
        found(&paths);
        let mut taken = HashSet::new();
        for p in &paths {
            let acct = browser_account(p);
            let name = uniq_name(&acct, &mut taken);
            let out = cat("BROWSER").join(format!("{}.sqlite", name));
            let tables = browser_history::parse_history(p)?;
            for (t, cols, rows) in &tables {
                write_table_cols(&out, t, rows, cols, &[])?;
                println!("[+] {} rows -> {} [{}]", rows.len(), out.display(), t);
            }
        }
    }); }

    // --- BrowserCache (BROWSERCACHE/<account>_Chrome_Cache.sqlite) ---
    if want("BrowserCache") { announce("BrowserCache"); guard!("BrowserCache", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["index"]));
        found(&paths);
        for (name, rows) in browser_cache::parse_caches(&paths) {
            let out = cat("BROWSERCACHE").join(format!("{}.sqlite", name));
            write_table(&out, browser_cache::CACHE_TABLE, &rows, browser_cache::CACHE_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        }
    }); }

    // --- Prefetch (PREFETCH/Prefetch_Execution.sqlite + Prefetch_LoadedFiles.sqlite) ---
    if want("Prefetch") { announce("Prefetch"); guard!("Prefetch", {
        let paths = finder::dedupe_by_content(finder::by_extension(&target, &[".pf"]));
        found(&paths);
        if !paths.is_empty() {
            let (exec_rows, loaded_rows) = prefetch::parse_prefetch(&paths);
            let ex = cat("PREFETCH").join(format!("{}.sqlite", prefetch::EXEC_TABLE));
            write_table(&ex, prefetch::EXEC_TABLE, &exec_rows, prefetch::EXEC_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", exec_rows.len(), ex.display());
            let lf = cat("PREFETCH").join(format!("{}.sqlite", prefetch::LOADED_TABLE));
            write_table(&lf, prefetch::LOADED_TABLE, &loaded_rows, prefetch::LOADED_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", loaded_rows.len(), lf.display());
        }
    }); }

    // --- PowerShell console history (POWERSHELL/PowerShell_ConsoleHistory.sqlite) ---
    if want("PowerShell") { announce("PowerShell"); guard!("PowerShell", {
        let paths = finder::dedupe_by_content(finder::by_name(&target, &["ConsoleHost_history.txt"]));
        found(&paths);
        if !paths.is_empty() {
            let rows = powershell_history::parse_console_history(&paths)?;
            let out = cat("POWERSHELL").join(format!("{}.sqlite", powershell_history::PS_TABLE));
            write_table(&out, powershell_history::PS_TABLE, &rows, powershell_history::PS_FIELD_ORDER)?;
            println!("[+] {} rows -> {}", rows.len(), out.display());
        }
    }); }

    println!("=== _OVERVIEW ===");
    let ov = out_dir.join("_OVERVIEW");
    let write_ov = |name: &str, rows: Vec<Row>, skip_empty: bool| -> Result<()> {
        if rows.is_empty() && skip_empty { return Ok(()); }
        let out = ov.join(format!("{}.sqlite", name));
        write_table(&out, name, &rows, &[])?;
        println!("[+] {} rows -> {}", rows.len(), out.display());
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

    let run_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    case_store::update_host_status(case_id, host_id, cases_dir,
        &run_at, if had_error { "error" } else { "ok" }, artifacts_run)?;
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
