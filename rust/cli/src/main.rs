use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Result};
use wina_core::case_store;
use wina_core::pipeline::run_host;

// Debug subcommands (single-file parse, used for validation).
use wina_core::parsers::amcache::{
    parse_amcache, FILES_FIELD_ORDER, FILES_TABLE, PROGRAMS_FIELD_ORDER, PROGRAMS_TABLE,
};
use wina_core::parsers::browser_history::parse_history;
use wina_core::parsers::eventlog::parse_evtx_stream;
use wina_core::parsers::jumplist::{parse_jumplists, JUMPLIST_FIELD_ORDER, JUMPLIST_TABLE};
use wina_core::parsers::mft::parse_mft_stream;
use wina_core::parsers::rdpcache::{parse_rdpcache, RDP_FIELD_ORDER, RDP_TABLE};
use wina_core::parsers::registry::parse_hive_stream;
use wina_core::parsers::srum::parse_srum_stream;
use wina_core::parsers::taskscheduler::{parse_tasks, TASK_FIELD_ORDER, TASK_TABLE};
use wina_core::parsers::usnjrnl::parse_usn_stream;
use wina_core::parsers::wer::{parse_wer, WER_FIELD_ORDER, WER_TABLE};
use wina_core::sqlite::{write_table, write_table_cols};

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Minimal --key value parser (values may follow the flag).
fn flags(args: &[String]) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            let v = if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                i += 1;
                args[i].clone()
            } else {
                String::new()
            };
            m.insert(k.to_string(), v);
        }
        i += 1;
    }
    m
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Debug parse-* subcommands (kept for validation).
    if let Some(cmd) = args.first() {
        if cmd.starts_with("parse-") {
            return debug_parse(&args);
        }
    }

    let f = flags(&args);
    if f.contains_key("list-artifacts") {
        println!(
            "{}",
            serde_json::to_string(wina_core::pipeline::ARTIFACT_NAMES)?
        );
        return Ok(());
    }
    let cases_dir = PathBuf::from(
        f.get("cases-dir")
            .ok_or_else(|| anyhow::anyhow!("--cases-dir required"))?,
    )
    .canonicalize()
    .unwrap_or_else(|_| PathBuf::from(f.get("cases-dir").unwrap()));

    if f.contains_key("list-cases") {
        let cases = case_store::list_cases(&cases_dir)?;
        println!("{}", serde_json::to_string(&cases)?);
    } else if let Some(name) = f.get("create-case") {
        let c = case_store::create_case(name, &now(), &cases_dir)?;
        println!("{}", serde_json::to_string(&c)?);
    } else if let Some(case_id) = f.get("create-host") {
        let (name, target) = (f.get("name"), f.get("target"));
        let (name, target) = match (name, target) {
            (Some(n), Some(t)) => (n, t),
            _ => bail!("--create-host requires --name and --target"),
        };
        let target = std::fs::canonicalize(target)
            .unwrap_or_else(|_| PathBuf::from(target))
            .to_string_lossy()
            .to_string();
        let h = case_store::create_host(case_id, name, &target, &now(), &cases_dir)?;
        println!("{}", serde_json::to_string(&h)?);
    } else if let Some(case_id) = f.get("run-host") {
        let host = f
            .get("host")
            .ok_or_else(|| anyhow::anyhow!("--run-host requires --host"))?;
        let only: Option<HashSet<String>> = f
            .get("only")
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|x| x.to_string()).collect());
        run_host(case_id, host, &cases_dir, only)?;
    } else {
        bail!("one of --create-case, --create-host, --run-host, --list-cases, --list-artifacts is required");
    }
    Ok(())
}

fn debug_parse(args: &[String]) -> Result<()> {
    let cmd = args[0].as_str();
    if args.len() != 3 {
        bail!("usage: wina {} <input> <out.sqlite>", cmd);
    }
    let inp = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    match cmd {
        "parse-mft" => {
            let n = parse_mft_stream(&inp, &out)?;
            eprintln!("MFT: {} rows", n);
        }
        "parse-reg" => {
            let n = parse_hive_stream(&inp, &out)?;
            eprintln!("Registry: {} rows", n);
        }
        "parse-evtx" => {
            let stem = inp
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "EventLog".into());
            let n = parse_evtx_stream(&inp, &out, &stem)?;
            eprintln!("EventLog[{}]: {} rows", stem, n);
        }
        "parse-usn" => {
            let n = parse_usn_stream(&inp, &out)?;
            eprintln!("UsnJrnl: {} rows", n);
        }
        "parse-amcache" => {
            let (p, fl) = parse_amcache(&inp)?;
            write_table(&out, PROGRAMS_TABLE, &p, PROGRAMS_FIELD_ORDER)?;
            write_table(&out, FILES_TABLE, &fl, FILES_FIELD_ORDER)?;
            eprintln!("Amcache: {} programs, {} files", p.len(), fl.len());
        }
        "parse-tasks" => {
            let r = parse_tasks(&inp)?;
            write_table(&out, TASK_TABLE, &r, TASK_FIELD_ORDER)?;
            eprintln!("TaskScheduler: {} tasks", r.len());
        }
        "parse-jumplists" => {
            let r = parse_jumplists(&inp)?;
            write_table(&out, JUMPLIST_TABLE, &r, JUMPLIST_FIELD_ORDER)?;
            eprintln!("JumpList: {} entries", r.len());
        }
        "parse-srum" => {
            let t = parse_srum_stream(&inp, &out)?;
            for (n, c) in &t {
                eprintln!("  {} : {} rows", n, c);
            }
            eprintln!("SRUM: {} tables", t.len());
        }
        "parse-wer" => {
            let r = parse_wer(&inp)?;
            write_table(&out, WER_TABLE, &r, WER_FIELD_ORDER)?;
            eprintln!("WER: {} reports", r.len());
        }
        "parse-history" => {
            let t = parse_history(&inp)?;
            for (n, cols, rows) in &t {
                write_table_cols(&out, n, rows, cols, &[])?;
            }
            eprintln!("BrowserHistory: {} tables", t.len());
        }
        "parse-rdpcache" => {
            let r = parse_rdpcache(&inp)?;
            write_table(&out, RDP_TABLE, &r, RDP_FIELD_ORDER)?;
            eprintln!("RdpCache: {} rows", r.len());
        }
        other => bail!("unknown command: {}", other),
    }
    Ok(())
}
