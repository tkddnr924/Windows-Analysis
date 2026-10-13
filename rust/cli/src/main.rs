use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Result};
use wina_core::case_store;
use wina_core::pipeline::run_host;

// Debug subcommands (single-file parse, used for validation).
use wina_core::parsers::amcache::{
    parse_amcache, FILES_FIELD_ORDER, FILES_TABLE, PROGRAMS_FIELD_ORDER, PROGRAMS_TABLE,
};
use wina_core::parsers::browser_history::parse_history_stream;
use wina_core::parsers::eventlog::parse_evtx_stream;
use wina_core::parsers::jumplist::{parse_jumplists, JUMPLIST_FIELD_ORDER, JUMPLIST_TABLE};
use wina_core::parsers::mft::parse_mft_stream;
use wina_core::parsers::rdpcache::{parse_rdpcache, RDP_FIELD_ORDER, RDP_TABLE};
use wina_core::parsers::recyclebin::{parse_recyclebin, recyclebin_sources, RecycleBinContext};
use wina_core::parsers::registry::parse_hive_stream;
use wina_core::parsers::srum::parse_srum_stream;
use wina_core::parsers::taskscheduler::{parse_tasks, TASK_FIELD_ORDER, TASK_TABLE};
use wina_core::parsers::usnjrnl::parse_usn_stream;
use wina_core::parsers::wer::{parse_wer, WER_FIELD_ORDER, WER_TABLE};
use wina_core::sqlite::{write_fixed_table, write_table};

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

type Flags = std::collections::HashMap<String, Option<String>>;

/// Minimal --key value parser; a flag with no following value maps to None.
fn flags(args: &[String]) -> Flags {
    let mut m = Flags::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            let v = if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                i += 1;
                Some(args[i].clone())
            } else {
                None
            };
            m.insert(k.to_string(), v);
        }
        i += 1;
    }
    m
}

/// Value of a flag that requires one: absent -> None, present but empty -> error.
fn value<'a>(f: &'a Flags, key: &str) -> Result<Option<&'a str>> {
    match f.get(key) {
        None => Ok(None),
        Some(Some(v)) if !v.trim().is_empty() => Ok(Some(v.as_str())),
        Some(_) => bail!("--{key} requires a value"),
    }
}

/// `--only a,b` artifact subset; None means every artifact.
fn only_artifacts(f: &Flags) -> Result<Option<HashSet<String>>> {
    let Some(list) = value(f, "only")? else {
        return Ok(None);
    };
    let set: HashSet<String> = list
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect();
    if set.is_empty() {
        bail!("--only requires at least one artifact name");
    }
    Ok(Some(set))
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
    let cases_dir = value(&f, "cases-dir")?
        .ok_or_else(|| anyhow::anyhow!("--cases-dir required"))?;
    let cases_dir = PathBuf::from(cases_dir)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(cases_dir));

    if f.contains_key("list-cases") {
        let cases = case_store::list_cases(&cases_dir)?;
        println!("{}", serde_json::to_string(&cases)?);
    } else if f.contains_key("create-case") {
        let name = value(&f, "create-case")?.unwrap_or_default();
        let c = case_store::create_case(name, &now(), &cases_dir)?;
        println!("{}", serde_json::to_string(&c)?);
    } else if f.contains_key("create-host") {
        let case_id = value(&f, "create-host")?.unwrap_or_default();
        let (name, target) = match (value(&f, "name")?, value(&f, "target")?) {
            (Some(n), Some(t)) => (n, t),
            _ => bail!("--create-host requires --name and --target"),
        };
        let target = std::fs::canonicalize(target)
            .unwrap_or_else(|_| PathBuf::from(target))
            .to_string_lossy()
            .to_string();
        let h = case_store::create_host(case_id, name, &target, &now(), &cases_dir)?;
        println!("{}", serde_json::to_string(&h)?);
    } else if f.contains_key("run-host") {
        let case_id = value(&f, "run-host")?.unwrap_or_default();
        let host = value(&f, "host")?
            .ok_or_else(|| anyhow::anyhow!("--run-host requires --host"))?;
        let only = only_artifacts(&f)?;
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
        "parse-recyclebin" => {
            let found = recyclebin_sources(&inp);
            if !found.errors.is_empty() {
                bail!("RecycleBin discovery: {}", found.errors.join("; "));
            }
            let parsed = parse_recyclebin(&found.paths, &[], &out, &RecycleBinContext::default())?;
            eprintln!("RecycleBin: {} rows, {} failed", parsed.rows, parsed.failed_rows);
            if parsed.failed_rows > 0 {
                bail!("RecycleBin contains failed inputs");
            }
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
            let parsed = parse_amcache(&inp, &wina_core::parsers::registry::sibling_logs(&inp))?;
            if let Some(reason) = &parsed.log_apply_error {
                eprintln!("Amcache: log apply failed, parsed primary hive only ({reason})");
            }
            write_table(&out, PROGRAMS_TABLE, &parsed.programs, PROGRAMS_FIELD_ORDER)?;
            write_table(&out, FILES_TABLE, &parsed.files, FILES_FIELD_ORDER)?;
            eprintln!(
                "Amcache: {} programs, {} files",
                parsed.programs.len(),
                parsed.files.len()
            );
        }
        "parse-tasks" => {
            let r = parse_tasks(&inp)?;
            let count = write_fixed_table(&out, TASK_TABLE, r, TASK_FIELD_ORDER)?;
            eprintln!("TaskScheduler: {} tasks", count);
        }
        "parse-jumplists" => {
            let r = parse_jumplists(&inp)?;
            write_table(&out, JUMPLIST_TABLE, &r, JUMPLIST_FIELD_ORDER)?;
            eprintln!("JumpList: {} entries", r.len());
        }
        "parse-srum" => {
            let parsed = parse_srum_stream(&inp, &out)?;
            for (n, c) in &parsed.tables {
                eprintln!("  {} : {} rows", n, c);
            }
            for note in &parsed.skipped {
                eprintln!("  skipped: {note}");
            }
            eprintln!("SRUM: {} tables", parsed.tables.len());
        }
        "parse-wer" => {
            let r = parse_wer(&inp)?;
            let count = write_fixed_table(&out, WER_TABLE, r, WER_FIELD_ORDER)?;
            eprintln!("WER: {} reports", count);
        }
        "parse-history" => {
            let sides = wina_core::parsers::timeline::wal_siblings(&inp);
            let parsed = parse_history_stream(&inp, &sides, &out)?;
            eprintln!("BrowserHistory: {} rows", parsed.rows);
            for error in &parsed.table_errors {
                eprintln!("BrowserHistory: table skipped: {error}");
            }
        }
        "parse-rdpcache" => {
            let r = parse_rdpcache(&inp)?;
            write_table(&out, RDP_TABLE, &r, RDP_FIELD_ORDER)?;
            eprintln!("RdpCache: {} rows", r.len());
        }
        other => bail!("unknown command: {}", other),
    }
    wina_core::derived::stamp_facts_generation(&out, &uuid::Uuid::new_v4().to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Flags {
        flags(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn valueless_only_is_rejected_not_full_run() {
        assert!(only_artifacts(&args(&["--run-host", "c", "--only", "--host", "h"])).is_err());
        assert!(only_artifacts(&args(&["--only", ","])).is_err());
        assert_eq!(only_artifacts(&args(&["--host", "h"])).unwrap(), None);
        let set = only_artifacts(&args(&["--only", "Registry,Amcache"])).unwrap().unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn valueless_cases_dir_is_rejected() {
        assert!(value(&args(&["--cases-dir", "--list-cases"]), "cases-dir").is_err());
        assert_eq!(value(&args(&["--cases-dir", "x"]), "cases-dir").unwrap(), Some("x"));
    }
}
