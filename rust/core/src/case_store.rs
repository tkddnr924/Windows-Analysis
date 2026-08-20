//! Case/host registry, mirroring common/case_store.py:
//!   <cases_dir>/<case_id>/case.json
//!   <cases_dir>/<case_id>/<host_id>/host.json
//! JSON field names/order match the Python dataclasses so the Electron viewer
//! parses the CLI output unchanged.
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub target_dir: String,
    pub created_at: String,
    #[serde(default)]
    pub last_run_at: Option<String>,
    #[serde(default)]
    pub last_run_status: Option<String>,
    #[serde(default)]
    pub artifacts_run: Vec<String>,
    #[serde(default)]
    pub last_run_duration_secs: Option<f64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Case {
    pub id: String,
    pub name: String,
    pub created_at: String,
    #[serde(default)]
    pub hosts: Vec<Host>,
}

/// Current local time as "YYYY-MM-DD HH:MM:SS" (case/host timestamp format).
pub fn now() -> String { chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string() }

pub fn case_dir(cases_dir: &Path, case_id: &str) -> PathBuf { cases_dir.join(case_id) }
pub fn host_dir(cases_dir: &Path, case_id: &str, host_id: &str) -> PathBuf { case_dir(cases_dir, case_id).join(host_id) }
fn case_meta(cases_dir: &Path, case_id: &str) -> PathBuf { case_dir(cases_dir, case_id).join("case.json") }
fn host_meta(cases_dir: &Path, case_id: &str, host_id: &str) -> PathBuf { host_dir(cases_dir, case_id, host_id).join("host.json") }

/// Python _slugify: replace runs of non-[word.-] with "_", strip leading/trailing "_".
/// \w (unicode) = alphanumeric + underscore across scripts.
fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut prev_us = false;
    for c in name.trim().chars() {
        if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' {
            out.push(c);
            prev_us = false;
        } else if !prev_us {
            out.push('_');
            prev_us = true;
        }
    }
    let s = out.trim_matches('_').to_string();
    if s.is_empty() { "item".to_string() } else { s }
}

fn id_for(name: &str, created_at: &str) -> String {
    let compact: String = created_at.replace(':', "").replace('-', "").replace(' ', "_");
    format!("{}_{}", slugify(name), compact)
}

pub fn create_case(name: &str, created_at: &str, cases_dir: &Path) -> Result<Case> {
    let case_id = id_for(name, created_at);
    let case = Case { id: case_id.clone(), name: name.to_string(), created_at: created_at.to_string(), hosts: vec![] };
    std::fs::create_dir_all(case_dir(cases_dir, &case_id))?;
    let meta = serde_json::json!({"id": case.id, "name": case.name, "created_at": case.created_at});
    std::fs::write(case_meta(cases_dir, &case_id), serde_json::to_string_pretty(&meta)?)?;
    Ok(case)
}

pub fn create_host(case_id: &str, name: &str, target_dir: &str, created_at: &str, cases_dir: &Path) -> Result<Host> {
    let host_id = id_for(name, created_at);
    let host = Host {
        id: host_id.clone(), name: name.to_string(), target_dir: target_dir.to_string(),
        created_at: created_at.to_string(), last_run_at: None, last_run_status: None, artifacts_run: vec![],
        last_run_duration_secs: None,
    };
    std::fs::create_dir_all(host_dir(cases_dir, case_id, &host_id))?;
    write_host(&host, cases_dir, case_id)?;
    Ok(host)
}

fn write_host(host: &Host, cases_dir: &Path, case_id: &str) -> Result<()> {
    std::fs::write(host_meta(cases_dir, case_id, &host.id), serde_json::to_string_pretty(host)?)?;
    Ok(())
}

pub fn load_host(case_id: &str, host_id: &str, cases_dir: &Path) -> Result<Host> {
    let raw = std::fs::read_to_string(host_meta(cases_dir, case_id, host_id))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn list_cases(cases_dir: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    let entries = match std::fs::read_dir(cases_dir) { Ok(e) => e, Err(_) => return Ok(cases) };
    for entry in entries.flatten() {
        if !entry.path().is_dir() { continue; }
        let meta = entry.path().join("case.json");
        let raw = match std::fs::read_to_string(&meta) { Ok(r) => r, Err(_) => continue };
        let mut case: Case = match serde_json::from_str(&raw) { Ok(c) => c, Err(_) => continue };
        // load hosts from subdirs
        if let Ok(subs) = std::fs::read_dir(entry.path()) {
            for sub in subs.flatten() {
                if !sub.path().is_dir() { continue; }
                let hmeta = sub.path().join("host.json");
                if let Ok(hraw) = std::fs::read_to_string(&hmeta) {
                    if let Ok(h) = serde_json::from_str::<Host>(&hraw) { case.hosts.push(h); }
                }
            }
        }
        case.hosts.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        cases.push(case);
    }
    cases.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(cases)
}

pub fn update_host_status(case_id: &str, host_id: &str, cases_dir: &Path, run_at: &str, status: &str, artifacts_run: Vec<String>, duration_secs: Option<f64>) -> Result<()> {
    let mut host = load_host(case_id, host_id, cases_dir)?;
    host.last_run_at = Some(run_at.to_string());
    host.last_run_status = Some(status.to_string());
    host.artifacts_run = artifacts_run;
    host.last_run_duration_secs = duration_secs;
    write_host(&host, cases_dir, case_id)
}
