// Tauri backend for the Windows-Analysis viewer. Replaces the Electron main
// process. Everything links wina-core directly — the app is a single
// self-contained binary with no sidecar.
//
// Case metadata and data reads (categories, result tables, $MFT browse, search,
// bookmarks) run in-process via wina-core/rusqlite. PARSING, however, runs in a
// child process: this same executable re-invoked with the hidden --__parse flag
// (see run_as_parse_worker). That keeps the heavy work off the GUI process and,
// crucially, makes cancel instant — a process can be killed, a thread can't.
//
// The React frontend is unchanged — a small `window.api` shim maps its calls
// onto these commands.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]


use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter};
use url::Url;
use wina_core::sqlite::write_table;
use wina_core::{case_store, overview, pipeline};

// --- paths -----------------------------------------------------------------

/// True when running from a `cargo`/`tauri dev` build tree (exe under target/).
fn is_dev_build() -> bool {
    std::env::current_exe()
        .ok()
        .map(|p| {
            let s = p.to_string_lossy().to_lowercase();
            s.contains("/target/debug/")
                || s.contains("/target/release/")
                || s.contains("\\target\\debug\\")
                || s.contains("\\target\\release\\")
        })
        .unwrap_or(false)
}

fn dev_repo_path(rel: &str) -> PathBuf {
    // viewer/src-tauri -> repo root
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    for part in rel.split('/') {
        p.push(part);
    }
    p
}

fn cases_dir() -> PathBuf {
    if let Ok(d) = std::env::var("WINA_CASES_DIR") {
        return PathBuf::from(d);
    }
    if is_dev_build() {
        return dev_repo_path("cases");
    }
    // Packaged: a `cases` folder next to the app executable.
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("cases")))
        .unwrap_or_else(|| dev_repo_path("cases"))
}

// --- shared types (camelCase to match the frontend) ------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    id: String,
    name: String,
    target_dir: String,
    dir: String,
    created_at: String,
    last_run_at: Option<String>,
    last_run_status: Option<String>,
    artifacts_run: Vec<String>,
    last_run_duration_secs: Option<f64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    id: String,
    name: String,
    created_at: String,
    dir: String,
    hosts: Vec<Host>,
}

#[derive(Serialize)]
struct ListCasesResult {
    cases: Vec<Case>,
    error: Option<String>,
}

// --- wina-core mapping (add the frontend's `dir` field) --------------------

fn gui_host(case_id: &str, h: &case_store::Host, cd: &Path) -> Host {
    Host {
        dir: case_store::host_dir(cd, case_id, &h.id)
            .to_string_lossy()
            .to_string(),
        id: h.id.clone(),
        name: h.name.clone(),
        target_dir: h.target_dir.clone(),
        created_at: h.created_at.clone(),
        last_run_at: h.last_run_at.clone(),
        last_run_status: h.last_run_status.clone(),
        artifacts_run: h.artifacts_run.clone(),
        last_run_duration_secs: h.last_run_duration_secs,
    }
}

fn gui_case(c: &case_store::Case, cd: &Path) -> Case {
    Case {
        dir: case_store::case_dir(cd, &c.id)
            .to_string_lossy()
            .to_string(),
        id: c.id.clone(),
        name: c.name.clone(),
        created_at: c.created_at.clone(),
        hosts: c.hosts.iter().map(|h| gui_host(&c.id, h, cd)).collect(),
    }
}

// --- sqlite plumbing -------------------------------------------------------

fn open_ro(path: &str) -> Result<Connection, String> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())
}

fn cell(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => {
            Value::from(b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
        }
    }
}

fn q(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn query_rows(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<Map<String, Value>>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params, |r| {
            let mut obj = Map::new();
            for (i, name) in cols.iter().enumerate() {
                obj.insert(name.clone(), cell(r.get_ref(i)?));
            }
            Ok(obj)
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn table_names(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid")
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(0))
                .map(|m| m.filter_map(|x| x.ok()).collect::<Vec<String>>())
        })
        .map(|names: Vec<String>| {
            // `_wina_*`는 파이프라인 내부 메타(출처 매핑 등) — 증거 테이블이
            // 아니므로 목록·기본 테이블 선택 어디에도 노출하지 않는다.
            names
                .into_iter()
                .filter(|name| !name.starts_with("_wina_"))
                .collect()
        })
        .unwrap_or_default()
}

fn checked_table_names(conn: &Connection) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid")
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    Ok(rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|name: &String| !name.starts_with("_wina_"))
        .collect())
}

fn first_table(conn: &Connection) -> Option<String> {
    table_names(conn).into_iter().next()
}

fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info({})", q(table)))
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(1))
                .map(|m| m.filter_map(|x| x.ok()).collect())
        })
        .unwrap_or_default()
}

// --- account identity directory ------------------------------------------

/// A compact, display-only SID directory read from the already parsed
/// TargetInfo overview.  This is deliberately not a second parser: when a
/// host has no SAM/ProfileList result (or a partial one), the caller simply
/// keeps the original SID visible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountDirectoryEntry {
    sid: String,
    account_name: String,
    source_artifact: String,
}

fn is_exact_sid(value: &str) -> bool {
    let value = value.trim();
    let mut parts = value.split('-');
    matches!(parts.next(), Some(prefix) if prefix.eq_ignore_ascii_case("s"))
        && parts.clone().next().is_some()
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn built_in_account_name(sid: &str) -> Option<&'static str> {
    match sid.to_ascii_uppercase().as_str() {
        "S-1-5-18" => Some("LocalSystem"),
        "S-1-5-19" => Some("LocalService"),
        "S-1-5-20" => Some("NetworkService"),
        _ => None,
    }
}

fn account_source_priority(source: &str) -> u8 {
    match source.trim().to_ascii_lowercase().as_str() {
        // SAM supplies the account name directly. Prefer it when both SAM and
        // ProfileList describe the same SID.
        "sam" => 2,
        "profilelist" => 1,
        _ => 0,
    }
}

fn account_directory_from_rows(
    rows: impl IntoIterator<Item = (String, String, String)>,
) -> Vec<AccountDirectoryEntry> {
    let mut selected: BTreeMap<String, (String, String, String, u8)> = BTreeMap::new();

    for (sid, account_name, source_artifact) in rows {
        let sid = sid.trim().to_string();
        let account_name = account_name.trim().to_string();
        if !is_exact_sid(&sid) || account_name.is_empty() || account_name.eq_ignore_ascii_case(&sid)
        {
            continue;
        }
        let key = sid.to_ascii_lowercase();
        let priority = account_source_priority(&source_artifact);
        let should_replace = selected
            .get(&key)
            .map(|(_, _, _, previous_priority)| priority > *previous_priority)
            .unwrap_or(true);
        if should_replace {
            selected.insert(key, (sid, account_name, source_artifact, priority));
        }
    }

    // The parsed account rows are authoritative. Well-known local service
    // identities are only a safe fallback when the overview does not include
    // them; never guess a domain/account RID.
    for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
        selected.entry(sid.to_ascii_lowercase()).or_insert_with(|| {
            (
                sid.to_string(),
                built_in_account_name(sid).unwrap_or_default().to_string(),
                "WellKnown".to_string(),
                0,
            )
        });
    }

    selected
        .into_values()
        .map(
            |(sid, account_name, source_artifact, _)| AccountDirectoryEntry {
                sid,
                account_name,
                source_artifact,
            },
        )
        .collect()
}

#[tauri::command]
fn account_directory(host_dir: String) -> Result<Vec<AccountDirectoryEntry>, String> {
    let path = Path::new(&host_dir)
        .join("_OVERVIEW")
        .join("TargetInfo.sqlite");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let conn = open_ro(&path.to_string_lossy())?;
    let tables = checked_table_names(&conn)?;
    let Some(table) = tables.into_iter().find(|table| table == "TargetInfo") else {
        return Ok(Vec::new());
    };
    let columns = table_columns(&conn, &table);
    if !["category", "name", "username", "source_artifact"]
        .iter()
        .all(|required| columns.iter().any(|column| column == required))
    {
        return Ok(Vec::new());
    }
    let rows = query_rows(
        &conn,
        &format!(
            "SELECT name, username, source_artifact FROM {} WHERE category = ?1",
            q(&table)
        ),
        &[&"Account"],
    )?;
    Ok(account_directory_from_rows(rows.into_iter().map(|row| {
        let get = |key: &str| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        (get("name"), get("username"), get("source_artifact"))
    })))
}

const EMPTY_SQLITE_MAX_BYTES: u64 = 100;

fn collect_sqlite(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_sqlite(&p, out);
            } else if p.extension().map(|x| x == "sqlite").unwrap_or(false)
                && std::fs::metadata(&p)
                    .map(|m| m.len() > EMPTY_SQLITE_MAX_BYTES)
                    .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
}

// --- commands: cases / pipeline (in-process via wina-core) -----------------

#[tauri::command]
fn list_cases() -> ListCasesResult {
    let cd = cases_dir();
    match case_store::list_cases(&cd) {
        Ok(cases) => ListCasesResult {
            cases: cases.iter().map(|c| gui_case(c, &cd)).collect(),
            error: None,
        },
        Err(e) => ListCasesResult {
            cases: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
fn create_case(name: String) -> Result<Case, String> {
    let cd = cases_dir();
    let c = case_store::create_case(&name, &case_store::now(), &cd).map_err(|e| e.to_string())?;
    Ok(gui_case(&c, &cd))
}

#[tauri::command]
fn create_host(case_id: String, name: String, target_dir: String) -> Result<Host, String> {
    let cd = cases_dir();
    let h = case_store::create_host(&case_id, &name, &target_dir, &case_store::now(), &cd)
        .map_err(|e| e.to_string())?;
    Ok(gui_host(&case_id, &h, &cd))
}

#[tauri::command]
fn rename_host(case_id: String, host_id: String, name: String) -> Result<Host, String> {
    if !valid_id(&case_id) || !valid_id(&host_id) {
        return Err("invalid case or host identifier".into());
    }
    let cd = cases_dir();
    let host = case_store::rename_host(&case_id, &host_id, &name, &cd)
        .map_err(|error| error.to_string())?;
    Ok(gui_host(&case_id, &host, &cd))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id != "." && id != ".." && !id.contains(['/', '\\']) && !id.contains("..")
}

#[tauri::command]
fn delete_case(case_id: String) -> bool {
    // CASE_* folders no longer exist. Refuse this legacy broad-delete command
    // rather than risking removal of the direct host-store root.
    let _ = case_id;
    false
}

#[tauri::command]
async fn delete_host(case_id: String, host_id: String) -> bool {
    // 수 GB 호스트 폴더의 remove_dir_all — 메인 스레드에서 돌리면 삭제가
    // 끝날 때까지 창이 멈춘다.
    tauri::async_runtime::spawn_blocking(move || {
        if !valid_id(&case_id) || !valid_id(&host_id) {
            return false;
        }
        let case_dir = case_store::case_dir(&cases_dir(), &case_id);
        delete_host_dir_and_bookmarks(&case_dir, &host_id)
    })
    .await
    .unwrap_or(false)
}

fn delete_host_dir_and_bookmarks(case_dir: &Path, host_id: &str) -> bool {
    let target = case_dir.join(host_id);
    if !target.exists() || std::fs::remove_dir_all(&target).is_err() {
        return false;
    }

    // Bookmarks are stored once at the direct host-store root while their source
    // rows live under a host directory. Delete only annotations tied to the removed host
    // after its output directory has been removed. `hostName` is deliberately
    // not used: several registered hosts can share a display name.
    let bookmarks = match read_bookmarks_path(case_dir) {
        Ok(bookmarks) => bookmarks,
        Err(_) => return false,
    };
    let bookmark_count = bookmarks.len();
    let retained: Vec<Value> = bookmarks
        .into_iter()
        .filter(|bookmark| !bookmark_belongs_to_host(bookmark, host_id, &target))
        .collect();
    if retained.len() != bookmark_count {
        // The host directory has already been removed, so report a failed
        // cleanup instead of pretending the case-level annotations were
        // persisted. `list_bookmarks` will retry the safely attributable
        // orphan cleanup on the next load.
        if write_bookmarks_path(case_dir, &retained).is_err() {
            return false;
        }
    }
    true
}

#[tauri::command]
fn list_artifacts() -> Vec<String> {
    pipeline::ARTIFACT_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunHostOptions {
    case_id: String,
    host_id: String,
    /// The renderer creates one immutable id before queueing a run. It is
    /// deliberately restricted to the same path-safe alphabet as case/host
    /// ids because it is also the name of the persistent run log.
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    only: Option<Vec<String>>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PipelineLogEntry {
    run_id: String,
    host_id: String,
    /// queued | running | complete | partial | error | cancelled. Regular stream
    /// output is emitted with `running`, allowing every renderer to keep
    /// independent per-run state rather than guessing from message order.
    status: String,
    line: String,
    stream: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineResult {
    run_id: String,
    host_id: String,
    status: String,
    exit_code: Option<i32>,
}

/// Tracks the running parse child and its immutable host-side log so GUI
/// supervision can record forced termination even after the child is gone.
struct RunningPipeline {
    child: std::process::Child,
    log_path: PathBuf,
}

const MAX_HOST_PIPELINES: usize = 2;

/// A bounded, keyed child supervisor. A run reserves a slot before spawning
/// so concurrent commands can never exceed `MAX_HOST_PIPELINES`; cancellation
/// can target an already-running child or a run that is still waiting.
#[derive(Default)]
struct PipelineScheduler {
    running: HashMap<String, RunningPipeline>,
    reserving: HashSet<String>,
    queued: HashSet<String>,
    cancelled: HashSet<String>,
    host_ids: HashMap<String, String>,
    case_ids: HashMap<String, String>,
}

#[derive(Default)]
struct PipelineState(std::sync::Mutex<PipelineScheduler>);

fn reserve_pipeline_slot(scheduler: &mut PipelineScheduler, run_id: &str, host_id: &str) -> bool {
    if scheduler.running.len() + scheduler.reserving.len() >= MAX_HOST_PIPELINES {
        return false;
    }
    // A host directory is the publish/report/status unit. Two children for the
    // same host would race over its staging parent and latest parse report even
    // though their run ids differ, so only distinct hosts may occupy slots.
    let same_host_is_active = scheduler
        .running
        .keys()
        .chain(scheduler.reserving.iter())
        .any(|other_run_id| {
            other_run_id != run_id
                && scheduler
                    .host_ids
                    .get(other_run_id)
                    .is_some_and(|other_host_id| other_host_id == host_id)
        });
    if same_host_is_active {
        return false;
    }
    scheduler.queued.remove(run_id);
    scheduler.reserving.insert(run_id.to_string());
    true
}

fn append_supervisor_log(log_path: &Path, event: &str) {
    pipeline::append_parse_log_event(log_path, &format!("[SUPERVISOR] {}", event));
}

fn record_child_exit(log_path: &Path, exit_code: Option<i32>) {
    if exit_code == Some(0) {
        return;
    }
    let outcome = exit_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string());
    append_supervisor_log(
        log_path,
        &format!("child_exit status=nonzero exit_code={outcome}"),
    );
}

/// The parser intentionally exits nonzero for a partial run so automation
/// cannot mistake a source failure for success.  The durable report carries
/// the finer terminal state; read only that tiny manifest here rather than
/// inferring meaning from the child exit code.
fn terminal_pipeline_status(host_dir: &Path, exit_code: Option<i32>) -> &'static str {
    if exit_code == Some(0) {
        return "complete";
    }
    let is_partial = std::fs::read_to_string(host_dir.join("parse_report.json"))
        .ok()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(&payload).ok())
        .and_then(|report| {
            report
                .get("status")
                .and_then(|status| status.as_str())
                .map(str::to_owned)
        })
        .is_some_and(|status| status == "partial");
    if is_partial {
        "partial"
    } else {
        "error"
    }
}

fn record_forced_gui_cancel(log_path: &Path, killed: bool) {
    append_supervisor_log(
        log_path,
        if killed {
            "termination status=forced reason=gui_cancel"
        } else {
            "termination status=unknown reason=gui_cancel_kill_failed"
        },
    );
}

fn emit_pipeline_event(
    app: &AppHandle,
    run_id: &str,
    host_id: &str,
    status: &str,
    stream: &str,
    line: impl Into<String>,
) {
    let _ = app.emit(
        "pipeline-log",
        PipelineLogEntry {
            run_id: run_id.to_string(),
            host_id: host_id.to_string(),
            status: status.to_string(),
            line: line.into(),
            stream: stream.to_string(),
        },
    );
}

fn pipeline_result(
    run_id: &str,
    host_id: &str,
    status: &str,
    exit_code: Option<i32>,
) -> PipelineResult {
    PipelineResult {
        run_id: run_id.to_string(),
        host_id: host_id.to_string(),
        status: status.to_string(),
        exit_code,
    }
}

/// GUI cancellation kills the worker deliberately, so the worker cannot write
/// its own final manifest. Persist an explicit terminal record in the parent
/// instead of leaving a prior successful report/status visible after reload.
fn write_cancelled_terminal_state(case_id: &str, host_id: &str, run_id: &str) {
    write_cancelled_terminal_state_at(&cases_dir(), case_id, host_id, run_id);
}

fn write_cancelled_terminal_state_at(cases: &Path, case_id: &str, host_id: &str, run_id: &str) {
    if !valid_id(case_id) || !valid_id(host_id) || !valid_id(run_id) {
        return;
    }
    let host_dir = case_store::host_dir(cases, case_id, host_id);
    let run_at = case_store::now();
    let report = serde_json::json!({
        "runId": run_id,
        "runAt": run_at,
        "status": "cancelled",
        "durationMs": 0,
        "published": false,
        "artifacts": [],
        "overview": [],
    });
    let payload = match serde_json::to_vec_pretty(&report) {
        Ok(payload) => payload,
        Err(_) => return,
    };
    let run_manifest = pipeline::parse_run_log_path(&host_dir, run_id).with_extension("json");
    if let Some(parent) = run_manifest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(run_manifest, &payload);
    let temporary = host_dir.join("parse_report.json.cancelled-staging");
    if std::fs::write(&temporary, payload).is_ok() {
        let _ = std::fs::rename(temporary, host_dir.join("parse_report.json"));
    }
    let _ = case_store::update_host_status(
        case_id,
        host_id,
        cases,
        &run_at,
        "cancelled",
        Vec::new(),
        None,
    );
}

#[tauri::command]
async fn run_host(
    app: AppHandle,
    state: tauri::State<'_, PipelineState>,
    options: RunHostOptions,
) -> Result<PipelineResult, String> {
    if !valid_id(&options.case_id) || !valid_id(&options.host_id) {
        return Err("invalid case or host identifier".into());
    }
    // A direct host path must exist before the scheduler records a run/log
    // location. This also upgrades legacy CASE_* folders for CLI-style calls
    // that start a parse without first opening the host list.
    let cd = cases_dir();
    case_store::ensure_direct_host_store(&cd).map_err(|error| error.to_string())?;
    let run_id = options.run_id.unwrap_or_else(pipeline::new_parse_run_id);
    if !valid_id(&run_id) {
        return Err("invalid pipeline run identifier".into());
    }
    {
        let mut scheduler = state
            .0
            .lock()
            .map_err(|_| "pipeline scheduler unavailable")?;
        if scheduler.running.contains_key(&run_id)
            || scheduler.reserving.contains(&run_id)
            || scheduler.queued.contains(&run_id)
        {
            return Err("duplicate pipeline run identifier".into());
        }
        scheduler.queued.insert(run_id.clone());
        scheduler
            .host_ids
            .insert(run_id.clone(), options.host_id.clone());
        scheduler
            .case_ids
            .insert(run_id.clone(), options.case_id.clone());
    }
    emit_pipeline_event(
        &app,
        &run_id,
        &options.host_id,
        "queued",
        "lifecycle",
        "[LIFECYCLE] queued",
    );

    // Do not reject additional hosts. They wait for a bounded slot, while a
    // cancellation can still remove them before any parser process is born.
    loop {
        let (cancelled, slot_acquired) = {
            let mut scheduler = state
                .0
                .lock()
                .map_err(|_| "pipeline scheduler unavailable")?;
            if scheduler.cancelled.remove(&run_id) {
                scheduler.queued.remove(&run_id);
                scheduler.host_ids.remove(&run_id);
                scheduler.case_ids.remove(&run_id);
                (true, false)
            } else if reserve_pipeline_slot(&mut scheduler, &run_id, &options.host_id) {
                (false, true)
            } else {
                (false, false)
            }
        };
        if cancelled {
            emit_pipeline_event(
                &app,
                &run_id,
                &options.host_id,
                "cancelled",
                "lifecycle",
                "[LIFECYCLE] cancelled before start",
            );
            return Ok(pipeline_result(
                &run_id,
                &options.host_id,
                "cancelled",
                None,
            ));
        }
        if slot_acquired {
            break;
        }
        tokio_sleep(120).await;
    }
    // Parsing runs in a CHILD PROCESS (this same executable, re-invoked with the
    // hidden --__parse flag) rather than a thread. A thread can't be killed in
    // Rust, so a cancel could only take effect at the pipeline's next poll —
    // and a single long library call (notatin's deleted-cell recovery on a big
    // hive) has no poll point inside it, which made cancel look broken. A child
    // process can simply be killed, so cancel is immediate. The app stays a
    // single self-contained binary (no sidecar).
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut args: Vec<String> = vec![
        PARSE_FLAG.to_string(),
        options.case_id.clone(),
        options.host_id.clone(),
        cd.to_string_lossy().to_string(),
    ];
    if let Some(only) = options.only.filter(|v| !v.is_empty()) {
        args.push(only.join(","));
    }
    let host_dir = case_store::host_dir(&cd, &options.case_id, &options.host_id);
    let log_path = pipeline::parse_run_log_path(&host_dir, &run_id);
    args.push(format!("--run-log-id={run_id}"));

    let mut child = match Command::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            if let Ok(mut scheduler) = state.0.lock() {
                scheduler.reserving.remove(&run_id);
                scheduler.host_ids.remove(&run_id);
                scheduler.case_ids.remove(&run_id);
            }
            emit_pipeline_event(
                &app,
                &run_id,
                &options.host_id,
                "error",
                "lifecycle",
                format!("[LIFECYCLE] failed to start: {error}"),
            );
            return Err(format!("failed to start parser process: {error}"));
        }
    };

    // Stream the child's stdout/stderr as `pipeline-log` events.
    let event_run_id = run_id.clone();
    let event_host_id = options.host_id.clone();
    let pump =
        |app: &AppHandle, reader: Option<Box<dyn std::io::Read + Send>>, stream: &'static str| {
            if let Some(r) = reader {
                let app = app.clone();
                let run_id = event_run_id.clone();
                let host_id = event_host_id.clone();
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    for line in std::io::BufReader::new(r).lines().map_while(Result::ok) {
                        if line.is_empty() {
                            continue;
                        }
                        emit_pipeline_event(&app, &run_id, &host_id, "running", stream, line);
                    }
                });
            }
        };
    pump(
        &app,
        child
            .stdout
            .take()
            .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
        "stdout",
    );
    pump(
        &app,
        child
            .stderr
            .take()
            .map(|e| Box::new(e) as Box<dyn std::io::Read + Send>),
        "stderr",
    );

    // A targeted cancel can race process creation. If it did, terminate the
    // newly-created child before publishing it as a running task.
    let cancelled_before_start = {
        let mut scheduler = state
            .0
            .lock()
            .map_err(|_| "pipeline scheduler unavailable")?;
        scheduler.reserving.remove(&run_id);
        let cancelled = scheduler.cancelled.remove(&run_id);
        if cancelled {
            scheduler.host_ids.remove(&run_id);
            scheduler.case_ids.remove(&run_id);
        }
        cancelled
    };
    if cancelled_before_start {
        let killed = child.kill().is_ok();
        let _ = child.wait();
        record_forced_gui_cancel(&log_path, killed);
        emit_pipeline_event(
            &app,
            &run_id,
            &options.host_id,
            "cancelled",
            "lifecycle",
            "[LIFECYCLE] cancelled before parser start",
        );
        return Ok(pipeline_result(
            &run_id,
            &options.host_id,
            "cancelled",
            None,
        ));
    }
    {
        let mut scheduler = state
            .0
            .lock()
            .map_err(|_| "pipeline scheduler unavailable")?;
        scheduler
            .running
            .insert(run_id.clone(), RunningPipeline { child, log_path });
    }
    emit_pipeline_event(
        &app,
        &run_id,
        &options.host_id,
        "running",
        "lifecycle",
        "[LIFECYCLE] running",
    );

    // Poll for exit so cancel_pipeline can still reach the child while it runs.
    loop {
        let exit = {
            let mut scheduler = state
                .0
                .lock()
                .map_err(|_| "pipeline scheduler unavailable")?;
            match scheduler.running.get_mut(&run_id) {
                Some(running) => running.child.try_wait().ok().flatten().map(|status| {
                    let exit_code = status.code();
                    let log_path = running.log_path.clone();
                    (exit_code, log_path)
                }),
                // A cancel takes the entry out of the map after killing it.
                None => {
                    return Ok(pipeline_result(
                        &run_id,
                        &options.host_id,
                        "cancelled",
                        None,
                    ))
                }
            }
        };
        if let Some((exit_code, log_path)) = exit {
            if let Ok(mut scheduler) = state.0.lock() {
                scheduler.running.remove(&run_id);
                scheduler.host_ids.remove(&run_id);
                scheduler.case_ids.remove(&run_id);
            }
            record_child_exit(&log_path, exit_code);
            let terminal = terminal_pipeline_status(&host_dir, exit_code);
            // 발행이 일어난 실행(complete/partial)은 이 호스트의 테이블을 다시
            // 썼다 — 이전 북마크의 rowid 참조가 무효라 삭제한다.
            if terminal == "complete" || terminal == "partial" {
                let removed = remove_host_bookmarks(&cd, &options.host_id);
                if removed > 0 {
                    emit_pipeline_event(
                        &app,
                        &run_id,
                        &options.host_id,
                        "running",
                        "lifecycle",
                        format!("[LIFECYCLE] 재파싱으로 이 호스트의 이전 북마크 {removed}건 삭제"),
                    );
                }
            }
            emit_pipeline_event(
                &app,
                &run_id,
                &options.host_id,
                terminal,
                "lifecycle",
                format!("[LIFECYCLE] {terminal}"),
            );
            return Ok(pipeline_result(
                &run_id,
                &options.host_id,
                terminal,
                exit_code,
            ));
        }
        tokio_sleep(120).await;
    }
}

async fn tokio_sleep(ms: u64) {
    // Small helper so the poll loop yields instead of blocking an async worker.
    tauri::async_runtime::spawn_blocking(move || {
        std::thread::sleep(std::time::Duration::from_millis(ms))
    })
    .await
    .ok();
}

#[tauri::command]
fn cancel_pipeline(
    app: AppHandle,
    state: tauri::State<'_, PipelineState>,
    run_id: Option<String>,
    #[allow(non_snake_case)] cancel_all: Option<bool>,
) -> bool {
    let mut scheduler = match state.0.lock() {
        Ok(scheduler) => scheduler,
        Err(_) => return false,
    };
    let target_all = cancel_all.unwrap_or(false) || run_id.is_none();
    let target_ids: Vec<String> = if target_all {
        scheduler
            .queued
            .iter()
            .chain(scheduler.reserving.iter())
            .chain(scheduler.running.keys())
            .cloned()
            .collect()
    } else {
        run_id.into_iter().collect()
    };
    let mut changed = false;
    let mut cancelled_contexts = Vec::<(String, String, String)>::new();
    for id in target_ids.into_iter().collect::<HashSet<_>>() {
        if scheduler.queued.remove(&id) || scheduler.reserving.remove(&id) {
            scheduler.cancelled.insert(id.clone());
            let host_id = scheduler.host_ids.get(&id).cloned().unwrap_or_default();
            let case_id = scheduler.case_ids.get(&id).cloned().unwrap_or_default();
            emit_pipeline_event(
                &app,
                &id,
                &host_id,
                "cancelled",
                "lifecycle",
                "[LIFECYCLE] cancelled while queued",
            );
            if !case_id.is_empty() && !host_id.is_empty() {
                cancelled_contexts.push((id.clone(), case_id, host_id));
            }
            changed = true;
        }
        if let Some(mut running) = scheduler.running.remove(&id) {
            let killed = running.child.kill().is_ok();
            let _ = running.child.wait();
            record_forced_gui_cancel(&running.log_path, killed);
            let host_id = scheduler.host_ids.remove(&id).unwrap_or_default();
            let case_id = scheduler.case_ids.remove(&id).unwrap_or_default();
            emit_pipeline_event(
                &app,
                &id,
                &host_id,
                "cancelled",
                "lifecycle",
                "[LIFECYCLE] cancellation requested",
            );
            if !case_id.is_empty() && !host_id.is_empty() {
                cancelled_contexts.push((id.clone(), case_id, host_id));
            }
            changed = true;
        }
    }
    drop(scheduler);
    for (id, case_id, host_id) in cancelled_contexts {
        write_cancelled_terminal_state(&case_id, &host_id, &id);
    }
    changed
}

// --- commands: result browsing (in-process sqlite) -------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryEntry {
    name: String,
    full_path: String,
}

fn is_internal_pipeline_directory(name: &str) -> bool {
    matches!(name, ".parse-staging" | "parse_logs")
}

fn has_internal_pipeline_path_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        std::path::Component::Normal(name) => {
            name.to_str().is_some_and(is_internal_pipeline_directory)
        }
        _ => false,
    })
}

#[tauri::command]
fn list_categories(host_dir: String) -> Vec<CategoryEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&host_dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                let name = e.file_name().to_string_lossy().to_string();
                if is_internal_pipeline_directory(&name) {
                    continue;
                }
                out.push(CategoryEntry {
                    full_path: e.path().to_string_lossy().to_string(),
                    name,
                });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// The master timeline is expensive to assemble (it scans every result table),
// so the frontend builds it once and caches the result here. The cache is a
// single JSON file at the host root — not a category directory, so it is
// invisible to `list_categories` and survives the per-category publish of a
// re-parse. Staleness is decided by the frontend via a `builtForRunAt` marker
// embedded in the payload, so this side only reads and writes the blob.
fn master_timeline_cache_path(host_dir: &str) -> PathBuf {
    Path::new(host_dir).join("_master_timeline.cache.json")
}

// 재빌드 직후 저장되는 캐시는 수백 MB다. 단발 raw 커맨드로 받으면 tauri
// Request가 차용만 허용해 페이로드 전체를 메인 스레드에서 한 번 복사해야
// 하고(순간 메모리 피크 2배), String 인자는 요청 JSON 파싱으로 더 심하게
// 멈춘다 — 청크 프로토콜로 나눈다: begin(임시 파일) → 8MB 단위 raw 청크
// 순차 append(청크당 메인 스레드 작업은 소량 복사 + 페이지 캐시 쓰기 수 ms)
// → finish(원자 rename). 실패한 저장의 임시 파일은 다음 begin이 정리한다.
fn master_timeline_saving_path(host_dir: &str, token: &str) -> PathBuf {
    Path::new(host_dir).join(format!("_master_timeline.cache.json.saving-{token}"))
}

fn valid_saving_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// 저장 세션 진행 상태 — 쓰기는 워커 스레드에서 수행되고, 메인 커맨드는
/// 소유 복사와 진행 카운트만 만진다. 프런트가 매 청크 후 drain을 await해
/// 동시 in-flight 쓰기는 1청크로 유지된다(순서·메모리 상한 보장).
struct TimelineSaveSession {
    host_dir: String,
    pending: usize,
    error: Option<String>,
}

type TimelineSaveHandle = std::sync::Arc<(Mutex<TimelineSaveSession>, std::sync::Condvar)>;

fn timeline_save_sessions() -> &'static Mutex<std::collections::HashMap<String, TimelineSaveHandle>> {
    static SESSIONS: OnceLock<Mutex<std::collections::HashMap<String, TimelineSaveHandle>>> =
        OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn timeline_save_begin_impl(host_dir: &str, token: &str) -> Result<(), String> {
    // 중단된 이전 저장의 임시 파일·세션 정리 (호스트당 단일 저장자 전제).
    if let Ok(rd) = std::fs::read_dir(host_dir) {
        for e in rd.flatten() {
            if e.file_name()
                .to_string_lossy()
                .starts_with("_master_timeline.cache.json.saving-")
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if let Ok(mut sessions) = timeline_save_sessions().lock() {
        sessions.retain(|_, handle| {
            handle
                .0
                .lock()
                .map(|session| session.host_dir != host_dir)
                .unwrap_or(true)
        });
        sessions.insert(
            token.to_string(),
            std::sync::Arc::new((
                Mutex::new(TimelineSaveSession {
                    host_dir: host_dir.to_string(),
                    pending: 0,
                    error: None,
                }),
                std::sync::Condvar::new(),
            )),
        );
    }
    std::fs::write(master_timeline_saving_path(host_dir, token), b"")
        .map_err(|error| format!("타임라인 캐시 임시 파일 생성 실패: {error}"))
}

/// 프로토콜 자원 상한 — 프런트 구현이 아니라 명령 경계에서 강제한다.
/// 초과 청크는 복사 전에 거부되고, drain 없는 연속 전송(진행 중 쓰기 1개
/// 초과)은 스레드·메모리가 쌓이기 전에 거부된다.
const TIMELINE_SAVE_MAX_CHUNK: usize = 8 * 1024 * 1024;

/// 동기 커맨드에서 호출되는 부분 — 세션 확인·카운트 증가까지만 하고, 실제
/// 파일 append는 워커 스레드로 넘긴다. 이전 청크의 쓰기 오류는 여기서
/// 조기 반환된다. `host_dir`은 세션 저장값과 대조해 토큰-경로 소유 관계를
/// 검증한다.
fn timeline_save_append_impl(host_dir: &str, token: &str, bytes: Vec<u8>) -> Result<(), String> {
    if bytes.len() > TIMELINE_SAVE_MAX_CHUNK {
        return Err("타임라인 캐시 청크가 허용 크기를 초과했습니다".to_string());
    }
    let handle = timeline_save_sessions()
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(token).cloned())
        .ok_or_else(|| "타임라인 캐시 저장 세션이 없습니다".to_string())?;
    let path = {
        let mut session = handle.0.lock().map_err(|_| "저장 세션 잠금 실패".to_string())?;
        if session.host_dir != host_dir {
            return Err("타임라인 캐시 저장 세션의 호스트 경로가 일치하지 않습니다".to_string());
        }
        if let Some(error) = &session.error {
            return Err(error.clone());
        }
        if session.pending > 0 {
            return Err("이전 청크 쓰기가 끝나지 않았습니다 — drain 후 전송해야 합니다".to_string());
        }
        session.pending += 1;
        master_timeline_saving_path(&session.host_dir, token)
    };
    let worker = handle.clone();
    std::thread::spawn(move || {
        use std::io::Write;
        let result = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(&bytes));
        if let Ok(mut session) = worker.0.lock() {
            session.pending = session.pending.saturating_sub(1);
            if let Err(error) = result {
                session.error.get_or_insert(format!("타임라인 캐시 청크 쓰기 실패: {error}"));
            }
        }
        worker.1.notify_all();
    });
    Ok(())
}

/// 잔여 쓰기 완료 대기 — 청크 사이(in-flight 1 유지)와 finish 직전에 쓴다.
fn timeline_save_wait_impl(token: &str) -> Result<(), String> {
    let handle = timeline_save_sessions()
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(token).cloned())
        .ok_or_else(|| "타임라인 캐시 저장 세션이 없습니다".to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut session = handle.0.lock().map_err(|_| "저장 세션 잠금 실패".to_string())?;
    while session.pending > 0 && session.error.is_none() {
        if std::time::Instant::now() >= deadline {
            return Err("타임라인 캐시 저장 시간 초과".to_string());
        }
        let (next, _) = handle
            .1
            .wait_timeout(session, std::time::Duration::from_millis(500))
            .map_err(|_| "저장 세션 잠금 실패".to_string())?;
        session = next;
    }
    match &session.error {
        Some(error) => Err(error.clone()),
        None => Ok(()),
    }
}

fn timeline_save_finish_impl(host_dir: &str, token: &str) -> Result<(), String> {
    // 세션 폐기 전에 토큰-호스트 소유 관계를 검증한다 — 불일치 상태에서
    // 세션을 먼저 지우면 실제 저장의 임시 파일이 남고 재시도도 불가능해진다.
    {
        let handle = timeline_save_sessions()
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(token).cloned())
            .ok_or_else(|| "타임라인 캐시 저장 세션이 없습니다".to_string())?;
        let session = handle.0.lock().map_err(|_| "저장 세션 잠금 실패".to_string())?;
        if session.host_dir != host_dir {
            return Err("타임라인 캐시 저장 세션의 호스트 경로가 일치하지 않습니다".to_string());
        }
    }
    let wait = timeline_save_wait_impl(token);
    if let Ok(mut sessions) = timeline_save_sessions().lock() {
        sessions.remove(token);
    }
    let saving = master_timeline_saving_path(host_dir, token);
    match wait {
        Ok(()) => std::fs::rename(&saving, master_timeline_cache_path(host_dir))
            .map_err(|error| format!("타임라인 캐시 확정 실패: {error}")),
        Err(error) => {
            let _ = std::fs::remove_file(&saving);
            Err(error)
        }
    }
}

#[tauri::command]
async fn save_master_timeline_begin(host_dir: String, token: String) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 캐시 저장 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || timeline_save_begin_impl(&host_dir, &token))
        .await
        .map_err(|error| format!("타임라인 캐시 저장 작업이 중단되었습니다: {error}"))?
}

/// raw 본문: "호스트경로\n토큰\n" + 청크 바이트. 메인에서는 헤더 파싱과
/// 소유 복사(청크 상한 크기, memcpy 수 ms)까지만 수행하고, 파일 쓰기는
/// 세션 워커로 넘긴다 — 느린 저장 매체의 append 지연이 이벤트 루프를 막지
/// 않는다. 순서는 프런트의 청크당 drain await가 보장한다.
#[tauri::command]
fn save_master_timeline_chunk(request: tauri::ipc::Request<'_>) -> Result<(), String> {
    let tauri::ipc::InvokeBody::Raw(body) = request.body() else {
        return Err("타임라인 캐시 저장 본문 형식이 잘못되었습니다".to_string());
    };
    let first = body
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "타임라인 캐시 저장 본문에 경로 구분자가 없습니다".to_string())?;
    let second = body[first + 1..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|at| first + 1 + at)
        .ok_or_else(|| "타임라인 캐시 저장 본문에 토큰 구분자가 없습니다".to_string())?;
    let host_dir = String::from_utf8(body[..first].to_vec())
        .map_err(|_| "타임라인 캐시 저장 경로 인코딩이 잘못되었습니다".to_string())?;
    let token = String::from_utf8(body[first + 1..second].to_vec())
        .map_err(|_| "타임라인 캐시 저장 토큰 인코딩이 잘못되었습니다".to_string())?;
    if !valid_saving_token(&token) {
        return Err("타임라인 캐시 저장 토큰이 잘못되었습니다".to_string());
    }
    let payload = &body[second + 1..];
    // 상한 검사는 소유 복사(to_vec) 전에 — 초과 요청이 메모리를 잡지 않는다.
    if payload.len() > TIMELINE_SAVE_MAX_CHUNK {
        return Err("타임라인 캐시 청크가 허용 크기를 초과했습니다".to_string());
    }
    timeline_save_append_impl(&host_dir, &token, payload.to_vec())
}

/// 직전 청크들의 쓰기 완료를 워커에서 대기 — 프런트가 매 청크 후 await해
/// in-flight를 1청크로 묶는다(메모리 상한·append 순서 보장).
#[tauri::command]
async fn save_master_timeline_drain(token: String) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 캐시 저장 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || timeline_save_wait_impl(&token))
        .await
        .map_err(|error| format!("타임라인 캐시 저장 작업이 중단되었습니다: {error}"))?
}

#[tauri::command]
async fn save_master_timeline_finish(host_dir: String, token: String) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 캐시 저장 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || timeline_save_finish_impl(&host_dir, &token))
        .await
        .map_err(|error| format!("타임라인 캐시 저장 작업이 중단되었습니다: {error}"))?
}

// 수백 MB급 캐시를 동기 커맨드의 String으로 돌려주면 메인 스레드(창 이벤트
// 루프)가 ① 파일을 읽고 ② 응답 전체를 JSON 이스케이프 직렬화하느라 수십 초
// 멈춘다 — 결과 보기 진입 멈춤의 실제 원인(스택 샘플로 확인). raw 바이트
// 응답은 JSON 직렬화를 거치지 않고, 읽기는 blocking 풀에서 수행한다.
// 캐시가 없으면 빈 바이트를 돌려준다.
#[tauri::command]
async fn load_master_timeline(host_dir: String) -> tauri::ipc::Response {
    tauri::async_runtime::spawn_blocking(move || {
        tauri::ipc::Response::new(
            std::fs::read(master_timeline_cache_path(&host_dir)).unwrap_or_default(),
        )
    })
    .await
    .unwrap_or_else(|_| tauri::ipc::Response::new(Vec::new()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultFileEntry {
    name: String,
    file_name: String,
    table_name: String,
    relative_path: String,
    full_path: String,
    row_count: i64,
}

fn find_result_files(dir: &Path, base: &Path, out: &mut Vec<ResultFileEntry>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if e.file_name()
                .to_str()
                .is_some_and(is_internal_pipeline_directory)
            {
                continue;
            }
            find_result_files(&p, base, out);
            continue;
        }
        if p.extension().map(|x| x != "sqlite").unwrap_or(true) {
            continue;
        }
        if std::fs::metadata(&p)
            .map(|m| m.len() <= EMPTY_SQLITE_MAX_BYTES)
            .unwrap_or(true)
        {
            continue;
        }
        let conn = match open_ro(&p.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let file_name = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let rel = p
            .strip_prefix(base)
            .unwrap_or(&p)
            .to_string_lossy()
            .to_string();
        for t in table_names(&conn) {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {}", q(&t)), [], |r| r.get(0))
                .unwrap_or(0);
            out.push(ResultFileEntry {
                name: t.clone(),
                file_name: file_name.clone(),
                table_name: t,
                relative_path: rel.clone(),
                full_path: p.to_string_lossy().to_string(),
                row_count: count,
            });
        }
    }
}

// 동기 커맨드는 Tauri 메인 스레드(창 이벤트 루프)에서 실행된다. 이 목록은
// 테이블별 COUNT(MFT 수백만 행 포함)를 도는 무거운 스캔이라, 메인 스레드에
// 두면 조회가 끝날 때까지 창 전체가 입력을 못 받는다(결과 보기 진입 멈춤).
#[tauri::command]
async fn list_result_files(category_dir: String) -> Vec<ResultFileEntry> {
    tauri::async_runtime::spawn_blocking(move || {
        let base = PathBuf::from(&category_dir);
        // This command is also callable directly. Do not rely on the category
        // list UI to hide staging/log directories: a supplied nested path must
        // never expose work-in-progress SQLite files.
        if has_internal_pipeline_path_component(&base) {
            return Vec::new();
        }
        let mut out = Vec::new();
        find_result_files(&base, &base, &mut out);
        out.sort_by(|a, b| {
            a.relative_path
                .cmp(&b.relative_path)
                .then(a.table_name.cmp(&b.table_name))
        });
        out
    })
    .await
    .unwrap_or_default()
}

/// Upgrade only the derived ExecutionHistory table when it predates source
/// record keys or the complete Prefetch execution-cache fields. This avoids an
/// expensive evidence reparse while making existing saved hosts participate in
/// cross-view bookmark synchronization and full Prefetch detail.
#[tauri::command]
async fn refresh_execution_history_overview(host_dir: String) -> Result<bool, String> {
    // 구버전 호스트에서는 파생 테이블 재빌드+쓰기까지 돌아 무겁다 — 메인
    // 스레드 밖에서 수행한다 (최신 호스트는 컬럼 확인 후 즉시 반환).
    tauri::async_runtime::spawn_blocking(move || refresh_execution_history_overview_blocking(host_dir))
        .await
        .map_err(|error| format!("실행 이력 개요 갱신 작업이 중단되었습니다: {error}"))?
}

fn refresh_execution_history_overview_blocking(host_dir: String) -> Result<bool, String> {
    let out_dir = PathBuf::from(host_dir);
    let overview_path = out_dir.join("_OVERVIEW").join("ExecutionHistory.sqlite");
    if !overview_path.exists() {
        return Ok(false);
    }
    let conn = open_ro(&overview_path.to_string_lossy())?;
    let columns = table_columns(&conn, "ExecutionHistory");
    if columns.iter().any(|column| column == "record_key")
        && columns.iter().any(|column| column == "prefetch_hash")
    {
        return Ok(false);
    }
    drop(conn);

    let rows = overview::build_execution_history(&out_dir);
    if rows.is_empty() {
        return Ok(false);
    }
    write_table(&overview_path, "ExecutionHistory", &rows, &[])
        .map_err(|error| error.to_string())?;
    Ok(true)
}

/// One source file represented in a parsed result table. `recovery` is the
/// parser's own marker (for registry artifacts, e.g. live/deleted recovery),
/// never a guessed state from the viewer.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultProvenance {
    source_file: String,
    recovery: String,
}

/// Reads one parser-recorded source path without materialising or aggregating
/// the table. This intentionally avoids `COUNT`/`GROUP BY`: an Amcache table
/// can contain millions of rows and the dashboard needs the source identity,
/// not another expensive statistical pass.
#[tauri::command]
fn result_provenance(
    full_path: String,
    table_name: String,
) -> Result<Vec<ResultProvenance>, String> {
    let conn = open_ro(&full_path)?;
    if !table_names(&conn).iter().any(|name| name == &table_name) {
        return Ok(Vec::new());
    }
    let columns = table_columns(&conn, &table_name);
    if !columns.iter().any(|column| column == "_source_file") {
        return Ok(Vec::new());
    }
    let recovery = if columns.iter().any(|column| column == "_recovery") {
        "COALESCE(NULLIF(_recovery, ''), 'live')"
    } else {
        "'live'"
    };
    let sql = format!(
        "SELECT _source_file, {recovery} FROM {} WHERE _source_file IS NOT NULL AND _source_file <> '' LIMIT 1",
        q(&table_name),
    );
    let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ResultProvenance {
                source_file: row.get(0)?,
                recovery: row.get(1)?,
            })
        })
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactInputFile {
    name: String,
    kind: String,
    detail: String,
}

/// Lists an Amcache hive and its sibling transaction logs from a parser-recorded
/// source path. It never re-walks the full evidence folder while the dashboard
/// is open, which keeps the detail accordion responsive for large collections.
#[tauri::command]
fn artifact_input_files(source_file: String) -> Vec<ArtifactInputFile> {
    let hive = PathBuf::from(source_file);
    let hive_name = hive
        .file_name()
        .map(|name| name.to_string_lossy().to_string());
    if hive_name
        .as_deref()
        .map(|name| !name.eq_ignore_ascii_case("Amcache.hve"))
        .unwrap_or(true)
    {
        return Vec::new();
    }
    let mut inputs = vec![ArtifactInputFile {
        name: hive_name.unwrap_or_else(|| "Amcache.hve".to_string()),
        kind: "hive".to_string(),
        detail: "레지스트리 하이브에서 할당된(live) 레코드를 파싱합니다.".to_string(),
    }];
    if let Some(parent) = hive.parent() {
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.to_ascii_lowercase().starts_with("amcache.hve.log") {
                    inputs.push(ArtifactInputFile {
                        name,
                        kind: "transactionLog".to_string(),
                        // 이 목록은 현재 디렉터리 재탐색 결과라 "적용 여부"를
                        // 단정하면 안 된다 — 실제 적용/폴백 실적은 실행 시
                        // parse_report.json의 amcacheHives에 기록된다.
                        detail: "하이브와 함께 발견된 트랜잭션 로그 — 실제 적용 여부는 파싱 보고서(amcacheHives)에 기록됩니다."
                            .to_string(),
                    });
                }
            }
        }
    }
    inputs.sort_by(|left, right| left.name.cmp(&right.name));
    inputs
}

/// Parse-time manifest written by the pipeline. It lets the dashboard render
/// input provenance without reopening and aggregating evidence databases.
#[tauri::command]
fn parse_report(host_dir: String) -> Option<Value> {
    std::fs::read_to_string(PathBuf::from(host_dir).join("parse_report.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParseLogPreview {
    text: String,
    truncated: bool,
}

/// Return a bounded immutable parser-run log for the row-level diagnostic UI.
/// The run id is strict so callers cannot turn this into a generic file read.
#[tauri::command]
fn parse_run_log(host_dir: String, run_id: String) -> Result<ParseLogPreview, String> {
    if !valid_id(&run_id) {
        return Err("invalid parser run identifier".to_string());
    }
    const MAX_BYTES: usize = 24 * 1024;
    let path = pipeline::parse_run_log_path(Path::new(&host_dir), &run_id);
    let file = std::fs::File::open(&path)
        .map_err(|error| format!("실행 로그를 읽지 못했습니다: {error}"))?;
    // Do not materialise an unbounded parser log in the GUI process. The one
    // extra byte distinguishes an exact 24KiB log from a truncated preview.
    let mut bytes = Vec::with_capacity(MAX_BYTES + 1);
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("실행 로그를 읽지 못했습니다: {error}"))?;
    let truncated = bytes.len() > MAX_BYTES;
    bytes.truncate(MAX_BYTES);
    let text = String::from_utf8_lossy(&bytes).to_string();
    Ok(ParseLogPreview { text, truncated })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CsvData {
    columns: Vec<String>,
    rows: Vec<Map<String, Value>>,
    row_count: i64,
}

/// One small, searchable page of records linked from the shared detail drawer.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkedRowsPage {
    rows: Vec<Map<String, Value>>,
    row_count: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserActivityQuery {
    account: Option<String>,
    kinds: Vec<String>,
    day: Option<String>,
    search: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
    descending: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserActivitySummary {
    accounts: Vec<String>,
    days: Vec<ColumnValue>,
    total: i64,
}

/// Compact domain aggregate for the Browser activity summary. Keeping this
/// result bounded prevents a large history database from being copied into the
/// webview merely to render its top domains.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserVisitedDomainStat {
    row_id: i64,
    domain: String,
    visit_count: i64,
    /// Exact count of distinct stored URLs represented by this hostname.
    url_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserActivityInsights {
    visit_total: i64,
    top_visited_domains: Vec<BrowserVisitedDomainStat>,
    download_total: i64,
    downloads: Vec<Map<String, Value>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserDomainStatsPage {
    domains: Vec<BrowserVisitedDomainStat>,
    total: i64,
}

/// Bounded LRU cache for the server-side hostname aggregation used by the
/// domain modal. The filesystem fingerprint prevents a re-parse/replaced
/// BrowserActivity SQLite from serving stale pages.
#[derive(Clone, PartialEq, Eq)]
struct BrowserDomainCacheKey {
    full_path: String,
    table_name: String,
    account: String,
    start: String,
    end: String,
    size: Option<u64>,
    modified_ns: Option<u128>,
}

struct BrowserDomainCacheEntry {
    key: BrowserDomainCacheKey,
    domains: Vec<BrowserVisitedDomainStat>,
    inserted_at: Instant,
}

#[derive(Default)]
struct BrowserDomainCache {
    entries: VecDeque<BrowserDomainCacheEntry>,
}

const BROWSER_DOMAIN_CACHE_MAX_ENTRIES: usize = 4;
const BROWSER_DOMAIN_CACHE_MAX_DOMAINS_PER_ENTRY: usize = 50_000;
const BROWSER_DOMAIN_CACHE_TTL: Duration = Duration::from_secs(30);
static BROWSER_DOMAIN_CACHE: OnceLock<Mutex<BrowserDomainCache>> = OnceLock::new();

/// One EventLog SQLite table selected by the renderer.  EventLog collection
/// can produce one result database per original EVTX, so account activity
/// needs to merge pages across more than one source table.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountEventSource {
    full_path: String,
    table_name: String,
    log_name: String,
}

/// Query contract for the account-detail EventLog list.  The start/end bounds
/// are already normalised to the parser's sortable timestamp format by the
/// renderer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountEventQuery {
    sid: String,
    username: String,
    search: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountEventPage {
    rows: Vec<Map<String, Value>>,
    row_count: i64,
    source_count: i64,
    sources_read: i64,
    source_failures: Vec<AccountEventSourceFailure>,
}

/// A per-source read failure.  The reason is intentionally a stable,
/// user-safe stage description rather than an arbitrary SQLite/OS error.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AccountEventSourceFailure {
    log_name: String,
    table_name: String,
    reason: String,
}

#[derive(Default)]
struct AccountRoleValues {
    sid: Vec<(String, String)>,
    name: Vec<(String, String)>,
}

#[derive(Clone)]
struct AccountEventHit {
    source_index: usize,
    rowid: i64,
    timestamp: String,
    evidence: String,
}

/// A cache key contains the source identity and a filesystem fingerprint, so a
/// re-parse/replacement naturally invalidates the account-event hit index.
#[derive(Clone, PartialEq, Eq)]
struct AccountEventSourceFingerprint {
    full_path: String,
    table_name: String,
    log_name: String,
    size: Option<u64>,
    modified_ns: Option<u128>,
}

#[derive(Clone, PartialEq, Eq)]
struct AccountEventCacheKey {
    sources: Vec<AccountEventSourceFingerprint>,
    sid: String,
    username: String,
    search: String,
    start: String,
    end: String,
}

#[derive(Clone)]
struct AccountEventIndex {
    hits: Vec<AccountEventHit>,
    source_count: i64,
    sources_read: i64,
    source_failures: Vec<AccountEventSourceFailure>,
}

struct AccountEventCacheEntry {
    key: AccountEventCacheKey,
    index: AccountEventIndex,
    inserted_at: Instant,
}

#[derive(Default)]
struct AccountEventIndexCache {
    entries: VecDeque<AccountEventCacheEntry>,
}

const ACCOUNT_EVENT_CACHE_MAX_ENTRIES: usize = 4;
const ACCOUNT_EVENT_CACHE_MAX_HITS_PER_ENTRY: usize = 250_000;
const ACCOUNT_EVENT_CACHE_TTL: Duration = Duration::from_secs(30);
static ACCOUNT_EVENT_INDEX_CACHE: OnceLock<Mutex<AccountEventIndexCache>> = OnceLock::new();

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => Some(
            values
                .iter()
                .filter_map(value_text)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        // EventData objects are recursively flattened before matching.  This
        // fallback is only for broad analyst search over a raw event payload.
        Value::Object(_) => Some(value.to_string()),
    }
}

fn map_text(row: &Map<String, Value>, key: &str) -> String {
    row.get(key).and_then(value_text).unwrap_or_default()
}

fn flatten_event_data(value: &Value, prefix: &str, output: &mut Vec<(String, String, String)>) {
    let Value::Object(values) = value else {
        return;
    };
    for (key, nested) in values {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if nested.is_object() {
            flatten_event_data(nested, &path, output);
        } else if let Some(text) = value_text(nested) {
            output.push((path, key.clone(), text));
        }
    }
}

fn account_sid_role(field: &str) -> Option<&'static str> {
    match field.to_ascii_lowercase().as_str() {
        "subjectsid" | "subjectusersid" | "subjectaccountsid" => Some("수행 계정"),
        "targetsid" | "targetusersid" | "targetaccountsid" => Some("대상 계정"),
        "membersid" | "membernamesid" => Some("그룹 구성원"),
        "accountsid" | "accountusersid" | "usersid" | "userusersid" | "callersid"
        | "callerusersid" | "clientsid" | "clientusersid" => Some("계정"),
        _ => None,
    }
}

fn account_name_role(row: &Map<String, Value>, field: &str) -> Option<&'static str> {
    match field.to_ascii_lowercase().as_str() {
        "subjectname" | "subjectusername" | "subjectaccountname" => Some("수행 계정"),
        "targetname" | "targetusername" | "targetaccountname" => Some("대상 계정"),
        "membername" => Some("그룹 구성원"),
        "accountname" | "accountusername" | "username" | "userusername" | "callername"
        | "callerusername" | "clientname" | "clientusername" => Some("계정"),
        "param1"
            if map_text(row, "Provider")
                == "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
                && map_text(row, "EventID") == "1149" =>
        {
            Some("RDP 세션 사용자")
        }
        "user"
            if map_text(row, "Provider")
                == "Microsoft-Windows-TerminalServices-LocalSessionManager"
                && matches!(
                    map_text(row, "EventID").as_str(),
                    "21" | "22" | "23" | "24" | "25" | "39" | "40"
                ) =>
        {
            Some("RDP 세션 사용자")
        }
        _ => None,
    }
}

fn normalise_account_name(value: &str) -> String {
    let cleaned = value.trim().replace('/', "\\");
    let without_domain = cleaned
        .rsplit_once('\\')
        .map(|(_, name)| name)
        .unwrap_or(&cleaned);
    without_domain
        .split('@')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Exact account correlation equivalent to the renderer's former matcher.
/// Arbitrary EventData strings are never interpreted as identity evidence.
fn account_event_evidence(row: &Map<String, Value>, wanted_sid: &str, wanted_name: &str) -> String {
    let wanted_sid = wanted_sid.trim().to_lowercase();
    let wanted_name = normalise_account_name(wanted_name);
    if wanted_sid.is_empty() && wanted_name.is_empty() {
        return String::new();
    }

    let mut roles: BTreeMap<String, AccountRoleValues> = BTreeMap::new();
    let mut add = |role: &str, is_sid: bool, field: String, value: String| {
        let values = roles.entry(role.to_string()).or_default();
        if is_sid {
            values.sid.push((field, value));
        } else {
            values.name.push((field, value));
        }
    };

    // Event/System Security.UserID is a structured principal, unlike an SID
    // embedded in a provider payload such as a firewall RuleId.
    if let Some(user_id) = row
        .get("UserID")
        .and_then(value_text)
        .filter(|value| !value.is_empty())
    {
        add("이벤트 보안 주체", true, "UserID".to_string(), user_id);
    }
    if let Some(event_data) = row
        .get("EventData")
        .and_then(value_text)
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
    {
        let mut values = Vec::new();
        flatten_event_data(&event_data, "", &mut values);
        for (path, field, value) in values {
            if let Some(role) = account_sid_role(&field) {
                add(role, true, path, value);
            } else if let Some(role) = account_name_role(row, &field) {
                add(role, false, path, value);
            }
        }
    }

    let mut evidence = Vec::new();
    for (role, values) in roles {
        let sid_matches: Vec<_> = if wanted_sid.is_empty() {
            Vec::new()
        } else {
            values
                .sid
                .iter()
                .filter(|(_, value)| value.trim().to_lowercase() == wanted_sid)
                .collect()
        };
        if !sid_matches.is_empty() {
            evidence.extend(
                sid_matches
                    .into_iter()
                    .map(|(field, value)| format!("[SID] {role} · {field} = {value}")),
            );
            continue;
        }
        // A role carrying any SID is never matched through a same-name
        // fallback.  This prevents false positives when account names repeat.
        if !values.sid.is_empty() || wanted_name.is_empty() {
            continue;
        }
        evidence.extend(
            values
                .name
                .iter()
                .filter(|(_, value)| normalise_account_name(value) == wanted_name)
                .map(|(field, value)| format!("[이름] {role} · {field} = {value}")),
        );
    }
    evidence.sort();
    evidence.dedup();
    evidence.join(" | ")
}

fn account_event_matches_search(
    row: &Map<String, Value>,
    log_name: &str,
    evidence: &str,
    search: &str,
) -> bool {
    let needle = search.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    log_name.to_lowercase().contains(&needle)
        || evidence.to_lowercase().contains(&needle)
        || row
            .values()
            .filter_map(value_text)
            .any(|value| value.to_lowercase().contains(&needle))
}

fn account_event_order(left: &AccountEventHit, right: &AccountEventHit) -> std::cmp::Ordering {
    match (left.timestamp.is_empty(), right.timestamp.is_empty()) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => left
            .timestamp
            .cmp(&right.timestamp)
            .then(left.source_index.cmp(&right.source_index))
            .then(left.rowid.cmp(&right.rowid)),
    }
}

fn event_row_by_rowid(
    source: &AccountEventSource,
    rowid: i64,
) -> Result<Map<String, Value>, String> {
    let conn = open_ro(&source.full_path)?;
    let sql = format!(
        "SELECT rowid AS __rowid, * FROM {} WHERE rowid = ?",
        q(&source.table_name)
    );
    let mut rows = query_rows(&conn, &sql, &[&rowid])?;
    rows.pop()
        .ok_or_else(|| "account event row was not found".to_owned())
}

fn account_event_source_failure(
    failures: &mut Vec<AccountEventSourceFailure>,
    source: &AccountEventSource,
    reason: &str,
) {
    let failure = AccountEventSourceFailure {
        log_name: source.log_name.clone(),
        table_name: source.table_name.clone(),
        reason: reason.to_string(),
    };
    if !failures.contains(&failure) {
        failures.push(failure);
    }
}

fn account_event_source_fingerprint(source: &AccountEventSource) -> AccountEventSourceFingerprint {
    let metadata = std::fs::metadata(&source.full_path).ok();
    let modified_ns = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    AccountEventSourceFingerprint {
        full_path: source.full_path.clone(),
        table_name: source.table_name.clone(),
        log_name: source.log_name.clone(),
        size: metadata.as_ref().map(|metadata| metadata.len()),
        modified_ns,
    }
}

fn account_event_cache_key(
    sources: &[AccountEventSource],
    query: &AccountEventQuery,
) -> AccountEventCacheKey {
    AccountEventCacheKey {
        sources: sources
            .iter()
            .map(account_event_source_fingerprint)
            .collect(),
        // The matcher normalises both identities before comparison, so aliases
        // such as DOMAIN\\Alice and alice share the same cached index.
        sid: query.sid.trim().to_lowercase(),
        username: normalise_account_name(&query.username),
        search: query
            .search
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_lowercase(),
        start: query.start.clone().unwrap_or_default(),
        end: query.end.clone().unwrap_or_default(),
    }
}

fn account_event_cache_get(key: &AccountEventCacheKey) -> Option<AccountEventIndex> {
    let cache =
        ACCOUNT_EVENT_INDEX_CACHE.get_or_init(|| Mutex::new(AccountEventIndexCache::default()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    cache
        .entries
        .retain(|entry| now.duration_since(entry.inserted_at) <= ACCOUNT_EVENT_CACHE_TTL);
    let index = cache.entries.iter().position(|entry| entry.key == *key)?;
    let entry = cache.entries.remove(index)?;
    let result = entry.index.clone();
    cache.entries.push_back(entry); // LRU refresh without retaining event rows.
    Some(result)
}

fn account_event_cache_put(key: AccountEventCacheKey, index: AccountEventIndex) {
    // The cache is intentionally bounded by both entry count and hit-reference
    // count.  Each hit is metadata only (source/rowid/timestamp/evidence), not
    // an EventLog row body; unusually broad accounts simply re-scan rather
    // than retaining an unbounded in-process index.
    if index.hits.len() > ACCOUNT_EVENT_CACHE_MAX_HITS_PER_ENTRY {
        return;
    }
    let cache =
        ACCOUNT_EVENT_INDEX_CACHE.get_or_init(|| Mutex::new(AccountEventIndexCache::default()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    cache.entries.retain(|entry| {
        now.duration_since(entry.inserted_at) <= ACCOUNT_EVENT_CACHE_TTL && entry.key != key
    });
    cache.entries.push_back(AccountEventCacheEntry {
        key,
        index,
        inserted_at: now,
    });
    while cache.entries.len() > ACCOUNT_EVENT_CACHE_MAX_ENTRIES {
        cache.entries.pop_front();
    }
}

#[cfg(test)]
static ACCOUNT_EVENT_SOURCE_SCAN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn clear_account_event_cache_for_test() {
    let cache =
        ACCOUNT_EVENT_INDEX_CACHE.get_or_init(|| Mutex::new(AccountEventIndexCache::default()));
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entries
        .clear();
    ACCOUNT_EVENT_SOURCE_SCAN_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Merges exact account-correlated EventLog rows across all EventLog files,
/// while serialising only the requested page into the webview. This is kept
/// synchronous so the worker can own SQLite connections without crossing an
/// await point.
fn build_account_event_index(
    sources: &[AccountEventSource],
    query: &AccountEventQuery,
) -> AccountEventIndex {
    let has_time_filter = query.start.as_ref().is_some_and(|value| !value.is_empty())
        || query.end.as_ref().is_some_and(|value| !value.is_empty());
    let mut hits = Vec::new();
    let mut source_failures = Vec::new();
    let mut sources_read = 0_i64;

    for (source_index, source) in sources.iter().enumerate() {
        #[cfg(test)]
        ACCOUNT_EVENT_SOURCE_SCAN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let conn = match open_ro(&source.full_path) {
            Ok(conn) => conn,
            Err(_) => {
                account_event_source_failure(
                    &mut source_failures,
                    source,
                    "원본 SQLite를 열 수 없습니다",
                );
                continue;
            }
        };
        if !table_names(&conn)
            .iter()
            .any(|name| name == &source.table_name)
        {
            account_event_source_failure(
                &mut source_failures,
                source,
                "결과 테이블을 찾을 수 없습니다",
            );
            continue;
        }
        let columns = table_columns(&conn, &source.table_name);
        let has_timestamp = columns.iter().any(|column| column == "timestamp");
        if has_time_filter && !has_timestamp {
            account_event_source_failure(
                &mut source_failures,
                source,
                "시간 열이 없어 기간 필터를 적용할 수 없습니다",
            );
            continue;
        }

        let mut clauses = Vec::new();
        let mut params = Vec::new();
        if has_time_filter {
            clauses.push("timestamp IS NOT NULL AND timestamp <> ''".to_string());
            if let Some(start) = query.start.as_ref().filter(|value| !value.is_empty()) {
                clauses.push("timestamp >= ?".to_string());
                params.push(start.clone());
            }
            if let Some(end) = query.end.as_ref().filter(|value| !value.is_empty()) {
                clauses.push("timestamp <= ?".to_string());
                params.push(end.clone());
            }
        }
        let where_clause = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT rowid AS __rowid, * FROM {}{}",
            q(&source.table_name),
            where_clause
        );
        let refs: Vec<&dyn rusqlite::ToSql> = params
            .iter()
            .map(|value| value as &dyn rusqlite::ToSql)
            .collect();
        let mut stmt = match conn.prepare(&sql) {
            Ok(statement) => statement,
            Err(_) => {
                account_event_source_failure(
                    &mut source_failures,
                    source,
                    "원본 SQL 조회를 준비할 수 없습니다",
                );
                continue;
            }
        };
        let names: Vec<String> = stmt
            .column_names()
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        let mut rows = match stmt.query(refs.as_slice()) {
            Ok(rows) => rows,
            Err(_) => {
                account_event_source_failure(
                    &mut source_failures,
                    source,
                    "원본 SQL 행 조회를 시작할 수 없습니다",
                );
                continue;
            }
        };
        sources_read = sources_read.saturating_add(1);
        loop {
            let row = match rows.next() {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(_) => {
                    account_event_source_failure(
                        &mut source_failures,
                        source,
                        "원본 SQL 행을 읽는 중 오류가 발생했습니다",
                    );
                    break;
                }
            };
            let rowid = match row.get::<_, i64>(0) {
                Ok(rowid) => rowid,
                Err(_) => {
                    account_event_source_failure(
                        &mut source_failures,
                        source,
                        "원본 행 식별자를 읽을 수 없습니다",
                    );
                    continue;
                }
            };
            let mut record = Map::new();
            let mut invalid = false;
            for (index, name) in names.iter().enumerate() {
                match row.get_ref(index) {
                    Ok(value) => {
                        record.insert(name.clone(), cell(value));
                    }
                    Err(_) => {
                        invalid = true;
                        break;
                    }
                }
            }
            if invalid {
                account_event_source_failure(
                    &mut source_failures,
                    source,
                    "원본 행 필드를 읽을 수 없습니다",
                );
                continue;
            }
            let evidence = account_event_evidence(&record, &query.sid, &query.username);
            if evidence.is_empty()
                || !account_event_matches_search(
                    &record,
                    &source.log_name,
                    &evidence,
                    query.search.as_deref().unwrap_or_default(),
                )
            {
                continue;
            }
            hits.push(AccountEventHit {
                source_index,
                rowid,
                timestamp: map_text(&record, "timestamp"),
                evidence,
            });
        }
    }

    hits.sort_by(account_event_order);
    AccountEventIndex {
        hits,
        source_count: i64::try_from(sources.len()).unwrap_or(i64::MAX),
        sources_read,
        source_failures,
    }
}

fn account_event_page_blocking(
    sources: Vec<AccountEventSource>,
    query: AccountEventQuery,
) -> Result<AccountEventPage, String> {
    let key = account_event_cache_key(&sources, &query);
    let index = match account_event_cache_get(&key) {
        Some(index) => index,
        None => {
            let index = build_account_event_index(&sources, &query);
            account_event_cache_put(key, index.clone());
            index
        }
    };
    let row_count = i64::try_from(index.hits.len()).unwrap_or(i64::MAX);
    let offset = usize::try_from(query.offset.max(0)).unwrap_or(usize::MAX);
    let limit = usize::try_from(query.limit.clamp(1, 100)).unwrap_or(100);
    let mut rows = Vec::with_capacity(limit);
    let mut source_failures = index.source_failures.clone();
    for hit in index.hits.iter().skip(offset).take(limit) {
        let source = &sources[hit.source_index];
        if let Ok(mut row) = event_row_by_rowid(source, hit.rowid) {
            row.insert("_log".to_string(), Value::String(source.log_name.clone()));
            // Account-detail rows are fetched from multiple raw EventLog
            // SQLite files. Carry the exact source identity so RowDetailPanel
            // bookmarking never writes an annotation against TargetInfo or an
            // arbitrary same-rowid EventLog file.
            row.insert(
                "_source_full_path".to_string(),
                Value::String(source.full_path.clone()),
            );
            row.insert(
                "_source_table_name".to_string(),
                Value::String(source.table_name.clone()),
            );
            row.insert(
                "_account_match".to_string(),
                Value::String(hit.evidence.clone()),
            );
            rows.push(row);
        } else {
            account_event_source_failure(
                &mut source_failures,
                source,
                "선택된 원본 행을 다시 읽을 수 없습니다",
            );
        }
    }
    Ok(AccountEventPage {
        rows,
        row_count,
        source_count: index.source_count,
        sources_read: index.sources_read,
        source_failures,
    })
}

/// Account EventLog scans parse every candidate EventData JSON to preserve
/// exact SID/role correlation and an accurate global count.  A synchronous
/// Tauri command runs this CPU + SQLite I/O on the command handler thread and
/// can stall the webview while opening an account or moving pages.  Keep the
/// full scan on Tauri's dedicated blocking executor instead.  The renderer's
/// existing effect cancellation still discards stale responses; a started
/// SQLite read is deliberately allowed to finish so no evidence scan is
/// interrupted midway.
#[tauri::command]
async fn account_event_page(
    sources: Vec<AccountEventSource>,
    query: AccountEventQuery,
) -> Result<AccountEventPage, String> {
    tauri::async_runtime::spawn_blocking(move || account_event_page_blocking(sources, query))
        .await
        .map_err(|error| format!("account event worker stopped unexpectedly: {error}"))?
}

fn browser_activity_where(query: &BrowserActivityQuery) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    if let Some(account) = query
        .account
        .as_ref()
        .filter(|v| !v.is_empty() && *v != "(전체)")
    {
        clauses.push("account = ?".to_string());
        params.push(account.clone());
    }
    if !query.kinds.is_empty() {
        clauses.push(format!(
            "kind IN ({})",
            (0..query.kinds.len())
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",")
        ));
        params.extend(query.kinds.iter().cloned());
    }
    if let Some(day) = query.day.as_ref().filter(|v| !v.is_empty()) {
        clauses.push("substr(timestamp, 1, 10) = ?".to_string());
        params.push(day.clone());
    }
    if let Some(start) = query.start.as_ref().filter(|v| !v.is_empty()) {
        clauses.push("timestamp >= ?".to_string());
        params.push(start.clone());
    }
    if let Some(end) = query.end.as_ref().filter(|v| !v.is_empty()) {
        clauses.push("timestamp <= ?".to_string());
        params.push(end.clone());
    }
    if let Some(search) = query.search.as_ref().filter(|v| !v.trim().is_empty()) {
        clauses.push("(url LIKE ? OR title LIKE ? OR url_raw LIKE ?)".to_string());
        let like = format!("%{}%", search.trim());
        params.extend([like.clone(), like.clone(), like]);
    }
    (
        if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        },
        params,
    )
}

fn browser_activity_summary_blocking(
    full_path: String,
    table_name: String,
    query: BrowserActivityQuery,
) -> Result<BrowserActivitySummary, String> {
    let conn = open_ro(&full_path)?;
    let (where_, params) = browser_activity_where(&query);
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let total = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {}{}", q(&table_name), where_),
            refs.as_slice(),
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let accounts = {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT DISTINCT account FROM {}{} ORDER BY account",
                q(&table_name),
                where_
            ))
            .map_err(|e| e.to_string())?;
        let accounts = stmt
            .query_map(refs.as_slice(), |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();
        accounts
    };
    let mut stmt = conn.prepare(&format!("SELECT substr(timestamp, 1, 10), COUNT(*) FROM {}{} GROUP BY substr(timestamp, 1, 10) ORDER BY 1", q(&table_name), where_)).map_err(|e| e.to_string())?;
    let days = stmt
        .query_map(refs.as_slice(), |r| {
            Ok(ColumnValue {
                value: r.get(0)?,
                count: r.get(1)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(BrowserActivitySummary {
        accounts,
        days,
        total,
    })
}

/// Browser summaries can group large activity tables. Keep SQLite work off
/// the command path so changing the date/account filter does not stall other
/// controls in the WebView.
#[tauri::command]
async fn browser_activity_summary(
    full_path: String,
    table_name: String,
    query: BrowserActivityQuery,
) -> Result<BrowserActivitySummary, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_activity_summary_blocking(full_path, table_name, query)
    })
    .await
    .map_err(|error| format!("브라우저 요약 작업이 중단되었습니다: {error}"))?
}

/// Extract a hostname only when the stored browser URL is a valid absolute URL
/// with a host. `Url` normalises authority syntax; lower-casing and trimming a
/// terminal DNS dot yields a stable display/grouping value while the original
/// URL evidence remains unchanged in SQLite.
fn browser_url_domain(value: &str) -> Option<String> {
    let parsed = Url::parse(value.trim()).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn browser_domain_cache_key(
    full_path: &str,
    table_name: &str,
    account: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
) -> BrowserDomainCacheKey {
    let metadata = std::fs::metadata(full_path).ok();
    let modified_ns = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    BrowserDomainCacheKey {
        full_path: full_path.to_string(),
        table_name: table_name.to_string(),
        account: account.unwrap_or_default().to_string(),
        start: start.unwrap_or_default().to_string(),
        end: end.unwrap_or_default().to_string(),
        size: metadata.as_ref().map(|metadata| metadata.len()),
        modified_ns,
    }
}

fn browser_domain_cache_get(key: &BrowserDomainCacheKey) -> Option<Vec<BrowserVisitedDomainStat>> {
    let cache = BROWSER_DOMAIN_CACHE.get_or_init(|| Mutex::new(BrowserDomainCache::default()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    cache
        .entries
        .retain(|entry| now.duration_since(entry.inserted_at) <= BROWSER_DOMAIN_CACHE_TTL);
    let index = cache.entries.iter().position(|entry| entry.key == *key)?;
    let entry = cache.entries.remove(index)?;
    let domains = entry.domains.clone();
    cache.entries.push_back(entry);
    Some(domains)
}

fn browser_domain_cache_put(key: BrowserDomainCacheKey, domains: Vec<BrowserVisitedDomainStat>) {
    // The cache is capped by entry count and domain count. Very broad scopes
    // still return a server page, but are deliberately not retained in memory.
    if domains.len() > BROWSER_DOMAIN_CACHE_MAX_DOMAINS_PER_ENTRY {
        return;
    }
    let cache = BROWSER_DOMAIN_CACHE.get_or_init(|| Mutex::new(BrowserDomainCache::default()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    cache.entries.retain(|entry| {
        now.duration_since(entry.inserted_at) <= BROWSER_DOMAIN_CACHE_TTL && entry.key != key
    });
    cache.entries.push_back(BrowserDomainCacheEntry {
        key,
        domains,
        inserted_at: now,
    });
    while cache.entries.len() > BROWSER_DOMAIN_CACHE_MAX_ENTRIES {
        cache.entries.pop_front();
    }
}

#[cfg(test)]
static BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn clear_browser_domain_cache_for_test() {
    let cache = BROWSER_DOMAIN_CACHE.get_or_init(|| Mutex::new(BrowserDomainCache::default()));
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entries
        .clear();
    BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Produces the complete, server-side domain ordering for one account and
/// incident period. Callers page the returned aggregate before serialisation;
/// individual browser activity records never leave the backend for this view.
fn browser_visit_domains(
    conn: &Connection,
    table_name: &str,
    visit_where: &str,
    refs: &[&dyn rusqlite::ToSql],
) -> Result<Vec<BrowserVisitedDomainStat>, String> {
    #[cfg(test)]
    BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // Aggregate one exact stored URL before grouping by normalised hostname.
    // This retains the former URL grouping semantics for `url_count`.
    let mut url_stmt = conn
        .prepare(&format!(
            "SELECT MIN(rowid), url, COALESCE(SUM(CAST(visit_count AS INTEGER)), 0) \
         FROM {}{visit_where} AND COALESCE(url, '') <> '' \
         GROUP BY url",
            q(table_name),
        ))
        .map_err(|error| error.to_string())?;
    let mut domain_totals: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    let mut url_rows = url_stmt.query(refs).map_err(|error| error.to_string())?;
    while let Some(row) = url_rows.next().map_err(|error| error.to_string())? {
        let row_id: i64 = row.get(0).map_err(|error| error.to_string())?;
        let url: String = row.get(1).map_err(|error| error.to_string())?;
        let visit_count: i64 = row.get(2).map_err(|error| error.to_string())?;
        let Some(domain) = browser_url_domain(&url) else {
            continue;
        };
        let entry = domain_totals.entry(domain).or_insert((row_id, 0, 0));
        entry.0 = entry.0.min(row_id);
        entry.1 += visit_count;
        entry.2 += 1;
    }
    let mut domains = domain_totals
        .into_iter()
        .map(
            |(domain, (row_id, visit_count, url_count))| BrowserVisitedDomainStat {
                row_id,
                domain,
                visit_count,
                url_count,
            },
        )
        .collect::<Vec<_>>();
    domains.sort_by(|left, right| {
        right
            .visit_count
            .cmp(&left.visit_count)
            .then_with(|| left.domain.cmp(&right.domain))
    });
    Ok(domains)
}

fn browser_visit_domains_cached(
    full_path: &str,
    table_name: &str,
    account: Option<&str>,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Vec<BrowserVisitedDomainStat>, String> {
    let key = browser_domain_cache_key(full_path, table_name, account, start, end);
    if let Some(domains) = browser_domain_cache_get(&key) {
        return Ok(domains);
    }
    let conn = open_ro(full_path)?;
    let query = BrowserActivityQuery {
        account: account.map(str::to_owned),
        kinds: Vec::new(),
        day: None,
        search: None,
        start: start.map(str::to_owned),
        end: end.map(str::to_owned),
        offset: 0,
        limit: 1,
        descending: None,
    };
    let (where_, params) = browser_activity_where(&query);
    let refs: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let visit_where = if where_.is_empty() {
        " WHERE kind = 'visit'".to_owned()
    } else {
        format!("{where_} AND kind = 'visit'")
    };
    let domains = browser_visit_domains(&conn, table_name, &visit_where, refs.as_slice())?;
    browser_domain_cache_put(key, domains.clone());
    Ok(domains)
}

/// Returns the bounded analysis strip above the date ledger. Unlike the
/// selected-day evidence table, these aggregates deliberately cover the active
/// account and global incident period so the displayed scope stays stable while
/// an analyst moves through individual dates.
fn browser_activity_insights_blocking(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
) -> Result<BrowserActivityInsights, String> {
    let mut top_visited_domains = browser_visit_domains_cached(
        &full_path,
        &table_name,
        account.as_deref(),
        start.as_deref(),
        end.as_deref(),
    )?;
    let conn = open_ro(&full_path)?;
    let query = BrowserActivityQuery {
        account,
        kinds: Vec::new(),
        day: None,
        search: None,
        start,
        end,
        offset: 0,
        limit: 8,
        descending: None,
    };
    let (where_, params) = browser_activity_where(&query);
    let refs: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    // The header total must match the domain list exactly: malformed/hostless
    // URLs cannot be represented as a domain and are therefore excluded from
    // this specific analytical scope.
    let visit_total = top_visited_domains
        .iter()
        .map(|domain| domain.visit_count)
        .sum();
    top_visited_domains.truncate(8);
    let download_where = if where_.is_empty() {
        " WHERE kind = 'download'".to_owned()
    } else {
        format!("{where_} AND kind = 'download'")
    };
    let download_total = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {}{download_where}", q(&table_name)),
            refs.as_slice(),
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    let downloads = query_rows(
        &conn,
        &format!(
            "SELECT rowid AS __rowid, * FROM {}{download_where} ORDER BY timestamp DESC LIMIT 8",
            q(&table_name)
        ),
        &refs,
    )?;
    Ok(BrowserActivityInsights {
        visit_total,
        top_visited_domains,
        download_total,
        downloads,
    })
}

#[tauri::command]
async fn browser_activity_insights(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
) -> Result<BrowserActivityInsights, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_activity_insights_blocking(full_path, table_name, account, start, end)
    })
    .await
    .map_err(|error| format!("브라우저 통계 작업이 중단되었습니다: {error}"))?
}

/// Server-paginated continuation of the compact domain analysis strip. The
/// same account and global incident-period where clause as insights is used;
/// a selected day or activity-kind toggle deliberately never narrows it.
#[allow(clippy::too_many_arguments)] // 정렬 옵션 포함 command 시그니처
fn browser_activity_domains_blocking(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
    ascending: Option<bool>,
) -> Result<BrowserDomainStatsPage, String> {
    let mut domains = browser_visit_domains_cached(
        &full_path,
        &table_name,
        account.as_deref(),
        start.as_deref(),
        end.as_deref(),
    )?;
    // 기본은 방문 많은 순 — 요청 시 적은 순으로 뒤집는다.
    if ascending.unwrap_or(false) {
        domains.reverse();
    }
    let total = i64::try_from(domains.len()).unwrap_or(i64::MAX);
    let page_offset = usize::try_from(offset.max(0)).unwrap_or(usize::MAX);
    let page_limit = usize::try_from(limit.clamp(1, 100)).unwrap_or(100);
    let domains = domains
        .into_iter()
        .skip(page_offset)
        .take(page_limit)
        .collect();
    Ok(BrowserDomainStatsPage { domains, total })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // 정렬 옵션 포함 command 시그니처
async fn browser_activity_domains(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
    ascending: Option<bool>,
) -> Result<BrowserDomainStatsPage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_activity_domains_blocking(full_path, table_name, account, start, end, offset, limit, ascending)
    })
    .await
    .map_err(|error| format!("도메인 통계 작업이 중단되었습니다: {error}"))?
}

fn browser_activity_page_blocking(
    full_path: String,
    table_name: String,
    query: BrowserActivityQuery,
) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let columns = table_columns(&conn, &table_name);
    let (where_, mut params) = browser_activity_where(&query);
    let count_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let row_count = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {}{}", q(&table_name), where_),
            count_refs.as_slice(),
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    params.push(query.limit.clamp(1, 200).to_string());
    params.push(query.offset.max(0).to_string());
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let order = if query.descending.unwrap_or(false) {
        "DESC"
    } else {
        "ASC"
    };
    let sql = format!(
        "SELECT rowid AS __rowid, * FROM {}{} ORDER BY timestamp {order} LIMIT ? OFFSET ?",
        q(&table_name),
        where_
    );
    let rows = query_rows(&conn, &sql, &refs)?;
    Ok(CsvData {
        columns,
        rows,
        row_count,
    })
}

#[tauri::command]
async fn browser_activity_page(
    full_path: String,
    table_name: String,
    query: BrowserActivityQuery,
) -> Result<CsvData, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_activity_page_blocking(full_path, table_name, query)
    })
    .await
    .map_err(|error| format!("브라우저 기록 작업이 중단되었습니다: {error}"))?
}

fn ai_referrals_blocking(
    full_path: String,
    table_name: String,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let mut clauses = vec!["(url LIKE '%utm_source=chatgpt.com%' OR url LIKE '%utm_source=gemini%' OR url LIKE '%utm_source=claude%')".to_string()];
    let mut params = Vec::new();
    if let Some(v) = start.filter(|v| !v.is_empty()) {
        clauses.push("timestamp >= ?".into());
        params.push(v);
    }
    if let Some(v) = end.filter(|v| !v.is_empty()) {
        clauses.push("timestamp <= ?".into());
        params.push(v);
    }
    let where_ = clauses.join(" AND ");
    let count_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let row_count = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE {}", q(&table_name), where_),
            count_refs.as_slice(),
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    params.push(limit.clamp(1, 100).to_string());
    params.push(offset.max(0).to_string());
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let rows = query_rows(
        &conn,
        &format!(
            "SELECT rowid AS __rowid, * FROM {} WHERE {} ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            q(&table_name),
            where_
        ),
        &refs,
    )?;
    Ok(CsvData {
        columns: table_columns(&conn, &table_name),
        rows,
        row_count,
    })
}

#[tauri::command]
async fn ai_referrals(
    full_path: String,
    table_name: String,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    tauri::async_runtime::spawn_blocking(move || {
        ai_referrals_blocking(full_path, table_name, start, end, offset, limit)
    })
    .await
    .map_err(|error| format!("AI 공유 링크 작업이 중단되었습니다: {error}"))?
}

/// WMI-Activity 이벤트 로그에서 구독 이벤트(5859~5861)만 서버에서 걸러
/// 돌려준다 — 원본 EventLog 테이블 전체를 IPC로 옮기지 않는다(payload가 로그
/// 크기가 아니라 구독 이벤트 수에 비례). rows에는 `__rowid`가 있어 원본
/// EventLog 행 기준 북마크가 연결된다. 로그가 없는 호스트는 빈 결과.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WmiSubscriptionEvents {
    columns: Vec<String>,
    rows: Vec<Map<String, Value>>,
    full_path: String,
    table_name: String,
}

#[tauri::command]
async fn wmi_subscription_events(host_dir: String) -> Result<WmiSubscriptionEvents, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&host_dir)
            .join("EVENTLOG")
            .join("Microsoft-Windows-WMI-Activity%4Operational.sqlite");
        let empty = WmiSubscriptionEvents {
            columns: Vec::new(),
            rows: Vec::new(),
            full_path: String::new(),
            table_name: String::new(),
        };
        if !path.is_file() {
            return Ok(empty);
        }
        let conn = open_ro(&path.to_string_lossy())?;
        let Some(table) = first_table(&conn) else {
            return Ok(empty);
        };
        let columns = table_columns(&conn, &table);
        let sql = format!(
            "SELECT rowid AS __rowid, * FROM {} WHERE \"EventID\" IN ('5859','5860','5861') ORDER BY timestamp ASC",
            q(&table)
        );
        let rows = query_rows(&conn, &sql, &[])?;
        Ok(WmiSubscriptionEvents {
            columns,
            rows,
            full_path: path.to_string_lossy().to_string(),
            table_name: table,
        })
    })
    .await
    .map_err(|error| format!("WMI 구독 이벤트 조회가 중단되었습니다: {error}"))?
}

/// PowerShellHistory 원문 검색 — 목록 IPC는 script_block/host_application을
/// 미리보기(1,000자)로만 싣기 때문에, 그 뒤의 IOC·명령 문자열은 서버에서
/// 원문 컬럼을 대상으로 찾아 일치 rowid를 돌려준다. 뷰는 이 집합을 화면
/// 필터에 합류시켜 절단 없이 검색 정확성을 유지한다.
#[tauri::command]
async fn powershell_search_rowids(
    full_path: String,
    query: String,
) -> Result<Vec<i64>, String> {
    tauri::async_runtime::spawn_blocking(move || -> Result<Vec<i64>, String> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let conn = open_ro(&full_path)?;
        let like = format!(
            "%{}%",
            needle
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let sql = "SELECT rowid FROM \"PowerShellHistory\" WHERE lower(COALESCE(command,'')) LIKE ?1 ESCAPE '\\' OR lower(COALESCE(script_block,'')) LIKE ?1 ESCAPE '\\' OR lower(COALESCE(host_application,'')) LIKE ?1 ESCAPE '\\'";
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([&like], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    })
    .await
    .map_err(|error| format!("파워셸 검색 작업이 중단되었습니다: {error}"))?
}

#[tauri::command]
async fn read_result_file(full_path: String, table_name: Option<String>) -> Result<CsvData, String> {
    // 개요 테이블 전량 로드 — 큰 테이블의 조회·응답 직렬화가 메인 스레드를
    // 막지 않게 blocking 풀에서 돈다.
    tauri::async_runtime::spawn_blocking(move || read_result_file_blocking(full_path, table_name))
        .await
        .map_err(|error| format!("결과 테이블 조회 작업이 중단되었습니다: {error}"))?
}

fn read_result_file_blocking(full_path: String, table_name: Option<String>) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let table = match table_name.or_else(|| first_table(&conn)) {
        Some(t) => t,
        None => {
            return Ok(CsvData {
                columns: vec![],
                rows: vec![],
                row_count: 0,
            })
        }
    };
    let mut columns = table_columns(&conn, &table);
    // Raw Chrome cache bodies can each be several MB. They are fetched on
    // demand by `cache_entry_body`; never serialize all bodies into the table.
    let is_cache = table == "CacheEntries";
    if is_cache {
        columns.retain(|c| c != "body_b64");
    }
    // 4104 ScriptBlock 본문은 행당 수 KB~수백 KB — 대량 스크립트 블록 로깅
    // 호스트에서 전량 직렬화하면 웹뷰 메모리가 고갈돼 앱이 강제 종료된다.
    // 목록/세션 묶음에는 앞부분 미리보기만 싣고, 상세 패널은 result_row로
    // 전체 원문을 다시 받는다 (증거 원문은 절단 없이 유지).
    let is_powershell = table == "PowerShellHistory";
    let select = if is_cache {
        columns.iter().map(|c| q(c)).collect::<Vec<_>>().join(", ")
    } else if is_powershell {
        columns
            .iter()
            .map(|c| match c.as_str() {
                "script_block" | "host_application" => {
                    format!("substr({q}, 1, 1000) AS {q}", q = q(c))
                }
                _ => q(c),
            })
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        "*".into()
    };
    let row_count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", q(&table)), [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    let sql = if is_cache {
        format!(
            "SELECT rowid AS __rowid, {} FROM {} ORDER BY rowid DESC LIMIT 1000",
            select,
            q(&table)
        )
    } else if is_powershell {
        format!("SELECT rowid AS __rowid, {} FROM {}", select, q(&table))
    } else {
        format!("SELECT rowid AS __rowid, * FROM {}", q(&table))
    };
    let rows = query_rows(&conn, &sql, &[])?;
    Ok(CsvData {
        columns,
        rows,
        row_count,
    })
}

/// 대형 원본 테이블용 페이지 조회. read_result_file과 같은 열 규칙(CacheEntries
/// body_b64 제외)을 따르되 offset/limit 창만 직렬화한다 — 원본 EVTX처럼 수십만
/// 행짜리 테이블을 웹뷰 메모리에 통째로 올리지 않기 위한 경로. row_count는
/// 전체 건수라 호출 측이 남은 분량을 스크롤 시점에 이어 받는다.
#[tauri::command]
async fn read_result_file_page(
    full_path: String,
    table_name: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    // 원본 대형 테이블의 청크(2만 행) 조회·직렬화 — 열람·스크롤 이어받기가
    // 메인 스레드를 막지 않게 blocking 풀에서 돈다.
    tauri::async_runtime::spawn_blocking(move || {
        read_result_file_page_blocking(full_path, table_name, offset, limit)
    })
    .await
    .map_err(|error| format!("결과 테이블 페이지 조회 작업이 중단되었습니다: {error}"))?
}

fn read_result_file_page_blocking(
    full_path: String,
    table_name: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let table = match table_name.or_else(|| first_table(&conn)) {
        Some(t) => t,
        None => {
            return Ok(CsvData {
                columns: vec![],
                rows: vec![],
                row_count: 0,
            })
        }
    };
    let mut columns = table_columns(&conn, &table);
    let is_cache = table == "CacheEntries";
    if is_cache {
        columns.retain(|c| c != "body_b64");
    }
    let select = if is_cache {
        columns.iter().map(|c| q(c)).collect::<Vec<_>>().join(", ")
    } else {
        "*".into()
    };
    let row_count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", q(&table)), [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    let sql = format!(
        "SELECT rowid AS __rowid, {} FROM {} ORDER BY rowid LIMIT ? OFFSET ?",
        select,
        q(&table)
    );
    let limit = limit.clamp(1, 100_000);
    let offset = offset.max(0);
    let rows = query_rows(&conn, &sql, &[&limit, &offset])?;
    Ok(CsvData {
        columns,
        rows,
        row_count,
    })
}

/// Reads a bounded page of evidence rows connected to a selected record.
///
/// The match column is verified against SQLite metadata before it is used as
/// an identifier. Values, search text, paging and limits always remain bound
/// parameters, so a long Prefetch loaded-file list never needs to be copied
/// into the webview just to render the first five rows.
#[tauri::command]
async fn linked_result_rows(
    full_path: String,
    table_name: String,
    match_column: String,
    match_value: String,
    search: String,
    offset: i64,
    limit: i64,
) -> Result<LinkedRowsPage, String> {
    // 비인덱스 컬럼 WHERE는 대형 테이블에서 풀스캔이다 — 상세 패널의 연결
    // 증거 조회가 메인 스레드를 막지 않게 blocking 풀에서 돈다.
    tauri::async_runtime::spawn_blocking(move || {
        linked_result_rows_blocking(full_path, table_name, match_column, match_value, search, offset, limit)
    })
    .await
    .map_err(|error| format!("연결 기록 조회 작업이 중단되었습니다: {error}"))?
}

#[allow(clippy::too_many_arguments)]
fn linked_result_rows_blocking(
    full_path: String,
    table_name: String,
    match_column: String,
    match_value: String,
    search: String,
    offset: i64,
    limit: i64,
) -> Result<LinkedRowsPage, String> {
    let conn = open_ro(&full_path)?;
    let columns = table_columns(&conn, &table_name);
    if columns.is_empty() {
        return Err("linked result table was not found".to_owned());
    }
    if !columns.iter().any(|column| column == &match_column) {
        return Err("linked result match column was not found".to_owned());
    }

    let search_column = if columns.iter().any(|column| column == "loaded_filename") {
        "loaded_filename"
    } else {
        &match_column
    };
    let mut clauses = vec![format!("{} = ?", q(&match_column))];
    let mut params = vec![match_value];
    if !search.trim().is_empty() {
        clauses.push(format!(
            "LOWER(COALESCE({}, '')) LIKE '%' || LOWER(?) || '%'",
            q(search_column)
        ));
        params.push(search.trim().to_owned());
    }
    let where_clause = clauses.join(" AND ");
    let count_params: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let row_count = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE {}",
                q(&table_name),
                where_clause
            ),
            count_params.as_slice(),
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;

    params.push(limit.clamp(1, 100).to_string());
    params.push(offset.max(0).to_string());
    let page_params: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let sql = format!(
        "SELECT rowid AS __rowid, * FROM {} WHERE {} ORDER BY rowid LIMIT ? OFFSET ?",
        q(&table_name),
        where_clause,
    );
    let rows = query_rows(&conn, &sql, page_params.as_slice())?;
    Ok(LinkedRowsPage { rows, row_count })
}

/// Resolve one bookmarked source row.  The bookmark view must never load an
/// entire source table just to display a handful of marked rows: Browser
/// Activity and Registry tables can contain hundreds of thousands of rows.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultRow {
    columns: Vec<String>,
    row: Option<Map<String, Value>>,
}

fn result_row_blocking(
    full_path: String,
    table_name: String,
    rowid: i64,
) -> Result<ResultRow, String> {
    let conn = open_ro(&full_path)?;
    let columns = table_columns(&conn, &table_name);
    if columns.is_empty() {
        return Ok(ResultRow { columns, row: None });
    }
    let sql = format!(
        "SELECT rowid AS __rowid, * FROM {} WHERE rowid = ?1",
        q(&table_name)
    );
    let row = query_rows(&conn, &sql, &[&rowid])?.into_iter().next();
    Ok(ResultRow { columns, row })
}

/// 대용량 원문 행(4104 ScriptBlock 등)을 상세에서 여는 경로 — SQLite I/O와
/// 행 변환을 메인 명령 경로에 두면 클릭 처리와 창 이벤트가 멈춘다.
#[tauri::command]
async fn result_row(
    full_path: String,
    table_name: String,
    rowid: i64,
) -> Result<ResultRow, String> {
    tauri::async_runtime::spawn_blocking(move || result_row_blocking(full_path, table_name, rowid))
        .await
        .map_err(|error| format!("행 조회 작업이 중단되었습니다: {error}"))?
}

#[derive(Serialize)]
struct ColumnValue {
    value: String,
    count: i64,
}

#[tauri::command]
async fn list_column_values(
    full_path: String,
    column: String,
    table_name: Option<String>,
) -> Vec<ColumnValue> {
    // 필터 드롭다운의 고유값 집계는 대형 테이블 GROUP BY 풀스캔이다 — 메인
    // 스레드 밖에서 수행한다.
    tauri::async_runtime::spawn_blocking(move || {
        list_column_values_blocking(full_path, column, table_name)
    })
    .await
    .unwrap_or_default()
}

fn list_column_values_blocking(
    full_path: String,
    column: String,
    table_name: Option<String>,
) -> Vec<ColumnValue> {
    let conn = match open_ro(&full_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let table = match table_name.or_else(|| first_table(&conn)) {
        Some(t) => t,
        None => return vec![],
    };
    if !table_columns(&conn, &table).contains(&column) {
        return vec![];
    }
    let sql = format!(
        "SELECT {c} AS value, COUNT(*) AS count FROM {t} GROUP BY {c} ORDER BY count DESC",
        c = q(&column),
        t = q(&table)
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = stmt.query_map([], |r| {
        let value = match r.get_ref(0) {
            Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
            Ok(ValueRef::Integer(i)) => i.to_string(),
            Ok(ValueRef::Real(f)) => f.to_string(),
            _ => String::new(),
        };
        Ok(ColumnValue {
            value,
            count: r.get(1)?,
        })
    });
    match rows {
        Ok(it) => it.filter_map(|x| x.ok()).collect(),
        Err(_) => vec![],
    }
}

const MFT_TABLE: &str = "MFT_Records";

#[tauri::command]
async fn mft_children(
    full_path: String,
    parent_entry: i64,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<MftChildrenPage, String> {
    // 대형 수집본의 폴더 탐색이 다른 IPC 응답성을 막지 않게 blocking
    // executor로 분리한다 (Browser Activity·Cache 본문과 같은 규칙).
    tauri::async_runtime::spawn_blocking(move || {
        mft_children_blocking(
            full_path,
            parent_entry,
            offset.unwrap_or(0),
            limit.unwrap_or(100),
        )
    })
    .await
    .map_err(|error| format!("MFT 자식 조회 작업이 중단되었습니다: {error}"))?
}

/// 읽기·쿼리 실패는 빈 폴더가 아니라 오류로 전파한다 — MFT 탐색은 증거
/// 누락·손상 판단 기능이라, 실패를 "비어 있음"으로 표시하면 잘못된 증거
/// 해석으로 이어진다. UI는 기존 failedEntries/rootError 경로로 재시도를
/// 안내한다.
fn mft_children_blocking(
    full_path: String,
    parent_entry: i64,
    offset: i64,
    limit: i64,
) -> Result<MftChildrenPage, String> {
    let conn = open_ro(&full_path)?;
    if !table_names(&conn).iter().any(|name| name == MFT_TABLE) {
        return Err("MFT 레코드 테이블을 찾을 수 없습니다".to_string());
    }
    // NTFS에는 자식 수만~수십만 개짜리 디렉터리가 실존한다 — 폴더 하나
    // 펼치기가 무제한 IPC가 되지 않게 서버에서 상한을 강제하고, UI가
    // "더 불러오기"로 이어 받는다. rowid 2차 정렬로 페이지 순서를 고정하며,
    // 파싱 단계에서 만든 (parent_entry, is_directory, file_name) 인덱스를
    // 그대로 탄다.
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);
    let pe = parent_entry.to_string();
    // 전체 건수는 첫 페이지에서만 계산한다 — "더 불러오기"마다 COUNT를
    // 반복하지 않도록 후속 페이지는 -1을 반환하고 UI가 보관한 값을 쓴다.
    let total: i64 = if offset == 0 {
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE parent_entry = ?1 AND entry != ?1",
                q(MFT_TABLE)
            ),
            [&pe],
            |r| r.get(0),
        )
        .map_err(|error| format!("MFT 자식 수 조회 실패: {error}"))?
    } else {
        -1
    };
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE parent_entry = ?1 AND entry != ?1 ORDER BY is_directory DESC, file_name COLLATE NOCASE, rowid LIMIT ?2 OFFSET ?3", q(MFT_TABLE));
    let rows = query_rows(&conn, &sql, &[&pe, &limit, &offset])?;
    Ok(MftChildrenPage { rows, total })
}

#[tauri::command]
async fn mft_search(full_path: String, query: String, limit: i64) -> Result<Vec<Map<String, Value>>, String> {
    // 수백만 행 MFT의 LIKE 풀스캔 — 검색이 메인 스레드를 막지 않게 blocking
    // 풀에서 돈다.
    tauri::async_runtime::spawn_blocking(move || mft_search_blocking(full_path, query, limit))
        .await
        .map_err(|error| format!("MFT 검색 작업이 중단되었습니다: {error}"))?
}

fn mft_search_blocking(full_path: String, query: String, limit: i64) -> Result<Vec<Map<String, Value>>, String> {
    // DB 열기·쿼리 실패를 빈 결과로 위장하지 않는다 — "일치 없음"과
    // "조회 실패"는 분석 판단이 달라지는 별개의 상태다.
    let conn = open_ro(&full_path)?;
    // 호출자 값에 의존하지 않는 서버 측 상한.
    let limit = limit.clamp(1, 500);
    let like = format!("%{}%", query);
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE file_name LIKE ?1 OR path LIKE ?1 ORDER BY is_directory DESC, path COLLATE NOCASE LIMIT ?2", q(MFT_TABLE));
    query_rows(&conn, &sql, &[&like, &limit])
}

/// A bounded, recursive MFT record page for the file-system ledger. Unlike
/// the explorer's child lookup, this does not require expanding each folder;
/// it still keeps the large MFT table in SQLite rather than materialising it
/// in the webview.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MftRecordsPage {
    rows: Vec<Map<String, Value>>,
    total: i64,
}

/// 탐색기 트리의 폴더 자식 한 페이지 — total로 UI가 "더 불러오기" 여부를
/// 판단한다.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MftChildrenPage {
    rows: Vec<Map<String, Value>>,
    total: i64,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // 검색·필터·기간·페이징 인자 — tauri command 시그니처
async fn usnjrnl_page(
    full_path: String,
    search: String,
    reason: String,
    start: String,
    end: String,
    ascending: bool,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    // 20만+ 행 테이블을 세 번 훑는 조회라, 메인 스레드에서 돌리면 탭 진입·
    // 검색·페이지 이동마다 창이 멈춘다 — blocking executor로 분리한다
    // (MFT 탐색·Browser Activity와 같은 규칙).
    tauri::async_runtime::spawn_blocking(move || {
        usnjrnl_page_blocking(full_path, search, reason, start, end, ascending, offset, limit)
    })
    .await
    .map_err(|error| format!("USN 저널 조회 작업이 중단되었습니다: {error}"))?
}

#[allow(clippy::too_many_arguments)]
fn usnjrnl_page_blocking(
    full_path: String,
    search: String,
    reason: String,
    start: String,
    end: String,
    ascending: bool,
    offset: i64,
    limit: i64,
) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let table = "UsnJrnl_Records";
    if !table_names(&conn).iter().any(|name| name == table) {
        return Err("USN 저널 테이블을 찾을 수 없습니다".to_string());
    }
    let mut columns = table_columns(&conn, table);
    columns.push("renamed_from".to_string());
    columns.push("group_count".to_string());
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if !search.trim().is_empty() {
        params.push(format!("%{}%", search.trim()));
        clauses.push(format!("filename LIKE ?{}", params.len()));
    }
    // 상태(대표 유형) 필터 — 뷰의 배지 판정과 같은 우선순위(삭제 > 생성 >
    // 이름 변경 > 데이터 > 정보 > 보안)로 걸어 배지와 필터 결과가 일치한다.
    match reason.as_str() {
        "delete" => clauses.push("reason LIKE '%FILE_DELETE%'".into()),
        "create" => clauses.push(
            "reason LIKE '%FILE_CREATE%' AND reason NOT LIKE '%FILE_DELETE%'".into(),
        ),
        "rename" => clauses.push(
            "reason LIKE '%RENAME\\_%' ESCAPE '\\' AND reason NOT LIKE '%FILE_DELETE%' AND reason NOT LIKE '%FILE_CREATE%'".into(),
        ),
        "data" => clauses.push(
            "reason LIKE '%DATA\\_%' ESCAPE '\\' AND reason NOT LIKE '%FILE_DELETE%' AND reason NOT LIKE '%FILE_CREATE%' AND reason NOT LIKE '%RENAME\\_%' ESCAPE '\\'".into(),
        ),
        "info" => clauses.push(
            "reason LIKE '%BASIC\\_INFO\\_CHANGE%' ESCAPE '\\' AND reason NOT LIKE '%FILE_DELETE%' AND reason NOT LIKE '%FILE_CREATE%' AND reason NOT LIKE '%RENAME\\_%' ESCAPE '\\' AND reason NOT LIKE '%DATA\\_%' ESCAPE '\\'".into(),
        ),
        "security" => clauses.push(
            "reason LIKE '%SECURITY\\_CHANGE%' ESCAPE '\\' AND reason NOT LIKE '%FILE_DELETE%' AND reason NOT LIKE '%FILE_CREATE%' AND reason NOT LIKE '%RENAME\\_%' ESCAPE '\\' AND reason NOT LIKE '%DATA\\_%' ESCAPE '\\' AND reason NOT LIKE '%BASIC\\_INFO\\_CHANGE%' ESCAPE '\\'".into(),
        ),
        _ => {}
    }
    if !start.trim().is_empty() {
        params.push(start.trim().to_string());
        clauses.push(format!("timestamp >= ?{}", params.len()));
    }
    if !end.trim().is_empty() {
        params.push(end.trim().to_string());
        clauses.push(format!("timestamp <= ?{}", params.len()));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    // USN 레코드는 파일 핸들이 닫힐 때까지 사유가 누적되며 여러 행으로
    // 남는다. 같은 파일(참조 번호)·같은 시각의 기록을 한 행동으로 묶는다 —
    // 누적 체인과 이름 변경(OLD/NEW 쌍)이 모두 하나로 합쳐진다.
    let base = format!("SELECT rowid AS __rowid, * FROM {}{}", q(table), where_clause);
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|value| value as &dyn rusqlite::ToSql).collect();

    let count_sql = format!(
        "SELECT COUNT(*) FROM (SELECT 1 FROM ({base}) GROUP BY file_reference, timestamp)"
    );
    let row_count: i64 = conn
        .query_row(&count_sql, refs.as_slice(), |row| row.get(0))
        .map_err(|error| format!("USN 저널 행 수를 읽지 못했습니다: {error}"))?;

    let direction = if ascending { "ASC" } else { "DESC" };
    let keys_sql = format!(
        "SELECT file_reference, timestamp FROM ({base}) GROUP BY file_reference, timestamp ORDER BY timestamp {direction}, MAX(CAST(usn AS INTEGER)) {direction} LIMIT {limit} OFFSET {offset}"
    );
    let keys = query_rows(&conn, &keys_sql, refs.as_slice())?;
    if keys.is_empty() {
        return Ok(CsvData {
            columns,
            rows: Vec::new(),
            row_count,
        });
    }

    // 이번 페이지 묶음의 구성 기록만 다시 읽는다 (USN 오름차순 = 기록 순서).
    let mut member_params = params.clone();
    let mut tuples = Vec::new();
    for key in &keys {
        let fr = key.get("file_reference").and_then(Value::as_str).unwrap_or("");
        let ts = key.get("timestamp").and_then(Value::as_str).unwrap_or("");
        member_params.push(fr.to_string());
        let a = member_params.len();
        member_params.push(ts.to_string());
        let b = member_params.len();
        tuples.push(format!("(?{a}, ?{b})"));
    }
    let members_sql = format!(
        "SELECT * FROM ({base}) WHERE (file_reference, timestamp) IN (VALUES {}) ORDER BY CAST(usn AS INTEGER) ASC",
        tuples.join(", ")
    );
    let member_refs: Vec<&dyn rusqlite::ToSql> = member_params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let members = query_rows(&conn, &members_sql, member_refs.as_slice())?;

    // 페이지 순서를 유지하며 묶음별로 병합한다.
    let mut grouped: std::collections::HashMap<(String, String), Vec<Map<String, Value>>> =
        std::collections::HashMap::new();
    for member in members {
        let fr = member
            .get("file_reference")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let ts = member
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        grouped.entry((fr, ts)).or_default().push(member);
    }
    let mut rows = Vec::new();
    for key in &keys {
        let fr = key.get("file_reference").and_then(Value::as_str).unwrap_or("");
        let ts = key.get("timestamp").and_then(Value::as_str).unwrap_or("");
        let Some(group) = grouped.remove(&(fr.to_string(), ts.to_string())) else {
            continue;
        };
        let Some(representative) = group.last().cloned() else {
            continue;
        };
        // 사유 플래그 합집합 — 기록 순서대로 처음 등장한 순서를 보존한다.
        let mut flags: Vec<String> = Vec::new();
        let mut renamed_from = String::new();
        let rep_name = representative
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("");
        for member in &group {
            let member_reason = member.get("reason").and_then(Value::as_str).unwrap_or("");
            for flag in member_reason.split('|') {
                if !flag.is_empty() && !flags.iter().any(|f| f == flag) {
                    flags.push(flag.to_string());
                }
            }
            if member_reason.contains("RENAME_OLD_NAME") {
                let old = member.get("filename").and_then(Value::as_str).unwrap_or("");
                if !old.is_empty() && old != rep_name {
                    renamed_from = old.to_string();
                }
            }
        }
        let mut row = representative;
        row.insert("reason".into(), Value::String(flags.join("|")));
        row.insert("renamed_from".into(), Value::String(renamed_from));
        row.insert(
            "group_count".into(),
            Value::String(group.len().to_string()),
        );
        rows.push(row);
    }
    Ok(CsvData {
        columns,
        rows,
        row_count,
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // 재귀 목록 전용 필터 인자들 — tauri command 시그니처
async fn mft_records_page(
    full_path: String,
    query: String,
    offset: i64,
    limit: i64,
    sort_key: Option<String>,
    sort_desc: Option<bool>,
    files_only: Option<bool>,
    name_pattern: Option<String>,
    time_key: Option<String>,
    time_start: Option<String>,
    time_end: Option<String>,
) -> Result<MftRecordsPage, String> {
    // 수백만 행 MFT의 비인덱스 정렬·필터 페이지 조회 — 메인 스레드 밖에서
    // 수행한다.
    tauri::async_runtime::spawn_blocking(move || {
        mft_records_page_blocking(
            full_path, query, offset, limit, sort_key, sort_desc, files_only, name_pattern,
            time_key, time_start, time_end,
        )
    })
    .await
    .map_err(|error| format!("MFT 목록 조회 작업이 중단되었습니다: {error}"))?
}

#[allow(clippy::too_many_arguments)]
fn mft_records_page_blocking(
    full_path: String,
    query: String,
    offset: i64,
    limit: i64,
    sort_key: Option<String>,
    sort_desc: Option<bool>,
    files_only: Option<bool>,
    name_pattern: Option<String>,
    time_key: Option<String>,
    time_start: Option<String>,
    time_end: Option<String>,
) -> Result<MftRecordsPage, String> {
    let conn = open_ro(&full_path)?;
    if !table_names(&conn).iter().any(|name| name == MFT_TABLE) {
        return Err("MFT 레코드 테이블을 찾을 수 없습니다".to_string());
    }
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);
    let query = query.trim();

    // 재귀 목록 전용 필터: 파일만 보기 / 파일명 글롭(*·?) / 정렬 기준.
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if !query.is_empty() {
        params.push(format!("%{query}%"));
        let n = params.len();
        clauses.push(format!("(file_name LIKE ?{n} OR path LIKE ?{n})"));
    }
    if files_only.unwrap_or(false) {
        clauses.push("is_directory != 'Y'".to_string());
    }
    if let Some(pattern) = name_pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        // 간단 글롭 → SQL LIKE: LIKE 메타문자를 이스케이프한 뒤 * → %, ? → _.
        let mut like = String::with_capacity(pattern.len() + 4);
        for ch in pattern.chars() {
            match ch {
                '\\' | '%' | '_' => {
                    like.push('\\');
                    like.push(ch);
                }
                '*' => like.push('%'),
                '?' => like.push('_'),
                other => like.push(other),
            }
        }
        params.push(like);
        let n = params.len();
        clauses.push(format!("file_name LIKE ?{n} ESCAPE '\\'"));
    }
    // 시간 범위 필터 — 지정한 시각 컬럼 기준. 빈 시각은 자연히 제외된다.
    let time_column = match time_key.as_deref().unwrap_or("created") {
        "modified" => "si_modified",
        "accessed" => "si_accessed",
        "mft_modified" => "si_mft_modified",
        // $FILE_NAME(0x30) 기준 — timestomping은 주로 $SI만 조작되므로
        // 조작 전 시각으로 표를 정렬·필터하는 수단(T7).
        "fn_created" => "fn_created",
        "fn_modified" => "fn_modified",
        "fn_accessed" => "fn_accessed",
        "fn_mft_modified" => "fn_mft_modified",
        _ => "si_created",
    };
    if let Some(start) = time_start.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        params.push(start.to_string());
        clauses.push(format!("{time_column} >= ?{}", params.len()));
    }
    if let Some(end) = time_end.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        params.push(end.to_string());
        clauses.push(format!("{time_column} <= ?{}", params.len()));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM {}{}", q(MFT_TABLE), where_clause);
    let count_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|value| value as &dyn rusqlite::ToSql).collect();
    let total = conn
        .query_row(&count_sql, count_refs.as_slice(), |row| row.get(0))
        .map_err(|error| format!("MFT 레코드 수를 읽지 못했습니다: {error}"))?;

    // 정렬 키 화이트리스트 — 시간 정렬은 값 없는 레코드를 항상 뒤로 보낸다.
    let order_by = match sort_key.as_deref().unwrap_or("path") {
        "name" => "file_name COLLATE NOCASE".to_string(),
        key @ ("created" | "modified" | "accessed" | "mft_modified" | "fn_created"
        | "fn_modified" | "fn_accessed" | "fn_mft_modified") => {
            let column = match key {
                "created" => "si_created",
                "modified" => "si_modified",
                "accessed" => "si_accessed",
                "mft_modified" => "si_mft_modified",
                // fn_* 키는 컬럼명과 동일 ($FILE_NAME 타임스탬프).
                other => other,
            };
            format!("CASE WHEN {column} = '' THEN 1 ELSE 0 END, {column}")
        }
        "size" => "CAST(file_size AS INTEGER)".to_string(),
        _ => "path COLLATE NOCASE".to_string(),
    };
    let direction = if sort_desc.unwrap_or(false) { "DESC" } else { "ASC" };

    let page_sql = format!(
        "SELECT rowid AS __rowid, * FROM {}{} ORDER BY {} {}, rowid LIMIT ?{} OFFSET ?{}",
        q(MFT_TABLE),
        where_clause,
        order_by,
        direction,
        params.len() + 1,
        params.len() + 2,
    );
    params.push(limit.to_string());
    params.push(offset.to_string());
    let page_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|value| value as &dyn rusqlite::ToSql).collect();
    let rows = query_rows(&conn, &page_sql, page_refs.as_slice())
        .map_err(|error| format!("MFT 레코드 페이지를 읽지 못했습니다: {error}"))?;
    Ok(MftRecordsPage { rows, total })
}

#[tauri::command]
fn mft_row(full_path: String, rowid: i64) -> Option<Map<String, Value>> {
    let conn = open_ro(&full_path).ok()?;
    let sql = format!(
        "SELECT rowid AS __rowid, * FROM {} WHERE rowid = ?1",
        q(MFT_TABLE)
    );
    query_rows(&conn, &sql, &[&rowid])
        .ok()
        .and_then(|mut v| v.drain(..).next())
}

#[derive(Deserialize, Clone)]
struct SearchHost {
    id: String,
    name: String,
    dir: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    host_id: String,
    host_name: String,
    file_name: String,
    table_name: String,
    full_path: String,
    rowid: i64,
    match_column: String,
    match_value: String,
    timestamp: String,
    record_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchCasePage {
    hits: Vec<SearchHit>,
    /// Offset cursor for the next page.  `None` means the scan was exhausted.
    next_offset: Option<usize>,
    /// A partial search remains useful, but the UI must not present it as a
    /// complete empty result when a host SQLite source could not be read.
    source_failures: Vec<String>,
}

fn search_case_blocking(
    query: String,
    hosts: Vec<SearchHost>,
    offset: usize,
    limit: usize,
    start: Option<String>,
    end: Option<String>,
    categories: Option<Vec<String>>,
) -> SearchCasePage {
    const MAX_PAGE_SIZE: usize = 100;
    const MATCH_PREVIEW_CHARS: usize = 512;
    let query = query.trim().to_string();
    if query.len() < 2 {
        return SearchCasePage {
            hits: vec![],
            next_offset: None,
            source_failures: vec![],
        };
    }
    let page_size = limit.clamp(1, MAX_PAGE_SIZE);
    let start = start.filter(|value| !value.trim().is_empty());
    let end = end.filter(|value| !value.trim().is_empty());
    let range_active = start.is_some() || end.is_some();
    // Case-fold the requested category folders once. An empty selection means
    // "no category filter" (search everything) rather than "match nothing", so
    // the analyst clearing every checkbox never silently returns zero rows.
    let category_filter: Option<std::collections::HashSet<String>> = categories
        .map(|list| {
            list.into_iter()
                .map(|name| name.trim().to_lowercase())
                .filter(|name| !name.is_empty())
                .collect::<std::collections::HashSet<String>>()
        })
        .filter(|set| !set.is_empty());
    let scan_target = offset.saturating_add(page_size).saturating_add(1);
    let like = format!(
        "%{}%",
        query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let mut hits = Vec::with_capacity(page_size);
    let mut source_failures = Vec::new();
    let mut skipped = 0usize;
    let mut has_next = false;

    for host in &hosts {
        let mut files = Vec::new();
        collect_sqlite(Path::new(&host.dir), &mut files);
        files.sort();
        for fp in files {
            // Restrict to the selected category folders. The category is the
            // first path segment under the host directory (BROWSER, EVENTLOG,
            // …); files that cannot be placed under a category are skipped when
            // a filter is active.
            //
            // `_OVERVIEW` is exempt: it is not a raw artifact bucket but the
            // derived 종합 분석 layer (BrowserActivity, ExecutionHistory,
            // RegistryFindings, …) re-composed from every artifact. The UI
            // deliberately omits it from the selectable categories, so it must
            // always be searched — otherwise unchecking any single artifact
            // would silently drop all correlated results.
            if let Some(ref allow) = category_filter {
                let category = fp
                    .strip_prefix(&host.dir)
                    .ok()
                    .and_then(|rel| rel.components().next())
                    .map(|segment| segment.as_os_str().to_string_lossy().to_lowercase());
                match category {
                    Some(name) if name == "_overview" || allow.contains(&name) => {}
                    _ => continue,
                }
            }
            let conn = match open_ro(&fp.to_string_lossy()) {
                Ok(c) => c,
                Err(_) => {
                    source_failures.push(format!("{}: SQLite 파일", host.name));
                    continue;
                }
            };
            let file_name = fp
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let mut tables = match checked_table_names(&conn) {
                Ok(tables) => tables,
                Err(_) => {
                    source_failures.push(format!("{}: {}", host.name, file_name));
                    continue;
                }
            };
            tables.sort();
            for table in tables {
                if has_next {
                    // Once the requested page is complete, do not continue
                    // evaluating a multi-column LIKE query just to discover
                    // failures. A bounded availability probe still reports
                    // inaccessible/invalid tables without scanning content.
                    let health_sql = format!("SELECT 1 FROM {} LIMIT 1", q(&table));
                    match conn.query_row(&health_sql, [], |_row| Ok(())) {
                        // An empty table is still a healthy, searchable
                        // source. `query_row` reports it as this sentinel.
                        Ok(()) | Err(rusqlite::Error::QueryReturnedNoRows) => {}
                        Err(_) => source_failures.push(format!("{}: {}", host.name, file_name)),
                    }
                    continue;
                }
                let cols = table_columns(&conn, &table);
                if cols.is_empty() {
                    continue;
                }
                // Query only the stable rowid, the first matched field/value,
                // and one candidate evidence time.  The full source row is
                // fetched on an analyst's explicit detail action.
                let where_ = cols
                    .iter()
                    .map(|c| format!("{} LIKE ?1 ESCAPE '\\'", q(c)))
                    .collect::<Vec<_>>()
                    .join(" OR ");
                let match_column = cols
                    .iter()
                    .map(|c| {
                        format!(
                            "WHEN {} LIKE ?1 ESCAPE '\\' THEN '{}'",
                            q(c),
                            c.replace('\'', "''")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let match_value = cols
                    .iter()
                    .map(|c| {
                        format!(
                            "WHEN {} LIKE ?1 ESCAPE '\\' THEN SUBSTR(CAST({} AS TEXT), 1, {})",
                            q(c),
                            q(c),
                            MATCH_PREVIEW_CHARS,
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let timestamp_column = [
                    "timestamp",
                    "time_created",
                    "event_time",
                    "last_write",
                    "created_at",
                    "modified_time",
                    // 후보에 없어 기간 검색에서 통째로 빠지던 테이블들(T7):
                    // MFT_Records(si_created) · CacheEntries(response_time) ·
                    // BROWSER 방문 기록 원본(urls.last_visit_time).
                    "si_created",
                    "response_time",
                    "last_visit_time",
                ]
                .iter()
                .find(|candidate| {
                    cols.iter()
                        .any(|column| column.eq_ignore_ascii_case(candidate))
                })
                .and_then(|candidate| {
                    cols.iter()
                        .find(|column| column.eq_ignore_ascii_case(candidate))
                });
                // last_visit_time은 Chrome/WebKit 에폭(1601-01-01 기준 µs) 원시
                // 정수라 텍스트 경계와 비교할 수 없다 — 다른 파서 출력과 같은
                // 로컬 "YYYY-MM-DD HH:MM:SS" 문자열로 변환해 비교·표시한다.
                let timestamp_sql = timestamp_column.map(|column| {
                    if column.eq_ignore_ascii_case("last_visit_time") {
                        format!(
                            "CASE WHEN CAST({c} AS INTEGER) > 0 THEN datetime(CAST({c} AS INTEGER) / 1000000 - 11644473600, 'unixepoch', 'localtime') ELSE '' END",
                            c = q(column)
                        )
                    } else {
                        format!("CAST({} AS TEXT)", q(column))
                    }
                });
                let timestamp_expr = timestamp_sql
                    .clone()
                    .unwrap_or_else(|| "''".to_string());
                // Overview tables retain a raw-evidence pointer. Carry only a
                // bounded copy so the renderer can bookmark that exact source
                // record without materialising the complete overview row.
                let record_key_column = cols.iter().find(|column| {
                    column.eq_ignore_ascii_case("record_key")
                        || column.eq_ignore_ascii_case("_record_key")
                });
                let record_key_expr = record_key_column
                    .map(|column| {
                        format!(
                            "SUBSTR(CAST({} AS TEXT), 1, {})",
                            q(column),
                            MATCH_PREVIEW_CHARS,
                        )
                    })
                    .unwrap_or_else(|| "''".to_string());
                if range_active && timestamp_column.is_none() {
                    // A table without a usable evidence time cannot be placed
                    // inside the incident window, so do not leak it into an
                    // otherwise global time-filtered result page.
                    continue;
                }
                let mut conditions = vec![format!("({})", where_)];
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&like];
                if let (Some(bound), Some(expr)) = (start.as_ref(), timestamp_sql.as_ref()) {
                    conditions.push(format!("{} >= ?{}", expr, params.len() + 1));
                    params.push(bound);
                }
                if let (Some(bound), Some(expr)) = (end.as_ref(), timestamp_sql.as_ref()) {
                    conditions.push(format!("{} <= ?{}", expr, params.len() + 1));
                    params.push(bound);
                }
                // Once this page has a continuation we still execute a tiny
                // source-aware probe for every remaining table. That keeps
                // unreadable/corrupt sources visible instead of hiding them
                // behind an early pagination exit, without retaining their
                // rows in memory.
                let query_limit = if has_next { 1 } else { scan_target };
                let sql = format!(
                    "SELECT rowid AS __rowid, CASE {} ELSE '' END AS __match_column, CASE {} ELSE '' END AS __match_value, {} AS __timestamp, {} AS __record_key FROM {} WHERE {} ORDER BY rowid LIMIT {}",
                    match_column,
                    match_value,
                    timestamp_expr,
                    record_key_expr,
                    q(&table),
                    conditions.join(" AND "),
                    query_limit,
                );
                let rows = match query_rows(&conn, &sql, &params) {
                    Ok(rows) => rows,
                    Err(_) => {
                        source_failures.push(format!("{}: {}", host.name, file_name));
                        continue;
                    }
                };
                for row in rows {
                    if has_next {
                        continue;
                    }
                    if skipped < offset {
                        skipped += 1;
                        continue;
                    }
                    if hits.len() >= page_size {
                        has_next = true;
                        break;
                    }
                    let rowid = row
                        .get("__rowid")
                        .and_then(|value| value.as_i64())
                        .unwrap_or(0);
                    hits.push(SearchHit {
                        host_id: host.id.clone(),
                        host_name: host.name.clone(),
                        file_name: file_name.clone(),
                        table_name: table.clone(),
                        full_path: fp.to_string_lossy().to_string(),
                        rowid,
                        match_column: row
                            .get("__match_column")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        match_value: row
                            .get("__match_value")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        timestamp: row
                            .get("__timestamp")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        record_key: row
                            .get("__record_key")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_string(),
                    });
                }
            }
        }
    }
    source_failures.sort();
    source_failures.dedup();
    let next_offset = has_next.then_some(offset.saturating_add(hits.len()));
    SearchCasePage {
        hits,
        next_offset,
        source_failures,
    }
}

#[tauri::command]
async fn search_case(
    query: String,
    hosts: Vec<SearchHost>,
    offset: usize,
    limit: usize,
    start: Option<String>,
    end: Option<String>,
    categories: Option<Vec<String>>,
) -> Result<SearchCasePage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        search_case_blocking(query, hosts, offset, limit, start, end, categories)
    })
    .await
    .map_err(|_| "케이스 검색 작업을 완료하지 못했습니다.".to_string())
}

// --- commands: browser cache bodies ----------------------------------------

/// Metadata-only cache entry (no body_b64) — safe to load for all rows.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheMeta {
    account: String,
    url: String,
    content_type: String,
    status: String,
    response_time: String,
    body_size: String,
    cache_key: String,
}

/// Returns metadata (no body) for all cache entries that have a stored body.
/// Callers fetch the body on-demand via `cache_entry_body`.
/// Capped at 20 000 rows to keep IPC snappy even for large caches.
#[tauri::command]
async fn cache_entries(host_dir: String) -> Vec<CacheMeta> {
    // 캐시 sqlite 여러 개를 훑는 메타 수집 — 메인 스레드 밖에서 수행한다.
    tauri::async_runtime::spawn_blocking(move || cache_entries_blocking(host_dir))
        .await
        .unwrap_or_default()
}

fn cache_entries_blocking(host_dir: String) -> Vec<CacheMeta> {
    let dir = PathBuf::from(&host_dir).join("BROWSER");
    let mut out = Vec::new();
    let files = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("_Cache.sqlite"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(_) => return out,
    };
    const ROW_CAP: usize = 20_000;
    for f in files {
        if out.len() >= ROW_CAP {
            break;
        }
        let conn = match open_ro(&f.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let limit = (ROW_CAP - out.len()) as i64;
        let sql = "SELECT account, url, content_type, status, response_time, body_size, cache_key \
                   FROM CacheEntries WHERE body_b64 IS NOT NULL AND body_b64 != '' LIMIT ?1";
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(it) = stmt.query_map([limit], |r| {
            Ok(CacheMeta {
                account: r.get(0).unwrap_or_default(),
                url: r.get(1).unwrap_or_default(),
                content_type: r.get(2).unwrap_or_default(),
                status: r.get(3).unwrap_or_default(),
                response_time: r.get(4).unwrap_or_default(),
                body_size: r.get(5).unwrap_or_default(),
                cache_key: r.get(6).unwrap_or_default(),
            })
        }) {
            for row in it.filter_map(|r| r.ok()) {
                out.push(row);
            }
        };
    }
    out
}

/// The cache-body response is intentionally a preview transport, not a raw
/// CacheEntries row.  Cache bodies may be several MiB and sending an entire
/// base64 value over the webview IPC queue makes the renderer stop responding.
/// `decoded_size` still describes the complete recovered response and
/// `truncated` tells the detail panel that the visible bytes are a prefix.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheBodyPreview {
    body_b64: String,
    decoded_size: usize,
    truncated: bool,
}

// A multiple of four keeps the base64 prefix decodable.  This holds common
// HTML/JS responses (including the observed 417 KiB response) while putting a
// hard upper bound on both SQLite-to-IPC and WebView work for large objects.
const CACHE_BODY_PREVIEW_B64_CAP: usize = 768 * 1024;

fn base64_decoded_size(encoded_len: usize, tail: &str) -> usize {
    let padding = tail
        .as_bytes()
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'=')
        .count();
    encoded_len
        .saturating_div(4)
        .saturating_mul(3)
        .saturating_sub(padding)
}

/// Reads the bounded preview of one *exact* cache record.  Kept synchronous so
/// the command wrapper can move all SQLite and filesystem work to Tauri's
/// blocking worker pool.
fn cache_entry_body_blocking(
    host_dir: String,
    account: String,
    url: String,
    cache_key: String,
) -> CacheBodyPreview {
    // URL alone is not an evidence identifier: the same URL can appear in
    // multiple cache entries with different responses. Old BrowserActivity
    // overviews did not retain `cache_key`; make those records reparse-only
    // instead of silently returning an arbitrary duplicate body.
    if cache_key.trim().is_empty() {
        return CacheBodyPreview::default();
    }
    let dir = PathBuf::from(&host_dir).join("BROWSER");
    let mut files = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("_Cache.sqlite"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(_) => return CacheBodyPreview::default(),
    };
    // A BrowserActivity account is derived from this source filename's prefix
    // (`<account>_<browser>_Cache.sqlite`). Check the account's own databases
    // first rather than scanning every account for every drawer open. The
    // browser is not part of the evidence identity, so match on the account
    // prefix (Chrome/Edge/Whale/Unknown all qualify). Remaining databases stay
    // as a correctness fallback for older data whose recorded account and
    // filename do not agree.
    let expected_prefix = format!("{}_", account);
    files.sort_by(|left, right| {
        let left_owned = left
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(&expected_prefix));
        let right_owned = right
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(&expected_prefix));
        right_owned.cmp(&left_owned).then_with(|| left.cmp(right))
    });
    for f in files {
        let conn = match open_ro(&f.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let sql = "SELECT substr(body_b64, 1, ?4), length(body_b64), substr(body_b64, -2) FROM CacheEntries WHERE account = ?1 AND url = ?2 AND cache_key = ?3 AND body_b64 IS NOT NULL AND body_b64 != '' LIMIT 1";
        if let Ok(mut stmt) = conn.prepare(sql) {
            let query = stmt.query(rusqlite::params![
                account,
                url,
                cache_key,
                CACHE_BODY_PREVIEW_B64_CAP as i64
            ]);
            if let Ok(mut rows) = query {
                if let Ok(Some(row)) = rows.next() {
                    let body_b64 = row.get::<_, String>(0).unwrap_or_default();
                    let encoded_size = row.get::<_, i64>(1).unwrap_or_default().max(0) as usize;
                    let tail = row.get::<_, String>(2).unwrap_or_default();
                    return CacheBodyPreview {
                        truncated: encoded_size > body_b64.len(),
                        decoded_size: base64_decoded_size(encoded_size, &tail),
                        body_b64,
                    };
                }
            }
        };
    }
    CacheBodyPreview::default()
}

/// Fetch a bounded body preview on Tauri's blocking pool.  A synchronous
/// command ran this disk/SQLite query on the invoke path, so opening a large
/// recovered cache record could freeze all click handling in the WebView.
#[tauri::command]
async fn cache_entry_body(
    host_dir: String,
    account: String,
    url: String,
    cache_key: String,
) -> CacheBodyPreview {
    tauri::async_runtime::spawn_blocking(move || {
        cache_entry_body_blocking(host_dir, account, url, cache_key)
    })
    .await
    .unwrap_or_default()
}

// --- Browser visit inflow chain (referrer / opener reconstruction) ----------
//
// The BrowserActivity overview intentionally keeps only per-URL metadata (it
// reads `urls`, never `visits`), so "어디서 이 페이지로 왔나" is not in it. This
// command reconstructs the inflow chain on demand from the *raw* browser
// History database that is already collected under BROWSER/, so it works on
// existing cases with no re-parse. Read-only, bounded, and blocking work runs
// on Tauri's worker pool.

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct VisitGraphNode {
    /// `visits.id` of this node — the *entry* visit when same-URL re-navigations
    /// were collapsed into it (see `reloads`).
    visit_id: String,
    url: String,
    title: String,
    time: String,
    transition: String,
    /// Raw `visits.transition` integer (decoded form is in `transition`).
    transition_raw: String,
    /// A visit of the looked-up page itself — the record the analyst opened
    /// (or, for a cache record, a page under the cache key's document origin).
    is_target: bool,
    /// Same-URL re-navigations (client/server redirect·reload) collapsed into
    /// this node — the page re-navigating to itself is one visit story, not
    /// separate nodes.
    reloads: usize,
    /// Raw cross-site referrer recorded on this visit (may be a site the
    /// visits table has no row for, e.g. `https://chatgpt.com/`).
    external_referrer: String,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct VisitGraphEdge {
    /// Parent (navigation source) node's `visits.id`.
    from: String,
    /// Child (navigation destination) node's `visits.id`.
    to: String,
    /// Column on the child's row that names the parent — the raw join the edge
    /// is built on: "from_visit" (same tab) or "opener_visit" (new tab).
    kind: String,
}

/// The navigation neighbourhood of the looked-up page: every visit reachable
/// from its visits through referrer/opener links in *both* directions —
/// ancestors (where the analyst came from), descendants (where they went next)
/// and sibling branches off shared ancestors.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct BrowserVisitGraph {
    nodes: Vec<VisitGraphNode>,
    edges: Vec<VisitGraphEdge>,
    source_file: String,
    /// For a cache resource: the navigated page we attributed it to.
    matched_page: String,
    note: String,
    /// 방문·노드 상한에 걸려 일부 연결만 표시한 경우.
    truncated: bool,
}

/// Decode a Chromium page-transition integer into a short Korean label.
fn decode_transition(raw: i64) -> String {
    let v = raw as u32;
    let core = match v & 0xff {
        0 => "링크 클릭",
        1 => "주소창 직접 입력",
        2 => "북마크",
        3 => "자동 하위프레임",
        4 => "수동 하위프레임",
        5 => "주소창 추천 이동",
        6 => "시작 페이지",
        7 => "폼 제출",
        8 => "새로고침",
        9 => "키워드 검색",
        10 => "키워드 생성",
        _ => "기타",
    };
    let mut quals: Vec<&str> = Vec::new();
    if v & 0x0100_0000 != 0 {
        quals.push("앞/뒤 이동");
    }
    if v & 0x0200_0000 != 0 {
        quals.push("주소창");
    }
    if v & 0x0800_0000 != 0 {
        quals.push("API");
    }
    if v & 0x4000_0000 != 0 {
        quals.push("클라이언트 리다이렉트");
    }
    if v & 0x8000_0000 != 0 {
        quals.push("서버 리다이렉트");
    }
    if quals.is_empty() {
        core.to_string()
    } else {
        format!("{} · {}", core, quals.join(", "))
    }
}

/// `scheme://host` of a URL, or None when it is not http(s).
fn url_origin(u: &str) -> Option<String> {
    let u = u.trim();
    let (scheme, rest) = u
        .strip_prefix("https://")
        .map(|r| ("https://", r))
        .or_else(|| u.strip_prefix("http://").map(|r| ("http://", r)))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(format!("{scheme}{host}"))
    }
}

/// The top-frame document origin encoded in a Chromium cache key (the first
/// http(s) token, i.e. the `_dk_<site>` entry), used to attribute a cached
/// subresource back to the page that loaded it.
fn cache_key_document_origin(cache_key: &str) -> Option<String> {
    cache_key
        .split_whitespace()
        .find(|tok| tok.starts_with("http://") || tok.starts_with("https://"))
        .and_then(url_origin)
}

/// 경로 비교용 정규화 — 소문자화 + 구분자 통일.
fn normalize_fs_path(p: &str) -> String {
    p.trim().to_lowercase().replace('\\', "/")
}

/// 캐시 index 수집 경로의 브라우저 프로필 루트 —
/// `.../<프로필>/Cache[/Cache_Data]/index` → `.../<프로필>`.
fn cache_profile_root(index_path: &str) -> Option<String> {
    let norm = normalize_fs_path(index_path);
    let mut parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    parts.pop()?; // index 파일명
    if parts.last().copied() == Some("cache_data") {
        parts.pop();
    }
    if parts.last().copied() == Some("cache") {
        parts.pop();
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// History 결과 DB에 파이프라인이 남긴 수집 원본 경로(_wina_source)의
/// 프로필 루트(부모 폴더). 매핑이 없는 구 파싱본은 None.
fn history_profile_root(db: &Path) -> Option<String> {
    let conn = open_ro(&db.to_string_lossy()).ok()?;
    let source: String = conn
        .query_row("SELECT source_path FROM \"_wina_source\" LIMIT 1", [], |r| {
            r.get(0)
        })
        .ok()?;
    let norm = normalize_fs_path(&source);
    let mut parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    parts.pop()?; // History 파일명
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// 대상 방문에서 양방향(선행·후행)으로 따라가는 최대 홉 수.
const VISIT_GRAPH_DEPTH_CAP: usize = 30;
/// 그래프에 담는 최대 노드 수 — 넘으면 truncated로 표시. BFS라 대상에서
/// 가까운(홉 수가 작은) 연결부터 채워진다.
const VISIT_GRAPH_MAX_NODES: usize = 200;
/// 그래프 출발점으로 삼는 대상 URL 방문(리다이렉트 접기 후) 상한 — 자주
/// 방문한 페이지에서 대상 방문만으로 노드 상한을 다 쓰면 맥락(조상·후행)
/// 노드가 전혀 못 들어가므로 훨씬 작게 잡는다.
const VISIT_GRAPH_MAX_TARGETS: usize = 40;
/// URL 하나에서 검사하는 최근 방문 수의 상한 — 최신 몇 건이 같은 유입의
/// 리다이렉트로 채워져도 그 뒤의 다른 유입 경로가 조사되도록 충분히 넓게
/// 잡는다. 이 상한에 걸리면 결과에 truncated로 표시한다.
const VISIT_FLOW_SCAN_VISITS: usize = 400;

/// Resolve one visit id into its stored fields, or None when absent. The
/// collected browser History copy stores every column as TEXT (ids and the
/// integer-typed `from_visit`/`opener_visit`/`transition`/`visit_time` all come
/// back as strings), so ids are threaded as strings and the numeric fields are
/// parsed explicitly.
struct VisitRow {
    transition: i64,
    external_referrer: String,
    time: String,
    url: String,
    title: String,
}

/// A visit id that references an actual row — a blank or "0" link is a chain
/// terminator, not a real ancestor.
fn nonzero_visit_id(id: &str) -> Option<String> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed == "0" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_visit(conn: &Connection, visit_id: &str) -> Option<VisitRow> {
    let sql = "SELECT COALESCE(v.transition, '0'), \
               COALESCE(v.external_referrer_url, ''), \
               CASE WHEN CAST(v.visit_time AS INTEGER) > 0 THEN datetime(CAST(v.visit_time AS INTEGER)/1000000 - 11644473600, 'unixepoch', 'localtime') ELSE '' END, \
               u.url, COALESCE(u.title, '') \
               FROM visits v JOIN urls u ON u.id = v.url WHERE v.id = ?1";
    conn.query_row(sql, [visit_id], |r| {
        let transition: String = r.get(0).unwrap_or_default();
        Ok(VisitRow {
            transition: transition.trim().parse::<i64>().unwrap_or(0),
            external_referrer: r.get(1).unwrap_or_default(),
            time: r.get(2).unwrap_or_default(),
            url: r.get(3).unwrap_or_default(),
            title: r.get(4).unwrap_or_default(),
        })
    })
    .ok()
}

/// One `visits` row in the in-memory navigation map: its url id and the parent
/// it navigated from — `from_visit` (same tab) taking priority over
/// `opener_visit` (the tab/window that spawned this one), the same rule the
/// old linear chain walked. The whole table is loaded in one scan because the
/// graph also needs the *forward* direction (children), which per-row queries
/// would turn into full-table scans per node.
struct VisitLinkRow {
    url_id: String,
    /// (parent `visits.id`, linking column: "from_visit" | "opener_visit").
    parent: Option<(String, &'static str)>,
}

fn load_visit_links(conn: &Connection) -> std::collections::HashMap<String, VisitLinkRow> {
    let mut links: std::collections::HashMap<String, VisitLinkRow> =
        std::collections::HashMap::new();
    let Ok(mut stmt) = conn.prepare(
        "SELECT id, COALESCE(url, ''), COALESCE(from_visit, ''), COALESCE(opener_visit, '') FROM visits",
    ) else {
        return links;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return links;
    };
    while let Ok(Some(r)) = rows.next() {
        let (Ok(id), Ok(url_id), Ok(from), Ok(opener)) = (
            r.get::<_, String>(0),
            r.get::<_, String>(1),
            r.get::<_, String>(2),
            r.get::<_, String>(3),
        ) else {
            continue;
        };
        let parent = nonzero_visit_id(&from)
            .map(|f| (f, "from_visit"))
            .or_else(|| nonzero_visit_id(&opener).map(|o| (o, "opener_visit")));
        links.insert(id, VisitLinkRow { url_id, parent });
    }
    links
}

/// The representative (entry) visit of a same-URL re-navigation run: walk up
/// the chosen parent link while the parent is a visit of the *same* url id.
/// The page re-navigating to itself (client/server redirect, reload) is one
/// visit story — those runs collapse into their entry node, with the member
/// count surfaced as `reloads`. Memoised; cycle-safe on corrupt data.
fn collapse_rep(
    id: &str,
    links: &std::collections::HashMap<String, VisitLinkRow>,
    memo: &mut std::collections::HashMap<String, String>,
) -> String {
    if let Some(rep) = memo.get(id) {
        return rep.clone();
    }
    let mut path: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cursor = id.to_string();
    let rep = loop {
        if let Some(rep) = memo.get(&cursor) {
            break rep.clone();
        }
        if !seen.insert(cursor.clone()) {
            break cursor;
        }
        let Some(row) = links.get(&cursor) else {
            break cursor;
        };
        match &row.parent {
            Some((p, _)) if links.get(p).is_some_and(|pr| pr.url_id == row.url_id) => {
                path.push(cursor.clone());
                cursor = p.clone();
            }
            _ => break cursor,
        }
    };
    for member in path {
        memo.insert(member, rep.clone());
    }
    memo.insert(id.to_string(), rep.clone());
    rep
}

/// The `_Cache`/`_IE_WebCache` outputs have no `visits` table; every other
/// `*.sqlite` under BROWSER is a candidate History database.
fn browser_history_dbs(host_dir: &str, account: &str) -> Vec<PathBuf> {
    let dir = PathBuf::from(host_dir).join("BROWSER");
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string());
                match name {
                    Some(n) => {
                        n.ends_with(".sqlite")
                            && !n.ends_with("_Cache.sqlite")
                            && !n.ends_with("_IE_WebCache.sqlite")
                    }
                    None => false,
                }
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    let prefix = format!("{account}_");
    files.sort_by(|left, right| {
        let l = left
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with(&prefix));
        let r = right
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with(&prefix));
        r.cmp(&l).then_with(|| left.cmp(right))
    });
    files
}

fn browser_visit_graph_blocking(
    host_dir: String,
    account: String,
    url: String,
    cache_key: Option<String>,
    source_file: Option<String>,
) -> BrowserVisitGraph {
    let is_cache = cache_key.as_deref().is_some_and(|k| !k.trim().is_empty());
    // 행이 가리키는 원본과 같은 브라우저의 History만 조회한다 — 같은 계정에
    // 여러 브라우저 프로필이 있을 때 먼저 일치한 다른 브라우저의 체인을
    // 증거처럼 연결하지 않기 위한 출처 고정이다.
    //  - `BROWSER/<계정_브라우저>.sqlite` (BrowserActivity 방문 행) → 그 DB 하나만.
    //  - 수집 원본 경로(캐시 index 등) → 경로에서 브라우저를 판별해 같은
    //    계정·같은 브라우저의 History만 후보.
    //  - 출처가 없으면(구 파싱본, `_source_file` 컬럼 도입 전) 고정을 포기하고
    //    이전 동작대로 계정의 History 후보 전체를 조회한다 — 재파싱 전
    //    케이스에서 기능을 끄지 않기 위한 완화이며, 체인을 낸 DB 파일명이
    //    결과(source_file)에 남아 어느 원본인지는 확인 가능하다.
    let source = source_file
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let candidates: Vec<PathBuf> = match source {
        None => browser_history_dbs(&host_dir, &account),
        Some(value) => {
            let name = Path::new(value)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.ends_with(".sqlite") {
                vec![PathBuf::from(&host_dir).join("BROWSER").join(name)]
            } else {
                match wina_core::parsers::browser_cache::browser_of(Path::new(value)) {
                    Some(browser) => {
                        let account_prefix = format!("{account}_");
                        let browser_token = format!("_{browser}");
                        let filtered: Vec<PathBuf> = browser_history_dbs(&host_dir, &account)
                            .into_iter()
                            .filter(|path| {
                                path.file_name().is_some_and(|n| {
                                    let n = n.to_string_lossy();
                                    n.starts_with(&account_prefix) && n.contains(&browser_token)
                                })
                            })
                            .collect();
                        // 같은 브라우저 다중 프로필 구분: History 산출물의 수집
                        // 원본(_wina_source) 프로필 루트와 캐시 index의 프로필
                        // 루트가 일치하는 DB만 채택한다. 매핑이 없고(구 파싱본)
                        // 후보가 여럿이면 임의 선택 대신 비활성 — Default 캐시에
                        // Profile 1 체인이 붙는 오귀속을 차단한다.
                        let cache_root = cache_profile_root(value);
                        let matched: Vec<PathBuf> = match cache_root.as_deref() {
                            Some(root) => filtered
                                .iter()
                                .filter(|db| history_profile_root(db).as_deref() == Some(root))
                                .cloned()
                                .collect(),
                            None => Vec::new(),
                        };
                        if matched.len() == 1 {
                            matched
                        } else if filtered.len() <= 1 {
                            // 후보가 하나뿐이면 프로필 모호성이 없고, 0개면
                            // 아래 공통 빈 후보 안내로 떨어진다.
                            filtered
                        } else {
                            return BrowserVisitGraph {
                                note: "같은 브라우저 프로필이 여러 개라 이 캐시의 원본 프로필을 특정할 수 없습니다 — 재파싱하면 사용할 수 있습니다.".to_string(),
                                ..Default::default()
                            };
                        }
                    }
                    None => {
                        return BrowserVisitGraph {
                            note: "크로미움 계열(Chrome·Edge·Whale) 방문 기록이 아닌 원본이라 유입 흐름을 복원할 수 없습니다.".to_string(),
                            ..Default::default()
                        };
                    }
                }
            }
        }
    };
    if candidates.is_empty() {
        return BrowserVisitGraph {
            note: "같은 브라우저의 방문 기록 결과가 없어 유입 흐름을 연결하지 않습니다.".to_string(),
            ..Default::default()
        };
    }
    // 원본 접근·스키마 실패는 "직접 확인 결과 유입 없음"과 구분해 남긴다 —
    // 손상·잠금이 빈 흐름으로 위장하면 분석가가 증거 부재로 오판한다.
    let mut source_failures: Vec<String> = Vec::new();
    let mut truncated = false;
    for db in candidates {
        let db_name = db
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let conn = match open_ro(&db.to_string_lossy()) {
            Ok(c) => c,
            Err(error) => {
                source_failures.push(format!("{db_name}: 열기 실패 ({error})"));
                continue;
            }
        };
        // Require both tables — a truncated copy is skipped, not reported empty.
        let has_tables = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('urls','visits')",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            == 2;
        if !has_tables {
            source_failures.push(format!("{db_name}: urls/visits 테이블 없음"));
            continue;
        }
        let source_file = db
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Resolve the navigated page URL id(s) whose chain we reconstruct.
        // ids are TEXT in the collected copy, so they are kept as strings.
        let mut matched_page = String::new();
        let mut url_ids: Vec<String> = Vec::new();
        if is_cache {
            // A cached subresource is not itself a navigated page; attribute it
            // to pages under the cache key's top-frame document origin.
            let origin = cache_key
                .as_deref()
                .and_then(cache_key_document_origin)
                .or_else(|| url_origin(&url));
            if let Some(origin) = origin {
                matched_page = origin.clone();
                // 접두어 LIKE만으로는 `https://example.com.evil/…`·다른 포트가
                // 후보 상한(60)을 점유해 실제 origin 페이지가 밀릴 수 있다 —
                // SQL 단계에서 origin 경계(정확 일치 / '/', '?', '#' 뒤따름)로
                // 후보를 제한하고, Rust에서 origin 완전 일치를 재검증한다.
                let escaped = origin
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT id, url FROM urls WHERE (url = ?1 OR url LIKE ?2 ESCAPE '\\' OR url LIKE ?3 ESCAPE '\\' OR url LIKE ?4 ESCAPE '\\') ORDER BY CAST(visit_count AS INTEGER) DESC LIMIT 60",
                ) {
                    if let Ok(mut rows) = stmt.query(rusqlite::params![
                        origin,
                        format!("{escaped}/%"),
                        format!("{escaped}?%"),
                        format!("{escaped}#%"),
                    ]) {
                        while let Ok(Some(r)) = rows.next() {
                            if url_ids.len() >= 6 {
                                break;
                            }
                            let (Ok(id), Ok(candidate)) =
                                (r.get::<_, String>(0), r.get::<_, String>(1))
                            else {
                                continue;
                            };
                            if url_origin(&candidate).as_deref() == Some(origin.as_str()) {
                                url_ids.push(id);
                            }
                        }
                    }
                }
            }
        } else if let Ok(mut stmt) = conn.prepare("SELECT id FROM urls WHERE url = ?1 LIMIT 4") {
            if let Ok(mut rows) = stmt.query([&url]) {
                while let Ok(Some(r)) = rows.next() {
                    if let Ok(id) = r.get::<_, String>(0) {
                        url_ids.push(id);
                    }
                }
            }
        }
        if url_ids.is_empty() {
            continue;
        }

        // ---- 전체 방문 연결 지도(한 번의 스캔) + 재이동 접기 ----------------
        let links = load_visit_links(&conn);
        let mut rep_memo: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        // 접힌 그래프의 인접 관계. 노드는 각 같은-URL 재이동 사슬의 entry 방문
        // (rep)이고, 간선은 서로 다른 URL 사이의 이동만 남는다. reload 수는
        // 사슬을 따라 접힌 구성원 수 — 기존 체인 뷰의 entry별 귀속과 같다.
        let mut reloads_of: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut parent_edge: std::collections::HashMap<String, (String, &'static str)> =
            std::collections::HashMap::new();
        let mut children_of: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let all_ids: Vec<String> = links.keys().cloned().collect();
        for id in &all_ids {
            let rep = collapse_rep(id, &links, &mut rep_memo);
            if rep != *id {
                *reloads_of.entry(rep).or_default() += 1;
                continue;
            }
            // rep(entry) 방문의 교차-URL 부모만 간선이 된다. 부모가 재이동
            // 사슬의 중간이면 그 사슬의 entry로 다시 접는다.
            let row = &links[id];
            if let Some((p, kind)) = &row.parent {
                if links.get(p).is_some_and(|pr| pr.url_id != row.url_id) {
                    let prep = collapse_rep(p, &links, &mut rep_memo);
                    parent_edge.insert(rep.clone(), (prep.clone(), kind));
                    children_of.entry(prep).or_default().push(rep.clone());
                }
            }
        }

        // ---- 대상 방문(시드) 수집 ------------------------------------------
        let target_url_ids: std::collections::HashSet<&str> =
            url_ids.iter().map(String::as_str).collect();
        let mut seeds: Vec<String> = Vec::new();
        let mut seed_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        'urls: for url_id in &url_ids {
            let mut visit_ids: Vec<String> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT id FROM visits WHERE url = ?1 ORDER BY CAST(visit_time AS INTEGER) DESC LIMIT ?2",
            ) {
                if let Ok(mut rows) =
                    stmt.query(rusqlite::params![url_id, VISIT_FLOW_SCAN_VISITS as i64])
                {
                    while let Ok(Some(r)) = rows.next() {
                        if let Ok(id) = r.get::<_, String>(0) {
                            visit_ids.push(id);
                        }
                    }
                }
            }
            if visit_ids.len() >= VISIT_FLOW_SCAN_VISITS {
                truncated = true;
            }
            for vid in visit_ids {
                let rep = collapse_rep(&vid, &links, &mut rep_memo);
                if !seed_seen.insert(rep.clone()) {
                    continue;
                }
                if seeds.len() >= VISIT_GRAPH_MAX_TARGETS {
                    truncated = true;
                    break 'urls;
                }
                seeds.push(rep);
            }
        }
        if seeds.is_empty() {
            continue;
        }

        // ---- 시드에서 양방향 BFS — 조상(유입)·후행 이동·형제 분기까지 ------
        let mut in_graph: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut order: Vec<String> = Vec::new();
        let mut queue: std::collections::VecDeque<(String, usize)> =
            std::collections::VecDeque::new();
        for seed in &seeds {
            if in_graph.insert(seed.clone()) {
                order.push(seed.clone());
                queue.push_back((seed.clone(), 0));
            }
        }
        while let Some((id, hop)) = queue.pop_front() {
            let mut neighbors: Vec<String> = Vec::new();
            if let Some((p, _)) = parent_edge.get(&id) {
                neighbors.push(p.clone());
            }
            if let Some(kids) = children_of.get(&id) {
                neighbors.extend(kids.iter().cloned());
            }
            for n in neighbors {
                if in_graph.contains(&n) {
                    continue;
                }
                if hop >= VISIT_GRAPH_DEPTH_CAP || in_graph.len() >= VISIT_GRAPH_MAX_NODES {
                    truncated = true;
                    continue;
                }
                in_graph.insert(n.clone());
                order.push(n.clone());
                queue.push_back((n, hop + 1));
            }
        }

        // ---- 노드·간선 구체화 ----------------------------------------------
        let visit_id_num = |s: &str| s.trim().parse::<i64>().unwrap_or(i64::MAX);
        let mut nodes: Vec<VisitGraphNode> = Vec::new();
        for id in &order {
            let Some(v) = read_visit(&conn, id) else {
                continue;
            };
            nodes.push(VisitGraphNode {
                visit_id: id.clone(),
                url: v.url,
                title: v.title,
                time: v.time,
                transition: decode_transition(v.transition),
                transition_raw: v.transition.to_string(),
                is_target: links
                    .get(id)
                    .is_some_and(|r| target_url_ids.contains(r.url_id.as_str())),
                reloads: reloads_of.get(id).copied().unwrap_or(0),
                external_referrer: v.external_referrer,
            });
        }
        nodes.sort_by(|a, b| {
            a.time
                .cmp(&b.time)
                .then_with(|| visit_id_num(&a.visit_id).cmp(&visit_id_num(&b.visit_id)))
        });
        let mut edges: Vec<VisitGraphEdge> = Vec::new();
        for id in &order {
            if let Some((p, kind)) = parent_edge.get(id) {
                if in_graph.contains(p) {
                    edges.push(VisitGraphEdge {
                        from: p.clone(),
                        to: id.clone(),
                        kind: (*kind).to_string(),
                    });
                }
            }
        }
        edges.sort_by_key(|e| visit_id_num(&e.to));
        // 연결도 재이동도 외부 referrer도 없는 외톨이 대상뿐이면 이 DB에는
        // 이동 이야기가 없다 — 기존 체인 뷰의 "유입 없음" 판정과 동일.
        let has_story = !edges.is_empty()
            || nodes
                .iter()
                .any(|n| !n.external_referrer.is_empty() || n.reloads > 0);
        if !has_story {
            continue;
        }
        let note = if is_cache {
            "이 캐시 리소스를 로드한 것으로 추정되는 페이지(캐시 키의 최상위 문서 출처)를 기준으로 한 방문 이동 그래프입니다.".to_string()
        } else {
            String::new()
        };
        return BrowserVisitGraph {
            nodes,
            edges,
            source_file,
            matched_page,
            note,
            truncated,
        };
    }
    // 모든 후보에서 체인을 만들지 못함 — 실패가 있으면 오류로 구분해 안내.
    if !source_failures.is_empty() {
        return BrowserVisitGraph {
            note: format!(
                "원본 방문 기록을 읽지 못해 유입 흐름을 확인할 수 없습니다 — {}",
                source_failures.join("; ")
            ),
            ..Default::default()
        };
    }
    BrowserVisitGraph {
        note: "이 항목에 대한 방문 유입 흐름을 원본 History에서 찾지 못했습니다 (새 탭·리다이렉트 없이 직접 접근했거나, 원본 방문 기록이 남아있지 않을 수 있습니다).".to_string(),
        ..Default::default()
    }
}

#[tauri::command]
async fn browser_visit_graph(
    host_dir: String,
    account: String,
    url: String,
    cache_key: Option<String>,
    source_file: Option<String>,
) -> BrowserVisitGraph {
    tauri::async_runtime::spawn_blocking(move || {
        browser_visit_graph_blocking(host_dir, account, url, cache_key, source_file)
    })
    .await
    .unwrap_or_else(|error| BrowserVisitGraph {
        note: format!("유입 흐름 작업이 중단되었습니다: {error}"),
        ..Default::default()
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiConversation {
    provider: String,
    account: String,
    title: String,
    /// Cache observation time. This is the evidence timestamp used by range filters.
    date: String,
    /// Conversation-authored timestamps are preserved separately from the cache time.
    created_at: String,
    updated_at: String,
    url: String,
    /// Raw JSON text of the conversation (pretty-printed). Frontend parses messages from this.
    raw_json: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AiConversationQuery {
    start: Option<String>,
    end: Option<String>,
    offset: usize,
    limit: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiConversationPage {
    conversations: Vec<AiConversation>,
    total: usize,
    source_count: usize,
    sources_read: usize,
    /// One source failure must not hide conversations recovered from other
    /// browser profiles. The UI presents this as a degraded-data warning,
    /// never as an empty result set.
    source_failures: Vec<String>,
}


/// 파싱 단계 파생(_OVERVIEW/AiConversations)을 기간·페이지 조건으로
/// 조회한다. 원본 캐시 재해석·행 상한(500/2,000)은 파생 이전으로 제거됐다 —
/// total은 기간 내 전체 건수이고 정렬(관찰 시각 내림차순 + URL)은 파생
/// 테이블 순서와 동일해 페이지가 재현된다. 파생 테이블이 없는 이전 파싱본은
/// 빈 결과를 돌려준다(재파싱하면 생성 — PathReferences와 같은 계약).
fn ai_conversations_blocking(
    host_dir: String,
    query: AiConversationQuery,
) -> Result<AiConversationPage, String> {
    let db = PathBuf::from(&host_dir)
        .join("_OVERVIEW")
        .join("AiConversations.sqlite");
    if !db.is_file() {
        return Ok(AiConversationPage {
            conversations: Vec::new(),
            total: 0,
            source_count: 0,
            sources_read: 0,
            source_failures: Vec::new(),
        });
    }
    let conn = open_ro(&db.to_string_lossy())
        .map_err(|error| format!("AI 대화 파생 테이블을 열 수 없습니다: {error}"))?;
    let mut clauses: Vec<&str> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if let Some(start) = query.start.as_ref().filter(|s| !s.is_empty()) {
        clauses.push("date >= ?");
        params.push(start.clone());
    }
    if let Some(end) = query.end.as_ref().filter(|s| !s.is_empty()) {
        clauses.push("date <= ?");
        params.push(end.clone());
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let bind: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
    let total: usize = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM \"AiConversations\"{where_sql}"),
            bind.as_slice(),
            |r| r.get::<_, i64>(0),
        )
        .map_err(|error| format!("AI 대화 건수를 읽을 수 없습니다: {error}"))? as usize;
    let limit = query.limit.clamp(1, 100);
    let sql = format!(
        "SELECT date, provider, account, title, created_at, updated_at, url, raw_json FROM \"AiConversations\"{where_sql} ORDER BY date DESC, url ASC LIMIT ? OFFSET ?"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|error| format!("AI 대화 조회를 준비할 수 없습니다: {error}"))?;
    let mut bind_page = bind;
    let limit_v = limit as i64;
    let offset_v = query.offset as i64;
    bind_page.push(&limit_v);
    bind_page.push(&offset_v);
    let conversations = stmt
        .query_map(bind_page.as_slice(), |r| {
            Ok(AiConversation {
                date: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                provider: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                account: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                title: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                created_at: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                updated_at: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                url: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                raw_json: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            })
        })
        .map_err(|error| format!("AI 대화를 읽을 수 없습니다: {error}"))?
        .filter_map(|row| row.ok())
        .collect();
    Ok(AiConversationPage {
        conversations,
        total,
        source_count: 1,
        sources_read: 1,
        source_failures: Vec::new(),
    })
}

/// Conversation discovery decodes and validates cached JSON. It is bounded,
/// but can still be CPU and disk intensive across several browser profiles,
/// so it must never run on the command path that serves the interactive view.
#[tauri::command]
async fn ai_conversations(
    host_dir: String,
    query: AiConversationQuery,
) -> Result<AiConversationPage, String> {
    tauri::async_runtime::spawn_blocking(move || ai_conversations_blocking(host_dir, query))
        .await
        .map_err(|error| format!("AI 대화 작업이 중단되었습니다: {error}"))?
}

// --- commands: cross-artifact path references ------------------------------

/// One other-artifact sighting of a filesystem path — currently JumpList
/// entries; `kind` is open so Shellbag/LNK/Prefetch can be added without a
/// frontend change. `path` is lowercased for matching against $MFT paths.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PathReference {
    path: String,
    kind: String,
    account: String,
    label: String,
    fields: Map<String, Value>,
    /// Source sqlite + row so the viewer can bookmark this reference's
    /// timestamps. Empty full_path / rowid < 0 means "not bookmarkable"
    /// (e.g. a Shellbag reconstructed from the registry, which has no row).
    full_path: String,
    table_name: String,
    rowid: i64,
}

/// Normalize a path to the volume-relative, lowercased form $MFT uses:
/// drop a leading drive letter (`C:\Windows` -> `\windows`) and lowercase.
/// UNC paths (`\\host\share`) and already-relative paths pass through lowered.
fn to_volume_relative(p: &str) -> String {
    let low = p.to_lowercase().replace('/', "\\");
    let b = low.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        let rest = &low[2..];
        if rest.is_empty() {
            "\\".to_string()
        } else if rest.starts_with('\\') {
            rest.to_string()
        } else {
            format!("\\{}", rest)
        }
    } else {
        low
    }
}


/// MFT 탐색기 교차 참조 — 파싱 단계에서 만들어 둔 `_OVERVIEW/PathReferences`
/// 파생 테이블을 **표시 중인 경로 배치**로만 조회한다. 화면 진입마다 JumpList
/// 전수 스캔·Shellbag 재구성을 하던 즉석 가공은 파서로 이전됐다(협약).
/// 파생 테이블이 없는 이전 파싱 호스트는 빈 결과를 돌려준다(재파싱 필요).
#[tauri::command]
async fn path_references(
    host_dir: String,
    paths: Vec<String>,
) -> Result<Vec<PathReference>, String> {
    tauri::async_runtime::spawn_blocking(move || path_references_blocking(host_dir, paths))
        .await
        .map_err(|error| format!("교차 참조 조회 작업이 중단되었습니다: {error}"))?
}

fn path_references_blocking(
    host_dir: String,
    paths: Vec<String>,
) -> Result<Vec<PathReference>, String> {
    let db = PathBuf::from(&host_dir)
        .join("_OVERVIEW")
        .join("PathReferences.sqlite");
    if !db.exists() {
        return Ok(vec![]);
    }
    let conn = open_ro(&db.to_string_lossy())?;
    // 요청 경로를 파생 테이블의 키와 같은 형식(볼륨 상대·소문자)으로 정규화.
    let mut keys: Vec<String> = paths.iter().map(|p| to_volume_relative(p)).collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    // SQLite 바인딩 수 제한을 고려해 청크로 조회한다.
    for chunk in keys.chunks(400) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT rowid AS __rowid, * FROM PathReferences WHERE path IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::ToSql> =
            chunk.iter().map(|k| k as &dyn rusqlite::ToSql).collect();
        for r in query_rows(&conn, &sql, &params)? {
            let get = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut fields = Map::new();
            for k in [
                "target_path",
                "app_id",
                "jumplist_type",
                "arguments",
                "working_directory",
                "machine_id",
                "timestamp",
                "created_time",
                "modified_time",
                "_source_file",
                "path",
                "account",
            ] {
                let v = get(k);
                if !v.is_empty() {
                    fields.insert(k.to_string(), Value::from(v));
                }
            }
            let source_relative = get("source_relative");
            let full_path = if source_relative.is_empty() {
                String::new()
            } else {
                PathBuf::from(&host_dir)
                    .join(&source_relative)
                    .to_string_lossy()
                    .to_string()
            };
            out.push(PathReference {
                path: get("path"),
                kind: get("kind"),
                account: get("account"),
                label: get("label"),
                fields,
                full_path,
                table_name: get("source_table"),
                rowid: get("source_rowid").parse().unwrap_or(-1),
            });
        }
    }
    Ok(out)
}

/// 교차 참조에 등장하는 계정 목록(필터 칩용) — 파생 테이블에서 바로 집계.
#[tauri::command]
async fn path_reference_accounts(host_dir: String) -> Result<Vec<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let db = PathBuf::from(&host_dir)
            .join("_OVERVIEW")
            .join("PathReferences.sqlite");
        if !db.exists() {
            return Ok(vec![]);
        }
        let conn = open_ro(&db.to_string_lossy())?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT account FROM PathReferences WHERE account != '' ORDER BY account LIMIT 500",
            )
            .map_err(|error| format!("교차 참조 계정 조회 실패: {error}"))?;
        let accounts = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|error| format!("교차 참조 계정 조회 실패: {error}"))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(accounts)
    })
    .await
    .map_err(|error| format!("교차 참조 계정 작업이 중단되었습니다: {error}"))?
}


// --- commands: bookmarks (JSON file) ---------------------------------------

fn normalize_bookmark_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn bookmark_path_is_within(full_path: &str, directory: &Path) -> bool {
    normalize_bookmark_path(Path::new(full_path)).starts_with(normalize_bookmark_path(directory))
}

fn bookmark_belongs_to_host(bookmark: &Value, host_id: &str, host_dir: &Path) -> bool {
    if let Some(stored_host_id) = bookmark
        .get("hostId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        // A modern host identity is authoritative. Do not discard an
        // annotation for another retained host merely because an older or
        // manually repaired source path happens to point into this directory.
        return stored_host_id == host_id;
    }
    bookmark
        .get("fullPath")
        .and_then(Value::as_str)
        .is_some_and(|full_path| bookmark_path_is_within(full_path, host_dir))
}

fn bookmark_targets_missing_host(bookmark: &Value, case_dir: &Path) -> bool {
    if let Some(host_id) = bookmark
        .get("hostId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        return !case_dir.join(host_id).join("host.json").is_file();
    }

    let Some(full_path) = bookmark.get("fullPath").and_then(Value::as_str) else {
        return false;
    };
    let full_path = normalize_bookmark_path(Path::new(full_path));
    let case_dir = normalize_bookmark_path(case_dir);
    let Ok(relative) = full_path.strip_prefix(&case_dir) else {
        // Do not discard older annotations if their source path cannot be
        // attributed safely to this case.
        return false;
    };
    let Some(std::path::Component::Normal(host_id)) = relative.components().next() else {
        return false;
    };
    !case_dir.join(host_id).join("host.json").is_file()
}

/// New bookmark IDs include the exact source table as well as the SQLite path
/// and row. Each variable-length component is URL-safe base64, so the `:`
/// separators cannot occur inside a component. Existing IDs are intentionally
/// left untouched: they remain readable/removable/editable through their
/// stored ID, while every newly created bookmark has collision-free identity.
fn bookmark_id_v2(full_path: &str, table_name: &str, rowid: i64, field: &str) -> String {
    use base64::Engine as _;
    let encode = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    format!(
        "v2:{}:{}:{}:{}",
        encode(full_path),
        encode(table_name),
        rowid,
        encode(field)
    )
}

// bookmarks.json은 read-modify-write라 임계 구역 보호가 없으면 겹치는 토글이
// 서로의 저장을 덮어쓴다 (마지막 rename만 남음). 케이스 파일 단위 잠금 대신
// 프로세스 전역 잠금 하나로 충분하다 — 북마크 쓰기는 드물고 짧다.
static BOOKMARK_FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_bookmarks() -> std::sync::MutexGuard<'static, ()> {
    BOOKMARK_FILE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_bookmarks_path(case_dir: &Path) -> Result<Vec<Value>, String> {
    match std::fs::read_to_string(case_dir.join("bookmarks.json")) {
        Ok(serialized) => serde_json::from_str::<Value>(&serialized)
            .map_err(|error| format!("북마크 파일을 읽을 수 없습니다: {error}"))?
            .as_array()
            .cloned()
            .ok_or_else(|| "북마크 파일 형식이 올바르지 않습니다".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("북마크 파일을 읽을 수 없습니다: {error}")),
    }
}

fn write_bookmarks_path(case_dir: &Path, bookmarks: &[Value]) -> Result<(), String> {
    let serialized = serde_json::to_string_pretty(bookmarks)
        .map_err(|error| format!("북마크 데이터를 저장할 수 없습니다: {error}"))?;
    if !case_dir.is_dir() {
        return Err("북마크 저장 위치를 찾을 수 없습니다".to_string());
    }
    let target = case_dir.join("bookmarks.json");
    let temporary = case_dir.join(format!(
        ".bookmarks-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    if let Err(error) =
        std::fs::write(&temporary, serialized).and_then(|()| std::fs::rename(&temporary, &target))
    {
        let _ = std::fs::remove_file(temporary);
        return Err(format!("북마크 저장에 실패했습니다: {error}"));
    }
    Ok(())
}

/// 재파싱이 발행되면 그 호스트를 가리키는 북마크는 rowid가 더 이상 같은
/// 레코드를 보장하지 않는다 — 잘못된 행으로 연결되는 것을 막기 위해 해당
/// 호스트의 북마크만 삭제한다 (2026-08-31 사용자 확정). 다른 호스트 북마크는
/// 유지된다.
fn remove_host_bookmarks(cases_dir: &Path, host_id: &str) -> usize {
    let _guard = lock_bookmarks();
    let Ok(bookmarks) = read_bookmarks_path(cases_dir) else {
        return 0;
    };
    let needle = format!("/{host_id}/");
    let kept: Vec<Value> = bookmarks
        .iter()
        .filter(|bookmark| {
            !bookmark
                .get("fullPath")
                .and_then(Value::as_str)
                .map(|path| path.contains(&needle))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let removed = bookmarks.len() - kept.len();
    if removed > 0 && write_bookmarks_path(cases_dir, &kept).is_err() {
        return 0;
    }
    removed
}

fn read_bookmarks(case_dir: &str) -> Result<Vec<Value>, String> {
    read_bookmarks_path(Path::new(case_dir))
}

fn write_bookmarks(case_dir: &str, bookmarks: &[Value]) -> Result<(), String> {
    write_bookmarks_path(Path::new(case_dir), bookmarks)
}

#[tauri::command]
fn list_bookmarks(case_dir: String) -> Result<Vec<Value>, String> {
    let _guard = lock_bookmarks();
    let case_path = Path::new(&case_dir);
    if !case_path.is_dir() {
        return Err("북마크 저장 위치를 찾을 수 없습니다".to_string());
    }
    let bookmarks = read_bookmarks_path(case_path)?;
    let retained: Vec<Value> = bookmarks
        .iter()
        .filter(|bookmark| !bookmark_targets_missing_host(bookmark, case_path))
        .cloned()
        .collect();
    if retained.len() != bookmarks.len() {
        write_bookmarks_path(case_path, &retained)?;
    }
    Ok(retained)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BookmarkInput {
    full_path: String,
    table_name: String,
    rowid: i64,
    #[serde(default)]
    field: Option<String>,
    /// 개요 행에서 승격된 북마크의 사건 시각. 원시 레코드(Registry 등)에는
    /// 실행 시각이 없어 last_write 같은 엉뚱한 시각으로 배치되는 것을 막는다.
    #[serde(default)]
    event_time: Option<String>,
    #[serde(default)]
    host_id: Option<String>,
    #[serde(default)]
    host_name: Option<String>,
}

#[tauri::command]
fn toggle_bookmark(case_dir: String, entry: BookmarkInput) -> Result<Vec<Value>, String> {
    let _guard = lock_bookmarks();
    let mut bookmarks = read_bookmarks(&case_dir)?;
    let field = entry.field.clone().unwrap_or_default();
    let idx = bookmarks.iter().position(|b| {
        b.get("fullPath").and_then(|v| v.as_str()) == Some(entry.full_path.as_str())
            && b.get("tableName").and_then(|v| v.as_str()) == Some(entry.table_name.as_str())
            && b.get("rowid").and_then(|v| v.as_i64()) == Some(entry.rowid)
            && b.get("field").and_then(|v| v.as_str()).unwrap_or("") == field
    });
    if let Some(i) = idx {
        bookmarks.remove(i);
    } else {
        let id = bookmark_id_v2(&entry.full_path, &entry.table_name, entry.rowid, &field);
        let mut b = Map::new();
        b.insert("id".into(), Value::from(id));
        b.insert("fullPath".into(), Value::from(entry.full_path));
        b.insert("tableName".into(), Value::from(entry.table_name));
        b.insert("rowid".into(), Value::from(entry.rowid));
        if !field.is_empty() {
            b.insert("field".into(), Value::from(field));
        }
        if let Some(event_time) = entry.event_time.filter(|t| !t.is_empty()) {
            b.insert("eventTime".into(), Value::from(event_time));
        }
        b.insert("note".into(), Value::from(""));
        b.insert("taggedAt".into(), Value::from(now_iso()));
        b.insert(
            "hostId".into(),
            Value::from(entry.host_id.unwrap_or_default()),
        );
        b.insert(
            "hostName".into(),
            Value::from(entry.host_name.unwrap_or_default()),
        );
        bookmarks.push(Value::Object(b));
    }
    write_bookmarks(&case_dir, &bookmarks)?;
    Ok(bookmarks)
}

#[tauri::command]
fn update_bookmark_note(case_dir: String, id: String, note: String) -> Result<Vec<Value>, String> {
    let _guard = lock_bookmarks();
    let mut bookmarks = read_bookmarks(&case_dir)?;
    for b in bookmarks.iter_mut() {
        if b.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
            if let Some(obj) = b.as_object_mut() {
                obj.insert("note".into(), Value::from(note.clone()));
            }
        }
    }
    write_bookmarks(&case_dir, &bookmarks)?;
    Ok(bookmarks)
}

// ISO-8601 UTC timestamp without pulling in chrono (matches JS toISOString shape closely enough).
fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let millis = d.subsec_millis();
    // days->y/m/d via civil calendar algorithm (Howard Hinnant)
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, h, mi, s, millis
    )
}

// --- commands: dialog ------------------------------------------------------

#[tauri::command]
async fn pick_folder(app: AppHandle) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_folder(move |p| {
        let _ = tx.send(p);
    });
    rx.recv().ok().flatten().map(|p| p.to_string())
}

/// Hidden flag that turns this executable into the parse worker:
///   <exe> --__parse <caseId> <hostId> <casesDir> [only,comma,separated]
/// Progress goes to stdout; the parent streams it as `pipeline-log` events and
/// kills this process on cancel.
const PARSE_FLAG: &str = "--__parse";

/// Runs the pipeline and exits — never opens a window. Returns None when the
/// args aren't the parse-worker form (i.e. normal GUI launch).
fn run_as_parse_worker() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 || args[1] != PARSE_FLAG {
        return None;
    }
    let (case_id, host_id, cases_dir) = (&args[2], &args[3], std::path::PathBuf::from(&args[4]));
    let (only, run_log_id) = parse_worker_options(&args[5..]);
    // Sink stays unset, so pipeline prints progress to stdout for the parent.
    match pipeline::run_host_with_log_id(case_id, host_id, &cases_dir, only, run_log_id.as_deref())
    {
        Ok(()) => Some(0),
        Err(e) => {
            if let Some(run_id) = run_log_id.as_deref() {
                let host_dir = case_store::host_dir(&cases_dir, case_id, host_id);
                pipeline::append_parse_log_event(
                    &pipeline::parse_run_log_path(&host_dir, run_id),
                    &format!("[WORKER] run_finished status=failed error={e}"),
                );
            }
            eprintln!("[!] {}", e);
            Some(1)
        }
    }
}

fn parse_worker_options(
    arguments: &[String],
) -> (Option<std::collections::HashSet<String>>, Option<String>) {
    let mut only = None;
    let mut run_log_id = None;
    for argument in arguments {
        if let Some(value) = argument.strip_prefix("--run-log-id=") {
            if !value.is_empty() {
                run_log_id = Some(value.to_string());
            }
        } else if !argument.is_empty() && only.is_none() {
            only = Some(
                argument
                    .split(',')
                    .map(|value| value.to_string())
                    .collect::<std::collections::HashSet<String>>(),
            );
        }
    }
    (only, run_log_id)
}

#[cfg(test)]
mod bookmark_tests {
    use super::*;

    fn temporary_case_dir(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "windows-analysis-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn create_host_directory(case_dir: &Path, host_id: &str) {
        let host_dir = case_dir.join(host_id);
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::write(host_dir.join("host.json"), "{}").unwrap();
    }

    fn bookmark(id: &str, full_path: impl Into<String>, host_id: Option<&str>) -> Value {
        let mut value = serde_json::json!({
            "id": id,
            "fullPath": full_path.into(),
            "tableName": "Evidence",
            "rowid": 1,
            "note": "",
            "taggedAt": "2026-01-01T00:00:00.000Z",
        });
        if let Some(host_id) = host_id {
            value
                .as_object_mut()
                .unwrap()
                .insert("hostId".into(), Value::from(host_id));
        }
        value
    }

    fn entry(table_name: &str) -> BookmarkInput {
        BookmarkInput {
            full_path: "/evidence/combined.sqlite".to_string(),
            table_name: table_name.to_string(),
            rowid: 42,
            field: None,
            event_time: None,
            host_id: Some("host-a".to_string()),
            host_name: Some("HOST-A".to_string()),
        }
    }

    #[test]
    fn concurrent_bookmark_toggles_preserve_every_record() {
        let case_dir = std::env::temp_dir().join(format!(
            "wina-bookmark-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&case_dir).unwrap();
        let dir = case_dir.to_string_lossy().to_string();
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for step in 0..5 {
                        let mut item = entry("Registry");
                        item.rowid = (worker * 100 + step) as i64;
                        toggle_bookmark(dir.clone(), item).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let stored = read_bookmarks(&dir).unwrap();
        assert_eq!(stored.len(), 40, "겹친 토글이 서로의 저장을 덮어쓰면 안 된다");
        std::fs::remove_dir_all(case_dir).unwrap();
    }

    #[test]
    fn bookmark_identity_keeps_same_rowid_in_different_tables_independent() {
        let case_dir = std::env::temp_dir().join(format!(
            "windows-analysis-bookmark-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&case_dir).unwrap();
        create_host_directory(&case_dir, "host-a");
        let case_dir = case_dir.to_string_lossy().to_string();

        // Pre-v2 bookmarks did not include a table in their ID. Preserve them
        // as-is so existing annotations remain available and editable.
        let legacy_id = "/evidence/combined.sqlite#21";
        write_bookmarks(
            &case_dir,
            &[serde_json::json!({
                "id": legacy_id,
                "fullPath": "/evidence/combined.sqlite",
                "tableName": "LegacyEvidence",
                "rowid": 21,
                "note": "legacy note",
                "taggedAt": "2026-01-01T00:00:00.000Z",
            })],
        )
        .unwrap();

        let first = toggle_bookmark(case_dir.clone(), entry("BrowserActivity")).unwrap();
        assert_eq!(first.len(), 2);

        // A source SQLite can contain multiple tables, each with rowid 42.
        // Toggling one table must not remove a bookmark for the other table.
        let second = toggle_bookmark(case_dir.clone(), entry("OtherEvidence")).unwrap();
        assert_eq!(second.len(), 3);
        let bookmark_id_for = |table_name: &str| {
            second
                .iter()
                .find(|bookmark| {
                    bookmark.get("tableName").and_then(Value::as_str) == Some(table_name)
                })
                .and_then(|bookmark| bookmark.get("id").and_then(Value::as_str))
                .expect("bookmark should exist")
                .to_string()
        };
        let browser_id = bookmark_id_for("BrowserActivity");
        let other_id = bookmark_id_for("OtherEvidence");
        assert_ne!(browser_id, other_id);
        assert!(browser_id.starts_with("v2:"));

        // Updating a note addresses one full bookmark identity, not every
        // same-rowid record in the source SQLite.
        let updated =
            update_bookmark_note(case_dir.clone(), browser_id, "browser note".to_string()).unwrap();
        assert_eq!(
            updated
                .iter()
                .find(|bookmark| bookmark.get("tableName").and_then(Value::as_str)
                    == Some("BrowserActivity"))
                .and_then(|bookmark| bookmark.get("note"))
                .and_then(Value::as_str),
            Some("browser note"),
        );
        assert_eq!(
            updated
                .iter()
                .find(|bookmark| bookmark.get("tableName").and_then(Value::as_str)
                    == Some("OtherEvidence"))
                .and_then(|bookmark| bookmark.get("note"))
                .and_then(Value::as_str),
            Some(""),
        );

        let after_browser_toggle =
            toggle_bookmark(case_dir.clone(), entry("BrowserActivity")).unwrap();
        assert_eq!(after_browser_toggle.len(), 2);
        assert_eq!(
            after_browser_toggle
                .iter()
                .find(|bookmark| bookmark.get("tableName").and_then(Value::as_str)
                    == Some("OtherEvidence"))
                .and_then(|bookmark| bookmark.get("id"))
                .and_then(Value::as_str),
            Some(other_id.as_str()),
        );
        assert!(after_browser_toggle
            .iter()
            .any(|bookmark| bookmark.get("id").and_then(Value::as_str) == Some(legacy_id)));
        assert_eq!(list_bookmarks(case_dir.clone()).unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn deleting_host_removes_only_its_case_bookmarks() {
        let case_dir = temporary_case_dir("bookmark-host-delete");
        create_host_directory(&case_dir, "removed-host");
        create_host_directory(&case_dir, "retained-host");

        let removed_path = case_dir
            .join("view")
            .join("..")
            .join("removed-host")
            .join("EVENTLOG")
            .join("Security.sqlite")
            .to_string_lossy()
            .to_string();
        let retained_path = case_dir
            .join("retained-host")
            .join("EVENTLOG")
            .join("Security.sqlite")
            .to_string_lossy()
            .to_string();
        let outside_path = std::env::temp_dir()
            .join("unattributed.sqlite")
            .to_string_lossy()
            .to_string();
        write_bookmarks_path(
            &case_dir,
            &[
                // Modern annotation: host identity is enough even when the
                // source file itself has already gone away.
                bookmark(
                    "removed-by-id",
                    "/missing/source.sqlite",
                    Some("removed-host"),
                ),
                // Legacy annotation: match its normalised source directory.
                bookmark("removed-by-path", removed_path, None),
                bookmark(
                    "retained-by-id",
                    retained_path.clone(),
                    Some("retained-host"),
                ),
                // Host identity wins over a stale/misrecorded source path.
                bookmark(
                    "retained-conflicting-path",
                    case_dir
                        .join("removed-host")
                        .join("old.sqlite")
                        .to_string_lossy(),
                    Some("retained-host"),
                ),
                bookmark("retained-legacy", retained_path, None),
                bookmark("outside-legacy", outside_path, None),
            ],
        )
        .unwrap();

        assert!(delete_host_dir_and_bookmarks(&case_dir, "removed-host"));
        assert!(!case_dir.join("removed-host").exists());
        let ids: Vec<String> = read_bookmarks_path(&case_dir)
            .unwrap()
            .iter()
            .filter_map(|value| value.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert_eq!(
            ids,
            [
                "retained-by-id",
                "retained-conflicting-path",
                "retained-legacy",
                "outside-legacy"
            ]
        );

        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn listing_bookmarks_prunes_only_entries_attributable_to_missing_hosts() {
        let case_dir = temporary_case_dir("bookmark-stale-prune");
        create_host_directory(&case_dir, "retained-host");
        let retained_path = case_dir
            .join("retained-host")
            .join("REGISTRY")
            .join("Registry.sqlite")
            .to_string_lossy()
            .to_string();
        let stale_path = case_dir
            .join("view")
            .join("..")
            .join("removed-host")
            .join("REGISTRY")
            .join("Registry.sqlite")
            .to_string_lossy()
            .to_string();
        let outside_path = std::env::temp_dir()
            .join("unattributed.sqlite")
            .to_string_lossy()
            .to_string();
        write_bookmarks_path(
            &case_dir,
            &[
                bookmark(
                    "retained-by-id",
                    retained_path.clone(),
                    Some("retained-host"),
                ),
                // Do not infer a missing source row as a deleted host. The
                // host still exists, so this remains the analyst's bookmark.
                bookmark("retained-legacy", retained_path, None),
                bookmark(
                    "stale-by-id",
                    "/missing/source.sqlite",
                    Some("removed-host"),
                ),
                bookmark("stale-legacy", stale_path, None),
                // Source paths outside this case are not safe to attribute.
                bookmark("outside-legacy", outside_path, None),
            ],
        )
        .unwrap();

        let listed = list_bookmarks(case_dir.to_string_lossy().to_string()).unwrap();
        let ids: Vec<String> = listed
            .iter()
            .filter_map(|value| value.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert_eq!(ids, ["retained-by-id", "retained-legacy", "outside-legacy"]);
        assert_eq!(read_bookmarks_path(&case_dir).unwrap(), listed);

        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn malformed_bookmark_file_is_reported_instead_of_looking_empty() {
        let case_dir = temporary_case_dir("bookmark-malformed");
        std::fs::write(case_dir.join("bookmarks.json"), "{ not valid json").unwrap();

        let result = list_bookmarks(case_dir.to_string_lossy().to_string());
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(case_dir);
    }
}

#[cfg(test)]
mod account_event_tests {
    use super::*;

    fn cache_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn event(event_data: Value) -> Map<String, Value> {
        let mut row = Map::new();
        row.insert(
            "EventData".to_string(),
            Value::String(event_data.to_string()),
        );
        row
    }

    #[test]
    fn matches_only_exact_structured_subject_sid() {
        let sid = "S-1-5-21-100-200-300-1001";
        let row = event(serde_json::json!({
            "SubjectUserSid": sid,
            "RuleId": format!("firewall:{}", sid),
        }));
        let evidence = account_event_evidence(&row, sid, "alice");
        assert!(evidence.contains("[SID] 수행 계정 · SubjectUserSid"));
        assert!(!evidence.contains("RuleId"));
    }

    #[test]
    fn ignores_sid_in_unstructured_provider_payload() {
        let sid = "S-1-5-21-100-200-300-1001";
        let row = event(serde_json::json!({ "RuleId": format!("firewall:{}", sid) }));
        assert!(account_event_evidence(&row, sid, "alice").is_empty());
    }

    #[test]
    fn does_not_fall_back_to_name_when_same_role_has_sid() {
        let row = event(serde_json::json!({
            "TargetUserSid": "S-1-5-21-100-200-300-9999",
            "TargetUserName": "alice",
        }));
        assert!(account_event_evidence(&row, "S-1-5-21-100-200-300-1001", "alice").is_empty());
    }

    #[test]
    fn permits_name_only_provider_role_when_no_sid_exists() {
        let mut row = event(serde_json::json!({ "TargetUserName": "DOMAIN\\Alice" }));
        row.insert("Provider".to_string(), Value::String("Example".to_string()));
        let evidence = account_event_evidence(&row, "", "alice");
        assert!(evidence.contains("[이름] 대상 계정 · TargetUserName = DOMAIN\\Alice"));
    }

    #[test]
    fn pages_globally_sorted_exact_hits_across_eventlog_sources() {
        let _lock = cache_test_lock();
        clear_account_event_cache_for_test();
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-account-events-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("Security.sqlite");
        let second = root.join("System.sqlite");
        let sid = "S-1-5-21-100-200-300-1001";
        for (path, timestamp, event_id) in [
            (&first, "2024-02-02 10:00:00.000", "4624"),
            (&second, "2024-02-01 10:00:00.000", "4625"),
        ] {
            let conn = Connection::open(path).unwrap();
            conn.execute_batch(
                "CREATE TABLE Events (timestamp TEXT, EventID TEXT, Provider TEXT, EventData TEXT)",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO Events (timestamp, EventID, Provider, EventData) VALUES (?, ?, ?, ?)",
                rusqlite::params![
                    timestamp,
                    event_id,
                    "Microsoft-Windows-Security-Auditing",
                    serde_json::json!({ "SubjectUserSid": sid }).to_string()
                ],
            )
            .unwrap();
        }
        // Same SID embedded in unstructured text must not affect the total.
        Connection::open(&second)
            .unwrap()
            .execute(
                "INSERT INTO Events (timestamp, EventID, Provider, EventData) VALUES (?, ?, ?, ?)",
                rusqlite::params![
                    "2024-02-01 11:00:00.000",
                    "0",
                    "Example",
                    serde_json::json!({ "RuleId": sid }).to_string()
                ],
            )
            .unwrap();

        let page = account_event_page_blocking(
            vec![
                AccountEventSource {
                    full_path: first.to_string_lossy().to_string(),
                    table_name: "Events".to_string(),
                    log_name: "Security".to_string(),
                },
                AccountEventSource {
                    full_path: second.to_string_lossy().to_string(),
                    table_name: "Events".to_string(),
                    log_name: "System".to_string(),
                },
                AccountEventSource {
                    full_path: root.join("missing.sqlite").to_string_lossy().to_string(),
                    table_name: "Events".to_string(),
                    log_name: "Missing".to_string(),
                },
            ],
            AccountEventQuery {
                sid: sid.to_string(),
                username: "alice".to_string(),
                search: Some("security".to_string()),
                start: Some("2024-02-01 00:00:00.000".to_string()),
                end: Some("2024-02-02 23:59:59.999".to_string()),
                offset: 0,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(page.row_count, 2);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(
            map_text(&page.rows[0], "timestamp"),
            "2024-02-01 10:00:00.000"
        );
        assert_eq!(
            map_text(&page.rows[0], "_source_full_path"),
            second.to_string_lossy()
        );
        assert_eq!(map_text(&page.rows[0], "_source_table_name"), "Events");
        assert_eq!(page.source_count, 3);
        assert_eq!(page.sources_read, 2);
        assert_eq!(
            page.source_failures,
            vec![AccountEventSourceFailure {
                log_name: "Missing".to_string(),
                table_name: "Events".to_string(),
                reason: "원본 SQLite를 열 수 없습니다".to_string(),
            }]
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn distinguishes_all_source_failures_from_an_empty_match() {
        let _lock = cache_test_lock();
        clear_account_event_cache_for_test();
        let page = account_event_page_blocking(
            vec![AccountEventSource {
                full_path: "/definitely/not/an/eventlog.sqlite".to_string(),
                table_name: "Events".to_string(),
                log_name: "Unavailable".to_string(),
            }],
            AccountEventQuery {
                sid: "S-1-5-21-1".to_string(),
                username: "alice".to_string(),
                search: None,
                start: None,
                end: None,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap();
        assert_eq!(page.row_count, 0);
        assert_eq!(page.source_count, 1);
        assert_eq!(page.sources_read, 0);
        assert_eq!(page.source_failures.len(), 1);
    }

    #[test]
    fn reuses_bounded_hit_index_for_following_page_and_invalidates_on_source_change() {
        let _lock = cache_test_lock();
        clear_account_event_cache_for_test();
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-account-event-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("Security.sqlite");
        let second = root.join("System.sqlite");
        let sid = "S-1-5-21-100-200-300-1001";
        for (path, parity) in [(&first, 1_u32), (&second, 2_u32)] {
            let conn = Connection::open(path).unwrap();
            conn.execute_batch(
                "CREATE TABLE Events (timestamp TEXT, EventID TEXT, Provider TEXT, EventData TEXT)",
            )
            .unwrap();
            for ordinal in 0..6_u32 {
                let day = ordinal * 2 + parity;
                conn.execute(
                    "INSERT INTO Events (timestamp, EventID, Provider, EventData) VALUES (?, ?, ?, ?)",
                    rusqlite::params![format!("2024-03-{day:02} 10:00:00.000"), "4624", "Microsoft-Windows-Security-Auditing", serde_json::json!({ "SubjectUserSid": sid }).to_string()],
                ).unwrap();
            }
        }
        let sources = vec![
            AccountEventSource {
                full_path: first.to_string_lossy().to_string(),
                table_name: "Events".to_string(),
                log_name: "Security".to_string(),
            },
            AccountEventSource {
                full_path: second.to_string_lossy().to_string(),
                table_name: "Events".to_string(),
                log_name: "System".to_string(),
            },
            AccountEventSource {
                full_path: root.join("unreadable.sqlite").to_string_lossy().to_string(),
                table_name: "Events".to_string(),
                log_name: "Unreadable".to_string(),
            },
        ];
        let base_query = |offset| AccountEventQuery {
            sid: sid.to_string(),
            username: "alice".to_string(),
            search: None,
            start: Some("2024-03-01 00:00:00.000".to_string()),
            end: Some("2024-03-31 23:59:59.999".to_string()),
            offset,
            limit: 10,
        };

        let first_page = account_event_page_blocking(sources.clone(), base_query(0)).unwrap();
        assert_eq!(first_page.row_count, 12);
        assert_eq!(first_page.rows.len(), 10);
        assert_eq!(
            map_text(&first_page.rows[0], "timestamp"),
            "2024-03-01 10:00:00.000"
        );
        assert_eq!(first_page.source_failures.len(), 1);
        let scans_after_first_page =
            ACCOUNT_EVENT_SOURCE_SCAN_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(scans_after_first_page, 3);

        let second_page = account_event_page_blocking(sources.clone(), base_query(10)).unwrap();
        assert_eq!(second_page.row_count, 12);
        assert_eq!(second_page.rows.len(), 2);
        assert_eq!(
            map_text(&second_page.rows[0], "timestamp"),
            "2024-03-11 10:00:00.000"
        );
        assert_eq!(second_page.source_failures, first_page.source_failures);
        assert_eq!(
            ACCOUNT_EVENT_SOURCE_SCAN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            scans_after_first_page
        );

        // Source fingerprint includes file size + mtime, so a re-parse/update
        // invalidates the old index even with the same source path and query.
        Connection::open(&first)
            .unwrap()
            .execute(
                "INSERT INTO Events (timestamp, EventID, Provider, EventData) VALUES (?, ?, ?, ?)",
                rusqlite::params![
                    "2024-03-13 10:00:00.000",
                    "4624",
                    "Microsoft-Windows-Security-Auditing",
                    serde_json::json!({ "SubjectUserSid": sid }).to_string()
                ],
            )
            .unwrap();
        let refreshed = account_event_page_blocking(sources, base_query(10)).unwrap();
        assert_eq!(refreshed.row_count, 13);
        assert_eq!(refreshed.rows.len(), 3);
        assert_eq!(
            map_text(&refreshed.rows[2], "timestamp"),
            "2024-03-13 10:00:00.000"
        );
        assert_eq!(
            ACCOUNT_EVENT_SOURCE_SCAN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            scans_after_first_page + 3
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod search_case_tests {
    use super::*;

    #[test]
    fn search_case_pages_bounded_preview_and_reports_failed_source() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-search-page-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("results.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Findings (timestamp TEXT, detail TEXT, record_key TEXT);\
             CREATE TABLE TrailingEmpty (value TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Findings VALUES (?1, ?2, ?3)",
            rusqlite::params![
                "2026-01-01 00:00:00.000",
                "needle first",
                "RawFindings::Findings::41"
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO Findings VALUES (?1, ?2, ?3)",
            rusqlite::params![
                "2026-01-02 00:00:00.000",
                "needle second",
                "RawFindings::Findings::42"
            ],
        )
        .unwrap();
        let long_detail = format!("verylong{}", "x".repeat(4_096));
        conn.execute(
            "INSERT INTO Findings VALUES (?1, ?2, ?3)",
            rusqlite::params![
                "2026-01-03 00:00:00.000",
                long_detail,
                format!("RawFindings::Findings::{}", "r".repeat(4_096))
            ],
        )
        .unwrap();
        drop(conn);
        std::fs::write(root.join("unreadable.sqlite"), vec![0_u8; 128]).unwrap();
        let hosts = vec![SearchHost {
            id: "host-1".to_string(),
            name: "HOST-1".to_string(),
            dir: root.to_string_lossy().to_string(),
        }];

        let first = search_case_blocking("needle".to_string(), hosts.clone(), 0, 1, None, None, None);
        assert_eq!(
            first.hits.len(),
            1,
            "source failures: {:?}",
            first.source_failures
        );
        assert_eq!(first.hits[0].match_column, "detail");
        assert_eq!(first.hits[0].match_value, "needle first");
        assert_eq!(first.hits[0].timestamp, "2026-01-01 00:00:00.000");
        assert_eq!(first.hits[0].record_key, "RawFindings::Findings::41");
        assert_eq!(first.next_offset, Some(1));
        // A continuation must not hide later unreadable sources.
        assert!(!first.source_failures.is_empty());
        // A later empty table is a valid source, not a health-check failure.
        assert!(!first
            .source_failures
            .iter()
            .any(|failure| failure == "HOST-1: results"));

        let second = search_case_blocking("needle".to_string(), hosts.clone(), 1, 1, None, None, None);
        assert_eq!(second.hits.len(), 1);
        assert_eq!(second.hits[0].match_value, "needle second");
        assert_eq!(second.next_offset, None);
        assert!(!second.source_failures.is_empty());

        let ranged = search_case_blocking(
            "needle".to_string(),
            hosts.clone(),
            0,
            10,
            Some("2026-01-02 00:00:00.000".to_string()),
            Some("2026-01-02 23:59:59.999".to_string()),
            None,
        );
        assert_eq!(ranged.hits.len(), 1);
        assert_eq!(ranged.hits[0].match_value, "needle second");

        let bounded_preview =
            search_case_blocking("verylong".to_string(), hosts, 0, 10, None, None, None);
        assert_eq!(bounded_preview.hits.len(), 1);
        assert_eq!(bounded_preview.hits[0].match_value.chars().count(), 512);
        assert_eq!(bounded_preview.hits[0].record_key.chars().count(), 512);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn search_case_restricts_to_selected_categories() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-search-cat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        // Two raw artifact folders plus the derived _OVERVIEW layer, each with
        // one matching row. The category is the first path segment under the
        // host directory.
        for category in ["BROWSER", "EVENTLOG", "_OVERVIEW"] {
            let dir = root.join(category);
            std::fs::create_dir_all(&dir).unwrap();
            let conn = Connection::open(dir.join("results.sqlite")).unwrap();
            conn.execute_batch("CREATE TABLE Rows (timestamp TEXT, detail TEXT);")
                .unwrap();
            conn.execute(
                "INSERT INTO Rows VALUES (?1, ?2)",
                rusqlite::params!["2026-01-01 00:00:00.000", format!("needle {category}")],
            )
            .unwrap();
        }
        let hosts = vec![SearchHost {
            id: "host-1".to_string(),
            name: "HOST-1".to_string(),
            dir: root.to_string_lossy().to_string(),
        }];

        // No filter → every folder searched (both artifacts + the overview).
        let all = search_case_blocking("needle".to_string(), hosts.clone(), 0, 10, None, None, None);
        assert_eq!(all.hits.len(), 3);

        // Only BROWSER → the BROWSER row, plus the always-on _OVERVIEW row. The
        // derived 종합 분석 layer must never be filtered out, so narrowing to a
        // single artifact still surfaces its correlated overview results.
        let browser = search_case_blocking(
            "needle".to_string(),
            hosts.clone(),
            0,
            10,
            None,
            None,
            Some(vec!["browser".to_string()]),
        );
        let browser_values: std::collections::HashSet<&str> =
            browser.hits.iter().map(|h| h.match_value.as_str()).collect();
        assert_eq!(browser.hits.len(), 2);
        assert!(browser_values.contains("needle BROWSER"));
        assert!(browser_values.contains("needle _OVERVIEW"));
        assert!(!browser_values.contains("needle EVENTLOG"));

        // An empty selection is treated as "no filter", not "match nothing".
        let empty = search_case_blocking(
            "needle".to_string(),
            hosts,
            0,
            10,
            None,
            None,
            Some(vec![]),
        );
        assert_eq!(empty.hits.len(), 3);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod timeline_save_tests {
    use super::*;

    /// begin → append×N(각각 drain으로 완료 대기) → finish가 이어붙인 내용을
    /// 원자적으로 확정하고, 세션 없는 append와 실패 후 finish가 오류를 낸다.
    #[test]
    fn chunked_save_appends_in_order_and_finishes_atomically() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-tl-save-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let host = root.to_string_lossy().to_string();
        let token = "test-token-1";

        timeline_save_begin_impl(&host, token).unwrap();
        for piece in [b"abc".as_slice(), b"def", b"ghi"] {
            timeline_save_append_impl(&host, token, piece.to_vec()).unwrap();
            timeline_save_wait_impl(token).unwrap();
        }
        // 정확히 허용 크기인 청크는 통과, 1바이트 초과는 복사 전에 거부.
        timeline_save_append_impl(&host, token, vec![b'!'; TIMELINE_SAVE_MAX_CHUNK]).unwrap();
        timeline_save_wait_impl(token).unwrap();
        assert!(
            timeline_save_append_impl(&host, token, vec![0u8; TIMELINE_SAVE_MAX_CHUNK + 1]).is_err(),
            "oversized chunk must be rejected"
        );
        timeline_save_finish_impl(&host, token).unwrap();
        let written = std::fs::read(master_timeline_cache_path(&host)).unwrap();
        assert_eq!(&written[..9], b"abcdefghi");
        assert_eq!(written.len(), 9 + TIMELINE_SAVE_MAX_CHUNK);
        // 임시 파일은 남지 않는다.
        assert!(!master_timeline_saving_path(&host, token).exists());

        // 세션이 끝난 뒤의 append는 오류.
        assert!(timeline_save_append_impl(&host, token, b"x".to_vec()).is_err());

        // begin이 이전 임시 파일을 정리한다.
        std::fs::write(master_timeline_saving_path(&host, "stale-1"), b"junk").unwrap();
        timeline_save_begin_impl(&host, "test-token-2").unwrap();
        assert!(!master_timeline_saving_path(&host, "stale-1").exists());
        // 호스트-토큰 소유 불일치: append/finish 모두 거부되고 세션은 유지된다.
        assert!(timeline_save_append_impl("/wrong/host", "test-token-2", b"a".to_vec()).is_err());
        assert!(timeline_save_finish_impl("/wrong/host", "test-token-2").is_err());
        // 실패 경로: 임시 파일을 지워 쓰기 실패 유도 → drain/finish가 오류 전파.
        std::fs::remove_file(master_timeline_saving_path(&host, "test-token-2")).unwrap();
        timeline_save_append_impl(&host, "test-token-2", b"zzz".to_vec()).unwrap();
        assert!(timeline_save_wait_impl("test-token-2").is_err());
        assert!(timeline_save_finish_impl(&host, "test-token-2").is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    /// drain 없이 연속 전송하면 진행 중 쓰기 1개 상한에서 거부된다 —
    /// 쓰기 스레드·대기 메모리가 무제한으로 쌓이지 않는다.
    #[test]
    fn consecutive_chunks_without_drain_are_rejected() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-tl-save-flood-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let host = root.to_string_lossy().to_string();
        let token = "flood-token";
        timeline_save_begin_impl(&host, token).unwrap();
        // 큰 청크로 쓰기 시간을 벌고, 완료 대기 없이 곧바로 다음 청크 전송을
        // 반복하면 최소 한 번은 in-flight 상한 거부가 발생해야 한다. 워커가
        // 그 사이 완료되어 통과한 전송은 정상 동작이다.
        let mut rejected = 0usize;
        for _ in 0..8 {
            if timeline_save_append_impl(&host, token, vec![b'x'; 4 * 1024 * 1024]).is_err() {
                rejected += 1;
            }
        }
        assert!(rejected > 0, "in-flight limit must reject drain-less floods");
        timeline_save_wait_impl(token).unwrap();
        timeline_save_finish_impl(&host, token).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod browser_activity_tests {
    use super::*;

    // Build a minimal browser History copy the way the collector writes it:
    // one `urls`/`visits` pair with *every* column typed TEXT (ids and the
    // integer-like link/time fields included).
    fn write_history_fixture(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        let conn = Connection::open(dir.join("user_Chrome.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
             CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);",
        )
        .unwrap();
        // A (typed) → B (link, same tab) → C (opened in a new tab from B),
        // then onward: C → D (a later move off the reload), and A → E (a
        // sibling branch off the shared ancestor).
        for (id, url, title) in [
            ("1", "https://a.test/", "A"),
            ("2", "https://b.test/", "B"),
            ("3", "https://c.test/page", "C"),
            ("4", "https://d.test/next", "D"),
            ("5", "https://e.test/side", "E"),
        ] {
            conn.execute(
                "INSERT INTO urls VALUES (?1, ?2, ?3, '1')",
                rusqlite::params![id, url, title],
            )
            .unwrap();
        }
        // transitions: TYPED (1) for A, LINK (0) for B, LINK (0x30000000) for C.
        // Visit 13 is C re-navigating to *itself* (client redirect, 0x60000000,
        // from_visit=12) — a reload of the same page, not a new inflow. Visit 14
        // leaves C *from that reload* (from_visit=13), and visit 15 branches off
        // A (from_visit=10) — a sibling path next to the target's ancestry.
        // visit_time: microseconds since 1601 (arbitrary increasing values).
        let rows = [
            ("10", "1", "0", "0", "1", "", "13427941143000000"),
            ("11", "2", "10", "0", "0", "", "13427941143100000"),
            ("12", "3", "0", "11", "805306368", "https://ext.test/", "13427941143200000"),
            ("13", "3", "12", "0", "1610612736", "", "13427941143300000"),
            ("14", "4", "13", "0", "0", "", "13427941143400000"),
            ("15", "5", "10", "0", "0", "", "13427941143500000"),
        ];
        for (id, url, from_visit, opener, transition, ext, time) in rows {
            conn.execute(
                "INSERT INTO visits (id, url, from_visit, opener_visit, transition, external_referrer_url, visit_time) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![id, url, from_visit, opener, transition, ext, time],
            )
            .unwrap();
        }
    }

    #[test]
    fn visit_graph_covers_ancestors_descendants_and_siblings() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        write_history_fixture(&root.join("BROWSER"));

        // 대상 C에서 조상(A→B→C), 후행(C→D), 형제 분기(A→E)까지 한 그래프로.
        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://c.test/page".to_string(),
            None,
            Some("BROWSER/user_Chrome.sqlite".to_string()),
        );
        assert_eq!(flow.source_file, "user_Chrome.sqlite");
        let by_id: std::collections::HashMap<&str, &VisitGraphNode> =
            flow.nodes.iter().map(|n| (n.visit_id.as_str(), n)).collect();
        // reload 방문(13)은 entry(12)에 접혀 노드가 아니다.
        assert_eq!(flow.nodes.len(), 5, "nodes: {:?}", flow.nodes.iter().map(|n| &n.visit_id).collect::<Vec<_>>());
        for id in ["10", "11", "12", "14", "15"] {
            assert!(by_id.contains_key(id), "missing node {id}");
        }
        let target = by_id["12"];
        assert!(target.is_target);
        assert_eq!(target.reloads, 1, "self-redirect 13 collapses into 12");
        assert_eq!(target.external_referrer, "https://ext.test/");
        assert_eq!(by_id["10"].transition, "주소창 직접 입력");
        assert!(!by_id["14"].is_target && !by_id["10"].is_target);
        // 간선: 조상 연결 그대로, 후행 이동은 reload가 아니라 entry에 붙는다.
        let edge = |from: &str, to: &str| flow.edges.iter().find(|e| e.from == from && e.to == to);
        assert_eq!(flow.edges.len(), 4);
        assert_eq!(edge("10", "11").unwrap().kind, "from_visit");
        assert_eq!(edge("11", "12").unwrap().kind, "opener_visit");
        assert!(edge("12", "14").is_some(), "C→D는 reload(13)를 접은 entry(12)에 연결");
        assert!(edge("10", "15").is_some(), "형제 분기 A→E 포함");

        // A cached subresource is attributed to its document origin's page.
        let cache_flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://c.test/asset/app.js".to_string(),
            Some("1/0/_dk_https://c.test https://c.test https://c.test/asset/app.js".to_string()),
            Some("/case/BROWSER/user/Chrome/Cache/Cache_Data/index".to_string()),
        );
        assert_eq!(cache_flow.matched_page, "https://c.test");
        assert!(cache_flow
            .nodes
            .iter()
            .any(|n| n.is_target && n.url == "https://c.test/page"));

        // An unknown URL yields no graph but a non-empty explanatory note.
        let none = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://nowhere.test/x".to_string(),
            None,
            Some("BROWSER/user_Chrome.sqlite".to_string()),
        );
        assert!(none.nodes.is_empty());
        assert!(!none.note.is_empty());

        // 출처가 없는 행(구 파싱본)은 고정을 포기하고 계정 후보 전체를
        // 조회한다 — 그래프를 낸 원본은 source_file로 남는다.
        let unsourced = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://c.test/page".to_string(),
            None,
            None,
        );
        assert!(!unsourced.nodes.is_empty());
        assert_eq!(unsourced.source_file, "user_Chrome.sqlite");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn visit_graph_keeps_every_entry_and_distinct_origins() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-distinct-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let dir = root.join("BROWSER");
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(dir.join("user_Chrome.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
             CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);",
        )
        .unwrap();
        // urls: 1 = source X, 2 = source Y, 3 = the target T.
        for (id, url) in [("1", "https://x.test/"), ("2", "https://y.test/"), ("3", "https://t.test/p")] {
            conn.execute("INSERT INTO urls VALUES (?1,?2,'',' 1')", rusqlite::params![id, url]).unwrap();
        }
        // Three genuine entries of T: two via X (both real visits — the graph
        // keeps each), one via Y (a different origin, in the same picture).
        let rows = [
            ("100", "1", "0", "0", "1", "", "13427941143000000"),
            ("101", "3", "100", "0", "0", "", "13427941143100000"),
            ("200", "2", "0", "0", "1", "", "13427941143200000"),
            ("201", "3", "200", "0", "0", "", "13427941143300000"),
            ("102", "3", "100", "0", "0", "", "13427941143400000"),
        ];
        for (id, url, fv, op, tr, ext, t) in rows {
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![id, url, fv, op, tr, ext, t],
            ).unwrap();
        }
        drop(conn);

        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://t.test/p".to_string(),
            None,
            Some("BROWSER/user_Chrome.sqlite".to_string()),
        );
        // 그래프는 T의 진짜 entry 방문을 전부 노드로 남긴다(101·102·201) —
        // 서로 다른 출발지 X·Y가 한 그림에서 같이 보인다.
        assert_eq!(flow.nodes.len(), 5);
        assert_eq!(flow.edges.len(), 3);
        assert_eq!(flow.nodes.iter().filter(|n| n.is_target).count(), 3);
        let origins: std::collections::HashSet<&str> = flow
            .nodes
            .iter()
            .filter(|n| !n.is_target)
            .map(|n| n.url.as_str())
            .collect();
        assert!(origins.contains("https://x.test/"));
        assert!(origins.contains("https://y.test/"));
        let edge = |from: &str, to: &str| flow.edges.iter().any(|e| e.from == from && e.to == to);
        assert!(edge("100", "101") && edge("100", "102") && edge("200", "201"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// 캐시 출처 origin은 접두어가 아니라 완전 일치 — `example.com.evil`·다른
    /// 포트의 방문이 기준 페이지로 오인되면 안 된다.
    #[test]
    fn cache_origin_match_rejects_lookalike_hosts_and_other_ports() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-origin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let dir = root.join("BROWSER");
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(dir.join("user_Chrome.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
             CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);",
        )
        .unwrap();
        // 미끼 호스트·다른 포트만 방문 기록에 있다 — 방문 횟수도 더 높다.
        for (id, url, count) in [
            ("1", "https://c.test.evil/lure", "9"),
            ("2", "https://c.test:8443/admin", "8"),
            ("3", "https://c.test/page", "1"),
            ("4", "https://o.test/", "1"),
        ] {
            conn.execute("INSERT INTO urls VALUES (?1,?2,'',?3)", rusqlite::params![id, url, count]).unwrap();
        }
        let rows = [
            ("10", "1", "0", "0", "1", "", "13427941143000000"),
            ("11", "1", "10", "0", "0", "", "13427941143100000"),
            ("20", "2", "0", "0", "1", "", "13427941143200000"),
            ("21", "2", "20", "0", "0", "", "13427941143300000"),
            ("30", "4", "0", "0", "1", "", "13427941143400000"),
            ("31", "3", "30", "0", "0", "", "13427941143500000"),
        ];
        for (id, url, fv, op, tr, ext, t) in rows {
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![id, url, fv, op, tr, ext, t],
            ).unwrap();
        }
        drop(conn);

        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://c.test/asset/app.js".to_string(),
            Some("1/0/_dk_https://c.test https://c.test https://c.test/asset/app.js".to_string()),
            Some("/case/BROWSER/user/Chrome/Cache/Cache_Data/index".to_string()),
        );
        assert_eq!(flow.matched_page, "https://c.test");
        // 미끼·타 포트 페이지가 아니라 정확한 origin의 페이지만 대상이 된다.
        let targets: Vec<&VisitGraphNode> = flow.nodes.iter().filter(|n| n.is_target).collect();
        assert!(!targets.is_empty());
        for node in &targets {
            assert!(node.url.starts_with("https://c.test/"), "wrong page attributed: {}", node.url);
        }
        // 미끼 호스트·타 포트의 컴포넌트는 그래프에 연결되지 않는다.
        assert!(flow
            .nodes
            .iter()
            .all(|n| !n.url.contains(".evil") && !n.url.contains(":8443")));
        let _ = std::fs::remove_dir_all(root);
    }

    /// 출처 고정: 같은 계정에 같은 URL을 가진 두 브라우저 DB가 있어도, 행의
    /// 원본 DB(Edge)만 조회한다 — 먼저 정렬된 Chrome 체인이 새면 안 된다.
    #[test]
    fn visit_flow_reads_only_the_source_browser_db() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-src-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let dir = root.join("BROWSER");
        std::fs::create_dir_all(&dir).unwrap();
        // 같은 URL이 두 브라우저 모두에 있고, 유입 출발지만 다르다.
        for (file, origin) in [
            ("user_Chrome.sqlite", "https://from-chrome.test/"),
            ("user_Edge.sqlite", "https://from-edge.test/"),
        ] {
            let conn = Connection::open(dir.join(file)).unwrap();
            conn.execute_batch(
                "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
                 CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);",
            )
            .unwrap();
            conn.execute("INSERT INTO urls VALUES ('1', ?1, '', '1')", [origin]).unwrap();
            conn.execute("INSERT INTO urls VALUES ('2', 'https://t.test/p', '', '1')", []).unwrap();
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES ('10','1','0','0','1','','13427941143000000')",
                [],
            ).unwrap();
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES ('11','2','10','0','0','','13427941143100000')",
                [],
            ).unwrap();
        }

        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://t.test/p".to_string(),
            None,
            Some("BROWSER/user_Edge.sqlite".to_string()),
        );
        assert_eq!(flow.source_file, "user_Edge.sqlite");
        assert!(flow.nodes.iter().any(|n| n.url == "https://from-edge.test/"));
        assert!(flow.nodes.iter().all(|n| n.url != "https://from-chrome.test/"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// reload 귀속: 독립 유입 두 개 중 리다이렉트가 이어진 entry에만 세고,
    /// 다른 유입 체인에는 0으로 남는다.
    #[test]
    fn reloads_are_attributed_per_entry_chain() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-reload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let dir = root.join("BROWSER");
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(dir.join("user_Chrome.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
             CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);",
        )
        .unwrap();
        for (id, url) in [("1", "https://x.test/"), ("2", "https://y.test/"), ("3", "https://t.test/p")] {
            conn.execute("INSERT INTO urls VALUES (?1,?2,'','1')", rusqlite::params![id, url]).unwrap();
        }
        // X→T(101) 뒤에 self-redirect 2회(102→103), Y→T(201)는 리다이렉트 없음.
        let rows = [
            ("100", "1", "0", "0", "1", "", "13427941143000000"),
            ("101", "3", "100", "0", "0", "", "13427941143100000"),
            ("102", "3", "101", "0", "1610612736", "", "13427941143200000"),
            ("103", "3", "102", "0", "1610612736", "", "13427941143300000"),
            ("200", "2", "0", "0", "1", "", "13427941143400000"),
            ("201", "3", "200", "0", "0", "", "13427941143500000"),
        ];
        for (id, url, fv, op, tr, ext, t) in rows {
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![id, url, fv, op, tr, ext, t],
            ).unwrap();
        }
        drop(conn);

        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://t.test/p".to_string(),
            None,
            Some("BROWSER/user_Chrome.sqlite".to_string()),
        );
        // reload 방문(102·103)은 노드가 아니라 자기 entry(101)의 접힌 수다.
        let by_id: std::collections::HashMap<&str, &VisitGraphNode> =
            flow.nodes.iter().map(|n| (n.visit_id.as_str(), n)).collect();
        assert_eq!(flow.nodes.len(), 4);
        assert!(!by_id.contains_key("102") && !by_id.contains_key("103"));
        assert_eq!(by_id["101"].reloads, 2, "X 유입 entry에만 재이동 2회 귀속");
        assert_eq!(by_id["201"].reloads, 0, "Y 유입 entry는 재이동 0회");
        let _ = std::fs::remove_dir_all(root);
    }

    /// 같은 계정·같은 브라우저의 다중 프로필: 캐시 행은 _wina_source의 프로필
    /// 루트가 일치하는 History만 연결되고, 매핑이 없는 산출물이 여럿이면
    /// 임의 선택 대신 비활성 안내가 반환된다.
    #[test]
    fn cache_flow_matches_only_the_same_browser_profile() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-visitflow-profile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let dir = root.join("BROWSER");
        std::fs::create_dir_all(&dir).unwrap();
        // Default / Profile 1 — 같은 URL, 유입 출발지만 다르다.
        for (file, origin, source) in [
            (
                "user_Chrome.sqlite",
                "https://from-default.test/",
                "/img/Users/user/AppData/Local/Google/Chrome/User Data/Default/History",
            ),
            (
                "user_Chrome_2.sqlite",
                "https://from-profile1.test/",
                "/img/Users/user/AppData/Local/Google/Chrome/User Data/Profile 1/History",
            ),
        ] {
            let conn = Connection::open(dir.join(file)).unwrap();
            conn.execute_batch(
                "CREATE TABLE urls (id TEXT, url TEXT, title TEXT, visit_count TEXT);\
                 CREATE TABLE visits (id TEXT, url TEXT, from_visit TEXT, opener_visit TEXT, transition TEXT, external_referrer_url TEXT, visit_time TEXT);\
                 CREATE TABLE \"_wina_source\" (source_path TEXT);",
            )
            .unwrap();
            conn.execute("INSERT INTO \"_wina_source\" VALUES (?1)", [source]).unwrap();
            conn.execute("INSERT INTO urls VALUES ('1', ?1, '', '1')", [origin]).unwrap();
            conn.execute("INSERT INTO urls VALUES ('2', 'https://t.test/p', '', '1')", []).unwrap();
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES ('10','1','0','0','1','','13427941143000000')",
                [],
            ).unwrap();
            conn.execute(
                "INSERT INTO visits (id,url,from_visit,opener_visit,transition,external_referrer_url,visit_time) VALUES ('11','2','10','0','0','','13427941143100000')",
                [],
            ).unwrap();
        }

        // Profile 1의 캐시 index → Profile 1 History 그래프만 연결된다.
        let flow = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://t.test/asset/app.js".to_string(),
            Some("1/0/_dk_https://t.test https://t.test https://t.test/asset/app.js".to_string()),
            Some("/img/Users/user/AppData/Local/Google/Chrome/User Data/Profile 1/Cache/Cache_Data/index".to_string()),
        );
        assert_eq!(flow.source_file, "user_Chrome_2.sqlite");
        assert!(flow.nodes.iter().any(|n| n.url == "https://from-profile1.test/"));
        assert!(flow.nodes.iter().all(|n| n.url != "https://from-default.test/"));

        // 프로필 매핑이 없는 산출물(구 파싱본)에서 후보가 여럿이면 비활성.
        for file in ["user_Chrome.sqlite", "user_Chrome_2.sqlite"] {
            let conn = Connection::open(dir.join(file)).unwrap();
            conn.execute_batch("DROP TABLE \"_wina_source\";").unwrap();
        }
        let ambiguous = browser_visit_graph_blocking(
            root.to_string_lossy().to_string(),
            "user".to_string(),
            "https://t.test/asset/app.js".to_string(),
            Some("1/0/_dk_https://t.test https://t.test https://t.test/asset/app.js".to_string()),
            Some("/img/Users/user/AppData/Local/Google/Chrome/User Data/Profile 1/Cache/Cache_Data/index".to_string()),
        );
        assert!(ambiguous.nodes.is_empty());
        assert!(ambiguous.note.contains("프로필"), "note: {}", ambiguous.note);

        let _ = std::fs::remove_dir_all(root);
    }

    fn browser_domain_cache_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn cache_body_preview_is_bounded_and_exactly_keyed() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-cache-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let browser_dir = root.join("BROWSER");
        std::fs::create_dir_all(&browser_dir).unwrap();
        let path = browser_dir.join("alice_Chrome_Cache.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE CacheEntries (account TEXT, url TEXT, cache_key TEXT, body_b64 TEXT)",
        )
        .unwrap();
        let long_body = "QUJD".repeat(CACHE_BODY_PREVIEW_B64_CAP / 4 + 2);
        conn.execute(
            "INSERT INTO CacheEntries (account, url, cache_key, body_b64) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "alice",
                "https://example.test/recovered.js",
                "exact-key",
                long_body
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO CacheEntries (account, url, cache_key, body_b64) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "alice",
                "https://example.test/recovered.js",
                "other-key",
                "eA=="
            ],
        )
        .unwrap();
        drop(conn);

        let preview = cache_entry_body_blocking(
            root.to_string_lossy().to_string(),
            "alice".to_string(),
            "https://example.test/recovered.js".to_string(),
            "exact-key".to_string(),
        );
        assert_eq!(preview.body_b64.len(), CACHE_BODY_PREVIEW_B64_CAP);
        assert!(preview.truncated);
        assert_eq!(
            preview.decoded_size,
            (CACHE_BODY_PREVIEW_B64_CAP / 4 + 2) * 3
        );

        let missing = cache_entry_body_blocking(
            root.to_string_lossy().to_string(),
            "alice".to_string(),
            "https://example.test/recovered.js".to_string(),
            "unknown-key".to_string(),
        );
        assert!(missing.body_b64.is_empty());
        assert_eq!(missing.decoded_size, 0);
        assert!(!missing.truncated);

        let no_key = cache_entry_body_blocking(
            root.to_string_lossy().to_string(),
            "alice".to_string(),
            "https://example.test/recovered.js".to_string(),
            String::new(),
        );
        assert!(no_key.body_b64.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cache_body_preview_recovers_non_chrome_browsers() {
        // The BrowserActivity overview ingests Chrome/Edge/Whale/Unknown caches
        // and marks any entry with a stored body as recoverable. The body fetch
        // must open those same databases — a body living in `*_Edge_Cache.sqlite`
        // used to be unreachable because the lookup only scanned Chrome files,
        // so the "복구 데이터 열기" button opened onto "복구 데이터 확인 불가".
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-cache-edge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let browser_dir = root.join("BROWSER");
        std::fs::create_dir_all(&browser_dir).unwrap();
        let path = browser_dir.join("profile1_Edge_Cache.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE CacheEntries (account TEXT, url TEXT, cache_key TEXT, body_b64 TEXT)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO CacheEntries (account, url, cache_key, body_b64) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "profile1",
                "https://example.test/js/app.min.js",
                "edge-entry-key",
                "SGVsbG8="
            ],
        )
        .unwrap();
        drop(conn);

        let preview = cache_entry_body_blocking(
            root.to_string_lossy().to_string(),
            "profile1".to_string(),
            "https://example.test/js/app.min.js".to_string(),
            "edge-entry-key".to_string(),
        );
        assert_eq!(preview.body_b64, "SGVsbG8=");
        assert_eq!(preview.decoded_size, 5);
        assert!(!preview.truncated);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_conversation_detection_excludes_chatgpt_non_conversation_json() {
        let payload = serde_json::json!({ "mapping": { "node": {} } });
        let object = payload.as_object().unwrap();
        assert!(wina_core::ai_activity::is_ai_conversation_payload(
            "ChatGPT",
            "https://chatgpt.com/backend-api/conversation/123e4567-e89b-12d3-a456-426614174000",
            object,
        ));
        assert!(!wina_core::ai_activity::is_ai_conversation_payload(
            "ChatGPT",
            "https://chatgpt.com/backend-api/conversation/123e4567-e89b-12d3-a456-426614174000/stream_status",
            object,
        ));
        assert!(!wina_core::ai_activity::is_ai_conversation_payload(
            "ChatGPT",
            "https://chatgpt.com/backend-api/settings/voices",
            object,
        ));
    }

    #[test]
    fn ai_conversation_time_fields_preserve_numeric_and_text_values() {
        let payload = serde_json::json!({ "create_time": 1_784_525_759.692_772, "updated_at": "2026-07-21T16:00:00Z" });
        let object = payload.as_object().unwrap();
        assert_eq!(
            wina_core::ai_activity::json_time_field(object, &["create_time", "created_at"]),
            "1784525759.692772"
        );
        assert_eq!(
            wina_core::ai_activity::json_time_field(object, &["update_time", "updated_at"]),
            "2026-07-21T16:00:00Z"
        );
    }

    #[test]
    fn ai_conversations_page_filters_range_and_reports_exact_total() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-ai-derived-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let ov = root.join("_OVERVIEW");
        std::fs::create_dir_all(&ov).unwrap();
        let conn = Connection::open(ov.join("AiConversations.sqlite")).unwrap();
        conn.execute_batch("CREATE TABLE AiConversations (date TEXT, provider TEXT, account TEXT, title TEXT, created_at TEXT, updated_at TEXT, url TEXT, raw_json TEXT, source_record_key TEXT, _source_file TEXT)").unwrap();
        for (date, url) in [
            ("2026-07-01 10:00:00.000", "https://chatgpt.com/backend-api/conversation/a"),
            ("2026-07-02 10:00:00.000", "https://chatgpt.com/backend-api/conversation/b"),
            ("2026-07-03 10:00:00.000", "https://chatgpt.com/backend-api/conversation/c"),
        ] {
            conn.execute(
                "INSERT INTO AiConversations VALUES (?1, 'ChatGPT', 'alice', 't', '', '', ?2, '{}', '', '')",
                rusqlite::params![date, url],
            )
            .unwrap();
        }
        drop(conn);

        // 기간 필터: 2건만, total도 기간 내 전체(절단이 아님).
        let page = ai_conversations_blocking(
            root.to_string_lossy().to_string(),
            AiConversationQuery {
                start: Some("2026-07-02 00:00:00.000".into()),
                end: None,
                offset: 0,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.conversations.len(), 1);
        // 관찰 시각 내림차순 — 첫 페이지는 최신.
        assert_eq!(page.conversations[0].date, "2026-07-03 10:00:00.000");
        let second = ai_conversations_blocking(
            root.to_string_lossy().to_string(),
            AiConversationQuery {
                start: Some("2026-07-02 00:00:00.000".into()),
                end: None,
                offset: 1,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(second.conversations[0].date, "2026-07-02 10:00:00.000");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_conversations_missing_derived_table_returns_empty_page() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-ai-derived-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        // 이전 파싱본(파생 없음) — 오류가 아니라 빈 결과 (재파싱하면 생성).
        let page = ai_conversations_blocking(
            root.to_string_lossy().to_string(),
            AiConversationQuery {
                start: None,
                end: None,
                offset: 0,
                limit: 10,
            },
        )
        .unwrap();
        assert!(page.conversations.is_empty());
        assert_eq!(page.total, 0);
        assert_eq!(page.source_count, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn browser_summary_uses_sql_aggregates_for_the_active_filter_scope() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-browser-summary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("Browser.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE BrowserActivity (account TEXT, kind TEXT, timestamp TEXT, title TEXT, url TEXT, url_raw TEXT)").unwrap();
        for (account, kind, timestamp) in [
            ("alice", "visit", "2024-06-01 10:00:00.000"),
            ("alice", "download", "2024-06-01 11:00:00.000"),
            ("bob", "cache", "2024-06-02 09:00:00.000"),
        ] {
            conn.execute(
                "INSERT INTO BrowserActivity (account, kind, timestamp, title, url, url_raw) VALUES (?, ?, ?, '', '', '')",
                rusqlite::params![account, kind, timestamp],
            ).unwrap();
        }
        drop(conn);

        let summary = browser_activity_summary_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            BrowserActivityQuery {
                account: Some("alice".to_string()),
                kinds: vec!["visit".to_string(), "download".to_string()],
                day: None,
                search: None,
                start: Some("2024-06-01 00:00:00.000".to_string()),
                end: Some("2024-06-01 23:59:59.999".to_string()),
                offset: 0,
                limit: 10,
                descending: None,
            },
        )
        .unwrap();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.accounts, vec!["alice"]);
        assert_eq!(summary.days.len(), 1);
        assert_eq!(summary.days[0].value, "2024-06-01");
        assert_eq!(summary.days[0].count, 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn browser_insights_are_bounded_and_use_the_active_account_and_period() {
        let _lock = browser_domain_cache_test_lock();
        clear_browser_domain_cache_for_test();
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-browser-insights-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("Browser.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE BrowserActivity (account TEXT, kind TEXT, timestamp TEXT, title TEXT, url TEXT, url_raw TEXT, visit_count TEXT)").unwrap();
        for (account, kind, timestamp, title, url, visits) in [
            (
                "alice",
                "visit",
                "2024-07-01 10:00:00.000",
                "Alpha",
                "https://alpha.example/a",
                "4",
            ),
            (
                "alice",
                "visit",
                "2024-07-01 11:00:00.000",
                "Alpha",
                "https://alpha.example/a",
                "3",
            ),
            (
                "alice",
                "download",
                "2024-07-02 09:00:00.000",
                "a.exe",
                "https://alpha.example/a.exe",
                "",
            ),
            (
                "bob",
                "visit",
                "2024-07-01 12:00:00.000",
                "Bob",
                "https://bob.example/",
                "99",
            ),
            (
                "alice",
                "visit",
                "2024-08-01 12:00:00.000",
                "Later",
                "https://later.example/",
                "50",
            ),
        ] {
            conn.execute(
                "INSERT INTO BrowserActivity (account, kind, timestamp, title, url, url_raw, visit_count) VALUES (?, ?, ?, ?, ?, '', ?)",
                rusqlite::params![account, kind, timestamp, title, url, visits],
            ).unwrap();
        }
        drop(conn);

        let insights = browser_activity_insights_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("alice".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
        )
        .unwrap();
        assert_eq!(insights.visit_total, 7);
        assert_eq!(insights.top_visited_domains.len(), 1);
        assert_eq!(insights.top_visited_domains[0].domain, "alpha.example");
        assert_eq!(insights.top_visited_domains[0].visit_count, 7);
        assert_eq!(insights.top_visited_domains[0].url_count, 1);
        assert_eq!(insights.download_total, 1);
        assert_eq!(insights.downloads.len(), 1);
        assert_eq!(map_text(&insights.downloads[0], "title"), "a.exe");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn browser_domain_stats_normalize_hosts_and_exclude_out_of_scope_or_hostless_urls() {
        let _lock = browser_domain_cache_test_lock();
        clear_browser_domain_cache_for_test();
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-browser-domains-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("Browser.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE BrowserActivity (account TEXT, kind TEXT, timestamp TEXT, title TEXT, url TEXT, url_raw TEXT, visit_count TEXT)").unwrap();
        for (account, timestamp, url, visits) in [
            (
                "alice",
                "2024-07-01 10:00:00.000",
                "https://User:pass@Alpha.Example:8443/a?q=1#top",
                "4",
            ),
            (
                "alice",
                "2024-07-01 11:00:00.000",
                "http://alpha.example./b",
                "3",
            ),
            (
                "alice",
                "2024-07-01 12:00:00.000",
                "https://beta.example/path",
                "2",
            ),
            (
                "alice",
                "2024-07-01 13:00:00.000",
                "file:///tmp/evidence",
                "40",
            ),
            (
                "bob",
                "2024-07-01 14:00:00.000",
                "https://bob.example/",
                "99",
            ),
            (
                "alice",
                "2024-08-01 14:00:00.000",
                "https://later.example/",
                "50",
            ),
        ] {
            conn.execute(
                "INSERT INTO BrowserActivity (account, kind, timestamp, title, url, url_raw, visit_count) VALUES (?, 'visit', ?, '', ?, '', ?)",
                rusqlite::params![account, timestamp, url, visits],
            ).unwrap();
        }
        drop(conn);

        let insights = browser_activity_insights_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("alice".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
        )
        .unwrap();
        assert_eq!(insights.visit_total, 9);
        assert_eq!(insights.top_visited_domains.len(), 2);
        assert_eq!(insights.top_visited_domains[0].domain, "alpha.example");
        assert_eq!(insights.top_visited_domains[0].visit_count, 7);
        assert_eq!(insights.top_visited_domains[0].url_count, 2);
        assert_eq!(insights.top_visited_domains[1].domain, "beta.example");
        assert_eq!(insights.top_visited_domains[1].visit_count, 2);

        let first_page = browser_activity_domains_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("alice".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
            0,
            1,
            None,
        )
        .unwrap();
        assert_eq!(first_page.total, 2);
        assert_eq!(first_page.domains.len(), 1);
        assert_eq!(first_page.domains[0].domain, "alpha.example");
        assert_eq!(
            BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let second_page = browser_activity_domains_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("alice".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
            1,
            1,
            None,
        )
        .unwrap();
        assert_eq!(second_page.total, 2);
        assert_eq!(second_page.domains.len(), 1);
        assert_eq!(second_page.domains[0].domain, "beta.example");
        assert_eq!(
            BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // A different account is a different scope and must not reuse Alice's
        // aggregate. The source database has no in-range Bob visit domain.
        let bob_page = browser_activity_domains_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("bob".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
            0,
            1,
            None,
        )
        .unwrap();
        assert_eq!(bob_page.total, 1);
        assert_eq!(bob_page.domains[0].domain, "bob.example");
        assert_eq!(
            BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            2
        );

        // Changing the SQLite file invalidates the old Alice key even though
        // account and period are unchanged.
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO BrowserActivity (account, kind, timestamp, title, url, url_raw, visit_count) VALUES ('alice', 'visit', '2024-07-02 00:00:00.000', '', 'https://new.example/', '', '1')",
            [],
        ).unwrap();
        drop(conn);
        let refreshed_page = browser_activity_domains_blocking(
            path.to_string_lossy().to_string(),
            "BrowserActivity".to_string(),
            Some("alice".to_string()),
            Some("2024-07-01 00:00:00.000".to_string()),
            Some("2024-07-31 23:59:59.999".to_string()),
            0,
            10,
            None,
        )
        .unwrap();
        assert_eq!(refreshed_page.total, 3);
        assert_eq!(
            BROWSER_DOMAIN_AGGREGATION_BUILD_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            3
        );

        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod pipeline_log_supervision_tests {
    use super::*;

    fn temporary_log_path(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "windows-analysis-supervisor-log-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        directory.join("parse_logs").join("run.txt")
    }

    #[test]
    fn supervisor_log_marks_nonzero_exit_and_forced_cancel() {
        let log_path = temporary_log_path("exit-cancel");
        record_child_exit(&log_path, Some(17));
        record_forced_gui_cancel(&log_path, true);
        let text = std::fs::read_to_string(&log_path).unwrap();
        assert!(text.contains("child_exit status=nonzero exit_code=17"));
        assert!(text.contains("termination status=forced reason=gui_cancel"));
        assert!(!text.contains("status=cancelled"));
        let root = log_path.parent().and_then(Path::parent).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nonzero_partial_report_is_not_reported_as_terminal_error() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-partial-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("parse_report.json"), r#"{"status":"partial"}"#).unwrap();
        assert_eq!(terminal_pipeline_status(&root, Some(1)), "partial");
        assert_eq!(terminal_pipeline_status(&root, Some(0)), "complete");
        assert_eq!(terminal_pipeline_status(&root, Some(2)), "partial");
        std::fs::write(root.join("parse_report.json"), r#"{"status":"error"}"#).unwrap();
        assert_eq!(terminal_pipeline_status(&root, Some(1)), "error");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn forced_cancel_replaces_prior_terminal_state_with_durable_cancelled_manifest() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-cancelled-manifest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let case = case_store::create_case("case", "2026-08-23 01:02:03", &root).unwrap();
        let host =
            case_store::create_host(&case.id, "host", "/evidence", "2026-08-23 01:02:03", &root)
                .unwrap();
        let host_dir = case_store::host_dir(&root, &case.id, &host.id);
        std::fs::write(
            host_dir.join("parse_report.json"),
            r#"{"status":"ok","published":true}"#,
        )
        .unwrap();

        write_cancelled_terminal_state_at(&root, &case.id, &host.id, "cancelled-run");

        let report: Value =
            serde_json::from_slice(&std::fs::read(host_dir.join("parse_report.json")).unwrap())
                .unwrap();
        assert_eq!(report["status"], "cancelled");
        assert_eq!(report["published"], false);
        assert!(pipeline::parse_run_log_path(&host_dir, "cancelled-run")
            .with_extension("json")
            .is_file());
        assert_eq!(
            case_store::load_host(&case.id, &host.id, &root)
                .unwrap()
                .last_run_status
                .as_deref(),
            Some("cancelled")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_run_log_reads_only_bounded_preview() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-log-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let path = pipeline::parse_run_log_path(&root, "bounded-log");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'x'; 25 * 1024]).unwrap();
        let preview = parse_run_log(
            root.to_string_lossy().to_string(),
            "bounded-log".to_string(),
        )
        .unwrap();
        assert!(preview.truncated);
        assert_eq!(preview.text.len(), 24 * 1024);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parse_worker_options_accepts_log_id_with_or_without_artifact_scope() {
        let no_scope = vec!["--run-log-id=run-no-scope".to_string()];
        let (only, run_id) = parse_worker_options(&no_scope);
        assert!(only.is_none());
        assert_eq!(run_id.as_deref(), Some("run-no-scope"));

        let scoped = vec![
            "Registry,EventLog".to_string(),
            "--run-log-id=run-scoped".to_string(),
        ];
        let (only, run_id) = parse_worker_options(&scoped);
        let only = only.expect("artifact scope");
        assert!(only.contains("Registry"));
        assert!(only.contains("EventLog"));
        assert_eq!(run_id.as_deref(), Some("run-scoped"));
    }

    #[test]
    fn scheduler_reserves_only_two_hosts_and_cancelled_queue_never_gets_a_slot() {
        let mut scheduler = PipelineScheduler::default();
        for (run_id, host_id) in [
            ("run-a", "host-a"),
            ("run-b", "host-b"),
            ("run-c", "host-c"),
        ] {
            scheduler.queued.insert(run_id.to_string());
            scheduler
                .host_ids
                .insert(run_id.to_string(), host_id.to_string());
        }
        assert!(reserve_pipeline_slot(&mut scheduler, "run-a", "host-a"));
        assert!(reserve_pipeline_slot(&mut scheduler, "run-b", "host-b"));
        assert!(!reserve_pipeline_slot(&mut scheduler, "run-c", "host-c"));
        assert_eq!(scheduler.reserving.len(), MAX_HOST_PIPELINES);
        assert!(scheduler.queued.contains("run-c"));

        // A queued cancellation removes the item before a freed slot can be
        // reserved, so it cannot later start after a UI navigation.
        assert!(scheduler.queued.remove("run-c"));
        scheduler.cancelled.insert("run-c".to_string());
        scheduler.reserving.remove("run-a");
        assert!(!scheduler.queued.contains("run-c"));
        assert!(scheduler.cancelled.contains("run-c"));
    }

    #[test]
    fn scheduler_serializes_same_host_even_when_a_second_global_slot_is_free() {
        let mut scheduler = PipelineScheduler::default();
        for (run_id, host_id) in [
            ("run-a", "host-a"),
            ("run-a-again", "host-a"),
            ("run-b", "host-b"),
        ] {
            scheduler.queued.insert(run_id.to_string());
            scheduler
                .host_ids
                .insert(run_id.to_string(), host_id.to_string());
        }
        assert!(reserve_pipeline_slot(&mut scheduler, "run-a", "host-a"));
        assert!(!reserve_pipeline_slot(
            &mut scheduler,
            "run-a-again",
            "host-a"
        ));
        assert!(reserve_pipeline_slot(&mut scheduler, "run-b", "host-b"));
        assert_eq!(scheduler.reserving.len(), MAX_HOST_PIPELINES);
    }

    #[test]
    fn internal_pipeline_directories_are_never_exposed_as_categories() {
        assert!(is_internal_pipeline_directory(".parse-staging"));
        assert!(is_internal_pipeline_directory("parse_logs"));
        assert!(!is_internal_pipeline_directory("REGISTRY"));
    }

    #[test]
    fn direct_result_file_request_rejects_internal_pipeline_path() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-internal-category-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let internal = root.join("host").join(".parse-staging").join("run-1");
        std::fs::create_dir_all(&internal).unwrap();
        assert!(has_internal_pipeline_path_component(&internal));
        assert!(tauri::async_runtime::block_on(list_result_files(
            internal.to_string_lossy().to_string()
        ))
        .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod account_directory_tests {
    use super::*;

    #[test]
    fn account_directory_prefers_sam_over_profilelist_and_keeps_only_exact_sids() {
        let directory = account_directory_from_rows(vec![
            (
                "S-1-5-21-100-200-300-1001".to_string(),
                "profile-alice".to_string(),
                "ProfileList".to_string(),
            ),
            (
                "S-1-5-21-100-200-300-1001".to_string(),
                "SAM-ALICE".to_string(),
                "SAM".to_string(),
            ),
            (
                "not-a-sid".to_string(),
                "must-not-appear".to_string(),
                "SAM".to_string(),
            ),
            (
                "S-1-5-21-100-200-300-1002".to_string(),
                "".to_string(),
                "SAM".to_string(),
            ),
        ]);

        let alice = directory
            .iter()
            .find(|entry| entry.sid == "S-1-5-21-100-200-300-1001")
            .expect("SAM entry");
        assert_eq!(alice.account_name, "SAM-ALICE");
        assert_eq!(alice.source_artifact, "SAM");
        assert!(!directory
            .iter()
            .any(|entry| entry.account_name == "must-not-appear"));
        assert!(!directory.iter().any(|entry| entry.sid.ends_with("-1002")));
    }

    #[test]
    fn account_directory_has_only_safe_well_known_fallbacks() {
        let directory = account_directory_from_rows(Vec::<(String, String, String)>::new());
        assert_eq!(
            directory
                .iter()
                .find(|entry| entry.sid == "S-1-5-18")
                .map(|entry| entry.account_name.as_str()),
            Some("LocalSystem")
        );
        assert!(!directory
            .iter()
            .any(|entry| entry.sid == "S-1-5-21-9-9-9-500"));
        assert!(is_exact_sid("S-1-5-21-9-9-9-500"));
        assert!(!is_exact_sid("S-1-5-21-9-user"));
    }
    #[test]
    fn account_directory_uses_profilelist_when_sam_is_absent() {
        let directory = account_directory_from_rows(vec![(
            "S-1-5-21-42-43-44-1004".to_string(),
            "profile-only-user".to_string(),
            "ProfileList".to_string(),
        )]);
        let entry = directory
            .iter()
            .find(|entry| entry.sid == "S-1-5-21-42-43-44-1004")
            .expect("ProfileList entry");
        assert_eq!(entry.account_name, "profile-only-user");
        assert_eq!(entry.source_artifact, "ProfileList");
    }
}

fn main() {
    if let Some(code) = run_as_parse_worker() {
        std::process::exit(code);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(PipelineState::default())
        .invoke_handler(tauri::generate_handler![
            list_cases,
            create_case,
            create_host,
            rename_host,
            delete_case,
            delete_host,
            list_artifacts,
            run_host,
            cancel_pipeline,
            list_categories,
            save_master_timeline_begin,
            save_master_timeline_chunk,
            save_master_timeline_drain,
            save_master_timeline_finish,
            load_master_timeline,
            list_result_files,
            refresh_execution_history_overview,
            account_directory,
            result_provenance,
            artifact_input_files,
            parse_report,
            parse_run_log,
            read_result_file,
            read_result_file_page,
            linked_result_rows,
            result_row,
            list_column_values,
            mft_children,
            mft_search,
            usnjrnl_page,
            mft_records_page,
            mft_row,
            search_case,
            list_bookmarks,
            toggle_bookmark,
            update_bookmark_note,
            pick_folder,
            path_references,
            path_reference_accounts,
            browser_activity_summary,
            browser_activity_insights,
            browser_activity_domains,
            browser_activity_page,
            account_event_page,
            ai_referrals,
            cache_entries,
            cache_entry_body,
            browser_visit_graph,
            ai_conversations,
            wmi_subscription_events,
            powershell_search_rowids
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
