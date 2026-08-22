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

mod shellbag;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition};
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

/// The case and host setup screens need a focused form factor, while artifact
/// analysis needs enough width for the navigation tree and evidence table.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum WindowLayout {
    Setup,
    Analysis,
}

#[tauri::command]
fn set_window_layout(app: AppHandle, layout: WindowLayout) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window is unavailable".to_owned())?;
    let (width, height, center) = match layout {
        WindowLayout::Setup => (1080.0, 760.0, true),
        WindowLayout::Analysis => (1680.0, 1020.0, true),
    };
    window
        .set_size(LogicalSize::new(width, height))
        .map_err(|error| format!("failed to resize main window: {error}"))?;
    if center {
        // On macOS, `center()` immediately after `set_size()` can still use
        // the previous (compact) geometry. Center the requested analysis size
        // directly in the active monitor instead.
        if let Some(monitor) = window
            .current_monitor()
            .map_err(|error| format!("failed to read current monitor: {error}"))?
        {
            let scale = monitor.scale_factor();
            let requested_width = (width * scale).round() as i32;
            let requested_height = (height * scale).round() as i32;
            let monitor_size = monitor.size();
            let monitor_position = monitor.position();
            let x = monitor_position.x + (monitor_size.width as i32 - requested_width) / 2;
            let y = monitor_position.y + (monitor_size.height as i32 - requested_height) / 2;
            window
                .set_position(PhysicalPosition::new(x, y))
                .map_err(|error| format!("failed to position main window: {error}"))?;
        } else {
            window
                .center()
                .map_err(|error| format!("failed to center main window: {error}"))?;
        }
    }
    Ok(())
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
                .map(|m| m.filter_map(|x| x.ok()).collect())
        })
        .unwrap_or_default()
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

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id != "." && id != ".." && !id.contains(['/', '\\']) && !id.contains("..")
}

#[tauri::command]
fn delete_case(case_id: String) -> bool {
    if !valid_id(&case_id) {
        return false;
    }
    let target = cases_dir().join(&case_id);
    if target.exists() {
        std::fs::remove_dir_all(&target).is_ok()
    } else {
        false
    }
}

#[tauri::command]
fn delete_host(case_id: String, host_id: String) -> bool {
    if !valid_id(&case_id) || !valid_id(&host_id) {
        return false;
    }
    let case_dir = cases_dir().join(&case_id);
    delete_host_dir_and_bookmarks(&case_dir, &host_id)
}

fn delete_host_dir_and_bookmarks(case_dir: &Path, host_id: &str) -> bool {
    let target = case_dir.join(&host_id);
    if !target.exists() || std::fs::remove_dir_all(&target).is_err() {
        return false;
    }

    // Bookmarks are stored once per case while their source rows live under a
    // host directory. Delete only the annotations tied to the removed host
    // after its output directory has been removed. `hostName` is deliberately
    // not used: several registered hosts can share a display name.
    let bookmarks = match read_bookmarks_path(&case_dir) {
        Ok(bookmarks) => bookmarks,
        Err(_) => return false,
    };
    let bookmark_count = bookmarks.len();
    let retained: Vec<Value> = bookmarks
        .into_iter()
        .filter(|bookmark| !bookmark_belongs_to_host(bookmark, &host_id, &target))
        .collect();
    if retained.len() != bookmark_count {
        // The host directory has already been removed, so report a failed
        // cleanup instead of pretending the case-level annotations were
        // persisted. `list_bookmarks` will retry the safely attributable
        // orphan cleanup on the next load.
        if write_bookmarks_path(&case_dir, &retained).is_err() {
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
    #[serde(default)]
    only: Option<Vec<String>>,
}

#[derive(Serialize, Clone)]
struct PipelineLogEntry {
    line: String,
    stream: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineResult {
    exit_code: Option<i32>,
}

/// Tracks the running parse child so cancel can kill it outright.
#[derive(Default)]
struct PipelineState(std::sync::Mutex<Option<std::process::Child>>);

#[tauri::command]
async fn run_host(
    app: AppHandle,
    state: tauri::State<'_, PipelineState>,
    options: RunHostOptions,
) -> Result<PipelineResult, String> {
    if !valid_id(&options.case_id) || !valid_id(&options.host_id) {
        return Err("invalid case or host identifier".into());
    }
    {
        let g = state.0.lock().unwrap();
        if g.is_some() {
            return Ok(PipelineResult {
                exit_code: Some(-1),
            });
        } // already running
    }
    let cd = cases_dir();
    std::fs::create_dir_all(&cd).ok();

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
        options.case_id,
        options.host_id,
        cd.to_string_lossy().to_string(),
    ];
    if let Some(only) = options.only.filter(|v| !v.is_empty()) {
        args.push(only.join(","));
    }

    let mut child = Command::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start parser process: {}", e))?;

    // Stream the child's stdout/stderr as `pipeline-log` events.
    let pump =
        |app: &AppHandle, reader: Option<Box<dyn std::io::Read + Send>>, stream: &'static str| {
            if let Some(r) = reader {
                let app = app.clone();
                std::thread::spawn(move || {
                    use std::io::BufRead;
                    for line in std::io::BufReader::new(r).lines().map_while(Result::ok) {
                        if line.is_empty() {
                            continue;
                        }
                        let _ = app.emit(
                            "pipeline-log",
                            PipelineLogEntry {
                                line,
                                stream: stream.to_string(),
                            },
                        );
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

    *state.0.lock().unwrap() = Some(child);

    // Poll for exit so cancel_pipeline can still reach the child while it runs.
    loop {
        {
            let mut g = state.0.lock().unwrap();
            match g.as_mut() {
                None => {
                    return Ok(PipelineResult {
                        exit_code: Some(-1),
                    })
                } // cancelled
                Some(ch) => {
                    if let Ok(Some(status)) = ch.try_wait() {
                        *g = None;
                        return Ok(PipelineResult {
                            exit_code: status.code(),
                        });
                    }
                }
            }
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
fn cancel_pipeline(state: tauri::State<'_, PipelineState>) -> bool {
    let mut g = state.0.lock().unwrap();
    if let Some(mut child) = g.take() {
        let _ = child.kill();
        let _ = child.wait();
        true
    } else {
        false
    }
}

// --- commands: result browsing (in-process sqlite) -------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryEntry {
    name: String,
    full_path: String,
}

#[tauri::command]
fn list_categories(host_dir: String) -> Vec<CategoryEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&host_dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                let name = e.file_name().to_string_lossy().to_string();
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

#[tauri::command]
fn list_result_files(category_dir: String) -> Vec<ResultFileEntry> {
    let base = PathBuf::from(&category_dir);
    let mut out = Vec::new();
    find_result_files(&base, &base, &mut out);
    out.sort_by(|a, b| {
        a.relative_path
            .cmp(&b.relative_path)
            .then(a.table_name.cmp(&b.table_name))
    });
    out
}

/// Upgrade only the derived ExecutionHistory table when it predates source
/// record keys or the complete Prefetch execution-cache fields. This avoids an
/// expensive evidence reparse while making existing saved hosts participate in
/// cross-view bookmark synchronization and full Prefetch detail.
#[tauri::command]
fn refresh_execution_history_overview(host_dir: String) -> Result<bool, String> {
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
        detail: "레지스트리 하이브를 파싱하며 삭제된 셀 복구를 포함합니다.".to_string(),
    }];
    if let Some(parent) = hive.parent() {
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.to_ascii_lowercase().starts_with("amcache.hve.log") {
                    inputs.push(ArtifactInputFile {
                        name,
                        kind: "transactionLog".to_string(),
                        detail: "트랜잭션 로그를 함께 적용해 복구 가능한 변경 사항을 파싱합니다."
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
fn browser_activity_domains_blocking(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<BrowserDomainStatsPage, String> {
    let domains = browser_visit_domains_cached(
        &full_path,
        &table_name,
        account.as_deref(),
        start.as_deref(),
        end.as_deref(),
    )?;
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
async fn browser_activity_domains(
    full_path: String,
    table_name: String,
    account: Option<String>,
    start: Option<String>,
    end: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<BrowserDomainStatsPage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        browser_activity_domains_blocking(full_path, table_name, account, start, end, offset, limit)
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

#[tauri::command]
fn read_result_file(full_path: String, table_name: Option<String>) -> Result<CsvData, String> {
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
    let sql = if is_cache {
        format!(
            "SELECT rowid AS __rowid, {} FROM {} ORDER BY rowid DESC LIMIT 1000",
            select,
            q(&table)
        )
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

/// Reads a bounded page of evidence rows connected to a selected record.
///
/// The match column is verified against SQLite metadata before it is used as
/// an identifier. Values, search text, paging and limits always remain bound
/// parameters, so a long Prefetch loaded-file list never needs to be copied
/// into the webview just to render the first five rows.
#[tauri::command]
fn linked_result_rows(
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

#[tauri::command]
fn result_row(full_path: String, table_name: String, rowid: i64) -> Result<ResultRow, String> {
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

#[derive(Serialize)]
struct ColumnValue {
    value: String,
    count: i64,
}

#[tauri::command]
fn list_column_values(
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
fn mft_children(full_path: String, parent_entry: i64) -> Vec<Map<String, Value>> {
    let conn = match open_ro(&full_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE parent_entry = ?1 AND entry != ?1 ORDER BY is_directory DESC, file_name COLLATE NOCASE", q(MFT_TABLE));
    let pe = parent_entry.to_string();
    query_rows(&conn, &sql, &[&pe]).unwrap_or_default()
}

#[tauri::command]
fn mft_search(full_path: String, query: String, limit: i64) -> Vec<Map<String, Value>> {
    let conn = match open_ro(&full_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let like = format!("%{}%", query);
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE file_name LIKE ?1 OR path LIKE ?1 ORDER BY is_directory DESC, path COLLATE NOCASE LIMIT ?2", q(MFT_TABLE));
    query_rows(&conn, &sql, &[&like, &limit]).unwrap_or_default()
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

#[derive(Deserialize)]
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
    columns: Vec<String>,
    row: Map<String, Value>,
}

#[tauri::command]
fn search_case(query: String, hosts: Vec<SearchHost>) -> Vec<SearchHit> {
    let query = query.trim().to_string();
    if query.len() < 2 {
        return vec![];
    }
    let like = format!(
        "%{}%",
        query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    let ql = query.to_lowercase();
    const PER_TABLE: usize = 50;
    const TOTAL: usize = 600;
    let mut hits = Vec::new();
    for host in &hosts {
        let mut files = Vec::new();
        collect_sqlite(Path::new(&host.dir), &mut files);
        for fp in files {
            let conn = match open_ro(&fp.to_string_lossy()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let file_name = fp
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            for table in table_names(&conn) {
                let cols = table_columns(&conn, &table);
                if cols.is_empty() {
                    continue;
                }
                let where_ = cols
                    .iter()
                    .map(|c| format!("{} LIKE ?1 ESCAPE '\\'", q(c)))
                    .collect::<Vec<_>>()
                    .join(" OR ");
                let sql = format!(
                    "SELECT rowid AS __rowid, * FROM {} WHERE {} LIMIT {}",
                    q(&table),
                    where_,
                    PER_TABLE
                );
                let rows = match query_rows(&conn, &sql, &[&like]) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                for row in rows {
                    let match_column = cols
                        .iter()
                        .find(|c| {
                            row.get(*c)
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_lowercase().contains(&ql))
                                .unwrap_or(false)
                        })
                        .cloned()
                        .unwrap_or_default();
                    let rowid = row.get("__rowid").and_then(|v| v.as_i64()).unwrap_or(0);
                    hits.push(SearchHit {
                        host_id: host.id.clone(),
                        host_name: host.name.clone(),
                        file_name: file_name.clone(),
                        table_name: table.clone(),
                        full_path: fp.to_string_lossy().to_string(),
                        rowid,
                        match_column,
                        columns: cols.clone(),
                        row,
                    });
                    if hits.len() >= TOTAL {
                        return hits;
                    }
                }
            }
        }
    }
    hits
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
fn cache_entries(host_dir: String) -> Vec<CacheMeta> {
    let dir = PathBuf::from(&host_dir).join("BROWSER");
    let mut out = Vec::new();
    let files = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("_Chrome_Cache.sqlite"))
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
                    .map(|n| n.to_string_lossy().ends_with("_Chrome_Cache.sqlite"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(_) => return CacheBodyPreview::default(),
    };
    // A BrowserActivity account is derived from this exact source filename.
    // Check it first rather than scanning every account database for every
    // drawer open. Keep the remaining databases as a correctness fallback for
    // older data where the recorded account and filename do not agree.
    let expected = format!("{}_Chrome_Cache.sqlite", account);
    files.sort_by(|left, right| {
        let left_exact = left
            .file_name()
            .is_some_and(|name| name.to_string_lossy() == expected);
        let right_exact = right
            .file_name()
            .is_some_and(|name| name.to_string_lossy() == expected);
        right_exact.cmp(&left_exact).then_with(|| left.cmp(right))
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

/// AI provider hosts we look for in the cache.
const AI_HOSTS: &[&str] = &[
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "gemini.google.com",
    "bard.google.com",
];

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

fn ai_provider(url: &str) -> Option<&'static str> {
    let host = url.split('/').nth(2).unwrap_or("").to_ascii_lowercase();
    if host == "chatgpt.com" || host == "chat.openai.com" {
        Some("ChatGPT")
    } else if host == "claude.ai" {
        Some("Claude")
    } else if host == "gemini.google.com" || host == "bard.google.com" {
        Some("Gemini")
    } else {
        None
    }
}

/// Accept only cache responses that are known to contain a complete conversation
/// payload. AI hosts emit many JSON responses (settings, stream state, assets),
/// which must not be presented as a conversation to an analyst.
fn is_ai_conversation_payload(
    provider: &str,
    url: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let endpoint = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    match provider {
        // The individual endpoint (not `/stream_status` or `/textdocs`) carries
        // the complete ChatGPT tree under `mapping`.
        "ChatGPT" => {
            endpoint
                .split("/backend-api/conversation/")
                .nth(1)
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
                && object
                    .get("mapping")
                    .is_some_and(serde_json::Value::is_object)
        }
        // Claude's complete chat endpoint stores actual turn objects. Other
        // organization/skills JSON is intentionally excluded.
        "Claude" => {
            endpoint.contains("/chat_conversations/")
                && (object
                    .get("chat_messages")
                    .is_some_and(serde_json::Value::is_array)
                    || object
                        .get("messages")
                        .is_some_and(serde_json::Value::is_array))
        }
        // Gemini conversations are returned by this concrete conversation API;
        // pages, widget responses and account JSON are not conversation records.
        "Gemini" => {
            endpoint.contains("BardFrontendService/GetConversation")
                && (object
                    .get("conversation")
                    .is_some_and(serde_json::Value::is_object)
                    || object
                        .get("messages")
                        .is_some_and(serde_json::Value::is_array))
        }
        _ => false,
    }
}

fn json_time_field(object: &serde_json::Map<String, serde_json::Value>, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| object.get(*name))
        .and_then(|value| match value {
            serde_json::Value::String(value) if !value.is_empty() => Some(value.clone()),
            serde_json::Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Scans the BROWSER cache SQLite files for AI conversation JSON bodies and
/// returns the parsed conversations. Runs in Rust so no GB of base64 blobs
/// are transferred over IPC — only the already-small JSON texts.
fn ai_conversations_blocking(
    host_dir: String,
    query: AiConversationQuery,
) -> Result<AiConversationPage, String> {
    let dir = PathBuf::from(&host_dir).join("BROWSER");
    let mut conversations = Vec::new();
    let files = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("_Chrome_Cache.sqlite"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(format!("AI 대화 캐시 목록을 읽을 수 없습니다: {error}")),
    };
    const SCAN_CAP: usize = 2_000;
    let mut total = 0usize;
    let mut source_failures = Vec::new();
    let source_count = files.len();
    let mut sources_read = 0usize;
    for f in files {
        if total >= SCAN_CAP {
            break;
        }
        let source_name = f
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "알 수 없는 캐시 파일".to_string());
        let conn = match open_ro(&f.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => {
                source_failures.push(format!("{source_name}: 캐시 파일을 열 수 없습니다"));
                continue;
            }
        };
        // Only read AI-host rows that have JSON bodies — avoid loading images/JS.
        let ai_like: Vec<String> = AI_HOSTS.iter().map(|h| format!("%{}%", h)).collect();
        let placeholders: String = ai_like
            .iter()
            .enumerate()
            .map(|(i, _)| format!("url LIKE ?{}", i + 1))
            .collect::<Vec<_>>()
            .join(" OR ");
        let sql = format!(
            "SELECT url, account, COALESCE(NULLIF(response_time, ''), NULLIF(request_time, ''), NULLIF(creation_time, ''), ''), body_b64 FROM CacheEntries \
             WHERE body_b64 IS NOT NULL AND body_b64 != '' \
             AND content_type LIKE '%json%' AND ({}) LIMIT 500",
            placeholders
        );
        let params: Vec<&dyn rusqlite::ToSql> =
            ai_like.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => {
                source_failures.push(format!("{source_name}: 캐시 테이블을 읽을 수 없습니다"));
                continue;
            }
        };
        let rows = match stmt.query_map(params.as_slice(), |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        }) {
            Ok(it) => it,
            Err(_) => {
                source_failures.push(format!("{source_name}: AI 대화 행을 읽을 수 없습니다"));
                continue;
            }
        };
        sources_read += 1;

        for row in rows {
            let (url, account, observation_time, body_b64) = match row {
                Ok(row) => row,
                Err(_) => {
                    source_failures.push(format!("{source_name}: AI 대화 행 일부를 읽을 수 없습니다"));
                    // A malformed row is source-local. Preserve results from
                    // prior rows and other profiles, but do not silently skip
                    // the read error as if the cache had no conversation.
                    break;
                }
            };
            if query
                .start
                .as_ref()
                .is_some_and(|start| !start.is_empty() && observation_time < *start)
                || query
                    .end
                    .as_ref()
                    .is_some_and(|end| !end.is_empty() && observation_time > *end)
            {
                continue;
            }
            // Decode base64 → UTF-8 in Rust; skip if not valid JSON text.
            let text =
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body_b64)
                {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
            // Strip anti-hijack prefix.
            let cleaned = text.trim_start_matches(|c: char| {
                c == ')' || c == ']' || c == '\'' || c == '\n' || c == '\r' || c == ' '
            });
            // Must be a concrete provider conversation endpoint with its
            // provider-specific conversation schema; host JSON alone is not
            // sufficient evidence of a user conversation.
            let val: serde_json::Value = match serde_json::from_str(cleaned) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let obj = match val.as_object() {
                Some(o) => o,
                None => continue,
            };
            let provider = match ai_provider(&url) {
                Some(provider) => provider,
                None => continue,
            };
            if !is_ai_conversation_payload(provider, &url, obj) {
                continue;
            }
            let title = obj
                .get("title")
                .or_else(|| obj.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = json_time_field(obj, &["create_time", "created_at"]);
            let updated_at = json_time_field(obj, &["update_time", "updated_at"]);
            let raw_json = serde_json::to_string_pretty(&val).unwrap_or(cleaned.to_string());
            conversations.push(AiConversation {
                provider: provider.to_string(),
                account,
                title,
                date: observation_time,
                created_at,
                updated_at,
                url,
                raw_json,
            });
            total += 1;
        }
    }
    conversations.sort_by(|left, right| {
        right
            .date
            .cmp(&left.date)
            .then_with(|| left.url.cmp(&right.url))
    });
    let page = conversations
        .into_iter()
        .skip(query.offset)
        .take(query.limit.clamp(1, 100))
        .collect();
    Ok(AiConversationPage {
        conversations: page,
        total,
        source_count,
        sources_read,
        source_failures,
    })
}

/// Conversation discovery decodes and validates cached JSON. It is bounded,
/// but can still be CPU and disk intensive across several browser profiles,
/// so it must never run on the command path that serves the interactive view.
#[tauri::command]
async fn ai_conversations(host_dir: String, query: AiConversationQuery) -> Result<AiConversationPage, String> {
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

/// The account a per-user artifact belongs to: the path component right after
/// a LNK/JUMPLIST collection folder (…/LNK/<account>/Recent/…).
fn account_from_source(src: &str) -> String {
    let parts: Vec<&str> = src.split(['/', '\\']).collect();
    for (i, p) in parts.iter().enumerate() {
        let up = p.to_uppercase();
        if (up == "LNK" || up == "JUMPLIST") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    String::new()
}

/// Every cross-artifact reference to a filesystem path for this host, so the
/// $MFT explorer can tag files that also appear in a JumpList (etc.) and show
/// the details on demand. Returned as a flat list; the frontend indexes it by
/// `path`.
#[tauri::command]
fn path_references(host_dir: String) -> Vec<PathReference> {
    let mut out = Vec::new();
    let jl = PathBuf::from(&host_dir)
        .join("JUMPLIST")
        .join("JumpList_Entries.sqlite");
    if let Ok(conn) = open_ro(&jl.to_string_lossy()) {
        let sql = "SELECT rowid AS __rowid, target_path, app_id, jumplist_type, arguments, working_directory, \
                   machine_id, timestamp, created_time, modified_time, _source_file \
                   FROM JumpList_Entries WHERE target_path IS NOT NULL AND target_path != ''";
        if let Ok(rows) = query_rows(&conn, sql, &[]) {
            for r in rows {
                let get = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let target = get("target_path");
                if target.is_empty() {
                    continue;
                }
                let src = get("_source_file");
                let rowid = r.get("__rowid").and_then(|v| v.as_i64()).unwrap_or(-1);
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
                ] {
                    let v = get(k);
                    if !v.is_empty() {
                        fields.insert(k.to_string(), Value::from(v));
                    }
                }
                out.push(PathReference {
                    path: to_volume_relative(&target),
                    kind: "Jumplist".to_string(),
                    account: account_from_source(&src),
                    label: target.clone(),
                    fields,
                    full_path: jl.to_string_lossy().to_string(),
                    table_name: "JumpList_Entries".to_string(),
                    rowid,
                });
            }
        }
    }
    out.extend(shellbag_references(&host_dir));
    out
}

/// Decode shellbags from the host's registry dumps and turn them into path
/// references (kind = "Shellbag").
fn shellbag_references(host_dir: &str) -> Vec<PathReference> {
    let reg_dir = PathBuf::from(host_dir).join("REGISTRY");
    let mut rows: Vec<shellbag::BagRow> = Vec::new();
    let files = match std::fs::read_dir(&reg_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect::<Vec<_>>(),
        Err(_) => return vec![],
    };
    for f in files {
        // Account = the hive's user prefix (Administrator_UsrClass.dat -> Administrator).
        let stem = f
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let account = stem.split('_').next().unwrap_or(&stem).to_string();
        let conn = match open_ro(&f.to_string_lossy()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let sql = "SELECT key_path, value_name, value_data FROM Registry \
                   WHERE lower(key_path) LIKE '%bagmru%' AND value_name GLOB '[0-9]*' \
                   AND value_data IS NOT NULL AND value_data != ''";
        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let it = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        });
        if let Ok(it) = it {
            for row in it.filter_map(|x| x.ok()) {
                let (key_path, value_name, hex) = row;
                let data = unhex(&hex);
                if data.is_empty() {
                    continue;
                }
                rows.push(shellbag::BagRow {
                    key_path,
                    value_name,
                    data,
                    account: account.clone(),
                });
            }
        }
    }
    shellbag::reconstruct(rows)
        .into_iter()
        .map(|s| {
            let mut fields = Map::new();
            fields.insert("path".into(), Value::from(s.display.clone()));
            if !s.account.is_empty() {
                fields.insert("account".into(), Value::from(s.account.clone()));
            }
            PathReference {
                path: s.path,
                kind: "Shellbag".to_string(),
                account: s.account,
                label: s.display,
                fields,
                full_path: String::new(),
                table_name: String::new(),
                rowid: -1,
            }
        })
        .collect()
}

/// Decode a lowercase/uppercase hex string to bytes ("" or odd length -> empty).
fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Vec::new();
    }
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        match (hv(b[i]), hv(b[i + 1])) {
            (Some(h), Some(l)) => out.push(h << 4 | l),
            _ => return Vec::new(),
        }
        i += 2;
    }
    out
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
    normalize_bookmark_path(Path::new(full_path))
        .starts_with(normalize_bookmark_path(directory))
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
    if let Some(host_id) = bookmark.get("hostId").and_then(Value::as_str).filter(|id| !id.is_empty()) {
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
    if let Err(error) = std::fs::write(&temporary, serialized)
        .and_then(|()| std::fs::rename(&temporary, &target))
    {
        let _ = std::fs::remove_file(temporary);
        return Err(format!("북마크 저장에 실패했습니다: {error}"));
    }
    Ok(())
}

fn read_bookmarks(case_dir: &str) -> Result<Vec<Value>, String> {
    read_bookmarks_path(Path::new(case_dir))
}

fn write_bookmarks(case_dir: &str, bookmarks: &[Value]) -> Result<(), String> {
    write_bookmarks_path(Path::new(case_dir), bookmarks)
}

#[tauri::command]
fn list_bookmarks(case_dir: String) -> Result<Vec<Value>, String> {
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
    #[serde(default)]
    host_id: Option<String>,
    #[serde(default)]
    host_name: Option<String>,
}

#[tauri::command]
fn toggle_bookmark(case_dir: String, entry: BookmarkInput) -> Result<Vec<Value>, String> {
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
    let only = args.get(5).filter(|s| !s.is_empty()).map(|s| {
        s.split(',')
            .map(|x| x.to_string())
            .collect::<std::collections::HashSet<String>>()
    });
    // Sink stays unset, so pipeline prints progress to stdout for the parent.
    match pipeline::run_host(case_id, host_id, &cases_dir, only) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("[!] {}", e);
            Some(1)
        }
    }
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
            host_id: Some("host-a".to_string()),
            host_name: Some("HOST-A".to_string()),
        }
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
        ).unwrap();

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

        let after_browser_toggle = toggle_bookmark(case_dir.clone(), entry("BrowserActivity")).unwrap();
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
                bookmark("removed-by-id", "/missing/source.sqlite", Some("removed-host")),
                // Legacy annotation: match its normalised source directory.
                bookmark("removed-by-path", removed_path, None),
                bookmark("retained-by-id", retained_path.clone(), Some("retained-host")),
                // Host identity wins over a stale/misrecorded source path.
                bookmark("retained-conflicting-path", case_dir.join("removed-host").join("old.sqlite").to_string_lossy(), Some("retained-host")),
                bookmark("retained-legacy", retained_path, None),
                bookmark("outside-legacy", outside_path, None),
            ],
        ).unwrap();

        assert!(delete_host_dir_and_bookmarks(&case_dir, "removed-host"));
        assert!(!case_dir.join("removed-host").exists());
        let ids: Vec<String> = read_bookmarks_path(&case_dir)
            .unwrap()
            .iter()
            .filter_map(|value| value.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert_eq!(ids, ["retained-by-id", "retained-conflicting-path", "retained-legacy", "outside-legacy"]);

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
                bookmark("retained-by-id", retained_path.clone(), Some("retained-host")),
                // Do not infer a missing source row as a deleted host. The
                // host still exists, so this remains the analyst's bookmark.
                bookmark("retained-legacy", retained_path, None),
                bookmark("stale-by-id", "/missing/source.sqlite", Some("removed-host")),
                bookmark("stale-legacy", stale_path, None),
                // Source paths outside this case are not safe to attribute.
                bookmark("outside-legacy", outside_path, None),
            ],
        ).unwrap();

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
mod browser_activity_tests {
    use super::*;

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
    fn ai_conversation_detection_excludes_chatgpt_non_conversation_json() {
        let payload = serde_json::json!({ "mapping": { "node": {} } });
        let object = payload.as_object().unwrap();
        assert!(is_ai_conversation_payload(
            "ChatGPT",
            "https://chatgpt.com/backend-api/conversation/123e4567-e89b-12d3-a456-426614174000",
            object,
        ));
        assert!(!is_ai_conversation_payload(
            "ChatGPT",
            "https://chatgpt.com/backend-api/conversation/123e4567-e89b-12d3-a456-426614174000/stream_status",
            object,
        ));
        assert!(!is_ai_conversation_payload(
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
            json_time_field(object, &["create_time", "created_at"]),
            "1784525759.692772"
        );
        assert_eq!(
            json_time_field(object, &["update_time", "updated_at"]),
            "2026-07-21T16:00:00Z"
        );
    }

    #[test]
    fn ai_conversation_scan_reports_unreadable_cache_sources() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-ai-conversation-failure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let browser_dir = root.join("BROWSER");
        std::fs::create_dir_all(&browser_dir).unwrap();
        std::fs::write(browser_dir.join("broken_Chrome_Cache.sqlite"), "not sqlite").unwrap();

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
        assert_eq!(page.source_count, 1);
        assert_eq!(page.sources_read, 0);
        assert_eq!(page.source_failures.len(), 1);
        assert!(page.source_failures[0].contains("broken_Chrome_Cache.sqlite"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_conversation_scan_reports_cache_row_decode_errors() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-ai-conversation-row-failure-{}-{}",
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
        conn.execute_batch("CREATE TABLE CacheEntries (url TEXT, account TEXT, response_time TEXT, request_time TEXT, creation_time TEXT, content_type TEXT, body_b64 BLOB)").unwrap();
        // The row passes the SQL predicate but cannot be decoded as a text
        // base64 payload. It must be surfaced as a source failure, not dropped.
        conn.execute(
            "INSERT INTO CacheEntries (url, account, response_time, content_type, body_b64) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "https://chatgpt.com/backend-api/conversation/abc",
                "alice",
                "2026-08-01 00:00:00.000",
                "application/json",
                vec![0_u8, 159_u8]
            ],
        ).unwrap();
        drop(conn);

        let page = ai_conversations_blocking(
            root.to_string_lossy().to_string(),
            AiConversationQuery { start: None, end: None, offset: 0, limit: 10 },
        ).unwrap();
        assert!(page.conversations.is_empty());
        assert_eq!(page.source_count, 1);
        assert_eq!(page.sources_read, 1);
        assert_eq!(page.source_failures.len(), 1);
        assert!(page.source_failures[0].contains("행 일부"));

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

fn main() {
    if let Some(code) = run_as_parse_worker() {
        std::process::exit(code);
    }
    // Debug: `--__shellbag <hostDir>` prints reconstructed shellbag refs.
    let a: Vec<String> = std::env::args().collect();
    if a.len() >= 3 && a[1] == "--__shellbag" {
        for r in shellbag_references(&a[2]) {
            println!("[{}] {}  {}", r.account, r.label, r.path);
        }
        std::process::exit(0);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(PipelineState::default())
        .invoke_handler(tauri::generate_handler![
            set_window_layout,
            list_cases,
            create_case,
            create_host,
            delete_case,
            delete_host,
            list_artifacts,
            run_host,
            cancel_pipeline,
            list_categories,
            list_result_files,
            refresh_execution_history_overview,
            result_provenance,
            artifact_input_files,
            parse_report,
            read_result_file,
            linked_result_rows,
            result_row,
            list_column_values,
            mft_children,
            mft_search,
            mft_row,
            search_case,
            list_bookmarks,
            toggle_bookmark,
            update_bookmark_note,
            pick_folder,
            path_references,
            browser_activity_summary,
            browser_activity_insights,
            browser_activity_domains,
            browser_activity_page,
            account_event_page,
            ai_referrals,
            cache_entries,
            cache_entry_body,
            ai_conversations
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
