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

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter};
use wina_core::{case_store, pipeline};

// --- paths -----------------------------------------------------------------

/// True when running from a `cargo`/`tauri dev` build tree (exe under target/).
fn is_dev_build() -> bool {
    std::env::current_exe().ok()
        .map(|p| { let s = p.to_string_lossy().to_lowercase(); s.contains("/target/debug/") || s.contains("/target/release/") || s.contains("\\target\\debug\\") || s.contains("\\target\\release\\") })
        .unwrap_or(false)
}

fn dev_repo_path(rel: &str) -> PathBuf {
    // viewer/src-tauri -> repo root
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(".."); p.push("..");
    for part in rel.split('/') { p.push(part); }
    p
}

fn cases_dir() -> PathBuf {
    if let Ok(d) = std::env::var("WINA_CASES_DIR") { return PathBuf::from(d); }
    if is_dev_build() { return dev_repo_path("cases"); }
    // Packaged: a `cases` folder next to the app executable.
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("cases")))
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
        dir: case_store::host_dir(cd, case_id, &h.id).to_string_lossy().to_string(),
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
        dir: case_store::case_dir(cd, &c.id).to_string_lossy().to_string(),
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
        ValueRef::Blob(b) => Value::from(b.iter().map(|x| format!("{:02x}", x)).collect::<String>()),
    }
}

fn q(ident: &str) -> String { format!("\"{}\"", ident.replace('"', "\"\"")) }

fn query_rows(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<Vec<Map<String, Value>>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt.query_map(params, |r| {
        let mut obj = Map::new();
        for (i, name) in cols.iter().enumerate() {
            obj.insert(name.clone(), cell(r.get_ref(i)?));
        }
        Ok(obj)
    }).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows { out.push(row.map_err(|e| e.to_string())?); }
    Ok(out)
}

fn table_names(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY rowid")
        .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0)).map(|m| m.filter_map(|x| x.ok()).collect()))
        .unwrap_or_default()
}

fn first_table(conn: &Connection) -> Option<String> { table_names(conn).into_iter().next() }

fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info({})", q(table)))
        .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(1)).map(|m| m.filter_map(|x| x.ok()).collect()))
        .unwrap_or_default()
}

const EMPTY_SQLITE_MAX_BYTES: u64 = 100;

fn collect_sqlite(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { collect_sqlite(&p, out); }
            else if p.extension().map(|x| x == "sqlite").unwrap_or(false)
                && std::fs::metadata(&p).map(|m| m.len() > EMPTY_SQLITE_MAX_BYTES).unwrap_or(false) {
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
        Ok(cases) => ListCasesResult { cases: cases.iter().map(|c| gui_case(c, &cd)).collect(), error: None },
        Err(e) => ListCasesResult { cases: vec![], error: Some(e.to_string()) },
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
    let h = case_store::create_host(&case_id, &name, &target_dir, &case_store::now(), &cd).map_err(|e| e.to_string())?;
    Ok(gui_host(&case_id, &h, &cd))
}

#[tauri::command]
fn delete_case(case_id: String) -> bool {
    let target = cases_dir().join(&case_id);
    if target.exists() { std::fs::remove_dir_all(&target).is_ok() } else { false }
}

#[tauri::command]
fn delete_host(case_id: String, host_id: String) -> bool {
    let target = cases_dir().join(&case_id).join(&host_id);
    if target.exists() { std::fs::remove_dir_all(&target).is_ok() } else { false }
}

#[tauri::command]
fn list_artifacts() -> Vec<String> {
    pipeline::ARTIFACT_NAMES.iter().map(|s| s.to_string()).collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunHostOptions { case_id: String, host_id: String, #[serde(default)] only: Option<Vec<String>> }

#[derive(Serialize, Clone)]
struct PipelineLogEntry { line: String, stream: String }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineResult { exit_code: Option<i32> }

/// Tracks the running parse child so cancel can kill it outright.
#[derive(Default)]
struct PipelineState(std::sync::Mutex<Option<std::process::Child>>);

#[tauri::command]
async fn run_host(app: AppHandle, state: tauri::State<'_, PipelineState>, options: RunHostOptions) -> Result<PipelineResult, String> {
    {
        let g = state.0.lock().unwrap();
        if g.is_some() { return Ok(PipelineResult { exit_code: Some(-1) }); } // already running
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
        PARSE_FLAG.to_string(), options.case_id, options.host_id,
        cd.to_string_lossy().to_string(),
    ];
    if let Some(only) = options.only.filter(|v| !v.is_empty()) { args.push(only.join(",")); }

    let mut child = Command::new(exe).args(&args)
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("failed to start parser process: {}", e))?;

    // Stream the child's stdout/stderr as `pipeline-log` events.
    let pump = |app: &AppHandle, reader: Option<Box<dyn std::io::Read + Send>>, stream: &'static str| {
        if let Some(r) = reader {
            let app = app.clone();
            std::thread::spawn(move || {
                use std::io::BufRead;
                for line in std::io::BufReader::new(r).lines().map_while(Result::ok) {
                    if line.is_empty() { continue; }
                    let _ = app.emit("pipeline-log", PipelineLogEntry { line, stream: stream.to_string() });
                }
            });
        }
    };
    pump(&app, child.stdout.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), "stdout");
    pump(&app, child.stderr.take().map(|e| Box::new(e) as Box<dyn std::io::Read + Send>), "stderr");

    *state.0.lock().unwrap() = Some(child);

    // Poll for exit so cancel_pipeline can still reach the child while it runs.
    loop {
        {
            let mut g = state.0.lock().unwrap();
            match g.as_mut() {
                None => return Ok(PipelineResult { exit_code: Some(-1) }), // cancelled
                Some(ch) => {
                    if let Ok(Some(status)) = ch.try_wait() {
                        *g = None;
                        return Ok(PipelineResult { exit_code: status.code() });
                    }
                }
            }
        }
        tokio_sleep(120).await;
    }
}

async fn tokio_sleep(ms: u64) {
    // Small helper so the poll loop yields instead of blocking an async worker.
    tauri::async_runtime::spawn_blocking(move || std::thread::sleep(std::time::Duration::from_millis(ms)))
        .await.ok();
}

#[tauri::command]
fn cancel_pipeline(state: tauri::State<'_, PipelineState>) -> bool {
    let mut g = state.0.lock().unwrap();
    if let Some(mut child) = g.take() { let _ = child.kill(); let _ = child.wait(); true } else { false }
}

// --- commands: result browsing (in-process sqlite) -------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryEntry { name: String, full_path: String }

#[tauri::command]
fn list_categories(host_dir: String) -> Vec<CategoryEntry> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&host_dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                let name = e.file_name().to_string_lossy().to_string();
                out.push(CategoryEntry { full_path: e.path().to_string_lossy().to_string(), name });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultFileEntry {
    name: String, file_name: String, table_name: String,
    relative_path: String, full_path: String, row_count: i64,
}

fn find_result_files(dir: &Path, base: &Path, out: &mut Vec<ResultFileEntry>) {
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() { find_result_files(&p, base, out); continue; }
        if p.extension().map(|x| x != "sqlite").unwrap_or(true) { continue; }
        if std::fs::metadata(&p).map(|m| m.len() <= EMPTY_SQLITE_MAX_BYTES).unwrap_or(true) { continue; }
        let conn = match open_ro(&p.to_string_lossy()) { Ok(c) => c, Err(_) => continue };
        let file_name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().to_string();
        for t in table_names(&conn) {
            let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {}", q(&t)), [], |r| r.get(0)).unwrap_or(0);
            out.push(ResultFileEntry {
                name: t.clone(), file_name: file_name.clone(), table_name: t,
                relative_path: rel.clone(), full_path: p.to_string_lossy().to_string(), row_count: count,
            });
        }
    }
}

#[tauri::command]
fn list_result_files(category_dir: String) -> Vec<ResultFileEntry> {
    let base = PathBuf::from(&category_dir);
    let mut out = Vec::new();
    find_result_files(&base, &base, &mut out);
    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path).then(a.table_name.cmp(&b.table_name)));
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CsvData { columns: Vec<String>, rows: Vec<Map<String, Value>>, row_count: i64 }

#[tauri::command]
fn read_result_file(full_path: String, table_name: Option<String>) -> Result<CsvData, String> {
    let conn = open_ro(&full_path)?;
    let table = match table_name.or_else(|| first_table(&conn)) { Some(t) => t, None => return Ok(CsvData { columns: vec![], rows: vec![], row_count: 0 }) };
    let columns = table_columns(&conn, &table);
    let rows = query_rows(&conn, &format!("SELECT rowid AS __rowid, * FROM {}", q(&table)), &[])?;
    let row_count = rows.len() as i64;
    Ok(CsvData { columns, rows, row_count })
}

#[derive(Serialize)]
struct ColumnValue { value: String, count: i64 }

#[tauri::command]
fn list_column_values(full_path: String, column: String, table_name: Option<String>) -> Vec<ColumnValue> {
    let conn = match open_ro(&full_path) { Ok(c) => c, Err(_) => return vec![] };
    let table = match table_name.or_else(|| first_table(&conn)) { Some(t) => t, None => return vec![] };
    if !table_columns(&conn, &table).contains(&column) { return vec![]; }
    let sql = format!("SELECT {c} AS value, COUNT(*) AS count FROM {t} GROUP BY {c} ORDER BY count DESC", c = q(&column), t = q(&table));
    let mut stmt = match conn.prepare(&sql) { Ok(s) => s, Err(_) => return vec![] };
    let rows = stmt.query_map([], |r| {
        let value = match r.get_ref(0) { Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(), Ok(ValueRef::Integer(i)) => i.to_string(), Ok(ValueRef::Real(f)) => f.to_string(), _ => String::new() };
        Ok(ColumnValue { value, count: r.get(1)? })
    });
    match rows { Ok(it) => it.filter_map(|x| x.ok()).collect(), Err(_) => vec![] }
}

const MFT_TABLE: &str = "MFT_Records";

#[tauri::command]
fn mft_children(full_path: String, parent_entry: i64) -> Vec<Map<String, Value>> {
    let conn = match open_ro(&full_path) { Ok(c) => c, Err(_) => return vec![] };
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE parent_entry = ?1 AND entry != ?1 ORDER BY is_directory DESC, file_name COLLATE NOCASE", q(MFT_TABLE));
    let pe = parent_entry.to_string();
    query_rows(&conn, &sql, &[&pe]).unwrap_or_default()
}

#[tauri::command]
fn mft_search(full_path: String, query: String, limit: i64) -> Vec<Map<String, Value>> {
    let conn = match open_ro(&full_path) { Ok(c) => c, Err(_) => return vec![] };
    let like = format!("%{}%", query);
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE file_name LIKE ?1 OR path LIKE ?1 ORDER BY is_directory DESC, path COLLATE NOCASE LIMIT ?2", q(MFT_TABLE));
    query_rows(&conn, &sql, &[&like, &limit]).unwrap_or_default()
}

#[tauri::command]
fn mft_row(full_path: String, rowid: i64) -> Option<Map<String, Value>> {
    let conn = open_ro(&full_path).ok()?;
    let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE rowid = ?1", q(MFT_TABLE));
    query_rows(&conn, &sql, &[&rowid]).ok().and_then(|mut v| v.drain(..).next())
}

#[derive(Deserialize)]
struct SearchHost { id: String, name: String, dir: String }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    host_id: String, host_name: String, file_name: String, table_name: String,
    full_path: String, rowid: i64, match_column: String, columns: Vec<String>, row: Map<String, Value>,
}

#[tauri::command]
fn search_case(query: String, hosts: Vec<SearchHost>) -> Vec<SearchHit> {
    let query = query.trim().to_string();
    if query.len() < 2 { return vec![]; }
    let like = format!("%{}%", query.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let ql = query.to_lowercase();
    const PER_TABLE: usize = 50;
    const TOTAL: usize = 600;
    let mut hits = Vec::new();
    for host in &hosts {
        let mut files = Vec::new();
        collect_sqlite(Path::new(&host.dir), &mut files);
        for fp in files {
            let conn = match open_ro(&fp.to_string_lossy()) { Ok(c) => c, Err(_) => continue };
            let file_name = fp.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            for table in table_names(&conn) {
                let cols = table_columns(&conn, &table);
                if cols.is_empty() { continue; }
                let where_ = cols.iter().map(|c| format!("{} LIKE ?1 ESCAPE '\\'", q(c))).collect::<Vec<_>>().join(" OR ");
                let sql = format!("SELECT rowid AS __rowid, * FROM {} WHERE {} LIMIT {}", q(&table), where_, PER_TABLE);
                let rows = match query_rows(&conn, &sql, &[&like]) { Ok(r) => r, Err(_) => continue };
                for row in rows {
                    let match_column = cols.iter().find(|c| row.get(*c).and_then(|v| v.as_str()).map(|s| s.to_lowercase().contains(&ql)).unwrap_or(false)).cloned().unwrap_or_default();
                    let rowid = row.get("__rowid").and_then(|v| v.as_i64()).unwrap_or(0);
                    hits.push(SearchHit {
                        host_id: host.id.clone(), host_name: host.name.clone(), file_name: file_name.clone(),
                        table_name: table.clone(), full_path: fp.to_string_lossy().to_string(), rowid,
                        match_column, columns: cols.clone(), row,
                    });
                    if hits.len() >= TOTAL { return hits; }
                }
            }
        }
    }
    hits
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
        if rest.is_empty() { "\\".to_string() }
        else if rest.starts_with('\\') { rest.to_string() }
        else { format!("\\{}", rest) }
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
    let jl = PathBuf::from(&host_dir).join("JUMPLIST").join("JumpList_Entries.sqlite");
    if let Ok(conn) = open_ro(&jl.to_string_lossy()) {
        let sql = "SELECT rowid AS __rowid, target_path, app_id, jumplist_type, arguments, working_directory, \
                   machine_id, timestamp, created_time, modified_time, _source_file \
                   FROM JumpList_Entries WHERE target_path IS NOT NULL AND target_path != ''";
        if let Ok(rows) = query_rows(&conn, sql, &[]) {
            for r in rows {
                let get = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let target = get("target_path");
                if target.is_empty() { continue; }
                let src = get("_source_file");
                let rowid = r.get("__rowid").and_then(|v| v.as_i64()).unwrap_or(-1);
                let mut fields = Map::new();
                for k in ["target_path", "app_id", "jumplist_type", "arguments", "working_directory",
                          "machine_id", "timestamp", "created_time", "modified_time", "_source_file"] {
                    let v = get(k);
                    if !v.is_empty() { fields.insert(k.to_string(), Value::from(v)); }
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
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false)).collect::<Vec<_>>(),
        Err(_) => return vec![],
    };
    for f in files {
        // Account = the hive's user prefix (Administrator_UsrClass.dat -> Administrator).
        let stem = f.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let account = stem.split('_').next().unwrap_or(&stem).to_string();
        let conn = match open_ro(&f.to_string_lossy()) { Ok(c) => c, Err(_) => continue };
        let sql = "SELECT key_path, value_name, value_data FROM Registry \
                   WHERE lower(key_path) LIKE '%bagmru%' AND value_name GLOB '[0-9]*' \
                   AND value_data IS NOT NULL AND value_data != ''";
        let mut stmt = match conn.prepare(sql) { Ok(s) => s, Err(_) => continue };
        let it = stmt.query_map([], |r| Ok((
            r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
        )));
        if let Ok(it) = it {
            for row in it.filter_map(|x| x.ok()) {
                let (key_path, value_name, hex) = row;
                let data = unhex(&hex);
                if data.is_empty() { continue; }
                rows.push(shellbag::BagRow { key_path, value_name, data, account: account.clone() });
            }
        }
    }
    shellbag::reconstruct(rows).into_iter().map(|s| {
        let mut fields = Map::new();
        fields.insert("path".into(), Value::from(s.display.clone()));
        if !s.account.is_empty() { fields.insert("account".into(), Value::from(s.account.clone())); }
        PathReference { path: s.path, kind: "Shellbag".to_string(), account: s.account, label: s.display, fields,
            full_path: String::new(), table_name: String::new(), rowid: -1 }
    }).collect()
}

/// Decode a lowercase/uppercase hex string to bytes ("" or odd length -> empty).
fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 { return Vec::new(); }
    let hv = |c: u8| -> Option<u8> { match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), b'A'..=b'F' => Some(c - b'A' + 10), _ => None } };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        match (hv(b[i]), hv(b[i + 1])) { (Some(h), Some(l)) => out.push(h << 4 | l), _ => return Vec::new() }
        i += 2;
    }
    out
}

// --- commands: bookmarks (JSON file) ---------------------------------------

fn bookmarks_path(case_dir: &str) -> PathBuf { PathBuf::from(case_dir).join("bookmarks.json") }

fn read_bookmarks(case_dir: &str) -> Vec<Value> {
    match std::fs::read_to_string(bookmarks_path(case_dir)) {
        Ok(s) => serde_json::from_str::<Value>(&s).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default(),
        Err(_) => vec![],
    }
}

fn write_bookmarks(case_dir: &str, bookmarks: &[Value]) {
    if let Ok(s) = serde_json::to_string_pretty(&bookmarks) {
        let _ = std::fs::write(bookmarks_path(case_dir), s);
    }
}

#[tauri::command]
fn list_bookmarks(case_dir: String) -> Vec<Value> { read_bookmarks(&case_dir) }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BookmarkInput {
    full_path: String, table_name: String, rowid: i64,
    #[serde(default)] field: Option<String>,
    #[serde(default)] host_id: Option<String>,
    #[serde(default)] host_name: Option<String>,
}

#[tauri::command]
fn toggle_bookmark(case_dir: String, entry: BookmarkInput) -> Vec<Value> {
    let mut bookmarks = read_bookmarks(&case_dir);
    let field = entry.field.clone().unwrap_or_default();
    let idx = bookmarks.iter().position(|b| {
        b.get("fullPath").and_then(|v| v.as_str()) == Some(entry.full_path.as_str())
            && b.get("rowid").and_then(|v| v.as_i64()) == Some(entry.rowid)
            && b.get("field").and_then(|v| v.as_str()).unwrap_or("") == field
    });
    if let Some(i) = idx {
        bookmarks.remove(i);
    } else {
        let id = format!("{}#{}{}", entry.full_path, entry.rowid, if field.is_empty() { String::new() } else { format!("@{}", field) });
        let mut b = Map::new();
        b.insert("id".into(), Value::from(id));
        b.insert("fullPath".into(), Value::from(entry.full_path));
        b.insert("tableName".into(), Value::from(entry.table_name));
        b.insert("rowid".into(), Value::from(entry.rowid));
        if !field.is_empty() { b.insert("field".into(), Value::from(field)); }
        b.insert("note".into(), Value::from(""));
        b.insert("taggedAt".into(), Value::from(now_iso()));
        b.insert("hostId".into(), Value::from(entry.host_id.unwrap_or_default()));
        b.insert("hostName".into(), Value::from(entry.host_name.unwrap_or_default()));
        bookmarks.push(Value::Object(b));
    }
    write_bookmarks(&case_dir, &bookmarks);
    bookmarks
}

#[tauri::command]
fn update_bookmark_note(case_dir: String, id: String, note: String) -> Vec<Value> {
    let mut bookmarks = read_bookmarks(&case_dir);
    for b in bookmarks.iter_mut() {
        if b.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
            if let Some(obj) = b.as_object_mut() { obj.insert("note".into(), Value::from(note.clone())); }
        }
    }
    write_bookmarks(&case_dir, &bookmarks);
    bookmarks
}

// ISO-8601 UTC timestamp without pulling in chrono (matches JS toISOString shape closely enough).
fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
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
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", year, month, day, h, mi, s, millis)
}

// --- commands: dialog ------------------------------------------------------

#[tauri::command]
async fn pick_folder(app: AppHandle) -> Option<String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_folder(move |p| { let _ = tx.send(p); });
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
    if args.len() < 5 || args[1] != PARSE_FLAG { return None; }
    let (case_id, host_id, cases_dir) = (&args[2], &args[3], std::path::PathBuf::from(&args[4]));
    let only = args.get(5)
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|x| x.to_string()).collect::<std::collections::HashSet<String>>());
    // Sink stays unset, so pipeline prints progress to stdout for the parent.
    match pipeline::run_host(case_id, host_id, &cases_dir, only) {
        Ok(()) => Some(0),
        Err(e) => { eprintln!("[!] {}", e); Some(1) }
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
            list_cases, create_case, create_host, delete_case, delete_host, list_artifacts,
            run_host, cancel_pipeline, list_categories, list_result_files, read_result_file,
            list_column_values, mft_children, mft_search, mft_row, search_case,
            list_bookmarks, toggle_bookmark, update_bookmark_note, pick_folder, path_references
        ])
        .setup(|_app| Ok(()))
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
