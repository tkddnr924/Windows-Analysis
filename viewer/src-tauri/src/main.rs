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
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
#[cfg(test)]
use std::time::UNIX_EPOCH;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter};
use url::Url;
use wina_core::{case_store, parse_eligibility, pipeline};

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

/// WebView2 user data folder.
///
/// Without an explicit path Tauri forces `%LOCALAPPDATA%\<identifier>` on
/// Windows/Linux and WebView2 creates `EBWebView\` inside it. Everything this
/// tool writes must stay under `cases/`, so pin it to `cases/.webview`.
/// Host listing needs `host.json` and legacy migration needs `case.json`, so
/// this folder is never mistaken for a host.
fn webview_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("WINA_WEBVIEW_DIR") {
        return PathBuf::from(d);
    }
    cases_dir().join(".webview")
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

/// Common contract marker of a derived result DB (docs-01 `overview_contract`).
/// Without it the file is not read as the new schema: the viewer never rebuilds
/// a result, it only reports that a re-parse is needed.
const OVERVIEW_CONTRACT_NAME: &str = "overview_contract";
const OVERVIEW_CONTRACT_VERSION: i64 = 1;

fn overview_contract_version(conn: &Connection) -> Option<i64> {
    conn.query_row(
        "SELECT version FROM _wina_derived_version WHERE name = ?1",
        rusqlite::params![OVERVIEW_CONTRACT_NAME],
        |row| row.get::<_, i64>(0),
    )
    .ok()
}

/// Analyst-facing table of a contract DB = file stem (Metadata.sqlite → metadata).
fn primary_table_name(path: &Path) -> Option<String> {
    path.file_stem().map(|stem| stem.to_string_lossy().to_string())
}

/// Tables exposed to listing, search and the timeline.
///
/// A contract DB publishes exactly one table (the file stem); `source_records`
/// and child tables (AiMessages, ExecutionTimes, …) are detail-only. Raw
/// artifact DBs without the marker keep exposing every table.
fn visible_table_names(conn: &Connection, path: &Path) -> Vec<String> {
    let names = table_names(conn);
    if overview_contract_version(conn).is_none() {
        return names;
    }
    let Some(primary) = primary_table_name(path) else {
        return names;
    };
    names
        .into_iter()
        .filter(|name| name.eq_ignore_ascii_case(&primary))
        .collect()
}

fn first_table(conn: &Connection, path: &Path) -> Option<String> {
    visible_table_names(conn, path).into_iter().next()
}

fn table_columns(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info({})", q(table)))
        .and_then(|mut s| {
            s.query_map([], |r| r.get::<_, String>(1))
                .map(|m| m.filter_map(|x| x.ok()).collect())
        })
        .unwrap_or_default()
}

/// Columns kept out of generic reads (list, page, search, timeline).
///
/// Declared-BLOB columns hold body bytes (FileSystemEntries.data). docs-21:
/// bodies are read only by an explicit detail request, never hex-expanded into
/// every listed row. CacheEntries.body_b64 is TEXT but follows the same rule.
fn excluded_payload_columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut excluded: Vec<String> = conn
        .prepare(&format!("PRAGMA table_info({})", q(table)))
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .map(|rows| {
                rows.filter_map(|row| row.ok())
                    .filter(|(_, declared)| declared.trim().eq_ignore_ascii_case("BLOB"))
                    .map(|(name, _)| name)
                    .collect()
            })
        })
        .unwrap_or_default();
    if table == "CacheEntries" {
        excluded.push("body_b64".to_string());
    }
    excluded
}

/// Columns to serialize into a response (body BLOBs excluded).
fn payload_columns(conn: &Connection, table: &str) -> Vec<String> {
    let excluded = excluded_payload_columns(conn, table);
    table_columns(conn, table)
        .into_iter()
        .filter(|column| !excluded.iter().any(|skip| skip == column))
        .collect()
}

/// `payload_columns` as a SELECT projection. None (instead of `*`) when the
/// columns cannot be read, so callers return an empty result explicitly.
fn payload_projection(columns: &[String]) -> Option<String> {
    (!columns.is_empty()).then(|| {
        columns
            .iter()
            .map(|column| q(column))
            .collect::<Vec<_>>()
            .join(", ")
    })
}

// --- account identity directory ------------------------------------------

/// A compact, display-only SID directory read from the host's `Metadata`
/// result (docs-01 §1, docs-24 §3).  This is deliberately not a second
/// parser: when a host has no resolved account rows (or a partial set), the
/// caller simply keeps the original SID visible.
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

/// SID → display account name. docs-01 runtime lookup: Metadata.sqlite row with
/// kind='account' or 'virtual_account' (service/DWM/UMFD), scope='machine', key=lower(SID). A NULL value stays
/// unresolved and the UI shows the SID; no name is invented. The old TargetInfo
/// composition is gone — metadata is the single source for account names.
#[tauri::command]
fn account_directory(host_dir: String) -> Result<Vec<AccountDirectoryEntry>, String> {
    let path = metadata_db_path(&host_dir);
    if !path.is_file() {
        return Ok(account_directory_from_rows(Vec::new()));
    }
    let conn = open_ro(&path.to_string_lossy())?;
    if overview_contract_version(&conn) != Some(OVERVIEW_CONTRACT_VERSION) {
        // No marker: never read a legacy result as the new schema.
        return Ok(account_directory_from_rows(Vec::new()));
    }
    let Some(table) = checked_table_names(&conn)?
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case("metadata"))
    else {
        return Ok(account_directory_from_rows(Vec::new()));
    };
    let rows = query_rows(
        &conn,
        &format!(
            "SELECT account_sid, value, COALESCE(name_source, '') AS name_source FROM {} \
             WHERE kind IN ('account', 'virtual_account') AND scope = 'machine' \
             AND account_sid IS NOT NULL AND value IS NOT NULL",
            q(&table)
        ),
        &[],
    )?;
    Ok(account_directory_from_rows(rows.into_iter().map(|row| {
        let get = |key: &str| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        (get("account_sid"), get("value"), get("name_source"))
    })))
}

fn metadata_db_path(host_dir: &str) -> PathBuf {
    Path::new(host_dir).join("_OVERVIEW").join("Metadata.sqlite")
}

/// One metadata bundle for the host view: the selected rows (by metadata_id or
/// kind) plus their child tables, read in one batch instead of reopening the DB
/// per TargetInfo.metadata_id (docs-24 §2.4). Cross-file FKs are not enforced
/// by SQLite, so caller-supplied metadata_id values are returned only when they
/// actually exist.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostMetadata {
    rows: Vec<Map<String, Value>>,
    addresses: Vec<Map<String, Value>>,
    gateways: Vec<Map<String, Value>>,
    dns_servers: Vec<Map<String, Value>>,
    groups: Vec<Map<String, Value>>,
    candidates: Vec<Map<String, Value>>,
    /// Whether metadata is stored under the common contract (overview_contract=1).
    /// false means "re-parse needed", which the UI separates from an empty result.
    contract_ok: bool,
}

fn host_metadata_blocking(
    host_dir: String,
    metadata_ids: Option<Vec<String>>,
    kind: Option<String>,
) -> Result<HostMetadata, String> {
    let path = metadata_db_path(&host_dir);
    if !path.is_file() {
        return Ok(HostMetadata::default());
    }
    let conn = open_ro(&path.to_string_lossy())?;
    if overview_contract_version(&conn) != Some(OVERVIEW_CONTRACT_VERSION) {
        return Ok(HostMetadata::default());
    }
    let Some(table) = checked_table_names(&conn)?
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case("metadata"))
    else {
        return Ok(HostMetadata::default());
    };
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if let Some(kind) = kind.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        params.push(kind.to_string());
        clauses.push(format!("kind = ?{}", params.len()));
    }
    if let Some(ids) = metadata_ids.as_ref() {
        let ids: Vec<&String> = ids.iter().filter(|id| !id.trim().is_empty()).collect();
        if ids.is_empty() {
            // Explicitly empty selection — nothing to read.
            return Ok(HostMetadata {
                contract_ok: true,
                ..HostMetadata::default()
            });
        }
        let placeholders = ids
            .iter()
            .map(|id| {
                params.push((*id).clone());
                format!("?{}", params.len())
            })
            .collect::<Vec<_>>()
            .join(", ");
        clauses.push(format!("metadata_id IN ({placeholders})"));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let refs: Vec<&dyn rusqlite::ToSql> = params
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let rows = query_rows(
        &conn,
        &format!(
            "SELECT rowid AS __rowid, * FROM {}{where_clause} ORDER BY kind, scope, key",
            q(&table)
        ),
        refs.as_slice(),
    )?;
    let selected: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            row.get("metadata_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    let mut result = HostMetadata {
        rows,
        contract_ok: true,
        ..HostMetadata::default()
    };
    if selected.is_empty() {
        return Ok(result);
    }
    let available = checked_table_names(&conn)?;
    for (child, target) in [
        ("MetadataAddresses", &mut result.addresses),
        ("MetadataGateways", &mut result.gateways),
        ("MetadataDnsServers", &mut result.dns_servers),
        ("MetadataGroups", &mut result.groups),
        ("MetadataCandidates", &mut result.candidates),
    ] {
        if !available.iter().any(|name| name == child) {
            continue;
        }
        for chunk in selected.chunks(400) {
            let placeholders = vec!["?"; chunk.len()].join(", ");
            let sql = format!(
                "SELECT rowid AS __rowid, * FROM {} WHERE metadata_id IN ({placeholders}) ORDER BY metadata_id, ordinal",
                q(child)
            );
            let chunk_refs: Vec<&dyn rusqlite::ToSql> = chunk
                .iter()
                .map(|id| id as &dyn rusqlite::ToSql)
                .collect();
            target.extend(query_rows(&conn, &sql, chunk_refs.as_slice())?);
        }
    }
    Ok(result)
}

#[tauri::command]
async fn host_metadata(
    host_dir: String,
    metadata_ids: Option<Vec<String>>,
    kind: Option<String>,
) -> Result<HostMetadata, String> {
    tauri::async_runtime::spawn_blocking(move || host_metadata_blocking(host_dir, metadata_ids, kind))
        .await
        .map_err(|error| format!("호스트 메타데이터 조회가 중단되었습니다: {error}"))?
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
    // Enforce the UI-01 rule here too, so a click made before the host list
    // refreshed (or any other caller) cannot bypass it. A scoped run (the
    // existing MFT-only retry) names its artifact explicitly and is exempt.
    let scoped_run = options.only.as_ref().is_some_and(|only| !only.is_empty());
    if !scoped_run {
        let (case_id, host_id, cases) = (options.case_id.clone(), options.host_id.clone(), cd.clone());
        let eligibility = tauri::async_runtime::spawn_blocking(move || {
            parse_eligibility::host_parse_eligibility(&case_id, &host_id, &cases)
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
        if !eligibility.can_parse {
            return Err(eligibility.reason);
        }
    }
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

fn valid_saving_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

// --- 타임라인 빌드용 원본 페이지 읽기 (바이트 예산) ---
// 일반 결과 페이지 조회는 행 수만 제한한다. 그러나 EventLog의 큰 EventData나
// 긴 스크립트 블록이 섞이면 "20,000행"의 실제 바이트는 증거 값 길이에 따라
// 무제한이라, 한 응답이 수백 MB가 되어 WebView 메모리를 고갈시킬 수 있다.
// 타임라인 빌드는 전 테이블을 훑으므로 여기서만 바이트 예산을 강제하고,
// 예산에 걸리면 행 수와 무관하게 페이지를 끊어 다음 offset을 돌려준다.
const TIMELINE_SOURCE_PAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineSourcePage {
    columns: Vec<String>,
    rows: Vec<Map<String, Value>>,
    /// 이어서 읽을 offset. None이면 이 테이블은 끝났다 — 호출자는 행 수로
    /// 종료를 판단하면 안 된다(예산으로 짧아진 페이지와 구분되지 않는다).
    next_offset: Option<i64>,
}

/// 결과 SQLite 한 테이블의 페이지를 읽는 공통 경로. `max_bytes`를 주면 누적
/// 직렬화 바이트가 그 예산에 닿는 순간 행 수와 무관하게 끊는다(단, 최소 1행은
/// 반환해 진행이 멈추지 않게 한다). 열 선택(CacheEntries의 body_b64 제외),
/// 식별자 인용, rowid 정렬, limit/offset 보정, 값 변환은 여기 한 곳에만 둔다 —
/// 타임라인 빌드와 일반 증거 표가 같은 원본을 다르게 노출하면 안 된다.
struct SqlitePage {
    columns: Vec<String>,
    rows: Vec<Map<String, Value>>,
    /// 예산에 걸려 끊겼는지 — 호출자가 "테이블 끝"과 구별하는 데 쓴다.
    budget_stopped: bool,
}

fn read_sqlite_page(
    conn: &Connection,
    table: &str,
    offset: i64,
    limit: i64,
    max_bytes: Option<usize>,
) -> Result<SqlitePage, String> {
    // Body BLOBs (FileSystemEntries.data) and cache bodies stay out of list
    // responses; detail-only commands read them.
    let columns = payload_columns(conn, table);
    let Some(select) = payload_projection(&columns) else {
        return Ok(SqlitePage {
            columns,
            rows: Vec::new(),
            budget_stopped: false,
        });
    };
    let sql = format!(
        "SELECT rowid AS __rowid, {} FROM {} ORDER BY rowid LIMIT ? OFFSET ?",
        select,
        q(table)
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut cursor = stmt
        .query(rusqlite::params![limit, offset])
        .map_err(|e| e.to_string())?;
    let mut rows: Vec<Map<String, Value>> = Vec::new();
    let mut bytes = 0usize;
    let mut budget_stopped = false;
    while let Some(row) = cursor.next().map_err(|e| e.to_string())? {
        let mut obj = Map::new();
        let mut row_bytes = 0usize;
        for (i, name) in names.iter().enumerate() {
            let value = cell(row.get_ref(i).map_err(|e| e.to_string())?);
            if max_bytes.is_some() {
                row_bytes += name.len()
                    + match &value {
                        Value::String(text) => text.len(),
                        _ => 8,
                    };
            }
            obj.insert(name.clone(), value);
        }
        rows.push(obj);
        if let Some(budget) = max_bytes {
            bytes += row_bytes;
            // 첫 행은 예산을 넘겨도 담는다 — 한 행이 예산보다 커도 진행이
            // 멈추지 않아야 한다(무한 루프 방지).
            if bytes >= budget && rows.len() < limit as usize {
                budget_stopped = true;
                break;
            }
        }
    }
    Ok(SqlitePage {
        columns,
        rows,
        budget_stopped,
    })
}

fn timeline_source_page_blocking(
    full_path: String,
    table_name: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<TimelineSourcePage, String> {
    let conn = open_ro(&full_path)?;
    let table = match table_name.or_else(|| first_table(&conn, Path::new(&full_path))) {
        Some(t) => t,
        None => {
            return Ok(TimelineSourcePage {
                columns: vec![],
                rows: vec![],
                next_offset: None,
            })
        }
    };
    let limit = limit.clamp(1, 100_000);
    let offset = offset.max(0);
    let mut page = read_sqlite_page(
        &conn,
        &table,
        offset,
        limit,
        Some(TIMELINE_SOURCE_PAGE_MAX_BYTES),
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut page.rows)?;
    let consumed = page.rows.len() as i64;
    // 예산으로 끊겼거나 요청한 행 수를 채웠으면 뒤가 더 있을 수 있다.
    let next_offset = if page.budget_stopped || consumed == limit {
        Some(offset + consumed)
    } else {
        None
    };
    Ok(TimelineSourcePage {
        columns: page.columns,
        rows: page.rows,
        next_offset,
    })
}

#[tauri::command]
async fn timeline_source_page(
    full_path: String,
    table_name: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<TimelineSourcePage, String> {
    tauri::async_runtime::spawn_blocking(move || {
        timeline_source_page_blocking(full_path, table_name, offset, limit)
    })
    .await
    .map_err(|error| format!("원본 페이지 조회가 중단되었습니다: {error}"))?
}

// --- 마스터 타임라인 sqlite materialize: 스트리밍 빌드 + 페이지 쿼리 ---
// 타임라인을 프런트 메모리에 전량 상주시키지 않도록, 각 결과 테이블을 청크로
// 변환해 이 sqlite로 흘려 넣고(빌드) 이후 검색·필터·정렬·페이지를 SQL로
// 조회한다. 빌드 세션은 raw 청크 + 워커 쓰기 + drain 구조로, 파일 append
// 대신 트랜잭션 insert를 수행한다.

/// 구조 로직(필터키·검색 blob·include 규칙) 버전. 규칙이 바뀌면 올려 재빌드 유도.
/// 3 = _OVERVIEW contract cutover (primary tables only, body BLOBs excluded,
/// source_records instead of record_key for raw evidence).
/// 4 = docs-18: _OVERVIEW tables only, a source shared by views shown once.
/// 5 = inputs limited to six views (user-confirmed). 6 = + browser visits/downloads.
const TIMELINE_LOGIC_VERSION: i64 = 6;

fn timeline_db_path(host_dir: &str) -> PathBuf {
    Path::new(host_dir).join("_master_timeline.sqlite")
}
fn timeline_db_building_path(host_dir: &str, token: &str) -> PathBuf {
    Path::new(host_dir).join(format!("_master_timeline.sqlite.building-{token}"))
}

/// 타임라인의 원본 행 참조 묶음을 원본 SQLite에서 한 번에 읽는다.
///
/// 타임라인 DB는 원본 행 전체를 복사해 두지 않는다 — 그러면 증거(185MB)보다
/// 큰 사본(782MB)이 만들어지고, 빌드 때 그 전량이 렌더러를 왕복한다. 대신
/// `full_path`+`rowid_src`만 저장하고, 필요한 시점(빌드 중 검색 문자열 생성,
/// 페이지 조회의 표시·상세)에 해당 행만 파일별로 묶어 읽는다.
///
/// 반환은 `(full_path, rowid) -> (컬럼 순서대로의 값)`. 컬럼 순서를 유지하는
/// 이유는 검색 문자열을 만들 때 프런트가 쓰던 값 순서와 같아야 하기 때문이다.
fn read_source_rows_by_rowid(
    refs: &[(String, String, i64)],
) -> std::collections::HashMap<(String, i64), Vec<(String, Value)>> {
    let mut by_file: std::collections::HashMap<(String, String), Vec<i64>> =
        std::collections::HashMap::new();
    for (path, table, rowid) in refs {
        by_file
            .entry((path.clone(), table.clone()))
            .or_default()
            .push(*rowid);
    }
    let mut out = std::collections::HashMap::new();
    for ((path, table), rowids) in by_file {
        let Ok(conn) = open_ro(&path) else { continue };
        // Timeline search text and display never carry body BLOBs either.
        let columns = payload_columns(&conn, &table);
        let Some(select) = payload_projection(&columns) else {
            continue;
        };
        // rowid 묶음은 100개씩 나눠 조회한다(플레이스홀더·SQL 길이 상한).
        for chunk in rowids.chunks(100) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT rowid AS __rowid, {} FROM {} WHERE rowid IN ({})",
                select,
                q(&table),
                placeholders
            );
            let Ok(mut stmt) = conn.prepare(&sql) else { continue };
            let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            let Ok(mut cursor) = stmt.query(params.as_slice()) else { continue };
            while let Ok(Some(row)) = cursor.next() {
                let mut values = Vec::with_capacity(names.len());
                let mut rowid = 0i64;
                for (i, name) in names.iter().enumerate() {
                    let Ok(raw) = row.get_ref(i) else { continue };
                    let value = cell(raw);
                    if name == "__rowid" {
                        rowid = value.as_i64().unwrap_or(0);
                    }
                    values.push((name.clone(), value));
                }
                out.insert((path.clone(), rowid), values);
            }
        }
    }
    out
}

/// 검색 문자열 — `[테이블, 카테고리, ...행 값]`을 공백으로 이은 소문자.
/// 빌드 시 프런트가 만들어 보내던 것을 백엔드에서 만든다(같은 내용을 IPC로
/// 한 번 더 나르지 않는다).
fn timeline_search_blob(table: &str, category: &str, values: &[(String, Value)]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(values.len() + 2);
    parts.push(table.to_string());
    parts.push(category.to_string());
    for (_, value) in values {
        parts.push(match value {
            Value::String(text) => text.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        });
    }
    parts.join(" ").to_lowercase()
}

const TIMELINE_SCHEMA: &str = "CREATE TABLE master_timeline (\
 ts TEXT NOT NULL, category TEXT NOT NULL, source_table TEXT NOT NULL,\
 artifact_group TEXT NOT NULL, filter_key TEXT NOT NULL DEFAULT '',\
 has_tags INTEGER NOT NULL, full_path TEXT NOT NULL, rowid_src INTEGER NOT NULL,\
 record_key TEXT NOT NULL DEFAULT '', record_id TEXT NOT NULL DEFAULT '',\
 event_time TEXT NOT NULL DEFAULT '',\
 search_blob TEXT NOT NULL);\
 CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT);";

#[derive(serde::Deserialize)]
struct TimelineInsertRow {
    ts: String,
    category: String,
    source_table: String,
    artifact_group: String,
    #[serde(default)]
    filter_key: String,
    has_tags: i64,
    full_path: String,
    rowid_src: i64,
    /// `<table>::<rowid>` pointer of a raw (facts) row. Empty for contract DBs.
    #[serde(default)]
    record_key: String,
    /// Derived row id; its raw evidence is looked up through source_records.
    #[serde(default)]
    record_id: String,
    #[serde(default)]
    event_time: String,
}

struct TimelineBuildSession {
    conn: rusqlite::Connection,
    host_dir: String,
    building_path: PathBuf,
    pending: usize,
    error: Option<String>,
    /// 마지막으로 이 세션에 작업이 오간 시각 — 웹뷰 리로드·크래시로 abort가
    /// 오지 않은 세션을 회수하는 기준이다.
    touched_at: Instant,
}
type TimelineBuildHandle = std::sync::Arc<(Mutex<TimelineBuildSession>, std::sync::Condvar)>;
/// 진행 중이 아니면서 이 시간 이상 방치된 빌드 세션은 다음 begin에서 회수한다.
const TIMELINE_BUILD_SESSION_IDLE: Duration = Duration::from_secs(600);
fn timeline_build_sessions(
) -> &'static Mutex<std::collections::HashMap<String, TimelineBuildHandle>> {
    static SESSIONS: LazyLock<Mutex<std::collections::HashMap<String, TimelineBuildHandle>>> =
        LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
    &SESSIONS
}

fn timeline_build_begin_impl(
    host_dir: &str,
    token: &str,
    built_for_run_at: &str,
) -> Result<(), String> {
    // 중단된 이전 빌드의 임시 DB·세션 정리 (호스트당 단일 빌더 전제).
    if let Ok(rd) = std::fs::read_dir(host_dir) {
        for e in rd.flatten() {
            if e.file_name()
                .to_string_lossy()
                .starts_with("_master_timeline.sqlite.building-")
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let mut abandoned: Vec<PathBuf> = Vec::new();
    if let Ok(mut sessions) = timeline_build_sessions().lock() {
        let now = Instant::now();
        sessions.retain(|_, handle| {
            let Ok(session) = handle.0.lock() else { return true };
            // 같은 호스트의 이전 빌드는 대체한다(호스트당 단일 빌더 전제).
            // 다른 호스트라도 진행 중이 아니면서 오래 방치된 세션은 회수한다 —
            // 프런트가 abort를 보내지 못한 경우(웹뷰 리로드·크래시) 열린 SQLite
            // 연결과 .building- 파일이 그 호스트로 다음 begin이 올 때까지 남는다.
            let stale = session.host_dir == host_dir
                || (session.pending == 0
                    && now.duration_since(session.touched_at) > TIMELINE_BUILD_SESSION_IDLE);
            if stale {
                abandoned.push(session.building_path.clone());
            }
            !stale
        });
    }
    for path in abandoned {
        let _ = std::fs::remove_file(path);
    }
    let building = timeline_db_building_path(host_dir, token);
    let conn = rusqlite::Connection::open(&building)
        .map_err(|e| format!("타임라인 임시 DB 생성 실패: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")
        .map_err(|e| format!("타임라인 DB 설정 실패: {e}"))?;
    conn.execute_batch(TIMELINE_SCHEMA)
        .map_err(|e| format!("타임라인 스키마 생성 실패: {e}"))?;
    conn.execute(
        "INSERT INTO _meta (key, value) VALUES ('built_for_run_at', ?1), ('logic_version', ?2)",
        rusqlite::params![built_for_run_at, TIMELINE_LOGIC_VERSION.to_string()],
    )
    .map_err(|e| format!("타임라인 메타 기록 실패: {e}"))?;
    if let Ok(mut sessions) = timeline_build_sessions().lock() {
        sessions.insert(
            token.to_string(),
            std::sync::Arc::new((
                Mutex::new(TimelineBuildSession {
                    conn,
                    host_dir: host_dir.to_string(),
                    building_path: building,
                    pending: 0,
                    error: None,
                    touched_at: Instant::now(),
                }),
                std::sync::Condvar::new(),
            )),
        );
    }
    Ok(())
}

/// 메인 커맨드에서 호출: 세션 확인·pending 증가까지만 하고 실제 insert는
/// 워커 스레드로 넘긴다(느린 저장 매체가 이벤트 루프를 막지 않게). 순서는
/// 프런트의 배치당 drain await가 보장한다.
fn timeline_build_insert_impl(
    host_dir: &str,
    token: &str,
    rows: Vec<TimelineInsertRow>,
) -> Result<(), String> {
    let handle = timeline_build_sessions()
        .lock()
        .ok()
        .and_then(|s| s.get(token).cloned())
        .ok_or_else(|| "타임라인 빌드 세션이 없습니다".to_string())?;
    {
        let mut session = handle.0.lock().map_err(|_| "빌드 세션 잠금 실패".to_string())?;
        if session.host_dir != host_dir {
            return Err("타임라인 빌드 세션의 호스트 경로가 일치하지 않습니다".to_string());
        }
        if let Some(error) = &session.error {
            return Err(error.clone());
        }
        if session.pending > 0 {
            return Err("이전 배치 쓰기가 끝나지 않았습니다 — drain 후 전송해야 합니다".to_string());
        }
        session.pending += 1;
        session.touched_at = Instant::now();
    }
    let worker = handle.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            // 검색 문자열은 원본에서 만든다 — 프런트가 행 사본을 IPC로 다시
            // 보내지 않게 한다(이 배치의 행만 파일별로 묶어 읽는다).
            let refs: Vec<(String, String, i64)> = rows
                .iter()
                .map(|r| (r.full_path.clone(), r.source_table.clone(), r.rowid_src))
                .collect();
            let sources = read_source_rows_by_rowid(&refs);
            let mut session = worker.0.lock().map_err(|_| "빌드 세션 잠금 실패".to_string())?;
            let tx = session
                .conn
                .transaction()
                .map_err(|e| format!("타임라인 트랜잭션 실패: {e}"))?;
            {
                let mut stmt = tx
                    .prepare_cached(
                        "INSERT INTO master_timeline (ts,category,source_table,artifact_group,filter_key,has_tags,full_path,rowid_src,record_key,record_id,event_time,search_blob) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    )
                    .map_err(|e| format!("타임라인 insert 준비 실패: {e}"))?;
                for r in &rows {
                    let blob = sources
                        .get(&(r.full_path.clone(), r.rowid_src))
                        .map(|values| timeline_search_blob(&r.source_table, &r.category, values))
                        .unwrap_or_default();
                    stmt.execute(rusqlite::params![
                        r.ts, r.category, r.source_table, r.artifact_group, r.filter_key,
                        r.has_tags, r.full_path, r.rowid_src, r.record_key, r.record_id, r.event_time,
                        blob
                    ])
                    .map_err(|e| format!("타임라인 insert 실패: {e}"))?;
                }
            }
            tx.commit().map_err(|e| format!("타임라인 커밋 실패: {e}"))?;
            Ok(())
        })();
        if let Ok(mut session) = worker.0.lock() {
            session.pending = session.pending.saturating_sub(1);
            session.touched_at = Instant::now();
            if let Err(error) = result {
                session.error.get_or_insert(error);
            }
        }
        worker.1.notify_all();
    });
    Ok(())
}

fn timeline_build_wait_impl(token: &str) -> Result<(), String> {
    let handle = timeline_build_sessions()
        .lock()
        .ok()
        .and_then(|s| s.get(token).cloned())
        .ok_or_else(|| "타임라인 빌드 세션이 없습니다".to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut session = handle.0.lock().map_err(|_| "빌드 세션 잠금 실패".to_string())?;
    while session.pending > 0 && session.error.is_none() {
        if std::time::Instant::now() >= deadline {
            return Err("타임라인 빌드 시간 초과".to_string());
        }
        let (next, _) = handle
            .1
            .wait_timeout(session, std::time::Duration::from_millis(500))
            .map_err(|_| "빌드 세션 잠금 실패".to_string())?;
        session = next;
    }
    match &session.error {
        Some(error) => Err(error.clone()),
        None => Ok(()),
    }
}

fn timeline_build_finish_impl(host_dir: &str, token: &str) -> Result<(), String> {
    {
        let handle = timeline_build_sessions()
            .lock()
            .ok()
            .and_then(|s| s.get(token).cloned())
            .ok_or_else(|| "타임라인 빌드 세션이 없습니다".to_string())?;
        let session = handle.0.lock().map_err(|_| "빌드 세션 잠금 실패".to_string())?;
        if session.host_dir != host_dir {
            return Err("타임라인 빌드 세션의 호스트 경로가 일치하지 않습니다".to_string());
        }
    }
    timeline_build_wait_impl(token)?;
    // bulk insert가 끝난 뒤 인덱스를 만든다(insert 속도).
    let building = {
        let handle = timeline_build_sessions()
            .lock()
            .ok()
            .and_then(|s| s.get(token).cloned())
            .ok_or_else(|| "타임라인 빌드 세션이 없습니다".to_string())?;
        let session = handle.0.lock().map_err(|_| "빌드 세션 잠금 실패".to_string())?;
        session
            .conn
            .execute_batch(
                "CREATE INDEX ix_ts ON master_timeline(ts); CREATE INDEX ix_group ON master_timeline(artifact_group);",
            )
            .map_err(|e| format!("타임라인 인덱스 생성 실패: {e}"))?;
        session.building_path.clone()
    };
    // 세션 제거 → conn drop(파일 닫힘) → 원자 rename.
    if let Ok(mut sessions) = timeline_build_sessions().lock() {
        sessions.remove(token);
    }
    std::fs::rename(&building, timeline_db_path(host_dir))
        .map_err(|e| format!("타임라인 DB 확정 실패: {e}"))
}

fn timeline_build_abort_impl(host_dir: &str, token: &str) {
    if let Ok(mut sessions) = timeline_build_sessions().lock() {
        sessions.remove(token);
    }
    let _ = std::fs::remove_file(timeline_db_building_path(host_dir, token));
}

#[tauri::command]
async fn master_timeline_build_begin(
    host_dir: String,
    token: String,
    built_for_run_at: String,
) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 빌드 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        timeline_build_begin_impl(&host_dir, &token, &built_for_run_at)
    })
    .await
    .map_err(|e| format!("타임라인 빌드 시작 작업이 중단되었습니다: {e}"))?
}

/// 줄바꿈 구분 JSON(NDJSON) 행 배치를 문자열 인자로 받는다. (raw 바이트 IPC는
/// 이 환경에서 custom protocol 로드 실패로 동작하지 않아 문자열 IPC를 쓴다.
/// 배치는 프런트에서 ~4MB로 제한돼 인자 역직렬화 부담이 작다.)
#[tauri::command]
async fn master_timeline_build_insert(
    host_dir: String,
    token: String,
    ndjson: String,
) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 빌드 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let rows: Vec<TimelineInsertRow> = ndjson
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("타임라인 빌드 행 파싱 실패: {e}"))?;
        timeline_build_insert_impl(&host_dir, &token, rows)
    })
    .await
    .map_err(|e| format!("타임라인 빌드 작업이 중단되었습니다: {e}"))?
}

#[tauri::command]
async fn master_timeline_build_drain(token: String) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 빌드 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || timeline_build_wait_impl(&token))
        .await
        .map_err(|e| format!("타임라인 빌드 작업이 중단되었습니다: {e}"))?
}

#[tauri::command]
async fn master_timeline_build_finish(host_dir: String, token: String) -> Result<(), String> {
    if !valid_saving_token(&token) {
        return Err("타임라인 빌드 토큰이 잘못되었습니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || timeline_build_finish_impl(&host_dir, &token))
        .await
        .map_err(|e| format!("타임라인 빌드 작업이 중단되었습니다: {e}"))?
}

#[tauri::command]
async fn master_timeline_build_abort(host_dir: String, token: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        timeline_build_abort_impl(&host_dir, &token);
        Ok(())
    })
    .await
    .map_err(|e| format!("타임라인 빌드 작업이 중단되었습니다: {e}"))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineMeta {
    exists: bool,
    built_for_run_at: String,
    logic_version: i64,
    total: i64,
}

fn timeline_meta_impl(host_dir: &str) -> TimelineMeta {
    let empty = || TimelineMeta {
        exists: false,
        built_for_run_at: String::new(),
        logic_version: 0,
        total: 0,
    };
    let path = timeline_db_path(host_dir);
    if !path.exists() {
        return empty();
    }
    let conn = match open_ro(&path.to_string_lossy()) {
        Ok(c) => c,
        Err(_) => return empty(),
    };
    let meta = |key: &str| -> String {
        conn.query_row("SELECT value FROM _meta WHERE key=?1", [key], |r| r.get(0))
            .unwrap_or_default()
    };
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM master_timeline", [], |r| r.get(0))
        .unwrap_or(0);
    TimelineMeta {
        exists: true,
        built_for_run_at: meta("built_for_run_at"),
        logic_version: meta("logic_version").parse().unwrap_or(0),
        total,
    }
}

#[tauri::command]
async fn master_timeline_meta(host_dir: String) -> TimelineMeta {
    tauri::async_runtime::spawn_blocking(move || timeline_meta_impl(&host_dir))
        .await
        .unwrap_or(TimelineMeta {
            exists: false,
            built_for_run_at: String::new(),
            logic_version: 0,
            total: 0,
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineFacetCount {
    key: String,
    count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineTableFacet {
    artifact_group: String,
    source_table: String,
    category: String,
    count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineFacets {
    tables: Vec<TimelineTableFacet>,
    exec_sources: Vec<TimelineFacetCount>,
    browser_kinds: Vec<TimelineFacetCount>,
}

fn timeline_facets_impl(host_dir: &str) -> Result<TimelineFacets, String> {
    let conn = open_ro(&timeline_db_path(host_dir).to_string_lossy())
        .map_err(|_| "타임라인 DB를 열 수 없습니다".to_string())?;
    let tables = {
        let mut stmt = conn
            .prepare(
                "SELECT artifact_group, source_table, category, COUNT(*) FROM master_timeline \
                 GROUP BY artifact_group, source_table, category ORDER BY artifact_group, source_table",
            )
            .map_err(|e| format!("타임라인 패싯 조회 실패: {e}"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TimelineTableFacet {
                    artifact_group: r.get(0)?,
                    source_table: r.get(1)?,
                    category: r.get(2)?,
                    count: r.get(3)?,
                })
            })
            .map_err(|e| format!("타임라인 패싯 조회 실패: {e}"))?;
        rows.filter_map(|r| r.ok()).collect::<Vec<_>>()
    };
    let facet_by_key = |conn: &rusqlite::Connection, source: &str| -> Vec<TimelineFacetCount> {
        conn.prepare(
            "SELECT filter_key, COUNT(*) FROM master_timeline \
             WHERE source_table=?1 AND filter_key<>'' GROUP BY filter_key ORDER BY COUNT(*) DESC",
        )
        .and_then(|mut stmt| {
            let rows = stmt.query_map([source], |r| {
                Ok(TimelineFacetCount {
                    key: r.get(0)?,
                    count: r.get(1)?,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
        })
        .unwrap_or_default()
    };
    Ok(TimelineFacets {
        tables,
        exec_sources: facet_by_key(&conn, "ExecutionHistory"),
        browser_kinds: facet_by_key(&conn, "BrowserActivity"),
    })
}

#[tauri::command]
async fn master_timeline_facets(host_dir: String) -> Result<TimelineFacets, String> {
    tauri::async_runtime::spawn_blocking(move || timeline_facets_impl(&host_dir))
        .await
        .map_err(|e| format!("타임라인 패싯 작업이 중단되었습니다: {e}"))?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimelineQuery {
    #[serde(default)]
    search: String,
    #[serde(default)]
    hidden_source_tables: Vec<String>,
    #[serde(default)]
    hidden_exec_sources: Vec<String>,
    #[serde(default)]
    hidden_browser_kinds: Vec<String>,
    #[serde(default)]
    only_suspicious: bool,
    #[serde(default)]
    start: String,
    #[serde(default)]
    end: String,
    #[serde(default)]
    sort_desc: bool,
    offset: i64,
    limit: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelinePageRow {
    ts: String,
    category: String,
    source_table: String,
    artifact_group: String,
    full_path: String,
    rowid_src: i64,
    record_key: String,
    record_id: String,
    event_time: String,
    /// 원본 행 — 타임라인 DB에 사본을 두지 않고 페이지마다 원본에서 읽어 붙인다.
    row: Map<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelinePage {
    rows: Vec<TimelinePageRow>,
    total: i64,
}

fn timeline_page_impl(host_dir: &str, query: TimelineQuery) -> Result<TimelinePage, String> {
    let conn = open_ro(&timeline_db_path(host_dir).to_string_lossy())
        .map_err(|_| "타임라인 DB를 열 수 없습니다".to_string())?;
    let limit = query.limit.clamp(1, 1000);
    let offset = query.offset.max(0);
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    let in_clause = |clauses: &mut Vec<String>,
                         params: &mut Vec<String>,
                         values: &[String],
                         wrap: &dyn Fn(&str) -> String| {
        if values.is_empty() {
            return;
        }
        let placeholders: Vec<String> = values
            .iter()
            .map(|value| {
                params.push(value.clone());
                format!("?{}", params.len())
            })
            .collect();
        clauses.push(wrap(&placeholders.join(",")));
    };
    in_clause(&mut clauses, &mut params, &query.hidden_source_tables, &|ph| {
        format!("source_table NOT IN ({ph})")
    });
    in_clause(&mut clauses, &mut params, &query.hidden_exec_sources, &|ph| {
        format!("NOT (source_table='ExecutionHistory' AND filter_key IN ({ph}))")
    });
    in_clause(&mut clauses, &mut params, &query.hidden_browser_kinds, &|ph| {
        format!("NOT (source_table='BrowserActivity' AND filter_key IN ({ph}))")
    });
    if query.only_suspicious {
        clauses.push("has_tags=1".to_string());
    }
    if !query.start.trim().is_empty() {
        params.push(query.start.trim().to_string());
        clauses.push(format!("ts >= ?{}", params.len()));
    }
    if !query.end.trim().is_empty() {
        params.push(query.end.trim().to_string());
        clauses.push(format!("ts <= ?{}", params.len()));
    }
    if !query.search.trim().is_empty() {
        // 검색 blob은 소문자로 저장돼 있으므로 검색어도 소문자화하고, LIKE
        // 와일드카드(%,_)와 이스케이프 문자는 리터럴로 처리해 현재 프런트의
        // 부분 문자열 검색과 의미를 맞춘다.
        let escaped = query
            .search
            .trim()
            .to_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        params.push(format!("%{escaped}%"));
        clauses.push(format!("search_blob LIKE ?{} ESCAPE '\\'", params.len()));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|value| value as &dyn rusqlite::ToSql).collect();
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM master_timeline{where_clause}"),
            refs.as_slice(),
            |r| r.get(0),
        )
        .map_err(|e| format!("타임라인 건수 조회 실패: {e}"))?;
    let dir = if query.sort_desc { "DESC" } else { "ASC" };
    let sql = format!(
        "SELECT ts,category,source_table,artifact_group,full_path,rowid_src,record_key,record_id,event_time \
         FROM master_timeline{where_clause} ORDER BY ts {dir}, source_table, rowid_src LIMIT {limit} OFFSET {offset}"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("타임라인 페이지 조회 실패: {e}"))?;
    let rows = stmt
        .query_map(refs.as_slice(), |r| {
            Ok(TimelinePageRow {
                ts: r.get(0)?,
                category: r.get(1)?,
                source_table: r.get(2)?,
                artifact_group: r.get(3)?,
                full_path: r.get(4)?,
                rowid_src: r.get(5)?,
                record_key: r.get(6)?,
                record_id: r.get(7)?,
                event_time: r.get(8)?,
                row: Map::new(),
            })
        })
        .map_err(|e| format!("타임라인 페이지 조회 실패: {e}"))?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    // 이 페이지(최대 1,000행)의 원본 행만 파일별로 묶어 읽어 붙인다 — 목록의
    // 제목·태그와 상세 드로어가 쓰던 값이 그대로 유지된다.
    let refs: Vec<(String, String, i64)> = rows
        .iter()
        .map(|r| (r.full_path.clone(), r.source_table.clone(), r.rowid_src))
        .collect();
    let sources = read_source_rows_by_rowid(&refs);
    let mut rows = rows;
    for row in &mut rows {
        if let Some(values) = sources.get(&(row.full_path.clone(), row.rowid_src)) {
            row.row = values.iter().cloned().collect();
        }
    }
    // Timeline rows carry the same raw evidence identities as the raw/overview
    // screens, so bookmark state matches. One lookup per source file.
    let mut by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        if contract_row_record_id(&row.row).is_some() {
            by_file.entry(row.full_path.clone()).or_default().push(index);
        }
    }
    for (path, indexes) in by_file {
        let Ok(source_conn) = open_ro(&path) else {
            continue;
        };
        let mut page: Vec<Map<String, Value>> = indexes
            .iter()
            .map(|index| rows[*index].row.clone())
            .collect();
        decorate_source_refs(&source_conn, Path::new(&path), &mut page)?;
        for (slot, index) in indexes.into_iter().enumerate() {
            rows[index].row = page[slot].clone();
        }
    }
    Ok(TimelinePage { rows, total })
}

#[tauri::command]
async fn master_timeline_page(host_dir: String, query: TimelineQuery) -> Result<TimelinePage, String> {
    tauri::async_runtime::spawn_blocking(move || timeline_page_impl(&host_dir, query))
        .await
        .map_err(|e| format!("타임라인 페이지 작업이 중단되었습니다: {e}"))?
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
    /// True for _OVERVIEW contract DBs; false for raw parser facts.
    derived: bool,
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
        // Derived (_OVERVIEW contract) DBs carry `_wina_derived_version`; raw
        // parser facts do not, even when stored under _OVERVIEW (MFT_Records).
        let derived = overview_contract_version(&conn).is_some();
        // A contract DB contributes one sidebar entry: source_records and child
        // tables are detail-only, not separate result files.
        for t in visible_table_names(&conn, &p) {
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
                derived,
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

/// The 21 derived result files of docs-01. Used only to decide whether a file
/// is a contract result; other `_OVERVIEW` files (raw facts such as
/// MFT_Records.sqlite) are out of scope.
const DERIVED_OVERVIEW_FILES: [&str; 23] = [
    "Metadata",
    "ExecutionHistory",
    "PowerShellHistory",
    "BrowserActivity",
    "AiConversations",
    "RegistryFindings",
    "RemoteDesktopHistory",
    "SmbHistory",
    "ScheduledTasks",
    "ServiceHistory",
    "Defender",
    "FirewallHistory",
    "BitsHistory",
    "WerReports",
    "RdpCache",
    "TargetInfo",
    "WmiSubscriptions",
    "FileSystemEntries",
    "UsnJournal",
    "PathReferences",
    "RecycleBin",
    "JumpListEntries",
    "TimelineActivities",
];

/// Reports whether stored results follow the common contract (overview_contract=1).
///
/// The read-time rebuild paths (refresh_*) are gone: opening a screen must not
/// overwrite evidence. Legacy results are only *reported* as needing a
/// re-parse (docs-24 §2.1).
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct OverviewContractStatus {
    contract_ok: bool,
    /// Derived files with a missing or different contract marker (host-relative).
    legacy_files: Vec<String>,
}

fn overview_contract_status_blocking(host_dir: String) -> OverviewContractStatus {
    let overview_dir = Path::new(&host_dir).join("_OVERVIEW");
    let mut legacy_files = Vec::new();
    for name in DERIVED_OVERVIEW_FILES {
        let path = overview_dir.join(format!("{name}.sqlite"));
        if !path.is_file() {
            // A view that was never produced may simply have no evidence.
            continue;
        }
        let current = open_ro(&path.to_string_lossy())
            .ok()
            .and_then(|conn| overview_contract_version(&conn));
        if current != Some(OVERVIEW_CONTRACT_VERSION) {
            legacy_files.push(format!("_OVERVIEW/{name}.sqlite"));
        }
    }
    OverviewContractStatus {
        contract_ok: legacy_files.is_empty(),
        legacy_files,
    }
}

#[tauri::command]
async fn overview_contract_status(host_dir: String) -> OverviewContractStatus {
    tauri::async_runtime::spawn_blocking(move || overview_contract_status_blocking(host_dir))
        .await
        .unwrap_or_default()
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

/// Reads the parser-recorded source paths without materialising or aggregating
/// the table. This intentionally avoids `COUNT`: an Amcache table can contain
/// millions of rows and the dashboard needs the source identity, not another
/// expensive statistical pass.
///
/// A contract DB's primary table has no `_source_file` column — the origins are
/// rows in source_records, so the verified collection files are returned from
/// there without duplicates. Every origin is shown; no representative is picked
/// (docs-24 §4). `recovery` is a registry-parser marker and stays empty here.
#[tauri::command]
fn result_provenance(
    full_path: String,
    table_name: String,
) -> Result<Vec<ResultProvenance>, String> {
    let conn = open_ro(&full_path)?;
    let tables = table_names(&conn);
    if !tables.iter().any(|name| name == &table_name) {
        return Ok(Vec::new());
    }
    let columns = table_columns(&conn, &table_name);
    if !columns.iter().any(|column| column == "_source_file") {
        if !tables.iter().any(|name| name == "source_records") {
            return Ok(Vec::new());
        }
        let sql = "SELECT DISTINCT source_file FROM \"source_records\" \
                   WHERE source_file IS NOT NULL AND source_file <> '' \
                   ORDER BY source_file LIMIT 20";
        let mut stmt = conn.prepare(sql).map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ResultProvenance {
                    source_file: row.get(0)?,
                    recovery: String::new(),
                })
            })
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .collect();
        return Ok(rows);
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

/// Whether this host has new data to parse (UI-01). The rule and its Korean
/// reason live in `wina_core::parse_eligibility`; `run_host` calls the same
/// function, so button state and what the backend allows cannot drift.
/// Discovery walks the collection folder, so it runs off the main thread.
#[tauri::command]
async fn host_parse_eligibility(
    case_id: String,
    host_id: String,
) -> Result<parse_eligibility::ParseEligibility, String> {
    if !valid_id(&case_id) || !valid_id(&host_id) {
        return Err("잘못된 케이스 또는 호스트 식별자입니다".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        parse_eligibility::host_parse_eligibility(&case_id, &host_id, &cases_dir())
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Resolve a stored run log inside its host boundary, so this can never become
/// a way to open an arbitrary path: the host folder must be a direct child of
/// the cases root holding `host.json`, and the log must be an existing file
/// under that host's `parse_logs/`.
fn parse_run_log_file_in(cases: &Path, host_dir: &str, run_id: &str) -> Result<PathBuf, String> {
    if !valid_id(run_id) {
        return Err("잘못된 실행 식별자입니다".to_string());
    }
    let cases = cases
        .canonicalize()
        .map_err(|error| format!("케이스 폴더를 찾을 수 없습니다: {error}"))?;
    let host = Path::new(host_dir)
        .canonicalize()
        .map_err(|error| format!("호스트 폴더를 찾을 수 없습니다: {error}"))?;
    if host.parent() != Some(cases.as_path()) || !host.join("host.json").is_file() {
        return Err("등록된 호스트 폴더가 아닙니다".to_string());
    }
    let logs = host.join(pipeline::PARSE_LOG_DIRECTORY);
    let path = pipeline::parse_run_log_path(&host, run_id)
        .canonicalize()
        .map_err(|error| format!("실행 로그 파일을 찾을 수 없습니다: {error}"))?;
    if !path.starts_with(&logs) || !path.is_file() {
        return Err("실행 로그 파일을 찾을 수 없습니다".to_string());
    }
    Ok(path)
}

/// Open a file with the OS default application. Arguments go through argv, not
/// a shell, so path metacharacters cannot be interpreted as commands (Windows
/// uses the rundll32 handler instead of `cmd /C start` for the same reason).
fn open_with_default_app(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(path);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("rundll32.exe");
        command.arg("url.dll,FileProtocolHandler").arg(path);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(path);
        command
    };
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("기본 앱으로 로그를 열지 못했습니다: {error}"))?;
    if !status.success() {
        return Err("이 파일을 열 기본 앱이 없습니다".to_string());
    }
    Ok(())
}

/// Open the stored run log (parse_logs/<run_id>.txt) with the default app (UI-05).
#[tauri::command]
async fn open_parse_run_log(host_dir: String, run_id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let path = parse_run_log_file_in(&cases_dir(), &host_dir, &run_id)?;
        open_with_default_app(&path)
    })
    .await
    .map_err(|error| error.to_string())?
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

/// Test helper: a JSON cell as display text.
#[cfg(test)]
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
        // Nested objects keep their JSON text.
        Value::Object(_) => Some(value.to_string()),
    }
}

#[cfg(test)]
fn map_text(row: &Map<String, Value>, key: &str) -> String {
    row.get(key).and_then(value_text).unwrap_or_default()
}

/// Account-detail activity: events stored at parse time for one TargetInfo
/// account parent (docs viewer-03). No raw EventLog scan at view time.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountEventQuery {
    record_id: String,
    /// Result generation the caller loaded the account from.
    dataset_id: String,
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
    /// Stored result predates target_info=2 (no account events): re-parse.
    stale: bool,
    /// The account parent/generation the caller holds no longer exists (result
    /// was re-published): reload, not "no activity".
    replaced: bool,
}

/// target_info version that first stores TargetAccountEvents/Matches.
const TARGET_INFO_EVENTS_VERSION: i64 = 2;

fn account_event_page_blocking(
    host_dir: String,
    query: AccountEventQuery,
) -> Result<AccountEventPage, String> {
    let path = Path::new(&host_dir).join("_OVERVIEW").join("TargetInfo.sqlite");
    let conn = open_ro(&path.to_string_lossy())?;
    let version: Option<i64> = conn
        .query_row(
            "SELECT version FROM _wina_derived_version WHERE name = 'target_info'",
            [],
            |row| row.get(0),
        )
        .ok();
    if overview_contract_version(&conn) != Some(OVERVIEW_CONTRACT_VERSION)
        || version.unwrap_or(0) < TARGET_INFO_EVENTS_VERSION
    {
        return Ok(AccountEventPage { rows: Vec::new(), row_count: 0, stale: true, replaced: false });
    }
    // Only a missing parent/generation means the result was replaced; read
    // failures surface as errors, never as a reparse hint.
    match conn.query_row(
        "SELECT 1 FROM TargetInfo WHERE record_id = ?1 AND dataset_id = ?2",
        [&query.record_id, &query.dataset_id],
        |_| Ok(()),
    ) {
        Ok(()) => {}
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(AccountEventPage { rows: Vec::new(), row_count: 0, stale: false, replaced: true });
        }
        Err(e) => return Err(format!("계정 행 조회 실패: {e}")),
    }

    let mut clauses = vec!["e.record_id = ?".to_string()];
    let mut params: Vec<String> = vec![query.record_id.clone()];
    if let Some(start) = query.start.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("e.timestamp >= ?".into());
        params.push(start.to_string());
    }
    if let Some(end) = query.end.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("e.timestamp <= ?".into());
        params.push(end.to_string());
    }
    if let Some(needle) = query.search.as_deref().map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty()) {
        // Event fields and the stored match evidence (role/field/value).
        clauses.push(
            "(instr(lower(coalesce(e.timestamp,'') || ' ' || coalesce(e.channel,'') || ' ' || \
             coalesce(e.provider,'') || ' ' || coalesce(e.event_id,'') || ' ' || coalesce(e.level_name,'') || ' ' || \
             coalesce(e.computer,'') || ' ' || coalesce(e.user_id,'') || ' ' || coalesce(e.event_data,'')), ?) > 0 \
             OR EXISTS (SELECT 1 FROM TargetAccountEventMatches m WHERE m.record_id = e.record_id \
             AND m.event_ordinal = e.ordinal \
             AND instr(lower(m.role || ' ' || coalesce(m.field,'') || ' ' || coalesce(m.value,'')), ?) > 0))"
                .into(),
        );
        params.push(needle.clone());
        params.push(needle);
    }
    let filter = clauses.join(" AND ");
    let bind: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
    let row_count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM TargetAccountEvents e WHERE {filter}"),
            bind.as_slice(),
            |row| row.get(0),
        )
        .map_err(|e| format!("계정 활동 건수 조회 실패: {e}"))?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);
    let mut page_bind = bind.clone();
    page_bind.push(&limit);
    page_bind.push(&offset);
    // EventLog-shaped keys keep the shared EventLog detail definition; the raw
    // source coordinates (source_records) stay the bookmark key until viewer-20.
    let sql = format!(
        "SELECT s.source_rowid AS __rowid, e.timestamp, e.channel AS Channel, e.event_id AS EventID, \
         e.level_name AS LevelName, e.level AS Level, e.provider AS Provider, e.computer AS Computer, \
         e.event_record_id AS EventRecordID, e.process_id AS ProcessID, e.thread_id AS ThreadID, \
         e.user_id AS UserID, e.event_data AS EventData, e.parse_status AS _parse_status, \
         e.parse_error AS _parse_error, s.source_db AS _source_db, s.source_table AS _source_table_name, \
         s.source_record_key AS _record_key \
         FROM TargetAccountEvents e \
         JOIN source_records s ON s.record_id = e.record_id AND s.ordinal = e.source_ordinal \
         WHERE {filter} ORDER BY e.timestamp IS NULL, e.timestamp, e.ordinal LIMIT ? OFFSET ?"
    );
    let mut rows = query_rows(&conn, &sql, page_bind.as_slice())?;
    for row in &mut rows {
        // source_db is host-relative with '/', rebuild with native joins so the
        // path matches list_result_files (bookmark key).
        if let Some(Value::String(db)) = row.remove("_source_db") {
            let mut full = PathBuf::from(&host_dir);
            full.extend(db.split('/'));
            row.insert("_source_full_path".into(), Value::String(full.to_string_lossy().to_string()));
        }
    }
    Ok(AccountEventPage { rows, row_count, stale: false, replaced: false })
}

#[tauri::command]
async fn account_event_page(
    host_dir: String,
    query: AccountEventQuery,
) -> Result<AccountEventPage, String> {
    tauri::async_runtime::spawn_blocking(move || account_event_page_blocking(host_dir, query))
        .await
        .map_err(|error| format!("account event worker stopped unexpectedly: {error}"))?
}

// --- commands: browser activity and AI conversations (docs-07) -------------
// Only _OVERVIEW BrowserActivity/AiConversations and their child tables are
// read; facts and collected browser files are never reopened.

const BROWSER_DB: &str = "BrowserActivity.sqlite";
/// Kinds that are events; `url_summary` is an aggregate (R04).
const BROWSER_EVENT_KINDS: &str = "('visit','download','cache')";
/// Columns sent for list rows; detail reads the full record (R17).
const BROWSER_LIST_COLUMNS: &str = "b.rowid AS __rowid, b.record_id, b.host_id, b.dataset_id, \
     b.overview_name, b.timestamp, b.timestamp_kind, b.event_type, b.input_id, b.browser, b.profile, \
     b.account, b.account_sid, b.account_label, b.input_kind, b.title, b.url, b.url_raw, b.detail, \
     b.source_url, b.visit_count, b.typed_count, b.transition_core, b.size, b.size_bytes, b.mime, \
     b.danger, b.download_state, b.download_opened, b.http_status, b.cache_body_recovered, \
     b.body_bytes, b.ai_service_provider, b.ai_referral_provider, b.ai_referral_param";
/// Parent columns matched by the browser search (R12).
const BROWSER_SEARCH_COLUMNS: &[&str] = &[
    "title", "url", "url_raw", "detail", "source_url", "external_referrer_url", "mime",
    "download_path", "download_path_resolved", "download_current_path",
    "download_current_path_resolved", "download_referrer", "download_tab_url",
    "download_tab_referrer_url", "download_site_url", "download_url_first", "download_url_final",
    "request_url", "cache_key", "account", "account_sid", "account_label", "browser", "profile",
];
const BROWSER_FLOW_MAX_NODES: usize = 200;
const BROWSER_CACHE_CHUNK_MAX: i64 = 4 * 1024 * 1024;

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
struct BrowserFilter {
    /// Selected inputs (empty: all).
    input_ids: Vec<String>,
    /// visit, url_summary, download, cache (empty: all).
    kinds: Vec<String>,
    day: Option<String>,
    /// Records without a representative time (time filters do not apply).
    untimed: bool,
    start: Option<String>,
    end: Option<String>,
    search: Option<String>,
    /// Only stored AI referral markers (R15).
    referral: bool,
}

/// Which filter parts a query applies.
#[derive(Clone, Copy)]
struct BrowserFilterParts {
    kinds: bool,
    day: bool,
    search: bool,
}

/// WHERE clauses over alias `b` with numbered text parameters.
fn browser_where(filter: &BrowserFilter, parts: BrowserFilterParts) -> (Vec<String>, Vec<String>) {
    let mut clauses = Vec::new();
    let mut params: Vec<String> = Vec::new();
    let bind = |params: &mut Vec<String>, value: String| {
        params.push(value);
        format!("?{}", params.len())
    };
    if !filter.input_ids.is_empty() {
        let marks: Vec<String> = filter.input_ids.iter().map(|id| bind(&mut params, id.clone())).collect();
        clauses.push(format!("b.input_id IN ({})", marks.join(",")));
    }
    if parts.kinds && !filter.kinds.is_empty() {
        let marks: Vec<String> = filter.kinds.iter().map(|kind| bind(&mut params, kind.clone())).collect();
        clauses.push(format!("b.event_type IN ({})", marks.join(",")));
    }
    if filter.untimed {
        clauses.push("b.timestamp IS NULL".into());
    } else {
        if parts.day {
            if let Some(day) = filter.day.as_ref().filter(|day| !day.is_empty()) {
                let from = bind(&mut params, day.clone());
                let to = bind(&mut params, format!("{day}~"));
                clauses.push(format!("b.timestamp >= {from} AND b.timestamp < {to}"));
            }
        }
        if let Some(start) = filter.start.as_ref().filter(|value| !value.is_empty()) {
            clauses.push(format!("b.timestamp >= {}", bind(&mut params, start.clone())));
        }
        if let Some(end) = filter.end.as_ref().filter(|value| !value.is_empty()) {
            clauses.push(format!("b.timestamp <= {}", bind(&mut params, end.clone())));
        }
    }
    if filter.referral {
        clauses.push("b.ai_referral_provider IS NOT NULL".into());
    }
    if parts.search {
        if let Some(needle) = filter.search.as_ref().filter(|value| !value.trim().is_empty()) {
            let n = bind(&mut params, like_contains(needle));
            let mut ors: Vec<String> = BROWSER_SEARCH_COLUMNS
                .iter()
                .map(|column| format!("b.{column} LIKE {n} ESCAPE '\\'"))
                .collect();
            // Child matches reduce to their parent row (EXISTS).
            ors.push(format!(
                "EXISTS (SELECT 1 FROM \"BrowserSearchTerms\" t WHERE t.summary_id IN (b.record_id, b.url_summary_id) \
                 AND (t.term LIKE {n} ESCAPE '\\' OR t.normalized_term LIKE {n} ESCAPE '\\'))"
            ));
            ors.push(format!(
                "EXISTS (SELECT 1 FROM \"BrowserDownloadChain\" c WHERE c.record_id = b.record_id \
                 AND (c.url LIKE {n} ESCAPE '\\' OR c.url_decoded LIKE {n} ESCAPE '\\'))"
            ));
            ors.push(format!(
                "EXISTS (SELECT 1 FROM \"BrowserCacheDetails\" d WHERE d.record_id = b.record_id \
                 AND (d.all_headers LIKE {n} ESCAPE '\\' OR d.status_line LIKE {n} ESCAPE '\\'))"
            ));
            clauses.push(format!("({})", ors.join(" OR ")));
        }
    }
    (clauses, params)
}

fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    }
}

fn text_refs(params: &[String]) -> Vec<&dyn rusqlite::ToSql> {
    params.iter().map(|value| value as &dyn rusqlite::ToSql).collect()
}

fn count_where(conn: &Connection, from: &str, clauses: &[String], params: &[String]) -> Result<i64, String> {
    conn.query_row(&format!("SELECT COUNT(*) FROM {from}{}", where_sql(clauses)), text_refs(params).as_slice(), |row| row.get(0))
        .map_err(|error| error.to_string())
}

fn browser_db_of(host_dir: &str) -> String {
    Path::new(host_dir).join("_OVERVIEW").join(BROWSER_DB).to_string_lossy().to_string()
}

/// One collected browser input (R10: label, confirmed account and SID apart).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserInputInfo {
    input_id: String,
    input_kind: String,
    browser: Option<String>,
    profile: Option<String>,
    account_label: Option<String>,
    account: Option<String>,
    account_sid: Option<String>,
    source_file: Option<String>,
    record_count: i64,
}

fn browser_scope_blocking(full_path: String) -> Result<Vec<BrowserInputInfo>, String> {
    let conn = open_ro(&full_path)?;
    let mut stmt = conn
        .prepare(
            "SELECT i.input_id, i.input_kind, i.browser, i.profile, i.account_label, i.account, i.account_sid, \
             i.source_file, (SELECT COUNT(*) FROM \"BrowserActivity\" b WHERE b.input_id = i.input_id) \
             FROM \"BrowserInputs\" i ORDER BY i.ordinal",
        )
        .map_err(|error| error.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserInputInfo {
                input_id: row.get(0)?,
                input_kind: row.get(1)?,
                browser: row.get(2)?,
                profile: row.get(3)?,
                account_label: row.get(4)?,
                account: row.get(5)?,
                account_sid: row.get(6)?,
                source_file: row.get(7)?,
                record_count: row.get(8)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
}

#[tauri::command]
async fn browser_scope(full_path: String) -> Result<Vec<BrowserInputInfo>, String> {
    tauri::async_runtime::spawn_blocking(move || browser_scope_blocking(full_path))
        .await
        .map_err(|error| format!("브라우저 입력 조회가 중단되었습니다: {error}"))?
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserDomainStat {
    domain: String,
    /// Individual visit events on this host.
    visit_count: i64,
    /// Distinct stored URLs on this host.
    url_count: i64,
}

/// Hostname of a stored absolute URL (display/grouping only).
fn browser_url_domain(value: &str) -> Option<String> {
    let parsed = Url::parse(value.trim()).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Visit events per host in scope (inputs + period); url_summary rows are not
/// visits and hostless URLs cannot form a domain.
fn browser_visit_domains(conn: &Connection, filter: &BrowserFilter) -> Result<Vec<BrowserDomainStat>, String> {
    let scope = BrowserFilter { kinds: Vec::new(), untimed: false, search: None, day: None, referral: false, ..filter.clone() };
    let (mut clauses, params) = browser_where(&scope, BrowserFilterParts { kinds: false, day: false, search: false });
    clauses.push("b.event_type = 'visit'".into());
    clauses.push("COALESCE(b.url, '') <> ''".into());
    let mut stmt = conn
        .prepare(&format!("SELECT b.url, COUNT(*) FROM \"BrowserActivity\" b{} GROUP BY b.url", where_sql(&clauses)))
        .map_err(|error| error.to_string())?;
    let mut totals: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut rows = stmt.query(text_refs(&params).as_slice()).map_err(|error| error.to_string())?;
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let url: String = row.get(0).map_err(|error| error.to_string())?;
        let visits: i64 = row.get(1).map_err(|error| error.to_string())?;
        let Some(domain) = browser_url_domain(&url) else { continue };
        let entry = totals.entry(domain).or_insert((0, 0));
        entry.0 += visits;
        entry.1 += 1;
    }
    let mut domains: Vec<BrowserDomainStat> = totals
        .into_iter()
        .map(|(domain, (visit_count, url_count))| BrowserDomainStat { domain, visit_count, url_count })
        .collect();
    domains.sort_by(|left, right| right.visit_count.cmp(&left.visit_count).then_with(|| left.domain.cmp(&right.domain)));
    Ok(domains)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserSummary {
    /// Event days (visit/download/cache), url_summary excluded.
    days: Vec<ColumnValue>,
    /// Records without a representative time in the selected kinds.
    untimed: i64,
    /// Records per kind in scope (inputs + period).
    kinds: Vec<ColumnValue>,
    visit_total: i64,
    top_domains: Vec<BrowserDomainStat>,
    domain_total: i64,
    download_total: i64,
    downloads: Vec<Map<String, Value>>,
}

fn browser_summary_blocking(full_path: String, filter: BrowserFilter) -> Result<BrowserSummary, String> {
    let conn = open_ro(&full_path)?;
    let scope = BrowserFilter { untimed: false, day: None, search: None, referral: false, ..filter.clone() };
    let no_search = BrowserFilterParts { kinds: true, day: false, search: false };

    let (mut day_clauses, day_params) = browser_where(&scope, no_search);
    day_clauses.push(format!("b.event_type IN {BROWSER_EVENT_KINDS}"));
    day_clauses.push("b.timestamp IS NOT NULL".into());
    let mut stmt = conn
        .prepare(&format!(
            "SELECT substr(b.timestamp, 1, 10), COUNT(*) FROM \"BrowserActivity\" b{} GROUP BY 1 ORDER BY 1",
            where_sql(&day_clauses)
        ))
        .map_err(|error| error.to_string())?;
    let days = stmt
        .query_map(text_refs(&day_params).as_slice(), |row| Ok(ColumnValue { value: row.get(0)?, count: row.get(1)? }))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;

    let untimed_filter = BrowserFilter { untimed: true, start: None, end: None, ..scope.clone() };
    let (untimed_clauses, untimed_params) = browser_where(&untimed_filter, no_search);
    let untimed = count_where(&conn, "\"BrowserActivity\" b", &untimed_clauses, &untimed_params)?;

    let all_kinds = BrowserFilter { kinds: Vec::new(), ..scope.clone() };
    let (kind_clauses, kind_params) = browser_where(&all_kinds, no_search);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT COALESCE(b.event_type, ''), COUNT(*) FROM \"BrowserActivity\" b{} GROUP BY 1 ORDER BY 1",
            where_sql(&kind_clauses)
        ))
        .map_err(|error| error.to_string())?;
    let kinds = stmt
        .query_map(text_refs(&kind_params).as_slice(), |row| Ok(ColumnValue { value: row.get(0)?, count: row.get(1)? }))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;

    let domains = browser_visit_domains(&conn, &scope)?;
    let visit_total = domains.iter().map(|domain| domain.visit_count).sum();
    let domain_total = i64::try_from(domains.len()).unwrap_or(i64::MAX);
    let top_domains = domains.into_iter().take(8).collect();

    let (mut download_clauses, download_params) = browser_where(&all_kinds, no_search);
    download_clauses.push("b.event_type = 'download'".into());
    let download_total = count_where(&conn, "\"BrowserActivity\" b", &download_clauses, &download_params)?;
    let mut downloads = query_rows(
        &conn,
        &format!(
            "SELECT {BROWSER_LIST_COLUMNS} FROM \"BrowserActivity\" b{} \
             ORDER BY b.timestamp IS NULL, b.timestamp DESC, b.record_id DESC LIMIT 8",
            where_sql(&download_clauses)
        ),
        text_refs(&download_params).as_slice(),
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut downloads)?;
    Ok(BrowserSummary { days, untimed, kinds, visit_total, top_domains, domain_total, download_total, downloads })
}

#[tauri::command]
async fn browser_summary(full_path: String, filter: BrowserFilter) -> Result<BrowserSummary, String> {
    tauri::async_runtime::spawn_blocking(move || browser_summary_blocking(full_path, filter))
        .await
        .map_err(|error| format!("브라우저 요약 작업이 중단되었습니다: {error}"))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserDomainPage {
    domains: Vec<BrowserDomainStat>,
    total: i64,
}

fn browser_domains_blocking(full_path: String, filter: BrowserFilter, offset: i64, limit: i64, ascending: bool) -> Result<BrowserDomainPage, String> {
    let conn = open_ro(&full_path)?;
    let mut domains = browser_visit_domains(&conn, &filter)?;
    if ascending {
        domains.reverse();
    }
    let total = i64::try_from(domains.len()).unwrap_or(i64::MAX);
    let domains = domains
        .into_iter()
        .skip(usize::try_from(offset.max(0)).unwrap_or(usize::MAX))
        .take(usize::try_from(limit.clamp(1, 100)).unwrap_or(100))
        .collect();
    Ok(BrowserDomainPage { domains, total })
}

#[tauri::command]
async fn browser_domains(full_path: String, filter: BrowserFilter, offset: i64, limit: i64, ascending: bool) -> Result<BrowserDomainPage, String> {
    tauri::async_runtime::spawn_blocking(move || browser_domains_blocking(full_path, filter, offset, limit, ascending))
        .await
        .map_err(|error| format!("도메인 통계 작업이 중단되었습니다: {error}"))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPage {
    rows: Vec<Map<String, Value>>,
    row_count: i64,
}

/// Time order with NULL times last and record_id as the tie-breaker (A04).
fn browser_page_blocking(full_path: String, filter: BrowserFilter, offset: i64, limit: i64, descending: bool) -> Result<BrowserPage, String> {
    let conn = open_ro(&full_path)?;
    let (clauses, mut params) = browser_where(&filter, BrowserFilterParts { kinds: true, day: true, search: true });
    let row_count = count_where(&conn, "\"BrowserActivity\" b", &clauses, &params)?;
    let direction = if descending { "DESC" } else { "ASC" };
    params.push(limit.clamp(1, 200).to_string());
    let limit_mark = params.len();
    params.push(offset.max(0).to_string());
    let offset_mark = params.len();
    let mut rows = query_rows(
        &conn,
        &format!(
            "SELECT {BROWSER_LIST_COLUMNS} FROM \"BrowserActivity\" b{} \
             ORDER BY b.timestamp IS NULL, b.timestamp {direction}, b.record_id {direction} LIMIT ?{limit_mark} OFFSET ?{offset_mark}",
            where_sql(&clauses)
        ),
        text_refs(&params).as_slice(),
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(BrowserPage { rows, row_count })
}

#[tauri::command]
async fn browser_page(full_path: String, filter: BrowserFilter, offset: i64, limit: i64, descending: bool) -> Result<BrowserPage, String> {
    tauri::async_runtime::spawn_blocking(move || browser_page_blocking(full_path, filter, offset, limit, descending))
        .await
        .map_err(|error| format!("브라우저 기록 작업이 중단되었습니다: {error}"))?
}

/// One record with its stored relations; the cache body itself is fetched
/// separately in chunks (R01, R17).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRecord {
    row: Map<String, Value>,
    input: Option<Map<String, Value>>,
    /// url_summary: its BrowserUrlSummaries row; visit: the summary record.
    url_summary: Option<Map<String, Value>>,
    search_terms: Vec<Map<String, Value>>,
    download_chain: Vec<Map<String, Value>>,
    /// BrowserCacheDetails without `body`, plus body_length/body_type.
    cache: Option<Map<String, Value>>,
    sources: Vec<Map<String, Value>>,
}

fn map_str(row: &Map<String, Value>, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()).map(str::to_string)
}

fn browser_record_blocking(host_dir: String, record_id: String) -> Result<BrowserRecord, String> {
    let full_path = browser_db_of(&host_dir);
    let conn = open_ro(&full_path)?;
    let mut rows = query_rows(&conn, "SELECT rowid AS __rowid, * FROM \"BrowserActivity\" WHERE record_id = ?1", &[&record_id])?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    let row = rows.pop().ok_or_else(|| "브라우저 기록을 찾을 수 없습니다".to_string())?;
    let input_id = map_str(&row, "input_id").unwrap_or_default();
    let input = query_rows(&conn, "SELECT * FROM \"BrowserInputs\" WHERE input_id = ?1", &[&input_id])?.pop();
    let summary_id = map_str(&row, "url_summary_id");
    let url_summary = if map_str(&row, "event_type").as_deref() == Some("url_summary") {
        query_rows(&conn, "SELECT * FROM \"BrowserUrlSummaries\" WHERE summary_id = ?1", &[&record_id])?.pop()
    } else if let Some(summary_id) = &summary_id {
        query_rows(
            &conn,
            "SELECT rowid AS __rowid, record_id, timestamp, timestamp_kind, url, title, visit_count, typed_count \
             FROM \"BrowserActivity\" WHERE record_id = ?1 AND input_id = ?2",
            &[summary_id, &input_id],
        )?
        .pop()
    } else {
        None
    };
    let summary_key = summary_id.unwrap_or_default();
    let search_terms = query_rows(
        &conn,
        "SELECT * FROM \"BrowserSearchTerms\" WHERE summary_id IN (?1, ?2) ORDER BY term, search_id",
        &[&record_id, &summary_key],
    )?;
    let download_chain = query_rows(&conn, "SELECT * FROM \"BrowserDownloadChain\" WHERE record_id = ?1 ORDER BY ordinal", &[&record_id])?;
    let cache = query_rows(
        &conn,
        "SELECT record_id, cache_key, request_url, status_line, http_status, http_reason, content_type, \
         content_encoding, content_length, body_size, body_file, body_recovered, body_bytes, all_headers, server, \
         date, last_modified, etag, cache_control, location, length(CAST(body AS BLOB)) AS body_length, \
         typeof(body) AS body_type FROM \"BrowserCacheDetails\" WHERE record_id = ?1",
        &[&record_id],
    )?
    .pop();
    let sources = query_rows(&conn, "SELECT * FROM \"source_records\" WHERE record_id = ?1 ORDER BY ordinal", &[&record_id])?;
    Ok(BrowserRecord { row, input, url_summary, search_terms, download_chain, cache, sources })
}

#[tauri::command]
async fn browser_record(host_dir: String, record_id: String) -> Result<BrowserRecord, String> {
    tauri::async_runtime::spawn_blocking(move || browser_record_blocking(host_dir, record_id))
        .await
        .map_err(|error| format!("브라우저 기록 상세 조회가 중단되었습니다: {error}"))?
}

/// A byte range of one stored cache body (TEXT or BLOB), base64 encoded.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserCacheBody {
    data_b64: String,
    offset: i64,
    total: i64,
}

fn browser_cache_body_blocking(host_dir: String, record_id: String, offset: i64, length: i64) -> Result<BrowserCacheBody, String> {
    use base64::Engine as _;
    let conn = open_ro(&browser_db_of(&host_dir))?;
    let offset = offset.max(0);
    let length = length.clamp(1, BROWSER_CACHE_CHUNK_MAX);
    let (bytes, total): (Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT substr(CAST(body AS BLOB), ?2 + 1, ?3), length(CAST(body AS BLOB)) FROM \"BrowserCacheDetails\" WHERE record_id = ?1",
            rusqlite::params![record_id, offset, length],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("캐시 본문을 찾을 수 없습니다: {error}"))?;
    let total = total.ok_or_else(|| "저장된 캐시 본문이 없습니다".to_string())?;
    Ok(BrowserCacheBody {
        data_b64: base64::engine::general_purpose::STANDARD.encode(bytes.unwrap_or_default()),
        offset,
        total,
    })
}

#[tauri::command]
async fn browser_cache_body(host_dir: String, record_id: String, offset: i64, length: i64) -> Result<BrowserCacheBody, String> {
    tauri::async_runtime::spawn_blocking(move || browser_cache_body_blocking(host_dir, record_id, offset, length))
        .await
        .map_err(|error| format!("캐시 본문 조회가 중단되었습니다: {error}"))?
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct VisitFlowNode {
    record_id: String,
    visit_id: String,
    url: String,
    title: String,
    time: String,
    transition: String,
    qualifiers: String,
    external_referrer: String,
    is_target: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VisitFlowEdge {
    from: String,
    to: String,
    /// "from_visit" (same tab) or "opener_visit" (new tab).
    kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserVisitFlow {
    nodes: Vec<VisitFlowNode>,
    edges: Vec<VisitFlowEdge>,
    truncated: bool,
}

/// Navigation around one visit from stored relations, both directions, inside
/// the visit's own input only (R08).
fn browser_visit_flow_blocking(host_dir: String, record_id: String) -> Result<BrowserVisitFlow, String> {
    let conn = open_ro(&browser_db_of(&host_dir))?;
    let input_id: String = conn
        .query_row("SELECT input_id FROM \"BrowserActivity\" WHERE record_id = ?1 AND event_type = 'visit'", [&record_id], |row| row.get(0))
        .map_err(|_| "방문 기록이 아닙니다".to_string())?;
    let fetch = |sql: &str, key: &str| -> Result<Vec<Map<String, Value>>, String> {
        query_rows(&conn, sql, &[&key, &input_id])
    };
    const NODE: &str = "SELECT record_id, visit_id, url, title, timestamp, transition_core, transition_qualifiers, \
         external_referrer_url, from_record_id, opener_record_id FROM \"BrowserActivity\" ";
    let mut nodes: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut edges: Vec<(String, String, String)> = Vec::new();
    let mut queue: VecDeque<String> = VecDeque::from([record_id.clone()]);
    let mut truncated = false;
    if let Some(start) = fetch(&format!("{NODE}WHERE record_id = ?1 AND input_id = ?2"), &record_id)?.pop() {
        nodes.insert(record_id.clone(), start);
    }
    while let Some(id) = queue.pop_front() {
        let Some(node) = nodes.get(&id).cloned() else { continue };
        let mut neighbors: Vec<Map<String, Value>> = Vec::new();
        for (column, kind) in [("from_record_id", "from_visit"), ("opener_record_id", "opener_visit")] {
            if let Some(parent) = map_str(&node, column) {
                edges.push((parent.clone(), id.clone(), kind.to_string()));
                neighbors.extend(fetch(&format!("{NODE}WHERE record_id = ?1 AND input_id = ?2 AND event_type = 'visit'"), &parent)?);
            }
            for child in fetch(&format!("{NODE}WHERE {column} = ?1 AND input_id = ?2 AND event_type = 'visit'"), &id)? {
                if let Some(child_id) = map_str(&child, "record_id") {
                    edges.push((id.clone(), child_id, kind.to_string()));
                }
                neighbors.push(child);
            }
        }
        for neighbor in neighbors {
            let Some(neighbor_id) = map_str(&neighbor, "record_id") else { continue };
            if nodes.contains_key(&neighbor_id) {
                continue;
            }
            if nodes.len() >= BROWSER_FLOW_MAX_NODES {
                truncated = true;
                continue;
            }
            nodes.insert(neighbor_id.clone(), neighbor);
            queue.push_back(neighbor_id);
        }
    }
    let text = |row: &Map<String, Value>, key: &str| map_str(row, key).unwrap_or_default();
    let mut flow_nodes: Vec<VisitFlowNode> = nodes
        .iter()
        .map(|(id, row)| VisitFlowNode {
            record_id: id.clone(),
            visit_id: text(row, "visit_id"),
            url: text(row, "url"),
            title: text(row, "title"),
            time: text(row, "timestamp"),
            transition: text(row, "transition_core"),
            qualifiers: text(row, "transition_qualifiers"),
            external_referrer: text(row, "external_referrer_url"),
            is_target: *id == record_id,
        })
        .collect();
    flow_nodes.sort_by(|left, right| left.time.cmp(&right.time).then_with(|| left.record_id.cmp(&right.record_id)));
    let mut seen = HashSet::new();
    let flow_edges = edges
        .into_iter()
        .filter(|(from, to, _)| nodes.contains_key(from) && nodes.contains_key(to))
        .filter(|edge| seen.insert(edge.clone()))
        .map(|(from, to, kind)| VisitFlowEdge { from, to, kind })
        .collect();
    Ok(BrowserVisitFlow { nodes: flow_nodes, edges: flow_edges, truncated })
}

#[tauri::command]
async fn browser_visit_flow(host_dir: String, record_id: String) -> Result<BrowserVisitFlow, String> {
    tauri::async_runtime::spawn_blocking(move || browser_visit_flow_blocking(host_dir, record_id))
        .await
        .map_err(|error| format!("이동 흐름 조회가 중단되었습니다: {error}"))?
}

const AI_LIST_COLUMNS: &str = "a.rowid AS __rowid, a.record_id, a.host_id, a.dataset_id, a.overview_name, \
     a.timestamp, a.timestamp_kind, a.event_type, a.description, a.record_kind, a.provider, a.conversation_id, \
     a.service_account, a.title, a.created_at, a.updated_at, a.url, a.browser, a.profile, a.input_label, \
     a.account, a.account_sid, a.input_kind, a.body_recovered, a.message_count, a.current_branch_message_count, \
     a.structural_node_count, a.attachment_count, a.list_ordinal, a.list_item_count, a.list_declared_total";

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct AiQuery {
    /// conversation | list_entry (empty: both).
    kind: Option<String>,
    untimed: bool,
    start: Option<String>,
    end: Option<String>,
    search: Option<String>,
    offset: i64,
    limit: i64,
    ascending: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiPage {
    rows: Vec<Map<String, Value>>,
    row_count: i64,
    /// Records per kind under the same filter without the kind choice.
    kinds: Vec<ColumnValue>,
}

fn ai_where(query: &AiQuery, with_kind: bool) -> (Vec<String>, Vec<String>) {
    let mut clauses = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if with_kind {
        if let Some(kind) = query.kind.as_ref().filter(|kind| !kind.is_empty()) {
            params.push(kind.clone());
            clauses.push(format!("a.record_kind = ?{}", params.len()));
        }
    }
    if query.untimed {
        clauses.push("a.timestamp IS NULL".into());
    } else {
        if let Some(start) = query.start.as_ref().filter(|value| !value.is_empty()) {
            params.push(start.clone());
            clauses.push(format!("a.timestamp >= ?{}", params.len()));
        }
        if let Some(end) = query.end.as_ref().filter(|value| !value.is_empty()) {
            params.push(end.clone());
            clauses.push(format!("a.timestamp <= ?{}", params.len()));
        }
    }
    if let Some(needle) = query.search.as_ref().filter(|value| !value.trim().is_empty()) {
        params.push(like_contains(needle));
        let n = params.len();
        let mut ors: Vec<String> = ["title", "conversation_id", "service_account", "url", "provider", "account", "account_sid", "input_label"]
            .iter()
            .map(|column| format!("a.{column} LIKE ?{n} ESCAPE '\\'"))
            .collect();
        ors.push(format!(
            "EXISTS (SELECT 1 FROM \"AiConversationTexts\" t WHERE t.record_id = a.record_id \
             AND t.text_kind = 'search_text' AND t.text_value LIKE ?{n} ESCAPE '\\')"
        ));
        clauses.push(format!("({})", ors.join(" OR ")));
    }
    (clauses, params)
}

fn ai_page_blocking(full_path: String, query: AiQuery) -> Result<AiPage, String> {
    let conn = open_ro(&full_path)?;
    let (clauses, mut params) = ai_where(&query, true);
    let row_count = count_where(&conn, "\"AiConversations\" a", &clauses, &params)?;
    let (kind_clauses, kind_params) = ai_where(&query, false);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT a.record_kind, COUNT(*) FROM \"AiConversations\" a{} GROUP BY 1 ORDER BY 1",
            where_sql(&kind_clauses)
        ))
        .map_err(|error| error.to_string())?;
    let kinds = stmt
        .query_map(text_refs(&kind_params).as_slice(), |row| Ok(ColumnValue { value: row.get(0)?, count: row.get(1)? }))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let direction = if query.ascending { "ASC" } else { "DESC" };
    params.push(query.limit.clamp(1, 100).to_string());
    let limit_mark = params.len();
    params.push(query.offset.max(0).to_string());
    let offset_mark = params.len();
    let mut rows = query_rows(
        &conn,
        &format!(
            "SELECT {AI_LIST_COLUMNS} FROM \"AiConversations\" a{} \
             ORDER BY a.timestamp IS NULL, a.timestamp {direction}, a.record_id {direction} LIMIT ?{limit_mark} OFFSET ?{offset_mark}",
            where_sql(&clauses)
        ),
        text_refs(&params).as_slice(),
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(AiPage { rows, row_count, kinds })
}

#[tauri::command]
async fn ai_page(full_path: String, query: AiQuery) -> Result<AiPage, String> {
    tauri::async_runtime::spawn_blocking(move || ai_page_blocking(full_path, query))
        .await
        .map_err(|error| format!("AI 대화 조회가 중단되었습니다: {error}"))?
}

/// One AI record: stored messages, attachments, interpretation JSON, evidence
/// sources (with collected response sizes) and other snapshots of the same
/// conversation (A03, R13, R14, R18).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiRecord {
    row: Map<String, Value>,
    messages: Vec<Map<String, Value>>,
    attachments: Vec<Map<String, Value>>,
    interpretation: Option<String>,
    sources: Vec<Map<String, Value>>,
    snapshots: Vec<Map<String, Value>>,
}

fn ai_record_blocking(full_path: String, record_id: String) -> Result<AiRecord, String> {
    let conn = open_ro(&full_path)?;
    let mut rows = query_rows(&conn, &format!("SELECT {AI_LIST_COLUMNS} FROM \"AiConversations\" a WHERE a.record_id = ?1"), &[&record_id])?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    let row = rows.pop().ok_or_else(|| "AI 대화 기록을 찾을 수 없습니다".to_string())?;
    let messages = query_rows(&conn, "SELECT * FROM \"AiMessages\" WHERE record_id = ?1 ORDER BY ordinal", &[&record_id])?;
    let attachments = query_rows(&conn, "SELECT * FROM \"AiAttachments\" WHERE record_id = ?1 ORDER BY ordinal", &[&record_id])?;
    let interpretation = conn
        .query_row(
            "SELECT text_value FROM \"AiConversationTexts\" WHERE record_id = ?1 AND text_kind = 'interpretation_json' ORDER BY ordinal LIMIT 1",
            [&record_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten();
    let sources = query_rows(
        &conn,
        "SELECT s.*, r.byte_length AS response_length FROM \"source_records\" s \
         LEFT JOIN \"AiResponseBodies\" r ON r.source_db = s.source_db AND r.source_table = s.source_table \
         AND r.source_rowid = s.source_rowid WHERE s.record_id = ?1 ORDER BY s.ordinal",
        &[&record_id],
    )?;
    let provider = map_str(&row, "provider").unwrap_or_default();
    let snapshots = match map_str(&row, "conversation_id") {
        Some(conversation_id) => {
            let mut snapshots = query_rows(
                &conn,
                &format!(
                    "SELECT {AI_LIST_COLUMNS} FROM \"AiConversations\" a WHERE a.conversation_id = ?1 \
                     AND COALESCE(a.provider, '') = ?2 AND a.record_id <> ?3 \
                     ORDER BY a.timestamp IS NULL, a.timestamp DESC, a.record_id DESC LIMIT 200"
                ),
                &[&conversation_id, &provider, &record_id],
            )?;
            decorate_source_refs(&conn, Path::new(&full_path), &mut snapshots)?;
            snapshots
        }
        None => Vec::new(),
    };
    Ok(AiRecord { row, messages, attachments, interpretation, sources, snapshots })
}

#[tauri::command]
async fn ai_record(full_path: String, record_id: String) -> Result<AiRecord, String> {
    tauri::async_runtime::spawn_blocking(move || ai_record_blocking(full_path, record_id))
        .await
        .map_err(|error| format!("AI 대화 상세 조회가 중단되었습니다: {error}"))?
}

/// A character range of one collected response body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiResponseChunk {
    data: String,
    offset: i64,
    total: i64,
}

fn ai_response_body_blocking(full_path: String, source_db: String, source_table: String, source_rowid: i64, offset: i64, length: i64) -> Result<AiResponseChunk, String> {
    let conn = open_ro(&full_path)?;
    let offset = offset.max(0);
    let length = length.clamp(1, 4 * 1024 * 1024);
    conn.query_row(
        "SELECT substr(response_body, ?4 + 1, ?5), length(response_body) FROM \"AiResponseBodies\" \
         WHERE source_db = ?1 AND source_table = ?2 AND source_rowid = ?3",
        rusqlite::params![source_db, source_table, source_rowid, offset, length],
        |row| Ok(AiResponseChunk { data: row.get(0)?, offset, total: row.get(1)? }),
    )
    .map_err(|error| format!("수집 응답 원문을 찾을 수 없습니다: {error}"))
}

#[tauri::command]
async fn ai_response_body(full_path: String, source_db: String, source_table: String, source_rowid: i64, offset: i64, length: i64) -> Result<AiResponseChunk, String> {
    tauri::async_runtime::spawn_blocking(move || ai_response_body_blocking(full_path, source_db, source_table, source_rowid, offset, length))
        .await
        .map_err(|error| format!("수집 응답 원문 조회가 중단되었습니다: {error}"))?
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
    tauri::async_runtime::spawn_blocking(move || powershell_search_rowids_blocking(&full_path, &query))
        .await
        .map_err(|error| format!("파워셸 검색 작업이 중단되었습니다: {error}"))?
}

fn powershell_search_rowids_blocking(full_path: &str, query: &str) -> Result<Vec<i64>, String> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let conn = open_ro(full_path)?;
    let like = format!(
        "%{}%",
        needle
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );
    // Full stored text (docs viewer-02): command, script, host command line,
    // script path, 4100 error/context and decoded EncodedCommand. Columns
    // and the decode child exist only from powershell_history=3.
    let columns = table_columns(&conn, "PowerShellHistory");
    let mut clauses: Vec<String> = ["command", "script_block", "host_application", "script_path", "error_message", "context_info"]
        .iter()
        .filter(|column| columns.iter().any(|c| c == *column))
        .map(|column| format!("lower(COALESCE(p.{column},'')) LIKE ?1 ESCAPE '\\'"))
        .collect();
    if table_names(&conn).iter().any(|name| name == "PowerShellEncodedCommands") {
        clauses.push(
            "EXISTS (SELECT 1 FROM \"PowerShellEncodedCommands\" e WHERE e.record_id = p.record_id \
             AND lower(COALESCE(e.decoded_command,'')) LIKE ?1 ESCAPE '\\')"
                .to_string(),
        );
    }
    if clauses.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!("SELECT p.rowid FROM \"PowerShellHistory\" p WHERE {}", clauses.join(" OR "));
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([&like], |r| r.get::<_, i64>(0))
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
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
    let table = match table_name.or_else(|| first_table(&conn, Path::new(&full_path))) {
        Some(t) => t,
        None => {
            return Ok(CsvData {
                columns: vec![],
                rows: vec![],
                row_count: 0,
            })
        }
    };
    // Body BLOBs and cache bodies are detail-only, never in list responses.
    let columns = payload_columns(&conn, &table);
    let Some(projection) = payload_projection(&columns) else {
        return Ok(CsvData {
            columns,
            rows: vec![],
            row_count: 0,
        });
    };
    let is_cache = table == "CacheEntries";
    // 4104 ScriptBlock 본문은 행당 수 KB~수백 KB — 대량 스크립트 블록 로깅
    // 호스트에서 전량 직렬화하면 웹뷰 메모리가 고갈돼 앱이 강제 종료된다.
    // 목록/세션 묶음에는 앞부분 미리보기만 싣고, 상세 패널은 result_row로
    // 전체 원문을 다시 받는다 (증거 원문은 절단 없이 유지).
    let select = if table == "PowerShellHistory" {
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
        projection
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
        format!("SELECT rowid AS __rowid, {} FROM {}", select, q(&table))
    };
    let mut rows = query_rows(&conn, &sql, &[])?;
    // Attach this page's raw evidence identities in one batch so raw, overview,
    // timeline and search share the same bookmark key.
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
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
    let table = match table_name.or_else(|| first_table(&conn, Path::new(&full_path))) {
        Some(t) => t,
        None => {
            return Ok(CsvData {
                columns: vec![],
                rows: vec![],
                row_count: 0,
            })
        }
    };
    let row_count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", q(&table)), [], |r| {
            r.get(0)
        })
        .unwrap_or(0);
    // 열 선택·정렬·값 변환은 타임라인 빌드 경로와 같은 리더를 쓴다. 일반 표는
    // 바이트 예산 없이 요청한 행 수만큼 받는다(페이지 계약이 행 수 기준).
    let mut page = read_sqlite_page(
        &conn,
        &table,
        offset.max(0),
        limit.clamp(1, 100_000),
        None,
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut page.rows)?;
    Ok(CsvData {
        columns: page.columns,
        rows: page.rows,
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
    let columns = payload_columns(&conn, &table_name);
    let Some(projection) = payload_projection(&columns) else {
        return Err("linked result table was not found".to_owned());
    };
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
        "SELECT rowid AS __rowid, {} FROM {} WHERE {} ORDER BY rowid LIMIT ? OFFSET ?",
        projection,
        q(&table_name),
        where_clause,
    );
    let mut rows = query_rows(&conn, &sql, page_params.as_slice())?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
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
    // A detail row carries no body BLOB either; bytes leave only through an
    // explicit request (mft_record_body / cache_entry_body).
    let columns = payload_columns(&conn, &table_name);
    let Some(projection) = payload_projection(&columns) else {
        return Ok(ResultRow { columns, row: None });
    };
    let sql = format!(
        "SELECT rowid AS __rowid, {} FROM {} WHERE rowid = ?1",
        projection,
        q(&table_name)
    );
    let mut rows = query_rows(&conn, &sql, &[&rowid])?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    let row = rows.into_iter().next();
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

/// docs-20: a bookmarked _OVERVIEW row by its record_id (rowids are not kept).
fn result_row_by_record_id_blocking(
    full_path: String,
    table_name: String,
    record_id: String,
) -> Result<ResultRow, String> {
    let conn = open_ro(&full_path)?;
    let sql = format!("SELECT rowid FROM {} WHERE record_id = ?1 LIMIT 1", q(&table_name));
    match conn.query_row(&sql, [&record_id], |row| row.get::<_, i64>(0)) {
        Ok(rowid) => result_row_blocking(full_path, table_name, rowid),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(ResultRow { columns: payload_columns(&conn, &table_name), row: None }),
        Err(error) => Err(format!("행 조회에 실패했습니다: {error}")),
    }
}

#[tauri::command]
async fn result_row_by_record_id(
    full_path: String,
    table_name: String,
    record_id: String,
) -> Result<ResultRow, String> {
    tauri::async_runtime::spawn_blocking(move || result_row_by_record_id_blocking(full_path, table_name, record_id))
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
    let table = match table_name.or_else(|| first_table(&conn, Path::new(&full_path))) {
        Some(t) => t,
        None => return vec![],
    };
    // Body BLOBs are not filter candidates: never GROUP BY raw bytes.
    if !payload_columns(&conn, &table).contains(&column) {
        return vec![];
    }
    // 필터 드롭다운은 최빈값 상위 N개만 필요하다. 고카디널리티 컬럼(MFT path,
    // timestamp 등)은 고유값이 수십만이라 전량을 IPC로 실으면 웹뷰 메모리가
    // 커지므로 상위 빈도만 잘라 보낸다 — 그 밖의 값은 검색으로 찾는다.
    const LIST_COLUMN_VALUES_MAX: usize = 2000;
    let sql = format!(
        "SELECT {c} AS value, COUNT(*) AS count FROM {t} GROUP BY {c} ORDER BY count DESC LIMIT {lim}",
        c = q(&column),
        t = q(&table),
        lim = LIST_COLUMN_VALUES_MAX,
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

/// Display-facing derived table (docs-01 §18). The file-system screens read
/// only this; raw MFT_Records is never a display fallback (docs-24 §0).
const FILE_SYSTEM_TABLE: &str = "FileSystemEntries";

fn file_system_table(conn: &Connection) -> Result<String, String> {
    if table_names(conn).iter().any(|name| name == FILE_SYSTEM_TABLE) {
        Ok(FILE_SYSTEM_TABLE.to_string())
    } else {
        Err("파일 시스템 레코드 테이블(FileSystemEntries)을 찾을 수 없습니다. 호스트를 다시 파싱하세요.".to_string())
    }
}

/// Records whose stored parent link is not verified (docs-04 §0): never
/// attached under a folder, listed in the separate "unlinked" bucket.
const UNLINKED_PARENT: &str = "(parent_status IS NULL OR parent_status NOT IN ('verified', 'root'))";

/// Volume scope for a query. `entry`/`parent_entry` are meaningful only inside
/// one volume_id (docs-01 §18), so the chosen volume is applied as a condition.
/// Without a chosen volume, or without the column, no scope is applied — record
/// numbers of different volumes are never merged, and no volume is inferred.
fn volume_scope(columns: &[String], volume_id: Option<String>) -> Option<String> {
    let volume = volume_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    columns
        .iter()
        .any(|column| column == "volume_id")
        .then_some(volume)
}

#[tauri::command]
async fn mft_children(
    full_path: String,
    parent_entry: Option<i64>,
    parent_seq: Option<i64>,
    volume_id: Option<String>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<MftChildrenPage, String> {
    // 대형 수집본의 폴더 탐색이 다른 IPC 응답성을 막지 않게 blocking
    // executor로 분리한다 (Browser Activity·Cache 본문과 같은 규칙).
    tauri::async_runtime::spawn_blocking(move || {
        mft_children_blocking(
            full_path,
            parent_entry,
            parent_seq,
            volume_id,
            offset.unwrap_or(0),
            limit.unwrap_or(100),
        )
    })
    .await
    .map_err(|error| format!("MFT 자식 조회 작업이 중단되었습니다: {error}"))?
}

/// One folder page of the explorer tree, from the stored link verification
/// (docs-04 §0/§4): a child belongs to a folder only when `parent_status` is
/// `verified` and its `parent_seq` equals the folder's `seq`. The tree never
/// re-derives or loosens that link (no NULL-tolerant match).
///
/// `parent_seq` None with a parent means the volume root: its seq is read
/// from the record stored as `parent_status = 'root'`. `parent_entry` None
/// lists the unlinked bucket (sequence mismatch / unknown parent).
///
/// 읽기·쿼리 실패는 빈 폴더가 아니라 오류로 전파한다 — 실패를 "비어 있음"으로
/// 표시하면 잘못된 증거 해석으로 이어진다.
fn mft_children_blocking(
    full_path: String,
    parent_entry: Option<i64>,
    parent_seq: Option<i64>,
    volume_id: Option<String>,
    offset: i64,
    limit: i64,
) -> Result<MftChildrenPage, String> {
    let conn = open_ro(&full_path)?;
    let table = file_system_table(&conn)?;
    // Resident bodies (data BLOB) are detail-only, never in a listing.
    let columns = payload_columns(&conn, &table);
    let Some(projection) = payload_projection(&columns) else {
        return Err("파일 시스템 레코드 컬럼을 읽지 못했습니다".to_string());
    };
    if !columns.iter().any(|column| column == "parent_status") {
        return Err("부모 연결 상태가 없는 이전 결과입니다. 호스트를 다시 파싱하세요.".to_string());
    }
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);
    let volume = volume_scope(&columns, volume_id);

    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(volume) = volume.as_ref() {
        binds.push(Box::new(volume.clone()));
        conditions.push(format!("volume_id = ?{}", binds.len()));
    }
    match parent_entry {
        Some(parent) => {
            let seq = match parent_seq {
                Some(seq) => Some(seq),
                None => {
                    // Root folder: the record the parser stored as the root.
                    let mut sql = format!(
                        "SELECT seq FROM {} WHERE entry = ?1 AND parent_status = 'root'",
                        q(&table)
                    );
                    if volume.is_some() {
                        sql.push_str(" AND volume_id = ?2");
                    }
                    let found: rusqlite::Result<Option<i64>> = match volume.as_ref() {
                        Some(volume) => conn.query_row(&sql, rusqlite::params![parent, volume], |row| row.get(0)),
                        None => conn.query_row(&sql, rusqlite::params![parent], |row| row.get(0)),
                    };
                    match found {
                        Ok(seq) => seq,
                        Err(rusqlite::Error::QueryReturnedNoRows) => None,
                        Err(error) => return Err(format!("루트 레코드를 읽지 못했습니다: {error}")),
                    }
                }
            };
            // Without the folder's seq no child can be verified as its own.
            let Some(seq) = seq else {
                return Ok(MftChildrenPage { rows: Vec::new(), total: 0 });
            };
            binds.push(Box::new(parent));
            let n = binds.len();
            binds.push(Box::new(seq));
            conditions.push(format!(
                "parent_entry = ?{n} AND entry <> ?{n} AND parent_seq = ?{} AND parent_status = 'verified'",
                binds.len()
            ));
        }
        None => conditions.push(UNLINKED_PARENT.to_string()),
    }
    let where_clause = conditions.join(" AND ");
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|value| value.as_ref()).collect();

    // 전체 건수는 첫 페이지에서만 계산한다 — 후속 페이지는 -1.
    let total: i64 = if offset == 0 {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE {where_clause}", q(&table)),
            refs.as_slice(),
            |row| row.get(0),
        )
        .map_err(|error| format!("MFT 자식 수 조회 실패: {error}"))?
    } else {
        -1
    };
    let mut page_refs = refs.clone();
    page_refs.push(&limit);
    let limit_index = page_refs.len();
    page_refs.push(&offset);
    let offset_index = page_refs.len();
    // is_directory is 0/1/NULL: DESC puts directories first, unknown last;
    // record_id fixes the order of equal names (docs-24 §2).
    let sql = format!(
        "SELECT rowid AS __rowid, {projection} FROM {} WHERE {where_clause} \
         ORDER BY is_directory DESC, file_name IS NULL, file_name COLLATE NOCASE, record_id \
         LIMIT ?{limit_index} OFFSET ?{offset_index}",
        q(&table)
    );
    let mut rows = query_rows(&conn, &sql, page_refs.as_slice())?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(MftChildrenPage { rows, total })
}

#[tauri::command]
async fn mft_search(
    full_path: String,
    query: String,
    volume_id: Option<String>,
    limit: i64,
) -> Result<Vec<Map<String, Value>>, String> {
    // 수백만 행 MFT의 LIKE 풀스캔 — 검색이 메인 스레드를 막지 않게 blocking
    // 풀에서 돈다.
    tauri::async_runtime::spawn_blocking(move || {
        mft_search_blocking(full_path, query, volume_id, limit)
    })
    .await
    .map_err(|error| format!("MFT 검색 작업이 중단되었습니다: {error}"))?
}

fn mft_search_blocking(
    full_path: String,
    query: String,
    volume_id: Option<String>,
    limit: i64,
) -> Result<Vec<Map<String, Value>>, String> {
    // DB 열기·쿼리 실패를 빈 결과로 위장하지 않는다 — "일치 없음"과
    // "조회 실패"는 분석 판단이 달라지는 별개의 상태다.
    let conn = open_ro(&full_path)?;
    let table = file_system_table(&conn)?;
    let columns = payload_columns(&conn, &table);
    let Some(projection) = payload_projection(&columns) else {
        return Err("파일 시스템 레코드 컬럼을 읽지 못했습니다".to_string());
    };
    // 호출자 값에 의존하지 않는 서버 측 상한.
    let limit = limit.clamp(1, 500);
    let like = like_contains(&query);
    let volume = volume_scope(&columns, volume_id);
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&like];
    let mut conditions = vec![fs_text_match(1)];
    if let Some(volume) = volume.as_ref() {
        binds.push(volume);
        conditions.push(format!("volume_id = ?{}", binds.len()));
    }
    binds.push(&limit);
    let sql = format!(
        "SELECT rowid AS __rowid, {projection} FROM {} WHERE {} \
         ORDER BY is_directory DESC, path IS NULL, path COLLATE NOCASE, record_id LIMIT ?{}",
        q(&table),
        conditions.join(" AND "),
        binds.len()
    );
    let mut rows = query_rows(&conn, &sql, binds.as_slice())?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(rows)
}

/// `%needle%` with LIKE metacharacters escaped (use with `ESCAPE '\'`).
fn like_contains(needle: &str) -> String {
    let escaped = needle.trim().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{escaped}%")
}

/// docs-04 §3 search fields: name, path, extension and account name/SID.
fn fs_text_match(n: usize) -> String {
    format!(
        "(file_name LIKE ?{n} ESCAPE '\\' OR path LIKE ?{n} ESCAPE '\\' OR extension LIKE ?{n} ESCAPE '\\' \
         OR account LIKE ?{n} ESCAPE '\\' OR account_sid LIKE ?{n} ESCAPE '\\')"
    )
}

/// Volume selector list: the internal key that separates volumes inside one
/// result, plus label and drive letter when `$Volume`/collection metadata
/// confirmed them. Unknown values stay NULL and are never guessed from the
/// collection folder name (docs-01 §18).
#[tauri::command]
async fn mft_volumes(db_path: String) -> Result<Vec<Map<String, Value>>, String> {
    tauri::async_runtime::spawn_blocking(move || mft_volumes_blocking(db_path))
        .await
        .map_err(|error| format!("볼륨 목록 조회가 중단되었습니다: {error}"))?
}

fn mft_volumes_blocking(db_path: String) -> Result<Vec<Map<String, Value>>, String> {
    let conn = open_ro(&db_path)?;
    let table = file_system_table(&conn)?;
    let columns = table_columns(&conn, &table);
    if !columns.iter().any(|column| column == "volume_id") {
        // No volume column: nothing to build a selector from.
        return Ok(Vec::new());
    }
    // Display identity of each input (docs-04 §0): confirmed drive/label when
    // stored, plus input name and collection-relative path so inputs stay
    // distinguishable even when those are NULL. Nothing is guessed.
    let pick = |column: &str| {
        if columns.iter().any(|c| c == column) {
            format!("MAX({column}) AS {column}")
        } else {
            format!("NULL AS {column}")
        }
    };
    let sql = format!(
        "SELECT volume_id, {}, {}, {}, {}, COUNT(*) AS record_count FROM {} \
         GROUP BY volume_id ORDER BY volume_id",
        pick("volume_label"),
        pick("drive_letter"),
        pick("input_name"),
        pick("source_relative"),
        q(&table)
    );
    query_rows(&conn, &sql, &[])
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

/// docs-05: one collected `$J` input (internal key, not a volume/journal ID).
#[derive(Serialize)]
struct UsnInput {
    input_id: String,
    input_name: Option<String>,
    source_relative: Option<String>,
    record_count: i64,
    group_count: i64,
}

#[derive(Serialize)]
struct UsnFilterOption {
    value: String,
    count: i64,
}

/// Inputs plus the stored representative types (per group) and reason flags
/// (per record) of one input, for the filter controls.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UsnOverview {
    inputs: Vec<UsnInput>,
    event_types: Vec<UsnFilterOption>,
    reason_flags: Vec<UsnFilterOption>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct UsnGroupOptions {
    input_id: Option<String>,
    /// File name, stored reason text or path of a member (LIKE, literal).
    search: Option<String>,
    /// Representative type of the stored group (`UsnChangeGroups.event_type`).
    event_type: Option<String>,
    /// Full reasons: a member holding any of these flags (`UsnReasonFlags`).
    reason_flags: Option<Vec<String>>,
    /// Period on member timestamps.
    time_start: Option<String>,
    time_end: Option<String>,
    descending: Option<bool>,
}

/// One stored group with every member (stored order) and its rename events.
#[derive(Serialize)]
struct UsnGroupEntry {
    group: Map<String, Value>,
    members: Vec<Map<String, Value>>,
    renames: Vec<UsnRenameEntry>,
}

/// A stored rename event with every OLD/NEW candidate (docs-05 §0/§1). The
/// parent reference comes from the candidate's linked journal record.
#[derive(Serialize, Clone)]
struct UsnRenameEntry {
    event: Map<String, Value>,
    candidates: Vec<Map<String, Value>>,
}

#[derive(Serialize)]
struct UsnGroupsPage {
    groups: Vec<UsnGroupEntry>,
    total: i64,
}

const USN_TABLES: [&str; 6] = ["UsnJournal", "UsnChangeGroups", "UsnGroupMembers", "UsnReasonFlags", "UsnRenameEvents", "UsnRenameCandidates"];

fn open_usn_journal(full_path: &str) -> Result<Connection, String> {
    let conn = open_ro(full_path)?;
    let names = table_names(&conn);
    if let Some(missing) = USN_TABLES.iter().find(|table| !names.iter().any(|name| name == *table)) {
        return Err(format!("USN 저널 저장본에 {missing} 테이블이 없습니다. 재파싱이 필요합니다."));
    }
    Ok(conn)
}

#[tauri::command]
async fn usn_overview(full_path: String, input_id: Option<String>) -> Result<UsnOverview, String> {
    tauri::async_runtime::spawn_blocking(move || usn_overview_blocking(full_path, input_id))
        .await
        .map_err(|error| format!("USN 저널 조회 작업이 중단되었습니다: {error}"))?
}

fn usn_overview_blocking(full_path: String, input_id: Option<String>) -> Result<UsnOverview, String> {
    let conn = open_usn_journal(&full_path)?;
    let read_error = |error: rusqlite::Error| format!("USN 저널 입력을 읽지 못했습니다: {error}");
    let mut inputs = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT g.input_id, MAX(g.input_name), MAX(g.source_relative), SUM(g.member_count), COUNT(*)
                 FROM UsnChangeGroups g GROUP BY g.input_id ORDER BY g.input_id",
            )
            .map_err(read_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(UsnInput {
                    input_id: row.get(0)?,
                    input_name: row.get(1)?,
                    source_relative: row.get(2)?,
                    record_count: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    group_count: row.get(4)?,
                })
            })
            .map_err(read_error)?;
        for row in rows {
            inputs.push(row.map_err(read_error)?);
        }
    }
    let options = |sql: &str| -> Result<Vec<UsnFilterOption>, String> {
        let mut stmt = conn.prepare(sql).map_err(read_error)?;
        let rows = stmt
            .query_map(rusqlite::params![input_id], |row| Ok(UsnFilterOption { value: row.get(0)?, count: row.get(1)? }))
            .map_err(read_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(read_error)
    };
    // NULL input = every input; empty representative types are not offered.
    let event_types = options(
        "SELECT event_type, COUNT(*) FROM UsnChangeGroups
         WHERE (?1 IS NULL OR input_id = ?1) AND event_type IS NOT NULL AND event_type <> ''
         GROUP BY event_type ORDER BY COUNT(*) DESC, event_type",
    )?;
    // A single input needs no join (654k flags): count straight from the index.
    let scoped = if inputs.len() > 1 { input_id.as_deref() } else { None };
    let reason_flags = if scoped.is_some() {
        options(
            "SELECT f.reason_flag, COUNT(*) FROM UsnReasonFlags f
             WHERE f.group_id IN (SELECT group_id FROM UsnChangeGroups WHERE input_id = ?1)
             GROUP BY f.reason_flag ORDER BY COUNT(*) DESC, f.reason_flag",
        )?
    } else {
        let mut stmt = conn
            .prepare("SELECT reason_flag, COUNT(*) FROM UsnReasonFlags GROUP BY reason_flag ORDER BY COUNT(*) DESC, reason_flag")
            .map_err(read_error)?;
        let rows = stmt.query_map([], |row| Ok(UsnFilterOption { value: row.get(0)?, count: row.get(1)? })).map_err(read_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(read_error)?
    };
    Ok(UsnOverview { inputs, event_types, reason_flags })
}

#[tauri::command]
async fn usn_groups_page(full_path: String, options: Option<UsnGroupOptions>, offset: i64, limit: i64) -> Result<UsnGroupsPage, String> {
    // 15만 묶음·33만 기록 조회 — 메인 스레드 밖에서 수행한다.
    tauri::async_runtime::spawn_blocking(move || usn_groups_page_blocking(full_path, options.unwrap_or_default(), offset, limit))
        .await
        .map_err(|error| format!("USN 저널 조회 작업이 중단되었습니다: {error}"))?
}

/// Stored groups (docs-05 §5). A group is listed when ONE member satisfies
/// every member condition (search, reason flags, period); its members are all
/// returned and the satisfying ones carry `__matched`. Groups are never
/// rebuilt here and the representative row never stands for the group.
fn usn_groups_page_blocking(full_path: String, options: UsnGroupOptions, offset: i64, limit: i64) -> Result<UsnGroupsPage, String> {
    let conn = open_usn_journal(&full_path)?;
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);

    // Member conditions, written for alias `j` over columns UsnJournal and
    // the narrow UsnGroupMembers share (file_name, reason, timestamp,
    // record_id). The group filter runs them on UsnGroupMembers; the member
    // rows reuse them for `__matched`. `path` is not searched: the builder
    // never stores it for $J (core derived/usn.rs).
    let mut member_clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(search) = options.search.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        params.push(Box::new(like_contains(search)));
        let index = params.len();
        member_clauses.push(format!("(j.file_name LIKE ?{index} ESCAPE '\\' OR j.reason LIKE ?{index} ESCAPE '\\')"));
    }
    let flags: Vec<String> = options.reason_flags.unwrap_or_default().into_iter().map(|flag| flag.trim().to_string()).filter(|flag| !flag.is_empty()).collect();
    if !flags.is_empty() {
        let first = params.len() + 1;
        let placeholders = (0..flags.len()).map(|i| format!("?{}", first + i)).collect::<Vec<_>>().join(", ");
        for flag in flags {
            params.push(Box::new(flag));
        }
        // Non-correlated IN: a correlated EXISTS lets the planner pick the
        // flag index and loop per member (measured > 100 s on 329k records).
        member_clauses.push(format!("j.record_id IN (SELECT f.record_id FROM UsnReasonFlags f WHERE f.reason_flag IN ({placeholders}))"));
    }
    if let Some(start) = options.time_start.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        params.push(Box::new(start.to_string()));
        member_clauses.push(format!("j.timestamp >= ?{}", params.len()));
    }
    if let Some(end) = options.time_end.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        params.push(Box::new(end.to_string()));
        member_clauses.push(format!("j.timestamp <= ?{}", params.len()));
    }
    let member_match = if member_clauses.is_empty() { "1".to_string() } else { member_clauses.join(" AND ") };

    let mut group_clauses: Vec<String> = Vec::new();
    if let Some(input) = options.input_id.filter(|value| !value.is_empty()) {
        params.push(Box::new(input));
        group_clauses.push(format!("g.input_id = ?{}", params.len()));
    }
    if let Some(event_type) = options.event_type.filter(|value| !value.is_empty()) {
        params.push(Box::new(event_type));
        group_clauses.push(format!("g.event_type = ?{}", params.len()));
    }
    if !member_clauses.is_empty() {
        group_clauses.push(format!("g.group_id IN (SELECT j.group_id FROM UsnGroupMembers j WHERE {member_match})"));
    }
    let where_clause = if group_clauses.is_empty() { String::new() } else { format!(" WHERE {}", group_clauses.join(" AND ")) };
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|value| value.as_ref()).collect();

    // Stored order keys only: time (NULL last), length-prefixed USN text, id.
    let direction = if options.descending.unwrap_or(false) { "DESC" } else { "ASC" };
    let order = format!("ORDER BY g.first_timestamp IS NULL, g.first_timestamp {direction}, g.first_usn_sort {direction}, g.group_id {direction}");
    let read_ids = |sql: &str| -> Result<Vec<String>, String> {
        let mut stmt = conn.prepare(sql).map_err(|error| format!("USN 저널 묶음을 읽지 못했습니다: {error}"))?;
        let rows = stmt.query_map(refs.as_slice(), |row| row.get::<_, String>(0)).map_err(|error| format!("USN 저널 묶음을 읽지 못했습니다: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| format!("USN 저널 묶음을 읽지 못했습니다: {error}"))
    };
    let (total, ids) = if member_clauses.is_empty() {
        // Index order + LIMIT; the count is a cheap index count.
        let total: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM UsnChangeGroups g{where_clause}"), refs.as_slice(), |row| row.get(0))
            .map_err(|error| format!("USN 저널 묶음 수를 읽지 못했습니다: {error}"))?;
        (total, read_ids(&format!("SELECT g.group_id FROM UsnChangeGroups g{where_clause} {order} LIMIT {limit} OFFSET {offset}"))?)
    } else {
        // Member conditions scan members once: total and page from one result.
        let all = read_ids(&format!("SELECT g.group_id FROM UsnChangeGroups g{where_clause} {order}"))?;
        let total = all.len() as i64;
        (total, all.into_iter().skip(offset as usize).take(limit as usize).collect())
    };
    if ids.is_empty() {
        return Ok(UsnGroupsPage { groups: Vec::new(), total });
    }
    let id_refs: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
    let id_only = (1..=ids.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
    let mut group_rows = query_rows(&conn, &format!("SELECT * FROM UsnChangeGroups WHERE group_id IN ({id_only})"), id_refs.as_slice())?;
    let rank: HashMap<String, usize> = ids.iter().enumerate().map(|(index, id)| (id.clone(), index)).collect();
    group_rows.sort_by_key(|row| row.get("group_id").and_then(Value::as_str).and_then(|id| rank.get(id)).copied().unwrap_or(usize::MAX));

    // Members and renames of this page only, in one query each.
    let id_start = params.len() + 1;
    let id_list = (0..ids.len()).map(|i| format!("?{}", id_start + i)).collect::<Vec<_>>().join(", ");
    let mut member_params: Vec<&dyn rusqlite::ToSql> = refs.clone();
    for id in &ids {
        member_params.push(id);
    }
    let columns = payload_columns(&conn, "UsnJournal");
    let projection = columns.iter().map(|column| format!("j.{}", q(column))).collect::<Vec<_>>().join(", ");
    let mut members = query_rows(
        &conn,
        &format!(
            "SELECT j.rowid AS __rowid, {projection}, ({member_match}) AS __matched
             FROM UsnJournal j WHERE j.group_id IN ({id_list})
             ORDER BY j.group_id, j.group_ordinal, j.usn_sort, j.record_id"
        ),
        member_params.as_slice(),
    )?;
    for member in members.iter_mut() {
        // No member condition = nothing to single out.
        let matched = !member_clauses.is_empty() && member.get("__matched").and_then(Value::as_i64) == Some(1);
        member.insert("__matched".into(), Value::Bool(matched));
    }
    decorate_source_refs(&conn, Path::new(&full_path), &mut members)?;
    let renames = query_rows(
        &conn,
        &format!(
            "SELECT * FROM UsnRenameEvents WHERE old_group_id IN ({id_only}) OR new_group_id IN ({id_only})
             ORDER BY COALESCE(old_usn_sort, new_usn_sort), rename_id"
        ),
        id_refs.as_slice(),
    )?;
    let mut candidates_by_rename: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    if !renames.is_empty() {
        let rename_ids: Vec<String> = renames.iter().filter_map(|rename| rename.get("rename_id").and_then(Value::as_str).map(str::to_string)).collect();
        let rename_refs: Vec<&dyn rusqlite::ToSql> = rename_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        let rename_list = (1..=rename_ids.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        let candidates = query_rows(
            &conn,
            &format!(
                "SELECT c.*, j.rowid AS __rowid, j.parent_reference
                 FROM UsnRenameCandidates c LEFT JOIN UsnJournal j ON j.record_id = c.record_id
                 WHERE c.rename_id IN ({rename_list}) ORDER BY c.rename_id, c.ordinal"
            ),
            rename_refs.as_slice(),
        )?;
        for candidate in candidates {
            if let Some(id) = candidate.get("rename_id").and_then(Value::as_str).map(str::to_string) {
                candidates_by_rename.entry(id).or_default().push(candidate);
            }
        }
    }

    let mut groups: Vec<UsnGroupEntry> = group_rows.into_iter().map(|group| UsnGroupEntry { group, members: Vec::new(), renames: Vec::new() }).collect();
    let position = &rank;
    for member in members {
        if let Some(&index) = member.get("group_id").and_then(Value::as_str).and_then(|id| position.get(id)) {
            groups[index].members.push(member);
        }
    }
    for event in renames {
        let old = event.get("old_group_id").and_then(Value::as_str).and_then(|id| position.get(id)).copied();
        let new = event.get("new_group_id").and_then(Value::as_str).and_then(|id| position.get(id)).copied();
        let candidates = event.get("rename_id").and_then(Value::as_str).and_then(|id| candidates_by_rename.remove(id)).unwrap_or_default();
        let entry = UsnRenameEntry { event, candidates };
        if let Some(index) = old {
            groups[index].renames.push(entry.clone());
        }
        if let Some(index) = new.filter(|index| Some(*index) != old) {
            groups[index].renames.push(entry);
        }
    }
    Ok(UsnGroupsPage { groups, total })
}

// ---------------------------------------------------------------------------
// Registry explorer (docs-06): every stored hive, key and value from
// _OVERVIEW/RegistryExplorer.sqlite; quick access joins RegistryFindings.
// ---------------------------------------------------------------------------

const REGISTRY_TABLES: [&str; 3] = ["RegistryHives", "RegistryExplorer", "RegistryQuickTargets"];

fn open_registry_explorer(full_path: &str) -> Result<Connection, String> {
    let conn = open_ro(full_path)?;
    let names = table_names(&conn);
    if let Some(missing) = REGISTRY_TABLES.iter().find(|table| !names.iter().any(|name| name == *table)) {
        return Err(format!("레지스트리 저장본에 {missing} 테이블이 없습니다. 재파싱이 필요합니다."));
    }
    Ok(conn)
}

fn registry_error(context: &str) -> impl Fn(rusqlite::Error) -> String + '_ {
    move |error| format!("{context}: {error}")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryHive {
    hive_id: String,
    ordinal: i64,
    hive_name: String,
    source_file: Option<String>,
    inventory_source: String,
    input_status: Option<String>,
    load_status: String,
    load_error: Option<String>,
    input_error: Option<String>,
    is_regback: bool,
    key_count: i64,
    value_count: i64,
    root_count: i64,
    logs_discovered: Option<i64>,
    logs_applied: Option<i64>,
    log_error: Option<String>,
    /// Keys whose parent could not be linked (shown as their own bucket).
    unresolved_count: i64,
}

#[tauri::command]
async fn registry_hives(full_path: String) -> Result<Vec<RegistryHive>, String> {
    tauri::async_runtime::spawn_blocking(move || registry_hives_blocking(full_path))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

fn registry_hives_blocking(full_path: String) -> Result<Vec<RegistryHive>, String> {
    let conn = open_registry_explorer(&full_path)?;
    let read = registry_error("레지스트리 하이브를 읽지 못했습니다");
    let mut unresolved: HashMap<String, i64> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT hive_id, COUNT(*) FROM RegistryExplorer WHERE entry_kind = 'key' AND parent_record_id IS NULL AND parent_status = 'unresolved' GROUP BY hive_id")
            .map_err(&read)?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))).map_err(&read)?;
        for row in rows {
            let (hive, count) = row.map_err(&read)?;
            unresolved.insert(hive, count);
        }
    }
    let mut stmt = conn
        .prepare(
            "SELECT hive_id, ordinal, hive_name, source_file, inventory_source, input_status, load_status, load_error, input_error,
                    is_regback, key_count, value_count, root_count, logs_discovered, logs_applied, log_error
             FROM RegistryHives ORDER BY ordinal",
        )
        .map_err(&read)?;
    let rows = stmt
        .query_map([], |row| {
            let hive_id: String = row.get(0)?;
            Ok(RegistryHive {
                unresolved_count: unresolved.get(&hive_id).copied().unwrap_or(0),
                hive_id,
                ordinal: row.get(1)?,
                hive_name: row.get(2)?,
                source_file: row.get(3)?,
                inventory_source: row.get(4)?,
                input_status: row.get(5)?,
                load_status: row.get(6)?,
                load_error: row.get(7)?,
                input_error: row.get(8)?,
                is_regback: row.get::<_, i64>(9)? == 1,
                key_count: row.get(10)?,
                value_count: row.get(11)?,
                root_count: row.get(12)?,
                logs_discovered: row.get(13)?,
                logs_applied: row.get(14)?,
                log_error: row.get(15)?,
            })
        })
        .map_err(&read)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(read)
}

const REGISTRY_KEY_COLUMNS: &str = "rowid AS __rowid, record_id, hive_id, entry_kind, parent_record_id, parent_status, key_name, key_path, key_depth, key_last_write, key_subkey_count, key_value_count, stored_subkey_count, stored_value_count, key_read_status, key_read_error, key_offset, recovery, source_rowid";

#[derive(Serialize)]
struct RegistryRowsPage {
    rows: Vec<Map<String, Value>>,
    total: i64,
}

#[tauri::command]
async fn registry_keys(full_path: String, hive_id: String, parent_record_id: Option<String>, unresolved: bool, offset: i64, limit: i64) -> Result<RegistryRowsPage, String> {
    tauri::async_runtime::spawn_blocking(move || registry_keys_blocking(full_path, hive_id, parent_record_id, unresolved, offset, limit))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

/// Child keys of one key, the hive roots (no parent) or the keys whose stored
/// parent link is unresolved — name order (`key_path_lower` under one parent).
fn registry_keys_blocking(full_path: String, hive_id: String, parent_record_id: Option<String>, unresolved: bool, offset: i64, limit: i64) -> Result<RegistryRowsPage, String> {
    let conn = open_registry_explorer(&full_path)?;
    // Large limits serve "reveal": a deep child must be in the loaded window.
    let limit = limit.clamp(1, 50_000);
    let offset = offset.max(0);
    // `+hive_id` keeps the planner on the (parent_record_id, key_path_lower)
    // index; on hive_id it scans every key of the hive (measured 1.5–3.3 s).
    let (filter, params): (&str, Vec<&dyn rusqlite::ToSql>) = match (&parent_record_id, unresolved) {
        (Some(parent), _) => ("entry_kind = 'key' AND parent_record_id = ?1 AND +hive_id = ?2", vec![parent, &hive_id]),
        (None, true) => ("entry_kind = 'key' AND parent_record_id IS NULL AND parent_status = 'unresolved' AND +hive_id = ?1", vec![&hive_id]),
        (None, false) => ("entry_kind = 'key' AND parent_record_id IS NULL AND parent_status = 'root' AND +hive_id = ?1", vec![&hive_id]),
    };
    let total: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM RegistryExplorer WHERE {filter}"), params.as_slice(), |row| row.get(0))
        .map_err(registry_error("레지스트리 키 수를 읽지 못했습니다"))?;
    let mut rows = query_rows(
        &conn,
        &format!("SELECT {REGISTRY_KEY_COLUMNS} FROM RegistryExplorer WHERE {filter} ORDER BY key_path_lower, record_id LIMIT {limit} OFFSET {offset}"),
        params.as_slice(),
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(RegistryRowsPage { rows, total })
}

#[tauri::command]
async fn registry_values(full_path: String, key_record_id: String, offset: i64, limit: i64) -> Result<RegistryRowsPage, String> {
    tauri::async_runtime::spawn_blocking(move || registry_values_blocking(full_path, key_record_id, offset, limit))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

/// One page of a key's values with previews. Default value first, then by
/// name; `total` lets the view page to the last value. Full data comes from
/// `registry_entry` / `registry_value_chunk`.
fn registry_values_blocking(full_path: String, key_record_id: String, offset: i64, limit: i64) -> Result<RegistryRowsPage, String> {
    let conn = open_registry_explorer(&full_path)?;
    let limit = limit.clamp(1, 5_000);
    let offset = offset.max(0);
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM RegistryExplorer WHERE entry_kind = 'value' AND key_record_id = ?1", [&key_record_id], |row| row.get(0))
        .map_err(registry_error("레지스트리 값 수를 읽지 못했습니다"))?;
    let mut rows = query_rows(
        &conn,
        &format!(
            "SELECT rowid AS __rowid, record_id, hive_id, entry_kind, key_record_id, value_name, value_is_default, value_display_name,
                    value_type_code, value_type_code_raw, value_type_name, value_data_length,
                    substr(value_data_text, 1, 512) AS value_preview, length(value_data_text) AS value_text_length,
                    substr(value_data_hex, 1, 96) AS value_hex_preview, value_read_status, value_read_error, recovery, source_rowid
             FROM RegistryExplorer WHERE entry_kind = 'value' AND key_record_id = ?1
             ORDER BY value_is_default DESC, value_name_lower, source_rowid, record_id LIMIT {limit} OFFSET {offset}"
        ),
        &[&key_record_id],
    )?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(RegistryRowsPage { rows, total })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryAncestor {
    record_id: String,
    key_name: Option<String>,
    parent_status: Option<String>,
    /// Index among the siblings in tree order (children page offset).
    position: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistryEntry {
    entry: Map<String, Value>,
    key: Map<String, Value>,
    /// Root → key (inclusive), for revealing the entry in the tree.
    ancestors: Vec<RegistryAncestor>,
}

#[tauri::command]
async fn registry_entry(full_path: String, record_id: String) -> Result<RegistryEntry, String> {
    tauri::async_runtime::spawn_blocking(move || registry_entry_blocking(full_path, record_id, REGISTRY_ENTRY_TEXT_CAP))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

/// First part of a value's text/hex sent with the detail (largest stored
/// value: 284,222 bytes); the rest comes through `registry_value_chunk`.
const REGISTRY_ENTRY_TEXT_CAP: i64 = 4 * 1024 * 1024;

fn registry_entry_blocking(full_path: String, record_id: String, cap: i64) -> Result<RegistryEntry, String> {
    let conn = open_registry_explorer(&full_path)?;
    let entry_columns = "rowid AS __rowid, record_id, hive_id, entry_kind, key_record_id, parent_record_id, parent_status, key_offset, parent_key_offset, key_name, key_path, key_depth, key_last_write, key_subkey_count, key_value_count, stored_subkey_count, stored_value_count, key_read_status, key_read_error, value_offset, value_name, value_is_default, value_display_name, value_type_code, value_type_code_raw, value_type_name, value_data_length, value_read_status, value_read_error, recovery, source_rowid";
    // Hex is cut on a byte boundary; lengths tell how much remains.
    let hex_cap = (cap - cap % 2).max(2);
    let fetch = |id: &str| -> Result<Option<Map<String, Value>>, String> {
        let mut rows = query_rows(
            &conn,
            &format!(
                "SELECT {entry_columns},
                        substr(value_data_hex, 1, {hex_cap}) AS value_data_hex, length(value_data_hex) AS value_hex_length, length(value_data_hex) > {hex_cap} AS value_hex_truncated,
                        substr(value_data_text, 1, {cap}) AS value_data_text, length(value_data_text) AS value_text_length, length(value_data_text) > {cap} AS value_text_truncated
                 FROM RegistryExplorer WHERE record_id = ?1"
            ),
            &[&id],
        )?;
        Ok(rows.pop())
    };
    let mut entry = fetch(&record_id)?.ok_or_else(|| "레지스트리 레코드를 찾지 못했습니다".to_string())?;
    let mut key = match entry.get("key_record_id").and_then(Value::as_str) {
        Some(key_id) => fetch(key_id)?.ok_or_else(|| "값이 속한 키를 찾지 못했습니다".to_string())?,
        None => entry.clone(),
    };
    let mut pair = vec![entry.clone(), key.clone()];
    decorate_source_refs(&conn, Path::new(&full_path), &mut pair)?;
    key = pair.pop().unwrap_or(key);
    entry = pair.pop().unwrap_or(entry);

    // Walk parent links up; each step records its position among siblings.
    let mut ancestors = Vec::new();
    let mut current = key.get("record_id").and_then(Value::as_str).map(str::to_string);
    let mut guard = 0;
    while let Some(id) = current.take() {
        guard += 1;
        if guard > 512 {
            break;
        }
        let row = conn
            .query_row(
                "SELECT record_id, key_name, parent_record_id, parent_status, hive_id, key_path_lower FROM RegistryExplorer WHERE record_id = ?1 AND entry_kind = 'key'",
                [&id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?)),
            )
            .map_err(registry_error("레지스트리 상위 키를 읽지 못했습니다"))?;
        let (record, name, parent, status, hive, lower) = row;
        let position: i64 = match &parent {
            Some(parent) => conn.query_row(
                "SELECT COUNT(*) FROM RegistryExplorer WHERE entry_kind = 'key' AND parent_record_id = ?1 AND (key_path_lower < ?2 OR (key_path_lower = ?2 AND record_id < ?3))",
                rusqlite::params![parent, lower, record],
                |row| row.get(0),
            ),
            None => conn.query_row(
                "SELECT COUNT(*) FROM RegistryExplorer WHERE entry_kind = 'key' AND parent_record_id IS NULL AND +hive_id = ?1 AND parent_status = ?4 AND (key_path_lower < ?2 OR (key_path_lower = ?2 AND record_id < ?3))",
                rusqlite::params![hive, lower, record, status.as_deref().unwrap_or("root")],
                |row| row.get(0),
            ),
        }
        .map_err(registry_error("레지스트리 키 위치를 읽지 못했습니다"))?;
        ancestors.push(RegistryAncestor { record_id: record, key_name: name, parent_status: status, position });
        current = parent;
    }
    ancestors.reverse();
    Ok(RegistryEntry { entry, key, ancestors })
}

#[derive(Serialize)]
struct RegistryValueChunk {
    /// Hex digits or text characters from `offset`.
    data: String,
    offset: i64,
    /// Full length of the field (hex digits or characters).
    total: i64,
}

#[tauri::command]
async fn registry_value_chunk(full_path: String, record_id: String, field: String, offset: i64, length: i64) -> Result<RegistryValueChunk, String> {
    tauri::async_runtime::spawn_blocking(move || registry_value_chunk_blocking(full_path, record_id, field, offset, length))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

/// A slice of a value's stored hex (byte-aligned) or text, so data past the
/// detail cap is reachable to the last byte / character.
fn registry_value_chunk_blocking(full_path: String, record_id: String, field: String, offset: i64, length: i64) -> Result<RegistryValueChunk, String> {
    let conn = open_registry_explorer(&full_path)?;
    let (column, offset, length) = match field.as_str() {
        "hex" => ("value_data_hex", offset.max(0) - offset.max(0) % 2, (length.clamp(2, REGISTRY_ENTRY_TEXT_CAP) + 1) / 2 * 2),
        "text" => ("value_data_text", offset.max(0), length.clamp(1, REGISTRY_ENTRY_TEXT_CAP)),
        _ => return Err(format!("알 수 없는 값 필드: {field}")),
    };
    let (data, total): (Option<String>, Option<i64>) = conn
        .query_row(
            &format!("SELECT substr({column}, ?2 + 1, ?3), length({column}) FROM RegistryExplorer WHERE record_id = ?1 AND entry_kind = 'value'"),
            rusqlite::params![record_id, offset, length],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(registry_error("레지스트리 값 데이터를 읽지 못했습니다"))?;
    Ok(RegistryValueChunk { data: data.unwrap_or_default(), offset, total: total.unwrap_or(0) })
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", default)]
struct RegistrySearchOptions {
    query: String,
    /// Limit to one hive.
    hive_id: Option<String>,
    /// Limit to this key and its descendants (its hive implied).
    key_record_id: Option<String>,
    /// Fields; each defaults to on.
    keys: Option<bool>,
    value_names: Option<bool>,
    value_data: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrySearchHit {
    record_id: String,
    rowid: i64,
    entry_kind: String,
    hive_id: String,
    /// The key itself, or the key holding the value.
    key_record_id: String,
    key_path: Option<String>,
    value_name: Option<String>,
    value_display_name: Option<String>,
    value_type_name: Option<String>,
    /// "key" | "value_name" | "value_data" | "value_hex".
    fields: Vec<String>,
    snippet: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrySearchPage {
    hits: Vec<RegistrySearchHit>,
    /// Resume after this rowid; None = the scope was scanned to the end.
    next_cursor: Option<i64>,
    scanned_to: i64,
    range_start: i64,
    range_end: i64,
}

#[tauri::command]
async fn registry_search(full_path: String, options: RegistrySearchOptions, cursor: Option<i64>, limit: i64) -> Result<RegistrySearchPage, String> {
    // ~150k rows per call: progress every second or so on 2.6M rows.
    tauri::async_runtime::spawn_blocking(move || registry_search_blocking(full_path, options, cursor, limit, 150_000))
        .await
        .map_err(|error| format!("레지스트리 검색 작업이 중단되었습니다: {error}"))?
}

/// Hex digits of a query that reads as bytes ("4D 5A 90"), lowercase.
fn registry_hex_query(query: &str) -> Option<String> {
    let compact: String = query.chars().filter(|c| !c.is_whitespace()).collect();
    (compact.len() >= 4 && compact.len() % 2 == 0 && compact.chars().all(|c| c.is_ascii_hexdigit())).then(|| compact.to_ascii_lowercase())
}

/// First occurrence of `needle` at a byte (even nibble) boundary.
fn aligned_hex_find(hex: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = hex[from..].find(needle) {
        let at = from + found;
        if at % 2 == 0 {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Text around a char range, cut on char boundaries.
fn registry_snippet(text: &str, start: usize, len: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let begin = start.saturating_sub(40);
    let end = (start + len + 40).min(chars.len());
    let mut out = String::new();
    if begin > 0 {
        out.push('…');
    }
    out.extend(&chars[begin..end]);
    if end < chars.len() {
        out.push('…');
    }
    out
}

/// Search the whole store (or one hive / key subtree) in rowid order. Each call
/// scans at most `budget` rows and stops at `limit` hits, so a rare term over
/// 2.6M rows streams in steps instead of blocking; `next_cursor` resumes.
fn registry_search_blocking(full_path: String, options: RegistrySearchOptions, cursor: Option<i64>, limit: i64, budget: i64) -> Result<RegistrySearchPage, String> {
    let conn = open_registry_explorer(&full_path)?;
    let read = registry_error("레지스트리를 검색하지 못했습니다");
    let query = options.query.trim().to_string();
    let limit = limit.clamp(1, 500) as usize;
    let empty = |start: i64, end: i64| RegistrySearchPage { hits: Vec::new(), next_cursor: None, scanned_to: end, range_start: start, range_end: end };
    if query.is_empty() {
        return Ok(empty(0, 0));
    }
    let lower = query.to_lowercase();
    let hex = registry_hex_query(&query);
    let (want_keys, want_names, want_data) = (options.keys.unwrap_or(true), options.value_names.unwrap_or(true), options.value_data.unwrap_or(true));

    // Scope: a key subtree implies its hive.
    let subtree: Option<(String, String)> = match options.key_record_id.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => Some(
            conn.query_row("SELECT hive_id, key_path_lower FROM RegistryExplorer WHERE record_id = ?1 AND entry_kind = 'key'", [id], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(registry_error("검색 범위 키를 찾지 못했습니다"))?,
        ),
        None => None,
    };
    let hive = subtree.as_ref().map(|(hive, _)| hive.clone()).or(options.hive_id.clone().filter(|id| !id.is_empty()));
    // Rows of one hive are contiguous in rowid; bound the scan to them.
    let (range_start, range_end): (i64, i64) = match &hive {
        Some(hive) => {
            let bound = |sql: &str| -> Result<(Option<i64>, Option<i64>), String> { conn.query_row(sql, [hive], |row| Ok((row.get(0)?, row.get(1)?))).map_err(&read) };
            let (key_min, key_max) = bound("SELECT min(rowid), max(rowid) FROM RegistryExplorer WHERE entry_kind = 'key' AND hive_id = ?1")?;
            let (value_min, value_max) = bound("SELECT min(rowid), max(rowid) FROM RegistryExplorer WHERE entry_kind = 'value' AND hive_id = ?1")?;
            match (key_min.into_iter().chain(value_min).min(), key_max.into_iter().chain(value_max).max()) {
                (Some(start), Some(end)) => (start, end),
                _ => return Ok(empty(0, 0)),
            }
        }
        None => {
            let (start, end): (Option<i64>, Option<i64>) = conn.query_row("SELECT min(rowid), max(rowid) FROM RegistryExplorer", [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(&read)?;
            match (start, end) {
                (Some(start), Some(end)) => (start, end),
                _ => return Ok(empty(0, 0)),
            }
        }
    };

    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(0i64), Box::new(0i64)];
    let mut ors = Vec::new();
    params.push(Box::new(like_contains(&lower)));
    let lower_index = params.len();
    if want_keys {
        ors.push(format!("(r.entry_kind = 'key' AND r.key_path_lower LIKE ?{lower_index} ESCAPE '\\')"));
    }
    if want_names {
        ors.push(format!("(r.entry_kind = 'value' AND r.value_name_lower LIKE ?{lower_index} ESCAPE '\\')"));
    }
    if want_data {
        params.push(Box::new(like_contains(&query)));
        let mut data = format!("r.value_data_text LIKE ?{} ESCAPE '\\'", params.len());
        if let Some(hex) = &hex {
            params.push(Box::new(like_contains(hex)));
            data.push_str(&format!(" OR r.value_data_hex LIKE ?{} ESCAPE '\\'", params.len()));
        }
        ors.push(format!("(r.entry_kind = 'value' AND ({data}))"));
    }
    if ors.is_empty() {
        return Ok(empty(range_start, range_end));
    }
    let mut clauses = vec![format!("({})", ors.join(" OR "))];
    if let Some(hive) = &hive {
        params.push(Box::new(hive.clone()));
        clauses.push(format!("r.hive_id = ?{}", params.len()));
    }
    if let Some((_, prefix)) = &subtree {
        let escaped = prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        params.push(Box::new(prefix.clone()));
        let exact = params.len();
        params.push(Box::new(format!("{escaped}\\\\%")));
        let below = params.len();
        let path = "(CASE WHEN r.entry_kind = 'key' THEN r.key_path_lower ELSE (SELECT k.key_path_lower FROM RegistryExplorer k WHERE k.record_id = r.key_record_id) END)";
        clauses.push(format!("({path} = ?{exact} OR {path} LIKE ?{below} ESCAPE '\\')"));
    }
    let hex_column = if hex.is_some() { "r.value_data_hex" } else { "NULL" };
    let sql = format!(
        "SELECT r.rowid, r.record_id, r.entry_kind, r.hive_id, r.key_record_id, r.key_path, r.key_path_lower, r.value_name, r.value_name_lower,
                r.value_display_name, r.value_type_name, r.value_data_text, {hex_column}
         FROM RegistryExplorer r WHERE r.rowid > ?1 AND r.rowid <= ?2 AND {} ORDER BY r.rowid LIMIT {{limit}}",
        clauses.join(" AND ")
    );

    const CHUNK: i64 = 50_000;
    let mut cursor = cursor.unwrap_or(range_start - 1).max(range_start - 1);
    let start_cursor = cursor;
    let mut hits: Vec<RegistrySearchHit> = Vec::new();
    while cursor < range_end && hits.len() < limit && cursor - start_cursor < budget {
        let chunk_end = (cursor + CHUNK).min(range_end);
        let remaining = limit - hits.len();
        params[0] = Box::new(cursor);
        params[1] = Box::new(chunk_end);
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|value| value.as_ref()).collect();
        let mut stmt = conn.prepare(&sql.replace("{limit}", &remaining.to_string())).map_err(&read)?;
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, Option<String>>(7)?, row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?, row.get::<_, Option<String>>(10)?, row.get::<_, Option<String>>(11)?, row.get::<_, Option<String>>(12)?,
                ))
            })
            .map_err(&read)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(&read)?;
        let returned = rows.len();
        let last_rowid = rows.last().map(|row| row.0);
        for (rowid, record_id, kind, hive_id, key_record_id, key_path, key_lower, value_name, name_lower, display, type_name, text, hex_value) in rows {
            let mut fields = Vec::new();
            let mut snippet = None;
            if want_keys && kind == "key" && key_lower.as_deref().is_some_and(|path| path.contains(&lower)) {
                fields.push("key".to_string());
            }
            if want_names && kind == "value" && name_lower.as_deref().is_some_and(|name| name.contains(&lower)) {
                fields.push("value_name".to_string());
            }
            if want_data && kind == "value" {
                if let Some(text) = text.as_deref() {
                    let folded = text.to_lowercase();
                    if let Some(at) = folded.find(&lower) {
                        fields.push("value_data".to_string());
                        let char_at = folded[..at].chars().count();
                        snippet = Some(registry_snippet(text, char_at, lower.chars().count()));
                    }
                }
                if let (Some(needle), Some(hex_value)) = (&hex, hex_value.as_deref()) {
                    if let Some(at) = aligned_hex_find(hex_value, needle) {
                        fields.push("value_hex".to_string());
                        if snippet.is_none() {
                            let begin = at.saturating_sub(32);
                            let end = (at + needle.len() + 32).min(hex_value.len());
                            snippet = Some(format!("{}{}{}", if begin > 0 { "…" } else { "" }, &hex_value[begin - begin % 2..end], if end < hex_value.len() { "…" } else { "" }));
                        }
                    }
                }
            }
            if fields.is_empty() {
                continue; // e.g. a hex hit off the byte boundary
            }
            hits.push(RegistrySearchHit {
                key_record_id: if kind == "key" { record_id.clone() } else { key_record_id.unwrap_or_default() },
                record_id,
                rowid,
                entry_kind: kind,
                hive_id,
                key_path,
                value_name,
                value_display_name: display,
                value_type_name: type_name,
                fields,
                snippet,
            });
        }
        cursor = if returned == remaining { last_rowid.unwrap_or(chunk_end) } else { chunk_end };
    }

    // Key paths of value hits, in one lookup.
    let missing: Vec<String> = hits.iter().filter(|hit| hit.key_path.is_none()).map(|hit| hit.key_record_id.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    if !missing.is_empty() {
        let list = (1..=missing.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        let refs: Vec<&dyn rusqlite::ToSql> = missing.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&format!("SELECT record_id, key_path FROM RegistryExplorer WHERE record_id IN ({list})")).map_err(&read)?;
        let paths: HashMap<String, Option<String>> = stmt
            .query_map(refs.as_slice(), |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))
            .map_err(&read)?
            .collect::<Result<_, _>>()
            .map_err(&read)?;
        for hit in hits.iter_mut().filter(|hit| hit.key_path.is_none()) {
            hit.key_path = paths.get(&hit.key_record_id).cloned().flatten();
        }
    }
    Ok(RegistrySearchPage { hits, next_cursor: (cursor < range_end).then_some(cursor), scanned_to: cursor, range_start, range_end })
}

#[derive(Serialize)]
struct RegistryQuickItem {
    finding: Map<String, Value>,
    targets: Vec<Map<String, Value>>,
}

#[derive(Serialize)]
struct RegistryQuickAccess {
    /// False when RegistryFindings.sqlite is not in the same _OVERVIEW.
    available: bool,
    items: Vec<RegistryQuickItem>,
}

#[tauri::command]
async fn registry_quick_access(full_path: String) -> Result<RegistryQuickAccess, String> {
    tauri::async_runtime::spawn_blocking(move || registry_quick_access_blocking(full_path))
        .await
        .map_err(|error| format!("레지스트리 조회 작업이 중단되었습니다: {error}"))?
}

/// Stored findings (RegistryFindings) with their stored explorer targets
/// (RegistryQuickTargets). Independent of evidence bookmarks; parser notes
/// (`detail`, `properties`) are not sent.
fn registry_quick_access_blocking(full_path: String) -> Result<RegistryQuickAccess, String> {
    let conn = open_registry_explorer(&full_path)?;
    let findings_path = Path::new(&full_path).with_file_name("RegistryFindings.sqlite");
    if !findings_path.is_file() {
        return Ok(RegistryQuickAccess { available: false, items: Vec::new() });
    }
    let findings = open_ro(&findings_path.to_string_lossy())?;
    let rows = query_rows(
        &findings,
        "SELECT record_id, category, subtype, name, substr(value, 1, 400) AS value, value_type, status, key_path, source, account, account_sid, timestamp, timestamp_kind
         FROM RegistryFindings ORDER BY rowid",
        &[],
    )?;
    let mut targets: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    for target in query_rows(&conn, "SELECT * FROM RegistryQuickTargets ORDER BY finding_record_id, ordinal", &[])? {
        if let Some(id) = target.get("finding_record_id").and_then(Value::as_str).map(str::to_string) {
            targets.entry(id).or_default().push(target);
        }
    }
    let items = rows
        .into_iter()
        .map(|finding| {
            let id = finding.get("record_id").and_then(Value::as_str).unwrap_or_default().to_string();
            RegistryQuickItem { targets: targets.remove(&id).unwrap_or_default(), finding }
        })
        .collect();
    Ok(RegistryQuickAccess { available: true, items })
}

/// Recursive list filters (docs-04 §3). All optional; unknown keys fall back
/// to the default whitelist entry.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct MftListOptions {
    volume_id: Option<String>,
    sort_key: Option<String>,
    sort_desc: Option<bool>,
    /// "file" | "dir"; anything else lists both.
    kind: Option<String>,
    /// 1 in use, 0 not in use; None both. NULL never matches either.
    in_use: Option<i64>,
    /// Extensions, case-insensitive, without dots; comma/space separated.
    extension: Option<String>,
    name_pattern: Option<String>,
    /// Folder scope: the folder itself and its descendants (drive prefix ignored).
    path_prefix: Option<String>,
    /// Folders left out (same matching as `path_prefix`).
    exclude_paths: Option<Vec<String>>,
    /// Byte size range (INTEGER file_size; NULL never matches a bound).
    size_min: Option<i64>,
    size_max: Option<i64>,
    /// Stored-state flags (docs-04 §0): path not complete / resident body.
    path_incomplete: Option<bool>,
    resident_only: Option<bool>,
    /// SI created earlier than FN created (both stored) — a value comparison.
    si_before_fn: Option<bool>,
    /// Time fields of the period filter (OR: any of them in range), chosen
    /// independently of the sort. Unknown keys are ignored.
    time_keys: Option<Vec<String>>,
    time_start: Option<String>,
    time_end: Option<String>,
}

/// Typed folder → (exact path, `folder\%` LIKE pattern). Stored paths are
/// volume-relative (`\Users\...`): a drive letter is dropped, `/` becomes `\`,
/// trailing `\` trimmed, LIKE metacharacters stay literal. Root → None.
fn folder_match(typed: &str) -> Option<(String, String)> {
    let mut folder = typed.trim().replace('/', "\\");
    if folder.len() >= 2 && folder.as_bytes()[1] == b':' && folder.as_bytes()[0].is_ascii_alphabetic() {
        folder = folder[2..].to_string();
    }
    let folder = format!("\\{}", folder.trim_matches('\\'));
    if folder == "\\" {
        return None;
    }
    let escaped = folder.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    Some((folder, format!("{escaped}\\\\%")))
}

/// SI/FN time keys → columns (docs-04 §4: eight times kept separately).
fn mft_time_column(key: &str) -> Option<&'static str> {
    Some(match key {
        "created" => "si_created",
        "modified" => "si_modified",
        "accessed" => "si_accessed",
        "mft_modified" => "si_mft_modified",
        // $FILE_NAME(0x30) — timestomping usually touches only $SI.
        "fn_created" => "fn_created",
        "fn_modified" => "fn_modified",
        "fn_accessed" => "fn_accessed",
        "fn_mft_modified" => "fn_mft_modified",
        _ => return None,
    })
}

#[tauri::command]
async fn mft_records_page(
    full_path: String,
    query: String,
    offset: i64,
    limit: i64,
    options: Option<MftListOptions>,
) -> Result<MftRecordsPage, String> {
    // 수백만 행 MFT의 비인덱스 정렬·필터 페이지 조회 — 메인 스레드 밖에서 수행한다.
    tauri::async_runtime::spawn_blocking(move || {
        mft_records_page_blocking(full_path, query, offset, limit, options.unwrap_or_default())
    })
    .await
    .map_err(|error| format!("MFT 목록 조회 작업이 중단되었습니다: {error}"))?
}

fn mft_records_page_blocking(
    full_path: String,
    query: String,
    offset: i64,
    limit: i64,
    options: MftListOptions,
) -> Result<MftRecordsPage, String> {
    let conn = open_ro(&full_path)?;
    let table = file_system_table(&conn)?;
    // Resident bodies (data BLOB) are never listed.
    let columns = payload_columns(&conn, &table);
    let Some(projection) = payload_projection(&columns) else {
        return Err("파일 시스템 레코드 컬럼을 읽지 못했습니다".to_string());
    };
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);
    let query = query.trim();

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if !query.is_empty() {
        params.push(Box::new(like_contains(query)));
        clauses.push(fs_text_match(params.len()));
    }
    if let Some(volume) = volume_scope(&columns, options.volume_id) {
        params.push(Box::new(volume));
        clauses.push(format!("volume_id = ?{}", params.len()));
    }
    // Of 0/1/NULL only the stated flag matches; unknown is never claimed.
    match options.kind.as_deref() {
        Some("file") => clauses.push("is_directory = 0".to_string()),
        Some("dir") => clauses.push("is_directory = 1".to_string()),
        _ => {}
    }
    if let Some(flag @ (0 | 1)) = options.in_use {
        params.push(Box::new(flag));
        clauses.push(format!("in_use = ?{}", params.len()));
    }
    let extensions: Vec<String> = options
        .extension
        .as_deref()
        .unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|value| value.trim().trim_start_matches('.').to_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if !extensions.is_empty() {
        let first = params.len() + 1;
        let placeholders = (0..extensions.len()).map(|i| format!("?{}", first + i)).collect::<Vec<_>>().join(", ");
        for extension in extensions {
            params.push(Box::new(extension));
        }
        clauses.push(format!("lower(extension) IN ({placeholders})"));
    }
    // The folder itself or `folder\...`, so `\Users\Admin` never pulls in
    // `\Users\Admin.old`. Root covers the whole volume: no clause.
    if let Some((exact, like)) = options.path_prefix.as_deref().and_then(folder_match) {
        params.push(Box::new(exact));
        let exact = params.len();
        params.push(Box::new(like));
        clauses.push(format!("(path = ?{exact} COLLATE NOCASE OR path LIKE ?{} ESCAPE '\\')", params.len()));
    }
    for (exact, like) in options.exclude_paths.iter().flatten().filter_map(|folder| folder_match(folder)) {
        params.push(Box::new(exact));
        let exact = params.len();
        params.push(Box::new(like));
        // NULL path is not inside the folder: keep it.
        clauses.push(format!("NOT COALESCE(path = ?{exact} COLLATE NOCASE OR path LIKE ?{} ESCAPE '\\', 0)", params.len()));
    }
    if let Some(min) = options.size_min {
        params.push(Box::new(min));
        clauses.push(format!("file_size >= ?{}", params.len()));
    }
    if let Some(max) = options.size_max {
        params.push(Box::new(max));
        clauses.push(format!("file_size <= ?{}", params.len()));
    }
    if options.path_incomplete.unwrap_or(false) {
        clauses.push("path_status IS NOT NULL AND path_status <> 'complete'".to_string());
    }
    if options.resident_only.unwrap_or(false) {
        clauses.push("data_status = 'resident'".to_string());
    }
    if options.si_before_fn.unwrap_or(false) {
        clauses.push("si_created IS NOT NULL AND fn_created IS NOT NULL AND si_created < fn_created".to_string());
    }
    if let Some(pattern) = options.name_pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
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
        params.push(Box::new(like));
        clauses.push(format!("file_name LIKE ?{} ESCAPE '\\'", params.len()));
    }
    // Period filter: a record matches when ANY chosen time field is in the
    // range. A NULL time never falls in a range; the full range keeps all.
    let start = options.time_start.as_deref().map(str::trim).filter(|v| !v.is_empty());
    let end = options.time_end.as_deref().map(str::trim).filter(|v| !v.is_empty());
    if start.is_some() || end.is_some() {
        let mut time_columns: Vec<&'static str> = options.time_keys.iter().flatten().filter_map(|key| mft_time_column(key)).collect();
        time_columns.sort_unstable();
        time_columns.dedup();
        if time_columns.is_empty() {
            time_columns.push("si_created");
        }
        let start_index = start.map(|value| { params.push(Box::new(value.to_string())); params.len() });
        let end_index = end.map(|value| { params.push(Box::new(value.to_string())); params.len() });
        let any = time_columns
            .iter()
            .map(|column| {
                let mut parts = Vec::new();
                if let Some(index) = start_index { parts.push(format!("{column} >= ?{index}")); }
                if let Some(index) = end_index { parts.push(format!("{column} <= ?{index}")); }
                format!("({})", parts.join(" AND "))
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        clauses.push(format!("({any})"));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let count_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|value| value.as_ref()).collect();
    let total = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}{}", q(&table), where_clause), count_refs.as_slice(), |row| row.get(0))
        .map_err(|error| format!("MFT 레코드 수를 읽지 못했습니다: {error}"))?;

    // Sort whitelist; NULL values sort last in both directions, record_id
    // fixes equal values (docs-24 §2).
    let sort_key = options.sort_key.as_deref().unwrap_or("path");
    let order_by = match sort_key {
        "name" => "file_name IS NULL, file_name COLLATE NOCASE".to_string(),
        // file_size is INTEGER bytes: no CAST or lexical ordering needed.
        "size" => "file_size IS NULL, file_size".to_string(),
        key => match mft_time_column(key) {
            Some(column) => format!("{column} IS NULL, {column}"),
            None => "path IS NULL, path COLLATE NOCASE".to_string(),
        },
    };
    let direction = if options.sort_desc.unwrap_or(false) { "DESC" } else { "ASC" };

    let page_sql = format!(
        "SELECT rowid AS __rowid, {projection} FROM {}{where_clause} ORDER BY {order_by} {direction}, record_id {direction} LIMIT ?{} OFFSET ?{}",
        q(&table),
        params.len() + 1,
        params.len() + 2,
    );
    let mut page_refs = count_refs;
    page_refs.push(&limit);
    page_refs.push(&offset);
    let mut rows = query_rows(&conn, &page_sql, page_refs.as_slice())
        .map_err(|error| format!("MFT 레코드 페이지를 읽지 못했습니다: {error}"))?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows)?;
    Ok(MftRecordsPage { rows, total })
}

/// One detail row. With `volume_id` the row is returned only when it belongs to
/// that volume, so a rowid from another volume context opens nothing.
#[tauri::command]
fn mft_row(
    full_path: String,
    rowid: i64,
    volume_id: Option<String>,
) -> Option<Map<String, Value>> {
    let conn = open_ro(&full_path).ok()?;
    let table = file_system_table(&conn).ok()?;
    let columns = payload_columns(&conn, &table);
    let projection = payload_projection(&columns)?;
    let volume = volume_scope(&columns, volume_id);
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&rowid];
    let mut conditions = vec!["rowid = ?1".to_string()];
    if let Some(volume) = volume.as_ref() {
        binds.push(volume);
        conditions.push(format!("volume_id = ?{}", binds.len()));
    }
    let sql = format!(
        "SELECT rowid AS __rowid, {projection} FROM {} WHERE {}",
        q(&table),
        conditions.join(" AND ")
    );
    let mut rows = query_rows(&conn, &sql, binds.as_slice()).ok()?;
    decorate_source_refs(&conn, Path::new(&full_path), &mut rows).ok()?;
    rows.into_iter().next()
}

/// One resident `$DATA` body. The only path that reads the bytes excluded from
/// list, search and page responses, and only on an explicit request
/// (docs-21 "data and size").
///
/// `dataPresent` is true or null: null means non-resident or not captured,
/// while a zero-length BLOB is a valid empty body (`dataPresent=true,
/// dataLen=0`). The two are never shown as the same thing. `dataStatus` is
/// the parser's stored state (resident / resident_empty / nonresident /
/// unavailable / not_applicable); the viewer shows it instead of guessing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MftRecordBody {
    data_present: Option<bool>,
    data_len: Option<i64>,
    truncated: bool,
    body_b64: Option<String>,
    data_status: Option<String>,
}

/// Cap for one body transfer. Beyond it only the prefix is sent with
/// `truncated`; `dataLen` is always the full length.
const MFT_BODY_MAX_BYTES: usize = 1024 * 1024;

#[tauri::command]
async fn mft_record_body(
    full_path: String,
    rowid: i64,
    volume_id: Option<String>,
) -> Result<MftRecordBody, String> {
    tauri::async_runtime::spawn_blocking(move || {
        mft_record_body_blocking(full_path, rowid, volume_id)
    })
    .await
    .map_err(|error| format!("본문 조회가 중단되었습니다: {error}"))?
}

fn mft_record_body_blocking(
    full_path: String,
    rowid: i64,
    volume_id: Option<String>,
) -> Result<MftRecordBody, String> {
    let conn = open_ro(&full_path)?;
    let table = file_system_table(&conn)?;
    let columns = table_columns(&conn, &table);
    if !columns.iter().any(|column| column == "data") {
        return Err("이 저장본에는 상주 본문 컬럼이 없습니다".to_string());
    }
    let volume = volume_scope(&columns, volume_id);
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&rowid];
    let mut conditions = vec!["rowid = ?1".to_string()];
    if let Some(volume) = volume.as_ref() {
        binds.push(volume);
        conditions.push(format!("volume_id = ?{}", binds.len()));
    }
    let status_column = if columns.iter().any(|column| column == "data_status") { "data_status" } else { "NULL" };
    let sql = format!(
        "SELECT data, {status_column} FROM {} WHERE {}",
        q(&table),
        conditions.join(" AND ")
    );
    let (body, data_status): (Option<Vec<u8>>, Option<String>) = conn
        .query_row(&sql, binds.as_slice(), |row| {
            Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => "레코드를 찾을 수 없습니다".to_string(),
            other => format!("상주 본문을 읽지 못했습니다: {other}"),
        })?;
    let Some(body) = body else {
        return Ok(MftRecordBody {
            data_present: None,
            data_len: None,
            truncated: false,
            body_b64: None,
            data_status,
        });
    };
    use base64::Engine as _;
    let data_len = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let truncated = body.len() > MFT_BODY_MAX_BYTES;
    let slice = &body[..body.len().min(MFT_BODY_MAX_BYTES)];
    Ok(MftRecordBody {
        data_present: Some(true),
        data_len: Some(data_len),
        truncated,
        body_b64: Some(base64::engine::general_purpose::STANDARD.encode(slice)),
        data_status,
    })
}

// --- evidence links (source_records) and child tables ----------------------

/// Reads the `record_id` of a selected result row. Verifying the main row first
/// prevents inventing evidence for a row that does not exist; None when absent.
fn record_id_of(
    conn: &Connection,
    table: &str,
    rowid: i64,
) -> Result<Option<String>, String> {
    if !table_columns(conn, table)
        .iter()
        .any(|column| column == "record_id")
    {
        return Ok(None);
    }
    let sql = format!("SELECT record_id FROM {} WHERE rowid = ?1", q(table));
    match conn.query_row(&sql, rusqlite::params![rowid], |row| {
        row.get::<_, Option<String>>(0)
    }) {
        Ok(value) => Ok(value.filter(|id| !id.is_empty())),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(format!("레코드를 읽지 못했습니다: {error}")),
    }
}

/// Resolves `source_db` to a real path inside the host root only. Outside the
/// root, or when the file is missing, the result is empty — source_db is a
/// host-relative source DB path, not an instruction to open any path (docs-24 §4).
fn resolve_source_db(host_root: &Path, source_db: &str) -> String {
    let relative = Path::new(source_db.trim());
    if source_db.trim().is_empty() || relative.is_absolute() {
        return String::new();
    }
    let joined = normalize_bookmark_path(&host_root.join(relative));
    if !joined.starts_with(host_root) || !joined.is_file() {
        return String::new();
    }
    joined.to_string_lossy().to_string()
}

/// One raw evidence identity — the same three parts as a bookmark key (source
/// SQLite path, table, rowid). It does not replace a derived record_id; the UI
/// uses it to keep raw, overview, timeline and search in the same state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourcePointer {
    full_path: String,
    table_name: String,
    rowid: i64,
}

/// Key of the evidence identity bundle (JSON string) added to page rows.
const SOURCE_REFS_KEY: &str = "__source_refs";
/// Max record_id values per source_records lookup.
const SOURCE_REFS_ID_CHUNK: usize = 400;

/// Whether this is a primary contract row, decided from the row's own keys:
/// `overview_name` + `record_id`, or metadata's `metadata_id` + `host_id` +
/// `dataset_id`. Child tables and source_records rows are never decorated, so
/// paging a parent does not fan out one lookup per child.
fn contract_row_record_id(row: &Map<String, Value>) -> Option<String> {
    let text = |key: &str| {
        row.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    if row.contains_key("overview_name") {
        return text("record_id");
    }
    // RegistryExplorer keys/values carry no overview_name column.
    if row.contains_key("entry_kind") && row.contains_key("hive_id") {
        return text("record_id");
    }
    if row.contains_key("host_id") && row.contains_key("dataset_id") {
        return text("metadata_id");
    }
    None
}

/// Host root = grandparent of `<host>/<category>/<file>.sqlite`.
fn host_root_of(db_path: &Path) -> Option<PathBuf> {
    db_path
        .parent()
        .and_then(Path::parent)
        .map(normalize_bookmark_path)
}

/// Reads the raw evidence identities of this page's rows from the same DB's
/// source_records in one batch, instead of a lookup per row. Only stored links
/// are read; raw DBs are never reopened and recomposed.
///
/// All origins are returned (no representative is chosen). Duplicates pointing
/// at the same (path, table, rowid) are kept once, and origins outside the host
/// root or missing from the collection are dropped because they cannot be opened.
fn source_pointers_for(
    conn: &Connection,
    db_path: &Path,
    record_ids: &[String],
) -> Result<BTreeMap<String, Vec<SourcePointer>>, String> {
    let mut out: BTreeMap<String, Vec<SourcePointer>> = BTreeMap::new();
    if record_ids.is_empty() || !table_names(conn).iter().any(|name| name == "source_records") {
        return Ok(out);
    }
    let Some(host_root) = host_root_of(db_path) else {
        return Ok(out);
    };
    for chunk in record_ids.chunks(SOURCE_REFS_ID_CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT record_id, source_db, source_table, source_rowid FROM \"source_records\" \
             WHERE record_id IN ({placeholders}) ORDER BY record_id, ordinal"
        );
        let params: Vec<&dyn rusqlite::ToSql> = chunk
            .iter()
            .map(|id| id as &dyn rusqlite::ToSql)
            .collect();
        for row in query_rows(conn, &sql, params.as_slice())? {
            let text = |key: &str| {
                row.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let record_id = text("record_id");
            let table_name = text("source_table");
            let Some(rowid) = row.get("source_rowid").and_then(Value::as_i64) else {
                continue;
            };
            let full_path = resolve_source_db(&host_root, &text("source_db"));
            if record_id.is_empty() || table_name.is_empty() || full_path.is_empty() {
                continue;
            }
            let pointer = SourcePointer {
                full_path,
                table_name,
                rowid,
            };
            let pointers = out.entry(record_id).or_default();
            if !pointers.contains(&pointer) {
                pointers.push(pointer);
            }
        }
    }
    Ok(out)
}

/// Adds `__source_refs` (evidence identities as a JSON string) to page rows so
/// raw, overview, timeline and search share one bookmark key. Rows that are not
/// primary contract rows are left untouched.
fn decorate_source_refs(
    conn: &Connection,
    db_path: &Path,
    rows: &mut [Map<String, Value>],
) -> Result<(), String> {
    let ids: Vec<String> = rows
        .iter()
        .filter_map(contract_row_record_id)
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .collect();
    let pointers = source_pointers_for(conn, db_path, &ids)?;
    if pointers.is_empty() {
        return Ok(());
    }
    for row in rows.iter_mut() {
        let Some(id) = contract_row_record_id(row) else {
            continue;
        };
        let Some(refs) = pointers.get(&id) else {
            continue;
        };
        let Ok(serialized) = serde_json::to_string(refs) else {
            continue;
        };
        row.insert(SOURCE_REFS_KEY.to_string(), Value::from(serialized));
    }
    Ok(())
}

/// Evidence links of one result row: `source_records` of the same file, by
/// `record_id`, in ordinal order. A row may have several origins and no
/// representative is chosen. Raw tables without `source_records` return empty —
/// they are the evidence, so no origin is invented.
#[tauri::command]
async fn read_record_sources(
    full_path: String,
    table_name: String,
    rowid: i64,
) -> Result<Vec<Map<String, Value>>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        read_record_sources_blocking(full_path, table_name, rowid)
    })
    .await
    .map_err(|error| format!("원본 근거 조회가 중단되었습니다: {error}"))?
}

fn read_record_sources_blocking(
    full_path: String,
    table_name: String,
    rowid: i64,
) -> Result<Vec<Map<String, Value>>, String> {
    let path = PathBuf::from(&full_path);
    let conn = open_ro(&full_path)?;
    let tables = table_names(&conn);
    if !tables.iter().any(|name| name == &table_name) {
        return Ok(Vec::new());
    }
    if !tables.iter().any(|name| name == "source_records") {
        return Ok(Vec::new());
    }
    let Some(record_id) = record_id_of(&conn, &table_name, rowid)? else {
        return Ok(Vec::new());
    };
    let columns = payload_columns(&conn, "source_records");
    let Some(projection) = payload_projection(&columns) else {
        return Ok(Vec::new());
    };
    let sql = format!(
        "SELECT {projection} FROM \"source_records\" WHERE record_id = ?1 ORDER BY ordinal"
    );
    let mut rows = query_rows(&conn, &sql, &[&record_id])?;
    let host_root = host_root_of(&path);
    for row in &mut rows {
        let source_db = row
            .get("source_db")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let resolved = host_root
            .as_deref()
            .map(|root| resolve_source_db(root, &source_db))
            .unwrap_or_default();
        row.insert("source_full_path".to_string(), Value::from(resolved));
    }
    Ok(rows)
}

/// Child rows of one result row (ExecutionTimes, TaskActions, AiMessages, …).
/// Values kept as child rows instead of being forced into the common columns
/// are read only in detail. `child_table` is validated against the file's own
/// tables and the primary table is rejected, so listing cannot be bypassed.
/// `child_key` names the child column holding the parent record_id (default
/// `record_id`, e.g. `matched_record_id` for reference tables).
/// With `via_table`/`via_key`, `child_table` is a link table: each link row's
/// `via_key` value selects the `via_table` row with that record_id. Link
/// columns come back as `link.<column>`, target columns as stored.
#[tauri::command]
async fn read_record_children(
    full_path: String,
    table_name: String,
    rowid: i64,
    child_table: String,
    child_key: Option<String>,
    via_table: Option<String>,
    via_key: Option<String>,
) -> Result<Vec<Map<String, Value>>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        read_record_children_blocking(full_path, table_name, rowid, child_table, child_key, via_table.zip(via_key))
    })
    .await
    .map_err(|error| format!("자식 레코드 조회가 중단되었습니다: {error}"))?
}

fn read_record_children_blocking(
    full_path: String,
    table_name: String,
    rowid: i64,
    child_table: String,
    child_key: Option<String>,
    via: Option<(String, String)>,
) -> Result<Vec<Map<String, Value>>, String> {
    let conn = open_ro(&full_path)?;
    let tables = table_names(&conn);
    if !tables.iter().any(|name| name == &table_name) {
        return Ok(Vec::new());
    }
    if child_table == table_name || !tables.iter().any(|name| name == &child_table) {
        return Ok(Vec::new());
    }
    let Some(record_id) = record_id_of(&conn, &table_name, rowid)? else {
        return Ok(Vec::new());
    };
    let key = child_key.unwrap_or_else(|| "record_id".to_string());
    let columns = payload_columns(&conn, &child_table);
    if !columns.iter().any(|column| column == &key) {
        return Ok(Vec::new());
    }
    let Some(projection) = payload_projection(&columns) else {
        return Ok(Vec::new());
    };
    let has_ordinal = columns.iter().any(|column| column == "ordinal");
    let Some((via_table, via_key)) = via else {
        let order = if has_ordinal { " ORDER BY ordinal" } else { "" };
        let sql = format!(
            "SELECT rowid AS __rowid, {projection} FROM {} WHERE {} = ?1{order}",
            q(&child_table),
            q(&key)
        );
        return query_rows(&conn, &sql, &[&record_id]);
    };
    // Target must be another table of this file keyed by record_id.
    if via_table == table_name
        || via_table == child_table
        || !tables.iter().any(|name| name == &via_table)
        || !columns.iter().any(|column| column == &via_key)
    {
        return Ok(Vec::new());
    }
    let target_columns = payload_columns(&conn, &via_table);
    if !target_columns.iter().any(|column| column == "record_id") {
        return Ok(Vec::new());
    }
    let link_projection = columns
        .iter()
        .map(|column| format!("l.{} AS {}", q(column), q(&format!("link.{column}"))))
        .collect::<Vec<_>>()
        .join(", ");
    let target_projection = target_columns
        .iter()
        .map(|column| format!("t.{}", q(column)))
        .collect::<Vec<_>>()
        .join(", ");
    let order = if has_ordinal { " ORDER BY l.ordinal" } else { "" };
    let sql = format!(
        "SELECT t.rowid AS __rowid, {link_projection}, {target_projection} FROM {} l JOIN {} t ON t.record_id = l.{} WHERE l.{} = ?1{order}",
        q(&child_table),
        q(&via_table),
        q(&via_key),
        q(&key)
    );
    query_rows(&conn, &sql, &[&record_id])
}

#[cfg(test)]
mod record_children_tests {
    use super::*;

    #[test]
    fn via_join_returns_linked_target_rows_in_link_order() {
        let path = std::env::temp_dir().join(format!("wa-children-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Main(record_id TEXT, v TEXT);
             CREATE TABLE Links(record_id TEXT, ordinal INTEGER, context_id TEXT, relation_kind TEXT);
             CREATE TABLE Ctx(record_id TEXT, event_id TEXT);
             INSERT INTO Main VALUES('r1','a'),('r2','b');
             INSERT INTO Links VALUES('r1',1,'c2','end'),('r1',0,'c1','priv'),('r2',0,'c3','end');
             INSERT INTO Ctx VALUES('c1','4672'),('c2','4634'),('c3','4634'),('c4','4776');",
        )
        .unwrap();
        drop(conn);
        let full = path.to_string_lossy().to_string();
        let via = Some(("Ctx".to_string(), "context_id".to_string()));
        let rows = read_record_children_blocking(full.clone(), "Main".into(), 1, "Links".into(), None, via).unwrap();
        let pairs: Vec<(String, String)> = rows
            .iter()
            .map(|row| (row["link.relation_kind"].as_str().unwrap().to_string(), row["event_id"].as_str().unwrap().to_string()))
            .collect();
        assert_eq!(pairs, vec![("priv".into(), "4672".into()), ("end".into(), "4634".into())]);
        // Target cannot be the primary table; the link column must exist.
        assert!(read_record_children_blocking(full.clone(), "Main".into(), 1, "Links".into(), None, Some(("Main".into(), "context_id".into()))).unwrap().is_empty());
        assert!(read_record_children_blocking(full.clone(), "Main".into(), 1, "Links".into(), None, Some(("Ctx".into(), "nope".into()))).unwrap().is_empty());
        // Plain children are unchanged.
        assert_eq!(read_record_children_blocking(full, "Main".into(), 2, "Links".into(), None, None).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn child_key_reads_reference_rows_by_another_column() {
        let path = std::env::temp_dir().join(format!("wa-children-key-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Main(record_id TEXT);
             CREATE TABLE Refs(entry_id TEXT, matched_record_id TEXT, tree_path TEXT);
             INSERT INTO Main VALUES('r1'),('r2');
             INSERT INTO Refs VALUES('e1','r1','\\A'),('e2','r2','\\B'),('e3',NULL,'\\C');",
        )
        .unwrap();
        drop(conn);
        let full = path.to_string_lossy().to_string();
        let rows = read_record_children_blocking(full.clone(), "Main".into(), 2, "Refs".into(), Some("matched_record_id".into()), None).unwrap();
        assert_eq!(rows.iter().map(|row| row["entry_id"].as_str().unwrap()).collect::<Vec<_>>(), vec!["e2"]);
        // Without the key the table has no record_id column → no rows.
        assert!(read_record_children_blocking(full.clone(), "Main".into(), 2, "Refs".into(), None, None).unwrap().is_empty());
        // Unknown key column → no rows (never interpolated unchecked).
        assert!(read_record_children_blocking(full, "Main".into(), 2, "Refs".into(), Some("nope".into()), None).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
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
    /// Derived row id; also the bookmark key with table_name (docs-20).
    record_id: String,
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
    // docs-19: categories are _OVERVIEW table names (case-folded). An empty
    // selection means "no filter"; the UI handles "nothing selected" itself.
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
        // docs-19: only the host's _OVERVIEW contract DBs are searched; raw
        // facts are evidence opened through source_records.
        let mut files = Vec::new();
        collect_sqlite(&Path::new(&host.dir).join("_OVERVIEW"), &mut files);
        files.sort();
        for fp in files {
            if let Some(ref allow) = category_filter {
                let stem = fp
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if !allow.contains(&stem) {
                    continue;
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
            // An unreadable source is reported, never hidden as "no match".
            let mut tables = match checked_table_names(&conn) {
                Ok(tables) => tables,
                Err(_) => {
                    source_failures.push(format!("{}: {}", host.name, file_name));
                    continue;
                }
            };
            // Primary table only (children would repeat one event per row);
            // raw facts under _OVERVIEW (no contract stamp) are not searched.
            match (overview_contract_version(&conn), primary_table_name(&fp)) {
                (Some(_), Some(primary)) => tables.retain(|name| name.eq_ignore_ascii_case(&primary)),
                _ => continue,
            }
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
                // Body BLOBs are excluded: LIKE over hex-expanded bytes would
                // match text the analyst never typed.
                let cols = payload_columns(&conn, &table);
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
                // Lookup key of a derived row; detail and bookmarks resolve it
                // through source_records.
                let record_id_expr = if cols.iter().any(|column| column == "record_id") {
                    "\"record_id\""
                } else {
                    "''"
                };
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
                    "SELECT rowid AS __rowid, CASE {} ELSE '' END AS __match_column, CASE {} ELSE '' END AS __match_value, {} AS __timestamp, {} AS __record_id FROM {} WHERE {} ORDER BY rowid LIMIT {}",
                    match_column,
                    match_value,
                    timestamp_expr,
                    record_id_expr,
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
                        record_id: row
                            .get("__record_id")
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

// --- commands: cross-artifact path references ------------------------------

/// One other-artifact reference that the parser matched to a file record as a
/// candidate (`PathReferenceCandidates`, docs-04 §0). A candidate is path
/// evidence, never "the same file". `row` is the stored PathReferences row
/// (typed, all columns); `full_path`/`table_name`/`rowid` are the first raw
/// origin, used only as the existing bookmark key (rowid -1: none).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileReference {
    file_record_id: String,
    match_basis: String,
    row: Map<String, Value>,
}

/// References for the file records currently on screen, via the stored
/// candidates of the same result generation and volume. No path string is
/// re-normalized or matched here (docs-24: no derivation at read time).
#[tauri::command]
async fn file_references(
    host_dir: String,
    dataset_id: String,
    volume_id: Option<String>,
    file_record_ids: Vec<String>,
) -> Result<Vec<FileReference>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        file_references_blocking(&host_dir, &dataset_id, volume_id.as_deref(), &file_record_ids)
    })
    .await
    .map_err(|error| format!("교차 참조 조회 작업이 중단되었습니다: {error}"))?
}

fn file_references_blocking(
    host_dir: &str,
    dataset_id: &str,
    volume_id: Option<&str>,
    file_record_ids: &[String],
) -> Result<Vec<FileReference>, String> {
    let db = PathBuf::from(host_dir).join("_OVERVIEW").join("PathReferences.sqlite");
    if !db.exists() || file_record_ids.is_empty() {
        return Ok(Vec::new());
    }
    let conn = open_ro(&db.to_string_lossy())?;
    let tables = table_names(&conn);
    if !tables.iter().any(|name| name == "PathReferenceCandidates") {
        return Err("교차 참조 후보 테이블이 없는 이전 결과입니다. 호스트를 다시 파싱하세요.".to_string());
    }
    let volume = volume_id.map(str::trim).filter(|value| !value.is_empty());
    let mut out = Vec::new();
    // SQLite bind limit: chunk the requested ids.
    for chunk in file_record_ids.chunks(400) {
        let mut params: Vec<&dyn rusqlite::ToSql> = vec![&dataset_id];
        let mut volume_clause = String::new();
        if let Some(volume) = volume.as_ref() {
            params.push(volume);
            volume_clause = format!(" AND c.volume_id = ?{}", params.len());
        }
        let first = params.len() + 1;
        let placeholders = (0..chunk.len()).map(|i| format!("?{}", first + i)).collect::<Vec<_>>().join(", ");
        params.extend(chunk.iter().map(|id| id as &dyn rusqlite::ToSql));
        let sql = format!(
            "SELECT c.file_record_id AS __file_record_id, c.match_basis AS __match_basis, p.rowid AS __rowid, p.* \
             FROM PathReferenceCandidates c JOIN PathReferences p ON p.record_id = c.record_id \
             WHERE p.dataset_id = ?1{volume_clause} AND c.file_record_id IN ({placeholders}) \
             ORDER BY c.file_record_id, p.timestamp IS NULL, p.timestamp, p.record_id"
        );
        let rows = query_rows(&conn, &sql, &params)?;
        for mut row in rows {
            let mut take = |key: &str| match row.remove(key) {
                Some(Value::String(value)) => value,
                _ => String::new(),
            };
            let file_record_id = take("__file_record_id");
            let match_basis = take("__match_basis");
            out.push(FileReference { file_record_id, match_basis, row });
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
                // Exclude unknown (NULL) and empty accounts: chips list only
                // confirmed accounts, unknown is not a filter value.
                "SELECT DISTINCT account FROM PathReferences WHERE account IS NOT NULL AND account <> '' ORDER BY account LIMIT 500",
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

/// Bookmark identity (docs-20): the _OVERVIEW result file, its table, the
/// record_id and an optional field. Components are URL-safe base64 so `:`
/// cannot occur inside one.
fn bookmark_id_v3(full_path: &str, table_name: &str, record_id: &str, field: &str) -> String {
    use base64::Engine as _;
    let encode = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    format!(
        "v3:{}:{}:{}:{}",
        encode(full_path),
        encode(table_name),
        encode(record_id),
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
        .filter(|bookmark| !bookmark_targets_missing_host(bookmark, case_path) && bookmark_record_present(bookmark))
        .cloned()
        .collect();
    if retained.len() != bookmarks.len() {
        write_bookmarks_path(case_path, &retained)?;
    }
    Ok(retained)
}

/// docs-20: whether a stored bookmark still names an existing _OVERVIEW
/// record. Legacy raw-coordinate entries (no recordId), a missing result file
/// and a missing record (re-parse) are not; a result that cannot be read right
/// now keeps its bookmark.
fn bookmark_record_present(bookmark: &Value) -> bool {
    let text = |key: &str| bookmark.get(key).and_then(Value::as_str).unwrap_or_default();
    let (full_path, table_name, record_id) = (text("fullPath"), text("tableName"), text("recordId"));
    if record_id.is_empty() || table_name.is_empty() {
        return false;
    }
    if !Path::new(full_path).is_file() {
        return false;
    }
    let Ok(conn) = open_ro(full_path) else {
        return true;
    };
    let sql = format!("SELECT 1 FROM {} WHERE record_id = ?1 LIMIT 1", q(table_name));
    match conn.query_row(&sql, [record_id], |_| Ok(())) {
        Ok(()) => true,
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(_) => true,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BookmarkInput {
    /// `_OVERVIEW/<table>.sqlite` of the bookmarked record.
    full_path: String,
    table_name: String,
    record_id: String,
    #[serde(default)]
    field: Option<String>,
    /// Time shown when the bookmark was set (field value or row timestamp).
    #[serde(default)]
    event_time: Option<String>,
    #[serde(default)]
    host_id: Option<String>,
    #[serde(default)]
    host_name: Option<String>,
}

/// docs-20: only an existing record of a contract DB's primary table can be
/// bookmarked; raw tables are evidence reached through source_records.
fn overview_record_exists(full_path: &str, table_name: &str, record_id: &str) -> bool {
    let Ok(conn) = open_ro(full_path) else {
        return false;
    };
    if overview_contract_version(&conn) != Some(OVERVIEW_CONTRACT_VERSION) {
        return false;
    }
    if !primary_table_name(Path::new(full_path)).is_some_and(|primary| primary.eq_ignore_ascii_case(table_name)) {
        return false;
    }
    let sql = format!("SELECT 1 FROM {} WHERE record_id = ?1 LIMIT 1", q(table_name));
    conn.query_row(&sql, [record_id], |_| Ok(())).is_ok()
}

#[tauri::command]
fn toggle_bookmark(case_dir: String, entry: BookmarkInput) -> Result<Vec<Value>, String> {
    let _guard = lock_bookmarks();
    let mut bookmarks = read_bookmarks(&case_dir)?;
    let field = entry.field.clone().unwrap_or_default();
    let idx = bookmarks.iter().position(|b| {
        b.get("fullPath").and_then(|v| v.as_str()) == Some(entry.full_path.as_str())
            && b.get("tableName").and_then(|v| v.as_str()) == Some(entry.table_name.as_str())
            && b.get("recordId").and_then(|v| v.as_str()) == Some(entry.record_id.as_str())
            && b.get("field").and_then(|v| v.as_str()).unwrap_or("") == field
    });
    if let Some(i) = idx {
        bookmarks.remove(i);
    } else {
        if !overview_record_exists(&entry.full_path, &entry.table_name, &entry.record_id) {
            return Err("분석 결과 행만 북마크할 수 있습니다.".to_string());
        }
        let id = bookmark_id_v3(&entry.full_path, &entry.table_name, &entry.record_id, &field);
        let mut b = Map::new();
        b.insert("id".into(), Value::from(id));
        b.insert("fullPath".into(), Value::from(entry.full_path));
        b.insert("tableName".into(), Value::from(entry.table_name));
        b.insert("recordId".into(), Value::from(entry.record_id));
        if !field.is_empty() {
            b.insert("field".into(), Value::from(field));
        }
        if let Some(event_time) = entry.event_time.filter(|t| !t.is_empty()) {
            b.insert("eventTime".into(), Value::from(event_time));
        }
        b.insert("note".into(), Value::from(""));
        b.insert("taggedAt".into(), Value::from(now_iso()));
        b.insert("hostId".into(), Value::from(entry.host_id.unwrap_or_default()));
        b.insert("hostName".into(), Value::from(entry.host_name.unwrap_or_default()));
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

    /// Host with `_OVERVIEW/Evidence.sqlite` (contract DB) holding `records`.
    fn create_host(case_dir: &Path, host_id: &str, records: &[&str]) -> String {
        let host_dir = case_dir.join(host_id);
        std::fs::create_dir_all(host_dir.join("_OVERVIEW")).unwrap();
        std::fs::write(host_dir.join("host.json"), "{}").unwrap();
        let path = host_dir.join("_OVERVIEW").join("Evidence.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Evidence (record_id TEXT, timestamp TEXT, detail TEXT);\
             CREATE TABLE _wina_derived_version (name TEXT, version INTEGER);\
             INSERT INTO _wina_derived_version VALUES ('overview_contract', 1);",
        )
        .unwrap();
        for record in records {
            conn.execute("INSERT INTO Evidence VALUES (?1, '2026-01-01 00:00:00.000', 'x')", [record]).unwrap();
        }
        path.to_string_lossy().to_string()
    }

    fn entry(full_path: &str, record_id: &str, field: Option<&str>, host_id: &str) -> BookmarkInput {
        BookmarkInput {
            full_path: full_path.to_string(),
            table_name: "Evidence".to_string(),
            record_id: record_id.to_string(),
            field: field.map(str::to_string),
            event_time: Some("2026-01-01 00:00:00.000".to_string()),
            host_id: Some(host_id.to_string()),
            host_name: Some(host_id.to_uppercase()),
        }
    }

    fn ids(values: &[Value]) -> Vec<String> {
        values.iter().filter_map(|value| value.get("id").and_then(Value::as_str).map(str::to_owned)).collect()
    }

    /// docs-20: a bookmark names one _OVERVIEW record (and optional field);
    /// toggling the same target removes it.
    #[test]
    fn toggle_adds_and_removes_an_overview_record_bookmark() {
        let case_dir = temporary_case_dir("bookmark-toggle");
        let db = create_host(&case_dir, "host-a", &["r1"]);
        let dir = case_dir.to_string_lossy().to_string();
        let added = toggle_bookmark(dir.clone(), entry(&db, "r1", None, "host-a")).unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0]["recordId"], "r1");
        assert_eq!(added[0]["tableName"], "Evidence");
        assert_eq!(added[0]["hostId"], "host-a");
        assert_eq!(added[0]["eventTime"], "2026-01-01 00:00:00.000");
        assert!(added[0].get("rowid").is_none());
        assert!(added[0]["id"].as_str().unwrap().starts_with("v3:"));
        // A field bookmark on the same record is a separate target.
        let both = toggle_bookmark(dir.clone(), entry(&db, "r1", Some("timestamp"), "host-a")).unwrap();
        assert_eq!(both.len(), 2);
        let removed = toggle_bookmark(dir.clone(), entry(&db, "r1", None, "host-a")).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0]["field"], "timestamp");
        let _ = std::fs::remove_dir_all(case_dir);
    }

    /// Raw tables and records that do not exist are not bookmark targets.
    #[test]
    fn raw_tables_and_missing_records_are_rejected() {
        let case_dir = temporary_case_dir("bookmark-reject");
        let db = create_host(&case_dir, "host-a", &["r1"]);
        let raw = case_dir.join("host-a").join("Raw.sqlite");
        Connection::open(&raw).unwrap().execute_batch("CREATE TABLE Evidence (record_id TEXT); INSERT INTO Evidence VALUES ('r1');").unwrap();
        let dir = case_dir.to_string_lossy().to_string();
        assert!(toggle_bookmark(dir.clone(), entry(&raw.to_string_lossy(), "r1", None, "host-a")).is_err());
        assert!(toggle_bookmark(dir.clone(), entry(&db, "nope", None, "host-a")).is_err());
        assert!(read_bookmarks(&dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(case_dir);
    }

    /// Re-parse replaces record ids: listing drops bookmarks whose record is
    /// gone, whose file is gone, legacy raw-coordinate entries and missing
    /// hosts; an unreadable result keeps its bookmark.
    #[test]
    fn listing_prunes_bookmarks_whose_record_no_longer_exists() {
        let case_dir = temporary_case_dir("bookmark-prune");
        let db = create_host(&case_dir, "host-a", &["r1", "r2"]);
        let dir = case_dir.to_string_lossy().to_string();
        toggle_bookmark(dir.clone(), entry(&db, "r1", None, "host-a")).unwrap();
        toggle_bookmark(dir.clone(), entry(&db, "r2", None, "host-a")).unwrap();
        let mut stored = read_bookmarks(&dir).unwrap();
        stored.push(serde_json::json!({"id": "legacy", "fullPath": db, "tableName": "Evidence", "rowid": 1, "hostId": "host-a", "note": "", "taggedAt": ""}));
        stored.push(serde_json::json!({"id": "gone-host", "fullPath": "/x/_OVERVIEW/Evidence.sqlite", "tableName": "Evidence", "recordId": "r9", "hostId": "removed-host", "note": "", "taggedAt": ""}));
        let unreadable = case_dir.join("host-a").join("_OVERVIEW").join("Broken.sqlite");
        std::fs::write(&unreadable, vec![0_u8; 128]).unwrap();
        stored.push(serde_json::json!({"id": "unreadable", "fullPath": unreadable.to_string_lossy(), "tableName": "Broken", "recordId": "r1", "hostId": "host-a", "note": "", "taggedAt": ""}));
        stored.push(serde_json::json!({"id": "missing-file", "fullPath": case_dir.join("host-a").join("_OVERVIEW").join("Gone.sqlite").to_string_lossy(), "tableName": "Gone", "recordId": "r1", "hostId": "host-a", "note": "", "taggedAt": ""}));
        write_bookmarks(&dir, &stored).unwrap();
        // Simulate a re-parse that no longer has r2.
        Connection::open(&db).unwrap().execute("DELETE FROM Evidence WHERE record_id='r2'", []).unwrap();

        let listed = list_bookmarks(dir.clone()).unwrap();
        let kept = ids(&listed);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept.iter().any(|id| id == "unreadable"));
        assert!(listed.iter().any(|value| value["recordId"] == "r1" && value["tableName"] == "Evidence"));
        assert_eq!(read_bookmarks(&dir).unwrap(), listed);
        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn concurrent_bookmark_toggles_preserve_every_record() {
        let case_dir = temporary_case_dir("bookmark-race");
        let records: Vec<String> = (0..40).map(|index| format!("r{index}")).collect();
        let db = create_host(&case_dir, "host-a", &records.iter().map(String::as_str).collect::<Vec<_>>());
        let dir = case_dir.to_string_lossy().to_string();
        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let (dir, db) = (dir.clone(), db.clone());
                std::thread::spawn(move || {
                    for step in 0..5 {
                        toggle_bookmark(dir.clone(), entry(&db, &format!("r{}", worker * 5 + step), None, "host-a")).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(read_bookmarks(&dir).unwrap().len(), 40, "겹친 토글이 서로의 저장을 덮어쓰면 안 된다");
        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn deleting_host_removes_only_its_case_bookmarks() {
        let case_dir = temporary_case_dir("bookmark-host-delete");
        let removed = create_host(&case_dir, "removed-host", &["r1"]);
        let retained = create_host(&case_dir, "retained-host", &["r1"]);
        let dir = case_dir.to_string_lossy().to_string();
        toggle_bookmark(dir.clone(), entry(&removed, "r1", None, "removed-host")).unwrap();
        toggle_bookmark(dir.clone(), entry(&retained, "r1", None, "retained-host")).unwrap();
        assert!(delete_host_dir_and_bookmarks(&case_dir, "removed-host"));
        assert!(!case_dir.join("removed-host").exists());
        let stored = read_bookmarks_path(&case_dir).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0]["hostId"], "retained-host");
        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn analysis_view_reads_a_row_by_record_id() {
        let case_dir = temporary_case_dir("bookmark-row");
        let db = create_host(&case_dir, "host-a", &["r1", "r2"]);
        let row = result_row_by_record_id_blocking(db.clone(), "Evidence".into(), "r2".into()).unwrap();
        assert_eq!(row.row.as_ref().and_then(|row| row.get("record_id")).and_then(Value::as_str), Some("r2"));
        assert!(result_row_by_record_id_blocking(db, "Evidence".into(), "nope".into()).unwrap().row.is_none());
        let _ = std::fs::remove_dir_all(case_dir);
    }

    #[test]
    fn malformed_bookmark_file_is_reported_instead_of_looking_empty() {
        let case_dir = temporary_case_dir("bookmark-malformed");
        std::fs::write(case_dir.join("bookmarks.json"), "{ not valid json").unwrap();
        assert!(list_bookmarks(case_dir.to_string_lossy().to_string()).is_err());
        let _ = std::fs::remove_dir_all(case_dir);
    }
}

#[cfg(test)]
mod powershell_search_tests {
    use super::*;

    fn db(tag: &str, ddl: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "windows-analysis-ps-search-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),
        ));
        Connection::open(&path).unwrap().execute_batch(ddl).unwrap();
        path
    }

    #[test]
    fn searches_decoded_commands_and_4100_text_beyond_the_list_preview() {
        let path = db("v3", "CREATE TABLE PowerShellHistory (record_id TEXT, command TEXT, script_block TEXT,
               host_application TEXT, script_path TEXT, error_message TEXT, context_info TEXT);
             CREATE TABLE PowerShellEncodedCommands (record_id TEXT, decoded_command TEXT);
             INSERT INTO PowerShellHistory VALUES
               ('a', NULL, NULL, 'powershell -enc VwBy', NULL, NULL, NULL),
               ('b', NULL, NULL, NULL, NULL, 'System error.', NULL),
               ('c', 'Get-Date', NULL, NULL, NULL, NULL, NULL);
             INSERT INTO PowerShellEncodedCommands VALUES ('a', 'Write-Output secret_100%');");
        let full = path.to_string_lossy().to_string();
        assert_eq!(powershell_search_rowids_blocking(&full, "SECRET_100%").unwrap(), vec![1]);
        assert_eq!(powershell_search_rowids_blocking(&full, "system error").unwrap(), vec![2]);
        // LIKE wildcards in the needle are literal.
        assert!(powershell_search_rowids_blocking(&full, "get_date").unwrap().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn older_results_without_new_columns_still_search() {
        let path = db("v2", "CREATE TABLE PowerShellHistory (record_id TEXT, command TEXT, script_block TEXT, host_application TEXT);
             INSERT INTO PowerShellHistory VALUES ('a', 'Invoke-Thing', NULL, NULL);");
        assert_eq!(powershell_search_rowids_blocking(&path.to_string_lossy(), "invoke").unwrap(), vec![1]);
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod account_event_tests {
    use super::*;

    fn host(tag: &str, version: i64) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-account-events-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),
        ));
        std::fs::create_dir_all(root.join("_OVERVIEW")).unwrap();
        let conn = Connection::open(root.join("_OVERVIEW").join("TargetInfo.sqlite")).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE _wina_derived_version (name TEXT PRIMARY KEY, version INTEGER);
             INSERT INTO _wina_derived_version VALUES ('overview_contract', 1), ('target_info', {version});
             CREATE TABLE TargetInfo (record_id TEXT, dataset_id TEXT);
             INSERT INTO TargetInfo VALUES ('acct', 'ds-1'), ('other', 'ds-1'), ('idle', 'ds-1');
             CREATE TABLE source_records (record_id TEXT, ordinal INTEGER, source_db TEXT, source_table TEXT,
               source_rowid INTEGER, source_record_key TEXT);
             CREATE TABLE TargetAccountEvents (record_id TEXT, ordinal INTEGER, source_ordinal INTEGER, timestamp TEXT,
               channel TEXT, event_id INTEGER, level_name TEXT, level INTEGER, provider TEXT, computer TEXT,
               event_record_id INTEGER, process_id INTEGER, thread_id INTEGER, user_id TEXT, event_data TEXT,
               parse_status TEXT, parse_error TEXT);
             CREATE TABLE TargetAccountEventMatches (record_id TEXT, ordinal INTEGER, event_ordinal INTEGER,
               role TEXT, match_kind TEXT, field TEXT, value TEXT);
             INSERT INTO source_records VALUES
               ('acct', 0, 'EVENTLOG/Security.sqlite', 'Security', 70, 'Security::70'),
               ('acct', 1, 'EVENTLOG/Security.sqlite', 'Security', 71, 'Security::71'),
               ('acct', 2, 'EVENTLOG/System.sqlite', 'System', 5, 'System::5'),
               ('other', 0, 'EVENTLOG/Security.sqlite', 'Security', 99, 'Security::99');
             INSERT INTO TargetAccountEvents VALUES
               ('acct', 0, 0, '2024-02-02 10:00:00.000', 'Security', 4624, 'Information', 4,
                'Microsoft-Windows-Security-Auditing', 'PC', 70, 4, 8, NULL, '{{\"TargetUserSid\":\"S-1-5-21-1\"}}', 'ok', NULL),
               ('acct', 1, 1, '2024-02-01 10:00:00.000', 'Security', 4672, 'Information', 4,
                'Microsoft-Windows-Security-Auditing', 'PC', 71, 4, 8, NULL, '{{}}', 'ok', NULL),
               ('acct', 2, 2, NULL, 'System', 7036, 'Information', 4, 'Service Control Manager', 'PC', 5, 4, 8,
                'S-1-5-21-1', 'not json', 'error', 'invalid json'),
               ('other', 0, 0, '2024-02-01 09:00:00.000', 'Security', 4624, 'Information', 4, 'X', 'PC', 99, 4, 8,
                NULL, '{{}}', 'ok', NULL);
             INSERT INTO TargetAccountEventMatches VALUES
               ('acct', 0, 0, '대상 계정', 'sid', 'TargetUserSid', 'S-1-5-21-1'),
               ('acct', 1, 1, '수행 계정', 'name', 'SubjectUserName', 'alice'),
               ('acct', 2, 2, '이벤트 보안 주체', 'sid', 'UserID', 'S-1-5-21-1');"
        ))
        .unwrap();
        root
    }

    fn query(search: Option<&str>, start: Option<&str>) -> AccountEventQuery {
        query_for("acct", "ds-1", search, start)
    }

    fn query_for(record_id: &str, dataset_id: &str, search: Option<&str>, start: Option<&str>) -> AccountEventQuery {
        AccountEventQuery {
            record_id: record_id.into(),
            dataset_id: dataset_id.into(),
            search: search.map(str::to_string),
            start: start.map(str::to_string),
            end: None,
            offset: 0,
            limit: 10,
        }
    }

    #[test]
    fn pages_stored_account_events_oldest_first_with_evidence_and_raw_bookmark_key() {
        let root = host("page", 2);
        let host_dir = root.to_string_lossy().to_string();
        let page = account_event_page_blocking(host_dir.clone(), query(None, None)).unwrap();
        assert!(!page.stale);
        assert_eq!(page.row_count, 3, "other account's event is excluded");
        let times: Vec<String> = page.rows.iter().map(|r| map_text(r, "timestamp")).collect();
        assert_eq!(times, vec!["2024-02-01 10:00:00.000", "2024-02-02 10:00:00.000", ""]);
        let first = &page.rows[0];
        assert_eq!(map_text(first, "EventID"), "4672");
        assert_eq!(map_text(first, "__rowid"), "71");
        assert_eq!(map_text(first, "_source_table_name"), "Security");
        let mut expected = PathBuf::from(&host_dir);
        expected.extend(["EVENTLOG", "Security.sqlite"]);
        assert_eq!(map_text(first, "_source_full_path"), expected.to_string_lossy());
        assert!(first.get("_source_db").is_none());

        // Range excludes undated events; search reaches match evidence.
        let ranged = account_event_page_blocking(host_dir.clone(), query(None, Some("2024-02-02 00:00:00.000"))).unwrap();
        assert_eq!(ranged.row_count, 1);
        let by_evidence = account_event_page_blocking(host_dir.clone(), query(Some("ALICE"), None)).unwrap();
        assert_eq!(by_evidence.row_count, 1);
        assert_eq!(map_text(&by_evidence.rows[0], "EventID"), "4672");
        let by_field = account_event_page_blocking(host_dir, query(Some("service control"), None)).unwrap();
        assert_eq!(by_field.row_count, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn results_before_target_info_2_report_reparse_instead_of_empty_activity() {
        let root = host("stale", 1);
        let page = account_event_page_blocking(root.to_string_lossy().to_string(), query(None, None)).unwrap();
        assert!(page.stale);
        assert_eq!(page.row_count, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replaced_result_is_distinguished_from_an_account_without_activity() {
        let root = host("replaced", 2);
        let host_dir = root.to_string_lossy().to_string();
        let idle = account_event_page_blocking(host_dir.clone(), query_for("idle", "ds-1", None, None)).unwrap();
        assert_eq!((idle.row_count, idle.stale, idle.replaced), (0, false, false));
        let old_generation = account_event_page_blocking(host_dir.clone(), query_for("acct", "ds-0", None, None)).unwrap();
        assert_eq!((old_generation.row_count, old_generation.replaced), (0, true));
        let gone = account_event_page_blocking(host_dir, query_for("missing", "ds-1", None, None)).unwrap();
        assert!(gone.replaced);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unreadable_current_result_is_an_error_not_a_replacement() {
        let root = host("broken", 2);
        Connection::open(root.join("_OVERVIEW").join("TargetInfo.sqlite"))
            .unwrap()
            .execute_batch("DROP TABLE TargetInfo;")
            .unwrap();
        assert!(account_event_page_blocking(root.to_string_lossy().to_string(), query(None, None)).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod search_case_tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-search-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(root.join("_OVERVIEW")).unwrap();
        root
    }

    /// A contract DB `_OVERVIEW/<name>.sqlite` with one primary table.
    fn contract_db(root: &Path, name: &str, rows: &[(&str, &str)]) {
        let conn = Connection::open(root.join("_OVERVIEW").join(format!("{name}.sqlite"))).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE \"{name}\" (record_id TEXT, timestamp TEXT, detail TEXT);\
             CREATE TABLE source_records (record_id TEXT, ordinal INTEGER, source_db TEXT, source_table TEXT, source_rowid INTEGER);\
             CREATE TABLE _wina_derived_version (name TEXT, version INTEGER);\
             INSERT INTO _wina_derived_version VALUES ('overview_contract', 1);"
        ))
        .unwrap();
        for (index, (timestamp, detail)) in rows.iter().enumerate() {
            conn.execute(
                &format!("INSERT INTO \"{name}\" VALUES (?1, ?2, ?3)"),
                rusqlite::params![format!("{name}-{index}"), timestamp, detail],
            )
            .unwrap();
        }
    }

    fn hosts(root: &Path) -> Vec<SearchHost> {
        vec![SearchHost { id: "host-1".into(), name: "HOST-1".into(), dir: root.to_string_lossy().to_string() }]
    }

    #[test]
    fn search_case_pages_bounded_preview_and_reports_failed_source() {
        let root = temp_root("page");
        let long_detail = format!("verylong{}", "x".repeat(4_096));
        contract_db(&root, "Findings", &[
            ("2026-01-01 00:00:00.000", "needle first"),
            ("2026-01-02 00:00:00.000", "needle second"),
            ("2026-01-03 00:00:00.000", &long_detail),
        ]);
        std::fs::write(root.join("_OVERVIEW").join("Zunreadable.sqlite"), vec![0_u8; 128]).unwrap();
        let hosts = hosts(&root);

        let first = search_case_blocking("needle".into(), hosts.clone(), 0, 1, None, None, None);
        assert_eq!(first.hits.len(), 1, "source failures: {:?}", first.source_failures);
        assert_eq!(first.hits[0].match_column, "detail");
        assert_eq!(first.hits[0].match_value, "needle first");
        assert_eq!(first.hits[0].timestamp, "2026-01-01 00:00:00.000");
        assert_eq!(first.hits[0].record_id, "Findings-0");
        assert_eq!(first.next_offset, Some(1));
        // A continuation must not hide later unreadable sources.
        assert!(!first.source_failures.is_empty());

        let second = search_case_blocking("needle".into(), hosts.clone(), 1, 1, None, None, None);
        assert_eq!(second.hits.len(), 1);
        assert_eq!(second.hits[0].match_value, "needle second");
        assert_eq!(second.next_offset, None);

        let ranged = search_case_blocking(
            "needle".into(),
            hosts.clone(),
            0,
            10,
            Some("2026-01-02 00:00:00.000".into()),
            Some("2026-01-02 23:59:59.999".into()),
            None,
        );
        assert_eq!(ranged.hits.len(), 1);
        assert_eq!(ranged.hits[0].match_value, "needle second");

        let bounded_preview = search_case_blocking("verylong".into(), hosts, 0, 10, None, None, None);
        assert_eq!(bounded_preview.hits.len(), 1);
        assert_eq!(bounded_preview.hits[0].match_value.chars().count(), 512);
        let _ = std::fs::remove_dir_all(root);
    }

    /// docs-19: only _OVERVIEW contract DBs are searched; raw folders and raw
    /// facts stored under _OVERVIEW (MFT_Records) are not. Categories name
    /// overview tables.
    #[test]
    fn search_case_reads_overview_contract_tables_only() {
        let root = temp_root("overview");
        contract_db(&root, "Alpha", &[("2026-01-01 00:00:00.000", "needle Alpha")]);
        contract_db(&root, "Beta", &[("2026-01-01 00:00:00.000", "needle Beta")]);
        for (folder, file) in [("BROWSER", "History"), ("_OVERVIEW", "MFT_Records")] {
            std::fs::create_dir_all(root.join(folder)).unwrap();
            let conn = Connection::open(root.join(folder).join(format!("{file}.sqlite"))).unwrap();
            conn.execute_batch(&format!("CREATE TABLE \"{file}\" (timestamp TEXT, detail TEXT); INSERT INTO \"{file}\" VALUES ('2026-01-01 00:00:00.000', 'needle {file}');"))
                .unwrap();
        }
        let hosts = hosts(&root);
        let values = |page: SearchCasePage| -> Vec<String> {
            let mut values: Vec<String> = page.hits.into_iter().map(|hit| hit.match_value).collect();
            values.sort();
            values
        };
        assert_eq!(values(search_case_blocking("needle".into(), hosts.clone(), 0, 10, None, None, None)), vec!["needle Alpha", "needle Beta"]);
        assert_eq!(values(search_case_blocking("needle".into(), hosts.clone(), 0, 10, None, None, Some(vec!["alpha".into()]))), vec!["needle Alpha"]);
        // An empty selection is "no filter", not "match nothing".
        assert_eq!(values(search_case_blocking("needle".into(), hosts, 0, 10, None, None, Some(vec![]))).len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }
}


#[cfg(test)]
mod timeline_build_tests {
    use super::*;

    /// 타임라인 DB는 원본 행 사본을 담지 않는다 — 검색 문자열은 백엔드가 원본에서
    /// 만들고, 페이지 조회는 그 페이지 분의 원본 행만 읽어 붙인다. 증거 사본을
    /// IPC로 나르지 않으면서 검색·표시 결과는 같아야 한다.
    #[test]
    fn timeline_derives_search_and_attaches_rows_without_storing_copies() {
        let root = std::env::temp_dir().join(format!("wina-tl-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&src_dir).unwrap();
        let src = src_dir.join("Security.sqlite");
        {
            let conn = Connection::open(&src).unwrap();
            conn.execute_batch(
                "CREATE TABLE Security (timestamp TEXT, EventID TEXT, EventData TEXT);
                 INSERT INTO Security VALUES ('2026-01-01 10:00:00.000','4624','{\"User\":\"CORP\\\\analyst\"}');
                 INSERT INTO Security VALUES ('2026-01-02 10:00:00.000','4625','{\"User\":\"CORP\\\\intruder\"}')",
            )
            .unwrap();
        }
        let host = root.to_string_lossy().to_string();
        let token = "tl-build-token";
        timeline_build_begin_impl(&host, token, "2026-01-01 00:00:00.000").unwrap();
        let full = src.to_string_lossy().to_string();
        // 프런트가 보내는 것은 경량 필드뿐이다(원본 사본·검색 문자열 없음).
        let ndjson = format!(
            "{}\n{}",
            serde_json::json!({
                "ts": "2026-01-01 10:00:00.000", "category": "EVENTLOG", "source_table": "Security",
                "artifact_group": "g", "filter_key": "", "has_tags": 0, "full_path": full,
                "rowid_src": 1, "record_key": "Security::1", "event_time": "2026-01-01 10:00:00.000"
            }),
            serde_json::json!({
                "ts": "2026-01-02 10:00:00.000", "category": "EVENTLOG", "source_table": "Security",
                "artifact_group": "g", "filter_key": "", "has_tags": 0, "full_path": full,
                "rowid_src": 2, "record_key": "Security::2", "event_time": "2026-01-02 10:00:00.000"
            })
        );
        let rows: Vec<TimelineInsertRow> = ndjson
            .split('\n')
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .unwrap();
        timeline_build_insert_impl(&host, token, rows).unwrap();
        timeline_build_finish_impl(&host, token).unwrap();

        // 타임라인 DB에 원본 행 사본 컬럼이 없다.
        let db = Connection::open(timeline_db_path(&host)).unwrap();
        let columns = table_columns(&db, "master_timeline");
        assert!(!columns.iter().any(|c| c == "row_json"), "columns={columns:?}");
        drop(db);

        let page = |search: &str| {
            timeline_page_impl(
                &host,
                TimelineQuery {
                    search: search.to_string(),
                    hidden_source_tables: vec![],
                    hidden_exec_sources: vec![],
                    hidden_browser_kinds: vec![],
                    only_suspicious: false,
                    start: String::new(),
                    end: String::new(),
                    sort_desc: false,
                    offset: 0,
                    limit: 50,
                },
            )
            .unwrap()
        };

        // 원본 행 값(EventData 안의 계정)으로 검색된다 — 백엔드가 만든 검색
        // 문자열이 프런트가 만들던 것과 같은 범위를 덮는다.
        let hit = page("intruder");
        assert_eq!(hit.total, 1);
        assert_eq!(hit.rows[0].rowid_src, 2);
        assert_eq!(page("analyst").total, 1);
        assert_eq!(page("4624").total, 1);
        assert_eq!(page("없는값").total, 0);

        // 페이지 조회는 원본 행을 붙여 준다(목록 제목·태그·상세가 쓰던 값).
        let all = page("");
        assert_eq!(all.rows.len(), 2);
        assert_eq!(all.rows[0].row["EventID"], serde_json::json!("4624"));
        assert!(all.rows[0].row.contains_key("EventData"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 웹뷰 리로드·크래시로 abort가 오지 않은 빌드 세션은 열린 SQLite 연결과
    /// `.building-` 임시 파일을 붙잡는다. 회수 조건이 "같은 host_dir"뿐이면 그
    /// 호스트로 다음 빌드가 오기 전까지 무기한 남는다 — 유휴 세션은 다른
    /// 호스트의 다음 빌드가 회수해야 한다.
    #[test]
    fn idle_abandoned_timeline_session_is_reclaimed_by_the_next_build() {
        let root = std::env::temp_dir().join(format!("wina-tl-idle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let abandoned_host = root.join("hostA");
        let next_host = root.join("hostB");
        std::fs::create_dir_all(&abandoned_host).unwrap();
        std::fs::create_dir_all(&next_host).unwrap();
        let abandoned = abandoned_host.to_string_lossy().to_string();
        let next = next_host.to_string_lossy().to_string();

        timeline_build_begin_impl(&abandoned, "tok-idle", "2026-01-01 00:00:00.000").unwrap();
        let building = {
            let handle = timeline_build_sessions()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get("tok-idle")
                .cloned()
                .expect("빌드 세션이 등록되어야 한다");
            let mut session = handle
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // abort를 받지 못한 채 방치된 상태를 만든다(진행 중인 배치 없음).
            session.touched_at = Instant::now()
                .checked_sub(TIMELINE_BUILD_SESSION_IDLE + Duration::from_secs(1))
                .unwrap();
            session.building_path.clone()
        };
        assert!(building.exists());

        timeline_build_begin_impl(&next, "tok-live", "2026-01-01 00:00:00.000").unwrap();
        {
            let sessions = timeline_build_sessions()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(
                sessions.get("tok-idle").is_none(),
                "유휴 세션이 회수되지 않았다"
            );
            assert!(
                sessions.get("tok-live").is_some(),
                "방금 시작한 세션은 남아야 한다"
            );
        }
        assert!(!building.exists(), "회수된 세션의 임시 DB 파일이 남았다");

        timeline_build_abort_impl(&next, "tok-live");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
#[cfg(test)]
mod timeline_source_page_tests {
    use super::*;

    fn fixture(dir: &Path, rows: &[(i64, String)]) -> String {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join("Source.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE Rows (timestamp TEXT, payload TEXT)")
            .unwrap();
        for (index, payload) in rows {
            conn.execute(
                "INSERT INTO Rows (timestamp, payload) VALUES (?1, ?2)",
                rusqlite::params![format!("2026-01-01 00:00:{:02}.000", index), payload],
            )
            .unwrap();
        }
        path.to_string_lossy().to_string()
    }

    /// 큰 증거 값이 섞이면 요청 행 수보다 먼저 바이트 예산에서 끊기고,
    /// nextOffset을 따라가면 한 행도 빠지지 않는다 — 행 수만으로 종료를
    /// 판단하면 잘린 페이지를 테이블 끝으로 오해해 증거가 누락된다.
    #[test]
    fn byte_budget_splits_pages_without_losing_rows() {
        let root = std::env::temp_dir().join(format!("wina-tl-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // 각 3MiB인 행 6개 — 8MiB 예산이면 페이지당 3행 남짓에서 끊긴다.
        let big = "x".repeat(3 * 1024 * 1024);
        let rows: Vec<(i64, String)> = (0..6).map(|i| (i, big.clone())).collect();
        let path = fixture(&root, &rows);

        let first =
            timeline_source_page_blocking(path.clone(), Some("Rows".into()), 0, 20_000).unwrap();
        assert!(
            first.rows.len() < 6,
            "예산보다 큰 페이지가 통째로 반환되면 안 된다 (rows={})",
            first.rows.len()
        );
        assert_eq!(first.next_offset, Some(first.rows.len() as i64));

        // nextOffset을 따라 끝까지 읽으면 전체 행이 정확히 한 번씩 나온다.
        let mut seen = Vec::new();
        let mut offset = Some(0i64);
        while let Some(at) = offset {
            let page =
                timeline_source_page_blocking(path.clone(), Some("Rows".into()), at, 20_000).unwrap();
            for row in &page.rows {
                seen.push(row["timestamp"].as_str().unwrap().to_string());
            }
            offset = page.next_offset;
        }
        assert_eq!(seen.len(), 6);
        assert_eq!(seen[0], "2026-01-01 00:00:00.000");
        assert_eq!(seen[5], "2026-01-01 00:00:05.000");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 타임라인 빌드와 일반 증거 표는 같은 리더를 써야 한다 — CacheEntries의
    /// 본문(body_b64) 제외 같은 열 선택이 한쪽에만 반영되면 같은 원본이 화면마다
    /// 다르게 보인다.
    #[test]
    fn timeline_and_raw_table_expose_the_same_columns() {
        let root = std::env::temp_dir().join(format!("wina-tl-same-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("Cache.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE CacheEntries (url TEXT, response_time TEXT, body_b64 TEXT);
                 INSERT INTO CacheEntries VALUES ('https://x/', '2026-01-01 00:00:00.000', 'QUJD')",
            )
            .unwrap();
        }
        let full = path.to_string_lossy().to_string();
        let raw = read_result_file_page_blocking(full.clone(), Some("CacheEntries".into()), 0, 10)
            .unwrap();
        let tl =
            timeline_source_page_blocking(full, Some("CacheEntries".into()), 0, 10).unwrap();
        assert_eq!(raw.columns, tl.columns);
        // 캐시 본문은 어느 경로에서도 페이지에 실리지 않는다.
        assert!(!raw.columns.contains(&"body_b64".to_string()));
        assert!(!tl.rows[0].contains_key("body_b64"));
        assert_eq!(raw.rows[0]["url"], tl.rows[0]["url"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 작은 테이블은 한 페이지로 끝나고 nextOffset=None으로 종료를 알린다.
    /// 한 행이 예산보다 커도 최소 한 행은 반환해 진행이 멈추지 않는다.
    #[test]
    fn small_table_ends_and_oversized_row_still_progresses() {
        let root = std::env::temp_dir().join(format!("wina-tl-src2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rows = vec![(0i64, "a".to_string()), (1, "b".to_string())];
        let path = fixture(&root, &rows);
        let page = timeline_source_page_blocking(path, Some("Rows".into()), 0, 20_000).unwrap();
        assert_eq!(page.rows.len(), 2);
        assert_eq!(page.next_offset, None);
        let _ = std::fs::remove_dir_all(&root);

        let root2 = std::env::temp_dir().join(format!("wina-tl-src3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root2);
        let huge = vec![(0i64, "y".repeat(TIMELINE_SOURCE_PAGE_MAX_BYTES + 1024))];
        let path2 = fixture(&root2, &huge);
        let page2 = timeline_source_page_blocking(path2, Some("Rows".into()), 0, 20_000).unwrap();
        assert_eq!(page2.rows.len(), 1, "예산 초과 단일 행도 진행을 위해 반환한다");
        let _ = std::fs::remove_dir_all(&root2);
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

    /// Only a log that really exists inside a registered host under the cases
    /// root may be opened; this must never become an arbitrary file opener.
    #[test]
    fn open_parse_run_log_rejects_paths_outside_a_registered_host() {
        let root = std::env::temp_dir().join(format!(
            "windows-analysis-log-open-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let cases = root.join("cases");
        let host = cases.join("HOST_1");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::write(host.join("host.json"), b"{}").unwrap();
        let log = pipeline::parse_run_log_path(&host, "run-1");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(&log, b"log").unwrap();

        let resolved =
            parse_run_log_file_in(&cases, &host.to_string_lossy(), "run-1").expect("stored log");
        assert_eq!(resolved, log.canonicalize().unwrap());

        // Non-host folder, unregistered folder, escaping run id, missing log.
        let outsider = root.join("elsewhere");
        std::fs::create_dir_all(&outsider).unwrap();
        assert!(parse_run_log_file_in(&cases, &outsider.to_string_lossy(), "run-1").is_err());
        let unregistered = cases.join("not-a-host");
        std::fs::create_dir_all(&unregistered).unwrap();
        assert!(parse_run_log_file_in(&cases, &unregistered.to_string_lossy(), "run-1").is_err());
        assert!(parse_run_log_file_in(&cases, &host.to_string_lossy(), "../run-1").is_err());
        assert!(parse_run_log_file_in(&cases, &host.to_string_lossy(), "missing-run").is_err());
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

#[cfg(test)]
mod overview_contract_tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wina-contract-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ))
    }

    #[test]
    fn host_metadata_does_not_silently_drop_large_host_records() {
        let root = temp_root("metadata-complete");
        let mut conn = wina_core::derived::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        let tx = conn.transaction().unwrap();
        {
            let mut insert = tx.prepare(
                "INSERT INTO metadata(metadata_id, host_id, dataset_id, kind, scope, key, value, resolution_status) VALUES (?1, 'host', 'generation', 'env', 'machine', ?2, ?3, 'resolved')",
            ).unwrap();
            for index in 0..=5000 {
                insert.execute(rusqlite::params![
                    format!("env-{index}"), format!("KEY_{index:05}"), format!("value-{index}"),
                ]).unwrap();
            }
        }
        tx.commit().unwrap();
        drop(conn);
        let result = host_metadata_blocking(root.to_string_lossy().into(), None, Some("env".into())).unwrap();
        assert!(result.contract_ok);
        assert_eq!(result.rows.len(), 5001);
        assert!(result.rows.iter().any(|row|
            row.get("key").and_then(Value::as_str) == Some("KEY_05000")
                && row.get("value").and_then(Value::as_str) == Some("value-5000")
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// One docs-01 §18 FileSystemEntries set: typed flags and byte sizes, stored
    /// link/path/data status, unknown time, a resident body, two volumes.
    fn write_file_system_entries(overview: &Path) -> PathBuf {
        let path = overview.join("FileSystemEntries.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE FileSystemEntries (record_id TEXT NOT NULL, host_id TEXT NOT NULL, dataset_id TEXT NOT NULL, timestamp TEXT, overview_name TEXT NOT NULL, account TEXT, account_sid TEXT, timestamp_kind TEXT, event_type TEXT, description TEXT, path TEXT, file_name TEXT, extension TEXT, is_directory INTEGER, in_use INTEGER, file_size INTEGER, data BLOB, volume_id TEXT, volume_label TEXT, volume_serial TEXT, drive_letter TEXT, ntfs_major_version INTEGER, ntfs_minor_version INTEGER, volume_flags TEXT, entry INTEGER, seq INTEGER, parent_entry INTEGER, parent_seq INTEGER, si_created TEXT, si_modified TEXT, si_mft_modified TEXT, si_accessed TEXT, owner_id INTEGER, security_id INTEGER, fn_created TEXT, fn_modified TEXT, fn_mft_modified TEXT, fn_accessed TEXT, parent_status TEXT, path_status TEXT, data_status TEXT, source_file TEXT, source_relative TEXT, input_name TEXT, path_key TEXT);
             CREATE TABLE source_records (record_id TEXT NOT NULL, ordinal INTEGER NOT NULL, source_dataset_id TEXT NOT NULL, source_artifact TEXT NOT NULL, source_db TEXT NOT NULL, source_table TEXT NOT NULL, source_rowid INTEGER NOT NULL, source_field TEXT, source_record_key TEXT, source_file TEXT, source_label TEXT);
             CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
             INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);",
        )
        .unwrap();
        let insert = "INSERT INTO FileSystemEntries (record_id, host_id, dataset_id, timestamp, overview_name, timestamp_kind, path, file_name, extension, is_directory, in_use, file_size, data, volume_id, volume_label, entry, seq, parent_entry, parent_seq, parent_status, path_status, data_status, account, account_sid, input_name, source_relative, si_modified) \
             VALUES (?1, 'h', 'd', ?2, 'FileSystemEntries', CASE WHEN ?2 IS NULL THEN NULL ELSE 'SI 수정 시각' END, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, CASE WHEN ?10 = 'v1' THEN 'SYSTEM' END, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, '$MFT', 'C/' || ?10 || '/$MFT', ?2)";
        type Fixture<'a> = (&'a str, Option<&'a str>, &'a str, &'a str, Option<&'a str>, i64, i64, Option<i64>, Option<Vec<u8>>, &'a str, i64, i64, i64, i64, &'a str, &'a str, &'a str, Option<&'a str>, Option<&'a str>);
        // Root, resident file, directory, file on another volume, unknown
        // parent, empty resident file, reused parent (sequence mismatch).
        let rows: Vec<Fixture> = vec![
            ("r1", None, "\\", ".", None, 1, 1, Some(0), None, "v1", 5, 5, 5, 5, "root", "complete", "not_applicable", None, None),
            ("r2", Some("2026-01-02 00:00:00.000"), "\\a.txt", "a.txt", Some("txt"), 0, 1, Some(3), Some(b"abc".to_vec()), "v1", 10, 1, 5, 5, "verified", "complete", "resident", None, None),
            ("r3", Some("2026-01-01 00:00:00.000"), "\\dir", "dir", None, 1, 1, Some(0), None, "v1", 11, 1, 5, 5, "verified", "complete", "not_applicable", None, None),
            ("r4", None, "\\other.txt", "other.txt", Some("TXT"), 0, 1, Some(7), None, "v2", 10, 1, 5, 5, "verified", "complete", "nonresident", None, None),
            ("r5", None, "orphan.bin", "orphan.bin", Some("bin"), 0, 0, None, None, "v1", 12, 1, 99, 1, "unknown", "unknown", "unavailable", None, None),
            ("r6", Some("2026-01-03 00:00:00.000"), "\\empty.txt", "empty.txt", Some("txt"), 0, 1, Some(0), Some(Vec::new()), "v1", 13, 1, 5, 5, "verified", "complete", "resident_empty", None, None),
            ("r7", None, "\\stale.log", "stale.log", Some("log"), 0, 0, Some(9), None, "v1", 14, 2, 5, 4, "sequence_mismatch", "sequence_mismatch", "nonresident", Some("alice"), Some("S-1-5-21-1-2-3-1001")),
        ];
        for (record_id, timestamp, path_value, name, extension, is_dir, in_use, size, data, volume, entry, seq, parent, parent_seq, parent_status, path_status, data_status, account, sid) in rows {
            conn.execute(
                insert,
                rusqlite::params![
                    record_id, timestamp, path_value, name, extension, is_dir, in_use, size, data, volume,
                    entry, seq, parent, parent_seq, parent_status, path_status, data_status, account, sid
                ],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO source_records VALUES ('r2', 0, 'd0', 'MFT', '_OVERVIEW/MFT_Records.sqlite', 'MFT_Records', 2, NULL, NULL, 'C:\\$MFT', NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO source_records VALUES ('r2', 1, 'd0', 'MFT', '../outside.sqlite', 'MFT_Records', 9, NULL, NULL, NULL, NULL)",
            [],
        )
        .unwrap();
        path
    }

    fn row_names(rows: &[Map<String, Value>]) -> Vec<String> {
        rows.iter()
            .map(|row| {
                row.get("file_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn contract_db_publishes_only_its_primary_table() {
        let root = temp_root("tables");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let db = write_file_system_entries(&overview);
        let conn = open_ro(&db.to_string_lossy()).unwrap();
        // source_records and the version table never appear as separate entries
        // in listing, search or the timeline.
        assert_eq!(visible_table_names(&conn, &db), vec!["FileSystemEntries"]);
        assert_eq!(
            first_table(&conn, &db).as_deref(),
            Some("FileSystemEntries")
        );
        assert_eq!(overview_contract_version(&conn), Some(1));

        let mut listed = Vec::new();
        find_result_files(&overview, &overview, &mut listed);
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.table_name.as_str())
                .collect::<Vec<_>>(),
            vec!["FileSystemEntries"]
        );
        assert!(listed[0].derived);
        // Raw facts stored under _OVERVIEW (no derived version) are listed as raw.
        Connection::open(overview.join("MFT_Records.sqlite"))
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE MFT_Records (volume_id TEXT, path TEXT); CREATE TABLE _wina_facts_generation (id TEXT); {}",
                (0..400).map(|i| format!("INSERT INTO MFT_Records VALUES ('v1', '\\\\file{i}.txt');")).collect::<String>()
            ))
            .unwrap();
        let mut listed = Vec::new();
        find_result_files(&overview, &overview, &mut listed);
        let facts = listed.iter().find(|entry| entry.table_name == "MFT_Records").expect("raw facts listed");
        assert!(!facts.derived);

        // A generic page response carries no body BLOB.
        let page = read_result_file_page_blocking(
            db.to_string_lossy().to_string(),
            None,
            0,
            10,
        )
        .unwrap();
        assert!(!page.columns.iter().any(|column| column == "data"));
        assert!(page.rows.iter().all(|row| !row.contains_key("data")));

        let status = overview_contract_status_blocking(root.to_string_lossy().to_string());
        assert!(status.contract_ok, "legacy: {:?}", status.legacy_files);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mft_queries_follow_stored_links_filters_and_volume_scope() {
        let root = temp_root("mft");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let db = write_file_system_entries(&overview);
        let full = db.to_string_lossy().to_string();
        let page = |query: &str, options: MftListOptions| mft_records_page_blocking(full.clone(), query.to_string(), 0, 100, options).unwrap();
        let v1 = |options: MftListOptions| MftListOptions { volume_id: Some("v1".into()), ..options };

        // Root folder: seq read from the stored root record; only verified
        // children with the same parent seq. The reused-parent record (same
        // parent number, other seq) is never attached under the folder.
        let children = mft_children_blocking(full.clone(), Some(5), None, Some("v1".into()), 0, 100).unwrap();
        assert_eq!(children.total, 3);
        assert_eq!(row_names(&children.rows), vec!["dir", "a.txt", "empty.txt"]);
        assert!(children.rows.iter().all(|row| !row.contains_key("data")));
        assert_eq!(children.rows[0].get("is_directory").and_then(Value::as_i64), Some(1));
        // A folder seq that does not match links nothing.
        assert_eq!(mft_children_blocking(full.clone(), Some(5), Some(4), Some("v1".into()), 0, 100).unwrap().total, 0);

        // Unlinked bucket: sequence mismatch and unknown parent, never the root.
        let unlinked = mft_children_blocking(full.clone(), None, None, Some("v1".into()), 0, 100).unwrap();
        assert_eq!(row_names(&unlinked.rows), vec!["orphan.bin", "stale.log"]);

        // Kind / in-use / extension filters; NULL time sorts last both ways.
        let files = page("", v1(MftListOptions { sort_key: Some("modified".into()), kind: Some("file".into()), in_use: Some(1), ..Default::default() }));
        assert_eq!(row_names(&files.rows), vec!["a.txt", "empty.txt"]);
        let unused = page("", v1(MftListOptions { in_use: Some(0), ..Default::default() }));
        assert_eq!(row_names(&unused.rows), vec!["stale.log", "orphan.bin"], "NULL-free paths first, by path");
        let dirs = page("", v1(MftListOptions { kind: Some("dir".into()), ..Default::default() }));
        assert_eq!(row_names(&dirs.rows), vec![".", "dir"]);
        let txt = page("", MftListOptions { extension: Some(".TXT".into()), ..Default::default() });
        assert_eq!(txt.total, 3, "extension match is case-insensitive across volumes");
        let descending = page("", v1(MftListOptions { sort_key: Some("modified".into()), sort_desc: Some(true), kind: Some("file".into()), ..Default::default() }));
        assert_eq!(row_names(&descending.rows), vec!["empty.txt", "a.txt", "stale.log", "orphan.bin"], "NULL times last; record_id follows the direction");

        // Period filter uses the chosen time field even when sorting by path.
        let ranged = page("", v1(MftListOptions { time_keys: Some(vec!["modified".into()]), time_start: Some("2026-01-02 00:00:00.000".into()), ..Default::default() }));
        assert_eq!(row_names(&ranged.rows), vec!["a.txt", "empty.txt"]);

        // Analysis filters: several extensions, folder scope (typed drive
        // letter ignored), size range, stored-state flags, SI<FN created.
        let names = |options: MftListOptions| row_names(&page("", v1(options)).rows);
        assert_eq!(names(MftListOptions { extension: Some("TXT, .bin".into()), ..Default::default() }), vec!["a.txt", "empty.txt", "orphan.bin"]);
        assert_eq!(names(MftListOptions { path_prefix: Some("C:\\dir".into()), ..Default::default() }), vec!["dir"]);
        assert!(names(MftListOptions { path_prefix: Some("\\a_txt".into()), ..Default::default() }).is_empty(), "LIKE metacharacters stay literal");
        assert_eq!(names(MftListOptions { size_min: Some(3), size_max: Some(9), ..Default::default() }), vec!["a.txt", "stale.log"]);
        assert_eq!(names(MftListOptions { path_incomplete: Some(true), ..Default::default() }), vec!["stale.log", "orphan.bin"]);
        assert_eq!(names(MftListOptions { resident_only: Some(true), ..Default::default() }), vec!["a.txt"]);
        Connection::open(&db).unwrap().execute_batch(
            "UPDATE FileSystemEntries SET si_created='2020-01-01 00:00:00.000', fn_created='2021-01-01 00:00:00.000' WHERE record_id='r2';
             UPDATE FileSystemEntries SET si_created='2022-01-01 00:00:00.000', fn_created='2021-01-01 00:00:00.000' WHERE record_id='r6';",
        ).unwrap();
        assert_eq!(names(MftListOptions { si_before_fn: Some(true), ..Default::default() }), vec!["a.txt"]);
        // Several time fields: a record matches when ANY of them is in range.
        let window = |keys: &[&str]| names(MftListOptions { time_keys: Some(keys.iter().map(|k| k.to_string()).collect()), time_start: Some("2020-06-01 00:00:00.000".into()), time_end: Some("2021-06-01 00:00:00.000".into()), ..Default::default() });
        assert!(window(&["created"]).is_empty());
        assert_eq!(window(&["created", "fn_created"]), vec!["a.txt", "empty.txt"]);
        assert_eq!(window(&["bogus", "fn_created"]), vec!["a.txt", "empty.txt"], "unknown keys are ignored");
        // Folder scope is the folder itself and its `\` descendants: a
        // same-prefix sibling (`\dir.old`) must not leak in; root is no filter.
        Connection::open(&db).unwrap().execute_batch(
            "CREATE TEMP TABLE extra AS SELECT * FROM FileSystemEntries WHERE record_id = 'r2';
             INSERT INTO extra SELECT * FROM extra;
             UPDATE extra SET record_id = 't1', path = '\\dir\\in.txt', file_name = 'in.txt' WHERE rowid = 1;
             UPDATE extra SET record_id = 't2', path = '\\dir.old\\x.txt', file_name = 'x.txt' WHERE rowid = 2;
             INSERT INTO FileSystemEntries SELECT * FROM extra;",
        ).unwrap();
        assert_eq!(names(MftListOptions { path_prefix: Some("c:/DIR/".into()), ..Default::default() }), vec!["dir", "in.txt"]);
        assert_eq!(names(MftListOptions { path_prefix: Some("\\".into()), ..Default::default() }).len(), names(MftListOptions::default()).len());
        // Excluded folders drop the folder and its descendants, not siblings.
        let excluded = names(MftListOptions { exclude_paths: Some(vec!["C:\\DIR\\".into()]), ..Default::default() });
        assert!(excluded.contains(&"x.txt".to_string()) && !excluded.contains(&"in.txt".to_string()) && !excluded.contains(&"dir".to_string()));
        assert_eq!(excluded.len(), names(MftListOptions::default()).len() - 2);
        Connection::open(&db).unwrap().execute_batch("DELETE FROM FileSystemEntries WHERE record_id IN ('t1', 't2');").unwrap();

        // Search covers extension and account/SID; LIKE metacharacters are literal.
        assert_eq!(row_names(&page("S-1-5-21-1-2-3-1001", MftListOptions::default()).rows), vec!["stale.log"]);
        assert_eq!(row_names(&mft_search_blocking(full.clone(), "alice".into(), None, 50).unwrap()), vec!["stale.log"]);
        assert!(page("a_txt", MftListOptions::default()).rows.is_empty());
        let searched = mft_search_blocking(full.clone(), "txt".into(), Some("v1".into()), 50).unwrap();
        assert_eq!(row_names(&searched), vec!["a.txt", "empty.txt"]);
        assert!(searched.iter().all(|row| !row.contains_key("data")));

        // Volume list keeps input identity; unknown drive stays NULL.
        let volumes = mft_volumes_blocking(full.clone()).unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].get("record_count").and_then(Value::as_i64), Some(6));
        assert_eq!(volumes[0].get("drive_letter"), Some(&Value::Null));
        assert_eq!(volumes[1].get("source_relative").and_then(Value::as_str), Some("C/v2/$MFT"));
        assert_eq!(volumes[1].get("input_name").and_then(Value::as_str), Some("$MFT"));

        // A rowid from another volume context opens nothing.
        let other_volume_rowid = mft_search_blocking(full.clone(), "other".into(), Some("v2".into()), 10).unwrap()[0]
            .get("__rowid")
            .and_then(Value::as_i64)
            .unwrap();
        assert!(mft_row(full.clone(), other_volume_rowid, Some("v1".into())).is_none());
        assert!(mft_row(full, other_volume_rowid, Some("v2".into())).is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    /// docs-05 stored groups: two inputs; a create group, a rename group
    /// (paired OLD/NEW + CLOSE), a delete group sharing the rename's first
    /// time, and a same-name record in another input.
    fn write_usn_journal(overview: &Path) -> PathBuf {
        let path = overview.join("UsnJournal.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE UsnJournal (record_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, timestamp TEXT, overview_name TEXT, account TEXT, account_sid TEXT, timestamp_kind TEXT, event_type TEXT, description TEXT, file_name TEXT, path TEXT, volume_id TEXT, journal_id TEXT, usn TEXT, record_version INTEGER, file_reference TEXT, parent_reference TEXT, reason_mask TEXT, reason TEXT, source_info TEXT, security_id INTEGER, file_attributes TEXT, input_id TEXT, input_name TEXT, source_file TEXT, source_relative TEXT, record_offset TEXT, input_sequence INTEGER, usn_sort TEXT, file_reference_sort TEXT, parent_reference_sort TEXT, group_id TEXT, group_ordinal INTEGER, rename_role TEXT);
             CREATE TABLE UsnChangeGroups (group_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, input_id TEXT, input_name TEXT, source_file TEXT, source_relative TEXT, record_version INTEGER, file_reference TEXT, file_reference_sort TEXT, first_parent_reference TEXT, last_parent_reference TEXT, first_file_name TEXT, last_file_name TEXT, distinct_file_name_count INTEGER, first_timestamp TEXT, last_timestamp TEXT, first_usn TEXT, first_usn_sort TEXT, last_usn TEXT, last_usn_sort TEXT, first_input_sequence INTEGER, last_input_sequence INTEGER, member_count INTEGER, event_type TEXT, reason_union_mask TEXT, reason_union TEXT, unknown_reason_mask TEXT, has_unknown_reason INTEGER, group_scope TEXT, grouping_basis TEXT, boundary_reason TEXT, close_observed INTEGER, is_display_summary INTEGER, operation_confirmed INTEGER);
             CREATE TABLE UsnReasonFlags (record_id TEXT, ordinal INTEGER, group_id TEXT, reason_flag TEXT, flag_bit TEXT, is_unknown INTEGER);
             CREATE TABLE UsnGroupMembers (group_id TEXT, ordinal INTEGER, record_id TEXT, input_id TEXT, input_sequence INTEGER, record_offset TEXT, timestamp TEXT, file_name TEXT, event_type TEXT, reason TEXT, reason_mask TEXT, usn TEXT, usn_sort TEXT);
             CREATE TABLE UsnRenameEvents (rename_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, input_id TEXT, input_name TEXT, record_version INTEGER, file_reference TEXT, file_reference_sort TEXT, status TEXT, ambiguity_reason TEXT, matching_basis TEXT, old_record_id TEXT, new_record_id TEXT, old_group_id TEXT, new_group_id TEXT, old_file_name TEXT, new_file_name TEXT, old_usn TEXT, old_usn_sort TEXT, new_usn TEXT, new_usn_sort TEXT, old_timestamp TEXT, new_timestamp TEXT, old_candidate_count INTEGER, new_candidate_count INTEGER);
             CREATE TABLE UsnRenameCandidates (rename_id TEXT, ordinal INTEGER, record_id TEXT, group_id TEXT, role TEXT, file_name TEXT, usn TEXT, usn_sort TEXT, timestamp TEXT, record_offset TEXT, input_sequence INTEGER, reason_mask TEXT);
             CREATE TABLE source_records (record_id TEXT NOT NULL, ordinal INTEGER NOT NULL, source_dataset_id TEXT NOT NULL, source_artifact TEXT NOT NULL, source_db TEXT NOT NULL, source_table TEXT NOT NULL, source_rowid INTEGER NOT NULL, source_field TEXT, source_record_key TEXT, source_file TEXT, source_label TEXT);",
        )
        .unwrap();
        // (group, input, first/last time, first usn_sort, event type, members)
        // member: (record, time, name, reasons, rename role)
        type Member<'a> = (&'a str, &'a str, &'a str, &'a [&'a str], Option<&'a str>);
        let groups: Vec<(&str, &str, &str, &str, &str, &str, Vec<Member>)> = vec![
            ("g1", "usn-1", "2026-01-01 10:00:00.000", "2026-01-01 10:01:00.000", "10100", "생성", vec![
                ("m1", "2026-01-01 10:00:00.000", "a.txt", &["FILE_CREATE"], None),
                ("m2", "2026-01-01 10:01:00.000", "a.txt", &["DATA_EXTEND", "CLOSE"], None),
            ]),
            ("g2", "usn-1", "2026-01-01 10:05:00.000", "2026-01-01 10:05:01.000", "10200", "이름 변경(이전 이름)", vec![
                ("m3", "2026-01-01 10:05:00.000", "old.doc", &["RENAME_OLD_NAME"], Some("old")),
                ("m4", "2026-01-01 10:05:00.500", "new.doc", &["RENAME_NEW_NAME"], Some("new")),
                ("m5", "2026-01-01 10:05:01.000", "new.doc", &["RENAME_NEW_NAME", "CLOSE"], None),
            ]),
            ("g3", "usn-1", "2026-01-01 10:05:00.000", "2026-01-01 10:05:00.000", "10300", "삭제", vec![
                ("m6", "2026-01-01 10:05:00.000", "x.log", &["FILE_DELETE", "CLOSE"], None),
            ]),
            ("g4", "usn-2", "2026-01-01 10:00:00.000", "2026-01-01 10:00:00.000", "10100", "생성", vec![
                ("m7", "2026-01-01 10:00:00.000", "a.txt", &["FILE_CREATE", "CLOSE"], None),
            ]),
            // usn-3: an ambiguous rename (two OLD names under different
            // parents) and an OLD name whose NEW was never seen.
            ("g5", "usn-3", "2026-01-02 09:00:00.000", "2026-01-02 09:00:02.000", "10500", "이름 변경(이전 이름)", vec![
                ("m8", "2026-01-02 09:00:00.000", "a1.txt", &["RENAME_OLD_NAME"], Some("old")),
                ("m9", "2026-01-02 09:00:01.000", "a2.txt", &["RENAME_OLD_NAME"], Some("old")),
                ("m10", "2026-01-02 09:00:02.000", "b.txt", &["RENAME_NEW_NAME", "CLOSE"], Some("new")),
            ]),
            ("g6", "usn-3", "2026-01-02 09:10:00.000", "2026-01-02 09:10:00.000", "10600", "이름 변경(이전 이름)", vec![
                ("m11", "2026-01-02 09:10:00.000", "gone.tmp", &["RENAME_OLD_NAME"], Some("old")),
            ]),
        ];
        for (group, input, first, last, usn_sort, event_type, members) in &groups {
            let reason_union = members.iter().flat_map(|m| m.3.iter().copied()).collect::<Vec<_>>().join("|");
            conn.execute(
                "INSERT INTO UsnChangeGroups (group_id, host_id, dataset_id, input_id, input_name, source_relative, first_file_name, last_file_name, first_timestamp, last_timestamp, first_usn_sort, member_count, event_type, reason_union, grouping_basis, boundary_reason, close_observed, is_display_summary, operation_confirmed)
                 VALUES (?1, 'h', 'd', ?2, '$J', 'C/' || ?2 || '/$J', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'close_delimited_observations', 'close_flag', 1, 1, 0)",
                rusqlite::params![group, input, members[0].2, members[members.len() - 1].2, first, last, usn_sort, members.len() as i64, event_type, reason_union],
            )
            .unwrap();
            for (ordinal, (record, time, name, reasons, role)) in members.iter().enumerate() {
                conn.execute(
                    "INSERT INTO UsnJournal (record_id, host_id, dataset_id, timestamp, overview_name, timestamp_kind, file_name, usn, usn_sort, reason, input_id, input_name, group_id, group_ordinal, rename_role, file_reference)
                     VALUES (?1, 'h', 'd', ?2, 'UsnJournal', '변경 기록 시각', ?3, '1844674407370955161' || ?7, '20' || ?4 || ?7, ?5, ?6, '$J', ?8, ?7, ?9, '281474976710656')",
                    rusqlite::params![record, time, name, usn_sort, reasons.join("|"), input, ordinal as i64, group, role],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO UsnGroupMembers (group_id, ordinal, record_id, input_id, timestamp, file_name, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![group, ordinal as i64, record, input, time, name, reasons.join("|")],
                )
                .unwrap();
                for (flag_ordinal, flag) in reasons.iter().enumerate() {
                    conn.execute(
                        "INSERT INTO UsnReasonFlags VALUES (?1, ?2, ?3, ?4, '0x1', 0)",
                        rusqlite::params![record, flag_ordinal as i64, group, flag],
                    )
                    .unwrap();
                }
            }
        }
        conn.execute_batch(
            "INSERT INTO UsnRenameEvents (rename_id, host_id, dataset_id, input_id, status, ambiguity_reason, matching_basis, old_record_id, new_record_id, old_group_id, new_group_id, old_file_name, new_file_name, old_candidate_count, new_candidate_count) VALUES
               ('rn1', 'h', 'd', 'usn-1', 'paired', NULL, 'same_group_usn_order', 'm3', 'm4', 'g2', 'g2', 'old.doc', 'new.doc', 1, 2),
               ('rn2', 'h', 'd', 'usn-3', 'ambiguous', 'multiple_old_names|multiple_old_parents', 'same_group_usn_order', NULL, 'm10', 'g5', 'g5', NULL, 'b.txt', 2, 1),
               ('rn3', 'h', 'd', 'usn-3', 'missing_new', NULL, 'same_group_usn_order', 'm11', NULL, 'g6', NULL, 'gone.tmp', NULL, 1, 0);
             INSERT INTO UsnRenameCandidates (rename_id, ordinal, record_id, group_id, role, file_name, usn, timestamp, record_offset) VALUES
               ('rn1', 0, 'm3', 'g2', 'old', 'old.doc', '1', '2026-01-01 10:05:00.000', '100'),
               ('rn1', 1, 'm4', 'g2', 'new', 'new.doc', '2', '2026-01-01 10:05:00.500', '200'),
               ('rn1', 2, 'm5', 'g2', 'new', 'new.doc', '3', '2026-01-01 10:05:01.000', '300'),
               ('rn2', 0, 'm8', 'g5', 'old', 'a1.txt', '8', '2026-01-02 09:00:00.000', '800'),
               ('rn2', 1, 'm9', 'g5', 'old', 'a2.txt', '9', '2026-01-02 09:00:01.000', '900'),
               ('rn2', 2, 'm10', 'g5', 'new', 'b.txt', '10', '2026-01-02 09:00:02.000', '1000'),
               ('rn3', 0, 'm11', 'g6', 'old', 'gone.tmp', '11', '2026-01-02 09:10:00.000', '1100');
             UPDATE UsnJournal SET parent_reference = CASE record_id WHEN 'm8' THEN '1407374883553285' WHEN 'm9' THEN '1688849860263941' ELSE '1407374883553285' END;
             INSERT INTO source_records VALUES ('m6', 0, 'd0', 'UsnJrnl', 'FILESYSTEM/UsnJrnl_Records.sqlite', 'UsnJrnl_Records', 6, NULL, NULL, NULL, NULL);",
        )
        .unwrap();
        path
    }

    #[test]
    fn usn_groups_come_from_stored_groups_with_every_member() {
        let root = temp_root("usn");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let full = write_usn_journal(&overview).to_string_lossy().to_string();
        let page = |options: UsnGroupOptions, offset: i64, limit: i64| usn_groups_page_blocking(full.clone(), options, offset, limit).unwrap();
        let one = |options: UsnGroupOptions| UsnGroupOptions { input_id: Some("usn-1".into()), ..options };
        let ids = |result: &UsnGroupsPage| result.groups.iter().map(|g| g.group.get("group_id").and_then(Value::as_str).unwrap_or_default().to_string()).collect::<Vec<_>>();
        let members_of = |entry: &UsnGroupEntry| entry.members.iter().map(|m| (m.get("record_id").and_then(Value::as_str).unwrap_or_default().to_string(), m.get("__matched").and_then(Value::as_bool).unwrap_or(false))).collect::<Vec<_>>();

        // Inputs stay apart; options are counted per input.
        let overview_all = usn_overview_blocking(full.clone(), Some("usn-1".into())).unwrap();
        assert_eq!(overview_all.inputs.iter().map(|i| (i.input_id.clone(), i.record_count, i.group_count)).collect::<Vec<_>>(), vec![("usn-1".to_string(), 6, 3), ("usn-2".to_string(), 1, 1), ("usn-3".to_string(), 4, 2)]);
        assert_eq!(overview_all.event_types.iter().find(|o| o.value == "생성").map(|o| o.count), Some(1));
        assert_eq!(overview_all.reason_flags.iter().find(|o| o.value == "CLOSE").map(|o| o.count), Some(3));

        // Time order, then first USN; the other input never leaks in.
        let all = page(one(UsnGroupOptions::default()), 0, 10);
        assert_eq!((ids(&all), all.total), (vec!["g1".to_string(), "g2".into(), "g3".into()], 3));
        let desc = page(one(UsnGroupOptions { descending: Some(true), ..Default::default() }), 0, 10);
        assert_eq!(ids(&desc), vec!["g3", "g2", "g1"]);
        let second = page(one(UsnGroupOptions::default()), 1, 1);
        assert_eq!((ids(&second), second.total), (vec!["g2".to_string()], 3));

        // Every member in stored order, rename linked from the stored event.
        let g2 = &all.groups[1];
        assert_eq!(members_of(g2).iter().map(|m| m.0.as_str()).collect::<Vec<_>>(), vec!["m3", "m4", "m5"]);
        assert_eq!(g2.renames.len(), 1);
        assert_eq!(g2.renames[0].event.get("old_file_name").and_then(Value::as_str), Some("old.doc"));
        assert_eq!(g2.renames[0].event.get("status").and_then(Value::as_str), Some("paired"));
        // Every stored candidate, CLOSE's accumulated NEW included.
        let names = |rename: &UsnRenameEntry| rename.candidates.iter().map(|c| format!("{}:{}", c.get("role").and_then(Value::as_str).unwrap_or(""), c.get("file_name").and_then(Value::as_str).unwrap_or(""))).collect::<Vec<_>>();
        assert_eq!(names(&g2.renames[0]), vec!["old:old.doc", "new:new.doc", "new:new.doc"]);
        assert!(g2.members[0].get("__rowid").is_some(), "members carry their row for detail/bookmark");
        // USN text keeps full precision (no numeric conversion).
        assert_eq!(g2.members[0].get("usn").and_then(Value::as_str), Some("18446744073709551610"));

        // A search on the new name keeps the whole group and marks matches.
        let renamed = page(one(UsnGroupOptions { search: Some("NEW.doc".into()), ..Default::default() }), 0, 10);
        assert_eq!(ids(&renamed), vec!["g2"]);
        assert_eq!(members_of(&renamed.groups[0]), vec![("m3".to_string(), false), ("m4".to_string(), true), ("m5".to_string(), true)]);
        // Search covers stored reasons; LIKE metacharacters are literal.
        assert_eq!(ids(&page(one(UsnGroupOptions { search: Some("file_delete".into()), ..Default::default() }), 0, 10)), vec!["g3"]);
        assert!(page(one(UsnGroupOptions { search: Some("a_txt".into()), ..Default::default() }), 0, 10).groups.is_empty());

        // Reason flags (any of them) differ from the representative type: g1 is
        // "생성" yet holds DATA_EXTEND.
        assert_eq!(ids(&page(one(UsnGroupOptions { reason_flags: Some(vec!["DATA_EXTEND".into(), "FILE_DELETE".into()]), ..Default::default() }), 0, 10)), vec!["g1", "g3"]);
        assert_eq!(ids(&page(one(UsnGroupOptions { event_type: Some("생성".into()), ..Default::default() }), 0, 10)), vec!["g1"]);
        assert!(page(one(UsnGroupOptions { event_type: Some("내용 변경".into()), reason_flags: Some(vec!["DATA_EXTEND".into()]), ..Default::default() }), 0, 10).groups.is_empty());

        // Period is checked on members: g1 spans 10:00–10:01 but none of its
        // members lies in 10:00:30–10:04.
        let window = page(one(UsnGroupOptions { time_start: Some("2026-01-01 10:00:30.000".into()), time_end: Some("2026-01-01 10:04:00.000".into()), ..Default::default() }), 0, 10);
        assert_eq!(ids(&window), vec!["g1"]);
        assert_eq!(members_of(&window.groups[0]), vec![("m1".to_string(), false), ("m2".to_string(), true)]);
        // One member must satisfy all member conditions together.
        assert!(page(one(UsnGroupOptions { search: Some("old.doc".into()), reason_flags: Some(vec!["CLOSE".into()]), ..Default::default() }), 0, 10).groups.is_empty());

        // Ambiguous and missing renames carry every candidate with the
        // parent reference read from the linked journal record.
        let three = page(UsnGroupOptions { input_id: Some("usn-3".into()), ..Default::default() }, 0, 10);
        assert_eq!(ids(&three), vec!["g5", "g6"]);
        let ambiguous = &three.groups[0].renames[0];
        assert_eq!(ambiguous.event.get("status").and_then(Value::as_str), Some("ambiguous"));
        assert_eq!(names(ambiguous), vec!["old:a1.txt", "old:a2.txt", "new:b.txt"]);
        let parents = ambiguous.candidates.iter().map(|c| c.get("parent_reference").and_then(Value::as_str).unwrap_or("").to_string()).collect::<Vec<_>>();
        assert_eq!(parents, vec!["1407374883553285", "1688849860263941", "1407374883553285"]);
        assert!(ambiguous.candidates.iter().all(|c| c.get("__rowid").is_some()), "candidates open their journal record");
        let missing = &three.groups[1].renames[0];
        assert_eq!(missing.event.get("status").and_then(Value::as_str), Some("missing_new"));
        assert_eq!(names(missing), vec!["old:gone.tmp"]);
        let _ = std::fs::remove_dir_all(root);
    }

    /// docs-06 RegistryExplorer: SOFTWARE and its RegBack copy (same paths),
    /// a hive that was not parsed, a sibling key sharing a name prefix, an
    /// empty key, an unresolved-parent key and values of several kinds.
    fn write_registry_explorer(overview: &Path) -> PathBuf {
        let path = overview.join("RegistryExplorer.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE RegistryHives (hive_id TEXT PRIMARY KEY, ordinal INTEGER, host_id TEXT, dataset_id TEXT, hive_name TEXT, source_file TEXT, facts_db TEXT, facts_dataset_id TEXT, inventory_source TEXT, input_status TEXT, load_status TEXT, load_error TEXT, input_error TEXT, facts_row_count INTEGER, logs_discovered INTEGER, logs_applied INTEGER, log_error TEXT, is_regback INTEGER, key_count INTEGER, value_count INTEGER, root_count INTEGER);
             CREATE TABLE RegistryExplorer (record_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, hive_id TEXT, entry_kind TEXT, key_record_id TEXT, parent_record_id TEXT, parent_status TEXT, key_offset TEXT, parent_key_offset TEXT, key_name TEXT, key_path TEXT, key_path_lower TEXT, key_depth INTEGER, key_last_write TEXT, key_subkey_count INTEGER, key_value_count INTEGER, stored_subkey_count INTEGER, stored_value_count INTEGER, key_read_status TEXT, key_read_error TEXT, value_offset TEXT, value_name TEXT, value_name_lower TEXT, value_is_default INTEGER, value_display_name TEXT, value_type_code INTEGER, value_type_code_raw TEXT, value_type_name TEXT, value_data BLOB, value_data_hex TEXT, value_data_length INTEGER, value_data_text TEXT, value_read_status TEXT, value_read_error TEXT, recovery TEXT, source_rowid INTEGER);
             CREATE TABLE RegistryQuickTargets (finding_record_id TEXT, ordinal INTEGER, resolution TEXT, basis TEXT, target_record_id TEXT, target_kind TEXT, target_key_path TEXT, hive_id TEXT, finding_source_db TEXT, finding_source_rowid INTEGER, finding_hive_name TEXT, finding_key_path TEXT, candidate_count INTEGER);
             CREATE TABLE source_records (record_id TEXT NOT NULL, ordinal INTEGER NOT NULL, source_dataset_id TEXT NOT NULL, source_artifact TEXT NOT NULL, source_db TEXT NOT NULL, source_table TEXT NOT NULL, source_rowid INTEGER NOT NULL, source_field TEXT, source_record_key TEXT, source_file TEXT, source_label TEXT);
             INSERT INTO RegistryHives VALUES
               ('h0', 0, 'h', 'd', 'SOFTWARE', 'C/config/SOFTWARE', 'REGISTRY/SOFTWARE.sqlite', 'f', 'manifest', 'completed', 'loaded', NULL, NULL, 10, 2, 2, NULL, 0, 6, 6, 1),
               ('h1', 1, 'h', 'd', 'SOFTWARE', 'C/config/RegBack/SOFTWARE', 'REGISTRY/SOFTWARE_RegBack.sqlite', 'f', 'manifest', 'completed', 'loaded', NULL, NULL, 4, 0, 0, NULL, 1, 3, 1, 1),
               ('h2', 2, 'h', 'd', 'NTUSER.DAT', 'C/Users/x/NTUSER.DAT', NULL, NULL, 'manifest', 'failed', 'not_parsed', NULL, 'bad header', NULL, NULL, NULL, NULL, 0, 0, 0, 0);",
        )
        .unwrap();
        let key = |id: &str, hive: &str, parent: Option<&str>, status: &str, name: &str, path_value: &str, depth: i64, subkeys: i64, values: i64| {
            conn.execute(
                "INSERT INTO RegistryExplorer (record_id, host_id, dataset_id, hive_id, entry_kind, parent_record_id, parent_status, key_offset, key_name, key_path, key_path_lower, key_depth, key_last_write, key_subkey_count, key_value_count, stored_subkey_count, stored_value_count, key_read_status, recovery, source_rowid)
                 VALUES (?1, 'h', 'd', ?2, 'key', ?3, ?4, '4096', ?5, ?6, lower(?6), ?7, '2026-04-27 13:10:15.030', ?8, ?9, ?8, ?9, 'ok', 'live', 1)",
                rusqlite::params![id, hive, parent, status, name, path_value, depth, subkeys, values],
            )
            .unwrap();
        };
        let value = |id: &str, hive: &str, key_id: &str, name: &str, type_name: &str, hex: &str, text: Option<&str>, status: &str, source: i64| {
            conn.execute(
                "INSERT INTO RegistryExplorer (record_id, host_id, dataset_id, hive_id, entry_kind, key_record_id, value_name, value_name_lower, value_is_default, value_display_name, value_type_name, value_data_hex, value_data_length, value_data_text, value_read_status, recovery, source_rowid)
                 VALUES (?1, 'h', 'd', ?2, 'value', ?3, ?4, lower(?4), ?4 = '', CASE WHEN ?4 = '' THEN '(default)' ELSE ?4 END, ?5, ?6, length(?6) / 2, ?7, ?8, 'live', ?9)",
                rusqlite::params![id, hive, key_id, name, type_name, hex, text, status, source],
            )
            .unwrap();
        };
        key("h0:k:1", "h0", None, "root", "ROOT", "\\ROOT", 0, 2, 0);
        key("h0:k:2", "h0", Some("h0:k:1"), "linked", "Microsoft", "\\ROOT\\Microsoft", 1, 2, 0);
        key("h0:k:3", "h0", Some("h0:k:2"), "linked", "Run", "\\ROOT\\Microsoft\\Run", 2, 0, 5);
        key("h0:k:4", "h0", Some("h0:k:2"), "linked", "Run_old", "\\ROOT\\Microsoft\\Run_old", 2, 0, 1);
        key("h0:k:5", "h0", Some("h0:k:1"), "linked", "Empty", "\\ROOT\\Empty", 1, 0, 0);
        key("h0:k:6", "h0", None, "unresolved", "Lost", "\\ROOT\\Lost", 1, 0, 0);
        value("h0:v:1", "h0", "h0:k:3", "", "REG_SZ", "43003a005c006500760069006c002e00650078006500", Some("C:\\evil.exe"), "ok", 1);
        value("h0:v:2", "h0", "h0:k:3", "Updater", "REG_SZ", "43003a00", Some("C:\\tools\\updater.exe -s"), "ok", 2);
        value("h0:v:3", "h0", "h0:k:4", "Legacy", "REG_SZ", "43003a00", Some("C:\\evil.exe"), "ok", 3);
        value("h0:v:4", "h0", "h0:k:3", "Blob", "REG_BINARY", "4d5a9000", None, "ok", 4);
        value("h0:v:5", "h0", "h0:k:3", "Odd", "REG_BINARY", "04d5a900", None, "ok", 5);
        value("h0:v:6", "h0", "h0:k:3", "Nothing", "REG_NONE", "", None, "empty", 6);
        key("h1:k:1", "h1", None, "root", "ROOT", "\\ROOT", 0, 1, 0);
        key("h1:k:2", "h1", Some("h1:k:1"), "linked", "Microsoft", "\\ROOT\\Microsoft", 1, 1, 0);
        key("h1:k:3", "h1", Some("h1:k:2"), "linked", "Run", "\\ROOT\\Microsoft\\Run", 2, 0, 1);
        value("h1:v:1", "h1", "h1:k:3", "Updater", "REG_SZ", "43003a00", Some("C:\\tools\\updater.exe -s"), "ok", 1);
        conn.execute_batch(
            "INSERT INTO RegistryQuickTargets VALUES
               ('f1', 0, 'exact_value', 'source_records', 'h0:v:2', 'value', NULL, 'h0', 'REGISTRY/SOFTWARE.sqlite', 2, 'SOFTWARE', '\\ROOT\\Microsoft\\Run', 1),
               ('f2', 0, 'parent_key', 'key_path', 'h0:k:3', 'key', '\\ROOT\\Microsoft\\Run', 'h0', NULL, NULL, 'SOFTWARE', '\\ROOT\\Microsoft\\Run', 1),
               ('f3', 0, 'missing_hive', 'key_path', NULL, NULL, NULL, NULL, NULL, NULL, 'NTUSER.DAT', '\\ROOT\\Software\\RunMRU', 0);
             INSERT INTO source_records VALUES ('h0:v:2', 0, 'f', 'Registry', 'REGISTRY/SOFTWARE.sqlite', 'Registry', 2, 'value', NULL, NULL, NULL);",
        )
        .unwrap();
        let findings = Connection::open(overview.join("RegistryFindings.sqlite")).unwrap();
        findings
            .execute_batch(
                "CREATE TABLE RegistryFindings (record_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, timestamp TEXT, overview_name TEXT, account TEXT, account_sid TEXT, timestamp_kind TEXT, event_type TEXT, description TEXT, category TEXT, name TEXT, value TEXT, value_type TEXT, status TEXT, detail TEXT, key_path TEXT, source TEXT, command TEXT, command_resolved TEXT, subtype TEXT, properties TEXT);
                 INSERT INTO RegistryFindings (record_id, host_id, dataset_id, timestamp, overview_name, timestamp_kind, category, name, value, status, detail, key_path, source, subtype) VALUES
                   ('f1', 'h', 'd', '2026-04-27 13:10:15.030', 'RegistryFindings', '키 기록 시각', '자동 실행', 'Updater', 'C:\\tools\\updater.exe -s', '주의', 'parser note', '\\ROOT\\Microsoft\\Run', 'SOFTWARE', NULL),
                   ('f2', 'h', 'd', NULL, 'RegistryFindings', NULL, '자격 증명 보호', 'UseLogonCredential', '미설정', '정보', 'parser note', '\\ROOT\\Microsoft\\Run', 'SOFTWARE', NULL),
                   ('f3', 'h', 'd', NULL, 'RegistryFindings', NULL, '기타 레지스트리', 'a', 'cmd.exe', '정보', 'parser note', '\\ROOT\\Software\\RunMRU', 'NTUSER.DAT', 'RunMRU');",
            )
            .unwrap();
        path
    }

    #[test]
    fn registry_explorer_reads_every_hive_key_and_value_from_overview() {
        let root = temp_root("registry");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let full = write_registry_explorer(&overview).to_string_lossy().to_string();
        let text = |row: &Map<String, Value>, key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default().to_string();

        // Every stored hive in order, RegBack and unparsed inputs included.
        let hives = registry_hives_blocking(full.clone()).unwrap();
        assert_eq!(hives.iter().map(|h| (h.hive_id.as_str(), h.is_regback, h.load_status.as_str())).collect::<Vec<_>>(), vec![("h0", false, "loaded"), ("h1", true, "loaded"), ("h2", false, "not_parsed")]);
        assert_eq!(hives[0].unresolved_count, 1);

        // Roots, ordered children with paging, empty keys, unresolved bucket.
        let names = |page: &RegistryRowsPage| page.rows.iter().map(|r| text(r, "key_name")).collect::<Vec<_>>();
        let roots = registry_keys_blocking(full.clone(), "h0".into(), None, false, 0, 100).unwrap();
        assert_eq!((names(&roots), roots.total), (vec!["ROOT".to_string()], 1));
        let children = registry_keys_blocking(full.clone(), "h0".into(), Some("h0:k:1".into()), false, 0, 100).unwrap();
        assert_eq!(names(&children), vec!["Empty", "Microsoft"]);
        let second = registry_keys_blocking(full.clone(), "h0".into(), Some("h0:k:1".into()), false, 1, 1).unwrap();
        assert_eq!((names(&second), second.total), (vec!["Microsoft".to_string()], 2));
        assert!(children.rows[0].get("__rowid").is_some());
        let lost = registry_keys_blocking(full.clone(), "h0".into(), None, true, 0, 100).unwrap();
        assert_eq!(names(&lost), vec!["Lost"]);

        // Values: default first, then by name; empty data stays distinct.
        let values = registry_values_blocking(full.clone(), "h0:k:3".into(), 0, 100).unwrap();
        assert_eq!(values.total, 5);
        assert_eq!(values.rows.iter().map(|v| text(v, "value_name")).collect::<Vec<_>>(), vec!["", "Blob", "Nothing", "Odd", "Updater"]);
        assert_eq!(text(&values.rows[2], "value_read_status"), "empty");
        assert_eq!(text(&values.rows[0], "value_preview"), "C:\\evil.exe");

        // A value's detail carries its key and the ancestor chain with the
        // position of each step among its siblings (to reveal it in the tree).
        let entry = registry_entry_blocking(full.clone(), "h0:v:2".into(), REGISTRY_ENTRY_TEXT_CAP).unwrap();
        assert_eq!(text(&entry.key, "record_id"), "h0:k:3");
        assert_eq!(entry.ancestors.iter().map(|a| (a.key_name.as_deref().unwrap_or(""), a.position)).collect::<Vec<_>>(), vec![("ROOT", 0), ("Microsoft", 1), ("Run", 0)]);
        assert_eq!(text(&entry.entry, "value_data_text"), "C:\\tools\\updater.exe -s");

        // Search: whole store by rowid cursor; hives stay apart.
        let search = |query: &str, options: RegistrySearchOptions| {
            let mut hits = Vec::new();
            let mut cursor = None;
            loop {
                let page = registry_search_blocking(full.clone(), RegistrySearchOptions { query: query.into(), ..options.clone() }, cursor, 1, 1_000_000).unwrap();
                hits.extend(page.hits.into_iter().map(|h| (h.record_id, h.fields.join(","))));
                match page.next_cursor { Some(next) => cursor = Some(next), None => break }
            }
            hits
        };
        let all = RegistrySearchOptions::default();
        assert_eq!(search("EVIL.exe", all.clone()), vec![("h0:v:1".to_string(), "value_data".to_string()), ("h0:v:3".into(), "value_data".into())]);
        assert_eq!(search("updater", all.clone()).iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["h0:v:2", "h1:v:1"]);
        assert_eq!(search("updater", RegistrySearchOptions { hive_id: Some("h1".into()), ..all.clone() }).iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["h1:v:1"]);
        // Subtree of Run: its own value only, never the Run_old sibling.
        assert_eq!(search("evil", RegistrySearchOptions { hive_id: Some("h0".into()), key_record_id: Some("h0:k:3".into()), ..all.clone() }).iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), vec!["h0:v:1"]);
        // Field selection: key paths only.
        let keys_only = RegistrySearchOptions { hive_id: Some("h0".into()), value_names: Some(false), value_data: Some(false), ..all.clone() };
        assert_eq!(search("run", keys_only), vec![("h0:k:3".to_string(), "key".to_string()), ("h0:k:4".into(), "key".into())]);
        // Hex matches on byte boundaries only (Odd holds 4d5a90 at nibble 1).
        assert_eq!(search("4D 5A 90", all.clone()), vec![("h0:v:4".to_string(), "value_hex".to_string())]);
        assert!(search("evil_exe", all.clone()).is_empty(), "LIKE metacharacters are literal");
        // A hit reports where it lives.
        let first = registry_search_blocking(full.clone(), RegistrySearchOptions { query: "evil".into(), ..all.clone() }, None, 10, 1_000_000).unwrap();
        assert_eq!((first.hits[0].key_path.as_deref(), first.next_cursor), (Some("\\ROOT\\Microsoft\\Run"), None));
        assert!(first.hits[0].snippet.as_deref().unwrap_or("").contains("evil.exe"));

        // Quick access: stored findings with their stored targets; a missing
        // hive keeps no target. Parser notes are not sent.
        let quick = registry_quick_access_blocking(full.clone()).unwrap();
        assert!(quick.available);
        assert_eq!(quick.items.iter().map(|i| text(&i.finding, "record_id")).collect::<Vec<_>>(), vec!["f1", "f2", "f3"]);
        assert_eq!(text(&quick.items[0].targets[0], "target_record_id"), "h0:v:2");
        assert_eq!(text(&quick.items[2].targets[0], "resolution"), "missing_hive");
        assert!(quick.items[0].finding.get("detail").is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn registry_values_and_value_data_reach_the_last_item_past_every_limit() {
        let root = temp_root("registry-limits");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let full = write_registry_explorer(&overview).to_string_lossy().to_string();
        {
            let mut conn = Connection::open(&full).unwrap();
            let tx = conn.transaction().unwrap();
            {
                let mut insert = tx
                    .prepare("INSERT INTO RegistryExplorer (record_id, host_id, dataset_id, hive_id, entry_kind, key_record_id, value_name, value_name_lower, value_is_default, value_display_name, value_type_name, value_data_hex, value_data_length, value_data_text, value_read_status, recovery, source_rowid) VALUES (?1, 'h', 'd', 'h0', 'value', 'h0:k:5', ?2, ?2, 0, ?2, 'REG_SZ', '00', 1, 'x', 'ok', 'live', ?3)")
                    .unwrap();
                for index in 0..20_001 {
                    insert.execute(rusqlite::params![format!("h0:v:many{index}"), format!("v{index:05}"), 100 + index]).unwrap();
                }
            }
            tx.execute(
                "INSERT INTO RegistryExplorer (record_id, host_id, dataset_id, hive_id, entry_kind, key_record_id, value_name, value_name_lower, value_is_default, value_display_name, value_type_name, value_data_hex, value_data_length, value_data_text, value_read_status, recovery, source_rowid)
                 VALUES ('h0:v:long', 'h', 'd', 'h0', 'value', 'h0:k:4', 'Long', 'long', 0, 'Long', 'REG_SZ', '00112233445566778899', 10, 'abcdefghijklmnop', 'ok', 'live', 99)",
                [],
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // Every value of a key with more than one page, to the last one.
        let mut names = Vec::new();
        let total = loop {
            let page = registry_values_blocking(full.clone(), "h0:k:5".into(), names.len() as i64, 5_000).unwrap();
            if page.rows.is_empty() {
                break page.total;
            }
            names.extend(page.rows.iter().map(|row| row.get("value_name").and_then(Value::as_str).unwrap_or_default().to_string()));
        };
        assert_eq!((total, names.len()), (20_001, 20_001));
        assert_eq!(names.last().map(String::as_str), Some("v20000"));

        // A value past the detail cap: the first part is marked, and the rest
        // comes in chunks up to the last byte / character.
        let entry = registry_entry_blocking(full.clone(), "h0:v:long".into(), 8).unwrap();
        let get = |key: &str| entry.entry.get(key).cloned().unwrap_or(Value::Null);
        assert_eq!((get("value_data_hex"), get("value_hex_truncated"), get("value_hex_length")), (Value::from("00112233"), Value::from(1), Value::from(20)));
        assert_eq!((get("value_data_text"), get("value_text_length")), (Value::from("abcdefgh"), Value::from(16)));
        let gather = |field: &str, start: i64, total: i64, step: i64| {
            let mut out = String::new();
            let mut offset = start;
            while offset < total {
                let chunk = registry_value_chunk_blocking(full.clone(), "h0:v:long".into(), field.into(), offset, step).unwrap();
                assert_eq!(chunk.total, total);
                offset += chunk.data.chars().count() as i64;
                out.push_str(&chunk.data);
            }
            out
        };
        assert_eq!(format!("00112233{}", gather("hex", 8, 20, 6)), "00112233445566778899");
        assert_eq!(format!("abcdefgh{}", gather("text", 8, 16, 5)), "abcdefghijklmnop");
        // Hex chunks start and end on byte boundaries.
        assert_eq!(registry_value_chunk_blocking(full.clone(), "h0:v:long".into(), "hex".into(), 9, 3).unwrap().data, "4455");
        assert!(registry_value_chunk_blocking(full.clone(), "h0:v:long".into(), "blob".into(), 0, 4).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_references_come_from_stored_candidates_of_the_same_generation() {
        let root = temp_root("fileref");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        Connection::open(overview.join("PathReferences.sqlite")).unwrap().execute_batch(
            "CREATE TABLE PathReferences (record_id TEXT PRIMARY KEY, host_id TEXT, dataset_id TEXT, timestamp TEXT, event_type TEXT, account TEXT, path TEXT, access_count INTEGER);
             CREATE TABLE PathReferenceCandidates (record_id TEXT, ordinal INTEGER, file_record_id TEXT, volume_id TEXT, match_basis TEXT);
             INSERT INTO PathReferences VALUES ('p1','h','d','2026-01-02 00:00:00.000','Jumplist','alice','\\a.txt',8),
                                               ('p2','h','old','2026-01-01 00:00:00.000','Jumplist','bob','\\a.txt',1),
                                               ('p3','h','d',NULL,'Shellbag',NULL,'\\a.txt',NULL);
             INSERT INTO PathReferenceCandidates VALUES ('p1',0,'r2','v1','path_and_drive'), ('p2',0,'r2','v1','path'), ('p3',0,'r2','v2','path');",
        ).unwrap();
        let host = root.to_string_lossy().to_string();
        let refs = file_references_blocking(&host, "d", Some("v1"), &["r2".to_string()]).unwrap();
        // Other generation (p2) and other volume (p3) are not linked.
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].file_record_id, "r2");
        assert_eq!(refs[0].match_basis, "path_and_drive");
        assert_eq!(refs[0].row.get("access_count").and_then(Value::as_i64), Some(8), "INTEGER stays typed");
        assert_eq!(file_references_blocking(&host, "d", None, &["r2".to_string()]).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resident_body_separates_absent_from_empty_and_is_detail_only() {
        let root = temp_root("body");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let db = write_file_system_entries(&overview);
        let full = db.to_string_lossy().to_string();
        let rowid_of = |name: &str| {
            mft_search_blocking(full.clone(), name.to_string(), None, 10)
                .unwrap()
                .into_iter()
                .next()
                .and_then(|row| row.get("__rowid").and_then(Value::as_i64))
                .unwrap()
        };

        let resident = mft_record_body_blocking(full.clone(), rowid_of("a.txt"), None).unwrap();
        assert_eq!(resident.data_present, Some(true));
        assert_eq!(resident.data_len, Some(3));
        assert!(!resident.truncated);

        let empty = mft_record_body_blocking(full.clone(), rowid_of("empty.txt"), None).unwrap();
        assert_eq!(empty.data_present, Some(true));
        assert_eq!(empty.data_len, Some(0), "길이 0 상주 본문은 정상 값이다");

        let absent = mft_record_body_blocking(full.clone(), rowid_of("orphan.bin"), None).unwrap();
        assert_eq!(absent.data_present, None, "비상주·미확보는 NULL이다");
        assert_eq!(absent.data_len, None);
        assert!(absent.body_b64.is_none());
        assert_eq!(absent.data_status.as_deref(), Some("unavailable"), "stored state, not guessed");

        // All evidence links are returned in ordinal order, and a source_db
        // outside the host root never resolves to an openable path.
        let facts = overview.join("MFT_Records.sqlite");
        Connection::open(&facts)
            .unwrap()
            .execute_batch("CREATE TABLE MFT_Records (volume_id TEXT NOT NULL, _source_file TEXT NOT NULL)")
            .unwrap();
        let sources = read_record_sources_blocking(
            full.clone(),
            "FileSystemEntries".to_string(),
            rowid_of("a.txt"),
        )
        .unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources[0].get("source_full_path").and_then(Value::as_str),
            Some(facts.to_string_lossy().to_string().as_str())
        );
        assert_eq!(
            sources[1].get("source_full_path").and_then(Value::as_str),
            Some("")
        );
        // A raw table has no source_records: no origin is invented.
        assert!(read_record_sources_blocking(
            facts.to_string_lossy().to_string(),
            "MFT_Records".to_string(),
            1,
        )
        .unwrap()
        .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Page rows carry their raw evidence identities (used by the master
    /// timeline to show a shared source once).
    /// Duplicate evidence for the
    /// same raw row collapses, distinct artifacts are all kept, and origins
    /// outside the host root are dropped.
    #[test]
    fn page_rows_carry_deduped_raw_source_identities() {
        let root = temp_root("refs");
        let overview = root.join("_OVERVIEW");
        std::fs::create_dir_all(&overview).unwrap();
        let db = write_file_system_entries(&overview);

        // The two collection files the evidence links point at.
        let facts = overview.join("MFT_Records.sqlite");
        Connection::open(&facts)
            .unwrap()
            .execute_batch(
                "CREATE TABLE MFT_Records (volume_id TEXT NOT NULL, _source_file TEXT NOT NULL);
                 INSERT INTO MFT_Records VALUES ('v1','C:\\$MFT');
                 INSERT INTO MFT_Records VALUES ('v1','C:\\$MFT')",
            )
            .unwrap();
        let eventlog = root.join("EVENTLOG");
        std::fs::create_dir_all(&eventlog).unwrap();
        let security = eventlog.join("Security.sqlite");
        Connection::open(&security)
            .unwrap()
            .execute_batch(
                "CREATE TABLE Security (timestamp TEXT, detail TEXT);
                 INSERT INTO Security VALUES ('2026-01-02 00:00:00.000','needle-a.txt')",
            )
            .unwrap();
        {
            let conn = Connection::open(&db).unwrap();
            // ordinal 2: same raw row again, as field-level evidence.
            conn.execute(
                "INSERT INTO source_records VALUES ('r2', 2, 'd0', 'MFT', '_OVERVIEW/MFT_Records.sqlite', 'MFT_Records', 2, 'file_size', NULL, NULL, NULL)",
                [],
            )
            .unwrap();
            // ordinal 3: a different artifact — not reduced to one representative.
            conn.execute(
                "INSERT INTO source_records VALUES ('r2', 3, 'd0', 'EventLog', 'EVENTLOG/Security.sqlite', 'Security', 1, NULL, NULL, NULL, NULL)",
                [],
            )
            .unwrap();
        }

        let expected = vec![
            SourcePointer {
                full_path: facts.to_string_lossy().to_string(),
                table_name: "MFT_Records".to_string(),
                rowid: 2,
            },
            SourcePointer {
                full_path: security.to_string_lossy().to_string(),
                table_name: "Security".to_string(),
                rowid: 1,
            },
        ];

        let page =
            read_result_file_page_blocking(db.to_string_lossy().to_string(), None, 0, 50).unwrap();
        let find = |record_id: &str| {
            page.rows
                .iter()
                .find(|row| row.get("record_id").and_then(Value::as_str) == Some(record_id))
                .expect("row")
        };
        let decorated: Vec<SourcePointer> = serde_json::from_str(
            find("r2")
                .get(SOURCE_REFS_KEY)
                .and_then(Value::as_str)
                .expect("source refs"),
        )
        .unwrap();
        assert_eq!(decorated, expected);
        // A row without evidence has no key at all: an empty array would look
        // like "evidence exists".
        assert!(!find("r1").contains_key(SOURCE_REFS_KEY));
        // Child and evidence tables are not decorated (no per-child fan-out).
        let child = read_result_file_page_blocking(
            db.to_string_lossy().to_string(),
            Some("source_records".to_string()),
            0,
            50,
        )
        .unwrap();
        assert!(child
            .rows
            .iter()
            .all(|row| !row.contains_key(SOURCE_REFS_KEY)));

        let _ = std::fs::remove_dir_all(root);
    }

    /// Inserts one row; `cells` are (column, value) pairs.
    fn insert_row(conn: &Connection, table: &str, cells: &[(&str, rusqlite::types::Value)]) {
        let columns: Vec<String> = cells.iter().map(|(column, _)| q(column)).collect();
        let marks: Vec<String> = (1..=cells.len()).map(|index| format!("?{index}")).collect();
        let values: Vec<&dyn rusqlite::ToSql> = cells.iter().map(|(_, value)| value as &dyn rusqlite::ToSql).collect();
        conn.execute(&format!("INSERT INTO {} ({}) VALUES ({})", q(table), columns.join(","), marks.join(",")), values.as_slice())
            .unwrap_or_else(|error| panic!("{table}: {error}"));
    }

    fn t(value: &str) -> rusqlite::types::Value {
        rusqlite::types::Value::Text(value.to_string())
    }

    fn n(value: i64) -> rusqlite::types::Value {
        rusqlite::types::Value::Integer(value)
    }

    /// Three inputs (two Chrome profiles + an Edge cache) with visits, URL
    /// summaries, a download with a URL chain, cache rows (text/blob/untimed)
    /// and one AI referral marker.
    fn write_browser_overview(root: &Path) -> PathBuf {
        let conn = wina_core::derived::create_database(&root.join("_OVERVIEW"), "BrowserActivity").unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        for (ordinal, (id, kind, browser, profile, label)) in [
            ("in1", "history", "Chrome", "Default", "alice"),
            ("in2", "cache", "Edge", "Default", "alice"),
            ("in3", "history", "Chrome", "Profile 1", "bob"),
        ]
        .into_iter()
        .enumerate()
        {
            insert_row(&conn, "BrowserInputs", &[
                ("input_id", t(id)), ("host_id", t("h")), ("dataset_id", t("g")), ("ordinal", n(ordinal as i64)),
                ("input_kind", t(kind)), ("browser", t(browser)), ("profile", t(profile)), ("account_label", t(label)),
                ("account", t(label)), ("account_sid", t(if label == "alice" { "S-1-5-21-1" } else { "S-1-5-21-2" })),
                ("source_file", t(&format!("/evidence/{label}/{browser}/{profile}"))), ("facts_db", t("BROWSER/x.sqlite")),
                ("facts_dataset_id", t("f")),
            ]);
        }
        let record = |id: &str, kind: &str, input: &str, time: Option<&str>, extra: &[(&str, rusqlite::types::Value)]| {
            let mut cells = vec![
                ("record_id", t(id)), ("host_id", t("h")), ("dataset_id", t("g")), ("overview_name", t("BrowserActivity")),
                ("event_type", t(kind)), ("input_id", t(input)), ("account", t(if input == "in3" { "bob" } else { "alice" })),
                ("account_sid", t(if input == "in3" { "S-1-5-21-2" } else { "S-1-5-21-1" })),
            ];
            if let Some(time) = time {
                cells.push(("timestamp", t(time)));
                cells.push(("timestamp_kind", t("시각")));
            }
            cells.extend(extra.iter().cloned());
            insert_row(&conn, "BrowserActivity", &cells);
            insert_row(&conn, "source_records", &[
                ("record_id", t(id)), ("ordinal", n(0)), ("source_dataset_id", t("f")), ("source_artifact", t("Browser")),
                ("source_db", t("BROWSER/x.sqlite")), ("source_table", t("BrowserHistory")), ("source_rowid", n(1)),
            ]);
        };
        record("v1", "visit", "in1", Some("2026-01-01 10:00:00.000"), &[("url", t("https://a.example/x")), ("title", t("A")), ("url_summary_id", t("s1")), ("visit_id", t("1"))]);
        record("v2", "visit", "in1", Some("2026-01-01 11:00:00.000"), &[("url", t("https://a.example/y")), ("from_record_id", t("v1")), ("visit_id", t("2"))]);
        // Two parents: same-tab source v1 and opener v2.
        record("v3", "visit", "in1", Some("2026-01-02 09:00:00.000"), &[("url", t("https://b.example/")), ("from_record_id", t("v1")), ("opener_record_id", t("v2")), ("visit_id", t("3"))]);
        // A link across inputs must never be followed.
        record("v4", "visit", "in3", Some("2026-01-01 10:30:00.000"), &[("url", t("https://a.example/z")), ("from_record_id", t("v2")), ("visit_id", t("2"))]);
        record("s1", "url_summary", "in1", Some("2026-01-01 11:00:00.000"), &[("url", t("https://a.example/x")), ("visit_count", n(2)), ("typed_count", n(0))]);
        record("s2", "url_summary", "in1", None, &[("url", t("https://c.example/"))]);
        record("d1", "download", "in1", Some("2026-01-02 10:00:00.000"), &[
            ("title", t("tool.exe")), ("url", t("https://dl.example/tool.exe")),
            ("download_path", t("C:\\Users\\alice\\Down%20loads\\tool.exe")), ("download_referrer", t("https://a.example/y")),
            ("received_bytes", n(10)), ("total_bytes", n(20)), ("download_state", n(2)), ("download_opened", n(0)),
        ]);
        record("c1", "cache", "in2", Some("2026-01-01 12:00:00.000"), &[("url", t("https://a.example/app.js")), ("request_url", t("https://a.example/app.js"))]);
        record("c2", "cache", "in2", None, &[("url", t("https://a.example/bin"))]);
        record("r1", "visit", "in1", Some("2026-01-03 08:00:00.000"), &[("url", t("https://x.example/?utm_source=chatgpt.com")), ("ai_referral_provider", t("ChatGPT"))]);
        for (id, ordinal) in [("s1", 0), ("s2", 1)] {
            insert_row(&conn, "BrowserUrlSummaries", &[
                ("summary_id", t(id)), ("host_id", t("h")), ("dataset_id", t("g")), ("input_id", t("in1")), ("url_id", n(ordinal)),
                ("source_dataset_id", t("f")), ("source_db", t("BROWSER/x.sqlite")), ("source_table", t("urls")), ("source_rowid", n(ordinal)),
            ]);
        }
        insert_row(&conn, "BrowserSearchTerms", &[
            ("search_id", t("k1")), ("host_id", t("h")), ("dataset_id", t("g")), ("input_id", t("in1")), ("summary_id", t("s1")),
            ("term", t("Secret Plan")), ("normalized_term", t("secret plan")), ("source_dataset_id", t("f")),
            ("source_db", t("BROWSER/x.sqlite")), ("source_table", t("keyword_search_terms")), ("source_rowid", n(1)),
        ]);
        for (ordinal, url) in [(0, "https://cdn.example/redirect"), (1, "https://dl.example/tool.exe")] {
            insert_row(&conn, "BrowserDownloadChain", &[("record_id", t("d1")), ("ordinal", n(ordinal)), ("chain_index", n(ordinal)), ("url", t(url))]);
        }
        insert_row(&conn, "BrowserCacheDetails", &[
            ("record_id", t("c1")), ("status_line", t("HTTP/1.1 200 OK")), ("http_status", n(200)), ("body_recovered", n(1)),
            ("body", t("hello cache")), ("all_headers", t("HTTP/1.1 200 OK\nX-Trace: needle-header")),
        ]);
        insert_row(&conn, "BrowserCacheDetails", &[
            ("record_id", t("c2")), ("body_recovered", n(1)), ("body", rusqlite::types::Value::Blob(vec![0, 1, 2, 255])),
        ]);
        root.join("_OVERVIEW").join("BrowserActivity.sqlite")
    }

    fn ids(rows: &[Map<String, Value>]) -> Vec<String> {
        rows.iter().map(|row| map_text(row, "record_id")).collect()
    }

    fn filter(kinds: &[&str]) -> BrowserFilter {
        BrowserFilter { kinds: kinds.iter().map(|kind| kind.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn browser_view_reads_only_the_overview_contract() {
        let root = temp_root("browser-overview");
        let db = write_browser_overview(&root).to_string_lossy().to_string();
        let host = root.to_string_lossy().to_string();

        let scope = browser_scope_blocking(db.clone()).unwrap();
        assert_eq!(
            scope.iter().map(|input| (input.input_id.as_str(), input.record_count)).collect::<Vec<_>>(),
            vec![("in1", 7), ("in2", 2), ("in3", 1)]
        );

        // Event days exclude URL summaries; untimed rows stay reachable.
        let summary = browser_summary_blocking(db.clone(), BrowserFilter::default()).unwrap();
        let days: Vec<(String, i64)> = summary.days.iter().map(|day| (day.value.clone(), day.count)).collect();
        assert_eq!(days, vec![("2026-01-01".into(), 4), ("2026-01-02".into(), 2), ("2026-01-03".into(), 1)]);
        assert_eq!(summary.untimed, 2);
        let domains: Vec<(String, i64, i64)> = summary.top_domains.iter().map(|d| (d.domain.clone(), d.visit_count, d.url_count)).collect();
        assert_eq!(domains[0], ("a.example".into(), 3, 3));
        assert_eq!(summary.visit_total, 5);
        assert_eq!((summary.download_total, ids(&summary.downloads)), (1, vec!["d1".to_string()]));

        let scoped = browser_summary_blocking(db.clone(), BrowserFilter { input_ids: vec!["in1".into()], ..filter(&["visit"]) }).unwrap();
        assert_eq!(scoped.days.iter().map(|day| day.count).collect::<Vec<_>>(), vec![2, 1, 1]);
        assert_eq!(scoped.visit_total, 4);

        // Day page: time order, record_id tie-break; descending mirrors it.
        let day = BrowserFilter { day: Some("2026-01-01".into()), ..filter(&["visit", "download", "cache"]) };
        assert_eq!(ids(&browser_page_blocking(db.clone(), day.clone(), 0, 50, false).unwrap().rows), ["v1", "v4", "v2", "c1"]);
        assert_eq!(ids(&browser_page_blocking(db.clone(), day, 0, 50, true).unwrap().rows), ["c1", "v2", "v4", "v1"]);
        let untimed = browser_page_blocking(db.clone(), BrowserFilter { untimed: true, ..Default::default() }, 0, 50, false).unwrap();
        assert_eq!(ids(&untimed.rows), ["c2", "s2"]);
        let all = browser_page_blocking(db.clone(), BrowserFilter::default(), 0, 50, false).unwrap();
        assert_eq!(ids(&all.rows).last().map(String::as_str), Some("s2"), "NULL times sort last");

        // Search reaches child values and reduces them to one parent row.
        let search = |needle: &str| {
            let mut found = ids(&browser_page_blocking(db.clone(), BrowserFilter { search: Some(needle.into()), ..Default::default() }, 0, 50, false).unwrap().rows);
            found.sort();
            found
        };
        assert_eq!(search("needle-header"), ["c1"]);
        assert_eq!(search("secret plan"), ["s1", "v1"]);
        assert_eq!(search("cdn.example/redirect"), ["d1"]);
        assert_eq!(search("Down%20loads"), ["d1"], "local paths are not URL-decoded");
        assert_eq!(search("S-1-5-21-2"), ["v4"]);
        assert_eq!(search("100%"), Vec::<String>::new(), "LIKE metacharacters are literal");
        let referrals = browser_page_blocking(db.clone(), BrowserFilter { referral: true, ..Default::default() }, 0, 50, false).unwrap();
        assert_eq!(ids(&referrals.rows), ["r1"]);

        let ascending = browser_domains_blocking(db.clone(), BrowserFilter::default(), 0, 1, true).unwrap();
        assert_eq!((ascending.total, ascending.domains[0].visit_count), (3, 1));

        // Record detail: relations by stored ids, no cache body inline.
        let download = browser_record_blocking(host.clone(), "d1".into()).unwrap();
        assert_eq!(map_text(&download.row, "download_path"), "C:\\Users\\alice\\Down%20loads\\tool.exe");
        assert_eq!(download.download_chain.iter().map(|row| map_text(row, "url")).collect::<Vec<_>>(), ["https://cdn.example/redirect", "https://dl.example/tool.exe"]);
        assert_eq!(download.input.as_ref().map(|input| map_text(input, "browser")), Some("Chrome".into()));
        assert_eq!(download.sources.len(), 1);
        let visit = browser_record_blocking(host.clone(), "v1".into()).unwrap();
        assert_eq!(visit.url_summary.as_ref().map(|summary| map_text(summary, "visit_count")), Some("2".into()));
        assert_eq!(visit.search_terms.len(), 1);
        let summary_record = browser_record_blocking(host.clone(), "s1".into()).unwrap();
        assert_eq!(summary_record.url_summary.as_ref().map(|summary| map_text(summary, "source_table")), Some("urls".into()));
        let cache = browser_record_blocking(host.clone(), "c1".into()).unwrap();
        let details = cache.cache.unwrap();
        assert_eq!((map_text(&details, "body_length"), map_text(&details, "body_type")), ("11".into(), "text".into()));
        assert!(!details.contains_key("body"));

        use base64::Engine as _;
        let decode = |chunk: BrowserCacheBody| base64::engine::general_purpose::STANDARD.decode(chunk.data_b64).unwrap();
        assert_eq!(decode(browser_cache_body_blocking(host.clone(), "c1".into(), 0, 5).unwrap()), b"hello");
        let tail = browser_cache_body_blocking(host.clone(), "c1".into(), 6, 100).unwrap();
        assert_eq!(tail.total, 11);
        assert_eq!(decode(tail), b"cache");
        assert_eq!(decode(browser_cache_body_blocking(host.clone(), "c2".into(), 0, 100).unwrap()), vec![0, 1, 2, 255]);
        assert!(browser_cache_body_blocking(host.clone(), "v1".into(), 0, 10).is_err());

        // Flow follows stored from/opener links inside the visit's input only.
        let flow = browser_visit_flow_blocking(host.clone(), "v2".into()).unwrap();
        assert_eq!(flow.nodes.iter().map(|node| node.record_id.as_str()).collect::<Vec<_>>(), ["v1", "v2", "v3"]);
        assert_eq!(flow.nodes.iter().filter(|node| node.is_target).map(|node| node.record_id.as_str()).collect::<Vec<_>>(), ["v2"]);
        let mut edges: Vec<(String, String, String)> = flow.edges.iter().map(|edge| (edge.from.clone(), edge.to.clone(), edge.kind.clone())).collect();
        edges.sort();
        assert_eq!(edges, vec![
            ("v1".into(), "v2".into(), "from_visit".into()),
            ("v1".into(), "v3".into(), "from_visit".into()),
            ("v2".into(), "v3".into(), "opener_visit".into()),
        ]);
        assert!(browser_visit_flow_blocking(host, "c1".into()).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Two snapshots of one ChatGPT conversation (messages with a non-current
    /// branch, an attachment, a collected response) and an untimed list trace.
    fn write_ai_overview(root: &Path) -> PathBuf {
        let conn = wina_core::derived::create_database(&root.join("_OVERVIEW"), "AiConversations").unwrap();
        let base = |id: &str, kind: &str, time: Option<&str>, extra: &[(&str, rusqlite::types::Value)]| {
            let mut cells = vec![
                ("record_id", t(id)), ("host_id", t("h")), ("dataset_id", t("g")), ("overview_name", t("AiConversations")),
                ("record_kind", t(kind)),
            ];
            if let Some(time) = time {
                cells.push(("timestamp", t(time)));
                cells.push(("timestamp_kind", t("캐시 관찰 시각")));
            }
            cells.extend(extra.iter().cloned());
            insert_row(&conn, "AiConversations", &cells);
        };
        let recovered = |messages: i64| -> Vec<(&str, rusqlite::types::Value)> {
            vec![
                ("provider", t("ChatGPT")), ("conversation_id", t("conv-x")), ("title", t("Plan")), ("body_recovered", n(1)),
                ("message_count", n(messages)), ("current_branch_message_count", n(messages - 1)), ("structural_node_count", n(messages + 1)),
                ("attachment_count", n(1)),
            ]
        };
        base("conv1", "conversation", Some("2026-02-01 10:00:00.000"), &recovered(3));
        base("conv2", "conversation", Some("2026-01-31 10:00:00.000"), &recovered(2));
        base("list1", "list_entry", None, &[
            ("provider", t("Claude")), ("conversation_id", t("conv-y")), ("title", t("Untimed list")), ("body_recovered", n(0)),
            ("list_ordinal", n(0)), ("list_item_count", n(1)),
        ]);
        for (ordinal, role, current, content) in [(0, "user", 1, "first question"), (1, "assistant", 0, "older answer"), (2, "assistant", 1, "current answer")] {
            insert_row(&conn, "AiMessages", &[
                ("record_id", t("conv1")), ("ordinal", n(ordinal)), ("node_id", t(&format!("n{ordinal}"))), ("role", t(role)),
                ("content", t(content)), ("on_current_branch", n(current)),
            ]);
        }
        insert_row(&conn, "AiAttachments", &[
            ("record_id", t("conv1")), ("ordinal", n(0)), ("message_ordinal", n(0)), ("file_name", t("a.pdf")), ("extracted_text", t("pdf text")),
        ]);
        insert_row(&conn, "AiConversationTexts", &[("record_id", t("conv1")), ("ordinal", n(0)), ("text_kind", t("interpretation_json")), ("text_value", t("{\"a\":1}"))]);
        insert_row(&conn, "AiConversationTexts", &[("record_id", t("conv1")), ("ordinal", n(1)), ("text_kind", t("search_text")), ("text_value", t("first question needle-msg"))]);
        insert_row(&conn, "source_records", &[
            ("record_id", t("conv1")), ("ordinal", n(0)), ("source_dataset_id", t("f")), ("source_artifact", t("Browser")),
            ("source_db", t("BROWSER/a_Cache.sqlite")), ("source_table", t("CacheEntries")), ("source_rowid", n(7)),
        ]);
        insert_row(&conn, "AiResponseBodies", &[
            ("source_db", t("BROWSER/a_Cache.sqlite")), ("source_table", t("CacheEntries")), ("source_rowid", n(7)),
            ("response_body", t("RAW-RESPONSE")), ("byte_length", n(12)),
        ]);
        root.join("_OVERVIEW").join("AiConversations.sqlite")
    }

    #[test]
    fn ai_view_reads_stored_messages_branches_and_snapshots() {
        let root = temp_root("ai-overview");
        let db = write_ai_overview(&root).to_string_lossy().to_string();
        let page = |query: AiQuery| ai_page_blocking(db.clone(), AiQuery { limit: 50, ..query }).unwrap();

        let all = page(AiQuery::default());
        assert_eq!(ids(&all.rows), ["conv1", "conv2", "list1"], "newest first, untimed last");
        assert_eq!(all.kinds.iter().map(|kind| (kind.value.as_str(), kind.count)).collect::<Vec<_>>(), [("conversation", 2), ("list_entry", 1)]);
        assert_eq!(ids(&page(AiQuery { kind: Some("list_entry".into()), ..Default::default() }).rows), ["list1"]);
        assert_eq!(ids(&page(AiQuery { untimed: true, ..Default::default() }).rows), ["list1"]);
        assert_eq!(ids(&page(AiQuery { search: Some("needle-msg".into()), ..Default::default() }).rows), ["conv1"]);
        let narrowed = page(AiQuery { kind: Some("conversation".into()), search: Some("plan".into()), ..Default::default() });
        assert_eq!((narrowed.row_count, narrowed.kinds.len()), (2, 1));

        let record = ai_record_blocking(db.clone(), "conv1".into()).unwrap();
        assert_eq!(
            record.messages.iter().map(|m| (map_text(m, "content"), map_text(m, "on_current_branch"))).collect::<Vec<_>>(),
            vec![("first question".into(), "1".into()), ("older answer".into(), "0".into()), ("current answer".into(), "1".into())]
        );
        assert_eq!(record.attachments.iter().map(|a| map_text(a, "message_ordinal")).collect::<Vec<_>>(), ["0"]);
        assert_eq!(record.interpretation.as_deref(), Some("{\"a\":1}"));
        assert_eq!(record.sources.iter().map(|s| map_text(s, "response_length")).collect::<Vec<_>>(), ["12"]);
        assert_eq!(ids(&record.snapshots), ["conv2"]);

        let list = ai_record_blocking(db.clone(), "list1".into()).unwrap();
        assert!(list.messages.is_empty() && list.snapshots.is_empty());
        assert_eq!(list.row.get("message_count"), Some(&Value::Null), "unknown counts stay NULL");

        let chunk = ai_response_body_blocking(db.clone(), "BROWSER/a_Cache.sqlite".into(), "CacheEntries".into(), 7, 4, 100).unwrap();
        assert_eq!((chunk.data.as_str(), chunk.total), ("RESPONSE", 12));
        assert!(ai_response_body_blocking(db, "BROWSER/a_Cache.sqlite".into(), "CacheEntries".into(), 8, 0, 10).is_err());
        let _ = std::fs::remove_dir_all(root);
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
            timeline_source_page,
            master_timeline_build_begin,
            master_timeline_build_insert,
            master_timeline_build_drain,
            master_timeline_build_finish,
            master_timeline_build_abort,
            master_timeline_meta,
            master_timeline_facets,
            master_timeline_page,
            list_result_files,
            overview_contract_status,
            account_directory,
            host_metadata,
            result_provenance,
            artifact_input_files,
            parse_report,
            parse_run_log,
            open_parse_run_log,
            host_parse_eligibility,
            read_result_file,
            read_result_file_page,
            linked_result_rows,
            result_row,
            result_row_by_record_id,
            list_column_values,
            mft_children,
            mft_search,
            usn_overview,
            usn_groups_page,
            registry_hives,
            registry_keys,
            registry_values,
            registry_entry,
            registry_value_chunk,
            registry_search,
            registry_quick_access,
            mft_records_page,
            mft_row,
            mft_record_body,
            mft_volumes,
            read_record_sources,
            read_record_children,
            search_case,
            list_bookmarks,
            toggle_bookmark,
            update_bookmark_note,
            pick_folder,
            file_references,
            path_reference_accounts,
            browser_scope,
            browser_summary,
            browser_domains,
            browser_page,
            browser_record,
            browser_cache_body,
            browser_visit_flow,
            account_event_page,
            ai_page,
            ai_record,
            ai_response_body,
            powershell_search_rowids
        ])
        .setup(|app| {
            // Window keeps the tauri.conf.json `main` config (`create: false`);
            // only the WebView2 data folder moves to `cases/.webview`.
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .cloned()
                .ok_or("tauri.conf.json has no `main` window config")?;
            let mut builder = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?;
            let dir = webview_data_dir();
            match std::fs::create_dir_all(&dir) {
                Ok(()) => builder = builder.data_directory(dir),
                Err(error) => eprintln!(
                    "[WEBVIEW] cannot create {} ({error}) — falling back to LocalAppData",
                    dir.display()
                ),
            }
            builder.build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}


