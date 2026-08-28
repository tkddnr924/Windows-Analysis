//! Direct host registry.
//!
//! Canonical storage is deliberately flat:
//! ```text
//! <cases_dir>/<host_id>/host.json
//! <cases_dir>/<host_id>/<artifact output>
//! <cases_dir>/bookmarks.json
//! ```
//! Older releases used `<cases_dir>/<case_id>/<host_id>`. The first store
//! access migrates those host directories into the direct layout without
//! deleting evidence, parser logs, or annotations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Internal API collection identifier. It keeps current worker/IPC contracts
/// stable without reintroducing a user-visible case directory.
pub const ROOT_COLLECTION_ID: &str = "root";
const BOOKMARKS_FILE: &str = "bookmarks.json";
const LEGACY_ARCHIVE_DIR: &str = ".legacy-case-archive";
const MIGRATION_JOURNAL_FILE: &str = ".direct-host-migration.json";
const MIGRATION_LOCK_FILE: &str = ".direct-host-migration.lock";

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
pub fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Compatibility collection root. New data is always `cases/<host_id>/`.
pub fn case_dir(cases_dir: &Path, _case_id: &str) -> PathBuf {
    cases_dir.to_path_buf()
}

pub fn host_dir(cases_dir: &Path, _case_id: &str, host_id: &str) -> PathBuf {
    cases_dir.join(host_id)
}

fn host_meta(cases_dir: &Path, case_id: &str, host_id: &str) -> PathBuf {
    host_dir(cases_dir, case_id, host_id).join("host.json")
}

/// Python _slugify: replace runs of non-[word.-] with "_", strip leading/trailing "_".
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
    let value = out.trim_matches('_').to_string();
    if value.is_empty() {
        "item".to_string()
    } else {
        value
    }
}

fn id_for(name: &str, created_at: &str) -> String {
    let compact = created_at.replace([':', '-'], "").replace(' ', "_");
    format!("{}_{}", slugify(name), compact)
}

fn unique_host_id(cases_dir: &Path, preferred: &str, legacy_case_id: Option<&str>) -> String {
    if !cases_dir.join(preferred).exists() {
        return preferred.to_string();
    }
    let base = legacy_case_id
        .filter(|id| !id.is_empty())
        .map(|id| format!("{preferred}--{}", slugify(id)))
        .unwrap_or_else(|| format!("{preferred}--migrated"));
    let mut candidate = base.clone();
    let mut suffix = 2usize;
    while cases_dir.join(&candidate).exists() {
        candidate = format!("{base}-{suffix}");
        suffix += 1;
    }
    candidate
}

fn normalized_path(value: &str) -> String {
    value.replace('\\', "/").trim_end_matches('/').to_string()
}

fn rewrite_bookmark_path(value: &str, from: &Path, to: &Path) -> Option<String> {
    let source = normalized_path(&from.to_string_lossy());
    let value = normalized_path(value);
    if value != source && !value.starts_with(&(source.clone() + "/")) {
        return None;
    }
    Some(format!(
        "{}{}",
        normalized_path(&to.to_string_lossy()),
        &value[source.len()..]
    ))
}

fn bookmark_identity(value: &Value) -> Option<(String, String, i64, String)> {
    Some((
        value.get("fullPath")?.as_str()?.to_string(),
        value.get("tableName")?.as_str()?.to_string(),
        value.get("rowid")?.as_i64()?,
        value
            .get("field")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    ))
}

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

fn read_bookmarks(path: &Path) -> Result<Vec<Value>> {
    let target = path.join(BOOKMARKS_FILE);
    match std::fs::read_to_string(&target) {
        Ok(raw) => serde_json::from_str::<Value>(&raw)
            .with_context(|| format!("invalid bookmark file {}", target.display()))?
            .as_array()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("bookmark file {} is not an array", target.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => {
            Err(error).with_context(|| format!("read bookmark file {}", target.display()))
        }
    }
}

fn write_bookmarks_atomic(path: &Path, bookmarks: &[Value]) -> Result<()> {
    std::fs::create_dir_all(path)?;
    let target = path.join(BOOKMARKS_FILE);
    let temporary = path.join(format!(
        ".bookmarks-migration-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    if let Err(error) = std::fs::write(&temporary, serde_json::to_vec_pretty(bookmarks)?)
        .and_then(|()| std::fs::rename(&temporary, &target))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("write bookmark file {}", target.display()));
    }
    Ok(())
}

fn write_host(host: &Host, cases_dir: &Path, case_id: &str) -> Result<()> {
    let target = host_meta(cases_dir, case_id, &host.id);
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("host metadata has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".host-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    if let Err(error) = std::fs::write(&temporary, serde_json::to_vec_pretty(host)?)
        .and_then(|()| std::fs::rename(&temporary, &target))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("write host metadata {}", target.display()));
    }
    Ok(())
}

#[derive(Clone)]
struct LegacyHostMove {
    source: PathBuf,
    destination: PathBuf,
    old_host_id: String,
    new_host_id: String,
    host: Host,
}

#[derive(Serialize, Deserialize, Default)]
struct MigrationJournal {
    #[serde(default)]
    cases: Vec<LegacyCaseJournal>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LegacyCaseJournal {
    legacy_case: String,
    #[serde(default = "migration_phase_planned")]
    phase: String,
    moves: Vec<LegacyMoveJournal>,
}

fn migration_phase_planned() -> String {
    "planned".to_string()
}

#[derive(Serialize, Deserialize, Clone)]
struct LegacyMoveJournal {
    source: String,
    destination: String,
    old_host_id: String,
    new_host_id: String,
}

fn read_migration_journal(cases_dir: &Path) -> Result<MigrationJournal> {
    let path = cases_dir.join(MIGRATION_JOURNAL_FILE);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw)
            .with_context(|| format!("invalid direct-host migration journal {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(MigrationJournal::default())
        }
        Err(error) => {
            Err(error).with_context(|| format!("read migration journal {}", path.display()))
        }
    }
}

fn write_migration_journal(cases_dir: &Path, journal: &MigrationJournal) -> Result<()> {
    let target = cases_dir.join(MIGRATION_JOURNAL_FILE);
    let temporary = cases_dir.join(format!(
        ".direct-host-migration-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    if let Err(error) = std::fs::write(&temporary, serde_json::to_vec_pretty(journal)?)
        .and_then(|()| std::fs::rename(&temporary, &target))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("write migration journal {}", target.display()));
    }
    Ok(())
}

// A persistent lock *file* is intentional. On Unix the advisory flock is held
// by the OS-owned descriptor and is released if the GUI dies, so a leftover
// sentinel never blocks the next launch.
#[cfg(unix)]
struct MigrationLock {
    _file: std::fs::File,
}

#[cfg(unix)]
fn acquire_migration_lock(cases_dir: &Path) -> Result<MigrationLock> {
    use std::os::fd::AsRawFd;
    let path = cases_dir.join(MIGRATION_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open migration lock {}", path.display()))?;
    for _ in 0..80 {
        // SAFETY: `file` remains open for the MigrationLock lifetime.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(MigrationLock { _file: file });
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error).with_context(|| format!("lock migration {}", path.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    anyhow::bail!("legacy host migration is already in progress; retry after it completes")
}

#[cfg(not(unix))]
struct MigrationLock(PathBuf);

#[cfg(not(unix))]
impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(not(unix))]
fn acquire_migration_lock(cases_dir: &Path) -> Result<MigrationLock> {
    let path = cases_dir.join(MIGRATION_LOCK_FILE);
    for _ in 0..80 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => return Ok(MigrationLock(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("lock migration {}", path.display()))
            }
        }
    }
    anyhow::bail!("legacy host migration is already in progress; retry after it completes")
}

/// Migrate one historical `<case>/<host>` directory. Root bookmarks are
/// atomically merged before directories move, making a retry safe after an
/// interruption. The former case folder is archived, never recursively erased.
fn migrate_legacy_case(cases_dir: &Path, legacy_case: &Path) -> Result<()> {
    let legacy_case_id = legacy_case
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("legacy");
    let legacy_case_key = legacy_case.to_string_lossy().to_string();
    let mut journal = read_migration_journal(cases_dir)?;
    let planned = if let Some(existing) = journal
        .cases
        .iter()
        .find(|entry| entry.legacy_case == legacy_case_key)
    {
        existing.clone()
    } else {
        let mut moves = Vec::new();
        for entry in std::fs::read_dir(legacy_case)? {
            let entry = entry?;
            let source = entry.path();
            if !source.is_dir() || !source.join("host.json").is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(source.join("host.json"))?;
            let host: Host = serde_json::from_str(&raw)
                .with_context(|| format!("read legacy host metadata {}", source.display()))?;
            let old_host_id = host.id;
            let new_host_id = unique_host_id(cases_dir, &old_host_id, Some(legacy_case_id));
            moves.push(LegacyMoveJournal {
                source: source.to_string_lossy().to_string(),
                destination: cases_dir.join(&new_host_id).to_string_lossy().to_string(),
                old_host_id,
                new_host_id,
            });
        }
        let planned = LegacyCaseJournal {
            legacy_case: legacy_case_key.clone(),
            phase: migration_phase_planned(),
            moves,
        };
        journal.cases.push(planned.clone());
        // Write the complete destination plan before any bookmark or evidence
        // mutation. A later retry uses these exact paths rather than making a
        // second collision suffix or duplicating rewritten bookmarks.
        write_migration_journal(cases_dir, &journal)?;
        planned
    };
    let mut moves = Vec::new();
    for movement in &planned.moves {
        let source = PathBuf::from(&movement.source);
        let destination = PathBuf::from(&movement.destination);
        let metadata_path = if source.join("host.json").is_file() {
            source.join("host.json")
        } else {
            destination.join("host.json")
        };
        let raw = std::fs::read_to_string(&metadata_path).with_context(|| {
            format!(
                "read planned legacy host metadata {}",
                metadata_path.display()
            )
        })?;
        let mut host: Host = serde_json::from_str(&raw).with_context(|| {
            format!(
                "read planned legacy host metadata {}",
                metadata_path.display()
            )
        })?;
        host.id = movement.new_host_id.clone();
        moves.push(LegacyHostMove {
            source,
            destination,
            old_host_id: movement.old_host_id.clone(),
            new_host_id: movement.new_host_id.clone(),
            host,
        });
    }

    for movement in &moves {
        if movement.source.exists() {
            anyhow::ensure!(
                !movement.destination.exists(),
                "migration destination already exists: {}",
                movement.destination.display()
            );
            std::fs::rename(&movement.source, &movement.destination).with_context(|| {
                format!(
                    "move legacy host {} to {}",
                    movement.source.display(),
                    movement.destination.display()
                )
            })?;
        } else {
            anyhow::ensure!(
                movement.destination.exists(),
                "planned migration source and destination are both missing: {}",
                movement.source.display()
            );
        }
        // A collision suffix changes only direct host identity/path. Evidence,
        // reports and immutable logs remain together in this renamed folder.
        write_host(&movement.host, cases_dir, ROOT_COLLECTION_ID)?;
        anyhow::ensure!(
            movement.destination.join("host.json").is_file(),
            "migrated host metadata was not written: {}",
            movement.destination.display()
        );
    }

    if let Some(entry) = journal
        .cases
        .iter_mut()
        .find(|entry| entry.legacy_case == legacy_case_key)
    {
        entry.phase = "hosts_moved".to_string();
    }
    write_migration_journal(cases_dir, &journal)?;

    // Do not rewrite/prune analyst annotations until every host directory has
    // been moved and verified. An interrupted migration therefore leaves the
    // legacy bookmark file authoritative rather than publishing partial paths.
    let mut merged = read_bookmarks(cases_dir)?;
    let mut identities = merged
        .iter()
        .filter_map(bookmark_identity)
        .collect::<std::collections::HashSet<_>>();
    for mut bookmark in read_bookmarks(legacy_case)? {
        if let Some(object) = bookmark.as_object_mut() {
            for movement in &moves {
                if let Some(full_path) = object.get("fullPath").and_then(Value::as_str) {
                    if let Some(rewritten) =
                        rewrite_bookmark_path(full_path, &movement.source, &movement.destination)
                    {
                        object.insert("fullPath".to_string(), Value::String(rewritten));
                    }
                }
                if object.get("hostId").and_then(Value::as_str)
                    == Some(movement.old_host_id.as_str())
                {
                    object.insert(
                        "hostId".to_string(),
                        Value::String(movement.new_host_id.clone()),
                    );
                }
            }
            // v2 IDs intentionally include the full evidence path. Rebuild
            // only that version after a path rewrite; legacy IDs stay intact
            // for backward-compatible note/remove operations.
            if object
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with("v2:"))
            {
                if let (Some(full_path), Some(table_name), Some(rowid)) = (
                    object.get("fullPath").and_then(Value::as_str),
                    object.get("tableName").and_then(Value::as_str),
                    object.get("rowid").and_then(Value::as_i64),
                ) {
                    let field = object
                        .get("field")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    object.insert(
                        "id".to_string(),
                        Value::String(bookmark_id_v2(full_path, table_name, rowid, field)),
                    );
                }
            }
        }
        if let Some(identity) = bookmark_identity(&bookmark) {
            if identities.insert(identity) {
                merged.push(bookmark);
            }
        } else {
            merged.push(bookmark);
        }
    }
    if !moves.is_empty() || legacy_case.join(BOOKMARKS_FILE).is_file() {
        write_bookmarks_atomic(cases_dir, &merged)?;
    }
    if let Some(entry) = journal
        .cases
        .iter_mut()
        .find(|entry| entry.legacy_case == legacy_case_key)
    {
        entry.phase = "bookmarks_committed".to_string();
    }
    write_migration_journal(cases_dir, &journal)?;

    let archive_root = cases_dir.join(LEGACY_ARCHIVE_DIR);
    std::fs::create_dir_all(&archive_root)?;
    let mut archive = archive_root.join(legacy_case_id);
    let mut suffix = 2usize;
    while archive.exists() {
        archive = archive_root.join(format!("{legacy_case_id}-{suffix}"));
        suffix += 1;
    }
    std::fs::rename(legacy_case, &archive)
        .with_context(|| format!("archive migrated legacy case {}", legacy_case.display()))?;
    journal
        .cases
        .retain(|entry| entry.legacy_case != legacy_case_key);
    write_migration_journal(cases_dir, &journal)?;
    Ok(())
}

/// Ensure canonical `cases/<host_id>/` storage. The operation is idempotent:
/// successfully moved legacy cases live under a recoverable archive, while
/// failures leave their source directory in place for a later safe retry.
pub fn ensure_direct_host_store(cases_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(cases_dir)?;
    let _lock = acquire_migration_lock(cases_dir)?;
    let legacy_cases = std::fs::read_dir(cases_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join("case.json").is_file())
        .collect::<Vec<_>>();
    for legacy_case in legacy_cases {
        migrate_legacy_case(cases_dir, &legacy_case)?;
    }
    Ok(())
}

fn direct_hosts(cases_dir: &Path) -> Result<Vec<Host>> {
    let mut hosts = Vec::new();
    for entry in std::fs::read_dir(cases_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("host.json").is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(path.join("host.json"))?;
        let host = serde_json::from_str::<Host>(&raw)
            .with_context(|| format!("read host metadata {}", path.display()))?;
        let directory_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        anyhow::ensure!(
            host.id == directory_id,
            "host metadata id '{}' does not match directory '{}'",
            host.id,
            directory_id
        );
        hosts.push(host);
    }
    hosts.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    Ok(hosts)
}

fn root_case(hosts: Vec<Host>) -> Case {
    Case {
        id: ROOT_COLLECTION_ID.to_string(),
        name: "분석 호스트".to_string(),
        created_at: hosts
            .first()
            .map(|host| host.created_at.clone())
            .unwrap_or_default(),
        hosts,
    }
}

/// Deprecated compatibility command. It creates no directory and returns the
/// direct root collection so old IPC callers cannot recreate CASE_* nesting.
pub fn create_case(_name: &str, _created_at: &str, cases_dir: &Path) -> Result<Case> {
    ensure_direct_host_store(cases_dir)?;
    Ok(root_case(direct_hosts(cases_dir)?))
}

pub fn create_host(
    _case_id: &str,
    name: &str,
    target_dir: &str,
    created_at: &str,
    cases_dir: &Path,
) -> Result<Host> {
    ensure_direct_host_store(cases_dir)?;
    let host = Host {
        id: unique_host_id(cases_dir, &id_for(name, created_at), None),
        name: name.to_string(),
        target_dir: target_dir.to_string(),
        created_at: created_at.to_string(),
        last_run_at: None,
        last_run_status: None,
        artifacts_run: vec![],
        last_run_duration_secs: None,
    };
    write_host(&host, cases_dir, ROOT_COLLECTION_ID)?;
    Ok(host)
}

pub fn rename_host(_case_id: &str, host_id: &str, name: &str, cases_dir: &Path) -> Result<Host> {
    ensure_direct_host_store(cases_dir)?;
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "host name must not be empty");
    for other in direct_hosts(cases_dir)? {
        anyhow::ensure!(
            other.id == host_id || !other.name.eq_ignore_ascii_case(name),
            "a host named '{name}' is already registered"
        );
    }
    let mut host = load_host(ROOT_COLLECTION_ID, host_id, cases_dir)?;
    host.name = name.to_string();
    write_host(&host, cases_dir, ROOT_COLLECTION_ID)?;
    Ok(host)
}

pub fn load_host(_case_id: &str, host_id: &str, cases_dir: &Path) -> Result<Host> {
    ensure_direct_host_store(cases_dir)?;
    let raw = std::fs::read_to_string(host_meta(cases_dir, ROOT_COLLECTION_ID, host_id))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn list_cases(cases_dir: &Path) -> Result<Vec<Case>> {
    ensure_direct_host_store(cases_dir)?;
    Ok(vec![root_case(direct_hosts(cases_dir)?)])
}

pub fn update_host_status(
    _case_id: &str,
    host_id: &str,
    cases_dir: &Path,
    run_at: &str,
    status: &str,
    artifacts_run: Vec<String>,
    duration_secs: Option<f64>,
) -> Result<()> {
    let mut host = load_host(ROOT_COLLECTION_ID, host_id, cases_dir)?;
    host.last_run_at = Some(run_at.to_string());
    host.last_run_status = Some(status.to_string());
    host.artifacts_run = artifacts_run;
    host.last_run_duration_secs = duration_secs;
    write_host(&host, cases_dir, ROOT_COLLECTION_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "windows-analysis-direct-host-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ))
    }

    #[test]
    fn direct_hosts_are_created_at_cases_root_without_case_nesting() {
        let root = temporary_directory("create");
        let host = create_host(
            "ignored",
            "FIRST",
            "/evidence/first",
            "2026-08-23 12:00:01",
            &root,
        )
        .unwrap();
        assert_eq!(host_dir(&root, "ignored", &host.id), root.join(&host.id));
        assert!(root.join(&host.id).join("host.json").is_file());
        assert!(!root.join("ignored").exists());
        let cases = list_cases(&root).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].id, ROOT_COLLECTION_ID);
        assert_eq!(cases[0].hosts.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_case_migration_moves_results_logs_and_rewrites_bookmarks() {
        let root = temporary_directory("legacy");
        let legacy_case = root.join("CASE_legacy");
        let legacy_host = legacy_case.join("HOST_A");
        std::fs::create_dir_all(legacy_host.join("REGISTRY")).unwrap();
        std::fs::write(
            legacy_case.join("case.json"),
            r#"{"id":"CASE_legacy","name":"legacy","created_at":"2026-08-01 00:00:00"}"#,
        )
        .unwrap();
        std::fs::write(legacy_host.join("REGISTRY/Registry.sqlite"), b"evidence").unwrap();
        std::fs::write(legacy_host.join("parse_report.json"), b"report").unwrap();
        std::fs::create_dir_all(legacy_host.join("parse_logs")).unwrap();
        std::fs::write(legacy_host.join("parse_logs/run.txt"), b"log").unwrap();
        std::fs::write(legacy_host.join("host.json"), r#"{"id":"HOST_A","name":"HOST A","target_dir":"/evidence","created_at":"2026-08-01 00:00:00"}"#).unwrap();
        let old_file = legacy_host
            .join("REGISTRY/Registry.sqlite")
            .to_string_lossy()
            .to_string();
        let legacy_bookmark_id = bookmark_id_v2(&old_file, "Registry", 7, "");
        std::fs::write(legacy_case.join(BOOKMARKS_FILE), serde_json::to_vec(&vec![serde_json::json!({"id":legacy_bookmark_id,"hostId":"HOST_A","fullPath":old_file,"tableName":"Registry","rowid":7,"note":"keep"})]).unwrap()).unwrap();

        let cases = list_cases(&root).unwrap();
        let host = &cases[0].hosts[0];
        let direct = root.join(&host.id);
        assert!(direct.join("REGISTRY/Registry.sqlite").is_file());
        assert!(direct.join("parse_report.json").is_file());
        assert!(direct.join("parse_logs/run.txt").is_file());
        assert!(root.join(LEGACY_ARCHIVE_DIR).join("CASE_legacy").is_dir());
        let bookmarks = read_bookmarks(&root).unwrap();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0]["hostId"], host.id);
        assert_eq!(
            bookmarks[0]["fullPath"],
            direct
                .join("REGISTRY/Registry.sqlite")
                .to_string_lossy()
                .to_string()
        );
        assert_eq!(
            bookmarks[0]["id"],
            bookmark_id_v2(
                &direct.join("REGISTRY/Registry.sqlite").to_string_lossy(),
                "Registry",
                7,
                ""
            )
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migration_lock_serializes_simultaneous_store_bootstrap() {
        let root = temporary_directory("lock");
        std::fs::create_dir_all(&root).unwrap();
        let lock = acquire_migration_lock(&root).unwrap();
        assert!(ensure_direct_host_store(&root).is_err());
        drop(lock);
        ensure_direct_host_store(&root).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn stale_migration_sentinel_does_not_block_recovery() {
        let root = temporary_directory("stale-lock");
        std::fs::create_dir_all(&root).unwrap();
        // Simulates the old create-new sentinel surviving a killed GUI. No
        // process owns an advisory lock for it, so bootstrap must continue.
        std::fs::write(root.join(MIGRATION_LOCK_FILE), b"stale pid=1").unwrap();
        ensure_direct_host_store(&root).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migration_collision_never_overwrites_existing_direct_host() {
        let root = temporary_directory("collision");
        let existing =
            create_host("root", "HOST", "/existing", "2026-08-01 00:00:00", &root).unwrap();
        let legacy_case = root.join("CASE_legacy");
        let legacy_host = legacy_case.join(&existing.id);
        std::fs::create_dir_all(&legacy_host).unwrap();
        std::fs::write(
            legacy_case.join("case.json"),
            r#"{"id":"CASE_legacy","name":"legacy","created_at":"2026-08-01 00:00:00"}"#,
        )
        .unwrap();
        std::fs::write(
            legacy_host.join("host.json"),
            serde_json::to_vec(&existing).unwrap(),
        )
        .unwrap();
        std::fs::write(legacy_host.join("parse_report.json"), b"legacy-report").unwrap();

        let cases = list_cases(&root).unwrap();
        assert_eq!(cases[0].hosts.len(), 2);
        assert!(root.join(&existing.id).join("host.json").is_file());
        let migrated = cases[0]
            .hosts
            .iter()
            .find(|host| host.id != existing.id)
            .unwrap();
        assert!(migrated
            .id
            .starts_with(&format!("{}--CASE_legacy", existing.id)));
        assert_eq!(
            std::fs::read(root.join(&migrated.id).join("parse_report.json")).unwrap(),
            b"legacy-report"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
