//! TaskCache registry evidence (A04).
//!
//! `…\Schedule\TaskCache\Tasks\{GUID}` holds the service's own copy of a task's
//! URI, security descriptor, hash and serialized trigger/action blobs, and
//! `…\TaskCache\Tree\<path>` maps the visible folder tree to those GUIDs.
//! Entries are compared with the definitions collected in this run by task
//! path only; a registry entry without a definition file is reported as such
//! and never treated as proof of deletion or of hiding.
use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};

use super::{normalize_task_path, DefinitionIndex};
use crate::derived::{Ctx, DerivedDb};

const MARKER: &str = "\\schedule\\taskcache\\";

struct Entry {
    /// value name -> (value data, value hex, rowid)
    values: BTreeMap<String, (String, String, i64)>,
    last_write: String,
    source_file: String,
    key_rowid: i64,
}

fn software_hives(ctx: &Ctx) -> Result<Vec<std::path::PathBuf>> {
    let directory = ctx.out_dir.join("REGISTRY");
    let mut paths = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("");
                path.extension().is_some_and(|ext| ext == "sqlite")
                    && (stem.eq_ignore_ascii_case("SOFTWARE")
                        || stem.strip_prefix("SOFTWARE_").is_some_and(|rest| {
                            !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
                        }))
            })
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    paths.sort();
    Ok(paths)
}

/// `…\TaskCache\Tasks\{GUID}` -> ("tasks", "{GUID}"), `…\Tree\A\B` ->
/// ("tree", "A\B"), `…\Boot\{GUID}` -> ("boot", "{GUID}").
fn classify(key_path: &str) -> Option<(&'static str, String)> {
    let lower = key_path.to_ascii_lowercase();
    let at = lower.find(MARKER)?;
    let rest = &key_path[at + MARKER.len()..];
    let (scope, remainder) = rest.split_once('\\')?;
    if remainder.is_empty() {
        return None;
    }
    let scope = match scope.to_ascii_lowercase().as_str() {
        "tasks" => "tasks",
        "tree" => "tree",
        "boot" => "boot",
        "logon" => "logon",
        "plain" => "plain",
        "maintenance" => "maintenance",
        _ => return None,
    };
    if scope == "tree" {
        Some((scope, remainder.to_string()))
    } else {
        // Only the GUID level identifies an entry; deeper keys belong to it.
        Some((scope, remainder.split('\\').next()?.to_string()))
    }
}

pub(super) fn populate(ctx: &Ctx, db: &DerivedDb, index: &DefinitionIndex) -> Result<()> {
    for path in software_hives(ctx)? {
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut query = conn.prepare(
            "SELECT rowid,last_write,key_path,value_name,value_data,value_data_hex,entry_kind,_source_file
             FROM Registry WHERE lower(key_path) LIKE '%\\schedule\\taskcache\\%' ORDER BY rowid",
        )?;
        let mut rows = query.query([])?;
        // (scope, identity) -> entry
        let mut entries: BTreeMap<(&'static str, String), Entry> = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let key_path: String = row.get(2)?;
            let Some((scope, identity)) = classify(&key_path) else {
                continue;
            };
            let entry = entries.entry((scope, identity)).or_insert_with(|| Entry {
                values: BTreeMap::new(),
                last_write: String::new(),
                source_file: String::new(),
                key_rowid: 0,
            });
            let rowid: i64 = row.get(0)?;
            let last_write: Option<String> = row.get(1)?;
            let name: Option<String> = row.get(3)?;
            let kind: Option<String> = row.get(6)?;
            if entry.source_file.is_empty() {
                entry.source_file = row.get::<_, Option<String>>(7)?.unwrap_or_default();
            }
            if let Some(stamp) = last_write.filter(|value| !value.is_empty()) {
                if entry.last_write.is_empty() {
                    entry.last_write = stamp;
                }
            }
            if kind.as_deref() == Some("key") || name.as_deref().unwrap_or("").is_empty() {
                if entry.key_rowid == 0 {
                    entry.key_rowid = rowid;
                }
                continue;
            }
            // Deeper subkeys keep their own values out of the entry's identity.
            let depth_ok = {
                let lower = key_path.to_ascii_lowercase();
                let at = lower.find(MARKER).unwrap_or(0) + MARKER.len();
                let rest = &key_path[at..];
                match scope {
                    "tree" => true,
                    _ => rest.matches('\\').count() == 1,
                }
            };
            if !depth_ok {
                continue;
            }
            entry.values.insert(
                name.unwrap_or_default(),
                (
                    row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    rowid,
                ),
            );
        }

        // GUIDs that actually have a Tasks key, for the Tree/scope comparison.
        let task_guids: HashMap<String, String> = entries
            .iter()
            .filter(|((scope, _), _)| *scope == "tasks")
            .map(|((_, guid), entry)| {
                (
                    guid.to_ascii_uppercase(),
                    entry
                        .values
                        .get("URI")
                        .or_else(|| entry.values.get("Path"))
                        .map(|(data, _, _)| data.clone())
                        .unwrap_or_default(),
                )
            })
            .collect();

        for ((scope, identity), entry) in &entries {
            let value = |name: &str| entry.values.get(name).map(|(data, _, _)| data.clone());
            let hex = |name: &str| {
                entry.values.get(name).map(|(data, hex, _)| {
                    if hex.is_empty() {
                        data.clone()
                    } else {
                        hex.clone()
                    }
                })
            };
            let (guid, tree_path, uri) = match *scope {
                "tasks" => (
                    Some(identity.clone()),
                    None,
                    value("URI").or_else(|| value("Path")),
                ),
                "tree" => {
                    let id = value("Id").unwrap_or_default();
                    (
                        (!id.is_empty()).then(|| id.clone()),
                        Some(identity.clone()),
                        Some(format!("\\{identity}")),
                    )
                }
                _ => {
                    let guid = identity.to_ascii_uppercase();
                    (
                        Some(identity.clone()),
                        None,
                        task_guids.get(&guid).cloned().filter(|uri| !uri.is_empty()),
                    )
                }
            };
            let normalized = uri.as_deref().map(normalize_task_path);
            let (mut matched, mut status) = match &normalized {
                Some(path) => super::match_definition(index, path),
                None => (None, "task_path_unknown".to_string()),
            };
            let mut basis = "taskcache_uri_vs_definition_path";
            // Structural axis kept apart so a definition match is never hidden.
            let mut tree_state = None;
            if *scope == "tree" {
                let id = value("Id").unwrap_or_default().to_ascii_uppercase();
                if id.is_empty() {
                    // A tree node without an Id is a folder, not a task.
                    matched = None;
                    status = "tree_folder_node".into();
                    basis = "tree key has no Id value";
                    tree_state = Some("folder_node");
                } else if task_guids.contains_key(&id) {
                    tree_state = Some("tasks_key_present");
                } else {
                    tree_state = Some("tasks_key_missing");
                }
            }
            let primary = entry
                .values
                .get("URI")
                .or_else(|| entry.values.get("Id"))
                .or_else(|| entry.values.get("Path"))
                .map(|(_, _, rowid)| *rowid)
                .unwrap_or(entry.key_rowid);
            let source = if primary > 0 {
                ctx.facts.source_from_row(
                    &path,
                    "Registry",
                    primary,
                    (!entry.source_file.is_empty()).then_some(entry.source_file.as_str()),
                    Some("TaskCache"),
                )?
            } else {
                None
            };
            db.conn().execute(
                "INSERT INTO TaskRegistryEntries(entry_id,host_id,dataset_id,scope,guid,registry_path,key_last_write,
                 tree_path,task_uri,task_path_normalized,security_descriptor,hash_hex,id_value,index_value,schema_value,
                 version_value,triggers_hex,actions_hex,dynamic_info_hex,user_sid,matched_record_id,match_status,match_basis,
                 tree_node_state,source_dataset_id,source_db,source_table,source_rowid,source_file)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    ctx.host_id,
                    ctx.dataset_id,
                    scope,
                    guid,
                    format!("TaskCache\\{}\\{identity}", title(scope)),
                    (!entry.last_write.is_empty()).then_some(entry.last_write.as_str()),
                    tree_path,
                    uri,
                    normalized,
                    value("SecurityDescriptor"),
                    hex("Hash"),
                    value("Id"),
                    value("Index"),
                    value("Schema"),
                    value("Version"),
                    hex("Triggers"),
                    hex("Actions"),
                    hex("DynamicInfo"),
                    value("UserSid"),
                    matched,
                    status,
                    basis,
                    tree_state,
                    source.as_ref().map(|source| source.dataset.clone()),
                    source.as_ref().map(|source| source.db.clone()),
                    source.as_ref().map(|source| source.table.clone()),
                    source.as_ref().map(|source| source.rowid),
                    source.as_ref().and_then(|source| source.file.clone()),
                ],
            )?;
        }
    }
    Ok(())
}

fn title(scope: &str) -> &'static str {
    match scope {
        "tasks" => "Tasks",
        "tree" => "Tree",
        "boot" => "Boot",
        "logon" => "Logon",
        "plain" => "Plain",
        _ => "Maintenance",
    }
}

// ---------------------------------------------------------------------------
// A03 — ComHandler ClassId vs the same host's COM registrations.
//
// The current registry state is compared with the task's declared ClassId. It
// tells which server is registered *now*; it is never evidence of the DLL a
// past run loaded, and no effective-precedence (machine vs user vs WOW view)
// is decided here — each found registration is stored as its own candidate.
// ---------------------------------------------------------------------------

const CLSID_MARKER: &str = "\\clsid\\{";

/// Hives that can carry class registrations. RegBack copies are excluded, as
/// everywhere else in this project.
fn class_hives(ctx: &Ctx) -> Result<Vec<std::path::PathBuf>> {
    let directory = ctx.out_dir.join("REGISTRY");
    let mut paths = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("");
                let upper = stem.to_ascii_uppercase();
                path.extension().is_some_and(|ext| ext == "sqlite")
                    && !upper.contains("REGBACK")
                    && (upper.starts_with("SOFTWARE")
                        || upper.ends_with("NTUSER.DAT")
                        || upper.ends_with("USRCLASS.DAT"))
            })
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    paths.sort();
    Ok(paths)
}

fn hive_scope(stem: &str) -> &'static str {
    let upper = stem.to_ascii_uppercase();
    if upper.starts_with("SOFTWARE") {
        "machine"
    } else if upper.ends_with("NTUSER.DAT") || upper.ends_with("USRCLASS.DAT") {
        "user"
    } else {
        "unknown"
    }
}

/// `…\CLSID\{guid}` or `…\CLSID\{guid}\<ServerKind>` -> (guid, server kind).
fn class_key(key_path: &str) -> Option<(String, Option<String>)> {
    let lower = key_path.to_ascii_lowercase();
    let at = lower.find(CLSID_MARKER)?;
    let rest = &key_path[at + CLSID_MARKER.len() - 1..];
    let mut parts = rest.splitn(3, '\\');
    let guid = parts.next()?.to_string();
    if !guid.ends_with('}') {
        return None;
    }
    match parts.next() {
        // Deeper keys (e.g. InprocServer32\Config) belong to their server key.
        Some(kind) if parts.next().is_none() => Some((guid, Some(kind.to_string()))),
        Some(_) => None,
        None => Some((guid, None)),
    }
}

struct ClassEntry {
    values: BTreeMap<String, (String, i64)>,
    last_write: String,
    source_file: String,
}

pub(super) fn populate_com(ctx: &Ctx, db: &DerivedDb, index: &DefinitionIndex) -> Result<()> {
    if index.com_handlers().is_empty() {
        return Ok(());
    }
    let mut wanted: HashMap<String, Vec<(&str, i64, &str)>> = HashMap::new();
    for (record_id, ordinal, class_id) in index.com_handlers() {
        wanted
            .entry(class_id.trim().to_ascii_uppercase())
            .or_default()
            .push((record_id.as_str(), *ordinal, class_id.as_str()));
    }
    let mut matched: HashMap<String, usize> = HashMap::new();

    for path in class_hives(ctx)? {
        let stem = crate::derived::stem_of(&path);
        let scope = hive_scope(&stem);
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut query = conn.prepare(
            "SELECT rowid,last_write,key_path,value_name,value_data,entry_kind,_source_file
             FROM Registry WHERE lower(key_path) LIKE '%\\clsid\\{%' ORDER BY rowid",
        )?;
        let mut rows = query.query([])?;
        // (key path, guid, server kind) -> values
        let mut entries: BTreeMap<(String, String, Option<String>), ClassEntry> = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let key_path: String = row.get(2)?;
            let Some((guid, kind)) = class_key(&key_path) else {
                continue;
            };
            let upper = guid.to_ascii_uppercase();
            if !wanted.contains_key(&upper) {
                continue;
            }
            let entry = entries
                .entry((key_path.clone(), upper, kind))
                .or_insert_with(|| ClassEntry {
                    values: BTreeMap::new(),
                    last_write: String::new(),
                    source_file: String::new(),
                });
            if entry.source_file.is_empty() {
                entry.source_file = row.get::<_, Option<String>>(6)?.unwrap_or_default();
            }
            if entry.last_write.is_empty() {
                entry.last_write = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            }
            let name: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
            if row.get::<_, Option<String>>(5)?.as_deref() == Some("key") {
                continue;
            }
            entry.values.insert(
                name,
                (
                    row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    row.get(0)?,
                ),
            );
        }

        for ((key_path, guid, kind), entry) in &entries {
            let view = if key_path.to_ascii_lowercase().contains("wow6432node") {
                "wow6432node"
            } else {
                "native"
            };
            let default = entry
                .values
                .get("(default)")
                .or_else(|| entry.values.get(""));
            let server_path = kind.as_ref().and_then(|_| default.map(|(data, _)| data.clone()));
            let class_name = if kind.is_none() {
                default.map(|(data, _)| data.clone())
            } else {
                None
            };
            let rowid = default
                .map(|(_, rowid)| *rowid)
                .or_else(|| entry.values.values().next().map(|(_, rowid)| *rowid));
            let source = match rowid {
                Some(rowid) => ctx.facts.source_from_row(
                    &path,
                    "Registry",
                    rowid,
                    (!entry.source_file.is_empty()).then_some(entry.source_file.as_str()),
                    Some("COM registration"),
                )?,
                None => None,
            };
            let resolved = match &server_path {
                Some(value) => ctx.meta.resolve_path(value, None),
                None => crate::derived::Cell::Null,
            };
            let resolved = match resolved {
                crate::derived::Cell::Text(text) => Some(text),
                _ => None,
            };
            for (record_id, ordinal, class_id_raw) in wanted.get(guid).into_iter().flatten() {
                *matched.entry((*record_id).to_string() + guid).or_default() += 1;
                db.conn().execute(
                    "INSERT INTO TaskComRegistrations(registration_id,host_id,dataset_id,record_id,action_ordinal,class_id,
                     hive,hive_scope,registry_view,key_path,server_kind,class_name,server_path_raw,server_path_resolved,
                     threading_model,key_last_write,match_status,match_basis,
                     source_dataset_id,source_db,source_table,source_rowid,source_file)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,'matched_registration',?17,?18,?19,?20,?21,?22)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        ctx.host_id,
                        ctx.dataset_id,
                        record_id,
                        ordinal,
                        class_id_raw,
                        stem,
                        scope,
                        view,
                        key_path,
                        kind,
                        class_name,
                        server_path,
                        resolved,
                        entry.values.get("ThreadingModel").map(|(data, _)| data.clone()),
                        (!entry.last_write.is_empty()).then_some(entry.last_write.as_str()),
                        "task action ClassId equals a CLSID key in this host's collected registry; current registration, not past execution",
                        source.as_ref().map(|source| source.dataset.clone()),
                        source.as_ref().map(|source| source.db.clone()),
                        source.as_ref().map(|source| source.table.clone()),
                        source.as_ref().map(|source| source.rowid),
                        source.as_ref().and_then(|source| source.file.clone()),
                    ],
                )?;
            }
        }
    }

    // ClassIds with no registration in this collection stay explicit.
    for (guid, actions) in &wanted {
        for (record_id, ordinal, class_id_raw) in actions {
            if matched.contains_key(&((*record_id).to_string() + guid)) {
                continue;
            }
            db.conn().execute(
                "INSERT INTO TaskComRegistrations(registration_id,host_id,dataset_id,record_id,action_ordinal,class_id,
                 match_status,match_basis)
                 VALUES(?1,?2,?3,?4,?5,?6,'no_registration_found',?7)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    ctx.host_id,
                    ctx.dataset_id,
                    record_id,
                    ordinal,
                    class_id_raw,
                    "no CLSID key for this ClassId in the collected registry hives; absence of a collected key is not proof of removal",
                ],
            )?;
        }
    }
    Ok(())
}
