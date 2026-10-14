//! Stored Windows metadata derived from raw registry facts.
//! Conflicts retain candidates; resolution never uses the analyst's environment.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags};
use uuid::Uuid;

use crate::sam::{le_u16, machine_sid_from_v, sam_v_field, unhex, utf16le, well_known_account};

const REGISTRY_DIR: &str = "REGISTRY";
const REG_TABLE: &str = "Registry";
const OVERVIEW_DIR: &str = "_OVERVIEW";
const METADATA_DB: &str = "Metadata.sqlite";
const ALIAS_MEMBERS_MARKER: &str = "\\aliases\\members\\";

// Equal-rank disagreement remains a conflict.
const RANK_PRIMARY: u8 = 0;
const RANK_SECONDARY: u8 = 1;

// ---------------------------------------------------------------------------
// Source evidence
// ---------------------------------------------------------------------------

/// Actual registry row coordinates; never synthetic rowids.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceRef {
    /// source_records.source_artifact (Registry, SRUM).
    artifact: &'static str,
    db: String,
    table: String,
    rowid: i64,
    field: Option<String>,
    record_key: Option<String>,
    file: Option<String>,
    label: Option<String>,
}

impl SourceRef {
    fn same_target(&self, other: &SourceRef) -> bool {
        self.db == other.db && self.rowid == other.rowid && self.field == other.field
    }
}

// ---------------------------------------------------------------------------
// Value selection
// ---------------------------------------------------------------------------

struct Cand {
    value: String,
    rank: u8,
    label: String,
    src: SourceRef,
    observed_at: Option<String>,
}

#[derive(Default)]
struct Field {
    cands: Vec<Cand>,
}

// Candidate ordinals index the ordered source references.
struct Picked {
    value: Option<String>,
    raw: Option<String>,
    status: &'static str,
    observed_at: Option<String>,
    selection_reason: Option<String>,
    refs: Vec<SourceRef>,
    candidates: Vec<(String, Option<i64>, String)>,
}

impl Field {
    fn push(
        &mut self,
        value: &str,
        rank: u8,
        label: &str,
        src: SourceRef,
        observed_at: Option<String>,
    ) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        self.cands.push(Cand {
            value: value.to_string(),
            rank,
            label: label.to_string(),
            src,
            observed_at,
        });
    }

    fn is_empty(&self) -> bool {
        self.cands.is_empty()
    }

    fn pick(self) -> Picked {
        let mut refs: Vec<SourceRef> = Vec::new();
        let mut ordinal_of: Vec<i64> = Vec::with_capacity(self.cands.len());
        for cand in &self.cands {
            match refs.iter().position(|r| r.same_target(&cand.src)) {
                Some(i) => ordinal_of.push(i as i64),
                None => {
                    refs.push(cand.src.clone());
                    ordinal_of.push((refs.len() - 1) as i64);
                }
            }
        }
        if self.cands.is_empty() {
            return Picked {
                value: None,
                raw: None,
                status: "missing",
                observed_at: None,
                selection_reason: None,
                refs,
                candidates: Vec::new(),
            };
        }
        let best = self.cands.iter().map(|c| c.rank).min().unwrap_or(0);
        let top: Vec<usize> = (0..self.cands.len())
            .filter(|i| self.cands[*i].rank == best)
            .collect();
        let mut distinct: Vec<usize> = Vec::new();
        for i in &top {
            if !distinct
                .iter()
                .any(|j| self.cands[*j].value.eq_ignore_ascii_case(&self.cands[*i].value))
            {
                distinct.push(*i);
            }
        }
        if distinct.len() > 1 {
            // Preserve conflicting candidates rather than choosing one.
            let candidates = distinct
                .iter()
                .map(|i| {
                    (
                        self.cands[*i].value.clone(),
                        Some(ordinal_of[*i]),
                        format!("동급 근거 충돌 — {}", self.cands[*i].label),
                    )
                })
                .collect();
            return Picked {
                value: None,
                raw: None,
                status: "conflict",
                observed_at: None,
                selection_reason: Some(format!("동급 근거 {}건이 서로 다름", distinct.len())),
                refs,
                candidates,
            };
        }
        let chosen = distinct[0];
        let mut candidates = Vec::new();
        for i in 0..self.cands.len() {
            if i == chosen {
                continue;
            }
            if self.cands[i].value.eq_ignore_ascii_case(&self.cands[chosen].value) {
                continue;
            }
            candidates.push((
                self.cands[i].value.clone(),
                Some(ordinal_of[i]),
                format!("미선택(낮은 우선순위) — {}", self.cands[i].label),
            ));
        }
        Picked {
            value: Some(self.cands[chosen].value.clone()),
            raw: Some(self.cands[chosen].value.clone()),
            status: "resolved",
            observed_at: self.cands[chosen].observed_at.clone(),
            selection_reason: Some(self.cands[chosen].label.clone()),
            refs,
            candidates,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry facts
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum HiveKind {
    System,
    Software,
    Sam,
    Security,
    User,
    Other,
}

struct RegRow {
    rowid: i64,
    key_path: String,
    key_low: String,
    value_name: String,
    value_type: String,
    value_data: String,
    value_hex: String,
    last_write: String,
    source_file: String,
}

struct Hive {
    kind: HiveKind,
    stem: String,
    db_rel: String,
    dataset_id: String,
    rows: Vec<RegRow>,
    active_set: String,
}

impl Hive {
    // Exclude inactive ControlSets without excluding unrelated keys.
    fn in_active_set(&self, row: &RegRow) -> bool {
        if !row.key_low.contains("\\controlset") {
            return true;
        }
        row.key_low.contains(&self.active_set)
    }

    fn source_ref(&self, row: &RegRow, field: &str) -> SourceRef {
        SourceRef {
            artifact: "Registry",
            db: self.db_rel.clone(),
            table: REG_TABLE.to_string(),
            rowid: row.rowid,
            field: Some(field.to_string()),
            record_key: Some(format!("{}::{}::{}", self.stem, REG_TABLE, row.rowid)),
            file: if row.source_file.is_empty() {
                None
            } else {
                Some(row.source_file.clone())
            },
            label: Some(if row.value_name.is_empty() {
                row.key_path.clone()
            } else {
                format!("{}\\{}", row.key_path, row.value_name)
            }),
        }
    }

    fn observed(&self, row: &RegRow) -> Option<String> {
        if row.last_write.trim().is_empty() {
            None
        } else {
            Some(row.last_write.clone())
        }
    }

    fn values(&self, key_suffix: &str, value_name: &str) -> Vec<&RegRow> {
        let suffix = key_suffix.to_lowercase();
        self.rows
            .iter()
            .filter(|r| self.in_active_set(r))
            .filter(|r| r.key_low.ends_with(&suffix))
            .filter(|r| r.value_name.eq_ignore_ascii_case(value_name))
            .filter(|r| !r.value_data.trim().is_empty())
            .collect()
    }
}

// Keep RegBack in facts, not in current-state metadata.
fn is_regback(stem: &str) -> bool {
    let low = stem.to_lowercase();
    strip_uniq_suffix(&low).ends_with("_regback")
}

fn strip_uniq_suffix(stem: &str) -> &str {
    match stem.rsplit_once('_') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => stem,
    }
}

// Compatibility and installation mirrors are not independent evidence.
fn is_mirror_key(key_low: &str) -> bool {
    key_low.contains("wow6432node") || key_low.contains("\\pnpresources\\")
}

fn hive_kind(stem: &str) -> HiveKind {
    let base = strip_uniq_suffix(&stem.to_lowercase()).to_string();
    if base == "system" {
        HiveKind::System
    } else if base == "software" {
        HiveKind::Software
    } else if base == "sam" {
        HiveKind::Sam
    } else if base == "security" {
        HiveKind::Security
    } else if base.ends_with("ntuser.dat") || base.ends_with("usrclass.dat") {
        HiveKind::User
    } else {
        HiveKind::Other
    }
}

fn active_control_set(rows: &[RegRow]) -> String {
    rows.iter()
        .find(|r| r.key_low.ends_with("\\select") && r.value_name.eq_ignore_ascii_case("Current"))
        .and_then(|r| r.value_data.trim().parse::<u32>().ok())
        .filter(|n| *n > 0)
        .map(|n| format!("controlset{:03}", n))
        .unwrap_or_else(|| "controlset001".into())
}

// Missing generation stamps require reparse; unrelated databases are skipped.
fn load_hive(db: &Path, target: &Path) -> Result<Option<Hive>> {
    let Some(stem) = db.file_stem().map(|s| s.to_string_lossy().to_string()) else {
        return Ok(None);
    };
    if is_regback(&stem) {
        return Ok(None);
    }
    let con = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db.display()))?;
    // Only a database without a Registry table is not a hive (e.g. RegistryInputs).
    let has_registry: bool = con
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [REG_TABLE],
            |r| r.get(0),
        )
        .with_context(|| format!("read schema {}", db.display()))?;
    if !has_registry {
        return Ok(None);
    }
    let query = format!(
        "SELECT rowid, key_path, value_name, value_type, value_data, last_write, \
         _source_file, _recovery, value_data_hex FROM \"{REG_TABLE}\""
    );
    let mut stmt = con
        .prepare(&query)
        .with_context(|| format!("read {}", db.display()))?;
    let dataset_id = crate::derived::facts_dataset_id(db)?;
    let mut rows = Vec::new();
    let mut q = stmt.query([]).with_context(|| format!("read {}", db.display()))?;
    while let Some(r) = q.next().with_context(|| format!("read {}", db.display()))? {
        // Historical recovered cells must not override current settings.
        let recovery: String = r.get(7).unwrap_or_default();
        if !recovery.is_empty() && recovery != "live" {
            continue;
        }
        let key_path: String = r.get(1).unwrap_or_default();
        let key_low = key_path.to_lowercase();
        // Raw bytes are kept only where the type field is not a real type.
        let value_hex = if key_low.contains(ALIAS_MEMBERS_MARKER) {
            r.get::<_, Option<String>>(8).ok().flatten().unwrap_or_default()
        } else {
            String::new()
        };
        let row = RegRow {
            rowid: r.get(0).unwrap_or_default(),
            key_low,
            value_hex,
            key_path,
            value_name: r.get(2).unwrap_or_default(),
            value_type: r.get(3).unwrap_or_default(),
            value_data: r.get(4).unwrap_or_default(),
            last_write: r.get(5).unwrap_or_default(),
            source_file: evidence_path(target, &r.get::<_, String>(6).unwrap_or_default()),
        };
        rows.push(row);
    }
    drop(q);
    drop(stmt);
    let active_set = active_control_set(&rows);
    Ok(Some(Hive {
        kind: hive_kind(&stem),
        db_rel: format!("{REGISTRY_DIR}/{stem}.sqlite"),
        dataset_id,
        stem,
        rows,
        active_set,
    }))
}

// Relative evidence paths are rooted at the collected target.
fn evidence_path(target: &Path, recorded: &str) -> String {
    let recorded = recorded.trim();
    if recorded.is_empty() {
        return String::new();
    }
    let path = Path::new(recorded);
    if path.is_absolute() {
        recorded.to_string()
    } else {
        target.join(path).to_string_lossy().to_string()
    }
}

struct Facts {
    hives: Vec<Hive>,
}

impl Facts {
    fn load(out_dir: &Path, target: &Path) -> Result<Self> {
        let dir = out_dir.join(REGISTRY_DIR);
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "sqlite"))
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        let mut hives = Vec::new();
        for path in &files {
            if let Some(hive) = load_hive(path, target)? {
                hives.push(hive);
            }
        }
        Ok(Self { hives })
    }

    fn of(&self, kind: HiveKind) -> impl Iterator<Item = &Hive> {
        self.hives.iter().filter(move |h| h.kind == kind)
    }
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn filetime(ticks: u64) -> Option<String> {
    if ticks == 0 {
        None
    } else {
        let text = crate::time::fmt_filetime(ticks as i64);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }
}

fn unix_time(value: &str) -> Option<String> {
    let secs: i64 = value.trim().parse().ok()?;
    if secs <= 0 {
        return None;
    }
    let text = crate::time::fmt_unix(secs);
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

// Decode raw multi-values, never comma-joined display values.
fn multi_values(raw: &str) -> Vec<String> {
    let s = raw.trim();
    if s.is_empty() {
        return Vec::new();
    }
    if s.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(s) {
            return v
                .into_iter()
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
        }
    }
    s.split([',', ' ', ';'])
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

// Unspecified and broadcast addresses are not assigned host addresses.
fn is_placeholder_address(addr: &str) -> bool {
    matches!(addr.trim(), "" | "0.0.0.0" | "::" | "255.255.255.255")
}

fn address_family(addr: &str) -> Option<i64> {
    if addr.contains(':') {
        Some(6)
    } else if addr.contains('.') {
        Some(4)
    } else {
        None
    }
}

// Reject non-contiguous IPv4 masks.
fn prefix_from_mask(mask: &str) -> Option<i64> {
    let parts: Vec<u8> = mask
        .split('.')
        .map(|p| p.trim().parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    if parts.len() != 4 {
        return None;
    }
    let bits = u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]);
    let ones = bits.leading_ones();
    if bits.checked_shl(ones).unwrap_or(0) != 0 {
        return None;
    }
    Some(ones as i64)
}

fn normalize_mac(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if cleaned.len() != 12 {
        return (!raw.trim().is_empty()).then(|| raw.trim().to_string());
    }
    Some(
        cleaned
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn sid_rid(sid: &str) -> Option<i64> {
    sid.rsplit('-').next()?.parse::<i64>().ok()
}

/// Virtual service (S-1-5-80) and IIS app pool (S-1-5-82) SIDs are the SHA-1 of
/// the uppercase service / lowercase pool name (UTF-16LE) as five LE u32s.
fn virtual_sid(prefix: &str, name: &str) -> String {
    use sha1::{Digest, Sha1};
    let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let digest = Sha1::digest(&bytes);
    let mut sid = prefix.to_string();
    for chunk in digest.chunks_exact(4) {
        sid.push_str(&format!("-{}", u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])));
    }
    sid
}

fn service_sid(name: &str) -> String {
    virtual_sid("S-1-5-80", &name.to_uppercase())
}

/// (domain, name, name_source) only when `candidate` hashes to `sid`.
fn hashed_virtual_account(sid: &str, candidate: &str) -> Option<(&'static str, String, &'static str)> {
    let upper = sid.to_uppercase();
    let (expected, domain, source) = if upper.starts_with("S-1-5-80-") {
        (service_sid(candidate), "NT SERVICE", "service_sid_hash")
    } else if upper.starts_with("S-1-5-82-") {
        (virtual_sid("S-1-5-82", &candidate.to_lowercase()), "IIS APPPOOL", "apppool_sid_hash")
    } else {
        return None;
    };
    (expected == upper).then(|| (domain, candidate.to_string(), source))
}

/// Fixed Microsoft patterns: S-1-5-90-0-N = Window Manager\DWM-N,
/// S-1-5-96-0-N = Font Driver Host\UMFD-N (session N). Returns (domain, name).
fn fixed_virtual_account(sid: &str) -> Option<(&'static str, String)> {
    let upper = sid.to_uppercase();
    let (domain, prefix, session) = if let Some(n) = upper.strip_prefix("S-1-5-90-0-") {
        ("Window Manager", "DWM", n)
    } else if let Some(n) = upper.strip_prefix("S-1-5-96-0-") {
        ("Font Driver Host", "UMFD", n)
    } else {
        return None;
    };
    session.parse::<u32>().ok().map(|n| (domain, format!("{prefix}-{n}")))
}

fn profile_folder_of(raw_path: &str) -> Option<&str> {
    raw_path.trim().trim_end_matches('\\').rsplit('\\').next().filter(|f| !f.is_empty())
}

/// One stored virtual account (kind='virtual_account'): name proven by SID
/// structure, kept out of the host account list.
fn virtual_account_row(sid: &str, domain: &str, name: &str, source: &str, reason: &str, src: SourceRef) -> MetaRow {
    let mut row = MetaRow::new("virtual_account", "machine", &sid.to_lowercase());
    row.value = Some(format!("{domain}\\{name}"));
    row.account_name = row.value.clone();
    row.account_sid = Some(sid.to_string());
    row.domain = Some(domain.to_string());
    row.account_kind = Some("well_known".into());
    row.name_source = Some(source.to_string());
    row.status = "resolved";
    row.selection_reason = Some(reason.to_string());
    row.refs.push(src);
    row
}

// ---------------------------------------------------------------------------
// Metadata rows
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MetaRow {
    kind: &'static str,
    scope: String,
    key: String,
    value: Option<String>,
    raw_value: Option<String>,
    status: &'static str,
    observed_at: Option<String>,
    account_name: Option<String>,
    account_sid: Option<String>,
    full_name: Option<String>,
    domain: Option<String>,
    account_kind: Option<String>,
    name_source: Option<String>,
    rid: Option<i64>,
    rid_sam: Option<i64>,
    home_directory: Option<String>,
    profile_path: Option<String>,
    profile_path_resolved: Option<String>,
    created: Option<String>,
    last_login: Option<String>,
    password_last_set: Option<String>,
    last_failed_login: Option<String>,
    login_count: Option<i64>,
    failed_login_count: Option<i64>,
    disabled: Option<i64>,
    special_account: Option<i64>,
    account_flags: Option<String>,
    interface_id: Option<String>,
    interface_name: Option<String>,
    mac_address: Option<String>,
    network_profile: Option<String>,
    dhcp_enabled: Option<i64>,
    dhcp_server: Option<String>,
    lease_obtained: Option<String>,
    lease_terminates: Option<String>,
    details: serde_json::Map<String, serde_json::Value>,
    selection_reason: Option<String>,
    refs: Vec<SourceRef>,
    candidates: Vec<(String, Option<i64>, String)>,
    addresses: Vec<AddressRow>,
    gateways: Vec<(String, Option<i64>)>,
    dns: Vec<String>,
    groups: Vec<(Option<String>, Option<String>)>,
}

struct AddressRow {
    address: String,
    family: Option<i64>,
    prefix_length: Option<i64>,
    subnet_mask: Option<String>,
}

impl MetaRow {
    fn new(kind: &'static str, scope: &str, key: &str) -> Self {
        Self {
            kind,
            scope: scope.to_string(),
            key: key.to_string(),
            status: "missing",
            ..Default::default()
        }
    }

    // Keep value, resolution state, evidence and candidates together.
    fn apply(&mut self, picked: Picked) {
        self.value = picked.value;
        self.raw_value = picked.raw;
        self.status = picked.status;
        self.observed_at = picked.observed_at;
        self.selection_reason = picked.selection_reason;
        self.refs = picked.refs;
        self.candidates = picked.candidates;
    }

    fn add_ref(&mut self, src: SourceRef) -> i64 {
        match self.refs.iter().position(|r| r.same_target(&src)) {
            Some(i) => i as i64,
            None => {
                self.refs.push(src);
                (self.refs.len() - 1) as i64
            }
        }
    }
}

struct Writer<'a> {
    conn: &'a Connection,
    host_id: String,
    dataset_id: String,
    source_dataset: HashMap<String, String>,
    seen: BTreeSet<(String, String, String)>,
    count: usize,
}

impl<'a> Writer<'a> {
    fn new(conn: &'a Connection, host_id: &str, dataset_id: &str, facts: &Facts) -> Self {
        let source_dataset = facts
            .hives
            .iter()
            .map(|h| (h.db_rel.clone(), h.dataset_id.clone()))
            .collect();
        Self {
            conn,
            host_id: host_id.to_string(),
            dataset_id: dataset_id.to_string(),
            source_dataset,
            seen: BTreeSet::new(),
            count: 0,
        }
    }

    fn write(&mut self, row: MetaRow) -> Result<Option<String>> {
        let unique = (row.kind.to_string(), row.scope.clone(), row.key.clone());
        if !self.seen.insert(unique) {
            // Preserve UNIQUE(kind, scope, key).
            return Ok(None);
        }
        let metadata_id = Uuid::new_v4().to_string();
        let details = if row.details.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(row.details.clone()).to_string())
        };
        let text = |v: &Option<String>| match v {
            Some(s) => SqlValue::Text(s.clone()),
            None => SqlValue::Null,
        };
        let int = |v: &Option<i64>| match v {
            Some(n) => SqlValue::Integer(*n),
            None => SqlValue::Null,
        };
        let params: Vec<SqlValue> = vec![
            SqlValue::Text(metadata_id.clone()),
            SqlValue::Text(self.host_id.clone()),
            SqlValue::Text(self.dataset_id.clone()),
            SqlValue::Text(row.kind.to_string()),
            SqlValue::Text(row.scope.clone()),
            SqlValue::Text(row.key.clone()),
            text(&row.value),
            text(&row.raw_value),
            SqlValue::Text(row.status.to_string()),
            text(&row.observed_at),
            text(&row.account_name),
            text(&row.account_sid),
            text(&row.full_name),
            text(&row.domain),
            text(&row.account_kind),
            text(&row.name_source),
            int(&row.rid),
            int(&row.rid_sam),
            text(&row.home_directory),
            text(&row.profile_path),
            text(&row.profile_path_resolved),
            text(&row.created),
            text(&row.last_login),
            text(&row.password_last_set),
            text(&row.last_failed_login),
            int(&row.login_count),
            int(&row.failed_login_count),
            int(&row.disabled),
            int(&row.special_account),
            text(&row.account_flags),
            text(&row.interface_id),
            text(&row.interface_name),
            text(&row.mac_address),
            text(&row.network_profile),
            int(&row.dhcp_enabled),
            text(&row.dhcp_server),
            text(&row.lease_obtained),
            text(&row.lease_terminates),
            text(&details),
            text(&row.selection_reason),
        ];
        self.conn
            .execute(
                "INSERT INTO \"metadata\" (\
                 metadata_id, host_id, dataset_id, kind, scope, key, value, raw_value, \
                 resolution_status, observed_at, account_name, account_sid, full_name, domain, \
                 account_kind, name_source, rid, rid_sam, home_directory, profile_path, \
                 profile_path_resolved, created, last_login, password_last_set, \
                 last_failed_login, login_count, failed_login_count, disabled, special_account, \
                 account_flags, interface_id, interface_name, mac_address, network_profile, \
                 dhcp_enabled, dhcp_server, lease_obtained, lease_terminates, \
                 details_json, selection_reason) VALUES (\
                 ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,\
                 ?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40)",
                rusqlite::params_from_iter(params),
            )
            .with_context(|| format!("metadata insert {}/{}", row.kind, row.key))?;

        for (ordinal, src) in row.refs.iter().enumerate() {
            // Source generations belong to facts, not this derived run.
            let source_dataset = self.source_dataset.get(&src.db).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "{}: 원본 facts 세대를 확인하지 못했습니다 — 이 아티팩트를 다시 파싱해야 합니다",
                    src.db
                )
            })?;
            self.conn.execute(
                "INSERT INTO \"source_records\" (record_id, ordinal, source_dataset_id, \
                 source_artifact, source_db, source_table, source_rowid, source_field, \
                 source_record_key, source_file, source_label) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                rusqlite::params![
                    metadata_id,
                    ordinal as i64,
                    source_dataset,
                    src.artifact,
                    src.db,
                    src.table,
                    src.rowid,
                    src.field,
                    src.record_key,
                    src.file,
                    src.label,
                ],
            )?;
        }
        for (ordinal, (value, source_ordinal, reason)) in row.candidates.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO \"MetadataCandidates\" (metadata_id, ordinal, candidate_value, \
                 source_ordinal, reason) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![metadata_id, ordinal as i64, value, source_ordinal, reason],
            )?;
        }
        for (ordinal, addr) in row.addresses.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO \"MetadataAddresses\" (metadata_id, ordinal, address, family, \
                 prefix_length, subnet_mask) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    metadata_id,
                    ordinal as i64,
                    addr.address,
                    addr.family,
                    addr.prefix_length,
                    addr.subnet_mask,
                ],
            )?;
        }
        for (ordinal, (address, metric)) in row.gateways.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO \"MetadataGateways\" (metadata_id, ordinal, address, metric) \
                 VALUES (?1,?2,?3,?4)",
                rusqlite::params![metadata_id, ordinal as i64, address, metric],
            )?;
        }
        for (ordinal, address) in row.dns.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO \"MetadataDnsServers\" (metadata_id, ordinal, address) \
                 VALUES (?1,?2,?3)",
                rusqlite::params![metadata_id, ordinal as i64, address],
            )?;
        }
        for (ordinal, (group_sid, group_name)) in row.groups.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO \"MetadataGroups\" (metadata_id, ordinal, group_sid, group_name) \
                 VALUES (?1,?2,?3,?4)",
                rusqlite::params![metadata_id, ordinal as i64, group_sid, group_name],
            )?;
        }
        self.count += 1;
        Ok(Some(metadata_id))
    }
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

type HostField = (Field, serde_json::Map<String, serde_json::Value>);

fn host_field<'a>(
    fields: &'a mut BTreeMap<&'static str, HostField>,
    key: &'static str,
) -> &'a mut HostField {
    fields.entry(key).or_default()
}

fn build_host(facts: &Facts, writer: &mut Writer<'_>) -> Result<()> {
    let mut fields: BTreeMap<&'static str, HostField> = BTreeMap::new();

    for hive in facts.of(HiveKind::System) {
        for row in hive.values("\\control\\computername\\computername", "ComputerName") {
            host_field(&mut fields, "computer_name").0.push(
                &row.value_data,
                RANK_PRIMARY,
                "SYSTEM Control\\ComputerName\\ComputerName",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        for row in hive.values("\\services\\tcpip\\parameters", "NV Hostname") {
            host_field(&mut fields, "computer_name").0.push(
                &row.value_data,
                RANK_SECONDARY,
                "SYSTEM Tcpip\\Parameters\\NV Hostname",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        for row in hive.values("\\control\\timezoneinformation", "TimeZoneKeyName") {
            host_field(&mut fields, "timezone_id").0.push(
                &row.value_data,
                RANK_PRIMARY,
                "SYSTEM Control\\TimeZoneInformation\\TimeZoneKeyName",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        for row in hive.values("\\control\\timezoneinformation", "Bias") {
            // Bias is signed minutes: UTC = local time + Bias. Standard time
            // only; the DST-inclusive value is ActiveTimeBias below.
            if let Ok(raw) = row.value_data.trim().parse::<u32>() {
                let offset = -(raw as i32 as i64);
                host_field(&mut fields, "standard_offset_minutes").0.push(
                    &offset.to_string(),
                    RANK_PRIMARY,
                    "SYSTEM Control\\TimeZoneInformation\\Bias",
                    hive.source_ref(row, "value_data"),
                    hive.observed(row),
                );
                host_field(&mut fields, "standard_offset_minutes")
                    .1
                    .insert("bias_raw".into(), row.value_data.clone().into());
            }
        }
        for row in hive.values("\\control\\timezoneinformation", "ActiveTimeBias") {
            if let Ok(raw) = row.value_data.trim().parse::<u32>() {
                let offset = -(raw as i32 as i64);
                host_field(&mut fields, "standard_offset_minutes")
                    .1
                    .insert("active_offset_minutes".into(), offset.into());
            }
        }
        for row in hive.values(
            "\\control\\session manager\\environment",
            "PROCESSOR_ARCHITECTURE",
        ) {
            host_field(&mut fields, "architecture").0.push(
                &row.value_data,
                RANK_PRIMARY,
                "SYSTEM Session Manager\\Environment\\PROCESSOR_ARCHITECTURE",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        for name in ["Domain", "NV Domain"] {
            for row in hive.values("\\services\\tcpip\\parameters", name) {
                host_field(&mut fields, "domain").0.push(
                    &row.value_data,
                    RANK_SECONDARY,
                    &format!("SYSTEM Tcpip\\Parameters\\{name}"),
                    hive.source_ref(row, "value_data"),
                    hive.observed(row),
                );
            }
        }
    }

    for hive in facts.of(HiveKind::Software) {
        let cv = "\\microsoft\\windows nt\\currentversion";
        for row in &hive.rows {
            // Ignore compatibility and setup mirrors.
            if !row.key_low.ends_with(cv) || is_mirror_key(&row.key_low) {
                continue;
            }
            let (key, rank, label): (&'static str, u8, &str) = match row.value_name.as_str() {
                "ProductName" => ("os_name", RANK_PRIMARY, "SOFTWARE CurrentVersion\\ProductName"),
                "DisplayVersion" => (
                    "os_version",
                    RANK_PRIMARY,
                    "SOFTWARE CurrentVersion\\DisplayVersion",
                ),
                "ReleaseId" => (
                    "os_version",
                    RANK_SECONDARY,
                    "SOFTWARE CurrentVersion\\ReleaseId",
                ),
                "CurrentBuild" => (
                    "os_build",
                    RANK_PRIMARY,
                    "SOFTWARE CurrentVersion\\CurrentBuild",
                ),
                "CurrentBuildNumber" => (
                    "os_build",
                    RANK_SECONDARY,
                    "SOFTWARE CurrentVersion\\CurrentBuildNumber",
                ),
                _ => continue,
            };
            host_field(&mut fields, key).0.push(
                &row.value_data,
                rank,
                label,
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        for name in ["EditionID", "InstallationType", "BuildLabEx", "UBR"] {
            if let Some(row) = hive
                .rows
                .iter()
                .find(|r| r.key_low.ends_with(cv) && !is_mirror_key(&r.key_low) && r.value_name == name)
            {
                let target = if name == "UBR" { "os_build" } else { "os_name" };
                host_field(&mut fields, target)
                    .1
                    .insert(name.to_lowercase(), row.value_data.clone().into());
            }
        }
    }

    // Domain membership requires the primary-domain SID, not just a name.
    for hive in facts.of(HiveKind::Security) {
        let joined = hive
            .rows
            .iter()
            .any(|r| r.key_low.ends_with("\\polprdms") && !r.value_data.trim().is_empty());
        let domain_sid = primary_domain_sid(hive);
        for row in &hive.rows {
            if !row.key_low.ends_with("\\polprdmn") {
                continue;
            }
            let Some(name) = lsa_string(&row.value_data) else {
                continue;
            };
            let key = if joined { "domain" } else { "workgroup" };
            if let Some(sid) = domain_sid.as_ref().filter(|_| joined) {
                host_field(&mut fields, key).1.insert("domain_sid".into(), sid.clone().into());
            }
            host_field(&mut fields, key).0.push(
                &name,
                RANK_PRIMARY,
                "SECURITY Policy\\PolPrDmN",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
    }

    for (key, (f, details)) in fields {
        if f.is_empty() {
            continue;
        }
        let mut row = MetaRow::new("host", "machine", key);
        row.apply(f.pick());
        row.details = details;
        writer.write(row)?;
    }
    Ok(())
}

// LSA string: u16 length, u16 capacity, u32 header, UTF-16LE payload.
fn lsa_string(hex: &str) -> Option<String> {
    let b = unhex(hex);
    if b.len() < 8 {
        return None;
    }
    let len = le_u16(&b, 0) as usize;
    if len == 0 || 8 + len > b.len() {
        return None;
    }
    let text = utf16le(&b[8..8 + len]);
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

// SECURITY Policy\PolPrDmS: binary SID of the joined primary domain.
fn primary_domain_sid(hive: &Hive) -> Option<String> {
    hive.rows
        .iter()
        .find(|r| r.key_low.ends_with("\\polprdms"))
        .and_then(|r| crate::hex::format_binary_sid(&unhex(&r.value_data)))
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// SID-keyed `DOMAIN\user` written by Windows for a domain logon.
struct DomainNameRecord {
    sid: String,
    name: String,
    label: &'static str,
    src: SourceRef,
}

#[derive(Default, Clone)]
struct ProfileEntry {
    sid: String,
    raw_path: String,
    refs: Vec<SourceRef>,
    observed_at: Option<String>,
    state: Option<String>,
    flags: Option<String>,
}

#[derive(Default)]
struct SamUser {
    rid: u32,
    names: Field,
    full_name: Option<String>,
    home_directory: Option<String>,
    sam_profile_path: Option<String>,
    rid_sam: Option<i64>,
    last_login: Option<String>,
    password_last_set: Option<String>,
    last_failed_login: Option<String>,
    login_count: Option<i64>,
    failed_login_count: Option<i64>,
    disabled: Option<i64>,
    acb: Option<u16>,
    created: Option<String>,
    observed_at: Option<String>,
    refs: Vec<SourceRef>,
}

struct AccountFacts {
    machine_sid: Option<String>,
    machine_sid_refs: Vec<SourceRef>,
    account_domain: Option<String>,
    profiles: Vec<ProfileEntry>,
    sam_users: Vec<SamUser>,
    hidden: HashMap<String, (String, SourceRef)>,
    groups: HashMap<String, Vec<(Option<String>, Option<String>)>>,
    /// Active ControlSet service names: candidates for S-1-5-80 virtual accounts.
    services: Vec<(String, SourceRef)>,
    /// Group Policy cache and LogonUI SID-to-name records.
    domain_names: Vec<DomainNameRecord>,
    /// LogonUI display name keyed by uppercase SID.
    display_names: HashMap<String, (String, SourceRef)>,
}

fn collect_accounts(facts: &Facts) -> AccountFacts {
    let mut machine = Field::default();
    let mut account_domain = None;
    let mut profiles: Vec<ProfileEntry> = Vec::new();
    let mut hidden: HashMap<String, (String, SourceRef)> = HashMap::new();
    let mut groups: HashMap<String, Vec<(Option<String>, Option<String>)>> = HashMap::new();
    let mut domain_names: Vec<DomainNameRecord> = Vec::new();
    let mut display_names: HashMap<String, (String, SourceRef)> = HashMap::new();

    // SOFTWARE profiles and hidden accounts.
    for hive in facts.of(HiveKind::Software) {
        let mut logon: HashMap<&str, &RegRow> = HashMap::new();
        for row in &hive.rows {
            // Group Policy\DataStore\<SID>\0 szName = DOMAIN\user.
            if row.value_name == "szName" && row.key_low.ends_with("\\0") {
                if let Some(i) = row.key_low.find("\\group policy\\datastore\\s-") {
                    let tail = &row.key_path[i + "\\group policy\\datastore\\".len()..];
                    let sid = tail.split('\\').next().unwrap_or("");
                    if !row.value_data.trim().is_empty() {
                        domain_names.push(DomainNameRecord {
                            sid: sid.to_string(),
                            name: row.value_data.trim().to_string(),
                            label: "group_policy_cache",
                            src: hive.source_ref(row, "value_data"),
                        });
                    }
                }
            }
            if row.key_low.ends_with("\\authentication\\logonui") {
                logon.insert(row.value_name.as_str(), row);
            }
            if row.key_low.contains("\\profilelist\\s-") {
                let sid = row.key_path.rsplit('\\').next().unwrap_or("").to_string();
                if sid.is_empty() {
                    continue;
                }
                let idx = match profiles.iter().position(|p| p.sid.eq_ignore_ascii_case(&sid)) {
                    Some(i) => i,
                    None => {
                        profiles.push(ProfileEntry {
                            sid: sid.clone(),
                            ..Default::default()
                        });
                        profiles.len() - 1
                    }
                };
                let entry = &mut profiles[idx];
                match row.value_name.as_str() {
                    "ProfileImagePath" => {
                        entry.raw_path = row.value_data.clone();
                        entry.refs.push(hive.source_ref(row, "value_data"));
                        entry.observed_at = hive.observed(row);
                    }
                    "State" => entry.state = Some(row.value_data.clone()),
                    "Flags" => entry.flags = Some(row.value_data.clone()),
                    _ => {}
                }
            }
            if row
                .key_low
                .ends_with(crate::sam::SPECIAL_ACCOUNTS_USERLIST_SUFFIX)
                && !row.value_name.is_empty()
            {
                hidden.insert(
                    row.value_name.to_lowercase(),
                    (
                        row.value_data.trim().to_string(),
                        hive.source_ref(row, "value_name"),
                    ),
                );
            }
        }
        // LogonUI names the last logged-on user only together with its SID.
        if let (Some(sid), Some(user)) = (logon.get("LastLoggedOnUserSID"), logon.get("LastLoggedOnSAMUser")) {
            let sid = sid.value_data.trim();
            if !sid.is_empty() && !user.value_data.trim().is_empty() {
                domain_names.push(DomainNameRecord {
                    sid: sid.to_string(),
                    name: user.value_data.trim().to_string(),
                    label: "logonui",
                    src: hive.source_ref(user, "value_data"),
                });
                if let Some(display) = logon.get("LastLoggedOnDisplayName").filter(|r| !r.value_data.trim().is_empty()) {
                    display_names.insert(
                        sid.to_uppercase(),
                        (display.value_data.trim().to_string(), hive.source_ref(display, "value_data")),
                    );
                }
            }
        }
    }

    // <ControlSetNNN>\Services\<name> only; deeper "Services" keys are not services.
    let mut services: Vec<(String, SourceRef)> = Vec::new();
    let mut seen_services: HashSet<String> = HashSet::new();
    for hive in facts.of(HiveKind::System) {
        for row in &hive.rows {
            if !row.key_low.contains("\\services\\") || !hive.in_active_set(row) {
                continue;
            }
            let parts: Vec<&str> = row.key_path.split('\\').collect();
            let Some(i) = parts.windows(2).position(|w| {
                w[0].to_ascii_lowercase().starts_with("controlset") && w[1].eq_ignore_ascii_case("services")
            }) else {
                continue;
            };
            let Some(name) = parts.get(i + 2).filter(|n| !n.is_empty()) else {
                continue;
            };
            if seen_services.insert(name.to_lowercase()) {
                services.push((name.to_string(), hive.source_ref(row, "key_path")));
            }
        }
    }

    // SECURITY account domain.
    for hive in facts.of(HiveKind::Security) {
        for row in &hive.rows {
            if row.key_low.ends_with("\\polacdmn") {
                if let Some(name) = lsa_string(&row.value_data) {
                    account_domain = Some(name);
                }
            }
        }
    }

    // SAM machine SID, users and groups.
    let mut sam_users: Vec<SamUser> = Vec::new();
    for hive in facts.of(HiveKind::Sam) {
        for row in &hive.rows {
            if row.key_low.ends_with("\\sam\\domains\\account") && row.value_name == "V" {
                if let Some(sid) = machine_sid_from_v(&row.value_data) {
                    machine.push(
                        &sid,
                        RANK_PRIMARY,
                        "SAM Domains\\Account\\V",
                        hive.source_ref(row, "value_data"),
                        hive.observed(row),
                    );
                }
            }
        }

        // The Names default value's type stores the RID.
        let mut rid_names: Vec<(u32, String, &RegRow)> = Vec::new();
        let mut alias_names: HashMap<u32, String> = HashMap::new();
        for row in &hive.rows {
            let marker = "\\sam\\domains\\account\\users\\names\\";
            if let Some(i) = row.key_low.find(marker) {
                let tail = &row.key_path[i + marker.len()..];
                if tail.is_empty() || tail.contains('\\') {
                    continue;
                }
                if let Ok(rid) = row.value_type.trim().parse::<u32>() {
                    rid_names.push((rid, tail.to_string(), row));
                }
                continue;
            }
            for marker in [
                "\\sam\\domains\\builtin\\aliases\\names\\",
                "\\sam\\domains\\account\\aliases\\names\\",
                "\\sam\\domains\\account\\groups\\names\\",
            ] {
                if let Some(i) = row.key_low.find(marker) {
                    let tail = &row.key_path[i + marker.len()..];
                    if tail.is_empty() || tail.contains('\\') {
                        continue;
                    }
                    if let Ok(rid) = row.value_type.trim().parse::<u32>() {
                        alias_names.insert(rid, tail.to_string());
                    }
                }
            }
        }

        let mut blobs: BTreeMap<String, (Vec<u8>, Vec<u8>, Option<SourceRef>, Option<SourceRef>, Option<String>)> =
            BTreeMap::new();
        for row in &hive.rows {
            let marker = "\\users\\";
            let Some(i) = row.key_low.rfind(marker) else {
                continue;
            };
            let tail = &row.key_path[i + marker.len()..];
            if tail.len() != 8 || !tail.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let entry = blobs.entry(tail.to_uppercase()).or_default();
            match row.value_name.as_str() {
                "F" => {
                    entry.0 = unhex(&row.value_data);
                    entry.2 = Some(hive.source_ref(row, "value_data"));
                    entry.4 = hive.observed(row);
                }
                "V" => {
                    entry.1 = unhex(&row.value_data);
                    entry.3 = Some(hive.source_ref(row, "value_data"));
                }
                _ => {}
            }
        }

        for (rid_hex, (f, v, f_ref, v_ref, observed)) in blobs {
            let rid = u32::from_str_radix(&rid_hex, 16).unwrap_or(0);
            if rid == 0 {
                continue;
            }
            let mut user = crate::sam::sam_f(&f).map_or_else(SamUser::default, |f| SamUser {
                rid_sam: Some(f.rid as i64),
                last_login: filetime(f.last_login),
                password_last_set: filetime(f.password_last_set),
                last_failed_login: filetime(f.last_failed_login),
                login_count: Some(f.login_count as i64),
                failed_login_count: Some(f.failed_login_count as i64),
                disabled: Some(i64::from(f.disabled())),
                acb: Some(f.acb),
                ..Default::default()
            });
            user.rid = rid;
            user.observed_at = observed;
            if let Some(r) = f_ref {
                user.refs.push(r);
            }
            if let Some(name) = sam_v_field(&v, 1) {
                if let Some(r) = v_ref.clone() {
                    user.names
                        .push(&name, RANK_PRIMARY, "SAM Users\\<RID>\\V", r, None);
                }
            }
            user.full_name = sam_v_field(&v, 2);
            user.home_directory = sam_v_field(&v, 6);
            user.sam_profile_path = sam_v_field(&v, 9);
            if let Some(r) = v_ref {
                user.refs.push(r);
            }
            for (named_rid, name, row) in &rid_names {
                if *named_rid == rid {
                    user.names.push(
                        name,
                        RANK_PRIMARY,
                        "SAM Users\\Names\\<이름>(타입=RID)",
                        hive.source_ref(row, "value_type"),
                        hive.observed(row),
                    );
                    user.created = hive.observed(row);
                }
            }
            sam_users.push(user);
        }

        // Member keys encode SID prefix and RID; value bytes list u32 LE alias RIDs.
        for row in &hive.rows {
            let marker = ALIAS_MEMBERS_MARKER;
            let Some(i) = row.key_low.find(marker) else {
                continue;
            };
            let tail = &row.key_path[i + marker.len()..];
            let mut parts = tail.split('\\');
            let (Some(prefix), Some(rid_hex)) = (parts.next(), parts.next()) else {
                continue;
            };
            if parts.next().is_some() || !prefix.to_uppercase().starts_with("S-") {
                continue;
            }
            let Ok(member_rid) = u32::from_str_radix(rid_hex, 16) else {
                continue;
            };
            // The type field holds the alias count, so value_data text is not the data.
            let bytes = unhex(&row.value_hex);
            if bytes.is_empty() || bytes.len() % 4 != 0 {
                continue;
            }
            let member_sid = format!("{prefix}-{member_rid}");
            let builtin = row.key_low.contains("\\domains\\builtin\\");
            let member_groups = groups.entry(member_sid.to_lowercase()).or_default();
            for chunk in bytes.chunks_exact(4) {
                let alias_rid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if alias_rid == 0 {
                    continue;
                }
                let group_sid = builtin.then(|| format!("S-1-5-32-{alias_rid}"));
                member_groups.push((group_sid, alias_names.get(&alias_rid).cloned()));
            }
        }
    }

    let machine_picked = machine.pick();
    AccountFacts {
        machine_sid: machine_picked.value,
        machine_sid_refs: machine_picked.refs,
        account_domain,
        profiles,
        sam_users,
        hidden,
        groups,
        services,
        domain_names,
        display_names,
    }
}

// Account kind follows SID structure, not display names.
fn classify_account(sid: &str, machine_sid: Option<&str>) -> &'static str {
    let upper = sid.to_uppercase();
    if well_known_account(sid).is_some() || upper.starts_with("S-1-5-80-") || upper.starts_with("S-1-5-82-")
    {
        return "well_known";
    }
    if let Some(machine) = machine_sid {
        if upper.starts_with(&format!("{}-", machine.to_uppercase())) {
            return "local";
        }
    }
    if upper.starts_with("S-1-5-21-") || upper.starts_with("S-1-12-1-") {
        return "domain";
    }
    "observed_unknown"
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct EnvVar {
    raw: Option<String>,
    status: &'static str,
    observed_at: Option<String>,
    selection_reason: Option<String>,
    refs: Vec<SourceRef>,
    candidates: Vec<(String, Option<i64>, String)>,
    note: Option<String>,
}

#[derive(Default)]
struct EnvModel {
    machine: BTreeMap<String, EnvVar>,
    users: BTreeMap<String, BTreeMap<String, EnvVar>>,
}

impl EnvModel {
    fn lookup(&self, name_low: &str, sid: Option<&str>) -> Option<&EnvVar> {
        // User scope overrides machine scope only with a known user context.
        if let Some(sid) = sid {
            if let Some(vars) = self.users.get(&sid.to_lowercase()) {
                if let Some(v) = vars.get(name_low) {
                    return Some(v);
                }
            }
        }
        self.machine.get(name_low)
    }

    fn expand(&self, raw: &str, sid: Option<&str>) -> Option<String> {
        let mut stack: Vec<String> = Vec::new();
        self.expand_inner(raw, sid, &mut stack)
    }

    fn expand_inner(&self, raw: &str, sid: Option<&str>, stack: &mut Vec<String>) -> Option<String> {
        if stack.len() > 16 {
            return None;
        }
        let mut out = String::with_capacity(raw.len());
        let bytes: Vec<char> = raw.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != '%' {
                out.push(bytes[i]);
                i += 1;
                continue;
            }
            let Some(close) = (i + 1..bytes.len()).find(|j| bytes[*j] == '%') else {
                // An unmatched percent sign is literal.
                out.extend(&bytes[i..]);
                break;
            };
            let name: String = bytes[i + 1..close].iter().collect();
            if name.is_empty() {
                out.push('%');
                i = close + 1;
                continue;
            }
            let low = name.to_lowercase();
            if stack.iter().any(|s| *s == low) {
                // Cycles remain unresolved.
                return None;
            }
            let var = self.lookup(&low, sid)?;
            let var_raw = var.raw.clone()?;
            stack.push(low);
            let expanded = self.expand_inner(&var_raw, sid, stack)?;
            stack.pop();
            out.push_str(&expanded);
            i = close + 1;
        }
        Some(out)
    }
}

fn env_var_from_field(field: Field, note: Option<String>) -> EnvVar {
    let picked = field.pick();
    EnvVar {
        raw: picked.value,
        status: picked.status,
        observed_at: picked.observed_at,
        selection_reason: picked.selection_reason,
        refs: picked.refs,
        candidates: picked.candidates,
        note,
    }
}

// Match hive-recorded shell paths to profiles; never infer SID from filenames.
fn hive_scope_sid(hive: &Hive, profiles: &[(String, String)]) -> Option<(String, SourceRef)> {
    let mut matched: Option<(String, SourceRef)> = None;
    for row in &hive.rows {
        if !row.key_low.ends_with("\\explorer\\shell folders") {
            continue;
        }
        if !matches!(
            row.value_name.as_str(),
            "AppData" | "Local AppData" | "Desktop" | "Personal" | "History"
        ) {
            continue;
        }
        let value = row.value_data.trim().to_lowercase().replace('/', "\\");
        if value.is_empty() {
            continue;
        }
        for (profile_low, sid) in profiles {
            if profile_low.is_empty() {
                continue;
            }
            let prefix = format!("{}\\", profile_low.trim_end_matches('\\'));
            if !value.starts_with(&prefix) {
                continue;
            }
            match &matched {
                Some((existing, _)) if !existing.eq_ignore_ascii_case(sid) => {
                    // Multiple matching profiles are ambiguous.
                    return None;
                }
                Some(_) => {}
                None => {
                    matched = Some((sid.clone(), hive.source_ref(row, "value_data")));
                }
            }
        }
    }
    matched
}

struct EnvBuild {
    model: EnvModel,
    scope_refs: BTreeMap<String, SourceRef>,
}

fn build_env_model(facts: &Facts, accounts: &AccountFacts) -> EnvBuild {
    let mut machine: BTreeMap<String, Field> = BTreeMap::new();

    let mut add_machine =
        |name: &str, data: &str, rank: u8, label: &str, src: SourceRef, observed: Option<String>| {
            if data.trim().is_empty() {
                return;
            }
            let low = name.to_lowercase();
            machine
                .entry(low)
                .or_default()
                .push(data, rank, label, src, observed);
        };

    for hive in facts.of(HiveKind::System) {
        for row in &hive.rows {
            if !hive.in_active_set(row)
                || !row.key_low.ends_with("\\control\\session manager\\environment")
                || row.value_name.is_empty()
                || row.value_name == "(default)"
            {
                continue;
            }
            add_machine(
                &row.value_name,
                &row.value_data,
                RANK_PRIMARY,
                "SYSTEM Session Manager\\Environment",
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
    }

    for hive in facts.of(HiveKind::Software) {
        for row in &hive.rows {
            if is_mirror_key(&row.key_low) {
                continue;
            }
            let nt_cv = row.key_low.ends_with("\\microsoft\\windows nt\\currentversion");
            let cv = row.key_low.ends_with("\\microsoft\\windows\\currentversion");
            let profile_list = row
                .key_low
                .ends_with("\\microsoft\\windows nt\\currentversion\\profilelist");
            let mapped: Option<&str> = if nt_cv && row.value_name == "SystemRoot" {
                Some("SystemRoot")
            } else if cv {
                match row.value_name.as_str() {
                    "ProgramFilesDir" => Some("ProgramFiles"),
                    "ProgramFilesDir (x86)" => Some("ProgramFiles(x86)"),
                    "ProgramW6432Dir" => Some("ProgramW6432"),
                    "CommonFilesDir" => Some("CommonProgramFiles"),
                    "CommonFilesDir (x86)" => Some("CommonProgramFiles(x86)"),
                    "CommonW6432Dir" => Some("CommonProgramW6432"),
                    _ => None,
                }
            } else if profile_list {
                match row.value_name.as_str() {
                    "ProgramData" => Some("ProgramData"),
                    "Public" => Some("Public"),
                    "ProfilesDirectory" => Some("ProfilesDirectory"),
                    _ => None,
                }
            } else {
                None
            };
            let Some(name) = mapped else { continue };
            add_machine(
                name,
                &row.value_data,
                RANK_PRIMARY,
                &format!("SOFTWARE {}\\{}", row.key_path, row.value_name),
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
    }

    let mut model = EnvModel::default();
    for (low, field) in machine {
        let var = env_var_from_field(field, None);
        model.machine.insert(low, var);
    }

    // Derive SystemDrive from the evidenced SystemRoot, preserving provenance.
    if !model.machine.contains_key("systemdrive") {
        if let Some(system_root) = model.machine.get("systemroot").cloned() {
            if let Some(resolved) = system_root
                .raw
                .as_deref()
                .and_then(|raw| model.expand(raw, None))
            {
                let bytes: Vec<char> = resolved.chars().collect();
                if bytes.len() >= 2 && bytes[1] == ':' && bytes[0].is_ascii_alphabetic() {
                    model.machine.insert(
                        "systemdrive".into(),
                        EnvVar {
                            raw: Some(format!("{}:", bytes[0])),
                            status: "resolved",
                            observed_at: system_root.observed_at.clone(),
                            selection_reason: Some(
                                "SystemRoot의 드라이브에서 파생(Windows 정의)".into(),
                            ),
                            refs: system_root.refs.clone(),
                            candidates: Vec::new(),
                            note: Some("derived_from_systemroot".into()),
                        },
                    );
                }
            }
        }
    }

    // Match user hives against resolved profile paths.
    let mut profile_paths: Vec<(String, String)> = Vec::new();
    for profile in &accounts.profiles {
        if profile.raw_path.trim().is_empty() {
            continue;
        }
        let resolved = model
            .expand(&profile.raw_path, None)
            .unwrap_or_else(|| profile.raw_path.clone());
        profile_paths.push((
            resolved.trim().to_lowercase().replace('/', "\\"),
            profile.sid.clone(),
        ));
    }
    profile_paths.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));

    let mut scope_refs: BTreeMap<String, SourceRef> = BTreeMap::new();
    for hive in facts.of(HiveKind::User) {
        let Some((sid, scope_ref)) = hive_scope_sid(hive, &profile_paths) else {
            continue;
        };
        let sid_low = sid.to_lowercase();
        scope_refs.entry(sid_low.clone()).or_insert(scope_ref);
        let mut vars: BTreeMap<String, Field> = BTreeMap::new();
        for row in &hive.rows {
            let user_env = row.key_low.ends_with("\\environment")
                && !row.key_low.contains("\\software\\");
            let volatile = row.key_low.ends_with("\\volatile environment")
                || row.key_low.contains("\\volatile environment\\");
            let shell = row.key_low.ends_with("\\explorer\\shell folders");
            let mapped: Option<&str> = if user_env || volatile {
                if row.value_name.is_empty() || row.value_name == "(default)" {
                    None
                } else {
                    Some(row.value_name.as_str())
                }
            } else if shell {
                match row.value_name.as_str() {
                    "AppData" => Some("APPDATA"),
                    "Local AppData" => Some("LOCALAPPDATA"),
                    _ => None,
                }
            } else {
                None
            };
            let Some(name) = mapped else { continue };
            if row.value_data.trim().is_empty() {
                continue;
            }
            let low = name.to_lowercase();
            let rank = if shell { RANK_SECONDARY } else { RANK_PRIMARY };
            vars.entry(low).or_default().push(
                &row.value_data,
                rank,
                &format!("{} {}\\{}", hive.stem, row.key_path, row.value_name),
                hive.source_ref(row, "value_data"),
                hive.observed(row),
            );
        }
        let entry = model.users.entry(sid_low).or_default();
        for (low, field) in vars {
            entry.insert(low, env_var_from_field(field, None));
        }
    }

    // USERPROFILE comes from this account's ProfileList entry.
    for profile in &accounts.profiles {
        if profile.raw_path.trim().is_empty() {
            continue;
        }
        let sid_low = profile.sid.to_lowercase();
        let entry = model.users.entry(sid_low).or_default();
        entry.entry("userprofile".into()).or_insert(EnvVar {
            raw: Some(profile.raw_path.clone()),
            status: "resolved",
            observed_at: profile.observed_at.clone(),
            selection_reason: Some("SOFTWARE ProfileList\\<SID>\\ProfileImagePath".into()),
            refs: profile.refs.clone(),
            candidates: Vec::new(),
            note: None,
        });
    }

    EnvBuild { model, scope_refs }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Interface {
    guid: String,
    values: BTreeMap<String, (String, SourceRef, Option<String>)>,
    v6_values: BTreeMap<String, (String, SourceRef, Option<String>)>,
}

fn build_networks(facts: &Facts, writer: &mut Writer<'_>) -> Result<()> {
    let mut order: Vec<String> = Vec::new();
    let mut ifaces: BTreeMap<String, Interface> = BTreeMap::new();

    for hive in facts.of(HiveKind::System) {
        for row in &hive.rows {
            if !hive.in_active_set(row) {
                continue;
            }
            let (marker, v6) = if let Some(i) = row
                .key_low
                .find("\\services\\tcpip\\parameters\\interfaces\\")
            {
                (Some(i + "\\services\\tcpip\\parameters\\interfaces\\".len()), false)
            } else if let Some(i) = row
                .key_low
                .find("\\services\\tcpip6\\parameters\\interfaces\\")
            {
                (Some(i + "\\services\\tcpip6\\parameters\\interfaces\\".len()), true)
            } else {
                (None, false)
            };
            let Some(start) = marker else { continue };
            let guid = row.key_path[start..]
                .split('\\')
                .next()
                .unwrap_or("")
                .to_string();
            if !guid.starts_with('{') || row.value_name.is_empty() {
                continue;
            }
            let key = guid.to_lowercase();
            let entry = ifaces.entry(key.clone()).or_insert_with(|| {
                order.push(key.clone());
                Interface {
                    guid: guid.clone(),
                    ..Default::default()
                }
            });
            let slot = if v6 {
                &mut entry.v6_values
            } else {
                &mut entry.values
            };
            slot.insert(
                row.value_name.to_lowercase(),
                (
                    row.value_data.clone(),
                    hive.source_ref(row, "value_data"),
                    hive.observed(row),
                ),
            );
        }
    }

    // Adapter names and MACs come from NetworkCards and the network class.
    let mut names: BTreeMap<String, Vec<(String, u8, String, SourceRef, Option<String>)>> =
        BTreeMap::new();
    let mut macs: BTreeMap<String, (String, SourceRef)> = BTreeMap::new();
    for hive in facts.of(HiveKind::Software) {
        let mut cards: BTreeMap<String, (Option<String>, Option<(String, SourceRef, Option<String>)>)> =
            BTreeMap::new();
        for row in &hive.rows {
            if !row.key_low.contains("\\currentversion\\networkcards\\") {
                continue;
            }
            let card = row.key_path.rsplit('\\').next().unwrap_or("").to_string();
            let entry = cards.entry(card).or_default();
            match row.value_name.as_str() {
                "ServiceName" => entry.0 = Some(row.value_data.to_lowercase()),
                "Description" => {
                    entry.1 = Some((
                        row.value_data.clone(),
                        hive.source_ref(row, "value_data"),
                        hive.observed(row),
                    ))
                }
                _ => {}
            }
        }
        for (_, (guid, desc)) in cards {
            if let (Some(guid), Some((name, src, observed))) = (guid, desc) {
                names.entry(guid).or_default().push((
                    name,
                    RANK_PRIMARY,
                    "SOFTWARE CurrentVersion\\NetworkCards\\<n>\\Description".into(),
                    src,
                    observed,
                ));
            }
        }
    }
    for hive in facts.of(HiveKind::System) {
        let mut adapters: BTreeMap<
            String,
            (
                Option<String>,
                Option<(String, SourceRef, Option<String>)>,
                Option<(String, SourceRef)>,
            ),
        > = BTreeMap::new();
        for row in &hive.rows {
            if !hive.in_active_set(row)
                || !row
                    .key_low
                    .contains("\\control\\class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\")
            {
                continue;
            }
            let sub = row.key_path.rsplit('\\').next().unwrap_or("").to_string();
            let entry = adapters.entry(sub).or_default();
            match row.value_name.as_str() {
                "NetCfgInstanceId" => entry.0 = Some(row.value_data.to_lowercase()),
                "DriverDesc" => {
                    entry.1 = Some((
                        row.value_data.clone(),
                        hive.source_ref(row, "value_data"),
                        hive.observed(row),
                    ))
                }
                "NetworkAddress" => {
                    entry.2 = Some((row.value_data.clone(), hive.source_ref(row, "value_data")))
                }
                _ => {}
            }
        }
        for (_, (guid, desc, mac)) in adapters {
            let Some(guid) = guid else { continue };
            if let Some((name, src, observed)) = desc {
                names.entry(guid.clone()).or_default().push((
                    name,
                    RANK_SECONDARY,
                    "SYSTEM Control\\Class\\{4d36e972-…}\\DriverDesc".into(),
                    src,
                    observed,
                ));
            }
            if let Some((mac, src)) = mac {
                if !mac.trim().is_empty() {
                    macs.insert(guid, (mac, src));
                }
            }
        }
    }

    for key in order {
        let Some(iface) = ifaces.get(&key) else {
            continue;
        };
        let get = |name: &str| iface.values.get(name);
        let mut row = MetaRow::new("network", "machine", &key);
        row.interface_id = Some(iface.guid.clone());

        let mut name_field = Field::default();
        if let Some(cands) = names.get(&key) {
            for (value, rank, label, src, observed) in cands {
                name_field.push(value, *rank, label, src.clone(), observed.clone());
            }
        }
        let had_name = !name_field.is_empty();
        row.apply(name_field.pick());
        row.interface_name = row.value.clone();
        if !had_name {
            row.status = "missing";
        }

        // Static address/mask pairs precede DHCP lease values; a static list holding
        // only placeholders (DHCP adapters keep "0.0.0.0") falls through to the lease.
        let assigned = |name: &str| {
            get(name)
                .map(|(data, src, _)| (multi_values(data), src.clone()))
                .filter(|(values, _)| values.iter().any(|a| !is_placeholder_address(a)))
        };
        let mut addresses: Vec<AddressRow> = Vec::new();
        let (addr_values, mask_values, addr_src) = match assigned("ipaddress") {
            Some((values, src)) => (
                values,
                get("subnetmask").map(|(d, _, _)| multi_values(d)).unwrap_or_default(),
                Some(src),
            ),
            None => match assigned("dhcpipaddress") {
                Some((values, src)) => (
                    values,
                    get("dhcpsubnetmask")
                        .map(|(d, _, _)| multi_values(d))
                        .unwrap_or_default(),
                    Some(src),
                ),
                None => (Vec::new(), Vec::new(), None),
            },
        };
        for (i, address) in addr_values.iter().enumerate() {
            if is_placeholder_address(address) {
                continue;
            }
            let mask = mask_values.get(i).cloned();
            addresses.push(AddressRow {
                address: address.clone(),
                family: address_family(address),
                prefix_length: mask.as_deref().and_then(prefix_from_mask),
                subnet_mask: mask,
            });
        }
        if !addresses.is_empty() {
            if let Some(src) = addr_src {
                row.add_ref(src);
            }
        }
        row.addresses = addresses;

        let (gw_values, gw_src) = match assigned("defaultgateway") {
            Some((values, src)) => (values, Some(src)),
            None => match assigned("dhcpdefaultgateway") {
                Some((values, src)) => (values, Some(src)),
                None => (Vec::new(), None),
            },
        };
        let metrics = get("defaultgatewaymetric")
            .map(|(d, _, _)| multi_values(d))
            .unwrap_or_default();
        for (i, address) in gw_values.iter().enumerate() {
            if is_placeholder_address(address) {
                continue;
            }
            row.gateways.push((
                address.clone(),
                metrics.get(i).and_then(|m| m.trim().parse::<i64>().ok()),
            ));
        }
        if !row.gateways.is_empty() {
            if let Some(src) = gw_src {
                row.add_ref(src);
            }
        }

        for (slot, source) in [(&iface.values, "tcpip"), (&iface.v6_values, "tcpip6")] {
            for name in ["nameserver", "dhcpnameserver", "dhcpv6dnsservers"] {
                let Some((data, src, _)) = slot.get(name) else {
                    continue;
                };
                let values: Vec<String> = multi_values(data)
                    .into_iter()
                    .filter(|a| !is_placeholder_address(a))
                    .collect();
                if values.is_empty() {
                    continue;
                }
                // Static DNS replaces, rather than extends, DHCP DNS.
                if name != "nameserver" && !row.dns.is_empty() {
                    continue;
                }
                for address in values {
                    if !row.dns.iter().any(|a| a.eq_ignore_ascii_case(&address)) {
                        row.dns.push(address);
                    }
                }
                row.add_ref(src.clone());
                row.details
                    .insert("dns_source".into(), format!("{source}\\{name}").into());
            }
        }

        if let Some((data, src, _)) = get("enabledhcp") {
            row.dhcp_enabled = match data.trim() {
                "1" => Some(1),
                "0" => Some(0),
                _ => None,
            };
            if row.dhcp_enabled.is_some() {
                row.add_ref(src.clone());
            }
        }
        if let Some((data, src, _)) = get("dhcpserver") {
            if !is_placeholder_address(data) {
                row.dhcp_server = Some(data.trim().to_string());
                row.add_ref(src.clone());
            }
        }
        if let Some((data, src, _)) = get("leaseobtainedtime") {
            row.lease_obtained = unix_time(data);
            if row.lease_obtained.is_some() {
                row.add_ref(src.clone());
            }
        }
        if let Some((data, src, _)) = get("leaseterminatestime") {
            row.lease_terminates = unix_time(data);
            if row.lease_terminates.is_some() {
                row.add_ref(src.clone());
            }
        }
        if let Some((mac, src)) = macs.get(&key) {
            row.mac_address = normalize_mac(mac);
            row.add_ref(src.clone());
        }
        if let Some((data, src, _)) = get("domain") {
            if !data.trim().is_empty() {
                row.domain = Some(data.trim().to_string());
                row.add_ref(src.clone());
            }
        }

        let empty = row.addresses.is_empty()
            && row.gateways.is_empty()
            && row.dns.is_empty()
            && row.dhcp_enabled.is_none()
            && row.value.is_none();
        if empty || row.refs.is_empty() {
            continue;
        }
        writer.write(row)?;
    }

    // NetworkList profiles are networks, not adapters; key them by provenance.
    for hive in facts.of(HiveKind::Software) {
        let mut profiles: BTreeMap<String, MetaRow> = BTreeMap::new();
        for row in &hive.rows {
            let marker = "\\networklist\\profiles\\{";
            let Some(i) = row.key_low.find(marker) else {
                continue;
            };
            let guid = row.key_path[i + marker.len() - 1..]
                .split('\\')
                .next()
                .unwrap_or("")
                .to_string();
            if guid.is_empty() {
                continue;
            }
            let key = format!("networklist\\profiles\\{}", guid.to_lowercase());
            let entry = profiles
                .entry(key.clone())
                .or_insert_with(|| MetaRow::new("network", "machine", &key));
            match row.value_name.as_str() {
                "ProfileName" => {
                    entry.value = Some(row.value_data.clone());
                    entry.raw_value = Some(row.value_data.clone());
                    entry.status = "resolved";
                    entry.selection_reason =
                        Some("SOFTWARE NetworkList\\Profiles\\<GUID>\\ProfileName".into());
                    entry.add_ref(hive.source_ref(row, "value_data"));
                }
                "Category" => {
                    entry.network_profile = match row.value_data.trim() {
                        "0" => Some("Public".into()),
                        "1" => Some("Private".into()),
                        "2" => Some("Domain".into()),
                        other => Some(other.to_string()),
                    };
                    entry.add_ref(hive.source_ref(row, "value_data"));
                }
                "DateLastConnected" => {
                    if let Some(when) = systemtime_hex(&row.value_data) {
                        entry.observed_at = Some(when);
                        // Host-local wall clock, not the KST used elsewhere.
                        entry
                            .details
                            .insert("observed_at_clock".into(), "host_local".into());
                        entry.add_ref(hive.source_ref(row, "value_data"));
                    }
                }
                "Description" => {
                    entry
                        .details
                        .insert("description".into(), row.value_data.clone().into());
                }
                _ => {}
            }
        }
        for (_, mut row) in profiles {
            if row.value.is_none() && row.network_profile.is_none() {
                continue;
            }
            row.details
                .insert("source".into(), "NetworkList\\Profiles".into());
            if row.value.is_none() {
                row.status = "missing";
            }
            writer.write(row)?;
        }
    }
    Ok(())
}

// Reformat a SYSTEMTIME as stored (host-local wall clock, no offset applied);
// zero year means unset.
fn systemtime_hex(hex: &str) -> Option<String> {
    let b = unhex(hex);
    if b.len() < 16 {
        return None;
    }
    let (y, mo, d) = (le_u16(&b, 0), le_u16(&b, 2), le_u16(&b, 6));
    let (h, mi, s) = (le_u16(&b, 8), le_u16(&b, 10), le_u16(&b, 12));
    let ms = le_u16(&b, 14);
    if y == 0 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        y, mo, d, h, mi, s, ms
    ))
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Metadata.sqlite build outcome.
#[derive(Debug)]
pub struct MetadataBuild {
    /// Primary-row count.
    pub rows: usize,
    /// Optional inputs that could not be read and were skipped.
    pub input_errors: Vec<String>,
}

/// Build Metadata.sqlite; unreadable SRUM facts are skipped and reported.
pub fn build_metadata(
    out_dir: &Path,
    target: &Path,
    host_id: &str,
    dataset_id: &str,
) -> Result<MetadataBuild> {
    let facts = Facts::load(out_dir, target)?;
    let conn = crate::derived::create_database(&out_dir.join(OVERVIEW_DIR), "Metadata")?;
    let accounts = collect_accounts(&facts);
    let env = build_env_model(&facts, &accounts);

    let tx = conn.unchecked_transaction()?;
    let mut writer = Writer::new(&conn, host_id, dataset_id, &facts);
    build_host(&facts, &mut writer)?;
    let mut input_errors = Vec::new();
    let observed_fixed = observed_fixed_sids(out_dir, &facts, &mut writer, &mut input_errors)?;
    write_accounts(&accounts, &env.model, &observed_fixed, &mut writer)?;
    build_networks(&facts, &mut writer)?;
    write_env(&env, &mut writer)?;
    let rows = writer.count;
    tx.commit()?;
    Ok(MetadataBuild { rows, input_errors })
}

/// First registry/SRUM observation of each DWM/UMFD SID. SRUM facts
/// generations are registered on `writer` so their refs can be stored.
/// Unreadable SRUM facts DBs are skipped and pushed to `input_errors`.
fn observed_fixed_sids(
    out_dir: &Path,
    facts: &Facts,
    writer: &mut Writer<'_>,
    input_errors: &mut Vec<String>,
) -> Result<Vec<(String, SourceRef)>> {
    let mut found: BTreeMap<String, SourceRef> = BTreeMap::new();
    for hive in &facts.hives {
        for row in &hive.rows {
            if !(row.key_low.contains("\\s-1-5-90-0-") || row.key_low.contains("\\s-1-5-96-0-")) {
                continue;
            }
            for part in row.key_path.split('\\') {
                if fixed_virtual_account(part).is_some() {
                    found.entry(part.to_uppercase()).or_insert_with(|| hive.source_ref(row, "key_path"));
                }
            }
        }
    }
    let dir = out_dir.join("SRUM");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "sqlite")).collect())
        .unwrap_or_default();
    files.sort();
    for path in files {
        // SRUM only adds DWM/UMFD evidence: an unreadable file is skipped and
        // reported instead of failing the whole Metadata build.
        match srum_fixed_sids(&path, &found) {
            Ok((sids, db_rel)) => {
                if !sids.is_empty() {
                    // Unstamped facts cannot be cited; reparse is required (same as registry).
                    writer.source_dataset.insert(db_rel, crate::derived::facts_dataset_id(&path)?);
                }
                found.extend(sids);
            }
            Err(error) => {
                let name = path.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();
                input_errors.push(format!("SRUM/{name} skipped: {error:#}"));
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// New DWM/UMFD SIDs in one SRUM facts DB and its relative path.
fn srum_fixed_sids(
    path: &Path,
    known: &BTreeMap<String, SourceRef>,
) -> Result<(Vec<(String, SourceRef)>, String)> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\'")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let db_rel = format!("SRUM/{}", path.file_name().map(|s| s.to_string_lossy()).unwrap_or_default());
    let mut out: Vec<(String, SourceRef)> = Vec::new();
    for table in tables {
        let has_user = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "user");
        if !has_user {
            continue;
        }
        let mut stmt = conn.prepare(&format!(
            "SELECT user, MIN(rowid) FROM \"{table}\" \
             WHERE user LIKE 'S-1-5-90-0-%' OR user LIKE 'S-1-5-96-0-%' GROUP BY user"
        ))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (sid, rowid) = row?;
            let upper = sid.to_uppercase();
            if fixed_virtual_account(&sid).is_none()
                || known.contains_key(&upper)
                || out.iter().any(|(k, _)| *k == upper)
            {
                continue;
            }
            out.push((upper, SourceRef {
                artifact: "SRUM",
                db: db_rel.clone(),
                table: table.clone(),
                rowid,
                field: Some("user".into()),
                record_key: Some(format!("{stem}::{table}::{rowid}")),
                file: None,
                label: Some(sid),
            }));
        }
    }
    Ok((out, db_rel))
}

fn write_accounts(
    accounts: &AccountFacts,
    env: &EnvModel,
    observed_fixed: &[(String, SourceRef)],
    writer: &mut Writer<'_>,
) -> Result<()> {
    let service_by_sid: BTreeMap<String, (&str, &SourceRef)> = accounts
        .services
        .iter()
        .map(|(name, src)| (service_sid(name), (name.as_str(), src)))
        .collect();
    let machine_sid = accounts.machine_sid.clone();
    let mut by_sid: BTreeMap<String, MetaRow> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();

    let ensure = |sid: &str,
                      by_sid: &mut BTreeMap<String, MetaRow>,
                      order: &mut Vec<String>|
     -> String {
        let key = sid.to_lowercase();
        if !by_sid.contains_key(&key) {
            let mut row = MetaRow::new("account", "machine", &key);
            row.account_sid = Some(sid.to_string());
            row.rid = sid_rid(sid);
            row.account_kind = Some(classify_account(sid, machine_sid.as_deref()).to_string());
            row.status = "missing";
            by_sid.insert(key.clone(), row);
            order.push(key.clone());
        }
        key
    };

    // SAM SIDs require the machine SID and the user's RID.
    for user in &accounts.sam_users {
        let Some(machine) = machine_sid.as_deref() else {
            continue;
        };
        let sid = format!("{machine}-{}", user.rid);
        let key = ensure(&sid, &mut by_sid, &mut order);
        let name_picked = account_name_field(user).pick();
        let row = by_sid.get_mut(&key).expect("account row");
        for src in &user.refs {
            row.add_ref(src.clone());
        }
        let mut candidate_base = Vec::new();
        for src in &name_picked.refs {
            candidate_base.push(row.add_ref(src.clone()));
        }
        for (value, ordinal, reason) in name_picked.candidates {
            let mapped = ordinal
                .and_then(|o| candidate_base.get(o as usize).copied())
                .or(ordinal);
            row.candidates.push((value, mapped, reason));
        }
        row.value = name_picked.value.clone();
        row.account_name = name_picked.value;
        row.status = match name_picked.status {
            "resolved" => "resolved",
            "conflict" => "conflict",
            _ => "missing",
        };
        row.selection_reason = name_picked.selection_reason;
        row.name_source = row.value.is_some().then(|| "SAM".to_string());
        row.observed_at = user.observed_at.clone().or(row.observed_at.clone());
        row.full_name = user.full_name.clone();
        row.home_directory = user.home_directory.clone();
        row.rid_sam = user.rid_sam;
        row.last_login = user.last_login.clone();
        row.password_last_set = user.password_last_set.clone();
        row.last_failed_login = user.last_failed_login.clone();
        row.login_count = user.login_count;
        row.failed_login_count = user.failed_login_count;
        row.disabled = user.disabled;
        row.created = user.created.clone();
        row.domain = accounts.account_domain.clone();
        if let Some(acb) = user.acb {
            row.account_flags = Some(format!("0x{acb:04X}"));
            let flags: Vec<serde_json::Value> = crate::sam::acb_flag_names(acb)
                .map(serde_json::Value::from)
                .collect();
            row.details
                .insert("acb_flags".into(), serde_json::Value::Array(flags));
            row.details.insert("acb".into(), (acb as i64).into());
        }
        if let Some(sam_profile) = &user.sam_profile_path {
            row.details
                .insert("sam_profile_path".into(), sam_profile.clone().into());
        }
        if let Some(name) = row.account_name.clone() {
            if let Some((value, src)) = accounts.hidden.get(&name.to_lowercase()) {
                row.special_account = Some(i64::from(value == "0" || value == "0x0"));
                row.details
                    .insert("special_accounts_userlist".into(), value.clone().into());
                row.add_ref(src.clone());
            }
        }
        for src in &accounts.machine_sid_refs {
            row.add_ref(src.clone());
        }
    }

    // Profile directories are evidence of paths, not account names.
    for profile in &accounts.profiles {
        let key = ensure(&profile.sid, &mut by_sid, &mut order);
        let row = by_sid.get_mut(&key).expect("account row");
        for src in &profile.refs {
            row.add_ref(src.clone());
        }
        if !profile.raw_path.trim().is_empty() {
            row.profile_path = Some(profile.raw_path.clone());
            row.profile_path_resolved = env.expand(&profile.raw_path, Some(&profile.sid)).filter(
                |resolved| !resolved.eq_ignore_ascii_case(profile.raw_path.trim()),
            );
            let folder = profile
                .raw_path
                .trim_end_matches('\\')
                .rsplit('\\')
                .next()
                .unwrap_or("")
                .to_string();
            if !folder.is_empty() {
                // Keep the folder name only as an unconfirmed hint.
                row.details
                    .insert("profile_folder".into(), folder.into());
            }
        }
        if let Some(state) = &profile.state {
            row.details.insert("profile_state".into(), state.clone().into());
        }
        if let Some(flags) = &profile.flags {
            row.details.insert("profile_flags".into(), flags.clone().into());
        }
        if row.observed_at.is_none() {
            row.observed_at = profile.observed_at.clone();
        }
        if row.value.is_none() {
            if let Some(name) = well_known_account(&profile.sid) {
                row.value = Some(name.to_string());
                row.account_name = Some(name.to_string());
                row.name_source = Some("well_known_sid".into());
                row.status = "resolved";
                row.selection_reason = Some("잘 알려진 SID".into());
            } else if let Some((domain, name, source)) = profile_folder_of(&profile.raw_path)
                .and_then(|folder| hashed_virtual_account(&profile.sid, folder))
                .or_else(|| {
                    let (name, src) = service_by_sid.get(&profile.sid.to_uppercase())?;
                    row.add_ref((*src).clone());
                    Some(("NT SERVICE", (*name).to_string(), "service_sid_hash"))
                })
            {
                // Folder or service name is only a candidate; the SID hash proves it.
                row.value = Some(format!("{domain}\\{name}"));
                row.account_name = row.value.clone();
                row.domain = Some(domain.into());
                row.name_source = Some(source.into());
                row.status = "resolved";
                row.selection_reason = Some("SID = SHA-1(이름) 일치".into());
            }
        }
    }

    // Domain accounts are absent from SAM; Windows' own SID-keyed records name them.
    for row in by_sid.values_mut() {
        if row.value.is_some() {
            continue;
        }
        let sid = row.account_sid.clone().unwrap_or_default();
        let records: Vec<&DomainNameRecord> = accounts
            .domain_names
            .iter()
            .filter(|r| r.sid.eq_ignore_ascii_case(&sid))
            .collect();
        if records.is_empty() {
            continue;
        }
        for record in &records {
            row.add_ref(record.src.clone());
        }
        let mut names: Vec<&str> = Vec::new();
        for record in &records {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&record.name)) {
                names.push(&record.name);
            }
        }
        if names.len() > 1 {
            row.details.insert(
                "domain_name_candidates".into(),
                serde_json::Value::Array(names.iter().map(|n| (*n).into()).collect()),
            );
            continue;
        }
        let name = names[0].to_string();
        let mut labels: Vec<&str> = records.iter().map(|r| r.label).collect();
        labels.sort_unstable();
        labels.dedup();
        row.domain = name.split_once('\\').map(|(domain, _)| domain.to_string());
        row.value = Some(name.clone());
        row.account_name = Some(name);
        row.name_source = Some(labels.join("+"));
        row.status = "resolved";
        row.selection_reason = Some("도메인 로그온 SID→이름 레지스트리 기록 일치".into());
        if let Some((display, src)) = accounts.display_names.get(&sid.to_uppercase()) {
            row.full_name = Some(display.clone());
            row.add_ref(src.clone());
        }
    }

    for key in order {
        let Some(mut row) = by_sid.remove(&key) else {
            continue;
        };
        if let Some(groups) = accounts.groups.get(&key) {
            row.groups = groups.clone();
        }
        if row.refs.is_empty() {
            continue;
        }
        if row.value.is_none() && row.status == "resolved" {
            row.status = "missing";
        }
        writer.write(row)?;
    }

    // Every active service has a deterministic NT SERVICE SID.
    for (sid, (name, src)) in &service_by_sid {
        writer.write(virtual_account_row(sid, "NT SERVICE", name, "service_sid_hash", "활성 서비스명 SHA-1", (*src).clone()))?;
    }
    for (sid, src) in observed_fixed {
        if let Some((domain, name)) = fixed_virtual_account(sid) {
            writer.write(virtual_account_row(sid, domain, &name, "fixed_virtual_sid", "고정 가상 계정 SID 규칙", src.clone()))?;
        }
    }
    Ok(())
}

// Conflicting SAM names remain candidates.
fn account_name_field(user: &SamUser) -> Field {
    Field {
        cands: user
            .names
            .cands
            .iter()
            .map(|c| Cand {
                value: c.value.clone(),
                rank: c.rank,
                label: c.label.clone(),
                src: c.src.clone(),
                observed_at: c.observed_at.clone(),
            })
            .collect(),
    }
}

fn write_env(env: &EnvBuild, writer: &mut Writer<'_>) -> Result<()> {
    for (low, var) in &env.model.machine {
        let mut row = MetaRow::new("env", "machine", low);
        apply_env(&mut row, var, &env.model, None);
        writer.write(row)?;
    }
    for (sid, vars) in &env.model.users {
        for (low, var) in vars {
            let mut row = MetaRow::new("env", sid, low);
            apply_env(&mut row, var, &env.model, Some(sid));
            if let Some(scope_ref) = env.scope_refs.get(sid) {
                row.add_ref(scope_ref.clone());
            }
            writer.write(row)?;
        }
    }
    Ok(())
}

fn apply_env(row: &mut MetaRow, var: &EnvVar, model: &EnvModel, sid: Option<&str>) {
    row.raw_value = var.raw.clone();
    row.observed_at = var.observed_at.clone();
    row.selection_reason = var.selection_reason.clone();
    row.refs = var.refs.clone();
    row.candidates = var.candidates.clone();
    if let Some(note) = &var.note {
        row.details.insert("derivation".into(), note.clone().into());
    }
    match var.status {
        "conflict" => {
            row.value = None;
            row.status = "conflict";
        }
        _ => match var.raw.as_deref().and_then(|raw| model.expand(raw, sid)) {
            Some(value) => {
                row.value = Some(value);
                row.status = "resolved";
            }
            None => {
                row.value = None;
                row.status = "unresolved";
            }
        },
    }
}

/// Return confirmed account names keyed by uppercase SID, excluding conflicts.
pub fn account_names_from_facts(out_dir: &Path) -> Result<HashMap<String, String>> {
    let facts = Facts::load(out_dir, Path::new(""))?;
    let accounts = collect_accounts(&facts);
    let mut out = HashMap::new();
    if let Some(machine) = accounts.machine_sid.as_deref() {
        for user in &accounts.sam_users {
            let picked = account_name_field(user).pick();
            if picked.status != "resolved" {
                continue;
            }
            if let Some(name) = picked.value {
                out.insert(format!("{machine}-{}", user.rid).to_uppercase(), name);
            }
        }
    }
    for profile in &accounts.profiles {
        let name = well_known_account(&profile.sid).map(str::to_string).or_else(|| {
            profile_folder_of(&profile.raw_path)
                .and_then(|folder| hashed_virtual_account(&profile.sid, folder))
                .map(|(domain, name, _)| format!("{domain}\\{name}"))
        });
        if let Some(name) = name {
            out.entry(profile.sid.to_uppercase()).or_insert(name);
        }
    }
    for (name, _) in &accounts.services {
        out.entry(service_sid(name)).or_insert_with(|| format!("NT SERVICE\\{name}"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Stored lookups
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AccountEntry {
    pub sid: String,
    pub name: Option<String>,
    pub account_kind: Option<String>,
    pub domain: Option<String>,
    pub profile_path: Option<String>,
    pub profile_path_resolved: Option<String>,
}

/// Read stored metadata without reparsing evidence.
pub struct MetadataLookup {
    /// (kind, scope, key) → metadata_id.
    index: HashMap<(String, String, String), String>,
    accounts: BTreeMap<String, AccountEntry>,
    names: HashMap<String, Vec<String>>,
    host: BTreeMap<String, String>,
    machine_env: BTreeMap<String, String>,
    user_env: BTreeMap<String, BTreeMap<String, String>>,
    profiles: Vec<(String, String)>,
    /// kind='virtual_account' names (service / DWM / UMFD); not host accounts.
    virtual_accounts: HashMap<String, String>,
}

impl MetadataLookup {
    pub fn load(out_dir: &Path) -> Result<Self> {
        let db = out_dir.join(OVERVIEW_DIR).join(METADATA_DB);
        let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("open {}", db.display()))?;
        let mut stmt = conn.prepare(
            "SELECT metadata_id, kind, scope, key, value, account_name, account_sid, \
             account_kind, domain, profile_path, profile_path_resolved \
             FROM \"metadata\"",
        )?;
        let mut index = HashMap::new();
        let mut accounts: BTreeMap<String, AccountEntry> = BTreeMap::new();
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        let mut host = BTreeMap::new();
        let mut machine_env = BTreeMap::new();
        let mut user_env: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        let mut profiles = Vec::new();
        let mut virtual_accounts = HashMap::new();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let metadata_id: String = r.get(0)?;
            let kind: String = r.get(1)?;
            let scope: String = r.get(2)?;
            let key: String = r.get(3)?;
            let value: Option<String> = r.get(4)?;
            match kind.as_str() {
                "host" => {
                    if let Some(v) = value.clone() {
                        host.insert(key.clone(), v);
                    }
                }
                "env" => {
                    if let Some(v) = value.clone() {
                        if scope == "machine" {
                            machine_env.insert(key.clone(), v);
                        } else {
                            user_env
                                .entry(scope.to_lowercase())
                                .or_default()
                                .insert(key.clone(), v);
                        }
                    }
                }
                "account" => {
                    let sid: Option<String> = r.get(6)?;
                    let sid = sid.unwrap_or_else(|| key.clone());
                    let entry = AccountEntry {
                        sid: sid.clone(),
                        name: r.get::<_, Option<String>>(5)?.or_else(|| value.clone()),
                        account_kind: r.get(7)?,
                        domain: r.get(8)?,
                        profile_path: r.get(9)?,
                        profile_path_resolved: r.get(10)?,
                    };
                    if let Some(name) = &entry.name {
                        names
                            .entry(name.to_lowercase())
                            .or_default()
                            .push(sid.clone());
                    }
                    let profile = entry
                        .profile_path_resolved
                        .clone()
                        .or_else(|| entry.profile_path.clone());
                    if let Some(path) = profile {
                        profiles.push((
                            path.trim().trim_end_matches('\\').to_lowercase(),
                            sid.clone(),
                        ));
                    }
                    accounts.insert(key.to_lowercase(), entry);
                }
                "virtual_account" => {
                    if let Some(v) = value.clone() {
                        virtual_accounts.insert(key.to_lowercase(), v);
                    }
                }
                _ => {}
            }
            index.insert((kind, scope, key), metadata_id);
        }
        profiles.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
        Ok(Self {
            index,
            accounts,
            names,
            host,
            machine_env,
            user_env,
            profiles,
            virtual_accounts,
        })
    }

    /// Resolve confirmed names; callers retain SID when unavailable.
    pub fn account(&self, sid: &str) -> Option<&str> {
        let key = sid.to_lowercase();
        self.accounts
            .get(&key)
            .and_then(|a| a.name.as_deref())
            .or_else(|| self.virtual_accounts.get(&key).map(String::as_str))
    }

    pub fn account_entry(&self, sid: &str) -> Option<&AccountEntry> {
        self.accounts.get(&sid.to_lowercase())
    }

    pub fn accounts(&self) -> impl Iterator<Item = &AccountEntry> {
        self.accounts.values()
    }

    /// Ambiguous account names do not resolve to a SID.
    pub fn sid_for_account_name(&self, name: &str) -> Option<&str> {
        let sids = self.names.get(&name.to_lowercase())?;
        if sids.len() != 1 {
            return None;
        }
        Some(sids[0].as_str())
    }

    /// Resolve only a unique longest profile-path match.
    pub fn sid_for_profile_path(&self, path: &str) -> Option<&str> {
        let needle = path.trim().to_lowercase().replace('/', "\\");
        let mut found: Option<&str> = None;
        let mut found_len = 0usize;
        for (profile, sid) in &self.profiles {
            if profile.is_empty() {
                continue;
            }
            let matches = needle == *profile || needle.starts_with(&format!("{profile}\\"));
            if !matches {
                continue;
            }
            if profile.len() > found_len {
                found = Some(sid.as_str());
                found_len = profile.len();
            } else if profile.len() == found_len
                && found.is_some_and(|existing| !existing.eq_ignore_ascii_case(sid))
            {
                return None;
            }
        }
        found
    }

    pub fn host_value(&self, key: &str) -> Option<&str> {
        self.host.get(key).map(String::as_str)
    }

    pub fn computer_name(&self) -> Option<&str> {
        self.host_value("computer_name")
    }

    /// Use the target's user scope first, then its machine scope.
    pub fn env_value(&self, name: &str, sid: Option<&str>) -> Option<&str> {
        let low = name.to_lowercase();
        if let Some(sid) = sid {
            if let Some(vars) = self.user_env.get(&sid.to_lowercase()) {
                if let Some(v) = vars.get(&low) {
                    return Some(v.as_str());
                }
            }
        }
        self.machine_env.get(&low).map(String::as_str)
    }

    /// Expand target variables; unchanged or unresolved paths return None.
    pub fn resolve_path(&self, raw: &str, sid: Option<&str>) -> Option<String> {
        if !raw.contains('%') {
            return None;
        }
        let mut out = String::with_capacity(raw.len());
        let chars: Vec<char> = raw.chars().collect();
        let mut i = 0;
        let mut expanded_any = false;
        while i < chars.len() {
            if chars[i] != '%' {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            let Some(close) = (i + 1..chars.len()).find(|j| chars[*j] == '%') else {
                out.extend(&chars[i..]);
                break;
            };
            let name: String = chars[i + 1..close].iter().collect();
            if name.is_empty() {
                out.push('%');
                i = close + 1;
                continue;
            }
            let value = self.env_value(&name, sid)?;
            out.push_str(value);
            expanded_any = true;
            i = close + 1;
        }
        if !expanded_any || out.contains('%') {
            return None;
        }
        Some(out)
    }

    /// Account SID and environment-name keys must be lowercase.
    pub fn metadata_id(&self, kind: &str, scope: &str, key: &str) -> Option<&str> {
        self.index
            .get(&(kind.to_string(), scope.to_string(), key.to_string()))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_srum_db_is_reported_without_failing_metadata() {
        let fx = Fixture::new("bad-srum");
        write_software(&fx, base_software("D:\\Users\\analyst"));
        let srum = fx.root.join("SRUM").join("SRUDB.sqlite");
        std::fs::create_dir_all(srum.parent().unwrap()).unwrap();
        std::fs::write(&srum, b"not a sqlite database, just garbage bytes....").unwrap();
        let build = build_metadata(&fx.root, Path::new("/evidence"), "host-1", "ds-1").unwrap();
        assert!(build.rows > 0);
        assert_eq!(build.input_errors.len(), 1);
        assert!(build.input_errors[0].starts_with("SRUM/SRUDB.sqlite skipped: "), "{:?}", build.input_errors);
    }

    #[test]
    fn unreadable_registry_table_is_an_error_not_missing_hive() {
        let dir = std::env::temp_dir().join(format!("wina-md-loadhive-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let broken = dir.join("SYSTEM.sqlite");
        Connection::open(&broken).unwrap().execute_batch("CREATE TABLE Registry(key_path TEXT);").unwrap();
        let other = dir.join("RegistryInputs.sqlite");
        Connection::open(&other).unwrap().execute_batch("CREATE TABLE inputs(x TEXT);").unwrap();
        let broken_result = load_hive(&broken, &dir);
        let other_result = load_hive(&other, &dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(broken_result.is_err());
        assert!(other_result.unwrap().is_none());
    }

    #[test]
    fn prefix_from_mask_accepts_slash_32() {
        assert_eq!(prefix_from_mask("255.255.255.255"), Some(32));
        assert_eq!(prefix_from_mask("255.255.255.254"), Some(31));
        assert_eq!(prefix_from_mask("0.0.0.0"), Some(0));
        assert_eq!(prefix_from_mask("255.0.255.0"), None);
    }

    // Distinct from the derived generation to detect provenance substitution.
    const FACTS_DATASET: &str = "facts-generation-0001";

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "wina-metadata-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(root.join(REGISTRY_DIR)).unwrap();
            Self { root }
        }

        fn hive(&self, name: &str, rows: &[(&str, &str, &str, &str)]) {
            let db = self.root.join(REGISTRY_DIR).join(format!("{name}.sqlite"));
            let conn = Connection::open(&db).unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS \"Registry\" (last_write TEXT, key_path TEXT, \
                 value_name TEXT, value_type TEXT, value_data TEXT, _recovery TEXT, \
                 _source_file TEXT, value_data_hex TEXT)",
                [],
            )
            .unwrap();
            for (key_path, value_name, value_type, value_data) in rows {
                // Parser keeps raw bytes; string types are UTF-16LE.
                let hex = if *value_type == "REG_BINARY" {
                    value_data.to_string()
                } else {
                    value_data
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .map(|b| format!("{b:02x}"))
                        .collect()
                };
                conn.execute(
                    "INSERT INTO \"Registry\" VALUES ('2026-01-02 03:04:05.678', ?1, ?2, ?3, ?4, \
                     'live', '/evidence/HIVE', ?5)",
                    rusqlite::params![key_path, value_name, value_type, value_data, hex],
                )
                .unwrap();
            }
            drop(conn);
            crate::derived::stamp_facts_generation(&db, FACTS_DATASET).unwrap();
        }

        fn build(&self) -> usize {
            build_metadata(&self.root, Path::new("/evidence"), "host-1", "ds-1").unwrap().rows
        }

        fn db(&self) -> Connection {
            Connection::open(self.root.join(OVERVIEW_DIR).join(METADATA_DB)).unwrap()
        }

        fn lookup(&self) -> MetadataLookup {
            MetadataLookup::load(&self.root).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn account_v_hex(sub: [u32; 3]) -> String {
        let mut b: Vec<u8> = vec![0; 16];
        b.extend([1u8, 4, 0, 0, 0, 0, 0, 5]);
        b.extend(21u32.to_le_bytes());
        for s in sub {
            b.extend(s.to_le_bytes());
        }
        crate::hex::hex_lower(&b)
    }

    fn user_v_hex(name: &str, full: &str) -> String {
        let mut head = vec![0u8; 0xCC];
        let mut data: Vec<u8> = Vec::new();
        let put = |index: usize, text: &str, head: &mut Vec<u8>, data: &mut Vec<u8>| {
            let off = data.len() as u32;
            let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            data.extend(&bytes);
            let base = index * 12;
            head[base..base + 4].copy_from_slice(&off.to_le_bytes());
            head[base + 4..base + 8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        };
        put(1, name, &mut head, &mut data);
        put(2, full, &mut head, &mut data);
        head.extend(data);
        crate::hex::hex_lower(&head)
    }

    fn user_f_hex(rid: u32, acb: u16, last_login: u64) -> String {
        let mut b = vec![0u8; 0x48];
        b[0x08..0x10].copy_from_slice(&last_login.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&rid.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&acb.to_le_bytes());
        b[0x42..0x44].copy_from_slice(&7u16.to_le_bytes());
        crate::hex::hex_lower(&b)
    }

    fn machine_sid() -> String {
        "S-1-5-21-11-22-33".to_string()
    }

    fn base_software(profile: &str) -> Vec<(&'static str, &'static str, &'static str, String)> {
        vec![
            (
                "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion",
                "ProductName",
                "REG_SZ",
                "Windows 10 Pro".to_string(),
            ),
            (
                "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion",
                "SystemRoot",
                "REG_SZ",
                "D:\\test".to_string(),
            ),
            (
                "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-11-22-33-1001",
                "ProfileImagePath",
                "REG_SZ",
                profile.to_string(),
            ),
        ]
    }

    fn write_software(fx: &Fixture, rows: Vec<(&str, &str, &str, String)>) {
        let owned: Vec<(&str, &str, &str, &str)> = rows
            .iter()
            .map(|(a, b, c, d)| (*a, *b, *c, d.as_str()))
            .collect();
        fx.hive("SOFTWARE", &owned);
    }

    #[test]
    fn accounts_use_lowercase_sid_keys_and_confirmed_names_only() {
        let fx = Fixture::new("accounts");
        let sid = machine_sid();
        let account_v = account_v_hex([11, 22, 33]);
        let user_f = user_f_hex(1001, 0x0210, 133_000_000_000_000_000);
        let user_v = user_v_hex("analyst", "Analyst User");
        fx.hive(
            "SAM",
            &[
                (
                    "\\ROOT\\SAM\\Domains\\Account",
                    "V",
                    "REG_BINARY",
                    account_v.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "F",
                    "REG_BINARY",
                    user_f.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "V",
                    "REG_BINARY",
                    user_v.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\Names\\analyst",
                    "(default)",
                    "1001",
                    "",
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Builtin\\Aliases\\Names\\Administrators",
                    "(default)",
                    "544",
                    "",
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Builtin\\Aliases\\Names\\Users",
                    "(default)",
                    "545",
                    "",
                ),
                // Two alias RIDs (545, 544): type code 2 is rendered as REG_EXPAND_SZ.
                (
                    "\\ROOT\\SAM\\Domains\\Builtin\\Aliases\\Members\\S-1-5-21-11-22-33\\000003E9",
                    "(default)",
                    "REG_EXPAND_SZ",
                    "\u{221}\u{0}\u{220}\u{0}",
                ),
            ],
        );
        let mut software = base_software("D:\\Users\\ghost");
        software.push((
            "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18",
            "ProfileImagePath",
            "REG_SZ",
            "%SystemRoot%\\system32\\config\\systemprofile".to_string(),
        ));
        write_software(&fx, software);
        assert!(fx.build() > 0);

        let conn = fx.db();
        let (key, value, kind, name_source): (String, Option<String>, String, Option<String>) = conn
            .query_row(
                "SELECT key, value, account_kind, name_source FROM metadata \
                 WHERE kind='account' AND rid=1001",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(key, format!("{sid}-1001").to_lowercase());
        assert_eq!(value.as_deref(), Some("analyst"));
        assert_eq!(kind, "local");
        assert_eq!(name_source.as_deref(), Some("SAM"));

        // A profile folder alone cannot establish an account name.
        let details: String = conn
            .query_row(
                "SELECT details_json FROM metadata WHERE kind='account' AND rid=1001",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(details.contains("\"profile_folder\":\"ghost\""));

        let lookup = fx.lookup();
        assert_eq!(lookup.account("S-1-5-18"), Some("LocalSystem"));
        assert_eq!(lookup.account(&format!("{sid}-1001")), Some("analyst"));
        assert_eq!(
            lookup.account(&format!("{sid}-1001").to_uppercase()),
            Some("analyst")
        );
        assert_eq!(lookup.account("S-1-5-21-99-99-99-1234"), None);

        let groups: Vec<(Option<String>, Option<String>)> = conn
            .prepare(
                "SELECT g.group_sid, g.group_name FROM MetadataGroups g \
                 JOIN metadata m ON m.metadata_id = g.metadata_id WHERE m.rid = 1001 \
                 ORDER BY g.group_sid",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            groups,
            vec![
                (Some("S-1-5-32-544".into()), Some("Administrators".into())),
                (Some("S-1-5-32-545".into()), Some("Users".into())),
            ]
        );
    }

    // Shapes copied from the PC1_20261014_023944 SOFTWARE/SECURITY hives.
    const DOMAIN_USER: &str = "S-1-5-21-3037839750-2636006196-3284199242-7583";

    fn lsa_hex(text: &str) -> String {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = Vec::new();
        b.extend_from_slice(&(units.len() as u16).to_le_bytes());
        b.extend_from_slice(&(units.len() as u16 + 2).to_le_bytes());
        b.extend_from_slice(&8u32.to_le_bytes());
        b.extend(units);
        b.extend_from_slice(&[0, 0]);
        crate::hex::hex_lower(&b)
    }

    fn domain_fixture(tag: &str, gp_name: Option<&str>, logon_user: Option<&str>) -> Fixture {
        let fx = Fixture::new(tag);
        let dom_sid = "01040000000000051500000086c111b534431e9d4ae7c0c3".to_string();
        let dom_name = lsa_hex("NAMYANG");
        fx.hive("SECURITY", &[
            ("\\ROOT\\Policy\\PolPrDmN", "(default)", "REG_NONE", dom_name.as_str()),
            ("\\ROOT\\Policy\\PolPrDmS", "(default)", "REG_NONE", dom_sid.as_str()),
        ]);
        let mut software: Vec<(&str, &str, &str, String)> = base_software("C:\\Users\\ny").into_iter().collect();
        let gp = format!("\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore\\{DOMAIN_USER}\\0");
        let logon = "\\ROOT\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI";
        let profile = format!("\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{DOMAIN_USER}");
        software.push((profile.as_str(), "ProfileImagePath", "REG_SZ", "C:\\Users\\2505002".to_string()));
        if let Some(name) = gp_name {
            software.push((gp.as_str(), "szName", "REG_SZ", name.to_string()));
        }
        if let Some(user) = logon_user {
            software.push((logon, "LastLoggedOnUserSID", "REG_SZ", DOMAIN_USER.to_string()));
            software.push((logon, "LastLoggedOnSAMUser", "REG_SZ", user.to_string()));
            software.push((logon, "LastLoggedOnDisplayName", "REG_SZ", "박 상현".to_string()));
        }
        write_software(&fx, software);
        fx
    }

    #[test]
    fn domain_account_names_come_from_agreeing_registry_records() {
        let fx = domain_fixture("domain-ok", Some("NAMYANG\\2505002"), Some("NAMYANG\\2505002"));
        assert!(fx.build() > 0);
        let conn = fx.db();
        let row: (Option<String>, Option<String>, Option<String>, String, Option<String>, String) = conn
            .query_row(
                "SELECT value, domain, full_name, account_kind, name_source, resolution_status FROM metadata \
                 WHERE kind='account' AND key=?1",
                [DOMAIN_USER.to_lowercase()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(row.0.as_deref(), Some("NAMYANG\\2505002"));
        assert_eq!(row.1.as_deref(), Some("NAMYANG"));
        assert_eq!(row.2.as_deref(), Some("박 상현"));
        assert_eq!(row.3, "domain");
        assert_eq!(row.4.as_deref(), Some("group_policy_cache+logonui"));
        assert_eq!(row.5, "resolved");
        assert_eq!(fx.lookup().account(DOMAIN_USER), Some("NAMYANG\\2505002"));
        // Joined primary domain from SECURITY policy.
        let domain: (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT value, details_json FROM metadata WHERE kind='host' AND key='domain'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(domain.0.as_deref(), Some("NAMYANG"));
        assert!(domain.1.unwrap_or_default().contains("S-1-5-21-3037839750-2636006196-3284199242"));
        // A local profile without SAM or registry name records stays unnamed.
        let local: Option<String> = conn
            .query_row("SELECT value FROM metadata WHERE kind='account' AND rid=1001", [], |r| r.get(0))
            .unwrap();
        assert_eq!(local, None);
    }

    #[test]
    fn conflicting_domain_account_records_stay_unresolved() {
        let fx = domain_fixture("domain-conflict", Some("NAMYANG\\2505002"), Some("NAMYANG\\someone"));
        assert!(fx.build() > 0);
        let (value, details): (Option<String>, String) = fx
            .db()
            .query_row(
                "SELECT value, details_json FROM metadata WHERE kind='account' AND key=?1",
                [DOMAIN_USER.to_lowercase()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(value, None);
        assert!(details.contains("NAMYANG\\\\someone") && details.contains("NAMYANG\\\\2505002"), "{details}");
    }

    #[test]
    fn a_single_sid_keyed_registry_record_names_the_domain_account() {
        for (tag, gp, logon, source, full) in [
            ("domain-gp-only", Some("NAMYANG\\2505002"), None, "group_policy_cache", None),
            ("domain-logon-only", None, Some("NAMYANG\\2505002"), "logonui", Some("박 상현")),
        ] {
            let fx = domain_fixture(tag, gp, logon);
            assert!(fx.build() > 0);
            let row: (Option<String>, Option<String>, Option<String>) = fx
                .db()
                .query_row(
                    "SELECT value, name_source, full_name FROM metadata WHERE kind='account' AND key=?1",
                    [DOMAIN_USER.to_lowercase()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(row.0.as_deref(), Some("NAMYANG\\2505002"), "{tag}");
            assert_eq!(row.1.as_deref(), Some(source), "{tag}");
            assert_eq!(row.2.as_deref(), full, "{tag}");
        }
    }

    #[test]
    fn virtual_accounts_resolve_only_when_sid_hash_matches() {
        // SIDs copied from the IDC_20261012_112701 ProfileList / SRUM.
        const TELEMETRY: &str = "S-1-5-80-2652535364-2169709536-2857650723-2622804123-1107741775";
        const FD_LAUNCHER: &str = "S-1-5-80-3263513310-3392720605-1798839546-683002060-3227631582";
        const AGENT: &str = "S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430";
        const SQLSERVER: &str = "S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003";
        const POOL: &str = "S-1-5-82-271721585-897601226-2024613209-625570482-296978595";
        let fx = Fixture::new("virtual-accounts");
        let profiles = [
            (TELEMETRY, "C:\\WINDOWS\\ServiceProfiles\\SQLTELEMETRY"),
            // Renamed folder: only the SYSTEM service list can prove this name.
            (FD_LAUNCHER, "C:\\WINDOWS\\ServiceProfiles\\Renamed"),
            (POOL, "C:\\Users\\.NET v4.5"),
            // Neither the folder nor any active service hashes to this SID.
            (SQLSERVER, "C:\\WINDOWS\\ServiceProfiles\\Other"),
        ]
        .map(|(sid, path)| (format!("\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}"), path));
        let base = base_software("D:\\Users\\analyst");
        let mut software: Vec<(&str, &str, &str, &str)> =
            base.iter().map(|(a, b, c, d)| (*a, *b, *c, d.as_str())).collect();
        for (key, path) in &profiles {
            software.push((key.as_str(), "ProfileImagePath", "REG_SZ", path));
        }
        fx.hive("SOFTWARE", &software);
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "1"),
                ("\\ROOT\\ControlSet001\\Services\\MSSQLFDLauncher", "ImagePath", "REG_EXPAND_SZ", "fd.exe"),
                ("\\ROOT\\ControlSet001\\Services\\SQLSERVERAGENT", "Start", "REG_DWORD", "2"),
                // Inactive ControlSet: not a candidate.
                ("\\ROOT\\ControlSet002\\Services\\MSSQLSERVER", "Start", "REG_DWORD", "2"),
            ],
        );
        let srum = fx.root.join("SRUM").join("SRUM_AppResourceUsage.sqlite");
        std::fs::create_dir_all(srum.parent().unwrap()).unwrap();
        let conn = Connection::open(&srum).unwrap();
        conn.execute_batch(
            "CREATE TABLE SRUM_AppResourceUsage (timestamp TEXT, app TEXT, user TEXT);
             INSERT INTO SRUM_AppResourceUsage VALUES ('t','a','S-1-5-90-0-3'),('t','a','S-1-5-96-0-0'),('t','a','S-1-5-18');",
        )
        .unwrap();
        drop(conn);
        crate::derived::stamp_facts_generation(&srum, FACTS_DATASET).unwrap();
        assert!(fx.build() > 0);

        let conn = fx.db();
        let row = |kind: &str, sid: &str| -> Option<(Option<String>, Option<String>, Option<String>)> {
            conn.query_row(
                "SELECT value, domain, name_source FROM metadata WHERE kind=?1 AND key=?2",
                [kind, &sid.to_lowercase()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok()
        };
        let named = |name: &str, domain: &str, source: &str| Some((Some(name.to_string()), Some(domain.to_string()), Some(source.to_string())));
        assert_eq!(row("account", TELEMETRY), named("NT SERVICE\\SQLTELEMETRY", "NT SERVICE", "service_sid_hash"));
        assert_eq!(row("account", FD_LAUNCHER), named("NT SERVICE\\MSSQLFDLauncher", "NT SERVICE", "service_sid_hash"));
        assert_eq!(row("account", POOL), named("IIS APPPOOL\\.NET v4.5", "IIS APPPOOL", "apppool_sid_hash"));
        assert_eq!(row("account", SQLSERVER), Some((None, None, None)));

        // Active services without a profile are stored apart from account rows.
        assert_eq!(row("virtual_account", AGENT), named("NT SERVICE\\SQLSERVERAGENT", "NT SERVICE", "service_sid_hash"));
        assert_eq!(row("virtual_account", SQLSERVER), None);
        assert_eq!(row("virtual_account", "S-1-5-90-0-3"), named("Window Manager\\DWM-3", "Window Manager", "fixed_virtual_sid"));
        assert_eq!(row("virtual_account", "S-1-5-96-0-0"), named("Font Driver Host\\UMFD-0", "Font Driver Host", "fixed_virtual_sid"));
        let (artifact, table, field): (String, String, String) = conn
            .query_row(
                "SELECT s.source_artifact, s.source_table, s.source_field FROM source_records s \
                 JOIN metadata m ON m.metadata_id = s.record_id WHERE m.key = 's-1-5-90-0-3'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((artifact.as_str(), table.as_str(), field.as_str()), ("SRUM", "SRUM_AppResourceUsage", "user"));

        let lookup = fx.lookup();
        assert_eq!(lookup.account(AGENT), Some("NT SERVICE\\SQLSERVERAGENT"));
        assert_eq!(lookup.account("S-1-5-90-0-3"), Some("Window Manager\\DWM-3"));
        assert_eq!(lookup.account("S-1-5-90-0-9"), None);
        assert_eq!(lookup.account(SQLSERVER), None);
        // Host account list stays limited to profile/SAM accounts.
        assert!(lookup.accounts().all(|a| !a.sid.eq_ignore_ascii_case(AGENT)));
    }

    #[test]
    fn sam_users_without_machine_sid_are_not_invented() {
        let fx = Fixture::new("nomachinesid");
        let user_v = user_v_hex("analyst", "");
        let user_f = user_f_hex(1001, 0x0210, 0);
        fx.hive(
            "SAM",
            &[
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "V",
                    "REG_BINARY",
                    user_v.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "F",
                    "REG_BINARY",
                    user_f.as_str(),
                ),
            ],
        );
        fx.build();
        let conn = fx.db();
        let accounts: i64 = conn
            .query_row("SELECT COUNT(*) FROM metadata WHERE kind='account'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(accounts, 0);
    }

    #[test]
    fn user_environment_wins_over_machine_scope() {
        let fx = Fixture::new("envprecedence");
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "1"),
                (
                    "\\ROOT\\ControlSet001\\Control\\Session Manager\\Environment",
                    "TEMP",
                    "REG_EXPAND_SZ",
                    "%SystemRoot%\\TEMP",
                ),
            ],
        );
        let account_v = account_v_hex([11, 22, 33]);
        fx.hive(
            "SAM",
            &[(
                "\\ROOT\\SAM\\Domains\\Account",
                "V",
                "REG_BINARY",
                account_v.as_str(),
            )],
        );
        write_software(&fx, base_software("D:\\Users\\analyst"));
        fx.hive(
            "analyst_NTUSER.DAT",
            &[
                (
                    "\\ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                    "AppData",
                    "REG_SZ",
                    "D:\\Users\\analyst\\AppData\\Roaming",
                ),
                (
                    "\\ROOT\\Environment",
                    "TEMP",
                    "REG_EXPAND_SZ",
                    "%USERPROFILE%\\AppData\\Local\\Temp",
                ),
            ],
        );
        fx.build();

        let lookup = fx.lookup();
        let sid = format!("{}-1001", machine_sid());
        assert_eq!(lookup.env_value("temp", None), Some("D:\\test\\TEMP"));
        assert_eq!(
            lookup.env_value("TEMP", Some(&sid)),
            Some("D:\\Users\\analyst\\AppData\\Local\\Temp")
        );
        assert_eq!(
            lookup.resolve_path("%TEMP%\\x.log", None).as_deref(),
            Some("D:\\test\\TEMP\\x.log")
        );
        assert_eq!(
            lookup.resolve_path("%SystemRoot%\\System32\\cmd.exe", None).as_deref(),
            Some("D:\\test\\System32\\cmd.exe")
        );
        assert_eq!(
            lookup.resolve_path("%systemroot%\\notepad.exe", None).as_deref(),
            Some("D:\\test\\notepad.exe")
        );
        assert_eq!(lookup.resolve_path("D:\\test\\cmd.exe", None), None);
        assert_eq!(lookup.env_value("systemdrive", None), Some("D:"));
        assert_eq!(
            lookup
                .account_entry("S-1-5-21-11-22-33-1001")
                .and_then(|a| a.profile_path.clone())
                .as_deref(),
            Some("D:\\Users\\analyst")
        );
        assert_eq!(lookup.sid_for_profile_path("D:\\Users\\analyst\\Desktop\\a.txt"), Some(sid.as_str()));
    }

    #[test]
    fn cyclic_and_undefined_variables_stay_unresolved() {
        let fx = Fixture::new("envcycle");
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "1"),
                (
                    "\\ROOT\\ControlSet001\\Control\\Session Manager\\Environment",
                    "LOOPA",
                    "REG_EXPAND_SZ",
                    "%LOOPB%\\a",
                ),
                (
                    "\\ROOT\\ControlSet001\\Control\\Session Manager\\Environment",
                    "LOOPB",
                    "REG_EXPAND_SZ",
                    "%LOOPA%\\b",
                ),
                (
                    "\\ROOT\\ControlSet001\\Control\\Session Manager\\Environment",
                    "ORPHAN",
                    "REG_EXPAND_SZ",
                    "%NOPE%\\x",
                ),
            ],
        );
        fx.build();
        let conn = fx.db();
        for key in ["loopa", "loopb", "orphan"] {
            let (value, status, raw): (Option<String>, String, Option<String>) = conn
                .query_row(
                    "SELECT value, resolution_status, raw_value FROM metadata \
                     WHERE kind='env' AND scope='machine' AND key=?1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(value, None, "{key} must not invent a value");
            assert_eq!(status, "unresolved");
            assert!(raw.is_some(), "{key} keeps the raw value");
        }
        let lookup = fx.lookup();
        assert_eq!(lookup.resolve_path("%NOPE%\\x", None), None);
    }

    #[test]
    fn conflicting_values_are_null_with_candidate_source_refs() {
        let fx = Fixture::new("conflict");
        write_software(
            &fx,
            vec![
                (
                    "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion",
                    "ProductName",
                    "REG_SZ",
                    "Windows 10 Pro".to_string(),
                ),
                (
                    "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion",
                    "ProductName",
                    "REG_SZ",
                    "Windows Server 2019".to_string(),
                ),
            ],
        );
        fx.build();
        let conn = fx.db();
        let (metadata_id, value, status): (String, Option<String>, String) = conn
            .query_row(
                "SELECT metadata_id, value, resolution_status FROM metadata \
                 WHERE kind='host' AND key='os_name'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(value, None);
        assert_eq!(status, "conflict");

        let candidates: Vec<(String, i64)> = conn
            .prepare(
                "SELECT candidate_value, source_ordinal FROM MetadataCandidates \
                 WHERE metadata_id=?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([&metadata_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].0, "Windows 10 Pro");
        assert_eq!(candidates[1].0, "Windows Server 2019");

        // Every candidate must resolve to an actual facts row.
        for (_, ordinal) in &candidates {
            let (db, table, rowid, source_dataset): (String, String, i64, String) = conn
                .query_row(
                    "SELECT source_db, source_table, source_rowid, source_dataset_id \
                     FROM source_records WHERE record_id=?1 AND ordinal=?2",
                    rusqlite::params![metadata_id, ordinal],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(db, "REGISTRY/SOFTWARE.sqlite");
            assert_eq!(table, "Registry");
            assert_eq!(source_dataset, FACTS_DATASET);
            let raw = Connection::open_with_flags(
                fx.root.join(REGISTRY_DIR).join("SOFTWARE.sqlite"),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let exists: i64 = raw
                .query_row(
                    "SELECT COUNT(*) FROM Registry WHERE rowid=?1 AND value_name='ProductName'",
                    [rowid],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "source_rowid must address a real raw row");
        }
    }

    #[test]
    fn unstamped_facts_require_reparse_instead_of_invented_generation() {
        let fx = Fixture::new("unstamped");
        let db = fx.root.join(REGISTRY_DIR).join("SOFTWARE.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "CREATE TABLE \"Registry\" (last_write TEXT, key_path TEXT, value_name TEXT, \
             value_type TEXT, value_data TEXT, _recovery TEXT, _source_file TEXT, value_data_hex TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO \"Registry\" VALUES ('2026-01-02 03:04:05.678', \
             '\\ROOT\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName', 'REG_SZ', \
             'Windows 10 Pro', 'live', '/evidence/SOFTWARE', '')",
            [],
        )
        .unwrap();
        drop(conn);
        let err = build_metadata(&fx.root, Path::new("/evidence"), "host-1", "ds-1")
            .expect_err("unstamped facts must not be published with an invented generation");
        let text = format!("{err:#}");
        assert!(
            text.contains("_wina_facts_generation") || text.contains("재파싱"),
            "error must name the missing stamp: {text}"
        );
    }

    #[test]
    fn active_control_set_wins_and_regback_is_excluded() {
        let fx = Fixture::new("activeset");
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "2"),
                (
                    "\\ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName",
                    "ComputerName",
                    "REG_SZ",
                    "STALE-PC",
                ),
                (
                    "\\ROOT\\ControlSet002\\Control\\ComputerName\\ComputerName",
                    "ComputerName",
                    "REG_SZ",
                    "ACTIVE-PC",
                ),
            ],
        );
        fx.hive(
            "SYSTEM_RegBack",
            &[(
                "\\ROOT\\ControlSet002\\Control\\ComputerName\\ComputerName",
                "ComputerName",
                "REG_SZ",
                "BACKUP-PC",
            )],
        );
        fx.build();
        let lookup = fx.lookup();
        assert_eq!(lookup.computer_name(), Some("ACTIVE-PC"));
        let conn = fx.db();
        let status: String = conn
            .query_row(
                "SELECT resolution_status FROM metadata WHERE kind='host' AND key='computer_name'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "resolved");
    }

    #[test]
    fn network_children_keep_typed_addresses() {
        let fx = Fixture::new("network");
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "1"),
                (
                    "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{abc}",
                    "IPAddress",
                    "REG_MULTI_SZ",
                    "[\"192.168.10.200\"]",
                ),
                (
                    "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{abc}",
                    "SubnetMask",
                    "REG_MULTI_SZ",
                    "[\"255.255.255.0\"]",
                ),
                (
                    "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{abc}",
                    "DefaultGateway",
                    "REG_MULTI_SZ",
                    "[\"192.168.10.1\"]",
                ),
                (
                    "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{abc}",
                    "NameServer",
                    "REG_SZ",
                    "168.126.63.1,168.126.63.2",
                ),
                (
                    "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{abc}",
                    "EnableDHCP",
                    "REG_DWORD",
                    "0",
                ),
            ],
        );
        write_software(
            &fx,
            vec![
                (
                    "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\2",
                    "ServiceName",
                    "REG_SZ",
                    "{ABC}".to_string(),
                ),
                (
                    "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\2",
                    "Description",
                    "REG_SZ",
                    "Broadcom NetXtreme".to_string(),
                ),
            ],
        );
        fx.build();
        let conn = fx.db();
        let (metadata_id, value, dhcp): (String, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT metadata_id, value, dhcp_enabled FROM metadata \
                 WHERE kind='network' AND key='{abc}'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(value.as_deref(), Some("Broadcom NetXtreme"));
        assert_eq!(dhcp, Some(0));
        let (address, family, prefix, mask): (String, i64, i64, String) = conn
            .query_row(
                "SELECT address, family, prefix_length, subnet_mask FROM MetadataAddresses \
                 WHERE metadata_id=?1 AND ordinal=0",
                [&metadata_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(address, "192.168.10.200");
        assert_eq!(family, 4);
        assert_eq!(prefix, 24);
        assert_eq!(mask, "255.255.255.0");
        let dns: Vec<String> = conn
            .prepare("SELECT address FROM MetadataDnsServers WHERE metadata_id=?1 ORDER BY ordinal")
            .unwrap()
            .query_map([&metadata_id], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(dns, vec!["168.126.63.1", "168.126.63.2"]);
        let gateway: String = conn
            .query_row(
                "SELECT address FROM MetadataGateways WHERE metadata_id=?1 AND ordinal=0",
                [&metadata_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gateway, "192.168.10.1");
    }

    #[test]
    fn dhcp_lease_used_when_static_list_is_placeholder() {
        let fx = Fixture::new("network_dhcp");
        let key = "\\ROOT\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{dhcp}";
        fx.hive(
            "SYSTEM",
            &[
                ("\\ROOT\\Select", "Current", "REG_DWORD", "1"),
                (key, "IPAddress", "REG_MULTI_SZ", "[\"0.0.0.0\"]"),
                (key, "SubnetMask", "REG_MULTI_SZ", "[\"0.0.0.0\"]"),
                (key, "DefaultGateway", "REG_MULTI_SZ", "[\"0.0.0.0\"]"),
                (key, "DhcpIPAddress", "REG_SZ", "10.0.0.15"),
                (key, "DhcpSubnetMask", "REG_SZ", "255.255.255.0"),
                (key, "DhcpDefaultGateway", "REG_MULTI_SZ", "[\"10.0.0.1\"]"),
                (key, "EnableDHCP", "REG_DWORD", "1"),
            ],
        );
        fx.build();
        let conn = fx.db();
        let metadata_id: String = conn
            .query_row(
                "SELECT metadata_id FROM metadata WHERE kind='network' AND key='{dhcp}'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let (address, prefix): (String, i64) = conn
            .query_row(
                "SELECT address, prefix_length FROM MetadataAddresses \
                 WHERE metadata_id=?1 AND ordinal=0",
                [&metadata_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(address, "10.0.0.15");
        assert_eq!(prefix, 24);
        let gateway: String = conn
            .query_row(
                "SELECT address FROM MetadataGateways WHERE metadata_id=?1 AND ordinal=0",
                [&metadata_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gateway, "10.0.0.1");
    }

    #[test]
    fn empty_facts_produce_zero_rows() {
        let fx = Fixture::new("empty");
        assert_eq!(fx.build(), 0);
        let conn = fx.db();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM metadata", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn account_names_from_facts_returns_confirmed_mappings_only() {
        let fx = Fixture::new("namemap");
        let account_v = account_v_hex([11, 22, 33]);
        let user_v = user_v_hex("analyst", "");
        let user_f = user_f_hex(1001, 0x0210, 0);
        fx.hive(
            "SAM",
            &[
                (
                    "\\ROOT\\SAM\\Domains\\Account",
                    "V",
                    "REG_BINARY",
                    account_v.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "V",
                    "REG_BINARY",
                    user_v.as_str(),
                ),
                (
                    "\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9",
                    "F",
                    "REG_BINARY",
                    user_f.as_str(),
                ),
            ],
        );
        write_software(&fx, base_software("D:\\Users\\analyst"));
        let map = account_names_from_facts(&fx.root).unwrap();
        assert_eq!(
            map.get("S-1-5-21-11-22-33-1001").map(String::as_str),
            Some("analyst")
        );
        assert!(!map.contains_key("S-1-5-21-11-22-33-500"));
    }
}
