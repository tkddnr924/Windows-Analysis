//! _OVERVIEW correlation builders (port of processing.py + correlate.py). They
//! read the per-artifact SQLite the parse stage wrote (under CATEGORY/) and
//! produce the derived overview tables. Reading from disk (not an in-memory
//! all_results) keeps memory bounded for large hosts.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use crate::sam::{le_u16, le_u32, le_u64, unhex};
use crate::sqlite::Row;

/// Read an entire table as Vec<Row> (TEXT cells; NULL -> absent key). A
/// missing DB or table is no evidence (empty); open, prepare and row-scan
/// failures are errors, never a silently shortened table.
pub fn read_table(db: &Path, table: &str) -> anyhow::Result<Vec<Row>> {
    read_table_inner(db, table, false, None)
}

/// Read a table together with each SQLite rowid. 파생은 이 rowid로 원본 행을
/// 가리키는 근거(source_records)를 만든다 — 추가 컬럼(`__source_rowid`)은
/// 내부 식별용이며 분석가에게 보여 주는 데이터가 아니다.
pub fn read_table_with_rowid(db: &Path, table: &str) -> anyhow::Result<Vec<Row>> {
    read_table_inner(db, table, true, None)
}

fn read_table_inner(
    db: &Path,
    table: &str,
    include_rowid: bool,
    fields: Option<&[&str]>,
) -> anyhow::Result<Vec<Row>> {
    use anyhow::Context;
    if !db.exists() {
        return Ok(Vec::new());
    }
    let at = || format!("{}: {table}", db.display());
    let con = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).with_context(at)?;
    let present: bool = con
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name=?1 COLLATE NOCASE)",
            [table],
            |row| row.get(0),
        )
        .with_context(at)?;
    if !present {
        return Ok(Vec::new());
    }
    let query = if include_rowid {
        format!("SELECT rowid AS \"__source_rowid\", * FROM \"{}\"", table)
    } else {
        format!("SELECT * FROM \"{}\"", table)
    };
    let mut stmt = con.prepare(&query).with_context(at)?;
    let cols: Vec<(usize, String)> = stmt.column_names().iter().enumerate()
        .filter(|(_, name)| fields.is_none_or(|fields| fields.contains(name)))
        .map(|(index, name)| (index, (*name).to_string()))
        .collect();
    let mut out = Vec::new();
    let mut q = stmt.query([]).with_context(at)?;
    while let Some(r) = q.next().with_context(at)? {
        let mut row = Row::new();
        for (i, c) in &cols {
            let v = match r.get_ref(*i).with_context(at)? {
                ValueRef::Null => continue,
                ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                ValueRef::Integer(n) => n.to_string(),
                ValueRef::Real(f) => f.to_string(),
                ValueRef::Blob(b) => crate::hex::hex_lower(b),
            };
            row.insert(c.clone(), v);
        }
        out.push(row);
    }
    Ok(out)
}

/// True for a live registry row (not a recovered-deleted entry). The Rust
/// registry parser additionally recovers deleted cells / transaction-log
/// entries and marks them in `_recovery`; those enrich the RAW registry tables
/// but the overview correlations mirror Python's live-only semantics, so they
/// are filtered here. (A row without the column is treated as live.)
fn is_live(r: &Row) -> bool {
    r.get("_recovery").map(|v| v == "live").unwrap_or(true)
}

/// Sorted `*.sqlite` files of a category folder; a missing folder is empty,
/// any other listing failure is an error.
fn sqlite_files(dir: &Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    use anyhow::Context;
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| dir.display().to_string()),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.with_context(|| dir.display().to_string())?.path();
        if path.extension().is_some_and(|x| x == "sqlite") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

// --- Event-log access helpers (shared by Defender + correlate builders) ---

/// All rows from every EventLog table whose stem (filename, lowercased)
/// contains `needle`. Rows keep the table's rowid order. Mirrors Python's
/// iteration over all_results["EventLog"] filtered by stem substring.
pub fn read_eventlog(out_dir: &Path, needle: &str) -> anyhow::Result<Vec<Row>> {
    let mut out = Vec::new();
    for p in sqlite_files(&out_dir.join("EVENTLOG"))? {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if stem == "EventLogInputs" || !stem.to_lowercase().contains(needle) {
            continue;
        }
        out.extend(read_table(&p, &stem)?);
    }
    Ok(out)
}

/// EventLog 행 공유 캐시 — SMB/RDP/PowerShell/Defender 빌더가 같은 이벤트
/// 행을 각자 SQLite에서 다시 읽지 않도록 가공 단계 동안 한 번만 로드한다.
pub struct EventLogOverviewCache {
    rows: Vec<Row>,
}

impl EventLogOverviewCache {
    pub fn load(out_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            rows: read_eventlog(out_dir, "")?,
        })
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// 테스트 전용 — 파일 픽스처 없이 이벤트 행으로 캐시를 만든다.
    #[cfg(test)]
    pub(crate) fn from_rows_for_tests(rows: Vec<Row>) -> Self {
        Self { rows }
    }

    /// `_source_file` 스템에 `needle`(소문자)이 들어간 행만 — read_eventlog의
    /// 파일 스템 필터와 같은 의미.
    pub fn rows_from(&self, needle: &str) -> impl Iterator<Item = &Row> + '_ {
        let needle = needle.to_string();
        self.rows.iter().filter(move |row| {
            row.get("_source_file")
                .map(|source| {
                    Path::new(source)
                        .file_stem()
                        .map(|stem| stem.to_string_lossy().to_lowercase().contains(&needle))
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        })
    }
}

/// Parse an EventData JSON blob into a serde_json object (empty on error).
pub fn parse_eventdata(raw: &str) -> serde_json::Map<String, serde_json::Value> {
    if raw.is_empty() {
        return serde_json::Map::new();
    }
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    }
}

/// Field accessor: "" if absent/null, the string value, or a number rendered
/// as its plain string (matching how these string-valued fields are used).
pub fn jget(m: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    match m.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        Some(serde_json::Value::Bool(b)) => b.to_string(),
        Some(v) => v.to_string(),
    }
}

/// True if `candidate` should replace `current` as the earliest timestamp.
fn earlier(candidate: &str, current: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }
    if current.is_empty() {
        return true;
    }
    candidate < current
}

fn vstr(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// RegBack 백업 하이브 산출물(`<이름>_RegBack[.uniq].sqlite`) 여부 — facts에는
/// 보존하되 파생 뷰 입력에서는 제외한다. 라이브 하이브와 섞으면 오래된 값이
/// 현재 상태처럼 이중 표시되기 때문 (2026-08-31 사용자 확정).
fn is_regback_output(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    strip_uniq_suffix(&stem).ends_with("_regback")
}

/// 파이프라인이 이름 충돌을 피하려고 붙인 접미(`_2`, `_3`…)를 떼어 낸 stem.
/// 산출물 이름으로 하이브 종류·계정을 판정하는 파생 코드가 이 접미 때문에
/// 하이브를 통째로 건너뛰지 않게 한다.
fn strip_uniq_suffix(stem: &str) -> &str {
    match stem.rsplit_once('_') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => stem,
    }
}

/// `<계정>_NTUSER.DAT` / `<계정>_UsrClass.dat` 산출물 이름에서 계정을 떼어 낸다.
/// 접두가 없는 이름이면 None.
fn account_prefix(stem: &str) -> Option<&str> {
    let up = stem.to_uppercase();
    ["_NTUSER.DAT", "_USRCLASS.DAT"]
        .into_iter()
        .filter(|suffix| up.ends_with(suffix))
        .find_map(|suffix| stem.len().checked_sub(suffix.len()).and_then(|n| stem.get(..n)))
        .filter(|account| !account.is_empty())
}

// PowerShell history
fn read_registry_all(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let mut out = Vec::new();
    for p in sqlite_files(&out_dir.join("REGISTRY"))? {
        if is_regback_output(&p) {
            continue;
        }
        out.extend(read_table(&p, "Registry")?.into_iter().filter(is_live));
    }
    Ok(out)
}

pub(crate) fn basename_win(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.replace('/', "\\")
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

fn user_map(registry: &[Row]) -> std::collections::HashMap<String, String> {
    let mut umap = std::collections::HashMap::new();
    for r in registry {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\profilelist\\s-")
            && r.get("value_name")
                .map(|s| s.eq_ignore_ascii_case("ProfileImagePath"))
                .unwrap_or(false)
        {
            let sid = kp.rsplit('\\').next().unwrap_or("").to_string();
            let name = basename_win(&r.get("value_data").cloned().unwrap_or_default());
            if !sid.is_empty() && !name.is_empty() {
                umap.insert(sid, name);
            }
        }
    }
    umap
}

/// Local accounts for resolving classic PowerShell `UserId=HOST\user`.
struct LocalAccounts {
    computer: String,
    /// lower(name) -> (SAM name, RID)
    sam: std::collections::HashMap<String, (String, String)>,
    /// Machine domain SID from SAM `Domains\Account` V; "" when absent.
    machine_sid: String,
}

impl LocalAccounts {
    fn load(registry: &[Row]) -> Self {
        let computer = reg_pick_row(registry, "\\control\\computername\\computername", "ComputerName")
            .and_then(|r| r.get("value_data").cloned())
            .unwrap_or_default();
        let mut sam = std::collections::HashMap::new();
        let mut machine_sid = String::new();
        let names = "\\sam\\domains\\account\\users\\names\\";
        for r in registry {
            let kp = r.get("key_path").cloned().unwrap_or_default();
            let low = kp.to_lowercase();
            if let Some(i) = low.find(names) {
                // SAM stores the RID as the Names\<user> default value's type.
                let name = &kp[i + names.len()..];
                let rid = r.get("value_type").cloned().unwrap_or_default();
                if !name.is_empty() && !name.contains('\\') && rid.chars().all(|c| c.is_ascii_digit()) && !rid.is_empty() {
                    sam.insert(name.to_lowercase(), (name.to_string(), rid));
                }
            } else if low.ends_with("\\sam\\domains\\account")
                && r.get("value_name").map(|v| v == "V").unwrap_or(false)
            {
                if let Some(sid) = crate::sam::machine_sid_from_v(r.get("value_data").map_or("", String::as_str)) {
                    machine_sid = sid;
                }
            }
        }
        Self { computer, sam, machine_sid }
    }

    /// `HOST\user` names this machine's local `user` only when HOST equals the
    /// stored ComputerName and SAM has the user. The SID is the SAM machine
    /// SID + RID; without the machine SID it stays "".
    fn resolve(&self, user_id: &str) -> Option<(String, String)> {
        let (host, user) = user_id.split_once('\\')?;
        if self.computer.is_empty() || !host.eq_ignore_ascii_case(&self.computer) {
            return None;
        }
        let (name, rid) = self.sam.get(&user.to_lowercase())?;
        let sid = if self.machine_sid.is_empty() { String::new() } else { format!("{}-{rid}", self.machine_sid) };
        Some((name.clone(), sid))
    }
}

fn all_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Object(m) => {
            for x in m.values() {
                all_strings(x, out);
            }
        }
        serde_json::Value::Array(a) => {
            for x in a {
                all_strings(x, out);
            }
        }
        _ => {}
    }
}

// Only known field labels delimit multiline command values.
const CTX_LABELS: &[&str] = &[
    "severity",
    "host name",
    "host version",
    "host id",
    "host application",
    "engine version",
    "runspace id",
    "pipeline id",
    "command name",
    "command type",
    "script name",
    "command path",
    "sequence number",
    "user",
    "connected user",
    "shell id",
    "user data",
    "심각도",
    "호스트 이름",
    "호스트 버전",
    "호스트 id",
    "호스트 응용 프로그램",
    "엔진 버전",
    "런스페이스 id",
    "파이프라인 id",
    "명령 이름",
    "명령 유형",
    "스크립트 이름",
    "명령 경로",
    "시퀀스 번호",
    "사용자",
    "연결된 사용자",
    "셸 id",
    "쉘 id",
];

fn ps_detail_fields(blob: &str, keys: &[&str], separator: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(&str, usize)> = None;
    let mut offset = 0;
    let emit = |out: &mut Vec<(String, String)>, key: &str, start: usize, end: usize| {
        let value = &blob[start..end];
        // Remove the event-format separator, not command whitespace.
        let value = value.strip_suffix("\r\n").or_else(|| value.strip_suffix('\n')).unwrap_or(value);
        out.push((key.to_string(), value.to_string()));
    };
    for line in blob.split_inclusive('\n') {
        if let Some((label, tail)) = line.split_once(separator) {
            let label = label.trim();
            if keys.iter().any(|key| key.eq_ignore_ascii_case(label)) {
                if let Some((key, start)) = current {
                    emit(&mut out, key, start, offset);
                }
                let tail = if separator == " =" { tail.strip_prefix(' ').unwrap_or(tail) } else { tail };
                current = Some((label, offset + line.len() - tail.len()));
            }
        }
        offset += line.len();
    }
    if let Some((key, start)) = current {
        emit(&mut out, key, start, blob.len());
    }
    out
}

fn ctx_fields(ctx: &str) -> Vec<(String, String)> {
    ps_detail_fields(ctx, CTX_LABELS, " =")
}

fn ctx_get(fields: &[(String, String)], tokens: &[&str]) -> String {
    fields.iter()
        .find(|(label, _)| tokens.iter().any(|token| label.eq_ignore_ascii_case(token)))
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

// Classic event detail strings use invariant Key=Value labels.
const CLASSIC_KEYS: &[&str] = &[
    "detailsequence",
    "detailtotal",
    "sequencenumber",
    "userid",
    "user",
    "hostname",
    "hostversion",
    "hostid",
    "hostapplication",
    "engineversion",
    "runspaceid",
    "pipelineid",
    "commandname",
    "commandtype",
    "scriptname",
    "commandpath",
    "commandline",
    "providername",
    "newproviderstate",
    "newenginestate",
    "previousenginestate",
    "errormessage",
    "severity",
];

fn classic_fields(ed: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, String)> {
    let mut strings = Vec::new();
    for value in ed.values() {
        all_strings(value, &mut strings);
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for blob in &strings {
        for (key, value) in ps_detail_fields(blob, CLASSIC_KEYS, "=") {
            if !out.iter().any(|(existing, _)| existing.eq_ignore_ascii_case(&key)) {
                out.push((key, value));
            }
        }
    }
    out
}

fn classic_get(fields: &[(String, String)], key: &str) -> String {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

// Session identifiers must exist in the source.
fn classic_session(row: &mut Row, fields: &[(String, String)]) {
    for (field, key) in [("session_id", "HostId"), ("runspace_id", "RunspaceId")] {
        let value = classic_get(fields, key);
        if !value.is_empty() {
            row.insert(field.to_string(), value);
        }
    }
}

// Preserve event context independently of the resolved account.
fn stamp_event(
    row: &mut Row,
    sid: &str,
    channel: &str,
    record_id: &str,
    level: &str,
    event_data: &str,
    source_file: &str,
) {
    for (field, value) in [
        ("account_sid", sid),
        ("event_channel", channel),
        ("event_record_id", record_id),
        ("event_level", level),
        ("event_data", event_data),
        ("_source_file", source_file),
    ] {
        if !value.is_empty() {
            row.insert(field.to_string(), value.to_string());
        }
    }
}

fn exe_from_host(host: &str) -> String {
    let h = host.trim();
    if h.is_empty() {
        return String::new();
    }
    let path = if let Some(rest) = h.strip_prefix('"') {
        match rest.find('"') {
            Some(e) => &rest[..e],
            None => rest,
        }
    } else if let Some(idx) = h
        .as_bytes()
        .windows(4)
        .position(|w| w.eq_ignore_ascii_case(b".exe"))
    {
        // "C:\Program Files\...\pwsh.exe -Command ..." 같은 비인용 경로가
        // 첫 공백에서 잘려 "Program"이 되지 않게 한다.
        &h[..idx + 4]
    } else {
        h.split(' ').next().unwrap_or(h)
    };
    let b = basename_win(path);
    if b.is_empty() {
        path.to_string()
    } else {
        b
    }
}

/// 이벤트가 남긴 정수 — 없거나 해석할 수 없으면 "모름"(None). 1 같은 기본값을
/// 넣으면 조각 번호·총수를 지어내는 것이 된다.
fn opt_int(v: Option<&serde_json::Value>) -> Option<i64> {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_i64(),
        Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)] // PowerShellHistory 행 고정 필드 세트
fn ps_row(
    timestamp: &str,
    account: &str,
    process: &str,
    process_id: &str,
    command: &str,
    script_block: &str,
    host_application: &str,
    kind: &str,
    event_id: &str,
    provider: &str,
    script_path: &str,
    record_key: &str,
) -> Row {
    let mut r = Row::new();
    r.insert("timestamp".into(), timestamp.into());
    r.insert("account".into(), account.into());
    r.insert("process".into(), process.into());
    r.insert("process_id".into(), process_id.into());
    r.insert("command".into(), command.into());
    r.insert("script_block".into(), script_block.into());
    // HostApplication is an independent execution evidence source in 4103/800.
    // Keep it even when CommandLine/Payload is empty: otherwise an investigator
    // loses the only recorded invocation context for the EventLog record.
    r.insert("host_application".into(), host_application.into());
    r.insert("kind".into(), kind.into());
    r.insert("event_id".into(), event_id.into());
    r.insert("provider".into(), provider.into());
    r.insert("script_path".into(), script_path.into());
    r.insert("record_key".into(), record_key.into());
    r
}

pub fn build_powershell_history_with_events(
    out_dir: &Path,
    events: &EventLogOverviewCache,
) -> anyhow::Result<Vec<Row>> {
    let registry = read_registry_all(out_dir)?;
    let umap = user_map(&registry);
    let locals = LocalAccounts::load(&registry);
    drop(registry);
    let account_for = |sid: &str| -> String {
        match umap.get(sid) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => sid.to_string(),
        }
    };
    let mut rows: Vec<Row> = Vec::new();
    // Keep every source event, including conflicting and duplicate fragments.
    struct ScriptPart {
        record_key: String,
        source_file: String,
        timestamp: String,
        number: Option<i64>,
        total: Option<i64>,
        text: String,
        event_data: String,
        event_record_id: String,
    }
    struct ScriptBlockGroup {
        row_index: usize,
        script_block_id: String,
        timestamp: String,
        sid: String,
        pid: String,
        path: String,
        record_key: String,
        source_file: String,
        channel: String,
        record_id: String,
        level: String,
        event_data: String,
        expected_total: Option<i64>,
        parts: Vec<ScriptPart>,
        bodies: std::collections::BTreeMap<i64, String>,
        conflicts: std::collections::BTreeSet<i64>,
        anomalies: Vec<String>,
    }
    fn push_once(anomalies: &mut Vec<String>, note: String) {
        if !anomalies.contains(&note) {
            anomalies.push(note);
        }
    }
    let mut groups: Vec<ScriptBlockGroup> = Vec::new();
    let mut group_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let event_id = r.get("EventID").cloned().unwrap_or_default();
        if !((provider == "Microsoft-Windows-PowerShell"
            && matches!(event_id.as_str(), "4100" | "4103" | "4104" | "40961"))
            || (provider == "PowerShell"
                && matches!(event_id.as_str(), "400" | "403" | "600" | "800")))
        {
            continue;
        }
        let raw_data = r.get("EventData").cloned().unwrap_or_default();
        let ed = parse_eventdata(&raw_data);
        let sid = r.get("UserID").cloned().unwrap_or_default();
        let pid = r.get("ProcessID").cloned().unwrap_or_default();
        let ts = r.get("timestamp").cloned().unwrap_or_default();
        let rk = r.get("_record_key").cloned().unwrap_or_default();
        let channel = r.get("Channel").cloned().unwrap_or_default();
        let computer = r.get("Computer").cloned().unwrap_or_default();
        let record_id = r.get("EventRecordID").cloned().unwrap_or_default();
        let level = r.get("Level").cloned().unwrap_or_default();
        let source_file = r.get("_source_file").cloned().unwrap_or_default();

        if provider == "Microsoft-Windows-PowerShell" && event_id == "4104" {
            let text = ed.get("ScriptBlockText").map(vstr).unwrap_or_default();
            let path = ed.get("Path").map(vstr).unwrap_or_default();
            let sbid = ed.get("ScriptBlockId").map(vstr).unwrap_or_default();
            let total = opt_int(ed.get("MessageTotal"));
            let number = opt_int(ed.get("MessageNumber"));
            // Scope block IDs to the source and recorded process identity.
            let identity = if sbid.is_empty() {
                format!("\u{1}no-id\u{1}{rk}\u{1}{}", rows.len())
            } else {
                [
                    rk.rsplit_once("::").map(|(table, _)| table).unwrap_or(""),
                    source_file.as_str(),
                    provider.as_str(),
                    channel.as_str(),
                    computer.as_str(),
                    pid.as_str(),
                    sid.as_str(),
                    sbid.as_str(),
                ]
                .join("\u{1}")
            };
            let index = match group_index.get(&identity).copied() {
                Some(index) => index,
                None => {
                    // Emit at the first fragment's position.
                    rows.push(Row::new());
                    groups.push(ScriptBlockGroup {
                        row_index: rows.len() - 1,
                        script_block_id: sbid.clone(),
                        timestamp: ts.clone(),
                        sid: sid.clone(),
                        pid: pid.clone(),
                        path: path.clone(),
                        record_key: rk.clone(),
                        source_file: source_file.clone(),
                        channel: channel.clone(),
                        record_id: record_id.clone(),
                        level: level.clone(),
                        event_data: raw_data.clone(),
                        expected_total: total,
                        parts: Vec::new(),
                        bodies: std::collections::BTreeMap::new(),
                        conflicts: std::collections::BTreeSet::new(),
                        anomalies: Vec::new(),
                    });
                    group_index.insert(identity, groups.len() - 1);
                    groups.len() - 1
                }
            };
            let slot = &mut groups[index];
            match (slot.expected_total, total) {
                (None, Some(_)) => slot.expected_total = total,
                (Some(prev), Some(now)) if prev != now => push_once(
                    &mut slot.anomalies,
                    format!("총 조각 수 불일치({prev} vs {now})"),
                ),
                _ => {}
            }
            if total.is_none() {
                push_once(&mut slot.anomalies, "총 조각 수 불명".into());
            }
            if total.is_some_and(|value| value <= 0) {
                push_once(&mut slot.anomalies, "유효하지 않은 총 조각 수".into());
            }
            match number {
                // Never infer an absent ordinal.
                None => push_once(&mut slot.anomalies, "조각 번호 불명".into()),
                Some(n) => {
                    let limit = slot.expected_total.unwrap_or(0).max(total.unwrap_or(0));
                    if n < 1 || (limit > 0 && n > limit) {
                        push_once(&mut slot.anomalies, format!("범위 밖 조각 번호 {n}"));
                    }
                    match slot.bodies.get(&n) {
                        // Preserve alternatives; the first body is representative only.
                        Some(existing) if *existing != text => {
                            slot.conflicts.insert(n);
                            push_once(&mut slot.anomalies, format!("조각 {n} 중복(내용 상이)"));
                        }
                        Some(_) => {}
                        None => {
                            slot.bodies.insert(n, text.clone());
                        }
                    }
                }
            }
            slot.parts.push(ScriptPart {
                record_key: rk.clone(),
                source_file: source_file.clone(),
                timestamp: ts.clone(),
                number,
                total,
                text,
                event_data: raw_data.clone(),
                event_record_id: record_id.clone(),
            });
            // Use the earliest fragment as the representative event.
            if !ts.is_empty() && (slot.timestamp.is_empty() || ts < slot.timestamp) {
                slot.timestamp = ts.clone();
                slot.record_key = rk.clone();
                slot.record_id = record_id.clone();
                slot.level = level.clone();
                slot.event_data = raw_data.clone();
            }
            if slot.path.is_empty() && !path.is_empty() {
                slot.path = path.clone();
            }
        } else if provider == "Microsoft-Windows-PowerShell"
            && (event_id == "4103" || event_id == "4100")
        {
            let ctx = ed.get("ContextInfo").map(vstr).unwrap_or_default();
            let fields = ctx_fields(&ctx);
            let host = ctx_get(&fields, &["Host Application", "호스트 응용 프로그램"]);
            let user = ctx_get(&fields, &["User", "사용자"]);
            let command_name = ctx_get(&fields, &["Command Name", "명령 이름"]);
            let script_name = ctx_get(&fields, &["Script Name", "스크립트 이름"]);
            let payload = ed.get("Payload").map(vstr).unwrap_or_default();
            // An error payload is not an executed command.
            let is_problem = event_id == "4100";
            let command = if is_problem || payload.trim().is_empty() {
                command_name
            } else {
                payload.clone()
            };
            let acct = if !user.is_empty() {
                user
            } else {
                account_for(&sid)
            };
            let proc = {
                let e = exe_from_host(&host);
                if e.is_empty() {
                    "powershell.exe".to_string()
                } else {
                    e
                }
            };
            // Preserve the distinction between errors and warnings.
            let kind = if !is_problem {
                "파이프라인"
            } else {
                match level.as_str() {
                    "1" | "2" => "실행 오류",
                    "3" => "실행 경고",
                    _ => "실행 오류·경고",
                }
            };
            let mut row = ps_row(
                &ts,
                &acct,
                &proc,
                &pid,
                &command,
                "",
                &host,
                kind,
                &event_id,
                &provider,
                &script_name,
                &rk,
            );
            if !ctx.is_empty() {
                row.insert("context_info".into(), ctx);
            }
            if is_problem && !payload.is_empty() {
                // Error payload is evidence, not an executed command.
                row.insert("error_message".into(), payload);
            }
            // Never infer session identifiers.
            for (field, tokens) in [
                ("session_id", ["Host ID", "호스트 ID"]),
                ("runspace_id", ["Runspace ID", "런스페이스 ID"]),
            ] {
                let value = ctx_get(&fields, &tokens);
                if !value.is_empty() {
                    row.insert(field.into(), value);
                }
            }
            stamp_event(
                &mut row,
                &sid,
                &channel,
                &record_id,
                &level,
                &raw_data,
                &source_file,
            );
            rows.push(row);
        } else if provider == "PowerShell" && event_id == "800" {
            let fields = classic_fields(&ed);
            let host = classic_get(&fields, "HostApplication");
            let command = classic_get(&fields, "CommandLine");
            // Classic 800 events record the invoked .ps1 as ScriptName=; surface
            // it as the row's script path so the PowerShell view shows it beside
            // the host application instead of leaving the column empty.
            let script_name = classic_get(&fields, "ScriptName");
            // Classic Windows PowerShell events frequently leave the outer
            // UserID empty while carrying the actual user in EventData.
            let event_user = classic_get(&fields, "UserId");
            // `THISHOST\user` is the SAM local account: store its name and,
            // when uniquely known, its SID. Other domains stay verbatim.
            let (account, account_sid) = if event_user.is_empty() {
                (account_for(&sid), sid.clone())
            } else if let Some((name, local_sid)) = locals.resolve(&event_user) {
                let resolved = if local_sid.is_empty() { sid.clone() } else { local_sid };
                (name, resolved)
            } else {
                (event_user, sid.clone())
            };
            // Event 800 can have no CommandLine while still carrying the
            // launching HostApplication. Preserve that evidence rather than
            // dropping the raw-event-linked overview row.
            if command.is_empty() && host.is_empty() {
                continue;
            }
            let proc = {
                let e = exe_from_host(&host);
                if e.is_empty() {
                    "powershell.exe".to_string()
                } else {
                    e
                }
            };
            let mut row = ps_row(
                &ts,
                &account,
                &proc,
                &pid,
                &command,
                "",
                &host,
                "명령 실행",
                &event_id,
                &provider,
                &script_name,
                &rk,
            );
            classic_session(&mut row, &fields);
            stamp_event(
                &mut row,
                &account_sid,
                &channel,
                &record_id,
                &level,
                &raw_data,
                &source_file,
            );
            rows.push(row);
        } else if provider == "PowerShell" && (event_id == "400" || event_id == "403") {
            // 엔진 수명주기 — 400 시작(Available)/403 종료(Stopped). 명령은 없지만
            // HostApplication이 실행 주체를 남기는 독립 증거다.
            let fields = classic_fields(&ed);
            let host = classic_get(&fields, "HostApplication");
            let proc = {
                let e = exe_from_host(&host);
                if e.is_empty() {
                    "powershell.exe".to_string()
                } else {
                    e
                }
            };
            let kind = if event_id == "400" {
                "엔진 시작"
            } else {
                "엔진 종료"
            };
            let mut row = ps_row(
                &ts,
                &account_for(&sid),
                &proc,
                &pid,
                "",
                "",
                &host,
                kind,
                &event_id,
                &provider,
                "",
                &rk,
            );
            classic_session(&mut row, &fields);
            stamp_event(
                &mut row,
                &sid,
                &channel,
                &record_id,
                &level,
                &raw_data,
                &source_file,
            );
            rows.push(row);
        } else if provider == "PowerShell" && event_id == "600" {
            // 공급자 시작은 세션마다 여러 건 나와 시끄럽다 — 원격(WinRM) 사용
            // 흔적인 WSMan 공급자만 남긴다.
            let fields = classic_fields(&ed);
            let provider_name = {
                let token = classic_get(&fields, "ProviderName");
                if token.is_empty() {
                    let mut strs = Vec::new();
                    for value in ed.values() {
                        all_strings(value, &mut strs);
                    }
                    strs.first().cloned().unwrap_or_default()
                } else {
                    token
                }
            };
            if !provider_name.eq_ignore_ascii_case("wsman") {
                continue;
            }
            let host = classic_get(&fields, "HostApplication");
            let proc = {
                let e = exe_from_host(&host);
                if e.is_empty() {
                    "powershell.exe".to_string()
                } else {
                    e
                }
            };
            let mut row = ps_row(
                &ts,
                &account_for(&sid),
                &proc,
                &pid,
                "",
                "",
                &host,
                "원격 공급자 시작",
                &event_id,
                &provider,
                "",
                &rk,
            );
            classic_session(&mut row, &fields);
            stamp_event(
                &mut row,
                &sid,
                &channel,
                &record_id,
                &level,
                &raw_data,
                &source_file,
            );
            rows.push(row);
        } else if provider == "Microsoft-Windows-PowerShell" && event_id == "40961" {
            // 콘솔 시작 — 클래식 400과 달리 UserID(SID)가 남는 실행 증거.
            let mut row = ps_row(
                &ts,
                &account_for(&sid),
                "powershell.exe",
                &pid,
                "",
                "",
                "",
                "콘솔 시작",
                &event_id,
                &provider,
                "",
                &rk,
            );
            stamp_event(
                &mut row,
                &sid,
                &channel,
                &record_id,
                &level,
                &raw_data,
                &source_file,
            );
            rows.push(row);
        }
    }

    for group in groups {
        let mut text = String::new();
        for body in group.bodies.values() {
            text.push_str(body);
        }
        // Append unknown ordinals without claiming their position is known.
        for part in group.parts.iter().filter(|part| part.number.is_none()) {
            text.push_str(&part.text);
        }
        // Gap ranges scale with observed parts, not the declared total.
        let missing: Vec<(i64, i64)> = match group.expected_total {
            Some(expected) if expected >= 1 => {
                let mut ranges = Vec::new();
                let mut prev = 0i64;
                for n in group
                    .bodies
                    .keys()
                    .copied()
                    .filter(|n| *n >= 1 && *n <= expected)
                {
                    if n > prev + 1 {
                        ranges.push((prev + 1, n - 1));
                    }
                    prev = n;
                }
                if prev < expected {
                    ranges.push((prev + 1, expected));
                }
                ranges
            }
            _ => Vec::new(),
        };
        let mut anomalies = group.anomalies.clone();
        if !missing.is_empty() {
            let spans: Vec<String> = missing
                .iter()
                .map(|(start, end)| {
                    if start == end {
                        start.to_string()
                    } else {
                        format!("{start}-{end}")
                    }
                })
                .collect();
            anomalies.push(format!("누락 조각: {}", spans.join(",")));
        }
        let mut row = ps_row(
            &group.timestamp,
            &account_for(&group.sid),
            "powershell.exe",
            &group.pid,
            "",
            &text,
            "",
            "스크립트 블록",
            "4104",
            "Microsoft-Windows-PowerShell",
            &group.path,
            &group.record_key,
        );
        if !group.script_block_id.is_empty() {
            row.insert("script_block_id".into(), group.script_block_id.clone());
        }
        if let Some(expected) = group.expected_total {
            row.insert("script_block_expected_parts".into(), expected.to_string());
        }
        // Observed count includes duplicate and conflicting source events.
        row.insert(
            "script_block_observed_parts".into(),
            group.parts.len().to_string(),
        );
        if !missing.is_empty() {
            let spans: Vec<serde_json::Value> = missing
                .iter()
                .map(|(start, end)| serde_json::json!({"start": start, "end": end}))
                .collect();
            row.insert(
                "script_block_missing".into(),
                serde_json::Value::Array(spans).to_string(),
            );
        }
        if !group.conflicts.is_empty() {
            let numbers: Vec<serde_json::Value> =
                group.conflicts.iter().map(|n| serde_json::json!(n)).collect();
            row.insert(
                "script_block_conflicts".into(),
                serde_json::Value::Array(numbers).to_string(),
            );
        }
        if !anomalies.is_empty() {
            let notes: Vec<serde_json::Value> = anomalies
                .iter()
                .map(|note| serde_json::Value::String(note.clone()))
                .collect();
            row.insert(
                "script_block_anomalies".into(),
                serde_json::Value::Array(notes).to_string(),
            );
            row.insert(
                "script_block_status".into(),
                format!("불완전 — {}", anomalies.join(" · ")),
            );
        }
        // Every child retains its own source coordinate and body.
        let parts: Vec<serde_json::Value> = group
            .parts
            .iter()
            .map(|part| {
                let mut obj = serde_json::Map::new();
                for (field, value) in [
                    ("record_key", &part.record_key),
                    ("_source_file", &part.source_file),
                    ("timestamp", &part.timestamp),
                    ("script_block", &part.text),
                    ("event_data", &part.event_data),
                    ("event_record_id", &part.event_record_id),
                ] {
                    if !value.is_empty() {
                        obj.insert(field.into(), serde_json::Value::String(value.clone()));
                    }
                }
                for (field, value) in
                    [("message_number", part.number), ("message_total", part.total)]
                {
                    if let Some(value) = value {
                        obj.insert(field.into(), serde_json::Value::String(value.to_string()));
                    }
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        row.insert(
            "script_block_parts".into(),
            serde_json::Value::Array(parts).to_string(),
        );
        stamp_event(
            &mut row,
            &group.sid,
            &group.channel,
            &group.record_id,
            &group.level,
            &group.event_data,
            &group.source_file,
        );
        rows[group.row_index] = row;
    }

    // PSReadLine serializes embedded newlines as a trailing backtick plus EOL.
    let console_db = out_dir.join("POWERSHELL").join("PowerShell_ConsoleHistory.sqlite");
    let mut console_rows = read_table_with_rowid(&console_db, "PowerShell_ConsoleHistory")?;
    let physical_line = |r: &Row| r.get("line_number").and_then(|v| v.parse::<i64>().ok());
    console_rows.sort_by(|a, b| {
        a.get("_source_file").cmp(&b.get("_source_file"))
            .then(a.get("user").cmp(&b.get("user")))
            .then(physical_line(a).cmp(&physical_line(b)))
            .then(a.get("__source_rowid").cmp(&b.get("__source_rowid")))
    });
    let mut input = console_rows.into_iter().peekable();
    while let Some(mut current) = input.next() {
        if current.get("command").is_none_or(|command| command.trim().is_empty()) {
            continue;
        }
        let account = current.get("user").cloned().unwrap_or_default();
        let source = current.get("_source_file").cloned().unwrap_or_default();
        let first_line = current.get("line_number").cloned().unwrap_or_default();
        let record_key = current.get("__source_rowid")
            .map(|rowid| format!("PowerShell_ConsoleHistory::{rowid}")).unwrap_or_default();
        let mut command = String::new();
        let mut lines = Vec::new();
        let mut status = None;
        loop {
            let line_number = physical_line(&current);
            let raw = current.remove("command").unwrap_or_default();
            let continued = raw.ends_with('`');
            if let Some(body) = raw.strip_suffix('`') {
                command.push_str(body);
                command.push('\n');
            } else {
                command.push_str(&raw);
            }
            let mut line = Row::new();
            line.insert("command".into(), raw);
            for field in ["line_number", "_source_file"] {
                if let Some(value) = current.remove(field) {
                    line.insert(field.into(), value);
                }
            }
            if let Some(rowid) = current.remove("__source_rowid") {
                line.insert("record_key".into(), format!("PowerShell_ConsoleHistory::{rowid}"));
            }
            lines.push(line);
            if !continued {
                break;
            }
            let Some(next) = input.peek() else {
                status = Some("incomplete_continuation");
                break;
            };
            if source.is_empty()
                || next.get("_source_file").map(String::as_str) != Some(source.as_str())
                || next.get("user").map(String::as_str).unwrap_or("") != account
            {
                status = Some("incomplete_continuation");
                break;
            }
            if line_number.and_then(|n| n.checked_add(1)).zip(physical_line(next))
                .is_none_or(|(expected, observed)| expected != observed)
            {
                status = Some("missing_line");
                break;
            }
            current = input.next().expect("peeked console line");
        }
        let mut row = ps_row("", &account, "powershell.exe", "", &command, "", "",
            "콘솔 히스토리", "", "PSReadLine", "", &record_key);
        row.insert("line_number".into(), first_line);
        row.insert("_source_file".into(), source);
        row.insert("console_lines".into(), serde_json::to_string(&lines).expect("console evidence rows"));
        if let Some(status) = status {
            row.insert("console_history_status".into(), status.into());
        }
        rows.push(row);
    }
    Ok(rows)
}

// --- TargetInfo ("TargetInfo") — system / accounts / networks / interfaces ---
pub const TI_KEYS: &[&str] = &[
    "timestamp",
    "category",
    "name",
    "value",
    "source_artifact",
    "username",
    "full_name",
    "rid",
    "rid_sam",
    "home_directory",
    "created",
    "last_login",
    "password_last_set",
    "last_failed_login",
    "login_count",
    "failed_login_count",
    "disabled",
    "special_account",
    "groups",
    "account_flags",
    "subnet_mask",
    "gateway",
    "dns_server",
    "dhcp_server",
    "dhcp_enabled",
    "domain",
    "lease_obtained",
    "lease_terminates",
];
/// 수집본의 hosts 파일(drivers/etc/hosts)에서 수동 등록 항목을 읽어
/// TargetInfo 행으로 만든다 — 호스트 간 관계 파악에 바로 쓰인다.
/// 유효 엔트리(IP + 이름, 주석 제외)가 없으면 빈 목록을 돌려 섹션이 숨는다.
pub fn ti_from_hosts_file(target: &Path) -> Vec<Row> {
    use std::str::FromStr;
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut files = crate::finder::by_name(target, &["hosts"]).paths;
    files.sort();
    for path in files {
        // 이름만으로는 오탐 가능 — etc 폴더 아래의 hosts만 대상.
        let in_etc = path
            .parent()
            .map(|p| {
                p.components().any(|c| {
                    c.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case("etc")
                })
            })
            .unwrap_or(false);
        if !in_etc {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (index, raw_line) in text.lines().enumerate() {
            // '#' 이후는 주석 — 줄 중간 주석도 잘라낸다.
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(ip) = parts.next() else { continue };
            if std::net::IpAddr::from_str(ip).is_err() {
                continue;
            }
            for name in parts {
                if !seen.insert((ip.to_string(), name.to_string())) {
                    continue;
                }
                rows.push(ti_row(&[
                    ("category", "HostsFile".into()),
                    ("name", name.into()),
                    ("value", ip.into()),
                    ("source_artifact", "hosts".into()),
                    // 수집 hosts 파일과 행 번호 — 파생의 원본 연결 근거.
                    ("_source_file", path.to_string_lossy().to_string()),
                    ("line_number", (index + 1).to_string()),
                    ("raw_line", raw_line.trim().to_string()),
                ]));
            }
        }
    }
    rows
}

fn ti_row(pairs: &[(&str, String)]) -> Row {
    let mut r = Row::new();
    for k in TI_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    for (k, v) in pairs {
        r.insert((*k).to_string(), v.clone());
    }
    r
}

/// FILETIME (100-ns since 1601) -> KST; "" for 0/unset.
fn filetime(value: u64) -> String {
    if value == 0 {
        String::new()
    } else {
        crate::time::fmt_filetime(value as i64)
    }
}

fn filetime_hex(hexstr: &str) -> String {
    let b = unhex(hexstr);
    if b.len() >= 8 {
        filetime(le_u64(&b, 0))
    } else {
        String::new()
    }
}

fn systemtime_hex(hexstr: &str) -> String {
    let b = unhex(hexstr);
    if b.len() < 16 {
        return String::new();
    }
    let (y, mo, d) = (le_u16(&b, 0), le_u16(&b, 2), le_u16(&b, 6));
    let (h, mi, s) = (le_u16(&b, 8), le_u16(&b, 10), le_u16(&b, 12));
    if y == 0 {
        String::new()
    } else {
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
    }
}

/// Unix epoch seconds -> KST "YYYY-MM-DD HH:MM:SS.000".
fn unixdate(value: &str) -> String {
    let ts: i64 = match value.trim().parse() {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if ts <= 0 {
        return String::new();
    }
    use chrono::{FixedOffset, TimeZone};
    let kst = FixedOffset::east_opt(9 * 3600).unwrap();
    match kst.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(dt) => format!("{}.000", dt.format("%Y-%m-%d %H:%M:%S")),
        _ => String::new(),
    }
}

/// One loaded raw Registry SQLite input for an overview build.  Rows retain
/// their SQLite rowid so derived BAM records keep their original evidence
/// identity even when TargetInfo and RegistryFindings reuse the same cache.
#[derive(Clone)]
struct RegistryOverviewHive {
    name: String,
    database: std::path::PathBuf,
    rows: Vec<Row>,
}

impl RegistryOverviewHive {
    /// 원본 3-요소 record_key(`<파일>::Registry::<rowid>`)를 각 행에 미리
    /// 새겨 둔다 — rf_* 판정 함수들이 시그니처 변경 없이 매칭 행에서 증거
    /// 키를 파생 행으로 옮겨 담아, 개요 북마크가 원본 Registry 레코드로
    /// 승격될 수 있게 한다.
    fn load(database: std::path::PathBuf) -> anyhow::Result<Self> {
        // Correlations do not need the Explorer's raw payloads or cell metadata.
        let mut rows: Vec<Row> = read_table_inner(&database, "Registry", true, Some(&[
            "__source_rowid", "last_write", "key_path", "value_name", "value_type",
            "value_data", "_recovery", "_source_file",
        ]))?
            .into_iter()
            .filter(is_live)
            .collect();
        for row in rows.iter_mut() {
            let key = source_record_key(&database, "Registry", row);
            if !key.is_empty() {
                row.insert("__record_key".into(), key);
            }
        }
        Ok(Self {
            name: database
                .file_stem()
                .map(|stem| stem.to_string_lossy().to_string())
                .unwrap_or_default(),
            rows,
            database,
        })
    }
}

/// 캐시 행에 새겨 둔 원본 record_key — 직접 캐시에서 읽은 행이 아니면(합성
/// 값·테스트 픽스처) 빈 값이고, 그 행의 북마크는 파생 행에 남는다.
fn reg_record_key(row: &Row) -> String {
    row.get("__record_key").cloned().unwrap_or_default()
}

fn picked_record_key(row: Option<&Row>) -> String {
    row.map(reg_record_key).unwrap_or_default()
}

/// Bounded to one overview generation.  This avoids reopening every large
/// recovered hive for TargetInfo, BAM, and RegistryFindings while never
/// crossing a host/run boundary or changing the raw parser/recovery output.
pub struct RegistryOverviewCache {
    hives: Vec<RegistryOverviewHive>,
}

impl RegistryOverviewCache {
    pub fn load(out_dir: &Path) -> anyhow::Result<Self> {
        let hives = sqlite_files(&out_dir.join("REGISTRY"))?
            .into_iter()
            .filter(|path| !is_regback_output(path))
            // Full Explorer discovery must not broaden legacy analysis rules.
            .filter(|path| {
                let Some(stem) = path.file_stem() else { return false };
                let stem = stem.to_string_lossy();
                let stem = strip_uniq_suffix(&stem);
                crate::parsers::registry::REG_FILENAMES.iter()
                    .any(|name| stem.eq_ignore_ascii_case(name))
                    || crate::parsers::registry::REG_SUFFIXES.iter().any(|suffix| {
                        stem.get(stem.len().saturating_sub(suffix.len())..)
                            .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
                    })
            })
            .map(RegistryOverviewHive::load)
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { hives })
    }

    fn rows(&self, name: &str) -> &[Row] {
        self.hives
            .iter()
            .find(|hive| hive.name.eq_ignore_ascii_case(name))
            .map(|hive| hive.rows.as_slice())
            .unwrap_or(&[])
    }

    fn hives(&self) -> &[RegistryOverviewHive] {
        &self.hives
    }
}

/// SYSTEM 하이브의 Select\Current가 가리키는 활성 ControlSet 토큰
/// ("controlset002" 등). 값이 없거나 못 읽으면 종전 기본인 001 — LKG 부팅
/// 후 002가 활성인 증거에서 001의 낡은 값을 고르지 않기 위한 기준점이다.
fn active_control_set(rows: &[Row]) -> String {
    rows.iter()
        .find(|r| {
            r.get("key_path")
                .map(|k| k.to_lowercase().ends_with("\\select"))
                .unwrap_or(false)
                && r.get("value_name")
                    .map(|n| n.eq_ignore_ascii_case("Current"))
                    .unwrap_or(false)
        })
        .and_then(|r| r.get("value_data"))
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .map(|n| format!("controlset{:03}", n))
        .unwrap_or_else(|| "controlset001".into())
}

/// First matching row for a key ending in `key_suffix` + value_name,
/// preferring the active ControlSet (Select\Current, 기본 001) over stale
/// mirrors — the row form exists so RegistryFindings can carry the matched
/// row's record_key alongside the value. 값 이름은 레지스트리 의미대로
/// 대소문자를 무시한다 (소문자 변형으로 탐지를 우회하지 못하게).
fn reg_pick_row<'a>(rows: &'a [Row], key_suffix: &str, value_name: &str) -> Option<&'a Row> {
    let ks = key_suffix.to_lowercase();
    let hits: Vec<&Row> = rows
        .iter()
        .filter(|r| {
            r.get("key_path")
                .map(|k| k.to_lowercase().ends_with(&ks))
                .unwrap_or(false)
                && r.get("value_name")
                    .map(|v| v.eq_ignore_ascii_case(value_name))
                    .unwrap_or(false)
                && r.get("value_data").map(|v| !v.is_empty()).unwrap_or(false)
        })
        .collect();
    if hits.len() > 1 {
        let active = active_control_set(rows);
        if let Some(r) = hits.iter().find(|r| {
            r.get("key_path")
                .map(|k| k.to_lowercase().contains(&active))
                .unwrap_or(false)
        }) {
            return Some(r);
        }
    }
    hits.first().copied()
}

/// First non-empty value for a key ending in `key_suffix` + value_name,
/// preferring ControlSet001 over the ...002 backup.
fn reg_pick(rows: &[Row], key_suffix: &str, value_name: &str) -> String {
    reg_pick_row(rows, key_suffix, value_name)
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default()
}

/// SOFTWARE\Microsoft\Windows NT\CurrentVersion에서 TargetInfo로 올리는 값.
/// `SystemRoot`는 대상 호스트의 실제 Windows 설치 경로다 — 프로필 등에서
/// `%SystemRoot%`를 펼칠 때 분석 호스트의 `C:\Windows`를 가정하지 않고
/// 이 값(예: `D:\test`)을 써야 한다.
const OS_VALUES: &[&str] = &[
    "ProductName",
    "EditionID",
    "DisplayVersion",
    "CurrentBuild",
    "SystemRoot",
    "RegisteredOwner",
    "InstallDate",
];

fn ti_system_info(software: &[Row], system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let cv = "\\microsoft\\windows nt\\currentversion";
    let mut seen: HashSet<String> = HashSet::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let name = r.get("value_name").cloned().unwrap_or_default();
        if kp.to_lowercase().ends_with(cv) && OS_VALUES.contains(&name.as_str()) {
            if seen.contains(&name) {
                continue;
            }
            let data = r.get("value_data").cloned().unwrap_or_default();
            let val = if name == "InstallDate" {
                unixdate(&data)
            } else {
                data
            };
            if name == "InstallDate" && val.is_empty() {
                continue;
            }
            seen.insert(name.clone());
            rows.push(ti_row(&[
                ("category", "SystemInfo".into()),
                ("name", name),
                ("value", val),
                ("source_artifact", "SOFTWARE".into()),
                ("record_key", reg_record_key(r)),
            ]));
        }
    }
    if let Some(r) = reg_pick_row(
        system,
        "\\control\\computername\\computername",
        "ComputerName",
    ) {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "ComputerName".into()),
            ("value", r.get("value_data").cloned().unwrap_or_default()),
            ("source_artifact", "SYSTEM".into()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    if let Some(r) = reg_pick_row(system, "\\control\\timezoneinformation", "TimeZoneKeyName") {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "TimeZone".into()),
            ("value", r.get("value_data").cloned().unwrap_or_default()),
            ("source_artifact", "SYSTEM".into()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    if let Some(r) = reg_pick_row(system, "\\control\\windows", "ShutdownTime") {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "LastShutdownTime".into()),
            (
                "value",
                filetime_hex(&r.get("value_data").cloned().unwrap_or_default()),
            ),
            ("source_artifact", "SYSTEM".into()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

fn special_accounts(software: &[Row]) -> HashMap<String, String> {
    let mark = crate::sam::SPECIAL_ACCOUNTS_USERLIST_SUFFIX;
    let mut out = HashMap::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let vn = r.get("value_name").cloned().unwrap_or_default();
        if kp.to_lowercase().ends_with(mark) && !vn.is_empty() {
            out.insert(
                vn.to_lowercase(),
                r.get("value_data")
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            );
        }
    }
    out
}

fn ti_accounts(sam: &[Row], software: &[Row]) -> Vec<Row> {
    let hidden = special_accounts(software);
    // Local SIDs need the SAM machine SID; ProfileList may list domain SIDs.
    let mut prefix = String::new();
    let mut profile_keys: Vec<String> = Vec::new();
    let mut profiles: HashMap<String, String> = HashMap::new();
    // 프로필 경로를 남긴 레지스트리 행 — 계정 행의 원본 연결 근거.
    let mut profile_rk: HashMap<String, String> = HashMap::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\profilelist\\s-")
            && r.get("value_name")
                .map(|v| v.eq_ignore_ascii_case("ProfileImagePath"))
                .unwrap_or(false)
        {
            let sid = kp.rsplit('\\').next().unwrap_or("").to_string();
            if !profiles.contains_key(&sid) {
                profile_keys.push(sid.clone());
            }
            profile_rk.insert(sid.clone(), reg_record_key(r));
            profiles.insert(
                sid.clone(),
                r.get("value_data").cloned().unwrap_or_default(),
            );
        }
    }

    let mut user_keys: Vec<String> = Vec::new();
    // rid_hex -> (F, V, 원본 연결 record_key)
    let mut users: HashMap<String, (Vec<u8>, Vec<u8>, String)> = HashMap::new();
    let mut names_created: HashMap<String, String> = HashMap::new();
    let hexset = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    for r in sam {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if low.ends_with("\\sam\\domains\\account") && r.get("value_name").is_some_and(|v| v == "V") {
            if let Some(sid) = crate::sam::machine_sid_from_v(r.get("value_data").map_or("", String::as_str)) {
                prefix = sid;
            }
            continue;
        }
        let nmark = "\\sam\\domains\\account\\users\\names\\";
        if let Some(i) = low.find(nmark) {
            let tail = &kp[i + nmark.len()..];
            if !tail.is_empty() && !tail.contains('\\') {
                names_created.insert(
                    tail.to_lowercase(),
                    r.get("last_write").cloned().unwrap_or_default(),
                );
            }
            continue;
        }
        let umark = "\\users\\";
        if let Some(i) = low.rfind(umark) {
            let tail = &kp[i + umark.len()..];
            if tail.len() == 8 && hexset(tail) {
                if !users.contains_key(tail) {
                    user_keys.push(tail.to_string());
                    users.insert(tail.to_string(), (Vec::new(), Vec::new(), String::new()));
                }
                let entry = users.get_mut(tail).unwrap();
                match r.get("value_name").map(|s| s.as_str()) {
                    Some("F") => {
                        entry.0 = unhex(&r.get("value_data").cloned().unwrap_or_default());
                        if entry.2.is_empty() {
                            entry.2 = reg_record_key(r);
                        }
                    }
                    // 이름·전체 이름을 담은 V 값을 대표 근거로 삼는다.
                    Some("V") => {
                        entry.1 = unhex(&r.get("value_data").cloned().unwrap_or_default());
                        entry.2 = reg_record_key(r);
                    }
                    _ => {}
                }
            }
        }
    }

    let mut rows = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();
    for rid_hex in &user_keys {
        let (fb, vb, record_key) = users.get(rid_hex).unwrap();
        let rid = u32::from_str_radix(rid_hex, 16).unwrap_or(0);
        let f = crate::sam::sam_f(fb);
        let username = crate::sam::sam_v_field(vb, 1).unwrap_or_default();
        let full_name = crate::sam::sam_v_field(vb, 2).unwrap_or_default();
        let sid = if !prefix.is_empty() {
            format!("{}-{}", prefix, rid)
        } else {
            String::new()
        };
        let path = profiles.get(&sid).cloned().unwrap_or_default();
        let created = names_created
            .get(&username.to_lowercase())
            .cloned()
            .unwrap_or_default();
        let special = match hidden.get(&username.to_lowercase()) {
            None => String::new(),
            Some(sp) if sp == "0" || sp == "0x0" => "예 (로그온 화면 숨김)".into(),
            Some(sp) => format!("UserList 값 {}", sp),
        };
        let f_text = |pick: fn(&crate::sam::SamF) -> String| f.as_ref().map(pick).unwrap_or_default();
        let last_login = f_text(|f| filetime(f.last_login));
        if !sid.is_empty() {
            emitted.insert(sid.clone());
        }
        rows.push(ti_row(&[
            ("category", "Account".into()),
            ("name", sid.clone()),
            ("value", path.clone()),
            ("source_artifact", "SAM".into()),
            ("record_key", record_key.clone()),
            ("username", username),
            ("full_name", full_name),
            ("rid", rid.to_string()),
            ("rid_sam", f_text(|f| f.rid.to_string())),
            ("home_directory", path.clone()),
            ("created", created.clone()),
            ("last_login", last_login.clone()),
            ("password_last_set", f_text(|f| filetime(f.password_last_set))),
            ("last_failed_login", f_text(|f| filetime(f.last_failed_login))),
            ("login_count", f_text(|f| f.login_count.to_string())),
            ("failed_login_count", f_text(|f| f.failed_login_count.to_string())),
            ("disabled", f_text(|f| if f.disabled() { "예" } else { "아니오" }.into())),
            ("account_flags", f_text(|f| crate::sam::acb_flag_names(f.acb).collect::<Vec<_>>().join(", "))),
            ("special_account", special),
            (
                "timestamp",
                if !last_login.is_empty() {
                    last_login
                } else {
                    created
                },
            ),
        ]));
    }

    for sid in &profile_keys {
        if emitted.contains(sid) {
            continue;
        }
        let path = profiles.get(sid).cloned().unwrap_or_default();
        let uname = crate::sam::well_known_account(sid)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                let b = basename_win(path.trim_end_matches('\\'));
                if !b.is_empty() {
                    b
                } else {
                    sid.clone()
                }
            });
        rows.push(ti_row(&[
            ("category", "Account".into()),
            ("name", sid.clone()),
            ("value", path.clone()),
            ("source_artifact", "ProfileList".into()),
            ("username", uname),
            ("record_key", profile_rk.get(sid).cloned().unwrap_or_default()),
            ("home_directory", path),
        ]));
    }
    rows
}

fn iplist(value: &str) -> String {
    let s = value.trim();
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with('[') {
        match serde_json::from_str::<Vec<String>>(s) {
            Ok(v) => v
                .into_iter()
                .filter(|x| !x.is_empty() && x != "0.0.0.0")
                .collect::<Vec<_>>()
                .join(", "),
            Err(_) => s.to_string(),
        }
    } else if s == "0.0.0.0" {
        String::new()
    } else {
        s.to_string()
    }
}

fn ti_networks(software: &[Row]) -> Vec<Row> {
    let mut keys: Vec<String> = Vec::new();
    // kp -> (ProfileName, DateLastConnected, 원본 연결 record_key)
    let mut prof: HashMap<String, (String, String, String)> = HashMap::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\networklist\\profiles\\{") {
            if !prof.contains_key(&kp) {
                keys.push(kp.clone());
                prof.insert(kp.clone(), (String::new(), String::new(), String::new()));
            }
            let e = prof.get_mut(&kp).unwrap();
            let name = r.get("value_name").cloned().unwrap_or_default();
            if name.eq_ignore_ascii_case("ProfileName") {
                e.0 = r.get("value_data").cloned().unwrap_or_default();
                e.2 = reg_record_key(r);
            } else if name.eq_ignore_ascii_case("DateLastConnected") {
                e.1 = systemtime_hex(&r.get("value_data").cloned().unwrap_or_default());
                if e.2.is_empty() {
                    e.2 = reg_record_key(r);
                }
            }
        }
    }
    keys.iter()
        .filter_map(|k| {
            let (name, when, record_key) = prof.get(k).unwrap();
            if name.is_empty() {
                None
            } else {
                Some(ti_row(&[
                    ("category", "Network".into()),
                    ("name", "연결한 네트워크".into()),
                    ("value", name.clone()),
                    ("timestamp", when.clone()),
                    ("source_artifact", "NetworkList".into()),
                    ("record_key", record_key.clone()),
                ]))
            }
        })
        .collect()
}

fn ti_network_interfaces(system: &[Row]) -> Vec<Row> {
    let mark = "\\services\\tcpip\\parameters\\interfaces\\";
    let mut guids: Vec<String> = Vec::new();
    let mut ifaces: HashMap<String, HashMap<String, String>> = HashMap::new();
    // 인터페이스별 대표 근거 — 주소 값을 남긴 레지스트리 행.
    let mut iface_rk: HashMap<String, String> = HashMap::new();
    // 두 ControlSet의 같은 GUID 값을 한 맵에 덮으면 현재 IP와 과거
    // DNS/게이트웨이가 섞인, 실존한 적 없는 네트워크 구성이 만들어진다 —
    // 활성 세트(Select\Current)의 행만 조합한다.
    let active_set = active_control_set(system);
    for r in system {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains(&active_set) {
            continue;
        }
        if let Some(i) = low.find(mark) {
            let rest = &kp[i + mark.len()..];
            let guid = rest.split('\\').next().unwrap_or("").to_string();
            if !guid.starts_with('{') {
                continue;
            }
            if !ifaces.contains_key(&guid) {
                guids.push(guid.clone());
                ifaces.insert(guid.clone(), HashMap::new());
            }
            // 값 이름은 레지스트리 의미대로 대소문자 무시 — 소문자 키로
            // 정규화해 ipaddress 같은 변형도 같은 속성으로 조회되게 한다.
            let value_name_lower = r
                .get("value_name")
                .cloned()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(value_name_lower.as_str(), "ipaddress" | "dhcpipaddress")
                || !iface_rk.contains_key(&guid)
            {
                iface_rk.insert(guid.clone(), reg_record_key(r));
            }
            ifaces.get_mut(&guid).unwrap().insert(
                r.get("value_name")
                    .cloned()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                r.get("value_data").cloned().unwrap_or_default(),
            );
        }
    }
    let mut rows = Vec::new();
    for guid in &guids {
        let d = &ifaces[guid];
        let g = |k: &str| d.get(&k.to_ascii_lowercase()).cloned().unwrap_or_default();
        let ip = {
            let a = iplist(&g("IPAddress"));
            if !a.is_empty() {
                a
            } else {
                g("DhcpIPAddress")
            }
        };
        if ip.is_empty() || ip == "0.0.0.0" {
            continue;
        }
        let dhcp = g("EnableDHCP");
        let or = |a: String, b: String| if !a.is_empty() { a } else { b };
        rows.push(ti_row(&[
            ("category", "NetworkInterface".into()),
            ("name", guid.clone()),
            ("value", ip),
            ("source_artifact", "Tcpip".into()),
            (
                "subnet_mask",
                or(iplist(&g("SubnetMask")), g("DhcpSubnetMask")),
            ),
            (
                "gateway",
                or(iplist(&g("DefaultGateway")), g("DhcpDefaultGateway")),
            ),
            ("dns_server", or(g("NameServer"), g("DhcpNameServer"))),
            ("dhcp_server", g("DhcpServer")),
            (
                "dhcp_enabled",
                if dhcp == "1" {
                    "예".into()
                } else if dhcp == "0" {
                    "아니오".into()
                } else {
                    String::new()
                },
            ),
            ("domain", or(g("Domain"), g("DhcpDomain"))),
            ("lease_obtained", unixdate(&g("LeaseObtainedTime"))),
            ("lease_terminates", unixdate(&g("LeaseTerminatesTime"))),
            ("record_key", iface_rk.get(guid).cloned().unwrap_or_default()),
        ]));
    }
    rows
}

pub fn build_target_info_with_registry(registry: &RegistryOverviewCache) -> Vec<Row> {
    let software = registry.rows("SOFTWARE");
    let system = registry.rows("SYSTEM");
    let sam = registry.rows("SAM");
    let mut rows = Vec::new();
    rows.extend(ti_system_info(software, system));
    rows.extend(ti_accounts(sam, software));
    rows.extend(ti_networks(software));
    rows.extend(ti_network_interfaces(system));
    rows
}

// --- ExecutionHistory ("ExecutionHistory") — amcache + userassist + srum + bam ---
pub const ROW_KEYS: &[&str] = &[
    "timestamp",
    "program_name",
    "program_path",
    "run_count",
    "focus_count",
    "focus_time_ms",
    "publisher",
    "sha1",
    "user",
    "source_artifact",
    "record_key",
    // Prefetch preserves its execution-cache structure here so the common
    // ExecutionHistory detail can show the run-time ring, volume provenance
    // and linked loaded-file cache without a second, ambiguous lookup.
    "prefetch_hash",
    "run_time_2",
    "run_time_3",
    "run_time_4",
    "run_time_5",
    "run_time_6",
    "run_time_7",
    "run_time_8",
    "volume_device_path",
    "volume_serial_number",
    "volume_creation_time",
    "source_file",
];
fn eh_row(pairs: &[(&str, String)]) -> Row {
    let mut r = Row::new();
    for k in ROW_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    for (k, v) in pairs {
        r.insert((*k).to_string(), v.clone());
    }
    r
}

/// Keep the parsed database filename and raw SQLite rowid while building an
/// overview. The key is intentionally source-qualified because categories such
/// as AMCACHE can contain several SQLite databases with the same table name.
fn read_category_all_with_rowid(
    out_dir: &Path,
    category: &str,
    table: &str,
) -> anyhow::Result<Vec<(std::path::PathBuf, Row)>> {
    let mut out = Vec::new();
    for p in sqlite_files(&out_dir.join(category))? {
        let rows = read_table_with_rowid(&p, table)?;
        out.extend(rows.into_iter().map(|row| (p.clone(), row)));
    }
    Ok(out)
}

fn source_record_key(db: &Path, table: &str, row: &Row) -> String {
    let Some(rowid) = row.get("__source_rowid").filter(|value| !value.is_empty()) else {
        return String::new();
    };
    let file_name = db
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default();
    if file_name.is_empty() {
        return String::new();
    }
    format!("{}::{}::{}", file_name, table, rowid)
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

const UA_MARKERS: &[&str] = &["UEME_CTLSESSION", "UEME_CTLCUACount:ctor"];

fn eh_from_amcache(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for (db, r) in read_category_all_with_rowid(out_dir, "AMCACHE", "Amcache_Programs")? {
        let g = |k: &str| r.get(k).cloned().unwrap_or_default();
        rows.push(eh_row(&[
            ("timestamp", g("timestamp")),
            ("program_name", g("Name")),
            ("program_path", g("RootDirPath")),
            ("publisher", g("Publisher")),
            ("source_artifact", "Amcache_Programs".into()),
            ("record_key", source_record_key(&db, "Amcache_Programs", &r)),
        ]));
    }
    for (db, r) in read_category_all_with_rowid(out_dir, "AMCACHE", "Amcache_Files")? {
        let g = |k: &str| r.get(k).cloned().unwrap_or_default();
        rows.push(eh_row(&[
            ("timestamp", g("timestamp")),
            ("program_name", g("name")),
            ("program_path", g("lower_case_long_path")),
            ("publisher", g("publisher")),
            ("sha1", g("SHA1")),
            ("source_artifact", "Amcache_Files".into()),
            ("record_key", source_record_key(&db, "Amcache_Files", &r)),
        ]));
    }
    Ok(rows)
}

fn eh_from_userassist(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for p in sqlite_files(&out_dir.join("REGISTRY"))? {
        if is_regback_output(&p) {
            continue;
        }
        let raw_stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        // 이름 충돌 접미(`_2`)가 붙은 하이브도 같은 NTUSER.DAT이다 — 여기서
        // 떼지 않으면 그 계정의 UserAssist가 실행 이력에서 통째로 빠진다.
        let stem = strip_uniq_suffix(&raw_stem);
        if !stem.to_uppercase().ends_with("NTUSER.DAT") {
            continue;
        }
        let user = account_prefix(stem).unwrap_or(stem).to_string();
        for r in read_table_with_rowid(&p, "Registry")?
            .into_iter()
            .filter(is_live)
        {
            let kp = r.get("key_path").cloned().unwrap_or_default();
            let name = r.get("value_name").cloned().unwrap_or_default();
            if !kp.contains("UserAssist")
                || !kp.ends_with("\\Count")
                || name.is_empty()
                || name == "(default)"
            {
                continue;
            }
            let decoded = rot13(&name);
            if UA_MARKERS.contains(&decoded.as_str()) {
                continue;
            }
            let data = unhex(&r.get("value_data").cloned().unwrap_or_default());
            let (mut run_count, mut focus_count, mut focus_ms, mut ts) =
                (String::new(), String::new(), String::new(), String::new());
            if data.len() >= 68 {
                run_count = le_u32(&data, 4).to_string();
                focus_count = le_u32(&data, 8).to_string();
                focus_ms = le_u32(&data, 12).to_string();
                ts = filetime(le_u64(&data, 60));
            }
            rows.push(eh_row(&[
                ("timestamp", ts),
                ("program_name", basename_win(&decoded)),
                ("program_path", decoded),
                ("run_count", run_count),
                ("focus_count", focus_count),
                ("focus_time_ms", focus_ms),
                ("user", user.clone()),
                ("source_artifact", "UserAssist".into()),
                ("record_key", source_record_key(&p, "Registry", &r)),
            ]));
        }
    }
    Ok(rows)
}

fn eh_from_srum(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut earliest: HashMap<(String, String), (String, String)> = HashMap::new();
    for (db, r) in read_category_all_with_rowid(out_dir, "SRUM", "SRUM_ApplicationResourceUsage")? {
        let app = r.get("app").cloned().unwrap_or_default();
        if app.is_empty() || app.to_lowercase().starts_with("svc.") {
            continue;
        }
        let user = r.get("user").cloned().unwrap_or_default();
        let ts = r.get("timestamp").cloned().unwrap_or_default();
        let key = (app, user);
        match earliest.get(&key) {
            None => {
                order.push(key.clone());
                earliest.insert(
                    key,
                    (
                        ts,
                        source_record_key(&db, "SRUM_ApplicationResourceUsage", &r),
                    ),
                );
            }
            Some((cur, _)) => {
                if earlier(&ts, cur) {
                    earliest.insert(
                        key,
                        (
                            ts,
                            source_record_key(&db, "SRUM_ApplicationResourceUsage", &r),
                        ),
                    );
                }
            }
        }
    }
    Ok(order
        .into_iter()
        .map(|key| {
            let (ts, record_key) = earliest.get(&key).cloned().unwrap_or_default();
            let app = key.0.clone();
            let pname = {
                let b = basename_win(&app);
                if b.is_empty() {
                    app.clone()
                } else {
                    b
                }
            };
            eh_row(&[
                ("timestamp", ts),
                ("program_name", pname),
                ("program_path", app),
                ("user", key.1),
                ("source_artifact", "SRUM".into()),
                ("record_key", record_key),
            ])
        })
        .collect())
}

fn eh_from_bam_registry(registry: &RegistryOverviewCache) -> Vec<Row> {
    let mut rows = Vec::new();
    for hive in registry
        .hives()
        .iter()
        .filter(|hive| hive.name.eq_ignore_ascii_case("SYSTEM"))
    {
        for r in &hive.rows {
            let kp = r.get("key_path").cloned().unwrap_or_default();
            let low = kp.to_lowercase();
            if !low.contains("\\services\\bam") || !low.contains("\\usersettings\\") {
                continue;
            }
            let exe = r.get("value_name").cloned().unwrap_or_default();
            if !exe.to_lowercase().ends_with(".exe") {
                continue;
            }
            let after = kp.rsplit("UserSettings\\").next().unwrap_or("");
            let sid = after.split('\\').next().unwrap_or("").to_string();
            let data = unhex(&r.get("value_data").cloned().unwrap_or_default());
            let ts = if data.len() >= 8 {
                filetime(le_u64(&data, 0))
            } else {
                String::new()
            };
            rows.push(eh_row(&[
                ("timestamp", ts),
                ("program_name", basename_win(&exe)),
                ("program_path", exe),
                ("user", sid),
                ("source_artifact", "BAM".into()),
                (
                    "record_key",
                    source_record_key(&hive.database, "Registry", r),
                ),
            ]));
        }
    }
    rows
}

fn eh_from_prefetch(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let db = out_dir.join("PREFETCH").join("Prefetch_Execution.sqlite");
    Ok(read_table_with_rowid(&db, "Prefetch_Execution")?
        .into_iter()
        .map(|r| {
            let g = |k: &str| r.get(k).cloned().unwrap_or_default();
            eh_row(&[
                ("timestamp", g("last_run_time")),
                ("program_name", g("executable_filename")),
                ("run_count", g("run_count")),
                ("source_artifact", "Prefetch".into()),
                ("prefetch_hash", g("prefetch_hash")),
                ("run_time_2", g("run_time_2")),
                ("run_time_3", g("run_time_3")),
                ("run_time_4", g("run_time_4")),
                ("run_time_5", g("run_time_5")),
                ("run_time_6", g("run_time_6")),
                ("run_time_7", g("run_time_7")),
                ("run_time_8", g("run_time_8")),
                ("volume_device_path", g("volume_device_path")),
                ("volume_serial_number", g("volume_serial_number")),
                ("volume_creation_time", g("volume_creation_time")),
                ("source_file", g("_source_file")),
                (
                    "record_key",
                    source_record_key(&db, "Prefetch_Execution", &r),
                ),
            ])
        })
        .collect())
}

pub fn build_execution_history_with_registry(
    out_dir: &Path,
    registry: &RegistryOverviewCache,
    wer_starts: Vec<Row>,
) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    rows.extend(eh_from_amcache(out_dir)?);
    rows.extend(eh_from_userassist(out_dir)?);
    rows.extend(eh_from_srum(out_dir)?);
    rows.extend(eh_from_bam_registry(registry));
    // ShimCache(AppCompatCache)는 여기 넣지 않는다 — 항목의 FILETIME은 대상
    // 파일의 수정 시각이지 실행 시각이 아니므로 실행 이력·타임라인 증거로
    // 부적합(v0.9.35 확정 결정). RegistryFindings(기타 레지스트리/ShimCache)
    // 에서 그 단서와 함께 표시한다.
    rows.extend(eh_from_prefetch(out_dir)?);
    rows.extend(eh_from_timeline(out_dir)?);
    rows.extend(wer_starts);
    Ok(rows)
}

/// Windows Timeline의 실행/열기(ActivityType 5) 활동을 실행 이력에 합류시킨다.
/// 포커스(6)·클립보드 등 나머지 유형은 실행 기록이 아니므로 원본 테이블
/// (TIMELINE/Timeline_Activities)에서만 본다.
fn eh_from_timeline(out_dir: &Path) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    let db = out_dir
        .join("TIMELINE")
        .join("Timeline_Activities.sqlite");
    for r in read_table_with_rowid(&db, "Timeline_Activities")? {
        if r.get("activity_type").map(String::as_str) != Some("5") {
            continue;
        }
        let path = r.get("app_path").cloned().unwrap_or_default();
        let name = {
            let named = r.get("app_name").cloned().unwrap_or_default();
            if named.is_empty() { basename_win(&path) } else { named }
        };
        if name.is_empty() && path.is_empty() {
            continue;
        }
        rows.push(eh_row(&[
            ("timestamp", r.get("timestamp").cloned().unwrap_or_default()),
            ("program_name", name),
            ("program_path", path),
            ("user", r.get("account").cloned().unwrap_or_default()),
            ("source_artifact", "Timeline".into()),
            ("record_key", source_record_key(&db, "Timeline_Activities", &r)),
        ]));
    }
    Ok(rows)
}

// --- RegistryFindings ("레지스트리 특이사항") ---
pub const RF_KEYS: &[&str] = &[
    "timestamp",
    "category",
    "name",
    "value",
    "status",
    "detail",
    "key_path",
    "source",
    "command",
    "user",
    "subtype",
    "record_key",
];
/// 속성 맵에서 값 이름을 레지스트리 의미대로 대소문자 무시로 찾는다 —
/// 저장 키는 원문 casing을 유지해 properties 직렬화(상세 화면)에 그대로
/// 남기고, 조회만 관대하게 한다. casing만 바꾼 값(actions, displayname 등)이
/// 표시·판정에서 빠지면 안 되기 때문.
fn prop_ci<'a>(
    props: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Option<&'a String> {
    props
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn rf_row(pairs: &[(&str, String)]) -> Row {
    let mut r = Row::new();
    for k in RF_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    for (k, v) in pairs {
        r.insert((*k).to_string(), v.clone());
    }
    r
}

fn hive_user(fname: &str) -> String {
    let fname = strip_uniq_suffix(fname);
    let up = fname.to_uppercase();
    if up == "SOFTWARE" {
        return "(시스템)".into();
    }
    account_prefix(fname).unwrap_or(fname).to_string()
}

fn find_sub_local(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// ShimCache 헤더 매직으로 미지원 구포맷을 추정한다 — 파싱 불가 사유를
/// "아티팩트 없음"과 구분해 보고하기 위한 식별 전용(T0). Win7·Win8.x는
/// T1에서 지원 경로로 빠지므로 여기 도달하지 않는다.
fn shimcache_format_guess(magic: u32) -> &'static str {
    match magic {
        0xDEAD_BEEF => "Windows XP",
        0xBADC_0FFE => "Windows Vista/Server 2003",
        _ => "알 수 없는 구포맷",
    }
}

struct ShimcacheParse {
    entries: Vec<(String, u64)>,
    /// 데이터는 있으나 지원 포맷으로 해석하지 못한 경우의 포맷 식별 문구.
    /// None이면 지원 포맷(엔트리 0개 포함) 또는 빈 데이터.
    unsupported: Option<String>,
    /// 구포맷(Win7/Win8.x)에서 해석된 경우의 포맷 표기 — 파생 행 detail용.
    /// Win10/11 경로는 None(기존 출력 불변).
    format_note: Option<&'static str>,
}

impl ShimcacheParse {
    fn empty() -> Self {
        ShimcacheParse {
            entries: Vec::new(),
            unsupported: None,
            format_note: None,
        }
    }
}

const SHIM_NT61_HEADER: usize = 0x80; // Win7/Win8.x 공통 헤더 크기

/// Win7/2008R2 (매직 0xBADC0FEE). 헤더 0x80 + 고정 크기 엔트리 배열
/// (x86 32B / x64 48B), 경로는 블롭 절대 오프셋의 UTF-16LE.
/// 레이아웃(Mandiant ShimCacheParser 준거):
///   x86: Length(2) MaxLength(2) Offset(4) FILETIME(8) InsertFlags(4)
///        ShimFlags(4) BlobSize(4) BlobOffset(4)
///   x64: Length(2) MaxLength(2) 패딩(4) Offset(8) FILETIME(8) InsertFlags(4)
///        ShimFlags(4) BlobSize(8) BlobOffset(8)
fn parse_shimcache_win7(data: &[u8]) -> ShimcacheParse {
    let mut out = ShimcacheParse::empty();
    let count = le_u32(data, 4) as usize;
    if data.len() < SHIM_NT61_HEADER + 8 || count == 0 {
        return out;
    }
    // x64 판별: 엔트리+4..8은 x64에서 정렬 패딩(0), x86에서는 경로 오프셋
    // (헤더 크기 0x80 이상의 값)이라 0이 될 수 없다.
    let is64 = le_u32(data, SHIM_NT61_HEADER + 4) == 0;
    let (esize, note) = if is64 {
        (48usize, "Windows 7/Server 2008 R2 x64")
    } else {
        (32usize, "Windows 7/Server 2008 R2 x86")
    };
    for i in 0..count {
        let o = SHIM_NT61_HEADER + i * esize;
        if o + esize > data.len() {
            break;
        }
        let path_len = le_u16(data, o) as usize;
        let (path_off, ft) = if is64 {
            (le_u64(data, o + 8) as usize, le_u64(data, o + 16))
        } else {
            (le_u32(data, o + 4) as usize, le_u64(data, o + 8))
        };
        let path_bytes = path_off.checked_add(path_len).and_then(|end| data.get(path_off..end));
        if let Some(bytes) = path_bytes.filter(|_| path_len >= 2 && path_off >= SHIM_NT61_HEADER) {
            let u16s: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let path = String::from_utf16_lossy(&u16s);
            if !path.is_empty() && (path.contains('\\') || path.contains(':')) {
                out.entries.push((path, ft));
            }
        }
    }
    if out.entries.is_empty() {
        // 매직은 Win7인데 엔트리를 하나도 못 읽었다면 조용히 넘기지 않는다.
        out.unsupported = Some("헤더 0xBADC0FEE(Windows 7/Server 2008 R2)이나 엔트리 해석 실패".into());
    } else {
        out.format_note = Some(note);
    }
    out
}

/// 'NNts' 태그 엔트리 나열 공용 워커 (Win8.x/Win10 계열).
/// 엔트리: 태그(4) + unknown(4) + ce_size(4) + 데이터[ce_size].
/// 데이터: 경로길이 u16 + UTF-16LE 경로 + (ft_gap 바이트 건너뜀) + FILETIME.
/// ft_gap: Win10/11은 0, Win8.x는 8(InsertFlags·ShimFlags가 시각 앞에 온다).
fn walk_ts_entries(data: &[u8], start: usize, tag: &[u8; 4], ft_gap: usize) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    let mut off = Some(start);
    while let Some(o) = off {
        if o + 12 > data.len() || data.get(o..o + 4) != Some(tag.as_slice()) {
            break;
        }
        let ce_size = le_u32(data, o + 8) as usize;
        let estart = o + 12;
        let eend = (estart + ce_size).min(data.len());
        let entry = &data[estart..eend];
        if entry.len() >= 2 {
            let path_len = le_u16(entry, 0) as usize;
            if 2 + path_len + ft_gap + 8 <= entry.len() {
                let path_bytes = &entry[2..2 + path_len];
                let u16s: Vec<u16> = path_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let path = String::from_utf16_lossy(&u16s);
                let ft = le_u64(entry, 2 + path_len + ft_gap);
                if !path.is_empty() && (path.contains('\\') || path.contains(':')) {
                    entries.push((path, ft));
                }
            }
        }
        off = Some(o + 12 + ce_size);
    }
    entries
}

/// Win8.0('00ts')/Win8.1('10ts') — 헤더 u32가 헤더 크기(0x80)이고 엔트리가
/// 0x80에서 시작. Win10과 달리 FILETIME 앞에 InsertFlags(4)+ShimFlags(4)가 있다.
fn parse_shimcache_win8(data: &[u8]) -> ShimcacheParse {
    let mut out = ShimcacheParse::empty();
    let (tag, note): (&[u8; 4], &'static str) =
        if data.get(SHIM_NT61_HEADER..SHIM_NT61_HEADER + 4) == Some(b"00ts") {
            (b"00ts", "Windows 8.0/Server 2012")
        } else {
            (b"10ts", "Windows 8.1/Server 2012 R2")
        };
    out.entries = walk_ts_entries(data, SHIM_NT61_HEADER, tag, 8);
    if out.entries.is_empty() {
        out.unsupported = Some(format!(
            "헤더 0x80({note})이나 엔트리 해석 실패"
        ));
    } else {
        out.format_note = Some(note);
    }
    out
}

/// AppCompatCache 값 블롭 파서 — 헤더 매직으로 포맷을 디스패치한다.
/// Win7/2008R2·Win8.x·Win10/11 지원, XP·Vista/2003은 식별 문구만 보고(T0).
fn parse_shimcache(data: &[u8]) -> ShimcacheParse {
    let mut out = ShimcacheParse::empty();
    if data.is_empty() {
        return out;
    }
    if data.len() < 4 {
        out.unsupported = Some("손상 데이터 (4바이트 미만)".into());
        return out;
    }
    let magic = le_u32(data, 0);
    if magic == 0xBADC_0FEE {
        return parse_shimcache_win7(data);
    }
    if magic == 0x80
        && matches!(
            data.get(SHIM_NT61_HEADER..SHIM_NT61_HEADER + 4),
            Some(b"00ts") | Some(b"10ts")
        )
    {
        return parse_shimcache_win8(data);
    }
    // Win10/11: 헤더 u32가 첫 '10ts' 엔트리의 오프셋(0x30/0x34), FILETIME이
    // 경로 바로 뒤. 헤더가 어긋난 블롭은 종전대로 시그니처 스캔으로 복원.
    let header = magic as usize;
    let start =
        if header > 0 && header < data.len() && data.get(header..header + 4) == Some(b"10ts") {
            Some(header)
        } else {
            find_sub_local(data, b"10ts")
        };
    match start {
        Some(s) => {
            out.entries = walk_ts_entries(data, s, b"10ts", 0);
        }
        None => {
            out.unsupported = Some(format!(
                "헤더 0x{magic:08X} — {} 포맷 추정",
                shimcache_format_guess(magic)
            ));
        }
    }
    out
}

// A rule target is not evidence that the key or value exists.
fn registry_rule_path(rows: &[Row], suffix: &str, control_set: bool) -> String {
    let fallback = || format!("…\\{suffix}");
    let Some(root) = rows.iter().filter_map(|row| row.get("key_path"))
        .find(|path| path.starts_with('\\') && !path[1..].contains('\\')) else {
        return fallback();
    };
    if !control_set {
        return format!("{root}\\{suffix}");
    }
    let select_path = format!("{root}\\Select");
    let current = rows.iter().find(|row| {
        row.get("key_path").is_some_and(|path| path.eq_ignore_ascii_case(&select_path))
            && row.get("value_name").is_some_and(|name| name.eq_ignore_ascii_case("Current"))
    }).and_then(|row| row.get("value_data"))
        .and_then(|value| value.parse::<u32>().ok()).filter(|value| *value > 0);
    match current {
        Some(current) => format!("{root}\\ControlSet{current:03}\\{suffix}"),
        None => fallback(),
    }
}

fn rf_credential_protection(system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let wd_row = reg_pick_row(system, "\\securityproviders\\wdigest", "UseLogonCredential");
    let wd = wd_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    let wd_rk = picked_record_key(wd_row);
    if wd == "1" {
        rows.push(rf_row(&[("category", "자격 증명 보호".into()), ("name", "WDigest UseLogonCredential".into()), ("value", "1 (사용)".into()), ("status", "의심".into()),
            ("detail", "WDigest 평문 자격증명 캐시가 켜져 있음 — mimikatz(sekurlsa/wdigest) 등으로 LSASS에서 평문 암호 추출 가능 (공격자 사전작업 흔적)".into()),
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()), ("source", "SYSTEM".into()), ("record_key", wd_rk)]));
    } else if wd == "0" {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "WDigest UseLogonCredential".into()),
            ("value", "0 (사용 안 함)".into()),
            ("status", "정상".into()),
            ("detail", "WDigest 평문 자격증명 캐시 비활성".into()),
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()),
            ("source", "SYSTEM".into()),
            ("record_key", wd_rk),
        ]));
    } else {
        rows.push(rf_row(&[("category", "자격 증명 보호".into()), ("name", "WDigest UseLogonCredential".into()), ("value", "미설정 (기본값)".into()), ("status", "정보".into()),
            ("detail", "미설정 — 최신 Windows(8.1/2012 R2+)는 기본 비활성이나, 구버전이거나 값이 추가되면 평문 캐시가 켜질 수 있음".into()),
            ("key_path", wd_row.and_then(|row| row.get("key_path")).cloned()
                .unwrap_or_else(|| registry_rule_path(system, r"Control\SecurityProviders\WDigest", true))),
            ("source", "SYSTEM".into())]));
    }
    let ppl_row = reg_pick_row(system, "\\control\\lsa", "RunAsPPL");
    let ppl = ppl_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    let ppl_rk = picked_record_key(ppl_row);
    if ppl == "1" || ppl == "2" {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "LSASS 보호(RunAsPPL)".into()),
            ("value", format!("{} (사용)", ppl)),
            ("status", "정상".into()),
            (
                "detail",
                "LSASS가 PPL(보호 프로세스)로 실행됨 — 자격증명 덤프 난이도 상승".into(),
            ),
            ("key_path", "…\\Control\\Lsa".into()),
            ("source", "SYSTEM".into()),
            ("record_key", ppl_rk),
        ]));
    } else {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "LSASS 보호(RunAsPPL)".into()),
            ("value", "미설정".into()),
            ("status", "주의".into()),
            (
                "detail",
                "RunAsPPL 미설정 — LSASS가 보호 프로세스로 실행되지 않아 자격증명 덤프에 노출"
                    .into(),
            ),
            ("key_path", ppl_row.and_then(|row| row.get("key_path")).cloned()
                .unwrap_or_else(|| registry_rule_path(system, r"Control\Lsa", true))),
            ("source", "SYSTEM".into()),
        ]));
    }
    rows.extend(rf_lsa_packages(system));
    rows
}

/// ⑭ Control\Lsa 확장 — 자격증명 노출도를 좌우하는 나머지 Lsa 값들.
/// 비표준 Notification/Security Packages는 평문 암호 필터/LSASS 주입 지속성의
/// 고전적 흔적이라 목록으로 뽑아 준다.
fn rf_lsa_packages(system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();

    let nolm_row = reg_pick_row(system, "\\control\\lsa", "NoLmHash");
    if nolm_row.and_then(|r| r.get("value_data").cloned()).as_deref() == Some("0") {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "NoLmHash".into()),
            ("value", "0 (LM 해시 저장)".into()),
            ("status", "주의".into()),
            ("detail", "LM 해시 저장이 켜져 있음 — 취약한 LM 해시가 SAM에 남아 크래킹이 용이".into()),
            ("key_path", "…\\Control\\Lsa".into()),
            ("source", "SYSTEM".into()),
            ("record_key", picked_record_key(nolm_row)),
        ]));
    }
    let dra_row = reg_pick_row(system, "\\control\\lsa", "DisableRestrictedAdmin");
    if dra_row.and_then(|r| r.get("value_data").cloned()).as_deref() == Some("0") {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "DisableRestrictedAdmin".into()),
            ("value", "0 (Restricted Admin 허용)".into()),
            ("status", "주의".into()),
            ("detail", "RDP Restricted Admin 모드 허용 — Pass-the-Hash 방식 RDP 접속에 노출".into()),
            ("key_path", "…\\Control\\Lsa".into()),
            ("source", "SYSTEM".into()),
            ("record_key", picked_record_key(dra_row)),
        ]));
    }

    // 표준 패키지 화이트리스트 밖의 값만 의심으로 뽑는다.
    const STD_NOTIFY: &[&str] = &["scecli"];
    const STD_SECURITY: &[&str] = &[
        "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts",
    ];
    let notify_row = reg_pick_row(system, "\\control\\lsa", "Notification Packages");
    let notify = notify_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    for pkg in multi_sz(&notify) {
        let low = pkg.to_lowercase();
        if pkg.trim().is_empty() || STD_NOTIFY.contains(&low.as_str()) {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "Notification Package (비표준)".into()),
            ("value", pkg),
            ("status", "의심".into()),
            ("detail", "비표준 암호 필터 DLL — 암호 변경 시 평문을 가로채는 자격증명 탈취 지속성 의심".into()),
            ("key_path", "…\\Control\\Lsa\\Notification Packages".into()),
            ("source", "SYSTEM".into()),
            ("record_key", picked_record_key(notify_row)),
        ]));
    }
    let secpkgs_row = reg_pick_row(system, "\\control\\lsa", "Security Packages");
    let secpkgs = secpkgs_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    for pkg in multi_sz(&secpkgs) {
        let low = pkg.to_lowercase();
        if pkg.trim().is_empty() || pkg == "\"\"" || STD_SECURITY.contains(&low.as_str()) {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "Security Package (비표준)".into()),
            ("value", pkg),
            ("status", "의심".into()),
            ("detail", "비표준 SSP 등록 — LSASS에 로드되어 자격증명을 수집하는 주입형 패키지 의심".into()),
            ("key_path", "…\\Control\\Lsa\\Security Packages".into()),
            ("source", "SYSTEM".into()),
            ("record_key", picked_record_key(secpkgs_row)),
        ]));
    }
    rows
}

/// REG_MULTI_SZ(JSON 배열 문자열) 또는 공백 구분 문자열을 항목 목록으로.
fn multi_sz(value: &str) -> Vec<String> {
    let v = value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    if v.starts_with('[') {
        if let Ok(items) = serde_json::from_str::<Vec<String>>(v) {
            return items;
        }
    }
    v.split_whitespace().map(|s| s.to_string()).collect()
}

fn utf16le_until_nul(b: &[u8]) -> String {
    let mut u16s = Vec::new();
    for c in b.chunks_exact(2) {
        let v = u16::from_le_bytes([c[0], c[1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

/// Winlogon 체인 — 로그온마다 무조건 실행되는 Shell/Userinit 값 변조와
/// 평문 자동 로그온 설정을 본다. 값 이름이 대문자(USERINIT)로 저장된
/// 하이브가 실재하므로 이름은 대소문자 무시로 매칭한다.
fn rf_winlogon(software: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let (mut shell, mut userinit, mut auto_logon) = (None, None, None);
    let (mut has_password, mut taskman, mut gina) = (false, None, None);
    for r in software {
        let low = r
            .get("key_path")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        if !low.ends_with("\\microsoft\\windows nt\\currentversion\\winlogon")
            || low.contains("wow6432node")
        {
            continue;
        }
        let data = r.get("value_data").cloned().unwrap_or_default();
        let name = r.get("value_name").cloned().unwrap_or_default();
        let rk = reg_record_key(r);
        match name.to_ascii_lowercase().as_str() {
            "shell" => shell = Some((data, rk)),
            "userinit" => userinit = Some((data, rk)),
            "autoadminlogon" => auto_logon = Some((data, rk)),
            "defaultpassword" => has_password = !data.is_empty(),
            "taskman" => taskman = Some((data, rk)).filter(|(d, _)| !d.is_empty()),
            "ginadll" => gina = Some((data, rk)).filter(|(d, _)| !d.is_empty()),
            _ => {}
        }
    }
    let kp = "…\\Windows NT\\CurrentVersion\\Winlogon";
    if let Some((shell, shell_rk)) = shell {
        let normal = shell.trim().eq_ignore_ascii_case("explorer.exe");
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "Winlogon".into()),
            ("name", "Winlogon Shell".into()),
            ("value", shell.clone()),
            ("command", shell),
            ("status", if normal { "정상" } else { "의심" }.into()),
            ("detail", if normal {
                "로그온 셸이 기본값(explorer.exe)".into()
            } else {
                "로그온 셸이 기본값(explorer.exe)이 아님 — 모든 로그온에서 대체/추가 페이로드 실행 (지속성)".into()
            }),
            ("key_path", kp.into()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", shell_rk),
        ]));
    }
    if let Some((userinit, userinit_rk)) = userinit {
        let items: Vec<&str> = userinit
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let normal = items.len() == 1
            && items[0].eq_ignore_ascii_case("c:\\windows\\system32\\userinit.exe");
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "Winlogon".into()),
            ("name", "Winlogon Userinit".into()),
            ("value", userinit.clone()),
            ("command", userinit),
            ("status", if normal { "정상" } else { "의심" }.into()),
            ("detail", if normal {
                "Userinit이 기본값(userinit.exe 단독)".into()
            } else {
                "Userinit에 기본 userinit.exe 외 항목이 있음 — 로그온마다 추가 바이너리 실행 (지속성)".into()
            }),
            ("key_path", kp.into()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", userinit_rk),
        ]));
    }
    if let Some((_, auto_rk)) = auto_logon.filter(|(v, _)| v.as_str() == "1") {
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "Winlogon".into()),
            ("name", "AutoAdminLogon".into()),
            ("value", if has_password { "1 (DefaultPassword 저장됨)" } else { "1" }.into()),
            ("status", if has_password { "의심" } else { "주의" }.into()),
            ("detail", if has_password {
                "자동 로그온 + DefaultPassword 평문 저장 — 레지스트리만 읽어도 계정 암호 탈취 가능".into()
            } else {
                "자동 로그온 활성 — 부팅만으로 해당 계정 세션 획득 가능".into()
            }),
            ("key_path", kp.into()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", auto_rk),
        ]));
    }
    if let Some((taskman, taskman_rk)) = taskman {
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "Winlogon".into()),
            ("name", "Winlogon Taskman".into()),
            ("value", taskman.clone()),
            ("command", taskman),
            ("status", "주의".into()),
            ("detail", "Taskman 값은 기본적으로 없음 — Ctrl+Alt+Del 작업 관리자 대체 실행 지점".into()),
            ("key_path", kp.into()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", taskman_rk),
        ]));
    }
    if let Some((gina, gina_rk)) = gina {
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "Winlogon".into()),
            ("name", "GinaDLL".into()),
            ("value", gina),
            ("status", "의심".into()),
            ("detail", "GinaDLL 등록 — 로그온 자격증명을 가로채는 구식 GINA 대체 DLL".into()),
            ("key_path", kp.into()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", gina_rk),
        ]));
    }
    rows
}

/// IFEO SilentProcessExit — 대상 프로세스가 종료될 때 MonitorProcess로 지정된
/// 프로그램이 실행된다 (lsass 종료 시 덤프 도구 실행 같은 은닉 트리거).
fn rf_silent_process_exit(software: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains("\\silentprocessexit\\") {
            continue;
        }
        if !r
            .get("value_name")
            .map(|n| n.eq_ignore_ascii_case("MonitorProcess"))
            .unwrap_or(false)
        {
            continue;
        }
        let target = kp.rsplit('\\').next().unwrap_or("").to_string();
        let cmd = r.get("value_data").cloned().unwrap_or_default();
        if cmd.is_empty() {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "SilentProcessExit".into()),
            ("name", format!("SilentProcessExit: {}", target)),
            ("value", cmd.clone()),
            ("command", cmd),
            ("status", "의심".into()),
            ("detail", format!(
                "{} 종료 시 MonitorProcess가 실행됨 — 정상 시스템엔 거의 없는 은닉 트리거 (lsass 대상이면 자격증명 덤프 자동화)",
                target
            )),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

/// TaskCache Actions(REG_BINARY) — 버전(u16) + Author 문자열 + 액션 목록에서
/// Exec(0x6666) 명령·인자와 ComHandler(0x7777) CLSID를 추출한다. 형식이
/// 어긋나면 그때까지 모은 것과 함께 미해석 여부(incomplete)를 돌려준다 —
/// 손상·미지원 Actions가 "명령 없는 정상 작업"으로 보이면 안 되기 때문.
fn parse_task_actions(b: &[u8]) -> (String, bool) {
    fn read_str(b: &[u8], off: &mut usize) -> Option<String> {
        if *off + 4 > b.len() {
            return None;
        }
        let len = le_u32(b, *off) as usize;
        *off += 4;
        if !len.is_multiple_of(2) || len > b.len().saturating_sub(*off) {
            return None;
        }
        let s = utf16le_until_nul(&b[*off..*off + len]);
        *off += len;
        Some(s)
    }
    const MAGICS: [u16; 4] = [0x6666, 0x7777, 0x8888, 0x9999];
    let mut parts: Vec<String> = Vec::new();
    if b.is_empty() {
        return (String::new(), false);
    }
    if b.len() < 2 {
        return (String::new(), true);
    }
    let mut incomplete = false;
    let mut off = 2usize;
    if read_str(b, &mut off).is_none() {
        return (String::new(), true);
    }
    while off + 2 <= b.len() {
        let magic = le_u16(b, off);
        off += 2;
        match magic {
            0x6666 => {
                // ID·작업 디렉터리는 요약에 쓰지 않지만, 잘림은 명령 잘림과
                // 같은 손상이므로 동일하게 미해석으로 전파한다.
                if read_str(b, &mut off).is_none() {
                    incomplete = true;
                }
                let Some(cmd) = read_str(b, &mut off) else {
                    incomplete = true;
                    break;
                };
                let args = match read_str(b, &mut off) {
                    Some(args) => args,
                    None => {
                        incomplete = true;
                        String::new()
                    }
                };
                if read_str(b, &mut off).is_none() {
                    incomplete = true;
                }
                // 버전 3 Exec 액션 뒤에는 2바이트 플래그가 올 수 있다 —
                // 다음 액션 매직이 아니면 한 번 건너뛴다.
                if off + 2 <= b.len() && !MAGICS.contains(&le_u16(b, off)) {
                    off += 2;
                }
                parts.push(if args.is_empty() {
                    cmd
                } else {
                    format!("{} {}", cmd, args)
                });
            }
            0x7777 => {
                if read_str(b, &mut off).is_none() {
                    incomplete = true;
                }
                if off + 16 > b.len() {
                    incomplete = true;
                    break;
                }
                let c = &b[off..off + 16];
                off += 16;
                let data = match read_str(b, &mut off) {
                    Some(data) => data,
                    None => {
                        incomplete = true;
                        String::new()
                    }
                };
                parts.push(format!(
                    "COM {{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}} {}",
                    le_u32(c, 0), le_u16(c, 4), le_u16(c, 6),
                    c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15], data
                ).trim_end().to_string());
            }
            // 이메일(0x8888)·메시지(0x9999) 등 해석하지 않는 액션 형식 —
            // 남은 바이트를 버리므로 미해석으로 표시한다.
            _ => {
                incomplete = true;
                break;
            }
        }
    }
    (parts.join(" ; "), incomplete)
}

/// TaskCache DynamicInfo — 오프셋 12의 FILETIME이 마지막 실행 시각.
fn task_last_run(b: &[u8]) -> String {
    if b.len() >= 20 {
        let ft = le_u64(b, 12);
        if ft > 0 {
            return filetime(ft);
        }
    }
    String::new()
}

/// 예약 작업 레지스트리 잔존(TaskCache) — XML 파일을 지워도 남는다.
/// 비-Microsoft 작업은 실행 명령과 함께 나열하고, Tree에 없는 Tasks 항목
/// (스케줄러 UI에서 안 보이는 은닉 작업)과 SD 삭제는 의심으로 올린다.
/// Tree에만 남고 대응 Tasks\{GUID}가 없는 항목도 삭제·손상된 작업의 잔존
/// (작업 삭제 흔적)이라 주의로 올린다 — 정상 시스템은 Tree/Tasks가 1:1이다.
fn rf_taskcache(software: &[Row]) -> Vec<Row> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut tasks: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut tree_guids: BTreeSet<String> = BTreeSet::new();
    let mut tree_id_keys: BTreeMap<String, (String, String)> = BTreeMap::new(); // key_path -> (guid, record_key)
    let mut tree_sd_keys: BTreeSet<String> = BTreeSet::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        let name = r.get("value_name").cloned().unwrap_or_default();
        let data = r.get("value_data").cloned().unwrap_or_default();
        if let Some(pos) = low.find("\\taskcache\\tasks\\") {
            let guid = low[pos + "\\taskcache\\tasks\\".len()..]
                .split('\\')
                .next()
                .unwrap_or("")
                .to_string();
            if guid.is_empty() {
                continue;
            }
            let entry = tasks.entry(guid).or_default();
            entry.insert("__key_path".into(), kp);
            // 대표 record_key — 핵심 증거인 Actions 값 행을 우선한다 (해석
            // 실패 시 원본 대조가 바로 그 행에서 이뤄져야 하므로).
            let rk = reg_record_key(r);
            if name.eq_ignore_ascii_case("Actions") {
                entry.insert("__record_key".into(), rk);
            } else {
                entry.entry("__record_key".into()).or_insert(rk);
            }
            entry
                .entry("__last_write".into())
                .or_insert_with(|| r.get("last_write").cloned().unwrap_or_default());
            if !name.is_empty() && name != "(default)" {
                entry.insert(name, data);
            }
        } else if low.contains("\\taskcache\\tree\\") {
            if name.eq_ignore_ascii_case("Id") {
                tree_guids.insert(data.to_lowercase());
                tree_id_keys.insert(kp, (data.to_lowercase(), reg_record_key(r)));
            } else if name.eq_ignore_ascii_case("SD") {
                tree_sd_keys.insert(kp);
            }
        }
    }
    let mut rows = Vec::new();
    for (guid, props) in &tasks {
        let path = prop_ci(props, "Path").cloned().unwrap_or_default();
        let hidden = !tree_guids.contains(guid);
        if !hidden && path.to_lowercase().starts_with("\\microsoft\\") {
            continue;
        }
        let (actions, actions_incomplete) = prop_ci(props, "Actions")
            .map(|h| parse_task_actions(&unhex(h)))
            .unwrap_or_default();
        let last_run = prop_ci(props, "DynamicInfo")
            .map(|h| task_last_run(&unhex(h)))
            .unwrap_or_default();
        let display = if path.is_empty() { guid.clone() } else { path.clone() };
        let mut detail = if hidden {
            "TaskCache Tasks에는 있으나 Tree에 없음 — 스케줄러 UI에 보이지 않는 은닉 예약 작업".to_string()
        } else {
            format!("예약 작업 (레지스트리 잔존){}", if last_run.is_empty() { String::new() } else { " — timestamp는 마지막 실행 시각".to_string() })
        };
        if actions_incomplete {
            detail.push_str(" · Actions 바이너리를 끝까지 해석하지 못함 — 손상되었거나 미지원 액션 형식이라 원본 값 확인 필요");
        }
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "TaskCache".into()),
            ("name", display),
            ("value", if actions.is_empty() && actions_incomplete {
                "Actions 해석 실패".into()
            } else {
                actions.clone()
            }),
            ("command", actions),
            ("status", if hidden {
                "의심"
            } else if actions_incomplete {
                "주의"
            } else {
                "정보"
            }.into()),
            ("detail", detail),
            ("key_path", props.get("__key_path").cloned().unwrap_or_default()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", props.get("__record_key").cloned().unwrap_or_default()),
            ("timestamp", if last_run.is_empty() {
                props.get("__last_write").cloned().unwrap_or_default()
            } else {
                last_run
            }),
        ]));
    }
    for (kp, (guid, rk)) in &tree_id_keys {
        let task_name = || {
            kp.split("\\Tree\\")
                .nth(1)
                .map(|s| format!("\\{}", s))
                .unwrap_or_else(|| kp.clone())
        };
        // Tree에 Id는 남았는데 대응 Tasks\{GUID} 키가 없다 — 삭제·손상된
        // 예약 작업의 잔존. Tasks 기준 첫 루프는 이 경우를 못 본다.
        if !tasks.contains_key(guid) {
            rows.push(rf_row(&[
                ("category", "자동 실행".into()),
                ("subtype", "TaskCache".into()),
                ("name", task_name()),
                ("value", format!("Tasks 항목 없음 ({})", guid)),
                ("status", "주의".into()),
                ("detail", "Tree에는 등록이 남았지만 대응 Tasks 키가 없음 — 삭제되었거나 손상된 예약 작업의 잔존 (작업 삭제 흔적)".into()),
                ("key_path", kp.clone()),
                ("source", "SOFTWARE".into()),
                ("user", "(시스템)".into()),
                ("record_key", rk.clone()),
            ]));
        }
        if tree_sd_keys.contains(kp) {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "TaskCache".into()),
            ("name", task_name()),
            ("value", format!("SD 값 없음 ({})", guid)),
            ("status", "의심".into()),
            ("detail", "Tree 항목에 보안 설명자(SD)가 없음 — SD 삭제는 작업을 스케줄러에서 숨기는 알려진 은닉 기법".into()),
            ("key_path", kp.clone()),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("record_key", rk.clone()),
        ]));
    }
    rows
}

/// Active Setup — 각 사용자가 최초 로그온할 때 StubPath가 1회 실행된다.
/// Run 키만 보는 도구가 놓치는 저명도 지속성 지점.
fn rf_active_setup(software: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains("\\active setup\\installed components\\") {
            continue;
        }
        if !r
            .get("value_name")
            .map(|n| n.eq_ignore_ascii_case("StubPath"))
            .unwrap_or(false)
        {
            continue;
        }
        let cmd = r.get("value_data").cloned().unwrap_or_default();
        if cmd.is_empty() {
            continue;
        }
        let comp = kp.rsplit('\\').next().unwrap_or("").to_string();
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "ActiveSetup".into()),
            ("name", format!("Active Setup {}", comp)),
            ("value", cmd.clone()),
            ("command", cmd),
            ("status", "정보".into()),
            ("detail", "사용자 최초 로그온 시 1회 실행되는 StubPath".into()),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

/// 전역 DLL 주입 지점 — AppInit_DLLs(user32를 로드하는 모든 프로세스)와
/// AppCertDLLs(CreateProcess 호출 프로세스). 정상 시스템은 둘 다 빈 값.
fn rf_appinit(software: &[Row], system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.ends_with("\\currentversion\\windows") {
            continue;
        }
        if !r
            .get("value_name")
            .map(|n| n.eq_ignore_ascii_case("AppInit_DLLs"))
            .unwrap_or(false)
        {
            continue;
        }
        let dlls = r.get("value_data").cloned().unwrap_or_default();
        if dlls.trim().is_empty() {
            continue;
        }
        // 활성 플래그는 이 AppInit_DLLs 행과 같은 키에서만 읽는다 — suffix
        // 검색은 일반/Wow6432Node 뷰를 구분하지 못해, 두 뷰의
        // LoadAppInit_DLLs가 다르면 남의 뷰 플래그로 활성/비활성을 오판한다
        // (두 값은 64/32비트 프로세스에 각각 독립 적용).
        let load = software
            .iter()
            .find(|row| {
                row.get("key_path").map(String::as_str) == Some(kp.as_str())
                    && row
                        .get("value_name")
                        .map(|n| n.eq_ignore_ascii_case("LoadAppInit_DLLs"))
                        .unwrap_or(false)
            })
            .and_then(|row| row.get("value_data").cloned())
            .unwrap_or_default();
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "AppInit".into()),
            ("name", "AppInit_DLLs".into()),
            ("value", dlls),
            ("status", if load == "1" { "의심" } else { "주의" }.into()),
            ("detail", if load == "1" {
                "AppInit_DLLs 등록 + LoadAppInit_DLLs=1 — user32를 로드하는 모든 프로세스에 DLL 주입 활성".into()
            } else {
                "AppInit_DLLs에 DLL이 등록됨 (LoadAppInit_DLLs 비활성 상태) — 주입 준비 흔적".into()
            }),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("user", "(시스템)".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    // AppCertDLLs도 전 행 순회 — 활성 ControlSet만 수집해 미러 중복과
    // 비활성 세트의 낡은 등록이 활성 주입 지점처럼 보이는 것을 막는다.
    let active_set = active_control_set(system);
    for r in system {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains("\\control\\session manager\\appcertdlls") || !low.contains(&active_set) {
            continue;
        }
        let name = r.get("value_name").cloned().unwrap_or_default();
        let dll = r.get("value_data").cloned().unwrap_or_default();
        if dll.trim().is_empty() {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "AppInit".into()),
            ("name", format!("AppCertDLLs {}", name)),
            ("value", dll),
            ("status", "의심".into()),
            ("detail", "AppCertDLLs 등록 — CreateProcess를 쓰는 모든 프로세스에 DLL이 로드되는 전역 주입 지점 (정상 시스템엔 없음)".into()),
            ("key_path", kp),
            ("source", "SYSTEM".into()),
            ("user", "(시스템)".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

/// Session Manager — 커널 초기화 단계 실행(BootExecute/SetupExecute)과
/// 재부팅 시 파일 이동·삭제 예약(PendingFileRenameOperations).
fn rf_session_manager(system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let boot_row = reg_pick_row(system, "\\control\\session manager", "BootExecute");
    let boot = boot_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    let extras: Vec<String> = multi_sz(&boot)
        .into_iter()
        .filter(|item| {
            let t = item.trim();
            !t.is_empty() && !t.eq_ignore_ascii_case("autocheck autochk *")
        })
        .collect();
    if !extras.is_empty() {
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "SessionManager".into()),
            ("name", "BootExecute (비기본)".into()),
            ("value", extras.join(" ; ")),
            ("command", extras.join(" ; ")),
            ("status", "의심".into()),
            ("detail", "부트 단계(커널 초기화)에 기본 autochk 외 항목 실행 — 백신·EDR보다 먼저 뜨는 지속성".into()),
            ("key_path", "…\\Control\\Session Manager".into()),
            ("source", "SYSTEM".into()),
            ("user", "(시스템)".into()),
            ("record_key", picked_record_key(boot_row)),
        ]));
    }
    let setup_row = reg_pick_row(system, "\\control\\session manager", "SetupExecute");
    let setup = setup_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    let setup_items: Vec<String> = multi_sz(&setup)
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect();
    if !setup_items.is_empty() {
        rows.push(rf_row(&[
            ("category", "자동 실행".into()),
            ("subtype", "SessionManager".into()),
            ("name", "SetupExecute".into()),
            ("value", setup_items.join(" ; ")),
            ("command", setup_items.join(" ; ")),
            ("status", "의심".into()),
            ("detail", "SetupExecute는 정상적으로 빈 값 — 부트 단계 실행 항목이 등록됨".into()),
            ("key_path", "…\\Control\\Session Manager".into()),
            ("source", "SYSTEM".into()),
            ("user", "(시스템)".into()),
            ("record_key", picked_record_key(setup_row)),
        ]));
    }
    // 재부팅 시 파일 조작 예약 — 목적지가 없는 항목은 삭제 예약이며,
    // 흔적 인멸 대상 파일 목록이 그대로 남는다. \??\ 접두 항목이 경로다.
    // 이 루프는 pick 헬퍼와 달리 전 행을 순회하므로 ControlSet 미러의 같은
    // 예약이 중복 출력되지 않게 한 세트만 수집한다 — 어느 세트가 실제 다음
    // 부팅에 적용되는지는 Select\Current가 결정하므로(LKG 부팅 후 002가
    // 활성인 증거가 실존) 001 고정이 아니라 활성 세트를 따른다.
    let active_set = active_control_set(system);
    for r in system {
        let low = r
            .get("key_path")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        if !low.ends_with("\\control\\session manager") || !low.contains(&active_set) {
            continue;
        }
        let name = r.get("value_name").cloned().unwrap_or_default();
        if !name
            .to_ascii_lowercase()
            .starts_with("pendingfilerenameoperations")
        {
            continue;
        }
        let items = multi_sz(&r.get("value_data").cloned().unwrap_or_default());
        let clean = |s: &str| -> String {
            match s.find("\\??\\") {
                Some(p) => s[p + 4..].to_string(),
                None => s.to_string(),
            }
        };
        let mut i = 0;
        while i < items.len() {
            let src = clean(&items[i]);
            let dst = items.get(i + 1).map(|s| clean(s)).unwrap_or_default();
            i += 2;
            if src.is_empty() {
                continue;
            }
            let delete = dst.is_empty();
            let benign = {
                let l = src.to_lowercase();
                l.contains("\\$recycle.bin\\")
                    || l.contains("\\temp\\")
                    || l.contains("\\windows\\installer\\")
            };
            rows.push(rf_row(&[
                ("category", "기타 레지스트리".into()),
                ("subtype", "PendingFileRename".into()),
                ("name", if delete { "재부팅 시 삭제 예약" } else { "재부팅 시 이동 예약" }.into()),
                ("value", if delete { src } else { format!("{} → {}", src, dst) }),
                ("status", if delete && !benign { "주의" } else { "정보" }.into()),
                ("detail", if delete {
                    "재부팅 시 삭제가 예약된 파일 — 자기삭제·흔적 인멸에 쓰이는 표준 경로 (수집 시점엔 파일이 아직 있을 수 있음)".into()
                } else {
                    "재부팅 시 파일 이동 예약 (업데이트·설치 과정에서도 흔함)".into()
                }),
                ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                ("source", "SYSTEM".into()),
                ("user", "(시스템)".into()),
                ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
                ("record_key", reg_record_key(r)),
            ]));
        }
    }
    rows
}

/// 보안 설정 — Defender 보호 기능 비활성 플래그와 PowerShell 로깅 상태.
/// PowerShell 로깅 상태는 EVTX 4104/4103 분석 결과의 해석 전제가 된다.
fn rf_security_config(software: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    const DEFENDER_DISABLES: &[(&str, &str, &str)] = &[
        ("DisableRealtimeMonitoring", "의심", "실시간 감시 비활성"),
        ("DisableBehaviorMonitoring", "의심", "행위 기반 탐지 비활성"),
        ("DisableScriptScanning", "의심", "스크립트 검사 비활성"),
        ("DisableIOAVProtection", "의심", "다운로드·첨부 검사 비활성"),
        ("DisableOnAccessProtection", "의심", "실시간 파일 접근 검사 비활성"),
        ("DisableAntiSpyware", "주의", "Defender 전체 비활성 플래그 (서드파티 백신 설치 시에도 설정됨)"),
        ("DisableAntiVirus", "주의", "Defender 바이러스 검사 비활성 플래그"),
    ];
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains("\\windows defender") {
            continue;
        }
        let name = r.get("value_name").cloned().unwrap_or_default();
        // 레지스트리 값 이름은 대소문자 무시 — 소문자로 만든 비활성 플래그도
        // Windows에는 동일하게 적용되므로 같은 규칙으로 매칭한다.
        let Some((_, status, what)) = DEFENDER_DISABLES
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case(&name))
        else {
            continue;
        };
        if r.get("value_data").map(|d| d != "1").unwrap_or(true) {
            continue;
        }
        let via_policy = low.contains("\\policies\\");
        rows.push(rf_row(&[
            ("category", "보안 설정".into()),
            ("subtype", "Defender".into()),
            ("name", name),
            ("value", "1 (비활성)".into()),
            ("status", if via_policy { "의심" } else { *status }.into()),
            ("detail", format!(
                "{}{} — 랜섬웨어·페이로드 배포 직전의 표준 무력화 절차와 일치하는지 시각을 확인",
                what,
                if via_policy { " (정책 키로 강제됨)" } else { "" }
            )),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    // PowerShell 로깅 — 4104(스크립트 블록) 존재 기대치를 결정한다.
    let sbl_row = reg_pick_row(software, "\\powershell\\scriptblocklogging", "EnableScriptBlockLogging");
    let sbl = sbl_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    let (value, status, detail) = match sbl.as_str() {
        "1" => ("1 (활성)", "정상", "스크립트 블록 로깅 활성 — EVTX 4104 이벤트가 존재해야 정상"),
        "0" => ("0 (명시적 비활성)", "주의", "스크립트 블록 로깅이 명시적으로 꺼짐 — 4104 부재는 로깅 차단의 결과일 수 있음"),
        _ => ("미설정 (기본 비활성)", "정보", "스크립트 블록 로깅 미설정 — 4104 이벤트 부재가 정상인 환경"),
    };
    rows.push(rf_row(&[
        ("category", "보안 설정".into()),
        ("subtype", "PowerShell".into()),
        ("name", "ScriptBlockLogging".into()),
        ("value", value.into()),
        ("status", status.into()),
        ("detail", detail.into()),
        ("key_path", if sbl_row.is_none() {
            registry_rule_path(software, r"Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", false)
        } else {
            "…\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging".into()
        }),
        ("source", "SOFTWARE".into()),
        ("record_key", picked_record_key(sbl_row)),
    ]));
    let transcript_row = reg_pick_row(software, "\\powershell\\transcription", "EnableTranscripting");
    let transcript = transcript_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    if transcript == "1" {
        let outdir = reg_pick(software, "\\powershell\\transcription", "OutputDirectory");
        rows.push(rf_row(&[
            ("category", "보안 설정".into()),
            ("subtype", "PowerShell".into()),
            ("name", "Transcription".into()),
            ("value", if outdir.is_empty() { "활성 (기본 내 문서 폴더)".into() } else { outdir }),
            ("status", "정보".into()),
            ("detail", "PowerShell 전사(Transcription) 활성 — 표시된 경로의 전사 로그가 추가 수집 대상".into()),
            ("key_path", "…\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription".into()),
            ("source", "SOFTWARE".into()),
            ("record_key", picked_record_key(transcript_row)),
        ]));
    }
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
        if !low.contains("\\powershell") {
            continue;
        }
        if !r
            .get("value_name")
            .map(|n| n.eq_ignore_ascii_case("ExecutionPolicy"))
            .unwrap_or(false)
        {
            continue;
        }
        let policy = r.get("value_data").cloned().unwrap_or_default();
        let lowp = policy.to_lowercase();
        if !(lowp.contains("bypass") || lowp.contains("unrestricted")) {
            continue;
        }
        rows.push(rf_row(&[
            ("category", "보안 설정".into()),
            ("subtype", "PowerShell".into()),
            ("name", "ExecutionPolicy".into()),
            ("value", policy),
            ("status", "주의".into()),
            ("detail", "실행 정책이 Bypass/Unrestricted — 스크립트 실행 제한이 해제된 상태".into()),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

/// 원격제어(RMM) 도구 설치 흔적("원격 접속")과 Sysinternals EULA 수락 키
/// ("Sysinternals 도구") — 같은 하이브 순회에서 뽑되 범주는 분리한다.
/// RMM은 정상 서명 도구라 백신에 안 걸려 C2 대용으로 선호된다 —
/// "조직이 쓰지 않는 도구의 존재" 자체가 침해 지표. Sysinternals EULA
/// 키는 해당 계정에서 그 도구가 실행됐다는 증거로, 실행파일을 지워도 남는다.
fn rf_remote_tools(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    const RMM_MARKERS: &[(&str, &str)] = &[
        ("\\teamviewer", "TeamViewer"),
        ("\\anydesk", "AnyDesk"),
        ("screenconnect", "ScreenConnect"),
        ("rustdesk", "RustDesk"),
        ("\\ateraagent", "Atera"),
        ("\\splashtop", "Splashtop"),
        ("\\netsupport", "NetSupport"),
        ("\\tightvnc", "TightVNC"),
        ("\\winvnc", "UltraVNC/WinVNC"),
        ("\\ammyy", "Ammyy Admin"),
        ("\\remoteutilities", "Remote Utilities"),
    ];
    const RMM_VALUES: &[&str] = &[
        "ImagePath",
        "InstallLocation",
        "InstallationDirectory",
        "Version",
        "DisplayVersion",
        "ClientID",
        "InstallationDate",
    ];
    let mut rows = Vec::new();
    for hive in hives {
        let user = hive_user(&hive.name);
        // (대표 key_path, last_write, 관심 값, 대표 record_key)
        type RmmEntry = (
            String,
            String,
            std::collections::BTreeMap<String, String>,
            String,
        );
        let mut tools: std::collections::BTreeMap<&str, RmmEntry> =
            std::collections::BTreeMap::new();
        for r in &hive.rows {
            let kp = r.get("key_path").cloned().unwrap_or_default();
            let low = kp.to_lowercase();
            let Some((_, tool)) = RMM_MARKERS.iter().find(|(m, _)| low.contains(m)) else {
                // Sysinternals EULA는 도구 집계와 무관하게 행 단위로 바로 뽑는다.
                if low.contains("\\software\\sysinternals\\")
                    && r.get("value_name")
                        .map(|n| n.eq_ignore_ascii_case("EulaAccepted"))
                        .unwrap_or(false)
                    && r.get("value_data").map(|d| d == "1").unwrap_or(false)
                {
                    let tool = kp.rsplit('\\').next().unwrap_or("").to_string();
                    let tl = tool.to_lowercase();
                    let critical = matches!(
                        tl.as_str(),
                        "psexec" | "psexec64" | "procdump" | "procdump64" | "sdelete" | "sdelete64"
                    );
                    rows.push(rf_row(&[
                        // 원격제어(RMM)와 달리 EULA 키는 "이 계정에서 도구를
                        // 실행했다"는 실행 증거다 — 원격 접속과 섞지 않는다.
                        ("category", "Sysinternals 도구".into()),
                        ("subtype", "Sysinternals".into()),
                        ("name", format!("Sysinternals {}", tool)),
                        ("value", "EulaAccepted=1".into()),
                        ("status", if critical { "의심" } else { "정보" }.into()),
                        ("detail", match tl.as_str() {
                            "psexec" | "psexec64" => "PsExec 실행 흔적 — 측면이동 표준 도구. 키 LastWrite가 이 계정의 최초 실행 시각".into(),
                            "procdump" | "procdump64" => "ProcDump 실행 흔적 — LSASS 덤프(자격증명 탈취)에 상용되는 도구".into(),
                            "sdelete" | "sdelete64" => "SDelete 실행 흔적 — 복구 불가 삭제(안티포렌식) 도구".into(),
                            _ => "Sysinternals 도구 실행 흔적 — EULA 수락 키는 실행파일 삭제 후에도 남음".into(),
                        }),
                        ("key_path", kp),
                        ("source", hive.name.clone()),
                        ("user", user.clone()),
                        ("timestamp", r.get("last_write").cloned().unwrap_or_default()),
                        ("record_key", reg_record_key(r)),
                    ]));
                }
                continue;
            };
            let entry = tools
                .entry(tool)
                .or_insert_with(|| (kp.clone(), String::new(), Default::default(), reg_record_key(r)));
            let lw = r.get("last_write").cloned().unwrap_or_default();
            if lw > entry.1 {
                entry.1 = lw;
            }
            let name = r.get("value_name").cloned().unwrap_or_default();
            if RMM_VALUES.iter().any(|v| name.eq_ignore_ascii_case(v)) {
                let data = r.get("value_data").cloned().unwrap_or_default();
                if !data.is_empty() {
                    entry.0 = kp;
                    // 대표 key_path를 제공한 행이 원본 승격 대상도 된다.
                    entry.3 = reg_record_key(r);
                    entry.2.entry(name).or_insert(data);
                }
            }
        }
        for (tool, (kp, last_write, props, record_key)) in tools {
            let path = prop_ci(&props, "ImagePath")
                .or_else(|| prop_ci(&props, "InstallLocation"))
                .or_else(|| prop_ci(&props, "InstallationDirectory"))
                .cloned()
                .unwrap_or_default();
            let version = prop_ci(&props, "Version")
                .or_else(|| prop_ci(&props, "DisplayVersion"))
                .cloned()
                .unwrap_or_default();
            let mut detail = format!(
                "원격제어 도구 설치 흔적{} — 조직에서 쓰지 않는 도구라면 침해 지표",
                if version.is_empty() { String::new() } else { format!(" (버전 {})", version) }
            );
            if tool == "ScreenConnect" && path.contains("h=") {
                detail.push_str(". ImagePath 인자에 접속 서버(C2 후보) 주소가 포함됨");
            }
            if let Some(cid) = prop_ci(&props, "ClientID") {
                detail.push_str(&format!(". ClientID {} — 접속 로그 대조용 식별자", cid));
            }
            rows.push(rf_row(&[
                ("category", "원격 접속".into()),
                ("subtype", "RMM".into()),
                ("name", tool.into()),
                ("value", if path.is_empty() { "설치 흔적 (경로 값 없음)".into() } else { path.clone() }),
                ("command", path),
                ("status", "정보".into()),
                ("detail", detail),
                ("key_path", kp),
                ("source", hive.name.clone()),
                ("user", user.clone()),
                ("timestamp", last_write),
                ("record_key", record_key),
            ]));
        }
    }
    rows
}

/// Uninstall 키 이름의 ProductCode GUID를 MSI Products 키의 packed(압축)
/// 형식으로 변환한다 — 앞 세 필드는 문자열 역순, 나머지 8바이트는 바이트별
/// 두 자리 스왑(Darwin 변환). GUID 형태가 아니면 None.
fn msi_packed_product_code(leaf: &str) -> Option<String> {
    let t = leaf.trim().strip_prefix('{')?.strip_suffix('}')?;
    let segs: Vec<&str> = t.split('-').collect();
    if segs.len() != 5
        || [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&segs)
            .any(|(len, seg)| seg.len() != *len)
        || !t.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
    {
        return None;
    }
    let mut out = String::with_capacity(32);
    out.extend(segs[0].chars().rev());
    out.extend(segs[1].chars().rev());
    out.extend(segs[2].chars().rev());
    let tail = format!("{}{}", segs[3], segs[4]);
    for pair in tail.as_bytes().chunks(2) {
        out.push(pair[1] as char);
        out.push(pair[0] as char);
    }
    Some(out.to_ascii_lowercase())
}

/// InstallProperties 키 경로에서 Products\<packed ProductCode> 구성 요소.
fn msi_products_component(kp: &str) -> Option<String> {
    let mut parts = kp.split('\\');
    while let Some(part) = parts.next() {
        if part.eq_ignore_ascii_case("Products") {
            return parts.next().map(str::to_ascii_lowercase);
        }
    }
    None
}

/// 비-MSI 설치 프로그램 — …\CurrentVersion\Uninstall\* (+Wow6432Node, NTUSER).
/// MSI 설치는 InstallProperties와 Uninstall 키 양쪽에 등록되므로 같은 설치의
/// Uninstall 쌍둥이만 걸러 한 번만 남긴다. 쌍 판정은 이름·버전 휴리스틱이
/// 아니라 Uninstall 키 GUID를 packed ProductCode로 변환한 정확 일치 — 이름과
/// 버전은 고유 식별자가 아니어서(동명 패키지, 위장 항목) 별개 증거가 함께
/// 사라진다. 쌍을 확인할 수 없는 키는 전부 보존한다.
fn rf_uninstall_installs(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    use std::collections::{BTreeMap, BTreeSet};
    // (하이브, packed ProductCode) — rf_msi_installs가 표시하는 키만 모은다.
    let mut msi_products: BTreeSet<(String, String)> = BTreeSet::new();
    for hive in hives {
        for r in &hive.rows {
            let Some(kp) = r.get("key_path") else { continue };
            let low = kp.to_lowercase();
            if !(low.contains("\\currentversion\\installer\\userdata\\")
                && low.ends_with("\\installproperties"))
            {
                continue;
            }
            if !r
                .get("value_name")
                .map(|n| n.eq_ignore_ascii_case("DisplayName"))
                .unwrap_or(false)
                || r.get("value_data").map(|d| d.is_empty()).unwrap_or(true)
            {
                continue;
            }
            if let Some(packed) = msi_products_component(kp) {
                msi_products.insert((hive.name.clone(), packed));
            }
        }
    }
    let mut rows = Vec::new();
    for hive in hives {
        let user = hive_user(&hive.name);
        let mut by_key: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        let mut key_write: BTreeMap<&str, String> = BTreeMap::new();
        let mut key_rk: BTreeMap<&str, String> = BTreeMap::new();
        for r in &hive.rows {
            let Some(kp) = r.get("key_path") else { continue };
            let low = kp.to_lowercase();
            if !low.contains("\\currentversion\\uninstall\\") {
                continue;
            }
            let name = r.get("value_name").cloned().unwrap_or_default();
            key_write
                .entry(kp.as_str())
                .or_insert_with(|| r.get("last_write").cloned().unwrap_or_default());
            key_rk
                .entry(kp.as_str())
                .or_insert_with(|| reg_record_key(r));
            if name.is_empty() || name == "(default)" {
                continue;
            }
            by_key
                .entry(kp.as_str())
                .or_default()
                .insert(name, r.get("value_data").cloned().unwrap_or_default());
        }
        for (kp, props) in by_key {
            let display_name = prop_ci(&props, "DisplayName").cloned().unwrap_or_default();
            if display_name.is_empty() {
                continue;
            }
            // 키 이름이 같은 하이브 MSI 제품의 ProductCode와 정확히 일치할
            // 때만 같은 설치의 쌍둥이로 보고 접는다. 그 외 키는 고유
            // key_path·record_key를 가진 별개 원본 증거라 전부 남긴다.
            let is_msi_twin = kp
                .rsplit('\\')
                .next()
                .and_then(msi_packed_product_code)
                .map(|packed| msi_products.contains(&(hive.name.clone(), packed)))
                .unwrap_or(false);
            if is_msi_twin {
                continue;
            }
            let timestamp = prop_ci(&props, "InstallDate")
                .map(|d| msi_install_date(d))
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| key_write.get(kp).cloned().unwrap_or_default());
            rows.push(rf_row(&[
                ("category", "설치 프로그램 (MSI)".into()),
                ("subtype", "Uninstall".into()),
                ("name", display_name),
                ("value", prop_ci(&props, "DisplayVersion").cloned().unwrap_or_default()),
                ("detail", prop_ci(&props, "Publisher").cloned().unwrap_or_default()),
                ("status", "정보".into()),
                ("user", user.clone()),
                ("timestamp", timestamp),
                (
                    "properties",
                    serde_json::to_string(&props).unwrap_or_default(),
                ),
                ("key_path", kp.to_string()),
                ("source", hive.name.clone()),
                ("record_key", key_rk.get(kp).cloned().unwrap_or_default()),
            ]));
        }
    }
    rows
}

fn share_path(value: &str) -> String {
    let items: Vec<String> = if value.starts_with('[') {
        serde_json::from_str::<Vec<String>>(value).unwrap_or_else(|_| vec![value.to_string()])
    } else {
        vec![value.to_string()]
    };
    for it in items {
        if it.to_lowercase().starts_with("path=") {
            return it[5..].to_string();
        }
    }
    String::new()
}

fn rf_shares(system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let start_row = reg_pick_row(system, "\\services\\lanmanserver", "Start");
    let start = start_row
        .and_then(|r| r.get("value_data").cloned())
        .unwrap_or_default();
    if !start.is_empty() {
        let enabled = start == "2" || start == "3";
        let vmap = match start.as_str() {
            "2" => "자동",
            "3" => "수동",
            "4" => "사용 안 함",
            _ => start.as_str(),
        };
        rows.push(rf_row(&[
            ("category", "공유 폴더".into()),
            ("name", "Server 서비스(LanmanServer)".into()),
            ("value", vmap.into()),
            (
                "status",
                if enabled {
                    "정보".into()
                } else {
                    "정상".into()
                },
            ),
            (
                "detail",
                format!(
                    "파일/프린터 공유 서비스{}",
                    if enabled {
                        "가 실행됩니다 (공유 가능 상태)."
                    } else {
                        "가 비활성화되어 있습니다."
                    }
                ),
            ),
            ("key_path", "…\\Services\\LanmanServer".into()),
            ("source", "SYSTEM".into()),
            ("record_key", picked_record_key(start_row)),
        ]));
    }
    for (vname, role) in [
        ("AutoShareServer", "서버"),
        ("AutoShareWks", "워크스테이션"),
    ] {
        let auto_row = reg_pick_row(system, "\\lanmanserver\\parameters", vname);
        let auto = auto_row
            .and_then(|r| r.get("value_data").cloned())
            .unwrap_or_default();
        if auto == "0" {
            rows.push(rf_row(&[
                ("category", "공유 폴더".into()),
                ("name", format!("관리 공유({})", vname)),
                ("value", "0 (사용 안 함)".into()),
                ("status", "정보".into()),
                (
                    "detail",
                    format!(
                        "기본 관리 공유(C$, ADMIN$)가 비활성화되어 있습니다. ({})",
                        role
                    ),
                ),
                ("key_path", "…\\LanmanServer\\Parameters".into()),
                ("source", "SYSTEM".into()),
                ("record_key", picked_record_key(auto_row)),
            ]));
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    // 전 행 순회라 ControlSet 미러가 그대로 섞인다 — 현재 노출된 공유는
    // 활성 세트의 것이므로 그쪽만 수집한다 (PendingFileRename과 같은 규칙).
    let active_set = active_control_set(system);
    for r in system {
        let low = r
            .get("key_path")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        if !low.ends_with("\\lanmanserver\\shares") || !low.contains(&active_set) {
            continue;
        }
        let name = r.get("value_name").cloned().unwrap_or_default();
        if name.is_empty() || name == "(default)" || seen.contains(&name) {
            continue;
        }
        seen.insert(name.clone());
        let vd = r.get("value_data").cloned().unwrap_or_default();
        let path = share_path(&vd);
        let value = if !path.is_empty() {
            path
        } else {
            vd.chars().take(80).collect()
        };
        rows.push(rf_row(&[
            ("category", "공유 폴더".into()),
            ("name", name),
            ("value", value),
            ("status", "주의".into()),
            (
                "detail",
                "사용자 정의 공유 폴더 — 외부 노출/권한 점검 필요".into(),
            ),
            ("key_path", r.get("key_path").cloned().unwrap_or_default()),
            ("source", "SYSTEM".into()),
            (
                "timestamp",
                r.get("last_write").cloned().unwrap_or_default(),
            ),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

fn mssql_year(ver: &str) -> Option<&'static str> {
    match ver {
        "10" => Some("2008"),
        "11" => Some("2012"),
        "12" => Some("2014"),
        "13" => Some("2016"),
        "14" => Some("2017"),
        "15" => Some("2019"),
        "16" => Some("2022"),
        "17" => Some("2025"),
        _ => None,
    }
}
fn sql_instance_label(inst: &str) -> String {
    if inst.is_empty() {
        return String::new();
    }
    let (ver_part, name) = match inst.split_once('.') {
        Some((v, n)) => (v, n),
        None => (inst, ""),
    };
    let year = mssql_year(&ver_part.to_uppercase().replace("MSSQL", ""));
    let label = if !name.is_empty() { name } else { inst };
    match year {
        Some(y) => format!("{} · SQL Server {}", label, y),
        None => label.to_string(),
    }
}

fn rf_sql_auth(software: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if !r
            .get("value_name")
            .map(|v| v.eq_ignore_ascii_case("LoginMode"))
            .unwrap_or(false)
            || !kp.to_lowercase().contains("microsoft sql server")
        {
            continue;
        }
        let val = r.get("value_data").cloned().unwrap_or_default();
        let inst = kp
            .split('\\')
            .find(|p| p.to_uppercase().starts_with("MSSQL") && p.contains('.'))
            .unwrap_or("")
            .to_string();
        let label = sql_instance_label(&inst);
        let mixed = val == "2";
        rows.push(rf_row(&[
            ("category", "SQL 인증".into()),
            (
                "name",
                if !label.is_empty() {
                    format!("LoginMode — {}", label)
                } else {
                    "LoginMode".into()
                },
            ),
            (
                "value",
                match val.as_str() {
                    "1" => "Windows 인증 전용".into(),
                    "2" => "혼합 모드 (SQL+Windows)".into(),
                    _ => format!("알 수 없음({})", val),
                },
            ),
            (
                "status",
                if mixed {
                    "주의".into()
                } else if val == "1" {
                    "정상".into()
                } else {
                    "정보".into()
                },
            ),
            (
                "detail",
                if mixed {
                    "혼합 모드 — sa 등 SQL 계정 로그인 사용 가능 (무차별 대입 표적)".into()
                } else if val == "1" {
                    "Windows 인증만 허용".into()
                } else {
                    "LoginMode 값 확인 필요".into()
                },
            ),
            ("key_path", kp),
            ("source", "SOFTWARE".into()),
            ("record_key", reg_record_key(r)),
        ]));
    }
    rows
}

const AUTORUN_SUFFIXES: &[&str] = &[
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\policies\\explorer\\run",
];

fn rf_autoruns(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    let mut rows = Vec::new();
    for hive in hives {
        let user = hive_user(&hive.name);
        for r in &hive.rows {
            let low = r
                .get("key_path")
                .cloned()
                .unwrap_or_default()
                .to_lowercase();
            if !AUTORUN_SUFFIXES.iter().any(|s| low.ends_with(s)) {
                continue;
            }
            let name = r.get("value_name").cloned().unwrap_or_default();
            if name.is_empty() || name == "(default)" {
                continue;
            }
            let cmd = r.get("value_data").cloned().unwrap_or_default();
            let kind = if low.ends_with("runonce") {
                "RunOnce"
            } else if low.contains("policies") {
                "Policy Run"
            } else {
                "Run"
            };
            rows.push(rf_row(&[
                ("category", "자동 실행".into()),
                ("name", name),
                ("value", cmd.clone()),
                ("status", "정보".into()),
                ("detail", kind.into()),
                ("command", cmd),
                ("user", user.clone()),
                ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                ("source", hive.name.clone()),
                (
                    "timestamp",
                    r.get("last_write").cloned().unwrap_or_default(),
                ),
                ("record_key", reg_record_key(r)),
            ]));
        }
    }
    rows
}

fn rf_execution_traces(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    let mut rows = Vec::new();
    for hive in hives {
        let user = hive_user(&hive.name);
        for r in &hive.rows {
            let low = r
                .get("key_path")
                .cloned()
                .unwrap_or_default()
                .to_lowercase();
            let name = r.get("value_name").cloned().unwrap_or_default();
            if name.is_empty() || name == "(default)" || name == "MRUList" || name == "MRUListEx" {
                continue;
            }
            let data = r.get("value_data").cloned().unwrap_or_default();
            if low.ends_with("\\explorer\\runmru") {
                let cmd = if data.ends_with("\\1") {
                    data[..data.len() - 2].to_string()
                } else {
                    data.clone()
                };
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "RunMRU".into()),
                    ("name", "RunMRU".into()),
                    ("value", cmd.clone()),
                    ("status", "정보".into()),
                    ("command", cmd),
                    ("user", user.clone()),
                    ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                    ("source", hive.name.clone()),
                    (
                        "timestamp",
                        r.get("last_write").cloned().unwrap_or_default(),
                    ),
                    ("record_key", reg_record_key(r)),
                ]));
            } else if low.ends_with("\\explorer\\typedpaths") {
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "TypedPaths".into()),
                    ("name", "TypedPath".into()),
                    ("value", data),
                    ("status", "정보".into()),
                    ("user", user.clone()),
                    ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                    ("source", hive.name.clone()),
                    (
                        "timestamp",
                        r.get("last_write").cloned().unwrap_or_default(),
                    ),
                    ("record_key", reg_record_key(r)),
                ]));
            } else if low.contains("\\explorer\\recentdocs\\") {
                // REG_BINARY 선두가 UTF-16LE 파일명 — 파일이 삭제돼도 이름이 남는다.
                // 부모 RecentDocs 키는 확장자 서브키와 같은 항목을 중복 보유하므로
                // 확장자별 서브키만 수집한다.
                let fname = utf16le_until_nul(&unhex(&data));
                if fname.is_empty() {
                    continue;
                }
                let kp = r.get("key_path").cloned().unwrap_or_default();
                let ext = kp.rsplit('\\').next().unwrap_or("").to_string();
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "RecentDocs".into()),
                    ("name", "최근 문서 (RecentDocs)".into()),
                    ("value", fname),
                    ("status", "정보".into()),
                    ("detail", format!("{} — 키 시각은 이 그룹의 최종 열람 시각", ext)),
                    ("user", user.clone()),
                    ("key_path", kp),
                    ("source", hive.name.clone()),
                    (
                        "timestamp",
                        r.get("last_write").cloned().unwrap_or_default(),
                    ),
                    ("record_key", reg_record_key(r)),
                ]));
            } else if low.ends_with("\\software\\bandizip")
                && name
                    .strip_prefix("RecentArchive")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            {
                // Bandizip recent archive list; empty slots are unused.
                if data.is_empty() {
                    continue;
                }
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "BandizipRecentArchive".into()),
                    ("name", "반디집 최근 압축 파일".into()),
                    ("value", data),
                    ("status", "정보".into()),
                    ("detail", name),
                    ("user", user.clone()),
                    ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                    ("source", hive.name.clone()),
                    (
                        "timestamp",
                        r.get("last_write").cloned().unwrap_or_default(),
                    ),
                    ("record_key", reg_record_key(r)),
                ]));
            } else if low.ends_with("\\explorer\\wordwheelquery") {
                // REG_BINARY UTF-16LE — 탐색기 검색창에 입력한 검색어.
                let term = utf16le_until_nul(&unhex(&data));
                if term.is_empty() {
                    continue;
                }
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "WordWheelQuery".into()),
                    ("name", "탐색기 검색어".into()),
                    ("value", term),
                    ("status", "정보".into()),
                    ("detail", "사용자가 탐색기에서 검색한 키워드 — 의도 입증 자료".into()),
                    ("user", user.clone()),
                    ("key_path", r.get("key_path").cloned().unwrap_or_default()),
                    ("source", hive.name.clone()),
                    (
                        "timestamp",
                        r.get("last_write").cloned().unwrap_or_default(),
                    ),
                    ("record_key", reg_record_key(r)),
                ]));
            }
        }
    }
    rows
}

fn rf_shimcache(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for hive in hives {
        if !hive.name.eq_ignore_ascii_case("SYSTEM") {
            continue;
        }
        // 두 ControlSet의 AppCompatCache를 다 읽으면 경로 dedup이 행 순서에
        // 따라 비활성 세트의 낡은 FILETIME을 남길 수 있다 — 실행 이력의
        // 시각·원본 연결이 임의로 뒤섞이지 않게 활성 세트만 해석한다.
        let active_set = active_control_set(&hive.rows);
        for r in &hive.rows {
            if !r
                .get("value_name")
                .map(|v| v.eq_ignore_ascii_case("AppCompatCache"))
                .unwrap_or(false)
                || !r
                    .get("key_path")
                    .map(|k| k.to_lowercase().contains(&active_set))
                    .unwrap_or(false)
            {
                continue;
            }
            let data = unhex(&r.get("value_data").cloned().unwrap_or_default());
            let parsed = parse_shimcache(&data);
            if let Some(reason) = &parsed.unsupported {
                // "아티팩트 없음"과 "포맷 미지원"을 구분해 표면화한다(T0) —
                // 구포맷 하이브에서 실행 흔적이 0행인 이유를 화면에서 알 수 있게.
                let dedup_key = format!("__unsupported__{reason}");
                if seen.insert(dedup_key) {
                    rows.push(rf_row(&[
                        ("category", "기타 레지스트리".into()),
                        ("subtype", "ShimCache".into()),
                        ("name", "ShimCache (AppcompatCache)".into()),
                        ("value", format!("미지원 포맷: {reason}")),
                        ("status", "정보".into()),
                        ("detail", "AppCompatCache 값이 존재하지만 현재 파서는 Windows 8.1/10/11 포맷('10ts')만 해석함 — 구버전 포맷이라 실행 흔적 경로가 표시되지 않음".into()),
                        (
                            "key_path",
                            "…\\Control\\Session Manager\\AppCompatCache".into(),
                        ),
                        ("source", "SYSTEM".into()),
                        ("record_key", reg_record_key(r)),
                    ]));
                }
                continue;
            }
            // 구포맷(Win7/Win8.x)에서 해석된 행은 포맷을 detail에 남긴다 —
            // Win10/11 행은 종전과 동일하게 detail 없음(기존 출력 불변).
            let detail = parsed
                .format_note
                .map(|note| format!("포맷: {note}"))
                .unwrap_or_default();
            for (path, ft) in parsed.entries {
                if seen.contains(&path) {
                    continue;
                }
                seen.insert(path.clone());
                rows.push(rf_row(&[
                    ("category", "기타 레지스트리".into()),
                    ("subtype", "ShimCache".into()),
                    ("name", "ShimCache (AppcompatCache)".into()),
                    ("value", path),
                    ("status", "정보".into()),
                    ("detail", detail.clone()),
                    ("timestamp", filetime(ft)),
                    (
                        "key_path",
                        "…\\Control\\Session Manager\\AppCompatCache".into(),
                    ),
                    ("source", "SYSTEM".into()),
                    // 파생 항목 전부가 같은 AppCompatCache 바이너리 행에서 나온다.
                    ("record_key", reg_record_key(r)),
                ]));
            }
        }
    }
    rows
}

/// MFT 탐색기 교차 참조 태그용 파생 테이블(PathReferences)의 고정 컬럼.
pub const PR_KEYS: &[&str] = &[
    "path",
    "kind",
    "account",
    "label",
    "timestamp",
    "target_path",
    "app_id",
    "jumplist_type",
    "arguments",
    "working_directory",
    "machine_id",
    "created_time",
    "modified_time",
    "timestamp_source",
    "lnk_accessed",
    "destlist_accessed",
    "access_count",
    "hostname",
    "target_drive_letter",
    "path_kind",
    "record_key",
    "_source_file",
    "source_relative",
    "source_table",
    "source_rowid",
];

fn pr_row() -> Row {
    let mut r = Row::new();
    for k in PR_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    r
}

/// Path comparison key and the original path's scope.
pub(crate) struct PathShape {
    pub key: String,
    pub kind: &'static str,
    /// Uppercase drive plus colon; empty when unknown.
    pub drive: String,
}

/// Only local absolute paths become MFT-relative candidate keys.
pub(crate) fn classify_path(raw: &str) -> PathShape {
    let mut low = raw.to_lowercase();
    // Win32 file/device namespaces and NT `\??\` wrap ordinary drive/UNC paths.
    for prefix in ["\\\\?\\", "\\\\.\\", "\\??\\", "//?/", "//./"] {
        if let Some(rest) = low.strip_prefix(prefix) {
            let rest = match rest.strip_prefix("unc\\").or_else(|| rest.strip_prefix("unc/")) {
                Some(share) => format!("\\\\{share}"),
                None if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
                None => break,
            };
            low = rest;
            break;
        }
    }
    let b = low.as_bytes();
    let sep = |c: u8| c == b'\\' || c == b'/';
    if b.len() >= 2 && sep(b[0]) && sep(b[1]) {
        return PathShape { key: low, kind: "unc", drive: String::new() };
    }
    if low.starts_with("\\device\\") || low.starts_with("/device/") {
        // Volume device paths need volume-to-drive evidence before MFT matching.
        return PathShape { key: volume_relative_key(low), kind: "device_volume", drive: String::new() };
    }
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        let drive = format!("{}:", (b[0] as char).to_ascii_uppercase());
        if b.len() > 2 && sep(b[2]) {
            low.drain(..2);
            return PathShape { key: volume_relative_key(low), kind: "drive_absolute", drive };
        }
        // Drive-relative paths require an unknown current directory.
        return PathShape { key: low, kind: "drive_relative", drive };
    }
    if !b.is_empty() && sep(b[0]) {
        return PathShape {
            key: volume_relative_key(low),
            kind: "volume_relative",
            drive: String::new(),
        };
    }
    let kind = if low.starts_with("::{") || low.starts_with("shell:") {
        "shell_namespace"
    } else {
        "relative"
    };
    PathShape { key: low, kind, drive: String::new() }
}

// Normalize separators without changing the raw evidence path.
fn volume_relative_key(mut key: String) -> String {
    if key.contains('/') {
        key = key.replace('/', "\\");
    }
    key.truncate(key.trim_end_matches('\\').len());
    if key.is_empty() {
        key.push('\\');
    }
    key
}

/// per-user 아티팩트의 계정: LNK/JUMPLIST 수집 폴더 바로 다음 경로 조각.
pub(crate) fn account_from_source(src: &str) -> String {
    let parts: Vec<&str> = src.split(['/', '\\']).collect();
    for (i, part) in parts.iter().enumerate() {
        let up = part.to_uppercase();
        if (up == "LNK" || up == "JUMPLIST") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    String::new()
}

// Keep parsed JumpList evidence separate from the candidate path key.
fn jumplist_path_row(r: &Row) -> Option<Row> {
    let target = r.get("target_path").cloned().unwrap_or_default();
    if target.is_empty() {
        return None;
    }
    let source = r.get("_source_file").cloned().unwrap_or_default();
    let shape = classify_path(&target);
    let mut row = pr_row();
    row.insert("path".into(), shape.key);
    row.insert("path_kind".into(), shape.kind.into());
    row.insert("target_drive_letter".into(), shape.drive);
    row.insert("kind".into(), "Jumplist".into());
    row.insert("account".into(), account_from_source(&source));
    row.insert("label".into(), target.clone());
    row.insert("target_path".into(), target);
    for k in [
        "timestamp",
        "timestamp_source",
        "lnk_accessed",
        "destlist_accessed",
        "access_count",
        "hostname",
        "app_id",
        "jumplist_type",
        "arguments",
        "working_directory",
        "machine_id",
        "created_time",
        "modified_time",
        "_source_file",
    ] {
        if let Some(v) = r.get(k) {
            row.insert((*k).to_string(), v.clone());
        }
    }
    row.insert(
        "source_relative".into(),
        "JUMPLIST/JumpList_Entries.sqlite".into(),
    );
    row.insert("source_table".into(), "JumpList_Entries".into());
    row.insert(
        "source_rowid".into(),
        r.get("__source_rowid").cloned().unwrap_or_default(),
    );
    Some(row)
}

// Shellbag references have no representative time; do not substitute hive time.
fn shellbag_path_row(bag: crate::shellbag::Shellbag) -> Row {
    let shape = classify_path(&bag.display);
    let mut row = pr_row();
    row.insert("path".into(), shape.key);
    row.insert("path_kind".into(), shape.kind.into());
    row.insert("target_drive_letter".into(), shape.drive);
    row.insert("kind".into(), "Shellbag".into());
    row.insert("account".into(), bag.account);
    row.insert("label".into(), bag.display);
    // Preserve the BagMRU value that supplied this folder.
    row.insert("record_key".into(), bag.record_key);
    row
}

/// $MFT 탐색기의 교차 참조(JumpList 대상 경로 + Shellbag 폴더 열람 흔적)를
/// 파싱 단계에서 미리 조합해 derived로 저장한다 — 화면 진입마다 원본 전수
/// 스캔·Shellbag 재구성을 하지 않기 위한 협약 이행. 뷰어는 이 테이블을
/// 표시 중인 경로 배치로만 조회한다.
pub fn build_path_references(out_dir: &Path, registry: &RegistryOverviewCache) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    let jumplist = out_dir.join("JUMPLIST").join("JumpList_Entries.sqlite");
    for r in read_table_with_rowid(&jumplist, "JumpList_Entries")? {
        if let Some(row) = jumplist_path_row(&r) {
            rows.push(row);
        }
    }
    // Shellbag — BagMRU 숫자 값(자식 셸 아이템)을 하이브별로 모아 재구성.
    // 계정은 하이브 파일명의 사용자 접두(Administrator_UsrClass.dat 등).
    let mut bag_rows: Vec<crate::shellbag::BagRow> = Vec::new();
    for hive in registry.hives() {
        let stem = strip_uniq_suffix(&hive.name);
        let account = account_prefix(stem).unwrap_or(stem).to_string();
        for r in &hive.rows {
            let key_path = r.get("key_path").cloned().unwrap_or_default();
            if !key_path.to_lowercase().contains("bagmru") {
                continue;
            }
            let value_name = r.get("value_name").cloned().unwrap_or_default();
            if !value_name
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                continue;
            }
            let data = unhex(&r.get("value_data").cloned().unwrap_or_default());
            if data.is_empty() {
                continue;
            }
            bag_rows.push(crate::shellbag::BagRow {
                hive: hive.name.clone(),
                key_path,
                value_name,
                data,
                account: account.clone(),
                record_key: reg_record_key(r),
            });
        }
    }
    for bag in crate::shellbag::reconstruct(bag_rows) {
        rows.push(shellbag_path_row(bag));
    }
    Ok(rows)
}

/// MSI InstallDate("20260808")를 "2026-08-08 00:00:00.000"으로. 날짜만 있고
/// 시각이 없는 값이라 자정으로 고정한다.
fn msi_install_date(raw: &str) -> String {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 8 {
        format!(
            "{}-{}-{} 00:00:00.000",
            &digits[0..4],
            &digits[4..6],
            &digits[6..8]
        )
    } else {
        String::new()
    }
}

/// Windows Installer(.msi)로 설치된 프로그램 —
/// ...\CurrentVersion\Installer\UserData\<SID>\Products\*\InstallProperties.
/// 키 하나가 프로그램 하나: 값 전체를 JSON(properties)으로 보존해 상세 보기에서
/// 다 보이게 하고, 행 요약은 DisplayName/버전/제조사만 쓴다.
fn rf_msi_installs(hives: &[RegistryOverviewHive]) -> Vec<Row> {
    let mut rows = Vec::new();
    for hive in hives {
        let mut by_key: std::collections::BTreeMap<&str, std::collections::BTreeMap<String, String>> =
            std::collections::BTreeMap::new();
        let mut key_rk: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
        for r in &hive.rows {
            let Some(kp) = r.get("key_path") else { continue };
            let low = kp.to_lowercase();
            if !(low.contains("\\currentversion\\installer\\userdata\\")
                && low.ends_with("\\installproperties"))
            {
                continue;
            }
            let name = r.get("value_name").cloned().unwrap_or_default();
            if name.is_empty() || name == "(default)" {
                continue;
            }
            key_rk
                .entry(kp.as_str())
                .or_insert_with(|| reg_record_key(r));
            by_key
                .entry(kp.as_str())
                .or_default()
                .insert(name, r.get("value_data").cloned().unwrap_or_default());
        }
        for (kp, props) in by_key {
            let display_name = prop_ci(&props, "DisplayName").cloned().unwrap_or_default();
            if display_name.is_empty() {
                continue;
            }
            let timestamp = prop_ci(&props, "InstallDate")
                .map(|d| msi_install_date(d))
                .unwrap_or_default();
            let sid = kp
                .split('\\')
                .skip_while(|p| !p.eq_ignore_ascii_case("UserData"))
                .nth(1)
                .unwrap_or("")
                .to_string();
            rows.push(rf_row(&[
                ("category", "설치 프로그램 (MSI)".into()),
                ("name", display_name),
                ("value", prop_ci(&props, "DisplayVersion").cloned().unwrap_or_default()),
                ("detail", prop_ci(&props, "Publisher").cloned().unwrap_or_default()),
                ("status", "정보".into()),
                ("user", sid),
                ("timestamp", timestamp),
                ("subtype", "MsiInstall".into()),
                (
                    "properties",
                    serde_json::to_string(&props).unwrap_or_default(),
                ),
                ("key_path", kp.to_string()),
                ("source", hive.name.clone()),
                ("record_key", key_rk.get(kp).cloned().unwrap_or_default()),
            ]));
        }
    }
    rows
}

pub fn build_registry_findings_with_registry(registry: &RegistryOverviewCache) -> Vec<Row> {
    // Registry rows are intentionally read once per overview build. The old
    // path separately opened SYSTEM/SOFTWARE and then opened every hive twice
    // more for findings and ShimCache, multiplying large-hive SQLite scans
    // without changing the resulting evidence rows.
    let system = registry.rows("SYSTEM");
    let software = registry.rows("SOFTWARE");
    let mut rows = Vec::new();
    // rf_credential_protection이 rf_lsa_packages 결과까지 합쳐 반환한다 —
    // 여기서 다시 호출하면 Lsa 확장 행이 전부 두 번 생긴다.
    if !system.is_empty() {
        rows.extend(rf_credential_protection(system));
    }
    rows.extend(rf_shares(system));
    rows.extend(rf_sql_auth(software));
    rows.extend(rf_autoruns(registry.hives()));
    rows.extend(rf_winlogon(software));
    rows.extend(rf_silent_process_exit(software));
    rows.extend(rf_taskcache(software));
    rows.extend(rf_active_setup(software));
    rows.extend(rf_appinit(software, system));
    rows.extend(rf_session_manager(system));
    if !software.is_empty() {
        rows.extend(rf_security_config(software));
    }
    rows.extend(rf_remote_tools(registry.hives()));
    rows.extend(rf_msi_installs(registry.hives()));
    rows.extend(rf_uninstall_installs(registry.hives()));
    rows.extend(rf_execution_traces(registry.hives()));
    rows.extend(rf_shimcache(registry.hives()));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Facts DB whose table spans many leaf pages, with one middle leaf
    /// overwritten so the scan fails part-way (open and prepare still work).
    fn corrupt_mid_table_db(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("wina-rd04-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("Facts.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA page_size=4096; CREATE TABLE Facts(v TEXT);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<2000)
             INSERT INTO Facts SELECT printf('%0200d', i) FROM c;",
        )
        .unwrap();
        drop(conn);
        let mut bytes = std::fs::read(&db).unwrap();
        let page = bytes.len() / 4096 / 2;
        let offset = page * 4096;
        assert_eq!(bytes[offset], 0x0D, "middle page must be a table leaf");
        bytes[offset..offset + 8].fill(0xFF);
        std::fs::write(&db, bytes).unwrap();
        (root, db)
    }

    // RD-04: a scan error part-way through must not look like a short table;
    // it reaches the builders (and so parse_report) as an error.
    #[test]
    fn row_scan_error_is_not_a_silent_short_read() {
        let (root, db) = corrupt_mid_table_db("scan");
        let error = read_table(&db, "Facts").expect_err("rows were silently truncated");
        assert!(format!("{error:#}").contains("Facts"), "{error:#}");
        assert!(read_table_with_rowid(&db, "Facts").is_err());
        // Missing DB or table is no evidence, not a failure.
        assert!(read_table(&db, "Absent").unwrap().is_empty());
        assert!(read_table(&root.join("none.sqlite"), "Facts").unwrap().is_empty());
        // The shared event cache carries the failure to every event builder.
        std::fs::create_dir_all(root.join("EVENTLOG")).unwrap();
        std::fs::rename(&db, root.join("EVENTLOG/Facts.sqlite")).unwrap();
        assert!(EventLogOverviewCache::load(&root).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_registry_settings_keep_confirmed_target_paths_without_inventing_values() {
        let root = Row::from([("key_path".into(), r"\ROOT".into())]);
        let select = Row::from([
            ("key_path".into(), r"\ROOT\Select".into()),
            ("value_name".into(), "Current".into()),
            ("value_data".into(), "2".into()),
        ]);
        let findings = rf_credential_protection(&[root.clone(), select]);
        for (name, path) in [
            ("WDigest UseLogonCredential", r"\ROOT\ControlSet002\Control\SecurityProviders\WDigest"),
            ("LSASS 보호(RunAsPPL)", r"\ROOT\ControlSet002\Control\Lsa"),
        ] {
            let row = findings.iter().find(|row| row["name"] == name).unwrap();
            assert_eq!(row["key_path"], path);
            assert!(row.get("record_key").is_none_or(String::is_empty));
        }
        let no_select = rf_credential_protection(&[root.clone()]);
        assert!(no_select.iter().all(|r| !r["key_path"].contains("ControlSet001")));
        let software = rf_security_config(&[root]);
        let row = software.iter().find(|row| row["name"] == "ScriptBlockLogging").unwrap();
        assert_eq!(row["key_path"], r"\ROOT\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
        assert!(row.get("record_key").is_none_or(String::is_empty));
    }

    #[test]
    fn classifies_local_absolute_paths_and_keeps_drive() {
        let c = classify_path("C:\\Users\\Alice\\a.txt");
        assert_eq!(c.kind, "drive_absolute");
        assert_eq!(c.key, "\\users\\alice\\a.txt");
        assert_eq!(c.drive, "C:");
        // Equal relative paths do not imply equal drives.
        let d = classify_path("D:/Users/Alice/a.txt");
        assert_eq!(d.key, c.key);
        assert_eq!(d.drive, "D:");
        assert_eq!(d.kind, "drive_absolute");
        assert_eq!(classify_path("C:\\Users\\Alice\\").key, "\\users\\alice");
        assert_eq!(classify_path("C:\\").key, "\\");
    }

    #[test]
    fn keeps_non_local_paths_out_of_volume_relative_keys() {
        let unc = classify_path("\\\\SRV\\Share\\f.txt");
        assert_eq!(unc.kind, "unc");
        assert_eq!(unc.key, "\\\\srv\\share\\f.txt");
        assert!(unc.drive.is_empty());

        // A drive-relative path is not an absolute path.
        let rel_drive = classify_path("C:foo\\bar");
        assert_eq!(rel_drive.kind, "drive_relative");
        assert_eq!(rel_drive.key, "c:foo\\bar");
        assert_eq!(rel_drive.drive, "C:");
        assert_eq!(classify_path("C:").kind, "drive_relative");

        let rel = classify_path("..\\docs\\a.txt");
        assert_eq!(rel.kind, "relative");
        assert_eq!(rel.key, "..\\docs\\a.txt");
        assert!(rel.drive.is_empty());

        let shell = classify_path("::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\x");
        assert_eq!(shell.kind, "shell_namespace");
        assert!(shell.drive.is_empty());

        let vol = classify_path("\\Users\\Alice");
        assert_eq!(vol.kind, "volume_relative");
        assert_eq!(vol.key, "\\users\\alice");
        assert!(vol.drive.is_empty());
    }

    #[test]
    fn strips_win32_and_nt_prefixes_before_classifying() {
        for raw in ["\\\\?\\C:\\Windows\\x.exe", "\\\\.\\C:\\Windows\\x.exe", "\\??\\C:\\Windows\\x.exe"] {
            let c = classify_path(raw);
            assert_eq!((c.kind, c.key.as_str(), c.drive.as_str()), ("drive_absolute", "\\windows\\x.exe", "C:"), "{raw}");
        }
        let unc = classify_path("\\\\?\\UNC\\Srv\\Share\\f.txt");
        assert_eq!((unc.kind, unc.key.as_str()), ("unc", "\\\\srv\\share\\f.txt"));
        // No volume-to-drive mapping evidence: not a volume-relative key.
        let dev = classify_path("\\Device\\HarddiskVolume1\\Windows\\x.exe");
        assert_eq!(dev.kind, "device_volume");
        assert!(dev.drive.is_empty());
    }

    #[test]
    fn jumplist_reference_keeps_parsed_usage_facts() {
        let mut r = Row::new();
        r.insert("target_path".into(), "C:\\Users\\Alice\\a.txt".into());
        r.insert("timestamp".into(), "2026-03-02 11:00:00.000".into());
        r.insert("timestamp_source".into(), "destlist_accessed".into());
        r.insert("lnk_accessed".into(), "2026-03-01 10:00:00.000".into());
        r.insert("destlist_accessed".into(), "2026-03-02 11:00:00.000".into());
        r.insert("access_count".into(), "7".into());
        r.insert("hostname".into(), "HOST-01".into());
        r.insert("_source_file".into(), "/c/JUMPLIST/Alice/x.ms".into());
        let row = jumplist_path_row(&r).expect("row");
        assert_eq!(row["path"], "\\users\\alice\\a.txt");
        assert_eq!(row["path_kind"], "drive_absolute");
        assert_eq!(row["target_drive_letter"], "C:");
        // 원본 대상 경로 전문은 그대로 남는다.
        assert_eq!(row["target_path"], "C:\\Users\\Alice\\a.txt");
        assert_eq!(row["access_count"], "7");
        assert_eq!(row["hostname"], "HOST-01");
        assert_eq!(row["lnk_accessed"], "2026-03-01 10:00:00.000");
        assert_eq!(row["destlist_accessed"], "2026-03-02 11:00:00.000");
        assert_eq!(row["timestamp_source"], "destlist_accessed");
        assert_eq!(row["account"], "Alice");
        assert!(jumplist_path_row(&Row::new()).is_none());
    }

    /// Shellbag은 시각 증거가 없다 — 하이브 마지막 쓰기 시각을 끌어오지 않는다.
    #[test]
    fn shellbag_reference_has_no_timestamp() {
        let row = shellbag_path_row(crate::shellbag::Shellbag {
            path: "\\users\\alice\\desktop".into(),
            display: "C:\\Users\\Alice\\Desktop".into(),
            account: "Alice".into(),
            record_key: "UsrClass::Registry::1".into(),
        });
        assert!(row["timestamp"].is_empty());
        assert!(row["timestamp_source"].is_empty());
        assert!(row["lnk_accessed"].is_empty());
        assert!(row["destlist_accessed"].is_empty());
        assert!(row["access_count"].is_empty());
        assert_eq!(row["path"], "\\users\\alice\\desktop");
        assert_eq!(row["path_kind"], "drive_absolute");
        assert_eq!(row["target_drive_letter"], "C:");

        let no_volume = shellbag_path_row(crate::shellbag::Shellbag {
            path: "\\desktop".into(),
            display: "\\Desktop".into(),
            account: "Alice".into(),
            record_key: String::new(),
        });
        assert_eq!(no_volume["path_kind"], "volume_relative");
        assert!(no_volume["target_drive_letter"].is_empty());
    }

    /// RegBack 산출물은 facts로 보존하되 파생 입력에서 제외된다 — 판별 회귀.
    #[test]
    fn regback_outputs_are_recognized_for_derived_exclusion() {
        assert!(is_regback_output(Path::new("/x/REGISTRY/SYSTEM_RegBack.sqlite")));
        assert!(is_regback_output(Path::new("/x/REGISTRY/SOFTWARE_RegBack_2.sqlite")));
        assert!(!is_regback_output(Path::new("/x/REGISTRY/SYSTEM.sqlite")));
        assert!(!is_regback_output(Path::new("/x/REGISTRY/NTUSER.DAT.sqlite")));
    }

    /// `%SystemRoot%` 전개는 분석 호스트의 `C:\Windows`가 아니라 대상 호스트
    /// 레지스트리 값이어야 한다 — SOFTWARE\...\CurrentVersion\SystemRoot를
    /// TargetInfo SystemInfo 행으로 올려 화면이 실제 경로(D:\test)를 쓰게 한다.
    #[test]
    fn system_info_carries_target_system_root_from_registry() {
        let sw = |name: &str, data: &str| {
            let mut r = Row::new();
            r.insert(
                "key_path".into(),
                "\\Microsoft\\Windows NT\\CurrentVersion".into(),
            );
            r.insert("value_name".into(), name.into());
            r.insert("value_data".into(), data.into());
            r
        };
        let software = vec![
            sw("ProductName", "Windows 10 Pro"),
            sw("SystemRoot", "D:\\test"),
        ];
        let out = ti_system_info(&software, &[]);
        let sr = out
            .iter()
            .find(|r| r["name"] == "SystemRoot")
            .expect("SystemRoot row");
        assert_eq!(sr["value"], "D:\\test");
        assert_eq!(sr["category"], "SystemInfo");
        assert_eq!(sr["source_artifact"], "SOFTWARE");
    }



    /// 이름 충돌 접미(`_2`)가 붙은 산출물도 같은 하이브다 — 접미를 떼지 않으면
    /// 그 계정의 UserAssist·Shellbag·특이사항이 파생에서 통째로 빠진다.
    #[test]
    fn uniq_suffix_does_not_hide_a_hive_from_derived_views() {
        assert_eq!(strip_uniq_suffix("Administrator_NTUSER.DAT"), "Administrator_NTUSER.DAT");
        assert_eq!(strip_uniq_suffix("NTUSER.DAT_2"), "NTUSER.DAT");
        assert_eq!(strip_uniq_suffix("NTUSER.DAT_"), "NTUSER.DAT_");
        assert!(strip_uniq_suffix("NTUSER.DAT_2").to_uppercase().ends_with("NTUSER.DAT"));
    }

    /// 산출물 이름의 계정 접두가 화면·파생의 계정 라벨로 복원된다.
    #[test]
    fn hive_account_labels_come_from_the_output_name_prefix() {
        assert_eq!(hive_user("Administrator_NTUSER.DAT"), "Administrator");
        assert_eq!(hive_user("Administrator_UsrClass.dat"), "Administrator");
        assert_eq!(hive_user("svcuser_NTUSER.DAT_2"), "svcuser");
        assert_eq!(hive_user("SOFTWARE"), "(시스템)");
        assert_eq!(hive_user("SYSTEM"), "SYSTEM");
        // 접두가 없는 예전 이름은 그대로 — 계정을 지어내지 않는다.
        assert_eq!(hive_user("NTUSER.DAT"), "NTUSER.DAT");
    }

    #[test]
    fn hosts_file_entries_join_target_info() {
        let root = std::env::temp_dir().join(format!("wina-hosts-ti-{}", std::process::id()));
        let etc = root.join("NonVolatile").join("ETC").join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("hosts"),
            "# comment\n#\t127.0.0.1 localhost\n10.0.0.5\tBACKUP\n10.0.0.5 SECOND # tail comment\nnot-an-ip name\n",
        )
        .unwrap();
        let rows = ti_from_hosts_file(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("category").map(String::as_str), Some("HostsFile"));
        assert_eq!(rows[0].get("name").map(String::as_str), Some("BACKUP"));
        assert_eq!(rows[0].get("value").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(rows[1].get("name").map(String::as_str), Some("SECOND"));
        assert_eq!(rows[0].get("source_artifact").map(String::as_str), Some("hosts"));
    }

    #[test]
    fn powershell_event_800_keeps_host_application_and_eventdata_account() {
        let root =
            std::env::temp_dir().join(format!("wina-powershell-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("PowerShell.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell (Provider TEXT, EventID TEXT, EventData TEXT, UserID TEXT, ProcessID TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO PowerShell VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "PowerShell",
                "800",
                r#"{"Message":"HostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile\nUserId=NAMYANG\\2505002"}"#,
                "",
                "4242",
                "2026-08-21 10:00:00.000",
                "Windows PowerShell.evtx::41",
            ],
        ).unwrap();
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            row.get("account").map(String::as_str),
            Some("NAMYANG\\2505002")
        );
        assert_eq!(
            row.get("host_application").map(String::as_str),
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile")
        );
        assert_eq!(row.get("command").map(String::as_str), Some(""));
        assert_eq!(
            row.get("record_key").map(String::as_str),
            Some("Windows PowerShell.evtx::41")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msi_install_properties_become_one_finding_with_midnight_date() {
        let hive = RegistryOverviewHive {
            name: "SOFTWARE".into(),
            database: std::path::PathBuf::new(),
            rows: [
                ("DisplayName", "Example App"),
                ("DisplayVersion", "1.2.3"),
                ("Publisher", "Example Corp"),
                ("InstallDate", "20260808"),
                ("InstallSource", "C:\\Users\\a\\Downloads\\"),
            ]
            .into_iter()
            .map(|(name, data)| {
                let mut r = Row::new();
                r.insert(
                    "key_path".into(),
                    "\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\ABC123\\InstallProperties".into(),
                );
                r.insert("value_name".into(), name.into());
                r.insert("value_data".into(), data.into());
                r.insert("last_write".into(), "2026-08-09 01:02:03.000".into());
                r
            })
            .collect(),
        };
        let rows = rf_msi_installs(&[hive]);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("name").map(String::as_str), Some("Example App"));
        assert_eq!(
            row.get("timestamp").map(String::as_str),
            Some("2026-08-08 00:00:00.000")
        );
        assert_eq!(row.get("value").map(String::as_str), Some("1.2.3"));
        assert_eq!(row.get("detail").map(String::as_str), Some("Example Corp"));
        assert_eq!(row.get("user").map(String::as_str), Some("S-1-5-18"));
        assert_eq!(row.get("subtype").map(String::as_str), Some("MsiInstall"));
        let props: serde_json::Value =
            serde_json::from_str(row.get("properties").unwrap()).unwrap();
        assert_eq!(props["InstallSource"], "C:\\Users\\a\\Downloads\\");
    }

    #[test]
    fn console_history_rows_join_powershell_overview_without_timestamp() {
        let root =
            std::env::temp_dir().join(format!("wina-psconsole-overview-{}", std::process::id()));
        let ps_dir = root.join("POWERSHELL");
        std::fs::create_dir_all(&ps_dir).unwrap();
        let db_path = ps_dir.join("PowerShell_ConsoleHistory.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell_ConsoleHistory (line_number TEXT, command TEXT, user TEXT, _source_file TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO PowerShell_ConsoleHistory VALUES ('2', 'whoami', 'analyst', 'ConsoleHost_history.txt')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO PowerShell_ConsoleHistory VALUES ('1', 'Get-Process', 'analyst', 'ConsoleHost_history.txt')",
            [],
        ).unwrap();
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("kind").map(String::as_str), Some("콘솔 히스토리"));
        assert_eq!(rows[0].get("timestamp").map(String::as_str), Some(""));
        // line_number 순서 보존
        assert_eq!(rows[0].get("command").map(String::as_str), Some("Get-Process"));
        assert_eq!(rows[1].get("command").map(String::as_str), Some("whoami"));
        assert_eq!(rows[0].get("account").map(String::as_str), Some("analyst"));
        assert!(rows[0].get("record_key").map(String::as_str).unwrap_or("").starts_with("PowerShell_ConsoleHistory::"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn powershell_event_400_becomes_engine_start_row() {
        let root =
            std::env::temp_dir().join(format!("wina-ps400-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("PowerShell.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell (Provider TEXT, EventID TEXT, EventData TEXT, UserID TEXT, ProcessID TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO PowerShell VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "PowerShell",
                "400",
                r#"{"Message":"NewEngineState=Available\n\tHostApplication=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAA"}"#,
                "",
                "512",
                "2026-08-21 09:59:59.000",
                "Windows PowerShell.evtx::40",
            ],
        ).unwrap();
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("kind").map(String::as_str), Some("엔진 시작"));
        assert_eq!(row.get("event_id").map(String::as_str), Some("400"));
        assert_eq!(
            row.get("host_application").map(String::as_str),
            Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAA")
        );
        std::fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn exe_from_host_handles_unquoted_path_with_spaces() {
        assert_eq!(
            exe_from_host("C:\\Program Files\\PowerShell\\7\\pwsh.exe -Command Get-Item"),
            "pwsh.exe"
        );
        assert_eq!(
            exe_from_host("\"C:\\Program Files\\a b\\x.exe\" -y"),
            "x.exe"
        );
        assert_eq!(exe_from_host("powershell.exe -NoProfile"), "powershell.exe");
    }




    #[test]
    fn pending_file_rename_follows_active_control_set() {
        let root = std::env::temp_dir().join(format!(
            "wina-pending-rename-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SYSTEM.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        // LKG 부팅 후 상태: 활성 세트는 002, 001에는 낡은 미러가 남아 있다.
        for row in [
            ("\\Select", "Current", "2"),
            (
                "\\ControlSet002\\Control\\Session Manager",
                "PendingFileRenameOperations",
                r#"["\\??\\C:\\Users\\victim\\mal.exe",""]"#,
            ),
            (
                "\\ControlSet001\\Control\\Session Manager",
                "PendingFileRenameOperations",
                r#"["\\??\\C:\\stale\\old.tmp",""]"#,
            ),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SYSTEM')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let pending: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("PendingFileRename"))
            .collect();
        // 활성 세트(002)의 예약만 나와야 한다 — 001 고정이면 낡은 미러가
        // 나오고, 필터가 없으면 두 세트가 중복 출력된다.
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].get("value").map(String::as_str),
            Some("C:\\Users\\victim\\mal.exe")
        );
        assert_eq!(
            pending[0].get("record_key").map(String::as_str),
            Some("SYSTEM::Registry::2")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bandizip_recent_archives_keep_every_stored_path() {
        let root = std::env::temp_dir().join(format!(
            "wina-bandizip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("analyst_NTUSER.DAT.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        for row in [
            ("\\ROOT\\SOFTWARE\\Bandizip", "RecentArchive0", "C:\\Users\\a\\Desktop\\out.zip"),
            ("\\ROOT\\SOFTWARE\\Bandizip", "RecentArchive1", "D:\\x.7z"),
            ("\\ROOT\\SOFTWARE\\Bandizip", "RecentArchive2", ""),
            ("\\ROOT\\SOFTWARE\\Bandizip", "RecentFolder0", "C:\\dest\\"),
            ("\\ROOT\\SOFTWARE\\Bandizip\\Other", "RecentArchive0", "C:\\nested.zip"),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/analyst_NTUSER.DAT')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let archives: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("BandizipRecentArchive"))
            .map(|row| {
                (
                    row.get("value").cloned().unwrap_or_default(),
                    row.get("detail").cloned().unwrap_or_default(),
                    row.get("record_key").cloned().unwrap_or_default(),
                )
            })
            .collect();
        // Empty slots, other values and other keys stay out; the slot name is kept.
        assert_eq!(
            archives,
            vec![
                ("C:\\Users\\a\\Desktop\\out.zip".to_string(), "RecentArchive0".to_string(), "analyst_NTUSER.DAT::Registry::1".to_string()),
                ("D:\\x.7z".to_string(), "RecentArchive1".to_string(), "analyst_NTUSER.DAT::Registry::2".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Actions 문자열 인코딩: u32 LE 바이트 길이 + UTF-16LE 본문.
    fn task_str(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = (utf16.len() as u32).to_le_bytes().to_vec();
        out.extend(utf16);
        out
    }

    #[test]
    fn task_actions_parses_exec_and_com_handler() {
        let mut b: Vec<u8> = vec![1, 0];
        b.extend(task_str("Author"));
        b.extend([0x66, 0x66]);
        b.extend(task_str("{id}"));
        b.extend(task_str("cmd.exe"));
        b.extend(task_str("/c evil"));
        b.extend(task_str(""));
        b.extend([0x77, 0x77]);
        b.extend(task_str(""));
        b.extend((0u8..16).collect::<Vec<u8>>());
        b.extend(task_str("payload.dll"));
        let (summary, incomplete) = parse_task_actions(&b);
        assert!(!incomplete);
        assert_eq!(
            summary,
            "cmd.exe /c evil ; COM {03020100-0504-0706-0809-0a0b0c0d0e0f} payload.dll"
        );
    }

    #[test]
    fn task_actions_flags_unsupported_magic_as_incomplete() {
        let mut b: Vec<u8> = vec![1, 0];
        b.extend(task_str("Author"));
        // 이메일(0x8888) 등 해석하지 않는 액션 — 남은 바이트가 버려지므로
        // "명령 없는 정상 작업"이 아니라 미해석으로 보여야 한다.
        b.extend([0x88, 0x88]);
        b.extend(task_str("dropped"));
        let (summary, incomplete) = parse_task_actions(&b);
        assert!(incomplete);
        assert_eq!(summary, "");
    }

    #[test]
    fn task_actions_flags_truncated_string_as_incomplete() {
        let mut b: Vec<u8> = vec![1, 0];
        b.extend(task_str("Author"));
        b.extend([0x66, 0x66]);
        b.extend(task_str("{id}"));
        // 명령 문자열이 선언 길이(100바이트)보다 짧게 잘림 — 손상 케이스.
        b.extend(100u32.to_le_bytes());
        b.extend([0x41, 0x00]);
        let (summary, incomplete) = parse_task_actions(&b);
        assert!(incomplete);
        assert_eq!(summary, "");
    }

    #[test]
    fn task_actions_flags_truncated_workdir_as_incomplete() {
        let mut b: Vec<u8> = vec![1, 0];
        b.extend(task_str("Author"));
        b.extend([0x66, 0x66]);
        b.extend(task_str("{id}"));
        b.extend(task_str("cmd.exe"));
        b.extend(task_str("/c evil"));
        // 명령·인자는 정상인데 작업 디렉터리 문자열이 선언 길이(50바이트)보다
        // 짧게 잘림 — 해석된 명령은 유지하되 미해석으로 표시해야 한다.
        b.extend(50u32.to_le_bytes());
        b.extend([0x41, 0x00]);
        let (summary, incomplete) = parse_task_actions(&b);
        assert!(incomplete);
        assert_eq!(summary, "cmd.exe /c evil");
    }

    #[test]
    fn task_actions_flags_truncated_com_id_as_incomplete() {
        let mut b: Vec<u8> = vec![1, 0];
        b.extend(task_str("Author"));
        b.extend([0x77, 0x77]);
        // ComHandler ID 문자열이 선언 길이(100바이트)보다 짧게 잘림.
        b.extend(100u32.to_le_bytes());
        b.extend([0x41, 0x00]);
        let (summary, incomplete) = parse_task_actions(&b);
        assert!(incomplete);
        assert_eq!(summary, "");
    }

    #[test]
    fn appinit_flag_is_read_from_same_registry_view() {
        let root = std::env::temp_dir().join(format!(
            "wina-appinit-view-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SOFTWARE.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        const NATIVE: &str = "\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        const WOW: &str = "\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        // 64비트 뷰는 주입 활성(Load=1), 32비트(Wow6432Node) 뷰는 비활성(Load=0)
        // — 각 행이 자기 뷰의 플래그로만 판정되어야 한다.
        for row in [
            (NATIVE, "AppInit_DLLs", "evil64.dll"),
            (NATIVE, "LoadAppInit_DLLs", "1"),
            (WOW, "AppInit_DLLs", "evil32.dll"),
            (WOW, "LoadAppInit_DLLs", "0"),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SOFTWARE')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let status_of = |value: &str| {
            findings
                .iter()
                .find(|row| {
                    row.get("subtype").map(String::as_str) == Some("AppInit")
                        && row.get("value").map(String::as_str) == Some(value)
                })
                .and_then(|row| row.get("status").cloned())
        };
        assert_eq!(status_of("evil64.dll").as_deref(), Some("의심"));
        assert_eq!(status_of("evil32.dll").as_deref(), Some("주의"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn script_block_reassembly_flags_incomplete_fragments() {
        let root = std::env::temp_dir().join(format!(
            "wina-ps4104-parts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let conn = Connection::open(event_dir.join("PowerShell.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell (Provider TEXT, EventID TEXT, EventData TEXT, UserID TEXT, ProcessID TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        let insert = |sbid: &str, num: i64, total: i64, text: &str, rk: &str| {
            conn.execute(
                "INSERT INTO PowerShell VALUES ('Microsoft-Windows-PowerShell', '4104', ?1, 'S-1-5-21-1', '100', '2026-08-01 10:00:00.000', ?2)",
                rusqlite::params![
                    format!(
                        r#"{{"ScriptBlockText":"{text}","ScriptBlockId":"{sbid}","MessageNumber":"{num}","MessageTotal":"{total}","Path":""}}"#
                    ),
                    rk,
                ],
            )
            .unwrap();
        };
        // 정상 1..2 / 중간 누락 / 중복(내용 상이) / 범위 밖 번호 / 총수 불일치
        insert("sb-full", 1, 2, "AA", "PowerShell::1");
        insert("sb-full", 2, 2, "BB", "PowerShell::2");
        insert("sb-miss", 1, 3, "M1", "PowerShell::3");
        insert("sb-miss", 3, 3, "M3", "PowerShell::4");
        insert("sb-dup", 1, 2, "D-first", "PowerShell::5");
        insert("sb-dup", 1, 2, "D-second", "PowerShell::6");
        insert("sb-dup", 2, 2, "D2", "PowerShell::7");
        insert("sb-range", 1, 2, "R1", "PowerShell::8");
        insert("sb-range", 5, 2, "R5", "PowerShell::9");
        insert("sb-total", 1, 2, "T1", "PowerShell::10");
        insert("sb-total", 2, 3, "T2", "PowerShell::11");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        let status_of = |needle: &str| -> Option<String> {
            rows.iter()
                .find(|row| {
                    row.get("script_block")
                        .map(|text| text.contains(needle))
                        .unwrap_or(false)
                })
                .map(|row| row.get("script_block_status").cloned().unwrap_or_default())
        };
        // 완전한 블록은 상태 표시가 없어야 한다.
        assert_eq!(status_of("AABB").as_deref(), Some(""));
        let miss = status_of("M1M3").expect("missing-fragment block");
        assert!(miss.contains("불완전") && miss.contains("누락 조각: 2"), "{miss}");
        // 충돌한 조각은 어느 쪽이 진짜인지 증명할 수 없다 — 대표 본문이 무엇인지
        // 고정하지 않고, 이상 표시와 원본 양쪽 보존만 요구한다.
        let dup_row = rows
            .iter()
            .find(|row| row.get("script_block_id").map(String::as_str) == Some("sb-dup"))
            .expect("duplicate-fragment block");
        let dup = dup_row
            .get("script_block_status")
            .cloned()
            .unwrap_or_default();
        assert!(dup.contains("조각 1 중복(내용 상이)"), "{dup}");
        let dup_parts = dup_row.get("script_block_parts").cloned().unwrap_or_default();
        assert!(
            dup_parts.contains("D-first") && dup_parts.contains("D-second"),
            "{dup_parts}"
        );
        let range = status_of("R1").expect("out-of-range block");
        assert!(range.contains("범위 밖 조각 번호 5"), "{range}");
        let total = status_of("T1T2").expect("total-mismatch block");
        assert!(total.contains("총 조각 수 불일치(2 vs 3)"), "{total}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// PowerShell 회귀 테스트용 임시 케이스 루트 — 동시 실행 충돌을 피한다.
    fn ps_tmp(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wina-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// 실수집본과 같은 컬럼 집합의 EVENTLOG 팩트 DB(파일 스템 = 테이블명).
    fn ps_event_facts(root: &std::path::Path) -> Connection {
        let dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(dir.join("PowerShell.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell (timestamp TEXT, Channel TEXT, Provider TEXT, EventID TEXT, \
             Level TEXT, Computer TEXT, EventRecordID TEXT, ProcessID TEXT, UserID TEXT, \
             EventData TEXT, _record_key TEXT, _source_file TEXT)",
            [],
        )
        .unwrap();
        conn
    }

    fn ps_insert(
        conn: &Connection,
        event_id: &str,
        record_id: &str,
        pid: &str,
        data: &str,
        source_file: &str,
    ) {
        conn.execute(
            "INSERT INTO PowerShell VALUES ('2026-10-08 01:02:03.004', \
             'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', ?1, '3', \
             'WIN-HOST', ?2, ?3, 'S-1-5-21-1-2-3-500', ?4, ?5, ?6)",
            rusqlite::params![
                event_id,
                record_id,
                pid,
                data,
                format!("PowerShell::{record_id}"),
                source_file
            ],
        )
        .unwrap();
    }

    fn ps_insert_classic(conn: &Connection, event_id: &str, record_id: &str, data: &str) {
        conn.execute(
            "INSERT INTO PowerShell VALUES ('2026-10-08 01:02:03.004', 'Windows PowerShell', \
             'PowerShell', ?1, '4', 'WIN-HOST', ?2, '512', '', ?3, ?4, 'Windows PowerShell.evtx')",
            rusqlite::params![event_id, record_id, data, format!("PowerShell::{record_id}")],
        )
        .unwrap();
    }

    fn ps_json(row: &Row, key: &str) -> serde_json::Value {
        let raw = row
            .get(key)
            .unwrap_or_else(|| panic!("{key} 키가 없습니다: {row:?}"));
        serde_json::from_str(raw).unwrap_or_else(|e| panic!("{key} JSON 아님: {raw} ({e})"))
    }

    /// ScriptBlockId로 4104 행을 찾는다.
    fn ps_row_of<'a>(rows: &'a [Row], sbid: &str) -> &'a Row {
        rows.iter()
            .find(|row| row.get("script_block_id").map(String::as_str) == Some(sbid))
            .unwrap_or_else(|| panic!("{sbid} 행 없음"))
    }

    // 실수집본 4100/4103 ContextInfo(ko) 형태 — 호스트 응용 프로그램 값이 여러
    // 줄이고 그 안에 ' = '와 '='가 모두 들어 있다.
    const CTX_KO: &str = concat!(
        "        심각도 = Warning\r\n",
        "        호스트 이름 = ConsoleHost\r\n",
        "        호스트 ID = ebf6a673-8b57-4c7e-86b2-43b6d1af9773\r\n",
        "        호스트 응용 프로그램 = powershell.exe -NoProfile -Command Write-Output \"=== a=b ===\"\n",
        "; $_ec = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }\n",
        "; exit $_ec\r\n",
        "        엔진 버전 = 5.1.26100.7462\r\n",
        "        Runspace ID = 3eee4306-36d0-4389-90a1-21d6ca3a7961\r\n",
        "        파이프라인 ID = 1\r\n",
        "        명령 이름 = \r\n",
        "        스크립트 이름 = C:\\scripts\\collect.ps1\r\n",
        "        사용자 = WIN-HOST\\Administrator\r\n",
    );
    const HOST_KO: &str = concat!(
        "powershell.exe -NoProfile -Command Write-Output \"=== a=b ===\"\n",
        "; $_ec = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }\n",
        "; exit $_ec",
    );

    #[test]
    fn powershell_4100_error_row_keeps_payload_and_explicit_ids() {
        let root = ps_tmp("ps4100-error");
        let conn = ps_event_facts(&root);
        let payload = "  Error Message = System error.\r\nfull warning  ";
        let data = serde_json::json!({
            "ContextInfo": CTX_KO, "UserData": "", "Payload": payload
        })
        .to_string();
        ps_insert(&conn, "4100", "17", "356", &data, "PowerShell.evtx");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        // Level 3 = 경고 — 수준을 무시하고 전부 "오류"라고 쓰지 않는다.
        assert_eq!(row.get("kind").map(String::as_str), Some("실행 경고"));
        assert_eq!(row.get("event_id").map(String::as_str), Some("4100"));
        // 오류 본문은 원문 그대로(앞뒤 공백 포함) 보존한다.
        assert_eq!(row.get("error_message").map(String::as_str), Some(payload));
        // 오류 메시지를 명령으로 둔갑시키지 않는다 — 명령 이름이 비면 비운다.
        assert_eq!(row.get("command").map(String::as_str), Some(""));
        assert_eq!(row.get("host_application").map(String::as_str), Some(HOST_KO));
        assert_eq!(
            row.get("session_id").map(String::as_str),
            Some("ebf6a673-8b57-4c7e-86b2-43b6d1af9773")
        );
        assert_eq!(
            row.get("runspace_id").map(String::as_str),
            Some("3eee4306-36d0-4389-90a1-21d6ca3a7961")
        );
        assert_eq!(
            row.get("account").map(String::as_str),
            Some("WIN-HOST\\Administrator")
        );
        assert_eq!(
            row.get("account_sid").map(String::as_str),
            Some("S-1-5-21-1-2-3-500")
        );
        assert_eq!(
            row.get("script_path").map(String::as_str),
            Some("C:\\scripts\\collect.ps1")
        );
        assert_eq!(row.get("context_info").map(String::as_str), Some(CTX_KO));
        assert_eq!(row.get("event_data").map(String::as_str), Some(data.as_str()));
        assert_eq!(
            row.get("event_channel").map(String::as_str),
            Some("Microsoft-Windows-PowerShell/Operational")
        );
        assert_eq!(row.get("event_record_id").map(String::as_str), Some("17"));
        assert_eq!(row.get("event_level").map(String::as_str), Some("3"));
        assert_eq!(
            row.get("_source_file").map(String::as_str),
            Some("PowerShell.evtx")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn powershell_4103_keeps_full_payload_and_context_boundaries() {
        let root = ps_tmp("ps4103-fulltext");
        let conn = ps_event_facts(&root);
        let host = "powershell.exe -NoProfile -Command Write-Output 'a=b'\n; Write-Output '두 번째 줄'";
        let ctx_en = format!(
            "        Severity = Informational\r\n        Host ID = host-session-1\r\n        \
             Host Application = {host}\r\n        Engine Version = 5.1\r\n        \
             Runspace ID = runspace-1\r\n        Command Name = Get-ChildItem\r\n        \
             User = DOMAIN\\user\r\n"
        );
        let payload = format!(
            "  CommandInvocation(Write-Output): {}\r\n후반 파이프라인  ",
            "x".repeat(450)
        );
        let piped =
            serde_json::json!({"ContextInfo": ctx_en, "Payload": payload}).to_string();
        ps_insert(&conn, "4103", "1", "356", &piped, "PowerShell.evtx");
        // Payload가 공백뿐이면 ContextInfo의 명령 이름으로 되돌아간다.
        let blank = serde_json::json!({"ContextInfo": ctx_en, "Payload": "   "}).to_string();
        ps_insert(&conn, "4103", "2", "356", &blank, "PowerShell.evtx");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 2);
        // 400자 자르기·첫 줄 자르기 없이 원문 그대로여야 한다.
        assert_eq!(rows[0].get("command"), Some(&payload));
        assert_eq!(rows[0].get("host_application").map(String::as_str), Some(host));
        assert_eq!(
            rows[0].get("session_id").map(String::as_str),
            Some("host-session-1")
        );
        assert_eq!(
            rows[0].get("runspace_id").map(String::as_str),
            Some("runspace-1")
        );
        assert_eq!(rows[0].get("account").map(String::as_str), Some("DOMAIN\\user"));
        assert_eq!(rows[0].get("kind").map(String::as_str), Some("파이프라인"));
        assert_eq!(rows[1].get("command").map(String::as_str), Some("Get-ChildItem"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn powershell_classic_800_keeps_multiline_fields_and_session_ids() {
        let root = ps_tmp("ps800-classic");
        let conn = ps_event_facts(&root);
        let host = "powershell.exe -Command $src = @'\nusing System;\npublic class X { int a = 1; }\n'@\n; exit 0";
        let detail = format!(
            "\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=21\r\n\r\n\t\
             UserId=WIN-HOST\\Administrator\r\n\tHostName=ConsoleHost\r\n\t\
             HostId=110087f2-5fdc-4d5a-bf41-1d330efb0bfe\r\n\tHostApplication={host}\r\n\t\
             EngineVersion=5.1\r\n\tRunspaceId=a68da8e0-4f30-43d3-966f-0d2dfa99224c\r\n\t\
             PipelineId=1\r\n\tScriptName=C:\\scripts\\s.ps1\r\n\t\
             CommandLine=Add-Type -TypeDefinition $src\nSecond-Line\r\n"
        );
        // 세 번째 요소(파이프라인 세부)는 필드가 아니다 — 앞 값에 흡수되면 안 된다.
        let tail = "CommandInvocation(Add-Type): \"Add-Type\"\nParameterBinding(Add-Type): name=\"TypeDefinition\"; value=\"using System;\"";
        let data = serde_json::json!({
            "Data": {"#text": ["Add-Type -TypeDefinition $src\n", detail, tail]}
        })
        .to_string();
        ps_insert_classic(&conn, "800", "280", &data);
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("host_application").map(String::as_str), Some(host));
        assert_eq!(
            row.get("command").map(String::as_str),
            Some("Add-Type -TypeDefinition $src\nSecond-Line")
        );
        assert_eq!(
            row.get("account").map(String::as_str),
            Some("WIN-HOST\\Administrator")
        );
        assert_eq!(
            row.get("session_id").map(String::as_str),
            Some("110087f2-5fdc-4d5a-bf41-1d330efb0bfe")
        );
        assert_eq!(
            row.get("runspace_id").map(String::as_str),
            Some("a68da8e0-4f30-43d3-966f-0d2dfa99224c")
        );
        assert_eq!(
            row.get("script_path").map(String::as_str),
            Some("C:\\scripts\\s.ps1")
        );
        assert_eq!(row.get("event_data").map(String::as_str), Some(data.as_str()));
        assert_eq!(row.get("event_level").map(String::as_str), Some("4"));
        let _ = std::fs::remove_dir_all(root);
    }

    fn ps800_with_user(tag: &str, user: &str, registry: &[(&str, &str, &str, &str, &str)]) -> Row {
        let root = ps_tmp(tag);
        let conn = ps_event_facts(&root);
        let detail = format!("\tUserId={user}\r\n\tHostApplication=powershell.exe -c x\r\n\tCommandLine=Get-Date\r\n");
        let data = serde_json::json!({ "Data": {"#text": ["Get-Date", detail, ""]} }).to_string();
        ps_insert_classic(&conn, "800", "281", &data);
        drop(conn);
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        for (hive, key, name, value_type, value) in registry {
            let reg = Connection::open(registry_dir.join(format!("{hive}.sqlite"))).unwrap();
            reg.execute("CREATE TABLE IF NOT EXISTS Registry (key_path TEXT, value_name TEXT, value_type TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT, value_data_hex TEXT)", []).unwrap();
            reg.execute("INSERT INTO Registry (key_path, value_name, value_type, value_data, last_write, _recovery, _source_file) VALUES (?1, ?2, ?3, ?4, '2026-01-01 00:00:00.000', 'live', ?5)", rusqlite::params![key, name, value_type, value, hive]).unwrap();
        }
        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(root);
        rows.into_iter().next().unwrap()
    }

    const COMPUTER: (&str, &str, &str, &str, &str) = ("SYSTEM", "\\ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "REG_SZ", "WIN-HOST");
    const SAM_ADMIN: (&str, &str, &str, &str, &str) = ("SAM", "\\ROOT\\SAM\\Domains\\Account\\Users\\Names\\Administrator", "(default)", "500", "");
    // Account V tail = SID S-1-5-21-1-2-3.
    const SAM_DOMAIN: (&str, &str, &str, &str, &str) = ("SAM", "\\ROOT\\SAM\\Domains\\Account", "V", "REG_BINARY", "00000000010400000000000515000000010000000200000003000000");
    const CORP_PROFILE_500: (&str, &str, &str, &str, &str) = ("SOFTWARE", "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-9-9-9-500", "ProfileImagePath", "REG_EXPAND_SZ", "C:\\Users\\Administrator");

    #[test]
    fn classic_800_this_host_user_resolves_to_the_local_account_and_sid() {
        let row = ps800_with_user("ps800-local", "win-host\\administrator", &[COMPUTER, SAM_ADMIN, SAM_DOMAIN, CORP_PROFILE_500]);
        assert_eq!(row.get("account").map(String::as_str), Some("Administrator"));
        assert_eq!(row.get("account_sid").map(String::as_str), Some("S-1-5-21-1-2-3-500"));
    }

    #[test]
    fn classic_800_other_domain_or_unknown_machine_sid_is_not_guessed() {
        // Different domain: verbatim, no SID.
        let row = ps800_with_user("ps800-domain", "CORP\\Administrator", &[COMPUTER, SAM_ADMIN, SAM_DOMAIN]);
        assert_eq!(row.get("account").map(String::as_str), Some("CORP\\Administrator"));
        assert!(row.get("account_sid").map(String::is_empty).unwrap_or(true));
        // Only a domain profile shares RID 500 and SAM has no machine SID:
        // the local name is confirmed, the SID stays unknown.
        let row = ps800_with_user("ps800-domain-profile", "WIN-HOST\\Administrator", &[COMPUTER, SAM_ADMIN, CORP_PROFILE_500]);
        assert_eq!(row.get("account").map(String::as_str), Some("Administrator"));
        assert!(row.get("account_sid").map(String::is_empty).unwrap_or(true));
        // Not in SAM: verbatim.
        let row = ps800_with_user("ps800-nosam", "WIN-HOST\\ghost", &[COMPUTER, SAM_ADMIN, SAM_DOMAIN]);
        assert_eq!(row.get("account").map(String::as_str), Some("WIN-HOST\\ghost"));
    }

    #[test]
    fn console_history_row_keeps_full_text_and_source_file() {
        let root = ps_tmp("psconsole-fulltext");
        let dir = root.join("POWERSHELL");
        std::fs::create_dir_all(&dir).unwrap();
        let conn = Connection::open(dir.join("PowerShell_ConsoleHistory.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE PowerShell_ConsoleHistory (line_number TEXT, command TEXT, user TEXT, _source_file TEXT)",
            [],
        )
        .unwrap();
        let command = format!("  Write-Output '{}'\n# 후반 검색 토큰  ", "가".repeat(450));
        conn.execute(
            "INSERT INTO PowerShell_ConsoleHistory VALUES ('17', ?1, 'unknown', 'C:\\Users\\a\\ConsoleHost_history.txt')",
            [&command],
        )
        .unwrap();
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("command"), Some(&command));
        assert_eq!(rows[0].get("line_number").map(String::as_str), Some("17"));
        assert_eq!(
            rows[0].get("_source_file").map(String::as_str),
            Some("C:\\Users\\a\\ConsoleHost_history.txt")
        );
        // 파일에 시각이 없다 — 지어내지 않는다. 세션 ID도 없다.
        assert_eq!(rows[0].get("timestamp").map(String::as_str), Some(""));
        assert_eq!(rows[0].get("session_id"), None);
        assert_eq!(rows[0].get("event_data"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn script_block_parts_preserve_every_source_event() {
        let root = ps_tmp("ps4104-provenance");
        let conn = ps_event_facts(&root);
        // 번호 1,3,3,1 — 2번 누락, 3번 내용 충돌, 1번 동일 내용 중복.
        for (id, number, body) in [
            (1, 1, "first"),
            (2, 3, "last"),
            (3, 3, "conflict"),
            (4, 1, "first"),
        ] {
            let data = serde_json::json!({
                "ScriptBlockId": "block-1", "MessageNumber": number, "MessageTotal": 3,
                "ScriptBlockText": body, "Path": "C:\\evidence.ps1"
            })
            .to_string();
            ps_insert(&conn, "4104", &id.to_string(), "356", &data, "PowerShell.evtx");
        }
        let single = serde_json::json!({
            "ScriptBlockId": "block-2", "MessageNumber": 1, "MessageTotal": 1,
            "ScriptBlockText": "solo", "Path": ""
        })
        .to_string();
        ps_insert(&conn, "4104", "5", "356", &single, "PowerShell.evtx");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        let block = ps_row_of(&rows, "block-1");
        // 충돌 조각의 승자는 증명 대상이 아니다 — 확인된 1번 조각이 앞에 오고
        // 충돌한 3번의 양쪽 원본이 모두 남아 있으면 된다.
        let body = block.get("script_block").map(String::as_str).unwrap_or("");
        assert!(body.starts_with("first"), "{body}");
        assert!(body == "firstlast" || body == "firstconflict", "{body}");
        assert_eq!(
            block.get("script_block_expected_parts").map(String::as_str),
            Some("3")
        );
        // 관측 조각 수는 중복 포함 원본 이벤트 수다.
        assert_eq!(
            block.get("script_block_observed_parts").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            ps_json(block, "script_block_missing"),
            serde_json::json!([{"start": 2, "end": 2}])
        );
        assert_eq!(
            ps_json(block, "script_block_conflicts"),
            serde_json::json!([3])
        );
        let status = block
            .get("script_block_status")
            .map(String::as_str)
            .unwrap_or_default();
        assert!(status.contains("불완전"), "{status}");
        let parts = ps_json(block, "script_block_parts");
        let parts = parts.as_array().unwrap();
        assert_eq!(parts.len(), 4);
        let shape: Vec<(&str, &str, &str)> = parts
            .iter()
            .map(|p| {
                (
                    p["message_number"].as_str().unwrap(),
                    p["script_block"].as_str().unwrap(),
                    p["record_key"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                ("1", "first", "PowerShell::1"),
                ("3", "last", "PowerShell::2"),
                ("3", "conflict", "PowerShell::3"),
                ("1", "first", "PowerShell::4"),
            ]
        );
        assert_eq!(parts[0]["message_total"], "3");
        assert_eq!(parts[0]["event_record_id"], "1");
        assert_eq!(parts[0]["_source_file"], "PowerShell.evtx");
        assert_eq!(parts[0]["timestamp"], "2026-10-08 01:02:03.004");
        assert!(parts[0]["event_data"].as_str().unwrap().contains("block-1"));
        assert_eq!(
            block.get("script_path").map(String::as_str),
            Some("C:\\evidence.ps1")
        );
        // 단일 4104도 조각 1건의 출처를 그대로 가진다.
        let solo = ps_row_of(&rows, "block-2");
        assert_eq!(solo.get("script_block_status"), None);
        assert_eq!(ps_json(solo, "script_block_parts").as_array().unwrap().len(), 1);
        assert_eq!(
            solo.get("script_block_observed_parts").map(String::as_str),
            Some("1")
        );
        assert_eq!(solo.get("script_block_missing"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn script_block_groups_require_matching_identity() {
        let root = ps_tmp("ps4104-identity");
        let conn = ps_event_facts(&root);
        let data = |sbid: &str, body: &str| {
            serde_json::json!({
                "ScriptBlockId": sbid, "MessageNumber": 1, "MessageTotal": 2,
                "ScriptBlockText": body, "Path": ""
            })
            .to_string()
        };
        // 같은 ScriptBlockId라도 프로세스·원본 파일이 다르면 다른 실행이다.
        ps_insert(&conn, "4104", "1", "100", &data("same", "A1"), "PowerShell.evtx");
        ps_insert(&conn, "4104", "2", "200", &data("same", "B1"), "PowerShell.evtx");
        ps_insert(&conn, "4104", "3", "100", &data("same", "C1"), "Other.evtx");
        // ScriptBlockId가 없으면 묶을 근거가 없다 — 각 이벤트가 그대로 한 행.
        let anon = serde_json::json!({
            "MessageNumber": 1, "MessageTotal": 2, "ScriptBlockText": "anon", "Path": ""
        })
        .to_string();
        ps_insert(&conn, "4104", "4", "100", &anon, "PowerShell.evtx");
        ps_insert(&conn, "4104", "5", "100", &anon, "PowerShell.evtx");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 5);
        let bodies: Vec<&str> = rows
            .iter()
            .map(|r| r.get("script_block").map(String::as_str).unwrap_or(""))
            .collect();
        assert_eq!(bodies, vec!["A1", "B1", "C1", "anon", "anon"]);
        for row in &rows {
            assert_eq!(ps_json(row, "script_block_parts").as_array().unwrap().len(), 1);
        }
        assert_eq!(rows[3].get("script_block_id"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn script_block_unknown_ordinal_and_huge_total_stay_unknown() {
        let root = ps_tmp("ps4104-unknown");
        let conn = ps_event_facts(&root);
        let unknown = serde_json::json!({
            "ScriptBlockId": "huge", "MessageNumber": "", "MessageTotal": 4_000_000_000i64,
            "ScriptBlockText": "U", "Path": ""
        })
        .to_string();
        let second = serde_json::json!({
            "ScriptBlockId": "huge", "MessageNumber": 2, "MessageTotal": 4_000_000_000i64,
            "ScriptBlockText": "S", "Path": ""
        })
        .to_string();
        ps_insert(&conn, "4104", "1", "356", &unknown, "PowerShell.evtx");
        ps_insert(&conn, "4104", "2", "356", &second, "PowerShell.evtx");
        drop(conn);

        let rows = build_powershell_history_with_events(&root, &EventLogOverviewCache::load(&root).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            row.get("script_block_expected_parts").map(String::as_str),
            Some("4000000000")
        );
        assert_eq!(
            row.get("script_block_observed_parts").map(String::as_str),
            Some("2")
        );
        // 번호를 알 수 없는 조각은 자리를 추측하지 않고 본문 끝에 남긴다.
        assert_eq!(row.get("script_block").map(String::as_str), Some("SU"));
        // 누락 구간은 범위로만 표현한다 — 40억 번 순회하지 않는다.
        assert_eq!(
            ps_json(row, "script_block_missing"),
            serde_json::json!([{"start": 1, "end": 1}, {"start": 3, "end": 4_000_000_000i64}])
        );
        let parts = ps_json(row, "script_block_parts");
        assert_eq!(parts[0].get("message_number"), None);
        assert_eq!(parts[0]["message_total"], "4000000000");
        let anomalies = ps_json(row, "script_block_anomalies");
        assert!(
            anomalies
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str().unwrap_or("").contains("조각 번호 불명")),
            "{anomalies}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn taskcache_reports_tree_entry_without_tasks_key() {
        let root = std::env::temp_dir().join(format!(
            "wina-taskcache-tree-only-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SOFTWARE.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        const TREE: &str = "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";
        const TASKS: &str = "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks";
        // EvilTask: Tree에 Id·SD가 남았지만 Tasks 키가 삭제됨(작업 삭제 잔존).
        // GoodTask: Tree/Tasks 1:1 정상 쌍 — 오탐 없이 일반 행으로만 나와야 한다.
        for row in [
            (format!("{TREE}\\EvilTask"), "Id", "{DEAD-1111}".to_string()),
            (format!("{TREE}\\EvilTask"), "SD", "01000480".to_string()),
            (format!("{TREE}\\GoodTask"), "Id", "{GOOD-2222}".to_string()),
            (format!("{TREE}\\GoodTask"), "SD", "01000480".to_string()),
            (format!("{TASKS}\\{{good-2222}}"), "Path", "\\GoodTask".to_string()),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SOFTWARE')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let task_rows: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("TaskCache"))
            .collect();
        let missing: Vec<_> = task_rows
            .iter()
            .filter(|row| {
                row.get("value")
                    .map(|value| value.starts_with("Tasks 항목 없음"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(missing.len(), 1, "Tree-only 잔존은 정확히 한 행이어야 한다");
        assert_eq!(missing[0].get("name").map(String::as_str), Some("\\EvilTask"));
        assert_eq!(
            missing[0].get("record_key").map(String::as_str),
            Some("SOFTWARE::Registry::1")
        );
        // SD가 존재하므로 SD-삭제 행은 나오지 않아야 한다.
        assert!(task_rows.iter().all(|row| {
            !row.get("value")
                .map(|value| value.starts_with("SD 값 없음"))
                .unwrap_or(false)
        }));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn uninstall_keeps_distinct_same_name_installs() {
        let root = std::env::temp_dir().join(format!(
            "wina-uninstall-dedup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        // SOFTWARE: 같은 설치(Tool X 1.0)가 MSI InstallProperties(packed
        // ProductCode)와 Uninstall({GUID}) 양쪽에 등록된 상태 + 이름·버전이
        // 같지만 키가 다른 위장 항목. NTUSER: 동명 다른 버전 사용자 설치.
        // GUID {12345678-1234-1234-1234-123456789ABC}의 packed(Darwin) 형식.
        const PACKED: &str = "8765432143214321214321436587A9CB";
        let msi_kp = format!("\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\{PACKED}\\InstallProperties");
        for (name, rows) in [
            (
                "SOFTWARE",
                vec![
                    (msi_kp.clone(), "DisplayName", "Tool X"),
                    (msi_kp.clone(), "DisplayVersion", "1.0"),
                    ("\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{12345678-1234-1234-1234-123456789ABC}".to_string(), "DisplayName", "Tool X"),
                    ("\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{12345678-1234-1234-1234-123456789ABC}".to_string(), "DisplayVersion", "1.0"),
                    ("\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FakeToolX".to_string(), "DisplayName", "Tool X"),
                    ("\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FakeToolX".to_string(), "DisplayVersion", "1.0"),
                ],
            ),
            (
                "analyst_NTUSER.DAT",
                vec![
                    ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ToolX".to_string(), "DisplayName", "Tool X"),
                    ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ToolX".to_string(), "DisplayVersion", "2.0"),
                ],
            ),
        ] {
            let conn = Connection::open(registry_dir.join(format!("{name}.sqlite"))).unwrap();
            conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
            for row in rows {
                conn.execute(
                    "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', ?4)",
                    rusqlite::params![row.0, row.1, row.2, format!("evidence/{name}")],
                )
                .unwrap();
            }
        }

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        // MSI 설치 자체는 rf_msi_installs가 한 번 표시한다.
        let msi: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("MsiInstall"))
            .collect();
        assert_eq!(msi.len(), 1);
        // Uninstall에는 ProductCode가 일치하는 진짜 쌍둥이({GUID} 키)만 접히고,
        // 이름·버전이 같아도 키가 다른 위장 항목(FakeToolX)과 동명 사용자
        // 설치(NTUSER 2.0)는 각자의 record_key와 함께 남는다.
        let uninstall: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("Uninstall"))
            .collect();
        assert_eq!(uninstall.len(), 2);
        let fake = uninstall
            .iter()
            .find(|row| {
                row.get("key_path")
                    .map(|kp| kp.ends_with("\\FakeToolX"))
                    .unwrap_or(false)
            })
            .expect("fake uninstall entry preserved");
        assert_eq!(fake.get("source").map(String::as_str), Some("SOFTWARE"));
        let user_install = uninstall
            .iter()
            .find(|row| row.get("source").map(String::as_str) == Some("analyst_NTUSER.DAT"))
            .expect("per-user install preserved");
        assert_eq!(user_install.get("value").map(String::as_str), Some("2.0"));
        assert_eq!(
            user_install.get("record_key").map(String::as_str),
            Some("analyst_NTUSER.DAT::Registry::1")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn value_name_matching_ignores_case() {
        let root = std::env::temp_dir().join(format!(
            "wina-value-case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        // 레지스트리 값 이름은 대소문자 무시 — 소문자로 만든 값도 Windows에는
        // 표준 이름과 동일하게 적용되므로 탐지도 잡아야 한다.
        for (hive, kp, name, data) in [
            (
                "SOFTWARE",
                "\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "disablerealtimemonitoring",
                "1",
            ),
            ("SYSTEM", "\\ControlSet001\\Control\\Lsa", "nolmhash", "0"),
        ] {
            let db = registry_dir.join(format!("{hive}.sqlite"));
            let conn = Connection::open(&db).unwrap();
            conn.execute("CREATE TABLE IF NOT EXISTS Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence')",
                rusqlite::params![kp, name, data],
            )
            .unwrap();
        }

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        assert!(
            findings.iter().any(|row| {
                row.get("subtype").map(String::as_str) == Some("Defender")
                    && row.get("value").map(String::as_str) == Some("1 (비활성)")
            }),
            "소문자 Defender 비활성 플래그를 탐지해야 한다"
        );
        assert!(
            findings.iter().any(|row| {
                row.get("name").map(String::as_str) == Some("NoLmHash")
            }),
            "소문자 nolmhash=0을 탐지해야 한다"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reg_picks_follow_active_control_set() {
        let root = std::env::temp_dir().join(format!(
            "wina-active-set-pick-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SYSTEM.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        // 활성 세트는 002 — 001에는 낡은 값이 남아 있다. BootExecute·Lsa 모두
        // 002의 값으로 판정되어야 한다 (001 고정이면 stale.exe와 NoLmHash=1을
        // 골라 판정이 뒤집힌다).
        for row in [
            ("\\Select", "Current", "2"),
            (
                "\\ControlSet001\\Control\\Session Manager",
                "BootExecute",
                r#"["autocheck autochk *","stale.exe"]"#,
            ),
            (
                "\\ControlSet002\\Control\\Session Manager",
                "BootExecute",
                r#"["autocheck autochk *","active.exe"]"#,
            ),
            ("\\ControlSet001\\Control\\Lsa", "NoLmHash", "1"),
            ("\\ControlSet002\\Control\\Lsa", "NoLmHash", "0"),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SYSTEM')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let boot = findings
            .iter()
            .find(|row| row.get("name").map(String::as_str) == Some("BootExecute (비기본)"))
            .expect("BootExecute finding");
        assert_eq!(boot.get("value").map(String::as_str), Some("active.exe"));
        assert!(
            findings
                .iter()
                .any(|row| row.get("name").map(String::as_str) == Some("NoLmHash")),
            "활성 세트(002)의 NoLmHash=0으로 판정해야 한다"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn taskcache_reads_properties_case_insensitively() {
        let root = std::env::temp_dir().join(format!(
            "wina-taskcache-case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SOFTWARE.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        let mut actions: Vec<u8> = vec![1, 0];
        actions.extend(task_str("Author"));
        actions.extend([0x66, 0x66]);
        actions.extend(task_str("{id}"));
        actions.extend(task_str("evil.exe"));
        actions.extend(task_str(""));
        actions.extend(task_str(""));
        const FT: u64 = 133_500_000_000_000_000;
        let mut dynamic = vec![0u8; 12];
        dynamic.extend(FT.to_le_bytes());
        let kp = "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{evil-1}";
        // 값 이름을 전부 소문자로 저장 — Windows에는 표준 casing과 동일하게
        // 적용되므로 경로·명령·마지막 실행 시각이 그대로 나와야 한다.
        for (name, data) in [
            ("path", "\\EvilTask".to_string()),
            ("actions", to_hex(&actions)),
            ("dynamicinfo", to_hex(&dynamic)),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SOFTWARE')",
                rusqlite::params![kp, name, data],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let task = findings
            .iter()
            .find(|row| row.get("subtype").map(String::as_str) == Some("TaskCache"))
            .expect("TaskCache finding");
        assert_eq!(task.get("name").map(String::as_str), Some("\\EvilTask"));
        assert_eq!(task.get("command").map(String::as_str), Some("evil.exe"));
        assert_eq!(task.get("timestamp").cloned(), Some(filetime(FT)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn msi_display_and_pair_suppression_agree_on_case() {
        let root = std::env::temp_dir().join(format!(
            "wina-msi-case-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SOFTWARE.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        // InstallProperties의 값 이름이 소문자(displayname)여도 MSI 행은
        // 만들어지고, ProductCode가 일치하는 Uninstall 쌍둥이만 억제되어야
        // 한다 — 표시와 쌍 판정의 casing 처리가 어긋나면 두 행이 모두 사라진다.
        const PACKED: &str = "8765432143214321214321436587A9CB";
        let msi_kp = format!("\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\{PACKED}\\InstallProperties");
        let un_kp = "\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{12345678-1234-1234-1234-123456789ABC}";
        for (kp, name, data) in [
            (msi_kp.as_str(), "displayname", "Tool Y"),
            (msi_kp.as_str(), "displayversion", "3.0"),
            (un_kp, "DisplayName", "Tool Y"),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SOFTWARE')",
                rusqlite::params![kp, name, data],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let msi: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("MsiInstall"))
            .collect();
        assert_eq!(msi.len(), 1, "소문자 displayname으로도 MSI 행이 생겨야 한다");
        assert_eq!(msi[0].get("name").map(String::as_str), Some("Tool Y"));
        assert_eq!(msi[0].get("value").map(String::as_str), Some("3.0"));
        assert!(
            !findings
                .iter()
                .any(|row| row.get("subtype").map(String::as_str) == Some("Uninstall")),
            "ProductCode가 일치하는 Uninstall 쌍둥이는 억제되어야 한다"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Win10 "10ts" AppCompatCache 블롭 한 항목: 헤더(u32 오프셋) + 시그니처 +
    /// ce_size + [u16 경로길이][UTF-16LE 경로][FILETIME].
    fn shim_blob(path: &str, ft: u64) -> Vec<u8> {
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ce_size = 2 + path_utf16.len() + 8;
        let mut b = 4u32.to_le_bytes().to_vec();
        b.extend(b"10ts");
        b.extend([0, 0, 0, 0]);
        b.extend((ce_size as u32).to_le_bytes());
        b.extend((path_utf16.len() as u16).to_le_bytes());
        b.extend(path_utf16);
        b.extend(ft.to_le_bytes());
        b
    }

    #[test]
    fn shares_and_appcert_follow_active_control_set() {
        let root = std::env::temp_dir().join(format!(
            "wina-shares-active-set-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SYSTEM.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        // 활성 세트는 002 — 001의 과거 공유·AppCertDLLs 등록은 현재 구성이
        // 아니므로 표시되면 안 되고, 같은 공유 이름은 002의 경로를 골라야 한다.
        for row in [
            ("\\Select", "Current", "2"),
            ("\\ControlSet001\\Services\\LanmanServer\\Shares", "OldShare", "Path=C:\\Old"),
            ("\\ControlSet001\\Services\\LanmanServer\\Shares", "Common", "Path=C:\\OldCommon"),
            ("\\ControlSet002\\Services\\LanmanServer\\Shares", "Data", "Path=C:\\Data"),
            ("\\ControlSet002\\Services\\LanmanServer\\Shares", "Common", "Path=C:\\NewCommon"),
            ("\\ControlSet001\\Control\\Session Manager\\AppCertDlls", "Legacy", "old.dll"),
            ("\\ControlSet002\\Control\\Session Manager\\AppCertDlls", "Inject", "evil.dll"),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SYSTEM')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let shares: Vec<_> = findings
            .iter()
            .filter(|row| {
                row.get("category").map(String::as_str) == Some("공유 폴더")
                    && row.get("status").map(String::as_str) == Some("주의")
            })
            .collect();
        let share_values: Vec<(&str, &str)> = shares
            .iter()
            .map(|row| {
                (
                    row.get("name").map(String::as_str).unwrap_or(""),
                    row.get("value").map(String::as_str).unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(shares.len(), 2, "활성 세트(002)의 공유만 나와야 한다: {share_values:?}");
        assert!(share_values.contains(&("Data", "C:\\Data")));
        assert!(share_values.contains(&("Common", "C:\\NewCommon")));
        let appcert: Vec<_> = findings
            .iter()
            .filter(|row| {
                row.get("name")
                    .map(|name| name.starts_with("AppCertDLLs"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(appcert.len(), 1);
        assert_eq!(
            appcert[0].get("value").map(String::as_str),
            Some("evil.dll")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shimcache_follows_active_control_set() {
        let root = std::env::temp_dir().join(format!(
            "wina-shim-active-set-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SYSTEM.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        const FT_OLD: u64 = 133_000_000_000_000_000;
        const FT_NEW: u64 = 133_500_000_000_000_000;
        // 같은 경로가 두 세트에 다른 FILETIME으로 존재 — 화면의 실행 시각은
        // 행 순서가 아니라 활성 세트(002)의 것이어야 한다.
        for row in [
            ("\\Select", "Current", "2".to_string()),
            (
                "\\ControlSet001\\Control\\Session Manager\\AppCompatCache",
                "AppCompatCache",
                to_hex(&shim_blob("C:\\tools\\evil.exe", FT_OLD)),
            ),
            (
                "\\ControlSet002\\Control\\Session Manager\\AppCompatCache",
                "AppCompatCache",
                to_hex(&shim_blob("C:\\tools\\evil.exe", FT_NEW)),
            ),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SYSTEM')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let shim: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("ShimCache"))
            .collect();
        assert_eq!(shim.len(), 1);
        assert_eq!(
            shim[0].get("value").map(String::as_str),
            Some("C:\\tools\\evil.exe")
        );
        assert_eq!(shim[0].get("timestamp").cloned(), Some(filetime(FT_NEW)));
        let _ = std::fs::remove_dir_all(root);
    }

    /// T0: 미지원 구포맷 AppCompatCache(XP 0xDEADBEEF 등)는 조용히 0행으로
    /// 끝나지 않고 "미지원 포맷" 정보 행으로 표면화돼야 한다 — 지원 포맷의 빈
    /// 데이터와 구분되게.
    #[test]
    fn shimcache_unsupported_legacy_format_is_reported() {
        // 파서 단위: XP 매직 + 임의 본문 → 엔트리 0, 미지원 사유에 매직 표기.
        let mut legacy = 0xDEAD_BEEFu32.to_le_bytes().to_vec();
        legacy.extend([0u8; 60]);
        let parsed = parse_shimcache(&legacy);
        assert!(parsed.entries.is_empty());
        let reason = parsed.unsupported.expect("구포맷은 unsupported여야 한다");
        assert!(reason.contains("0xDEADBEEF"), "{reason}");
        assert!(reason.contains("Windows XP"), "{reason}");
        // 빈 데이터는 포맷 문제가 아니므로 표면화하지 않는다.
        assert!(parse_shimcache(&[]).unsupported.is_none());

        // 파생 행: RegistryFindings에 status=정보 행이 하나 나온다.
        let root = std::env::temp_dir().join(format!(
            "wina-shim-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        let conn = Connection::open(registry_dir.join("SYSTEM.sqlite")).unwrap();
        conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
        for row in [
            ("\\Select", "Current", "1".to_string()),
            (
                "\\ControlSet001\\Control\\Session Manager\\AppCompatCache",
                "AppCompatCache",
                to_hex(&legacy),
            ),
        ] {
            conn.execute(
                "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', 'evidence/SYSTEM')",
                rusqlite::params![row.0, row.1, row.2],
            )
            .unwrap();
        }
        drop(conn);

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        let shim: Vec<_> = findings
            .iter()
            .filter(|row| row.get("subtype").map(String::as_str) == Some("ShimCache"))
            .collect();
        assert_eq!(shim.len(), 1, "미지원 안내 행 하나만 나와야 한다");
        assert_eq!(shim[0].get("status").map(String::as_str), Some("정보"));
        let value = shim[0].get("value").cloned().unwrap_or_default();
        assert!(value.starts_with("미지원 포맷"), "{value}");
        assert!(value.contains("0xDEADBEEF"), "{value}");
        let _ = std::fs::remove_dir_all(root);
    }

    /// T1: Win7/2008R2(0xBADC0FEE) x86/x64 고정 엔트리 배열 해석.
    fn shim_blob_win7(paths: &[(&str, u64)], is64: bool) -> Vec<u8> {
        let esize = if is64 { 48 } else { 32 };
        let hdr = 0x80usize;
        let mut b = vec![0u8; hdr + paths.len() * esize];
        b[0..4].copy_from_slice(&0xBADC_0FEEu32.to_le_bytes());
        b[4..8].copy_from_slice(&(paths.len() as u32).to_le_bytes());
        let mut strings: Vec<u8> = Vec::new();
        for (i, (p, ft)) in paths.iter().enumerate() {
            let utf16: Vec<u8> = p.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let off = hdr + paths.len() * esize + strings.len();
            let o = hdr + i * esize;
            b[o..o + 2].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
            b[o + 2..o + 4].copy_from_slice(&((utf16.len() + 2) as u16).to_le_bytes());
            if is64 {
                // o+4..8은 정렬 패딩(0) — x64 판별 근거.
                b[o + 8..o + 16].copy_from_slice(&(off as u64).to_le_bytes());
                b[o + 16..o + 24].copy_from_slice(&ft.to_le_bytes());
            } else {
                b[o + 4..o + 8].copy_from_slice(&(off as u32).to_le_bytes());
                b[o + 8..o + 16].copy_from_slice(&ft.to_le_bytes());
            }
            strings.extend(utf16);
        }
        b.extend(strings);
        b
    }

    /// Win8.x 'NNts' 블롭: 헤더 u32=0x80, 엔트리 데이터는 경로 뒤에
    /// InsertFlags(4)+ShimFlags(4)가 오고 그 다음이 FILETIME.
    fn shim_blob_win8(tag: &[u8; 4], path: &str, ft: u64) -> Vec<u8> {
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ce_size = 2 + path_utf16.len() + 4 + 4 + 8;
        let mut b = 0x80u32.to_le_bytes().to_vec();
        b.resize(0x80, 0);
        b.extend(tag);
        b.extend([0, 0, 0, 0]);
        b.extend((ce_size as u32).to_le_bytes());
        b.extend((path_utf16.len() as u16).to_le_bytes());
        b.extend(path_utf16);
        b.extend(2u32.to_le_bytes()); // InsertFlags
        b.extend(0u32.to_le_bytes()); // ShimFlags
        b.extend(ft.to_le_bytes());
        b
    }

    #[test]
    fn shimcache_parses_win7_x64_and_x86() {
        const FT: u64 = 129_600_000_000_000_000;
        for is64 in [true, false] {
            let blob = shim_blob_win7(
                &[("\\??\\C:\\tools\\a.exe", FT), ("\\??\\C:\\tools\\b.exe", FT + 1)],
                is64,
            );
            let parsed = parse_shimcache(&blob);
            assert!(parsed.unsupported.is_none(), "is64={is64}");
            let note = parsed.format_note.expect("구포맷 표기 필요");
            assert!(note.contains(if is64 { "x64" } else { "x86" }), "{note}");
            assert_eq!(
                parsed.entries,
                vec![
                    ("\\??\\C:\\tools\\a.exe".to_string(), FT),
                    ("\\??\\C:\\tools\\b.exe".to_string(), FT + 1),
                ],
                "is64={is64}"
            );
        }
    }

    #[test]
    fn ti_accounts_takes_machine_sid_from_sam_not_profile_list() {
        let reg = |kp: &str, name: &str, data: &str| -> Row {
            [("key_path", kp), ("value_name", name), ("value_data", data)]
                .into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let pl = "\\ROOT\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\";
        // Domain profile listed first must not define the local prefix.
        let software = vec![
            reg(&format!("{pl}S-1-5-21-7-8-9-1105"), "ProfileImagePath", "C:\\Users\\corp"),
            reg(&format!("{pl}S-1-5-21-11-22-33-1001"), "ProfileImagePath", "C:\\Users\\analyst"),
        ];
        let mut tail = vec![1u8, 4, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 11, 22, 33] {
            tail.extend(sub.to_le_bytes());
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let user = reg("\\ROOT\\SAM\\Domains\\Account\\Users\\000003E9", "F", "");
        let account = reg("\\ROOT\\SAM\\Domains\\Account", "V", &hex(&tail));
        let sid_of = |rows: Vec<Row>| rows.iter()
            .find(|r| r.get("source_artifact").map(String::as_str) == Some("SAM"))
            .and_then(|r| r.get("name").cloned());
        assert_eq!(
            sid_of(ti_accounts(&[account, user.clone()], &software)).as_deref(),
            Some("S-1-5-21-11-22-33-1001")
        );
        // Without SAM machine SID evidence the SID stays empty.
        assert_eq!(sid_of(ti_accounts(&[user], &software)).as_deref(), Some(""));
    }

    #[test]
    fn shimcache_win7_x64_rejects_wrapping_path_offset() {
        let mut blob = shim_blob_win7(&[("\\??\\C:\\tools\\a.exe", 1)], true);
        blob[0x80 + 8..0x80 + 16].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        let parsed = parse_shimcache(&blob);
        assert!(parsed.entries.is_empty());
        assert!(parsed.unsupported.is_some());
    }

    #[test]
    fn shimcache_parses_win8_tags_with_flag_gap() {
        const FT: u64 = 130_100_000_000_000_000;
        // 8.0('00ts')과 8.1('10ts') 모두 FILETIME이 플래그 8바이트 뒤에 있다 —
        // 8.1을 Win10 레이아웃으로 읽으면 플래그가 시각으로 오독되는 회귀 방지.
        for (tag, ver) in [(b"00ts", "8.0"), (b"10ts", "8.1")] {
            let blob = shim_blob_win8(tag, "C:\\apps\\run.exe", FT);
            let parsed = parse_shimcache(&blob);
            assert!(parsed.unsupported.is_none(), "{ver}");
            assert_eq!(
                parsed.entries,
                vec![("C:\\apps\\run.exe".to_string(), FT)],
                "{ver}"
            );
            let note = parsed.format_note.expect("구포맷 표기 필요");
            assert!(note.contains(ver), "{note}");
        }
    }

    #[test]
    fn target_info_network_follows_active_set_and_ignores_value_case() {
        let root = std::env::temp_dir().join(format!(
            "wina-ti-network-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        // SYSTEM: 활성 세트는 002. 001에는 낡은 IP·DNS가 남아 있고, 002의 값
        // 이름은 소문자다 — 출력은 002 구성만으로 만들어져야 하며(현재 IP +
        // 과거 DNS 합성 금지), 소문자 값 이름도 같은 속성으로 해석돼야 한다.
        const IFACE_001: &str =
            "\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{IF-1}";
        const IFACE_002: &str =
            "\\ControlSet002\\Services\\Tcpip\\Parameters\\Interfaces\\{IF-1}";
        for (hive, rows) in [
            (
                "SYSTEM",
                vec![
                    ("\\Select", "Current", "2"),
                    (IFACE_001, "IPAddress", "192.168.0.9"),
                    (IFACE_001, "NameServer", "9.9.9.9"),
                    (IFACE_002, "ipaddress", "10.0.0.5"),
                    (IFACE_002, "nameserver", "8.8.8.8"),
                ],
            ),
            (
                "SOFTWARE",
                vec![(
                    "\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{P-1}",
                    "profilename",
                    "CorpWiFi",
                )],
            ),
        ] {
            let conn = Connection::open(registry_dir.join(format!("{hive}.sqlite"))).unwrap();
            conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
            for row in rows {
                conn.execute(
                    "INSERT INTO Registry VALUES (?1, ?2, ?3, '2026-01-01 00:00:00.000', 'live', ?4)",
                    rusqlite::params![row.0, row.1, row.2, format!("evidence/{hive}")],
                )
                .unwrap();
            }
        }

        let registry = RegistryOverviewCache::load(&root).unwrap();
        let rows = build_target_info_with_registry(&registry);
        let iface = rows
            .iter()
            .find(|row| row.get("category").map(String::as_str) == Some("NetworkInterface"))
            .expect("network interface row");
        assert_eq!(iface.get("value").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(iface.get("dns_server").map(String::as_str), Some("8.8.8.8"));
        assert!(
            rows.iter().any(|row| {
                row.get("category").map(String::as_str) == Some("Network")
                    && row.get("value").map(String::as_str) == Some("CorpWiFi")
            }),
            "소문자 profilename도 네트워크 프로필로 나와야 한다"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn msi_packed_product_code_applies_darwin_transform() {
        assert_eq!(
            msi_packed_product_code("{12345678-1234-1234-1234-123456789ABC}").as_deref(),
            Some("8765432143214321214321436587a9cb")
        );
        assert_eq!(msi_packed_product_code("FakeToolX"), None);
        assert_eq!(msi_packed_product_code("{1234-5678}"), None);
    }

    #[test]
    fn registry_findings_reuses_single_hive_load_without_changing_rows() {
        let root = std::env::temp_dir().join(format!(
            "wina-registry-findings-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        let registry_dir = root.join("REGISTRY");
        std::fs::create_dir_all(&registry_dir).unwrap();
        for (name, rows) in [
            (
                "SYSTEM",
                vec![
                    (
                        "\\Control\\Session Manager\\AppCompatCache",
                        "AppCompatCache",
                        "",
                        "2026-01-01 00:00:00.000",
                    ),
                    // rf_lsa_packages가 행을 내놓아야 빌더의 이중 호출(중복
                    // 생성) 회귀가 아래 유일성 검사에 걸린다.
                    (
                        "\\ControlSet001\\Control\\Lsa",
                        "NoLmHash",
                        "0",
                        "2026-01-01 00:00:00.000",
                    ),
                ],
            ),
            (
                "SOFTWARE",
                vec![(
                    "\\Microsoft\\MSSQLServer\\MSSQLServer",
                    "LoginMode",
                    "2",
                    "2026-01-02 00:00:00.000",
                )],
            ),
            (
                "analyst_NTUSER.DAT",
                vec![(
                    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
                    "a",
                    "cmd.exe\\1",
                    "2026-01-03 00:00:00.000",
                )],
            ),
        ] {
            let db = registry_dir.join(format!("{name}.sqlite"));
            let conn = Connection::open(db).unwrap();
            conn.execute("CREATE TABLE Registry (key_path TEXT, value_name TEXT, value_data TEXT, last_write TEXT, _recovery TEXT, _source_file TEXT)", []).unwrap();
            for row in rows {
                conn.execute(
                    "INSERT INTO Registry VALUES (?1, ?2, ?3, ?4, 'live', ?5)",
                    rusqlite::params![row.0, row.1, row.2, row.3, format!("evidence/{name}")],
                )
                .unwrap();
            }
        }
        // Baseline the former direct table-reader behavior, then compare it
        // with the one-load cache used by the overview pipeline.
        let mut databases = std::fs::read_dir(&registry_dir)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "sqlite")
            })
            .collect::<Vec<_>>();
        databases.sort();
        let legacy_hives = databases
            .into_iter()
            .map(|database| RegistryOverviewHive::load(database).unwrap())
            .collect::<Vec<_>>();
        let legacy_system = legacy_hives
            .iter()
            .find(|hive| hive.name.eq_ignore_ascii_case("SYSTEM"))
            .map(|hive| hive.rows.as_slice())
            .unwrap_or(&[]);
        let legacy_software = legacy_hives
            .iter()
            .find(|hive| hive.name.eq_ignore_ascii_case("SOFTWARE"))
            .map(|hive| hive.rows.as_slice())
            .unwrap_or(&[]);
        let mut legacy = Vec::new();
        legacy.extend(rf_credential_protection(legacy_system));
        legacy.extend(rf_shares(legacy_system));
        legacy.extend(rf_sql_auth(legacy_software));
        legacy.extend(rf_autoruns(&legacy_hives));
        legacy.extend(rf_winlogon(legacy_software));
        legacy.extend(rf_silent_process_exit(legacy_software));
        legacy.extend(rf_taskcache(legacy_software));
        legacy.extend(rf_active_setup(legacy_software));
        legacy.extend(rf_appinit(legacy_software, legacy_system));
        legacy.extend(rf_session_manager(legacy_system));
        legacy.extend(rf_security_config(legacy_software));
        legacy.extend(rf_remote_tools(&legacy_hives));
        legacy.extend(rf_msi_installs(&legacy_hives));
        legacy.extend(rf_uninstall_installs(&legacy_hives));
        legacy.extend(rf_execution_traces(&legacy_hives));
        legacy.extend(rf_shimcache(&legacy_hives));
        // Broader Explorer discovery must not expand legacy analysis inputs.
        let extra = Connection::open(registry_dir.join("Amcache.hve.sqlite")).unwrap();
        extra.execute_batch(
            "CREATE TABLE Registry(key_path TEXT,value_name TEXT,value_data TEXT,last_write TEXT,_recovery TEXT,_source_file TEXT);
             INSERT INTO Registry VALUES ('\\ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
               'a','unrelated.exe','2026-01-03 00:00:00.000','live','evidence/Amcache.hve');",
        ).unwrap();
        drop(extra);
        let registry = RegistryOverviewCache::load(&root).unwrap();
        let findings = build_registry_findings_with_registry(&registry);
        assert_eq!(findings, legacy);
        // Lsa 확장(rf_lsa_packages)이 rf_credential_protection 내부와 빌더
        // 양쪽에서 호출되면 같은 행이 두 번 생긴다 — 동일 식별 4요소는 한
        // 번만 나와야 한다.
        let mut seen = std::collections::HashSet::new();
        for row in &findings {
            let identity = (
                row.get("category").cloned().unwrap_or_default(),
                row.get("name").cloned().unwrap_or_default(),
                row.get("value").cloned().unwrap_or_default(),
                row.get("key_path").cloned().unwrap_or_default(),
            );
            assert!(
                seen.insert(identity.clone()),
                "duplicate finding emitted twice: {identity:?}"
            );
        }
        // 원본 레지스트리 행에서 나온 판정은 3-요소 record_key를 보존해
        // 개요 북마크가 원본 Registry 레코드로 승격될 수 있어야 한다.
        let nolm = findings
            .iter()
            .find(|row| row.get("name").map(String::as_str) == Some("NoLmHash"))
            .expect("NoLmHash finding");
        assert_eq!(
            nolm.get("record_key").map(String::as_str),
            Some("SYSTEM::Registry::2")
        );
        let run_mru = findings
            .iter()
            .find(|row| row.get("subtype").map(String::as_str) == Some("RunMRU"))
            .expect("RunMRU finding");
        assert_eq!(
            run_mru.get("record_key").map(String::as_str),
            Some("analyst_NTUSER.DAT::Registry::1")
        );
        let mut raw_identity = registry
            .hives()
            .iter()
            .flat_map(|hive| hive.rows.iter())
            .map(|row| {
                (
                    row.get("_recovery").cloned().unwrap_or_default(),
                    row.get("_source_file").cloned().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        raw_identity.sort();
        assert_eq!(
            raw_identity,
            vec![
                ("live".to_string(), "evidence/SOFTWARE".to_string()),
                ("live".to_string(), "evidence/SYSTEM".to_string()),
                ("live".to_string(), "evidence/SYSTEM".to_string()),
                (
                    "live".to_string(),
                    "evidence/analyst_NTUSER.DAT".to_string()
                ),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
