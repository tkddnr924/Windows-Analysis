//! _OVERVIEW correlation builders (port of processing.py + correlate.py). They
//! read the per-artifact SQLite the parse stage wrote (under CATEGORY/) and
//! produce the derived overview tables. Reading from disk (not an in-memory
//! all_results) keeps memory bounded for large hosts.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use crate::sqlite::Row;

/// Read an entire table as Vec<Row> (TEXT cells; NULL -> absent key). Returns
/// empty if the DB/table is missing.
pub fn read_table(db: &Path, table: &str) -> Vec<Row> {
    read_table_inner(db, table, false)
}

/// Read a table together with each SQLite rowid. Overview tables use this only
/// to preserve a stable pointer back to the raw parsed record; the additional
/// column is deliberately private and never emitted as analyst-facing data.
fn read_table_with_rowid(db: &Path, table: &str) -> Vec<Row> {
    read_table_inner(db, table, true)
}

fn read_table_inner(db: &Path, table: &str, include_rowid: bool) -> Vec<Row> {
    if !db.exists() {
        return Vec::new();
    }
    let con = match Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let query = if include_rowid {
        format!("SELECT rowid AS \"__source_rowid\", * FROM \"{}\"", table)
    } else {
        format!("SELECT * FROM \"{}\"", table)
    };
    let mut stmt = match con.prepare(&query) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let mut q = match stmt.query([]) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    while let Ok(Some(r)) = q.next() {
        let mut row = Row::new();
        for (i, c) in cols.iter().enumerate() {
            let v = match r.get_ref(i) {
                Ok(ValueRef::Null) => continue,
                Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
                Ok(ValueRef::Integer(n)) => n.to_string(),
                Ok(ValueRef::Real(f)) => f.to_string(),
                Ok(ValueRef::Blob(b)) => crate::hex::hex_lower(b),
                Err(_) => continue,
            };
            row.insert(c.clone(), v);
        }
        out.push(row);
    }
    out
}

/// True for a live registry row (not a recovered-deleted entry). The Rust
/// registry parser additionally recovers deleted cells / transaction-log
/// entries and marks them in `_recovery`; those enrich the RAW registry tables
/// but the overview correlations mirror Python's live-only semantics, so they
/// are filtered here. (A row without the column is treated as live.)
fn is_live(r: &Row) -> bool {
    r.get("_recovery").map(|v| v == "live").unwrap_or(true)
}

/// Read every table in a DB (used for per-account browser History etc.).
pub fn read_all_tables(db: &Path) -> Vec<(String, Vec<Row>)> {
    if !db.exists() {
        return Vec::new();
    }
    let con = match Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let names: Vec<String> = {
        let mut s = match con.prepare("SELECT name FROM sqlite_master WHERE type='table'") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let it = s
            .query_map([], |r| r.get::<_, String>(0))
            .map(|m| m.filter_map(|x| x.ok()).collect::<Vec<_>>())
            .unwrap_or_default();
        it
    };
    names
        .into_iter()
        .map(|t| {
            let rows = read_table(db, &t);
            (t, rows)
        })
        .collect()
}

// --- ScheduledTasks ("작업 스케줄러") ---
const ST_KEYS: &[&str] = &[
    "timestamp",
    "task_name",
    "is_microsoft",
    "actions",
    "trigger_types",
    "trigger_start",
    "run_as",
    "run_level",
    "logon_type",
    "enabled",
    "hidden",
    "author",
    "description",
    "uri",
    "_source_file",
    "_status",
    "_error",
];
pub fn build_scheduled_tasks(out_dir: &Path) -> Vec<Row> {
    let src = read_table(
        &out_dir
            .join("TASKSCHEDULER")
            .join("TaskScheduler_Tasks.sqlite"),
        "TaskScheduler_Tasks",
    );
    let mut out = Vec::new();
    for r in &src {
        let uri = r.get("uri").cloned().unwrap_or_default();
        let author = r.get("author").cloned().unwrap_or_default();
        let is_ms = uri.to_lowercase().starts_with("\\microsoft\\")
            || author.to_lowercase().contains("microsoft");
        let mut row = Row::new();
        for k in ST_KEYS {
            if let Some(v) = r.get(*k) {
                row.insert((*k).to_string(), v.clone());
            }
        }
        row.insert(
            "is_microsoft".into(),
            if is_ms { "1".into() } else { String::new() },
        );
        out.push(row);
    }
    out
}

// --- RdpCache ("RDP 캐시") — the reconstructed "fragment" rows only ---
pub fn build_rdp_cache(out_dir: &Path) -> Vec<Row> {
    read_table(
        &out_dir.join("RDPCACHE").join("RdpBitmapCache.sqlite"),
        "RdpBitmapCache",
    )
    .into_iter()
    .filter(|r| r.get("kind").map(|k| k == "fragment").unwrap_or(false))
    .collect()
}

// --- Event-log access helpers (shared by Defender + correlate builders) ---

/// All rows from every EventLog table whose stem (filename, lowercased)
/// contains `needle`. Rows keep the table's rowid order. Mirrors Python's
/// iteration over all_results["EventLog"] filtered by stem substring.
pub fn read_eventlog(out_dir: &Path, needle: &str) -> Vec<Row> {
    let dir = out_dir.join("EVENTLOG");
    let mut out = Vec::new();
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return out,
    };
    files.sort();
    for p in files {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if !stem.to_lowercase().contains(needle) {
            continue;
        }
        out.extend(read_table(&p, &stem));
    }
    out
}

/// EventLog 행 공유 캐시 — SMB/RDP/PowerShell/Defender 빌더가 같은 이벤트
/// 행을 각자 SQLite에서 다시 읽지 않도록 가공 단계 동안 한 번만 로드한다.
pub struct EventLogOverviewCache {
    rows: Vec<Row>,
}

impl EventLogOverviewCache {
    pub fn load(out_dir: &Path) -> Self {
        Self {
            rows: read_eventlog(out_dir, ""),
        }
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
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

// --- Defender ("Windows Defender") ---
const DEF_KEYS: &[&str] = &[
    "section",
    "timestamp",
    "event_id",
    "title",
    "detail",
    "severity",
    "category",
    "action",
    "action_time",
    "process",
    "user",
    "source",
    "remediation",
    "record_key",
    "additional_actions",
    "origin",
    "detection_user",
];
fn def_row() -> Row {
    let mut r = Row::new();
    for k in DEF_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    r
}
const TAMPER_KEYS: &[&str] = &[
    "disableantispyware",
    "disableantivirus",
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableioavprotection",
    "disableonaccessprotection",
    "disablescanonrealtimeenable",
    "tamperprotection",
    "exclusions",
    "disableblockatfirstseen",
    "puaprotection",
    "disablescriptscanning",
];

pub fn build_defender(out_dir: &Path) -> Vec<Row> {
    build_defender_with_events(&EventLogOverviewCache::load(out_dir))
}

pub fn build_defender_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    // detections: insertion-ordered map keyed by detection id (Vec preserves
    // order for stable tie-break in the timestamp sort below).
    let mut det_keys: Vec<String> = Vec::new();
    let mut detections: std::collections::HashMap<String, Row> = std::collections::HashMap::new();
    let mut tampering: Vec<(String, String, String, String, String, String)> = Vec::new(); // ts,title,detail,user,rk,eid
    let mut scans: std::collections::BTreeMap<String, (String, String, String, String)> =
        std::collections::BTreeMap::new();
    let mut history_cleared: Vec<(String, String, String)> = Vec::new();
    let mut rt_events: Vec<(String, bool, String)> = Vec::new();
    let mut sig_latest: Option<(String, String, String)> = None;

    for r in events.rows_from("defender") {
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let ts = r.get("timestamp").cloned().unwrap_or_default();
        let rk = r.get("_record_key").cloned().unwrap_or_default();
        let d = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));

        if ["1116", "1117", "1006", "1007", "1015"].contains(&eid.as_str()) {
            let detected = ["1116", "1006", "1015"].contains(&eid.as_str());
            let did_raw = jget(&d, "Detection ID");
            let did = if !did_raw.is_empty() {
                did_raw
            } else {
                format!("{}|{}", ts, jget(&d, "Threat Name"))
            };
            if !detections.contains_key(&did) {
                det_keys.push(did.clone());
                let mut rec = def_row();
                rec.insert("section".into(), "threat".into());
                rec.insert("event_id".into(), eid.clone());
                detections.insert(did.clone(), rec);
            }
            let rec = detections.get_mut(&did).unwrap();
            for (dst, src) in [
                ("title", "Threat Name"),
                ("severity", "Severity Name"),
                ("category", "Category Name"),
                ("process", "Process Name"),
                ("user", "Detection User"),
                ("detection_user", "Detection User"),
                ("source", "Source Name"),
                ("origin", "Origin Name"),
            ] {
                let v = jget(&d, src);
                if !v.is_empty() {
                    rec.insert(dst.into(), v);
                }
            }
            let path = jget(&d, "Path");
            let proc = jget(&d, "Process Name");
            if !path.is_empty() {
                rec.insert("detail".into(), path);
            } else if !proc.is_empty() {
                rec.insert("detail".into(), proc);
            }
            if detected {
                if earlier(&ts, rec.get("timestamp").map(|s| s.as_str()).unwrap_or("")) {
                    rec.insert("timestamp".into(), ts.clone());
                    rec.insert("record_key".into(), rk.clone());
                }
            } else {
                rec.insert("action_time".into(), ts.clone());
                let act = jget(&d, "Action Name");
                if !act.is_empty() && act != "해당 없음" {
                    rec.insert("action".into(), act);
                }
                let rem = jget(&d, "Remediation User");
                if !rem.is_empty() {
                    rec.insert("remediation".into(), rem);
                }
                let addl = jget(&d, "Additional Actions String");
                if !addl.is_empty() && addl != "No additional actions required" {
                    rec.insert("additional_actions".into(), addl);
                }
                if rec.get("timestamp").map(|s| s.is_empty()).unwrap_or(true) {
                    rec.insert("timestamp".into(), ts.clone());
                }
                if rec.get("record_key").map(|s| s.is_empty()).unwrap_or(true) {
                    rec.insert("record_key".into(), rk.clone());
                }
            }
        } else if eid == "5001" {
            rt_events.push((ts, false, rk));
        } else if eid == "5000" {
            rt_events.push((ts, true, rk));
        } else if eid == "5004" {
            tampering.push((
                ts,
                "실시간 보호 구성 변경".into(),
                "실시간 보호 설정이 변경됨".into(),
                String::new(),
                rk,
                eid,
            ));
        } else if eid == "5010" {
            tampering.push((
                ts,
                "바이러스 검사 사용 안 함".into(),
                String::new(),
                String::new(),
                rk,
                eid,
            ));
        } else if eid == "5012" {
            tampering.push((
                ts,
                "스파이웨어 검사 사용 안 함".into(),
                String::new(),
                String::new(),
                rk,
                eid,
            ));
        } else if eid == "1119" {
            tampering.push((
                ts,
                "위협 제거 실패".into(),
                format!("{} 제거/치료 실패", jget(&d, "Threat Name")),
                String::new(),
                rk,
                eid,
            ));
        } else if eid == "1013" {
            let user = format!("{}\\{}", jget(&d, "Domain"), jget(&d, "User"));
            history_cleared.push((ts, user.trim_matches('\\').to_string(), rk));
        } else if eid == "1001" {
            let stype = {
                let sp = jget(&d, "Scan Parameters");
                if !sp.is_empty() {
                    sp
                } else {
                    let st = jget(&d, "Scan Type");
                    if !st.is_empty() {
                        st
                    } else {
                        "검사".into()
                    }
                }
            };
            let user = format!("{}\\{}", jget(&d, "Domain"), jget(&d, "User"));
            let replace = scans.get(&stype).map(|cur| ts > cur.0).unwrap_or(true);
            if replace {
                scans.insert(
                    stype,
                    (
                        ts,
                        jget(&d, "Scan Type"),
                        user.trim_matches('\\').to_string(),
                        rk,
                    ),
                );
            }
        } else if eid == "2000" {
            let replace = sig_latest.as_ref().map(|s| ts > s.0).unwrap_or(true);
            if replace {
                sig_latest = Some((ts, jget(&d, "Current security intelligence Version"), rk));
            }
        } else if eid == "5007" {
            let blob = format!("{}{}", jget(&d, "New Value"), jget(&d, "Old Value")).to_lowercase();
            if TAMPER_KEYS.iter().any(|k| blob.contains(k)) {
                tampering.push((
                    ts,
                    "보호 구성 변경".into(),
                    format!("{} → {}", jget(&d, "Old Value"), jget(&d, "New Value")),
                    String::new(),
                    rk,
                    eid,
                ));
            }
        }
    }

    let mut out: Vec<Row> = Vec::new();
    // detections sorted by timestamp (stable → insertion order tie-break).
    let mut recs: Vec<Row> = det_keys
        .iter()
        .map(|k| detections.remove(k).unwrap())
        .collect();
    recs.sort_by(|a, b| a.get("timestamp").cmp(&b.get("timestamp")));
    for mut rec in recs {
        if rec.get("action").map(|s| s.is_empty()).unwrap_or(true) {
            rec.insert("action".into(), "탐지만 됨".into());
        }
        out.push(rec);
    }

    // Real-time protection: collapse to state changes only.
    rt_events.sort();
    let mut prev: Option<bool> = None;
    for (ts, is_on, rk) in rt_events {
        match prev {
            None => {
                prev = Some(is_on);
                if !is_on {
                    tampering.push((
                        ts,
                        "실시간 보호 사용 안 함".into(),
                        "Defender 실시간 보호가 해제됨".into(),
                        String::new(),
                        rk,
                        "5001".into(),
                    ));
                }
            }
            Some(p) if is_on == p => {}
            Some(_) => {
                prev = Some(is_on);
                if is_on {
                    tampering.push((
                        ts,
                        "실시간 보호 복원".into(),
                        "Defender 실시간 보호가 다시 켜짐".into(),
                        String::new(),
                        rk,
                        "5000".into(),
                    ));
                } else {
                    tampering.push((
                        ts,
                        "실시간 보호 사용 안 함".into(),
                        "Defender 실시간 보호가 해제됨".into(),
                        String::new(),
                        rk,
                        "5001".into(),
                    ));
                }
            }
        }
    }

    if !history_cleared.is_empty() {
        history_cleared.sort();
        let (ts, user, rk) = history_cleared.last().unwrap().clone();
        let mut r = def_row();
        r.insert("section".into(), "tampering".into());
        r.insert("timestamp".into(), ts);
        r.insert("event_id".into(), "1013".into());
        r.insert("title".into(), "검사/위협 기록 삭제".into());
        r.insert(
            "detail".into(),
            format!(
                "Defender 기록이 삭제됨 (총 {}회, 최근 시각 표시)",
                history_cleared.len()
            ),
        );
        r.insert("user".into(), user);
        r.insert("record_key".into(), rk);
        out.push(r);
    }
    tampering.sort();
    for (ts, title, detail, user, rk, eid) in tampering {
        let mut r = def_row();
        r.insert("section".into(), "tampering".into());
        r.insert("timestamp".into(), ts);
        r.insert("event_id".into(), eid);
        r.insert("title".into(), title);
        r.insert("detail".into(), detail);
        r.insert("user".into(), user);
        r.insert("record_key".into(), rk);
        out.push(r);
    }
    for (stype, (ts, scan_type, user, rk)) in scans {
        let mut r = def_row();
        r.insert("section".into(), "scan".into());
        r.insert("timestamp".into(), ts);
        r.insert("event_id".into(), "1001".into());
        r.insert("title".into(), stype);
        r.insert("detail".into(), scan_type);
        r.insert("user".into(), user);
        r.insert("record_key".into(), rk);
        out.push(r);
    }
    if let Some((ts, ver, rk)) = sig_latest {
        let mut r = def_row();
        r.insert("section".into(), "signature".into());
        r.insert("timestamp".into(), ts);
        r.insert("event_id".into(), "2000".into());
        r.insert("title".into(), "보안 인텔리전스 버전".into());
        r.insert("detail".into(), ver);
        r.insert("record_key".into(), rk);
        out.push(r);
    }
    out
}

// --- correlate.py builders (RemoteDesktop / SMB / PowerShell) ---

fn vstr(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

/// Read a field, checking a nested "EventXML" object first then the top level
/// (mirrors correlate._ed_field). Returns the first non-empty match.
fn ed_field(ed: &serde_json::Map<String, serde_json::Value>, names: &[&str]) -> String {
    let mut sources: Vec<&serde_json::Map<String, serde_json::Value>> = Vec::new();
    if let Some(serde_json::Value::Object(x)) = ed.get("EventXML") {
        sources.push(x);
    }
    sources.push(ed);
    for src in &sources {
        for n in names {
            if let Some(v) = src.get(*n) {
                let s = vstr(v);
                if !s.is_empty() {
                    return s;
                }
            }
        }
    }
    String::new()
}

/// Normalize an account to a bare username (drop DOMAIN\\ or HOST\\ and @upn).
fn bare_account(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let tail = name.replace('/', "\\");
    let tail = tail.rsplit('\\').next().unwrap_or("");
    tail.split('@').next().unwrap_or("").trim().to_string()
}

fn smb_client_ip(client_name: &str) -> String {
    client_name.trim_start_matches('\\').trim().to_string()
}

pub fn build_smb_history(out_dir: &Path) -> Vec<Row> {
    build_smb_history_with_events(&EventLogOverviewCache::load(out_dir))
}

pub fn build_smb_history_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        let (mut remote, mut account, result, description);
        if provider == "Microsoft-Windows-Security-Auditing" && (eid == "4624" || eid == "4625") {
            if ed_field(&ed, &["LogonType"]) != "3" {
                continue;
            }
            remote = ed_field(&ed, &["IpAddress", "SourceNetworkAddress"]);
            account = ed_field(&ed, &["TargetUserName"]);
            result = if eid == "4624" { "성공" } else { "실패" }.to_string();
            description = if eid == "4624" {
                "네트워크 로그온 성공 (SMB 등)"
            } else {
                "네트워크 로그온 실패 (SMB 등)"
            }
            .to_string();
        } else if provider == "Microsoft-Windows-SMBServer" && (eid == "551" || eid == "1009") {
            let inner = match ed.get("EventData") {
                Some(serde_json::Value::Object(m)) => m.clone(),
                _ => ed.clone(),
            };
            remote = smb_client_ip(&inner.get("ClientName").map(vstr).unwrap_or_default());
            account = inner.get("UserName").map(vstr).unwrap_or_default();
            if eid == "551" {
                result = "실패".into();
                description = "SMB 인증 실패".into();
            } else {
                result = "실패".into();
                description = "SMB 세션 인증 실패".into();
            }
        } else {
            continue;
        }
        if remote.is_empty() || remote == "-" {
            continue;
        }
        let mut row = Row::new();
        row.insert(
            "timestamp".into(),
            r.get("timestamp").cloned().unwrap_or_default(),
        );
        row.insert("direction".into(), "inbound".into());
        row.insert("remote_address".into(), std::mem::take(&mut remote));
        row.insert(
            "account".into(),
            bare_account(std::mem::take(&mut account).as_str()),
        );
        row.insert("description".into(), description);
        row.insert("result".into(), result);
        row.insert("event_id".into(), eid);
        row.insert("provider".into(), provider);
        row.insert(
            "record_key".into(),
            r.get("_record_key").cloned().unwrap_or_default(),
        );
        rows.push(row);
    }
    rows
}

/// BITS(Background Intelligent Transfer Service) 전송 이벤트를 개요 테이블로.
/// 공격자가 파일 다운로드 수단으로 자주 악용하므로 작업 생성~전송 결과까지
/// 한 테이블로 모은다 (Microsoft-Windows-Bits-Client/Operational).
pub fn build_bits_history(out_dir: &Path) -> Vec<Row> {
    build_bits_history_with_events(&EventLogOverviewCache::load(out_dir))
}

pub fn build_bits_history_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    // bytesTotal이 이 값이면 전체 크기를 알 수 없다는 뜻 (u64::MAX 센티널).
    const BITS_UNKNOWN_SIZE: &str = "18446744073709551615";
    let mut rows = Vec::new();
    for r in events.rows() {
        if r.get("Provider").map(|s| s.as_str()) != Some("Microsoft-Windows-Bits-Client") {
            continue;
        }
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        let hr = ed_field(&ed, &["hr"]);
        let (result, description) = match eid.as_str() {
            "3" => ("정보", "BITS 전송 작업 생성"),
            "4" => ("성공", "BITS 전송 작업 완료"),
            "5" => ("정보", "BITS 전송 작업 취소"),
            "59" => ("정보", "BITS URL 전송 시작"),
            "60" => {
                if hr.is_empty() || hr == "0" {
                    ("성공", "BITS URL 전송 완료")
                } else {
                    ("실패", "BITS URL 전송 실패")
                }
            }
            "61" => ("실패", "BITS URL 전송 오류"),
            _ => continue,
        };
        let status = match eid.as_str() {
            "60" => hr,
            "61" => ed_field(&ed, &["error"]),
            _ => String::new(),
        };
        let bytes_total = match ed_field(&ed, &["bytesTotal"]) {
            v if v == BITS_UNKNOWN_SIZE => String::new(),
            v => v,
        };
        let mut row = Row::new();
        row.insert(
            "timestamp".into(),
            r.get("timestamp").cloned().unwrap_or_default(),
        );
        row.insert("job_name".into(), ed_field(&ed, &["name", "jobTitle"]));
        row.insert("job_id".into(), ed_field(&ed, &["Id", "jobId"]));
        row.insert("url".into(), ed_field(&ed, &["url"]));
        row.insert(
            "account".into(),
            bare_account(&ed_field(&ed, &["jobOwner", "User"])),
        );
        row.insert(
            "process".into(),
            ed_field(&ed, &["processPath", "ProcessPath"]),
        );
        row.insert(
            "bytes_transferred".into(),
            ed_field(&ed, &["bytesTransferred"]),
        );
        row.insert("bytes_total".into(), bytes_total);
        row.insert("status".into(), status);
        row.insert("result".into(), result.to_string());
        row.insert("description".into(), description.to_string());
        row.insert("event_id".into(), eid);
        row.insert(
            "record_key".into(),
            r.get("_record_key").cloned().unwrap_or_default(),
        );
        rows.push(row);
    }
    rows
}

struct RdpSpec {
    direction: &'static str,
    result: &'static str,
    description: &'static str,
    addr: &'static [&'static str],
    acct: &'static [&'static str],
    lt10: bool,
}
fn rdp_spec(provider: &str, eid: &str) -> Option<RdpSpec> {
    let s = |direction,
             result,
             description,
             addr: &'static [&'static str],
             acct: &'static [&'static str],
             lt10| {
        Some(RdpSpec {
            direction,
            result,
            description,
            addr,
            acct,
            lt10,
        })
    };
    const SEC: &str = "Microsoft-Windows-Security-Auditing";
    const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    const AX: &str = "Microsoft-Windows-TerminalServices-ClientActiveXCore";
    match (provider, eid) {
        (SEC, "4624") => s(
            "inbound",
            "성공",
            "RDP 로그온 성공",
            &["IpAddress"],
            &["TargetUserName"],
            true,
        ),
        (SEC, "4625") => s(
            "inbound",
            "실패",
            "RDP 로그온 실패",
            &["IpAddress"],
            &["TargetUserName"],
            true,
        ),
        (RCM, "1149") => s(
            "inbound",
            "성공",
            "RDP 네트워크 인증 성공(로그인 화면 도달)",
            &["Param3"],
            &["Param1"],
            false,
        ),
        (LSM, "21") => s(
            "inbound",
            "성공",
            "RDP 세션 로그온",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "25") => s(
            "inbound",
            "성공",
            "RDP 세션 재연결",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "22") => s(
            "inbound",
            "정보",
            "RDP 셸 시작",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "23") => s(
            "inbound",
            "정보",
            "RDP 세션 로그오프",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "24") => s(
            "inbound",
            "정보",
            "RDP 세션 연결 끊김",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "39") => s(
            "inbound",
            "정보",
            "RDP 세션 연결 끊김(다른 세션에 의해)",
            &["Address"],
            &["User"],
            false,
        ),
        (LSM, "40") => s(
            "inbound",
            "정보",
            "RDP 세션 연결 끊김",
            &["Address"],
            &["User"],
            false,
        ),
        (AX, "1024") => s(
            "outbound",
            "정보",
            "RDP 아웃바운드 연결 시도",
            &["Value"],
            &[],
            false,
        ),
        (AX, "1102") => s(
            "outbound",
            "정보",
            "RDP 아웃바운드 서버 주소",
            &["Value"],
            &[],
            false,
        ),
        (AX, "1025") => s("outbound", "성공", "RDP 아웃바운드 연결됨", &[], &[], false),
        (AX, "1026") => s(
            "outbound",
            "정보",
            "RDP 아웃바운드 연결 끊김",
            &[],
            &[],
            false,
        ),
        _ => None,
    }
}

fn ts_epoch(ts: &str) -> Option<f64> {
    if ts.is_empty() {
        return None;
    }
    use chrono::NaiveDateTime;
    for (fmt, cut) in [
        ("%Y-%m-%d %H:%M:%S%.f", 23usize),
        ("%Y-%m-%d %H:%M:%S", 19usize),
    ] {
        let slice = if ts.len() >= cut { &ts[..cut] } else { ts };
        if let Ok(dt) = NaiveDateTime::parse_from_str(slice, fmt) {
            return Some(dt.and_utc().timestamp_micros() as f64 / 1_000_000.0);
        }
    }
    None
}

pub fn build_remote_desktop_history(out_dir: &Path) -> Vec<Row> {
    build_remote_desktop_history_with_events(&EventLogOverviewCache::load(out_dir))
}

pub fn build_remote_desktop_history_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    let mut rows: Vec<Row> = Vec::new();
    let mut sess_info: std::collections::HashMap<String, [Option<String>; 2]> =
        std::collections::HashMap::new();
    let mut lsm_pending: Vec<(usize, String)> = Vec::new();

    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let spec = match rdp_spec(&provider, &eid) {
            Some(s) => s,
            None => continue,
        };
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        if spec.lt10 && ed.get("LogonType").map(vstr).unwrap_or_default() != "10" {
            continue;
        }
        let addr = if !spec.addr.is_empty() {
            ed_field(&ed, spec.addr)
        } else {
            String::new()
        };
        let acct = if !spec.acct.is_empty() {
            bare_account(&ed_field(&ed, spec.acct))
        } else {
            String::new()
        };
        let mut row = Row::new();
        row.insert(
            "timestamp".into(),
            r.get("timestamp").cloned().unwrap_or_default(),
        );
        row.insert("direction".into(), spec.direction.into());
        row.insert("remote_address".into(), addr.clone());
        row.insert("account".into(), acct.clone());
        row.insert("description".into(), spec.description.into());
        row.insert("result".into(), spec.result.into());
        row.insert("event_id".into(), eid.clone());
        row.insert("provider".into(), provider.clone());
        row.insert(
            "record_key".into(),
            r.get("_record_key").cloned().unwrap_or_default(),
        );
        rows.push(row);

        if provider == LSM {
            let src: &serde_json::Map<String, serde_json::Value> = match ed.get("EventXML") {
                Some(serde_json::Value::Object(x)) => x,
                _ => &ed,
            };
            let skey = ["SessionID", "Session", "TargetSession"]
                .iter()
                .find_map(|k| src.get(*k).map(vstr).filter(|s| !s.is_empty()));
            if let Some(skey) = skey {
                let info = sess_info.entry(skey.clone()).or_insert([None, None]);
                if !addr.is_empty() {
                    info[0] = Some(addr);
                }
                if !acct.is_empty() {
                    info[1] = Some(acct);
                }
                lsm_pending.push((rows.len() - 1, skey));
            }
        }
    }

    for (idx, skey) in lsm_pending {
        if let Some(info) = sess_info.get(&skey) {
            if rows[idx]
                .get("remote_address")
                .map(|s| s.is_empty())
                .unwrap_or(true)
            {
                if let Some(a) = &info[0] {
                    rows[idx].insert("remote_address".into(), a.clone());
                }
            }
            if rows[idx]
                .get("account")
                .map(|s| s.is_empty())
                .unwrap_or(true)
            {
                if let Some(a) = &info[1] {
                    rows[idx].insert("account".into(), a.clone());
                }
            }
        }
    }

    // Outbound carry-forward within a 5-min window (iterate by timestamp order).
    const WINDOW: f64 = 5.0 * 60.0;
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&a, &b| rows[a].get("timestamp").cmp(&rows[b].get("timestamp")));
    let mut last_out: Option<(Option<f64>, String)> = None;
    for i in order {
        if rows[i].get("direction").map(|s| s.as_str()) != Some("outbound") {
            continue;
        }
        let t = ts_epoch(rows[i].get("timestamp").map(|s| s.as_str()).unwrap_or(""));
        if !rows[i]
            .get("remote_address")
            .map(|s| s.is_empty())
            .unwrap_or(true)
        {
            last_out = Some((
                t,
                rows[i].get("remote_address").cloned().unwrap_or_default(),
            ));
        } else if let Some((Some(lt), addr)) = &last_out {
            if let Some(t) = t {
                if t - lt >= 0.0 && t - lt <= WINDOW {
                    rows[i].insert("remote_address".into(), addr.clone());
                }
            }
        }
    }
    rows
}

// PowerShell history
fn read_registry_all(out_dir: &Path) -> Vec<Row> {
    let dir = out_dir.join("REGISTRY");
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    let mut out = Vec::new();
    for p in files {
        out.extend(read_table(&p, "Registry").into_iter().filter(is_live));
    }
    out
}

fn basename_win(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    path.replace('/', "\\")
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

fn user_map(out_dir: &Path) -> std::collections::HashMap<String, String> {
    let mut umap = std::collections::HashMap::new();
    for r in read_registry_all(out_dir) {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\profilelist\\s-")
            && r.get("value_name")
                .map(|s| s == "ProfileImagePath")
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

fn ctx_value(ctx: &str, tokens: &[&str]) -> String {
    for line in ctx.lines() {
        if !line.contains('=') {
            continue;
        }
        let (label, value) = line.split_once('=').unwrap();
        let label = label.trim();
        if tokens.iter().any(|t| !t.is_empty() && label.contains(t)) {
            return value.trim().to_string();
        }
    }
    String::new()
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

fn first_line(text: &str, limit: usize) -> String {
    for line in text.lines() {
        let s = line.trim();
        if !s.is_empty() {
            return s.chars().take(limit).collect();
        }
    }
    text.trim().chars().take(limit).collect()
}

fn find_token(blob: &str, prefix: &str) -> String {
    // Emulate re.search(r"PREFIX(.+)") — first occurrence, capture to line end.
    if let Some(pos) = blob.find(prefix) {
        let after = &blob[pos + prefix.len()..];
        let line = after.split('\n').next().unwrap_or("");
        let line = line.trim_end_matches('\r');
        if !line.is_empty() {
            return line.trim().to_string();
        }
    }
    String::new()
}

fn to_int(v: Option<&serde_json::Value>, default: i64) -> i64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(default),
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(default),
        _ => default,
    }
}

#[allow(clippy::too_many_arguments)]
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

pub fn build_powershell_history(out_dir: &Path) -> Vec<Row> {
    build_powershell_history_with_events(out_dir, &EventLogOverviewCache::load(out_dir))
}

pub fn build_powershell_history_with_events(
    out_dir: &Path,
    events: &EventLogOverviewCache,
) -> Vec<Row> {
    let umap = user_map(out_dir);
    let account_for = |sid: &str| -> String {
        match umap.get(sid) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => sid.to_string(),
        }
    };
    let mut rows: Vec<Row> = Vec::new();
    // (parts: BTreeMap<i64,String>, timestamp, sid, pid, rk, path)
    type BlockEntry = (
        std::collections::BTreeMap<i64, String>,
        String,
        String,
        String,
        String,
        String,
    );
    let mut block_keys: Vec<String> = Vec::new();
    let mut blocks: std::collections::HashMap<String, BlockEntry> =
        std::collections::HashMap::new();

    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let event_id = r.get("EventID").cloned().unwrap_or_default();
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        let sid = r.get("UserID").cloned().unwrap_or_default();
        let pid = r.get("ProcessID").cloned().unwrap_or_default();
        let ts = r.get("timestamp").cloned().unwrap_or_default();
        let rk = r.get("_record_key").cloned().unwrap_or_default();

        if provider == "Microsoft-Windows-PowerShell" && event_id == "4104" {
            let text = ed.get("ScriptBlockText").map(vstr).unwrap_or_default();
            let path = ed.get("Path").map(vstr).unwrap_or_default();
            let sbid = ed.get("ScriptBlockId").map(vstr).unwrap_or_default();
            let total = to_int(ed.get("MessageTotal"), 1);
            let num = to_int(ed.get("MessageNumber"), 1);
            if !sbid.is_empty() && total > 1 {
                if !blocks.contains_key(&sbid) {
                    block_keys.push(sbid.clone());
                    blocks.insert(
                        sbid.clone(),
                        (
                            std::collections::BTreeMap::new(),
                            ts.clone(),
                            sid.clone(),
                            pid.clone(),
                            rk.clone(),
                            path.clone(),
                        ),
                    );
                }
                let slot = blocks.get_mut(&sbid).unwrap();
                slot.0.insert(num, text);
                if !ts.is_empty() && (slot.1.is_empty() || ts < slot.1) {
                    slot.1 = ts.clone();
                    slot.4 = rk.clone();
                }
                continue;
            }
            rows.push(ps_row(
                &ts,
                &account_for(&sid),
                "powershell.exe",
                &pid,
                "",
                &text,
                "",
                "스크립트 블록",
                &event_id,
                &provider,
                &path,
                &rk,
            ));
        } else if provider == "Microsoft-Windows-PowerShell" && event_id == "4103" {
            let ctx = ed.get("ContextInfo").map(vstr).unwrap_or_default();
            let host = ctx_value(&ctx, &["Host Application", "호스트 응용"]);
            let user = ctx_value(&ctx, &["User", "사용자"]);
            let payload = ed
                .get("Payload")
                .map(vstr)
                .unwrap_or_default()
                .trim()
                .to_string();
            let command = if !payload.is_empty() {
                payload
            } else {
                ctx_value(&ctx, &["Command Name", "명령 이름"])
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
            rows.push(ps_row(
                &ts,
                &acct,
                &proc,
                &pid,
                &first_line(&command, 400),
                "",
                &host,
                "파이프라인",
                &event_id,
                &provider,
                "",
                &rk,
            ));
        } else if provider == "PowerShell" && event_id == "800" {
            let mut strs = Vec::new();
            all_strings(&serde_json::Value::Object(ed.clone()), &mut strs);
            let blob = strs.join("\n");
            let host = find_token(&blob, "HostApplication=");
            let command = find_token(&blob, "CommandLine=");
            // Classic 800 events record the invoked .ps1 as ScriptName=; surface
            // it as the row's script path so the PowerShell view shows it beside
            // the host application instead of leaving the column empty.
            let script_name = find_token(&blob, "ScriptName=");
            // Classic Windows PowerShell events frequently leave the outer
            // UserID empty while carrying the actual user in EventData.
            let event_user = find_token(&blob, "UserId=");
            let account = if event_user.is_empty() {
                account_for(&sid)
            } else {
                event_user
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
            rows.push(ps_row(
                &ts,
                &account,
                &proc,
                &pid,
                &first_line(&command, 400),
                "",
                &host,
                "명령 실행",
                &event_id,
                &provider,
                &script_name,
                &rk,
            ));
        }
    }

    for k in &block_keys {
        let slot = &blocks[k];
        let text: String = slot.0.values().cloned().collect();
        rows.push(ps_row(
            &slot.1,
            &account_for(&slot.2),
            "powershell.exe",
            &slot.3,
            "",
            &text,
            "",
            "스크립트 블록",
            "4104",
            "Microsoft-Windows-PowerShell",
            &slot.5,
            &slot.4,
        ));
    }
    rows
}

// --- BrowserActivity ("BrowserActivity") — visits + downloads + cache ---
const BH_KEYS: &[&str] = &[
    "account",
    "kind",
    "timestamp",
    "title",
    "url",
    "url_raw",
    "visit_count",
    "typed_count",
    "detail",
    "size",
    "size_bytes",
    "mime",
    "danger",
    "source_url",
    "status",
    "cache_key",
    "cache_body_recovered",
];
fn bh_row(pairs: &[(&str, String)]) -> Row {
    let mut r = Row::new();
    for k in BH_KEYS {
        r.insert((*k).to_string(), String::new());
    }
    for (k, v) in pairs {
        r.insert((*k).to_string(), v.clone());
    }
    r
}

/// Chrome/WebKit time = microseconds since 1601-01-01 UTC -> KST display.
fn chrome_time(value: &str) -> String {
    let v: i64 = match value.trim().parse() {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if v <= 0 {
        return String::new();
    }
    match v.checked_mul(10) {
        Some(ticks) => crate::time::fmt_filetime(ticks),
        None => String::new(),
    }
}

/// urllib.parse.unquote — percent-decode %XX as UTF-8 (errors=replace); '+' is
/// left as-is (unquote, not unquote_plus). Non-%XX text passes through.
fn url_decode(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let b = url.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    let hexval = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn human_bytes(value: &str) -> String {
    let n: i64 = match value.trim().parse() {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if n < 0 {
        return String::new();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    for (idx, u) in units.iter().enumerate() {
        if f < 1024.0 || idx == units.len() - 1 {
            return if *u == "B" {
                format!("{} {}", f as i64, u)
            } else {
                format!("{:.1} {}", f, u)
            };
        }
        f /= 1024.0;
    }
    format!("{} B", n)
}

fn browser_sources(
    out_dir: &Path,
    category: &str,
    suffix: &str,
) -> Vec<(String, std::path::PathBuf)> {
    let dir = out_dir.join(category);
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let account = stem.strip_suffix(suffix).unwrap_or(&stem).to_string();
            (account, p)
        })
        .collect()
}

/// CacheEntries에서 브라우저 활동 개요가 쓰는 메타데이터 컬럼만 읽는다.
/// body_b64는 본문 존재 여부만 필요하므로 플래그("1"/"")로 축약해, 다중 MB
/// base64 본문이 개요 생성 중 메모리에 올라오지 않게 한다. 없는 컬럼은 빈 값.
fn read_cache_entry_meta(db: &Path) -> Vec<Row> {
    const META_COLUMNS: &[&str] = &[
        "account",
        "url",
        "response_time",
        "creation_time",
        "content_length",
        "body_size",
        "content_type",
        "status",
        "cache_key",
    ];
    if !db.exists() {
        return Vec::new();
    }
    let con = match Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut present: Vec<String> = Vec::new();
    if let Ok(mut stmt) = con.prepare("SELECT name FROM pragma_table_info('CacheEntries')") {
        if let Ok(mut q) = stmt.query([]) {
            while let Ok(Some(r)) = q.next() {
                if let Ok(name) = r.get::<_, String>(0) {
                    present.push(name);
                }
            }
        }
    }
    let mut select: Vec<String> = Vec::new();
    let mut keys: Vec<&str> = Vec::new();
    for column in META_COLUMNS {
        if present.iter().any(|name| name == column) {
            select.push(format!("\"{}\"", column));
            keys.push(column);
        }
    }
    if present.iter().any(|name| name == "body_b64") {
        select.push("CASE WHEN \"body_b64\" IS NULL OR \"body_b64\" = '' THEN '' ELSE '1' END".to_string());
        keys.push("body_b64");
    }
    if select.is_empty() {
        return Vec::new();
    }
    let mut stmt = match con.prepare(&format!(
        "SELECT {} FROM \"CacheEntries\"",
        select.join(", ")
    )) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut q = match stmt.query([]) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    while let Ok(Some(r)) = q.next() {
        let mut row = Row::new();
        for (i, key) in keys.iter().enumerate() {
            let value: String = r.get::<_, Option<String>>(i).ok().flatten().unwrap_or_default();
            row.insert((*key).to_string(), value);
        }
        out.push(row);
    }
    out
}

pub fn build_browser_history(out_dir: &Path) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    // Cached HTTP responses (BrowserCache) — empty when no cache artifact present.
    for (account, db) in browser_sources(out_dir, "BROWSER", "_Chrome_Cache") {
        for c in read_cache_entry_meta(&db) {
            let g = |k: &str| c.get(k).cloned().unwrap_or_default();
            let ts = {
                let r = g("response_time");
                if !r.is_empty() {
                    r
                } else {
                    g("creation_time")
                }
            };
            let url = g("url");
            if ts.is_empty() || url.is_empty() {
                continue;
            }
            let acct = {
                let a = g("account");
                if !a.is_empty() {
                    a
                } else {
                    account.clone()
                }
            };
            let size = {
                let s = g("content_length");
                if !s.is_empty() {
                    s
                } else {
                    g("body_size")
                }
            };
            let title = {
                let b = basename_win(&url);
                if b.is_empty() {
                    url.clone()
                } else {
                    b
                }
            };
            // A cache response is marked as recovered only when the cache
            // parser retained an actual decoded response body. Metadata or a
            // body address alone is not sufficient: those cannot be opened
            // as recovered evidence in the common detail panel.
            let cache_body_recovered = if g("body_b64").is_empty() {
                String::new()
            } else {
                "1".into()
            };
            rows.push(bh_row(&[
                ("account", acct),
                ("kind", "cache".into()),
                ("timestamp", ts),
                ("title", title),
                ("url", url),
                ("mime", g("content_type")),
                ("size", size.clone()),
                ("size_bytes", size),
                ("status", g("status")),
                ("cache_key", g("cache_key")),
                ("cache_body_recovered", cache_body_recovered),
            ]));
        }
    }
    for (account, db) in browser_sources(out_dir, "BROWSER", "_Chrome_History") {
        for u in read_table(&db, "urls") {
            let g = |k: &str| u.get(k).cloned().unwrap_or_default();
            let raw = g("url");
            // Python: str(x or "") — a 0 count is falsy, rendered blank.
            let count = |v: String| {
                if v.is_empty() || v == "0" {
                    String::new()
                } else {
                    v
                }
            };
            rows.push(bh_row(&[
                ("account", account.clone()),
                ("kind", "visit".into()),
                ("timestamp", chrome_time(&g("last_visit_time"))),
                ("title", g("title")),
                ("url", url_decode(&raw)),
                ("url_raw", raw.clone()),
                ("visit_count", count(g("visit_count"))),
                ("typed_count", count(g("typed_count"))),
            ]));
        }
        for d in read_table(&db, "downloads") {
            let g = |k: &str| d.get(k).cloned().unwrap_or_default();
            let tgt = {
                let t = g("target_path");
                if !t.is_empty() {
                    t
                } else {
                    g("current_path")
                }
            };
            let src = {
                let a = g("tab_url");
                if !a.is_empty() {
                    a
                } else {
                    let b = g("referrer");
                    if !b.is_empty() {
                        b
                    } else {
                        g("site_url")
                    }
                }
            };
            // Python's guard tests the string "0", but danger_type is an integer
            // column, so an in-memory int 0 never matches and is kept as "0";
            // only a genuinely empty/NULL value blanks. Match that observable
            // behavior (pass the raw value; blank only when empty).
            let danger = g("danger_type");
            let size_raw = {
                let t = g("total_bytes");
                if !t.is_empty() {
                    t
                } else {
                    g("received_bytes")
                }
            };
            rows.push(bh_row(&[
                ("account", account.clone()),
                ("kind", "download".into()),
                ("timestamp", chrome_time(&g("start_time"))),
                ("title", basename_win(&url_decode(&tgt))),
                ("detail", url_decode(&tgt)),
                ("url", url_decode(&src)),
                ("url_raw", src.clone()),
                ("source_url", url_decode(&src)),
                ("size", human_bytes(&size_raw)),
                ("size_bytes", size_raw),
                ("mime", g("mime_type")),
                ("danger", danger),
            ]));
        }
    }
    rows
}

// --- TargetInfo ("TargetInfo") — system / accounts / networks / interfaces ---
const TI_KEYS: &[&str] = &[
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

fn le_u16(b: &[u8], off: usize) -> u16 {
    if off + 2 > b.len() {
        0
    } else {
        u16::from_le_bytes([b[off], b[off + 1]])
    }
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() {
        0
    } else {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    if off + 8 > b.len() {
        0
    } else {
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[off..off + 8]);
        u64::from_le_bytes(a)
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
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

/// Bounded to one overview generation.  This avoids reopening every large
/// recovered hive for TargetInfo, BAM, and RegistryFindings while never
/// crossing a host/run boundary or changing the raw parser/recovery output.
pub struct RegistryOverviewCache {
    hives: Vec<RegistryOverviewHive>,
}

impl RegistryOverviewCache {
    pub fn load(out_dir: &Path) -> Self {
        let dir = out_dir.join("REGISTRY");
        let mut files: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sqlite")
                })
                .collect(),
            Err(_) => return Self { hives: Vec::new() },
        };
        files.sort();
        let hives = files
            .into_iter()
            .map(|database| RegistryOverviewHive {
                name: database
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
                    .unwrap_or_default(),
                rows: read_table_with_rowid(&database, "Registry")
                    .into_iter()
                    .filter(is_live)
                    .collect(),
                database,
            })
            .collect();
        Self { hives }
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

/// First non-empty value for a key ending in `key_suffix` + value_name,
/// preferring ControlSet001 over the ...002 backup.
fn reg_pick(rows: &[Row], key_suffix: &str, value_name: &str) -> String {
    let ks = key_suffix.to_lowercase();
    let hits: Vec<&Row> = rows
        .iter()
        .filter(|r| {
            r.get("key_path")
                .map(|k| k.to_lowercase().ends_with(&ks))
                .unwrap_or(false)
                && r.get("value_name")
                    .map(|v| v == value_name)
                    .unwrap_or(false)
                && r.get("value_data").map(|v| !v.is_empty()).unwrap_or(false)
        })
        .collect();
    for r in &hits {
        if r.get("key_path")
            .map(|k| k.to_lowercase().contains("controlset001"))
            .unwrap_or(false)
        {
            return r.get("value_data").cloned().unwrap_or_default();
        }
    }
    hits.first()
        .map(|r| r.get("value_data").cloned().unwrap_or_default())
        .unwrap_or_default()
}

const OS_VALUES: &[&str] = &[
    "ProductName",
    "EditionID",
    "DisplayVersion",
    "CurrentBuild",
    "RegisteredOwner",
    "InstallDate",
];
const ACB: &[(u16, &str)] = &[
    (0x0001, "Disabled"),
    (0x0002, "HomeDirRequired"),
    (0x0004, "PwNotRequired"),
    (0x0008, "TempDuplicate"),
    (0x0010, "Normal"),
    (0x0020, "MNSLogon"),
    (0x0040, "DomainTrust"),
    (0x0080, "WorkstationTrust"),
    (0x0100, "ServerTrust"),
    (0x0200, "PwNoExpire"),
    (0x0400, "AutoLocked"),
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
            ]));
        }
    }
    let cn = reg_pick(
        system,
        "\\control\\computername\\computername",
        "ComputerName",
    );
    if !cn.is_empty() {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "ComputerName".into()),
            ("value", cn),
            ("source_artifact", "SYSTEM".into()),
        ]));
    }
    let tz = reg_pick(system, "\\control\\timezoneinformation", "TimeZoneKeyName");
    if !tz.is_empty() {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "TimeZone".into()),
            ("value", tz),
            ("source_artifact", "SYSTEM".into()),
        ]));
    }
    let sd = reg_pick(system, "\\control\\windows", "ShutdownTime");
    if !sd.is_empty() {
        rows.push(ti_row(&[
            ("category", "SystemInfo".into()),
            ("name", "LastShutdownTime".into()),
            ("value", filetime_hex(&sd)),
            ("source_artifact", "SYSTEM".into()),
        ]));
    }
    rows
}

fn sam_f(b: &[u8]) -> Option<HashMap<&'static str, String>> {
    if b.len() < 0x44 {
        return None;
    }
    let acb = le_u16(b, 0x38);
    let mut m = HashMap::new();
    m.insert("rid", le_u32(b, 0x30).to_string());
    m.insert("last_login", filetime(le_u64(b, 0x08)));
    m.insert("password_last_set", filetime(le_u64(b, 0x18)));
    m.insert("last_failed_login", filetime(le_u64(b, 0x28)));
    m.insert("login_count", le_u16(b, 0x42).to_string());
    m.insert("failed_login_count", le_u16(b, 0x40).to_string());
    m.insert(
        "disabled",
        if acb & 0x0001 != 0 {
            "예".into()
        } else {
            "아니오".into()
        },
    );
    m.insert(
        "account_flags",
        ACB.iter()
            .filter(|(bit, _)| acb & bit != 0)
            .map(|(_, n)| *n)
            .collect::<Vec<_>>()
            .join(", "),
    );
    Some(m)
}

fn sam_v(b: &[u8]) -> (String, String) {
    if b.len() < 0xCC {
        return (String::new(), String::new());
    }
    let field = |idx: usize| -> String {
        let base = idx * 12;
        let off = le_u32(b, base) as usize;
        let length = le_u32(b, base + 4) as usize;
        let start = 0xCC + off;
        let end = (start + length).min(b.len());
        if start >= b.len() {
            return String::new();
        }
        let raw = &b[start..end];
        // UTF-16LE decode (lossy)
        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    };
    (field(1), field(2))
}

fn special_accounts(software: &[Row]) -> HashMap<String, String> {
    let mark = "\\microsoft\\windows nt\\currentversion\\winlogon\\specialaccounts\\userlist";
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

fn well_known_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("LocalSystem"),
        "S-1-5-19" => Some("LocalService"),
        "S-1-5-20" => Some("NetworkService"),
        _ => None,
    }
}

fn ti_accounts(sam: &[Row], software: &[Row]) -> Vec<Row> {
    let hidden = special_accounts(software);
    let mut prefix = String::new();
    let mut profile_keys: Vec<String> = Vec::new();
    let mut profiles: HashMap<String, String> = HashMap::new();
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\profilelist\\s-")
            && r.get("value_name")
                .map(|v| v == "ProfileImagePath")
                .unwrap_or(false)
        {
            let sid = kp.rsplit('\\').next().unwrap_or("").to_string();
            if !profiles.contains_key(&sid) {
                profile_keys.push(sid.clone());
            }
            profiles.insert(
                sid.clone(),
                r.get("value_data").cloned().unwrap_or_default(),
            );
            if sid.starts_with("S-1-5-21-") && prefix.is_empty() {
                if let Some(p) = sid.rfind('-') {
                    prefix = sid[..p].to_string();
                }
            }
        }
    }

    let mut user_keys: Vec<String> = Vec::new();
    let mut users: HashMap<String, (Vec<u8>, Vec<u8>)> = HashMap::new(); // rid_hex -> (F, V)
    let mut names_created: HashMap<String, String> = HashMap::new();
    let hexset = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    for r in sam {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
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
                    users.insert(tail.to_string(), (Vec::new(), Vec::new()));
                }
                let entry = users.get_mut(tail).unwrap();
                match r.get("value_name").map(|s| s.as_str()) {
                    Some("F") => entry.0 = unhex(&r.get("value_data").cloned().unwrap_or_default()),
                    Some("V") => entry.1 = unhex(&r.get("value_data").cloned().unwrap_or_default()),
                    _ => {}
                }
            }
        }
    }

    let mut rows = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();
    for rid_hex in &user_keys {
        let (fb, vb) = users.get(rid_hex).unwrap();
        let rid = u32::from_str_radix(rid_hex, 16).unwrap_or(0);
        let f = sam_f(fb);
        let (username, full_name) = sam_v(vb);
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
        let g = |k: &str| {
            f.as_ref()
                .and_then(|m| m.get(k))
                .cloned()
                .unwrap_or_default()
        };
        let last_login = g("last_login");
        if !sid.is_empty() {
            emitted.insert(sid.clone());
        }
        rows.push(ti_row(&[
            ("category", "Account".into()),
            ("name", sid.clone()),
            ("value", path.clone()),
            ("source_artifact", "SAM".into()),
            ("username", username),
            ("full_name", full_name),
            ("rid", rid.to_string()),
            ("rid_sam", g("rid")),
            ("home_directory", path.clone()),
            ("created", created.clone()),
            ("last_login", last_login.clone()),
            ("password_last_set", g("password_last_set")),
            ("last_failed_login", g("last_failed_login")),
            ("login_count", g("login_count")),
            ("failed_login_count", g("failed_login_count")),
            ("disabled", g("disabled")),
            ("account_flags", g("account_flags")),
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
        let uname = well_known_sid(sid)
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
    let mut prof: HashMap<String, (String, String)> = HashMap::new(); // kp -> (name, when)
    for r in software {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        if kp.to_lowercase().contains("\\networklist\\profiles\\{") {
            if !prof.contains_key(&kp) {
                keys.push(kp.clone());
                prof.insert(kp.clone(), (String::new(), String::new()));
            }
            let e = prof.get_mut(&kp).unwrap();
            match r.get("value_name").map(|s| s.as_str()) {
                Some("ProfileName") => e.0 = r.get("value_data").cloned().unwrap_or_default(),
                Some("DateLastConnected") => {
                    e.1 = systemtime_hex(&r.get("value_data").cloned().unwrap_or_default())
                }
                _ => {}
            }
        }
    }
    keys.iter()
        .filter_map(|k| {
            let (name, when) = prof.get(k).unwrap();
            if name.is_empty() {
                None
            } else {
                Some(ti_row(&[
                    ("category", "Network".into()),
                    ("name", "연결한 네트워크".into()),
                    ("value", name.clone()),
                    ("timestamp", when.clone()),
                    ("source_artifact", "NetworkList".into()),
                ]))
            }
        })
        .collect()
}

fn ti_network_interfaces(system: &[Row]) -> Vec<Row> {
    let mark = "\\services\\tcpip\\parameters\\interfaces\\";
    let mut guids: Vec<String> = Vec::new();
    let mut ifaces: HashMap<String, HashMap<String, String>> = HashMap::new();
    for r in system {
        let kp = r.get("key_path").cloned().unwrap_or_default();
        let low = kp.to_lowercase();
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
            ifaces.get_mut(&guid).unwrap().insert(
                r.get("value_name").cloned().unwrap_or_default(),
                r.get("value_data").cloned().unwrap_or_default(),
            );
        }
    }
    let mut rows = Vec::new();
    for guid in &guids {
        let d = &ifaces[guid];
        let g = |k: &str| d.get(k).cloned().unwrap_or_default();
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
        ]));
    }
    rows
}

pub fn build_target_info(out_dir: &Path) -> Vec<Row> {
    let registry = RegistryOverviewCache::load(out_dir);
    build_target_info_with_registry(&registry)
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
const ROW_KEYS: &[&str] = &[
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
) -> Vec<(std::path::PathBuf, Row)> {
    let dir = out_dir.join(category);
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    let mut out = Vec::new();
    for p in files {
        out.extend(
            read_table_with_rowid(&p, table)
                .into_iter()
                .map(|row| (p.clone(), row)),
        );
    }
    out
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

fn eh_from_amcache(out_dir: &Path) -> Vec<Row> {
    let mut rows = Vec::new();
    for (db, r) in read_category_all_with_rowid(out_dir, "AMCACHE", "Amcache_Programs") {
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
    for (db, r) in read_category_all_with_rowid(out_dir, "AMCACHE", "Amcache_Files") {
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
    rows
}

fn eh_from_userassist(out_dir: &Path) -> Vec<Row> {
    let mut rows = Vec::new();
    let dir = out_dir.join("REGISTRY");
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return rows,
    };
    files.sort();
    for p in files {
        let stem = p
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if !stem.to_uppercase().ends_with("NTUSER.DAT") {
            continue;
        }
        let user = if stem.to_uppercase().ends_with("_NTUSER.DAT") {
            stem[..stem.len() - "_NTUSER.DAT".len()].to_string()
        } else {
            stem.clone()
        };
        for r in read_table_with_rowid(&p, "Registry")
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
    rows
}

fn eh_from_srum(out_dir: &Path) -> Vec<Row> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut earliest: HashMap<(String, String), (String, String)> = HashMap::new();
    for (db, r) in read_category_all_with_rowid(out_dir, "SRUM", "SRUM_ApplicationResourceUsage") {
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
    order
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
        .collect()
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

fn eh_from_prefetch(out_dir: &Path) -> Vec<Row> {
    let db = out_dir.join("PREFETCH").join("Prefetch_Execution.sqlite");
    read_table_with_rowid(&db, "Prefetch_Execution")
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
        .collect()
}

pub fn build_execution_history(out_dir: &Path) -> Vec<Row> {
    let registry = RegistryOverviewCache::load(out_dir);
    build_execution_history_with_registry(out_dir, &registry)
}

pub fn build_execution_history_with_registry(
    out_dir: &Path,
    registry: &RegistryOverviewCache,
) -> Vec<Row> {
    let mut rows = Vec::new();
    rows.extend(eh_from_amcache(out_dir));
    rows.extend(eh_from_userassist(out_dir));
    rows.extend(eh_from_srum(out_dir));
    rows.extend(eh_from_bam_registry(registry));
    rows.extend(eh_from_prefetch(out_dir));
    rows
}

// --- RegistryFindings ("레지스트리 특이사항") ---
const RF_KEYS: &[&str] = &[
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
];
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
    let up = fname.to_uppercase();
    if up == "SOFTWARE" {
        return "(시스템)".into();
    }
    if up == "DEFAULT" {
        return ".DEFAULT".into();
    }
    if up.ends_with("NTUSER.DAT") {
        return if up.ends_with("_NTUSER.DAT") {
            fname[..fname.len() - "_NTUSER.DAT".len()].to_string()
        } else {
            fname.to_string()
        };
    }
    fname.to_string()
}

fn find_sub_local(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_shimcache(data: &[u8]) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    if data.len() < 4 {
        return entries;
    }
    let header = le_u32(data, 0) as usize;
    let mut off: Option<usize> =
        if header > 0 && header < data.len() && data.get(header..header + 4) == Some(b"10ts") {
            Some(header)
        } else {
            find_sub_local(data, b"10ts")
        };
    while let Some(o) = off {
        if o + 12 > data.len() || data.get(o..o + 4) != Some(b"10ts") {
            break;
        }
        let ce_size = le_u32(data, o + 8) as usize;
        let estart = o + 12;
        let eend = (estart + ce_size).min(data.len());
        let entry = &data[estart..eend];
        if entry.len() >= 2 {
            let path_len = le_u16(entry, 0) as usize;
            if 2 + path_len + 8 <= entry.len() {
                let path_bytes = &entry[2..2 + path_len];
                let u16s: Vec<u16> = path_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let path = String::from_utf16_lossy(&u16s);
                let ft = le_u64(entry, 2 + path_len);
                if !path.is_empty() && (path.contains('\\') || path.contains(':')) {
                    entries.push((path, ft));
                }
            }
        }
        off = Some(o + 12 + ce_size);
    }
    entries
}

fn rf_credential_protection(system: &[Row]) -> Vec<Row> {
    let mut rows = Vec::new();
    let wd = reg_pick(system, "\\securityproviders\\wdigest", "UseLogonCredential");
    if wd == "1" {
        rows.push(rf_row(&[("category", "자격 증명 보호".into()), ("name", "WDigest UseLogonCredential".into()), ("value", "1 (사용)".into()), ("status", "의심".into()),
            ("detail", "WDigest 평문 자격증명 캐시가 켜져 있음 — mimikatz(sekurlsa/wdigest) 등으로 LSASS에서 평문 암호 추출 가능 (공격자 사전작업 흔적)".into()),
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()), ("source", "SYSTEM".into())]));
    } else if wd == "0" {
        rows.push(rf_row(&[
            ("category", "자격 증명 보호".into()),
            ("name", "WDigest UseLogonCredential".into()),
            ("value", "0 (사용 안 함)".into()),
            ("status", "정상".into()),
            ("detail", "WDigest 평문 자격증명 캐시 비활성".into()),
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()),
            ("source", "SYSTEM".into()),
        ]));
    } else {
        rows.push(rf_row(&[("category", "자격 증명 보호".into()), ("name", "WDigest UseLogonCredential".into()), ("value", "미설정 (기본값)".into()), ("status", "정보".into()),
            ("detail", "미설정 — 최신 Windows(8.1/2012 R2+)는 기본 비활성이나, 구버전이거나 값이 추가되면 평문 캐시가 켜질 수 있음".into()),
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()), ("source", "SYSTEM".into())]));
    }
    let ppl = reg_pick(system, "\\control\\lsa", "RunAsPPL");
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
            ("key_path", "…\\Control\\Lsa".into()),
            ("source", "SYSTEM".into()),
        ]));
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
    let start = reg_pick(system, "\\services\\lanmanserver", "Start");
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
        ]));
    }
    for (vname, role) in [
        ("AutoShareServer", "서버"),
        ("AutoShareWks", "워크스테이션"),
    ] {
        let auto = reg_pick(system, "\\lanmanserver\\parameters", vname);
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
            ]));
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    for r in system {
        if !r
            .get("key_path")
            .map(|k| k.to_lowercase().ends_with("\\lanmanserver\\shares"))
            .unwrap_or(false)
        {
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
        if r.get("value_name")
            .map(|v| v != "LoginMode")
            .unwrap_or(true)
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
        for r in &hive.rows {
            if r.get("value_name")
                .map(|v| v != "AppCompatCache")
                .unwrap_or(true)
            {
                continue;
            }
            let data = unhex(&r.get("value_data").cloned().unwrap_or_default());
            for (path, ft) in parse_shimcache(&data) {
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
                    ("timestamp", filetime(ft)),
                    (
                        "key_path",
                        "…\\Control\\Session Manager\\AppCompatCache".into(),
                    ),
                    ("source", "SYSTEM".into()),
                ]));
            }
        }
    }
    rows
}

pub fn build_registry_findings(out_dir: &Path) -> Vec<Row> {
    let registry = RegistryOverviewCache::load(out_dir);
    build_registry_findings_with_registry(&registry)
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
            by_key
                .entry(kp.as_str())
                .or_default()
                .insert(name, r.get("value_data").cloned().unwrap_or_default());
        }
        for (kp, props) in by_key {
            let display_name = props.get("DisplayName").cloned().unwrap_or_default();
            if display_name.is_empty() {
                continue;
            }
            let timestamp = props
                .get("InstallDate")
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
                ("value", props.get("DisplayVersion").cloned().unwrap_or_default()),
                ("detail", props.get("Publisher").cloned().unwrap_or_default()),
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
    rows.extend(rf_credential_protection(system));
    rows.extend(rf_shares(system));
    rows.extend(rf_sql_auth(software));
    rows.extend(rf_autoruns(registry.hives()));
    rows.extend(rf_msi_installs(registry.hives()));
    rows.extend(rf_execution_traces(registry.hives()));
    rows.extend(rf_shimcache(registry.hives()));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let rows = build_powershell_history(&root);
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
    fn smb_server_event_1009_is_retained_as_failure() {
        let root = std::env::temp_dir().join(format!("wina-smb-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("SMBServer.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE SMBServer (Provider TEXT, EventID TEXT, EventData TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO SMBServer VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "Microsoft-Windows-SMBServer",
                "1009",
                r#"{"EventData":{"ClientName":"\\\\192.0.2.15","UserName":"CONTOSO\\analyst"}}"#,
                "2026-08-21 10:00:00.000",
                "SMBServer.evtx::1009",
            ],
        )
        .unwrap();
        drop(conn);

        let rows = build_smb_history(&root);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            row.get("remote_address").map(String::as_str),
            Some("192.0.2.15")
        );
        assert_eq!(row.get("account").map(String::as_str), Some("analyst"));
        assert_eq!(row.get("result").map(String::as_str), Some("실패"));
        assert_eq!(
            row.get("description").map(String::as_str),
            Some("SMB 세션 인증 실패")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn browser_activity_marks_only_cache_rows_with_stored_recovered_bodies() {
        let root = std::env::temp_dir().join(format!(
            "wina-browser-cache-overview-{}",
            std::process::id()
        ));
        let browser_dir = root.join("BROWSER");
        std::fs::create_dir_all(&browser_dir).unwrap();
        let db_path = browser_dir.join("analyst_Chrome_Cache.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE CacheEntries (account TEXT, url TEXT, response_time TEXT, creation_time TEXT, content_length TEXT, body_size TEXT, content_type TEXT, status TEXT, cache_key TEXT, body_b64 TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO CacheEntries VALUES (?1, ?2, ?3, '', '12', '12', 'text/plain', '200 OK', 'cache-1', ?4)",
            rusqlite::params!["analyst", "https://example.test/recovered.txt", "2026-08-22 10:00:00.000", "aGVsbG8="],
        ).unwrap();
        conn.execute(
            "INSERT INTO CacheEntries VALUES (?1, ?2, ?3, '', '12', '12', 'text/plain', '200 OK', 'cache-2', '')",
            rusqlite::params!["analyst", "https://example.test/metadata-only.txt", "2026-08-22 10:00:01.000"],
        ).unwrap();
        drop(conn);

        let rows = build_browser_history(&root);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get("cache_body_recovered").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            rows[1].get("cache_body_recovered").map(String::as_str),
            Some("")
        );
        assert!(rows
            .iter()
            .all(|row| row.get("kind").map(String::as_str) == Some("cache")));
        std::fs::remove_dir_all(root).unwrap();
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
                vec![(
                    "\\Control\\Session Manager\\AppCompatCache",
                    "AppCompatCache",
                    "",
                    "2026-01-01 00:00:00.000",
                )],
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
            .map(|database| RegistryOverviewHive {
                name: database
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
                    .unwrap_or_default(),
                rows: read_table(&database, "Registry")
                    .into_iter()
                    .filter(is_live)
                    .collect(),
                database,
            })
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
        legacy.extend(rf_msi_installs(&legacy_hives));
        legacy.extend(rf_execution_traces(&legacy_hives));
        legacy.extend(rf_shimcache(&legacy_hives));
        let registry = RegistryOverviewCache::load(&root);
        assert_eq!(build_registry_findings_with_registry(&registry), legacy);
        assert_eq!(
            build_target_info(&root),
            build_target_info_with_registry(&registry),
            "sharing the overview cache must not alter TargetInfo rows"
        );
        assert_eq!(
            build_execution_history(&root),
            build_execution_history_with_registry(&root, &registry),
            "sharing the overview cache must not alter execution evidence rows"
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
                (
                    "live".to_string(),
                    "evidence/analyst_NTUSER.DAT".to_string()
                ),
            ]
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
