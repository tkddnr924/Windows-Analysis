//! _OVERVIEW correlation builders (port of processing.py + correlate.py). They
//! read the per-artifact SQLite the parse stage wrote (under CATEGORY/) and
//! produce the derived overview tables. Reading from disk (not an in-memory
//! all_results) keeps memory bounded for large hosts.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use des::Des;
use des::cipher::{BlockDecrypt, KeyInit as DesKeyInit};
use md5::Md5;
use md5::Digest;
use rc4::{Rc4, StreamCipher};

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
// pub: 0건에도 스키마를 만들 고정 컬럼 목록으로 write_ov에서도 쓴다.
pub const ST_KEYS: &[&str] = &[
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
    "last_run_time",
    "run_count",
    "last_run_result",
    "last_run_action",
    "_source_file",
    "_status",
    "_error",
];

/// TaskScheduler Operational 이벤트를 태스크 경로별로 집계한 실행 요약.
#[derive(Default)]
struct ScheduledTaskRuns {
    run_count: u64,
    last_run_time: String,
    last_result_time: String,
    last_result: &'static str,
    last_action_time: String,
    last_action: String,
    /// 129(CreatedTaskProcess)의 Path는 실제 생성된 프로세스라 200의
    /// ActionName(정의된 액션)보다 정확하다 — 한번 잡히면 200으로 덮지 않는다.
    last_action_exact: bool,
}

/// "\\Microsoft\\Windows\\...\\Foo"(이벤트 TaskName)와 "Microsoft\\Windows\\...\\Foo"
/// (XML uri — 선행 역슬래시 유무가 섞여 있음)를 같은 키로 만든다.
fn scheduled_task_key(name: &str) -> String {
    name.trim_start_matches('\\').trim().to_lowercase()
}

pub fn build_scheduled_tasks(out_dir: &Path) -> Vec<Row> {
    build_scheduled_tasks_with_events(out_dir, &EventLogOverviewCache::load(out_dir))
}

/// XML 정의 행에 TaskScheduler%4Operational 실행 기록을 태스크 경로로 조인해
/// "실제로 언제·몇 번·어떤 결과로 돌았고 무슨 프로세스를 만들었나"를 병합한다
/// — 정의(86건)와 실행 이력(수만 건)이 서로 연결되지 않던 갭(T5)의 해소.
/// 이벤트만 있고 XML 정의가 없는 태스크(삭제됨 등)는 여기 나타나지 않는다 —
/// 원본 이벤트는 EVENTLOG 테이블·통합 타임라인에 그대로 남는다.
pub fn build_scheduled_tasks_with_events(out_dir: &Path, events: &EventLogOverviewCache) -> Vec<Row> {
    let mut runs: std::collections::HashMap<String, ScheduledTaskRuns> =
        std::collections::HashMap::new();
    for r in events.rows() {
        if r.get("Provider").map(String::as_str) != Some("Microsoft-Windows-TaskScheduler") {
            continue;
        }
        let eid = r.get("EventID").map(String::as_str).unwrap_or("");
        // 100 시작 / 102 성공 / 101·103·111·202·203 실패 계열 / 129 프로세스
        // 생성 / 200 액션 시작 — 나머지(트리거·엔진 상태 등)는 요약에 불필요.
        if !matches!(
            eid,
            "100" | "101" | "102" | "103" | "111" | "129" | "200" | "202" | "203"
        ) {
            continue;
        }
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        let task = ed_field(&ed, &["TaskName"]);
        if task.is_empty() {
            continue;
        }
        let ts = r.get("timestamp").cloned().unwrap_or_default();
        let entry = runs.entry(scheduled_task_key(&task)).or_default();
        match eid {
            "100" => {
                entry.run_count += 1;
                if ts > entry.last_run_time {
                    entry.last_run_time = ts;
                }
            }
            "102" => {
                if ts >= entry.last_result_time {
                    entry.last_result_time = ts;
                    entry.last_result = "성공";
                }
            }
            "101" | "103" | "111" | "202" | "203" => {
                if ts >= entry.last_result_time {
                    entry.last_result_time = ts;
                    entry.last_result = "실패";
                }
            }
            "129" => {
                let path = ed_field(&ed, &["Path"]);
                if !path.is_empty() && (!entry.last_action_exact || ts >= entry.last_action_time) {
                    entry.last_action = path;
                    entry.last_action_time = ts;
                    entry.last_action_exact = true;
                }
            }
            "200" => {
                let action = ed_field(&ed, &["ActionName"]);
                if !action.is_empty() && !entry.last_action_exact && ts >= entry.last_action_time {
                    entry.last_action = action;
                    entry.last_action_time = ts;
                }
            }
            _ => {}
        }
    }

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
        // uri가 비어 있는 정의는 task_name(경로 아님)으로라도 대조한다 —
        // 루트 태스크("\Foo")는 이름과 경로가 사실상 같아 유효한 폴백.
        let key = if uri.is_empty() {
            scheduled_task_key(&r.get("task_name").cloned().unwrap_or_default())
        } else {
            scheduled_task_key(&uri)
        };
        if let Some(record) = runs.get(&key) {
            if !record.last_run_time.is_empty() {
                row.insert("last_run_time".into(), record.last_run_time.clone());
            }
            if record.run_count > 0 {
                row.insert("run_count".into(), record.run_count.to_string());
            }
            if !record.last_result.is_empty() {
                row.insert("last_run_result".into(), record.last_result.into());
            }
            if !record.last_action.is_empty() {
                row.insert("last_run_action".into(), record.last_action.clone());
            }
        }
        out.push(row);
    }
    out
}

// --- RdpCache ("RDP 캐시") — the reconstructed "fragment" rows only ---
pub const RC_KEYS: &[&str] = &[
    "kind",
    "account",
    "source_file",
    "fragment_index",
    "tile_count",
    "width",
    "height",
    "rows",
    "cols",
    "image",
    "_status",
    "_source_file",
];

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

// --- Defender ("Windows Defender") ---
pub const DEF_KEYS: &[&str] = &[
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
    "raw_line",
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

/// MPDetection 타임스탬프("2026-03-22T17:20:21.623")는 UTC — 다른 행들과
/// 같은 KST 표기로 변환한다 (실수집본 EVTX 대조로 +9h 확인).
fn mp_ts_kst(raw: &str) -> String {
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(raw, fmt) {
            return (dt + chrono::Duration::hours(9))
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string();
        }
    }
    raw.to_string()
}

/// Defender 지원 로그 MPDetection-*.log에서 DETECTION 라인만 threat 행으로
/// 만든다 (2026-08-31 사용자 확정: MPLog 제외, DETECTION만, EVTX 중복 허용 —
/// 다른 소스라 얻는 정보가 다르다는 판단). source 컬럼 "MPDetection"으로
/// 출처를 구분한다. 파일은 UTF-16LE(BOM) 또는 UTF-8.
pub fn defender_from_mpdetection(target: &Path) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut files: Vec<std::path::PathBuf> = walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| {
            p.file_name()
                .map(|n| {
                    let name = n.to_string_lossy().to_lowercase();
                    name.starts_with("mpdetection") && name.ends_with(".log")
                })
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    for path in files {
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let text = if raw.starts_with(&[0xFF, 0xFE]) {
            let units: Vec<u16> = raw[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        };
        for line in text.lines() {
            let Some((ts_raw, rest)) = line.trim().split_once(" DETECTION ") else {
                continue;
            };
            let (threat, resource) = match rest.trim().split_once(' ') {
                Some((a, b)) => (a.to_string(), b.trim().to_string()),
                None => (rest.trim().to_string(), String::new()),
            };
            if threat.is_empty() {
                continue;
            }
            let mut rec = def_row();
            rec.insert("section".into(), "threat".into());
            rec.insert("timestamp".into(), mp_ts_kst(ts_raw.trim()));
            rec.insert("title".into(), threat);
            rec.insert("detail".into(), resource);
            rec.insert("source".into(), "MPDetection".into());
            rec.insert("raw_line".into(), line.trim().to_string());
            rows.push(rec);
        }
    }
    rows
}

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

/// SmbClient 이벤트의 대상 "\\server\share" 또는 "\\server"에서 서버 부분만
/// 뽑는다 — SmbHistory의 remote_address(연결 상대)로 쓴다.
fn smb_target_server(name: &str) -> String {
    name.trim_start_matches('\\')
        .split('\\')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// SmbClient 이벤트 NTSTATUS 중 분석에서 판별 가치가 있는 값만 이름을 붙인다
/// — 나머지는 원문 숫자 없이 이벤트 설명만 남긴다(미주석 코드 나열 방지).
fn ntstatus_note(status: u64) -> Option<&'static str> {
    match status {
        0xC000_0022 => Some("접근 거부"),
        0xC000_006D => Some("로그온 실패"),
        0xC000_006A => Some("잘못된 비밀번호"),
        0xC000_0064 => Some("존재하지 않는 계정"),
        0xC000_0234 => Some("계정 잠김"),
        _ => None,
    }
}

pub fn build_smb_history(out_dir: &Path) -> Vec<Row> {
    build_smb_history_with_events(&EventLogOverviewCache::load(out_dir))
}

pub const SMB_KEYS: &[&str] = &[
    "timestamp",
    "direction",
    "remote_address",
    "account",
    "result",
    "description",
    "event_id",
    "provider",
    "record_key",
];

pub fn build_smb_history_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    let mut rows = Vec::new();
    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        let (mut remote, mut account, result, description, direction);
        if provider == "Microsoft-Windows-Security-Auditing" && (eid == "4624" || eid == "4625") {
            direction = "inbound";
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
            direction = "inbound";
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
        } else if provider.eq_ignore_ascii_case("Microsoft-Windows-SMBClient") {
            // SmbClient%4Security — 이 호스트가 클라이언트로서 원격 서버·공유에
            // 접근한 기록(아웃바운드). 이 채널에는 실패 계열만 남지만 "이
            // 호스트가 어디로 SMB 접속을 시도했는가"라는 횡적 이동의 방향
            // 정보를 준다. 대상(ShareName/ServerName)이 없는 행은 연결 상대를
            // 특정할 수 없어 아래 remote 공백 검사에서 걸러진다.
            direction = "outbound";
            let inner = match ed.get("EventData") {
                Some(serde_json::Value::Object(m)) => m.clone(),
                _ => ed.clone(),
            };
            let target = {
                let share = inner.get("ShareName").map(vstr).unwrap_or_default();
                if share.is_empty() {
                    inner.get("ServerName").map(vstr).unwrap_or_default()
                } else {
                    share
                }
            };
            remote = smb_target_server(&target);
            account = inner.get("UserName").map(vstr).unwrap_or_default();
            result = "실패".into();
            let what = match eid.as_str() {
                "31010" => "SMB 공유 접근 실패",
                "31001" => "SMB 서버 인증 실패",
                _ => "SMB 클라이언트 연결 실패",
            };
            let status_note = inner
                .get("Status")
                .map(vstr)
                .and_then(|value| value.trim().parse::<u64>().ok())
                .and_then(ntstatus_note);
            description = match status_note {
                Some(note) => format!("{what} ({target} — {note})"),
                None => format!("{what} ({target})"),
            };
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
        row.insert("direction".into(), direction.into());
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

pub const BITS_KEYS: &[&str] = &[
    "timestamp",
    "job_name",
    "job_id",
    "url",
    "account",
    "process",
    "bytes_transferred",
    "bytes_total",
    "status",
    "result",
    "description",
    "event_id",
    "record_key",
];

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

/// 방화벽 규칙·정책 변경 이력 — Windows Firewall With Advanced Security/Firewall
/// 채널(2004 추가, 2005 변경, 2006 삭제, 2033 전체 삭제, 2010 프로필 전환,
/// 2002·2003 설정 변경, 2011 수신 차단)과 Security 감사 이벤트(4946~4950,
/// 5025, 5031)를 한 테이블로 모은다. 새 정책(규칙) 등록이 핵심 증거다.
const FIREWALL_PROVIDER: &str = "Microsoft-Windows-Windows Firewall With Advanced Security";

fn fw_direction(raw: &str) -> String {
    match raw {
        "1" => "인바운드".into(),
        "2" => "아웃바운드".into(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn fw_action(raw: &str) -> String {
    // MS-FASP FW_RULE_ACTION: 1 AllowBypass, 2 Block, 3 Allow.
    match raw {
        "1" => "보안 허용".into(),
        "2" => "차단".into(),
        "3" => "허용".into(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn fw_protocol(raw: &str) -> String {
    match raw {
        "1" => "ICMP".into(),
        "2" => "IGMP".into(),
        "6" => "TCP".into(),
        "17" => "UDP".into(),
        "47" => "GRE".into(),
        "50" => "ESP".into(),
        "51" => "AH".into(),
        "58" => "ICMPv6".into(),
        "256" => "모든 프로토콜".into(),
        "" => String::new(),
        other => other.to_string(),
    }
}

fn fw_profiles(raw: &str) -> String {
    let Ok(mask) = raw.parse::<u32>() else {
        return raw.to_string();
    };
    if mask == 0x7FFF_FFFF {
        return "모든 프로필".into();
    }
    let mut parts = Vec::new();
    if mask & 1 != 0 {
        parts.push("도메인");
    }
    if mask & 2 != 0 {
        parts.push("개인");
    }
    if mask & 4 != 0 {
        parts.push("공용");
    }
    if parts.is_empty() {
        raw.to_string()
    } else {
        parts.join(", ")
    }
}

/// 프로필 값 하나를 표시명으로. 0은 "없음" (2010의 OldProfile 등).
fn fw_profile_name(raw: &str) -> String {
    if raw == "0" {
        return "없음".into();
    }
    fw_profiles(raw)
}

pub fn build_firewall_history(out_dir: &Path) -> Vec<Row> {
    build_firewall_history_with_events(out_dir, &EventLogOverviewCache::load(out_dir))
}

pub const FW_KEYS: &[&str] = &[
    "timestamp",
    "kind",
    "rule_name",
    "rule_id",
    "app_path",
    "service",
    "direction",
    "action",
    "protocol",
    "local_ports",
    "remote_ports",
    "profiles",
    "account",
    "modifying_app",
    "detail",
    "event_id",
    "provider",
    "record_key",
];

pub fn build_firewall_history_with_events(
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
    let mut rows = Vec::new();
    for r in events.rows() {
        let provider = r.get("Provider").cloned().unwrap_or_default();
        let eid = r.get("EventID").cloned().unwrap_or_default();
        let (kind, detail) = if provider == FIREWALL_PROVIDER {
            match eid.as_str() {
                "2004" => ("규칙 추가", "새 방화벽 규칙 등록"),
                "2005" => ("규칙 변경", "방화벽 규칙 수정"),
                "2006" => ("규칙 삭제", "방화벽 규칙 삭제"),
                "2033" => ("모든 규칙 삭제", "방화벽 규칙 일괄 삭제"),
                "2010" => ("프로필 전환", "네트워크 인터페이스 방화벽 프로필 변경"),
                "2002" | "2003" => ("설정 변경", "방화벽 설정 변경"),
                "2011" => ("수신 차단", "인바운드 수신 차단 알림"),
                _ => continue,
            }
        } else if provider == "Microsoft-Windows-Security-Auditing" {
            match eid.as_str() {
                "4946" => ("규칙 추가", "방화벽 예외 규칙 추가 (감사)"),
                "4947" => ("규칙 변경", "방화벽 예외 규칙 수정 (감사)"),
                "4948" => ("규칙 삭제", "방화벽 예외 규칙 삭제 (감사)"),
                "4950" => ("설정 변경", "방화벽 설정 변경 (감사)"),
                "5025" => ("서비스 중지", "Windows 방화벽 서비스 중지"),
                "5031" => ("수신 차단", "응용 프로그램 인바운드 수신 차단"),
                _ => continue,
            }
        } else {
            continue;
        };
        let ed = parse_eventdata(r.get("EventData").map(|s| s.as_str()).unwrap_or(""));
        // 이벤트별 실데이터 보강: 규칙 이름이 없는 이벤트(프로필 전환·설정
        // 변경)는 인터페이스/설정값 같은 관찰 데이터를 제목·설명으로 쓴다.
        let mut rule_name = ed_field(&ed, &["RuleName"]);
        let mut detail_text = detail.to_string();
        let mut profiles = fw_profiles(&ed_field(&ed, &["Profiles", "Profile", "ProfileChanged"]));
        if provider == FIREWALL_PROVIDER && eid == "2010" {
            let interface = ed_field(&ed, &["InterfaceName", "InterfaceGuid"]);
            let old_profile = fw_profile_name(&ed_field(&ed, &["OldProfile"]));
            let new_profile = fw_profile_name(&ed_field(&ed, &["NewProfile"]));
            if !interface.is_empty() {
                rule_name = interface;
            }
            if !new_profile.is_empty() {
                detail_text = if old_profile.is_empty() {
                    format!("적용 프로필 {}", new_profile)
                } else {
                    format!("적용 프로필 {} → {}", old_profile, new_profile)
                };
                profiles = new_profile;
            }
        } else if provider == FIREWALL_PROVIDER && (eid == "2002" || eid == "2003") {
            let setting = ed_field(&ed, &["Type", "SettingType"]);
            let value = ed_field(&ed, &["Value", "SettingValue"]);
            if !setting.is_empty() {
                rule_name = setting.clone();
                if !value.is_empty() {
                    detail_text = format!("{} = {}", setting, value);
                }
            }
        }
        // Security 감사 이벤트에는 ModifyingUser가 없다 — Subject 필드와
        // 이벤트 레코드의 UserID(SID)로 폴백해 변경 주체를 남긴다.
        let modifying_user = {
            let field = ed_field(&ed, &["ModifyingUser", "SubjectUserName", "SubjectUserSid"]);
            if field.is_empty() {
                r.get("UserID").cloned().unwrap_or_default()
            } else {
                field
            }
        };
        let account = if modifying_user.is_empty() {
            String::new()
        } else {
            account_for(&modifying_user)
        };
        let mut row = Row::new();
        row.insert(
            "timestamp".into(),
            r.get("timestamp").cloned().unwrap_or_default(),
        );
        row.insert("kind".into(), kind.to_string());
        row.insert("rule_name".into(), rule_name);
        row.insert("rule_id".into(), ed_field(&ed, &["RuleId"]));
        row.insert(
            "app_path".into(),
            ed_field(&ed, &["ApplicationPath", "Application"]),
        );
        row.insert("service".into(), ed_field(&ed, &["ServiceName"]));
        row.insert(
            "direction".into(),
            fw_direction(&ed_field(&ed, &["Direction"])),
        );
        row.insert("action".into(), fw_action(&ed_field(&ed, &["Action"])));
        row.insert(
            "protocol".into(),
            fw_protocol(&ed_field(&ed, &["Protocol"])),
        );
        row.insert(
            "local_ports".into(),
            ed_field(&ed, &["LocalPorts", "LocalPort", "Port"]),
        );
        row.insert(
            "remote_ports".into(),
            ed_field(&ed, &["RemotePorts", "RemotePort"]),
        );
        row.insert("profiles".into(), profiles);
        row.insert("account".into(), account);
        row.insert(
            "modifying_app".into(),
            ed_field(&ed, &["ModifyingApplication"]),
        );
        row.insert("detail".into(), detail_text);
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
    const CORE: &str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";
    match (provider, eid) {
        // RdpCoreTS 131 — 전송 계층 연결 수립. ClientIP에 소스 IP·포트가
        // 인증 이전 단계부터 남아 기존 TerminalServices 로그보다 상세하다.
        (CORE, "131") => s(
            "inbound",
            "성공",
            "RDP 전송 계층 연결 수립",
            &["ClientIP"],
            &[],
            false,
        ),
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

/// RemoteDesktopHistory 파생 테이블의 고정 컬럼 (0건 스키마 생성용).
pub const RDP_KEYS: &[&str] = &[
    "timestamp",
    "account",
    "description",
    "direction",
    "event_id",
    "provider",
    "remote_address",
    "result",
    "record_key",
];

pub fn build_remote_desktop_history(out_dir: &Path) -> Vec<Row> {
    build_remote_desktop_history_with_events(&EventLogOverviewCache::load(out_dir))
}

/// RdpCoreTS ClientIP는 "ip:port" 또는 "[ip]:port" 형태다. 원격 접근
/// 이력·호스트 연결 그래프의 피어 매칭은 IP 문자열 기준이라 포트를 떼어낸다.
/// 대괄호 없는 IPv6(콜론 여러 개)는 그대로 둔다.
fn strip_client_port(addr: &str) -> String {
    let addr = addr.trim();
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    if addr.matches(':').count() == 1 {
        return addr.split(':').next().unwrap_or("").to_string();
    }
    addr.to_string()
}

pub fn build_remote_desktop_history_with_events(events: &EventLogOverviewCache) -> Vec<Row> {
    const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    let mut rows: Vec<Row> = Vec::new();
    // (행 인덱스, 로그 출처, SessionID) — 세션 상관은 (출처, SessionID)로 묶고
    // 증거 시간순 전방 전파만 한다. Windows SessionID는 재사용되고 서로 다른
    // 수집 로그에도 같은 값이 있으므로, 전역 최종값 역전파는 이전 세션 행에
    // 이후 사용자의 IP·계정을 붙이는 허위 상관을 만든다.
    let mut lsm_pending: Vec<(usize, String, String)> = Vec::new();

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
        let addr = if provider == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" {
            strip_client_port(&addr)
        } else {
            addr
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
            // 출처(수집 로그) = EventLog record_key의 테이블 부분. 출처가 없는
            // 행은 세션 상관에서 제외한다(빈 값 보존).
            let source = r
                .get("_record_key")
                .and_then(|key| key.split("::").next())
                .unwrap_or("")
                .to_string();
            if let Some(skey) = skey {
                if !source.is_empty() {
                    lsm_pending.push((rows.len() - 1, source, skey));
                }
            }
        }
    }

    // (출처, SessionID) 그룹별로 증거 시간순 전방 전파 — 로그온(21)/재연결(25)
    // 등에서 얻은 IP·계정을 같은 세션 구간의 후속 이벤트에만 채우고, 세션 종료
    // 이벤트(23/24/39/40) 뒤에는 상태를 폐기한다. 시간 없는 행은 순서를 정할 수
    // 없어 전파 대상에서 제외한다(빈 값 보존).
    let mut session_groups: std::collections::HashMap<(String, String), Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, source, skey) in lsm_pending {
        session_groups.entry((source, skey)).or_default().push(idx);
    }
    const SESSION_END_IDS: [&str; 4] = ["23", "24", "39", "40"];
    for indices in session_groups.values_mut() {
        // 같은 시각은 원본(rowid) 순서 유지 — 안정 정렬.
        indices.sort_by(|&a, &b| {
            rows[a]
                .get("timestamp")
                .cmp(&rows[b].get("timestamp"))
                .then(a.cmp(&b))
        });
        let mut state: [Option<String>; 2] = [None, None];
        for &i in indices.iter() {
            let has_time = rows[i]
                .get("timestamp")
                .map(|t| !t.is_empty())
                .unwrap_or(false);
            if !has_time {
                continue;
            }
            for (slot, field) in [(0usize, "remote_address"), (1usize, "account")] {
                let value = rows[i].get(field).cloned().unwrap_or_default();
                if !value.is_empty() {
                    state[slot] = Some(value);
                } else if let Some(known) = &state[slot] {
                    rows[i].insert(field.into(), known.clone());
                }
            }
            let eid = rows[i].get("event_id").cloned().unwrap_or_default();
            if SESSION_END_IDS.contains(&eid.as_str()) {
                state = [None, None];
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

/// RegBack 백업 하이브 산출물(`<이름>_RegBack[.uniq].sqlite`) 여부 — facts에는
/// 보존하되 파생 뷰 입력에서는 제외한다. 라이브 하이브와 섞으면 오래된 값이
/// 현재 상태처럼 이중 표시되기 때문 (2026-08-31 사용자 확정).
fn is_regback_output(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let trimmed = match stem.rsplit_once('_') {
        Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => stem.as_str(),
    };
    trimmed.ends_with("_regback")
}

// PowerShell history
fn read_registry_all(out_dir: &Path) -> Vec<Row> {
    let dir = out_dir.join("REGISTRY");
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "sqlite").unwrap_or(false))
            .filter(|p| !is_regback_output(p))
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
/// PowerShellHistory 파생 테이블의 고정 컬럼 — 0건에도 스키마를 만들 수
/// 있게 발행 측(write_ov)이 사용한다. script_block_status는 분할 4104가
/// 불완전할 때만 값이 생기는 상태 컬럼이다.
pub const PS_KEYS: &[&str] = &[
    "timestamp",
    "account",
    "process",
    "process_id",
    "command",
    "script_block",
    "host_application",
    "kind",
    "event_id",
    "provider",
    "script_path",
    "record_key",
    "script_block_status",
];

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
    // 재조합 중인 분할 ScriptBlock — 완전성 검증을 위해 기대 조각 수와
    // 이상(누락·중복·범위 밖·총수 불일치)을 함께 추적한다. EVTX 손상·유실로
    // 조각이 빠져도 최선의 본문은 남기되 불완전함을 표시해, 잘린 문자열이
    // 완전한 원문으로 오인되지 않게 한다.
    struct ScriptBlockParts {
        parts: std::collections::BTreeMap<i64, String>,
        timestamp: String,
        sid: String,
        pid: String,
        record_key: String,
        path: String,
        expected_total: i64,
        anomalies: Vec<String>,
    }
    let mut block_keys: Vec<String> = Vec::new();
    let mut blocks: std::collections::HashMap<String, ScriptBlockParts> =
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
                        ScriptBlockParts {
                            parts: std::collections::BTreeMap::new(),
                            timestamp: ts.clone(),
                            sid: sid.clone(),
                            pid: pid.clone(),
                            record_key: rk.clone(),
                            path: path.clone(),
                            expected_total: total,
                            anomalies: Vec::new(),
                        },
                    );
                }
                let slot = blocks.get_mut(&sbid).unwrap();
                if total != slot.expected_total {
                    let note = format!(
                        "총 조각 수 불일치({} vs {})",
                        slot.expected_total, total
                    );
                    if !slot.anomalies.contains(&note) {
                        slot.anomalies.push(note);
                    }
                }
                if num < 1 || num > slot.expected_total.max(total) {
                    slot.anomalies.push(format!("범위 밖 조각 번호 {}", num));
                }
                match slot.parts.get(&num) {
                    // 같은 번호가 다른 내용으로 오면 어느 쪽이 진짜인지 알 수
                    // 없다 — 나중 값을 쓰되 이상으로 남긴다. 동일 내용 중복은
                    // 로그 중복 수집의 정상 잔상이라 조용히 무시한다.
                    Some(existing) if *existing != text => {
                        slot.anomalies.push(format!("조각 {} 중복(내용 상이)", num));
                        slot.parts.insert(num, text);
                    }
                    Some(_) => {}
                    None => {
                        slot.parts.insert(num, text);
                    }
                }
                if !ts.is_empty() && (slot.timestamp.is_empty() || ts < slot.timestamp) {
                    slot.timestamp = ts.clone();
                    slot.record_key = rk.clone();
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
            for value in ed.values() {
                all_strings(value, &mut strs);
            }
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
        } else if provider == "PowerShell" && (event_id == "400" || event_id == "403") {
            // 엔진 수명주기 — 400 시작(Available)/403 종료(Stopped). 명령은 없지만
            // HostApplication이 실행 주체를 남기는 독립 증거다.
            let mut strs = Vec::new();
            for value in ed.values() {
                all_strings(value, &mut strs);
            }
            let blob = strs.join("\n");
            let host = find_token(&blob, "HostApplication=");
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
            rows.push(ps_row(
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
            ));
        } else if provider == "PowerShell" && event_id == "600" {
            // 공급자 시작은 세션마다 여러 건 나와 시끄럽다 — 원격(WinRM) 사용
            // 흔적인 WSMan 공급자만 남긴다.
            let mut strs = Vec::new();
            for value in ed.values() {
                all_strings(value, &mut strs);
            }
            let blob = strs.join("\n");
            let provider_name = {
                let token = find_token(&blob, "ProviderName=");
                if token.is_empty() {
                    strs.first().cloned().unwrap_or_default()
                } else {
                    token
                }
            };
            if !provider_name.eq_ignore_ascii_case("wsman") {
                continue;
            }
            let host = find_token(&blob, "HostApplication=");
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
            ));
        } else if provider == "Microsoft-Windows-PowerShell" && event_id == "40961" {
            // 콘솔 시작 — 클래식 400과 달리 UserID(SID)가 남는 실행 증거.
            rows.push(ps_row(
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
            ));
        }
    }

    for k in &block_keys {
        let slot = &blocks[k];
        let text: String = slot.parts.values().cloned().collect();
        let missing: Vec<String> = (1..=slot.expected_total)
            .filter(|n| !slot.parts.contains_key(n))
            .map(|n| n.to_string())
            .collect();
        let mut anomalies = slot.anomalies.clone();
        if !missing.is_empty() {
            anomalies.push(format!("누락 조각: {}", missing.join(",")));
        }
        let mut row = ps_row(
            &slot.timestamp,
            &account_for(&slot.sid),
            "powershell.exe",
            &slot.pid,
            "",
            &text,
            "",
            "스크립트 블록",
            "4104",
            "Microsoft-Windows-PowerShell",
            &slot.path,
            &slot.record_key,
        );
        if !anomalies.is_empty() {
            row.insert(
                "script_block_status".into(),
                format!("불완전 — {}", anomalies.join(" · ")),
            );
        }
        rows.push(row);
    }

    // PSReadLine ConsoleHost_history — 사용자가 콘솔에 입력한 명령 원문.
    // 파일에 시각이 없으므로 timestamp는 비워 두고(뷰의 "시간 정보 없음"
    // 구역으로 분리 표시) 입력 순서는 line_number로 보존한다.
    let console_db = out_dir
        .join("POWERSHELL")
        .join("PowerShell_ConsoleHistory.sqlite");
    let mut console_rows = read_table_with_rowid(&console_db, "PowerShell_ConsoleHistory");
    console_rows.sort_by(|a, b| {
        let user_a = a.get("user").map(String::as_str).unwrap_or("");
        let user_b = b.get("user").map(String::as_str).unwrap_or("");
        let line = |r: &Row| {
            r.get("line_number")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(i64::MAX)
        };
        user_a.cmp(user_b).then(line(a).cmp(&line(b)))
    });
    for r in console_rows {
        let command = r.get("command").cloned().unwrap_or_default();
        if command.trim().is_empty() {
            continue;
        }
        let account = r.get("user").cloned().unwrap_or_default();
        let record_key = r
            .get("__source_rowid")
            .map(|rowid| format!("PowerShell_ConsoleHistory::{rowid}"))
            .unwrap_or_default();
        let mut row = ps_row(
            "",
            &account,
            "powershell.exe",
            "",
            &first_line(&command, 400),
            "",
            "",
            "콘솔 히스토리",
            "",
            "PSReadLine",
            "",
            &record_key,
        );
        row.insert(
            "line_number".into(),
            r.get("line_number").cloned().unwrap_or_default(),
        );
        rows.push(row);
    }
    rows
}

// --- BrowserActivity ("BrowserActivity") — visits + downloads + cache ---
pub const BH_KEYS: &[&str] = &[
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

/// 파일 stem에서 첫 번째로 맞는 접미를 떼어 계정명을 복원한다 — 산출물
/// 이름이 `<계정>[_<브라우저>][_Cache]` 꼴이므로(T8 브라우저 표기), 접미
/// 목록에는 브라우저 변형 전부가 들어온다.
fn browser_sources(
    out_dir: &Path,
    category: &str,
    suffixes: &[&str],
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
            let account = suffixes
                .iter()
                .find_map(|suffix| stem.strip_suffix(suffix))
                .unwrap_or(&stem)
                .to_string();
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

/// IE 방문 URL은 "Visited: <계정>@<URL>" 또는 "<계정>@<URL>" 형태로
/// 저장된다 — 표시·도메인 집계용 url은 실제 URL만 남긴다 (원문은 url_raw).
/// ftp://user@host 처럼 '@' 앞에 스킴·경로가 있는 정상 URL은 건드리지 않는다.
fn ie_visit_url(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("Visited:").map(str::trim).unwrap_or(s);
    match s.split_once('@') {
        Some((head, rest)) if !head.contains('/') && !head.contains(':') => rest.to_string(),
        _ => s.to_string(),
    }
}

/// iedownload 메타데이터(" | " 구분 세그먼트)에서 원본 URL을 찾는다.
/// http(s) 세그먼트가 없으면 원래 값(iedownload:{GUID})을 그대로 쓴다.
fn ie_download_url(metadata: &str, fallback: &str) -> String {
    match metadata.rfind("http") {
        Some(at) => metadata[at..]
            .split(" | ")
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        None => fallback.to_string(),
    }
}

pub fn build_browser_history(out_dir: &Path) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    // Cached HTTP responses (BrowserCache) — empty when no cache artifact present.
    for (account, db) in browser_sources(
        out_dir,
        "BROWSER",
        &["_Chrome_Cache", "_Edge_Cache", "_Whale_Cache", "_Unknown_Cache"],
    ) {
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
    // "_Chrome_History"는 Python 시절 산출물 접미(하위 호환).
    for (account, db) in browser_sources(
        out_dir,
        "BROWSER",
        &["_Chrome_History", "_Chrome", "_Edge", "_Whale"],
    ) {
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
    // IE10+/구형 Edge WebCache — History 컨테이너의 방문과 iedownload 항목.
    for (account, db) in browser_sources(out_dir, "BROWSER", &["_IE_WebCache"]) {
        for h in read_table(&db, "IEWebCache_History") {
            let g = |k: &str| h.get(k).cloned().unwrap_or_default();
            let raw = g("url");
            let url = ie_visit_url(&raw);
            let ts = g("accessed_time");
            if url.is_empty() || ts.is_empty() {
                continue;
            }
            let acct = {
                let a = g("account");
                if !a.is_empty() { a } else { account.clone() }
            };
            let count = g("access_count");
            rows.push(bh_row(&[
                ("account", acct),
                ("kind", "visit".into()),
                ("timestamp", ts),
                ("url", url_decode(&url)),
                ("url_raw", raw),
                (
                    "visit_count",
                    if count.is_empty() || count == "0" { String::new() } else { count },
                ),
            ]));
        }
        for d in read_table(&db, "IEWebCache_Downloads") {
            let g = |k: &str| d.get(k).cloned().unwrap_or_default();
            let ts = {
                let a = g("accessed_time");
                if !a.is_empty() { a } else { g("modified_time") }
            };
            if ts.is_empty() {
                continue;
            }
            let acct = {
                let a = g("account");
                if !a.is_empty() { a } else { account.clone() }
            };
            let url = ie_download_url(&g("metadata"), &g("url"));
            rows.push(bh_row(&[
                ("account", acct),
                ("kind", "download".into()),
                ("timestamp", ts),
                ("title", basename_win(&url_decode(&url))),
                ("url", url_decode(&url)),
                ("url_raw", g("url")),
                ("source_url", url_decode(&url)),
            ]));
        }
    }
    // IE5~9 index.dat — History 컨테이너(MSHist·History.IE5)의 방문 기록.
    // Content(캐시)·Cookies 컨테이너는 원본 테이블에서 본다.
    for (account, db) in browser_sources(out_dir, "BROWSER", &["_IE_IndexDat"]) {
        for r in read_table(&db, "IEIndexDat_Records") {
            let g = |k: &str| r.get(k).cloned().unwrap_or_default();
            if !g("container").to_lowercase().contains("hist") {
                continue;
            }
            let raw = g("url");
            let url = ie_visit_url(&raw);
            let ts = {
                let a = g("accessed_time");
                if !a.is_empty() { a } else { g("modified_time") }
            };
            if url.is_empty() || ts.is_empty() {
                continue;
            }
            let acct = {
                let a = g("account");
                if !a.is_empty() { a } else { account.clone() }
            };
            let hits = g("hits");
            rows.push(bh_row(&[
                ("account", acct),
                ("kind", "visit".into()),
                ("timestamp", ts),
                ("url", url_decode(&url)),
                ("url_raw", raw),
                (
                    "visit_count",
                    if hits.is_empty() || hits == "0" { String::new() } else { hits },
                ),
            ]));
        }
    }
    rows
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
    "ntlm_hash",
    "ntlm_hash_status",
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
        for line in text.lines() {
            // '#' 이후는 주석 — 줄 중간 주석도 잘라낸다.
            let line = line.split('#').next().unwrap_or("").trim();
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

const BOOTKEY_PERMUTE: [usize; 16] = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7];
const QWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const DIGITS: &[u8] = b"0123456789012345678901234567890123456789\0";
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";
const V_DATA_OFFSET: usize = 0xCC;

fn to_hex_lower(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn set_odd_parity(key: u8) -> u8 {
    let mut ones = 0u8;
    let mut v = key;
    v &= 0xfe;
    for _ in 0..7 {
        ones ^= v & 1;
        v >>= 1;
    }
    key & 0xfe | (ones ^ 1)
}

fn des_transform_key(input: &[u8; 7]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = input[0] >> 1;
    out[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2);
    out[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3);
    out[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4);
    out[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5);
    out[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6);
    out[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7);
    out[7] = input[6] & 0x7f;
    for item in &mut out {
        *item = set_odd_parity(*item);
    }
    out
}

fn derive_des_keys(base_key: &[u8]) -> Option<([u8; 8], [u8; 8])> {
    if base_key.len() < 4 {
        return None;
    }
    let rid = base_key.get(0..4)?;
    let i = [rid[0], rid[1], rid[2], rid[3]];
    let key1 = [i[0], i[1], i[2], i[3], i[0], i[1], i[2]];
    let key2 = [i[3], i[0], i[1], i[2], i[3], i[0], i[1]];
    Some((des_transform_key(&key1), des_transform_key(&key2)))
}

fn rc4_xor(mut data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    // SAM/NTLM 경로의 RC4 키는 항상 md5_16 출력(16바이트)이라 U16으로 고정한다.
    let Ok(mut cipher) = Rc4::<rc4::consts::U16>::new_from_slice(key) else {
        return Vec::new();
    };
    cipher.apply_keystream(&mut data);
    data
}

fn md5_16(data: &[u8]) -> Vec<u8> {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().to_vec()
}

fn aes_cbc_decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Vec<u8> {
    if key.len() != 16 || iv.len() != 16 || !data.len().is_multiple_of(16) {
        return Vec::new();
    }
    let Ok(cipher) = Decryptor::<Aes128>::new_from_slices(key, iv) else {
        return Vec::new();
    };
    let mut buf = data.to_vec();
    let Ok(plain) = cipher.decrypt_padded_mut::<NoPadding>(&mut buf) else {
        return Vec::new();
    };
    plain.to_vec()
}

fn des_ecb_decrypt(key: &[u8; 8], data: &[u8]) -> Vec<u8> {
    if data.len() != 8 {
        return Vec::new();
    }
    let Ok(c) = Des::new_from_slice(key) else {
        return Vec::new();
    };
    let mut block = des::cipher::generic_array::GenericArray::clone_from_slice(data);
    c.decrypt_block(&mut block);
    block.to_vec()
}

fn bootkey_permute(raw: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = raw[BOOTKEY_PERMUTE[i]];
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

impl RegistryOverviewHive {
    /// 원본 3-요소 record_key(`<파일>::Registry::<rowid>`)를 각 행에 미리
    /// 새겨 둔다 — rf_* 판정 함수들이 시그니처 변경 없이 매칭 행에서 증거
    /// 키를 파생 행으로 옮겨 담아, 개요 북마크가 원본 Registry 레코드로
    /// 승격될 수 있게 한다.
    fn load(database: std::path::PathBuf) -> Self {
        let mut rows: Vec<Row> = read_table_with_rowid(&database, "Registry")
            .into_iter()
            .filter(is_live)
            .collect();
        for row in rows.iter_mut() {
            let key = source_record_key(&database, "Registry", row);
            if !key.is_empty() {
                row.insert("__record_key".into(), key);
            }
        }
        Self {
            name: database
                .file_stem()
                .map(|stem| stem.to_string_lossy().to_string())
                .unwrap_or_default(),
            rows,
            database,
        }
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
    pub fn load(out_dir: &Path) -> Self {
        let dir = out_dir.join("REGISTRY");
        let mut files: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "sqlite")
                })
                .filter(|path| !is_regback_output(path))
                .collect(),
            Err(_) => return Self { hives: Vec::new() },
        };
        files.sort();
        let hives = files.into_iter().map(RegistryOverviewHive::load).collect();
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

fn nt_hash_from_v(v: &[u8], hashed_boot_key: &[u8], rid: u32) -> (String, String) {
    if v.len() < V_DATA_OFFSET + 0xB4 {
        return (String::new(), "V 블롭 크기 부족".to_string());
    }
    let lm_offset = le_u32(v, V_DATA_OFFSET + 0xA0) as usize;
    let lm_len = le_u32(v, V_DATA_OFFSET + 0xA4) as usize;
    let nt_offset = le_u32(v, V_DATA_OFFSET + 0xAC) as usize;
    let nt_len = le_u32(v, V_DATA_OFFSET + 0xB0) as usize;
    let nt_start = V_DATA_OFFSET + nt_offset;
    let nt_end = nt_start.saturating_add(nt_len);
    if nt_len < 20 || nt_start >= v.len() || nt_end > v.len() {
        return (String::new(), "NTHash 범위 오류".to_string());
    }
    // 유효한 파싱 상태인지 확인하기 위해 LMHash 길이도 확인한다(항목 동기성 유지).
    if lm_len > 0 && lm_offset >= v.len() {
        return (String::new(), "LMHash 범위 오류".to_string());
    }
    let nt_blob = &v[nt_start..nt_end];
    if nt_blob.len() < 20 {
        return (String::new(), "NTHash 블롭 길이 부족".to_string());
    }
    if hashed_boot_key.len() < 16 {
        return (String::new(), "hashedBootKey 미확인".to_string());
    }

    let is_new_style = if nt_blob.len() > 2 {
        nt_blob[2] != 0x01
    } else {
        false
    };

    let mut key = if !is_new_style {
        let hash = nt_blob.get(4..20).unwrap_or_default();
        if hash.len() != 16 {
            return (String::new(), "SAM_HASH 크기 오류".to_string());
        }
        let mut hash = hash.to_vec();
        let rc4_key = md5_16(&[
            &hashed_boot_key[..16],
            &rid.to_le_bytes(),
            NTPASSWORD,
        ]
        .concat());
        hash = rc4_xor(hash, &rc4_key);
        hash
    } else {
        if nt_blob.len() < 20 {
            return (String::new(), "NTHASH new-style 블롭 부족".to_string());
        }
        let salt = &nt_blob[12..28];
        let data_offset = le_u32(nt_blob, 8) as usize;
        let data_start = 8 + data_offset;
        if data_start >= nt_blob.len() {
            return (String::new(), "NTHASH new-style 오프셋 오류".to_string());
        }
        let dec = aes_cbc_decrypt(&hashed_boot_key[..16], &nt_blob[data_start..], salt);
        if dec.len() < 16 {
            return (String::new(), "NTHASH new-style AES 복호화 실패".to_string());
        }
        dec
    };
    if key.len() < 16 {
        return (String::new(), "복호화 키 생성 실패".to_string());
    }
    key.truncate(16);
    let (k1, k2) = match derive_des_keys(&rid.to_le_bytes()) {
        Some(v) => v,
        None => return (String::new(), "RID 기반 DES 키 생성 실패".to_string()),
    };
    let d1 = des_ecb_decrypt(&k1, &key[0..8]);
    let d2 = des_ecb_decrypt(&k2, &key[8..16]);
    if d1.len() != 8 || d2.len() != 8 {
        return (String::new(), "NTHash DES 복호화 실패".to_string());
    }
    (to_hex_lower(&[d1, d2].concat()), "복호화 완료".to_string())
}

fn get_bootkey_from_system(system: &[Row]) -> [u8; 16] {
    let cs = active_control_set(system);
    let mut chunks: Vec<u8> = Vec::new();
    let mut keys = Vec::new();
    for p in [
        ("\\control\\lsa\\jd", 0usize),
        ("\\control\\lsa\\skew1", 1),
        ("\\control\\lsa\\gbg", 2),
        ("\\control\\lsa\\data", 3),
    ] {
        let rows = reg_pick_exact_path(
            system,
            &(cs.to_lowercase() + p.0),
            &[
                "(default)",
                "",
                "jd",
                "skew1",
                "gbg",
                "data",
                "skewmatrix",
                "lookup",
                "grafblumgroup",
                "pattern",
            ],
        );
        let mut part = None;
        for r in rows {
            if let Some(v) = r.get("value_data") {
                let bytes = unhex(v);
                if bytes.len() >= 4 {
                    part = Some(bytes[..4.min(bytes.len())].to_vec());
                    break;
                }
            }
        }
        if let Some(v) = part {
            keys.push((p.1, v));
        } else {
            return [0u8; 16];
        }
    }
    keys.sort_by_key(|(i, _)| *i);
    for (_, b) in keys {
        chunks.extend_from_slice(&b);
    }
    if chunks.len() != 64 {
        return [0u8; 16];
    }
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&chunks[..16]);
    bootkey_permute(raw)
}

fn get_hashed_boot_key(system: &[Row], sam: &[Row]) -> Vec<u8> {
    let boot_key = get_bootkey_from_system(system);
    if boot_key == [0u8; 16] {
        return Vec::new();
    }
    let f = pick_sam_f(sam);
    if f.is_empty() || f.len() < 0x6c + 1 {
        return Vec::new();
    }
    let key0 = &f[0x6c..];
    if key0.is_empty() {
        return Vec::new();
    }
    let (hbk, _) = parse_sam_hashed_bootkey(&boot_key, key0);
    hbk
}

fn reg_pick_exact_path<'a>(rows: &'a [Row], key_suffix: &str, value_names: &[&str]) -> Vec<&'a Row> {
    let ks = key_suffix.to_lowercase();
    rows.iter()
        .filter(|r| {
            let kp = r.get("key_path").map(String::as_str).unwrap_or("");
            let vn = r.get("value_name").map(String::as_str).unwrap_or("");
            kp.to_lowercase().ends_with(&ks)
                && !r.get("value_data").map(String::as_str).unwrap_or("").is_empty()
                && value_names
                    .iter()
                    .any(|n| vn.eq_ignore_ascii_case(n) || (vn.is_empty() && n.is_empty()))
        })
        .collect()
}

fn pick_sam_f(sam: &[Row]) -> Vec<u8> {
    let mark = "\\sam\\domains\\account\\f";
    reg_pick_row(sam, mark, "(default)")
        .or_else(|| reg_pick_row(sam, mark, ""))
        .or_else(|| reg_pick_row(sam, mark, "F"))
        .and_then(|r| r.get("value_data").map(|v| unhex(v)))
        .unwrap_or_default()
}

fn parse_sam_hashed_bootkey(boot_key: &[u8], key0: &[u8]) -> (Vec<u8>, String) {
    if key0.is_empty() {
        return (Vec::new(), "Key0 없음".to_string());
    }
    if key0[0] == 0x01 {
        if key0.len() < 0x3C {
            return (Vec::new(), "Key0 v1 길이 부족".to_string());
        }
        let salt = &key0[8..24];
        let key = &key0[24..40];
        let checksum = &key0[40..56];
        let rc4_key = md5_16(&[salt, QWERTY, boot_key, DIGITS].concat());
        let crypt = {
            let mut merged = Vec::new();
            merged.extend_from_slice(key);
            merged.extend_from_slice(checksum);
            rc4_xor(merged, &rc4_key)
        };
        if crypt.len() < 32 {
            return (Vec::new(), "Key0 v1 복호화 실패".to_string());
        }
        let expect = md5_16(&[
            &crypt[0..16],
            DIGITS,
            &crypt[0..16],
            QWERTY,
        ]
        .concat());
        if expect.as_slice() != &crypt[16..32] {
            return (
                Vec::new(),
                "hashedBootKey checksum mismatch(시작 암호 여부 후보)".to_string(),
            );
        }
        (crypt[..16].to_vec(), String::new())
    } else if key0[0] == 0x02 {
        if key0.len() < 0x24 {
            return (Vec::new(), "Key0 v2 헤더 부족".to_string());
        }
        let data_len = le_u32(key0, 12) as usize;
        if boot_key.len() < 16 {
            return (Vec::new(), "SYSTEM bootkey 부족".to_string());
        }
        let salt = &key0[16..32];
        let key_data = if key0.len() < 32 + data_len {
            return (Vec::new(), "Key0 v2 데이터 길이 부족".to_string());
        } else {
            &key0[32..32 + data_len]
        };
        let dec = aes_cbc_decrypt(&boot_key[..16], key_data, salt);
        if dec.is_empty() {
            return (Vec::new(), "Key0 v2 AES 복호화 실패".to_string());
        }
        (dec[..16.min(dec.len())].to_vec(), String::new())
    } else {
        (Vec::new(), "지원되지 않는 Key0 타입".to_string())
    }
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

fn ti_accounts(sam: &[Row], software: &[Row], system: &[Row], _security: &[Row]) -> Vec<Row> {
    let hashed_boot_key = get_hashed_boot_key(system, sam);
    let hidden = special_accounts(software);
    let mut prefix = String::new();
    let mut profile_keys: Vec<String> = Vec::new();
    let mut profiles: HashMap<String, String> = HashMap::new();
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
        let (ntlm_hash, ntlm_hash_status) = if hashed_boot_key.is_empty() {
            (
                String::new(),
                "hashedBootKey 미확인".to_string(),
            )
        } else {
            let rid = rid.to_le_bytes();
            nt_hash_from_v(vb, &hashed_boot_key, u32::from_le_bytes(rid))
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
            ("ntlm_hash", ntlm_hash),
            ("ntlm_hash_status", ntlm_hash_status),
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
            let name = r.get("value_name").cloned().unwrap_or_default();
            if name.eq_ignore_ascii_case("ProfileName") {
                e.0 = r.get("value_data").cloned().unwrap_or_default();
            } else if name.eq_ignore_ascii_case("DateLastConnected") {
                e.1 = systemtime_hex(&r.get("value_data").cloned().unwrap_or_default());
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
    let security = registry.rows("SECURITY");
    let mut rows = Vec::new();
    rows.extend(ti_system_info(software, system));
    rows.extend(ti_accounts(sam, software, system, security));
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
            .filter(|p| !is_regback_output(p))
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
    // ShimCache(AppCompatCache)는 여기 넣지 않는다 — 항목의 FILETIME은 대상
    // 파일의 수정 시각이지 실행 시각이 아니므로 실행 이력·타임라인 증거로
    // 부적합(v0.9.35 확정 결정). RegistryFindings(기타 레지스트리/ShimCache)
    // 에서 그 단서와 함께 표시한다.
    rows.extend(eh_from_prefetch(out_dir));
    rows.extend(eh_from_timeline(out_dir));
    rows
}

/// Windows Timeline의 실행/열기(ActivityType 5) 활동을 실행 이력에 합류시킨다.
/// 포커스(6)·클립보드 등 나머지 유형은 실행 기록이 아니므로 원본 테이블
/// (TIMELINE/Timeline_Activities)에서만 본다.
fn eh_from_timeline(out_dir: &Path) -> Vec<Row> {
    let mut rows = Vec::new();
    let db = out_dir
        .join("TIMELINE")
        .join("Timeline_Activities.sqlite");
    for r in read_table_with_rowid(&db, "Timeline_Activities") {
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
    rows
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
        if path_len >= 2 && path_off >= SHIM_NT61_HEADER && path_off + path_len <= data.len() {
            let u16s: Vec<u16> = data[path_off..path_off + path_len]
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
            ("key_path", "…\\Control\\SecurityProviders\\WDigest".into()), ("source", "SYSTEM".into())]));
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
            ("key_path", "…\\Control\\Lsa".into()),
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
        ("key_path", "…\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging".into()),
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

/// 원격제어(RMM) 도구 설치 흔적과 Sysinternals EULA 수락 키.
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
                        ("category", "원격 접속".into()),
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

/// "C:\Users\x" → "\users\x" — $MFT 경로와 대조 가능한 볼륨 상대·소문자 키.
fn to_volume_relative(p: &str) -> String {
    let low = p.to_lowercase();
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

/// per-user 아티팩트의 계정: LNK/JUMPLIST 수집 폴더 바로 다음 경로 조각.
fn account_from_source(src: &str) -> String {
    let parts: Vec<&str> = src.split(['/', '\\']).collect();
    for (i, part) in parts.iter().enumerate() {
        let up = part.to_uppercase();
        if (up == "LNK" || up == "JUMPLIST") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    String::new()
}

/// $MFT 탐색기의 교차 참조(JumpList 대상 경로 + Shellbag 폴더 열람 흔적)를
/// 파싱 단계에서 미리 조합해 derived로 저장한다 — 화면 진입마다 원본 전수
/// 스캔·Shellbag 재구성을 하지 않기 위한 협약 이행. 뷰어는 이 테이블을
/// 표시 중인 경로 배치로만 조회한다.
pub fn build_path_references(out_dir: &Path, registry: &RegistryOverviewCache) -> Vec<Row> {
    let mut rows = Vec::new();
    let jumplist = out_dir.join("JUMPLIST").join("JumpList_Entries.sqlite");
    for r in read_table_with_rowid(&jumplist, "JumpList_Entries") {
        let target = r.get("target_path").cloned().unwrap_or_default();
        if target.is_empty() {
            continue;
        }
        let source = r.get("_source_file").cloned().unwrap_or_default();
        let mut row = pr_row();
        row.insert("path".into(), to_volume_relative(&target));
        row.insert("kind".into(), "Jumplist".into());
        row.insert("account".into(), account_from_source(&source));
        row.insert("label".into(), target.clone());
        row.insert("target_path".into(), target);
        for k in [
            "timestamp",
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
            r.get("__source_rowid").cloned().unwrap_or_else(|| "-1".into()),
        );
        rows.push(row);
    }
    // Shellbag — BagMRU 숫자 값(자식 셸 아이템)을 하이브별로 모아 재구성.
    // 계정은 하이브 파일명의 사용자 접두(Administrator_UsrClass.dat 등).
    let mut bag_rows: Vec<crate::shellbag::BagRow> = Vec::new();
    for hive in registry.hives() {
        let account = hive
            .name
            .split('_')
            .next()
            .unwrap_or(hive.name.as_str())
            .to_string();
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
                key_path,
                value_name,
                data,
                account: account.clone(),
            });
        }
    }
    for bag in crate::shellbag::reconstruct(bag_rows) {
        let mut row = pr_row();
        row.insert("path".into(), bag.path);
        row.insert("kind".into(), "Shellbag".into());
        row.insert("account".into(), bag.account);
        row.insert("label".into(), bag.display);
        row.insert("source_rowid".into(), "-1".into());
        rows.push(row);
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
    rows.extend(rf_credential_protection(system));
    rows.extend(rf_shares(system));
    rows.extend(rf_sql_auth(software));
    rows.extend(rf_autoruns(registry.hives()));
    rows.extend(rf_winlogon(software));
    rows.extend(rf_silent_process_exit(software));
    rows.extend(rf_taskcache(software));
    rows.extend(rf_active_setup(software));
    rows.extend(rf_appinit(software, system));
    rows.extend(rf_session_manager(system));
    rows.extend(rf_security_config(software));
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

    /// RegBack 산출물은 facts로 보존하되 파생 입력에서 제외된다 — 판별 회귀.
    #[test]
    fn regback_outputs_are_recognized_for_derived_exclusion() {
        assert!(is_regback_output(Path::new("/x/REGISTRY/SYSTEM_RegBack.sqlite")));
        assert!(is_regback_output(Path::new("/x/REGISTRY/SOFTWARE_RegBack_2.sqlite")));
        assert!(!is_regback_output(Path::new("/x/REGISTRY/SYSTEM.sqlite")));
        assert!(!is_regback_output(Path::new("/x/REGISTRY/NTUSER.DAT.sqlite")));
    }

    /// SessionID 재사용 회귀: 세션 종료(23) 뒤 같은 SessionID로 다른 사용자가
    /// 로그온해도, 이전 세션 행에 이후 사용자의 IP·계정이 붙지 않는다 —
    /// 상관은 (출처, SessionID) 그룹의 시간순 전방 전파로만 이뤄진다.
    #[test]
    fn rdp_session_enrichment_does_not_cross_session_id_reuse() {
        const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
        let mk = |eid: &str, ts: &str, user: &str, addr: &str, key: &str| {
            let mut r = Row::new();
            r.insert("Provider".into(), LSM.into());
            r.insert("EventID".into(), eid.into());
            r.insert("timestamp".into(), ts.into());
            r.insert("_record_key".into(), key.into());
            let ed = serde_json::json!({
                "EventXML": {"SessionID": "3", "User": user, "Address": addr}
            });
            r.insert("EventData".into(), ed.to_string());
            r
        };
        let rows = vec![
            mk("21", "2026-01-01 10:00:00.000", "CORP\\alice", "10.0.0.5", "LSM_Log::1"),
            // 값 없는 로그오프 — 같은 세션 구간이므로 alice로 채워진다.
            mk("23", "2026-01-01 10:30:00.000", "", "", "LSM_Log::2"),
            // 종료 후 재사용된 SessionID=3의 새 로그온 (다른 사용자).
            mk("21", "2026-01-02 09:00:00.000", "CORP\\bob", "10.0.0.9", "LSM_Log::3"),
            mk("22", "2026-01-02 09:00:05.000", "", "", "LSM_Log::4"),
        ];
        let out = build_remote_desktop_history_with_events(
            &EventLogOverviewCache::from_rows_for_tests(rows),
        );
        assert_eq!(out[1]["account"], "alice", "로그오프 행은 같은 세션 값으로 채움");
        assert_eq!(out[1]["remote_address"], "10.0.0.5");
        // 이전 구현(전역 최종값 역전파)이라면 alice 세션 행이 bob으로 오염됐다.
        assert_ne!(out[0]["account"], "bob");
        assert_ne!(out[1]["account"], "bob");
        assert_eq!(out[3]["account"], "bob", "새 세션 구간은 bob 값으로 전파");
        assert_eq!(out[3]["remote_address"], "10.0.0.9");
    }

    /// 서로 다른 수집 로그의 같은 SessionID는 상관되지 않는다 (출처 분리).
    #[test]
    fn rdp_session_enrichment_is_scoped_to_the_source_log() {
        const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager";
        let mk = |ts: &str, user: &str, addr: &str, key: &str| {
            let mut r = Row::new();
            r.insert("Provider".into(), LSM.into());
            r.insert("EventID".into(), if user.is_empty() { "22" } else { "21" }.into());
            r.insert("timestamp".into(), ts.into());
            r.insert("_record_key".into(), key.into());
            let ed = serde_json::json!({
                "EventXML": {"SessionID": "7", "User": user, "Address": addr}
            });
            r.insert("EventData".into(), ed.to_string());
            r
        };
        let rows = vec![
            mk("2026-01-01 10:00:00.000", "CORP\\alice", "10.0.0.5", "LogA::1"),
            // 다른 로그 파일의 같은 SessionID — 값이 채워지면 허위 상관.
            mk("2026-01-01 11:00:00.000", "", "", "LogB::1"),
        ];
        let out = build_remote_desktop_history_with_events(
            &EventLogOverviewCache::from_rows_for_tests(rows),
        );
        assert_eq!(out[1]["account"], "", "다른 출처의 세션에는 전파하지 않는다");
        assert_eq!(out[1]["remote_address"], "");
    }

    #[test]
    fn mpdetection_lines_become_threat_rows_in_kst() {
        assert_eq!(mp_ts_kst("2026-03-22T17:20:21.623"), "2026-03-23 02:20:21.623");
        assert_eq!(mp_ts_kst("junk"), "junk");

        let root = std::env::temp_dir().join(format!("wina-mpdet-{}", std::process::id()));
        std::fs::create_dir_all(root.join("Support")).unwrap();
        // UTF-16LE + BOM, DETECTION 외 라인 섞임
        let text = "\u{feff}2026-03-22T17:20:00.000 Service started - Windows Defender\n2026-03-22T17:20:21.623 DETECTION Ransom:Win32/Test!X file:C:\\evil.exe\n2026-03-22T17:21:00.000 Version: Product 4.18\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.trim_start_matches('\u{feff}').encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(root.join("Support/MPDetection-20260322-172000.log"), &bytes).unwrap();

        let rows = defender_from_mpdetection(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["section"], "threat");
        assert_eq!(rows[0]["title"], "Ransom:Win32/Test!X");
        assert_eq!(rows[0]["detail"], "file:C:\\evil.exe");
        assert_eq!(rows[0]["timestamp"], "2026-03-23 02:20:21.623");
        assert_eq!(rows[0]["source"], "MPDetection");
        assert!(rows[0]["raw_line"].contains(" DETECTION "));
    }

    #[test]
    fn ie_webcache_rows_join_browser_activity() {
        assert_eq!(ie_visit_url("Visited: Administrator@file:///E:/a.txt"), "file:///E:/a.txt");
        assert_eq!(ie_visit_url("user@http://x.example/"), "http://x.example/");
        assert_eq!(ie_visit_url("http://plain.example/"), "http://plain.example/");
        assert_eq!(ie_download_url("garbage | NAVER Corp. | https://dl.example/f.exe", "iedownload:{X}"), "https://dl.example/f.exe");
        assert_eq!(ie_download_url("no url here", "iedownload:{X}"), "iedownload:{X}");

        let root = std::env::temp_dir().join(format!("wina-ie-bh-{}", std::process::id()));
        let browser = root.join("BROWSER");
        std::fs::create_dir_all(&browser).unwrap();
        let conn = Connection::open(browser.join("Admin_IE_WebCache.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE IEWebCache_History (accessed_time TEXT, url TEXT, container TEXT, access_count TEXT, account TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO IEWebCache_History VALUES ('2026-03-26 13:32:29.295', 'Visited: Admin@file:///C:/x.pbl', 'History', '1', 'Admin')",
            [],
        ).unwrap();
        conn.execute(
            "CREATE TABLE IEWebCache_Downloads (accessed_time TEXT, modified_time TEXT, url TEXT, metadata TEXT, account TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO IEWebCache_Downloads VALUES ('2025-05-21 10:38:56.389', '', 'iedownload:{G}', 'a | https://dl.example/setup.exe', 'Admin')",
            [],
        ).unwrap();
        drop(conn);

        let rows = build_browser_history(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(rows.len(), 2);
        let visit = rows.iter().find(|r| r["kind"] == "visit").unwrap();
        assert_eq!(visit["url"], "file:///C:/x.pbl");
        assert_eq!(visit["account"], "Admin");
        assert_eq!(visit["visit_count"], "1");
        let dl = rows.iter().find(|r| r["kind"] == "download").unwrap();
        assert_eq!(dl["url"], "https://dl.example/setup.exe");
        assert_eq!(dl["title"], "setup.exe");
    }

    #[test]
    fn rdpcorets_131_joins_remote_desktop_history_with_bare_ip() {
        assert_eq!(strip_client_port("10.0.0.1:59151"), "10.0.0.1");
        assert_eq!(strip_client_port("[10.0.0.1]:52550"), "10.0.0.1");
        assert_eq!(strip_client_port("fe80::1"), "fe80::1");
        let spec = rdp_spec("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", "131");
        assert!(spec.is_some());
        assert_eq!(spec.unwrap().direction, "inbound");
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

        let rows = build_powershell_history(&root);
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

        let rows = build_powershell_history(&root);
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
    fn firewall_profile_change_event_2010_surfaces_interface_and_profiles() {
        let root =
            std::env::temp_dir().join(format!("wina-fw2010-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("Firewall.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE Firewall (Provider TEXT, EventID TEXT, EventData TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO Firewall VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                FIREWALL_PROVIDER,
                "2010",
                r#"{"InterfaceName":"이더넷","OldProfile":"4","NewProfile":"2"}"#,
                "2026-08-21 11:05:00.000",
                "Firewall.evtx::9",
            ],
        ).unwrap();
        drop(conn);

        let rows = build_firewall_history(&root);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("rule_name").map(String::as_str), Some("이더넷"));
        assert_eq!(
            row.get("detail").map(String::as_str),
            Some("적용 프로필 공용 → 개인")
        );
        assert_eq!(row.get("profiles").map(String::as_str), Some("개인"));
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
    fn firewall_block_event_2011_reads_singular_port_and_userid_fallback() {
        let root =
            std::env::temp_dir().join(format!("wina-fw2011-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("Firewall.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE Firewall (Provider TEXT, EventID TEXT, EventData TEXT, UserID TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO Firewall VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                FIREWALL_PROVIDER,
                "2011",
                r#"{"ApplicationPath":"C:\\tools\\srv.exe","Port":"8443","Protocol":"6"}"#,
                "S-1-5-18",
                "2026-08-21 11:10:00.000",
                "Firewall.evtx::11",
            ],
        ).unwrap();
        drop(conn);

        let rows = build_firewall_history(&root);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("local_ports").map(String::as_str), Some("8443"));
        assert_eq!(row.get("account").map(String::as_str), Some("S-1-5-18"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn firewall_rule_added_event_2004_maps_direction_action_protocol() {
        let root =
            std::env::temp_dir().join(format!("wina-fw2004-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("Firewall.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE Firewall (Provider TEXT, EventID TEXT, EventData TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO Firewall VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                FIREWALL_PROVIDER,
                "2004",
                r#"{"RuleName":"Evil Ingress","RuleId":"{11111111-2222}","Direction":"1","Action":"3","Protocol":"6","LocalPorts":"4444","Profiles":"2147483647","ApplicationPath":"C:\\tools\\nc.exe","ModifyingApplication":"C:\\Windows\\System32\\netsh.exe"}"#,
                "2026-08-21 11:00:00.000",
                "Firewall.evtx::7",
            ],
        ).unwrap();
        drop(conn);

        let rows = build_firewall_history(&root);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.get("kind").map(String::as_str), Some("규칙 추가"));
        assert_eq!(row.get("rule_name").map(String::as_str), Some("Evil Ingress"));
        assert_eq!(row.get("direction").map(String::as_str), Some("인바운드"));
        assert_eq!(row.get("action").map(String::as_str), Some("허용"));
        assert_eq!(row.get("protocol").map(String::as_str), Some("TCP"));
        assert_eq!(row.get("profiles").map(String::as_str), Some("모든 프로필"));
        assert_eq!(row.get("local_ports").map(String::as_str), Some("4444"));
        std::fs::remove_dir_all(root).unwrap();
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
        assert_eq!(row.get("direction").map(String::as_str), Some("inbound"));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// SmbClient%4Security(31010 등)는 이 호스트가 클라이언트로서 원격 공유에
    /// 접근한 기록 — outbound로 채택돼야 한다. EventData는 실측 그대로 평탄
    /// JSON이고 Status 0xC0000022(접근 거부)는 설명에 이름으로 풀린다.
    #[test]
    fn smb_client_share_failure_is_retained_as_outbound() {
        let root = std::env::temp_dir().join(format!("wina-smbclient-overview-{}", std::process::id()));
        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let db_path = event_dir.join("SmbClientSecurity.sqlite");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE SmbClientSecurity (Provider TEXT, EventID TEXT, EventData TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        for (eid, data, key) in [
            (
                "31010",
                r#"{"Reason": 12, "Status": 3221225506, "ShareNameLength": 24, "ShareName": "\\192.168.10.199\\dbbackup", "ObjectNameLength": 0, "ObjectName": ""}"#,
                "SmbClient.evtx::1",
            ),
            // ShareName 없이 ServerName만 있는 이벤트(31013 등)도 서버 주소로 채택.
            (
                "31013",
                r#"{"Smb2Command": 11, "ServerName": "\\192.168.10.63", "Status": 3221266432}"#,
                "SmbClient.evtx::2",
            ),
            // 대상 정보가 없는 행은 연결 상대를 특정할 수 없어 제외.
            ("31017", r#"{"Status": 0}"#, "SmbClient.evtx::3"),
        ] {
            conn.execute(
                "INSERT INTO SmbClientSecurity VALUES (?1, ?2, ?3, '2026-08-21 12:00:00.000', ?4)",
                rusqlite::params!["Microsoft-Windows-SMBClient", eid, data, key],
            )
            .unwrap();
        }
        drop(conn);

        let rows = build_smb_history(&root);
        assert_eq!(rows.len(), 2);
        let share = &rows[0];
        assert_eq!(share.get("direction").map(String::as_str), Some("outbound"));
        assert_eq!(
            share.get("remote_address").map(String::as_str),
            Some("192.168.10.199")
        );
        assert_eq!(share.get("result").map(String::as_str), Some("실패"));
        assert_eq!(
            share.get("description").map(String::as_str),
            Some("SMB 공유 접근 실패 (\\192.168.10.199\\dbbackup — 접근 거부)")
        );
        let server = &rows[1];
        assert_eq!(server.get("direction").map(String::as_str), Some("outbound"));
        assert_eq!(
            server.get("remote_address").map(String::as_str),
            Some("192.168.10.63")
        );
        assert_eq!(
            server.get("description").map(String::as_str),
            Some("SMB 클라이언트 연결 실패 (\\192.168.10.63)")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// T5: XML 정의에 Operational 이벤트 실행 요약이 병합된다 — 키는 선행
    /// 역슬래시 유무(uri vs TaskName)를 무시하고, 129의 실제 프로세스 경로가
    /// 200의 정의된 액션보다 우선하며, 실행 기록 없는 태스크는 빈 값으로 남는다.
    #[test]
    fn scheduled_tasks_merge_operational_run_summary() {
        let root = std::env::temp_dir().join(format!("wina-schtask-overview-{}", std::process::id()));
        let task_dir = root.join("TASKSCHEDULER");
        std::fs::create_dir_all(&task_dir).unwrap();
        let conn = Connection::open(task_dir.join("TaskScheduler_Tasks.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE TaskScheduler_Tasks (timestamp TEXT, task_name TEXT, uri TEXT, author TEXT, actions TEXT)",
            [],
        ).unwrap();
        // 실측처럼 uri에 선행 역슬래시가 없는 형태 + 실행 기록 없는 MS 태스크.
        for (name, uri) in [("WhaleUpdateD", "WhaleUpdateD"), ("Idle", "\\Microsoft\\Windows\\Idle")] {
            conn.execute(
                "INSERT INTO TaskScheduler_Tasks VALUES ('2026-01-01 00:00:00.000', ?1, ?2, 'CORP', 'C:\\x.exe')",
                rusqlite::params![name, uri],
            )
            .unwrap();
        }
        drop(conn);

        let event_dir = root.join("EVENTLOG");
        std::fs::create_dir_all(&event_dir).unwrap();
        let conn = Connection::open(event_dir.join("TaskSchedulerOperational.sqlite")).unwrap();
        conn.execute(
            "CREATE TABLE TaskSchedulerOperational (Provider TEXT, EventID TEXT, EventData TEXT, timestamp TEXT, _record_key TEXT)",
            [],
        ).unwrap();
        for (eid, data, ts) in [
            ("100", r##"{"#attributes": {"Name": "TaskStartEvent"}, "TaskName": "\\WhaleUpdateD"}"##, "2026-02-01 10:00:00.000"),
            ("200", r##"{"#attributes": {"Name": "ActionStart"}, "TaskName": "\\WhaleUpdateD", "ActionName": "C:\\defined\\action.exe"}"##, "2026-02-01 10:00:00.100"),
            ("129", r##"{"#attributes": {"Name": "CreatedTaskProcess"}, "TaskName": "\\WhaleUpdateD", "Path": "C:\\real\\whale_update.exe", "ProcessID": 4856}"##, "2026-02-01 10:00:00.200"),
            ("102", r##"{"#attributes": {"Name": "TaskSuccessEvent"}, "TaskName": "\\WhaleUpdateD"}"##, "2026-02-01 10:00:01.000"),
            ("100", r#"{"TaskName": "\\WhaleUpdateD"}"#, "2026-03-01 09:00:00.000"),
            ("103", r#"{"TaskName": "\\WhaleUpdateD"}"#, "2026-03-01 09:00:01.000"),
        ] {
            conn.execute(
                "INSERT INTO TaskSchedulerOperational VALUES ('Microsoft-Windows-TaskScheduler', ?1, ?2, ?3, 'ts.evtx::1')",
                rusqlite::params![eid, data, ts],
            )
            .unwrap();
        }
        drop(conn);

        let rows = build_scheduled_tasks(&root);
        assert_eq!(rows.len(), 2);
        let whale = rows
            .iter()
            .find(|row| row.get("task_name").map(String::as_str) == Some("WhaleUpdateD"))
            .expect("whale task");
        assert_eq!(
            whale.get("last_run_time").map(String::as_str),
            Some("2026-03-01 09:00:00.000")
        );
        assert_eq!(whale.get("run_count").map(String::as_str), Some("2"));
        // 마지막 완료 이벤트는 103(실패) — 이전 102(성공)를 덮는다.
        assert_eq!(whale.get("last_run_result").map(String::as_str), Some("실패"));
        assert_eq!(
            whale.get("last_run_action").map(String::as_str),
            Some("C:\\real\\whale_update.exe")
        );
        let idle = rows
            .iter()
            .find(|row| row.get("task_name").map(String::as_str) == Some("Idle"))
            .expect("idle task");
        assert!(idle.get("last_run_time").is_none());
        assert!(idle.get("run_count").is_none());
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let rows = build_powershell_history(&root);
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
        let dup = status_of("D-secondD2").expect("duplicate-fragment block");
        assert!(dup.contains("조각 1 중복(내용 상이)"), "{dup}");
        let range = status_of("R1").expect("out-of-range block");
        assert!(range.contains("범위 밖 조각 번호 5"), "{range}");
        let total = status_of("T1T2").expect("total-mismatch block");
        assert!(total.contains("총 조각 수 불일치(2 vs 3)"), "{total}");
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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

        let registry = RegistryOverviewCache::load(&root);
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
            .map(RegistryOverviewHive::load)
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
        let registry = RegistryOverviewCache::load(&root);
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
