//! Windows Event Log (.evtx) parser via the `evtx` crate (omerbenamram) — the
//! same engine the Python `evtx` binding wraps, so the JSON structure matches.
//! One table per source log; schema identical to the Python parser, including
//! the EventData column serialized json.dumps-style (spaces after `,`/`:`,
//! insertion-ordered keys via serde_json's preserve_order).
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use serde::Serialize;
use serde_json::Value;

use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_kst;

/// The IR-relevant .evtx to parse (exact filenames, case-insensitive), matching
/// the Python parser's allowlist. "%4" is the on-disk escaping for "/".
pub const ALLOWLIST: &[&str] = &[
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Security.evtx",
    "Microsoft-Windows-SMBServer%4Audit.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",
    "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
    // 원격 WMI 실행·구독(5857~5861) — WMI 이벤트 구독 뷰와 짝.
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    // WinRM/원격 PowerShell 접속.
    "Microsoft-Windows-WinRM%4Operational.evtx",
    // RDP 접속 소스 IP·포트·전송 방식(EventID 131) — 원격 접근 이력 보강.
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
    // Run 키 실행 결과(9707/9708) — 영속성 발동 여부.
    "Microsoft-Windows-Shell-Core%4Operational.evtx",
    // 오류 보고(WER) 전용 채널 — 크래시 진단·보고 업로드 흔적.
    "Microsoft-Windows-WER-Diag%4Operational.evtx",
    "Microsoft-Windows-WER-PayloadHealth%4Operational.evtx",
    "Microsoft-Windows-WerKernel%4Operational.evtx",
];

/// XP/2003 구형 이벤트 로그(.evt) 기본 파일명 — Vista+에서 .evtx로 대체됐다.
pub const EVT_ALLOWLIST: &[&str] = &["SecEvent.Evt", "SysEvent.Evt", "AppEvent.Evt"];

pub const EVENT_COLUMNS: &[&str] = &[
    "timestamp",
    "Channel",
    "EventID",
    "LevelName",
    "Level",
    "Provider",
    "Computer",
    "EventRecordID",
    "ProcessID",
    "ThreadID",
    "UserID",
    "EventData",
    "_record_key",
    "_status",
    "_error",
    "_source_file",
];

fn level_name(level: Option<&str>) -> String {
    match level {
        Some("0") | Some("4") => "Information".into(),
        Some("1") => "Critical".into(),
        Some("2") => "Error".into(),
        Some("3") => "Warning".into(),
        Some("5") => "Verbose".into(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// json.dumps(v, ensure_ascii=False): compact but with a space after every
/// ',' and ':'. serde_json's preserve_order keeps the evtx crate's key order.
struct PyFmt;
impl serde_json::ser::Formatter for PyFmt {
    fn begin_array_value<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_key<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_value<W: ?Sized + std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        w.write_all(b": ")
    }
}
fn py_json(v: &Value) -> String {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, PyFmt);
    v.serialize(&mut ser).ok();
    String::from_utf8(buf).unwrap_or_default()
}

fn get<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    if cur.is_null() {
        None
    } else {
        Some(cur)
    }
}
/// Legacy events wrap a scalar as {"#attributes": ..., "#text": N}; unwrap it.
fn scalar(v: Option<&Value>) -> Option<&Value> {
    match v {
        Some(Value::Object(m)) if m.contains_key("#text") => m.get("#text"),
        other => other,
    }
}
fn cell(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(if *b { "true" } else { "false" }.into()),
        Some(other) => Some(py_json(other)),
    }
}

fn fmt_ts(system_time: Option<&Value>, record_ts: DateTime<Utc>) -> String {
    if let Some(Value::String(s)) = system_time {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return fmt_kst(dt.with_timezone(&Utc));
        }
    }
    fmt_kst(record_ts)
}

pub fn parse_evtx_stream(path: &Path, out: &Path, table: &str) -> Result<usize> {
    let src = path.to_string_lossy().to_string();
    let mut parser = EvtxParser::from_path(path)?;
    let mut writer = StreamWriter::create(out, table, EVENT_COLUMNS, EVENT_COLUMNS)?;

    // _record_key = "<출력 테이블명>::<rowid>". 테이블명은 파이프라인이 동명
    // 로그를 고유화한 이름(Security_2 등)이라 같은 basename의 로그끼리 키가
    // 충돌하지 않고, 뒷부분은 이 파서가 삽입하는 순번 == 출력 SQLite의 실제
    // rowid라서(corrupted_chunk 행 포함) 뷰어가 키만으로 원본 행을 조회할 수
    // 있다. EventRecordID는 별도 컬럼에 그대로 보존된다.
    let mut next_rowid: i64 = 0;
    for rec in parser.records_json_value() {
        if crate::pipeline::cancelled() {
            break;
        }
        match rec {
            Err(e) => {
                next_rowid += 1;
                let mut row = Row::new();
                row.insert("timestamp".into(), String::new());
                row.insert("_status".into(), "corrupted_chunk".into());
                row.insert("_error".into(), e.to_string());
                // 손상 행도 record_key 계약(<테이블>::<rowid>)을 지켜야 상세
                // 패널·북마크가 이 행을 안정적으로 참조할 수 있다.
                row.insert(
                    "_record_key".into(),
                    format!("{}::{}", table, next_rowid),
                );
                row.insert("_source_file".into(), src.clone());
                writer.push(row)?;
            }
            Ok(r) => {
                next_rowid += 1;
                let data = &r.data;
                let system = get(data, &["Event", "System"]);
                let sys = system.unwrap_or(&Value::Null);
                let payload = get(data, &["Event", "EventData"])
                    .or_else(|| get(data, &["Event", "UserData"]));

                let level = cell(scalar(sys.get("Level")));
                let mut row = Row::new();
                row.insert(
                    "timestamp".into(),
                    fmt_ts(
                        get(sys, &["TimeCreated", "#attributes", "SystemTime"]),
                        r.timestamp,
                    ),
                );
                if let Some(v) = cell(sys.get("Channel")) {
                    row.insert("Channel".into(), v);
                }
                if let Some(v) = cell(scalar(sys.get("EventID"))) {
                    row.insert("EventID".into(), v);
                }
                row.insert("LevelName".into(), level_name(level.as_deref()));
                if let Some(v) = level {
                    row.insert("Level".into(), v);
                }
                if let Some(v) = cell(get(sys, &["Provider", "#attributes", "Name"])) {
                    row.insert("Provider".into(), v);
                }
                if let Some(v) = cell(sys.get("Computer")) {
                    row.insert("Computer".into(), v);
                }
                let erid = cell(sys.get("EventRecordID"));
                if let Some(v) = &erid {
                    row.insert("EventRecordID".into(), v.clone());
                }
                if let Some(v) = cell(get(sys, &["Execution", "#attributes", "ProcessID"])) {
                    row.insert("ProcessID".into(), v);
                }
                if let Some(v) = cell(get(sys, &["Execution", "#attributes", "ThreadID"])) {
                    row.insert("ThreadID".into(), v);
                }
                if let Some(v) = cell(get(sys, &["Security", "#attributes", "UserID"])) {
                    row.insert("UserID".into(), v);
                }
                row.insert(
                    "EventData".into(),
                    match payload {
                        Some(p) => py_json(p),
                        None => String::new(),
                    },
                );
                row.insert("_status".into(), "ok".into());
                row.insert("_error".into(), String::new());
                row.insert(
                    "_record_key".into(),
                    format!("{}::{}", table, next_rowid),
                );
                row.insert("_source_file".into(), src.clone());
                writer.push(row)?;
            }
        }
    }
    writer.finish()
}

// ---------------------------------------------------------------------------
// XP/2003 .evt (EVT/"ELF") 파서 — T3. 순환 버퍼 포맷: 0x30 헤더 뒤의 레코드
// 영역이 링으로 순환하고, 레코드 하나가 파일 끝에서 0x30 직후로 감길 수 있다.
// dirty 로그(헤더 오프셋 신뢰 불가)는 floating EOF 레코드(0x11111111…44444444
// 매직)를 스캔해 가장 오래된 레코드 위치를 복원한다. 출력 스키마·record_key
// 계약은 EVTX 경로(EVENT_COLUMNS)와 동일 — 뷰어가 구분 없이 읽는다.
// ---------------------------------------------------------------------------

const EVT_HEADER: usize = 0x30;
const EVT_LFLE: u32 = 0x654c_664c; // "LfLe"
const EVT_EOF_MAGIC: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
/// EVENTLOGRECORD 고정부 크기 — 이보다 짧은 length는 레코드가 아니다.
const EVT_MIN_RECORD: usize = 0x38;

fn evt_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

fn evt_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// 레코드 영역(0x30 이후)을 링으로 읽는다 — 감긴 레코드 처리용.
struct EvtRing<'a> {
    buf: &'a [u8],
}

impl<'a> EvtRing<'a> {
    fn len(&self) -> usize {
        self.buf.len()
    }
    fn byte(&self, pos: usize) -> u8 {
        self.buf[pos % self.buf.len()]
    }
    fn u32(&self, pos: usize) -> u32 {
        u32::from_le_bytes([
            self.byte(pos),
            self.byte(pos + 1),
            self.byte(pos + 2),
            self.byte(pos + 3),
        ])
    }
    fn read(&self, pos: usize, n: usize) -> Vec<u8> {
        (0..n).map(|i| self.byte(pos + i)).collect()
    }
}

/// 바이너리 SID → "S-1-5-…" (srum.rs의 _format_sid와 동일 규칙).
fn evt_format_sid(data: &[u8]) -> String {
    if data.len() < 8 {
        return String::new();
    }
    let revision = data[0];
    let sub_count = data[1] as usize;
    let authority = data[2..8].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut parts = vec!["S".to_string(), revision.to_string(), authority.to_string()];
    let mut off = 8;
    for _ in 0..sub_count {
        if off + 4 > data.len() {
            break;
        }
        parts.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()).to_string());
        off += 4;
    }
    parts.join("-")
}

/// UTF-16LE 널 종료 문자열 (오프셋부터, 버퍼 끝까지 안전 절단).
fn evt_utf16z(b: &[u8], off: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut pos = off;
    while pos + 2 <= b.len() {
        let u = u16::from_le_bytes([b[pos], b[pos + 1]]);
        pos += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), pos)
}

/// EventType → (Level, LevelName). 감사 이벤트는 EVTX처럼 Level 0으로 두되
/// 이름은 Audit 구분을 남긴다.
fn evt_level(event_type: u16) -> (String, String) {
    match event_type {
        0x01 => ("2".into(), "Error".into()),
        0x02 => ("3".into(), "Warning".into()),
        0x04 => ("4".into(), "Information".into()),
        0x08 => ("0".into(), "AuditSuccess".into()),
        0x10 => ("0".into(), "AuditFailure".into()),
        other => (String::new(), other.to_string()),
    }
}

/// SecEvent/SysEvent/AppEvent 파일명 → EVTX Channel 명명과 맞춘 표기.
fn evt_channel(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    match stem.to_ascii_lowercase().as_str() {
        "secevent" => "Security".into(),
        "sysevent" => "System".into(),
        "appevent" => "Application".into(),
        _ => stem,
    }
}

/// 가장 오래된 레코드의 링 오프셋을 결정한다: 헤더 StartOffset이 유효하면
/// 그대로, 아니면(dirty/손상) floating EOF 레코드를 스캔해 BeginRecord를 쓰고,
/// 그마저 없으면 앞에서부터 첫 유효 시그니처를 찾는다.
fn evt_start(data: &[u8], ring: &EvtRing) -> usize {
    let looks_like_record = |pos: usize| {
        let len = ring.u32(pos) as usize;
        ring.u32(pos + 4) == EVT_LFLE && (EVT_MIN_RECORD..=ring.len()).contains(&len)
    };
    let hdr_start = evt_u32(data, 0x10) as usize;
    if hdr_start >= EVT_HEADER && hdr_start < data.len() && looks_like_record(hdr_start - EVT_HEADER)
    {
        return hdr_start - EVT_HEADER;
    }
    // floating footer: 파일 전체에서 EOF 매직(4개 u32 연속)을 4바이트 정렬로 찾는다.
    let mut i = EVT_HEADER;
    while i + 16 <= data.len() {
        if evt_u32(data, i) == EVT_EOF_MAGIC[0]
            && evt_u32(data, i + 4) == EVT_EOF_MAGIC[1]
            && evt_u32(data, i + 8) == EVT_EOF_MAGIC[2]
            && evt_u32(data, i + 12) == EVT_EOF_MAGIC[3]
        {
            let footer = i - 4; // 매직 앞의 length(0x28) 필드가 레코드 시작
            let begin = evt_u32(data, footer + 0x14) as usize;
            if begin >= EVT_HEADER && begin < data.len() && looks_like_record(begin - EVT_HEADER) {
                return begin - EVT_HEADER;
            }
            // BeginRecord가 깨졌으면 링 순서상 EOF 레코드 바로 뒤가 가장 오래됨.
            return (footer - EVT_HEADER + 0x28) % ring.len().max(1);
        }
        i += 4;
    }
    // 마지막 수단: 앞에서부터 첫 유효 레코드.
    let mut pos = 0usize;
    while pos + 8 <= ring.len() {
        if looks_like_record(pos) {
            return pos;
        }
        pos += 4;
    }
    0
}

/// EVENTLOGRECORD 바이트(링에서 복사한 연속 버퍼)를 행으로 해석한다.
fn evt_record_row(rec: &[u8], channel: &str) -> Option<Row> {
    let record_number = evt_u32(rec, 0x08);
    let time_generated = evt_u32(rec, 0x0C) as i64;
    let time_written = evt_u32(rec, 0x10) as i64;
    let event_id_full = evt_u32(rec, 0x14);
    let event_type = evt_u16(rec, 0x18);
    let num_strings = evt_u16(rec, 0x1A) as usize;
    let category = evt_u16(rec, 0x1C);
    let string_off = evt_u32(rec, 0x24) as usize;
    let sid_len = evt_u32(rec, 0x28) as usize;
    let sid_off = evt_u32(rec, 0x2C) as usize;
    let data_len = evt_u32(rec, 0x30) as usize;
    let data_off = evt_u32(rec, 0x34) as usize;

    let (source_name, computer_pos) = evt_utf16z(rec, 0x38);
    let (computer_name, _) = evt_utf16z(rec, computer_pos);
    if source_name.is_empty() && computer_name.is_empty() {
        return None;
    }

    let mut strings: Vec<Value> = Vec::new();
    let mut spos = string_off;
    for _ in 0..num_strings.min(256) {
        if spos >= rec.len() {
            break;
        }
        let (s, next) = evt_utf16z(rec, spos);
        strings.push(Value::String(s));
        spos = next;
    }
    let sid = if sid_len > 0 && sid_off + sid_len <= rec.len() {
        evt_format_sid(&rec[sid_off..sid_off + sid_len])
    } else {
        String::new()
    };

    // EVTX EventData JSON과 같은 자리에는 위치 기반 삽입 문자열을 담는다 —
    // 메시지 DLL 리소스 결합(렌더링)은 범위 밖(T3 문서 참조).
    let mut payload = serde_json::Map::new();
    payload.insert("Strings".into(), Value::Array(strings));
    payload.insert(
        "EventType".into(),
        Value::Number(serde_json::Number::from(event_type)),
    );
    payload.insert(
        "Category".into(),
        Value::Number(serde_json::Number::from(category)),
    );
    payload.insert(
        "TimeWritten".into(),
        Value::String(
            DateTime::<Utc>::from_timestamp(time_written, 0)
                .map(fmt_kst)
                .unwrap_or_default(),
        ),
    );
    if data_len > 0 && data_off + data_len <= rec.len() {
        payload.insert(
            "Data".into(),
            Value::String(crate::hex::hex_lower(&rec[data_off..data_off + data_len])),
        );
    }

    let (level, level_name) = evt_level(event_type);
    let mut row = Row::new();
    row.insert(
        "timestamp".into(),
        DateTime::<Utc>::from_timestamp(time_generated, 0)
            .map(fmt_kst)
            .unwrap_or_default(),
    );
    row.insert("Channel".into(), channel.to_string());
    // Event Viewer 표기와 동일하게 하위 16비트가 이벤트 번호다(상위는
    // severity/facility 비트).
    row.insert("EventID".into(), (event_id_full & 0xFFFF).to_string());
    row.insert("LevelName".into(), level_name);
    row.insert("Level".into(), level);
    row.insert("Provider".into(), source_name);
    row.insert("Computer".into(), computer_name);
    row.insert("EventRecordID".into(), record_number.to_string());
    if !sid.is_empty() {
        row.insert("UserID".into(), sid);
    }
    row.insert("EventData".into(), py_json(&Value::Object(payload)));
    Some(row)
}

/// .evt 하나를 EVTX와 동일한 테이블 스키마로 스트리밍 파싱한다.
pub fn parse_evt_stream(path: &Path, out: &Path, table: &str) -> Result<usize> {
    let src = path.to_string_lossy().to_string();
    let data = std::fs::read(path)?;
    if data.len() < EVT_HEADER + 8 || evt_u32(&data, 4) != EVT_LFLE {
        anyhow::bail!("not an EVT log (LfLe header missing)");
    }
    let ring = EvtRing {
        buf: &data[EVT_HEADER..],
    };
    if ring.len() < 8 {
        anyhow::bail!("EVT record area too small");
    }
    let mut writer = StreamWriter::create(out, table, EVENT_COLUMNS, EVENT_COLUMNS)?;
    let channel = evt_channel(path);
    let start = evt_start(&data, &ring);

    let mut next_rowid: i64 = 0;
    let push_corrupted = |writer: &mut StreamWriter,
                              next_rowid: &mut i64,
                              error: String|
     -> Result<()> {
        *next_rowid += 1;
        let mut row = Row::new();
        row.insert("timestamp".into(), String::new());
        row.insert("_status".into(), "corrupted_chunk".into());
        row.insert("_error".into(), error);
        row.insert("_record_key".into(), format!("{}::{}", table, *next_rowid));
        row.insert("_source_file".into(), src.clone());
        writer.push(row)
    };

    let mut pos = start;
    let mut consumed = 0usize;
    let mut gap = 0usize;
    while consumed < ring.len() {
        if crate::pipeline::cancelled() {
            break;
        }
        // EOF 레코드(최신 레코드 뒤의 커서)에 닿으면 한 바퀴 다 읽은 것이다.
        if ring.u32(pos + 4) == EVT_EOF_MAGIC[0]
            && ring.u32(pos + 8) == EVT_EOF_MAGIC[1]
            && ring.u32(pos + 12) == EVT_EOF_MAGIC[2]
            && ring.u32(pos + 16) == EVT_EOF_MAGIC[3]
        {
            break;
        }
        let len = ring.u32(pos) as usize;
        if ring.u32(pos + 4) == EVT_LFLE && (EVT_MIN_RECORD..=ring.len()).contains(&len) {
            if gap > 0 {
                push_corrupted(
                    &mut writer,
                    &mut next_rowid,
                    format!("resync: skipped {gap} bytes"),
                )?;
                gap = 0;
            }
            let rec = ring.read(pos, len);
            match evt_record_row(&rec, &channel) {
                Some(mut row) => {
                    next_rowid += 1;
                    row.insert("_status".into(), "ok".into());
                    row.insert("_error".into(), String::new());
                    row.insert("_record_key".into(), format!("{}::{}", table, next_rowid));
                    row.insert("_source_file".into(), src.clone());
                    writer.push(row)?;
                }
                None => {
                    push_corrupted(
                        &mut writer,
                        &mut next_rowid,
                        "unparsable EVENTLOGRECORD".into(),
                    )?;
                }
            }
            pos = (pos + len) % ring.len();
            consumed += len;
        } else {
            pos = (pos + 4) % ring.len();
            consumed += 4;
            gap += 4;
        }
    }
    writer.finish()
}

#[cfg(test)]
mod evt_tests {
    use super::*;
    use std::path::PathBuf;

    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn utf16z(s: &str) -> Vec<u8> {
        let mut b: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        b.extend([0, 0]);
        b
    }

    /// EVENTLOGRECORD 하나 (source/computer/문자열 1개, 8바이트 정렬 길이).
    fn record(record_number: u32, event_id: u32, event_type: u16, s: &str) -> Vec<u8> {
        let source = utf16z("TestSource");
        let computer = utf16z("HOST-XP");
        let insert = utf16z(s);
        let string_off = 0x38 + source.len() + computer.len();
        let mut len = string_off + insert.len() + 4; // + trailing length
        len = (len + 7) & !7;
        let mut b = vec![0u8; len];
        put_u32(&mut b, 0x00, len as u32);
        put_u32(&mut b, 0x04, EVT_LFLE);
        put_u32(&mut b, 0x08, record_number);
        put_u32(&mut b, 0x0C, 1_100_000_000); // TimeGenerated (unix)
        put_u32(&mut b, 0x10, 1_100_000_001); // TimeWritten
        put_u32(&mut b, 0x14, event_id);
        put_u16(&mut b, 0x18, event_type);
        put_u16(&mut b, 0x1A, 1); // NumStrings
        put_u32(&mut b, 0x24, string_off as u32);
        b[0x38..0x38 + source.len()].copy_from_slice(&source);
        b[0x38 + source.len()..string_off].copy_from_slice(&computer);
        b[string_off..string_off + insert.len()].copy_from_slice(&insert);
        let l = b.len();
        put_u32(&mut b, l - 4, len as u32);
        b
    }

    /// EOF(커서) 레코드 0x28바이트. begin_record는 절대 파일 오프셋.
    fn eof_record(begin_record: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x28];
        put_u32(&mut b, 0x00, 0x28);
        for (i, m) in EVT_EOF_MAGIC.iter().enumerate() {
            put_u32(&mut b, 4 + i * 4, *m);
        }
        put_u32(&mut b, 0x14, begin_record);
        put_u32(&mut b, 0x24, 0x28);
        b
    }

    fn header(start_offset: u32, dirty: bool, file_len: u32) -> Vec<u8> {
        let mut b = vec![0u8; EVT_HEADER];
        put_u32(&mut b, 0x00, 0x30);
        put_u32(&mut b, 0x04, EVT_LFLE);
        put_u32(&mut b, 0x08, 1);
        put_u32(&mut b, 0x0C, 1);
        put_u32(&mut b, 0x10, start_offset);
        put_u32(&mut b, 0x20, file_len);
        put_u32(&mut b, 0x24, if dirty { 1 } else { 0 });
        put_u32(&mut b, 0x2C, 0x30);
        b
    }

    fn parse_to_rows(data: &[u8]) -> Vec<Row> {
        let dir = std::env::temp_dir().join(format!(
            "wina-evt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let evt = dir.join("SecEvent.Evt");
        std::fs::write(&evt, data).unwrap();
        let out = dir.join("out.sqlite");
        let n = parse_evt_stream(&evt, &out, "SecEvent").unwrap();
        let rows = crate::overview::read_table(&out, "SecEvent");
        assert_eq!(rows.len(), n);
        let _ = std::fs::remove_dir_all(dir);
        rows
    }

    #[test]
    fn parses_clean_evt_with_two_records() {
        let r1 = record(1, 0x0210, 0x08, "Administrator"); // 528 logon
        let r2 = record(2, 0x0211, 0x10, "guest");
        let mut stream = Vec::new();
        stream.extend(&r1);
        stream.extend(&r2);
        let eof_at = EVT_HEADER + stream.len();
        stream.extend(eof_record(EVT_HEADER as u32));
        let file_len = (EVT_HEADER + stream.len()) as u32;
        let mut data = header(EVT_HEADER as u32, false, file_len);
        data.extend(stream);

        let rows = parse_to_rows(&data);
        assert_eq!(rows.len(), 2, "eof_at={eof_at}");
        assert_eq!(rows[0].get("EventID").map(String::as_str), Some("528"));
        assert_eq!(rows[0].get("Provider").map(String::as_str), Some("TestSource"));
        assert_eq!(rows[0].get("Computer").map(String::as_str), Some("HOST-XP"));
        assert_eq!(rows[0].get("Channel").map(String::as_str), Some("Security"));
        assert_eq!(
            rows[0].get("LevelName").map(String::as_str),
            Some("AuditSuccess")
        );
        assert!(rows[0]
            .get("EventData")
            .unwrap()
            .contains("\"Strings\": [\"Administrator\"]"));
        assert!(!rows[0].get("timestamp").unwrap().is_empty());
        assert_eq!(rows[1].get("EventID").map(String::as_str), Some("529"));
        assert_eq!(
            rows[1].get("LevelName").map(String::as_str),
            Some("AuditFailure")
        );
    }

    /// dirty 헤더(StartOffset 무효) + 링 경계를 감아 도는 레코드 —
    /// floating footer로 시작점을 복원하고 wrap된 레코드도 온전히 읽어야 한다.
    #[test]
    fn parses_dirty_wrapped_evt_via_floating_footer() {
        let r1 = record(7, 0x0200, 0x04, "wrapped-first");
        let r2 = record(8, 0x0201, 0x04, "second");
        let eof = eof_record(0); // BeginRecord 손상(0) — footer 뒤 폴백 경로
        // 링 크기: 레코드들+EOF보다 넉넉히 크게, r1이 끝에서 감기도록 배치.
        let ring_len = r1.len() + r2.len() + eof.len() + 0x40;
        let shift = ring_len - r1.len() / 2; // r1의 후반부가 링 앞으로 감긴다
        let mut stream = Vec::new();
        stream.extend(&r1);
        stream.extend(&r2);
        stream.extend(&eof);
        stream.resize(ring_len, 0xCC);
        let mut ring = vec![0u8; ring_len];
        for (i, b) in stream.iter().enumerate() {
            ring[(i + shift) % ring_len] = *b;
        }
        // EOF 레코드가 파일에서 연속(비감김)이어야 footer 스캔이 찾는다.
        let eof_ring_pos = (r1.len() + r2.len() + shift) % ring_len;
        assert!(eof_ring_pos + eof.len() <= ring_len, "test layout: EOF must not wrap");
        let file_len = (EVT_HEADER + ring_len) as u32;
        let mut data = header(0xFFFF_FFFF, true, file_len); // StartOffset 무효
        data.extend(&ring);

        let rows = parse_to_rows(&data);
        // BeginRecord가 0이라 footer 뒤(=r1 시작)로 폴백 — r1(감김)·r2 순서.
        let ok: Vec<_> = rows
            .iter()
            .filter(|r| r.get("_status").map(String::as_str) == Some("ok"))
            .collect();
        assert_eq!(ok.len(), 2);
        assert!(ok[0].get("EventData").unwrap().contains("wrapped-first"));
        assert_eq!(ok[0].get("EventRecordID").map(String::as_str), Some("7"));
        assert!(ok[1].get("EventData").unwrap().contains("second"));
    }

    #[test]
    fn evt_channel_maps_default_log_names() {
        assert_eq!(evt_channel(&PathBuf::from("/x/SecEvent.Evt")), "Security");
        assert_eq!(evt_channel(&PathBuf::from("/x/SysEvent.Evt")), "System");
        assert_eq!(evt_channel(&PathBuf::from("/x/AppEvent.Evt")), "Application");
        assert_eq!(evt_channel(&PathBuf::from("/x/Custom.evt")), "Custom");
    }
}
