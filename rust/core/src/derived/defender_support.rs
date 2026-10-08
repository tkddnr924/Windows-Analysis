//! MPDetection support-log facts. Decoding, timestamp and line parse states
//! are preserved so a failed read never looks like a healthy zero-detection
//! file (뷰어13 A07). MPLog stays out of scope; only DETECTION lines become
//! detection rows.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

pub(super) const SUPPORT_CATEGORY: &str = "SUPPLEMENTAL";
pub(super) const SUPPORT_FILE: &str = "Defender_Support_Logs.sqlite";
/// Host-relative evidence database.
pub(super) const SUPPORT_DB: &str = "SUPPLEMENTAL/Defender_Support_Logs.sqlite";
pub(super) const FILES_TABLE: &str = "Defender_MPDetection_Files";
pub(super) const RECORDS_TABLE: &str = "Defender_MPDetection_Records";
pub(super) const ARTIFACT: &str = "MPDetection";

const CREATE_SQL: &str = r#"
CREATE TABLE "Defender_MPDetection_Files" (
  "_source_file" TEXT NOT NULL,
  "byte_count" INTEGER,
  "bom" TEXT,
  "encoding" TEXT,
  "decode_state" TEXT NOT NULL,
  "decode_error" TEXT,
  "line_count" INTEGER,
  "detection_line_count" INTEGER,
  "other_line_count" INTEGER,
  "unparsed_time_count" INTEGER,
  "incomplete_detection_count" INTEGER
);
CREATE TABLE "Defender_MPDetection_Records" (
  "_source_file" TEXT NOT NULL,
  "line_number" INTEGER NOT NULL,
  "raw_line" TEXT NOT NULL,
  "timestamp_raw" TEXT,
  "timestamp" TEXT,
  "timestamp_state" TEXT NOT NULL,
  "threat_name" TEXT,
  "resource_raw" TEXT,
  "parse_state" TEXT NOT NULL
);
"#;

/// 확인된 수집 인코딩만 해독한다 — 나머지는 실패로 남긴다.
pub(super) const DECODED_UTF16LE: &str = "decoded_utf16le_bom";
pub(super) const DECODED_UTF8_BOM: &str = "decoded_utf8_bom";
pub(super) const DECODED_UTF8: &str = "decoded_utf8";
pub(super) const DECODED_UTF8_LOSSY: &str = "decoded_utf8_lossy";
pub(super) const UNSUPPORTED_ENCODING: &str = "unsupported_encoding";
pub(super) const READ_FAILED: &str = "read_failed";

pub(super) fn support_path(out_dir: &Path) -> PathBuf {
    out_dir.join(SUPPORT_CATEGORY).join(SUPPORT_FILE)
}

pub(super) struct FileRow {
    pub rowid: i64,
    pub source_file: String,
    pub byte_count: Option<i64>,
    pub bom: Option<String>,
    pub encoding: Option<String>,
    pub decode_state: String,
    pub decode_error: Option<String>,
    pub line_count: Option<i64>,
    pub detection_line_count: Option<i64>,
    pub other_line_count: Option<i64>,
    pub unparsed_time_count: Option<i64>,
    pub incomplete_detection_count: Option<i64>,
}

pub(super) struct DetectionRow {
    pub rowid: i64,
    pub source_file: String,
    pub line_number: i64,
    pub raw_line: String,
    pub timestamp_raw: Option<String>,
    pub timestamp: Option<String>,
    pub timestamp_state: String,
    pub threat_name: Option<String>,
    pub resource_raw: Option<String>,
    pub parse_state: String,
}

struct Decoded {
    bom: Option<&'static str>,
    encoding: Option<&'static str>,
    state: &'static str,
    error: Option<String>,
    text: Option<String>,
}

/// Only the confirmed UTF-16LE(BOM)/UTF-8 forms are decoded; anything else is
/// recorded as an unsupported input instead of silently producing no rows.
fn decode(raw: &[u8]) -> Decoded {
    if raw.starts_with(&[0xFF, 0xFE]) {
        let body = &raw[2..];
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let error = (body.len() % 2 != 0)
            .then(|| "UTF-16LE 바이트 수가 홀수여서 마지막 바이트를 해독하지 못했습니다".to_string());
        return Decoded {
            bom: Some("FF FE"),
            encoding: Some("UTF-16LE"),
            state: DECODED_UTF16LE,
            error,
            text: Some(String::from_utf16_lossy(&units)),
        };
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        return Decoded {
            bom: Some("FE FF"),
            encoding: Some("UTF-16BE"),
            state: UNSUPPORTED_ENCODING,
            error: Some("확인된 지원 인코딩(UTF-16LE BOM/UTF-8)이 아닙니다".to_string()),
            text: None,
        };
    }
    let (bom, body, state_bom) = if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (Some("EF BB BF"), &raw[3..], true)
    } else {
        (None, raw, false)
    };
    match std::str::from_utf8(body) {
        Ok(text) => Decoded {
            bom,
            encoding: Some("UTF-8"),
            state: if state_bom { DECODED_UTF8_BOM } else { DECODED_UTF8 },
            error: None,
            text: Some(text.to_string()),
        },
        Err(error) => Decoded {
            bom,
            encoding: Some("UTF-8"),
            state: DECODED_UTF8_LOSSY,
            error: Some(format!("UTF-8 해독 실패 위치 {}: 대체 문자로 복원", error.valid_up_to())),
            text: Some(String::from_utf8_lossy(body).into_owned()),
        },
    }
}

/// MPDetection timestamps are UTC; the confirmed display rule is +9h KST.
pub(super) fn to_kst(raw: &str) -> Option<String> {
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(raw.trim(), format) {
            return Some(
                (parsed + chrono::Duration::hours(9))
                    .format("%Y-%m-%d %H:%M:%S%.3f")
                    .to_string(),
            );
        }
    }
    None
}

struct Scanned {
    file: FileRow,
    detections: Vec<DetectionRow>,
}

fn scan(path: &Path) -> Scanned {
    let display = path.to_string_lossy().to_string();
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(error) => {
            return Scanned {
                file: FileRow {
                    rowid: 0,
                    source_file: display,
                    byte_count: None,
                    bom: None,
                    encoding: None,
                    decode_state: READ_FAILED.to_string(),
                    decode_error: Some(error.to_string()),
                    line_count: None,
                    detection_line_count: None,
                    other_line_count: None,
                    unparsed_time_count: None,
                    incomplete_detection_count: None,
                },
                detections: Vec::new(),
            }
        }
    };
    let byte_count = Some(raw.len() as i64);
    let decoded = decode(&raw);
    let Some(text) = decoded.text else {
        return Scanned {
            file: FileRow {
                rowid: 0,
                source_file: display,
                byte_count,
                bom: decoded.bom.map(str::to_string),
                encoding: decoded.encoding.map(str::to_string),
                decode_state: decoded.state.to_string(),
                decode_error: decoded.error,
                line_count: None,
                detection_line_count: None,
                other_line_count: None,
                unparsed_time_count: None,
                incomplete_detection_count: None,
            },
            detections: Vec::new(),
        };
    };

    let mut detections = Vec::new();
    let (mut lines, mut detection_lines, mut unparsed, mut incomplete) = (0i64, 0i64, 0i64, 0i64);
    for (index, line) in text.lines().enumerate() {
        lines += 1;
        let trimmed = line.trim();
        let Some((time_raw, rest)) = trimmed.split_once(" DETECTION ") else {
            continue;
        };
        detection_lines += 1;
        let (threat, resource) = match rest.trim().split_once(' ') {
            Some((threat, resource)) => (threat.to_string(), resource.trim().to_string()),
            None => (rest.trim().to_string(), String::new()),
        };
        let time_raw = time_raw.trim();
        let converted = to_kst(time_raw);
        let timestamp_state = if time_raw.is_empty() {
            "absent"
        } else if converted.is_some() {
            "parsed_utc_plus9"
        } else {
            unparsed += 1;
            "unparsed"
        };
        let parse_state = if threat.is_empty() {
            incomplete += 1;
            "incomplete"
        } else {
            "parsed"
        };
        detections.push(DetectionRow {
            rowid: 0,
            source_file: display.clone(),
            line_number: index as i64 + 1,
            raw_line: line.to_string(),
            timestamp_raw: (!time_raw.is_empty()).then(|| time_raw.to_string()),
            timestamp: converted,
            timestamp_state: timestamp_state.to_string(),
            threat_name: (!threat.is_empty()).then_some(threat),
            resource_raw: (!resource.is_empty()).then_some(resource),
            parse_state: parse_state.to_string(),
        });
    }
    Scanned {
        file: FileRow {
            rowid: 0,
            source_file: display,
            byte_count,
            bom: decoded.bom.map(str::to_string),
            encoding: decoded.encoding.map(str::to_string),
            decode_state: decoded.state.to_string(),
            decode_error: decoded.error,
            line_count: Some(lines),
            detection_line_count: Some(detection_lines),
            other_line_count: Some(lines - detection_lines),
            unparsed_time_count: Some(unparsed),
            incomplete_detection_count: Some(incomplete),
        },
        detections,
    }
}

fn collected_logs(target: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(target)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            path.file_name()
                .map(|name| {
                    let name = name.to_string_lossy().to_lowercase();
                    name.starts_with("mpdetection") && name.ends_with(".log")
                })
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// Materialize MPDetection evidence before the Defender overview references it.
pub(super) fn prepare_inputs(out_dir: &Path, target: &Path, dataset_id: &str) -> Result<Vec<String>> {
    let dir = out_dir.join(SUPPORT_CATEGORY);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Defender 보조 증거 폴더 생성: {}", dir.display()))?;
    let path = support_path(out_dir);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 Defender 보조 증거 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("Defender 보조 증거 DB 생성: {}", path.display()))?;
    conn.execute_batch(CREATE_SQL)?;
    conn.execute_batch("BEGIN")?;
    let mut rows = 0usize;
    {
        let mut files = conn.prepare(&format!(
            "INSERT INTO \"{FILES_TABLE}\" (_source_file, byte_count, bom, encoding, decode_state, \
             decode_error, line_count, detection_line_count, other_line_count, unparsed_time_count, \
             incomplete_detection_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
        ))?;
        let mut records = conn.prepare(&format!(
            "INSERT INTO \"{RECORDS_TABLE}\" (_source_file, line_number, raw_line, timestamp_raw, \
             timestamp, timestamp_state, threat_name, resource_raw, parse_state) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
        ))?;
        for log in collected_logs(target) {
            let scanned = scan(&log);
            let file = &scanned.file;
            rows += files.execute(rusqlite::params![
                file.source_file,
                file.byte_count,
                file.bom,
                file.encoding,
                file.decode_state,
                file.decode_error,
                file.line_count,
                file.detection_line_count,
                file.other_line_count,
                file.unparsed_time_count,
                file.incomplete_detection_count,
            ])?;
            for detection in &scanned.detections {
                rows += records.execute(rusqlite::params![
                    detection.source_file,
                    detection.line_number,
                    detection.raw_line,
                    detection.timestamp_raw,
                    detection.timestamp,
                    detection.timestamp_state,
                    detection.threat_name,
                    detection.resource_raw,
                    detection.parse_state,
                ])?;
            }
        }
    }
    conn.execute_batch("COMMIT")?;
    drop(conn);
    super::stamp_facts_generation(&path, dataset_id)?;
    Ok(if rows == 0 {
        Vec::new()
    } else {
        vec![SUPPORT_DB.to_string()]
    })
}

fn open_support(out_dir: &Path) -> Result<Option<Connection>> {
    let path = support_path(out_dir);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?))
}

pub(super) fn read_files(out_dir: &Path) -> Result<Vec<FileRow>> {
    let Some(conn) = open_support(out_dir)? else {
        return Ok(Vec::new());
    };
    let mut query = conn.prepare(&format!(
        "SELECT rowid,_source_file,byte_count,bom,encoding,decode_state,decode_error,line_count, \
         detection_line_count,other_line_count,unparsed_time_count,incomplete_detection_count \
         FROM \"{FILES_TABLE}\" ORDER BY rowid"
    ))?;
    let rows = query.query_map([], |row| {
        Ok(FileRow {
            rowid: row.get(0)?,
            source_file: row.get(1)?,
            byte_count: row.get(2)?,
            bom: row.get(3)?,
            encoding: row.get(4)?,
            decode_state: row.get(5)?,
            decode_error: row.get(6)?,
            line_count: row.get(7)?,
            detection_line_count: row.get(8)?,
            other_line_count: row.get(9)?,
            unparsed_time_count: row.get(10)?,
            incomplete_detection_count: row.get(11)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(super) fn read_detections(out_dir: &Path) -> Result<Vec<DetectionRow>> {
    let Some(conn) = open_support(out_dir)? else {
        return Ok(Vec::new());
    };
    let mut query = conn.prepare(&format!(
        "SELECT rowid,_source_file,line_number,raw_line,timestamp_raw,timestamp,timestamp_state, \
         threat_name,resource_raw,parse_state FROM \"{RECORDS_TABLE}\" ORDER BY rowid"
    ))?;
    let rows = query.query_map([], |row| {
        Ok(DetectionRow {
            rowid: row.get(0)?,
            source_file: row.get(1)?,
            line_number: row.get(2)?,
            raw_line: row.get(3)?,
            timestamp_raw: row.get(4)?,
            timestamp: row.get(5)?,
            timestamp_state: row.get(6)?,
            threat_name: row.get(7)?,
            resource_raw: row.get(8)?,
            parse_state: row.get(9)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
