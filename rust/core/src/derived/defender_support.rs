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
  "timestamp_raw" TEXT NOT NULL,
  "timestamp" TEXT,
  "timestamp_state" TEXT NOT NULL,
  "source_timezone" TEXT,
  "threat_name" TEXT,
  "resource_raw" TEXT,
  "parse_state" TEXT NOT NULL
);
"#;

/// 확인된 포맷만 해독한다 — 인코딩을 확정하지 못하면 실패로 남긴다.
/// BOM 바이트열은 Unicode 표준(UTF-16LE `FF FE`, UTF-16BE `FE FF`,
/// UTF-32LE `FF FE 00 00`, UTF-32BE `00 00 FE FF`)을 따른다.
pub(super) const DECODED_UTF16LE: &str = "decoded_utf16le_bom";
pub(super) const DECODED_UTF16BE: &str = "decoded_utf16be_bom";
pub(super) const DECODED_UTF8_BOM: &str = "decoded_utf8_bom";
pub(super) const DECODED_UTF8: &str = "decoded_utf8";
pub(super) const DECODED_UTF8_LOSSY: &str = "decoded_utf8_lossy";
pub(super) const UNSUPPORTED_ENCODING: &str = "unsupported_encoding";
pub(super) const UNDETERMINED_ENCODING: &str = "undetermined_encoding";
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
    /// Text before ` DETECTION ` on a trimmed line; never empty.
    pub timestamp_raw: String,
    pub timestamp: Option<String>,
    pub timestamp_state: String,
    /// Where the recorded instant's zone came from; never an assumed +9.
    pub source_timezone: Option<String>,
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

/// UTF-16 with a byte order mark and UTF-8 are decoded from their standard
/// signatures. A BOM-less stream carrying NUL bytes is not plain UTF-8 text,
/// so it stays undetermined instead of silently producing zero detections.
fn decode(raw: &[u8]) -> Decoded {
    let utf16 = |body: &[u8], big_endian: bool| -> (String, Option<String>) {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| {
                if big_endian {
                    u16::from_be_bytes([pair[0], pair[1]])
                } else {
                    u16::from_le_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        let error = (body.len() % 2 != 0)
            .then(|| "UTF-16 바이트 수가 홀수여서 마지막 바이트를 해독하지 못했습니다".to_string());
        (String::from_utf16_lossy(&units), error)
    };
    // UTF-32 signatures share a prefix with UTF-16 and are not supported.
    if raw.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) || raw.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        let little = raw.starts_with(&[0xFF, 0xFE]);
        return Decoded {
            bom: Some(if little { "FF FE 00 00" } else { "00 00 FE FF" }),
            encoding: Some(if little { "UTF-32LE" } else { "UTF-32BE" }),
            state: UNSUPPORTED_ENCODING,
            error: Some("UTF-32 BOM 입력은 지원 인코딩이 아닙니다".to_string()),
            text: None,
        };
    }
    if raw.starts_with(&[0xFF, 0xFE]) {
        let (text, error) = utf16(&raw[2..], false);
        return Decoded {
            bom: Some("FF FE"),
            encoding: Some("UTF-16LE"),
            state: DECODED_UTF16LE,
            error,
            text: Some(text),
        };
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        let (text, error) = utf16(&raw[2..], true);
        return Decoded {
            bom: Some("FE FF"),
            encoding: Some("UTF-16BE"),
            state: DECODED_UTF16BE,
            error,
            text: Some(text),
        };
    }
    let (bom, body, state_bom) = if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (Some("EF BB BF"), &raw[3..], true)
    } else {
        (None, raw, false)
    };
    if !state_bom && body.contains(&0) {
        return Decoded {
            bom: None,
            encoding: None,
            state: UNDETERMINED_ENCODING,
            error: Some(
                "BOM이 없고 NUL 바이트가 있어 인코딩을 확정하지 못했습니다(UTF-8 텍스트가 아님)"
                    .to_string(),
            ),
            text: None,
        };
    }
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

/// Recorded source zone; display timestamps follow the UTC+9 contract.
pub(super) const ZONE_UTC_EXPLICIT: &str = "utc_explicit";
pub(super) const ZONE_OFFSET_EXPLICIT: &str = "offset_explicit";
pub(super) const ZONE_UTC_DOCUMENTED: &str = "utc_documented_unzoned";

pub(super) struct ParsedTime {
    pub display: String,
    pub zone: &'static str,
}

impl ParsedTime {
    /// The stored state keeps the zone evidence visible next to the value.
    pub fn state(&self) -> &'static str {
        match self.zone {
            ZONE_UTC_EXPLICIT => "parsed_utc_explicit",
            ZONE_OFFSET_EXPLICIT => "parsed_offset_explicit",
            _ => "parsed_utc_documented",
        }
    }
}

fn as_kst(utc: chrono::NaiveDateTime) -> Option<String> {
    utc.checked_add_signed(chrono::Duration::hours(9))
        .map(|time| time.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// An explicit `Z` or numeric offset (RFC 3339 §5.6) is used as written; an
/// unzoned value follows Defender's documented UTC logging. Nothing else is
/// shifted, so a +9 is never invented for an unknown zone.
pub(super) fn parse_log_time(raw: &str) -> Option<ParsedTime> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let zulu = trimmed.ends_with('Z') || trimmed.ends_with('z');
        return Some(ParsedTime {
            display: as_kst(parsed.naive_utc())?,
            zone: if zulu { ZONE_UTC_EXPLICIT } else { ZONE_OFFSET_EXPLICIT },
        });
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(ParsedTime { display: as_kst(parsed)?, zone: ZONE_UTC_DOCUMENTED });
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
        let converted = parse_log_time(time_raw);
        let timestamp_state = if let Some(parsed) = &converted {
            parsed.state()
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
            timestamp_raw: time_raw.to_string(),
            timestamp: converted.as_ref().map(|parsed| parsed.display.clone()),
            timestamp_state: timestamp_state.to_string(),
            source_timezone: converted.as_ref().map(|parsed| parsed.zone.to_string()),
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
             timestamp, timestamp_state, source_timezone, threat_name, resource_raw, parse_state) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
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
                    detection.source_timezone,
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
         source_timezone,threat_name,resource_raw,parse_state FROM \"{RECORDS_TABLE}\" ORDER BY rowid"
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
            source_timezone: row.get(7)?,
            threat_name: row.get(8)?,
            resource_raw: row.get(9)?,
            parse_state: row.get(10)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
        let mut bytes = if big_endian { vec![0xFE, 0xFF] } else { vec![0xFF, 0xFE] };
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&if big_endian {
                unit.to_be_bytes()
            } else {
                unit.to_le_bytes()
            });
        }
        bytes
    }

    // A07: both UTF-16 byte orders decode; the odd trailing byte stays an
    // explicit error instead of a silently shortened line.
    #[test]
    fn utf16_byte_orders_decode_and_odd_length_is_reported() {
        let little = decode(&utf16("DETECTION", false));
        assert_eq!(little.state, DECODED_UTF16LE);
        assert_eq!(little.text.as_deref(), Some("DETECTION"));
        assert!(little.error.is_none());

        let big = decode(&utf16("DETECTION", true));
        assert_eq!(big.state, DECODED_UTF16BE);
        assert_eq!(big.encoding, Some("UTF-16BE"));
        assert_eq!(big.text.as_deref(), Some("DETECTION"));

        let mut odd = utf16("AB", true);
        odd.push(0x00);
        let odd = decode(&odd);
        assert_eq!(odd.text.as_deref(), Some("AB"));
        assert!(odd.error.is_some());
    }

    // A BOM-less UTF-16 stream is valid UTF-8 byte-wise, so without this rule
    // it would read as a healthy file with zero detections.
    #[test]
    fn bom_less_nul_bytes_stay_undetermined_not_empty() {
        let mut bytes = Vec::new();
        for unit in "2026-04-01T01:00:00.000 DETECTION X res".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode(&bytes);
        assert_eq!(decoded.state, UNDETERMINED_ENCODING);
        assert!(decoded.text.is_none());
        assert!(decoded.encoding.is_none());

        // UTF-32 shares the UTF-16 prefix and is not decoded as UTF-16.
        let utf32 = decode(&[0xFF, 0xFE, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]);
        assert_eq!(utf32.state, UNSUPPORTED_ENCODING);
        assert_eq!(utf32.encoding, Some("UTF-32LE"));

        let plain = decode("2026-04-01T01:00:00.000 DETECTION X res".as_bytes());
        assert_eq!(plain.state, DECODED_UTF8);
    }

    // A07: the source zone is evidence, never an assumed +9.
    #[test]
    fn time_zone_source_is_recorded_per_format() {
        let zulu = parse_log_time("2026-04-01T01:00:00.000Z").unwrap();
        assert_eq!(zulu.zone, ZONE_UTC_EXPLICIT);
        assert_eq!(zulu.display, "2026-04-01 10:00:00.000");
        assert_eq!(zulu.state(), "parsed_utc_explicit");

        let offset = parse_log_time("2026-04-01T01:00:00+02:00").unwrap();
        assert_eq!(offset.zone, ZONE_OFFSET_EXPLICIT);
        // 01:00+02:00 is 23:00Z of the previous day, so KST is 08:00.
        assert_eq!(offset.display, "2026-04-01 08:00:00.000");

        let unzoned = parse_log_time("2026-04-01T01:00:00.000").unwrap();
        assert_eq!(unzoned.zone, ZONE_UTC_DOCUMENTED);
        assert_eq!(unzoned.display, "2026-04-01 10:00:00.000");

        assert!(parse_log_time("NOT-A-TIME").is_none());
        assert!(parse_log_time("  ").is_none());
    }

    #[test]
    fn unrepresentable_display_timestamp_stays_unparsed() {
        let maximum = chrono::NaiveDateTime::MAX.format("%Y-%m-%dT%H:%M:%S%.f").to_string();
        assert!(parse_log_time(&maximum).is_none());
    }
}
