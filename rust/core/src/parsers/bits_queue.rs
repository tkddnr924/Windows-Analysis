//! BITS job queue (qmgr) parser: the service's own transfer queue, not the
//! Bits-Client event log.
//!
//! Two containers exist and both are parsed here:
//!
//! * `qmgr.db` — Windows 10 and later. An ESE database whose `Jobs` and
//!   `Files` tables hold one `Id` GUID plus one `Blob` per record. Each blob
//!   starts with a 16 byte record delimiter that is kept as evidence and then
//!   the job (`CONTROL` + transfer + metadata) or file structure.
//! * `qmgr0.dat` / `qmgr1.dat` — Windows 8.1 and earlier. A flat queue file
//!   with a 16 byte header, the queue file marker, the queue marker, the
//!   declared job count and the job region. Jobs inside that region are
//!   separated by a version-specific delimiter.
//!
//! Record structures are the reverse-engineered layout published by ANSSI
//! (`ANSSI-FR/bits_parser`, MIT) and FireEye/Mandiant (`fireeye/BitsParser`,
//! Apache-2.0); the enumerations they map onto are the documented BITS COM
//! values (`BG_JOB_TYPE`, `BG_JOB_PRIORITY`, `BG_JOB_STATE`, `BG_NOTIFY_*`,
//! `BG_SIZE_UNKNOWN`).
//!
//! Only live records are read: the ESE tables are enumerated through
//! `libesedb` and the legacy job region is bounded by the queue markers. The
//! unallocated remainder of a queue file and ESE page slack are never carved,
//! and no value is inferred from another record: every field is either read
//! from the bytes or stays absent with the failure recorded.
use std::path::{Path, PathBuf};

use libesedb::EseDb;

use crate::hex::hex_lower;

// ---------------------------------------------------------------------------
// Format constants (ANSSI bits/const.py, FireEye BitsParser.py)
// ---------------------------------------------------------------------------

/// File marker after the version-dependent legacy header.
pub const FILE_HEADER: [u8; 16] = [
    0x13, 0xF7, 0x2B, 0xC8, 0x40, 0x99, 0x12, 0x4A, 0x9F, 0x1A, 0x3A, 0xAE, 0xBD, 0x89, 0x4E, 0xEA,
];
/// Marker that brackets the job region of a legacy queue file.
pub const QUEUE_HEADER: [u8; 16] = [
    0x47, 0x44, 0x5F, 0x00, 0xA9, 0xBD, 0xBA, 0x44, 0x98, 0x51, 0xC4, 0x7B, 0xB6, 0xC0, 0x7A, 0xCE,
];
/// Marker that brackets the transfer (file) section of a job record.
pub const XFER_HEADER: [u8; 16] = [
    0x36, 0xDA, 0x56, 0x77, 0x6F, 0x51, 0x5A, 0x43, 0xAC, 0xAC, 0x44, 0xA2, 0x48, 0xFF, 0xF3, 0x4D,
];
/// First four bytes of the trailer that follows a file record in both
/// containers (observed in the public Win10/Win11/Win8.1 samples). Framing
/// never searches for it: a size of 3 or a three-character string produces the
/// same bytes, so records are walked by their own field sizes.
#[cfg(test)]
const FILE_TRAILER_MARKER: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
/// ESE database signature at offset 4 (0x89ABCDEF little endian).
pub const ESE_SIGNATURE: [u8; 4] = [0xEF, 0xCD, 0xAB, 0x89];

/// Job delimiters of the legacy queue; each BITS build uses exactly one. The
/// id is the ANSSI table key and identifies the delimiter only — it is not a
/// Windows version claim.
pub const JOB_DELIMITERS: [(i64, [u8; 16]); 5] = [
    (
        1,
        [
            0x93, 0x36, 0x20, 0x35, 0xA0, 0x0C, 0x10, 0x4A, 0x84, 0xF3, 0xB1, 0x7E, 0x7B, 0x49,
            0x9C, 0xD7,
        ],
    ),
    (
        2,
        [
            0x10, 0x13, 0x70, 0xC8, 0x36, 0x53, 0xB3, 0x41, 0x83, 0xE5, 0x81, 0x55, 0x7F, 0x36,
            0x1B, 0x87,
        ],
    ),
    (
        3,
        [
            0x8C, 0x93, 0xEA, 0x64, 0x03, 0x0F, 0x68, 0x40, 0xB4, 0x6F, 0xF9, 0x7F, 0xE5, 0x1D,
            0x4D, 0xCD,
        ],
    ),
    (
        4,
        [
            0xB3, 0x46, 0xED, 0x3D, 0x3B, 0x10, 0xF9, 0x44, 0xBC, 0x2F, 0xE8, 0x37, 0x8B, 0xD3,
            0x19, 0x86,
        ],
    ),
    (
        5,
        [
            0x74, 0xE7, 0x0C, 0x81, 0xD2, 0xBB, 0xCC, 0x48, 0x9E, 0x47, 0x86, 0x2E, 0x8D, 0x58,
            0xF3, 0xC6,
        ],
    ),
];

/// `BG_SIZE_UNKNOWN`: the documented "size not known yet" sentinel.
pub const SIZE_UNKNOWN: u64 = u64::MAX;

pub const ESE_JOBS_TABLE: &str = "Jobs";
pub const ESE_FILES_TABLE: &str = "Files";
/// Every ESE blob starts with a 16 byte record delimiter.
const ESE_BLOB_PREFIX: usize = 16;
/// Bytes between the end of a parsed ESE file record and the trailing
/// FILETIME observed by BitsParser.
const ESE_FILE_TRAILER_GAP: usize = 29;

// ---------------------------------------------------------------------------
// Documented enumerations
// ---------------------------------------------------------------------------

/// `BG_JOB_TYPE` (bits.h).
pub fn job_type_name(raw: u32) -> Option<&'static str> {
    match raw {
        0 => Some("BG_JOB_TYPE_DOWNLOAD"),
        1 => Some("BG_JOB_TYPE_UPLOAD"),
        2 => Some("BG_JOB_TYPE_UPLOAD_REPLY"),
        _ => None,
    }
}

/// `BG_JOB_PRIORITY` (bits.h).
pub fn job_priority_name(raw: u32) -> Option<&'static str> {
    match raw {
        0 => Some("BG_JOB_PRIORITY_FOREGROUND"),
        1 => Some("BG_JOB_PRIORITY_HIGH"),
        2 => Some("BG_JOB_PRIORITY_NORMAL"),
        3 => Some("BG_JOB_PRIORITY_LOW"),
        _ => None,
    }
}

/// `BG_JOB_STATE` (bits.h).
pub fn job_state_name(raw: u32) -> Option<&'static str> {
    match raw {
        0 => Some("BG_JOB_STATE_QUEUED"),
        1 => Some("BG_JOB_STATE_CONNECTING"),
        2 => Some("BG_JOB_STATE_TRANSFERRING"),
        3 => Some("BG_JOB_STATE_SUSPENDED"),
        4 => Some("BG_JOB_STATE_ERROR"),
        5 => Some("BG_JOB_STATE_TRANSIENT_ERROR"),
        6 => Some("BG_JOB_STATE_TRANSFERRED"),
        7 => Some("BG_JOB_STATE_ACKNOWLEDGED"),
        8 => Some("BG_JOB_STATE_CANCELLED"),
        _ => None,
    }
}

const NOTIFY_FLAGS: [(u32, &str); 6] = [
    (0x0001, "BG_NOTIFY_JOB_TRANSFERRED"),
    (0x0002, "BG_NOTIFY_JOB_ERROR"),
    (0x0004, "BG_NOTIFY_DISABLE"),
    (0x0008, "BG_NOTIFY_JOB_MODIFICATION"),
    (0x0010, "BG_NOTIFY_FILE_TRANSFERRED"),
    (0x0020, "BG_NOTIFY_FILE_RANGES_TRANSFERRED"),
];

/// Documented notify flags plus the bits no documented flag covers.
pub fn notify_flags(raw: u32) -> (Vec<&'static str>, u32) {
    let mut names = Vec::new();
    let mut rest = raw;
    for (bit, name) in NOTIFY_FLAGS {
        if raw & bit != 0 {
            names.push(name);
            rest &= !bit;
        }
    }
    (names, rest)
}

// ---------------------------------------------------------------------------
// Parsed records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// Windows 10+ `qmgr.db` (ESE).
    Ese,
    /// `qmgr0.dat` / `qmgr1.dat`.
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueFormat {
    Ese,
    Legacy,
    Unknown,
}

impl QueueFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            QueueFormat::Ese => "ese_qmgr_db",
            QueueFormat::Legacy => "legacy_qmgr_queue",
            QueueFormat::Unknown => "unknown",
        }
    }
}

/// One recorded job error structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobError {
    pub code: u64,
    pub stat1: u32,
    pub stat2: u32,
    pub stat3: u32,
    pub stat4: u32,
    pub reserved: u8,
}

#[derive(Debug, Clone, Default)]
pub struct QueueJob {
    pub record_index: i64,
    pub container_table: Option<String>,
    pub container_record_index: Option<i64>,
    pub record_offset: Option<i64>,
    pub record_length: i64,
    pub container_record_id: Option<String>,
    pub blob_prefix_hex: Option<String>,
    pub job_type_raw: Option<u32>,
    pub priority_raw: Option<u32>,
    pub state_raw: Option<u32>,
    pub control_reserved_raw: Option<u32>,
    pub job_id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub notify_command: Option<String>,
    pub notify_arguments: Option<String>,
    pub owner_sid: Option<String>,
    pub notify_flags_raw: Option<u32>,
    pub access_token_offset: Option<i64>,
    pub access_token_length: Option<i64>,
    pub transfer_section_kind: Option<&'static str>,
    pub declared_file_count: Option<u32>,
    pub file_reference_guids: Vec<String>,
    pub files: Vec<QueueFile>,
    pub error_count: Option<u32>,
    pub errors: Vec<JobError>,
    pub transient_error_count: Option<u32>,
    pub retry_delay_raw: Option<u32>,
    pub timeout_raw: Option<u32>,
    pub created_raw: Option<u64>,
    pub modified_raw: Option<u64>,
    pub other_time0_raw: Option<u64>,
    pub other_time1_raw: Option<u64>,
    pub other_time2_raw: Option<u64>,
    pub metadata_padding_hex: Option<String>,
    pub metadata_state: &'static str,
    /// Bytes past the declared GUID references in an ESE transfer section.
    pub transfer_trailing_length: Option<i64>,
    /// Bytes left after the parsed metadata fields.
    pub metadata_trailing_length: Option<i64>,
    pub parse_status: &'static str,
    pub parse_method: &'static str,
    pub parse_error: Option<String>,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct QueueFile {
    pub record_index: i64,
    pub container_table: Option<String>,
    pub container_record_index: Option<i64>,
    pub record_offset: Option<i64>,
    pub record_length: i64,
    pub container_record_id: Option<String>,
    pub blob_prefix_hex: Option<String>,
    pub job_record_index: Option<i64>,
    pub job_id: Option<String>,
    pub link_basis: &'static str,
    pub file_index_in_job: Option<i64>,
    pub dest_file: Option<String>,
    pub source_url: Option<String>,
    pub tmp_file: Option<String>,
    pub download_size: Option<u64>,
    pub transfer_size: Option<u64>,
    pub reserved_byte: Option<u8>,
    pub drive: Option<String>,
    pub volume_guid: Option<String>,
    pub trailing_filetime: Option<u64>,
    pub trailing_length: Option<i64>,
    pub parse_status: &'static str,
    pub parse_method: &'static str,
    pub parse_error: Option<String>,
    pub blob: Vec<u8>,
}

/// Everything one queue input yielded, including the reason it yielded nothing.
#[derive(Debug, Clone)]
pub struct ParsedQueue {
    pub format: QueueFormat,
    pub format_detail: Option<String>,
    /// `parsed`, `parsed_with_errors`, `unsupported_format`, `open_failed`,
    /// `read_failed`, `truncated`.
    pub status: &'static str,
    pub error: Option<String>,
    pub declared_job_count: Option<u32>,
    pub job_delimiter: Option<String>,
    pub job_delimiter_id: Option<i64>,
    pub jobs: Vec<QueueJob>,
    /// File records that are not nested in a job record (ESE `Files` table).
    pub files: Vec<QueueFile>,
}

impl ParsedQueue {
    fn empty(format: QueueFormat, status: &'static str, error: Option<String>) -> Self {
        Self {
            format,
            format_detail: None,
            status,
            error,
            declared_job_count: None,
            job_delimiter: None,
            job_delimiter_id: None,
            jobs: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Records whose own parse failed or stayed partial.
    pub fn failed_record_count(&self) -> i64 {
        let jobs = self
            .jobs
            .iter()
            .filter(|job| job.parse_status != "parsed")
            .count();
        let nested = self
            .jobs
            .iter()
            .flat_map(|job| job.files.iter())
            .filter(|file| file.parse_status != "parsed")
            .count();
        let loose = self
            .files
            .iter()
            .filter(|file| file.parse_status != "parsed")
            .count();
        (jobs + nested + loose) as i64
    }

    pub fn file_record_count(&self) -> i64 {
        let nested: usize = self.jobs.iter().map(|job| job.files.len()).sum();
        (nested + self.files.len()) as i64
    }

    fn settle(mut self) -> Self {
        if self.status == "parsed" && self.failed_record_count() > 0 {
            self.status = "parsed_with_errors";
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMatch {
    FileName,
    PathContains,
}

/// Queue inputs looked for inside a collection. The directory entry records
/// whether the queue folder itself was collected.
pub const INPUT_PATTERNS: [(&str, &str, InputMatch, &str); 4] = [
    (
        "qmgr_database",
        "qmgr.db",
        InputMatch::FileName,
        "Windows 10 이후 BITS 작업 큐 ESE DB(%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader)",
    ),
    (
        "qmgr_legacy_queue",
        "qmgr0.dat",
        InputMatch::FileName,
        "구형 BITS 작업 큐 파일",
    ),
    (
        "qmgr_legacy_queue",
        "qmgr1.dat",
        InputMatch::FileName,
        "구형 BITS 작업 큐 파일",
    ),
    (
        "downloader_directory",
        "microsoft/network/downloader",
        InputMatch::PathContains,
        "BITS 작업 큐 디렉터리 수집 여부",
    ),
];

#[derive(Debug, Clone)]
pub struct DiscoveredInput {
    pub kind: &'static str,
    pub pattern: &'static str,
    pub note: &'static str,
    /// None when the pattern matched nothing.
    pub path: Option<PathBuf>,
    /// True for the directory pattern, whose match is a path fragment.
    pub directory_only: bool,
}

/// Match the queue patterns against an already collected file list.
pub fn discover_inputs(files: &[PathBuf]) -> Vec<DiscoveredInput> {
    let mut found = Vec::new();
    for (kind, pattern, mode, note) in INPUT_PATTERNS {
        let mut hits: Vec<PathBuf> = Vec::new();
        for path in files {
            let hit = match mode {
                InputMatch::FileName => path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_lowercase() == pattern)
                    .unwrap_or(false),
                InputMatch::PathContains => path
                    .to_string_lossy()
                    .to_lowercase()
                    .replace('\\', "/")
                    .contains(pattern),
            };
            if hit {
                hits.push(path.clone());
            }
        }
        hits.sort();
        let directory_only = mode == InputMatch::PathContains;
        if hits.is_empty() {
            found.push(DiscoveredInput {
                kind,
                pattern,
                note,
                path: None,
                directory_only,
            });
            continue;
        }
        if directory_only {
            // One observation per collected queue directory, not per file.
            let mut dirs: Vec<PathBuf> = hits
                .iter()
                .filter_map(|path| path.parent().map(Path::to_path_buf))
                .collect();
            dirs.sort();
            dirs.dedup();
            for dir in dirs {
                found.push(DiscoveredInput {
                    kind,
                    pattern,
                    note,
                    path: Some(dir),
                    directory_only,
                });
            }
            continue;
        }
        for path in hits {
            found.push(DiscoveredInput {
                kind,
                pattern,
                note,
                path: Some(path),
                directory_only,
            });
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Byte readers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        if self.remaining() < count {
            return Err(format!(
                "{count}바이트가 필요하지만 {}바이트만 남았습니다(위치 {})",
                self.remaining(),
                self.pos
            ));
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn guid(&mut self) -> Result<String, String> {
        Ok(format_guid(self.take(16)?))
    }

    /// `u32` character count followed by that many UTF-16LE code units.
    fn pascal_utf16(&mut self) -> Result<String, String> {
        let count = self.u32()? as usize;
        let bytes = count
            .checked_mul(2)
            .ok_or_else(|| format!("문자열 길이 {count}이 범위를 벗어났습니다"))?;
        let raw = self.take(bytes)?;
        Ok(decode_utf16(raw))
    }
}

/// GUID bytes in Windows (mixed endian) order to its canonical text form.
pub fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return hex_lower(bytes);
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        hex_lower(&bytes[10..16])
    )
}

fn decode_utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\u{0}')
        .to_string()
}

fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    (from..=data.len() - needle.len()).find(|&start| &data[start..start + needle.len()] == needle)
}

fn count_occurrences(data: &[u8], needle: &[u8]) -> usize {
    let mut total = 0;
    let mut from = 0;
    while let Some(found) = find(data, needle, from) {
        total += 1;
        from = found + needle.len();
    }
    total
}

// ---------------------------------------------------------------------------
// Record parsing
// ---------------------------------------------------------------------------

/// Parse one ESE `Files` blob body: the record starts at offset 0 and the
/// remainder of the blob is its trailer, which is kept as evidence.
pub fn parse_file_record(body: &[u8], container: Container) -> QueueFile {
    let (mut file, end) = read_file_record(body, 0);
    file.record_length = body.len() as i64;
    file.blob = body.to_vec();
    if let Some(end) = end {
        file.trailing_length = Some(body.len().saturating_sub(end) as i64);
        if container == Container::Ese {
            // Observed in the public Win10/Win11 samples: a FILETIME sits 29
            // bytes past the end of the record. Its meaning is not documented,
            // so it is preserved and not named.
            let offset = end + ESE_FILE_TRAILER_GAP;
            if offset + 8 <= body.len() {
                let bytes: [u8; 8] = body[offset..offset + 8].try_into().unwrap();
                file.trailing_filetime = Some(u64::from_le_bytes(bytes));
            }
        }
    }
    file
}

/// Read the fields of one file record at `start`, bounded by the buffer.
///
/// Returns the record with every field it could read plus the end offset of
/// the record when the whole structure was present. Framing never depends on
/// searching for a byte pattern: a record is located by its own field sizes,
/// because any of its strings, sizes or paths may contain the same bytes as a
/// separator (a transferred size of 3, for example, is `03 00 00 00 …`).
fn read_file_record(body: &[u8], start: usize) -> (QueueFile, Option<usize>) {
    let mut file = QueueFile {
        record_offset: Some(start as i64),
        link_basis: "unlinked",
        parse_status: "parsed",
        parse_method: "sequential",
        ..QueueFile::default()
    };
    let mut reader = Reader::at(body, start);
    let result = (|| -> Result<usize, String> {
        file.dest_file = Some(reader.pascal_utf16()?);
        file.source_url = Some(reader.pascal_utf16()?);
        file.tmp_file = Some(reader.pascal_utf16()?);
        file.download_size = Some(reader.u64()?);
        file.transfer_size = Some(reader.u64()?);
        file.reserved_byte = Some(reader.u8()?);
        file.drive = Some(reader.pascal_utf16()?);
        file.volume_guid = Some(reader.pascal_utf16()?);
        Ok(reader.pos)
    })();
    match result {
        Ok(end) => (file, Some(end)),
        Err(error) => {
            file.parse_status = "failed";
            file.parse_error = Some(error);
            (file, None)
        }
    }
}

/// A re-synchronised candidate must be a complete record with a destination
/// and a source; a run of zero bytes parses as empty strings and is not one.
fn is_plausible_record(file: &QueueFile) -> bool {
    let filled = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
    filled(&file.dest_file) && filled(&file.source_url)
}

/// Parse one job record body (ESE: the blob after its 16 byte prefix; legacy:
/// one job of the live region). The job markers are 16 byte GUIDs, so the
/// section boundaries come from those markers and every field inside is read
/// by its own size.
pub fn parse_job_record(body: &[u8], container: Container) -> QueueJob {
    let mut job = QueueJob {
        record_length: body.len() as i64,
        metadata_state: "absent",
        parse_status: "parsed",
        parse_method: "sequential",
        blob: body.to_vec(),
        ..QueueJob::default()
    };
    let mut reader = Reader::new(body);
    if let Err(error) = read_control(&mut reader, &mut job) {
        job.parse_status = "failed";
        job.parse_error = Some(error);
        return job;
    }

    let Some(first) = find(body, &XFER_HEADER, reader.pos) else {
        job.parse_status = "partial";
        job.parse_error = Some("전송 구간 표식(XFER_HEADER)을 찾지 못했습니다".into());
        job.access_token_offset = Some(reader.pos as i64);
        job.access_token_length = Some(body.len().saturating_sub(reader.pos) as i64);
        return job;
    };
    job.access_token_offset = Some(reader.pos as i64);
    job.access_token_length = Some((first - reader.pos) as i64);

    let mut reader = Reader::at(body, first + XFER_HEADER.len());
    match reader.u32() {
        Ok(count) => job.declared_file_count = Some(count),
        Err(error) => {
            job.parse_status = "partial";
            job.parse_error = Some(format!("전송 구간의 파일 수를 읽지 못했습니다: {error}"));
            return job;
        }
    }
    let second = find(body, &XFER_HEADER, reader.pos);
    let section_end = second.unwrap_or(body.len());
    let section = &body[reader.pos.min(section_end)..section_end];
    read_transfer_section(section, reader.pos, container, &mut job);

    match second {
        Some(position) => {
            let metadata = &body[position + XFER_HEADER.len()..];
            read_metadata(metadata, &mut job);
        }
        None => {
            job.metadata_state = "absent";
            if job.parse_status == "parsed" {
                job.parse_status = "partial";
                job.parse_error.get_or_insert_with(|| {
                    "작업 메타데이터 구간 표식이 없어 시각·오류 정보를 확인할 수 없습니다".into()
                });
            }
        }
    }
    job
}

fn read_control(reader: &mut Reader<'_>, job: &mut QueueJob) -> Result<(), String> {
    job.job_type_raw = Some(reader.u32()?);
    job.priority_raw = Some(reader.u32()?);
    job.state_raw = Some(reader.u32()?);
    job.control_reserved_raw = Some(reader.u32()?);
    job.job_id = Some(reader.guid()?);
    job.name = Some(reader.pascal_utf16()?);
    job.description = Some(reader.pascal_utf16()?);
    job.notify_command = Some(reader.pascal_utf16()?);
    job.notify_arguments = Some(reader.pascal_utf16()?);
    job.owner_sid = Some(reader.pascal_utf16()?);
    job.notify_flags_raw = Some(reader.u32()?);
    Ok(())
}

/// The transfer section holds file records (legacy queue) or 16 byte GUID
/// references into the ESE `Files` table.
fn read_transfer_section(
    section: &[u8],
    section_offset: usize,
    container: Container,
    job: &mut QueueJob,
) {
    let declared = job.declared_file_count.unwrap_or(0) as usize;
    if container == Container::Ese {
        let exact = declared.checked_mul(16).is_some_and(|need| need <= section.len());
        if exact {
            job.transfer_section_kind = Some("file_reference_guids");
            for index in 0..declared {
                let start = index * 16;
                job.file_reference_guids
                    .push(format_guid(&section[start..start + 16]));
            }
            if declared * 16 < section.len() {
                job.transfer_trailing_length = Some((section.len() - declared * 16) as i64);
            }
            return;
        }
        job.transfer_section_kind = Some("unknown");
        job.parse_status = "partial";
        job.parse_error.get_or_insert_with(|| {
            format!(
                "파일 참조 {declared}개에 필요한 {}바이트보다 전송 구간이 짧습니다({}바이트)",
                declared * 16,
                section.len()
            )
        });
        return;
    }

    // Legacy queue: the declared number of records follow one another, each
    // one followed by a trailer whose length is not documented (73 bytes in
    // the single public Windows 8.1 job, which carries one file — that is one
    // observation, not a corroborated schema). The record that starts the
    // section has a proven boundary: it begins right after the declared file
    // count. Any later record has to be found past an unknown trailer, so it
    // is reported as a re-synchronised candidate, never as proven framing.
    job.transfer_section_kind = Some("file_records");
    let mut bounds: Vec<(usize, usize)> = Vec::new();
    let mut cursor = 0usize;
    let mut index = 0i64;
    let mut expected = 0usize;
    while job.files.len() < declared && cursor < section.len() {
        // The bytes right after a record are its trailer, which can itself
        // parse as empty strings, so every position must look like a record.
        let located = match read_file_record(section, cursor) {
            (file, Some(end)) if is_plausible_record(&file) => Some((cursor, file, end)),
            _ => resync_file_record(section, cursor),
        };
        let Some((start, mut file, end)) = located else {
            let (mut file, end) = read_file_record(section, cursor);
            if end.is_some() {
                // Fields parsed, but the bytes were rejected as a record above:
                // keep the bytes, not values decoded from them.
                file = QueueFile {
                    parse_status: "failed",
                    parse_method: "sequential",
                    parse_error: Some(format!(
                        "{cursor}바이트 지점부터 파일 레코드 구조(대상 경로·원본 URL)를 찾지 못했습니다"
                    )),
                    ..QueueFile::default()
                };
            }
            file.record_index = index;
            file.record_offset = Some((section_offset + cursor) as i64);
            file.record_length = (section.len() - cursor) as i64;
            file.file_index_in_job = Some(index);
            file.link_basis = "legacy_job_transfer_section";
            file.blob = section[cursor..].to_vec();
            job.files.push(file);
            bounds.push((cursor, section.len()));
            break;
        };
        file.record_index = index;
        file.record_offset = Some((section_offset + start) as i64);
        file.file_index_in_job = Some(index);
        file.link_basis = "legacy_job_transfer_section";
        if start != expected {
            // The boundary is not established by the format: the structure of
            // a trailer could hold text that parses as a record.
            file.parse_status = "heuristic_boundary";
            file.parse_method = "heuristic_resync";
            file.parse_error = Some(format!(
                "이전 레코드({expected}바이트 지점) 뒤 트레일러 길이가 문서화되지 않아 \
                 전체 구조가 파싱되는 첫 위치({start})에서 재동기화했습니다. \
                 레코드 경계는 증명되지 않았습니다"
            ));
        }
        job.files.push(file);
        bounds.push((start, end));
        index += 1;
        expected = end;
        cursor = end;
    }
    // A record owns the bytes up to the next record: its trailer is evidence.
    for position in 0..job.files.len() {
        let (start, end) = bounds[position];
        let boundary = bounds
            .get(position + 1)
            .map(|(next, _)| *next)
            .unwrap_or(section.len());
        let file = &mut job.files[position];
        if file.parse_status != "failed" {
            file.record_length = boundary.saturating_sub(start) as i64;
            file.trailing_length = Some(boundary.saturating_sub(end) as i64);
            file.blob = section[start..boundary].to_vec();
        }
    }
    let proven = job.files.iter().filter(|f| f.parse_status == "parsed").count();
    let recovered = job
        .files
        .iter()
        .filter(|f| f.parse_status == "heuristic_boundary")
        .count();
    if proven + recovered != declared {
        job.parse_status = "partial";
        job.parse_error.get_or_insert_with(|| {
            format!(
                "선언된 파일 수 {declared}개와 복원한 {}개가 다릅니다",
                proven + recovered
            )
        });
    } else if recovered > 0 {
        // The declared count is met only by candidates whose boundary is not
        // proven, so the job's file list is not authoritative.
        job.parse_status = "partial";
        job.parse_error.get_or_insert_with(|| {
            format!(
                "파일 {recovered}개는 문서화되지 않은 트레일러 뒤에서 재동기화로 찾은 후보이며 \
                 경계가 증명되지 않았습니다"
            )
        });
    }
}

/// Bytes between two records are a trailer of unknown length, so the next
/// record is located by finding the first offset whose complete structure
/// parses. The scan is bounded and never accepts an empty-looking record.
fn resync_file_record(section: &[u8], from: usize) -> Option<(usize, QueueFile, usize)> {
    const WINDOW: usize = 64 * 1024;
    let limit = section.len().min(from.saturating_add(WINDOW));
    for start in (from + 1)..limit {
        if let (file, Some(end)) = read_file_record(section, start) {
            if is_plausible_record(&file) {
                return Some((start, file, end));
            }
        }
    }
    None
}

fn read_metadata(data: &[u8], job: &mut QueueJob) {
    let mut reader = Reader::new(data);
    let count = match reader.u32() {
        Ok(count) => count,
        Err(error) => {
            job.metadata_state = "truncated";
            mark_partial(job, format!("메타데이터 오류 수를 읽지 못했습니다: {error}"));
            return;
        }
    };
    job.error_count = Some(count);
    for _ in 0..count {
        match read_job_error(&mut reader) {
            Ok(error) => job.errors.push(error),
            Err(error) => {
                job.metadata_state = "truncated";
                mark_partial(job, format!("작업 오류 구조를 읽지 못했습니다: {error}"));
                return;
            }
        }
    }
    let Some(transient) = next_u32(job, &mut reader) else {
        return;
    };
    job.transient_error_count = Some(transient);
    let Some(retry) = next_u32(job, &mut reader) else {
        return;
    };
    job.retry_delay_raw = Some(retry);
    let Some(timeout) = next_u32(job, &mut reader) else {
        return;
    };
    job.timeout_raw = Some(timeout);

    let Some(created) = next_time(job, &mut reader) else {
        return;
    };
    job.created_raw = Some(created);
    let Some(modified) = next_time(job, &mut reader) else {
        return;
    };
    job.modified_raw = Some(modified);
    let Some(other0) = next_time(job, &mut reader) else {
        return;
    };
    job.other_time0_raw = Some(other0);
    match reader.take(14) {
        Ok(padding) => job.metadata_padding_hex = Some(hex_lower(padding)),
        Err(error) => {
            job.metadata_state = "truncated";
            mark_partial(job, format!("메타데이터 예약 구간을 읽지 못했습니다: {error}"));
            return;
        }
    }
    let Some(other1) = next_time(job, &mut reader) else {
        return;
    };
    job.other_time1_raw = Some(other1);
    let Some(other2) = next_time(job, &mut reader) else {
        return;
    };
    job.other_time2_raw = Some(other2);
    job.metadata_state = "parsed";
    job.metadata_trailing_length = Some(reader.remaining() as i64);
}

/// A truncated metadata value keeps everything read so far and records why
/// the rest is missing.
fn next_u32(job: &mut QueueJob, reader: &mut Reader<'_>) -> Option<u32> {
    match reader.u32() {
        Ok(value) => Some(value),
        Err(error) => {
            job.metadata_state = "truncated";
            mark_partial(job, format!("메타데이터 값을 읽지 못했습니다: {error}"));
            None
        }
    }
}

fn next_time(job: &mut QueueJob, reader: &mut Reader<'_>) -> Option<u64> {
    match reader.u64() {
        Ok(value) => Some(value),
        Err(error) => {
            job.metadata_state = "truncated";
            mark_partial(job, format!("메타데이터 시각을 읽지 못했습니다: {error}"));
            None
        }
    }
}

fn read_job_error(reader: &mut Reader<'_>) -> Result<JobError, String> {
    Ok(JobError {
        code: reader.u64()?,
        stat1: reader.u32()?,
        stat2: reader.u32()?,
        stat3: reader.u32()?,
        stat4: reader.u32()?,
        reserved: reader.u8()?,
    })
}

fn mark_partial(job: &mut QueueJob, message: String) {
    if job.parse_status == "parsed" {
        job.parse_status = "partial";
    }
    job.parse_error.get_or_insert(message);
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

/// Largest file header accepted before the queue markers. The header is the
/// first structure of the file, so only that region is examined — later
/// occurrences of the markers belong to freed space and are never used.
pub const MAX_QUEUE_HEADER_LENGTH: usize = 4096;

/// Offset of the queue file marker that the queue marker follows.
///
/// The leading header is not a fixed 16 bytes: the published structure treats
/// it as "everything up to the file marker" and the public Windows 8.1 sample
/// carries 24 bytes (file marker at 0x18, queue marker at 0x28, job count at
/// 0x38). The first pair inside the header region is the live queue.
pub fn queue_marker_offset(data: &[u8]) -> Option<usize> {
    let window = data.len().min(MAX_QUEUE_HEADER_LENGTH + FILE_HEADER.len());
    let head = &data[..window];
    let mut from = 0usize;
    while let Some(found) = find(head, &FILE_HEADER, from) {
        if data
            .get(found + FILE_HEADER.len()..found + FILE_HEADER.len() + QUEUE_HEADER.len())
            .is_some_and(|next| next == QUEUE_HEADER)
        {
            return Some(found);
        }
        from = found + 1;
    }
    None
}

/// Container decided by the on-disk signatures, never by the file name.
pub fn detect_format(head: &[u8]) -> QueueFormat {
    if head.len() >= 8 && head[4..8] == ESE_SIGNATURE {
        return QueueFormat::Ese;
    }
    if queue_marker_offset(head).is_some() {
        return QueueFormat::Legacy;
    }
    QueueFormat::Unknown
}

/// Read one queue input. Unsupported or unreadable inputs return their reason;
/// they never return an empty success.
pub fn parse_queue_file(path: &Path) -> ParsedQueue {
    // The legacy header length varies, so the detection window covers more
    // than the first record; the ESE signature sits at offset 4.
    let head = match read_head(path, 64 * 1024) {
        Ok(head) => head,
        Err(error) => {
            return ParsedQueue::empty(QueueFormat::Unknown, "read_failed", Some(error.to_string()))
        }
    };
    let format = detect_format(&head);
    let detail = Some(hex_lower(&head[..head.len().min(0x20)]));
    let mut parsed = match format {
        QueueFormat::Ese => parse_ese_queue(path),
        QueueFormat::Legacy => match std::fs::read(path) {
            Ok(data) => parse_legacy_queue(&data),
            Err(error) => ParsedQueue::empty(
                QueueFormat::Legacy,
                "read_failed",
                Some(error.to_string()),
            ),
        },
        QueueFormat::Unknown => ParsedQueue::empty(
            QueueFormat::Unknown,
            "unsupported_format",
            Some(
                "BITS 큐 서명(ESE 0x89ABCDEF 또는 큐 파일·큐 표식 쌍)이 없습니다".to_string(),
            ),
        ),
    };
    if parsed.format_detail.is_none() {
        parsed.format_detail = detail;
    }
    parsed
}

fn read_head(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; limit];
    let mut filled = 0;
    while filled < limit {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Legacy queue file: parse the live job region only.
pub fn parse_legacy_queue(data: &[u8]) -> ParsedQueue {
    let mut parsed = ParsedQueue::empty(QueueFormat::Legacy, "parsed", None);
    let Some(marker) = queue_marker_offset(data) else {
        parsed.status = "unsupported_format";
        parsed.error = Some("큐 파일 표식과 큐 표식 쌍을 찾지 못했습니다".into());
        return parsed;
    };
    // The bytes before the marker are the file header; its length varies by
    // build (16 in the published structure, 24 in the Windows 8.1 sample), so
    // it is preserved verbatim instead of being assumed.
    parsed.format_detail = Some(format!(
        "header_length={marker};header={};queue_marker_offset={marker}",
        hex_lower(&data[..marker])
    ));
    let count_at = marker + FILE_HEADER.len() + QUEUE_HEADER.len();
    let Some(count_bytes) = data.get(count_at..count_at + 4) else {
        parsed.status = "truncated";
        parsed.error = Some("큐 표식 뒤의 작업 수를 읽지 못했습니다".into());
        return parsed;
    };
    let declared = u32::from_le_bytes(count_bytes.try_into().unwrap());
    parsed.declared_job_count = Some(declared);

    let region_start = count_at + 4;
    let Some(region_end) = find(data, &QUEUE_HEADER, region_start) else {
        parsed.status = "truncated";
        parsed.error = Some("작업 구간을 닫는 큐 표식이 없습니다".into());
        return parsed;
    };
    let region = &data[region_start..region_end];

    let (delimiter_id, delimiter) = match best_delimiter(region) {
        Some(found) => found,
        None => {
            parsed.status = if declared == 0 { "parsed" } else { "truncated" };
            if declared > 0 {
                parsed.error = Some(format!(
                    "작업 {declared}개가 선언됐지만 알려진 작업 구분자가 없습니다"
                ));
            }
            return parsed;
        }
    };
    parsed.job_delimiter_id = Some(delimiter_id);
    parsed.job_delimiter = Some(hex_lower(&delimiter));

    // Every chunk between delimiters is a record candidate, including the one
    // before the first delimiter; all-zero padding is not a record.
    let mut index = 0i64;
    let mut file_index = 0i64;
    let mut cursor = 0usize;
    while cursor < region.len() {
        let start = if region[cursor..].starts_with(&delimiter) {
            cursor + delimiter.len()
        } else {
            cursor
        };
        if start >= region.len() {
            break;
        }
        let next = find(region, &delimiter, start).unwrap_or(region.len());
        let body = &region[start..next];
        if !body.iter().any(|byte| *byte != 0) {
            cursor = next;
            continue;
        }
        let mut job = parse_job_record(body, Container::Legacy);
        job.record_index = index;
        job.record_offset = Some((region_start + start) as i64);
        let job_id = job.job_id.clone();
        for file in &mut job.files {
            file.record_index = file_index;
            file_index += 1;
            file.job_record_index = Some(index);
            file.job_id = job_id.clone();
        }
        parsed.jobs.push(job);
        index += 1;
        cursor = next;
    }
    if parsed.jobs.len() as u32 != declared {
        parsed.status = "parsed_with_errors";
        parsed.error = Some(format!(
            "선언된 작업 {declared}개와 복원한 {}개가 다릅니다",
            parsed.jobs.len()
        ));
    }
    parsed.settle()
}

fn best_delimiter(region: &[u8]) -> Option<(i64, [u8; 16])> {
    JOB_DELIMITERS
        .iter()
        .map(|(id, delimiter)| (count_occurrences(region, delimiter), *id, *delimiter))
        .filter(|(count, _, _)| *count > 0)
        .max_by_key(|(count, id, _)| (*count, -*id))
        .map(|(_, id, delimiter)| (id, delimiter))
}

/// Windows 10 `qmgr.db`: enumerate the live `Jobs` and `Files` records.
pub fn parse_ese_queue(path: &Path) -> ParsedQueue {
    let mut parsed = ParsedQueue::empty(QueueFormat::Ese, "parsed", None);
    let db = match EseDb::open(path) {
        Ok(db) => db,
        Err(error) => {
            return ParsedQueue::empty(
                QueueFormat::Ese,
                "open_failed",
                Some(format!("ESE 데이터베이스를 열지 못했습니다: {error}")),
            )
        }
    };

    let mut problems: Vec<String> = Vec::new();
    let mut table_failure = false;
    let files = match read_ese_table(&db, ESE_FILES_TABLE, &mut problems) {
        Ok((_, records)) => records,
        Err(error) => {
            table_failure = true;
            problems.push(error);
            Vec::new()
        }
    };
    let jobs_raw = match read_ese_table(&db, ESE_JOBS_TABLE, &mut problems) {
        Ok((count, records)) => {
            parsed.declared_job_count = u32::try_from(count).ok();
            records
        }
        Err(error) => {
            table_failure = true;
            problems.push(error);
            Vec::new()
        }
    };

    let mut files: Vec<QueueFile> = files
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let mut file = parse_file_record(&record.body, Container::Ese);
            file.record_index = index as i64;
            file.container_table = Some(ESE_FILES_TABLE.to_string());
            file.container_record_index = Some(record.record_index);
            file.container_record_id = record.id.clone();
            file.blob_prefix_hex = Some(record.prefix_hex.clone());
            file.record_length = record.body.len() as i64;
            file
        })
        .collect();

    for (index, record) in jobs_raw.into_iter().enumerate() {
        let mut job = parse_job_record(&record.body, Container::Ese);
        job.record_index = index as i64;
        job.container_table = Some(ESE_JOBS_TABLE.to_string());
        job.container_record_index = Some(record.record_index);
        job.container_record_id = record.id.clone();
        job.blob_prefix_hex = Some(record.prefix_hex.clone());
        for (position, guid) in job.file_reference_guids.clone().into_iter().enumerate() {
            if let Some(file) = files
                .iter_mut()
                .find(|file| file.container_record_id.as_deref() == Some(guid.as_str()))
            {
                file.job_record_index = Some(index as i64);
                file.job_id = job.job_id.clone();
                file.file_index_in_job = Some(position as i64);
                file.link_basis = "ese_job_file_reference_guid";
            }
        }
        parsed.jobs.push(job);
    }

    parsed.files = files;
    if !problems.is_empty() {
        parsed.error = Some(problems.join(" | "));
        if table_failure && parsed.jobs.is_empty() && parsed.files.is_empty() {
            parsed.status = "unsupported_format";
        } else {
            parsed.status = "parsed_with_errors";
        }
    }
    parsed.settle()
}

struct EseRecord {
    record_index: i64,
    id: Option<String>,
    prefix_hex: String,
    body: Vec<u8>,
}

fn read_ese_table(
    db: &EseDb,
    name: &str,
    problems: &mut Vec<String>,
) -> Result<(i32, Vec<EseRecord>), String> {
    let table = db
        .table_by_name(name)
        .map_err(|error| format!("{name} 테이블을 열지 못했습니다: {error}"))?;
    let columns: Vec<String> = table
        .iter_columns()
        .map_err(|error| format!("{name} 컬럼을 읽지 못했습니다: {error}"))?
        .map(|column| column.and_then(|column| column.name()))
        .collect::<std::io::Result<_>>()
        .map_err(|error| format!("{name} 컬럼 정의를 읽지 못했습니다: {error}"))?;
    let index_of = |wanted: &str| {
        columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(wanted))
            .map(|index| index as i32)
    };
    let (Some(id_column), Some(blob_column)) = (index_of("Id"), index_of("Blob")) else {
        return Err(format!(
            "{name} 테이블에 Id/Blob 컬럼이 없습니다(확인한 컬럼: {})",
            columns.join(",")
        ));
    };
    let count = table
        .count_records()
        .map_err(|error| format!("{name} 레코드 수를 읽지 못했습니다: {error}"))?;
    let mut records = Vec::new();
    for index in 0..count {
        let record = match table.record(index) {
            Ok(record) => record,
            Err(error) => {
                problems.push(format!("{name} {index}번 레코드를 읽지 못했습니다: {error}"));
                continue;
            }
        };
        let id = match value_bytes(&record, id_column) {
            Ok(bytes) => bytes.map(|bytes| format_guid(&bytes)),
            Err(error) => {
                problems.push(format!("{name} {index}번 레코드의 Id 읽기 실패: {error}"));
                None
            }
        };
        let blob = match value_bytes(&record, blob_column) {
            Ok(Some(blob)) => blob,
            Ok(None) => {
                problems.push(format!("{name} {index}번 레코드의 Blob 값이 NULL입니다"));
                continue;
            }
            Err(error) => {
                problems.push(format!("{name} {index}번 레코드의 Blob 읽기 실패: {error}"));
                continue;
            }
        };
        if blob.len() <= ESE_BLOB_PREFIX {
            problems.push(format!(
                "{name} {index}번 레코드의 Blob이 {}바이트로 레코드 표식보다 짧습니다",
                blob.len()
            ));
            continue;
        }
        records.push(EseRecord {
            record_index: index as i64,
            id,
            prefix_hex: hex_lower(&blob[..ESE_BLOB_PREFIX]),
            body: blob[ESE_BLOB_PREFIX..].to_vec(),
        });
    }
    Ok((count, records))
}

fn value_bytes(record: &libesedb::Record, entry: i32) -> std::io::Result<Option<Vec<u8>>> {
    use libesedb::Value;

    let bytes = match record.value(entry)? {
        Value::Null(_) => return Ok(None),
        Value::Long => record.long(entry)?.vec()?,
        Value::Binary(bytes)
        | Value::LargeBinary(bytes)
        | Value::SuperLarge(bytes)
        | Value::Guid(bytes) => bytes,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Id/Blob 컬럼이 바이너리 값이 아닙니다",
            ));
        }
    };
    Ok(Some(bytes))
}

/// Spec-built queue bytes shared by the parser and the storage tests. Every
/// value is assembled from the documented/reverse-engineered layout, so a
/// fixture proves the layout, never a captured sample.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub(crate) fn pascal(value: &str) -> Vec<u8> {
        let units: Vec<u16> = value.encode_utf16().collect();
        let mut out = (units.len() as u32).to_le_bytes().to_vec();
        for unit in units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    pub(crate) fn file_record(dest: &str, url: &str, tmp: &str, done: u64, total: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(pascal(dest));
        out.extend(pascal(url));
        out.extend(pascal(tmp));
        out.extend_from_slice(&done.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.push(0);
        out.extend(pascal("C:"));
        out.extend(pascal("{11111111-2222-3333-4444-555555555555}"));
        out
    }

    pub(crate) struct JobSpec<'a> {
        pub job_type: u32,
        pub priority: u32,
        pub state: u32,
        pub guid: [u8; 16],
        pub name: &'a str,
        pub description: &'a str,
        pub command: &'a str,
        pub arguments: &'a str,
        pub sid: &'a str,
        pub flags: u32,
        pub token: &'a [u8],
    }

    impl Default for JobSpec<'_> {
        fn default() -> Self {
            Self {
                job_type: 0,
                priority: 2,
                state: 3,
                guid: [
                    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9A, 0xBC, 0xDE, 0xF0, 0x11,
                    0x22, 0x33, 0x44,
                ],
                name: "job",
                description: "desc",
                command: "",
                arguments: "",
                sid: "S-1-5-18",
                flags: 0,
                token: &[],
            }
        }
    }

    pub(crate) fn control(spec: &JobSpec<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&spec.job_type.to_le_bytes());
        out.extend_from_slice(&spec.priority.to_le_bytes());
        out.extend_from_slice(&spec.state.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&spec.guid);
        out.extend(pascal(spec.name));
        out.extend(pascal(spec.description));
        out.extend(pascal(spec.command));
        out.extend(pascal(spec.arguments));
        out.extend(pascal(spec.sid));
        out.extend_from_slice(&spec.flags.to_le_bytes());
        out.extend_from_slice(spec.token);
        out
    }

    pub(crate) fn metadata(created: u64, modified: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0x8007_0005u64.to_le_bytes());
        for stat in 1..=4u32 {
            out.extend_from_slice(&stat.to_le_bytes());
        }
        out.push(0);
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&600u32.to_le_bytes());
        out.extend_from_slice(&1_209_600u32.to_le_bytes());
        out.extend_from_slice(&created.to_le_bytes());
        out.extend_from_slice(&modified.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&[0xAA; 14]);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out
    }

    /// Per-record trailer modelled on the public samples: the marker, opaque
    /// values and a FILETIME 29 bytes past the record. Its length is not
    /// documented, so the parser must not depend on it.
    pub(crate) fn file_trailer(filetime: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&FILE_TRAILER_MARKER);
        out.extend_from_slice(&[0x6F, 0x12, 0x9D, 0xD4]);
        out.extend_from_slice(&4096u64.to_le_bytes());
        out.extend_from_slice(&128u64.to_le_bytes());
        out.extend_from_slice(&[0u8; 5]);
        out.extend_from_slice(&filetime.to_le_bytes());
        out.extend_from_slice(&[0u8; 36]);
        out
    }

    /// Legacy job: control, transfer section (record + trailer per file) and
    /// the metadata section.
    pub(crate) fn legacy_job(spec: &JobSpec<'_>, files: &[Vec<u8>]) -> Vec<u8> {
        let mut out = control(spec);
        out.extend_from_slice(&XFER_HEADER);
        out.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for file in files {
            out.extend_from_slice(file);
            out.extend(file_trailer(133_159_473_950_000_000));
        }
        out.extend_from_slice(&XFER_HEADER);
        out.extend(metadata(132_000_000_000_000_000, 132_000_000_000_000_001));
        out
    }

    /// Windows 10 job blob body: control, transfer section with GUID refs.
    pub(crate) fn ese_job(spec: &JobSpec<'_>, refs: &[[u8; 16]]) -> Vec<u8> {
        let mut out = control(spec);
        out.extend_from_slice(&XFER_HEADER);
        out.extend_from_slice(&(refs.len() as u32).to_le_bytes());
        for reference in refs {
            out.extend_from_slice(reference);
        }
        out.extend_from_slice(&XFER_HEADER);
        out.extend(metadata(132_100_000_000_000_000, 132_100_000_000_000_002));
        out
    }

    /// The header before the queue marker is not a fixed size; the public
    /// Windows 8.1 sample uses 24 bytes.
    pub(crate) fn legacy_queue(jobs: &[Vec<u8>], delimiter: [u8; 16], declared: u32) -> Vec<u8> {
        let mut out = vec![0x11; 24];
        out.extend_from_slice(&FILE_HEADER);
        out.extend_from_slice(&QUEUE_HEADER);
        out.extend_from_slice(&declared.to_le_bytes());
        for job in jobs {
            out.extend_from_slice(&delimiter);
            out.extend_from_slice(job);
        }
        out.extend_from_slice(&QUEUE_HEADER);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&FILE_HEADER);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn documented_enumerations_map_only_known_values() {
        assert_eq!(job_type_name(0), Some("BG_JOB_TYPE_DOWNLOAD"));
        assert_eq!(job_type_name(3), None);
        assert_eq!(job_priority_name(3), Some("BG_JOB_PRIORITY_LOW"));
        assert_eq!(job_state_name(8), Some("BG_JOB_STATE_CANCELLED"));
        assert_eq!(job_state_name(9), None);
        let (names, rest) = notify_flags(0x8013);
        assert_eq!(
            names,
            vec![
                "BG_NOTIFY_JOB_TRANSFERRED",
                "BG_NOTIFY_JOB_ERROR",
                "BG_NOTIFY_FILE_TRANSFERRED"
            ]
        );
        assert_eq!(rest, 0x8000);
    }

    #[test]
    fn guid_bytes_use_windows_mixed_endian_order() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44,
        ];
        assert_eq!(format_guid(&bytes), "12345678-1234-5678-9abc-def011223344");
    }

    #[test]
    fn file_record_keeps_sizes_and_unknown_sentinel() {
        let body = file_record(
            r"C:\Users\a\Downloads\patch.exe",
            "http://example.test/patch.exe",
            r"C:\Users\a\AppData\Local\Temp\BITF1.tmp",
            4096,
            SIZE_UNKNOWN,
        );
        let parsed = parse_file_record(&body, Container::Legacy);
        assert_eq!(parsed.parse_status, "parsed");
        assert_eq!(parsed.dest_file.as_deref(), Some(r"C:\Users\a\Downloads\patch.exe"));
        assert_eq!(parsed.source_url.as_deref(), Some("http://example.test/patch.exe"));
        assert_eq!(parsed.download_size, Some(4096));
        assert_eq!(parsed.transfer_size, Some(SIZE_UNKNOWN));
        assert_eq!(parsed.drive.as_deref(), Some("C:"));
        assert_eq!(parsed.blob, body);
    }

    #[test]
    fn truncated_file_record_reports_the_failure_with_its_bytes() {
        let body = file_record("C:\\a", "http://x/", "C:\\a.tmp", 1, 2);
        let parsed = parse_file_record(&body[..body.len() - 9], Container::Legacy);
        assert_eq!(parsed.parse_status, "failed");
        assert!(parsed.parse_error.is_some());
        assert!(parsed.dest_file.is_none() || parsed.volume_guid.is_none());
        assert_eq!(parsed.blob.len(), body.len() - 9);
    }

    #[test]
    fn implausible_string_length_fails_instead_of_allocating() {
        let mut body = vec![0xFF, 0xFF, 0xFF, 0x7F];
        body.extend_from_slice(&[0u8; 32]);
        let parsed = parse_file_record(&body, Container::Legacy);
        assert_eq!(parsed.parse_status, "failed");
        assert!(parsed.parse_error.unwrap().contains("바이트"));
    }

    #[test]
    fn legacy_job_keeps_control_files_and_metadata() {
        let spec = JobSpec {
            command: r"C:\Windows\System32\cmd.exe",
            arguments: "/c echo done",
            flags: 0x0001,
            token: &[0xAB; 12],
            ..JobSpec::default()
        };
        let files = vec![
            file_record(r"C:\a\one.bin", "https://host.test/one.bin", r"C:\a\BIT1.tmp", 10, 20),
            file_record(r"C:\a\two.bin", "https://host.test/two.bin", r"C:\a\BIT2.tmp", 0, SIZE_UNKNOWN),
        ];
        let job = parse_job_record(&legacy_job(&spec, &files), Container::Legacy);
        // The first record's boundary is proven; the second is only a
        // re-synchronised candidate, so the job is not fully established.
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.files[0].parse_status, "parsed");
        assert_eq!(job.files[1].parse_status, "heuristic_boundary");
        assert!(job.parse_error.as_deref().is_some_and(|m| m.contains("재동기화")));
        assert_eq!(job.job_id.as_deref(), Some("12345678-1234-5678-9abc-def011223344"));
        assert_eq!(job.job_type_raw, Some(0));
        assert_eq!(job.state_raw, Some(3));
        assert_eq!(job.name.as_deref(), Some("job"));
        assert_eq!(job.notify_command.as_deref(), Some(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(job.notify_arguments.as_deref(), Some("/c echo done"));
        assert_eq!(job.owner_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(job.notify_flags_raw, Some(1));
        assert_eq!(job.access_token_length, Some(12));
        assert_eq!(job.declared_file_count, Some(2));
        assert_eq!(job.transfer_section_kind, Some("file_records"));
        assert_eq!(job.files.len(), 2);
        assert_eq!(job.files[1].transfer_size, Some(SIZE_UNKNOWN));
        assert_eq!(job.metadata_state, "parsed");
        assert_eq!(job.error_count, Some(1));
        assert_eq!(job.errors[0].code, 0x8007_0005);
        assert_eq!(job.transient_error_count, Some(2));
        assert_eq!(job.retry_delay_raw, Some(600));
        assert_eq!(job.timeout_raw, Some(1_209_600));
        assert_eq!(job.created_raw, Some(132_000_000_000_000_000));
        assert_eq!(job.metadata_padding_hex.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn job_without_metadata_marker_stays_partial() {
        let spec = JobSpec::default();
        let mut body = control(&spec);
        body.extend_from_slice(&XFER_HEADER);
        body.extend_from_slice(&0u32.to_le_bytes());
        let job = parse_job_record(&body, Container::Legacy);
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.metadata_state, "absent");
        assert!(job.parse_error.is_some());
        assert_eq!(job.job_id.as_deref(), Some("12345678-1234-5678-9abc-def011223344"));
    }

    #[test]
    fn job_without_transfer_marker_keeps_control_values() {
        let spec = JobSpec::default();
        let job = parse_job_record(&control(&spec), Container::Legacy);
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.name.as_deref(), Some("job"));
        assert!(job.declared_file_count.is_none());
    }

    /// Payload bytes can be identical to any separator: a transferred size of
    /// 3 and a three character string both encode as `03 00 00 00`.
    #[test]
    fn delimiter_like_payload_bytes_do_not_split_records() {
        let files = vec![
            file_record(r"C:\dl\three.bin", "http://host.test/3", "abc", 3, 3),
            file_record(
                r"C:\dl\second.bin",
                "https://host.test/second.bin",
                r"C:\dl\BIT2.tmp",
                11,
                22,
            ),
        ];
        let job = parse_job_record(&legacy_job(&JobSpec::default(), &files), Container::Legacy);
        // The first record is proven; the second is a re-synchronised
        // candidate, so the job itself stays unproven.
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.files[0].parse_status, "parsed");
        assert_eq!(job.declared_file_count, Some(2));
        assert_eq!(job.files.len(), 2);
        assert_eq!(job.files[0].dest_file.as_deref(), Some(r"C:\dl\three.bin"));
        assert_eq!(job.files[0].tmp_file.as_deref(), Some("abc"));
        assert_eq!(job.files[0].download_size, Some(3));
        assert_eq!(job.files[0].transfer_size, Some(3));
        assert_eq!(job.files[1].dest_file.as_deref(), Some(r"C:\dl\second.bin"));
        assert_eq!(job.files[1].download_size, Some(11));
        assert_eq!(job.files[1].transfer_size, Some(22));
        // The second record was found after the first record's trailer and is
        // reported as an unproven boundary, with its reason.
        assert_eq!(job.files[1].parse_status, "heuristic_boundary");
        assert_eq!(job.files[1].parse_method, "heuristic_resync");
        assert!(job.files[1].parse_error.is_some());
        assert!(job.files[0].trailing_length.is_some_and(|value| value > 0));
    }

    /// A trailer could itself contain text that parses as a record. Such a
    /// candidate is kept with its bytes, but never reported as proven framing
    /// and never raises the job's file list to an authoritative count.
    #[test]
    fn record_shaped_bytes_inside_a_trailer_stay_an_unproven_candidate() {
        let spec = JobSpec { name: "one-real-file", ..JobSpec::default() };
        let real = file_record(
            r"C:\dl\real.bin",
            "https://host.test/real.bin",
            r"C:\dl\BIT1.tmp",
            5,
            6,
        );
        let planted = file_record(r"C:\fake\x.bin", "http://fake.test/x", "t", 1, 2);
        let mut body = control(&spec);
        body.extend_from_slice(&XFER_HEADER);
        // The job declares two files; only one record is real and the trailer
        // of that record carries record-shaped bytes.
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&real);
        body.extend_from_slice(&FILE_TRAILER_MARKER);
        body.extend_from_slice(&[0u8; 25]);
        body.extend_from_slice(&planted);
        body.extend_from_slice(&XFER_HEADER);
        body.extend(metadata(1, 2));

        let job = parse_job_record(&body, Container::Legacy);
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.files.len(), 2);
        assert_eq!(job.files[0].parse_status, "parsed");
        assert_eq!(job.files[0].dest_file.as_deref(), Some(r"C:\dl\real.bin"));
        let candidate = &job.files[1];
        assert_eq!(candidate.parse_status, "heuristic_boundary");
        assert_eq!(candidate.parse_method, "heuristic_resync");
        assert_eq!(candidate.dest_file.as_deref(), Some(r"C:\fake\x.bin"));
        assert!(candidate.parse_error.is_some(), "the unproven boundary is recorded");
        assert!(!candidate.blob.is_empty(), "candidate bytes stay available");
        // The declared count is met only with a candidate, so the job says so.
        assert!(job
            .parse_error
            .as_deref()
            .is_some_and(|message| message.contains("증명되지")));
    }

    #[test]
    fn declared_file_count_mismatch_is_reported() {
        let spec = JobSpec::default();
        let mut body = control(&spec);
        body.extend_from_slice(&XFER_HEADER);
        body.extend_from_slice(&5u32.to_le_bytes());
        body.extend(file_record(r"C:\a", "http://x/", r"C:\a.tmp", 1, 2));
        body.extend(file_trailer(133_159_473_950_000_000));
        body.extend_from_slice(&XFER_HEADER);
        body.extend(metadata(1, 2));
        let job = parse_job_record(&body, Container::Legacy);
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.declared_file_count, Some(5));
        // One record was read; the bytes that should hold the rest are kept as
        // an explicitly failed record instead of being dropped.
        assert_eq!(job.files.len(), 2);
        assert_eq!(job.files[0].parse_status, "parsed");
        assert_eq!(job.files[1].parse_status, "failed");
        assert!(job.files[1].parse_error.is_some());
        assert!(!job.files[1].blob.is_empty());
        assert!(job.parse_error.unwrap().contains('5'));
    }

    /// Zero padding parses as empty strings; it is not a proven file record.
    #[test]
    fn zero_padding_transfer_section_is_not_a_parsed_file() {
        let spec = JobSpec::default();
        let mut body = control(&spec);
        body.extend_from_slice(&XFER_HEADER);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 64]);
        body.extend_from_slice(&XFER_HEADER);
        body.extend(metadata(1, 2));
        let job = parse_job_record(&body, Container::Legacy);
        assert_eq!(job.files[0].dest_file, None);
        assert_eq!(job.files.len(), 1);
        assert_eq!(job.files[0].parse_status, "failed");
        assert!(job.files[0].parse_error.is_some());
        assert!(!job.files[0].blob.is_empty());
        assert_eq!(job.parse_status, "partial");
    }

    #[test]
    fn ese_job_records_file_reference_guids() {
        let reference = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let job = parse_job_record(&ese_job(&JobSpec::default(), &[reference]), Container::Ese);
        assert_eq!(job.parse_status, "parsed");
        assert_eq!(job.transfer_section_kind, Some("file_reference_guids"));
        assert_eq!(job.file_reference_guids, vec![format_guid(&reference)]);
        assert!(job.files.is_empty());
        assert_eq!(job.metadata_state, "parsed");
    }

    #[test]
    fn ese_job_with_short_reference_section_is_partial() {
        let mut body = control(&JobSpec::default());
        body.extend_from_slice(&XFER_HEADER);
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&XFER_HEADER);
        body.extend(metadata(1, 2));
        let job = parse_job_record(&body, Container::Ese);
        assert_eq!(job.parse_status, "partial");
        assert_eq!(job.transfer_section_kind, Some("unknown"));
        assert!(job.file_reference_guids.is_empty());
    }

    #[test]
    fn legacy_queue_file_parses_live_region_only() {
        let (_, delimiter) = JOB_DELIMITERS[2];
        let files = vec![file_record(
            r"C:\dl\a.bin",
            "http://host.test/a.bin",
            r"C:\dl\BITA.tmp",
            1,
            2,
        )];
        let job = legacy_job(&JobSpec::default(), &files);
        let mut data = legacy_queue(&[job], delimiter, 1);
        // Deleted remnants after the queue markers must never be parsed.
        data.extend_from_slice(&delimiter);
        data.extend(legacy_job(&JobSpec { name: "deleted", ..JobSpec::default() }, &files));
        let parsed = parse_legacy_queue(&data);
        assert_eq!(parsed.status, "parsed");
        assert_eq!(parsed.declared_job_count, Some(1));
        assert_eq!(parsed.job_delimiter_id, Some(3));
        assert_eq!(parsed.jobs.len(), 1);
        assert_eq!(parsed.jobs[0].name.as_deref(), Some("job"));
        assert_eq!(parsed.jobs[0].files.len(), 1);
        assert_eq!(parsed.jobs[0].files[0].link_basis, "legacy_job_transfer_section");
        assert_eq!(parsed.file_record_count(), 1);
        assert_eq!(parsed.failed_record_count(), 0);
    }

    #[test]
    fn legacy_queue_file_record_index_is_per_record() {
        let (_, delimiter) = JOB_DELIMITERS[0];
        let files = vec![
            file_record(r"C:\dl\a.bin", "http://host.test/a", r"C:\dl\a.tmp", 1, 2),
            file_record(r"C:\dl\b.bin", "http://host.test/b", r"C:\dl\b.tmp", 1, 2),
        ];
        let first = legacy_job(&JobSpec::default(), &files);
        let second = legacy_job(&JobSpec::default(), &files[..1]);
        let parsed = parse_legacy_queue(&legacy_queue(&[first, second], delimiter, 2));
        let rows: Vec<(i64, Option<i64>, Option<i64>)> = parsed
            .jobs
            .iter()
            .flat_map(|job| job.files.iter())
            .map(|file| (file.record_index, file.job_record_index, file.file_index_in_job))
            .collect();
        assert_eq!(
            rows,
            vec![(0, Some(0), Some(0)), (1, Some(0), Some(1)), (2, Some(1), Some(0))]
        );
    }

    #[test]
    fn ese_transfer_and_metadata_trailers_are_kept_apart() {
        let spec = JobSpec::default();
        let mut body = control(&spec);
        body.extend_from_slice(&XFER_HEADER);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0x11; 16]);
        body.extend_from_slice(&[0x22; 5]);
        body.extend_from_slice(&XFER_HEADER);
        body.extend(metadata(1, 2));
        body.extend_from_slice(&[0x33; 3]);
        let job = parse_job_record(&body, Container::Ese);
        assert_eq!(job.transfer_trailing_length, Some(5));
        assert_eq!(job.metadata_trailing_length, Some(3));
    }

    #[test]
    fn legacy_queue_job_count_mismatch_is_reported() {
        let (_, delimiter) = JOB_DELIMITERS[0];
        let job = legacy_job(&JobSpec::default(), &[]);
        let data = legacy_queue(&[job], delimiter, 4);
        let parsed = parse_legacy_queue(&data);
        assert_eq!(parsed.status, "parsed_with_errors");
        assert!(parsed.error.unwrap().contains('4'));
        assert_eq!(parsed.jobs.len(), 1);
    }

    #[test]
    fn legacy_queue_without_closing_marker_is_truncated() {
        let (_, delimiter) = JOB_DELIMITERS[0];
        let mut data = vec![0x11; 0x10];
        data.extend_from_slice(&FILE_HEADER);
        data.extend_from_slice(&QUEUE_HEADER);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&delimiter);
        data.extend(legacy_job(&JobSpec::default(), &[]));
        let parsed = parse_legacy_queue(&data);
        assert_eq!(parsed.status, "truncated");
        assert!(parsed.jobs.is_empty());
        assert!(parsed.error.is_some());
    }

    #[test]
    fn foreign_file_is_reported_as_unsupported_format() {
        assert_eq!(detect_format(b"SQLite format 3\0"), QueueFormat::Unknown);
        let parsed = parse_legacy_queue(b"not a bits queue at all, really not");
        assert_eq!(parsed.status, "unsupported_format");
        assert!(parsed.jobs.is_empty());
        assert!(parsed.error.is_some());
    }

    #[test]
    fn format_detection_uses_signatures() {
        let mut ese = vec![0u8; 8];
        ese[4..8].copy_from_slice(&ESE_SIGNATURE);
        assert_eq!(detect_format(&ese), QueueFormat::Ese);
        // The queue header length varies; only the marker pair identifies the
        // container, at whatever offset it sits.
        for header in [16usize, 24, 40] {
            let mut legacy = vec![0x11; header];
            legacy.extend_from_slice(&FILE_HEADER);
            legacy.extend_from_slice(&QUEUE_HEADER);
            assert_eq!(detect_format(&legacy), QueueFormat::Legacy);
            assert_eq!(queue_marker_offset(&legacy), Some(header));
        }
        // The file marker alone is not the queue: the queue marker must follow.
        let mut lone = vec![0x11; 16];
        lone.extend_from_slice(&FILE_HEADER);
        lone.extend_from_slice(&[0u8; 16]);
        assert_eq!(detect_format(&lone), QueueFormat::Unknown);
        // Marker pairs past the header region are freed space, not the queue.
        let mut slack = vec![0x11; MAX_QUEUE_HEADER_LENGTH + 64];
        slack.extend_from_slice(&FILE_HEADER);
        slack.extend_from_slice(&QUEUE_HEADER);
        assert_eq!(queue_marker_offset(&slack), None);
        assert_eq!(detect_format(&slack), QueueFormat::Unknown);
    }

    #[test]
    fn unreadable_and_wrong_type_inputs_report_their_reason() {
        let dir = std::env::temp_dir().join(format!("wina-qmgr-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("qmgr0.dat");
        let parsed = parse_queue_file(&missing);
        assert_eq!(parsed.status, "read_failed");
        assert!(parsed.error.is_some());

        let foreign = dir.join("qmgr.db");
        std::fs::write(&foreign, b"SQLite format 3\0 and more bytes to read").unwrap();
        let parsed = parse_queue_file(&foreign);
        assert_eq!(parsed.status, "unsupported_format");
        assert_eq!(parsed.format, QueueFormat::Unknown);
        assert!(parsed.format_detail.is_some());

        // ESE signature without a usable database: the open failure is kept.
        let broken = dir.join("broken-qmgr.db");
        let mut bytes = vec![0u8; 64];
        bytes[4..8].copy_from_slice(&ESE_SIGNATURE);
        std::fs::write(&broken, &bytes).unwrap();
        let parsed = parse_queue_file(&broken);
        assert_eq!(parsed.format, QueueFormat::Ese);
        assert_eq!(parsed.status, "open_failed");
        assert!(parsed.error.unwrap().contains("ESE"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discovery_reports_missing_and_found_inputs() {
        let files = vec![
            PathBuf::from("/case/NonVolatile/BITS/Microsoft/Network/Downloader/qmgr.db"),
            PathBuf::from("/case/NonVolatile/BITS/Microsoft/Network/Downloader/qmgr.jfm"),
        ];
        let found = discover_inputs(&files);
        let database: Vec<_> = found
            .iter()
            .filter(|input| input.kind == "qmgr_database")
            .collect();
        assert_eq!(database.len(), 1);
        assert!(database[0].path.is_some());
        let legacy: Vec<_> = found
            .iter()
            .filter(|input| input.kind == "qmgr_legacy_queue")
            .collect();
        assert_eq!(legacy.len(), 2);
        assert!(legacy.iter().all(|input| input.path.is_none()));
        let directory: Vec<_> = found
            .iter()
            .filter(|input| input.kind == "downloader_directory")
            .collect();
        assert_eq!(directory.len(), 1);
        assert_eq!(
            directory[0].path.as_deref(),
            Some(Path::new(
                "/case/NonVolatile/BITS/Microsoft/Network/Downloader"
            ))
        );
    }
}
