//! Windows user-mode minidump (`MDMP`) reader for collected `.dmp` evidence.
//!
//! Only the documented minidump container is interpreted: the header, the
//! stream directory and the streams whose layout Microsoft publishes
//! (`minidumpapiset.h`). Everything else — unknown stream types, streams whose
//! declared ranges leave the file, counts that do not match the declared sizes
//! — is reported as evidence instead of being guessed at. Other `.dmp`
//! containers (kernel crash dumps, legacy user-mode crash dumps) are detected
//! by signature and refused rather than parsed as a minidump.
//!
//! Scope limits that are intentional: no thread CPU context decoding, no
//! process memory extraction, no carving and no executable analysis. Memory
//! streams contribute region metadata (address, size, protection) only.
//!
//! Format references:
//! * MINIDUMP_HEADER / MINIDUMP_DIRECTORY / MINIDUMP_STREAM_TYPE —
//!   <https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header>
//! * MINIDUMP_SYSTEM_INFO, MINIDUMP_MISC_INFO(_2.._5), MINIDUMP_EXCEPTION,
//!   MINIDUMP_THREAD, MINIDUMP_MODULE, MINIDUMP_UNLOADED_MODULE_LIST,
//!   MINIDUMP_MEMORY_INFO_LIST, MINIDUMP_THREAD_INFO_LIST — same API set.
//! * Cross-checked against Breakpad `minidump_format.h` (BSD-3) and
//!   rust-minidump `minidump-common/src/format.rs` (MIT/Apache-2.0); neither is
//!   linked, the layouts are reimplemented here with bounded reads.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Digest, Sha256};

/// `MDMP` in little-endian order.
pub const MINIDUMP_SIGNATURE: u32 = 0x504d_444d;
/// Low word of `MINIDUMP_HEADER.Version`.
pub const MINIDUMP_VERSION: u32 = 0xa793;

const HEADER_SIZE: u64 = 32;
const DIRECTORY_ENTRY_SIZE: u64 = 12;

/// A single bounded read never allocates more than this.
const MAX_READ: u64 = 32 * 1024 * 1024;
/// `MINIDUMP_STRING.Length` beyond this is treated as damaged, not allocated.
const MAX_STRING_BYTES: u64 = 64 * 1024;
/// Retained raw prefix for streams that carry no process memory.
const RAW_PREFIX_BYTES: usize = 64;
/// Streams larger than this keep their size only, no hash.
const RAW_HASH_LIMIT: u64 = 1024 * 1024;
/// Stored list rows per dump; a hostile count can never drive allocation.
const MAX_LIST_ENTRIES: u64 = 100_000;

// --- container formats ------------------------------------------------------

pub const FORMAT_MINIDUMP: &str = "user_minidump";
pub const FORMAT_KERNEL_X86: &str = "kernel_dump_x86";
pub const FORMAT_KERNEL_X64: &str = "kernel_dump_x64";
pub const FORMAT_USERDUMP_X86: &str = "legacy_user_dump_x86";
pub const FORMAT_USERDUMP_X64: &str = "legacy_user_dump_x64";
pub const FORMAT_CAB: &str = "cabinet";
pub const FORMAT_EMPTY: &str = "empty_file";
pub const FORMAT_UNKNOWN: &str = "unknown";

pub const STATUS_PARSED: &str = "parsed";
pub const STATUS_PARSED_WITH_ISSUES: &str = "parsed_with_issues";
pub const STATUS_UNSUPPORTED_FORMAT: &str = "unsupported_format";
pub const STATUS_UNSUPPORTED_VERSION: &str = "unsupported_version";
pub const STATUS_TRUNCATED: &str = "truncated";
pub const STATUS_READ_FAILED: &str = "read_failed";

// --- public structures ------------------------------------------------------

#[derive(Debug, Default)]
pub struct Dump {
    pub byte_count: u64,
    pub format: &'static str,
    /// Printable form of the leading signature bytes, when any were read.
    pub signature_ascii: Option<String>,
    pub signature_hex: Option<String>,
    pub version_raw: Option<u32>,
    pub version_low: Option<u32>,
    pub version_high: Option<u32>,
    pub checksum: Option<u32>,
    /// `time_t` seconds, as written in the header.
    pub time_date_stamp: Option<u32>,
    pub flags: Option<u64>,
    pub stream_count: Option<u32>,
    pub directory_rva: Option<u32>,
    pub directory_state: Option<&'static str>,
    pub streams: Vec<Stream>,
    pub system: Option<SystemInfo>,
    pub misc: Option<MiscInfo>,
    pub exception: Option<Exception>,
    pub threads: Vec<Thread>,
    pub modules: Vec<Module>,
    pub regions: Vec<Region>,
    /// Documented singleton counter structures (`MINIDUMP_PROCESS_VM_COUNTERS_2`,
    /// handle/function-table headers) kept under their own member names.
    pub counters: Vec<Counter>,
    pub parse_status: &'static str,
    pub parse_error: Option<String>,
    /// Every structural problem found, in discovery order.
    pub issues: Vec<String>,
}

impl Dump {
    pub fn is_minidump(&self) -> bool {
        self.format == FORMAT_MINIDUMP
    }

    pub fn issues_text(&self) -> Option<String> {
        if self.issues.is_empty() {
            None
        } else {
            Some(self.issues.join("\n"))
        }
    }

    /// The entry at index 0 of `MINIDUMP_MODULE_LIST`. The documented contract
    /// is an array of loaded modules only — it does not promise that the first
    /// entry is the process image — so this stays "the first loaded module"
    /// and is never presented as the process identity.
    pub fn first_loaded_module(&self) -> Option<&Module> {
        self.modules
            .iter()
            .find(|module| module.kind == MODULE_LOADED && module.index == 0)
    }
}

#[derive(Debug, Clone)]
pub struct Stream {
    pub index: u32,
    pub type_code: u32,
    pub type_name: Option<&'static str>,
    pub data_size: u32,
    pub rva: u32,
    pub range_state: &'static str,
    pub parse_state: &'static str,
    pub overlaps: bool,
    /// List-stream header values as declared by the stream itself.
    pub header_size: Option<u32>,
    pub entry_size: Option<u32>,
    pub declared_entries: Option<u64>,
    pub stored_entries: Option<u64>,
    pub sha256: Option<String>,
    pub prefix_hex: Option<String>,
    pub text: Option<String>,
    pub note: Option<String>,
}

/// One documented numeric field of a singleton stream structure. The field
/// name is the member name from `minidumpapiset.h`; nothing is renamed.
#[derive(Debug, Clone)]
pub struct Counter {
    pub stream_type: u32,
    pub group: &'static str,
    pub field: &'static str,
    pub value: u64,
}

pub const RANGE_IN_FILE: &str = "in_file";
pub const RANGE_OUT_OF_FILE: &str = "out_of_file";
pub const RANGE_EMPTY: &str = "empty";

pub const STREAM_TYPED: &str = "typed";
pub const STREAM_METADATA_ONLY: &str = "metadata_only";
pub const STREAM_RECOGNIZED_NOT_PARSED: &str = "recognized_not_parsed";
pub const STREAM_UNKNOWN_TYPE: &str = "unknown_type";
pub const STREAM_UNUSED: &str = "unused";
/// The structure's leading, revision-stable fields were read; the rest of the
/// layout for this revision is not in the referenced documentation.
pub const STREAM_HEADER_ONLY: &str = "header_only";
pub const STREAM_OUT_OF_FILE: &str = "out_of_file";
pub const STREAM_INVALID_STRUCTURE: &str = "invalid_structure";

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub processor_architecture: u16,
    pub architecture_name: Option<&'static str>,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    pub product_type: u8,
    pub product_type_name: Option<&'static str>,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub platform_name: Option<&'static str>,
    pub suite_mask: u16,
    pub csd_version: Option<String>,
    pub csd_state: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct MiscInfo {
    pub size_of_info: u32,
    /// 1..=5 for the documented revisions, 0 when the size matches none.
    pub revision: u32,
    pub flags1: u32,
    pub flag_names: Option<String>,
    pub unknown_flag_bits: Option<u32>,
    pub process_id: Option<u32>,
    /// `time_t` seconds.
    pub process_create_time: Option<u32>,
    pub process_user_time: Option<u32>,
    pub process_kernel_time: Option<u32>,
    pub processor_max_mhz: Option<u32>,
    pub processor_current_mhz: Option<u32>,
    pub process_integrity_level: Option<u32>,
    pub process_execute_flags: Option<u32>,
    pub protected_process: Option<u32>,
    pub time_zone_id: Option<u32>,
    pub build_string: Option<String>,
    pub debug_build_string: Option<String>,
    pub process_cookie: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct Exception {
    pub thread_id: u32,
    pub code: u32,
    pub code_name: Option<&'static str>,
    pub flags: u32,
    pub nested_record_address: u64,
    pub address: u64,
    pub number_parameters: u32,
    pub parameters: Vec<u64>,
    pub context_rva: u32,
    pub context_size: u32,
    pub parameters_truncated: bool,
}

pub const THREAD_FROM_LIST: &str = "thread_list";
pub const THREAD_FROM_INFO_ONLY: &str = "thread_info_list";

#[derive(Debug, Clone, Default)]
pub struct Thread {
    pub index: u32,
    pub source_stream: &'static str,
    pub thread_id: u32,
    pub suspend_count: Option<u32>,
    pub priority_class: Option<u32>,
    pub priority: Option<u32>,
    pub teb: Option<u64>,
    pub stack_start: Option<u64>,
    pub stack_size: Option<u32>,
    pub stack_rva: Option<u32>,
    pub context_rva: Option<u32>,
    pub context_size: Option<u32>,
    pub name: Option<String>,
    pub info: Option<ThreadInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreadInfo {
    pub dump_flags: u32,
    pub dump_error: u32,
    pub exit_status: u32,
    /// FILETIME ticks.
    pub create_time: u64,
    pub exit_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
    pub start_address: u64,
    pub affinity: u64,
}

pub const MODULE_LOADED: &str = "loaded";
pub const MODULE_UNLOADED: &str = "unloaded";

#[derive(Debug, Clone, Default)]
pub struct Module {
    pub index: u32,
    pub kind: &'static str,
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub checksum: u32,
    /// `time_t` seconds from the PE header.
    pub time_date_stamp: u32,
    pub name: Option<String>,
    pub name_state: &'static str,
    pub version: Option<VersionInfo>,
    pub cv: Option<CvRecord>,
    pub misc_record_size: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub file_version: String,
    pub product_version: String,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
}

#[derive(Debug, Clone, Default)]
pub struct CvRecord {
    pub signature: String,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub pdb_file_name: Option<String>,
    pub size: u32,
    pub rva: u32,
    pub state: &'static str,
}

pub const REGION_FROM_INFO_LIST: &str = "memory_info_list";
pub const REGION_FROM_MEMORY_LIST: &str = "memory_list";
pub const REGION_FROM_MEMORY64_LIST: &str = "memory64_list";

#[derive(Debug, Clone, Default)]
pub struct Region {
    pub index: u32,
    pub source_stream: &'static str,
    pub base_address: u64,
    pub allocation_base: Option<u64>,
    pub allocation_protect: Option<u32>,
    pub region_size: u64,
    pub state: Option<u32>,
    pub state_name: Option<&'static str>,
    pub protect: Option<u32>,
    pub protect_name: Option<String>,
    pub region_type: Option<u32>,
    pub region_type_name: Option<&'static str>,
    /// Bytes of this region stored inside the dump; contents are never read.
    pub data_size: Option<u64>,
}

// --- names ------------------------------------------------------------------

/// `MINIDUMP_STREAM_TYPE`. Unlisted codes stay unnamed.
pub fn stream_type_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "UnusedStream",
        1 => "ReservedStream0",
        2 => "ReservedStream1",
        3 => "ThreadListStream",
        4 => "ModuleListStream",
        5 => "MemoryListStream",
        6 => "ExceptionStream",
        7 => "SystemInfoStream",
        8 => "ThreadExListStream",
        9 => "Memory64ListStream",
        10 => "CommentStreamA",
        11 => "CommentStreamW",
        12 => "HandleDataStream",
        13 => "FunctionTableStream",
        14 => "UnloadedModuleListStream",
        15 => "MiscInfoStream",
        16 => "MemoryInfoListStream",
        17 => "ThreadInfoListStream",
        18 => "HandleOperationListStream",
        19 => "TokenStream",
        20 => "JavaScriptDataStream",
        21 => "SystemMemoryInfoStream",
        22 => "ProcessVmCountersStream",
        23 => "IptTraceStream",
        24 => "ThreadNamesStream",
        0x8000 => "ceStreamNull",
        0x8001 => "ceStreamSystemInfo",
        0x8002 => "ceStreamException",
        0x8003 => "ceStreamModuleList",
        0x8004 => "ceStreamProcessList",
        0x8005 => "ceStreamThreadList",
        0x8006 => "ceStreamThreadContextList",
        0x8007 => "ceStreamThreadCallStackList",
        0x8008 => "ceStreamMemoryVirtualList",
        0x8009 => "ceStreamMemoryPhysicalList",
        0x800a => "ceStreamBucketParameters",
        0x800b => "ceStreamProcessModuleMap",
        0x800c => "ceStreamDiagnosisList",
        _ => return None,
    })
}

fn architecture_name(value: u16) -> Option<&'static str> {
    Some(match value {
        0 => "x86",
        5 => "ARM",
        6 => "IA64",
        9 => "x64",
        10 => "x86_on_x64",
        12 => "ARM64",
        0xffff => "unknown",
        _ => return None,
    })
}

fn product_type_name(value: u8) -> Option<&'static str> {
    Some(match value {
        1 => "workstation",
        2 => "domain_controller",
        3 => "server",
        _ => return None,
    })
}

fn platform_name(value: u32) -> Option<&'static str> {
    Some(match value {
        0 => "win32s",
        1 => "windows",
        2 => "windows_nt",
        3 => "windows_ce",
        _ => return None,
    })
}

/// Documented `EXCEPTION_*` / `STATUS_*` codes only.
fn exception_code_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x8000_0003 => "EXCEPTION_BREAKPOINT",
        0x8000_0004 => "EXCEPTION_SINGLE_STEP",
        0xc000_0005 => "EXCEPTION_ACCESS_VIOLATION",
        0xc000_0006 => "EXCEPTION_IN_PAGE_ERROR",
        0xc000_0008 => "EXCEPTION_INVALID_HANDLE",
        0xc000_001d => "EXCEPTION_ILLEGAL_INSTRUCTION",
        0xc000_0025 => "EXCEPTION_NONCONTINUABLE_EXCEPTION",
        0xc000_0026 => "EXCEPTION_INVALID_DISPOSITION",
        0xc000_008c => "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
        0xc000_008d => "EXCEPTION_FLT_DENORMAL_OPERAND",
        0xc000_008e => "EXCEPTION_FLT_DIVIDE_BY_ZERO",
        0xc000_008f => "EXCEPTION_FLT_INEXACT_RESULT",
        0xc000_0090 => "EXCEPTION_FLT_INVALID_OPERATION",
        0xc000_0091 => "EXCEPTION_FLT_OVERFLOW",
        0xc000_0092 => "EXCEPTION_FLT_STACK_CHECK",
        0xc000_0093 => "EXCEPTION_FLT_UNDERFLOW",
        0xc000_0094 => "EXCEPTION_INT_DIVIDE_BY_ZERO",
        0xc000_0095 => "EXCEPTION_INT_OVERFLOW",
        0xc000_0096 => "EXCEPTION_PRIV_INSTRUCTION",
        0xc000_00fd => "EXCEPTION_STACK_OVERFLOW",
        0xc000_0194 => "EXCEPTION_POSSIBLE_DEADLOCK",
        0xc000_0409 => "STATUS_STACK_BUFFER_OVERRUN",
        0xc000_0374 => "STATUS_HEAP_CORRUPTION",
        0xc000_041d => "STATUS_FATAL_USER_CALLBACK_EXCEPTION",
        0xe06d_7363 => "CPP_EH_EXCEPTION",
        0x4064_2443 => "CLR_EXCEPTION",
        _ => return None,
    })
}

/// `MINIDUMP_MISC_INFO*.Flags1`.
const MISC_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "PROCESS_ID"),
    (0x0000_0002, "PROCESS_TIMES"),
    (0x0000_0004, "PROCESSOR_POWER_INFO"),
    (0x0000_0010, "PROCESS_INTEGRITY"),
    (0x0000_0020, "PROCESS_EXECUTE_FLAGS"),
    (0x0000_0040, "TIMEZONE"),
    (0x0000_0080, "PROTECTED_PROCESS"),
    (0x0000_0100, "BUILDSTRING"),
    (0x0000_0200, "PROCESS_COOKIE"),
];

fn memory_state_name(value: u32) -> Option<&'static str> {
    Some(match value {
        0x1000 => "MEM_COMMIT",
        0x2000 => "MEM_RESERVE",
        0x10000 => "MEM_FREE",
        _ => return None,
    })
}

fn memory_type_name(value: u32) -> Option<&'static str> {
    Some(match value {
        0x20000 => "MEM_PRIVATE",
        0x40000 => "MEM_MAPPED",
        0x1000000 => "MEM_IMAGE",
        _ => return None,
    })
}

/// Page protection constants; unknown bits are reported as a hex remainder.
fn memory_protect_name(value: u32) -> Option<String> {
    if value == 0 {
        return None;
    }
    const BASE: &[(u32, &str)] = &[
        (0x01, "PAGE_NOACCESS"),
        (0x02, "PAGE_READONLY"),
        (0x04, "PAGE_READWRITE"),
        (0x08, "PAGE_WRITECOPY"),
        (0x10, "PAGE_EXECUTE"),
        (0x20, "PAGE_EXECUTE_READ"),
        (0x40, "PAGE_EXECUTE_READWRITE"),
        (0x80, "PAGE_EXECUTE_WRITECOPY"),
    ];
    const MODIFIERS: &[(u32, &str)] = &[
        (0x100, "PAGE_GUARD"),
        (0x200, "PAGE_NOCACHE"),
        (0x400, "PAGE_WRITECOMBINE"),
        (0x4000_0000, "PAGE_TARGETS_NO_UPDATE"),
    ];
    let mut names: Vec<&str> = Vec::new();
    let mut rest = value;
    for (bit, name) in BASE {
        if value & 0xff == *bit {
            names.push(name);
            rest &= !bit;
        }
    }
    for (bit, name) in MODIFIERS {
        if value & bit == *bit {
            names.push(name);
            rest &= !bit;
        }
    }
    if rest != 0 {
        names.push("");
    }
    let mut text = names
        .iter()
        .filter(|name| !name.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("|");
    if rest != 0 {
        if !text.is_empty() {
            text.push('|');
        }
        text.push_str(&format!("0x{rest:x}"));
    }
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

// --- bounded reading --------------------------------------------------------

struct Reader {
    file: File,
    len: u64,
    io_error: Option<String>,
}

impl Reader {
    /// Never allocates for a range that the file cannot hold.
    fn read(&mut self, offset: u64, len: u64) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        if len > MAX_READ {
            return None;
        }
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        if let Err(error) = self.file.seek(SeekFrom::Start(offset)) {
            self.io_error = Some(error.to_string());
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if let Err(error) = self.file.read_exact(&mut buf) {
            self.io_error = Some(error.to_string());
            return None;
        }
        Some(buf)
    }

    /// `MINIDUMP_STRING`: UTF-16LE with a byte length prefix.
    fn string_at(&mut self, rva: u32) -> (Option<String>, &'static str) {
        let Some(header) = self.read(u64::from(rva), 4) else {
            return (None, "out_of_file");
        };
        let declared = u32le(&header, 0) as u64;
        if declared == 0 {
            return (Some(String::new()), "present_empty");
        }
        let limited = declared.min(MAX_STRING_BYTES);
        let available = self.len.saturating_sub(u64::from(rva) + 4);
        let usable = limited.min(available) & !1;
        if usable == 0 {
            return (None, "out_of_file");
        }
        let Some(body) = self.read(u64::from(rva) + 4, usable) else {
            return (None, "out_of_file");
        };
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        let text = text.trim_end_matches('\0').to_string();
        let state = if usable < declared {
            "truncated"
        } else {
            "present"
        };
        (Some(text), state)
    }
}

fn u16le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn u32le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn u64le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn utf16_fixed(buf: &[u8]) -> Option<String> {
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

fn ascii_signature(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() {
                *byte as char
            } else {
                '.'
            }
        })
        .collect()
}

// --- entry point ------------------------------------------------------------

/// Read one collected dump file. Problems are returned as evidence; this never
/// fails the caller and never reads process memory contents.
pub fn parse_file(path: &Path) -> Dump {
    let mut dump = Dump {
        format: FORMAT_UNKNOWN,
        parse_status: STATUS_READ_FAILED,
        ..Dump::default()
    };
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            dump.parse_error = Some(error.to_string());
            return dump;
        }
    };
    let len = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(error) => {
            dump.parse_error = Some(error.to_string());
            return dump;
        }
    };
    dump.byte_count = len;
    let mut reader = Reader {
        file,
        len,
        io_error: None,
    };
    if len == 0 {
        dump.format = FORMAT_EMPTY;
        dump.parse_status = STATUS_TRUNCATED;
        dump.parse_error = Some("빈 파일입니다".to_string());
        return dump;
    }
    let lead = reader.read(0, len.min(8)).unwrap_or_default();
    dump.signature_ascii = Some(ascii_signature(&lead));
    dump.signature_hex = Some(crate::hex::hex_lower(&lead));
    if let Some(other) = other_container(&lead) {
        dump.format = other;
        dump.parse_status = STATUS_UNSUPPORTED_FORMAT;
        dump.parse_error = Some(format!(
            "미니덤프가 아닌 컨테이너입니다: {}",
            dump.signature_ascii.clone().unwrap_or_default()
        ));
        return dump;
    }
    if lead.len() < 4 || u32le(&lead, 0) != MINIDUMP_SIGNATURE {
        dump.parse_status = if len < HEADER_SIZE {
            STATUS_TRUNCATED
        } else {
            STATUS_UNSUPPORTED_FORMAT
        };
        dump.parse_error = Some("MDMP 서명이 아닙니다".to_string());
        return dump;
    }
    let Some(header) = reader.read(0, HEADER_SIZE) else {
        dump.parse_status = STATUS_TRUNCATED;
        dump.parse_error = Some(format!(
            "헤더 {HEADER_SIZE}바이트를 읽을 수 없습니다 (파일 {len}바이트)"
        ));
        return dump;
    };
    let version = u32le(&header, 4);
    dump.version_raw = Some(version);
    dump.version_low = Some(version & 0xffff);
    dump.version_high = Some(version >> 16);
    dump.stream_count = Some(u32le(&header, 8));
    dump.directory_rva = Some(u32le(&header, 12));
    dump.checksum = Some(u32le(&header, 16));
    dump.time_date_stamp = Some(u32le(&header, 20));
    dump.flags = Some(u64le(&header, 24));
    if version & 0xffff != MINIDUMP_VERSION {
        dump.format = FORMAT_MINIDUMP;
        dump.parse_status = STATUS_UNSUPPORTED_VERSION;
        dump.parse_error = Some(format!(
            "지원하지 않는 미니덤프 버전입니다: 0x{:04x}",
            version & 0xffff
        ));
        return dump;
    }
    dump.format = FORMAT_MINIDUMP;
    read_directory(&mut reader, &mut dump);
    read_streams(&mut reader, &mut dump);
    if let Some(error) = reader.io_error.take() {
        dump.issues.push(format!("읽기 오류: {error}"));
    }
    dump.parse_status = if dump.issues.is_empty() {
        STATUS_PARSED
    } else {
        STATUS_PARSED_WITH_ISSUES
    };
    dump
}

/// Containers that use `.dmp` but are not user-mode minidumps. They are named
/// and refused; nothing inside them is interpreted.
fn other_container(lead: &[u8]) -> Option<&'static str> {
    if lead.len() >= 8 {
        match &lead[..8] {
            b"PAGEDUMP" => return Some(FORMAT_KERNEL_X86),
            b"PAGEDU64" => return Some(FORMAT_KERNEL_X64),
            b"USERDUMP" => return Some(FORMAT_USERDUMP_X86),
            b"USERDU64" => return Some(FORMAT_USERDUMP_X64),
            _ => {}
        }
    }
    if lead.len() >= 4 && &lead[..4] == b"MSCF" {
        return Some(FORMAT_CAB);
    }
    None
}

fn read_directory(reader: &mut Reader, dump: &mut Dump) {
    let count = u64::from(dump.stream_count.unwrap_or(0));
    let rva = u64::from(dump.directory_rva.unwrap_or(0));
    let Some(bytes) = count.checked_mul(DIRECTORY_ENTRY_SIZE) else {
        dump.directory_state = Some(RANGE_OUT_OF_FILE);
        dump.issues
            .push(format!("스트림 개수 {count}가 범위를 벗어납니다"));
        return;
    };
    let fits = rva
        .checked_add(bytes)
        .map(|end| end <= reader.len)
        .unwrap_or(false);
    if !fits {
        dump.directory_state = Some(RANGE_OUT_OF_FILE);
        dump.issues.push(format!(
            "스트림 디렉터리 범위가 파일을 벗어납니다: rva {rva}, {count}개, 파일 {}바이트",
            reader.len
        ));
        return;
    }
    let Some(table) = reader.read(rva, bytes) else {
        dump.directory_state = Some(RANGE_OUT_OF_FILE);
        dump.issues
            .push("스트림 디렉터리를 읽지 못했습니다".to_string());
        return;
    };
    dump.directory_state = Some(RANGE_IN_FILE);
    for index in 0..count as usize {
        let base = index * DIRECTORY_ENTRY_SIZE as usize;
        let type_code = u32le(&table, base);
        let data_size = u32le(&table, base + 4);
        let stream_rva = u32le(&table, base + 8);
        let in_file = u64::from(stream_rva)
            .checked_add(u64::from(data_size))
            .map(|end| end <= reader.len)
            .unwrap_or(false);
        let range_state = if data_size == 0 {
            RANGE_EMPTY
        } else if in_file {
            RANGE_IN_FILE
        } else {
            RANGE_OUT_OF_FILE
        };
        if range_state == RANGE_OUT_OF_FILE {
            dump.issues.push(format!(
                "스트림 {index}(type {type_code}) 범위가 파일을 벗어납니다: rva {stream_rva}, {data_size}바이트"
            ));
        }
        dump.streams.push(Stream {
            index: index as u32,
            type_code,
            type_name: stream_type_name(type_code),
            data_size,
            rva: stream_rva,
            range_state,
            parse_state: match (type_code, range_state) {
                (_, RANGE_OUT_OF_FILE) => STREAM_OUT_OF_FILE,
                (0, _) => STREAM_UNUSED,
                _ => STREAM_RECOGNIZED_NOT_PARSED,
            },
            overlaps: false,
            header_size: None,
            entry_size: None,
            declared_entries: None,
            stored_entries: None,
            sha256: None,
            prefix_hex: None,
            text: None,
            note: None,
        });
    }
    mark_overlaps(dump);
}

/// Overlapping stream ranges are kept as evidence, not silently merged.
fn mark_overlaps(dump: &mut Dump) {
    let mut ranges: Vec<(u64, u64, usize)> = dump
        .streams
        .iter()
        .enumerate()
        .filter(|(_, stream)| stream.range_state == RANGE_IN_FILE)
        .map(|(index, stream)| {
            (
                u64::from(stream.rva),
                u64::from(stream.rva) + u64::from(stream.data_size),
                index,
            )
        })
        .collect();
    ranges.sort();
    for window in 0..ranges.len().saturating_sub(1) {
        let (_, end, left) = ranges[window];
        let (start, _, right) = ranges[window + 1];
        if start < end {
            dump.streams[left].overlaps = true;
            dump.streams[right].overlaps = true;
            dump.issues.push(format!(
                "스트림 {}과 {}의 범위가 겹칩니다",
                dump.streams[left].index, dump.streams[right].index
            ));
        }
    }
    for (index, stream) in dump.streams.iter_mut().enumerate() {
        if stream.range_state == RANGE_IN_FILE && u64::from(stream.rva) < HEADER_SIZE {
            stream.overlaps = true;
            let _ = index;
        }
    }
}

/// Bulk streams — process memory and native unwind data — keep metadata only.
fn bulk_stream(type_code: u32) -> bool {
    matches!(type_code, 5 | 8 | 9 | 13)
}

fn read_streams(reader: &mut Reader, dump: &mut Dump) {
    let streams = dump.streams.clone();
    let mut thread_infos: Vec<(u32, ThreadInfo)> = Vec::new();
    let mut thread_names: Vec<(u32, String)> = Vec::new();
    for stream in &streams {
        if stream.range_state == RANGE_OUT_OF_FILE {
            continue;
        }
        let slot = stream.index as usize;
        match stream.type_code {
            3 => {
                let state = read_thread_list(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            4 => {
                let state = read_module_list(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            14 => {
                let state = read_unloaded_modules(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            6 => {
                let state = read_exception(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            7 => {
                let state = read_system_info(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            15 => {
                let state = read_misc_info(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            16 => {
                let state = read_memory_info_list(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            5 => {
                let state = read_memory_list(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            9 => {
                let state = read_memory64_list(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            17 => {
                let (state, found) = read_thread_info_list(reader, dump, stream);
                thread_infos = found;
                dump.streams[slot].parse_state = state;
            }
            24 => {
                let (state, found) = read_thread_names(reader, dump, stream);
                thread_names = found;
                dump.streams[slot].parse_state = state;
            }
            10 | 11 => {
                let state = read_comment(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            12 => {
                let state = read_handle_data(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            13 => {
                let state = read_function_table(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            21 => {
                let state = read_system_memory_info(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            22 => {
                let state = read_process_vm_counters(reader, dump, stream);
                dump.streams[slot].parse_state = state;
            }
            0 => {}
            _ => {
                dump.streams[slot].parse_state = if stream.type_name.is_some() {
                    STREAM_RECOGNIZED_NOT_PARSED
                } else {
                    STREAM_UNKNOWN_TYPE
                };
            }
        }
        retain_raw(reader, dump, slot);
    }
    attach_thread_details(dump, thread_infos, thread_names);
}

/// Unparsed streams keep an identity: size, hash and a short prefix. Streams
/// that can carry process memory keep their size only.
fn retain_raw(reader: &mut Reader, dump: &mut Dump, slot: usize) {
    let stream = &dump.streams[slot];
    if stream.range_state != RANGE_IN_FILE || stream.type_code == 0 {
        return;
    }
    if bulk_stream(stream.type_code) {
        dump.streams[slot].note = Some("raw_not_retained_bulk_stream".to_string());
        return;
    }
    let size = u64::from(stream.data_size);
    let rva = u64::from(stream.rva);
    if size <= RAW_HASH_LIMIT {
        if let Some(bytes) = reader.read(rva, size) {
            dump.streams[slot].sha256 = Some(hex_digest(&bytes));
            let prefix = &bytes[..bytes.len().min(RAW_PREFIX_BYTES)];
            dump.streams[slot].prefix_hex = Some(crate::hex::hex_lower(prefix));
        }
    } else {
        dump.streams[slot].note = Some("raw_not_retained_over_limit".to_string());
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    crate::hex::hex_lower(&hasher.finalize())
}

/// Entry counts are believed only as far as the declared stream size and the
/// file allow; the smaller bound wins and the difference is reported.
fn bounded_count(
    dump: &mut Dump,
    stream: &Stream,
    header_size: u64,
    entry_size: u64,
    declared: u64,
) -> u64 {
    let slot = stream.index as usize;
    dump.streams[slot].header_size = Some(header_size as u32);
    dump.streams[slot].entry_size = Some(entry_size as u32);
    dump.streams[slot].declared_entries = Some(declared);
    if entry_size == 0 {
        dump.streams[slot].stored_entries = Some(0);
        dump.issues.push(format!(
            "스트림 {}(type {}) 항목 크기가 0입니다",
            stream.index, stream.type_code
        ));
        return 0;
    }
    let available = u64::from(stream.data_size).saturating_sub(header_size);
    let fit = available / entry_size;
    let mut count = declared.min(fit);
    if declared > fit {
        dump.issues.push(format!(
            "스트림 {}(type {}) 항목 수 {declared}가 스트림 크기({}바이트)를 넘습니다. {count}개만 읽습니다",
            stream.index, stream.type_code, stream.data_size
        ));
    }
    if count > MAX_LIST_ENTRIES {
        dump.issues.push(format!(
            "스트림 {}(type {}) 항목 수 {count}가 저장 한도 {MAX_LIST_ENTRIES}를 넘어 잘립니다",
            stream.index, stream.type_code
        ));
        count = MAX_LIST_ENTRIES;
    }
    dump.streams[slot].stored_entries = Some(count);
    count
}

/// `MINIDUMP_HANDLE_DATA_STREAM` header. Handle descriptors are not stored:
/// only the stream's own declared shape becomes evidence.
fn read_handle_data(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let Some(head) = reader.read(u64::from(stream.rva), 16) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let header_size = u64::from(u32le(&head, 0));
    let entry_size = u64::from(u32le(&head, 4));
    let declared = u64::from(u32le(&head, 8));
    if header_size < 16 || entry_size == 0 {
        dump.issues.push(format!(
            "핸들 데이터 스트림 헤더가 올바르지 않습니다: header {header_size}, entry {entry_size}"
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    bounded_count(dump, stream, header_size, entry_size, declared);
    dump.counters.push(Counter {
        stream_type: stream.type_code,
        group: "MINIDUMP_HANDLE_DATA_STREAM",
        field: "Reserved",
        value: u64::from(u32le(&head, 12)),
    });
    STREAM_HEADER_ONLY
}

/// `MINIDUMP_FUNCTION_TABLE_STREAM` header. The native function entries that
/// follow are CPU-specific unwind data and are not interpreted here.
fn read_function_table(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let Some(head) = reader.read(u64::from(stream.rva), 24) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let header_size = u64::from(u32le(&head, 0));
    let descriptor_size = u64::from(u32le(&head, 4));
    let declared = u64::from(u32le(&head, 16));
    if header_size < 24 || descriptor_size == 0 {
        dump.issues.push(format!(
            "함수 테이블 스트림 헤더가 올바르지 않습니다: header {header_size}, descriptor {descriptor_size}"
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let slot = stream.index as usize;
    dump.streams[slot].header_size = Some(header_size as u32);
    dump.streams[slot].entry_size = Some(descriptor_size as u32);
    dump.streams[slot].declared_entries = Some(declared);
    for (field, value) in [
        ("SizeOfNativeDescriptor", u64::from(u32le(&head, 8))),
        ("SizeOfFunctionEntry", u64::from(u32le(&head, 12))),
        ("NumberOfDescriptors", declared),
        ("SizeOfAlignPad", u64::from(u32le(&head, 20))),
    ] {
        dump.counters.push(Counter {
            stream_type: stream.type_code,
            group: "MINIDUMP_FUNCTION_TABLE_STREAM",
            field,
            value,
        });
    }
    STREAM_HEADER_ONLY
}

/// `MINIDUMP_SYSTEM_MEMORY_INFO_1` starts with `Revision`/`Flags`. Only
/// revision 1 has a published body layout, so other revisions keep the two
/// leading values and the retained raw identity instead of guessed fields.
fn read_system_memory_info(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let revision = u64::from(u16le(&head, 0));
    let flags = u64::from(u16le(&head, 2));
    for (field, value) in [("Revision", revision), ("Flags", flags)] {
        dump.counters.push(Counter {
            stream_type: stream.type_code,
            group: "MINIDUMP_SYSTEM_MEMORY_INFO",
            field,
            value,
        });
    }
    dump.streams[stream.index as usize].note = Some(format!(
        "system_memory_info_revision_{revision}_body_layout_not_documented"
    ));
    STREAM_HEADER_ONLY
}

/// `MINIDUMP_PROCESS_VM_COUNTERS_2`: each field group is only read when its
/// own `Flags` bit says the writer filled it in, so an absent group stays
/// unknown instead of being stored as zero.
fn read_process_vm_counters(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const SIZE: u64 = 152;
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let revision = u16le(&head, 0);
    if revision != 2 || u64::from(stream.data_size) < SIZE {
        dump.counters.push(Counter {
            stream_type: stream.type_code,
            group: "MINIDUMP_PROCESS_VM_COUNTERS",
            field: "Revision",
            value: u64::from(revision),
        });
        dump.streams[stream.index as usize].note = Some(format!(
            "process_vm_counters_revision_{revision}_size_{}_not_documented",
            stream.data_size
        ));
        return STREAM_HEADER_ONLY;
    }
    let Some(body) = reader.read(u64::from(stream.rva), SIZE) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let flags = u16le(&body, 2);
    let group = "MINIDUMP_PROCESS_VM_COUNTERS_2";
    let mut push = |field: &'static str, value: u64| {
        dump.counters.push(Counter {
            stream_type: stream.type_code,
            group,
            field,
            value,
        });
    };
    push("Revision", u64::from(revision));
    push("Flags", u64::from(flags));
    // MINIDUMP_PROCESS_VM_COUNTERS 0x0001: the base counter set.
    if flags & 0x0001 != 0 {
        push("PageFaultCount", u64::from(u32le(&body, 4)));
        for (index, field) in [
            "PeakWorkingSetSize",
            "WorkingSetSize",
            "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage",
            "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage",
            "PagefileUsage",
            "PeakPagefileUsage",
        ]
        .into_iter()
        .enumerate()
        {
            push(field, u64le(&body, 8 + index * 8));
        }
    }
    // VIRTUALSIZE 0x0002, EX 0x0004, EX2 0x0008, JOB 0x0010.
    if flags & 0x0002 != 0 {
        push("PeakVirtualSize", u64le(&body, 72));
        push("VirtualSize", u64le(&body, 80));
    }
    if flags & 0x0004 != 0 {
        push("PrivateUsage", u64le(&body, 88));
    }
    if flags & 0x0008 != 0 {
        push("PrivateWorkingSetSize", u64le(&body, 96));
        push("SharedCommitUsage", u64le(&body, 104));
    }
    if flags & 0x0010 != 0 {
        for (index, field) in [
            "JobSharedCommitUsage",
            "JobPrivateCommitUsage",
            "JobPeakPrivateCommitUsage",
            "JobPrivateCommitLimit",
            "JobTotalCommitLimit",
        ]
        .into_iter()
        .enumerate()
        {
            push(field, u64le(&body, 112 + index * 8));
        }
    }
    STREAM_TYPED
}

fn read_thread_list(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const ENTRY: u64 = 48;
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let declared = u64::from(u32le(&head, 0));
    let count = bounded_count(dump, stream, 4, ENTRY, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_TYPED
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + 4, count * ENTRY) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * ENTRY as usize;
        dump.threads.push(Thread {
            index: index as u32,
            source_stream: THREAD_FROM_LIST,
            thread_id: u32le(&body, at),
            suspend_count: Some(u32le(&body, at + 4)),
            priority_class: Some(u32le(&body, at + 8)),
            priority: Some(u32le(&body, at + 12)),
            teb: Some(u64le(&body, at + 16)),
            stack_start: Some(u64le(&body, at + 24)),
            stack_size: Some(u32le(&body, at + 32)),
            stack_rva: Some(u32le(&body, at + 36)),
            context_size: Some(u32le(&body, at + 40)),
            context_rva: Some(u32le(&body, at + 44)),
            name: None,
            info: None,
        });
    }
    STREAM_TYPED
}

fn read_module_list(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const ENTRY: u64 = 108;
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let declared = u64::from(u32le(&head, 0));
    let count = bounded_count(dump, stream, 4, ENTRY, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_TYPED
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + 4, count * ENTRY) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * ENTRY as usize;
        let name_rva = u32le(&body, at + 20);
        let (name, name_state) = reader.string_at(name_rva);
        if name_state == "out_of_file" {
            dump.issues.push(format!(
                "모듈 {index} 이름 위치 {name_rva}가 파일을 벗어납니다"
            ));
        }
        let version = version_info(&body[at + 24..at + 76]);
        let cv_size = u32le(&body, at + 76);
        let cv_rva = u32le(&body, at + 80);
        let misc_size = u32le(&body, at + 84);
        dump.modules.push(Module {
            index: index as u32,
            kind: MODULE_LOADED,
            base_of_image: u64le(&body, at),
            size_of_image: u32le(&body, at + 8),
            checksum: u32le(&body, at + 12),
            time_date_stamp: u32le(&body, at + 16),
            name,
            name_state: static_state(name_state),
            version,
            cv: cv_record(reader, cv_size, cv_rva),
            misc_record_size: Some(misc_size),
        });
    }
    STREAM_TYPED
}

fn static_state(state: &str) -> &'static str {
    match state {
        "present" => "present",
        "present_empty" => "present_empty",
        "truncated" => "truncated",
        _ => "out_of_file",
    }
}

/// `VS_FIXEDFILEINFO` is only interpreted when its own signature matches.
fn version_info(buf: &[u8]) -> Option<VersionInfo> {
    if buf.len() < 52 || u32le(buf, 0) != 0xfeef_04bd {
        return None;
    }
    let quad = |ms: u32, ls: u32| {
        format!(
            "{}.{}.{}.{}",
            ms >> 16,
            ms & 0xffff,
            ls >> 16,
            ls & 0xffff
        )
    };
    Some(VersionInfo {
        file_version: quad(u32le(buf, 8), u32le(buf, 12)),
        product_version: quad(u32le(buf, 16), u32le(buf, 20)),
        file_flags: u32le(buf, 28),
        file_os: u32le(buf, 32),
        file_type: u32le(buf, 36),
        file_subtype: u32le(buf, 40),
    })
}

/// CodeView debug identity (`RSDS`/`NB10`) as written in the module record.
fn cv_record(reader: &mut Reader, size: u32, rva: u32) -> Option<CvRecord> {
    if size == 0 {
        return None;
    }
    let mut record = CvRecord {
        size,
        rva,
        state: "out_of_file",
        ..CvRecord::default()
    };
    let Some(bytes) = reader.read(u64::from(rva), u64::from(size).min(MAX_STRING_BYTES)) else {
        return Some(record);
    };
    if bytes.len() < 4 {
        record.state = "truncated";
        return Some(record);
    }
    record.signature = ascii_signature(&bytes[..4]);
    record.state = "present";
    if &bytes[..4] == b"RSDS" && bytes.len() >= 24 {
        let d1 = u32le(&bytes, 4);
        let d2 = u16le(&bytes, 8);
        let d3 = u16le(&bytes, 10);
        let tail = &bytes[12..20];
        record.guid = Some(format!(
            "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7]
        ));
        record.age = Some(u32le(&bytes, 20));
        record.pdb_file_name = cstr(&bytes[24..]);
    } else if &bytes[..4] == b"NB10" && bytes.len() >= 16 {
        record.age = Some(u32le(&bytes, 12));
        record.pdb_file_name = cstr(&bytes[16..]);
    }
    Some(record)
}

fn cstr(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn read_unloaded_modules(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let Some(head) = reader.read(u64::from(stream.rva), 12) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let header_size = u64::from(u32le(&head, 0));
    let entry_size = u64::from(u32le(&head, 4));
    let declared = u64::from(u32le(&head, 8));
    if header_size < 12 || entry_size < 24 {
        dump.issues.push(format!(
            "언로드 모듈 목록 헤더가 올바르지 않습니다: header {header_size}, entry {entry_size}"
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let count = bounded_count(dump, stream, header_size, entry_size, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_TYPED
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + header_size, count * entry_size) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * entry_size as usize;
        let name_rva = u32le(&body, at + 20);
        let (name, name_state) = reader.string_at(name_rva);
        dump.modules.push(Module {
            index: index as u32,
            kind: MODULE_UNLOADED,
            base_of_image: u64le(&body, at),
            size_of_image: u32le(&body, at + 8),
            checksum: u32le(&body, at + 12),
            time_date_stamp: u32le(&body, at + 16),
            name,
            name_state: static_state(name_state),
            version: None,
            cv: None,
            misc_record_size: None,
        });
    }
    STREAM_TYPED
}

fn read_exception(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const SIZE: u64 = 168;
    if u64::from(stream.data_size) < SIZE {
        dump.issues.push(format!(
            "예외 스트림 크기 {}바이트가 {SIZE}바이트 미만입니다",
            stream.data_size
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let Some(body) = reader.read(u64::from(stream.rva), SIZE) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let number = u32le(&body, 32);
    let stored = number.min(15) as usize;
    let mut parameters = Vec::with_capacity(stored);
    for index in 0..stored {
        parameters.push(u64le(&body, 40 + index * 8));
    }
    let code = u32le(&body, 8);
    dump.exception = Some(Exception {
        thread_id: u32le(&body, 0),
        code,
        code_name: exception_code_name(code),
        flags: u32le(&body, 12),
        nested_record_address: u64le(&body, 16),
        address: u64le(&body, 24),
        number_parameters: number,
        parameters,
        context_size: u32le(&body, 160),
        context_rva: u32le(&body, 164),
        parameters_truncated: number > 15,
    });
    if number > 15 {
        dump.issues
            .push(format!("예외 매개변수 수 {number}가 최대 15를 넘습니다"));
    }
    STREAM_TYPED
}

fn read_system_info(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const SIZE: u64 = 56;
    if u64::from(stream.data_size) < SIZE {
        dump.issues.push(format!(
            "시스템 정보 스트림 크기 {}바이트가 {SIZE}바이트 미만입니다",
            stream.data_size
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let Some(body) = reader.read(u64::from(stream.rva), SIZE) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let architecture = u16le(&body, 0);
    let csd_rva = u32le(&body, 24);
    let (csd_version, csd_state) = if csd_rva == 0 {
        (None, "not_recorded")
    } else {
        let (text, state) = reader.string_at(csd_rva);
        (text, static_state(state))
    };
    let platform = u32le(&body, 20);
    dump.system = Some(SystemInfo {
        processor_architecture: architecture,
        architecture_name: architecture_name(architecture),
        processor_level: u16le(&body, 2),
        processor_revision: u16le(&body, 4),
        number_of_processors: body[6],
        product_type: body[7],
        product_type_name: product_type_name(body[7]),
        major_version: u32le(&body, 8),
        minor_version: u32le(&body, 12),
        build_number: u32le(&body, 16),
        platform_id: platform,
        platform_name: platform_name(platform),
        suite_mask: u16le(&body, 28),
        csd_version,
        csd_state,
    });
    STREAM_TYPED
}

fn read_misc_info(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const MIN: u64 = 24;
    if u64::from(stream.data_size) < MIN {
        dump.issues.push(format!(
            "MiscInfo 스트림 크기 {}바이트가 {MIN}바이트 미만입니다",
            stream.data_size
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let read_size = u64::from(stream.data_size).min(4096);
    let Some(body) = reader.read(u64::from(stream.rva), read_size) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let size_of_info = u32le(&body, 0);
    let flags1 = u32le(&body, 4);
    let covered = |needed: usize| body.len() >= needed && size_of_info as usize >= needed;
    let has = |bit: u32| flags1 & bit == bit;
    let mut info = MiscInfo {
        size_of_info,
        revision: match size_of_info {
            24 => 1,
            44 => 2,
            232 => 3,
            832 => 4,
            1364 => 5,
            _ => 0,
        },
        flags1,
        ..MiscInfo::default()
    };
    let known: u32 = MISC_FLAGS.iter().map(|(bit, _)| bit).sum();
    let names: Vec<&str> = MISC_FLAGS
        .iter()
        .filter(|(bit, _)| has(*bit))
        .map(|(_, name)| *name)
        .collect();
    if !names.is_empty() {
        info.flag_names = Some(names.join("|"));
    }
    if flags1 & !known != 0 {
        info.unknown_flag_bits = Some(flags1 & !known);
    }
    if has(0x1) && covered(12) {
        info.process_id = Some(u32le(&body, 8));
    }
    if has(0x2) && covered(24) {
        info.process_create_time = Some(u32le(&body, 12));
        info.process_user_time = Some(u32le(&body, 16));
        info.process_kernel_time = Some(u32le(&body, 20));
    }
    if has(0x4) && covered(44) {
        info.processor_max_mhz = Some(u32le(&body, 24));
        info.processor_current_mhz = Some(u32le(&body, 28));
    }
    if has(0x10) && covered(48) {
        info.process_integrity_level = Some(u32le(&body, 44));
    }
    if has(0x20) && covered(52) {
        info.process_execute_flags = Some(u32le(&body, 48));
    }
    if has(0x80) && covered(56) {
        info.protected_process = Some(u32le(&body, 52));
    }
    if has(0x40) && covered(60) {
        info.time_zone_id = Some(u32le(&body, 56));
    }
    if has(0x100) && covered(832) {
        info.build_string = utf16_fixed(&body[232..752]);
        info.debug_build_string = utf16_fixed(&body[752..832]);
    }
    if has(0x200) && covered(1364) {
        info.process_cookie = Some(u32le(&body, 1360));
    }
    if info.revision == 0 {
        dump.issues.push(format!(
            "MiscInfo 크기 {size_of_info}는 문서화된 개정판과 일치하지 않습니다"
        ));
    }
    dump.misc = Some(info);
    STREAM_TYPED
}

fn read_memory_info_list(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let Some(head) = reader.read(u64::from(stream.rva), 16) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let header_size = u64::from(u32le(&head, 0));
    let entry_size = u64::from(u32le(&head, 4));
    let declared = u64le(&head, 8);
    if header_size < 16 || entry_size < 48 {
        dump.issues.push(format!(
            "메모리 정보 목록 헤더가 올바르지 않습니다: header {header_size}, entry {entry_size}"
        ));
        return STREAM_INVALID_STRUCTURE;
    }
    let count = bounded_count(dump, stream, header_size, entry_size, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_TYPED
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + header_size, count * entry_size) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * entry_size as usize;
        let state = u32le(&body, at + 32);
        let protect = u32le(&body, at + 36);
        let region_type = u32le(&body, at + 40);
        dump.regions.push(Region {
            index: index as u32,
            source_stream: REGION_FROM_INFO_LIST,
            base_address: u64le(&body, at),
            allocation_base: Some(u64le(&body, at + 8)),
            allocation_protect: Some(u32le(&body, at + 16)),
            region_size: u64le(&body, at + 24),
            state: Some(state),
            state_name: memory_state_name(state),
            protect: Some(protect),
            protect_name: memory_protect_name(protect),
            region_type: Some(region_type),
            region_type_name: memory_type_name(region_type),
            data_size: None,
        });
    }
    STREAM_TYPED
}

/// Descriptor metadata only: the stored byte ranges are never read.
fn read_memory_list(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const ENTRY: u64 = 16;
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let declared = u64::from(u32le(&head, 0));
    let count = bounded_count(dump, stream, 4, ENTRY, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_METADATA_ONLY
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + 4, count * ENTRY) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * ENTRY as usize;
        dump.regions.push(Region {
            index: index as u32,
            source_stream: REGION_FROM_MEMORY_LIST,
            base_address: u64le(&body, at),
            region_size: u64::from(u32le(&body, at + 8)),
            data_size: Some(u64::from(u32le(&body, at + 8))),
            ..Region::default()
        });
    }
    STREAM_METADATA_ONLY
}

fn read_memory64_list(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    const ENTRY: u64 = 16;
    let Some(head) = reader.read(u64::from(stream.rva), 16) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let declared = u64le(&head, 0);
    let count = bounded_count(dump, stream, 16, ENTRY, declared);
    if count == 0 {
        return if declared == 0 {
            STREAM_METADATA_ONLY
        } else {
            STREAM_INVALID_STRUCTURE
        };
    }
    let Some(body) = reader.read(u64::from(stream.rva) + 16, count * ENTRY) else {
        return STREAM_INVALID_STRUCTURE;
    };
    for index in 0..count as usize {
        let at = index * ENTRY as usize;
        let size = u64le(&body, at + 8);
        dump.regions.push(Region {
            index: index as u32,
            source_stream: REGION_FROM_MEMORY64_LIST,
            base_address: u64le(&body, at),
            region_size: size,
            data_size: Some(size),
            ..Region::default()
        });
    }
    STREAM_METADATA_ONLY
}

fn read_thread_info_list(
    reader: &mut Reader,
    dump: &mut Dump,
    stream: &Stream,
) -> (&'static str, Vec<(u32, ThreadInfo)>) {
    let Some(head) = reader.read(u64::from(stream.rva), 12) else {
        return (STREAM_INVALID_STRUCTURE, Vec::new());
    };
    let header_size = u64::from(u32le(&head, 0));
    let entry_size = u64::from(u32le(&head, 4));
    let declared = u64::from(u32le(&head, 8));
    if header_size < 12 || entry_size < 64 {
        dump.issues.push(format!(
            "스레드 정보 목록 헤더가 올바르지 않습니다: header {header_size}, entry {entry_size}"
        ));
        return (STREAM_INVALID_STRUCTURE, Vec::new());
    }
    let count = bounded_count(dump, stream, header_size, entry_size, declared);
    if count == 0 {
        return (STREAM_TYPED, Vec::new());
    }
    let Some(body) = reader.read(u64::from(stream.rva) + header_size, count * entry_size) else {
        return (STREAM_INVALID_STRUCTURE, Vec::new());
    };
    let mut found = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let at = index * entry_size as usize;
        found.push((
            u32le(&body, at),
            ThreadInfo {
                dump_flags: u32le(&body, at + 4),
                dump_error: u32le(&body, at + 8),
                exit_status: u32le(&body, at + 12),
                create_time: u64le(&body, at + 16),
                exit_time: u64le(&body, at + 24),
                kernel_time: u64le(&body, at + 32),
                user_time: u64le(&body, at + 40),
                start_address: u64le(&body, at + 48),
                affinity: u64le(&body, at + 56),
            },
        ));
    }
    (STREAM_TYPED, found)
}

fn read_thread_names(
    reader: &mut Reader,
    dump: &mut Dump,
    stream: &Stream,
) -> (&'static str, Vec<(u32, String)>) {
    const ENTRY: u64 = 12;
    let Some(head) = reader.read(u64::from(stream.rva), 4) else {
        return (STREAM_INVALID_STRUCTURE, Vec::new());
    };
    let declared = u64::from(u32le(&head, 0));
    let count = bounded_count(dump, stream, 4, ENTRY, declared);
    if count == 0 {
        return (STREAM_TYPED, Vec::new());
    }
    let Some(body) = reader.read(u64::from(stream.rva) + 4, count * ENTRY) else {
        return (STREAM_INVALID_STRUCTURE, Vec::new());
    };
    let mut found = Vec::new();
    for index in 0..count as usize {
        let at = index * ENTRY as usize;
        let thread_id = u32le(&body, at);
        let rva = u64le(&body, at + 4);
        if rva > u64::from(u32::MAX) {
            dump.issues
                .push(format!("스레드 이름 위치 {rva}가 범위를 벗어납니다"));
            continue;
        }
        if let (Some(name), state) = reader.string_at(rva as u32) {
            if state != "out_of_file" && !name.is_empty() {
                found.push((thread_id, name));
            }
        }
    }
    (STREAM_TYPED, found)
}

fn read_comment(reader: &mut Reader, dump: &mut Dump, stream: &Stream) -> &'static str {
    let size = u64::from(stream.data_size).min(MAX_STRING_BYTES);
    let Some(bytes) = reader.read(u64::from(stream.rva), size) else {
        return STREAM_INVALID_STRUCTURE;
    };
    let text = if stream.type_code == 11 {
        utf16_fixed(&bytes).unwrap_or_default()
    } else {
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    };
    dump.streams[stream.index as usize].text = Some(text);
    STREAM_TYPED
}

/// Thread detail streams relate to threads by thread id only. An id with no
/// thread-list entry keeps its own row instead of being dropped or merged.
fn attach_thread_details(
    dump: &mut Dump,
    infos: Vec<(u32, ThreadInfo)>,
    names: Vec<(u32, String)>,
) {
    for (thread_id, info) in infos {
        match dump
            .threads
            .iter_mut()
            .find(|thread| thread.thread_id == thread_id)
        {
            Some(thread) => thread.info = Some(info),
            None => {
                let index = dump.threads.len() as u32;
                dump.threads.push(Thread {
                    index,
                    source_stream: THREAD_FROM_INFO_ONLY,
                    thread_id,
                    info: Some(info),
                    ..Thread::default()
                });
            }
        }
    }
    for (thread_id, name) in names {
        if let Some(thread) = dump
            .threads
            .iter_mut()
            .find(|thread| thread.thread_id == thread_id)
        {
            thread.name = Some(name);
        }
    }
}

/// Spec-built minidump bytes shared with the storage tests of this crate.
#[cfg(test)]
pub(crate) fn test_fixture_bytes() -> Vec<u8> {
    tests::full_fixture()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal spec-built minidump writer: every structure follows
    /// minidumpapiset.h so the fixtures exercise the real layout.
    struct Builder {
        body: Vec<u8>,
        directory: Vec<(u32, u32, u32)>,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                body: vec![0u8; HEADER_SIZE as usize],
                directory: Vec::new(),
            }
        }

        fn place(&mut self, bytes: &[u8]) -> u32 {
            while self.body.len() % 4 != 0 {
                self.body.push(0);
            }
            let rva = self.body.len() as u32;
            self.body.extend_from_slice(bytes);
            rva
        }

        fn stream(&mut self, type_code: u32, bytes: &[u8]) {
            let rva = self.place(bytes);
            self.directory.push((type_code, bytes.len() as u32, rva));
        }

        fn raw_stream(&mut self, type_code: u32, size: u32, rva: u32) {
            self.directory.push((type_code, size, rva));
        }

        fn string(&mut self, text: &str) -> u32 {
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut bytes = ((units.len() * 2) as u32).to_le_bytes().to_vec();
            for unit in units {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
            self.place(&bytes)
        }

        fn finish(mut self, version: u32, timestamp: u32, flags: u64) -> Vec<u8> {
            let mut table = Vec::new();
            for (type_code, size, rva) in &self.directory {
                table.extend_from_slice(&type_code.to_le_bytes());
                table.extend_from_slice(&size.to_le_bytes());
                table.extend_from_slice(&rva.to_le_bytes());
            }
            let directory_rva = self.place(&table);
            let header = &mut self.body[..HEADER_SIZE as usize];
            header[..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
            header[4..8].copy_from_slice(&version.to_le_bytes());
            header[8..12].copy_from_slice(&(self.directory.len() as u32).to_le_bytes());
            header[12..16].copy_from_slice(&directory_rva.to_le_bytes());
            header[16..20].copy_from_slice(&0u32.to_le_bytes());
            header[20..24].copy_from_slice(&timestamp.to_le_bytes());
            header[24..32].copy_from_slice(&flags.to_le_bytes());
            self.body
        }
    }

    fn thread_entry(id: u32, teb: u64, stack: u64, stack_size: u32, stack_rva: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // suspend count
        out.extend_from_slice(&2u32.to_le_bytes()); // priority class
        out.extend_from_slice(&3u32.to_le_bytes()); // priority
        out.extend_from_slice(&teb.to_le_bytes());
        out.extend_from_slice(&stack.to_le_bytes());
        out.extend_from_slice(&stack_size.to_le_bytes());
        out.extend_from_slice(&stack_rva.to_le_bytes());
        out.extend_from_slice(&1232u32.to_le_bytes()); // context size
        out.extend_from_slice(&0u32.to_le_bytes()); // context rva
        out
    }

    fn module_entry(base: u64, size: u32, stamp: u32, name_rva: u32, cv: (u32, u32)) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&base.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&0x1234u32.to_le_bytes()); // checksum
        out.extend_from_slice(&stamp.to_le_bytes());
        out.extend_from_slice(&name_rva.to_le_bytes());
        // VS_FIXEDFILEINFO: signature, struct version, file/product versions...
        out.extend_from_slice(&0xfeef_04bdu32.to_le_bytes());
        out.extend_from_slice(&0x0001_0000u32.to_le_bytes());
        out.extend_from_slice(&0x0004_0012u32.to_le_bytes());
        out.extend_from_slice(&0x65d6_0009u32.to_le_bytes());
        out.extend_from_slice(&0x0004_0012u32.to_le_bytes());
        out.extend_from_slice(&0x65d6_0009u32.to_le_bytes());
        out.extend_from_slice(&0x3fu32.to_le_bytes()); // flags mask
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&4u32.to_le_bytes()); // file os
        out.extend_from_slice(&1u32.to_le_bytes()); // file type
        out.extend_from_slice(&0u32.to_le_bytes()); // file subtype
        out.extend_from_slice(&0u32.to_le_bytes()); // file date ms
        out.extend_from_slice(&0u32.to_le_bytes()); // file date ls
        out.extend_from_slice(&cv.0.to_le_bytes()); // cv size
        out.extend_from_slice(&cv.1.to_le_bytes()); // cv rva
        out.extend_from_slice(&0u32.to_le_bytes()); // misc size
        out.extend_from_slice(&0u32.to_le_bytes()); // misc rva
        out.extend_from_slice(&[0u8; 16]); // reserved0/1
        out
    }

    fn write(bytes: &[u8]) -> (tempdir::TempPath, std::path::PathBuf) {
        let dir = tempdir::TempPath::new();
        let path = dir.path().join("sample.dmp");
        let mut file = File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        (dir, path)
    }

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempPath(PathBuf);

        impl TempPath {
            pub fn new() -> Self {
                let base = std::env::temp_dir().join(format!(
                    "wina-dump-{}-{}",
                    std::process::id(),
                    uuid::Uuid::new_v4()
                ));
                std::fs::create_dir_all(&base).unwrap();
                Self(base)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempPath {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    pub(super) fn full_fixture() -> Vec<u8> {
        let mut builder = Builder::new();
        let app_name = builder.string("C:\\Windows\\System32\\app.exe");
        let dll_name = builder.string("C:\\Windows\\System32\\ntdll.dll");
        let unloaded_name = builder.string("C:\\Windows\\System32\\gone.dll");
        let mut cv = b"RSDS".to_vec();
        cv.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        cv.extend_from_slice(&0x5566u16.to_le_bytes());
        cv.extend_from_slice(&0x7788u16.to_le_bytes());
        cv.extend_from_slice(&[0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]);
        cv.extend_from_slice(&7u32.to_le_bytes());
        cv.extend_from_slice(b"app.pdb\0");
        let cv_rva = builder.place(&cv);

        // SystemInfo
        let mut system = Vec::new();
        system.extend_from_slice(&9u16.to_le_bytes()); // x64
        system.extend_from_slice(&6u16.to_le_bytes());
        system.extend_from_slice(&0xb701u16.to_le_bytes());
        system.push(8); // processors
        system.push(3); // server
        system.extend_from_slice(&10u32.to_le_bytes());
        system.extend_from_slice(&0u32.to_le_bytes());
        system.extend_from_slice(&26100u32.to_le_bytes());
        system.extend_from_slice(&2u32.to_le_bytes());
        system.extend_from_slice(&0u32.to_le_bytes()); // csd rva
        system.extend_from_slice(&0x110u16.to_le_bytes());
        system.extend_from_slice(&0u16.to_le_bytes());
        system.extend_from_slice(&[0u8; 24]); // CPU_INFORMATION
        builder.stream(7, &system);

        // MiscInfo revision 1
        let mut misc = Vec::new();
        misc.extend_from_slice(&24u32.to_le_bytes());
        misc.extend_from_slice(&0x3u32.to_le_bytes()); // PROCESS_ID|PROCESS_TIMES
        misc.extend_from_slice(&4242u32.to_le_bytes());
        misc.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        misc.extend_from_slice(&11u32.to_le_bytes());
        misc.extend_from_slice(&22u32.to_le_bytes());
        builder.stream(15, &misc);

        // Exception
        let mut exception = Vec::new();
        exception.extend_from_slice(&777u32.to_le_bytes());
        exception.extend_from_slice(&0u32.to_le_bytes());
        exception.extend_from_slice(&0xc000_0005u32.to_le_bytes());
        exception.extend_from_slice(&0u32.to_le_bytes());
        exception.extend_from_slice(&0u64.to_le_bytes());
        exception.extend_from_slice(&0x7ffb_55a8_e48bu64.to_le_bytes());
        exception.extend_from_slice(&2u32.to_le_bytes());
        exception.extend_from_slice(&0u32.to_le_bytes());
        exception.extend_from_slice(&1u64.to_le_bytes());
        exception.extend_from_slice(&0xdead_beefu64.to_le_bytes());
        exception.extend_from_slice(&[0u8; 13 * 8]);
        exception.extend_from_slice(&1232u32.to_le_bytes());
        exception.extend_from_slice(&0u32.to_le_bytes());
        builder.stream(6, &exception);

        // ThreadList
        let mut threads = 2u32.to_le_bytes().to_vec();
        threads.extend_from_slice(&thread_entry(777, 0xa000, 0xb000, 4096, 0));
        threads.extend_from_slice(&thread_entry(888, 0xc000, 0xd000, 8192, 0));
        builder.stream(3, &threads);

        // ModuleList
        let mut modules = 2u32.to_le_bytes().to_vec();
        modules.extend_from_slice(&module_entry(
            0x7ff6_0000_0000,
            0x4_5000,
            0x9a78_fc05,
            app_name,
            (cv.len() as u32, cv_rva),
        ));
        modules.extend_from_slice(&module_entry(
            0x7ffb_0000_0000,
            0x26_6000,
            0xc0ef_630d,
            dll_name,
            (0, 0),
        ));
        builder.stream(4, &modules);

        // UnloadedModuleList
        let mut unloaded = Vec::new();
        unloaded.extend_from_slice(&12u32.to_le_bytes());
        unloaded.extend_from_slice(&24u32.to_le_bytes());
        unloaded.extend_from_slice(&1u32.to_le_bytes());
        unloaded.extend_from_slice(&0x7ffa_0000_0000u64.to_le_bytes());
        unloaded.extend_from_slice(&0x1000u32.to_le_bytes());
        unloaded.extend_from_slice(&0u32.to_le_bytes());
        unloaded.extend_from_slice(&0x6500_0000u32.to_le_bytes());
        unloaded.extend_from_slice(&unloaded_name.to_le_bytes());
        builder.stream(14, &unloaded);

        // MemoryInfoList with one committed private region
        let mut regions = Vec::new();
        regions.extend_from_slice(&16u32.to_le_bytes());
        regions.extend_from_slice(&48u32.to_le_bytes());
        regions.extend_from_slice(&1u64.to_le_bytes());
        regions.extend_from_slice(&0x1_0000u64.to_le_bytes());
        regions.extend_from_slice(&0x1_0000u64.to_le_bytes());
        regions.extend_from_slice(&0x04u32.to_le_bytes());
        regions.extend_from_slice(&0u32.to_le_bytes());
        regions.extend_from_slice(&0x2_0000u64.to_le_bytes());
        regions.extend_from_slice(&0x1000u32.to_le_bytes());
        regions.extend_from_slice(&0x04u32.to_le_bytes());
        regions.extend_from_slice(&0x2_0000u32.to_le_bytes());
        regions.extend_from_slice(&0u32.to_le_bytes());
        builder.stream(16, &regions);

        // ThreadInfoList for the first thread only
        let mut infos = Vec::new();
        infos.extend_from_slice(&12u32.to_le_bytes());
        infos.extend_from_slice(&64u32.to_le_bytes());
        infos.extend_from_slice(&1u32.to_le_bytes());
        infos.extend_from_slice(&777u32.to_le_bytes());
        infos.extend_from_slice(&0u32.to_le_bytes());
        infos.extend_from_slice(&0u32.to_le_bytes());
        infos.extend_from_slice(&259u32.to_le_bytes());
        infos.extend_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        infos.extend_from_slice(&0u64.to_le_bytes());
        infos.extend_from_slice(&10_000u64.to_le_bytes());
        infos.extend_from_slice(&20_000u64.to_le_bytes());
        infos.extend_from_slice(&0x7ff6_0000_1000u64.to_le_bytes());
        infos.extend_from_slice(&0xffu64.to_le_bytes());
        builder.stream(17, &infos);

        // ThreadNames
        let name_rva = builder.string("worker");
        let mut names = 1u32.to_le_bytes().to_vec();
        names.extend_from_slice(&888u32.to_le_bytes());
        names.extend_from_slice(&u64::from(name_rva).to_le_bytes());
        builder.stream(24, &names);

        // CommentStreamA and an application-defined stream
        builder.stream(10, b"collected by test\0");
        builder.stream(0x1_0000, &[1, 2, 3, 4]);
        builder.stream(0, &[]);
        builder.finish(0xa0f4_a793, 1_787_166_007, 0x0020_0121)
    }

    #[test]
    fn parses_every_supported_stream_of_a_spec_built_dump() {
        let (_dir, path) = write(&full_fixture());
        let dump = parse_file(&path);
        assert_eq!(dump.format, FORMAT_MINIDUMP);
        assert_eq!(dump.parse_status, STATUS_PARSED, "{:?}", dump.issues);
        assert_eq!(dump.version_low, Some(MINIDUMP_VERSION));
        assert_eq!(dump.time_date_stamp, Some(1_787_166_007));
        assert_eq!(dump.flags, Some(0x0020_0121));
        assert_eq!(dump.stream_count, Some(12));
        assert_eq!(dump.directory_state, Some(RANGE_IN_FILE));

        let system = dump.system.clone().unwrap();
        assert_eq!(system.architecture_name, Some("x64"));
        assert_eq!(system.build_number, 26100);
        assert_eq!(system.number_of_processors, 8);
        assert_eq!(system.product_type_name, Some("server"));
        assert_eq!(system.platform_name, Some("windows_nt"));
        assert_eq!(system.csd_state, "not_recorded");

        let misc = dump.misc.clone().unwrap();
        assert_eq!(misc.revision, 1);
        assert_eq!(misc.process_id, Some(4242));
        assert_eq!(misc.process_create_time, Some(1_700_000_000));
        assert_eq!(misc.flag_names.as_deref(), Some("PROCESS_ID|PROCESS_TIMES"));
        // Fields outside the stored revision stay unknown.
        assert_eq!(misc.process_integrity_level, None);

        let exception = dump.exception.clone().unwrap();
        assert_eq!(exception.thread_id, 777);
        assert_eq!(exception.code, 0xc000_0005);
        assert_eq!(exception.code_name, Some("EXCEPTION_ACCESS_VIOLATION"));
        assert_eq!(exception.address, 0x7ffb_55a8_e48b);
        assert_eq!(exception.parameters, vec![1, 0xdead_beef]);
        assert!(!exception.parameters_truncated);

        assert_eq!(dump.threads.len(), 2);
        let first = &dump.threads[0];
        assert_eq!(first.thread_id, 777);
        assert_eq!(first.teb, Some(0xa000));
        assert_eq!(first.stack_start, Some(0xb000));
        assert_eq!(first.stack_size, Some(4096));
        assert_eq!(first.info.as_ref().unwrap().exit_status, 259);
        assert_eq!(dump.threads[1].name.as_deref(), Some("worker"));

        let loaded: Vec<&Module> = dump
            .modules
            .iter()
            .filter(|module| module.kind == MODULE_LOADED)
            .collect();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded[0].name.as_deref(),
            Some("C:\\Windows\\System32\\app.exe")
        );
        assert_eq!(
            loaded[0].version.as_ref().unwrap().file_version,
            "4.18.26070.9"
        );
        let cv = loaded[0].cv.as_ref().unwrap();
        assert_eq!(cv.signature, "RSDS");
        assert_eq!(cv.age, Some(7));
        assert_eq!(cv.pdb_file_name.as_deref(), Some("app.pdb"));
        assert_eq!(
            cv.guid.as_deref(),
            Some("11223344-5566-7788-99aa-bbccddeeff00")
        );

        let unloaded: Vec<&Module> = dump
            .modules
            .iter()
            .filter(|module| module.kind == MODULE_UNLOADED)
            .collect();
        assert_eq!(unloaded.len(), 1);
        assert_eq!(
            unloaded[0].name.as_deref(),
            Some("C:\\Windows\\System32\\gone.dll")
        );

        assert_eq!(dump.regions.len(), 1);
        let region = &dump.regions[0];
        assert_eq!(region.base_address, 0x1_0000);
        assert_eq!(region.region_size, 0x2_0000);
        assert_eq!(region.state_name, Some("MEM_COMMIT"));
        assert_eq!(region.region_type_name, Some("MEM_PRIVATE"));
        assert_eq!(region.protect_name.as_deref(), Some("PAGE_READWRITE"));

        let comment = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 10)
            .unwrap();
        assert_eq!(comment.text.as_deref(), Some("collected by test"));
        assert!(comment.sha256.is_some());

        let unknown = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 0x1_0000)
            .unwrap();
        assert_eq!(unknown.parse_state, STREAM_UNKNOWN_TYPE);
        assert_eq!(unknown.type_name, None);
        assert_eq!(unknown.prefix_hex.as_deref(), Some("01020304"));

        let unused = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 0)
            .unwrap();
        assert_eq!(unused.parse_state, STREAM_UNUSED);
    }

    #[test]
    fn empty_and_short_files_are_truncated_not_parsed() {
        let (_dir, path) = write(&[]);
        let dump = parse_file(&path);
        assert_eq!(dump.format, FORMAT_EMPTY);
        assert_eq!(dump.parse_status, STATUS_TRUNCATED);

        let (_dir2, path2) = write(&[0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7]);
        let dump = parse_file(&path2);
        assert_eq!(dump.parse_status, STATUS_TRUNCATED);
        assert!(dump.streams.is_empty());
    }

    #[test]
    fn truncated_body_keeps_header_and_reports_out_of_file_streams() {
        let full = full_fixture();
        let cut = full.len() / 2;
        let mut truncated = full.clone();
        truncated.truncate(cut);
        // The directory sits at the end of the file, so a cut body leaves the
        // header readable and the directory out of range.
        let dump = parse_file(&write(&truncated).1);
        assert!(matches!(
            dump.parse_status,
            STATUS_PARSED_WITH_ISSUES | STATUS_TRUNCATED
        ));
        assert!(dump.byte_count as usize == cut);
    }

    #[test]
    fn hostile_counts_do_not_allocate_or_succeed_silently() {
        let mut builder = Builder::new();
        // ThreadList claiming 0xffff_ffff threads inside a 8-byte stream.
        let mut threads = 0xffff_ffffu32.to_le_bytes().to_vec();
        threads.extend_from_slice(&[0u8; 4]);
        builder.stream(3, &threads);
        // ModuleList claiming 1e9 modules.
        let mut modules = 1_000_000_000u32.to_le_bytes().to_vec();
        modules.extend_from_slice(&[0u8; 8]);
        builder.stream(4, &modules);
        // Memory64List with a 64-bit count.
        let mut memory = u64::MAX.to_le_bytes().to_vec();
        memory.extend_from_slice(&0u64.to_le_bytes());
        builder.stream(9, &memory);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.parse_status, STATUS_PARSED_WITH_ISSUES);
        assert!(dump.threads.is_empty());
        assert!(dump.modules.is_empty());
        assert!(dump.regions.is_empty());
        assert!(dump
            .issues
            .iter()
            .any(|issue| issue.contains("4294967295")));
        assert!(dump
            .streams
            .iter()
            .all(|stream| stream.parse_state == STREAM_INVALID_STRUCTURE));
    }

    #[test]
    fn stream_ranges_outside_the_file_are_reported_not_read() {
        let mut builder = Builder::new();
        builder.stream(7, &[0u8; 56]);
        builder.raw_stream(4, 0xffff_ff00, 0x1000);
        builder.raw_stream(3, 16, 0xffff_0000);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.parse_status, STATUS_PARSED_WITH_ISSUES);
        let out_of_file: Vec<&Stream> = dump
            .streams
            .iter()
            .filter(|stream| stream.range_state == RANGE_OUT_OF_FILE)
            .collect();
        assert_eq!(out_of_file.len(), 2);
        assert!(out_of_file
            .iter()
            .all(|stream| stream.parse_state == STREAM_OUT_OF_FILE));
        assert!(dump.modules.is_empty());
        assert!(dump.threads.is_empty());
    }

    #[test]
    fn overlapping_streams_are_flagged() {
        let mut builder = Builder::new();
        let rva = builder.place(&[0u8; 128]);
        builder.raw_stream(10, 64, rva);
        builder.raw_stream(11, 64, rva + 32);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert!(dump.streams.iter().all(|stream| stream.overlaps));
        assert!(dump.issues.iter().any(|issue| issue.contains("겹칩니다")));
    }

    #[test]
    fn module_name_outside_the_file_keeps_the_module_row() {
        let mut builder = Builder::new();
        let mut modules = 1u32.to_le_bytes().to_vec();
        modules.extend_from_slice(&module_entry(0x1000, 0x2000, 0, 0x7fff_0000, (0, 0)));
        builder.stream(4, &modules);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.modules.len(), 1);
        assert_eq!(dump.modules[0].name, None);
        assert_eq!(dump.modules[0].name_state, "out_of_file");
        assert_eq!(dump.modules[0].base_of_image, 0x1000);
        assert_eq!(dump.parse_status, STATUS_PARSED_WITH_ISSUES);
    }

    #[test]
    fn kernel_and_legacy_containers_are_refused_by_signature() {
        for (lead, format) in [
            (&b"PAGEDUMP"[..], FORMAT_KERNEL_X86),
            (&b"PAGEDU64"[..], FORMAT_KERNEL_X64),
            (&b"USERDUMP"[..], FORMAT_USERDUMP_X86),
            (&b"USERDU64"[..], FORMAT_USERDUMP_X64),
            (&b"MSCF\0\0\0\0"[..], FORMAT_CAB),
        ] {
            let mut bytes = lead.to_vec();
            bytes.extend_from_slice(&[0u8; 4096]);
            let (_dir, path) = write(&bytes);
            let dump = parse_file(&path);
            assert_eq!(dump.format, format);
            assert_eq!(dump.parse_status, STATUS_UNSUPPORTED_FORMAT);
            assert!(dump.streams.is_empty());
            assert!(dump.threads.is_empty());
        }
    }

    #[test]
    fn unknown_minidump_version_is_not_parsed_as_data() {
        let bytes = full_fixture();
        let mut altered = bytes.clone();
        altered[4..8].copy_from_slice(&0xa0f4_0001u32.to_le_bytes());
        let (_dir, path) = write(&altered);
        let dump = parse_file(&path);
        assert_eq!(dump.format, FORMAT_MINIDUMP);
        assert_eq!(dump.parse_status, STATUS_UNSUPPORTED_VERSION);
        assert_eq!(dump.version_low, Some(1));
        assert!(dump.streams.is_empty());
        assert!(dump.system.is_none());
    }

    #[test]
    fn memory_streams_keep_metadata_without_raw_retention() {
        let mut builder = Builder::new();
        let mut memory = 2u32.to_le_bytes().to_vec();
        memory.extend_from_slice(&0x1_0000u64.to_le_bytes());
        memory.extend_from_slice(&0x100u32.to_le_bytes());
        memory.extend_from_slice(&0u32.to_le_bytes());
        memory.extend_from_slice(&0x2_0000u64.to_le_bytes());
        memory.extend_from_slice(&0x200u32.to_le_bytes());
        memory.extend_from_slice(&0u32.to_le_bytes());
        builder.stream(5, &memory);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.regions.len(), 2);
        assert_eq!(dump.regions[0].source_stream, REGION_FROM_MEMORY_LIST);
        assert_eq!(dump.regions[1].data_size, Some(0x200));
        let stream = &dump.streams[0];
        assert_eq!(stream.parse_state, STREAM_METADATA_ONLY);
        assert_eq!(stream.sha256, None);
        assert_eq!(stream.prefix_hex, None);
        assert_eq!(
            stream.note.as_deref(),
            Some("raw_not_retained_bulk_stream")
        );
    }

    #[test]
    fn thread_info_without_a_thread_list_entry_keeps_its_own_row() {
        let mut builder = Builder::new();
        let mut threads = 1u32.to_le_bytes().to_vec();
        threads.extend_from_slice(&thread_entry(10, 0, 0, 0, 0));
        builder.stream(3, &threads);
        let mut infos = Vec::new();
        infos.extend_from_slice(&12u32.to_le_bytes());
        infos.extend_from_slice(&64u32.to_le_bytes());
        infos.extend_from_slice(&2u32.to_le_bytes());
        for id in [10u32, 99u32] {
            infos.extend_from_slice(&id.to_le_bytes());
            infos.extend_from_slice(&[0u8; 12]);
            infos.extend_from_slice(&[0u8; 48]);
        }
        builder.stream(17, &infos);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.threads.len(), 2);
        assert_eq!(dump.threads[0].source_stream, THREAD_FROM_LIST);
        assert_eq!(dump.threads[1].source_stream, THREAD_FROM_INFO_ONLY);
        assert_eq!(dump.threads[1].thread_id, 99);
        assert_eq!(dump.threads[1].suspend_count, None);
    }

    #[test]
    fn documented_singleton_streams_keep_their_named_fields() {
        let mut builder = Builder::new();
        // MINIDUMP_PROCESS_VM_COUNTERS_2 with VIRTUALSIZE|EX but no EX2/JOB.
        let mut counters = Vec::new();
        counters.extend_from_slice(&2u16.to_le_bytes()); // Revision
        counters.extend_from_slice(&0x0007u16.to_le_bytes()); // Flags
        counters.extend_from_slice(&1234u32.to_le_bytes()); // PageFaultCount
        for value in [
            32_411_648u64,
            23_998_464,
            402_448,
            197_640,
            287_904,
            27_304,
            11_194_368,
            12_242_944,
        ] {
            counters.extend_from_slice(&value.to_le_bytes());
        }
        counters.extend_from_slice(&2_203_466_379_264u64.to_le_bytes()); // PeakVirtualSize
        counters.extend_from_slice(&2_203_460_075_520u64.to_le_bytes()); // VirtualSize
        counters.extend_from_slice(&11_194_368u64.to_le_bytes()); // PrivateUsage
        counters.extend_from_slice(&[0u8; 7 * 8]); // EX2 + JOB fields, flagged off
        assert_eq!(counters.len(), 152);
        builder.stream(22, &counters);

        // MINIDUMP_SYSTEM_MEMORY_INFO revision 2: only the leading fields are
        // documented for revision 1, so the body stays unread.
        let mut system_memory = 2u16.to_le_bytes().to_vec();
        system_memory.extend_from_slice(&0x3fu16.to_le_bytes());
        system_memory.extend_from_slice(&[0u8; 520]);
        builder.stream(21, &system_memory);

        // MINIDUMP_FUNCTION_TABLE_STREAM header plus one descriptor.
        let mut function_table = Vec::new();
        function_table.extend_from_slice(&24u32.to_le_bytes()); // SizeOfHeader
        function_table.extend_from_slice(&32u32.to_le_bytes()); // SizeOfDescriptor
        function_table.extend_from_slice(&56u32.to_le_bytes()); // SizeOfNativeDescriptor
        function_table.extend_from_slice(&12u32.to_le_bytes()); // SizeOfFunctionEntry
        function_table.extend_from_slice(&1u32.to_le_bytes()); // NumberOfDescriptors
        function_table.extend_from_slice(&0u32.to_le_bytes()); // SizeOfAlignPad
        function_table.extend_from_slice(&[0u8; 32]);
        builder.stream(13, &function_table);

        // MINIDUMP_HANDLE_DATA_STREAM header.
        let mut handles = Vec::new();
        handles.extend_from_slice(&16u32.to_le_bytes());
        handles.extend_from_slice(&40u32.to_le_bytes());
        handles.extend_from_slice(&2u32.to_le_bytes());
        handles.extend_from_slice(&0u32.to_le_bytes());
        handles.extend_from_slice(&[0u8; 80]);
        builder.stream(12, &handles);

        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.parse_status, STATUS_PARSED, "{:?}", dump.issues);

        let value = |field: &str| {
            dump.counters
                .iter()
                .find(|counter| counter.field == field)
                .map(|counter| counter.value)
        };
        assert_eq!(value("WorkingSetSize"), Some(23_998_464));
        assert_eq!(value("PageFaultCount"), Some(1234));
        assert_eq!(value("VirtualSize"), Some(2_203_460_075_520));
        assert_eq!(value("PrivateUsage"), Some(11_194_368));
        // EX2 and JOB groups are not flagged: they stay unknown, not zero.
        assert_eq!(value("PrivateWorkingSetSize"), None);
        assert_eq!(value("JobTotalCommitLimit"), None);
        assert_eq!(value("SizeOfNativeDescriptor"), Some(56));
        assert_eq!(value("NumberOfDescriptors"), Some(1));

        let vm = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 22)
            .unwrap();
        assert_eq!(vm.parse_state, STREAM_TYPED);
        let memory = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 21)
            .unwrap();
        assert_eq!(memory.parse_state, STREAM_HEADER_ONLY);
        assert!(memory.sha256.is_some());
        assert_eq!(
            memory.note.as_deref(),
            Some("system_memory_info_revision_2_body_layout_not_documented")
        );
        let table = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 13)
            .unwrap();
        assert_eq!(table.parse_state, STREAM_HEADER_ONLY);
        assert_eq!(table.entry_size, Some(32));
        assert_eq!(table.declared_entries, Some(1));
        // Native unwind data is never retained raw.
        assert_eq!(table.sha256, None);
        let handle = dump
            .streams
            .iter()
            .find(|stream| stream.type_code == 12)
            .unwrap();
        assert_eq!(handle.parse_state, STREAM_HEADER_ONLY);
        assert_eq!(handle.stored_entries, Some(2));
    }

    /// `MINIDUMP_MODULE_LIST` is documented as an array of loaded modules, so
    /// index 0 may be a DLL. The reader reports "the first loaded module" and
    /// keeps every module's own evidence; it marks no module as the process.
    #[test]
    fn first_loaded_module_is_only_the_module_at_index_zero() {
        let mut builder = Builder::new();
        let dll = builder.string("C:\\Windows\\System32\\ntdll.dll");
        let exe = builder.string("C:\\Windows\\System32\\app.exe");
        let mut modules = 2u32.to_le_bytes().to_vec();
        modules.extend_from_slice(&module_entry(0x7ffb_0000_0000, 0x26_6000, 0, dll, (0, 0)));
        modules.extend_from_slice(&module_entry(0x7ff6_0000_0000, 0x4_5000, 0, exe, (0, 0)));
        builder.stream(4, &modules);
        let bytes = builder.finish(0xa0f4_a793, 1, 0);
        let (_dir, path) = write(&bytes);
        let dump = parse_file(&path);
        assert_eq!(dump.modules.len(), 2);
        let first = dump.first_loaded_module().unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(
            first.name.as_deref(),
            Some("C:\\Windows\\System32\\ntdll.dll")
        );
        assert_eq!(
            dump.modules[1].name.as_deref(),
            Some("C:\\Windows\\System32\\app.exe")
        );
        assert!(dump.modules.iter().all(|module| module.kind == MODULE_LOADED));
    }
}
