//! Registry facts: legacy columns and row order plus loss-aware tree/value evidence.
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_key_value::CellKeyValue;
use notatin::cell_value::CellValue;
use notatin::log::Logs;
use notatin::parser::ParserIterator;
use notatin::parser_builder::ParserBuilder;
use serde::Serialize;

use crate::hex::hex_lower;
use crate::sqlite::{Row, StreamWriter};
use crate::time::fmt_kst;

pub const REG_TABLE: &str = "Registry";
pub const REG_FILENAMES: &[&str] = &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
pub const REG_SUFFIXES: &[&str] = &["NTUSER.DAT", "USRCLASS.DAT"];
pub const REG_FIELD_ORDER: &[&str] = &[
    // 기존 7열 — 이름·순서·의미 고정.
    "last_write",
    "key_path",
    "value_name",
    "value_type",
    "value_data",
    "_recovery",
    "_source_file",
    // 추가 facts — 항상 끝에만 덧붙인다.
    "entry_kind",
    "key_offset",
    "parent_key_offset",
    "key_name",
    "key_subkey_count",
    "key_value_count",
    "key_read_status",
    "key_read_error",
    "value_offset",
    "value_name_raw",
    "value_type_code",
    "value_data_hex",
    "value_data_text",
    "value_read_status",
    "value_read_error",
];

/// 산출물 SQLite의 기본 이름. 사용자 하이브(NTUSER.DAT/UsrClass.dat)는 계정마다
/// 하나씩 수집되므로 `<계정>_<하이브>`로 발행한다 — 파생 계층(hive_user,
/// UserAssist 실행 이력, Shellbag 계정)이 이 규칙으로 어느 계정의 값인지
/// 복원하기 때문이다. 머신 하이브(SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT)는
/// 파생이 이름을 그대로 조회하므로 접두를 붙이지 않는다.
pub fn output_base_name(primary: &Path) -> String {
    let fname = primary
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "hive".to_string());
    let Some(canonical) = canonical_user_hive_name(&fname) else {
        return fname;
    };
    match hive_account(primary) {
        // 케이스 편차(ntuser.dat)도 정규 표기로 통일한다 — 대소문자를 구분하지
        // 않는 파일시스템에서 같은 하이브가 두 이름으로 갈리지 않게.
        Some(account) => format!("{account}_{canonical}"),
        None => canonical.to_string(),
    }
}

/// 파일명이 사용자 하이브 그 자체일 때만 정규 표기를 돌려준다. 수집기가 이미
/// `<계정>_NTUSER.DAT`처럼 접두를 붙여 둔 이름은 그대로 보존한다.
fn canonical_user_hive_name(fname: &str) -> Option<&'static str> {
    if fname.eq_ignore_ascii_case("NTUSER.DAT") {
        return Some("NTUSER.DAT");
    }
    if fname.eq_ignore_ascii_case("UsrClass.dat") {
        return Some("UsrClass.dat");
    }
    None
}

/// 계정별 프로필 디렉터리를 담는 것으로 확인된 컨테이너 이름. 사용자 하이브의
/// 계정은 **이 컨테이너 바로 아래 디렉터리일 때만** 인정한다.
///
/// 이전에는 반대로 "계정일 수 없는 이름" 차단 목록을 썼는데, 두 방향 모두에서
/// 틀렸다 — 목록에 없는 임의 수집 폴더(`Collected/`, `EvidenceExport/`)는 여전히
/// 가짜 계정을 만들었고, 반대로 목록 단어와 이름이 같은 **실제 계정**
/// (`REGISTRY/Windows/NTUSER.DAT`)은 계정을 잃었다. 계정은 추측이 아니라 경로
/// 구조가 뒷받침할 때만 부여한다.
const ACCOUNT_CONTAINER_DIRS: &[&str] = &[
    // 수집기가 계정별로 하이브를 모아 두는 폴더
    "REGISTRY",
    "REGISTRY_WOW64",
    "REGISTRIES",
    "HIVES",
    "HIVE",
    // Windows의 프로필 루트
    "USERS",
    "DOCUMENTS AND SETTINGS",
    "PROFILES",
    // Windows\System32\config\systemprofile
    "CONFIG",
];

/// 하이브 경로에서 계정명을 복원한다. 근거는 둘 중 하나여야 한다.
///
/// 1. `…\<계정>\AppData\…\UsrClass.dat` — AppData 바로 앞이 프로필 디렉터리.
/// 2. `<계정 컨테이너>\<계정>\NTUSER.DAT` — 계정별 프로필을 담는 것으로 확인된
///    컨테이너(`Users`, 수집기의 `REGISTRY/` 등) 바로 아래 디렉터리.
///
/// 그 외(평면 수집본 `REGISTRY/NTUSER.DAT`, 임의 폴더 `Collected/NTUSER.DAT`)는
/// 계정을 알 수 없으므로 접두 없이 발행한다 — 원본에 없는 값을 계정으로 제시하면
/// UserAssist·Shellbag·레지스트리 특이사항이 존재하지 않는 사용자 활동처럼 보인다.
///
/// 증거 경로 자체가 분석 호스트의 `Users` 아래 있을 수 있으므로 경로 전체에서
/// `Users`를 찾아 올라가지 않는다 — 하이브 바로 위 두 단계만 본다.
fn hive_account(primary: &Path) -> Option<String> {
    let parts: Vec<String> = primary
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    // 파일명 자신은 계정 후보가 아니다.
    let dirs = &parts[..parts.len().saturating_sub(1)];
    // 하이브에 가장 가까운 AppData를 기준으로 삼는다 — 증거를 담아 둔 분석
    // 호스트 경로에 AppData가 들어 있어도 그쪽을 계정으로 잡지 않게.
    let account = match dirs
        .iter()
        .rposition(|part| part.eq_ignore_ascii_case("AppData"))
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| dirs.get(i))
    {
        Some(profile) => profile,
        None => {
            // 부모가 계정 디렉터리라는 근거는 그 위(조부모)가 계정 컨테이너인지다.
            let parent = dirs.last()?;
            let container = dirs.get(dirs.len().checked_sub(2)?)?;
            if !ACCOUNT_CONTAINER_DIRS
                .iter()
                .any(|known| container.eq_ignore_ascii_case(known))
            {
                return None;
            }
            parent
        }
    };
    let account = sanitize_name_component(account);
    // 루트(`/`, `C:\\`)처럼 계정으로 볼 수 없는 컴포넌트는 접두를 만들지 않는다.
    if account.is_empty() || account.chars().all(|c| c == '_' || c == '.') {
        None
    } else {
        Some(account)
    }
}

/// 계정명을 파일명 한 조각으로 쓸 수 있게 다듬는다. 계정은 원본 경로에서 오므로
/// 보통 그대로 안전하지만, 산출물 이름은 `record_key`(`<이름>::<테이블>::<rowid>`)의
/// 앞부분이기도 해서 구분자를 깨뜨릴 수 있는 문자는 남기지 않는다.
fn sanitize_name_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Temporary incident-response performance switch.  Keep this explicit rather
/// than deleting recovery code: normal, allocated Registry records continue to
/// be parsed and published, but deleted-cell discovery is deliberately not
/// performed for this run generation (비용이 큰 복구 단계).
pub const TEMPORARILY_DISABLE_RECOVERY: bool = true;

/// 트랜잭션 로그(.LOG1/.LOG2)는 복구가 아니라 하이브의 최신 정합 상태를 만드는
/// 조합 단계다 — 로그 파일이 하이브 옆에 있으면 항상 적용한다.
pub const APPLY_TRANSACTION_LOGS: bool = true;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistryRecoveryPlan {
    recover_deleted_cells: bool,
    apply_transaction_logs: bool,
}

fn registry_recovery_plan() -> RegistryRecoveryPlan {
    RegistryRecoveryPlan {
        recover_deleted_cells: !TEMPORARILY_DISABLE_RECOVERY,
        apply_transaction_logs: APPLY_TRANSACTION_LOGS,
    }
}

fn transaction_logs_to_apply(logs: &[PathBuf], plan: RegistryRecoveryPlan) -> &[PathBuf] {
    if plan.apply_transaction_logs {
        logs
    } else {
        &[]
    }
}

pub fn registry_recovery_disabled() -> bool {
    TEMPORARILY_DISABLE_RECOVERY
}

/// Per-hive timings are deliberately phase-labelled.  Iteration and SQLite
/// buffering share a streaming loop, so reporting them as one phase avoids a
/// false precision while still making recovery/build bottlenecks observable.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HiveParseMetrics {
    pub row_count: usize,
    /// Transaction logs found beside this hive.
    pub recovery_logs_discovered: usize,
    /// Transaction logs actually applied during this parse.
    pub recovery_log_count: usize,
    /// False while the temporary live-only mode is enabled.
    pub recovery_enabled: bool,
    pub recovered_row_count: usize,
    /// Time waiting for a process-wide deleted-recovery permit. Kept separate
    /// from parser build time so a concurrent host is not misdiagnosed as a
    /// slow or damaged hive.
    pub recovery_permit_wait_ms: u128,
    pub build_recovery_ms: u128,
    pub iteration_and_sqlite_write_ms: u128,
    /// 발견된 트랜잭션 로그를 적용하지 못하고 기본 하이브만으로 폴백했을 때의
    /// 실패 사유. None이면 로그가 없었거나 정상 적용된 것이다.
    pub recovery_log_apply_error: Option<String>,
}

/// Deleted-cell discovery is the costly part of a Registry hive parse.  The
/// GUI can run two hosts, and a single host can have SYSTEM and SOFTWARE that
/// both benefit from parallel recovery.  These process-wide advisory permits
/// cap *builder/recovery* work at two across child processes, while allowing a
/// lone host to use both CPU slots.  The lock is released automatically by the
/// OS when a cancelled worker process is killed, so it cannot strand a future
/// parse behind a stale marker file.
#[cfg(unix)]
struct RegistryRecoveryPermit(File);

#[cfg(unix)]
impl Drop for RegistryRecoveryPermit {
    fn drop(&mut self) {
        // Best-effort only: closing the file also releases flock().
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn acquire_recovery_permit() -> Result<RegistryRecoveryPermit> {
    let root = std::env::temp_dir().join("windows-analysis-registry-recovery-v1");
    std::fs::create_dir_all(&root)?;
    loop {
        if crate::pipeline::cancelled() {
            anyhow::bail!("registry recovery permit wait cancelled");
        }
        for slot in 0..2 {
            let path = root.join(format!("slot-{slot}.lock"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            let result = unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            };
            if result == 0 {
                return Ok(RegistryRecoveryPermit(file));
            }
        }
        // The bounded scheduler keeps UI work responsive. Waiting briefly for
        // a global recovery permit is preferable to four deleted-cell scans
        // competing for the same memory/CPU and taking longer overall.
        std::thread::sleep(Duration::from_millis(40));
    }
}

#[cfg(not(unix))]
struct RegistryRecoveryPermit;

#[cfg(not(unix))]
fn acquire_recovery_permit() -> Result<RegistryRecoveryPermit> {
    // Keep the existing one-worker behaviour on platforms where this crate
    // does not have a process-wide advisory-lock implementation.
    Ok(RegistryRecoveryPermit)
}

pub(crate) fn registry_recovery_worker_count(hive_count: usize) -> usize {
    if hive_count == 0 {
        return 0;
    }
    #[cfg(unix)]
    {
        hive_count.min(2)
    }
    #[cfg(not(unix))]
    {
        let _ = hive_count;
        1
    }
}

fn has_control(s: &str) -> bool {
    s.chars()
        .any(|c| c == '\u{0}' || ((c as u32) < 32 && c != '\t' && c != '\n' && c != '\r'))
}
/// Mirror the Python `_clean` for a decoded string: strip a trailing NUL, and
/// if control bytes remain, hex-encode (latin-1) instead of storing a BLOB.
fn clean_str(s: &str) -> String {
    let s = s.trim_end_matches('\u{0}');
    if has_control(s) {
        let bytes: Vec<u8> = s
            .chars()
            .map(|c| if (c as u32) <= 255 { c as u8 } else { b'?' })
            .collect();
        hex_lower(&bytes)
    } else {
        s.to_string()
    }
}
/// json.dumps(list, ensure_ascii=False) — ["a", "b"] with a space after commas.
fn json_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", parts.join(", "))
}
fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn type_name(value: &CellKeyValue) -> String {
    // notatin's variant names match regipy's REG_* strings except 0x03
    // (notatin REG_BIN -> regipy REG_BINARY). For a type notatin doesn't map
    // (REG_UNKNOWN=999) regipy surfaces the raw numeric type instead — SAM
    // abuses the type field to store a RID (500, 1000, ...), so keep the raw
    // number to stay 1:1 with regipy (and preserve that RID).
    let s = format!("{:?}", value.data_type);
    match s.as_str() {
        "REG_BIN" => "REG_BINARY".to_string(),
        "REG_UNKNOWN" => value.detail.data_type_raw().to_string(),
        _ => s,
    }
}

fn render_value(cv: &CellValue) -> String {
    match cv {
        CellValue::String(s) => clean_str(s),
        CellValue::Binary(b) => hex_lower(b),
        CellValue::MultiString(v) => json_list(v),
        CellValue::U32(v) => v.to_string(),
        CellValue::I32(v) => v.to_string(),
        CellValue::U64(v) => v.to_string(),
        CellValue::I64(v) => v.to_string(),
        _ => String::new(),
    }
}

// Keys with values carry their key metadata on each value row.
const ENTRY_KIND_KEY: &str = "key";
const ENTRY_KIND_VALUE: &str = "value";

// notatin 1.0.1 base_block.rs: 512-byte base plus 3584-byte extension.
pub(crate) const HIVE_BIN_DATA_OFFSET: usize = 4096;

// KeyNodeFlags::KEY_HIVE_ENTRY.
const KEY_HIVE_ENTRY: u16 = 0x0004;
// KEY_PREDEF_HANDLE stores a handle instead of a value count.
const KEY_PREDEF_HANDLE: u16 = 0x0040;
// Resident data occupies the vk offset field.
const DATA_IS_RESIDENT_MASK: u32 = 0x8000_0000;

// Empty payloads and unreadable payloads must remain distinguishable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueReadState {
    Ok,
    Empty,
    Error,
    Partial,
}

impl ValueReadState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Empty => "empty",
            Self::Error => "error",
            Self::Partial => "partial",
        }
    }
}

fn classify_value_read(
    read_len: Option<usize>,
    declared_len: usize,
    decode_failed: bool,
    has_diagnostics: bool,
) -> ValueReadState {
    let Some(read_len) = read_len else {
        return ValueReadState::Error;
    };
    if decode_failed {
        return ValueReadState::Error;
    }
    if read_len == 0 {
        return if declared_len == 0 {
            ValueReadState::Empty
        } else {
            ValueReadState::Error
        };
    }
    if has_diagnostics || read_len != declared_len {
        ValueReadState::Partial
    } else {
        ValueReadState::Ok
    }
}

// Recovery may increase counts; predefined handles are not value counts.
fn key_read_shortfalls(
    declared_values: u32,
    values_read: usize,
    declared_subkeys: u32,
    subkeys_listed: usize,
    predefined_handle: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    if !predefined_handle && (values_read as u64) < u64::from(declared_values) {
        notes.push(format!(
            "값 {declared_values}개 중 {values_read}개만 읽혔다"
        ));
    }
    if (subkeys_listed as u64) < u64::from(declared_subkeys) {
        notes.push(format!(
            "하위 키 {declared_subkeys}개 중 {subkeys_listed}개만 목록화됐다"
        ));
    }
    notes
}

// Keep decoded text unchanged; binary payloads live in value_data_hex.
fn decode_value_text(content: &CellValue) -> String {
    match content {
        CellValue::String(s) => s.clone(),
        CellValue::MultiString(v) => json_list(v),
        CellValue::U32(v) => v.to_string(),
        CellValue::I32(v) => v.to_string(),
        CellValue::U64(v) => v.to_string(),
        CellValue::I64(v) => v.to_string(),
        CellValue::Binary(_) | CellValue::None | CellValue::Error => String::new(),
    }
}

struct KeyFacts {
    offset: String,
    parent_offset: String,
    name: String,
    subkey_count: String,
    value_count: String,
    read_status: &'static str,
    read_error: String,
}

impl KeyFacts {
    fn insert_into(&self, row: &mut Row) {
        row.insert("key_offset".into(), self.offset.clone());
        row.insert("parent_key_offset".into(), self.parent_offset.clone());
        row.insert("key_name".into(), self.name.clone());
        row.insert("key_subkey_count".into(), self.subkey_count.clone());
        row.insert("key_value_count".into(), self.value_count.clone());
        row.insert("key_read_status".into(), self.read_status.into());
        row.insert("key_read_error".into(), self.read_error.clone());
    }
}

// values_read counts emitted values, not the declared count.
fn key_facts(key: &CellKeyNode, values_read: usize) -> KeyFacts {
    let flags = key.detail.key_node_flag_bits();
    let declared_subkeys = key.detail.number_of_sub_keys();
    let declared_values = key.detail.number_of_key_values();
    let mut notes = key_read_shortfalls(
        declared_values,
        values_read,
        declared_subkeys,
        key.cell_sub_key_offsets_absolute.len(),
        flags & KEY_PREDEF_HANDLE != 0,
    );
    let parse_logs = key.logs.to_string();
    if !parse_logs.is_empty() {
        notes.push(parse_logs);
    }
    // Invalid parent offsets are partial evidence, not additional roots.
    let parent_offset = if flags & KEY_HIVE_ENTRY != 0 {
        String::new()
    } else {
        let relative = key.detail.parent_key_offset_relative();
        if relative >= 0 {
            (HIVE_BIN_DATA_OFFSET + relative as usize).to_string()
        } else {
            notes.push(format!("부모 키 오프셋이 유효하지 않다({relative})"));
            String::new()
        }
    };
    KeyFacts {
        offset: key.file_offset_absolute.to_string(),
        parent_offset,
        name: key.key_name.clone(),
        subkey_count: declared_subkeys.to_string(),
        value_count: declared_values.to_string(),
        read_status: if notes.is_empty() { "ok" } else { "partial" },
        read_error: notes.join(" / "),
    }
}

struct ValueFacts {
    offset: String,
    name_raw: String,
    type_code: String,
    data_hex: String,
    data_text: String,
    read_status: &'static str,
    read_error: String,
}

impl ValueFacts {
    fn insert_into(self, row: &mut Row) {
        row.insert("value_offset".into(), self.offset);
        row.insert("value_name_raw".into(), self.name_raw);
        row.insert("value_type_code".into(), self.type_code);
        row.insert("value_data_hex".into(), self.data_hex);
        row.insert("value_data_text".into(), self.data_text);
        row.insert("value_read_status".into(), self.read_status.into());
        row.insert("value_read_error".into(), self.read_error);
    }
}

// Empty strings identify non-value rows without introducing NULLs.
fn blank_value_facts(row: &mut Row) {
    for column in [
        "value_offset",
        "value_name_raw",
        "value_type_code",
        "value_data_hex",
        "value_data_text",
        "value_read_status",
        "value_read_error",
    ] {
        row.insert(column.into(), String::new());
    }
}

// notatin stops UTF-16 decoding at the first NUL; allow one terminator.
fn text_interpretation_coverage(content: &CellValue) -> Option<usize> {
    const UTF16_UNIT: usize = 2;
    match content {
        CellValue::String(s) => Some(s.encode_utf16().count() * UTF16_UNIT + UTF16_UNIT),
        CellValue::MultiString(items) => Some(
            items
                .iter()
                .map(|s| s.encode_utf16().count() * UTF16_UNIT + UTF16_UNIT)
                .sum::<usize>()
                + UTF16_UNIT,
        ),
        _ => None,
    }
}

// notatin truncates oversized numeric payloads; never fabricate the missing tail.
fn value_facts(
    value: &CellKeyValue,
    content: &CellValue,
    content_logs: Option<&Logs>,
) -> ValueFacts {
    let declared_len = (value.detail.data_size_raw() & !DATA_IS_RESIDENT_MASK) as usize;
    let bytes = value.detail.value_bytes();
    let read_len = bytes.as_ref().map(|b| b.len());

    let mut notes: Vec<String> = Vec::new();
    let cell_logs = value.logs.to_string();
    if !cell_logs.is_empty() {
        notes.push(cell_logs);
    }
    if let Some(logs) = content_logs {
        let logs = logs.to_string();
        if !logs.is_empty() {
            notes.push(logs);
        }
    }
    let decode_failed = matches!(content, CellValue::Error);
    let mut state = classify_value_read(read_len, declared_len, decode_failed, !notes.is_empty());
    match (state, read_len) {
        (ValueReadState::Error, None) => notes.push("값 데이터를 읽지 못했다".to_string()),
        (ValueReadState::Error, Some(0)) => {
            notes.push(format!("선언 {declared_len}바이트 중 0바이트만 읽혔다"))
        }
        (ValueReadState::Partial, Some(len)) if len != declared_len => notes.push(format!(
            "선언 {declared_len}바이트 중 {len}바이트만 보존됐다"
        )),
        _ => {}
    }
    if decode_failed {
        notes.push("데이터 해석 실패".to_string());
    }
    // Hex remains authoritative when decoded text covers only part of the payload.
    if let (Some(covered), Some(len)) = (text_interpretation_coverage(content), read_len) {
        if len > covered {
            notes.push(format!(
                "원문 {len}바이트 중 {covered}바이트만 문자열로 해석됐다(첫 NUL에서 종료) — 전체 원문은 value_data_hex"
            ));
            if state == ValueReadState::Ok {
                state = ValueReadState::Partial;
            }
        }
    }

    ValueFacts {
        offset: value.file_offset_absolute.to_string(),
        name_raw: value.detail.value_name(),
        type_code: value.detail.data_type_raw().to_string(),
        data_hex: bytes.as_deref().map(hex_lower).unwrap_or_default(),
        data_text: decode_value_text(content),
        read_status: state.as_str(),
        read_error: notes.join(" / "),
    }
}

/// Sibling transaction logs (.LOG1/.LOG2) next to a primary hive.
pub fn sibling_logs(primary: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    if let Some(dir) = primary.parent() {
        let name = primary
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                let up = fname.to_uppercase();
                if up == format!("{}.LOG1", name).to_uppercase()
                    || up == format!("{}.LOG2", name).to_uppercase()
                {
                    logs.push(e.path());
                }
            }
        }
    }
    logs.sort();
    logs
}

/// "live" for an allocated cell, else notatin's deleted/recovered state name
/// (DeletedPrimaryFile, DeletedPrimaryFileSlack, DeletedTransactionLog, ...).
fn recovery_label(
    key: &notatin::cell_key_node::CellKeyNode,
    value_deleted: Option<&notatin::cell_key_value::CellKeyValue>,
) -> String {
    if let Some(v) = value_deleted {
        if v.cell_state.is_deleted() {
            return format!("{:?}", v.cell_state);
        }
    }
    if key.cell_state.is_deleted() {
        return format!("{:?}", key.cell_state);
    }
    "live".to_string()
}

pub fn parse_hive_stream(primary: &Path, out: &Path) -> Result<usize> {
    let logs = sibling_logs(primary);
    Ok(parse_hive_stream_with_metrics(primary, &logs, out)?.row_count)
}

/// `logs`: 파이프라인이 계획 단계에서 고정한 이 하이브의 트랜잭션 로그 목록.
/// 파싱 시점에 다시 발견하지 않으므로, 목록화 이후 수집 디렉터리가 변해도
/// 계획·실제 입력·보고서가 같은 스냅샷을 쓴다 (Amcache와 동일 계약).
pub fn parse_hive_stream_with_metrics(
    primary: &Path,
    logs: &[PathBuf],
    out: &Path,
) -> Result<HiveParseMetrics> {
    let source = primary.to_string_lossy().to_string();
    let recovery_plan = registry_recovery_plan();
    let recovery_logs_discovered = logs.len();
    let logs_to_apply: Vec<PathBuf> = transaction_logs_to_apply(logs, recovery_plan).to_vec();
    let make_builder = |with_logs: bool| {
        // notatin stores the path, so a borrowed &Path fails the 'static bound.
        #[allow(clippy::unnecessary_to_owned)]
        let mut builder = ParserBuilder::from_path(primary.to_path_buf());
        if with_logs {
            for log in &logs_to_apply {
                builder.with_transaction_log(log.clone());
            }
        }
        if recovery_plan.recover_deleted_cells {
            builder.recover_deleted(true);
        }
        builder
    };
    // 로그 포함 빌드가 실패해도(손상·적용 불가 .LOG1/.LOG2) 유효한 기본
    // 하이브까지 통째로 버리지 않는다 — 정책은 "로그 문제를 기록하고 하이브
    // 파싱은 계속". 실패 사유를 메트릭에 남기고 로그 없이 한 번 재시도한다.
    let mut recovery_log_count = logs_to_apply.len();
    let mut recovery_log_apply_error: Option<String> = None;
    let mut build_parser = || match make_builder(!logs_to_apply.is_empty()).build() {
        Ok(parser) => Ok(parser),
        Err(error) => {
            if logs_to_apply.is_empty() {
                return Err(error);
            }
            recovery_log_apply_error = Some(error.to_string());
            recovery_log_count = 0;
            make_builder(false).build()
        }
    };
    let (parser, recovery_permit_wait_ms, build_recovery_ms) =
        if recovery_plan.recover_deleted_cells {
            let permit_wait_started = std::time::Instant::now();
            let recovery_permit = acquire_recovery_permit()?;
            let recovery_permit_wait_ms = permit_wait_started.elapsed().as_millis();
            let build_started = std::time::Instant::now();
            let parser = build_parser()?;
            drop(recovery_permit);
            (
                parser,
                recovery_permit_wait_ms,
                build_started.elapsed().as_millis(),
            )
        } else {
            // Do not acquire a recovery permit in temporary live-only mode.
            // `build_recovery_ms` is zero so reports cannot imply that a
            // recovery phase ran.
            (build_parser()?, 0, 0)
        };

    let iteration_started = std::time::Instant::now();
    let mut recovered_row_count = 0usize;
    let mut writer = StreamWriter::create(out, REG_TABLE, REG_FIELD_ORDER, REG_FIELD_ORDER)?;
    for key in ParserIterator::new(&parser) {
        if crate::pipeline::cancelled() {
            break;
        }
        let last_write = fmt_kst(key.last_key_written_date_and_time());
        let path = key.path.clone();
        // Buffer one key to attach its final readable-value count to every row.
        let mut value_rows: Vec<Row> = Vec::new();
        for value in key.value_iter() {
            let (cv, content_logs) = value.get_content();
            let name = value.get_pretty_name();
            let name = if name.is_empty() {
                "(default)".to_string()
            } else {
                clean_str(&name)
            };
            let mut row = Row::new();
            row.insert("last_write".into(), last_write.clone());
            row.insert("key_path".into(), path.clone());
            row.insert("value_name".into(), name);
            row.insert("value_type".into(), type_name(&value));
            row.insert("value_data".into(), render_value(&cv));
            let recovery = if recovery_plan.recover_deleted_cells {
                recovery_label(&key, Some(&value))
            } else {
                "live".to_string()
            };
            if recovery != "live" {
                recovered_row_count += 1;
            }
            row.insert("_recovery".into(), recovery);
            row.insert("_source_file".into(), source.clone());
            row.insert("entry_kind".into(), ENTRY_KIND_VALUE.into());
            value_facts(&value, &cv, content_logs.as_ref()).insert_into(&mut row);
            value_rows.push(row);
        }
        let facts = key_facts(&key, value_rows.len());
        if value_rows.is_empty() {
            let mut row = Row::new();
            row.insert("last_write".into(), last_write);
            row.insert("key_path".into(), path);
            row.insert("value_name".into(), String::new());
            row.insert("value_type".into(), String::new());
            row.insert("value_data".into(), String::new());
            let recovery = if recovery_plan.recover_deleted_cells {
                recovery_label(&key, None)
            } else {
                "live".to_string()
            };
            if recovery != "live" {
                recovered_row_count += 1;
            }
            row.insert("_recovery".into(), recovery);
            row.insert("_source_file".into(), source.clone());
            row.insert("entry_kind".into(), ENTRY_KIND_KEY.into());
            blank_value_facts(&mut row);
            facts.insert_into(&mut row);
            writer.push(row)?;
        } else {
            for mut row in value_rows {
                facts.insert_into(&mut row);
                writer.push(row)?;
            }
        }
    }
    let row_count = writer.finish()?;
    Ok(HiveParseMetrics {
        row_count,
        recovery_logs_discovered,
        recovery_log_count,
        recovery_enabled: recovery_plan.recover_deleted_cells,
        recovered_row_count,
        recovery_permit_wait_ms,
        build_recovery_ms,
        iteration_and_sqlite_write_ms: iteration_started.elapsed().as_millis(),
        recovery_log_apply_error,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        output_base_name, registry_recovery_plan, registry_recovery_worker_count,
        transaction_logs_to_apply, TEMPORARILY_DISABLE_RECOVERY,
    };
    use std::path::{Path, PathBuf};

    /// 사용자 하이브는 계정 접두로 발행되어야 한다 — 계정마다 같은 파일명이
    /// 오므로 접두가 없으면 산출물이 서로를 덮어쓰고, 파생 계층도 계정을
    /// 복원하지 못한다. 케이스 편차(ntuser.dat)도 정규 표기로 모인다.
    #[test]
    fn user_hives_are_published_with_their_account_prefix() {
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/Administrator/NTUSER.DAT")),
            "Administrator_NTUSER.DAT"
        );
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/svcuser/NTUSER.DAT")),
            "svcuser_NTUSER.DAT"
        );
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/config/systemprofile/ntuser.dat")),
            "systemprofile_NTUSER.DAT"
        );
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/Administrator/UsrClass.dat")),
            "Administrator_UsrClass.dat"
        );
    }

    /// 원본 디스크 배치(UsrClass.dat이 AppData 아래 깊이 놓임)에서도 계정은
    /// AppData 바로 앞 컴포넌트로 복원된다.
    #[test]
    fn usrclass_account_comes_from_the_profile_above_appdata() {
        assert_eq!(
            output_base_name(Path::new(
                "/img/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat"
            )),
            "Administrator_UsrClass.dat"
        );
    }

    /// 계정은 경로 구조가 뒷받침할 때만 부여한다 — 임의 수집 폴더를 계정으로
    /// 쓰면 원본에 없는 사용자가 UserAssist·Shellbag·자동 실행의 소유자로
    /// 표시되고, 반대로 실제 계정 이름이 흔한 단어라고 버리면 계정 귀속을 잃는다.
    #[test]
    fn hive_account_requires_structural_evidence() {
        // 계정 근거 없음 — 평면 수집본과 지원하지 않는 임의 수집 폴더.
        for path in [
            "/e/REGISTRY/NTUSER.DAT",
            "/e/REGISTRY/UsrClass.dat",
            "/e/registry/ntuser.dat",
            "/e/Collected/NTUSER.DAT",
            "/e/EvidenceExport/NTUSER.DAT",
            "/e/Collection_2026/NTUSER.DAT",
            "/img/Users/NTUSER.DAT",
        ] {
            let name = output_base_name(Path::new(path));
            assert!(
                name == "NTUSER.DAT" || name == "UsrClass.dat",
                "{path} → {name}: 계정 근거가 없는데 접두가 붙었다"
            );
        }

        // 계정 컨테이너 바로 아래 디렉터리는 계정이다 — 이름이 흔한 단어여도
        // 구조가 계정임을 보증하므로 버리지 않는다.
        for (path, expected) in [
            ("/e/REGISTRY/Administrator/NTUSER.DAT", "Administrator_NTUSER.DAT"),
            ("/e/REGISTRY/svcuser/NTUSER.DAT", "svcuser_NTUSER.DAT"),
            ("/e/REGISTRY/Windows/NTUSER.DAT", "Windows_NTUSER.DAT"),
            ("/e/REGISTRY/config/systemprofile/ntuser.dat", "systemprofile_NTUSER.DAT"),
            ("/e/REGISTRY/Administrator/UsrClass.dat", "Administrator_UsrClass.dat"),
            ("/img/Users/Administrator/NTUSER.DAT", "Administrator_NTUSER.DAT"),
            (
                "/img/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat",
                "Administrator_UsrClass.dat",
            ),
        ] {
            assert_eq!(output_base_name(Path::new(path)), expected, "path={path}");
        }
    }

    /// 머신 하이브는 파생이 이름을 그대로 조회하므로 접두를 붙이지 않는다.    /// 머신 하이브는 파생이 이름을 그대로 조회하므로 접두를 붙이지 않는다.
    /// 수집기가 이미 접두를 붙여 둔 사용자 하이브 이름도 보존한다.
    #[test]
    fn machine_hives_and_prefixed_names_keep_their_own_name() {
        assert_eq!(output_base_name(Path::new("/e/REGISTRY/config/SYSTEM")), "SYSTEM");
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/config/RegBack/SOFTWARE")),
            "SOFTWARE"
        );
        assert_eq!(
            output_base_name(Path::new("/e/REGISTRY/flat/analyst_NTUSER.DAT")),
            "analyst_NTUSER.DAT"
        );
    }

    #[test]
    fn recovery_workers_are_bounded_and_skip_empty_jobs() {
        assert_eq!(registry_recovery_worker_count(0), 0);
        assert_eq!(registry_recovery_worker_count(1), 1);
        #[cfg(unix)]
        assert_eq!(registry_recovery_worker_count(20), 2);
        #[cfg(not(unix))]
        assert_eq!(registry_recovery_worker_count(20), 1);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn transaction_logs_are_applied_while_deleted_cell_recovery_stays_off() {
        let plan = registry_recovery_plan();
        let discovered_logs = vec![PathBuf::from("SYSTEM.LOG1"), PathBuf::from("SYSTEM.LOG2")];
        assert!(TEMPORARILY_DISABLE_RECOVERY);
        assert!(!plan.recover_deleted_cells);
        assert!(plan.apply_transaction_logs);
        assert_eq!(
            transaction_logs_to_apply(&discovered_logs, plan),
            discovered_logs.as_slice()
        );
    }

    // Real REGF fixture using notatin 1.0.1 base/nk/vk/li cell layouts.

    use crate::hex::hex_lower;
    use crate::parsers::registry::{
        classify_value_read, key_read_shortfalls, parse_hive_stream_with_metrics, ValueReadState,
        HIVE_BIN_DATA_OFFSET,
    };
    use rusqlite::Connection;
    use std::collections::BTreeMap;

    const EXPECTED_COLUMNS: &[&str] = &[
        "last_write",
        "key_path",
        "value_name",
        "value_type",
        "value_data",
        "_recovery",
        "_source_file",
        "entry_kind",
        "key_offset",
        "parent_key_offset",
        "key_name",
        "key_subkey_count",
        "key_value_count",
        "key_read_status",
        "key_read_error",
        "value_offset",
        "value_name_raw",
        "value_type_code",
        "value_data_hex",
        "value_data_text",
        "value_read_status",
        "value_read_error",
    ];

    const FIXTURE_FILETIME: u64 = 130_000_000_000_000_000;

    // Cell offsets are relative to the first hive bin.
    struct HiveBuilder {
        bin: Vec<u8>,
    }

    impl HiveBuilder {
        fn new() -> Self {
            let mut bin = Vec::new();
            bin.extend_from_slice(b"hbin");
            bin.extend_from_slice(&0u32.to_le_bytes()); // offset_from_first_hbin
            bin.extend_from_slice(&0u32.to_le_bytes()); // Filled by finish.
            bin.extend_from_slice(&0u32.to_le_bytes()); // unknown1
            bin.extend_from_slice(&0u32.to_le_bytes()); // unknown2
            bin.extend_from_slice(&FIXTURE_FILETIME.to_le_bytes()); // timestamp
            bin.extend_from_slice(&0u32.to_le_bytes()); // spare
            Self { bin }
        }

        // Allocated cells use negative sizes and eight-byte alignment.
        fn cell(&mut self, body: &[u8]) -> u32 {
            let offset = self.bin.len() as u32;
            let size = (4 + body.len()).next_multiple_of(8);
            self.bin.extend_from_slice(&(-(size as i32)).to_le_bytes());
            self.bin.extend_from_slice(body);
            self.bin.resize(offset as usize + size, 0);
            offset
        }

        fn value_list(&mut self, value_offsets: &[u32]) -> u32 {
            let mut body = Vec::new();
            for offset in value_offsets {
                body.extend_from_slice(&offset.to_le_bytes());
            }
            self.cell(&body)
        }

        fn subkey_list(&mut self, key_offsets: &[u32]) -> u32 {
            let mut body = Vec::new();
            body.extend_from_slice(b"li");
            body.extend_from_slice(&(key_offsets.len() as u16).to_le_bytes());
            for offset in key_offsets {
                body.extend_from_slice(&offset.to_le_bytes());
            }
            self.cell(&body)
        }

        // Parents precede children; patch the subkey list afterward.
        fn patch_subkey_list(&mut self, key_offset: u32, list_offset: u32) {
            let at = key_offset as usize + 32;
            self.bin[at..at + 4].copy_from_slice(&list_offset.to_le_bytes());
        }

        fn finish(mut self) -> Vec<u8> {
            let bin_size = self.bin.len().next_multiple_of(4096);
            self.bin.resize(bin_size, 0);
            self.bin[8..12].copy_from_slice(&(bin_size as u32).to_le_bytes());

            let mut out = vec![0u8; HIVE_BIN_DATA_OFFSET];
            out[0..4].copy_from_slice(b"regf");
            out[4..8].copy_from_slice(&1u32.to_le_bytes()); // primary sequence
            out[8..12].copy_from_slice(&1u32.to_le_bytes()); // secondary sequence
            out[12..20].copy_from_slice(&FIXTURE_FILETIME.to_le_bytes());
            out[20..24].copy_from_slice(&1u32.to_le_bytes()); // major version
            out[24..28].copy_from_slice(&3u32.to_le_bytes()); // minor version
            out[28..32].copy_from_slice(&0u32.to_le_bytes()); // FileType::Primary
            out[32..36].copy_from_slice(&1u32.to_le_bytes()); // DirectMemoryLoad
            out[36..40].copy_from_slice(&32i32.to_le_bytes()); // First cell is root.
            out[40..44].copy_from_slice(&(bin_size as u32).to_le_bytes());
            out[44..48].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
            let name: Vec<u8> = "FIXTURE"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            out[48..48 + name.len()].copy_from_slice(&name);
            let mut checksum = 0u32;
            for chunk in out[..508].chunks_exact(4) {
                checksum ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            let checksum = match checksum {
                0 => 1,
                0xFFFF_FFFF => 0xFFFF_FFFE,
                other => other,
            };
            out[508..512].copy_from_slice(&checksum.to_le_bytes());
            out.extend_from_slice(&self.bin);
            out
        }
    }

    struct KeyCell<'a> {
        flags: u16,
        parent_relative: i32,
        subkey_count: u32,
        value_count: u32,
        value_list_relative: i32,
        name: &'a str,
    }

    impl KeyCell<'_> {
        fn body(&self) -> Vec<u8> {
            let name = self.name.as_bytes();
            let mut body = Vec::new();
            body.extend_from_slice(b"nk");
            body.extend_from_slice(&self.flags.to_le_bytes());
            body.extend_from_slice(&FIXTURE_FILETIME.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // access flags
            body.extend_from_slice(&self.parent_relative.to_le_bytes());
            body.extend_from_slice(&self.subkey_count.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // volatile subkey count
            body.extend_from_slice(&0u32.to_le_bytes()); // subkey list(patch)
            body.extend_from_slice(&(-1i32).to_le_bytes()); // volatile subkey list
            body.extend_from_slice(&self.value_count.to_le_bytes());
            body.extend_from_slice(&self.value_list_relative.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes()); // security key
            body.extend_from_slice(&(-1i32).to_le_bytes()); // class name
            for _ in 0..5 {
                // largest_sub_key_name/class, largest_value_name/data, work_var
                body.extend_from_slice(&0u32.to_le_bytes());
            }
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes()); // class name size
            body.extend_from_slice(name);
            body
        }
    }

    struct ValueCell<'a> {
        name: &'a str,
        data_size_raw: u32,
        data_offset_relative: u32,
        data_type_raw: u32,
    }

    impl ValueCell<'_> {
        fn body(&self) -> Vec<u8> {
            let name = self.name.as_bytes();
            let mut body = Vec::new();
            body.extend_from_slice(b"vk");
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&self.data_size_raw.to_le_bytes());
            body.extend_from_slice(&self.data_offset_relative.to_le_bytes());
            body.extend_from_slice(&self.data_type_raw.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes()); // VALUE_COMP_NAME_ASCII
            body.extend_from_slice(&0u16.to_le_bytes()); // padding
            body.extend_from_slice(name);
            body
        }
    }

    fn utf16_sz(s: &str) -> Vec<u8> {
        let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    fn utf16_multi(items: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for item in items {
            bytes.extend_from_slice(&utf16_sz(item));
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    fn long_blob() -> Vec<u8> {
        (0..600u32).map(|i| (i % 251) as u8).collect()
    }

    struct FixtureKeys {
        root: usize,
        soft: usize,
        empty: usize,
        odd: usize,
        truncated: usize,
    }

    // Root, populated keys, an empty leaf, and a partially readable key.
    fn fixture_hive() -> (Vec<u8>, FixtureKeys) {
        let mut builder = HiveBuilder::new();

        // notatin reads the first cell as the root.
        let root = builder.cell(
            &KeyCell {
                flags: 0x0024, // KEY_HIVE_ENTRY | KEY_COMP_NAME
                parent_relative: -1,
                subkey_count: 3,
                value_count: 0,
                value_list_relative: -1,
                name: "ROOT",
            }
            .body(),
        );

        let data_default = builder.cell(&utf16_sz("Default"));
        let data_literal = builder.cell(&utf16_sz("literal name"));
        let data_str = builder.cell(&utf16_sz("hello"));
        let data_multi = builder.cell(&utf16_multi(&["a", "b"]));
        let data_long = builder.cell(&long_blob());
        let data_blob = builder.cell(&[0x00, 0x01, 0xff, 0x80, 0x0a]);
        let data_rid = builder.cell(&[0xf4, 0x01, 0x00, 0x00]);
        let data_none = builder.cell(&[]);
        // Embedded NUL leaves an uninterpreted tail.
        let data_embedded_nul = builder.cell(&[0x61, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00]);
        // notatin resolves only four bytes of this oversized DWORD.
        let data_wide_dword = builder.cell(&[0x2a, 0x00, 0x00, 0x00, 0x99, 0x99, 0x99, 0x99]);

        let value_default = builder.cell(
            &ValueCell {
                name: "",
                data_size_raw: utf16_sz("Default").len() as u32,
                data_offset_relative: data_default,
                data_type_raw: 1, // REG_SZ
            }
            .body(),
        );
        let value_literal = builder.cell(
            &ValueCell {
                name: "(default)",
                data_size_raw: utf16_sz("literal name").len() as u32,
                data_offset_relative: data_literal,
                data_type_raw: 1,
            }
            .body(),
        );
        let value_str = builder.cell(
            &ValueCell {
                name: "Str",
                data_size_raw: utf16_sz("hello").len() as u32,
                data_offset_relative: data_str,
                data_type_raw: 1,
            }
            .body(),
        );
        let value_dword = builder.cell(
            &ValueCell {
                name: "Dword",
                data_size_raw: 0x8000_0004, // Resident payload.
                data_offset_relative: 42,
                data_type_raw: 4, // REG_DWORD
            }
            .body(),
        );
        let value_multi = builder.cell(
            &ValueCell {
                name: "Multi",
                data_size_raw: utf16_multi(&["a", "b"]).len() as u32,
                data_offset_relative: data_multi,
                data_type_raw: 7, // REG_MULTI_SZ
            }
            .body(),
        );
        let value_empty = builder.cell(
            &ValueCell {
                name: "NoData",
                data_size_raw: 0,
                data_offset_relative: data_none,
                data_type_raw: 0, // REG_NONE
            }
            .body(),
        );
        let value_long = builder.cell(
            &ValueCell {
                name: "Long",
                data_size_raw: long_blob().len() as u32,
                data_offset_relative: data_long,
                data_type_raw: 3, // REG_BINARY
            }
            .body(),
        );
        let value_embedded_nul = builder.cell(
            &ValueCell {
                name: "EmbeddedNul",
                data_size_raw: 8,
                data_offset_relative: data_embedded_nul,
                data_type_raw: 1, // REG_SZ
            }
            .body(),
        );
        let value_wide_dword = builder.cell(
            &ValueCell {
                name: "WideDword",
                data_size_raw: 8,
                data_offset_relative: data_wide_dword,
                data_type_raw: 4, // REG_DWORD
            }
            .body(),
        );
        let value_rid = builder.cell(
            &ValueCell {
                name: "Rid",
                data_size_raw: 4,
                data_offset_relative: data_rid,
                data_type_raw: 500, // SAM RID.
            }
            .body(),
        );
        let value_blob = builder.cell(
            &ValueCell {
                name: "Blob",
                data_size_raw: 5,
                data_offset_relative: data_blob,
                data_type_raw: 3, // REG_BINARY
            }
            .body(),
        );
        let value_unreadable = builder.cell(
            &ValueCell {
                name: "Bad",
                data_size_raw: 16,
                data_offset_relative: 0x0fff_fff0, // Out of bounds.
                data_type_raw: 1,
            }
            .body(),
        );

        let soft_values = builder.value_list(&[
            value_default,
            value_literal,
            value_str,
            value_dword,
            value_multi,
            value_empty,
            value_long,
            value_embedded_nul,
            value_wide_dword,
        ]);
        let odd_values = builder.value_list(&[value_rid, value_blob, value_unreadable]);
        // Two declared values cannot be read.
        let truncated_values = builder.value_list(&[value_blob, 0x0fff_fff0, 0x0fff_fff4]);

        let soft = builder.cell(
            &KeyCell {
                flags: 0x0020, // KEY_COMP_NAME
                parent_relative: root as i32,
                subkey_count: 1,
                value_count: 9,
                value_list_relative: soft_values as i32,
                name: "Soft",
            }
            .body(),
        );
        let empty = builder.cell(
            &KeyCell {
                flags: 0x0020,
                parent_relative: soft as i32,
                subkey_count: 0,
                value_count: 0,
                value_list_relative: -1,
                name: "Empty",
            }
            .body(),
        );
        let odd = builder.cell(
            &KeyCell {
                flags: 0x0020,
                parent_relative: root as i32,
                subkey_count: 0,
                value_count: 3,
                value_list_relative: odd_values as i32,
                name: "Odd",
            }
            .body(),
        );
        let truncated = builder.cell(
            &KeyCell {
                flags: 0x0020,
                parent_relative: root as i32,
                subkey_count: 0,
                value_count: 3,
                value_list_relative: truncated_values as i32,
                name: "Truncated",
            }
            .body(),
        );

        let root_children = builder.subkey_list(&[soft, odd, truncated]);
        let soft_children = builder.subkey_list(&[empty]);
        builder.patch_subkey_list(root, root_children);
        builder.patch_subkey_list(soft, soft_children);

        let offsets = FixtureKeys {
            root: HIVE_BIN_DATA_OFFSET + root as usize,
            soft: HIVE_BIN_DATA_OFFSET + soft as usize,
            empty: HIVE_BIN_DATA_OFFSET + empty as usize,
            odd: HIVE_BIN_DATA_OFFSET + odd as usize,
            truncated: HIVE_BIN_DATA_OFFSET + truncated as usize,
        };
        (builder.finish(), offsets)
    }

    fn registry_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-registry-{label}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Parse real bytes; expose unexpected SQL NULLs explicitly.
    fn parse_fixture(label: &str) -> (Vec<String>, Vec<BTreeMap<String, String>>, FixtureKeys) {
        let dir = registry_temp_dir(label);
        let (bytes, offsets) = fixture_hive();
        let hive = dir.join("SYSTEM");
        std::fs::write(&hive, bytes).unwrap();
        let out = dir.join("SYSTEM.sqlite");
        let metrics = parse_hive_stream_with_metrics(&hive, &[], &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let columns: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('Registry')")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let select = format!(
            "SELECT {} FROM Registry ORDER BY rowid",
            columns
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut stmt = conn.prepare(&select).unwrap();
        let rows: Vec<BTreeMap<String, String>> = stmt
            .query_map([], |r| {
                let mut row = BTreeMap::new();
                for (i, column) in columns.iter().enumerate() {
                    let value: Option<String> = r.get(i)?;
                    row.insert(column.clone(), value.unwrap_or_else(|| "<NULL>".into()));
                }
                Ok(row)
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(metrics.row_count, rows.len());
        (columns, rows, offsets)
    }

    // Raw names distinguish the default value from literal "(default)".
    fn value_row<'a>(
        rows: &'a [BTreeMap<String, String>],
        key_path: &str,
        value_name_raw: &str,
    ) -> &'a BTreeMap<String, String> {
        let found: Vec<_> = rows
            .iter()
            .filter(|r| {
                r["entry_kind"] == "value"
                    && r["key_path"] == key_path
                    && r["value_name_raw"] == value_name_raw
            })
            .collect();
        assert_eq!(found.len(), 1, "{key_path} / {value_name_raw:?} 행이 1개여야 한다");
        found[0]
    }

    fn key_row<'a>(
        rows: &'a [BTreeMap<String, String>],
        key_path: &str,
    ) -> &'a BTreeMap<String, String> {
        rows.iter()
            .find(|r| r["entry_kind"] == "key" && r["key_path"] == key_path)
            .unwrap_or_else(|| panic!("빈 키 행을 찾지 못했다: {key_path}"))
    }

    #[test]
    fn appended_facts_keep_the_legacy_columns_rows_and_values() {
        let (columns, rows, _) = parse_fixture("legacy");
        assert_eq!(columns.as_slice(), EXPECTED_COLUMNS);

        assert_eq!(rows.len(), 15);
        assert_eq!(rows.iter().filter(|r| r["entry_kind"] == "key").count(), 2);

        // Legacy display names collide; the records must not.
        let legacy_default_named: Vec<_> = rows
            .iter()
            .filter(|r| r["key_path"] == "\\ROOT\\Soft" && r["value_name"] == "(default)")
            .collect();
        assert_eq!(legacy_default_named.len(), 2);

        let default_value = value_row(&rows, "\\ROOT\\Soft", "");
        assert_eq!(default_value["value_name"], "(default)");
        assert_eq!(default_value["value_type"], "REG_SZ");
        assert_eq!(default_value["value_data"], "Default");
        let literal = value_row(&rows, "\\ROOT\\Soft", "(default)");
        assert_eq!(literal["value_name"], "(default)");
        assert_eq!(literal["value_data"], "literal name");
        assert_eq!(value_row(&rows, "\\ROOT\\Soft", "Str")["value_data"], "hello");
        assert_eq!(value_row(&rows, "\\ROOT\\Soft", "Dword")["value_data"], "42");
        assert_eq!(
            value_row(&rows, "\\ROOT\\Soft", "Multi")["value_data"],
            "[\"a\", \"b\"]"
        );
        assert_eq!(
            value_row(&rows, "\\ROOT\\Soft", "Long")["value_data"],
            hex_lower(&long_blob())
        );
        assert_eq!(
            value_row(&rows, "\\ROOT\\Odd", "Blob")["value_data"],
            "0001ff800a"
        );
        assert_eq!(value_row(&rows, "\\ROOT\\Odd", "Rid")["value_type"], "500");

        let empty_key = key_row(&rows, "\\ROOT\\Soft\\Empty");
        assert_eq!(empty_key["value_name"], "");
        assert_eq!(empty_key["value_type"], "");
        assert_eq!(empty_key["value_data"], "");
        for row in &rows {
            assert_eq!(row["_recovery"], "live");
            assert!(row["_source_file"].ends_with("SYSTEM"));
            assert!(!row["last_write"].is_empty());
            for column in EXPECTED_COLUMNS {
                assert_ne!(row[*column], "<NULL>", "{column}이 NULL로 저장됐다");
            }
        }
    }

    #[test]
    fn every_key_carries_its_offset_parent_and_expected_counts() {
        let (_, rows, offsets) = parse_fixture("tree");

        let mut keys: BTreeMap<String, String> = BTreeMap::new();
        for row in &rows {
            assert!(!row["key_offset"].is_empty(), "값 행에도 키 좌표가 있어야 한다");
            keys.insert(row["key_offset"].clone(), row["key_path"].clone());
        }
        assert_eq!(keys.len(), 5, "키 5개가 모두 좌표로 드러나야 한다");

        let root = key_row(&rows, "\\ROOT");
        assert_eq!(root["key_offset"], offsets.root.to_string());
        assert_eq!(root["parent_key_offset"], "", "루트만 부모가 비어야 한다");
        assert_eq!(root["key_name"], "ROOT");
        assert_eq!(root["key_subkey_count"], "3");
        assert_eq!(root["key_value_count"], "0");
        assert_eq!(root["key_read_status"], "ok");
        assert_eq!(root["key_read_error"], "");
        assert_eq!(
            rows.iter()
                .filter(|r| r["parent_key_offset"].is_empty())
                .count(),
            1
        );

        let soft = value_row(&rows, "\\ROOT\\Soft", "Str");
        assert_eq!(soft["entry_kind"], "value");
        assert_eq!(soft["key_offset"], offsets.soft.to_string());
        assert_eq!(soft["parent_key_offset"], offsets.root.to_string());
        assert_eq!(soft["key_name"], "Soft");
        assert_eq!(soft["key_subkey_count"], "1");
        assert_eq!(soft["key_value_count"], "9");
        assert_eq!(soft["key_read_status"], "ok");

        let empty = key_row(&rows, "\\ROOT\\Soft\\Empty");
        assert_eq!(empty["key_offset"], offsets.empty.to_string());
        assert_eq!(empty["parent_key_offset"], offsets.soft.to_string());
        assert_eq!(empty["key_subkey_count"], "0");
        assert_eq!(empty["key_value_count"], "0");
        for column in [
            "value_offset",
            "value_name_raw",
            "value_type_code",
            "value_data_hex",
            "value_data_text",
            "value_read_status",
            "value_read_error",
        ] {
            assert_eq!(empty[column], "", "{column}이 키 행에서 채워졌다");
        }

        assert_eq!(
            value_row(&rows, "\\ROOT\\Odd", "Rid")["parent_key_offset"],
            offsets.root.to_string()
        );
        assert_eq!(
            value_row(&rows, "\\ROOT\\Truncated", "Blob")["key_offset"],
            offsets.truncated.to_string()
        );
        let blob_in_odd = value_row(&rows, "\\ROOT\\Odd", "Blob");
        let blob_in_truncated = value_row(&rows, "\\ROOT\\Truncated", "Blob");
        assert_ne!(blob_in_odd["value_offset"], blob_in_odd["key_offset"]);
        assert_eq!(
            blob_in_odd["value_offset"], blob_in_truncated["value_offset"],
            "같은 vk 셀을 가리키는 두 키는 같은 값 좌표를 보고해야 한다"
        );
    }

    #[test]
    fn value_payload_states_distinguish_empty_missing_and_unreadable() {
        let (_, rows, _) = parse_fixture("payload");

        let default_value = value_row(&rows, "\\ROOT\\Soft", "");
        assert_eq!(default_value["value_type_code"], "1");
        assert_eq!(
            default_value["value_data_hex"],
            hex_lower(&utf16_sz("Default")),
            "NUL 종단까지 포함한 원문 바이트가 남아야 한다"
        );
        assert_eq!(default_value["value_data_text"], "Default");
        assert_eq!(default_value["value_read_status"], "ok");
        assert_eq!(default_value["value_read_error"], "");
        assert!(!default_value["value_offset"].is_empty());

        let dword = value_row(&rows, "\\ROOT\\Soft", "Dword");
        assert_eq!(dword["value_type_code"], "4");
        assert_eq!(dword["value_data_hex"], "2a000000");
        assert_eq!(dword["value_data_text"], "42");
        assert_eq!(dword["value_read_status"], "ok");

        let multi = value_row(&rows, "\\ROOT\\Soft", "Multi");
        assert_eq!(multi["value_type_code"], "7");
        assert_eq!(multi["value_data_hex"], hex_lower(&utf16_multi(&["a", "b"])));
        assert_eq!(multi["value_data_text"], "[\"a\", \"b\"]");
        assert_eq!(multi["value_read_status"], "ok");

        let long = value_row(&rows, "\\ROOT\\Soft", "Long");
        assert_eq!(long["value_data_hex"], hex_lower(&long_blob()));
        assert_eq!(long["value_read_status"], "ok");

        // Preserve the full payload and mark partial interpretation.
        let embedded = value_row(&rows, "\\ROOT\\Soft", "EmbeddedNul");
        assert_eq!(embedded["value_data_hex"], "6100000062000000");
        assert_eq!(embedded["value_data_text"], "a");
        assert_eq!(embedded["value_read_status"], "partial");

        // The unavailable oversized tail must not be invented.
        let wide = value_row(&rows, "\\ROOT\\Soft", "WideDword");
        assert_eq!(wide["value_data_hex"], "2a000000");
        assert_eq!(wide["value_data_text"], "42");
        assert_eq!(wide["value_read_status"], "partial");
        assert!(
            wide["value_read_error"].contains('8') && wide["value_read_error"].contains('4'),
            "선언/보존 바이트 수가 남아야 한다: {}",
            wide["value_read_error"]
        );

        let empty_payload = value_row(&rows, "\\ROOT\\Soft", "NoData");
        assert_eq!(empty_payload["value_type_code"], "0");
        assert_eq!(empty_payload["value_data_hex"], "");
        assert_eq!(empty_payload["value_data_text"], "");
        assert_eq!(empty_payload["value_read_status"], "empty");

        let rid = value_row(&rows, "\\ROOT\\Odd", "Rid");
        assert_eq!(rid["value_type_code"], "500");
        assert_eq!(rid["value_data_hex"], "f4010000");
        assert_eq!(rid["value_data_text"], "");
        assert_eq!(rid["value_read_status"], "ok");

        let blob = value_row(&rows, "\\ROOT\\Odd", "Blob");
        assert_eq!(blob["value_data_hex"], "0001ff800a");
        assert_eq!(blob["value_data_text"], "");
        assert_eq!(blob["value_read_status"], "ok");

        let unreadable = value_row(&rows, "\\ROOT\\Odd", "Bad");
        assert_eq!(unreadable["value_data_hex"], "");
        assert_eq!(unreadable["value_read_status"], "error");
        assert!(
            !unreadable["value_read_error"].is_empty(),
            "읽기 실패 사유가 남아야 한다"
        );
    }

    #[test]
    fn key_read_status_reports_values_that_could_not_be_read() {
        let (_, rows, _) = parse_fixture("partial");
        let truncated: Vec<_> = rows
            .iter()
            .filter(|r| r["key_path"] == "\\ROOT\\Truncated")
            .collect();
        assert_eq!(truncated.len(), 1, "읽힌 값만 행이 된다");
        let row = truncated[0];
        assert_eq!(row["key_value_count"], "3");
        assert_eq!(row["key_read_status"], "partial");
        assert!(
            row["key_read_error"].contains('3'),
            "선언/실제 개수가 사유에 남아야 한다: {}",
            row["key_read_error"]
        );
        assert_eq!(
            value_row(&rows, "\\ROOT\\Odd", "Blob")["key_read_status"],
            "ok"
        );
    }

    #[test]
    fn value_read_state_boundaries() {
        assert_eq!(
            classify_value_read(None, 16, false, false),
            ValueReadState::Error
        );
        assert_eq!(
            classify_value_read(Some(4), 4, true, false),
            ValueReadState::Error
        );
        assert_eq!(
            classify_value_read(Some(0), 0, false, false),
            ValueReadState::Empty
        );
        assert_eq!(
            classify_value_read(Some(0), 8, false, true),
            ValueReadState::Error
        );
        assert_eq!(
            classify_value_read(Some(4), 8, false, false),
            ValueReadState::Partial
        );
        assert_eq!(
            classify_value_read(Some(8), 8, false, true),
            ValueReadState::Partial
        );
        assert_eq!(
            classify_value_read(Some(8), 8, false, false),
            ValueReadState::Ok
        );
    }

    #[test]
    fn key_read_shortfalls_only_report_missing_reads() {
        assert!(key_read_shortfalls(5, 5, 1, 1, false).is_empty());
        assert!(key_read_shortfalls(5, 7, 1, 1, false).is_empty());
        assert!(key_read_shortfalls(3, 1, 0, 0, false)[0].contains('3'));
        assert!(key_read_shortfalls(2, 2, 4, 2, false)[0].contains('4'));
        assert!(key_read_shortfalls(500, 0, 0, 0, true).is_empty());
    }
}
