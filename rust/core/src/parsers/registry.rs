//! Registry hive parser. Produces the uniform dump schema
//! last_write | key_path | value_name | value_type | value_data.
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use notatin::cell_key_value::CellKeyValue;
use notatin::cell_value::CellValue;
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
    "last_write",
    "key_path",
    "value_name",
    "value_type",
    "value_data",
    "_recovery",
    "_source_file",
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
        let mut had_value = false;
        for value in key.value_iter() {
            had_value = true;
            let (cv, _logs) = value.get_content();
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
            writer.push(row)?;
        }
        if !had_value {
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
            writer.push(row)?;
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
}
