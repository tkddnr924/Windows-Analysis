//! Amcache.hve parser. Amcache is a registry hive, so it reuses notatin.
//! Emits Amcache_Programs (Root\InventoryApplication / legacy Root\Programs)
//! and Amcache_Files (Root\InventoryApplicationFile / legacy Root\File).
//! Files use the same snake_case column names + sha1/file_id handling as the
//! Python parser (regipy's AmCachePlugin) so it feeds the execution-history
//! overview identically.
use std::path::{Path, PathBuf};

use anyhow::Result;
use notatin::cell_value::CellValue;
use notatin::parser::ParserIterator;
use notatin::parser_builder::ParserBuilder;

use crate::hex::hex_lower;
use crate::sqlite::Row;
use crate::time::{fmt_filetime, fmt_kst};

pub const PROGRAMS_TABLE: &str = "Amcache_Programs";
pub const FILES_TABLE: &str = "Amcache_Files";
pub const PROGRAMS_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "InstallDate",
    "MsiInstallDate",
    "Name",
    "Version",
    "Publisher",
    "ProgramId",
    "ProgramInstanceId",
    "Source",
    "RootDirPath",
    "UninstallString",
    "_recovery",
    "_source_file",
];
pub const FILES_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "link_date",
    "name",
    "lower_case_long_path",
    "original_file_name",
    "publisher",
    "product_name",
    "version",
    "product_version",
    "bin_file_version",
    "bin_product_version",
    "size",
    "SHA1",
    "program_id",
    "file_id",
    "binary_type",
    "language",
    "_recovery",
    "_source_file",
];

// Legacy (Win7/2008R2) \Root\File numeric value-name mapping — value names
// are hex ids. Mapped to the modern snake_case columns so the execution
// history overview and views read legacy rows identically.
fn map_legacy_file(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    match lowered.as_str() {
        "0" => "product_name",
        "1" => "publisher",
        "2" => "file_version_number",
        "3" => "language",
        "5" => "version",
        "6" => "size",
        "c" => "file_description",
        "11" => "last_modified",
        "12" => "created",
        "15" => "full_path",
        "17" => "last_modified_2",
        "100" => "program_id",
        "101" => "file_id",
        _ => return lowered,
    }
    .to_string()
}

/// FILETIME 정수 문자열이면 KST 표기로 바꾼다 (구형 File 항목 11/12/17).
fn legacy_filetime(value: &str) -> Option<String> {
    let ticks: i64 = value.trim().parse().ok()?;
    if ticks <= 0 {
        return None;
    }
    let formatted = fmt_filetime(ticks);
    if formatted.is_empty() { None } else { Some(formatted) }
}

// Legacy Win8 \Root\Programs numeric value-name mapping (high-confidence subset).
fn map_legacy_program(name: &str) -> &str {
    match name {
        "0" => "Name",
        "1" => "Version",
        "2" => "Publisher",
        "3" => "Language",
        other => other,
    }
}

fn render(cv: &CellValue) -> String {
    match cv {
        CellValue::String(s) => s.trim_end_matches('\u{0}').to_string(),
        CellValue::Binary(b) => hex_lower(b),
        CellValue::MultiString(v) => v.join(","),
        CellValue::U32(v) => v.to_string(),
        CellValue::I32(v) => v.to_string(),
        CellValue::U64(v) => v.to_string(),
        CellValue::I64(v) => v.to_string(),
        _ => String::new(),
    }
}

/// inflection.underscore — CamelCase -> snake_case (matches regipy's plugin).
fn underscore(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::new();
    for i in 0..ch.len() {
        let c = ch[i];
        if i > 0 && c.is_ascii_uppercase() {
            let prev = ch[i - 1];
            let next_lower = ch.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            if prev.is_ascii_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_ascii_uppercase() && next_lower)
            {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out.replace('-', "_")
}

/// Path segments after the hive's "\...\Root\" prefix, or None.
fn after_root(path: &str) -> Option<Vec<&str>> {
    let low = path.to_ascii_lowercase();
    let idx = low.find("\\root\\")?;
    Some(path[idx + 6..].split('\\').collect())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AmcacheKeyKind {
    ProgramModern,
    ProgramLegacy,
    FileModern,
    FileLegacy,
    Other,
}

/// Root 하위 세그먼트를 Programs/Files 분기로 분류한다. 레지스트리 키 이름은
/// 대소문자를 구분하지 않으므로 inventoryapplication 같은 표기 변형도 같은
/// 분기로 들어가야 유효한 설치·실행 증거가 표기만으로 누락되지 않는다.
fn classify_key(segs: &[&str]) -> AmcacheKeyKind {
    match segs {
        // programs: Root\InventoryApplication\<id> (modern) or Root\Programs\<id> (legacy)
        [root, _] if root.eq_ignore_ascii_case("InventoryApplication") => {
            AmcacheKeyKind::ProgramModern
        }
        [root, _] if root.eq_ignore_ascii_case("Programs") => AmcacheKeyKind::ProgramLegacy,
        // files: Root\InventoryApplicationFile\<id> (modern) or Root\File\<vol>\<fileid> (legacy)
        [root, _] if root.eq_ignore_ascii_case("InventoryApplicationFile") => {
            AmcacheKeyKind::FileModern
        }
        [root, _, _] if root.eq_ignore_ascii_case("File") => AmcacheKeyKind::FileLegacy,
        _ => AmcacheKeyKind::Other,
    }
}

pub struct AmcacheParse {
    pub programs: Vec<Row>,
    pub files: Vec<Row>,
    /// 발견된 트랜잭션 로그를 적용하지 못해 기본 하이브만으로 폴백한 사유.
    /// None이면 로그가 없었거나 정상 적용된 것이다.
    pub log_apply_error: Option<String>,
}

/// `logs`는 호출자가 확정한 파싱 계획의 트랜잭션 로그 목록이다 — 파서가
/// 디렉터리를 재탐색하지 않아야 보고서의 입력 목록·logsDiscovered와 실제
/// 적용 로그가 항상 같은 스냅샷을 가리킨다.
pub fn parse_amcache(hive: &Path, logs: &[PathBuf]) -> Result<AmcacheParse> {
    let source = hive.to_string_lossy().to_string();
    let make_builder = |with_logs: bool| {
        // notatin stores the path, so a borrowed &Path fails the 'static bound.
        #[allow(clippy::unnecessary_to_owned)]
        let mut builder = ParserBuilder::from_path(hive.to_path_buf());
        if with_logs {
            for log in logs {
                builder.with_transaction_log(log.clone());
            }
        }
        // 복구 정책(사용자 확정): 삭제된 셀은 복구하지 않는다 — Registry
        // 파서와 동일하게 할당된(live) 키만 순회한다.
        builder
    };
    // Registry 파서와 같은 규칙: 로그 포함 빌드가 실패해도 유효한 기본
    // 하이브까지 버리지 않고, 실패 사유를 남긴 뒤 로그 없이 한 번 재시도한다.
    let mut log_apply_error: Option<String> = None;
    let parser = match make_builder(!logs.is_empty()).build() {
        Ok(parser) => parser,
        Err(error) => {
            if logs.is_empty() {
                return Err(error.into());
            }
            log_apply_error = Some(error.to_string());
            make_builder(false).build()?
        }
    };
    let mut programs: Vec<Row> = Vec::new();
    let mut files: Vec<Row> = Vec::new();

    for key in ParserIterator::new(&parser) {
        let segs = match after_root(&key.path) {
            Some(s) => s,
            None => continue,
        };
        let ts = fmt_kst(key.last_key_written_date_and_time());

        let kind = classify_key(&segs);
        let is_prog_modern = kind == AmcacheKeyKind::ProgramModern;
        let is_prog_legacy = kind == AmcacheKeyKind::ProgramLegacy;
        let is_file_modern = kind == AmcacheKeyKind::FileModern;
        let is_file_legacy = kind == AmcacheKeyKind::FileLegacy;

        if is_prog_modern || is_prog_legacy {
            let mut row = Row::new();
            for v in key.value_iter() {
                let (cv, _) = v.get_content();
                let name = v.get_pretty_name();
                let name = if is_prog_legacy {
                    map_legacy_program(&name).to_string()
                } else {
                    name
                };
                row.insert(name, render(&cv));
            }
            row.insert("timestamp".into(), ts);
            row.insert("_recovery".into(), "live".into());
            row.insert("_source_file".into(), source.clone());
            programs.push(row);
        } else if is_file_modern || is_file_legacy {
            let mut row = Row::new();
            for v in key.value_iter() {
                let (cv, _) = v.get_content();
                let pretty = v.get_pretty_name();
                let column = if is_file_legacy {
                    map_legacy_file(&pretty)
                } else {
                    underscore(&pretty)
                };
                row.insert(column, render(&cv));
            }
            if is_file_legacy {
                // 경로에서 파일명·소문자 경로 파생 + FILETIME 값 변환 —
                // 신형 스키마(name/lower_case_long_path)와 같은 모양으로 만든다.
                if let Some(full) = row.get("full_path").cloned() {
                    let base = full.rsplit(['\\', '/']).next().unwrap_or("").to_string();
                    if !base.is_empty() {
                        row.entry("name".into()).or_insert(base);
                    }
                    row.insert("lower_case_long_path".into(), full.to_lowercase());
                }
                for column in ["last_modified", "created", "last_modified_2"] {
                    if let Some(raw) = row.get(column).cloned() {
                        if let Some(formatted) = legacy_filetime(&raw) {
                            row.insert(column.into(), formatted);
                        }
                    }
                }
            }
            // regipy AmCachePlugin post-processing: strip the 4-char prefix on
            // file_id / program_id, derive sha1 from file_id, size hex->int.
            if let Some(fid) = row.get("file_id").cloned() {
                if fid != "0" && fid.len() > 4 {
                    let stripped = fid[4..].to_string();
                    row.insert("file_id".into(), stripped.clone());
                    row.entry("sha1".into()).or_insert(stripped);
                }
            }
            if let Some(sha) = row.get("sha1").cloned() {
                let s = if sha.len() > 4 && row.get("file_id").is_none_or(|f| *f != sha) {
                    sha[4..].to_string()
                } else {
                    sha
                };
                row.insert("sha1".into(), s);
            }
            if let Some(pid) = row.get("program_id").cloned() {
                if pid.len() > 4 {
                    row.insert("program_id".into(), pid[4..].to_string());
                }
            }
            if !is_file_legacy {
                if let Some(sz) = row.get("size").cloned() {
                    if let Ok(n) = i64::from_str_radix(sz.trim_start_matches("0x"), 16) {
                        row.insert("size".into(), n.to_string());
                    }
                }
            }
            // rename sha1 -> SHA1 (Python column name)
            if let Some(s) = row.remove("sha1") {
                row.insert("SHA1".into(), s);
            }
            row.insert("timestamp".into(), ts);
            row.insert("_recovery".into(), "live".into());
            row.insert("_source_file".into(), source.clone());
            files.push(row);
        }
    }
    Ok(AmcacheParse {
        programs,
        files,
        log_apply_error,
    })
}

#[cfg(test)]
mod tests {
    use super::{after_root, classify_key, legacy_filetime, map_legacy_file, AmcacheKeyKind};

    #[test]
    fn legacy_file_value_ids_map_to_modern_columns() {
        assert_eq!(map_legacy_file("15"), "full_path");
        assert_eq!(map_legacy_file("17"), "last_modified_2");
        assert_eq!(map_legacy_file("101"), "file_id");
        assert_eq!(map_legacy_file("100"), "program_id");
        assert_eq!(map_legacy_file("1"), "publisher");
        assert_eq!(map_legacy_file("0"), "product_name");
        // 미지의 ID는 소문자 원문 그대로 보존한다.
        assert_eq!(map_legacy_file("16"), "16");
    }

    #[test]
    fn legacy_filetime_formats_ticks_and_rejects_junk() {
        let formatted = legacy_filetime("128992604620000512").expect("filetime");
        assert!(formatted.starts_with("2009-"), "{formatted}");
        assert!(legacy_filetime("0").is_none());
        assert!(legacy_filetime("not-a-number").is_none());
    }

    #[test]
    fn key_classification_ignores_case() {
        let cases: &[(&str, AmcacheKeyKind)] = &[
            ("\\Root\\InventoryApplication\\id1", AmcacheKeyKind::ProgramModern),
            ("\\Root\\inventoryapplication\\id1", AmcacheKeyKind::ProgramModern),
            ("\\Root\\PROGRAMS\\id2", AmcacheKeyKind::ProgramLegacy),
            ("\\Root\\INVENTORYAPPLICATIONFILE\\id3", AmcacheKeyKind::FileModern),
            ("\\Root\\file\\vol1\\fid1", AmcacheKeyKind::FileLegacy),
            // 세그먼트 수가 다르거나 무관한 키는 분류되지 않아야 한다.
            ("\\Root\\InventoryApplication\\id\\extra", AmcacheKeyKind::Other),
            ("\\Root\\File\\onlyvol", AmcacheKeyKind::Other),
            ("\\Root\\DeviceContainers\\x", AmcacheKeyKind::Other),
        ];
        for (path, expected) in cases {
            let segs = after_root(path).expect("segments");
            assert_eq!(classify_key(&segs), *expected, "path: {path}");
        }
    }
}
