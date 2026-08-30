//! File discovery, mirroring common/finder.py: by exact name, extension,
//! suffix, or content marker. Recursive walk of the target tree.
//! 수집기는 같은 파일을 두 경로에 두지 않는다는 운영 전제에 따라(2026-08-30
//! 사용자 확정) 내용 지문 기반 중복 제거는 두지 않는다 — 발견된 파일은 전부
//! 파싱 계획에 포함되어 증거가 접혀 사라지는 일이 없다.
//!
//! 탐색 중 만난 접근·순회 실패는 버리지 않고 `Found.errors`로 반환한다 —
//! 권한 거부된 하위 디렉터리의 "발견 0건"이 실제 무증거와 구분되도록
//! 파이프라인이 이를 아티팩트 보고서에 기록한다.
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// 탐색 결과: 발견 경로 + 순회·읽기 실패("경로: 사유").
#[derive(Default)]
pub struct Found {
    pub paths: Vec<PathBuf>,
    pub errors: Vec<String>,
}

/// 대상 트리의 파일 목록과 순회 실패를 함께 모은다. 다른 아티팩트의
/// 전용 탐색 함수(WalkDir 직접 사용)도 같은 계약을 따르도록 공개한다.
pub fn walk_files(root: &Path) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for entry in WalkDir::new(root) {
        match entry {
            Ok(e) => {
                if e.file_type().is_file() {
                    files.push(e.into_path());
                }
            }
            Err(error) => {
                let at = error
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| root.display().to_string());
                errors.push(format!("{at}: {error}"));
            }
        }
    }
    (files, errors)
}

pub fn by_name(root: &Path, names: &[&str]) -> Found {
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let (files, errors) = walk_files(root);
    Found {
        paths: files
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .map(|n| lower.contains(&n.to_string_lossy().to_lowercase()))
                    .unwrap_or(false)
            })
            .collect(),
        errors,
    }
}
pub fn by_extension(root: &Path, exts: &[&str]) -> Found {
    // exts include the dot, e.g. ".wer"; match case-insensitive on the tail.
    let lower: Vec<String> = exts.iter().map(|e| e.to_lowercase()).collect();
    let (files, errors) = walk_files(root);
    Found {
        paths: files
            .into_iter()
            .filter(|p| {
                let n = p
                    .file_name()
                    .map(|x| x.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                lower.iter().any(|e| n.ends_with(e))
            })
            .collect(),
        errors,
    }
}
pub fn by_suffix(root: &Path, suffixes: &[&str]) -> Found {
    let lower: Vec<String> = suffixes.iter().map(|s| s.to_lowercase()).collect();
    let (files, errors) = walk_files(root);
    Found {
        paths: files
            .into_iter()
            .filter(|p| {
                let n = p
                    .file_name()
                    .map(|x| x.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                lower.iter().any(|s| n.ends_with(s))
            })
            .collect(),
        errors,
    }
}
pub fn by_content(root: &Path, marker: &str) -> Found {
    use std::io::Read;
    let utf8 = marker.as_bytes().to_vec();
    let utf16: Vec<u8> = marker.bytes().flat_map(|b| [b, 0]).collect();
    let (files, mut errors) = walk_files(root);
    let mut paths = Vec::new();
    for p in files {
        // Only the first 4 KB — never slurp whole files (a target can hold huge
        // unrelated files, which made content discovery crawl).
        let mut head = Vec::new();
        match std::fs::File::open(&p) {
            Ok(f) => {
                if std::io::Read::take(f, 4096).read_to_end(&mut head).is_err() {
                    // 열렸지만 앞부분을 읽지 못한 파일은 "비대상"이 아니라
                    // 판정 불가 — 실패로 기록해 증거 누락과 구분한다.
                    errors.push(format!("{}: 내용 판별용 앞부분 읽기 실패", p.display()));
                    continue;
                }
            }
            Err(error) => {
                errors.push(format!("{}: {error}", p.display()));
                continue;
            }
        }
        if head.windows(utf8.len()).any(|w| w == utf8.as_slice())
            || head.windows(utf16.len()).any(|w| w == utf16.as_slice())
        {
            paths.push(p);
        }
    }
    Found { paths, errors }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 접근 거부된 하위 디렉터리는 "발견 0건"으로 사라지지 않고 실패로
    /// 반환된다 — 파이프라인이 보고서에 기록할 근거.
    #[cfg(unix)]
    #[test]
    fn permission_denied_subtree_is_reported_not_dropped() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("wina-finder-perm-{}", std::process::id()));
        let locked = root.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("Amcache.hve"), b"x").unwrap();
        std::fs::write(root.join("Amcache.hve"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let found = by_name(&root, &["Amcache.hve"]);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();

        assert_eq!(found.paths.len(), 1, "readable file still discovered");
        assert!(
            !found.errors.is_empty(),
            "denied subtree must surface as an error"
        );
        assert!(found.errors[0].contains("locked"));
    }
}
