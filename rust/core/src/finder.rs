//! File discovery, mirroring common/finder.py: by exact name, extension,
//! suffix, or content marker. Recursive walk of the target tree.
//! 수집기는 같은 파일을 두 경로에 두지 않는다는 운영 전제에 따라(2026-08-30
//! 사용자 확정) 내용 지문 기반 중복 제거는 두지 않는다 — 발견된 파일은 전부
//! 파싱 계획에 포함되어 증거가 접혀 사라지는 일이 없다.
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

fn walk_files(root: &Path) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
}

pub fn by_name(root: &Path, names: &[&str]) -> Vec<PathBuf> {
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    walk_files(root)
        .filter(|p| {
            p.file_name()
                .map(|n| lower.contains(&n.to_string_lossy().to_lowercase()))
                .unwrap_or(false)
        })
        .collect()
}
pub fn by_extension(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    // exts include the dot, e.g. ".wer"; match case-insensitive on the tail.
    let lower: Vec<String> = exts.iter().map(|e| e.to_lowercase()).collect();
    walk_files(root)
        .filter(|p| {
            let n = p
                .file_name()
                .map(|x| x.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            lower.iter().any(|e| n.ends_with(e))
        })
        .collect()
}
pub fn by_suffix(root: &Path, suffixes: &[&str]) -> Vec<PathBuf> {
    let lower: Vec<String> = suffixes.iter().map(|s| s.to_lowercase()).collect();
    walk_files(root)
        .filter(|p| {
            let n = p
                .file_name()
                .map(|x| x.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            lower.iter().any(|s| n.ends_with(s))
        })
        .collect()
}
pub fn by_content(root: &Path, marker: &str) -> Vec<PathBuf> {
    let utf8 = marker.as_bytes().to_vec();
    let utf16: Vec<u8> = marker.bytes().flat_map(|b| [b, 0]).collect();
    walk_files(root)
        .filter(|p| {
            // Only the first 4 KB — never slurp whole files (a target can hold huge
            // unrelated files, which made content discovery crawl).
            let mut head = Vec::new();
            match std::fs::File::open(p) {
                Ok(f) => {
                    use std::io::Read;
                    if std::io::Read::take(f, 4096).read_to_end(&mut head).is_err() {
                        return false;
                    }
                }
                Err(_) => return false,
            }
            head.windows(utf8.len()).any(|w| w == utf8.as_slice())
                || head.windows(utf16.len()).any(|w| w == utf16.as_slice())
        })
        .collect()
}
