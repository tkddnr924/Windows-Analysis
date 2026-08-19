//! File discovery, mirroring common/finder.py: by exact name, extension,
//! suffix, or content marker; plus dedupe_by_content (drop byte-identical
//! copies). Recursive walk of the target tree.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

fn walk_files(root: &Path) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()).map(|e| e.into_path())
}

pub fn by_name(root: &Path, names: &[&str]) -> Vec<PathBuf> {
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    walk_files(root).filter(|p| p.file_name().map(|n| lower.contains(&n.to_string_lossy().to_lowercase())).unwrap_or(false)).collect()
}
pub fn by_extension(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    // exts include the dot, e.g. ".wer"; match case-insensitive on the tail.
    let lower: Vec<String> = exts.iter().map(|e| e.to_lowercase()).collect();
    walk_files(root).filter(|p| { let n = p.file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default(); lower.iter().any(|e| n.ends_with(e)) }).collect()
}
pub fn by_suffix(root: &Path, suffixes: &[&str]) -> Vec<PathBuf> {
    let lower: Vec<String> = suffixes.iter().map(|s| s.to_lowercase()).collect();
    walk_files(root).filter(|p| { let n = p.file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default(); lower.iter().any(|s| n.ends_with(s)) }).collect()
}
pub fn by_content(root: &Path, marker: &str) -> Vec<PathBuf> {
    let utf8 = marker.as_bytes().to_vec();
    let utf16: Vec<u8> = marker.bytes().flat_map(|b| [b, 0]).collect();
    walk_files(root).filter(|p| {
        let data = match std::fs::read(p) { Ok(d) => d, Err(_) => return false };
        let head = &data[..data.len().min(4096)];
        head.windows(utf8.len()).any(|w| w == utf8.as_slice()) || head.windows(utf16.len()).any(|w| w == utf16.as_slice())
    }).collect()
}

/// Drop byte-identical copies (a collector saving the same file under two
/// category folders). Keeps first occurrence.
pub fn dedupe_by_content(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        match std::fs::read(&p) {
            Ok(bytes) => {
                let mut h = DefaultHasher::new();
                bytes.hash(&mut h);
                let key = (bytes.len(), h.finish());
                if seen.insert(key) { out.push(p); }
            }
            Err(_) => out.push(p),
        }
    }
    out
}
