//! File discovery, mirroring common/finder.py: by exact name, extension,
//! suffix, or content marker; plus dedupe_by_content (drop byte-identical
//! copies). Recursive walk of the target tree.
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
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
        // Only the first 4 KB — never slurp whole files (a target can hold huge
        // unrelated files, which made content discovery crawl).
        let mut head = Vec::new();
        match std::fs::File::open(p) {
            Ok(f) => { use std::io::Read; if std::io::Read::take(f, 4096).read_to_end(&mut head).is_err() { return false; } }
            Err(_) => return false,
        }
        head.windows(utf8.len()).any(|w| w == utf8.as_slice()) || head.windows(utf16.len()).any(|w| w == utf16.as_slice())
    }).collect()
}

/// Drop byte-identical copies (a collector saving the same file under two
/// category folders). Keeps first occurrence.
/// A cheap content fingerprint: file size + a hash of the first and last 64 KB.
/// Byte-identical files share it; distinct files (which diverge in the hive
/// header/first pages and/or the tail) don't. Bounded to 128 KB/file so a
/// 100 MB+ registry hive or a 1 GB $MFT isn't slurped whole just to de-dup —
/// the parser reads the real bytes afterward anyway.
fn content_key(p: &Path) -> Option<(u64, u64)> {
    const CHUNK: usize = 64 * 1024;
    let mut f = std::fs::File::open(p).ok()?;
    let len = f.metadata().ok()?.len();
    let mut h = DefaultHasher::new();
    len.hash(&mut h);
    if len as usize <= CHUNK * 2 {
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ok()?;
        buf.hash(&mut h);
    } else {
        let mut head = vec![0u8; CHUNK];
        f.read_exact(&mut head).ok()?;
        head.hash(&mut h);
        f.seek(SeekFrom::End(-(CHUNK as i64))).ok()?;
        let mut tail = vec![0u8; CHUNK];
        f.read_exact(&mut tail).ok()?;
        tail.hash(&mut h);
    }
    Some((len, h.finish()))
}

pub fn dedupe_by_content(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        match content_key(&p) {
            Some(key) => { if seen.insert(key) { out.push(p); } }
            None => out.push(p), // unreadable — keep it (parser will report)
        }
    }
    out
}
