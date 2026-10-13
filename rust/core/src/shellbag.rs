//! Shellbag reconstruction from the already-parsed registry dumps. Shellbags
//! live in the registry (UsrClass.dat `…\Shell\BagMRU`, NTUSER.DAT
//! `Software\…\Shell\BagMRU`), which we already dump — but each BagMRU value is
//! a binary shell item (ITEMIDLIST fragment), so the folder path has to be
//! decoded, not just read. Each BagMRU key's numbered values are the shell
//! items of its child nodes; walking the key hierarchy and decoding each item
//! reconstructs the folder the user browsed in Explorer.
//!
//! Folder names come from the 0xBEEF0004 extension block's long name. Rather
//! than chase version-specific offsets, we take the longest printable UTF-16LE
//! run in the item — robust across versions and for non-Latin (e.g. Korean)
//! names. Volume items (0x2x) give the drive; root/GUID items (0x1x) are the
//! "This PC"/Desktop anchors and are dropped so the path is volume-relative
//! (matching how $MFT stores paths).

/// One reconstructed shellbag folder.
pub struct Shellbag {
    /// Volume-relative, lowercased, for matching against $MFT paths (e.g. `\users\administrator\desktop`).
    pub path: String,
    /// Display path with drive when known (e.g. `C:\Users\Administrator\Desktop`).
    pub display: String,
    pub account: String,
    /// 이 폴더를 가리킨 BagMRU 값 행의 원본 연결 키(`<하이브>::Registry::<rowid>`).
    pub record_key: String,
}

/// A BagMRU numbered value: the shell item naming child node `key_path\value_name`.
pub struct BagRow {
    /// Source hive identity; NTUSER.DAT hives share key paths, so nodes only
    /// link within one hive.
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub data: Vec<u8>,
    pub account: String,
    /// 이 값을 읽은 레지스트리 산출물 행의 record_key — 파생의 원본 연결용.
    pub record_key: String,
}

enum Name {
    Root,           // My Computer / Desktop / GUID — dropped from the path
    Volume(String), // "C:"
    Dir(String),    // a folder name
    Unknown,
}

/// Longest printable UTF-16LE run in `b`, null-terminated or to the end.
fn longest_utf16(b: &[u8]) -> String {
    let mut best: Vec<u16> = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        let printable = (0x20..=0xD7FF).contains(&u) || (0xE000..=0xFFFD).contains(&u);
        if printable {
            cur.push(u);
        } else {
            if cur.len() > best.len() {
                best = cur.clone();
            }
            cur.clear();
        }
        i += 2;
    }
    if cur.len() > best.len() {
        best = cur;
    }
    String::from_utf16_lossy(&best).trim().to_string()
}

/// UTF-16LE null-terminated string starting at `off`.
fn utf16_at(b: &[u8], off: usize) -> String {
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < b.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Long folder name from a 0x3x file/folder shell item. Prefers the
/// 0xBEEF0004 extension block's long name at its recorded offset (block+16,
/// libfwsi) — exact, so no stray leading bytes — and only falls back to the
/// longest UTF-16 run, then the 8.3 short name, if that fails.
fn folder_long_name(b: &[u8]) -> String {
    if let Some(sig) = find_sub(b, &[0x04, 0x00, 0xef, 0xbe]) {
        if sig >= 4 {
            let block_start = sig - 4;
            let version = u16::from_le_bytes([b[block_start + 2], b[block_start + 3]]);
            let block_size = u16::from_le_bytes([b[block_start], b[block_start + 1]]) as usize;
            let recorded = b
                .get(block_start + 16..block_start + 18)
                .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
                .filter(|&off| off >= 18 && off + 2 <= block_size);
            let name_off = block_start
                + recorded.unwrap_or(match version {
                    9.. => 46,
                    8 => 42,
                    7 => 38,
                    _ => 20,
                });
            if name_off < b.len() {
                let first = u16::from_le_bytes([b[name_off], *b.get(name_off + 1).unwrap_or(&0)]);
                if (0x20..=0xFFFD).contains(&first) {
                    let n = utf16_at(b, name_off);
                    if !n.trim().is_empty() {
                        return n.trim().to_string();
                    }
                }
            }
        }
    }
    let long = longest_utf16(b);
    if long.len() >= 2 {
        return long;
    }
    ascii_at(b, 14)
}

/// ASCII (single-byte) null-terminated string starting at `off`.
fn ascii_at(b: &[u8], off: usize) -> String {
    if off >= b.len() {
        return String::new();
    }
    let end = b[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| off + p)
        .unwrap_or(b.len());
    String::from_utf8_lossy(&b[off..end]).trim().to_string()
}

fn decode_item(b: &[u8]) -> Name {
    if b.len() < 3 {
        return Name::Unknown;
    }
    let typ = b[2]; // b[0..2] = item size
    match typ & 0x70 {
        0x10 => Name::Root, // 0x1x root/GUID
        0x20 => {
            // 0x2x volume: "C:\"
            let v = ascii_at(b, 3);
            let drive = v.trim_end_matches('\\').to_string();
            if drive.is_empty() {
                Name::Unknown
            } else {
                Name::Volume(drive)
            }
        }
        0x30 => {
            // 0x3x file/folder
            let n = folder_long_name(b);
            if n.is_empty() {
                Name::Unknown
            } else {
                Name::Dir(n)
            }
        }
        _ => Name::Unknown,
    }
}

fn lower(s: &str) -> String {
    s.to_lowercase()
}

/// Reconstruct every shellbag folder from a flat list of BagMRU numbered values.
pub fn reconstruct(rows: Vec<BagRow>) -> Vec<Shellbag> {
    use std::collections::HashMap;
    // (hive, lowercased node path) -> raw shell-item bytes, parent node, account
    type Node = (String, String);
    let mut item: HashMap<Node, Vec<u8>> = HashMap::new();
    let mut parent: HashMap<Node, Node> = HashMap::new();
    let mut account: HashMap<Node, String> = HashMap::new();
    let mut record_key: HashMap<Node, String> = HashMap::new();
    for r in rows {
        let node = (r.hive.clone(), lower(&format!("{}\\{}", r.key_path, r.value_name)));
        parent.insert(node.clone(), (r.hive, lower(&r.key_path)));
        item.insert(node.clone(), r.data);
        account.insert(node.clone(), r.account);
        record_key.insert(node, r.record_key);
    }

    let mut out = Vec::new();
    for node in item.keys() {
        // Walk from this node up to the BagMRU root, collecting decoded names.
        let mut chain: Vec<Name> = Vec::new();
        let mut cur = node.clone();
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 64 {
                break;
            }
            let bytes = match item.get(&cur) {
                Some(b) => b,
                None => break,
            };
            chain.push(decode_item(bytes));
            match parent.get(&cur) {
                Some(p) if item.contains_key(p) => cur = p.clone(),
                _ => break, // parent is the BagMRU root (no shell item) — stop
            }
        }
        chain.reverse(); // root-most first

        let mut drive = String::new();
        let mut dirs: Vec<String> = Vec::new();
        let mut ok = false;
        for n in chain {
            match n {
                Name::Root => {}
                Name::Volume(d) => {
                    drive = d;
                    ok = true;
                }
                Name::Dir(name) => {
                    dirs.push(name);
                    ok = true;
                }
                Name::Unknown => {}
            }
        }
        if !ok || dirs.is_empty() {
            continue;
        } // need at least one folder name
        let rel = format!("\\{}", dirs.join("\\"));
        let display = if drive.is_empty() {
            rel.clone()
        } else {
            format!("{}{}", drive, rel)
        };
        out.push(Shellbag {
            path: rel.to_lowercase(),
            display,
            account: account.get(node).cloned().unwrap_or_default(),
            record_key: record_key.get(node).cloned().unwrap_or_default(),
        });
    }
    // De-dup identical (display, account) — the drive separates volumes;
    // record_key keeps the survivor stable.
    out.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.account.cmp(&b.account))
            .then(a.display.cmp(&b.display))
            .then(a.record_key.cmp(&b.record_key))
    });
    out.dedup_by(|a, b| a.path == b.path && a.account == b.account && a.display == b.display);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(drive: &str) -> Vec<u8> {
        let mut item = vec![0, 0, 0x2f];
        item.extend_from_slice(drive.as_bytes());
        item.extend_from_slice(b"\\\0");
        item
    }

    /// 0x31 folder item; 0xD8 keeps the type byte out of the UTF-16 name run.
    fn folder(name: &str) -> Vec<u8> {
        let mut item = vec![0, 0, 0x31, 0xd8];
        item.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        item.extend_from_slice(&[0, 0]);
        item
    }

    fn row(account: &str, key_path: &str, value_name: &str, data: Vec<u8>) -> BagRow {
        BagRow {
            hive: format!("{account}_NTUSER.DAT"),
            key_path: key_path.into(),
            value_name: value_name.into(),
            data,
            account: account.into(),
            record_key: format!("{account}::{key_path}\\{value_name}"),
        }
    }

    /// NTUSER.DAT hives share the `\ROOT\…\BagMRU` key path: nodes of one
    /// hive never overwrite or link into another hive's nodes.
    #[test]
    fn same_key_paths_in_two_hives_stay_separate_trees() {
        let bag = "\\ROOT\\SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU";
        let child = format!("{bag}\\0");
        let mut out = reconstruct(vec![
            row("alice", bag, "0", volume("C:")),
            row("alice", &child, "0", folder("Alpha")),
            row("bob", bag, "0", volume("D:")),
            row("bob", &child, "0", folder("Beta")),
        ]);
        out.sort_by(|a, b| a.display.cmp(&b.display));
        let got: Vec<(String, String, String)> = out
            .into_iter()
            .map(|s| (s.display, s.account, s.record_key))
            .collect();
        assert_eq!(
            got,
            vec![
                ("C:\\Alpha".into(), "alice".into(), format!("alice::{child}\\0")),
                ("D:\\Beta".into(), "bob".into(), format!("bob::{child}\\0")),
            ]
        );
    }

    #[test]
    fn same_folder_on_two_volumes_is_kept() {
        let bag = "\\ROOT\\SOFTWARE\\Microsoft\\Windows\\Shell\\BagMRU";
        let mut out = reconstruct(vec![
            row("alice", bag, "0", volume("C:")),
            row("alice", &format!("{bag}\\0"), "0", folder("Alpha")),
            row("alice", bag, "1", volume("D:")),
            row("alice", &format!("{bag}\\1"), "0", folder("Alpha")),
        ]);
        out.sort_by(|a, b| a.display.cmp(&b.display));
        let got: Vec<String> = out.into_iter().map(|s| s.display).collect();
        assert_eq!(got, vec!["C:\\Alpha".to_string(), "D:\\Alpha".to_string()]);
    }

    /// v7 (Vista) BEEF0004: long name at the recorded offset 38, not 34.
    #[test]
    fn beef0004_v7_name_uses_recorded_offset() {
        let name: Vec<u8> = "Gamma".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut block = vec![0u8; 38];
        block[2] = 7; // version
        block[4..8].copy_from_slice(&[0x04, 0x00, 0xef, 0xbe]);
        block[16] = 38; // long name offset
        block[34..38].copy_from_slice(&[b'X', 0, b'Y', 0]); // printable decoy at 34
        block.extend(&name);
        block.extend_from_slice(&[0, 0, 0, 0]);
        let size = block.len() as u16;
        block[0..2].copy_from_slice(&size.to_le_bytes());
        let mut item = vec![0, 0, 0x31, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'G', b'A', 0, 0];
        item.extend(block);
        assert_eq!(folder_long_name(&item), "Gamma");
    }
}
