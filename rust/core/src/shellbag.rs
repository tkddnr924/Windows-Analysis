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
}

/// A BagMRU numbered value: the shell item naming child node `key_path\value_name`.
pub struct BagRow {
    pub key_path: String,
    pub value_name: String,
    pub data: Vec<u8>,
    pub account: String,
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
/// 0xBEEF0004 extension block's long name at its (version-based) fixed offset —
/// exact, so no stray leading bytes — and only falls back to the longest UTF-16
/// run, then the 8.3 short name, if that fails.
fn folder_long_name(b: &[u8]) -> String {
    if let Some(sig) = find_sub(b, &[0x04, 0x00, 0xef, 0xbe]) {
        if sig >= 4 {
            let block_start = sig - 4;
            let version = u16::from_le_bytes([b[block_start + 2], b[block_start + 3]]);
            let name_off = block_start
                + if version >= 9 {
                    46
                } else if version >= 8 {
                    42
                } else {
                    34
                };
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
        0x00 if typ == 0x1f || (typ & 0xf0) == 0x10 => Name::Root,
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
    // node_key(lower) -> (raw shell-item bytes, parent_key(lower), account)
    let mut item: HashMap<String, Vec<u8>> = HashMap::new();
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut account: HashMap<String, String> = HashMap::new();
    for r in &rows {
        let node = lower(&format!("{}\\{}", r.key_path, r.value_name));
        parent.insert(node.clone(), lower(&r.key_path));
        item.insert(node.clone(), r.data.clone());
        account.insert(node, r.account.clone());
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
        });
    }
    // De-dup identical (path, account).
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.account.cmp(&b.account)));
    out.dedup_by(|a, b| a.path == b.path && a.account == b.account);
    out
}
