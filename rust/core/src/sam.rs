//! SAM F/V record decoding and byte helpers shared by Metadata and _OVERVIEW.

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    let b = s.as_bytes();
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        match (hv(pair[0]), hv(pair[1])) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Vec::new(),
        }
    }
    out
}

pub(crate) fn le_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off.saturating_add(2))
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

pub(crate) fn le_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off.saturating_add(4))
        .map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn le_u64(b: &[u8], off: usize) -> u64 {
    b.get(off..off.saturating_add(8)).map_or(0, |s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

/// Lossy UTF-16LE with trailing NULs removed.
pub(crate) fn utf16le(raw: &[u8]) -> String {
    let u: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
        .trim_end_matches('\0')
        .to_string()
}

pub(crate) const ACB_FLAGS: &[(u16, &str)] = &[
    (0x0001, "Disabled"),
    (0x0002, "HomeDirRequired"),
    (0x0004, "PwNotRequired"),
    (0x0008, "TempDuplicate"),
    (0x0010, "Normal"),
    (0x0020, "MNSLogon"),
    (0x0040, "DomainTrust"),
    (0x0080, "WorkstationTrust"),
    (0x0100, "ServerTrust"),
    (0x0200, "PwNoExpire"),
    (0x0400, "AutoLocked"),
];

/// Names of the ACB bits set in `acb`, in table order.
pub(crate) fn acb_flag_names(acb: u16) -> impl Iterator<Item = &'static str> {
    ACB_FLAGS
        .iter()
        .filter(move |(bit, _)| acb & bit != 0)
        .map(|(_, name)| *name)
}

/// SOFTWARE key (lowercase suffix) listing accounts hidden from the logon screen.
pub(crate) const SPECIAL_ACCOUNTS_USERLIST_SUFFIX: &str =
    "\\microsoft\\windows nt\\currentversion\\winlogon\\specialaccounts\\userlist";

pub(crate) fn well_known_account(sid: &str) -> Option<&'static str> {
    match sid.to_uppercase().as_str() {
        "S-1-5-18" => Some("LocalSystem"),
        "S-1-5-19" => Some("LocalService"),
        "S-1-5-20" => Some("NetworkService"),
        _ => None,
    }
}

/// Decoded SAM `F` value. FILETIMEs stay raw ticks (0 = unset).
pub(crate) struct SamF {
    pub rid: u32,
    pub last_login: u64,
    pub password_last_set: u64,
    pub last_failed_login: u64,
    pub login_count: u16,
    pub failed_login_count: u16,
    pub acb: u16,
}

impl SamF {
    pub(crate) fn disabled(&self) -> bool {
        self.acb & 0x0001 != 0
    }
}

pub(crate) fn sam_f(b: &[u8]) -> Option<SamF> {
    if b.len() < 0x44 {
        return None;
    }
    Some(SamF {
        rid: le_u32(b, 0x30),
        last_login: le_u64(b, 0x08),
        password_last_set: le_u64(b, 0x18),
        last_failed_login: le_u64(b, 0x28),
        login_count: le_u16(b, 0x42),
        failed_login_count: le_u16(b, 0x40),
        acb: le_u16(b, 0x38),
    })
}

/// SAM `V` table entry `index` (1 = name, 2 = full name). Offsets are relative
/// to the data region at 0xCC; empty/blank values are None.
pub(crate) fn sam_v_field(b: &[u8], index: usize) -> Option<String> {
    if b.len() < 0xCC {
        return None;
    }
    let base = index * 12;
    if base + 8 > b.len() {
        return None;
    }
    let off = le_u32(b, base) as usize;
    let len = le_u32(b, base + 4) as usize;
    if len == 0 {
        return None;
    }
    let start = 0xCC + off;
    let end = start.checked_add(len)?;
    if start >= b.len() {
        return None;
    }
    let text = utf16le(&b[start..end.min(b.len())]);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Machine SID from the validated 24-byte SAM V tail.
pub(crate) fn machine_sid_from_v(hex: &str) -> Option<String> {
    let b = unhex(hex);
    if b.len() < 24 {
        return None;
    }
    let tail = &b[b.len() - 24..];
    if tail[0] != 1 || tail[1] != 4 || tail[7] != 5 {
        return None;
    }
    let subs: [u32; 4] = std::array::from_fn(|i| le_u32(tail, 8 + i * 4));
    if subs[0] != 21 {
        return None;
    }
    Some(format!("S-1-5-21-{}-{}-{}", subs[1], subs[2], subs[3]))
}
