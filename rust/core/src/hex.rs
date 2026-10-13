//! 소문자 hex 인코딩 — 바이트별 format! 대신 니블 룩업으로 조립한다.
//! Registry REG_BINARY·SRUM blob처럼 큰 값에서 수 배 빠르다.

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize]);
        out.push(HEX_DIGITS[(byte & 0x0F) as usize]);
    }
    // ASCII만 넣었다.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Binary SID -> "S-1-5-..."; None when shorter than the fixed 8-byte header.
pub(crate) fn format_binary_sid(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let authority = data[2..8].iter().fold(0u64, |a, &b| (a << 8) | b as u64);
    let mut out = format!("S-{}-{authority}", data[0]);
    for sub in data[8..].chunks_exact(4).take(data[1] as usize) {
        out.push('-');
        out.push_str(&u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]]).to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::hex_lower;

    #[test]
    fn matches_per_byte_formatting() {
        let bytes: Vec<u8> = (0..=255).collect();
        let expected: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_lower(&bytes), expected);
        assert_eq!(hex_lower(&[]), "");
    }
}
