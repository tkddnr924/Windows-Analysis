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
