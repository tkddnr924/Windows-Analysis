//! Timestamp formatting matching the Python pipeline's `format_timestamp`:
//! KST (UTC+9) "YYYY-MM-DD HH:MM:SS.fff". Python builds the datetime via
//! `timedelta(microseconds = ticks/10)` (round-half-to-even to the microsecond)
//! then displays `microsecond // 1000` (floor to millisecond). We reproduce
//! that exactly with integer math on nanoseconds — no float noise, so it's at
//! least as precise as the Python path.
//!
//! 표시 문자열은 chrono의 `%Y-%m-%d %H:%M:%S%.3f`와 바이트 단위로 동일하지만,
//! 포맷 문자열 해석 없이 직접 조립한다 — 파서들이 행마다(MFT는 행당 8회)
//! 호출하는 최상위 CPU 소비처라 여기만으로 파싱이 눈에 띄게 빨라진다.
use chrono::{DateTime, FixedOffset, Utc};

pub fn kst_offset() -> FixedOffset {
    FixedOffset::east_opt(9 * 3600).unwrap()
}

const KST_OFFSET_SECS: i64 = 9 * 3600;

/// Howard Hinnant civil_from_days: 1970-01-01 기준 일수 -> (년, 월, 일).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn push_2(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}
fn push_3(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 100) as u8);
    push_2(out, v % 100);
}
fn push_4(out: &mut Vec<u8>, v: u32) {
    push_2(out, v / 100);
    push_2(out, v % 100);
}

/// unix 초 + 그 초의 밀리초 -> "YYYY-MM-DD HH:MM:SS.mmm" (KST).
/// 표시 가능한 연도(1..=9999)를 벗어나면 빈 문자열(비정상 시각).
fn fmt_kst_secs_ms(secs: i64, ms: u32) -> String {
    let kst = secs + KST_OFFSET_SECS;
    let days = kst.div_euclid(86_400);
    let second_of_day = kst.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    if !(1..=9999).contains(&year) {
        return String::new();
    }
    let mut out = Vec::with_capacity(23);
    push_4(&mut out, year as u32);
    out.push(b'-');
    push_2(&mut out, month);
    out.push(b'-');
    push_2(&mut out, day);
    out.push(b' ');
    push_2(&mut out, second_of_day / 3600);
    out.push(b':');
    push_2(&mut out, (second_of_day / 60) % 60);
    out.push(b':');
    push_2(&mut out, second_of_day % 60);
    out.push(b'.');
    push_3(&mut out, ms.min(999));
    // 위에서 ASCII 숫자·구분자만 넣었다.
    unsafe { String::from_utf8_unchecked(out) }
}

/// Plain KST millisecond string (truncating). Kept for non-FILETIME sources.
pub fn fmt_kst(dt: DateTime<Utc>) -> String {
    fmt_kst_secs_ms(dt.timestamp(), dt.timestamp_subsec_millis())
}

/// FILETIME-derived datetime -> Python-compatible KST millisecond string.
/// The unset FILETIME decodes to 1601, which falls outside chrono's i64-ns
/// range and yields "" (matching Python dropping FILETIME <= 0).
pub fn fmt_kst_ft(dt: DateTime<Utc>) -> String {
    let ns = match dt.timestamp_nanos_opt() {
        Some(n) => n,
        None => return String::new(), // pre-1678 (incl. the 1601 "zero") -> empty
    };
    // round nanoseconds to the nearest microsecond, half-to-even.
    // (The 1601->1970 offset is a whole number of microseconds, so doing this
    //  on 1970-based ns gives the same remainder and the same even/odd parity
    //  as Python's 1601-based microsecond count.)
    let q = ns.div_euclid(1000);
    let r = ns.rem_euclid(1000);
    let micros = if r < 500 {
        q
    } else if r > 500 {
        q + 1
    } else if q % 2 == 0 {
        q
    } else {
        q + 1
    };
    let secs = micros.div_euclid(1_000_000);
    let ms = (micros.rem_euclid(1_000_000) / 1000) as u32;
    fmt_kst_secs_ms(secs, ms)
}

/// Format a raw FILETIME tick count (100 ns since 1601) to the pipeline's KST
/// millisecond string, reproducing Python's `timedelta(microseconds=ticks/10)`
/// exactly: round the ticks to the nearest microsecond (half-to-even) with
/// integer math, then floor to the millisecond. Empty for ticks <= 0.
const EPOCH_1601_TO_1970_MICROS: i64 = 11_644_473_600_000_000;
pub fn fmt_filetime(ticks: i64) -> String {
    if ticks <= 0 {
        return String::new();
    }
    let q = ticks / 10;
    let r = ticks % 10;
    let micros_1601 = q + if r > 5 || (r == 5 && q % 2 != 0) { 1 } else { 0 };
    let unix_micros = micros_1601 - EPOCH_1601_TO_1970_MICROS;
    let secs = unix_micros.div_euclid(1_000_000);
    let ms = (unix_micros.rem_euclid(1_000_000) / 1000) as u32;
    fmt_kst_secs_ms(secs, ms)
}

/// OLE automation date (f64 days since 1899-12-30 UTC) -> KST millisecond
/// string. This is how SRUM's TimeStamp column is stored (NOT a FILETIME).
pub fn fmt_ole(days: f64) -> String {
    if days == 0.0 || !days.is_finite() {
        return String::new();
    }
    let micros = (days * 86_400_000_000.0).round() as i64;
    // 1899-12-30 UTC in unix micros:
    const OLE_EPOCH_UNIX_MICROS: i64 = -2_209_161_600_000_000;
    let unix_micros = OLE_EPOCH_UNIX_MICROS + micros;
    let secs = unix_micros.div_euclid(1_000_000);
    let ms = (unix_micros.rem_euclid(1_000_000) / 1000) as u32;
    fmt_kst_secs_ms(secs, ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// 직접 조립한 문자열이 chrono 포맷과 바이트 단위로 같아야 한다 —
    /// 타임라인 정렬·캐시 키 비교가 문자열 동일성에 의존한다.
    #[test]
    fn manual_format_is_byte_identical_to_chrono() {
        // 1601~2100년 범위를 불규칙 간격으로 훑고 밀리초 경계도 포함한다.
        let mut secs: i64 = -11_644_473_600; // 1601-01-01
        while secs < 4_102_444_800 {
            // 2100-01-01
            for ms in [0u32, 1, 499, 500, 999] {
                let manual = fmt_kst_secs_ms(secs, ms);
                let expected = Utc
                    .timestamp_opt(secs, ms * 1_000_000)
                    .single()
                    .map(|dt| {
                        dt.with_timezone(&kst_offset())
                            .format("%Y-%m-%d %H:%M:%S%.3f")
                            .to_string()
                    })
                    .unwrap_or_default();
                assert_eq!(manual, expected, "secs={secs} ms={ms}");
            }
            secs += 86_400 * 97 + 12_345; // 소수(97일+α)로 요일·월 경계 순환
        }
    }

    #[test]
    fn out_of_display_range_years_yield_empty() {
        assert_eq!(fmt_kst_secs_ms(-63_000_000_000, 0), ""); // 서기 이전
        assert_eq!(fmt_kst_secs_ms(260_000_000_000, 0), ""); // 9999년 초과
    }
}
