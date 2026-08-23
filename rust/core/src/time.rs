//! Timestamp formatting matching the Python pipeline's `format_timestamp`:
//! KST (UTC+9) "YYYY-MM-DD HH:MM:SS.fff". Python builds the datetime via
//! `timedelta(microseconds = ticks/10)` (round-half-to-even to the microsecond)
//! then displays `microsecond // 1000` (floor to millisecond). We reproduce
//! that exactly with integer math on nanoseconds — no float noise, so it's at
//! least as precise as the Python path.
use chrono::{DateTime, FixedOffset, LocalResult, TimeZone, Utc};

pub fn kst_offset() -> FixedOffset {
    FixedOffset::east_opt(9 * 3600).unwrap()
}

/// Plain KST millisecond string (truncating). Kept for non-FILETIME sources.
pub fn fmt_kst(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&kst_offset())
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
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
    let ms = micros.rem_euclid(1_000_000) / 1000;
    match Utc.timestamp_opt(secs, 0) {
        LocalResult::Single(base) => format!(
            "{}.{:03}",
            base.with_timezone(&kst_offset())
                .format("%Y-%m-%d %H:%M:%S"),
            ms
        ),
        _ => fmt_kst(dt),
    }
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
    let micros_1601 = q + if r > 5 || (r == 5 && q % 2 != 0) {
        1
    } else {
        0
    };
    let unix_micros = micros_1601 - EPOCH_1601_TO_1970_MICROS;
    let secs = unix_micros.div_euclid(1_000_000);
    let ms = unix_micros.rem_euclid(1_000_000) / 1000;
    match Utc.timestamp_opt(secs, 0) {
        LocalResult::Single(base) => format!(
            "{}.{:03}",
            base.with_timezone(&kst_offset())
                .format("%Y-%m-%d %H:%M:%S"),
            ms
        ),
        _ => String::new(),
    }
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
    let ms = unix_micros.rem_euclid(1_000_000) / 1000;
    match Utc.timestamp_opt(secs, 0) {
        LocalResult::Single(base) => format!(
            "{}.{:03}",
            base.with_timezone(&kst_offset())
                .format("%Y-%m-%d %H:%M:%S"),
            ms
        ),
        _ => String::new(),
    }
}
