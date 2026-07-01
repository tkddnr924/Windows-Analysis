"""Shared analysis-output conventions.

This project is for timeline analysis, so every parser must present time
values the same way:

1. Format: "YYYY-MM-DD hh:mm:ss.fff"
2. If no sub-second precision is available, pad with ".000"
3. Always convert to UTC+9 (KST)

Point 3 only means something once you know what timezone the *raw* value
is actually in. A tz-aware value (e.g. an ISO string with a "+00:00"
offset, like a FILETIME-derived timestamp) carries that answer with it and
is always safe to convert. A naive value (a plain string/datetime with no
offset) does NOT default to UTC here — you must look up what that specific
artifact field actually records and pass it explicitly as `source_tz`.
Some fields are UTC (most FILETIME/telemetry-derived fields), some are
already local/KST, and getting this wrong silently produces a wrong
timeline. Don't guess; check the artifact's documented behavior per field.

Use `format_timestamp()` on every time-valued field before writing a row,
and put those formatted fields first in the parser's FIELD_ORDER so the
timestamp leads each CSV.
"""
from __future__ import annotations

import datetime as dt

UTC = dt.timezone.utc
KST = dt.timezone(dt.timedelta(hours=9))
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Common non-ISO formats artifact hives store timestamps as
_STRING_FORMATS = (
    "%m/%d/%Y %H:%M:%S",  # e.g. Amcache LinkDate / InstallDate
    "%Y-%m-%d %H:%M:%S",
)


def format_timestamp(value, source_tz: dt.tzinfo) -> str:
    """Normalize a datetime/epoch/string value to 'YYYY-MM-DD hh:mm:ss.fff'
    in KST (UTC+9).

    `source_tz` is the timezone to assume ONLY when `value` has no timezone
    of its own (naive datetime or plain date string) — it is ignored when
    the value already carries an offset, and it never applies to numeric
    epoch values (Unix epoch is unambiguously UTC by definition). Pass
    `common.utils.UTC` or `common.utils.KST` after confirming which one
    matches the artifact field being parsed.

    Returns '' for empty/None input, or str(value) if it can't be parsed.
    """
    if value is None or value == "":
        return ""

    parsed = _parse(value, source_tz)
    if parsed is None:
        return str(value)

    parsed = parsed.astimezone(KST)

    millis = f"{parsed.microsecond // 1000:03d}"
    return f"{parsed.strftime(TIME_FORMAT)}.{millis}"


def _parse(value, source_tz: dt.tzinfo):
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=source_tz)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # Unix epoch is UTC by definition, regardless of source_tz.
        return dt.datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            parsed = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=source_tz)
        except ValueError:
            pass
        for fmt in _STRING_FORMATS:
            try:
                return dt.datetime.strptime(s, fmt).replace(tzinfo=source_tz)
            except ValueError:
                continue
    return None
