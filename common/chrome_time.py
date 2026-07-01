"""Chromium/WebKit timestamp conversion, shared by every Chromium-family
browser database parser (History, Login Data, Cookies, Web Data, ...).

Chromium stores time as microseconds since 1601-01-01 00:00:00 UTC — same
epoch as Windows FILETIME, different unit (microseconds, not 100ns ticks).
Always UTC (base::Time is UTC-based internally in Chromium), so no
per-field guessing is needed here the way Amcache's naive strings required.
"""
from datetime import datetime, timedelta, timezone

from common.utils import UTC, format_timestamp

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_timestamp(value) -> str:
    """Format a Chromium time value (microseconds since 1601-01-01 UTC) as
    'YYYY-MM-DD hh:mm:ss.fff' in KST. Returns '' for empty/zero input."""
    if not value:
        return ""
    try:
        dt = _CHROME_EPOCH + timedelta(microseconds=int(value))
    except (ValueError, OverflowError, TypeError):
        return ""
    return format_timestamp(dt.isoformat(), source_tz=UTC)
