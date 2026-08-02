"""Windows Error Reporting (WER) — the Report.wer files under
ReportArchive/ReportQueue, one per crash/hang report. Each is a UTF-16LE
key=value text file describing a faulting application (name, version, path),
the event type (APPCRASH, APPHANG, ...), and the fault signature.

Each report file becomes one row. Well-known keys are pulled into named
leading columns; every other real `Key=Value` pair in the file is kept as
its own column so nothing is dropped (reports carry different key sets, and
the sqlite writer tolerates rows with differing keys).

EventTime / UploadTime are Windows FILETIME values (100-ns ticks since
1601-01-01 UTC) — converted and formatted; the raw values are also kept.
"""
import datetime as dt
import re
from pathlib import Path

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "WER"
EXTENSIONS = [".wer"]

FIELD_ORDER = {
    "WER_Reports": [
        "timestamp", "EventType", "AppName", "AppPath", "TargetAppId",
        "ReportIdentifier", "_source_file",
    ],
}

# Only accept clean key names — WER files contain a few binary/garbled
# Sig[n].Name lines whose "key" isn't real text.
_KEY_RE = re.compile(r"^[A-Za-z0-9_.\[\]]+$")


def _filetime_to_dt(value: str):
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    return dt.datetime(1601, 1, 1, tzinfo=UTC) + dt.timedelta(microseconds=ticks / 10)


def _parse_report(path: Path) -> dict:
    data = path.read_bytes()
    # WER reports are UTF-16LE with a BOM; fall back to utf-8 just in case.
    if data[:2] == b"\xff\xfe":
        text = data.decode("utf-16-le", errors="replace")
    else:
        text = data.decode("utf-8", errors="replace")
    text = text.lstrip("﻿")

    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            continue
        fields[key] = value.strip()

    row: dict = {"_source_file": str(path)}
    row.update(fields)

    event_dt = _filetime_to_dt(fields.get("EventTime", ""))
    row["timestamp"] = format_timestamp(event_dt, source_tz=UTC) if event_dt else ""
    return row


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for path in paths:
        try:
            rows.append(_parse_report(path))
        except Exception as exc:
            rows.append(
                {
                    "timestamp": "",
                    "_source_file": str(path),
                    "_status": "unreadable_file",
                    "_error": str(exc),
                }
            )
    return {"WER_Reports": rows}
