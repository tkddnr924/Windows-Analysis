"""Windows Error Reporting (WER) — the Report.wer files under
ReportArchive/ReportQueue, one per crash/hang report. Each is a UTF-16LE
key=value text file describing a faulting application (name, version, path),
the event type (APPCRASH, APPHANG, ...), and the fault signature.

Each report file becomes one row. Well-known scalar keys are pulled into
named leading columns; every other real `Key=Value` pair is kept so nothing
is dropped.

Indexed key families (LoadedModule[0..N], File[N].Path, Sig[N].Name/Value,
DynamicSig[N], OsInfo[N], UI[N], ...) are collapsed into a single JSON column
per family instead of one column per index. A busy host's reports each list
hundreds of loaded modules, so exploding those into per-index columns made
the sqlite table balloon to thousands of sparse columns — the union is taken
across every report — which made writing the table extremely slow (and could
exceed SQLite's column limit). Collapsing keeps the schema bounded (~35
columns) no matter how many/large the reports are, while preserving all data.

EventTime / UploadTime are Windows FILETIME values (100-ns ticks since
1601-01-01 UTC) — converted and formatted; the raw values are also kept.
"""
import datetime as dt
import json
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

# An indexed family key: "LoadedModule[3]", "File[0].Path", "Sig[2].Name".
# family = the name before the bracket, sub = the ".Field" after it (if any).
_INDEX_RE = re.compile(r"^(?P<family>[A-Za-z0-9_.]+)\[(?P<idx>\d+)\](?P<sub>\.[A-Za-z0-9_.]+)?$")


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

    scalars: dict[str, str] = {}
    # family -> {index -> value(str) | {sub: value}} — collapsed below so each
    # indexed family (LoadedModule, File, Sig, ...) becomes ONE json column.
    families: dict[str, dict[int, object]] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            continue
        value = value.strip()
        m = _INDEX_RE.match(key)
        if m:
            fam = m.group("family")
            idx = int(m.group("idx"))
            sub = m.group("sub")
            bucket = families.setdefault(fam, {})
            if sub:
                slot = bucket.get(idx)
                if not isinstance(slot, dict):
                    slot = {}
                    bucket[idx] = slot
                slot[sub[1:]] = value
            else:
                bucket[idx] = value
        else:
            scalars[key] = value

    row: dict = {"_source_file": str(path)}
    row.update(scalars)
    for fam, bucket in families.items():
        # ordered by index so the json array reads in report order
        row[fam] = json.dumps([bucket[i] for i in sorted(bucket)], ensure_ascii=False)

    event_dt = _filetime_to_dt(scalars.get("EventTime", ""))
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
