"""Windows Event Log (.evtx) parser, similar in spirit to Eric Zimmerman's
EvtxECmd.

Uses the `evtx` package (omerbenamram/evtx, Rust-based) instead of the
older pure-Python `python-evtx`, specifically because it recovers records
around damaged chunks instead of failing the whole file — this matters
because Microsoft Message Analyzer refuses to show anything from a
corrupted evtx, while EZ's tools still surface what they can. A corrupted
chunk is emitted here as its own row (_status="corrupted_chunk") rather
than silently dropped, so a broken log is still visible in the CSV instead
of just vanishing.
"""
import json
from pathlib import Path

from evtx import PyEvtxParser

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "EventLog"
EXTENSIONS = [".evtx"]

FIELD_ORDER = {
    "EventLog_Events": [
        "timestamp", "Channel", "EventID", "LevelName", "Level", "Provider",
        "Computer", "EventRecordID", "ProcessID", "ThreadID", "UserID",
        "EventData", "_status", "_error", "_source_file",
    ],
}

# EVTX System.TimeCreated is always stored in UTC — Event Viewer only
# converts to local time for display, the underlying value is untouched.
_TIME_FIELDS = ("timestamp",)

_LEVEL_NAMES = {
    0: "Information",  # "LogAlways", conventionally shown as Information
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}


def _iter_records(parser: PyEvtxParser):
    """Yield every record from `parser`, tolerating both raised
    RuntimeErrors and RuntimeError-valued items — a plain for-loop over
    records_json() can abort partway through a damaged file, so this
    manually advances the iterator and keeps going past errors."""
    it = iter(parser.records_json())
    while True:
        try:
            record = next(it)
        except StopIteration:
            break
        except RuntimeError as exc:
            yield None, exc
            continue
        if isinstance(record, RuntimeError):
            yield None, record
        else:
            yield record, None


def _get(d: dict, *path, default=None):
    for key in path:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d if d is not None else default


def _scalar(value):
    """Legacy (non-manifest) events render e.g. <EventID Qualifiers="0">8231</EventID>
    as {"#attributes": {...}, "#text": 8231} instead of a plain value — unwrap it."""
    if isinstance(value, dict) and "#text" in value:
        return value["#text"]
    return value


def _flatten(event: dict) -> dict:
    system = _get(event, "Event", "System", default={})
    payload = _get(event, "Event", "EventData")
    if payload is None:
        payload = _get(event, "Event", "UserData")

    level = _scalar(_get(system, "Level"))
    return {
        "timestamp": _get(system, "TimeCreated", "#attributes", "SystemTime"),
        "Channel": _get(system, "Channel"),
        "EventID": _scalar(_get(system, "EventID")),
        "Level": level,
        "LevelName": _LEVEL_NAMES.get(level, str(level) if level is not None else ""),
        "Provider": _get(system, "Provider", "#attributes", "Name"),
        "Computer": _get(system, "Computer"),
        "EventRecordID": _get(system, "EventRecordID"),
        "ProcessID": _get(system, "Execution", "#attributes", "ProcessID"),
        "ThreadID": _get(system, "Execution", "#attributes", "ThreadID"),
        "UserID": _get(system, "Security", "#attributes", "UserID"),
        "EventData": json.dumps(payload, ensure_ascii=False) if payload is not None else "",
    }


def parse_one(evtx_path: Path) -> list[dict]:
    rows = []
    parser = PyEvtxParser(str(evtx_path))
    for record, error in _iter_records(parser):
        if error is not None:
            rows.append(
                {
                    "timestamp": "",
                    "_status": "corrupted_chunk",
                    "_error": str(error),
                    "_source_file": str(evtx_path),
                }
            )
            continue

        try:
            event = json.loads(record["data"])
            row = _flatten(event)
            if not row.get("timestamp"):
                # Fall back to the library's own timestamp field (format:
                # "2026-04-30T20:54:48.9762693Z UTC") if TimeCreated was
                # missing from the parsed XML for some reason.
                row["timestamp"] = record.get("timestamp", "").replace(" UTC", "")
            row["timestamp"] = format_timestamp(row["timestamp"], source_tz=UTC)
        except Exception as exc:
            rows.append(
                {
                    "timestamp": "",
                    "EventRecordID": record.get("event_record_id"),
                    "_status": "corrupted_record",
                    "_error": f"Failed to interpret record data: {exc}",
                    "_source_file": str(evtx_path),
                }
            )
            continue

        row["_status"] = "ok"
        row["_error"] = ""
        row["_source_file"] = str(evtx_path)
        rows.append(row)

    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    all_events = []
    for evtx_path in paths:
        try:
            all_events.extend(parse_one(evtx_path))
        except Exception as exc:
            all_events.append(
                {
                    "timestamp": "",
                    "_status": "unreadable_file",
                    "_error": str(exc),
                    "_source_file": str(evtx_path),
                }
            )

    return {"EventLog_Events": all_events}
