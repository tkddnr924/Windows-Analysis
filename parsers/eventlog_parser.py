"""Windows Event Log (.evtx) parser, similar in spirit to Eric Zimmerman's
EvtxECmd.

Uses the `evtx` package (omerbenamram/evtx, Rust-based) instead of the
older pure-Python `python-evtx`, specifically because it recovers records
around damaged chunks instead of failing the whole file — this matters
because Microsoft Message Analyzer refuses to show anything from a
corrupted evtx, while EZ's tools still surface what they can. A corrupted
chunk is emitted here as its own row (_status="corrupted_chunk") rather
than silently dropped, so a broken log is still visible instead of vanishing.

Output is ONE table per source .evtx (Security.evtx -> Security.sqlite),
keyed by the log's filename, rather than one merged EventLog table. This
keeps the parsed output 1:1 with the collected logs — a Security log and an
Application log stay distinct artifacts, the way an analyst reasons about
them — instead of flattening 300+ logs into a single blob.
"""
import contextlib
import json
import logging
import os

# The evtx (pyevtx-rs) native parser logs a warning for every EventData field
# whose bytes aren't valid UTF-8 ("could not parse data as string, formating to
# hex: ..."). It recovers by hex-encoding the value — the parsed data is fine —
# but on a real system this floods the viewer's streamed pipeline log. Quiet
# the native logger's env_logger path here, before it initializes on import.
os.environ.setdefault("RUST_LOG", "off")

from pathlib import Path

from evtx import PyEvtxParser

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "EventLog"
EXTENSIONS = [".evtx"]

# A collected machine ships 300+ .evtx, almost all irrelevant to an intrusion.
# Parsing every one buries the analyst and bloats the case, so only the logs
# that actually carry incident evidence are parsed — matched by exact filename
# (case-insensitive) via the registry's find_files_by_name. Names use the
# on-disk "%4" escaping for "/". To widen coverage, add filenames here.
ALLOWLIST = [
    # --- Tier 1: core + primary IR ---
    "Security.evtx",                # logon/logoff, account mgmt, 4688, 1102 log-clear
    "System.evtx",                  # 7045 service install, service start/stop, boot/shutdown
    "Application.evtx",             # app crashes, some AV/install traces
    "Microsoft-Windows-PowerShell%4Operational.evtx",   # 4104 script-block logging
    "Windows PowerShell.evtx",      # engine start 400/403/600, downgrade attacks
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",     # RDP session logon/logoff 21-25/39/40
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx", # RDP auth (inbound) 1149
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",               # outbound RDP 1024/1102
    "Microsoft-Windows-Windows Defender%4Operational.evtx",     # malware detection 1116/1117, config change 5001/5007
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",        # task register/run (persistence) 106/140/141/200/201
    # --- Tier 2 (selected: SMB / BITS / Firewall) ---
    "Microsoft-Windows-SMBServer%4Security.evtx",   # inbound share access (lateral movement)
    "Microsoft-Windows-SMBServer%4Audit.evtx",
    "Microsoft-Windows-SmbClient%4Security.evtx",   # outbound SMB
    "Microsoft-Windows-Bits-Client%4Operational.evtx",  # BITS payload download
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",  # firewall rule changes
]

# Every per-file EventLog table shares this column order.
_EVENT_COLUMNS = [
    "timestamp", "Channel", "EventID", "LevelName", "Level", "Provider",
    "Computer", "EventRecordID", "ProcessID", "ThreadID", "UserID",
    "EventData", "_record_key", "_status", "_error", "_source_file",
]


class _SharedFieldOrder(dict):
    """Output table names here are dynamic (one per .evtx file), so there's no
    fixed key to look up. Return the shared EventLog column order whatever
    output name main.py asks about."""

    def get(self, key, default=None):
        return _EVENT_COLUMNS


FIELD_ORDER = _SharedFieldOrder()

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
        # EventRecordID only counts up within a single .evtx file — two
        # different logs both have a "record 50". Pair it with the source
        # filename for a value that's actually unique across the merged
        # table, so cross-artifact links (e.g. RemoteAccessHistory) can
        # jump to exactly one record instead of matching dozens.
        row["_record_key"] = f"{evtx_path.name}::{row.get('EventRecordID', '')}"
        rows.append(row)

    return rows


@contextlib.contextmanager
def _quiet_native_logs():
    """Raise the root logging threshold to ERROR for the duration of parsing,
    covering the pyo3-log routing some pyevtx-rs wheels use (the RUST_LOG env
    var above covers the env_logger routing). The evtx "formating to hex"
    warnings are recoverable-value notices, not errors, so this hides them
    without hiding genuine errors."""
    root = logging.getLogger()
    previous = root.level
    root.setLevel(logging.ERROR)
    try:
        yield
    finally:
        root.setLevel(previous)


def _output_name(evtx_path: Path, taken: set[str]) -> str:
    """Table name for one log = its filename without the .evtx extension
    (Security.evtx -> "Security"). Disambiguate the rare case of two collected
    logs sharing a name (e.g. a RegBack copy) by suffixing a counter."""
    base = evtx_path.stem or evtx_path.name
    name = base
    i = 2
    while name in taken:
        name = f"{base}_{i}"
        i += 1
    taken.add(name)
    return name


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    outputs: dict[str, list[dict]] = {}
    taken: set[str] = set()
    with _quiet_native_logs():
        for evtx_path in paths:
            try:
                rows = parse_one(evtx_path)
            except Exception as exc:
                rows = [
                    {
                        "timestamp": "",
                        "_status": "unreadable_file",
                        "_error": str(exc),
                        "_source_file": str(evtx_path),
                    }
                ]
            # A log with no records at all produces no table (would just be an
            # empty 0-byte file). Unreadable/corrupt logs still emit a status
            # row, so real problems stay visible.
            if rows:
                outputs[_output_name(evtx_path, taken)] = rows

    return outputs
