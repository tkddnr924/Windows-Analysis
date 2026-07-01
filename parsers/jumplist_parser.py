"""Windows JumpList parser (AutomaticDestinations-ms / CustomDestinations-ms),
similar in spirit to Eric Zimmerman's JLECmd.

AutomaticDestinations-ms files are OLE compound files (`olefile`): a
"DestList" stream (MRU bookkeeping — not parsed yet, see below) plus one
stream per jump list entry, each holding a raw Shell Link (.lnk)
structure, parsed with `LnkParse3`.

CustomDestinations-ms files are NOT OLE containers — they're just LNK
structures concatenated back-to-back with a small header/footer around
them, and no widely-used Python library parses that container format
directly. Since a LNK structure is self-describing (its own size fields
mark where it ends), this scans the raw bytes for the LNK header
signature and hands `LnkParse3` everything from each match onward — it
reads exactly one LNK's worth and ignores the trailing bytes, so this
works without needing to model CustomDestinations' own framing.

Scope note: DestList's own "last used in this jump list" timestamp/pin
status/access-count isn't parsed here — only each entry's own LNK header
times (creation/accessed/modified) and target info. That's a real gap
versus JLECmd but a deliberate one for this first pass; DestList is a
distinct, fiddlier binary format that can be added as a follow-up.

A stream/entry that fails to parse is recorded as its own row with
_status="corrupted" rather than silently skipped.
"""
from pathlib import Path

import olefile
from LnkParse3.lnk_file import LnkFile

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "JumpList"
EXTENSIONS = [".automaticDestinations-ms", ".customDestinations-ms"]

FIELD_ORDER = {
    "JumpList_Entries": [
        "timestamp", "created_time", "modified_time", "app_id",
        "jumplist_type", "target_path", "arguments", "working_directory",
        "machine_id", "stream_id", "_status", "_error", "_source_file",
    ],
}

# Shell Link header: HeaderSize(4 bytes, always 0x4C) + CLSID
# 00021401-0000-0000-C000-000000000046 in on-disk byte order.
_LNK_SIGNATURE = bytes.fromhex("4c0000000114020000000000c0000000000000 46".replace(" ", ""))

# LNK header times are already UTC (FILETIME) — LnkParse3 returns them as
# tz-aware ISO strings ("...+00:00"), so format_timestamp trusts that
# embedded offset rather than needing a source_tz guess.
_TIME_FIELDS = ("timestamp", "created_time", "modified_time")


def _fmt(value) -> str:
    return format_timestamp(value, source_tz=UTC) if value else ""


def _extract_target_path(parsed: dict) -> str:
    link_info = parsed.get("link_info") or {}
    base_path = link_info.get("local_base_path")
    if base_path:
        return base_path + (link_info.get("common_path_suffix") or "")

    relative_path = (parsed.get("data") or {}).get("relative_path")
    if relative_path:
        return relative_path

    items = (parsed.get("target") or {}).get("items") or []
    names = [
        item.get("primary_name") or item.get("long_name") or item.get("volume_name")
        for item in items
    ]
    names = [n for n in names if n]
    return "\\".join(names)


def _row_from_lnk(parsed: dict, app_id: str, jumplist_type: str, stream_id: str, source_file: str) -> dict:
    header = parsed.get("header") or {}
    data = parsed.get("data") or {}
    tracker = (parsed.get("extra") or {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
    return {
        "timestamp": _fmt(header.get("accessed_time")),
        "created_time": _fmt(header.get("creation_time")),
        "modified_time": _fmt(header.get("modified_time")),
        "app_id": app_id,
        "jumplist_type": jumplist_type,
        "target_path": _extract_target_path(parsed),
        "arguments": data.get("command_line_arguments") or "",
        "working_directory": data.get("working_directory") or "",
        "machine_id": tracker.get("machine_identifier") or "",
        "stream_id": stream_id,
        "_status": "ok",
        "_error": "",
        "_source_file": source_file,
    }


def _error_row(app_id: str, jumplist_type: str, stream_id: str, source_file: str, error: Exception) -> dict:
    return {
        "timestamp": "",
        "app_id": app_id,
        "jumplist_type": jumplist_type,
        "stream_id": stream_id,
        "_status": "corrupted",
        "_error": str(error),
        "_source_file": source_file,
    }


def _parse_automatic(path: Path) -> list[dict]:
    app_id = path.stem
    source_file = str(path)
    rows = []

    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as exc:
        return [_error_row(app_id, "Automatic", "", source_file, exc)]

    try:
        stream_names = [s[0] for s in ole.listdir() if s[0] not in ("DestList", "DestListPropertyStore")]
        for stream_id in stream_names:
            try:
                data = ole.openstream(stream_id).read()
                parsed = LnkFile(indata=data, cp="utf-8").get_json()
                rows.append(_row_from_lnk(parsed, app_id, "Automatic", stream_id, source_file))
            except Exception as exc:
                rows.append(_error_row(app_id, "Automatic", stream_id, source_file, exc))
    finally:
        ole.close()

    return rows


def _parse_custom(path: Path) -> list[dict]:
    app_id = path.stem
    source_file = str(path)
    data = path.read_bytes()

    offsets = []
    start = 0
    while True:
        idx = data.find(_LNK_SIGNATURE, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    rows = []
    for i, offset in enumerate(offsets):
        stream_id = str(i)
        try:
            parsed = LnkFile(indata=data[offset:], cp="utf-8").get_json()
            rows.append(_row_from_lnk(parsed, app_id, "Custom", stream_id, source_file))
        except Exception as exc:
            rows.append(_error_row(app_id, "Custom", stream_id, source_file, exc))

    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    entries = []
    for path in paths:
        if path.suffix.lower() == ".automaticdestinations-ms":
            entries.extend(_parse_automatic(path))
        else:
            entries.extend(_parse_custom(path))

    return {"JumpList_Entries": entries}
