"""UserAssist execution history — ROT13-encoded GUI program launch records
under HKCU\\...\\UserAssist, similar in spirit to Eric Zimmerman's UserAssist
parser (or RegRipper's userassist plugin). Covers every collected per-user
NTUSER.DAT, tagging each row with the account it came from.

Each GUID subkey under UserAssist groups a different launch surface (UWP
tile launches vs. classic .exe/.lnk shortcuts); every one is walked rather
than assuming a fixed GUID set, since which GUIDs exist shifts across
Windows versions.

Value names are ROT13-encoded; two special names (UEME_CTLSESSION,
UEME_CTLCUACount:ctor) are internal bookkeeping counters, not real
program-launch records, and are excluded.

The 72-byte value layout (Vista+) — offset 4 = run count, 8 = focus count,
12 = focus time in ms, 60 = FILETIME of last execution — was verified
against this project's own real Windows 10/11 data by unpacking sample
entries and confirming the decoded timestamps land in the same activity
window as this dataset's other artifacts (Prefetch/Amcache/BrowserHistory),
not assumed from documentation alone.
"""
import codecs
import struct
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from common.hive_recovery import open_hive
from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "UserAssist"
FILE_SUFFIXES = ["_NTUSER.DAT"]

FIELD_ORDER = {
    "UserAssist_Execution": [
        "timestamp", "program_path", "run_count", "focus_count",
        "focus_time_ms", "user", "_source_file",
    ],
}

# Internal UserAssist bookkeeping entries, not real program launches.
_INTERNAL_MARKERS = ("UEME_CTLSESSION", "UEME_CTLCUACount:ctor")


def _user_from_filename(path: Path) -> str:
    suffix = "_NTUSER.DAT"
    if path.name.upper().endswith(suffix.upper()):
        return path.name[: -len(suffix)]
    return path.name


def _parse_hive(hive: RegistryHive, user: str, source_file: str) -> list[dict]:
    rows = []
    try:
        key = hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    except RegistryKeyNotFoundException:
        return rows

    for guid_key in key.iter_subkeys():
        try:
            count_key = guid_key.get_subkey("Count")
        except Exception:
            continue

        for value in count_key.iter_values(as_json=True):
            try:
                name = codecs.decode(value.name, "rot13")
            except Exception:
                name = value.name
            if name in _INTERNAL_MARKERS:
                continue

            raw = value.value
            if not isinstance(raw, str):
                continue
            try:
                data = bytes.fromhex(raw)
            except ValueError:
                continue
            if len(data) < 68:
                continue

            run_count = struct.unpack_from("<I", data, 4)[0]
            focus_count = struct.unpack_from("<I", data, 8)[0]
            focus_time_ms = struct.unpack_from("<I", data, 12)[0]
            filetime = struct.unpack_from("<Q", data, 60)[0]

            rows.append(
                {
                    "timestamp": format_timestamp(convert_wintime(filetime, as_json=True), source_tz=UTC) if filetime else "",
                    "program_path": name,
                    "run_count": run_count,
                    "focus_count": focus_count,
                    "focus_time_ms": focus_time_ms,
                    "user": user,
                    "_source_file": source_file,
                }
            )
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows = []
    for path in paths:
        user = _user_from_filename(path)
        source_file = str(path)
        try:
            with open_hive(path) as hive:
                rows.extend(_parse_hive(hive, user, source_file))
        except Exception as exc:
            rows.append(
                {
                    "timestamp": "",
                    "program_path": "",
                    "run_count": "",
                    "focus_count": "",
                    "focus_time_ms": "",
                    "user": user,
                    "_source_file": source_file,
                    "_status": "unreadable_file",
                    "_error": str(exc),
                }
            )
    return {"UserAssist_Execution": rows}
