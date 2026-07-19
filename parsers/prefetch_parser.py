"""Windows Prefetch (.pf) parser, similar in spirit to Eric Zimmerman's
PECmd.

Windows 10/11 prefetch files are MAM-compressed (Xpress Huffman); `pyscca`
(libyal's libscca Python bindings) auto-decompresses and parses the SCCA
structure transparently, so no separate decompression step is needed.

Two outputs:
- Prefetch_Execution: one row per .pf file — last run time (and up to 7
  earlier run times Windows 8+ tracks), run count, and the volume the
  executable ran from.
- Prefetch_LoadedFiles: one row per (executable, referenced file) pair —
  every DLL/resource the executable touched during the run(s) prefetch
  traced, useful for correlating what a given binary actually loaded.

Only the first volume record is used for Prefetch_Execution's volume
columns — a .pf file can reference more than one volume if the executable
ran from different volumes across its history, but that's not split out
here yet.

A .pf that fails to open/parse (corrupted, decompression failure, unknown
format version) is recorded as its own row with _status="corrupted"
rather than silently skipped.
"""
from pathlib import Path

import pyscca
from regipy.utils import convert_wintime

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "Prefetch"
EXTENSIONS = [".pf"]

FIELD_ORDER = {
    "Prefetch_Execution": [
        "last_run_time", "run_time_2", "run_time_3", "run_time_4",
        "run_time_5", "run_time_6", "run_time_7", "run_time_8",
        "executable_filename", "prefetch_hash", "run_count", "format_version",
        "volume_device_path", "volume_serial_number", "volume_creation_time",
        "_status", "_error", "_source_file",
    ],
    "Prefetch_LoadedFiles": [
        "executable_filename", "prefetch_hash", "loaded_filename",
        "file_reference", "_source_file",
    ],
}

# SCCA last-run-time / volume-creation-time fields are raw Windows FILETIME
# (100ns since 1601-01-01 UTC) — unambiguous UTC by definition.
_TIME_FIELDS = (
    "last_run_time", "run_time_2", "run_time_3", "run_time_4",
    "run_time_5", "run_time_6", "run_time_7", "run_time_8",
    "volume_creation_time",
)


def _fmt(filetime: int) -> str:
    if not filetime:
        return ""
    return format_timestamp(convert_wintime(filetime, as_json=True), source_tz=UTC)


def _run_times(scca) -> list[int]:
    times = []
    for i in range(8):
        try:
            times.append(scca.get_last_run_time_as_integer(i))
        except Exception:
            break
    return (times + [0] * 8)[:8]


def _parse_one(path: Path) -> tuple[dict, list[dict]]:
    source_file = str(path)
    scca = pyscca.file()
    scca.open(str(path.resolve()))

    run_times = _run_times(scca)
    executable_filename = scca.get_executable_filename() or ""
    prefetch_hash = f"{scca.get_prefetch_hash():08X}" if scca.get_prefetch_hash() is not None else ""

    volume_device_path = volume_serial_number = volume_creation_time = ""
    if scca.get_number_of_volumes():
        vol = scca.get_volume_information(0)
        volume_device_path = vol.get_device_path() or ""
        serial = vol.get_serial_number()
        volume_serial_number = f"{serial:08X}" if serial is not None else ""
        volume_creation_time = vol.get_creation_time_as_integer()

    execution_row = {
        "last_run_time": _fmt(run_times[0]),
        "run_time_2": _fmt(run_times[1]),
        "run_time_3": _fmt(run_times[2]),
        "run_time_4": _fmt(run_times[3]),
        "run_time_5": _fmt(run_times[4]),
        "run_time_6": _fmt(run_times[5]),
        "run_time_7": _fmt(run_times[6]),
        "run_time_8": _fmt(run_times[7]),
        "executable_filename": executable_filename,
        "prefetch_hash": prefetch_hash,
        "run_count": scca.get_run_count(),
        "format_version": scca.get_format_version(),
        "volume_device_path": volume_device_path,
        "volume_serial_number": volume_serial_number,
        "volume_creation_time": _fmt(volume_creation_time) if volume_creation_time else "",
        "_status": "ok",
        "_error": "",
        "_source_file": source_file,
    }

    loaded_file_rows = []
    for i in range(scca.get_number_of_file_metrics_entries()):
        entry = scca.get_file_metrics_entry(i)
        loaded_file_rows.append(
            {
                "executable_filename": executable_filename,
                "prefetch_hash": prefetch_hash,
                "loaded_filename": entry.get_filename() or "",
                "file_reference": entry.get_file_reference(),
                "_source_file": source_file,
            }
        )

    scca.close()
    return execution_row, loaded_file_rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    execution_rows = []
    loaded_file_rows = []

    for path in paths:
        try:
            execution_row, entries = _parse_one(path)
        except Exception as exc:
            execution_rows.append(
                {
                    "last_run_time": "",
                    "_status": "corrupted",
                    "_error": str(exc),
                    "_source_file": str(path),
                }
            )
            continue

        execution_rows.append(execution_row)
        loaded_file_rows.extend(entries)

    return {
        "Prefetch_Execution": execution_rows,
        "Prefetch_LoadedFiles": loaded_file_rows,
    }
