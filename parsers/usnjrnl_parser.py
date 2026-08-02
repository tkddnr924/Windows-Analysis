"""USN Change Journal ($UsnJrnl:$J) — NTFS's per-volume log of file/directory
changes (create, delete, rename, data change, ...). Each USN record names one
change: the file, what changed (reason flags), and when.

The $J data stream is collected as a file literally named "$J". It begins
with a large sparse (all-zero) region that is skipped; records follow,
8-byte aligned, each self-describing via its RecordLength. Both USN_RECORD_V2
(64-bit file references) and V3 (128-bit) layouts are handled.

Timestamps are FILETIME (100-ns ticks since 1601-01-01 UTC). File references
are split into their MFT entry number (low 48 bits) for readability; full
MFT-path resolution using $MFT is a later step.

"Parsing" is just turning each record into a row — no filtering or judgment.
"""
import datetime as dt
import struct
from pathlib import Path

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "UsnJrnl"
FILENAMES = ["$J"]

FIELD_ORDER = {
    "UsnJrnl_Records": [
        "timestamp", "filename", "reason", "file_attributes", "mft_entry",
        "parent_mft_entry", "usn", "source_info", "security_id",
        "file_reference", "parent_file_reference", "_source_file",
    ],
}

_REASON_FLAGS = [
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
]

_ATTR_FLAGS = [
    (0x00000001, "READONLY"),
    (0x00000002, "HIDDEN"),
    (0x00000004, "SYSTEM"),
    (0x00000010, "DIRECTORY"),
    (0x00000020, "ARCHIVE"),
    (0x00000080, "NORMAL"),
    (0x00000100, "TEMPORARY"),
    (0x00000200, "SPARSE_FILE"),
    (0x00000400, "REPARSE_POINT"),
    (0x00000800, "COMPRESSED"),
    (0x00001000, "OFFLINE"),
    (0x00004000, "ENCRYPTED"),
]


def _decode_flags(value: int, table) -> str:
    return "|".join(name for bit, name in table if value & bit)


def _filetime_to_dt(ticks: int):
    if ticks <= 0:
        return None
    return dt.datetime(1601, 1, 1, tzinfo=UTC) + dt.timedelta(microseconds=ticks / 10)


def _iter_records(data: bytes):
    pos = 0
    n = len(data)
    while pos < n:
        # Skip sparse/zero padding between records and the leading gap.
        if data[pos] == 0:
            pos += 1
            continue
        if pos + 4 > n:
            break
        reclen = struct.unpack_from("<I", data, pos)[0]
        if reclen < 60 or pos + reclen > n:
            break
        major = struct.unpack_from("<H", data, pos + 4)[0]
        try:
            if major == 2:
                file_ref, parent_ref = struct.unpack_from("<QQ", data, pos + 8)
                usn, ts, reason, source_info, security_id, attrs, name_len, name_off = struct.unpack_from(
                    "<QQIIIIHH", data, pos + 24
                )
            elif major == 3:
                # 128-bit file references; everything after shifts by 16 bytes.
                file_ref = int.from_bytes(data[pos + 8 : pos + 24], "little")
                parent_ref = int.from_bytes(data[pos + 24 : pos + 40], "little")
                usn, ts, reason, source_info, security_id, attrs, name_len, name_off = struct.unpack_from(
                    "<QQIIIIHH", data, pos + 40
                )
            else:
                pos += (reclen + 7) & ~7
                continue
            name = data[pos + name_off : pos + name_off + name_len].decode("utf-16-le", errors="replace")
        except Exception:
            pos += (reclen + 7) & ~7
            continue

        yield {
            "file_ref": file_ref,
            "parent_ref": parent_ref,
            "usn": usn,
            "ts": ts,
            "reason": reason,
            "source_info": source_info,
            "security_id": security_id,
            "attrs": attrs,
            "name": name,
        }
        pos += (reclen + 7) & ~7


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for path in paths:
        source_file = str(path)
        try:
            data = path.read_bytes()
        except Exception as exc:
            rows.append(
                {"timestamp": "", "filename": "", "_source_file": source_file, "_status": "unreadable_file", "_error": str(exc)}
            )
            continue

        for rec in _iter_records(data):
            ftime = _filetime_to_dt(rec["ts"])
            rows.append(
                {
                    "timestamp": format_timestamp(ftime, source_tz=UTC) if ftime else "",
                    "filename": rec["name"],
                    "reason": _decode_flags(rec["reason"], _REASON_FLAGS),
                    "file_attributes": _decode_flags(rec["attrs"], _ATTR_FLAGS),
                    "mft_entry": rec["file_ref"] & 0xFFFFFFFFFFFF,
                    "parent_mft_entry": rec["parent_ref"] & 0xFFFFFFFFFFFF,
                    "usn": rec["usn"],
                    "source_info": rec["source_info"],
                    "security_id": rec["security_id"],
                    "file_reference": rec["file_ref"],
                    "parent_file_reference": rec["parent_ref"],
                    "_source_file": source_file,
                }
            )
    return {"UsnJrnl_Records": rows}
