"""NTFS $MFT parser — pulls one row per MFT record, similar in spirit to Eric
Zimmerman's MFTECmd: entry/sequence, in-use vs deleted, parent reference,
file vs directory, name, full path (resolved by walking parent references),
size, and both timestamp sets — $STANDARD_INFORMATION (0x10) and $FILE_NAME
(0x30), each with Created / Modified / MFT-modified / Accessed.

Pure-Python, no native deps, so it runs unchanged inside the frozen exe. Only
the two resident metadata attributes (0x10, 0x30) are read; $DATA runs and
index allocations are ignored — this is a metadata/timeline view, not a file
carver. Records are fixed 1024 bytes (the standard MFT record size); the
update-sequence (fixup) array is applied before reading fields.

All MFT FILETIMEs are UTC (100-ns ticks since 1601-01-01); they're converted
and formatted to the project's KST display strings, consistent with the other
artifacts.
"""
import datetime as dt
import struct
from pathlib import Path

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "MFT"
FILENAMES = ["$MFT"]

RECORD_SIZE = 1024
SECTOR = 512
ROOT_ENTRY = 5  # the "." root directory is always MFT entry 5

FIELD_ORDER = {
    "MFT_Records": [
        "path", "file_name", "extension", "is_directory", "in_use",
        "file_size", "entry", "seq", "parent_entry",
        "si_created", "si_modified", "si_mft_modified", "si_accessed",
        "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
        "_source_file",
    ],
}

_REC_HDR = struct.Struct("<4sHH8xHHHHII")  # sig, usoff, ussize, seq, links, attroff, flags, used, alloc
_ATTR_HDR = struct.Struct("<IIBBHHH")       # type, len, nonres, namelen, nameoff, flags, id
_RES_HDR = struct.Struct("<IH")             # content_len, content_off
_FILETIME = struct.Struct("<Q")
_EPOCH = dt.datetime(1601, 1, 1, tzinfo=UTC)


def _ft(raw: bytes, off: int) -> str:
    """8-byte FILETIME at raw[off:] -> formatted KST string ("" if unset)."""
    (ticks,) = _FILETIME.unpack_from(raw, off)
    if ticks <= 0:
        return ""
    try:
        d = _EPOCH + dt.timedelta(microseconds=ticks / 10)
    except (OverflowError, OSError):
        return ""
    return format_timestamp(d, source_tz=UTC)


def _apply_fixup(rec: bytearray, us_off: int, us_size: int) -> None:
    """Apply the update-sequence (fixup) array: the last 2 bytes of every
    512-byte sector are a stamp that must be swapped back to the real values
    stored in the array. Silently no-ops on a malformed array."""
    if us_size < 1 or us_off + us_size * 2 > len(rec):
        return
    for i in range(1, us_size):
        sector_end = i * SECTOR - 2
        src = us_off + i * 2
        if sector_end + 2 > len(rec) or src + 2 > len(rec):
            break
        rec[sector_end] = rec[src]
        rec[sector_end + 1] = rec[src + 1]


def _parse_record(rec: bytearray):
    """Parse one 1024-byte record. Returns a dict of raw fields (path resolved
    later), or None if it isn't a valid in-use/deleted FILE record."""
    if rec[:4] != b"FILE":
        return None
    sig, us_off, us_size, seq, _links, attr_off, flags, _used, _alloc = _REC_HDR.unpack_from(rec, 0)
    _apply_fixup(rec, us_off, us_size)

    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)

    si = None            # (created, modified, mft_modified, accessed)
    best_fn = None       # chosen $FILE_NAME dict
    best_ns = -1         # namespace priority of the chosen name

    off = attr_off
    end = len(rec)
    while off + 16 <= end:
        atype, alen, nonres, _nl, _no, _af, _aid = _ATTR_HDR.unpack_from(rec, off)
        if atype == 0xFFFFFFFF or alen < 16:
            break
        if off + alen > end:
            break
        if nonres == 0 and off + 22 <= end:  # only resident attrs carry the metadata we want
            clen, coff = _RES_HDR.unpack_from(rec, off + 16)
            c = off + coff
            if atype == 0x10 and c + 32 <= end:            # $STANDARD_INFORMATION
                si = (_ft(rec, c), _ft(rec, c + 8), _ft(rec, c + 16), _ft(rec, c + 24))
            elif atype == 0x30 and c + 66 <= end:          # $FILE_NAME
                (parent_ref,) = struct.unpack_from("<Q", rec, c)
                parent_entry = parent_ref & 0x0000FFFFFFFFFFFF
                name_len = rec[c + 64]
                namespace = rec[c + 65]
                name_bytes = rec[c + 66 : c + 66 + name_len * 2]
                try:
                    name = name_bytes.decode("utf-16-le", errors="replace")
                except Exception:
                    name = ""
                # Prefer a Win32 / Win32&DOS / POSIX name over a DOS 8.3 alias.
                prio = {1: 3, 3: 3, 0: 2, 2: 1}.get(namespace, 0)
                if prio > best_ns:
                    best_ns = prio
                    best_fn = {
                        "parent_entry": parent_entry,
                        "name": name,
                        "size": struct.unpack_from("<Q", rec, c + 48)[0],
                        "created": _ft(rec, c + 8),
                        "modified": _ft(rec, c + 16),
                        "mft_modified": _ft(rec, c + 24),
                        "accessed": _ft(rec, c + 32),
                    }
        off += alen

    if best_fn is None and si is None:
        return None  # no usable metadata (e.g. $MFT extension record)

    name = best_fn["name"] if best_fn else ""
    ext = ""
    if name and not is_dir:
        dot = name.rfind(".")
        if dot > 0:
            ext = name[dot + 1 :].lower()

    return {
        "entry": None,  # filled by caller (record index)
        "seq": seq,
        "parent_entry": best_fn["parent_entry"] if best_fn else -1,
        "in_use": "Y" if in_use else "N",
        "is_directory": "Y" if is_dir else "N",
        "file_name": name,
        "extension": ext,
        "file_size": (best_fn["size"] if best_fn and not is_dir else 0),
        "si_created": si[0] if si else "",
        "si_modified": si[1] if si else "",
        "si_mft_modified": si[2] if si else "",
        "si_accessed": si[3] if si else "",
        "fn_created": best_fn["created"] if best_fn else "",
        "fn_modified": best_fn["modified"] if best_fn else "",
        "fn_mft_modified": best_fn["mft_modified"] if best_fn else "",
        "fn_accessed": best_fn["accessed"] if best_fn else "",
    }


def _resolve_paths(rows: list[dict], by_entry: dict) -> None:
    """Fill each row's `path` by walking parent_entry references up to the root.
    Memoized; guards against cycles and dangling parents (orphans)."""
    cache: dict[int, str] = {ROOT_ENTRY: ""}

    def resolve(entry: int, guard: set) -> str:
        if entry in cache:
            return cache[entry]
        node = by_entry.get(entry)
        if node is None or entry in guard:
            return "\\$Orphan"
        guard.add(entry)
        parent = node["parent_entry"]
        base = "\\$Orphan" if parent == entry else resolve(parent, guard)
        full = base + "\\" + node["file_name"] if node["file_name"] else base
        cache[entry] = full
        return full

    for r in rows:
        e = r["entry"]
        if e == ROOT_ENTRY or r["file_name"] == ".":
            r["path"] = "\\"
            continue
        node = by_entry.get(e)
        if node is None:
            r["path"] = "\\" + r["file_name"]
            continue
        parent = r["parent_entry"]
        parent_path = cache.get(parent)
        if parent_path is None:
            parent_path = resolve(parent, set())
        p = parent_path + "\\" + r["file_name"] if r["file_name"] else parent_path
        r["path"] = p or "\\"


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for mft_path in paths:
        by_entry: dict[int, dict] = {}
        idx = 0
        with open(mft_path, "rb") as f:
            while True:
                block = f.read(RECORD_SIZE * 4096)  # ~4MB of records at a time
                if not block:
                    break
                for pos in range(0, len(block) - RECORD_SIZE + 1, RECORD_SIZE):
                    rec = bytearray(block[pos : pos + RECORD_SIZE])
                    parsed = _parse_record(rec)
                    if parsed is not None:
                        parsed["entry"] = idx
                        parsed["_source_file"] = str(mft_path)
                        rows.append(parsed)
                        by_entry[idx] = {
                            "file_name": parsed["file_name"],
                            "parent_entry": parsed["parent_entry"],
                        }
                    idx += 1
        _resolve_paths(rows, by_entry)
    return {"MFT_Records": rows}
