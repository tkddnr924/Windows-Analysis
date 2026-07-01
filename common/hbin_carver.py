"""Carve deleted-but-not-yet-overwritten registry keys out of a hive.

Deleting a registry key only marks its hbin cell as "free" (unallocated);
Windows does not wipe the bytes. The old data survives until something
else reuses that space. regipy's normal traversal (get_key/iter_subkeys)
only follows the live key tree via allocated cells, so it can never see
these. This matters in practice for self-updating apps (Squirrel-based
installers like Discord/Slack/Claude) that write a brand-new registry key
per version: the previous version's key becomes exactly this kind of
orphaned, recoverable free-cell data. Eric Zimmerman's tools carve this by
default; this module does the equivalent for regipy-based parsers.

This is opportunistic recovery, not a source of truth: a carved record's
bytes may be partially overwritten by later writes, with no reliable way
to detect that beyond "did every field parse cleanly". Callers should tag
carved rows so analysts can tell them apart from live-tree data.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass

from construct import Int32sl
from regipy.registry import Cell, NKRecord, REGF_HEADER_SIZE
from regipy.structs import HBIN_HEADER

_NK_SIGNATURE = b"nk"
_MAX_SANE_NAME_LEN = 512
_MAX_SANE_COUNT = 100_000


@dataclass
class CarvedKey:
    offset: int
    name: str
    values: dict
    last_modified: int  # raw FILETIME (100ns since 1601-01-01), same as a live key's header.last_modified


@contextmanager
def _quiet_regipy_logger():
    """Carving deliberately probes free cells, most of which are garbage
    or partially overwritten — regipy logs each rejected VK as an error
    ("registry hive is probably corrupted"), which is just noise here
    since _safe_values() already treats that as an expected reject."""
    target = logging.getLogger("regipy.registry")
    previous_level = target.level
    target.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        target.setLevel(previous_level)


def find_deleted_keys(hive) -> list[CarvedKey]:
    """Scan every hbin in `hive` for free cells that look like orphaned
    CM_KEY_NODE ("nk") records, and return the ones whose header stats and
    values all parse cleanly."""
    stream = hive._stream
    data_start = REGF_HEADER_SIZE
    data_end = data_start + hive.header.hive_bins_data_size

    found = []
    with _quiet_regipy_logger():
        hbin_start = data_start
        while hbin_start < data_end:
            stream.seek(hbin_start)
            try:
                hbin_header = HBIN_HEADER.parse_stream(stream)
            except Exception:
                break
            hbin_size = hbin_header.size
            if hbin_size <= 0:
                break

            for cell_offset, is_allocated in _iter_hbin_cells(stream, hbin_start, hbin_size):
                if is_allocated:
                    continue  # live cells are already covered by normal traversal

                stream.seek(cell_offset)
                if stream.read(2) != _NK_SIGNATURE:
                    continue

                try:
                    cell = Cell(cell_type="nk", offset=cell_offset + 2, size=0)
                    nk_record = NKRecord(cell, stream)
                except Exception:
                    continue

                if not _looks_sane(nk_record):
                    continue

                values = _safe_values(nk_record)
                if not values:
                    continue

                found.append(
                    CarvedKey(
                        offset=cell_offset,
                        name=nk_record.name,
                        values=values,
                        last_modified=nk_record.header.last_modified,
                    )
                )

            hbin_start += hbin_size

    return found


def _iter_hbin_cells(stream, hbin_start: int, hbin_size: int):
    """Yield (offset_past_size_field, is_allocated) for every cell in one
    hbin, correctly advancing past each cell regardless of allocation
    state. (regipy's own HBin.iter_cells never advances past free cells,
    so it can't be reused for a full free+allocated walk.)"""
    end = hbin_start + hbin_size
    offset = hbin_start + HBIN_HEADER.sizeof()

    while offset + 4 <= end:
        stream.seek(offset)
        raw_size = Int32sl.parse_stream(stream)
        cell_size = abs(raw_size)
        if cell_size < 8 or offset + cell_size > end:
            break  # corrupted cell length; stop scanning this hbin
        yield offset + 4, raw_size < 0
        offset += cell_size


def _looks_sane(nk_record: NKRecord) -> bool:
    name = nk_record.name or ""
    if not name or len(name) > _MAX_SANE_NAME_LEN:
        return False
    if nk_record.header.subkey_count > _MAX_SANE_COUNT or nk_record.header.values_count > _MAX_SANE_COUNT:
        return False
    return True


def _safe_values(nk_record: NKRecord) -> dict | None:
    try:
        return {v.name: v.value for v in nk_record.iter_values(as_json=True)}
    except Exception:
        return None
