"""Registry hive loading with dirty-hive transaction log recovery.

Registry hives (Amcache.hve, SYSTEM, SOFTWARE, NTUSER.DAT, ...) can be
"dirty": the most recent writes may exist only in the sibling
.LOG1/.LOG2 transaction log files and not yet be flushed into the base
hive file. Parsing the base hive alone silently drops those latest
changes. Eric Zimmerman's tools replay these logs by default, so we do
the same here for parity.
"""
import tempfile
from contextlib import contextmanager
from pathlib import Path

from regipy.recovery import apply_transaction_logs
from regipy.registry import REGF_HEADER_SIZE, NKRecord, RegistryHive, VKRecord

# --- regipy performance patch -------------------------------------------------
# regipy's NKRecord.read_value() does `stream.read(vk.data_size)` without
# masking the "resident data" flag. The MAJORITY of registry values (every
# REG_DWORD and any value <=4 bytes) store their data inline in the data_offset
# field and signal it by setting bit 0x80000000 in data_size — so data_size is
# a huge number (>=0x80000000). The stock code then calls stream.read(0x8000…),
# which on the fully-in-memory hive copies every remaining byte to end-of-hive
# (tens of MB) FOR EACH such value. On a 90 MB SOFTWARE hive with tens of
# thousands of inline values that is minutes of pure memcpy — the parser looks
# frozen. iter_values() never uses this copy for resident values (it rebuilds
# them from data_offset), so we skip the read entirely; a stray cap guards a
# corrupted (non-resident) data_size from copying the whole hive too.
_RESIDENT_FLAG = 0x80000000
_READ_CAP = 0x1000000  # 16 MB — far above any real value; bounds corrupt sizes


def _fast_read_value(vk, stream):
    if vk.data_size >= _RESIDENT_FLAG:
        data = b""  # inline data lives in data_offset; iter_values reads it there
    else:
        stream.seek(REGF_HEADER_SIZE + 4 + vk.data_offset)
        data = stream.read(min(vk.data_size, _READ_CAP))
    return VKRecord(
        value_type=vk.data_type,
        value_type_str=str(vk.data_type),
        value=data,
        size=vk.data_size,
    )


NKRecord.read_value = staticmethod(_fast_read_value)
# -----------------------------------------------------------------------------


def _sibling_log(hive_path: Path, ext: str) -> Path | None:
    r"""Locate the hive's `<name>.LOG1`/`.LOG2` sibling, matched
    case-insensitively. Collectors are inconsistent about case — a hive saved
    as "Administrator_NTUSER.DAT" can have its log as
    "Administrator_ntuser.dat.LOG1" — so an exact-name lookup misses it on a
    case-sensitive filesystem. Returns the real path (correct on-disk case) or
    None."""
    want = (hive_path.name + ext).lower()
    try:
        for child in hive_path.parent.iterdir():
            if child.name.lower() == want:
                return child
    except OSError:
        return None
    return None


@contextmanager
def open_hive(hive_path: Path):
    """Yield a RegistryHive for `hive_path`, replaying .LOG1/.LOG2
    transaction logs first if they exist next to it. Falls back to the
    unmodified hive if no logs are present or recovery fails."""
    log1 = _sibling_log(hive_path, ".LOG1")
    log2 = _sibling_log(hive_path, ".LOG2")

    if log1 is None:
        yield RegistryHive(str(hive_path))
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        restored_path = Path(tmp_dir) / f"{hive_path.name}.restored"
        # Recovery failures are caught here; the yield itself is deliberately
        # outside this try block so an exception raised by *caller* code
        # (while using the yielded hive) propagates normally instead of
        # being misattributed to log replay and re-entering this except
        # clause with a second, illegal yield.
        try:
            _, recovered_pages = apply_transaction_logs(
                str(hive_path),
                str(log1),
                str(log2) if log2 else None,
                restored_hive_path=str(restored_path),
            )
            hive = RegistryHive(str(restored_path))
            print(f"    [log-replay] recovered {recovered_pages} dirty page(s) for {hive_path.name}")
        except Exception as exc:
            print(f"    [log-replay] failed for {hive_path.name} ({exc}); using base hive as-is")
            hive = RegistryHive(str(hive_path))

        yield hive
