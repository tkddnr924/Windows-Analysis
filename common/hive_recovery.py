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
from regipy.registry import RegistryHive


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
