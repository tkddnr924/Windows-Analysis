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


@contextmanager
def open_hive(hive_path: Path):
    """Yield a RegistryHive for `hive_path`, replaying .LOG1/.LOG2
    transaction logs first if they exist next to it. Falls back to the
    unmodified hive if no logs are present or recovery fails."""
    log1 = hive_path.with_name(hive_path.name + ".LOG1")
    log2 = hive_path.with_name(hive_path.name + ".LOG2")

    if not log1.exists():
        yield RegistryHive(str(hive_path))
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        restored_path = Path(tmp_dir) / f"{hive_path.name}.restored"
        try:
            _, recovered_pages = apply_transaction_logs(
                str(hive_path),
                str(log1),
                str(log2) if log2.exists() else None,
                restored_hive_path=str(restored_path),
            )
            print(f"    [log-replay] recovered {recovered_pages} dirty page(s) for {hive_path.name}")
            yield RegistryHive(str(restored_path))
        except Exception as exc:
            print(f"    [log-replay] failed for {hive_path.name} ({exc}); using base hive as-is")
            yield RegistryHive(str(hive_path))
