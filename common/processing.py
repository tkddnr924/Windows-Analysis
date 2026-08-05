"""Processing ("가공") layer — build investigative views by extracting and
correlating evidence out of the RAW parsed output (the per-hive registry
dumps, the SRUM/Amcache tables, ...). The parsers stay faithful and dumb; all
interpretation (ROT13-decoding UserAssist, pulling a FILETIME out of a BAM
blob, ...) lives here so it can be changed without re-parsing.

ExecutionHistory: "what ran on this machine", merged from every execution
artifact we can currently recover from the raw output —
  - Amcache          (installed programs + file entries)
  - UserAssist       (per-user GUI program launches; NTUSER hive dump)
  - SRUM             (per-app resource usage = the app ran)
  - BAM/DAM          (per-user last-execution time; SYSTEM hive dump)
Prefetch is included when present (its own artifact). AppCompatCache/ShimCache
is NOT yet available: regipy truncates its large REG_BINARY value to 128 bytes
in the raw dump, cutting off the entry list — recovering it needs a dedicated
raw-hive read (a follow-up).
"""
from __future__ import annotations

import codecs
import struct

from common.utils import UTC, format_timestamp

try:
    from regipy.utils import convert_wintime
except Exception:  # pragma: no cover
    convert_wintime = None


_ROW_KEYS = (
    "timestamp", "program_name", "program_path", "run_count",
    "focus_count", "focus_time_ms", "publisher", "sha1", "user", "source_artifact",
)

# UserAssist internal bookkeeping value names (after ROT13), not real launches.
_UA_MARKERS = ("UEME_CTLSESSION", "UEME_CTLCUACount:ctor")


def _row(**kw) -> dict:
    r = {k: "" for k in _ROW_KEYS}
    r.update(kw)
    return r


def _basename(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").split("\\")[-1] if path else ""


def _unhex(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except (ValueError, TypeError):
        return b""


def _filetime(value: int) -> str:
    if not value or convert_wintime is None:
        return ""
    try:
        return format_timestamp(convert_wintime(value, as_json=True), source_tz=UTC)
    except Exception:
        return ""


# --- raw-registry access helpers -------------------------------------------

def _registry_hives(all_results: dict):
    """Yield (hive_filename, [raw rows]) for every dumped registry hive. Each
    row is {key_path, value_name, value_type, value_data, last_write, ...}."""
    for fname, tables in all_results.get("Registry", {}).items():
        yield fname, tables.get("Registry", [])


def _amcache_tables(all_results: dict, table: str):
    for tables in all_results.get("Amcache", {}).values():
        yield from tables.get(table, [])


def _srum_rows(all_results: dict, table: str):
    for tables in all_results.get("SRUM", {}).values():
        yield from tables.get(table, [])


# --- per-source extractors ---------------------------------------------------

def _from_amcache(all_results: dict) -> list[dict]:
    rows = []
    for r in _amcache_tables(all_results, "Amcache_Programs"):
        rows.append(_row(
            timestamp=r.get("timestamp", ""), program_name=r.get("Name", ""),
            program_path=r.get("RootDirPath", ""), publisher=r.get("Publisher", ""),
            source_artifact="Amcache_Programs",
        ))
    for r in _amcache_tables(all_results, "Amcache_Files"):
        rows.append(_row(
            timestamp=r.get("timestamp", ""), program_name=r.get("name", ""),
            program_path=r.get("lower_case_long_path", ""), publisher=r.get("publisher", ""),
            sha1=r.get("SHA1", ""), source_artifact="Amcache_Files",
        ))
    return rows


def _from_userassist(all_results: dict) -> list[dict]:
    rows = []
    for fname, reg_rows in _registry_hives(all_results):
        if not fname.upper().endswith("NTUSER.DAT"):
            continue
        user = fname[: -len("_NTUSER.DAT")] if fname.upper().endswith("_NTUSER.DAT") else fname
        for r in reg_rows:
            kp = r.get("key_path", "")
            name = r.get("value_name", "")
            if "UserAssist" not in kp or not kp.endswith("\\Count") or name in ("", "(default)"):
                continue
            try:
                decoded = codecs.decode(name, "rot13")
            except Exception:
                decoded = name
            if decoded in _UA_MARKERS:
                continue
            data = _unhex(r.get("value_data", ""))
            run_count = focus_count = focus_ms = ""
            ts = ""
            if len(data) >= 68:
                run_count = str(struct.unpack_from("<I", data, 4)[0])
                focus_count = str(struct.unpack_from("<I", data, 8)[0])
                focus_ms = str(struct.unpack_from("<I", data, 12)[0])
                ts = _filetime(struct.unpack_from("<Q", data, 60)[0])
            rows.append(_row(
                timestamp=ts, program_name=_basename(decoded), program_path=decoded,
                run_count=run_count, focus_count=focus_count, focus_time_ms=focus_ms,
                user=user, source_artifact="UserAssist",
            ))
    return rows


def _from_bam(all_results: dict) -> list[dict]:
    rows = []
    for fname, reg_rows in _registry_hives(all_results):
        if fname.upper() != "SYSTEM":
            continue
        for r in reg_rows:
            kp = r.get("key_path", "")
            low = kp.lower()
            if "\\services\\bam" not in low or "\\usersettings\\" not in low:
                continue
            exe = r.get("value_name", "")
            if not exe.lower().endswith(".exe"):
                continue
            # …\UserSettings\<SID>\  -> the SID
            after = kp.split("UserSettings\\", 1)[-1]
            sid = after.split("\\", 1)[0]
            data = _unhex(r.get("value_data", ""))
            ts = _filetime(struct.unpack_from("<Q", data, 0)[0]) if len(data) >= 8 else ""
            rows.append(_row(
                timestamp=ts, program_name=_basename(exe), program_path=exe,
                user=sid, source_artifact="BAM",
            ))
    return rows


def _from_srum(all_results: dict) -> list[dict]:
    rows = []
    for r in _srum_rows(all_results, "SRUM_ApplicationResourceUsage"):
        app = r.get("app", "")
        rows.append(_row(
            timestamp=r.get("timestamp", ""), program_name=_basename(app) or app,
            program_path=app, user=r.get("user", ""), source_artifact="SRUM",
        ))
    return rows


def _parse_shimcache(data: bytes) -> list[tuple]:
    """Windows 8/10 AppCompatCache (ShimCache) entries: (path, last_modified
    FILETIME). Each entry starts with the '10ts' signature, then a uint32
    entry size, then path-length/path (UTF-16LE)/FILETIME. A single misaligned
    entry is skipped (path sanity check) rather than derailing the rest."""
    entries = []
    if len(data) < 4:
        return entries
    header = struct.unpack_from("<I", data, 0)[0]
    off = header if 0 < header < len(data) and data[header:header + 4] == b"10ts" else data.find(b"10ts")
    while off != -1 and off + 12 <= len(data) and data[off:off + 4] == b"10ts":
        ce_size = struct.unpack_from("<I", data, off + 8)[0]
        entry = data[off + 12 : off + 12 + ce_size]
        try:
            path_len = struct.unpack_from("<H", entry, 0)[0]
            path = entry[2 : 2 + path_len].decode("utf-16-le", "replace")
            ft = struct.unpack_from("<Q", entry, 2 + path_len)[0]
            if path and ("\\" in path or ":" in path):
                entries.append((path, ft))
        except (struct.error, IndexError):
            pass
        off += 12 + ce_size
    return entries


def _from_appcompatcache(all_results: dict) -> list[dict]:
    """AppCompatCache / ShimCache from the SYSTEM hive dump — evidence a
    program existed on / ran from a path, with the executable's last-modified
    time. Deduped across ControlSet001/002 (both keep a copy)."""
    rows = []
    seen = set()
    for fname, reg_rows in _registry_hives(all_results):
        if fname.upper() != "SYSTEM":
            continue
        for r in reg_rows:
            if r.get("value_name") != "AppCompatCache":
                continue
            for path, ft in _parse_shimcache(_unhex(r.get("value_data", ""))):
                key = (path, ft)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(_row(
                    timestamp=_filetime(ft), program_name=_basename(path),
                    program_path=path, source_artifact="AppCompatCache",
                ))
    return rows


def _from_prefetch(all_results: dict) -> list[dict]:
    rows = []
    pf = all_results.get("Prefetch", {})
    # Prefetch stays a flat {table: rows} artifact.
    for r in pf.get("Prefetch_Execution", []) if isinstance(pf, dict) else []:
        rows.append(_row(
            timestamp=r.get("last_run_time", ""), program_name=r.get("executable_filename", ""),
            run_count=r.get("run_count", ""), source_artifact="Prefetch",
        ))
    return rows


def build_execution_history(all_results: dict) -> list[dict]:
    rows: list[dict] = []
    rows += _from_amcache(all_results)
    rows += _from_userassist(all_results)
    rows += _from_srum(all_results)
    rows += _from_bam(all_results)
    rows += _from_appcompatcache(all_results)
    rows += _from_prefetch(all_results)
    return rows
