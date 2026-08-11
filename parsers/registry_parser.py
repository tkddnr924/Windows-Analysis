"""Registry hive parser — a faithful, uniform dump of EVERY key and value in a
hive. One sqlite per source hive (SOFTWARE.sqlite, SYSTEM.sqlite, SAM.sqlite,
<user>_NTUSER.DAT.sqlite, ...), each with the SAME single-table schema:

    last_write | key_path | value_name | value_type | value_data

This is the raw layer: the parsed output stays 1:1 with the source hive and
makes no interpretation. Pulling specific artifacts out of it (local accounts,
UserAssist run counts, autostart entries, network config, RDP client history,
...) is a later "processing" step that reads these dumps — not something the
parser decides. Because every hive dumps to the same schema, that processing
step can treat SAM.sqlite, SOFTWARE.sqlite and every NTUSER.DAT.sqlite
identically.

`last_write` is the containing key's last-write time (the registry stores no
per-key creation time); "-" when a hive doesn't provide one.
"""
import json
import logging
from pathlib import Path

from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from common.hive_recovery import open_hive
from common.utils import UTC, format_timestamp

# regipy is chatty on a full-hive dump: a warning for every binary value it
# can't render as text, and an ERROR ("Could not parse VK at …, registry hive
# is probably corrupted.") for every damaged/slack cell it hits near a hive's
# tail. Neither is fatal — _collect() keeps everything read before the bad cell
# and _dump_hive() records the damage in-band as a `_status=corrupted` row — so
# it's pure console noise. Silence regipy entirely (CRITICAL) and rely on the
# in-data damage markers instead.
logging.getLogger("regipy").setLevel(logging.CRITICAL)

ARTIFACT_NAME = "Registry"
# System hives by exact name; per-user hives by suffix (the collector prefixes
# them with the account, e.g. "Administrator_NTUSER.DAT", but they can also be
# a bare "NTUSER.DAT").
FILENAMES = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"]
FILE_SUFFIXES = ["NTUSER.DAT", "USRCLASS.DAT"]

_TABLE = "Registry"
FIELD_ORDER = {
    _TABLE: ["last_write", "key_path", "value_name", "value_type", "value_data", "_source_file"],
}


def _has_control(s: str) -> bool:
    return any(ch == "\x00" or (ord(ch) < 32 and ch not in "\t\n\r") for ch in s)


def _clean(value) -> str:
    """Coerce any key name / value into clean plaintext for storage.

    regipy is inconsistent for binary data — sometimes a hex string, sometimes
    a raw byte-string with embedded NULs. A string with embedded NULs/control
    bytes is stored by sqlite as TEXT but shows up as a BLOB in viewers and is
    effectively unreadable, so anything binary is rendered as hex (the standard
    representation for REG_BINARY). A REG_SZ's common trailing NUL is stripped
    first so ordinary text ("en\\x00") stays text, not hex."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, default=str)
    s = str(value).rstrip("\x00")
    if _has_control(s):
        # Binary content (raw REG_BINARY, or a corrupted key name) — hex it so
        # the cell is clean, readable text instead of a BLOB.
        return s.encode("latin-1", "replace").hex()
    return s


# Runaway backstops for corruption-induced cycles/garbage (a damaged cell can
# point back up the tree, or spawn bogus subkeys). Set far above any real
# hive so genuine data is never clipped — they only stop a pathological loop.
_MAX_ROWS = 10_000_000
_MAX_DEPTH = 512


def _collect(iterator) -> tuple[list, bool]:
    """Drain a regipy iterator one item at a time, keeping everything read
    before any error. Returns (items, truncated) — `truncated` True if it died
    partway, so the caller can flag where the hive became unreadable. (list()
    would lose the whole batch on a single bad entry; this keeps the good part
    — the point of 'recover as much as is visible'.)"""
    items = []
    truncated = False
    try:
        it = iter(iterator)
    except Exception:
        return items, True
    while True:
        try:
            items.append(next(it))
        except StopIteration:
            break
        except Exception:
            truncated = True
            break
    return items, truncated


def _key_rows(key, path: str, source_file: str) -> list[dict]:
    try:
        last_write = format_timestamp(convert_wintime(key.header.last_modified, as_json=True), source_tz=UTC)
    except Exception:
        last_write = "-"
    # as_json=False AND trim_values=False, both deliberate:
    #   * as_json=True renders binary as a (capped) hex string;
    #   * trim_values=True (regipy's DEFAULT) hex-encodes an ordinary REG_BINARY
    #     and then truncates that hex to MAX_LEN (256) chars = 128 bytes.
    # Either one silently cut REG_BINARY off at 128 bytes — which is exactly the
    # size of a truncated SAM V/F record, so account parsing looked "genuinely"
    # capped when it was really regipy trimming. With both False regipy returns
    # the full raw bytes (e.g. a real SAM V is ~684 B, not 128) and _clean()
    # hex-encodes them, keeping the dump 1:1 with the hive.
    values, truncated = _collect(key.iter_values(as_json=False, trim_values=False))
    rows = []
    for v in values:
        try:
            rows.append(
                {
                    "last_write": last_write,
                    "key_path": path,
                    "value_name": _clean(v.name) or "(default)",
                    "value_type": v.value_type,
                    "value_data": _clean(v.value),
                    "_source_file": source_file,
                }
            )
        except Exception:
            truncated = True
            break
    if not rows:
        rows.append({"last_write": last_write, "key_path": path, "value_name": "", "value_type": "", "value_data": "", "_source_file": source_file})
    if truncated:
        rows.append({"last_write": last_write, "key_path": path, "value_name": "", "value_type": "", "value_data": "", "_source_file": source_file, "_status": "corrupted", "_error": "values truncated (hive damage)"})
    return rows


def _dump_hive(hive: RegistryHive, source_file: str) -> list[dict]:
    r"""Iterative, corruption-tolerant walk of the whole hive. regipy's own
    recurse_subkeys() raises and aborts the ENTIRE hive the moment it hits a
    damaged subkey — common in collected hives — so this walks manually and
    recovers as much as is readable: every key up to the point of damage is
    kept, damage points are flagged (_status=corrupted) rather than dropped,
    and only a pathological loop (cycle/garbage from corruption) is stopped by
    the runaway backstops."""
    rows: list[dict] = []
    root = hive.root
    stack = [(root, "\\" + _clean(getattr(root, "name", "") or ""))]
    while stack:
        key, path = stack.pop()
        rows.extend(_key_rows(key, path, source_file))
        if len(rows) >= _MAX_ROWS or path.count("\\") >= _MAX_DEPTH:
            continue
        subkeys, truncated = _collect(key.iter_subkeys())
        for sub in subkeys:
            try:
                name = sub.name
            except Exception:
                truncated = True
                break
            # A real key name never contains NUL/control bytes. When it does,
            # regipy has misread a damaged/slack hive region and handed back raw
            # cell bytes as a bogus subkey — descending into it just yields more
            # garbage (and is the source of the "Could not parse VK" storm). So
            # flag the damage point and do NOT treat it as a real key or recurse.
            if isinstance(name, bytes) or (isinstance(name, str) and _has_control(name.rstrip("\x00"))):
                rows.append({"last_write": "-", "key_path": path, "value_name": "", "value_type": "", "value_data": "", "_source_file": source_file, "_status": "corrupted", "_error": "unreadable subkey (hive damage)"})
                continue
            stack.append((sub, f"{path}\\{name}"))
        if truncated:
            rows.append({"last_write": "-", "key_path": path, "value_name": "", "value_type": "", "value_data": "", "_source_file": source_file, "_status": "corrupted", "_error": "subkeys truncated (hive damage)"})
    if len(rows) >= _MAX_ROWS:
        rows.append({"last_write": "-", "key_path": "", "value_name": "", "value_type": "", "value_data": "", "_source_file": source_file, "_status": "aborted", "_error": f"row cap {_MAX_ROWS} reached (possible corruption loop)"})
    return rows


def parse(paths: list[Path]) -> dict[str, dict[str, list[dict]]]:
    # A collection usually includes both the live hive (config\SOFTWARE) and
    # its periodic backup (config\RegBack\SOFTWARE); dumping both doubles every
    # key, so drop a RegBack copy when the live hive of the same name is present.
    live_names = {p.name.upper() for p in paths if "regback" not in {x.lower() for x in p.parts}}
    paths = [p for p in paths if "regback" not in {x.lower() for x in p.parts} or p.name.upper() not in live_names]

    outputs: dict[str, dict[str, list[dict]]] = {}
    taken: set[str] = set()
    for path in paths:
        source_file = str(path)
        try:
            with open_hive(path) as hive:
                rows = _dump_hive(hive, source_file)
        except Exception as exc:
            rows = [
                {
                    "last_write": "-",
                    "key_path": "",
                    "value_name": "",
                    "value_type": "",
                    "value_data": str(exc),
                    "_source_file": source_file,
                    "_status": "unreadable_file",
                }
            ]

        # Name the sqlite after the source hive (SOFTWARE, SAM,
        # Administrator_NTUSER.DAT, ...), disambiguating the rare duplicate.
        base = path.name
        name = base
        i = 2
        while name in taken:
            name = f"{base}_{i}"
            i += 1
        taken.add(name)
        outputs[name] = {_TABLE: rows}

    return outputs
