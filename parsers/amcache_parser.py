"""Amcache.hve parser, similar to Eric Zimmerman's AmcacheParser.

Supports both the Windows 10+ format (Root\\InventoryApplication /
Root\\InventoryApplicationFile) and the legacy format
(Root\\Programs / Root\\File).
"""
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.plugins.amcache.amcache import AmCachePlugin
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from common.hbin_carver import find_deleted_keys
from common.hive_recovery import open_hive
from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "Amcache"
FILENAMES = ["Amcache.hve"]

# Values that only appear on a genuine InventoryApplication (Program) entry,
# as opposed to an InventoryApplicationFile (File) entry — both carry
# "Name"/"ProgramId", so this is needed to tell them apart when carving.
_PROGRAM_SCHEMA_FIELDS = ("ProgramId", "Name", "ProgramInstanceId")

# Time columns always lead a CSV, most-representative timestamp first.
FIELD_ORDER = {
    "Amcache_Programs": [
        "timestamp", "InstallDate", "MsiInstallDate",
        "Name", "Version", "Publisher", "ProgramId",
        "ProgramInstanceId", "Source", "RootDirPath", "UninstallString",
        "_recovery",
    ],
    "Amcache_Files": [
        "timestamp", "link_date", "last_modified_timestamp",
        "created_timestamp", "last_modified_timestamp_2",
        "name", "lower_case_long_path", "original_file_name", "publisher",
        "product_name", "version", "product_version", "bin_file_version",
        "bin_product_version", "size", "SHA1", "program_id", "file_id",
        "binary_type", "language", "usn",
    ],
}

# All Amcache time fields are UTC:
# - "timestamp" comes from the registry key's FILETIME last-write time,
#   which is UTC by definition (and arrives here already tz-aware).
# - link_date/*InstallDate are naive "MM/DD/YYYY HH:MM:SS" REG_SZ strings
#   sourced from PE header build times / MSI-inventory telemetry, which
#   Amcache records in UTC (consistent with the hive's own FILETIME data).
_TIME_FIELDS = (
    "timestamp", "link_date", "last_modified_timestamp",
    "created_timestamp", "last_modified_timestamp_2",
    "InstallDate", "MsiInstallDate",
)


def _apply_time_format(row: dict) -> dict:
    for field in _TIME_FIELDS:
        if field in row:
            row[field] = format_timestamp(row[field], source_tz=UTC)
    return row


def _key_values_to_dict(key) -> dict:
    return {v.name: v.value for v in key.iter_values(as_json=True)}


def _parse_programs(hive: RegistryHive) -> list[dict]:
    """Root\\InventoryApplication (Win10+) or Root\\Programs (older format)."""
    for key_path in (r"\Root\InventoryApplication", r"\Root\Programs"):
        try:
            key = hive.get_key(key_path)
        except RegistryKeyNotFoundException:
            continue

        entries = []
        for sub in key.iter_subkeys():
            entry = _key_values_to_dict(sub)
            entry["timestamp"] = convert_wintime(sub.header.last_modified, as_json=True)
            entry["_recovery"] = "live"
            entries.append(entry)
        return entries
    return []


def _parse_deleted_programs(hive: RegistryHive, live_program_ids: set) -> list[dict]:
    """Recover Program entries from deleted-but-not-overwritten hbin cells
    (see common/hbin_carver.py). Only entries whose full Program-schema
    field set survived intact are kept — a partially overwritten record is
    dropped rather than emitted with missing/corrupted fields."""
    entries = []
    for carved in find_deleted_keys(hive):
        if not all(field in carved.values for field in _PROGRAM_SCHEMA_FIELDS):
            continue
        program_id = carved.values.get("ProgramId")
        if program_id in live_program_ids:
            continue

        entry = dict(carved.values)
        entry["timestamp"] = convert_wintime(carved.last_modified, as_json=True)
        entry["_recovery"] = "carved_deleted_cell"
        entries.append(entry)
        live_program_ids.add(program_id)
    return entries


def _parse_files(hive: RegistryHive) -> list[dict]:
    """Root\\File (older format) and/or Root\\InventoryApplicationFile (Win10+)."""
    plugin = AmCachePlugin(hive, as_json=True)
    plugin.run()

    entries = []
    for entry in plugin.entries:
        if isinstance(entry, dict):
            entries.append(entry)
        else:
            # regipy falls back to the raw registry key object for a handful
            # of older-format subkeys that hold values directly.
            entries.append(_key_values_to_dict(entry))

    for entry in entries:
        if "sha1" in entry:
            entry["SHA1"] = entry.pop("sha1")

    return entries


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    all_programs, all_files = [], []
    for hive_path in paths:
        with open_hive(hive_path) as hive:
            programs = _parse_programs(hive)
            live_program_ids = {row.get("ProgramId") for row in programs}
            programs += _parse_deleted_programs(hive, live_program_ids)
            programs = [_apply_time_format(row) for row in programs]

            files = [_apply_time_format(row) for row in _parse_files(hive)]

        for row in programs:
            row["_source_file"] = str(hive_path)
        for row in files:
            row["_source_file"] = str(hive_path)

        all_programs.extend(programs)
        all_files.extend(files)

    return {
        "Amcache_Programs": all_programs,
        "Amcache_Files": all_files,
    }
