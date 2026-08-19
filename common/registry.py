"""Registry of known artifacts: how to locate their source files and which
parser module handles them. Add a new artifact by writing a parser module
with ARTIFACT_NAME / FIELD_ORDER / parse(paths), plus either FILENAMES
(exact filename match) or EXTENSIONS (match by extension, for artifacts
that show up under many different filenames like EventLogs), then listing
it here.

`category` controls the top-level result/ folder an artifact's CSVs land
in. Several artifacts can share one category (e.g. BrowserHistory and
BrowserLoginData both file under "Browser") so related output doesn't get
scattered across separate top-level folders. Defaults to the artifact's
own name when a category isn't given.

`subfolder` optionally nests output one level deeper within the category,
for when an artifact's output would otherwise be confusable with another
artifact's in the same category folder.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from parsers import (
    amcache_parser,
    browser_cache_parser,
    browser_history_parser,
    eventlog_parser,
    jumplist_parser,
    mft_parser,
    powershell_history_parser,
    prefetch_parser,
    rdpcache_parser,
    registry_parser,
    srum_parser,
    taskscheduler_parser,
    usnjrnl_parser,
)

from common.finder import (
    find_files_by_content,
    find_files_by_extension,
    find_files_by_name,
    find_files_by_suffix,
)


@dataclass
class ArtifactDefinition:
    name: str
    find_paths: Callable[[Path], list[Path]]
    parse: Callable[[list[Path]], dict[str, list[dict]]]
    field_order: dict[str, list[str]] = field(default_factory=dict)
    category: str = ""
    subfolder: str = ""

    def __post_init__(self):
        if not self.category:
            self.category = self.name


def _by_filenames(names: list[str]) -> Callable[[Path], list[Path]]:
    return lambda target_dir: find_files_by_name(target_dir, names)


def _by_extensions(extensions: list[str]) -> Callable[[Path], list[Path]]:
    return lambda target_dir: find_files_by_extension(target_dir, extensions)


# Base parse-stage artifacts, in the order the user specified. $LogFile
# and Windows Defender are planned but not yet implemented.
ARTIFACTS: list[ArtifactDefinition] = [
    ArtifactDefinition(
        name=amcache_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(amcache_parser.FILENAMES),
        parse=amcache_parser.parse,
        field_order=amcache_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=prefetch_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(prefetch_parser.EXTENSIONS),
        parse=prefetch_parser.parse,
        field_order=prefetch_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        # Only the IR-relevant logs (eventlog_parser.ALLOWLIST), not all 300+
        # collected .evtx — matched by exact filename, case-insensitive.
        name=eventlog_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(eventlog_parser.ALLOWLIST),
        parse=eventlog_parser.parse,
        field_order=eventlog_parser.FIELD_ORDER,
    ),
    # Every registry hive — system hives by name (SYSTEM/SOFTWARE/SAM/...) and
    # per-user hives by suffix (NTUSER.DAT / UsrClass.dat, with or without a
    # username prefix) — is dumped to one uniform-schema sqlite per hive.
    ArtifactDefinition(
        name=registry_parser.ARTIFACT_NAME,
        find_paths=lambda target_dir: (
            find_files_by_name(target_dir, registry_parser.FILENAMES)
            + find_files_by_suffix(target_dir, registry_parser.FILE_SUFFIXES)
        ),
        parse=registry_parser.parse,
        field_order=registry_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=usnjrnl_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(usnjrnl_parser.FILENAMES),
        parse=usnjrnl_parser.parse,
        field_order=usnjrnl_parser.FIELD_ORDER,
        category="FileSystem",
    ),
    ArtifactDefinition(
        name=mft_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(mft_parser.FILENAMES),
        parse=mft_parser.parse,
        field_order=mft_parser.FIELD_ORDER,
        # Surfaced under 종합 분석(_OVERVIEW) alongside the correlation tables,
        # not as a raw FileSystem dump — it's a primary analysis view.
        category="_OVERVIEW",
    ),
    ArtifactDefinition(
        name=jumplist_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(jumplist_parser.EXTENSIONS),
        parse=jumplist_parser.parse,
        field_order=jumplist_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=srum_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(srum_parser.FILENAMES),
        parse=srum_parser.parse,
        field_order=srum_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=taskscheduler_parser.ARTIFACT_NAME,
        find_paths=lambda target_dir: find_files_by_content(target_dir, taskscheduler_parser.TASK_NAMESPACE),
        parse=taskscheduler_parser.parse,
        field_order=taskscheduler_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        # RDP bitmap cache (Cache####.bin) located by its RDP8bmp magic, so an
        # arbitrary filename/extension still matches and empty bcache files
        # are skipped.
        name=rdpcache_parser.ARTIFACT_NAME,
        find_paths=lambda target_dir: find_files_by_content(target_dir, rdpcache_parser.CONTENT_MARKER),
        parse=rdpcache_parser.parse,
        field_order=rdpcache_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=powershell_history_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(powershell_history_parser.FILENAMES),
        parse=powershell_history_parser.parse,
        field_order=powershell_history_parser.FIELD_ORDER,
    ),
    # Chrome "History" SQLite DB, one sqlite per account (its tables copied
    # as-is). Only the History database for now.
    ArtifactDefinition(
        name=browser_history_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(browser_history_parser.FILENAMES),
        parse=browser_history_parser.parse,
        field_order=browser_history_parser.FIELD_ORDER,
        category="Browser",
    ),
    ArtifactDefinition(
        name=browser_cache_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(browser_cache_parser.FILENAMES),
        parse=browser_cache_parser.parse,
        field_order=browser_cache_parser.FIELD_ORDER,
        category="Browser",
    ),
]
