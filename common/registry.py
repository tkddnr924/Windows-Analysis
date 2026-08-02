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

# The parse stage produces the base artifacts below. Browser history/login,
# the generic browser-SQLite dump, UserAssist, and RDP client history are
# deliberately NOT parse-stage artifacts — they are "선별"(curated selections)
# derived from parsed results in a later step, so their parser modules stay
# in parsers/ but aren't registered here.
from parsers import (
    amcache_parser,
    eventlog_parser,
    jumplist_parser,
    powershell_history_parser,
    prefetch_parser,
    registry_parser,
    srum_parser,
    taskscheduler_parser,
    usnjrnl_parser,
    wer_parser,
)

from common.finder import (
    find_files_by_content,
    find_files_by_extension,
    find_files_by_name,
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


# Base parse-stage artifacts, in the order the user specified. $MFT / $LogFile
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
        name=eventlog_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(eventlog_parser.EXTENSIONS),
        parse=eventlog_parser.parse,
        field_order=eventlog_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=registry_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(registry_parser.FILENAMES),
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
        name=wer_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(wer_parser.EXTENSIONS),
        parse=wer_parser.parse,
        field_order=wer_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=taskscheduler_parser.ARTIFACT_NAME,
        find_paths=lambda target_dir: find_files_by_content(target_dir, taskscheduler_parser.TASK_NAMESPACE),
        parse=taskscheduler_parser.parse,
        field_order=taskscheduler_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=powershell_history_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(powershell_history_parser.FILENAMES),
        parse=powershell_history_parser.parse,
        field_order=powershell_history_parser.FIELD_ORDER,
    ),
]
