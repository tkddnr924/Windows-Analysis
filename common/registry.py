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
    browser_history_parser,
    browser_login_data_parser,
    eventlog_parser,
    jumplist_parser,
    sqlite_generic_parser,
)

from common.finder import find_files_by_extension, find_files_by_name, find_sqlite_files


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


ARTIFACTS: list[ArtifactDefinition] = [
    ArtifactDefinition(
        name=amcache_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(amcache_parser.FILENAMES),
        parse=amcache_parser.parse,
        field_order=amcache_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=eventlog_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(eventlog_parser.EXTENSIONS),
        parse=eventlog_parser.parse,
        field_order=eventlog_parser.FIELD_ORDER,
    ),
    ArtifactDefinition(
        name=browser_history_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(browser_history_parser.FILENAMES),
        parse=browser_history_parser.parse,
        field_order=browser_history_parser.FIELD_ORDER,
        category="Browser",
    ),
    ArtifactDefinition(
        name=browser_login_data_parser.ARTIFACT_NAME,
        find_paths=_by_filenames(browser_login_data_parser.FILENAMES),
        parse=browser_login_data_parser.parse,
        field_order=browser_login_data_parser.FIELD_ORDER,
        category="Browser",
    ),
    ArtifactDefinition(
        name="SQLite (browser)",
        find_paths=lambda target_dir: find_sqlite_files(target_dir, under_folder="BROWSER"),
        parse=sqlite_generic_parser.parse,
        field_order=sqlite_generic_parser.FIELD_ORDER,
        category="Browser",
    ),
    ArtifactDefinition(
        name=jumplist_parser.ARTIFACT_NAME,
        find_paths=_by_extensions(jumplist_parser.EXTENSIONS),
        parse=jumplist_parser.parse,
        field_order=jumplist_parser.FIELD_ORDER,
    ),
]
