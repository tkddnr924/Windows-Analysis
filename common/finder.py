"""Locate collected artifact files under a target directory by filename.

Collected images/triage output don't have a consistent folder layout, so
artifacts are located by matching filenames (exact, case-insensitive)
rather than by expecting a fixed directory structure.
"""
import hashlib
from pathlib import Path


def dedupe_by_content(paths: list[Path]) -> list[Path]:
    """Collapse paths that are byte-identical copies of the same file down
    to one — collectors sometimes save the same underlying file under more
    than one category folder (e.g. JumpLists showing up under both a
    `JUMPLIST` folder and a `LNK\\Recent` folder), which would otherwise
    make every entry look duplicated in the parsed output."""
    seen_hashes = set()
    unique = []
    for path in paths:
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            unique.append(path)  # let the parser itself report the read failure
            continue
        if digest not in seen_hashes:
            seen_hashes.add(digest)
            unique.append(path)
    return unique


def find_files_by_name(target_dir: Path, names: list[str]) -> list[Path]:
    """Recursively find files under target_dir whose filename matches
    one of `names` (case-insensitive, exact match)."""
    wanted = {n.lower() for n in names}
    matches = []
    for path in target_dir.rglob("*"):
        if path.is_file() and path.name.lower() in wanted:
            matches.append(path)
    return matches


def find_files_by_extension(target_dir: Path, extensions: list[str]) -> list[Path]:
    """Recursively find files under target_dir whose extension matches one
    of `extensions` (case-insensitive, e.g. [".evtx"]). Used for artifacts
    that show up under many different filenames."""
    wanted = {e.lower() for e in extensions}
    matches = []
    for path in target_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in wanted:
            matches.append(path)
    return matches


_SQLITE_MAGIC = b"SQLite format 3\x00"


def find_sqlite_files(target_dir: Path, under_folder: str | None = None) -> list[Path]:
    """Recursively find real SQLite3 database files under target_dir by
    magic header bytes, not filename — browser/app SQLite databases show
    up under all kinds of names and extensions (History, "Login Data",
    Favicons, *.db, ...), and going by content is the only way to catch
    all of them without hand-maintaining a name list.

    `under_folder`, if given, restricts results to paths that have that
    folder name as one of their path segments (case-insensitive) — e.g.
    "BROWSER", to scope a scan to the collected browser-profile tree and
    skip unrelated SQLite files elsewhere (Windows notification/timeline
    databases, etc.)."""
    wanted_folder = under_folder.lower() if under_folder else None
    matches = []
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        if wanted_folder and wanted_folder not in {p.lower() for p in path.parts}:
            continue
        try:
            with open(path, "rb") as f:
                header = f.read(len(_SQLITE_MAGIC))
        except OSError:
            continue
        if header == _SQLITE_MAGIC:
            matches.append(path)
    return matches
