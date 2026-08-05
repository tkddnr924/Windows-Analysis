"""Chrome/Chromium browsing history — the per-profile "History" SQLite
database. Raw layer, same philosophy as the registry hives: each collected
History DB is copied table-for-table into one sqlite per source (named for the
account it belongs to), with values stored exactly as they are.

That means timestamps stay in Chrome/WebKit's native epoch (microseconds since
1601-01-01) and urls/visits stay as separate tables — converting the times and
joining them into a readable browse timeline is a later "processing" step that
reads this raw output, not something the parser bakes in.

Only the "History" database is handled here (per request). It is recognised by
having a `urls` table, so an unrelated file that happens to be named "History"
is skipped rather than mis-parsed.
"""
import sqlite3
from pathlib import Path

ARTIFACT_NAME = "BrowserHistory"
FILENAMES = ["History"]

# Column order is per source table (copied as-is), so nothing fixed here.
FIELD_ORDER: dict[str, list[str]] = {}

# SQLite bookkeeping / sync-internal tables with no investigative value.
_SKIP_TABLES = {"sqlite_sequence", "sqlite_stat1", "history_sync_metadata"}


def _clean(value):
    # Chrome stores a few columns as BLOBs; hex them so the cell is clean text
    # rather than an unreadable blob (matches the registry dump's convention).
    if isinstance(value, bytes):
        return value.hex()
    return value


def _account(path: Path) -> str:
    """Account this profile belongs to — the folder right under BROWSER in the
    collected tree (…/BROWSER/<account>/CHROME/Default/History)."""
    parts = path.parts
    for i, part in enumerate(parts):
        if part.upper() == "BROWSER" and i + 1 < len(parts):
            return parts[i + 1]
    return path.parent.name


def _copy_history(path: Path):
    """Copy every user table of a Chrome History DB. Returns a {table: rows}
    dict, or None if this isn't a Chrome History database."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "urls" not in names:
            return None  # not a Chrome History DB
        tables: dict[str, list[dict]] = {}
        for table in names:
            if table in _SKIP_TABLES or table.startswith("sqlite_"):
                continue
            cur = con.execute(f'SELECT * FROM "{table}"')
            cols = [d[0] for d in cur.description]
            rows = [{c: _clean(v) for c, v in zip(cols, row)} for row in cur.fetchall()]
            if rows:
                tables[table] = rows
        return tables
    finally:
        con.close()


def parse(paths: list[Path]) -> dict[str, dict[str, list[dict]]]:
    outputs: dict[str, dict[str, list[dict]]] = {}
    taken: set[str] = set()
    for path in paths:
        try:
            tables = _copy_history(path)
        except Exception as exc:
            tables = {"_errors": [{"_source_file": str(path), "_status": "unreadable_file", "_error": str(exc)}]}
        if not tables:
            continue  # not a Chrome History DB, or empty

        base = f"{_account(path)}_Chrome_History"
        name = base
        i = 2
        while name in taken:
            name = f"{base}_{i}"
            i += 1
        taken.add(name)
        outputs[name] = tables
    return outputs
