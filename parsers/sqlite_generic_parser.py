"""Generic SQLite table dumper for the browser profile tree.

`common.finder.find_sqlite_files(target_dir, under_folder="BROWSER")`
restricts discovery to the collected `BROWSER` folder, so this only ever
sees Chromium-family browser databases (Edge, Brave, ...) — SQLite files
elsewhere in target (Windows notification/timeline databases, etc.) are
never even considered.

Dedicated parsers (browser_history_parser, browser_login_data_parser)
already produce a curated, timestamp-converted view of a few tables
(History's urls/visits/downloads/keyword_search_terms, Login Data's
logins). Dumping those same tables again here would just create
confusingly-similar near-duplicate CSVs sitting next to the curated ones,
so they're skipped — everything else (Cookies, Web Data, Favicons, Top
Sites, Shortcuts, ...) is dumped as-is, since no dedicated parser exists
for those yet.

Column values that look like Chrome-epoch timestamps ARE converted (format
+ UTC->KST), unlike a fully-unscoped generic dump: discovery is already
restricted to confirmed Chromium databases under BROWSER, so "an integer
column named *_time/*_utc/*_date, in the range a real Chrome timestamp
would fall in" is a safe bet here — the ambiguity that would exist for an
arbitrary unknown app's SQLite file doesn't apply once every file in scope
is already known to be Chromium's own schema.

BLOB columns are replaced with "<blob: N bytes>" rather than dumped raw,
since raw binary would corrupt/bloat a CSV — this keeps their presence and
size visible without embedding undecoded bytes.
"""
import sqlite3
from pathlib import Path

from common.browser_id import guess_browser_name
from common.chrome_time import chrome_timestamp
from common.sqlite_utils import decode_value, open_readonly

ARTIFACT_NAME = "SQLite"
FIELD_ORDER: dict[str, list[str]] = {}  # output columns vary per db/table; no fixed order

_ERRORS_KEY = "SQLite_Errors"

# (db filename stem, table name) pairs already covered by a dedicated
# parser's curated output — skipped here to avoid confusing near-duplicates.
_ALREADY_CURATED = {
    ("History", "urls"),
    ("History", "visits"),
    ("History", "downloads"),
    ("History", "keyword_search_terms"),
    ("Login Data", "logins"),
    ("Login Data For Account", "logins"),
}

_TIME_COLUMN_HINTS = ("time", "utc", "date")
# Chrome-epoch microseconds corresponding to roughly year 1990 .. 2100 —
# outside this range a "*_time"-named integer is more likely a counter,
# duration, or something else that just happens to have "time" in its name.
_PLAUSIBLE_CHROME_TIME_RANGE = (12_275_625_600_000_000, 15_746_918_400_000_000)


def _sanitize(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name).strip("_") or "db"


def _looks_like_chrome_timestamp(column_name: str, value) -> bool:
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if not any(hint in column_name.lower() for hint in _TIME_COLUMN_HINTS):
        return False
    low, high = _PLAUSIBLE_CHROME_TIME_RANGE
    return low <= value <= high


def _row_to_dict(columns: list[str], row: tuple) -> dict:
    result = {}
    for col, value in zip(columns, row):
        if _looks_like_chrome_timestamp(col, value):
            result[col] = chrome_timestamp(value)
        else:
            result[col] = decode_value(value)
    return result


def _dump_table(con: sqlite3.Connection, table_name: str) -> list[dict]:
    cur = con.execute(f'SELECT * FROM "{table_name}"')
    columns = [d[0] for d in cur.description]
    return [_row_to_dict(columns, row) for row in cur.fetchall()]


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    results: dict[str, list[dict]] = {}
    errors = []

    for db_path in paths:
        source_file = str(db_path)
        db_stem = db_path.stem or db_path.name
        db_label = _sanitize(db_stem)
        browser = guess_browser_name(db_path)

        try:
            con = open_readonly(db_path)
        except sqlite3.Error as exc:
            errors.append({"_source_file": source_file, "_table": "", "_error": f"Failed to open: {exc}"})
            continue

        try:
            table_names = [
                decode_value(r[0]) for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            ]
        except sqlite3.Error as exc:
            errors.append({"_source_file": source_file, "_table": "", "_error": f"Failed to list tables: {exc}"})
            con.close()
            continue

        for table_name in table_names:
            if (db_stem, table_name) in _ALREADY_CURATED:
                continue

            output_name = f"{db_label}__{_sanitize(table_name)}"
            try:
                rows = _dump_table(con, table_name)
            except sqlite3.Error as exc:
                errors.append({"_source_file": source_file, "_table": table_name, "_error": str(exc)})
                continue

            for row in rows:
                row["_source_file"] = source_file
                row["browser"] = browser
            results.setdefault(output_name, []).extend(rows)

        con.close()

    results[_ERRORS_KEY] = errors
    return results
