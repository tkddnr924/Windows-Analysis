"""Write a list of flat dicts to a table in a case's SQLite database,
tolerating rows with different keys (e.g. corrupted-record rows carrying
only timestamp/_status/_error alongside normal rows with the full field
set) — same tolerance csv_writer.py had, same rules besides the storage
format: timestamp-first column order, and rows with `_status`/`_error`
stay visible as ordinary rows instead of being dropped.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


# sqlite3's INTEGER storage class is a signed 64-bit int; binding a Python int
# outside this range raises "OverflowError: Python int too large to convert to
# SQLite INTEGER" and kills the whole run. Such values do occur (a large
# REG_QWORD, a 128-bit-ish identifier a parser handed back as an int, ...).
_INT64_MIN = -(2 ** 63)
_INT64_MAX = 2 ** 63 - 1


def _to_cell(value):
    """Coerce a parser value into something sqlite3 can bind to a TEXT column.

    Registry values such as REG_MULTI_SZ come back as Python lists (and some
    parsers emit dict/tuple/set values), which sqlite3 refuses to bind
    ("type 'list' is not supported"). Serialize any non-scalar to a JSON
    string — lossless and readable — while leaving the scalar types sqlite3
    already handles (str/float/bytes/None) untouched. An int that doesn't fit
    sqlite's 64-bit INTEGER is stored as its decimal string instead of crashing.
    """
    if value is None or isinstance(value, (str, float, bytes)):
        return value
    if isinstance(value, int):  # bool included; both fit the range
        return value if _INT64_MIN <= value <= _INT64_MAX else str(value)
    return json.dumps(value, ensure_ascii=False, default=str)


def write_rows_to_sqlite(
    rows: list[dict],
    db_path: Path,
    table_name: str,
    preferred_order: list[str] | None = None,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute(f'DROP TABLE IF EXISTS "{table_name}"')
        if not rows:
            return

        all_keys: set[str] = set()
        for row in rows:
            all_keys.update(row.keys())

        preferred_order = preferred_order or []
        ordered_fields = [f for f in preferred_order if f in all_keys]
        ordered_fields += sorted(all_keys - set(ordered_fields))

        columns_sql = ", ".join(f'"{f}" TEXT' for f in ordered_fields)
        conn.execute(f'CREATE TABLE "{table_name}" ({columns_sql})')

        placeholders = ", ".join("?" for _ in ordered_fields)
        quoted_fields = ", ".join(f'"{f}"' for f in ordered_fields)
        insert_sql = f'INSERT INTO "{table_name}" ({quoted_fields}) VALUES ({placeholders})'
        conn.executemany(
            insert_sql,
            [[_to_cell(row.get(f, "")) for f in ordered_fields] for row in rows],
        )
        conn.commit()
