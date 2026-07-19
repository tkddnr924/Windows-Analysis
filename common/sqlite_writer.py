"""Write a list of flat dicts to a table in a case's SQLite database,
tolerating rows with different keys (e.g. corrupted-record rows carrying
only timestamp/_status/_error alongside normal rows with the full field
set) — same tolerance csv_writer.py had, same rules besides the storage
format: timestamp-first column order, and rows with `_status`/`_error`
stay visible as ordinary rows instead of being dropped.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


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
            [[row.get(f, "") for f in ordered_fields] for row in rows],
        )
        conn.commit()
