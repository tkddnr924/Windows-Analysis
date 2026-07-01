"""Shared SQLite helpers for browser/app database parsers.

Some apps declare a column as TEXT but store raw binary in it anyway （e.g.
Edge's HubApps Icons stores a PNG in a TEXT-affinity column). Python's
sqlite3 module auto-decodes TEXT-affinity columns as UTF-8 by default and
raises OperationalError on the first bad row — which loses every other row
in that table, not just the bad cell. Opening the connection with
`text_factory=bytes` disables that auto-decode so we can decode column by
column and degrade a single bad value instead of losing the whole table.
"""
import sqlite3
from pathlib import Path


def open_readonly(path: Path) -> sqlite3.Connection:
    """Open a SQLite file read-only/immutable (safe for a forensic copy —
    never attempts to create a WAL/journal file next to the evidence),
    with raw bytes instead of auto-UTF-8-decoding text columns."""
    con = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
    con.text_factory = bytes
    return con


def decode_value(value):
    """Decode a value returned under text_factory=bytes. Genuine text
    decodes cleanly; a column that's actually binary (mislabeled TEXT
    affinity, or a real BLOB) becomes a "<blob: N bytes>" placeholder
    instead of raising or corrupting the CSV with raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return f"<blob: {len(value)} bytes>"
    return value


def table_exists(con: sqlite3.Connection, name: str) -> bool:
    cur = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def is_chromium_profile_db(con: sqlite3.Connection) -> bool:
    """Chromium's sql::MetaTable convention creates a `meta` table in
    almost every profile-scoped database (History, Cookies, Login Data,
    Web Data, ...), regardless of which Chromium-based browser it is
    (Edge, Brave, Chrome, ...) — checking for it classifies a SQLite file
    as browser data by its own schema, not by a hardcoded browser/app
    name list."""
    return table_exists(con, "meta")
