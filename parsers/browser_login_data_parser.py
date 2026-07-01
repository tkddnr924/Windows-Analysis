"""Chromium-based browser "Login Data" / "Login Data For Account" SQLite
database parser (Edge/Chrome/Brave/...).

The actual password bytes (`password_value`) are OS-DPAPI-encrypted and
never read here — only whether one is present (`has_password`) via
`length()` in SQL, so the encrypted blob never even enters Python memory.
"""
import sqlite3
from pathlib import Path

from common.browser_id import guess_browser_name
from common.chrome_time import chrome_timestamp
from common.sqlite_utils import decode_value, open_readonly, table_exists

ARTIFACT_NAME = "BrowserLoginData"
FILENAMES = ["Login Data", "Login Data For Account"]

FIELD_ORDER = {
    "LoginData_Logins": [
        "date_created", "browser", "date_last_used", "date_password_modified",
        "origin_url", "username_value", "signon_realm", "times_used",
        "blacklisted_by_user", "password_type", "has_password", "_source_file",
    ],
    "LoginData_Errors": ["_source_file", "_error"],
}


def _parse_logins(con, source_file: str, browser: str) -> list[dict]:
    if not table_exists(con, "logins"):
        return []
    cur = con.execute(
        """
        SELECT origin_url, username_value, signon_realm, date_created,
               date_last_used, date_password_modified, times_used,
               blacklisted_by_user, password_type, length(password_value)
        FROM logins
        """
    )
    rows = []
    for (
        origin_url, username_value, signon_realm, date_created,
        date_last_used, date_password_modified, times_used,
        blacklisted_by_user, password_type, password_len,
    ) in cur.fetchall():
        rows.append(
            {
                "date_created": chrome_timestamp(date_created),
                "browser": browser,
                "date_last_used": chrome_timestamp(date_last_used),
                "date_password_modified": chrome_timestamp(date_password_modified),
                "origin_url": decode_value(origin_url),
                "username_value": decode_value(username_value),
                "signon_realm": decode_value(signon_realm),
                "times_used": times_used,
                "blacklisted_by_user": bool(blacklisted_by_user),
                "password_type": password_type,
                "has_password": bool(password_len),
                "_source_file": source_file,
            }
        )
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    logins, errors = [], []

    for db_path in paths:
        source_file = str(db_path)
        browser = guess_browser_name(db_path)
        try:
            con = open_readonly(db_path)
        except sqlite3.Error as exc:
            errors.append({"_source_file": source_file, "_error": f"Failed to open database: {exc}"})
            continue

        try:
            logins.extend(_parse_logins(con, source_file, browser))
        except sqlite3.Error as exc:
            errors.append({"_source_file": source_file, "_error": f"Failed to read logins: {exc}"})
        finally:
            con.close()

    return {"LoginData_Logins": logins, "LoginData_Errors": errors}
