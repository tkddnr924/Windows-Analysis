"""Chromium-based browser History SQLite database parser (Edge/Chrome/Brave/...).

Handles the `History` file's shared Chromium schema (urls/visits/downloads/
keyword_search_terms) — this schema is common across all Chromium-family
browsers, only the filename differs from vendor extensions in some forks.
Other browser databases (Cookies, Web Data, Login Data, Firefox's
places.sqlite) use different schemas/epochs and aren't handled here yet.

A broken/unreadable file, or a table missing/renamed in a given browser
version, is recorded as its own row in History_Errors rather than silently
skipped, so a damaged DB is still visible in the output.
"""
import sqlite3
from pathlib import Path

from common.browser_id import guess_browser_name
from common.chrome_time import chrome_timestamp
from common.sqlite_utils import decode_value, open_readonly, table_exists

ARTIFACT_NAME = "BrowserHistory"
FILENAMES = ["History"]

# Chromium page transition core type is the low byte of the `transition`
# bitmask (upper bits are qualifiers like FORWARD_BACK / CLIENT_REDIRECT).
_TRANSITION_CORE = {
    0: "LINK", 1: "TYPED", 2: "AUTO_BOOKMARK", 3: "AUTO_SUBFRAME",
    4: "MANUAL_SUBFRAME", 5: "GENERATED", 6: "START_PAGE", 7: "FORM_SUBMIT",
    8: "RELOAD", 9: "KEYWORD", 10: "KEYWORD_GENERATED",
}

FIELD_ORDER = {
    "History_Visits": [
        "timestamp", "browser", "url", "title", "transition_type",
        "visit_duration_sec", "from_visit", "visit_id", "_source_file",
    ],
    "History_Urls": [
        "last_visit_time", "browser", "url", "title", "visit_count",
        "typed_count", "hidden", "_source_file",
    ],
    "History_Downloads": [
        "start_time", "browser", "end_time", "last_access_time", "target_path",
        "current_path", "tab_url", "referrer", "received_bytes",
        "total_bytes", "state", "danger_type", "mime_type", "_source_file",
    ],
    "History_KeywordSearchTerms": [
        "term", "browser", "url", "normalized_term", "_source_file",
    ],
    "History_Errors": ["_source_file", "_error"],
}


def _fmt(value) -> str:
    return chrome_timestamp(value)


def _parse_visits(con, source_file: str, browser: str) -> list[dict]:
    if not table_exists(con, "visits") or not table_exists(con, "urls"):
        return []
    cur = con.execute(
        """
        SELECT v.id, v.visit_time, v.from_visit, v.transition, v.visit_duration,
               u.url, u.title
        FROM visits v JOIN urls u ON v.url = u.id
        """
    )
    rows = []
    for visit_id, visit_time, from_visit, transition, duration, url, title in cur.fetchall():
        core_type = (transition or 0) & 0xFF
        rows.append(
            {
                "timestamp": _fmt(visit_time),
                "browser": browser,
                "url": decode_value(url),
                "title": decode_value(title),
                "transition_type": _TRANSITION_CORE.get(core_type, str(core_type)),
                "visit_duration_sec": round((duration or 0) / 1_000_000, 3),
                "from_visit": from_visit,
                "visit_id": visit_id,
                "_source_file": source_file,
            }
        )
    return rows


def _parse_urls(con, source_file: str, browser: str) -> list[dict]:
    if not table_exists(con, "urls"):
        return []
    cur = con.execute("SELECT url, title, visit_count, typed_count, last_visit_time, hidden FROM urls")
    rows = []
    for url, title, visit_count, typed_count, last_visit_time, hidden in cur.fetchall():
        rows.append(
            {
                "last_visit_time": _fmt(last_visit_time),
                "browser": browser,
                "url": decode_value(url),
                "title": decode_value(title),
                "visit_count": visit_count,
                "typed_count": typed_count,
                "hidden": hidden,
                "_source_file": source_file,
            }
        )
    return rows


def _parse_downloads(con, source_file: str, browser: str) -> list[dict]:
    if not table_exists(con, "downloads"):
        return []
    cur = con.execute(
        """
        SELECT start_time, end_time, last_access_time, target_path, current_path,
               tab_url, referrer, received_bytes, total_bytes, state, danger_type, mime_type
        FROM downloads
        """
    )
    rows = []
    for (
        start_time, end_time, last_access_time, target_path, current_path,
        tab_url, referrer, received_bytes, total_bytes, state, danger_type, mime_type,
    ) in cur.fetchall():
        rows.append(
            {
                "start_time": _fmt(start_time),
                "browser": browser,
                "end_time": _fmt(end_time),
                "last_access_time": _fmt(last_access_time),
                "target_path": decode_value(target_path),
                "current_path": decode_value(current_path),
                "tab_url": decode_value(tab_url),
                "referrer": decode_value(referrer),
                "received_bytes": received_bytes,
                "total_bytes": total_bytes,
                "state": state,
                "danger_type": danger_type,
                "mime_type": mime_type,
                "_source_file": source_file,
            }
        )
    return rows


def _parse_keyword_search_terms(con, source_file: str, browser: str) -> list[dict]:
    if not table_exists(con, "keyword_search_terms") or not table_exists(con, "urls"):
        return []
    cur = con.execute(
        """
        SELECT k.term, u.url, k.normalized_term
        FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id
        """
    )
    rows = []
    for term, url, normalized_term in cur.fetchall():
        rows.append(
            {
                "term": decode_value(term),
                "browser": browser,
                "url": decode_value(url),
                "normalized_term": decode_value(normalized_term),
                "_source_file": source_file,
            }
        )
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    visits, urls, downloads, keywords, errors = [], [], [], [], []

    for db_path in paths:
        source_file = str(db_path)
        browser = guess_browser_name(db_path)
        try:
            con = open_readonly(db_path)
        except sqlite3.Error as exc:
            errors.append({"_source_file": source_file, "_error": f"Failed to open database: {exc}"})
            continue

        try:
            for label, sub_parser, sink in (
                ("visits", _parse_visits, visits),
                ("urls", _parse_urls, urls),
                ("downloads", _parse_downloads, downloads),
                ("keyword_search_terms", _parse_keyword_search_terms, keywords),
            ):
                try:
                    sink.extend(sub_parser(con, source_file, browser))
                except sqlite3.Error as exc:
                    errors.append({"_source_file": source_file, "_error": f"Failed to read {label}: {exc}"})
        finally:
            con.close()

    return {
        "History_Visits": visits,
        "History_Urls": urls,
        "History_Downloads": downloads,
        "History_KeywordSearchTerms": keywords,
        "History_Errors": errors,
    }
