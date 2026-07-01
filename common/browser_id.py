"""Identify which browser a collected file belongs to, from its path.

The collector groups every browser's profile under a `BROWSER` folder as
`.../BROWSER/<user>/<BrowserName>/...`. Reading the browser name from that
path segment works for any browser the collector happens to gather —
nothing here hardcodes a list of known browser names. This is purely a
labeling step for files already found (by filename/content elsewhere);
it doesn't change how those files were located.
"""
from pathlib import Path


def guess_browser_name(path: Path) -> str:
    parts = path.parts
    for i, part in enumerate(parts):
        if part.upper() == "BROWSER" and i + 2 < len(parts):
            return parts[i + 2]
    return ""
