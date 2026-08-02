"""PowerShell console history — the PSReadLine ConsoleHost_history.txt file,
which records every command typed at an interactive PowerShell prompt, one
per line, appended in execution order.

The file itself carries NO timestamps (PSReadLine only stores the command
text), so there is no time column here — order is the only temporal signal,
preserved as line_number. Each collected user has their own copy; the source
path is recorded and a best-effort account name is taken from it.

"Parsing" here is just faithfully turning the text file into one row per
command; interpretation (which commands are suspicious) is a later step.
"""
from pathlib import Path

ARTIFACT_NAME = "PowerShell"
FILENAMES = ["ConsoleHost_history.txt"]

FIELD_ORDER = {
    "PowerShell_ConsoleHistory": ["line_number", "command", "user", "_source_file"],
}


def _user_from_path(path: Path) -> str:
    """Best-effort account name. The canonical location is
    ...\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\
    PSReadLine\\ConsoleHost_history.txt; collectors often flatten it to
    <user>\\ConsoleHost_history.txt. Walk up skipping the known PSReadLine
    path segments and take the first remaining folder name."""
    skip = {"psreadline", "powershell", "windows", "microsoft", "roaming", "appdata", "local"}
    for parent in path.parents:
        name = parent.name
        if name and name.lower() not in skip:
            return name
        if not name:
            break
    return ""


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for path in paths:
        source_file = str(path)
        user = _user_from_path(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            rows.append(
                {
                    "line_number": "",
                    "command": "",
                    "user": user,
                    "_source_file": source_file,
                    "_status": "unreadable_file",
                    "_error": str(exc),
                }
            )
            continue

        for i, line in enumerate(text.splitlines(), start=1):
            if line == "":
                continue
            rows.append(
                {
                    "line_number": i,
                    "command": line,
                    "user": user,
                    "_source_file": source_file,
                }
            )
    return {"PowerShell_ConsoleHistory": rows}
