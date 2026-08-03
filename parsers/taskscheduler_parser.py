"""Task Scheduler — the per-task XML definitions under \\Windows\\System32\\
Tasks (and \\Tasks). Each file is one registered scheduled task described in
the Task Scheduler schema (namespace .../2004/02/mit/task); the files have no
extension and arbitrary names, so they're located by that XML namespace in
their content, not by filename or folder.

Each task becomes one row: what it runs (Exec command/arguments or a COM
handler), who it runs as and at what privilege, whether it's enabled/hidden,
and its triggers. "Parsing" is just turning the XML into that flat row;
judging which tasks are suspicious is a later step.

Timestamps in task XML (RegistrationInfo/Date, trigger StartBoundary) are
written in the machine's LOCAL time with no offset. This dataset was
collected from a KST machine, so they're interpreted as KST — passed
explicitly as source_tz rather than defaulted.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

from common.utils import KST, format_timestamp

ARTIFACT_NAME = "TaskScheduler"
TASK_NAMESPACE = "schemas.microsoft.com/windows/2004/02/mit/task"

FIELD_ORDER = {
    "TaskScheduler_Tasks": [
        "timestamp", "task_name", "enabled", "hidden", "run_as", "run_level",
        "actions", "trigger_types", "trigger_start", "author", "description",
        "logon_type", "uri", "_source_file",
    ],
}


def _local(tag: str) -> str:
    """Strip the XML namespace from a tag, leaving the local element name."""
    return tag.rsplit("}", 1)[-1]


def _find(elem, name):
    for child in elem.iter():
        if _local(child.tag) == name:
            return child
    return None


def _text(elem, name) -> str:
    node = _find(elem, name)
    return (node.text or "").strip() if node is not None else ""


def _leaf(uri: str) -> str:
    r"""Last path segment of a task URI, e.g. '\Microsoft\Windows\Defrag\
    ScheduledDefrag' -> 'ScheduledDefrag'. The full path stays in `uri`."""
    return uri.rstrip("\\").split("\\")[-1] if uri else ""


def _parse_task(path: Path) -> dict:
    root = ET.fromstring(path.read_bytes())

    reg = _find(root, "RegistrationInfo")
    settings = _find(root, "Settings")
    principals = _find(root, "Principals")
    actions_el = _find(root, "Actions")
    triggers_el = _find(root, "Triggers")

    uri = _text(reg, "URI") if reg is not None else ""
    date = _text(reg, "Date") if reg is not None else ""
    author = _text(reg, "Author") if reg is not None else ""
    description = _text(reg, "Description") if reg is not None else ""

    enabled = _text(settings, "Enabled") if settings is not None else ""
    hidden = _text(settings, "Hidden") if settings is not None else ""

    run_as = run_level = logon_type = ""
    if principals is not None:
        principal = _find(principals, "Principal")
        if principal is not None:
            run_as = _text(principal, "UserId") or _text(principal, "GroupId")
            run_level = _text(principal, "RunLevel")
            logon_type = _text(principal, "LogonType")

    # Actions: Exec (command + args) and/or ComHandler (ClassId).
    action_parts: list[str] = []
    if actions_el is not None:
        for act in actions_el:
            kind = _local(act.tag)
            if kind == "Exec":
                cmd = _text(act, "Command")
                args = _text(act, "Arguments")
                action_parts.append((cmd + " " + args).strip())
            elif kind == "ComHandler":
                action_parts.append("COM:" + _text(act, "ClassId"))
            elif kind:
                action_parts.append(kind)

    # Triggers: element type names + the first StartBoundary.
    trigger_types: list[str] = []
    trigger_start = ""
    if triggers_el is not None:
        for trig in triggers_el:
            trigger_types.append(_local(trig.tag))
            if not trigger_start:
                sb = _text(trig, "StartBoundary")
                if sb:
                    trigger_start = sb

    return {
        "timestamp": format_timestamp(date, source_tz=KST) if date else "",
        # Just the task's leaf name for scanning; the full \folder\path stays
        # in `uri` (shown in the detail view).
        "task_name": _leaf(uri) or path.name,
        "enabled": enabled,
        "hidden": hidden,
        "run_as": run_as,
        "run_level": run_level,
        "actions": " | ".join(p for p in action_parts if p),
        "trigger_types": ", ".join(trigger_types),
        "trigger_start": format_timestamp(trigger_start, source_tz=KST) if trigger_start else "",
        "author": author,
        "description": description,
        "logon_type": logon_type,
        "uri": uri,
        "_source_file": str(path),
    }


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for path in paths:
        try:
            rows.append(_parse_task(path))
        except Exception as exc:
            rows.append(
                {
                    "timestamp": "",
                    "task_name": path.name,
                    "_source_file": str(path),
                    "_status": "unreadable_file",
                    "_error": str(exc),
                }
            )
    return {"TaskScheduler_Tasks": rows}
