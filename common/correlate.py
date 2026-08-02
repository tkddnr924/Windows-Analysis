"""Cross-artifact correlation — build small "investigative view" tables by
combining already-parsed per-artifact rows into one table per DFIR question
(what does this machine look like, what ran, was there remote access, what
did the browser do) instead of requiring an analyst to open every artifact's
raw table separately to answer one question.

These are ADDITIVE: every source artifact's own raw table is still written
and browsable as-is — nothing here replaces or hides anything, this is a
summary/index layered on top (written under a case's _OVERVIEW/ category).

Each build_* function only reads whatever `all_results` actually contains
for the current run (main.py accumulates this from the same run_case() call
that just parsed everything) — it never falls back to stale data left on
disk from a previous run, so a partial `--only` run doesn't silently mix in
an older run's numbers.
"""
from __future__ import annotations

import json


def _rows(all_results: dict, artifact_name: str, output_name: str) -> list[dict]:
    return all_results.get(artifact_name, {}).get(output_name, [])


def build_target_info(all_results: dict) -> list[dict]:
    rows = []

    for r in _rows(all_results, "Registry", "Registry_SystemInfo"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "category": r.get("category", ""),
                "name": r.get("name", ""),
                "value": r.get("value", ""),
                "source_artifact": "Registry_SystemInfo",
            }
        )

    for r in _rows(all_results, "Registry", "Registry_UserProfiles"):
        rows.append(
            {
                "timestamp": r.get("load_time", ""),
                "category": "Account",
                "name": r.get("sid", ""),
                "value": r.get("profile_image_path", ""),
                "source_artifact": "Registry_UserProfiles",
            }
        )

    # Not an IP address — NetworkList only records which named network
    # profile this machine connected to and when, verified against this
    # project's real data (common/../registry_parser.py has the details).
    for r in _rows(all_results, "Registry", "Registry_NetworkProfiles"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "category": "Network",
                "name": "연결한 네트워크",
                "value": r.get("profile_name", ""),
                "source_artifact": "Registry_NetworkProfiles",
            }
        )

    return rows


def build_execution_history(all_results: dict) -> list[dict]:
    rows = []

    # Amcache's own timestamp is a registry-key write time — evidence the
    # system became aware of the program around this time (install/first
    # sight), not a precise "last executed" the way Prefetch/UserAssist are.
    for r in _rows(all_results, "Amcache", "Amcache_Programs"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "program_name": r.get("Name", ""),
                "program_path": r.get("RootDirPath", ""),
                "run_count": "",
                "publisher": r.get("Publisher", ""),
                "sha1": "",
                "focus_count": "",
                "focus_time_ms": "",
                "source_artifact": "Amcache_Programs",
            }
        )

    for r in _rows(all_results, "Amcache", "Amcache_Files"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "program_name": r.get("name", ""),
                "program_path": r.get("lower_case_long_path", ""),
                "run_count": "",
                "publisher": r.get("publisher", ""),
                "sha1": r.get("SHA1", ""),
                "focus_count": "",
                "focus_time_ms": "",
                "source_artifact": "Amcache_Files",
            }
        )

    for r in _rows(all_results, "Prefetch", "Prefetch_Execution"):
        rows.append(
            {
                "timestamp": r.get("last_run_time", ""),
                "program_name": r.get("executable_filename", ""),
                "program_path": "",
                "run_count": r.get("run_count", ""),
                "publisher": "",
                "sha1": "",
                "focus_count": "",
                "focus_time_ms": "",
                "source_artifact": "Prefetch_Execution",
            }
        )

    for r in _rows(all_results, "UserAssist", "UserAssist_Execution"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "program_name": r.get("program_path", ""),
                "program_path": r.get("program_path", ""),
                "run_count": r.get("run_count", ""),
                "publisher": "",
                "sha1": "",
                "focus_count": r.get("focus_count", ""),
                "focus_time_ms": r.get("focus_time_ms", ""),
                "source_artifact": "UserAssist_Execution",
            }
        )

    return rows


def _parse_event_data(raw: str) -> dict:
    try:
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _ed_field(event_data: dict, *names: str) -> str:
    """Read a field from an event's data. Security-Auditing events expose
    named fields at the top level (IpAddress, TargetUserName, ...), while the
    TerminalServices providers store theirs one level down under 'EventXML'
    (User/Address/SessionID or Param1/Param2/Param3) — check both."""
    xml = event_data.get("EventXML")
    sources = [xml] if isinstance(xml, dict) else []
    sources.append(event_data)
    for src in sources:
        for name in names:
            value = src.get(name)
            if value not in (None, ""):
                return str(value)
    return ""


# RDP evidence across the providers that actually carry it, verified against
# this project's real EventData field names (Security uses top-level
# IpAddress/TargetUserName; TerminalServices events nest fields under
# EventXML). direction = inbound (someone connected TO this host) vs outbound
# (this host connected out via the RDP client). result feeds the viewer's
# success/failure tabs. addr/acct list the EventData field names to read.
#
# Only 4624/4625 are LogonType-gated (type 10 = RDP); the TerminalServices
# providers are RDP-specific already.
_RDP_EVENTS: dict[tuple[str, str], dict] = {
    ("Microsoft-Windows-Security-Auditing", "4624"): {
        "direction": "inbound", "result": "성공", "description": "RDP 로그온 성공",
        "addr": ["IpAddress"], "acct": ["TargetUserName"], "logon_type_10": True,
    },
    ("Microsoft-Windows-Security-Auditing", "4625"): {
        "direction": "inbound", "result": "실패", "description": "RDP 로그온 실패",
        "addr": ["IpAddress"], "acct": ["TargetUserName"], "logon_type_10": True,
    },
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", "1149"): {
        "direction": "inbound", "result": "성공", "description": "RDP 네트워크 인증 성공(로그인 화면 도달)",
        "addr": ["Param3"], "acct": ["Param1"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "21"): {
        "direction": "inbound", "result": "성공", "description": "RDP 세션 로그온",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "25"): {
        "direction": "inbound", "result": "성공", "description": "RDP 세션 재연결",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "22"): {
        "direction": "inbound", "result": "정보", "description": "RDP 셸 시작",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "23"): {
        "direction": "inbound", "result": "정보", "description": "RDP 세션 로그오프",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "24"): {
        "direction": "inbound", "result": "정보", "description": "RDP 세션 연결 끊김",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "39"): {
        "direction": "inbound", "result": "정보", "description": "RDP 세션 연결 끊김(다른 세션에 의해)",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "40"): {
        "direction": "inbound", "result": "정보", "description": "RDP 세션 연결 끊김",
        "addr": ["Address"], "acct": ["User"],
    },
    ("Microsoft-Windows-TerminalServices-ClientActiveXCore", "1024"): {
        "direction": "outbound", "result": "정보", "description": "RDP 아웃바운드 연결 시도",
        "addr": ["Value"], "acct": [],
    },
    ("Microsoft-Windows-TerminalServices-ClientActiveXCore", "1102"): {
        "direction": "outbound", "result": "정보", "description": "RDP 아웃바운드 서버 주소",
        "addr": ["Value"], "acct": [],
    },
    # 1025/1026 are connect/disconnect signals whose "Value" is a session/reason
    # code, not a server address — no remote_address for these.
    ("Microsoft-Windows-TerminalServices-ClientActiveXCore", "1025"): {
        "direction": "outbound", "result": "성공", "description": "RDP 아웃바운드 연결됨",
        "addr": [], "acct": [],
    },
    ("Microsoft-Windows-TerminalServices-ClientActiveXCore", "1026"): {
        "direction": "outbound", "result": "정보", "description": "RDP 아웃바운드 연결 끊김",
        "addr": [], "acct": [],
    },
}


def build_remote_desktop_history(all_results: dict) -> list[dict]:
    """Inbound (someone connected to this host) and outbound (this host's RDP
    client connected out) Remote Desktop activity, pulled from the Security
    and TerminalServices event logs. Direction and success/failure are
    classified per event so the viewer can split them."""
    rows = []

    for r in _rows(all_results, "EventLog", "EventLog_Events"):
        spec = _RDP_EVENTS.get((r.get("Provider", ""), str(r.get("EventID", ""))))
        if not spec:
            continue

        event_data = _parse_event_data(r.get("EventData", ""))
        if spec.get("logon_type_10") and str(event_data.get("LogonType", "")) != "10":
            continue

        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "direction": spec["direction"],
                "remote_address": _ed_field(event_data, *spec["addr"]),
                "account": _ed_field(event_data, *spec["acct"]),
                "description": spec["description"],
                "result": spec["result"],
                "event_id": str(r.get("EventID", "")),
                "provider": r.get("Provider", ""),
                "record_key": r.get("_record_key", ""),
            }
        )

    return rows


def build_browser_timeline(all_results: dict) -> list[dict]:
    rows = []

    for r in _rows(all_results, "BrowserHistory", "History_Visits"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "browser": r.get("browser", ""),
                "activity_type": "방문",
                "title_or_target": r.get("title", ""),
                "url": r.get("url", ""),
                "source_artifact": "History_Visits",
            }
        )

    for r in _rows(all_results, "BrowserHistory", "History_Downloads"):
        target = r.get("target_path", "")
        filename = target.replace("/", "\\").split("\\")[-1] if target else ""
        rows.append(
            {
                "timestamp": r.get("end_time", ""),
                "browser": r.get("browser", ""),
                "activity_type": "다운로드",
                "title_or_target": filename,
                "url": r.get("tab_url", ""),
                "source_artifact": "History_Downloads",
            }
        )

    for r in _rows(all_results, "BrowserLoginData", "LoginData_Logins"):
        rows.append(
            {
                "timestamp": r.get("date_last_used", ""),
                "browser": r.get("browser", ""),
                "activity_type": "로그인 저장",
                "title_or_target": r.get("origin_url", ""),
                "url": r.get("origin_url", ""),
                "source_artifact": "LoginData_Logins",
            }
        )

    return rows
