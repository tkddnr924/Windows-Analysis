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


# (Provider, EventID) combinations that are remote-access evidence — the
# inbound/server-side half. RemoteAccess_RDPClientHistory covers the
# outbound/client-side half. Kept narrow to this table's purpose; the full
# IR event catalog (persistence, account changes, etc.) lives in the
# viewer's lib/eventCatalog.ts for the raw EventLog_Events table.
_REMOTE_EVENT_IDS = {
    ("Microsoft-Windows-Security-Auditing", "4624"): "로그온 성공",
    ("Microsoft-Windows-Security-Auditing", "4625"): "로그온 실패",
    ("Microsoft-Windows-Security-Auditing", "5140"): "네트워크 공유 접근(SMB)",
    ("Microsoft-Windows-Security-Auditing", "5145"): "공유 파일 상세 접근(SMB)",
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", "1149"): "RDP 클라이언트 인증 성공",
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "21"): "RDP 세션 로그온",
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "24"): "RDP 세션 연결 끊김",
    ("Microsoft-Windows-TerminalServices-LocalSessionManager", "25"): "RDP 세션 재연결",
}

_LOGON_TYPE_LABELS = {
    "3": "네트워크",
    "8": "네트워크(평문)",
    "9": "새 자격 증명",
    "10": "원격 데스크톱(RDP)",
}


def _parse_event_data(raw: str) -> dict:
    try:
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def build_remote_access_history(all_results: dict) -> list[dict]:
    rows = []

    for r in _rows(all_results, "TerminalServerClient", "RemoteAccess_RDPClientHistory"):
        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "direction": "outbound(RDP client)",
                "remote_address": r.get("server", ""),
                "account": r.get("username_hint", ""),
                "detail": "RDP 클라이언트 접속 기록",
                "record_key": "",
                "source_artifact": "RemoteAccess_RDPClientHistory",
            }
        )

    for r in _rows(all_results, "EventLog", "EventLog_Events"):
        key = (r.get("Provider", ""), str(r.get("EventID", "")))
        label = _REMOTE_EVENT_IDS.get(key)
        if not label:
            continue

        event_data = _parse_event_data(r.get("EventData", ""))
        logon_type = str(event_data.get("LogonType", ""))
        # 4624/4625 without a remote-ish logon type (local console, service,
        # unlock, etc.) aren't remote-access evidence — skip those.
        if key[1] in ("4624", "4625") and logon_type not in _LOGON_TYPE_LABELS:
            continue

        detail = f"{label} ({_LOGON_TYPE_LABELS[logon_type]})" if logon_type in _LOGON_TYPE_LABELS else label

        rows.append(
            {
                "timestamp": r.get("timestamp", ""),
                "direction": "inbound",
                "remote_address": event_data.get("IpAddress") or event_data.get("WorkstationName") or "",
                "account": event_data.get("TargetUserName", ""),
                "detail": detail,
                "record_key": r.get("_record_key", ""),
                "source_artifact": "EventLog_Events",
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
