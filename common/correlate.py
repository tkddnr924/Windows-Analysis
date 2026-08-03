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
import re


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

    # Account rows = user profiles (SID + profile path) enriched with SAM
    # account metadata (creation date, last login) joined on RID — a SID's
    # trailing number IS its RID. SAM accounts with no profile (e.g. a
    # created-but-never-logged-in account) are added afterward so they aren't
    # missed. `created`/`last_login`/`username` ride along as extra columns the
    # TargetInfo view reads; other categories simply leave them blank.
    def _sam_fields(sam: dict) -> dict:
        # Every SAM-derived account detail the TargetInfo view shows in its
        # account detail panel. Kept as extra columns on the Account row.
        return {
            "created": sam.get("account_created", ""),
            "username": sam.get("username", ""),
            "full_name": sam.get("full_name", ""),
            "rid": sam.get("rid", ""),
            "last_login": sam.get("last_login", ""),
            "password_last_set": sam.get("password_last_set", ""),
            "last_failed_login": sam.get("last_failed_login", ""),
            "login_count": sam.get("login_count", ""),
            "failed_login_count": sam.get("failed_login_count", ""),
            "disabled": sam.get("disabled", ""),
            "special_account": sam.get("special_account", ""),
            "groups": sam.get("groups", ""),
            "account_flags": sam.get("account_flags", ""),
        }

    sam_by_rid = {}
    for a in _rows(all_results, "Registry", "Registry_Accounts"):
        rid = a.get("rid", "")
        if rid:
            sam_by_rid[rid] = a

    machine_sid_prefix = ""  # S-1-5-21-A-B-C, shared by every local account
    seen_rids = set()
    for r in _rows(all_results, "Registry", "Registry_UserProfiles"):
        sid = r.get("sid", "")
        rid = sid.rsplit("-", 1)[-1] if "-" in sid else ""
        if rid:
            seen_rids.add(rid)
        if not machine_sid_prefix and sid.startswith("S-1-5-21-"):
            machine_sid_prefix = sid.rsplit("-", 1)[0]
        sam = sam_by_rid.get(rid, {})
        rows.append(
            {
                "timestamp": r.get("load_time", ""),
                "category": "Account",
                "name": sid,
                "value": r.get("profile_image_path", ""),
                "home_directory": r.get("profile_image_path", "") or sam.get("home_directory", ""),
                "source_artifact": "Registry_UserProfiles",
                **_sam_fields(sam),
                # rid from the SID is authoritative even when there's no SAM row.
                "rid": sam.get("rid", "") or rid,
            }
        )

    for rid, a in sam_by_rid.items():
        if rid in seen_rids:
            continue
        # No profile for this account — synthesize its SID from the machine
        # prefix so the view can still classify/display it (username kept
        # explicitly since there's no profile path to derive it from).
        sid = f"{machine_sid_prefix}-{rid}" if machine_sid_prefix else ""
        rows.append(
            {
                "timestamp": a.get("account_created", ""),
                "category": "Account",
                "name": sid,
                "value": "",
                "home_directory": a.get("home_directory", ""),
                "source_artifact": "SAM_Accounts",
                **_sam_fields(a),
            }
        )

    # Named networks this machine joined + when (NetworkList\Profiles). This
    # key has NO IP address, only the profile name and last-connected time.
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

    # Actual IP configuration per adapter (SYSTEM Tcpip\...\Interfaces) — the
    # addresses the "연결한 네트워크" list can't provide.
    for r in _rows(all_results, "Registry", "Registry_NetworkInterfaces"):
        rows.append(
            {
                "timestamp": r.get("lease_obtained", ""),
                "category": "NetworkInterface",
                "name": r.get("interface_guid", ""),
                "value": r.get("ip_address", ""),
                "subnet_mask": r.get("subnet_mask", ""),
                "gateway": r.get("default_gateway", ""),
                "dns_server": r.get("dns_server", ""),
                "dhcp_server": r.get("dhcp_server", ""),
                "domain": r.get("domain", ""),
                "dhcp_enabled": r.get("dhcp_enabled", ""),
                "lease_obtained": r.get("lease_obtained", ""),
                "lease_terminates": r.get("lease_terminates", ""),
                "source_artifact": "Registry_NetworkInterfaces",
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


# --- PowerShell command history (from the event logs) -----------------------
#
# Built ONLY from EventLog_Events, per the DFIR question "what did PowerShell
# actually run": the raw PSReadLine ConsoleHost_history.txt (parsed separately
# as PowerShell_ConsoleHistory) is deliberately NOT merged in here — it carries
# no time/account/process, so it belongs in its own raw table, not this
# correlated view.
#
# Three event shapes carry a command, across the two PowerShell logs:
#   - Microsoft-Windows-PowerShell/Operational 4104 — script block logging:
#     the ScriptBlockText IS the code that ran (the richest source). Long
#     scripts are split across several 4104 records sharing one ScriptBlockId
#     (MessageNumber/MessageTotal), reassembled back into one row below. These
#     manifest fields are NOT localized, so they parse reliably on any locale.
#   - Microsoft-Windows-PowerShell/Operational 4103 — pipeline/module logging:
#     ContextInfo (host application + user) and Payload (the invocation).
#     ContextInfo's field *labels* are localized, so values are read
#     best-effort with a value-shape fallback.
#   - Windows PowerShell (classic) 800 — pipeline execution details: the
#     HostApplication= / CommandLine= tokens in its detail text are literal
#     (not localized), pulled out by regex.


def _basename(path: str) -> str:
    return path.replace("/", "\\").split("\\")[-1] if path else ""


def _user_map(all_results: dict) -> dict:
    """SID -> readable account name, from Registry_UserProfiles, so a bare
    logon SID on a PowerShell event can be shown as e.g. 'administrator'."""
    umap = {}
    for r in _rows(all_results, "Registry", "Registry_UserProfiles"):
        sid = r.get("sid", "")
        name = _basename(r.get("profile_image_path", ""))
        if sid and name:
            umap[sid] = name
    return umap


def _all_strings(obj) -> list[str]:
    """Every string value anywhere inside a parsed EventData structure —
    flattens dict/list/str uniformly so a token can be found regardless of how
    the (legacy) event serialized its data."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out += _all_strings(v)
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out += _all_strings(v)
        return out
    return []


def _ctx_value(context_info: str, *label_tokens: str) -> str:
    """Read a 'Label = Value' line out of a 4103 ContextInfo block. Labels are
    localized (English 'Host Application' becomes '호스트 응용 프로그램' on a
    Korean host), so match if the line's label contains ANY of the given
    tokens (pass both the English and localized forms)."""
    for line in context_info.splitlines():
        if "=" not in line:
            continue
        label, _, value = line.partition("=")
        label = label.strip()
        if any(tok and tok in label for tok in label_tokens):
            return value.strip()
    return ""


def _exe_from_host(host_application: str) -> str:
    """Executable name out of a host-application command line, e.g.
    '"C:\\...\\powershell.exe" -File x.ps1' -> 'powershell.exe'. Kept as a
    stable per-process label (the full command line varies per invocation, so
    it can't group a session)."""
    h = host_application.strip()
    if not h:
        return ""
    if h.startswith('"'):
        end = h.find('"', 1)
        path = h[1:end] if end != -1 else h[1:]
    else:
        path = h.split(" ", 1)[0]
    return _basename(path) or path


def _first_line(text: str, limit: int = 400) -> str:
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:limit]
    return (text or "").strip()[:limit]


def _find(blob: str, pattern: str) -> str:
    m = re.search(pattern, blob)
    return m.group(1).strip() if m else ""


def _to_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ps_row(*, timestamp, account, process, process_id, command, script_block, kind, event_id, provider, script_path, record_key) -> dict:
    return {
        "timestamp": timestamp,
        "account": account,
        "process": process,
        "process_id": process_id,
        "command": command,
        "script_block": script_block,
        "kind": kind,
        "event_id": event_id,
        "provider": provider,
        "script_path": script_path,
        "record_key": record_key,
    }


def build_powershell_history(all_results: dict) -> list[dict]:
    umap = _user_map(all_results)

    def account_for(sid: str) -> str:
        return umap.get(sid, "") or sid

    rows: list[dict] = []
    # ScriptBlockId -> reassembly slot, for multi-part 4104 script blocks.
    blocks: dict[str, dict] = {}

    for r in _rows(all_results, "EventLog", "EventLog_Events"):
        provider = r.get("Provider", "") or ""
        event_id = str(r.get("EventID", ""))
        ed = _parse_event_data(r.get("EventData", ""))
        sid = r.get("UserID", "") or ""
        pid = str(r.get("ProcessID", "") or "")
        ts = r.get("timestamp", "") or ""
        rk = r.get("_record_key", "") or ""

        if provider == "Microsoft-Windows-PowerShell" and event_id == "4104":
            text = str(ed.get("ScriptBlockText", "") or "")
            path = str(ed.get("Path", "") or "")
            sbid = str(ed.get("ScriptBlockId", "") or "")
            total = _to_int(ed.get("MessageTotal"), 1)
            num = _to_int(ed.get("MessageNumber"), 1)

            if sbid and total > 1:
                slot = blocks.setdefault(
                    sbid,
                    {"parts": {}, "timestamp": ts, "sid": sid, "pid": pid, "rk": rk, "path": path},
                )
                slot["parts"][num] = text
                if ts and (not slot["timestamp"] or ts < slot["timestamp"]):
                    slot["timestamp"] = ts
                    slot["rk"] = rk  # link to the first record of the block
                continue

            # A 4104 script block has no distinct "command line" — the code IS
            # the record. Leave `command` empty (the viewer shows "-") and keep
            # the full code in `script_block`, shown in the detail view.
            rows.append(_ps_row(
                timestamp=ts, account=account_for(sid), process="powershell.exe", process_id=pid,
                command="", script_block=text, kind="스크립트 블록",
                event_id=event_id, provider=provider, script_path=path, record_key=rk,
            ))

        elif provider == "Microsoft-Windows-PowerShell" and event_id == "4103":
            ctx = str(ed.get("ContextInfo", "") or "")
            host = _ctx_value(ctx, "Host Application", "호스트 응용")
            user = _ctx_value(ctx, "User", "사용자")
            payload = str(ed.get("Payload", "") or "").strip()
            command = payload or _ctx_value(ctx, "Command Name", "명령 이름")
            rows.append(_ps_row(
                timestamp=ts, account=user or account_for(sid), process=_exe_from_host(host) or "powershell.exe",
                process_id=pid, command=_first_line(command), script_block="", kind="파이프라인",
                event_id=event_id, provider=provider, script_path="", record_key=rk,
            ))

        elif provider == "PowerShell" and event_id == "800":
            blob = "\n".join(_all_strings(ed))
            host = _find(blob, r"HostApplication=(.+)")
            command = _find(blob, r"CommandLine=(.+)")
            if not command:
                continue  # a 800 with no command line carries nothing useful here
            rows.append(_ps_row(
                timestamp=ts, account=account_for(sid), process=_exe_from_host(host) or "powershell.exe",
                process_id=pid, command=_first_line(command), script_block="", kind="명령 실행",
                event_id=event_id, provider=provider, script_path="", record_key=rk,
            ))

    for slot in blocks.values():
        text = "".join(slot["parts"][k] for k in sorted(slot["parts"]))
        rows.append(_ps_row(
            timestamp=slot["timestamp"], account=account_for(slot["sid"]), process="powershell.exe",
            process_id=slot["pid"], command="", script_block=text, kind="스크립트 블록",
            event_id="4104", provider="Microsoft-Windows-PowerShell", script_path=slot["path"], record_key=slot["rk"],
        ))

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
