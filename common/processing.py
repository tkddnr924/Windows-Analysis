"""Processing ("가공") layer — build investigative views by extracting and
correlating evidence out of the RAW parsed output (the per-hive registry
dumps, the SRUM/Amcache tables, ...). The parsers stay faithful and dumb; all
interpretation (ROT13-decoding UserAssist, pulling a FILETIME out of a BAM
blob, ...) lives here so it can be changed without re-parsing.

ExecutionHistory: "what ran on this machine", merged from every execution
artifact we can currently recover from the raw output —
  - Amcache          (installed programs + file entries)
  - UserAssist       (per-user GUI program launches; NTUSER hive dump)
  - SRUM             (per-app resource usage = the app ran)
  - BAM/DAM          (per-user last-execution time; SYSTEM hive dump)
Prefetch is included when present (its own artifact). AppCompatCache/ShimCache
is NOT yet available: regipy truncates its large REG_BINARY value to 128 bytes
in the raw dump, cutting off the entry list — recovering it needs a dedicated
raw-hive read (a follow-up).
"""
from __future__ import annotations

import codecs
import datetime as _dt
import json
import struct

from common.utils import UTC, format_timestamp

try:
    from regipy.utils import convert_wintime
except Exception:  # pragma: no cover
    convert_wintime = None


_ROW_KEYS = (
    "timestamp", "program_name", "program_path", "run_count",
    "focus_count", "focus_time_ms", "publisher", "sha1", "user", "source_artifact",
)

# UserAssist internal bookkeeping value names (after ROT13), not real launches.
_UA_MARKERS = ("UEME_CTLSESSION", "UEME_CTLCUACount:ctor")


def _row(**kw) -> dict:
    r = {k: "" for k in _ROW_KEYS}
    r.update(kw)
    return r


def _basename(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").split("\\")[-1] if path else ""


def _unhex(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except (ValueError, TypeError):
        return b""


def _filetime(value: int) -> str:
    if not value or convert_wintime is None:
        return ""
    try:
        return format_timestamp(convert_wintime(value, as_json=True), source_tz=UTC)
    except Exception:
        return ""


# --- raw-registry access helpers -------------------------------------------

def _registry_hives(all_results: dict):
    """Yield (hive_filename, [raw rows]) for every dumped registry hive. Each
    row is {key_path, value_name, value_type, value_data, last_write, ...}."""
    for fname, tables in all_results.get("Registry", {}).items():
        yield fname, tables.get("Registry", [])


def _amcache_tables(all_results: dict, table: str):
    for tables in all_results.get("Amcache", {}).values():
        yield from tables.get(table, [])


def _srum_rows(all_results: dict, table: str):
    for tables in all_results.get("SRUM", {}).values():
        yield from tables.get(table, [])


# --- per-source extractors ---------------------------------------------------

def _from_amcache(all_results: dict) -> list[dict]:
    rows = []
    for r in _amcache_tables(all_results, "Amcache_Programs"):
        rows.append(_row(
            timestamp=r.get("timestamp", ""), program_name=r.get("Name", ""),
            program_path=r.get("RootDirPath", ""), publisher=r.get("Publisher", ""),
            source_artifact="Amcache_Programs",
        ))
    for r in _amcache_tables(all_results, "Amcache_Files"):
        rows.append(_row(
            timestamp=r.get("timestamp", ""), program_name=r.get("name", ""),
            program_path=r.get("lower_case_long_path", ""), publisher=r.get("publisher", ""),
            sha1=r.get("SHA1", ""), source_artifact="Amcache_Files",
        ))
    return rows


def _from_userassist(all_results: dict) -> list[dict]:
    rows = []
    for fname, reg_rows in _registry_hives(all_results):
        if not fname.upper().endswith("NTUSER.DAT"):
            continue
        user = fname[: -len("_NTUSER.DAT")] if fname.upper().endswith("_NTUSER.DAT") else fname
        for r in reg_rows:
            kp = r.get("key_path", "")
            name = r.get("value_name", "")
            if "UserAssist" not in kp or not kp.endswith("\\Count") or name in ("", "(default)"):
                continue
            try:
                decoded = codecs.decode(name, "rot13")
            except Exception:
                decoded = name
            if decoded in _UA_MARKERS:
                continue
            data = _unhex(r.get("value_data", ""))
            run_count = focus_count = focus_ms = ""
            ts = ""
            if len(data) >= 68:
                run_count = str(struct.unpack_from("<I", data, 4)[0])
                focus_count = str(struct.unpack_from("<I", data, 8)[0])
                focus_ms = str(struct.unpack_from("<I", data, 12)[0])
                ts = _filetime(struct.unpack_from("<Q", data, 60)[0])
            rows.append(_row(
                timestamp=ts, program_name=_basename(decoded), program_path=decoded,
                run_count=run_count, focus_count=focus_count, focus_time_ms=focus_ms,
                user=user, source_artifact="UserAssist",
            ))
    return rows


def _from_bam(all_results: dict) -> list[dict]:
    rows = []
    for fname, reg_rows in _registry_hives(all_results):
        if fname.upper() != "SYSTEM":
            continue
        for r in reg_rows:
            kp = r.get("key_path", "")
            low = kp.lower()
            if "\\services\\bam" not in low or "\\usersettings\\" not in low:
                continue
            exe = r.get("value_name", "")
            if not exe.lower().endswith(".exe"):
                continue
            # …\UserSettings\<SID>\  -> the SID
            after = kp.split("UserSettings\\", 1)[-1]
            sid = after.split("\\", 1)[0]
            data = _unhex(r.get("value_data", ""))
            ts = _filetime(struct.unpack_from("<Q", data, 0)[0]) if len(data) >= 8 else ""
            rows.append(_row(
                timestamp=ts, program_name=_basename(exe), program_path=exe,
                user=sid, source_artifact="BAM",
            ))
    return rows


def _earlier(candidate: str, current: str) -> bool:
    """True if `candidate` timestamp should replace `current` as the earliest.
    A real time beats an empty one; timestamps are 'YYYY-MM-DD HH:MM:SS…' so a
    plain string compare is chronological."""
    if not candidate:
        return False
    if not current:
        return True
    return candidate < current


def _from_srum(all_results: dict) -> list[dict]:
    # SRUM's ApplicationResourceUsage samples every running app about once an
    # hour, so one program shows up dozens of times. For ExecutionHistory we
    # only want the FIRST sighting (earliest timestamp) per app+user — that's
    # the "it ran" evidence; the repeated hourly rows are noise here.
    earliest: dict[tuple, dict] = {}
    for r in _srum_rows(all_results, "SRUM_ApplicationResourceUsage"):
        key = (r.get("app", ""), r.get("user", ""))
        ts = r.get("timestamp", "")
        cur = earliest.get(key)
        if cur is None or _earlier(ts, cur["timestamp"]):
            earliest[key] = {"app": key[0], "user": key[1], "timestamp": ts}
    rows = []
    for e in earliest.values():
        app = e["app"]
        rows.append(_row(
            timestamp=e["timestamp"], program_name=_basename(app) or app,
            program_path=app, user=e["user"], source_artifact="SRUM",
        ))
    return rows


def _parse_shimcache(data: bytes) -> list[tuple]:
    """Windows 8/10 AppCompatCache (ShimCache) entries: (path, last_modified
    FILETIME). Each entry starts with the '10ts' signature, then a uint32
    entry size, then path-length/path (UTF-16LE)/FILETIME. A single misaligned
    entry is skipped (path sanity check) rather than derailing the rest."""
    entries = []
    if len(data) < 4:
        return entries
    header = struct.unpack_from("<I", data, 0)[0]
    off = header if 0 < header < len(data) and data[header:header + 4] == b"10ts" else data.find(b"10ts")
    while off != -1 and off + 12 <= len(data) and data[off:off + 4] == b"10ts":
        ce_size = struct.unpack_from("<I", data, off + 8)[0]
        entry = data[off + 12 : off + 12 + ce_size]
        try:
            path_len = struct.unpack_from("<H", entry, 0)[0]
            path = entry[2 : 2 + path_len].decode("utf-16-le", "replace")
            ft = struct.unpack_from("<Q", entry, 2 + path_len)[0]
            if path and ("\\" in path or ":" in path):
                entries.append((path, ft))
        except (struct.error, IndexError):
            pass
        off += 12 + ce_size
    return entries


def _from_appcompatcache(all_results: dict) -> list[dict]:
    """AppCompatCache / ShimCache from the SYSTEM hive dump — evidence a
    program existed on / ran from a path, with the executable's last-modified
    time. Deduped across ControlSet001/002 (both keep a copy)."""
    rows = []
    seen = set()
    for fname, reg_rows in _registry_hives(all_results):
        if fname.upper() != "SYSTEM":
            continue
        for r in reg_rows:
            if r.get("value_name") != "AppCompatCache":
                continue
            for path, ft in _parse_shimcache(_unhex(r.get("value_data", ""))):
                key = (path, ft)
                if key in seen:
                    continue
                seen.add(key)
                rows.append(_row(
                    timestamp=_filetime(ft), program_name=_basename(path),
                    program_path=path, source_artifact="AppCompatCache",
                ))
    return rows


def _from_prefetch(all_results: dict) -> list[dict]:
    rows = []
    pf = all_results.get("Prefetch", {})
    # Prefetch stays a flat {table: rows} artifact.
    for r in pf.get("Prefetch_Execution", []) if isinstance(pf, dict) else []:
        rows.append(_row(
            timestamp=r.get("last_run_time", ""), program_name=r.get("executable_filename", ""),
            run_count=r.get("run_count", ""), source_artifact="Prefetch",
        ))
    return rows


def build_execution_history(all_results: dict) -> list[dict]:
    rows: list[dict] = []
    rows += _from_amcache(all_results)
    rows += _from_userassist(all_results)
    rows += _from_srum(all_results)
    rows += _from_bam(all_results)
    rows += _from_appcompatcache(all_results)
    rows += _from_prefetch(all_results)
    return rows


# --- TargetInfo ("분석 대상") --------------------------------------------------
# System identity + local accounts + network config, all extracted from the raw
# registry dumps (SOFTWARE/SYSTEM/SAM). The TargetInfoView reads a small fixed
# column set per `category`; every row carries the full set so the schema stays
# uniform. Accounts come from the SAM V/F binary structures (see _parse_sam_*).

_TI_KEYS = (
    "timestamp", "category", "name", "value", "source_artifact",
    "username", "full_name", "rid", "home_directory", "created", "last_login",
    "password_last_set", "last_failed_login", "login_count", "failed_login_count",
    "disabled", "special_account", "groups", "account_flags",
    "subnet_mask", "gateway", "dns_server", "dhcp_server", "dhcp_enabled",
    "domain", "lease_obtained", "lease_terminates",
)


def _ti_row(**kw) -> dict:
    r = {k: "" for k in _TI_KEYS}
    r.update(kw)
    return r


def _hives_by_name(all_results: dict) -> dict:
    hives: dict[str, list] = {}
    for fname, rows in _registry_hives(all_results):
        hives.setdefault(fname.upper(), []).extend(rows)
    return hives


def _unixdate(value: str) -> str:
    try:
        ts = int(value)
    except (ValueError, TypeError):
        return ""
    if ts <= 0:
        return ""
    try:
        return format_timestamp(_dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat(), source_tz=UTC)
    except (OverflowError, OSError, ValueError):
        return ""


def _filetime_hex(hexstr: str) -> str:
    b = _unhex(hexstr)
    return _filetime(struct.unpack_from("<Q", b, 0)[0]) if len(b) >= 8 else ""


def _systemtime_hex(hexstr: str) -> str:
    b = _unhex(hexstr)
    if len(b) < 16:
        return ""
    y, mo, _dow, d, h, mi, s, _ms = struct.unpack_from("<8H", b, 0)
    return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}" if y else ""


def _pick(rows: list, key_suffix: str, value_name: str) -> str:
    """First non-empty value for a key ending in `key_suffix`, preferring the
    live control set (ControlSet001) over its ...002 backup copy."""
    ks = key_suffix.lower()
    hits = [
        r for r in rows
        if r.get("key_path", "").lower().endswith(ks)
        and r.get("value_name") == value_name and r.get("value_data", "") != ""
    ]
    for r in hits:
        if "controlset001" in r["key_path"].lower():
            return r["value_data"]
    return hits[0]["value_data"] if hits else ""


_OS_VALUES = ("ProductName", "EditionID", "DisplayVersion", "CurrentBuild", "RegisteredOwner", "InstallDate")


def _system_info(software: list, system: list) -> list[dict]:
    rows = []
    cv = "\\microsoft\\windows nt\\currentversion"
    seen = set()
    for r in software:
        if r.get("key_path", "").lower().endswith(cv) and r.get("value_name") in _OS_VALUES:
            name = r["value_name"]
            if name in seen:
                continue
            seen.add(name)
            val = _unixdate(r.get("value_data", "")) if name == "InstallDate" else r.get("value_data", "")
            rows.append(_ti_row(category="SystemInfo", name=name, value=val, source_artifact="SOFTWARE"))
    cn = _pick(system, "\\control\\computername\\computername", "ComputerName")
    if cn:
        rows.append(_ti_row(category="SystemInfo", name="ComputerName", value=cn, source_artifact="SYSTEM"))
    tz = _pick(system, "\\control\\timezoneinformation", "TimeZoneKeyName")
    if tz:
        rows.append(_ti_row(category="SystemInfo", name="TimeZone", value=tz, source_artifact="SYSTEM"))
    sd = _pick(system, "\\control\\windows", "ShutdownTime")
    if sd:
        rows.append(_ti_row(category="SystemInfo", name="LastShutdownTime", value=_filetime_hex(sd), source_artifact="SYSTEM"))
    return rows


# SAM account-control bits (ACB) — the human-readable flag names.
_ACB = [
    (0x0001, "Disabled"), (0x0002, "HomeDirRequired"), (0x0004, "PwNotRequired"),
    (0x0008, "TempDuplicate"), (0x0010, "Normal"), (0x0020, "MNSLogon"),
    (0x0040, "DomainTrust"), (0x0080, "WorkstationTrust"), (0x0100, "ServerTrust"),
    (0x0200, "PwNoExpire"), (0x0400, "AutoLocked"),
]


def _parse_sam_f(b: bytes) -> dict:
    """The SAM F value (fixed-length) — account timestamps, RID, ACB flags and
    the logon/failed-logon counters, at their well-known offsets."""
    if len(b) < 0x44:
        return {}
    acb = struct.unpack_from("<H", b, 0x38)[0]
    return {
        "last_login": _filetime(struct.unpack_from("<Q", b, 0x08)[0]),
        "password_last_set": _filetime(struct.unpack_from("<Q", b, 0x18)[0]),
        "last_failed_login": _filetime(struct.unpack_from("<Q", b, 0x28)[0]),
        "login_count": str(struct.unpack_from("<H", b, 0x42)[0]),
        "failed_login_count": str(struct.unpack_from("<H", b, 0x40)[0]),
        "disabled": "예" if acb & 0x0001 else "아니오",
        "account_flags": ", ".join(n for bit, n in _ACB if acb & bit),
    }


def _parse_sam_v(b: bytes) -> dict:
    """The SAM V value — a table of (offset, length) pairs (relative to 0xCC)
    followed by the strings. Entry 1 is the username, entry 2 the full name."""
    if len(b) < 0xCC:
        return {}

    def field(idx: int) -> str:
        base = idx * 12
        try:
            off = struct.unpack_from("<I", b, base)[0]
            length = struct.unpack_from("<I", b, base + 4)[0]
        except struct.error:
            return ""
        raw = b[0xCC + off: 0xCC + off + length]
        return raw.decode("utf-16-le", "replace")

    return {"username": field(1), "full_name": field(2)}


_HEX = set("0123456789abcdefABCDEF")


def _accounts(sam: list, software: list) -> list[dict]:
    # Machine SID prefix + per-SID profile path, from SOFTWARE ProfileList.
    prefix = ""
    profiles: dict[str, str] = {}
    for r in software:
        kp = r.get("key_path", "")
        if "\\profilelist\\s-" in kp.lower() and r.get("value_name") == "ProfileImagePath":
            sid = kp.rsplit("\\", 1)[-1]
            profiles[sid] = r.get("value_data", "")
            if sid.startswith("S-1-5-21-") and not prefix:
                prefix = sid.rsplit("-", 1)[0]

    # SAM: per-RID V/F blobs, plus each account's creation time (the last-write
    # of its Users\Names\<username> key).
    users: dict[str, dict] = {}
    names_created: dict[str, str] = {}
    for r in sam:
        kp = r.get("key_path", "")
        low = kp.lower()
        nmark = "\\sam\\domains\\account\\users\\names\\"
        if nmark in low:
            tail = kp[low.index(nmark) + len(nmark):]
            if tail and "\\" not in tail:
                names_created[tail.lower()] = r.get("last_write", "")
            continue
        i = low.rfind("\\users\\")
        if i == -1:
            continue
        tail = kp[i + len("\\users\\"):]
        if len(tail) == 8 and all(c in _HEX for c in tail):
            u = users.setdefault(tail, {})
            if r.get("value_name") == "F":
                u["F"] = _unhex(r.get("value_data", ""))
            elif r.get("value_name") == "V":
                u["V"] = _unhex(r.get("value_data", ""))

    rows = []
    for rid_hex, fv in users.items():
        rid = int(rid_hex, 16)
        f = _parse_sam_f(fv.get("F", b""))
        v = _parse_sam_v(fv.get("V", b""))
        username = v.get("username", "")
        sid = f"{prefix}-{rid}" if prefix else ""
        path = profiles.get(sid, "")
        created = names_created.get(username.lower(), "")
        rows.append(_ti_row(
            category="Account", name=sid, value=path, source_artifact="SAM",
            username=username, full_name=v.get("full_name", ""), rid=str(rid),
            home_directory=path, created=created,
            last_login=f.get("last_login", ""), password_last_set=f.get("password_last_set", ""),
            last_failed_login=f.get("last_failed_login", ""), login_count=f.get("login_count", ""),
            failed_login_count=f.get("failed_login_count", ""), disabled=f.get("disabled", ""),
            account_flags=f.get("account_flags", ""),
            timestamp=f.get("last_login", "") or created,
        ))
    return rows


def _networks(software: list) -> list[dict]:
    prof: dict[str, dict] = {}
    for r in software:
        kp = r.get("key_path", "")
        if "\\networklist\\profiles\\{" in kp.lower():
            d = prof.setdefault(kp, {})
            if r.get("value_name") == "ProfileName":
                d["name"] = r.get("value_data", "")
            elif r.get("value_name") == "DateLastConnected":
                d["when"] = _systemtime_hex(r.get("value_data", ""))
    return [
        _ti_row(category="Network", name="연결한 네트워크", value=d["name"], timestamp=d.get("when", ""), source_artifact="NetworkList")
        for d in prof.values() if d.get("name")
    ]


def _iplist(value: str) -> str:
    """A REG_MULTI_SZ IP list is stored as a JSON array string ('["1.2.3.4"]')
    by the parser; flatten it to a comma list and drop empty/0.0.0.0."""
    if not value:
        return ""
    s = value.strip()
    if s.startswith("["):
        try:
            return ", ".join(x for x in json.loads(s) if x and x != "0.0.0.0")
        except (ValueError, TypeError):
            return s
    return "" if s == "0.0.0.0" else s


def _network_interfaces(system: list) -> list[dict]:
    mark = "\\services\\tcpip\\parameters\\interfaces\\"
    ifaces: dict[str, dict] = {}
    for r in system:
        low = r.get("key_path", "").lower()
        i = low.find(mark)
        if i == -1:
            continue
        rest = r["key_path"][i + len(mark):]
        guid = rest.split("\\", 1)[0]
        if not guid.startswith("{"):
            continue
        ifaces.setdefault(guid, {})[r.get("value_name", "")] = r.get("value_data", "")

    rows = []
    for guid, d in ifaces.items():
        ip = _iplist(d.get("IPAddress", "")) or d.get("DhcpIPAddress", "")
        if not ip or ip == "0.0.0.0":
            continue
        dhcp = d.get("EnableDHCP", "")
        rows.append(_ti_row(
            category="NetworkInterface", name=guid, value=ip, source_artifact="Tcpip",
            subnet_mask=_iplist(d.get("SubnetMask", "")) or d.get("DhcpSubnetMask", ""),
            gateway=_iplist(d.get("DefaultGateway", "")) or d.get("DhcpDefaultGateway", ""),
            dns_server=d.get("NameServer", "") or d.get("DhcpNameServer", ""),
            dhcp_server=d.get("DhcpServer", ""),
            dhcp_enabled="예" if dhcp in ("1", 1) else "아니오" if dhcp in ("0", 0) else "",
            domain=d.get("Domain", "") or d.get("DhcpDomain", ""),
            lease_obtained=_unixdate(d.get("LeaseObtainedTime", "")),
            lease_terminates=_unixdate(d.get("LeaseTerminatesTime", "")),
        ))
    return rows


def build_target_info(all_results: dict) -> list[dict]:
    hives = _hives_by_name(all_results)
    software = hives.get("SOFTWARE", [])
    system = hives.get("SYSTEM", [])
    sam = hives.get("SAM", [])
    rows: list[dict] = []
    rows += _system_info(software, system)
    rows += _accounts(sam, software)
    rows += _networks(software)
    rows += _network_interfaces(system)
    return rows


# --- Defender ("Windows Defender 요약") ---------------------------------------
# Distil the Defender Operational log (thousands of hourly health rows) into the
# handful of facts an investigator actually wants: what malware was found and
# what was done about it, whether protection was tampered with / history wiped,
# recent scans, and the current signature version. Not a table dump — a
# per-section summary the DefenderView renders as cards.

_DEF_KEYS = (
    "section", "timestamp", "event_id", "title", "detail", "severity", "category",
    "action", "action_time", "process", "user", "source", "remediation", "record_key",
)


def _def_row(**kw) -> dict:
    r = {k: "" for k in _DEF_KEYS}
    r.update(kw)
    return r


def _json(raw: str) -> dict:
    try:
        d = json.loads(raw) if raw else {}
        return d if isinstance(d, dict) else {}
    except (ValueError, TypeError):
        return {}


def _defender_events(all_results: dict):
    for stem, rows in all_results.get("EventLog", {}).items():
        if "defender" in stem.lower():
            yield from rows


# 5007 config-change events are mostly signature/hash churn; only surface the
# ones that touch protection policy (an attacker weakening Defender).
_TAMPER_KEYS = (
    "disableantispyware", "disableantivirus", "disablerealtimemonitoring",
    "disablebehaviormonitoring", "disableioavprotection", "disableonaccessprotection",
    "disablescanonrealtimeenable", "tamperprotection", "exclusions",
    "disableblockatfirstseen", "puaprotection", "disablescriptscanning",
)


def build_defender(all_results: dict) -> list[dict]:
    detections: dict[str, dict] = {}
    tampering: list[tuple] = []
    scans: dict[str, tuple] = {}
    history_cleared: list[tuple] = []
    sig_latest = None  # (ts, version, record_key)

    for r in _defender_events(all_results):
        eid = str(r.get("EventID", ""))
        ts = r.get("timestamp", "")
        rk = r.get("_record_key", "")
        d = _json(r.get("EventData", ""))

        if eid in ("1116", "1117"):
            did = d.get("Detection ID") or f"{ts}|{d.get('Threat Name', '')}"
            rec = detections.setdefault(did, _def_row(section="threat", event_id="1116/1117"))
            for dst, src in (
                ("title", "Threat Name"), ("severity", "Severity Name"),
                ("category", "Category Name"), ("process", "Process Name"),
                ("user", "Detection User"), ("source", "Source Name"),
            ):
                if d.get(src):
                    rec[dst] = d[src]
            if d.get("Path"):
                rec["detail"] = d["Path"]
            elif d.get("Process Name"):
                rec["detail"] = d["Process Name"]
            if eid == "1116":  # detected
                if _earlier(ts, rec["timestamp"]):
                    rec["timestamp"] = ts
                    rec["record_key"] = rk
            else:  # 1117 = action taken
                rec["action_time"] = ts
                act = d.get("Action Name", "")
                if act and act != "해당 없음":
                    rec["action"] = act
                if d.get("Remediation User"):
                    rec["remediation"] = d["Remediation User"]
                if not rec["timestamp"]:
                    rec["timestamp"] = ts
                if not rec["record_key"]:
                    rec["record_key"] = rk

        elif eid == "5001":
            tampering.append((ts, "실시간 보호 사용 안 함", "Defender 실시간 보호가 해제됨", "", rk, eid))
        elif eid == "5010":
            tampering.append((ts, "바이러스 검사 사용 안 함", "", "", rk, eid))
        elif eid == "5012":
            tampering.append((ts, "스파이웨어 검사 사용 안 함", "", "", rk, eid))
        elif eid == "1013":
            history_cleared.append((ts, f"{d.get('Domain', '')}\\{d.get('User', '')}".strip("\\"), rk))
        elif eid == "1001":
            stype = d.get("Scan Parameters") or d.get("Scan Type") or "검사"
            cur = scans.get(stype)
            if cur is None or ts > cur[0]:
                scans[stype] = (ts, d.get("Scan Type", ""), f"{d.get('Domain', '')}\\{d.get('User', '')}".strip("\\"), rk)
        elif eid == "2000":
            if sig_latest is None or ts > sig_latest[0]:
                sig_latest = (ts, d.get("Current security intelligence Version", ""), rk)
        elif eid == "5007":
            blob = (d.get("New Value", "") + d.get("Old Value", "")).lower()
            if any(k in blob for k in _TAMPER_KEYS):
                tampering.append((ts, "보호 구성 변경", f"{d.get('Old Value', '')} → {d.get('New Value', '')}", "", rk, eid))

    out: list[dict] = []
    for rec in sorted(detections.values(), key=lambda x: x["timestamp"]):
        if not rec["action"]:
            rec["action"] = "탐지만 됨"
        out.append(rec)

    if history_cleared:
        history_cleared.sort()
        ts, user, rk = history_cleared[-1]
        out.append(_def_row(
            section="tampering", timestamp=ts, event_id="1013", title="검사/위협 기록 삭제",
            detail=f"Defender 기록이 삭제됨 (총 {len(history_cleared)}회, 최근 시각 표시)",
            user=user, record_key=rk,
        ))
    for ts, title, detail, user, rk, eid in sorted(tampering):
        out.append(_def_row(section="tampering", timestamp=ts, event_id=eid, title=title, detail=detail, user=user, record_key=rk))

    for stype, (ts, scan_type, user, rk) in sorted(scans.items()):
        out.append(_def_row(section="scan", timestamp=ts, event_id="1001", title=stype, detail=scan_type, user=user, record_key=rk))

    if sig_latest:
        out.append(_def_row(section="signature", timestamp=sig_latest[0], event_id="2000", title="보안 인텔리전스 버전", detail=sig_latest[1], record_key=sig_latest[2]))

    return out
