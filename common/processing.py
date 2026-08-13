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
import urllib.parse

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
    "username", "full_name", "rid", "rid_sam", "home_directory", "created", "last_login",
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
            val = _unixdate(r.get("value_data", "")) if name == "InstallDate" else r.get("value_data", "")
            # The Wow6432Node CurrentVersion mirror often carries InstallDate=0;
            # skip an empty/invalid InstallDate so the real one still wins.
            if name == "InstallDate" and not val:
                continue
            seen.add(name)
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
        # RID embedded in the F record (offset 0x30). This is what LSASS uses at
        # logon; when it disagrees with the account's key/folder RID it's the
        # tell-tale of RID hijacking (a low-priv account given RID 500).
        "rid": str(struct.unpack_from("<I", b, 0x30)[0]),
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


def _special_accounts(software: list) -> dict:
    r"""Winlogon SpecialAccounts\UserList: username(lower) -> raw value. A user
    listed with 0 is hidden from the Windows logon screen — a well-known way to
    stash a persistence account so it doesn't show up on the welcome screen."""
    mark = "\\microsoft\\windows nt\\currentversion\\winlogon\\specialaccounts\\userlist"
    out: dict[str, str] = {}
    for r in software:
        if r.get("key_path", "").lower().endswith(mark) and r.get("value_name"):
            out[r["value_name"].lower()] = str(r.get("value_data", "")).strip()
    return out


def _accounts(sam: list, software: list) -> list[dict]:
    hidden = _special_accounts(software)
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
        sp = hidden.get(username.lower())
        special = "" if sp is None else ("예 (로그온 화면 숨김)" if sp in ("0", "0x0") else f"UserList 값 {sp}")
        rows.append(_ti_row(
            category="Account", name=sid, value=path, source_artifact="SAM",
            username=username, full_name=v.get("full_name", ""),
            rid=str(rid), rid_sam=f.get("rid", ""),
            home_directory=path, created=created,
            last_login=f.get("last_login", ""), password_last_set=f.get("password_last_set", ""),
            last_failed_login=f.get("last_failed_login", ""), login_count=f.get("login_count", ""),
            failed_login_count=f.get("failed_login_count", ""), disabled=f.get("disabled", ""),
            account_flags=f.get("account_flags", ""), special_account=special,
            timestamp=f.get("last_login", "") or created,
        ))

    # Accounts that have a profile but no SAM entry — virtual service accounts
    # (S-1-5-80-…, e.g. NT SERVICE\MSSQLSERVER), well-known identities, and
    # domain users. They're real accounts on this host; without this they'd be
    # missing entirely (SAM only holds local security-principal accounts).
    emitted = {r["name"] for r in rows if r["name"]}
    for sid, path in profiles.items():
        if sid in emitted:
            continue
        rows.append(_ti_row(
            category="Account", name=sid, value=path, source_artifact="ProfileList",
            username=_WELL_KNOWN_SIDS.get(sid) or _basename(path.rstrip("\\")) or sid,
            home_directory=path,
        ))
    return rows


_WELL_KNOWN_SIDS = {
    "S-1-5-18": "LocalSystem", "S-1-5-19": "LocalService", "S-1-5-20": "NetworkService",
}


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
    "additional_actions", "origin", "detection_user",
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
    rt_events: list[tuple] = []  # (ts, is_on, record_key) — 5000 on / 5001 off
    sig_latest = None  # (ts, version, record_key)

    for r in _defender_events(all_results):
        eid = str(r.get("EventID", ""))
        ts = r.get("timestamp", "")
        rk = r.get("_record_key", "")
        d = _json(r.get("EventData", ""))

        # Threat detected / action-taken — 1116/1117 (current) and 1006/1007
        # (legacy) both come in a detected+action pair; 1015 is a suspicious-
        # behavior detection. Merge the pair into one record by Detection ID.
        if eid in ("1116", "1117", "1006", "1007", "1015"):
            detected = eid in ("1116", "1006", "1015")
            did = d.get("Detection ID") or f"{ts}|{d.get('Threat Name', '')}"
            rec = detections.setdefault(did, _def_row(section="threat", event_id=eid))
            for dst, src in (
                ("title", "Threat Name"), ("severity", "Severity Name"),
                ("category", "Category Name"), ("process", "Process Name"),
                ("user", "Detection User"), ("detection_user", "Detection User"),
                ("source", "Source Name"), ("origin", "Origin Name"),
            ):
                if d.get(src):
                    rec[dst] = d[src]
            if d.get("Path"):
                rec["detail"] = d["Path"]
            elif d.get("Process Name"):
                rec["detail"] = d["Process Name"]
            if detected:
                if _earlier(ts, rec["timestamp"]):
                    rec["timestamp"] = ts
                    rec["record_key"] = rk
            else:  # action taken (1117 / 1007)
                rec["action_time"] = ts
                act = d.get("Action Name", "")
                if act and act != "해당 없음":
                    rec["action"] = act
                if d.get("Remediation User"):
                    rec["remediation"] = d["Remediation User"]
                if d.get("Additional Actions String") and d["Additional Actions String"] != "No additional actions required":
                    rec["additional_actions"] = d["Additional Actions String"]
                if not rec["timestamp"]:
                    rec["timestamp"] = ts
                if not rec["record_key"]:
                    rec["record_key"] = rk

        elif eid == "5001":
            rt_events.append((ts, False, rk))
        elif eid == "5000":
            rt_events.append((ts, True, rk))
        elif eid == "5004":
            tampering.append((ts, "실시간 보호 구성 변경", "실시간 보호 설정이 변경됨", "", rk, eid))
        elif eid == "5010":
            tampering.append((ts, "바이러스 검사 사용 안 함", "", "", rk, eid))
        elif eid == "5012":
            tampering.append((ts, "스파이웨어 검사 사용 안 함", "", "", rk, eid))
        elif eid == "1119":
            tampering.append((ts, "위협 제거 실패", f"{d.get('Threat Name', '')} 제거/치료 실패", "", rk, eid))
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

    # Real-time protection: collapse the raw 5000/5001 stream to state changes
    # only — routine boot-time "enabled" events would otherwise flood the list.
    # A leading "enabled" (the normal baseline) is not surfaced; a disable and
    # any later re-enable ("복원") are.
    rt_events.sort()
    prev = None
    for ts, is_on, rk in rt_events:
        if prev is None:
            prev = is_on
            if not is_on:
                tampering.append((ts, "실시간 보호 사용 안 함", "Defender 실시간 보호가 해제됨", "", rk, "5001"))
            continue
        if is_on == prev:
            continue
        prev = is_on
        if is_on:
            tampering.append((ts, "실시간 보호 복원", "Defender 실시간 보호가 다시 켜짐", "", rk, "5000"))
        else:
            tampering.append((ts, "실시간 보호 사용 안 함", "Defender 실시간 보호가 해제됨", "", rk, "5001"))

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


# --- RegistryFindings ("레지스트리 특이사항") ----------------------------------
# Curated "things worth a second look" pulled out of the raw hive dumps. Meant
# to grow over time (add a _rf_* extractor + call it in build_registry_findings);
# each finding carries a category + status so the view can group and flag them.
#   status: "의심"(danger) | "주의"(warning) | "정보"(info) | "정상"(ok)

_RF_KEYS = ("timestamp", "category", "name", "value", "status", "detail", "key_path", "source", "command", "user")


def _rf_row(**kw) -> dict:
    r = {k: "" for k in _RF_KEYS}
    r.update(kw)
    return r


def _hive_user(fname: str) -> str:
    up = fname.upper()
    if up == "SOFTWARE":
        return "(시스템)"
    if up == "DEFAULT":
        return ".DEFAULT"
    if up.endswith("NTUSER.DAT"):
        return fname[: -len("_NTUSER.DAT")] if up.endswith("_NTUSER.DAT") else fname
    return fname


def _share_path(value: str) -> str:
    """A LanmanServer\\Shares value is a REG_MULTI_SZ (stored as a JSON list by
    the parser) of 'Key=Value' lines; pull out the Path=."""
    try:
        items = json.loads(value) if value.startswith("[") else [value]
    except (ValueError, TypeError):
        items = [value]
    for it in items:
        if isinstance(it, str) and it.lower().startswith("path="):
            return it[5:]
    return ""


def _rf_shares(system: list) -> list[dict]:
    rows = []
    start = _pick(system, "\\services\\lanmanserver", "Start")
    if start:
        enabled = start in ("2", "3")
        rows.append(_rf_row(
            category="공유 폴더", name="Server 서비스(LanmanServer)",
            value={"2": "자동", "3": "수동", "4": "사용 안 함"}.get(start, start),
            status="정보" if enabled else "정상",
            detail="파일/프린터 공유 서비스" + ("가 실행됩니다 (공유 가능 상태)." if enabled else "가 비활성화되어 있습니다."),
            key_path="…\\Services\\LanmanServer", source="SYSTEM",
        ))
    # Admin-share master switch — AutoShareServer on servers, AutoShareWks on
    # client OSes; a machine may carry either, so check both.
    for vname, role in (("AutoShareServer", "서버"), ("AutoShareWks", "워크스테이션")):
        auto = _pick(system, "\\lanmanserver\\parameters", vname)
        if auto == "0":
            rows.append(_rf_row(
                category="공유 폴더", name=f"관리 공유({vname})", value="0 (사용 안 함)", status="정보",
                detail=f"기본 관리 공유(C$, ADMIN$)가 비활성화되어 있습니다. ({role})",
                key_path="…\\LanmanServer\\Parameters", source="SYSTEM",
            ))
    seen = set()
    for r in system:
        if not r.get("key_path", "").lower().endswith("\\lanmanserver\\shares"):
            continue
        name = r.get("value_name", "")
        if name in ("", "(default)") or name in seen:
            continue
        seen.add(name)
        path = _share_path(r.get("value_data", ""))
        rows.append(_rf_row(
            category="공유 폴더", name=name, value=path or r.get("value_data", "")[:80], status="주의",
            detail="사용자 정의 공유 폴더 — 외부 노출/권한 점검 필요",
            key_path=r.get("key_path", ""), source="SYSTEM", timestamp=r.get("last_write", ""),
        ))
    return rows


# SQL Server internal version → release year. Any instance (MSSQL11.. onward,
# default or named) is handled generically; the map is only for a nicer label.
_MSSQL_VERSIONS = {
    "10": "2008", "11": "2012", "12": "2014", "13": "2016",
    "14": "2017", "15": "2019", "16": "2022", "17": "2025",
}


def _sql_instance_label(inst: str) -> str:
    """'MSSQL15.SQLEXPRESS' -> 'SQLEXPRESS · SQL Server 2019'. Works for every
    version and for named instances; unknown versions still return the raw id."""
    if not inst:
        return ""
    ver_part, _, name = inst.partition(".")
    year = _MSSQL_VERSIONS.get(ver_part.upper().replace("MSSQL", ""))
    label = name or inst
    return f"{label} · SQL Server {year}" if year else label


def _rf_sql_auth(software: list) -> list[dict]:
    # Every SQL Server instance stores its own LoginMode under
    # …\Microsoft SQL Server\<MSSQL##.INSTANCE>\MSSQLServer\LoginMode (also
    # under Wow6432Node on some installs). Scan them all — don't assume a single
    # instance or a particular version.
    rows = []
    for r in software:
        if r.get("value_name") != "LoginMode" or "microsoft sql server" not in r.get("key_path", "").lower():
            continue
        val = r.get("value_data", "")
        inst = next((p for p in r.get("key_path", "").split("\\") if p.upper().startswith("MSSQL") and "." in p), "")
        label = _sql_instance_label(inst)
        mixed = val == "2"
        rows.append(_rf_row(
            category="SQL 인증", name=f"LoginMode — {label}" if label else "LoginMode",
            value={"1": "Windows 인증 전용", "2": "혼합 모드 (SQL+Windows)"}.get(val, f"알 수 없음({val})"),
            status="주의" if mixed else "정상" if val == "1" else "정보",
            detail="혼합 모드 — sa 등 SQL 계정 로그인 사용 가능 (무차별 대입 표적)" if mixed else "Windows 인증만 허용" if val == "1" else "LoginMode 값 확인 필요",
            key_path=r.get("key_path", ""), source="SOFTWARE",
        ))
    return rows


_AUTORUN_SUFFIXES = ("\\currentversion\\run", "\\currentversion\\runonce", "\\policies\\explorer\\run")


def _rf_autoruns(all_results: dict) -> list[dict]:
    rows = []
    for fname, reg in _registry_hives(all_results):
        user = _hive_user(fname)
        for r in reg:
            low = r.get("key_path", "").lower()
            if not any(low.endswith(s) for s in _AUTORUN_SUFFIXES):
                continue
            name = r.get("value_name", "")
            if name in ("", "(default)"):
                continue
            cmd = r.get("value_data", "")
            kind = "RunOnce" if low.endswith("runonce") else "Policy Run" if "policies" in low else "Run"
            rows.append(_rf_row(
                category="자동 실행", name=name, value=cmd, status="정보", detail=kind,
                command=cmd, user=user, key_path=r.get("key_path", ""), source=fname,
                timestamp=r.get("last_write", ""),
            ))
    return rows


def _rf_credential_protection(system: list) -> list[dict]:
    """Settings that decide how exposed cached credentials are to tools like
    mimikatz. Always reported (present or not) so the answer is explicit."""
    rows = []
    wd = _pick(system, "\\securityproviders\\wdigest", "UseLogonCredential")
    if wd == "1":
        rows.append(_rf_row(
            category="자격 증명 보호", name="WDigest UseLogonCredential", value="1 (사용)", status="의심",
            detail="WDigest 평문 자격증명 캐시가 켜져 있음 — mimikatz(sekurlsa/wdigest) 등으로 LSASS에서 평문 암호 추출 가능 (공격자 사전작업 흔적)",
            key_path="…\\Control\\SecurityProviders\\WDigest", source="SYSTEM",
        ))
    elif wd == "0":
        rows.append(_rf_row(
            category="자격 증명 보호", name="WDigest UseLogonCredential", value="0 (사용 안 함)", status="정상",
            detail="WDigest 평문 자격증명 캐시 비활성",
            key_path="…\\Control\\SecurityProviders\\WDigest", source="SYSTEM",
        ))
    else:
        rows.append(_rf_row(
            category="자격 증명 보호", name="WDigest UseLogonCredential", value="미설정 (기본값)", status="정보",
            detail="미설정 — 최신 Windows(8.1/2012 R2+)는 기본 비활성이나, 구버전이거나 값이 추가되면 평문 캐시가 켜질 수 있음",
            key_path="…\\Control\\SecurityProviders\\WDigest", source="SYSTEM",
        ))
    ppl = _pick(system, "\\control\\lsa", "RunAsPPL")
    if ppl in ("1", "2"):
        rows.append(_rf_row(
            category="자격 증명 보호", name="LSASS 보호(RunAsPPL)", value=f"{ppl} (사용)", status="정상",
            detail="LSASS가 PPL(보호 프로세스)로 실행됨 — 자격증명 덤프 난이도 상승",
            key_path="…\\Control\\Lsa", source="SYSTEM",
        ))
    else:
        rows.append(_rf_row(
            category="자격 증명 보호", name="LSASS 보호(RunAsPPL)", value="미설정", status="주의",
            detail="RunAsPPL 미설정 — LSASS가 보호 프로세스로 실행되지 않아 자격증명 덤프에 노출",
            key_path="…\\Control\\Lsa", source="SYSTEM",
        ))
    return rows


def build_registry_findings(all_results: dict) -> list[dict]:
    hives = _hives_by_name(all_results)
    software = hives.get("SOFTWARE", [])
    system = hives.get("SYSTEM", [])
    rows: list[dict] = []
    rows += _rf_credential_protection(system)
    rows += _rf_shares(system)
    rows += _rf_sql_auth(software)
    rows += _rf_autoruns(all_results)
    rows += _rf_execution_traces(all_results)
    return rows


def _rf_execution_traces(all_results: dict) -> list[dict]:
    r"""What a user actually typed/ran, from per-user NTUSER hives:
      - RunMRU  (\...\Explorer\RunMRU): commands typed into the Win+R Run box.
      - TypedPaths (\...\Explorer\TypedPaths): paths typed into Explorer's
        address bar.
    Both are direct evidence of hands-on-keyboard activity, valuable in an
    intrusion; surfaced so they aren't buried in the raw hive dump."""
    rows = []
    for fname, reg in _registry_hives(all_results):
        user = _hive_user(fname)
        for r in reg:
            low = r.get("key_path", "").lower()
            name = r.get("value_name", "")
            if name in ("", "(default)", "MRUList", "MRUListEx"):
                continue
            data = r.get("value_data", "")
            if low.endswith("\\explorer\\runmru"):
                # RunMRU values are '<command>\1' — the trailing \1 is the
                # ShowWindow flag, not part of the command.
                cmd = data[:-2] if data.endswith("\\1") else data
                rows.append(_rf_row(
                    category="실행 흔적", name="Run 대화상자 입력 (RunMRU)", value=cmd, status="정보",
                    command=cmd, user=user, key_path=r.get("key_path", ""), source=fname,
                    timestamp=r.get("last_write", ""),
                ))
            elif low.endswith("\\explorer\\typedpaths"):
                rows.append(_rf_row(
                    category="실행 흔적", name="탐색기 주소 입력 (TypedPaths)", value=data, status="정보",
                    user=user, key_path=r.get("key_path", ""), source=fname,
                    timestamp=r.get("last_write", ""),
                ))
    return rows


# --- BrowserActivity ("브라우저 활동") -----------------------------------------
# Per-account view of the parsed Chrome History: visited URLs and downloaded
# files, with Chrome's WebKit timestamps converted and percent-encoded URLs
# decoded to readable text (so "%EC%B0%A8%EB%9F%89" reads as "차량"). Downloads
# carry the page they came from (tab_url) so a visit ↔ download links up.

_BH_KEYS = (
    "account", "kind", "timestamp", "title", "url", "url_raw",
    "visit_count", "typed_count", "detail", "size", "mime", "danger", "source_url", "status",
)


def _bh_row(**kw) -> dict:
    r = {k: "" for k in _BH_KEYS}
    r.update(kw)
    return r


def _chrome_time(value) -> str:
    """Chrome/WebKit time = microseconds since 1601-01-01 UTC."""
    try:
        v = int(value)
    except (ValueError, TypeError):
        return ""
    if v <= 0:
        return ""
    try:
        dt = _dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=v)
        return format_timestamp(dt.isoformat(), source_tz=UTC)
    except (OverflowError, ValueError):
        return ""


def _url_decode(url: str) -> str:
    if not url:
        return ""
    try:
        return urllib.parse.unquote(url)
    except (ValueError, TypeError):
        return url


def _human_bytes(value) -> str:
    try:
        n = int(value)
    except (ValueError, TypeError):
        return ""
    if n < 0:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{int(f)} {u}" if u == "B" else f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


def _browser_histories(all_results: dict):
    for fname, tables in all_results.get("BrowserHistory", {}).items():
        account = fname[: -len("_Chrome_History")] if fname.endswith("_Chrome_History") else fname
        if isinstance(tables, dict):
            yield account, tables


def _browser_caches(all_results: dict):
    for fname, tables in all_results.get("BrowserCache", {}).items():
        account = fname[: -len("_Chrome_Cache")] if fname.endswith("_Chrome_Cache") else fname
        if isinstance(tables, dict):
            yield account, tables


def build_browser_history(all_results: dict) -> list[dict]:
    rows: list[dict] = []
    # Cached HTTP responses — "what resource was fetched, and when" — so the
    # calendar timeline shows them alongside visits/downloads. The cache parser
    # already formats its timestamps, so reuse them as-is.
    for account, tables in _browser_caches(all_results):
        for c in tables.get("CacheEntries", []):
            # When the response was received (revalidations included); fall back
            # to the entry's creation time, which is always present.
            ts = c.get("response_time") or c.get("creation_time") or ""
            url = c.get("url", "")
            if not ts or not url:
                continue
            rows.append(_bh_row(
                account=c.get("account") or account, kind="cache", timestamp=ts,
                title=_basename(url) or url, url=url,
                mime=c.get("content_type", ""),
                size=c.get("content_length", "") or c.get("body_size", ""),
                status=c.get("status", ""),
            ))
    for account, tables in _browser_histories(all_results):
        for u in tables.get("urls", []):
            raw = u.get("url", "")
            rows.append(_bh_row(
                account=account, kind="visit",
                timestamp=_chrome_time(u.get("last_visit_time", "")),
                title=u.get("title", ""), url=_url_decode(raw), url_raw=raw,
                visit_count=str(u.get("visit_count", "") or ""),
                typed_count=str(u.get("typed_count", "") or ""),
            ))
        for d in tables.get("downloads", []):
            tgt = d.get("target_path", "") or d.get("current_path", "")
            src = d.get("tab_url", "") or d.get("referrer", "") or d.get("site_url", "")
            danger = d.get("danger_type", "")
            rows.append(_bh_row(
                account=account, kind="download",
                timestamp=_chrome_time(d.get("start_time", "")),
                title=_basename(_url_decode(tgt)), detail=_url_decode(tgt),
                url=_url_decode(src), url_raw=src, source_url=_url_decode(src),
                size=_human_bytes(d.get("total_bytes", "") or d.get("received_bytes", "")),
                mime=d.get("mime_type", ""),
                danger=danger if danger not in ("", "0") else "",
            ))
    return rows


def build_rdp_cache(all_results: dict) -> list[dict]:
    """The stitched/reconstructed RDP bitmap-cache images — the reassembled
    "fragment"s only — pulled out of the raw RdpBitmapCache table so they live
    under the processed overview ("RDP 캐시"). The single tiles AND the per-file
    "mosaic" (every tile laid out in cache order, essentially the raw tiles) stay
    in the raw view; nothing is recomputed, the derived rows are just surfaced
    where they belong."""
    rows = []
    for r in all_results.get("RdpCache", {}).get("RdpBitmapCache", []):
        if r.get("kind") == "fragment":
            rows.append(r)
    return rows
