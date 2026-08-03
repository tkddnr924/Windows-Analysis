"""SYSTEM / SOFTWARE registry hive parser, similar in spirit to RegRipper /
Eric Zimmerman's RECmd — pulls a curated set of well-known, high-value keys
rather than dumping the entire hive tree.

Covers:
- Registry_Run: Run/RunOnce autostart entries (SOFTWARE, persistence)
- Registry_InstalledPrograms: Add/Remove Programs (Uninstall) entries
- Registry_UserProfiles: local user profiles, with load/unload times
- Registry_SystemInfo: computer name, OS version, timezone, shutdown time,
  active ControlSet — a small flat "finding" table, since these are
  heterogeneous single values rather than a uniform row-per-item table
- Registry_USBDevices: USB/USBSTOR device enumeration history (SYSTEM)
- Registry_NetworkProfiles: networks this machine has connected to, with
  last-connected time (SOFTWARE) — not an IP address, but the closest
  "what network was this on, and when" evidence available without a
  dedicated network-interface artifact

SAM/SECURITY/DEFAULT and the full \\Services / \\Enum trees are
intentionally out of scope for this first pass — SAM in particular touches
credential material and deserves a deliberate, separate decision rather
than being folded in here.

SYSTEM can have more than one ControlSetNNN (a backup set survives a bad
boot); every ControlSetNNN found at the hive root is walked and tagged
with its own name rather than assuming ControlSet001 is authoritative.
"""
import datetime as dt
import struct
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

# SAM account metadata (creation/login times, flags) comes from regipy's SAM
# plugin. Imported defensively: it was added in newer regipy releases, and a
# missing/renamed plugin must degrade to "no accounts table", never break the
# whole registry parser's import.
try:
    from regipy.plugins.sam.samparse import SAMParsePlugin
except Exception:  # pragma: no cover - depends on installed regipy version
    SAMParsePlugin = None

from common.hive_recovery import open_hive
from common.utils import KST, UTC, format_timestamp

ARTIFACT_NAME = "Registry"
# SAM is included ONLY for account metadata (creation/login times) — no
# credential/hash material is read (see _parse_sam_accounts).
FILENAMES = ["SYSTEM", "SOFTWARE", "SAM"]

FIELD_ORDER = {
    "Registry_Run": [
        "key_last_write", "hive", "run_type", "key_path", "value_name",
        "value_data", "_source_file",
    ],
    "Registry_InstalledPrograms": [
        "install_date", "key_last_write", "display_name", "display_version",
        "publisher", "install_location", "uninstall_string",
        "estimated_size_kb", "registry_key", "_source_file",
    ],
    "Registry_UserProfiles": [
        "load_time", "unload_time", "sid", "profile_image_path", "flags",
        "state", "_source_file",
    ],
    "Registry_SystemInfo": [
        "timestamp", "category", "name", "value", "source_path", "_source_file",
    ],
    "Registry_USBDevices": [
        "key_last_write", "control_set", "device_class", "instance_id",
        "friendly_name", "service", "_source_file",
    ],
    "Registry_NetworkProfiles": [
        "timestamp", "profile_name", "_source_file",
    ],
    "Registry_NetworkInterfaces": [
        "ip_address", "subnet_mask", "default_gateway", "dhcp_server",
        "dns_server", "domain", "dhcp_enabled", "lease_obtained",
        "lease_terminates", "interface_guid", "control_set", "_source_file",
    ],
    "Registry_Accounts": [
        "account_created", "username", "full_name", "rid", "home_directory",
        "last_login", "password_last_set", "last_failed_login",
        "login_count", "failed_login_count", "disabled", "special_account",
        "groups", "account_flags", "_source_file",
    ],
}


def _fmt(value, source_tz=UTC) -> str:
    return format_timestamp(value, source_tz=source_tz) if value else ""


def _key_values(key) -> dict:
    return {v.name: v.value for v in key.iter_values(as_json=True)}


def _combine_filetime(low, high) -> int:
    if not low and not high:
        return 0
    return ((high or 0) << 32) | (low or 0)


def _binary_filetime_hex_to_int(hex_str: str) -> int:
    """Some FILETIME values are stored as REG_BINARY (8 bytes,
    little-endian) rather than REG_QWORD — e.g. \\Control\\Windows'
    ShutdownTime — and arrive here as a hex string."""
    try:
        return int.from_bytes(bytes.fromhex(hex_str), byteorder="little")
    except (ValueError, TypeError):
        return 0


def _parse_run_keys(hive: RegistryHive, source_file: str) -> list[dict]:
    rows = []
    candidates = [
        (r"\Microsoft\Windows\CurrentVersion\Run", "Run"),
        (r"\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
        (r"\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "Run (Wow6432Node)"),
        (r"\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce (Wow6432Node)"),
    ]
    for key_path, run_type in candidates:
        try:
            key = hive.get_key(key_path)
        except RegistryKeyNotFoundException:
            continue
        key_last_write = _fmt(convert_wintime(key.header.last_modified, as_json=True))
        for value in key.iter_values(as_json=True):
            if value.name == "(default)":
                continue
            rows.append(
                {
                    "key_last_write": key_last_write,
                    "hive": "SOFTWARE",
                    "run_type": run_type,
                    "key_path": key_path.lstrip("\\"),
                    "value_name": value.name,
                    "value_data": value.value,
                    "_source_file": source_file,
                }
            )
    return rows


def _parse_installed_programs(hive: RegistryHive, source_file: str) -> list[dict]:
    rows = []
    for base in (
        r"\Microsoft\Windows\CurrentVersion\Uninstall",
        r"\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ):
        try:
            key = hive.get_key(base)
        except RegistryKeyNotFoundException:
            continue

        for sub in key.iter_subkeys():
            vals = _key_values(sub)
            display_name = vals.get("DisplayName")
            if not display_name:
                continue  # many Uninstall subkeys are patches/components with no user-facing name

            install_date_str = vals.get("InstallDate")
            install_date = ""
            if install_date_str and len(install_date_str) == 8 and install_date_str.isdigit():
                try:
                    # Written by the installer using the local system clock
                    # at install time — already local, not UTC.
                    naive = dt.datetime.strptime(install_date_str, "%Y%m%d")
                    install_date = format_timestamp(naive, source_tz=KST)
                except ValueError:
                    install_date = install_date_str

            rows.append(
                {
                    "install_date": install_date,
                    "key_last_write": _fmt(convert_wintime(sub.header.last_modified, as_json=True)),
                    "display_name": display_name,
                    "display_version": vals.get("DisplayVersion", ""),
                    "publisher": vals.get("Publisher", ""),
                    "install_location": vals.get("InstallLocation", ""),
                    "uninstall_string": vals.get("UninstallString", ""),
                    "estimated_size_kb": vals.get("EstimatedSize", ""),
                    "registry_key": f"{base.lstrip(chr(92))}\\{sub.name}",
                    "_source_file": source_file,
                }
            )
    return rows


def _parse_user_profiles(hive: RegistryHive, source_file: str) -> list[dict]:
    try:
        key = hive.get_key(r"\Microsoft\Windows NT\CurrentVersion\ProfileList")
    except RegistryKeyNotFoundException:
        return []

    rows = []
    for sub in key.iter_subkeys():
        vals = _key_values(sub)
        load_time = _combine_filetime(vals.get("LocalProfileLoadTimeLow"), vals.get("LocalProfileLoadTimeHigh"))
        unload_time = _combine_filetime(vals.get("LocalProfileUnloadTimeLow"), vals.get("LocalProfileUnloadTimeHigh"))
        rows.append(
            {
                "load_time": _fmt(convert_wintime(load_time, as_json=True)) if load_time else "",
                "unload_time": _fmt(convert_wintime(unload_time, as_json=True)) if unload_time else "",
                "sid": sub.name,
                "profile_image_path": vals.get("ProfileImagePath", ""),
                "flags": vals.get("Flags", ""),
                "state": vals.get("State", ""),
                "_source_file": source_file,
            }
        )
    return rows


def _parse_system_info_from_software(hive: RegistryHive, source_file: str) -> list[dict]:
    rows = []
    try:
        key = hive.get_key(r"\Microsoft\Windows NT\CurrentVersion")
        vals = _key_values(key)
    except RegistryKeyNotFoundException:
        vals = {}

    # InstallDate here is a Unix epoch integer (seconds since 1970 UTC) —
    # unambiguous by definition, unlike the per-program ARP InstallDate.
    install_date_formatted = _fmt(vals.get("InstallDate"), source_tz=UTC)
    findings = [
        ("OS", "ProductName", vals.get("ProductName", ""), ""),
        ("OS", "DisplayVersion", vals.get("DisplayVersion", vals.get("ReleaseId", "")), ""),
        ("OS", "CurrentBuild", vals.get("CurrentBuild", ""), ""),
        ("OS", "EditionID", vals.get("EditionID", ""), ""),
        ("OS", "RegisteredOwner", vals.get("RegisteredOwner", ""), ""),
        ("OS", "InstallDate", install_date_formatted, install_date_formatted),
    ]
    for category, name, value, timestamp in findings:
        if not value:
            continue
        rows.append(
            {
                "timestamp": timestamp,
                "category": category,
                "name": name,
                "value": value,
                "source_path": r"Microsoft\Windows NT\CurrentVersion",
                "_source_file": source_file,
            }
        )
    return rows


def _parse_system_info_from_system(hive: RegistryHive, control_set: str, source_file: str) -> list[dict]:
    rows = []

    try:
        cn = _key_values(hive.get_key(f"{control_set}\\Control\\ComputerName\\ComputerName"))
        if cn.get("ComputerName"):
            rows.append(
                {
                    "timestamp": "",
                    "category": "System",
                    "name": "ComputerName",
                    "value": cn["ComputerName"],
                    "source_path": f"{control_set}\\Control\\ComputerName\\ComputerName",
                    "_source_file": source_file,
                }
            )
    except RegistryKeyNotFoundException:
        pass

    try:
        tz = _key_values(hive.get_key(f"{control_set}\\Control\\TimeZoneInformation"))
        if tz.get("TimeZoneKeyName"):
            rows.append(
                {
                    "timestamp": "",
                    "category": "System",
                    "name": "TimeZone",
                    "value": tz["TimeZoneKeyName"],
                    "source_path": f"{control_set}\\Control\\TimeZoneInformation",
                    "_source_file": source_file,
                }
            )
    except RegistryKeyNotFoundException:
        pass

    try:
        win = _key_values(hive.get_key(f"{control_set}\\Control\\Windows"))
        shutdown_raw = win.get("ShutdownTime")
        if shutdown_raw:
            shutdown_filetime = _binary_filetime_hex_to_int(shutdown_raw)
            rows.append(
                {
                    "timestamp": _fmt(convert_wintime(shutdown_filetime, as_json=True)) if shutdown_filetime else "",
                    "category": "System",
                    "name": "LastShutdownTime",
                    "value": "",
                    "source_path": f"{control_set}\\Control\\Windows",
                    "_source_file": source_file,
                }
            )
    except RegistryKeyNotFoundException:
        pass

    return rows


def _parse_usb_devices(hive: RegistryHive, control_set: str, source_file: str) -> list[dict]:
    rows = []
    for enum_class in ("USBSTOR", "USB"):
        try:
            enum_key = hive.get_key(f"{control_set}\\Enum\\{enum_class}")
        except RegistryKeyNotFoundException:
            continue

        for device_class in enum_key.iter_subkeys():
            for instance in device_class.iter_subkeys():
                vals = _key_values(instance)
                rows.append(
                    {
                        "key_last_write": _fmt(convert_wintime(instance.header.last_modified, as_json=True)),
                        "control_set": control_set,
                        "device_class": device_class.name,
                        "instance_id": instance.name,
                        "friendly_name": vals.get("FriendlyName", ""),
                        "service": vals.get("Service", ""),
                        "_source_file": source_file,
                    }
                )
    return rows


def _systemtime_to_datetime(hex_str: str) -> dt.datetime | None:
    """Decode a Windows SYSTEMTIME structure (8 little-endian uint16 fields:
    year, month, day-of-week, day, hour, minute, second, millisecond) —
    the format NetworkList\\Profiles stores DateCreated/DateLastConnected
    in, not a FILETIME. Verified against this project's own real data
    (decoded values land in this dataset's known activity window)."""
    try:
        data = bytes.fromhex(hex_str)
        year, month, _dow, day, hour, minute, second, ms = struct.unpack_from("<8H", data, 0)
        return dt.datetime(year, month, day, hour, minute, second, ms * 1000)
    except (ValueError, TypeError):
        return None


def _parse_network_profiles(hive: RegistryHive, source_file: str) -> list[dict]:
    try:
        key = hive.get_key(r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    except RegistryKeyNotFoundException:
        return []

    rows = []
    for sub in key.iter_subkeys():
        vals = _key_values(sub)
        profile_name = vals.get("ProfileName")
        if not profile_name:
            continue
        raw = vals.get("DateLastConnected")
        # NetworkList's DateLastConnected is documented as local system
        # time, not UTC (unlike FILETIME-based fields elsewhere in this
        # project) — so it's tagged KST directly, not shifted.
        connected = _systemtime_to_datetime(raw) if isinstance(raw, str) else None
        rows.append(
            {
                "timestamp": format_timestamp(connected, source_tz=KST) if connected else "",
                "profile_name": profile_name,
                "_source_file": source_file,
            }
        )
    return rows


def _control_sets(hive: RegistryHive) -> list[str]:
    return [s.name for s in hive.root.iter_subkeys() if s.name.upper().startswith("CONTROLSET")]


def _ip_value(vals: dict, dhcp_key: str, static_key: str) -> str:
    """An interface's address (or gateway/mask): DHCP value if leased, else the
    static (REG_MULTI_SZ) value. Drops the 0.0.0.0 placeholder DHCP writes when
    no lease is held."""
    dhcp = vals.get(dhcp_key)
    if isinstance(dhcp, str) and dhcp.strip() and dhcp.strip() != "0.0.0.0":
        return dhcp.strip()
    static = vals.get(static_key)
    if isinstance(static, list):
        joined = ", ".join(x for x in static if x and x != "0.0.0.0")
        if joined:
            return joined
    if isinstance(static, str) and static.strip() and static.strip() != "0.0.0.0":
        return static.strip()
    return ""


def _dns_servers(vals: dict) -> str:
    dhcp = vals.get("DhcpNameServer")
    if isinstance(dhcp, str) and dhcp.strip():
        return dhcp.strip().replace(" ", ", ")
    static = vals.get("NameServer")
    if isinstance(static, str) and static.strip():
        return static.strip()
    return ""


def _parse_network_interfaces(hive: RegistryHive, source_file: str) -> list[dict]:
    r"""TCP/IP configuration per network adapter, from SYSTEM
    \<ControlSet>\Services\Tcpip\Parameters\Interfaces\<GUID> — the actual IP
    addresses, gateway, DNS and DHCP lease. This is where a machine's IPs
    live; the NetworkList\Profiles key only has the network's *name* and
    last-connected time, no address. Adapters with no address are skipped, and
    a GUID seen in one ControlSet isn't repeated from the backup set."""
    seen = set()
    rows = []
    for control_set in _control_sets(hive):
        try:
            key = hive.get_key(f"\\{control_set}\\Services\\Tcpip\\Parameters\\Interfaces")
        except RegistryKeyNotFoundException:
            continue
        for sub in key.iter_subkeys():
            guid = sub.name
            if guid in seen:
                continue
            vals = _key_values(sub)
            ip = _ip_value(vals, "DhcpIPAddress", "IPAddress")
            if not ip:
                continue
            seen.add(guid)
            lease_o = vals.get("LeaseObtainedTime")
            lease_t = vals.get("LeaseTerminatesTime")
            enable_dhcp = vals.get("EnableDHCP")
            domain = vals.get("Domain") or vals.get("DhcpDomain") or ""
            dhcp_server = vals.get("DhcpServer")
            rows.append(
                {
                    "ip_address": ip,
                    "subnet_mask": _ip_value(vals, "DhcpSubnetMask", "SubnetMask"),
                    "default_gateway": _ip_value(vals, "DhcpDefaultGateway", "DefaultGateway"),
                    "dhcp_server": dhcp_server.strip() if isinstance(dhcp_server, str) else "",
                    "dns_server": _dns_servers(vals),
                    "domain": domain if isinstance(domain, str) else "",
                    "dhcp_enabled": "예" if enable_dhcp == 1 else ("아니오" if enable_dhcp is not None else ""),
                    # LeaseObtainedTime/LeaseTerminatesTime are Unix epoch (UTC).
                    "lease_obtained": format_timestamp(lease_o, source_tz=UTC) if isinstance(lease_o, int) and lease_o else "",
                    "lease_terminates": format_timestamp(lease_t, source_tz=UTC) if isinstance(lease_t, int) and lease_t else "",
                    "interface_guid": guid,
                    "control_set": control_set,
                    "_source_file": source_file,
                }
            )
    return rows


# Well-known local group (alias) RIDs -> readable name, used when the group's
# own name string can't be read from its C value.
_WELLKNOWN_ALIASES = {
    544: "Administrators(관리자)", 545: "Users(사용자)", 546: "Guests(게스트)",
    547: "Power Users", 548: "Account Operators", 549: "Server Operators",
    550: "Print Operators", 551: "Backup Operators(백업 운영자)", 552: "Replicators",
    555: "Remote Desktop Users(원격 데스크톱)", 556: "Network Configuration Operators",
    559: "Performance Log Users", 562: "Distributed COM Users", 568: "IIS_IUSRS",
    569: "Cryptographic Operators", 573: "Event Log Readers",
    574: "Certificate Service DCOM Access", 578: "Hyper-V Administrators",
    579: "Access Control Assistance Operators", 580: "Remote Management Users(WinRM)",
}


def _as_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("latin-1", "ignore")
    return b""


def _read_sid(data: bytes, off: int):
    """Parse one binary SID at `off`; return (sid_string, bytes_consumed) or
    (None, 0) if it doesn't look like a SID."""
    if off + 8 > len(data):
        return None, 0
    revision = data[off]
    sub_count = data[off + 1]
    if revision != 1 or sub_count > 15:
        return None, 0
    length = 8 + 4 * sub_count
    if off + length > len(data):
        return None, 0
    authority = int.from_bytes(data[off + 2 : off + 8], "big")
    subs = [int.from_bytes(data[off + 8 + 4 * i : off + 12 + 4 * i], "little") for i in range(sub_count)]
    sid = f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)
    return sid, length


def _parse_alias_c(data: bytes):
    """Group name + member SIDs from an Aliases\\<RID>\\C binary value.
    Offsets are relative to a 0x34-byte header. Best-effort: any mismatch
    yields an empty member list rather than wrong data."""
    if len(data) < 0x34:
        return "", []
    try:
        name_off = int.from_bytes(data[0x0C:0x10], "little") + 0x34
        name_len = int.from_bytes(data[0x10:0x14], "little")
        name = data[name_off : name_off + name_len].decode("utf-16-le", "replace") if 0 < name_len and name_off + name_len <= len(data) else ""

        members_off = int.from_bytes(data[0x24:0x28], "little") + 0x34
        members_len = int.from_bytes(data[0x28:0x2C], "little")
        end = min(len(data), members_off + members_len) if members_len else len(data)
        members = []
        off = members_off
        while off < end:
            sid, consumed = _read_sid(data, off)
            if not sid or consumed == 0:
                break
            members.append(sid)
            off += consumed
        return name, members
    except (struct.error, IndexError, ValueError):
        return "", []


def _parse_sam_groups(hive: RegistryHive) -> dict:
    """Map a local RID -> the local groups it belongs to, from the Aliases
    membership under SAM (Builtin + Account domains). Members are stored as
    full SIDs; we key by the trailing RID so a user (keyed by RID elsewhere)
    can be matched without needing the machine SID prefix."""
    by_rid: dict[str, list[str]] = {}
    for alias_path in (r"\SAM\Domains\Builtin\Aliases", r"\SAM\Domains\Account\Aliases"):
        try:
            aliases = hive.get_key(alias_path)
        except RegistryKeyNotFoundException:
            continue
        for sub in aliases.iter_subkeys():
            if sub.name in ("Members", "Names"):
                continue
            try:
                alias_rid = int(sub.name, 16)
            except ValueError:
                continue
            c_value = None
            for v in sub.iter_values():
                if v.name == "C":
                    c_value = v.value
                    break
            if c_value is None:
                continue
            name, members = _parse_alias_c(_as_bytes(c_value))
            group_name = name or _WELLKNOWN_ALIASES.get(alias_rid, f"RID {alias_rid}")
            for sid in members:
                member_rid = sid.rsplit("-", 1)[-1]
                by_rid.setdefault(member_rid, [])
                if group_name not in by_rid[member_rid]:
                    by_rid[member_rid].append(group_name)
    return by_rid


def _parse_special_accounts(hive: RegistryHive) -> dict:
    """Winlogon SpecialAccounts\\UserList (SOFTWARE): username -> value.
    Value 0 = the account is HIDDEN from the logon screen — a common
    account-hiding / persistence technique. Keyed lowercase for joining."""
    try:
        key = hive.get_key(r"\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList")
    except RegistryKeyNotFoundException:
        return {}
    result = {}
    for v in key.iter_values(as_json=True):
        if v.name:
            result[v.name.lower()] = v.value
    return result


def _parse_sam_accounts(hive: RegistryHive, source_file: str) -> list[dict]:
    """Local user accounts from the SAM hive: creation date, login/password
    times, counts, flags and local group membership — NOT password hashes or
    any other credential material.

    The account CREATION date is the last-write time of each account's
    SAM\\...\\Users\\Names\\<username> subkey (the standard forensic proxy for
    when the account was created), surfaced by the plugin as
    `name_key_last_write`. Login/password times and counts come from the F
    value; name/home directory from the V value; groups from the Aliases.
    """
    if SAMParsePlugin is None:
        return []

    try:
        plugin = SAMParsePlugin(hive, as_json=True)
        plugin.run()
        entries = plugin.entries or []
    except Exception:
        return []

    groups_by_rid = _parse_sam_groups(hive)

    rows = []
    for e in entries:
        flags = e.get("account_flags_parsed") or []
        rid = e.get("rid")
        rid_str = str(rid) if rid is not None else ""
        rows.append(
            {
                "account_created": _fmt(e.get("name_key_last_write")),
                "username": e.get("username", "") or "",
                "full_name": e.get("full_name", "") or "",
                "rid": rid_str,
                "home_directory": e.get("home_directory", "") or "",
                "last_login": _fmt(e.get("last_login")),
                "password_last_set": _fmt(e.get("password_last_set")),
                "last_failed_login": _fmt(e.get("last_failed_login")),
                "login_count": str(e.get("login_count", "") or ""),
                "failed_login_count": str(e.get("failed_login_count", "") or ""),
                "disabled": "예" if "Account Disabled" in flags else "아니오",
                "special_account": "",  # filled in from SOFTWARE after all hives parse
                "groups": ", ".join(groups_by_rid.get(rid_str, [])),
                "account_flags": ", ".join(flags),
                "_source_file": source_file,
            }
        )
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    run_rows, program_rows, profile_rows, system_info_rows, usb_rows, network_rows = [], [], [], [], [], []
    account_rows = []
    network_iface_rows = []
    special_accounts: dict = {}  # from SOFTWARE; joined onto SAM accounts below

    for path in paths:
        source_file = str(path)
        hive_name = path.name.upper()

        try:
            with open_hive(path) as hive:
                if hive_name == "SOFTWARE":
                    run_rows.extend(_parse_run_keys(hive, source_file))
                    program_rows.extend(_parse_installed_programs(hive, source_file))
                    profile_rows.extend(_parse_user_profiles(hive, source_file))
                    system_info_rows.extend(_parse_system_info_from_software(hive, source_file))
                    network_rows.extend(_parse_network_profiles(hive, source_file))
                    special_accounts.update(_parse_special_accounts(hive))
                elif hive_name == "SYSTEM":
                    for control_set in _control_sets(hive):
                        system_info_rows.extend(_parse_system_info_from_system(hive, f"\\{control_set}", source_file))
                        usb_rows.extend(_parse_usb_devices(hive, f"\\{control_set}", source_file))
                    network_iface_rows.extend(_parse_network_interfaces(hive, source_file))
                elif hive_name == "SAM":
                    account_rows.extend(_parse_sam_accounts(hive, source_file))
        except Exception as exc:
            system_info_rows.append(
                {
                    "timestamp": "",
                    "category": "_error",
                    "name": hive_name,
                    "value": str(exc),
                    "source_path": "",
                    "_source_file": source_file,
                }
            )

    # SpecialAccounts lives in SOFTWARE but describes SAM accounts, so join it
    # in after every hive is parsed (order of `paths` isn't guaranteed).
    for row in account_rows:
        val = special_accounts.get((row.get("username") or "").lower())
        if val is None:
            row["special_account"] = "아니오"
        else:
            row["special_account"] = "예(로그온 화면 숨김)" if str(val) in ("0", "0x0") else f"예(값 {val})"

    return {
        "Registry_Run": run_rows,
        "Registry_InstalledPrograms": program_rows,
        "Registry_UserProfiles": profile_rows,
        "Registry_SystemInfo": system_info_rows,
        "Registry_USBDevices": usb_rows,
        "Registry_NetworkProfiles": network_rows,
        "Registry_NetworkInterfaces": network_iface_rows,
        "Registry_Accounts": account_rows,
    }
