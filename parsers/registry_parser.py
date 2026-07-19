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

from common.hive_recovery import open_hive
from common.utils import KST, UTC, format_timestamp

ARTIFACT_NAME = "Registry"
FILENAMES = ["SYSTEM", "SOFTWARE"]

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


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    run_rows, program_rows, profile_rows, system_info_rows, usb_rows, network_rows = [], [], [], [], [], []

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
                elif hive_name == "SYSTEM":
                    for control_set in _control_sets(hive):
                        system_info_rows.extend(_parse_system_info_from_system(hive, f"\\{control_set}", source_file))
                        usb_rows.extend(_parse_usb_devices(hive, f"\\{control_set}", source_file))
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

    return {
        "Registry_Run": run_rows,
        "Registry_InstalledPrograms": program_rows,
        "Registry_UserProfiles": profile_rows,
        "Registry_SystemInfo": system_info_rows,
        "Registry_USBDevices": usb_rows,
        "Registry_NetworkProfiles": network_rows,
    }
