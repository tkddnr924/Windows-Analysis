"""RDP client connection history — HKCU\\...\\Terminal Server Client\\Servers,
the record of servers this account has connected TO via the built-in RDP
client (mstsc). Complements the server-side evidence already surfaced in
EventLog_Events (inbound RDP logons, LogonType 10 etc.) with the
outbound/client-side half of remote access activity.

Covers every collected per-user NTUSER.DAT, same as userassist_parser.py.
"""
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from common.hive_recovery import open_hive
from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "TerminalServerClient"
FILE_SUFFIXES = ["_NTUSER.DAT"]

FIELD_ORDER = {
    "RemoteAccess_RDPClientHistory": [
        "timestamp", "server", "username_hint", "cert_hash", "user", "_source_file",
    ],
}


def _user_from_filename(path: Path) -> str:
    suffix = "_NTUSER.DAT"
    if path.name.upper().endswith(suffix.upper()):
        return path.name[: -len(suffix)]
    return path.name


def _parse_hive(hive: RegistryHive, user: str, source_file: str) -> list[dict]:
    rows = []
    try:
        servers_key = hive.get_key(r"\Software\Microsoft\Terminal Server Client\Servers")
    except RegistryKeyNotFoundException:
        return rows

    for server_key in servers_key.iter_subkeys():
        vals = {v.name: v.value for v in server_key.iter_values(as_json=True)}
        rows.append(
            {
                "timestamp": format_timestamp(
                    convert_wintime(server_key.header.last_modified, as_json=True), source_tz=UTC
                ),
                "server": server_key.name,
                "username_hint": vals.get("UsernameHint", ""),
                "cert_hash": vals.get("CertHash", ""),
                "user": user,
                "_source_file": source_file,
            }
        )
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows = []
    for path in paths:
        user = _user_from_filename(path)
        source_file = str(path)
        try:
            with open_hive(path) as hive:
                rows.extend(_parse_hive(hive, user, source_file))
        except Exception as exc:
            rows.append(
                {
                    "timestamp": "",
                    "server": "",
                    "username_hint": "",
                    "cert_hash": "",
                    "user": user,
                    "_source_file": source_file,
                    "_status": "unreadable_file",
                    "_error": str(exc),
                }
            )
    return {"RemoteAccess_RDPClientHistory": rows}
