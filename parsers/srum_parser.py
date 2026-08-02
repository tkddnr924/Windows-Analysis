"""SRUM (System Resource Usage Monitor) — SRUDB.dat, an ESE database that
records per-application resource usage over time: network bytes sent/received,
application run time/CPU, network connectivity, push notifications, energy.
Excellent for "what ran and used the network, and when".

Each data table (named by a provider GUID) becomes its own output. Rows keep
every column; on top of that:
  - TimeStamp (ESE DATE_TIME = OLE automation date, UTC) → a leading
    formatted `timestamp` column.
  - AppId / UserId are indexes into SruDbIdMapTable → resolved to the app
    path/name and the user SID as `app` / `user`.

ESE parsing uses libesedb (pyesedb), the same libyal family as the prefetch
parser's libscca — it ships as a self-contained wheel, so the packaged build
needs no extra runtime.

"Parsing" here is faithful table dump + id resolution; interpretation is a
later step.
"""
import datetime as dt
import struct
from pathlib import Path

import pyesedb

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "SRUM"
FILENAMES = ["SRUDB.dat"]

# Provider GUID -> friendly output table name.
_SRUM_TABLES = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "SRUM_NetworkDataUsage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "SRUM_ApplicationResourceUsage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "SRUM_NetworkConnectivityUsage",
    "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "SRUM_PushNotifications",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "SRUM_ApplicationTimeline",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "SRUM_EnergyUsage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "SRUM_EnergyUsageLongTerm",
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": "SRUM_VfuProv",
}

# Shared leading-column order applied to every SRUM output table. The ESE
# "TimeStamp" column is emitted as the formatted, leading "timestamp" (SQLite
# column names are case-insensitive, so keeping both would collide).
_PREFIX = ["timestamp", "app", "user", "AutoIncId", "AppId", "UserId"]
FIELD_ORDER = {name: list(_PREFIX) for name in _SRUM_TABLES.values()}

_CT = pyesedb.column_types
_INT_TYPES = {
    _CT.BOOLEAN, _CT.INTEGER_8BIT_UNSIGNED, _CT.INTEGER_16BIT_SIGNED,
    _CT.INTEGER_16BIT_UNSIGNED, _CT.INTEGER_32BIT_SIGNED, _CT.INTEGER_32BIT_UNSIGNED,
    _CT.INTEGER_64BIT_SIGNED, _CT.CURRENCY,
}
_FLOAT_TYPES = {_CT.FLOAT_32BIT, _CT.DOUBLE_64BIT}
_TEXT_TYPES = {_CT.TEXT, _CT.LARGE_TEXT}

_OLE_EPOCH = dt.datetime(1899, 12, 30, tzinfo=UTC)


def _ole_to_dt(days: float):
    if not days:
        return None
    return _OLE_EPOCH + dt.timedelta(days=days)


def _format_sid(data: bytes) -> str:
    """Binary SID -> S-1-5-.. string."""
    if len(data) < 8:
        return data.hex()
    revision = data[0]
    sub_count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    subs = []
    off = 8
    for _ in range(sub_count):
        if off + 4 > len(data):
            break
        subs.append(str(struct.unpack_from("<I", data, off)[0]))
        off += 4
    return "-".join(["S", str(revision), str(authority)] + subs)


def _value(record, i, ctype):
    raw = record.get_value_data(i)
    if raw is None:
        return ""
    try:
        if ctype in _INT_TYPES:
            return record.get_value_data_as_integer(i)
        if ctype in _FLOAT_TYPES:
            return record.get_value_data_as_floating_point(i)
        if ctype in _TEXT_TYPES:
            try:
                return record.get_value_data_as_string(i) or ""
            except Exception:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if ctype == _CT.DATE_TIME:
            return _ole_to_dt(struct.unpack("<d", raw[:8])[0])
        if ctype == _CT.GUID:
            return raw.hex()
        return raw.hex()
    except Exception:
        return raw.hex() if isinstance(raw, bytes) else str(raw)


def _build_id_map(db) -> dict[int, str]:
    """SruDbIdMapTable maps AppId/UserId indexes to app strings / user SIDs.
    IdType 3 = user (binary SID); everything else = UTF-16 app identifier."""
    id_map: dict[int, str] = {}
    table = None
    for i in range(db.number_of_tables):
        t = db.get_table(i)
        if t.name == "SruDbIdMapTable":
            table = t
            break
    if table is None:
        return id_map

    col_idx = {table.get_column(i).name: i for i in range(table.number_of_columns)}
    it = col_idx.get("IdType")
    ii = col_idx.get("IdIndex")
    ib = col_idx.get("IdBlob")
    if ii is None or ib is None:
        return id_map

    for r in range(table.number_of_records):
        rec = table.get_record(r)
        try:
            idx = rec.get_value_data_as_integer(ii)
            blob = rec.get_value_data(ib)
            id_type = rec.get_value_data_as_integer(it) if it is not None else None
        except Exception:
            continue
        if blob is None or idx is None:
            continue
        if id_type == 3:
            id_map[idx] = _format_sid(blob)
        else:
            id_map[idx] = blob.decode("utf-16-le", errors="replace").rstrip("\x00")
    return id_map


def _dump_table(table, id_map: dict[int, str], source_file: str) -> list[dict]:
    rows: list[dict] = []
    col_types = [(table.get_column(i).name, table.get_column(i).type) for i in range(table.number_of_columns)]
    for r in range(table.number_of_records):
        rec = table.get_record(r)
        row: dict = {"_source_file": source_file}
        app_id = user_id = None
        for i, (name, ctype) in enumerate(col_types):
            val = _value(rec, i, ctype)
            if isinstance(val, dt.datetime):
                val = format_timestamp(val, source_tz=UTC)
            if name == "AppId" and isinstance(val, int):
                app_id = val
            elif name == "UserId" and isinstance(val, int):
                user_id = val
            # The ESE "TimeStamp" column becomes the leading formatted
            # "timestamp"; keeping both would collide (case-insensitive).
            row["timestamp" if name == "TimeStamp" else name] = val
        if app_id is not None:
            row["app"] = id_map.get(app_id, "")
        if user_id is not None:
            row["user"] = id_map.get(user_id, "")
        rows.append(row)
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    results: dict[str, list[dict]] = {}
    for path in paths:
        source_file = str(path)
        db = pyesedb.file()
        try:
            db.open(source_file)
        except Exception as exc:
            results.setdefault("SRUM_Errors", []).append(
                {"timestamp": "", "_source_file": source_file, "_status": "unreadable_file", "_error": str(exc)}
            )
            continue
        try:
            id_map = _build_id_map(db)
            for i in range(db.number_of_tables):
                table = db.get_table(i)
                gname = table.name
                if gname.startswith("MSys") or gname in ("SruDbCheckpointTable", "SruDbIdMapTable"):
                    continue
                output_name = _SRUM_TABLES.get(gname, "SRUM_" + gname.strip("{}").replace("-", ""))
                try:
                    results[output_name] = _dump_table(table, id_map, source_file)
                except Exception as exc:
                    results.setdefault(output_name, []).append(
                        {"timestamp": "", "_source_file": source_file, "_status": "corrupted", "_error": str(exc)}
                    )
        finally:
            db.close()
    return results
