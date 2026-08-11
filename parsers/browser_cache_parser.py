"""Chrome/Chromium disk cache (legacy "blockfile" format) parser.

The HTTP cache lives in a profile's `Cache/Cache_Data/` folder:
  index            hash table of cache-entry addresses (magic 0xC103CAC3)
  data_0..data_3   block files (36 / 256 / 1024 / 4096-byte blocks)
  f_######         separate files, one per large stream (bodies, big headers)

Each cache entry (EntryStore, a 256-byte record in data_1) holds the request
key (the URL) and up to 4 data streams. Stream 0 is the serialized
HttpResponseInfo — request/response times and the raw HTTP response headers
("HTTP/1.1 200 OK\\0Content-Type: …\\0…"). Stream 1 is the response body.

This parser walks the index, pulls each entry's URL and decodes stream 0 into
the HTTP status + headers, so cached responses are reviewable. One sqlite per
account cache (named <account>_Chrome_Cache), table `CacheEntries`.
"""
from __future__ import annotations

import struct
from pathlib import Path

from common.utils import UTC, format_timestamp

ARTIFACT_NAME = "BrowserCache"
# 'index' is found broadly; parse() keeps only real blockfile HTTP caches
# (magic match + parent folder "Cache_Data", excluding "Code Cache").
FILENAMES = ["index"]

_TABLE = "CacheEntries"
FIELD_ORDER = {
    _TABLE: [
        "request_time", "response_time", "creation_time", "url", "status",
        "content_type", "content_length", "content_encoding", "server", "date",
        "last_modified", "etag", "cache_control", "location", "body_size",
        "body_file", "cache_key", "all_headers", "account", "_source_file", "_status", "_error",
    ]
}

_INDEX_MAGIC = 0xC103CAC3
_BLOCK_MAGIC = 0xC104CAC3
_INDEX_HEADER_SIZE = 368
_BLOCK_HEADER_SIZE = 8192
_ENTRY_SIZE = 256
# A cache address (uint32):
#   0x80000000 initialized   0x70000000 file_type (block SIZE class)
#   0x03000000 num_blocks-1  0x00FF0000 file_selector (which data_N file)
#   0x0000FFFF block number   (external files instead use 0x0FFFFFFF as f_ number)
# file_type -> block size in bytes.
_BLOCK_SIZE = {1: 36, 2: 256, 3: 1024, 4: 4096}
_MAX_ENTRIES = 2_000_000


def _account(path: Path) -> str:
    parts = path.parts
    for i, part in enumerate(parts):
        if part.upper() == "BROWSER" and i + 1 < len(parts):
            return parts[i + 1]
    return path.parent.name


def _chrome_time(value: int) -> str:
    if not value or value <= 0:
        return ""
    try:
        import datetime as dt
        return format_timestamp((dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=value)).isoformat(), source_tz=UTC)
    except (OverflowError, ValueError):
        return ""


class _Cache:
    """One Cache_Data folder: keeps the block files in memory and resolves
    cache addresses to raw stream bytes."""

    def __init__(self, cache_dir: Path):
        self.dir = cache_dir
        self._blocks: dict[str, bytes] = {}

    def _block_bytes(self, name: str) -> bytes:
        if name not in self._blocks:
            f = self.dir / name
            self._blocks[name] = f.read_bytes() if f.exists() else b""
        return self._blocks[name]

    def read(self, addr: int, size: int) -> bytes:
        if not (addr & 0x80000000):  # not initialized
            return b""
        file_type = (addr >> 28) & 0x7
        if file_type == 0:  # external f_######
            f = self.dir / f"f_{addr & 0x0FFFFFFF:06x}"
            try:
                data = f.read_bytes()
            except OSError:
                return b""
            return data[:size] if size else data
        block_size = _BLOCK_SIZE.get(file_type)
        if not block_size:
            return b""
        file_selector = (addr >> 16) & 0xFF
        num_blocks = ((addr >> 24) & 0x3) + 1
        block_num = addr & 0xFFFF
        data = self._block_bytes(f"data_{file_selector}")
        off = _BLOCK_HEADER_SIZE + block_num * block_size
        length = size if size else num_blocks * block_size
        return data[off: off + length]


def _parse_headers(stream0: bytes) -> dict:
    """Pull request/response times and the HTTP response headers out of a
    serialized HttpResponseInfo. Robust to version drift: times are read at
    their fixed pickle offsets, headers by locating the 'HTTP/1.' status line
    and reading the following NUL-separated header list."""
    out = {"request_time": "", "response_time": "", "status": "", "all_headers": "", "headers": {}}
    if len(stream0) >= 24:
        # Pickle: [payload_size u32][flags i32][request_time i64][response_time i64]…
        try:
            out["request_time"] = _chrome_time(struct.unpack_from("<q", stream0, 8)[0])
            out["response_time"] = _chrome_time(struct.unpack_from("<q", stream0, 16)[0])
        except struct.error:
            pass
    i = stream0.find(b"HTTP/1.")
    if i == -1:
        i = stream0.find(b"HTTP/2")
    if i != -1:
        end = stream0.find(b"\x00\x00", i)
        blob = stream0[i: end if end != -1 else len(stream0)]
        parts = [p for p in blob.split(b"\x00")]
        lines = []
        headers: dict[str, str] = {}
        for idx, p in enumerate(parts):
            try:
                s = p.decode("utf-8", "replace").strip()
            except Exception:
                continue
            if not s:
                continue
            lines.append(s)
            if idx == 0:
                sp = s.split(" ", 2)
                if len(sp) >= 2:
                    out["status"] = sp[1] + (f" {sp[2]}" if len(sp) > 2 else "")
            elif ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        out["all_headers"] = "\n".join(lines)
        out["headers"] = headers
    return out


def _walk_addresses(cache: _Cache, index_bytes: bytes) -> list[int]:
    """Every EntryStore address reachable from the index hash table (bucket
    heads + their collision `next` chains)."""
    if len(index_bytes) < 32 or struct.unpack_from("<I", index_bytes, 0)[0] != _INDEX_MAGIC:
        return []
    table_len = struct.unpack_from("<i", index_bytes, 28)[0]
    table_len = max(0, min(table_len, (len(index_bytes) - _INDEX_HEADER_SIZE) // 4))
    addrs: list[int] = []
    seen: set[int] = set()
    for b in range(table_len):
        addr = struct.unpack_from("<I", index_bytes, _INDEX_HEADER_SIZE + b * 4)[0]
        while addr and (addr & 0x80000000) and addr not in seen and len(addrs) < _MAX_ENTRIES:
            seen.add(addr)
            addrs.append(addr)
            entry = cache.read(addr, _ENTRY_SIZE)
            if len(entry) < 8:
                break
            addr = struct.unpack_from("<I", entry, 4)[0]  # next (collision chain)
    return addrs


def _entry_row(cache: _Cache, addr: int, account: str, source: str) -> dict | None:
    buf = cache.read(addr, _ENTRY_SIZE)
    if len(buf) < 96:
        return None
    try:
        creation_time = struct.unpack_from("<Q", buf, 24)[0]
        key_len = struct.unpack_from("<i", buf, 32)[0]
        long_key = struct.unpack_from("<I", buf, 36)[0]
        data_size = struct.unpack_from("<4I", buf, 40)
        data_addr = struct.unpack_from("<4I", buf, 56)
    except struct.error:
        return None
    if key_len <= 0 or key_len > 64 * 1024:
        return None
    # Key: inline (from offset 96) when it fits, else in the long_key stream.
    if key_len <= _ENTRY_SIZE - 96:
        key_bytes = buf[96: 96 + key_len]
    else:
        key_bytes = cache.read(long_key, key_len)
    cache_key = key_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
    url = _url_from_key(cache_key)

    h = _parse_headers(cache.read(data_addr[0], data_size[0])) if data_addr[0] else {"headers": {}}
    hd = h.get("headers", {})
    body_addr = data_addr[1]
    body_file = ""
    if body_addr and not ((body_addr >> 28) & 0x7):
        body_file = f"f_{body_addr & 0x0FFFFFFF:06x}"

    return {
        "account": account,
        "url": url,
        "cache_key": cache_key,
        "creation_time": _chrome_time(creation_time),
        "request_time": h.get("request_time", ""),
        "response_time": h.get("response_time", ""),
        "status": h.get("status", ""),
        "content_type": hd.get("content-type", ""),
        "content_length": hd.get("content-length", ""),
        "content_encoding": hd.get("content-encoding", ""),
        "server": hd.get("server", ""),
        "date": hd.get("date", ""),
        "last_modified": hd.get("last-modified", ""),
        "etag": hd.get("etag", ""),
        "cache_control": hd.get("cache-control", ""),
        "location": hd.get("location", ""),
        "body_size": str(data_size[1]) if data_size[1] else "",
        "body_file": body_file,
        "all_headers": h.get("all_headers", ""),
        "_source_file": source,
    }


def _url_from_key(key: str) -> str:
    """Cache keys can be partitioned ("1/0/_dk_https://top https://frame url").
    The fetched resource URL is the last http(s):// token."""
    if not key:
        return ""
    pos = max(key.rfind("http://"), key.rfind("https://"))
    return key[pos:].strip() if pos != -1 else key


def parse(paths: list[Path]) -> dict[str, dict[str, list[dict]]]:
    outputs: dict[str, dict[str, list[dict]]] = {}
    taken: set[str] = set()
    for index_path in paths:
        # Only real HTTP blockfile caches: parent folder Cache_Data, and not the
        # Code Cache (compiled JS/wasm, not HTTP responses).
        if index_path.parent.name != "Cache_Data" or "code cache" in str(index_path).lower():
            continue
        try:
            index_bytes = index_path.read_bytes()
        except OSError:
            continue
        if len(index_bytes) < 4 or struct.unpack_from("<I", index_bytes, 0)[0] != _INDEX_MAGIC:
            continue

        cache = _Cache(index_path.parent)
        account = _account(index_path)
        rows: list[dict] = []
        try:
            for addr in _walk_addresses(cache, index_bytes):
                row = _entry_row(cache, addr, account, str(index_path))
                if row:
                    rows.append(row)
        except Exception as exc:  # keep whatever was recovered
            rows.append({"account": account, "url": "", "_source_file": str(index_path), "_status": "corrupted", "_error": str(exc)})
        if not rows:
            continue

        base = f"{account}_Chrome_Cache"
        name, i = base, 2
        while name in taken:
            name, i = f"{base}_{i}", i + 1
        taken.add(name)
        outputs[name] = {_TABLE: rows}
    return outputs
