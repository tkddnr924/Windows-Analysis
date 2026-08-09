"""RDP bitmap cache parser (RDP8bmp persistent cache — Cache####.bin).

When a user connects out via mstsc.exe, the RDP client caches the screen tiles
it has already drawn so it doesn't re-download them. Each tile is a 64-wide
(height varies) fragment of what was displayed in the remote session — file
names, window titles, dialog text. Reassembling them can reveal what an
operator actually did over RDP, which is high value in an intrusion.

Format (newer clients, "%LOCALAPPDATA%\\...\\Terminal Server Client\\Cache\\
Cache0000.bin"): a 12-byte container header (b"RDP8bmp\\x00" + 4 bytes), then
repeating tiles:

    key (8 bytes) | width (uint16 LE) | height (uint16 LE) | pixels (w*h*4, BGRA)

The old bcacheXX.bmc container is handled too but is usually empty on modern
systems, so it simply yields no tiles.

Tiles carry NO screen coordinates, so a perfect screen rebuild is impossible.
But the pixels are lossless, so two tiles that were adjacent on screen share an
identical border column/row. We exploit that: hash each tile's four edges and
join tiles whose touching edges match exactly (skipping blank/uniform edges,
which would join everything), then lay each connected group out on a grid and
render it as one stitched image — a reconstructed screen fragment. This is the
same idea as RdpCacheStitcher, done automatically.

Output is ONE table (RdpBitmapCache) mixing row kinds via `kind`:
  - "mosaic"  : per source file, every tile stitched in cache order (see-all).
  - "fragment": a reconstructed multi-tile region (the useful part), largest first.
  - "tile"    : leftover single tiles that didn't join, exact-deduped with a count.
Each image rides as a base64 PNG in `image`, so the output stays self-contained
in SQLite. PNGs use a small stdlib zlib encoder — no image library to bundle. A
tile whose declared size runs past EOF is surfaced as a _status="corrupted" row.
"""
from __future__ import annotations

import base64
import hashlib
import struct
import zlib
from collections import defaultdict, deque
from pathlib import Path

ARTIFACT_NAME = "RdpCache"
CONTENT_MARKER = "RDP8bmp"  # container magic, used to locate cache files by content
_MAGIC = b"RDP8bmp\x00"

_OUTPUT = "RdpBitmapCache"
FIELD_ORDER = {
    _OUTPUT: [
        "kind", "source_file", "fragment_index", "tile_count", "cols", "rows",
        "tile_index", "count", "width", "height", "key", "image",
        "_source_file", "_status", "_error",
    ]
}

_TILE = 64            # grid cell size for stitched/mosaic layout (tiles are <= 64)
_MOSAIC_COLS = 48     # tiles per row in the see-all mosaic
_MAX_DIM = 256        # sanity bound; a larger declared tile means corruption
_BG = (16, 20, 26)    # dark background behind stitched cells
_MIN_FRAGMENT = 2     # a "fragment" is 2+ tiles joined; singles fall to "tile"


def _png(width: int, height: int, rgb: bytes) -> str:
    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    stride = width * 3
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type 0 (none)
        raw += rgb[y * stride:(y + 1) * stride]
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    return base64.b64encode(png).decode("ascii")


def _bgra_to_rgb(bgra: bytes, count: int) -> bytearray:
    rgb = bytearray(count * 3)
    rgb[0::3] = bgra[2::4]  # R
    rgb[1::3] = bgra[1::4]  # G
    rgb[2::3] = bgra[0::4]  # B
    return rgb


def _decode_file(path: Path) -> tuple[list[dict], list[dict]]:
    data = path.read_bytes()
    src, full = path.name, str(path)
    tiles: list[dict] = []
    corrupt: list[dict] = []

    if data[:8] != _MAGIC:
        corrupt.append({"kind": "tile", "source_file": src, "_source_file": full,
                        "_status": "unreadable_file", "_error": f"not an RDP8bmp cache (magic={data[:8]!r})"})
        return tiles, corrupt

    off, idx, n = 12, 0, len(data)
    while off + 12 <= n:
        key = data[off:off + 8]
        width, height = struct.unpack_from("<HH", data, off + 8)
        px_off = off + 12
        px_len = width * height * 4
        if width == 0 or height == 0 or width > _MAX_DIM or height > _MAX_DIM or px_off + px_len > n:
            corrupt.append({"kind": "tile", "source_file": src, "tile_index": str(idx), "_source_file": full,
                            "_status": "corrupted",
                            "_error": f"tile {idx}: declared {width}x{height} at offset {off} runs past end"})
            break
        tiles.append({"i": idx, "w": width, "h": height, "key": key.hex(),
                      "rgb": _bgra_to_rgb(data[px_off:px_off + px_len], width * height)})
        off = px_off + px_len
        idx += 1

    return tiles, corrupt


def _blit(canvas: bytearray, stride: int, cx: int, cy: int, t: dict) -> None:
    w3 = t["w"] * 3
    rgb = t["rgb"]
    for y in range(t["h"]):
        dst = (cy + y) * stride + cx * 3
        canvas[dst:dst + w3] = rgb[y * w3:(y + 1) * w3]


def _mosaic_row(src: str, full: str, tiles: list[dict]) -> dict | None:
    if not tiles:
        return None
    cols = min(_MOSAIC_COLS, len(tiles))
    rows_n = (len(tiles) + cols - 1) // cols
    mw, mh = cols * _TILE, rows_n * _TILE
    canvas = bytearray(struct.pack("BBB", *_BG) * (mw * mh))
    for i, t in enumerate(tiles):
        _blit(canvas, mw * 3, (i % cols) * _TILE, (i // cols) * _TILE, t)
    return {"kind": "mosaic", "source_file": src, "tile_count": str(len(tiles)),
            "width": str(mw), "height": str(mh), "image": _png(mw, mh, bytes(canvas)),
            "_source_file": full, "_status": "ok"}


def _col(t: dict, x: int) -> bytes:
    w, h, rgb = t["w"], t["h"], t["rgb"]
    out = bytearray(h * 3)
    for y in range(h):
        p = (y * w + x) * 3
        out[y * 3:y * 3 + 3] = rgb[p:p + 3]
    return bytes(out)


def _uniform(edge: bytes) -> bool:
    return len({edge[i:i + 3] for i in range(0, len(edge), 3)}) <= 1


def _stitch(tiles: list[dict]):
    """Join tiles by exact matching edges into connected components, each with a
    grid position. Returns (components, pos) where components is a list of member
    id-lists (largest first) and pos maps tile id -> (col, row)."""
    left_idx, top_idx = defaultdict(list), defaultdict(list)
    edge = {}
    for t in tiles:
        L, R = _col(t, 0), _col(t, t["w"] - 1)
        T = bytes(t["rgb"][0:t["w"] * 3])
        B = bytes(t["rgb"][(t["h"] - 1) * t["w"] * 3:t["h"] * t["w"] * 3])
        edge[t["i"]] = (L, R, T, B)
        if not _uniform(L):
            left_idx[(t["h"], L)].append(t["i"])
        if not _uniform(T):
            top_idx[(t["w"], T)].append(t["i"])

    right_of, down_of = {}, {}
    for t in tiles:
        L, R, T, B = edge[t["i"]]
        if not _uniform(R):
            cand = [b for b in left_idx[(t["h"], R)] if b != t["i"]]
            if cand:
                right_of[t["i"]] = cand[0]
        if not _uniform(B):
            cand = [b for b in top_idx[(t["w"], B)] if b != t["i"]]
            if cand:
                down_of[t["i"]] = cand[0]
    left_of = {v: k for k, v in right_of.items()}
    up_of = {v: k for k, v in down_of.items()}

    pos: dict[int, tuple[int, int]] = {}
    seen: set[int] = set()
    comps: list[list[int]] = []
    for t in tiles:
        if t["i"] in seen:
            continue
        pos[t["i"]] = (0, 0)
        seen.add(t["i"])
        members = [t["i"]]
        q = deque([t["i"]])
        while q:
            cur = q.popleft()
            cx, cy = pos[cur]
            for nid, (dx, dy) in ((right_of.get(cur), (1, 0)), (down_of.get(cur), (0, 1)),
                                   (left_of.get(cur), (-1, 0)), (up_of.get(cur), (0, -1))):
                if nid is not None and nid not in seen:
                    seen.add(nid)
                    pos[nid] = (cx + dx, cy + dy)
                    members.append(nid)
                    q.append(nid)
        comps.append(members)
    comps.sort(key=len, reverse=True)
    return comps, pos


def _fragment_image(members: list[int], pos: dict, byid: dict) -> tuple[int, int, int, int, bytes]:
    xs = [pos[m][0] for m in members]
    ys = [pos[m][1] for m in members]
    minx, miny = min(xs), min(ys)
    cols, rows = max(xs) - minx + 1, max(ys) - miny + 1
    W, H = cols * _TILE, rows * _TILE
    canvas = bytearray(struct.pack("BBB", *_BG) * (W * H))
    for m in members:
        _blit(canvas, W * 3, (pos[m][0] - minx) * _TILE, (pos[m][1] - miny) * _TILE, byid[m])
    return cols, rows, W, H, bytes(canvas)


def _tile_rows(src: str, full: str, tiles: list[dict]) -> list[dict]:
    byid = {t["i"]: t for t in tiles}
    comps, pos = _stitch(tiles)

    rows: list[dict] = []
    singles: list[dict] = []
    frag_no = 0
    for members in comps:
        if len(members) >= _MIN_FRAGMENT:
            frag_no += 1
            cols, rowsn, W, H, rgb = _fragment_image(members, pos, byid)
            rows.append({"kind": "fragment", "source_file": src, "fragment_index": str(frag_no),
                         "tile_count": str(len(members)), "cols": str(cols), "rows": str(rowsn),
                         "width": str(W), "height": str(H), "image": _png(W, H, rgb),
                         "_source_file": full, "_status": "ok"})
        else:
            singles.append(byid[members[0]])

    # Leftover singles: exact-dedup with a count so identical stray tiles fold up.
    uniq: dict[bytes, dict] = {}
    for t in singles:
        h = hashlib.sha1(t["rgb"]).digest()
        u = uniq.get(h)
        if u:
            u["count"] += 1
        else:
            uniq[h] = {"t": t, "count": 1}
    for u in sorted(uniq.values(), key=lambda u: -u["count"]):
        t = u["t"]
        rows.append({"kind": "tile", "source_file": src, "count": str(u["count"]),
                     "tile_index": str(t["i"]), "width": str(t["w"]), "height": str(t["h"]),
                     "key": t["key"], "image": _png(t["w"], t["h"], bytes(t["rgb"])),
                     "_source_file": full, "_status": "ok"})
    return rows


def parse(paths: list[Path]) -> dict[str, list[dict]]:
    rows: list[dict] = []
    for path in paths:
        tiles, corrupt = _decode_file(path)
        mosaic = _mosaic_row(path.name, str(path), tiles)
        if mosaic:
            rows.append(mosaic)
        rows.extend(_tile_rows(path.name, str(path), tiles))
        rows.extend(corrupt)
    return {_OUTPUT: rows}
