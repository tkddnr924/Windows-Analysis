//! RDP bitmap cache (RDP8bmp persistent cache, Cache####.bin). Decodes tiles,
//! stitches adjacent tiles by exact-matching edges into reconstructed screen
//! fragments (same idea as RdpCacheStitcher), and emits mosaic/fragment/tile
//! rows, each with a base64 PNG. Mirrors the Python parser's algorithm.
//!
//! Note: PNG bytes are NOT byte-identical to the Python output (zlib encoders
//! differ) — the images are visually identical; validation is structural
//! (tile/fragment counts, dimensions, keys).
use std::collections::{HashMap, VecDeque};
use std::path::Path;

use anyhow::Result;
use base64::Engine;

use crate::hex::hex_lower;
use crate::sqlite::Row;

pub const RDP_TABLE: &str = "RdpBitmapCache";
pub const CONTENT_MARKER: &str = "RDP8bmp";
const MAGIC: &[u8] = b"RDP8bmp\x00";
pub const RDP_FIELD_ORDER: &[&str] = &[
    "kind",
    "account",
    "source_file",
    "fragment_index",
    "tile_count",
    "cols",
    "rows",
    "tile_index",
    "count",
    "width",
    "height",
    "key",
    "image",
    "_source_file",
    "_status",
    "_error",
];

/// The account an RDP cache file belongs to — the path segment right after the
/// `RDP_CACHE` collection folder (…/RDP_CACHE/<account>/Cache/Cache0000.bin).
/// Collected data isn't always laid out that way, so when no account can be
/// derived from the path this returns "unknown" rather than an empty string.
fn account_of(path: &std::path::Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, p) in parts.iter().enumerate() {
        if p.eq_ignore_ascii_case("RDP_CACHE") && i + 1 < parts.len() {
            let a = parts[i + 1].trim();
            if !a.is_empty() && !a.eq_ignore_ascii_case("Cache") {
                return a.to_string();
            }
        }
    }
    // 원본 이미지 경로(…\Users\<계정>\…\Terminal Server Client\Cache\bcache24.bmc)
    // 폴백 — 수집기 배치(RDP_CACHE/<계정>)가 아닐 때 계정을 복원한다.
    for (i, p) in parts.iter().enumerate() {
        if (p.eq_ignore_ascii_case("Users") || p.eq_ignore_ascii_case("Documents and Settings"))
            && i + 1 < parts.len()
        {
            let a = parts[i + 1].trim();
            if !a.is_empty() {
                return a.to_string();
            }
        }
    }
    // Fallback: the folder above a "Cache" directory.
    for (i, p) in parts.iter().enumerate() {
        if p.eq_ignore_ascii_case("Cache") && i >= 1 {
            let a = parts[i - 1].trim();
            if !a.is_empty() {
                return a.to_string();
            }
        }
    }
    "unknown".to_string()
}

const TILE: usize = 64;
const MOSAIC_COLS: usize = 48;
const MAX_DIM: usize = 256;
const BG: [u8; 3] = [16, 20, 26];
const MIN_FRAGMENT: usize = 2;
const MAX_EDGE_SHARE: usize = 8;

struct Tile {
    i: usize,
    w: usize,
    h: usize,
    key: String,
    rgb: Vec<u8>,
}


fn png_b64(width: usize, height: usize, rgb: &[u8]) -> String {
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, width as u32, height as u32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        // 무손실은 그대로, 압축 수준만 빠르게 — 타일 수천 개 인코딩이 RdpCache
        // 파싱 시간의 대부분이라 크기 약간 늘리고 속도를 몇 배 얻는다.
        enc.set_compression(png::Compression::Fast);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(rgb).unwrap();
    }
    base64::engine::general_purpose::STANDARD.encode(&buf)
}

fn bgra_to_rgb(bgra: &[u8], count: usize) -> Vec<u8> {
    let mut rgb = vec![0u8; count * 3];
    for i in 0..count {
        rgb[i * 3] = bgra[i * 4 + 2]; // R
        rgb[i * 3 + 1] = bgra[i * 4 + 1]; // G
        rgb[i * 3 + 2] = bgra[i * 4]; // B
    }
    rgb
}

// ---------------------------------------------------------------------------
// 구형(RDP8 이전, Win7 시대 클라이언트) bcache##.bmc 컨테이너 — T5.
// 전역 헤더 없이 엔트리 나열: key(8) + width u16 + height u16 + data_len u32 +
// params u32 + 픽셀 데이터(top-down). bpp는 data_len/(w*h)로 판별(1/2/3/4),
// params bit 0x08은 RLE 압축(미지원 — corrupted 행으로 표면화, T0 원칙).
// 레이아웃·픽셀 변환은 ANSSI BMC-Tools 준거.
// ---------------------------------------------------------------------------

const BMC_TILE_HEADER: usize = 0x14;
const BMC_RLE_FLAG: u32 = 0x08;

fn is_bmc_name(path: &Path) -> bool {
    path.file_name()
        .map(|n| {
            let lower = n.to_string_lossy().to_ascii_lowercase();
            lower.starts_with("bcache") && lower.ends_with(".bmc")
        })
        .unwrap_or(false)
}

/// RGB565(LE u16) → RGB — BMC-Tools와 같은 시프트 확장.
fn rgb565_to_rgb(px: &[u8], count: usize) -> Vec<u8> {
    let mut rgb = vec![0u8; count * 3];
    for i in 0..count {
        let v = u16::from_le_bytes([px[i * 2], px[i * 2 + 1]]);
        rgb[i * 3] = ((v >> 8) & 0xF8) as u8;
        rgb[i * 3 + 1] = ((v >> 3) & 0xFC) as u8;
        rgb[i * 3 + 2] = ((v << 3) & 0xF8) as u8;
    }
    rgb
}

fn bgr_to_rgb(px: &[u8], count: usize) -> Vec<u8> {
    let mut rgb = vec![0u8; count * 3];
    for i in 0..count {
        rgb[i * 3] = px[i * 3 + 2];
        rgb[i * 3 + 1] = px[i * 3 + 1];
        rgb[i * 3 + 2] = px[i * 3];
    }
    rgb
}

/// 8bpp 팔레트 타일 — 팔레트가 파일에 없어 인덱스를 그레이스케일로 표기.
fn gray_to_rgb(px: &[u8], count: usize) -> Vec<u8> {
    let mut rgb = vec![0u8; count * 3];
    for i in 0..count {
        rgb[i * 3] = px[i];
        rgb[i * 3 + 1] = px[i];
        rgb[i * 3 + 2] = px[i];
    }
    rgb
}

fn decode_bmc(data: &[u8], src: &str, full: &str) -> (Vec<Tile>, Vec<Row>) {
    let mut tiles = Vec::new();
    let mut corrupt = Vec::new();
    let n = data.len();
    let mut off = 0usize;
    let mut idx = 0usize;
    let corrupted_row = |idx: usize, error: String| {
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into());
        r.insert("source_file".into(), src.to_string());
        r.insert("tile_index".into(), idx.to_string());
        r.insert("_source_file".into(), full.to_string());
        r.insert("_status".into(), "corrupted".into());
        r.insert("_error".into(), error);
        r
    };
    while off + BMC_TILE_HEADER <= n {
        let key = &data[off..off + 8];
        let width = u16::from_le_bytes([data[off + 8], data[off + 9]]) as usize;
        let height = u16::from_le_bytes([data[off + 10], data[off + 11]]) as usize;
        let size = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]) as usize;
        let params = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]);
        // 사전 할당된 빈 꼬리(전부 0) — 정상 종료.
        if width == 0 || height == 0 || size == 0 {
            break;
        }
        let px_off = off + BMC_TILE_HEADER;
        if width > MAX_DIM || height > MAX_DIM || px_off + size > n {
            corrupt.push(corrupted_row(
                idx,
                format!(
                    "bmc tile {}: declared {}x{} size {} at offset {} runs past end",
                    idx, width, height, size, off
                ),
            ));
            break;
        }
        if params & BMC_RLE_FLAG != 0 {
            // RLE 압축 타일 — 미지원을 조용히 삼키지 않는다. 크기를 알므로
            // 다음 엔트리로 계속 진행.
            corrupt.push(corrupted_row(
                idx,
                format!("bmc tile {idx}: RLE-compressed (params=0x{params:08X}) — 미지원"),
            ));
            off = px_off + size;
            idx += 1;
            continue;
        }
        let pixels = width * height;
        let px = &data[px_off..px_off + size];
        let rgb = match size / pixels {
            4 if size == pixels * 4 => bgra_to_rgb(px, pixels),
            3 if size == pixels * 3 => bgr_to_rgb(px, pixels),
            2 if size == pixels * 2 => rgb565_to_rgb(px, pixels),
            1 if size == pixels => gray_to_rgb(px, pixels),
            _ => {
                corrupt.push(corrupted_row(
                    idx,
                    format!(
                        "bmc tile {}: size {} not a whole 1/2/3/4 bpp of {}x{}",
                        idx, size, width, height
                    ),
                ));
                off = px_off + size;
                idx += 1;
                continue;
            }
        };
        tiles.push(Tile {
            i: idx,
            w: width,
            h: height,
            key: hex_lower(key),
            rgb,
        });
        off = px_off + size;
        idx += 1;
    }
    (tiles, corrupt)
}

fn decode_file(path: &Path) -> (Vec<Tile>, Vec<Row>) {
    let src = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let full = path.to_string_lossy().to_string();
    let mut tiles = Vec::new();
    let mut corrupt = Vec::new();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let mut r = Row::new();
            r.insert("kind".into(), "tile".into());
            r.insert("source_file".into(), src);
            r.insert("_source_file".into(), full);
            r.insert("_status".into(), "unreadable_file".into());
            r.insert("_error".into(), e.to_string());
            return (tiles, vec![r]);
        }
    };
    if data.len() < 8 || &data[..8] != MAGIC {
        // RDP8bmp 매직이 없는 bcache##.bmc는 구형(RDP8 이전) 컨테이너다.
        if is_bmc_name(path) {
            return decode_bmc(&data, &src, &full);
        }
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into());
        r.insert("source_file".into(), src);
        r.insert("_source_file".into(), full);
        r.insert("_status".into(), "unreadable_file".into());
        r.insert(
            "_error".into(),
            format!(
                "not an RDP8bmp cache (magic={:?})",
                &data[..data.len().min(8)]
            ),
        );
        return (tiles, vec![r]);
    }
    let n = data.len();
    let mut off = 12usize;
    let mut idx = 0usize;
    while off + 12 <= n {
        let key = &data[off..off + 8];
        let width = u16::from_le_bytes([data[off + 8], data[off + 9]]) as usize;
        let height = u16::from_le_bytes([data[off + 10], data[off + 11]]) as usize;
        let px_off = off + 12;
        let px_len = width * height * 4;
        if width == 0 || height == 0 || width > MAX_DIM || height > MAX_DIM || px_off + px_len > n {
            let mut r = Row::new();
            r.insert("kind".into(), "tile".into());
            r.insert("source_file".into(), src.clone());
            r.insert("tile_index".into(), idx.to_string());
            r.insert("_source_file".into(), full.clone());
            r.insert("_status".into(), "corrupted".into());
            r.insert(
                "_error".into(),
                format!(
                    "tile {}: declared {}x{} at offset {} runs past end",
                    idx, width, height, off
                ),
            );
            corrupt.push(r);
            break;
        }
        tiles.push(Tile {
            i: idx,
            w: width,
            h: height,
            key: hex_lower(key),
            rgb: bgra_to_rgb(&data[px_off..px_off + px_len], width * height),
        });
        off = px_off + px_len;
        idx += 1;
    }
    (tiles, corrupt)
}

fn blit(canvas: &mut [u8], stride: usize, cx: usize, cy: usize, t: &Tile) {
    let w3 = t.w * 3;
    for y in 0..t.h {
        let dst = (cy + y) * stride + cx * 3;
        canvas[dst..dst + w3].copy_from_slice(&t.rgb[y * w3..(y + 1) * w3]);
    }
}
fn bg_canvas(w: usize, h: usize) -> Vec<u8> {
    let mut c = vec![0u8; w * h * 3];
    for i in 0..w * h {
        c[i * 3..i * 3 + 3].copy_from_slice(&BG);
    }
    c
}

fn mosaic_row(src: &str, full: &str, tiles: &[Tile]) -> Option<Row> {
    if tiles.is_empty() {
        return None;
    }
    let cols = MOSAIC_COLS.min(tiles.len());
    let rows_n = tiles.len().div_ceil(cols);
    let (mw, mh) = (cols * TILE, rows_n * TILE);
    let mut canvas = bg_canvas(mw, mh);
    for (i, t) in tiles.iter().enumerate() {
        blit(&mut canvas, mw * 3, (i % cols) * TILE, (i / cols) * TILE, t);
    }
    let mut r = Row::new();
    r.insert("kind".into(), "mosaic".into());
    r.insert("source_file".into(), src.into());
    r.insert("tile_count".into(), tiles.len().to_string());
    r.insert("width".into(), mw.to_string());
    r.insert("height".into(), mh.to_string());
    r.insert("image".into(), png_b64(mw, mh, &canvas));
    r.insert("_source_file".into(), full.into());
    r.insert("_status".into(), "ok".into());
    Some(r)
}

fn col_bytes(t: &Tile, x: usize) -> Vec<u8> {
    let mut out = vec![0u8; t.h * 3];
    for y in 0..t.h {
        let p = (y * t.w + x) * 3;
        out[y * 3..y * 3 + 3].copy_from_slice(&t.rgb[p..p + 3]);
    }
    out
}
fn uniform(edge: &[u8]) -> bool {
    if edge.len() < 3 {
        return true;
    }
    edge.chunks_exact(3).all(|px| px == &edge[0..3])
}

/// Edge lookup key: (edge length, edge pixel bytes).
type EdgeKey = (usize, Vec<u8>);
/// A tile's four edges: (left, right, top, bottom) pixel bytes.
type TileEdges = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Stitch result: (tile-index components, tile index -> grid (col, row)).
type StitchResult = (Vec<Vec<usize>>, HashMap<usize, (i32, i32)>);

/// Stitch tiles into connected components with grid positions (mirrors Python).
fn stitch(tiles: &[Tile]) -> StitchResult {
    let mut left_idx: HashMap<EdgeKey, Vec<usize>> = HashMap::new();
    let mut top_idx: HashMap<EdgeKey, Vec<usize>> = HashMap::new();
    let mut edge: HashMap<usize, TileEdges> = HashMap::new();
    for t in tiles {
        let l = col_bytes(t, 0);
        let r = col_bytes(t, t.w - 1);
        let top = t.rgb[0..t.w * 3].to_vec();
        let bot = t.rgb[(t.h - 1) * t.w * 3..t.h * t.w * 3].to_vec();
        if !uniform(&l) {
            left_idx.entry((t.h, l.clone())).or_default().push(t.i);
        }
        if !uniform(&top) {
            top_idx.entry((t.w, top.clone())).or_default().push(t.i);
        }
        edge.insert(t.i, (l, r, top, bot));
    }
    let mut right_of: HashMap<usize, usize> = HashMap::new();
    let mut down_of: HashMap<usize, usize> = HashMap::new();
    for t in tiles {
        let (_, r, _, b) = &edge[&t.i];
        if !uniform(r) {
            if let Some(grp) = left_idx.get(&(t.h, r.clone())) {
                let cand: Vec<usize> = grp.iter().copied().filter(|&x| x != t.i).collect();
                if !cand.is_empty() && grp.len() <= MAX_EDGE_SHARE {
                    right_of.insert(t.i, cand[0]);
                }
            }
        }
        if !uniform(b) {
            if let Some(grp) = top_idx.get(&(t.w, b.clone())) {
                let cand: Vec<usize> = grp.iter().copied().filter(|&x| x != t.i).collect();
                if !cand.is_empty() && grp.len() <= MAX_EDGE_SHARE {
                    down_of.insert(t.i, cand[0]);
                }
            }
        }
    }
    // Invert in tile order (like Python's dict comprehension over insertion
    // order): on a collision the later tile wins. HashMap::iter order is
    // arbitrary and would pick a different winner, changing the components.
    let mut left_of: HashMap<usize, usize> = HashMap::new();
    let mut up_of: HashMap<usize, usize> = HashMap::new();
    for t in tiles {
        if let Some(&r) = right_of.get(&t.i) {
            left_of.insert(r, t.i);
        }
        if let Some(&d) = down_of.get(&t.i) {
            up_of.insert(d, t.i);
        }
    }

    let mut pos: HashMap<usize, (i32, i32)> = HashMap::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut comps: Vec<Vec<usize>> = Vec::new();
    for t in tiles {
        if seen.contains(&t.i) {
            continue;
        }
        pos.insert(t.i, (0, 0));
        seen.insert(t.i);
        let mut members = vec![t.i];
        let mut occupied: HashMap<(i32, i32), usize> = HashMap::new();
        occupied.insert((0, 0), t.i);
        let mut q = VecDeque::new();
        q.push_back(t.i);
        while let Some(cur) = q.pop_front() {
            let (cx, cy) = pos[&cur];
            for (nid, (dx, dy)) in [
                (right_of.get(&cur).copied(), (1, 0)),
                (down_of.get(&cur).copied(), (0, 1)),
                (left_of.get(&cur).copied(), (-1, 0)),
                (up_of.get(&cur).copied(), (0, -1)),
            ] {
                let Some(nid) = nid else { continue };
                if seen.contains(&nid) {
                    continue;
                }
                let cell = (cx + dx, cy + dy);
                if occupied.contains_key(&cell) {
                    continue;
                }
                seen.insert(nid);
                pos.insert(nid, cell);
                occupied.insert(cell, nid);
                members.push(nid);
                q.push_back(nid);
            }
        }
        comps.push(members);
    }
    comps.sort_by_key(|component| std::cmp::Reverse(component.len()));
    (comps, pos)
}

fn fragment_image(
    members: &[usize],
    pos: &HashMap<usize, (i32, i32)>,
    byid: &HashMap<usize, &Tile>,
) -> (usize, usize, usize, usize, Vec<u8>) {
    let xs: Vec<i32> = members.iter().map(|m| pos[m].0).collect();
    let ys: Vec<i32> = members.iter().map(|m| pos[m].1).collect();
    let (minx, miny) = (*xs.iter().min().unwrap(), *ys.iter().min().unwrap());
    let cols = (*xs.iter().max().unwrap() - minx + 1) as usize;
    let rows = (*ys.iter().max().unwrap() - miny + 1) as usize;
    if cols > 200 || rows > 200 {
        return (0, 0, 0, 0, Vec::new());
    } // cap at ~12800x12800 px to prevent OOM
    let (w, h) = (cols * TILE, rows * TILE);
    let mut canvas = bg_canvas(w, h);
    for m in members {
        let (px, py) = pos[m];
        blit(
            &mut canvas,
            w * 3,
            (px - minx) as usize * TILE,
            (py - miny) as usize * TILE,
            byid[m],
        );
    }
    (cols, rows, w, h, canvas)
}

fn tile_rows(src: &str, full: &str, tiles: &[Tile]) -> Vec<Row> {
    let byid: HashMap<usize, &Tile> = tiles.iter().map(|t| (t.i, t)).collect();
    let (comps, pos) = stitch(tiles);
    let mut rows = Vec::new();
    let mut singles: Vec<usize> = Vec::new();
    let mut frag_no = 0;
    for members in &comps {
        if members.len() >= MIN_FRAGMENT {
            frag_no += 1;
            let (cols, rowsn, w, h, rgb) = fragment_image(members, &pos, &byid);
            if w == 0 || h == 0 {
                continue;
            } // skipped due to OOM protection
            let mut r = Row::new();
            r.insert("kind".into(), "fragment".into());
            r.insert("source_file".into(), src.into());
            r.insert("fragment_index".into(), frag_no.to_string());
            r.insert("tile_count".into(), members.len().to_string());
            r.insert("cols".into(), cols.to_string());
            r.insert("rows".into(), rowsn.to_string());
            r.insert("width".into(), w.to_string());
            r.insert("height".into(), h.to_string());
            r.insert("image".into(), png_b64(w, h, &rgb));
            r.insert("_source_file".into(), full.into());
            r.insert("_status".into(), "ok".into());
            rows.push(r);
        } else {
            singles.push(members[0]);
        }
    }
    // dedup leftover singles by exact rgb, keep a count; first-seen order then stable sort by count desc.
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut uniq: HashMap<Vec<u8>, (usize, usize)> = HashMap::new(); // rgb -> (tile_id, count)
    for &sid in &singles {
        let t = byid[&sid];
        match uniq.get_mut(&t.rgb) {
            Some(e) => e.1 += 1,
            None => {
                order.push(t.rgb.clone());
                uniq.insert(t.rgb.clone(), (sid, 1));
            }
        }
    }
    let mut items: Vec<(Vec<u8>, usize, usize)> = order
        .into_iter()
        .map(|rgb| {
            let (id, c) = uniq[&rgb];
            (rgb, id, c)
        })
        .collect();
    items.sort_by_key(|item| std::cmp::Reverse(item.2)); // stable, count desc
    for (_, id, count) in items {
        let t = byid[&id];
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into());
        r.insert("source_file".into(), src.into());
        r.insert("count".into(), count.to_string());
        r.insert("tile_index".into(), t.i.to_string());
        r.insert("width".into(), t.w.to_string());
        r.insert("height".into(), t.h.to_string());
        r.insert("key".into(), t.key.clone());
        r.insert("image".into(), png_b64(t.w, t.h, &t.rgb));
        r.insert("_source_file".into(), full.into());
        r.insert("_status".into(), "ok".into());
        rows.push(r);
    }
    rows
}

/// Cache files carrying the RDP bitmap signature are evidence inputs even when
/// tile decoding yields no rows (for example, a valid but empty/corrupt cache).
/// Only the first 4 KB of each candidate is read for the signature test.
pub fn rdpcache_sources(root: &Path) -> Vec<std::path::PathBuf> {
    let mut sources = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        // 구형 bcache##.bmc는 매직이 없다 — 파일명으로 채택.
        if is_bmc_name(entry.path()) {
            sources.push(entry.path().to_path_buf());
            continue;
        }
        // located by content marker (like the Python find_files_by_content)
        let mut head = Vec::new();
        match std::fs::File::open(entry.path()) {
            Ok(f) => {
                use std::io::Read;
                if Read::take(f, 4096).read_to_end(&mut head).is_err() {
                    continue;
                }
            }
            Err(_) => continue,
        }
        if head.windows(MAGIC.len()).any(|w| w == MAGIC) {
            sources.push(entry.path().to_path_buf());
        }
    }
    sources.sort();
    sources
}

/// Decode already-discovered RDP bitmap cache files, handing each row to
/// `push` as soon as its source file is decoded — only one file's tiles live
/// in memory at a time, so the base64 PNG payloads never accumulate.
pub fn parse_rdpcache_into(
    sources: &[std::path::PathBuf],
    push: &mut dyn FnMut(Row) -> Result<()>,
) -> Result<()> {
    for path in sources {
        let (tiles, corrupt) = decode_file(path);
        let src = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let full = path.to_string_lossy().to_string();
        let account = account_of(path);
        // Collect this file's rows, then stamp the account on every one so the
        // viewer can group/tag RDP cache by the user it was captured under.
        let mut file_rows: Vec<Row> = Vec::new();
        if let Some(m) = mosaic_row(&src, &full, &tiles) {
            file_rows.push(m);
        }
        file_rows.extend(tile_rows(&src, &full, &tiles));
        file_rows.extend(corrupt);
        for mut r in file_rows {
            r.insert("account".into(), account.clone());
            push(r)?;
        }
    }
    Ok(())
}

/// Decode already-discovered RDP bitmap cache files into one row list.
pub fn parse_rdpcache_from(sources: &[std::path::PathBuf]) -> Vec<Row> {
    let mut rows = Vec::new();
    let _ = parse_rdpcache_into(sources, &mut |row| {
        rows.push(row);
        Ok(())
    });
    rows
}

pub fn parse_rdpcache_with_sources(root: &Path) -> Result<(Vec<std::path::PathBuf>, Vec<Row>)> {
    let sources = rdpcache_sources(root);
    let rows = parse_rdpcache_from(&sources);
    Ok((sources, rows))
}

pub fn parse_rdpcache(root: &Path) -> Result<Vec<Row>> {
    Ok(parse_rdpcache_with_sources(root)?.1)
}

#[cfg(test)]
mod bmc_tests {
    use super::*;

    /// bmc 엔트리 하나: key(8)+w(2)+h(2)+size(4)+params(4)+픽셀.
    fn entry(key: u64, w: u16, h: u16, params: u32, px: &[u8]) -> Vec<u8> {
        let mut b = key.to_le_bytes().to_vec();
        b.extend(w.to_le_bytes());
        b.extend(h.to_le_bytes());
        b.extend((px.len() as u32).to_le_bytes());
        b.extend(params.to_le_bytes());
        b.extend(px);
        b
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-bmc-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn decodes_32bpp_and_16bpp_tiles() {
        // 2x2 32bpp: BGRA 픽셀 (B=1,G=2,R=3) → RGB (3,2,1).
        let px32 = [1u8, 2, 3, 255].repeat(4);
        // 2x2 16bpp RGB565: 0xF800(순빨강) → R=0xF8.
        let px16 = 0xF800u16.to_le_bytes().repeat(4);
        let mut data = entry(0x1122_3344_5566_7788, 2, 2, 0, &px32);
        data.extend(entry(0xAABB_CCDD_EEFF_0011, 2, 2, 0, &px16));
        data.extend(vec![0u8; 0x40]); // 사전 할당된 빈 꼬리

        let (tiles, corrupt) = decode_bmc(&data, "bcache24.bmc", "/x/bcache24.bmc");
        assert!(corrupt.is_empty(), "{corrupt:?}");
        assert_eq!(tiles.len(), 2);
        assert_eq!(&tiles[0].rgb[..3], &[3, 2, 1]);
        assert_eq!(tiles[0].key, "8877665544332211"); // LE 저장 바이트 순 hex
        assert_eq!(&tiles[1].rgb[..3], &[0xF8, 0, 0]);
    }

    #[test]
    fn rle_tile_is_surfaced_and_next_tile_still_decodes() {
        let px = [9u8, 9, 9, 255].repeat(4);
        let mut data = entry(1, 2, 2, BMC_RLE_FLAG, &[0xAB; 7]); // RLE 표시
        data.extend(entry(2, 2, 2, 0, &px));
        let (tiles, corrupt) = decode_bmc(&data, "bcache22.bmc", "/x/bcache22.bmc");
        assert_eq!(corrupt.len(), 1);
        assert!(corrupt[0].get("_error").unwrap().contains("RLE"), "{corrupt:?}");
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].i, 1);
    }

    #[test]
    fn truncated_tile_is_corrupted_row() {
        let mut data = entry(1, 2, 2, 0, &[0u8; 16]);
        data.truncate(data.len() - 4); // 픽셀이 선언 크기보다 짧다
        let (tiles, corrupt) = decode_bmc(&data, "bcache2.bmc", "/x/bcache2.bmc");
        assert!(tiles.is_empty());
        assert_eq!(corrupt.len(), 1);
        assert!(corrupt[0].get("_error").unwrap().contains("runs past end"));
    }

    #[test]
    fn discovery_and_rows_for_bmc_file() {
        let dir = temp_dir("discover");
        let cache = dir
            .join("Users")
            .join("victim")
            .join("Terminal Server Client")
            .join("Cache");
        std::fs::create_dir_all(&cache).unwrap();
        // 64x64 32bpp 두 타일 — 프래그먼트/모자이크 경로까지 통과시킨다.
        let px = [7u8, 8, 9, 255].repeat(64 * 64);
        let mut data = entry(1, 64, 64, 0, &px);
        data.extend(entry(2, 64, 64, 0, &px));
        std::fs::write(cache.join("bcache24.bmc"), &data).unwrap();
        std::fs::write(cache.join("unrelated.txt"), b"noise").unwrap();

        let sources = rdpcache_sources(&dir);
        assert_eq!(sources.len(), 1);
        let rows = parse_rdpcache_from(&sources);
        assert!(!rows.is_empty());
        let mosaic: Vec<_> = rows
            .iter()
            .filter(|r| r.get("kind").map(String::as_str) == Some("mosaic"))
            .collect();
        assert_eq!(mosaic.len(), 1);
        assert_eq!(
            mosaic[0].get("source_file").map(String::as_str),
            Some("bcache24.bmc")
        );
        assert!(rows
            .iter()
            .all(|r| r.get("account").map(String::as_str) == Some("victim")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
