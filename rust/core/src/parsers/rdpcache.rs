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

use crate::sqlite::Row;

pub const RDP_TABLE: &str = "RdpBitmapCache";
pub const CONTENT_MARKER: &str = "RDP8bmp";
const MAGIC: &[u8] = b"RDP8bmp\x00";
pub const RDP_FIELD_ORDER: &[&str] = &[
    "kind", "source_file", "fragment_index", "tile_count", "cols", "rows",
    "tile_index", "count", "width", "height", "key", "image",
    "_source_file", "_status", "_error",
];

const TILE: usize = 64;
const MOSAIC_COLS: usize = 48;
const MAX_DIM: usize = 256;
const BG: [u8; 3] = [16, 20, 26];
const MIN_FRAGMENT: usize = 2;
const MAX_EDGE_SHARE: usize = 8;

struct Tile { i: usize, w: usize, h: usize, key: String, rgb: Vec<u8> }

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{:02x}", x)); }
    s
}

fn png_b64(width: usize, height: usize, rgb: &[u8]) -> String {
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, width as u32, height as u32);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().unwrap();
        w.write_image_data(rgb).unwrap();
    }
    base64::engine::general_purpose::STANDARD.encode(&buf)
}

fn bgra_to_rgb(bgra: &[u8], count: usize) -> Vec<u8> {
    let mut rgb = vec![0u8; count * 3];
    for i in 0..count {
        rgb[i * 3] = bgra[i * 4 + 2];     // R
        rgb[i * 3 + 1] = bgra[i * 4 + 1]; // G
        rgb[i * 3 + 2] = bgra[i * 4];     // B
    }
    rgb
}

fn decode_file(path: &Path) -> (Vec<Tile>, Vec<Row>) {
    let src = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let full = path.to_string_lossy().to_string();
    let mut tiles = Vec::new();
    let mut corrupt = Vec::new();
    let data = match std::fs::read(path) { Ok(d) => d, Err(e) => {
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into()); r.insert("source_file".into(), src);
        r.insert("_source_file".into(), full); r.insert("_status".into(), "unreadable_file".into());
        r.insert("_error".into(), e.to_string());
        return (tiles, vec![r]);
    }};
    if data.len() < 8 || &data[..8] != MAGIC {
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into()); r.insert("source_file".into(), src);
        r.insert("_source_file".into(), full); r.insert("_status".into(), "unreadable_file".into());
        r.insert("_error".into(), format!("not an RDP8bmp cache (magic={:?})", &data[..data.len().min(8)]));
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
            r.insert("kind".into(), "tile".into()); r.insert("source_file".into(), src.clone());
            r.insert("tile_index".into(), idx.to_string()); r.insert("_source_file".into(), full.clone());
            r.insert("_status".into(), "corrupted".into());
            r.insert("_error".into(), format!("tile {}: declared {}x{} at offset {} runs past end", idx, width, height, off));
            corrupt.push(r);
            break;
        }
        tiles.push(Tile { i: idx, w: width, h: height, key: hex_lower(key), rgb: bgra_to_rgb(&data[px_off..px_off + px_len], width * height) });
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
    for i in 0..w * h { c[i * 3..i * 3 + 3].copy_from_slice(&BG); }
    c
}

fn mosaic_row(src: &str, full: &str, tiles: &[Tile]) -> Option<Row> {
    if tiles.is_empty() { return None; }
    let cols = MOSAIC_COLS.min(tiles.len());
    let rows_n = (tiles.len() + cols - 1) / cols;
    let (mw, mh) = (cols * TILE, rows_n * TILE);
    let mut canvas = bg_canvas(mw, mh);
    for (i, t) in tiles.iter().enumerate() {
        blit(&mut canvas, mw * 3, (i % cols) * TILE, (i / cols) * TILE, t);
    }
    let mut r = Row::new();
    r.insert("kind".into(), "mosaic".into()); r.insert("source_file".into(), src.into());
    r.insert("tile_count".into(), tiles.len().to_string());
    r.insert("width".into(), mw.to_string()); r.insert("height".into(), mh.to_string());
    r.insert("image".into(), png_b64(mw, mh, &canvas));
    r.insert("_source_file".into(), full.into()); r.insert("_status".into(), "ok".into());
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
    if edge.len() < 3 { return true; }
    edge.chunks_exact(3).all(|px| px == &edge[0..3])
}

/// Stitch tiles into connected components with grid positions (mirrors Python).
fn stitch(tiles: &[Tile]) -> (Vec<Vec<usize>>, HashMap<usize, (i32, i32)>) {
    let mut left_idx: HashMap<(usize, Vec<u8>), Vec<usize>> = HashMap::new();
    let mut top_idx: HashMap<(usize, Vec<u8>), Vec<usize>> = HashMap::new();
    let mut edge: HashMap<usize, (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = HashMap::new();
    for t in tiles {
        let l = col_bytes(t, 0);
        let r = col_bytes(t, t.w - 1);
        let top = t.rgb[0..t.w * 3].to_vec();
        let bot = t.rgb[(t.h - 1) * t.w * 3..t.h * t.w * 3].to_vec();
        if !uniform(&l) { left_idx.entry((t.h, l.clone())).or_default().push(t.i); }
        if !uniform(&top) { top_idx.entry((t.w, top.clone())).or_default().push(t.i); }
        edge.insert(t.i, (l, r, top, bot));
    }
    let mut right_of: HashMap<usize, usize> = HashMap::new();
    let mut down_of: HashMap<usize, usize> = HashMap::new();
    for t in tiles {
        let (_, r, _, b) = &edge[&t.i];
        if !uniform(r) {
            if let Some(grp) = left_idx.get(&(t.h, r.clone())) {
                let cand: Vec<usize> = grp.iter().copied().filter(|&x| x != t.i).collect();
                if !cand.is_empty() && grp.len() <= MAX_EDGE_SHARE { right_of.insert(t.i, cand[0]); }
            }
        }
        if !uniform(b) {
            if let Some(grp) = top_idx.get(&(t.w, b.clone())) {
                let cand: Vec<usize> = grp.iter().copied().filter(|&x| x != t.i).collect();
                if !cand.is_empty() && grp.len() <= MAX_EDGE_SHARE { down_of.insert(t.i, cand[0]); }
            }
        }
    }
    // Invert in tile order (like Python's dict comprehension over insertion
    // order): on a collision the later tile wins. HashMap::iter order is
    // arbitrary and would pick a different winner, changing the components.
    let mut left_of: HashMap<usize, usize> = HashMap::new();
    let mut up_of: HashMap<usize, usize> = HashMap::new();
    for t in tiles {
        if let Some(&r) = right_of.get(&t.i) { left_of.insert(r, t.i); }
        if let Some(&d) = down_of.get(&t.i) { up_of.insert(d, t.i); }
    }

    let mut pos: HashMap<usize, (i32, i32)> = HashMap::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut comps: Vec<Vec<usize>> = Vec::new();
    for t in tiles {
        if seen.contains(&t.i) { continue; }
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
                if seen.contains(&nid) { continue; }
                let cell = (cx + dx, cy + dy);
                if occupied.contains_key(&cell) { continue; }
                seen.insert(nid);
                pos.insert(nid, cell);
                occupied.insert(cell, nid);
                members.push(nid);
                q.push_back(nid);
            }
        }
        comps.push(members);
    }
    comps.sort_by(|a, b| b.len().cmp(&a.len()));
    (comps, pos)
}

fn fragment_image(members: &[usize], pos: &HashMap<usize, (i32, i32)>, byid: &HashMap<usize, &Tile>) -> (usize, usize, usize, usize, Vec<u8>) {
    let xs: Vec<i32> = members.iter().map(|m| pos[m].0).collect();
    let ys: Vec<i32> = members.iter().map(|m| pos[m].1).collect();
    let (minx, miny) = (*xs.iter().min().unwrap(), *ys.iter().min().unwrap());
    let cols = (*xs.iter().max().unwrap() - minx + 1) as usize;
    let rows = (*ys.iter().max().unwrap() - miny + 1) as usize;
    let (w, h) = (cols * TILE, rows * TILE);
    let mut canvas = bg_canvas(w, h);
    for m in members {
        let (px, py) = pos[m];
        blit(&mut canvas, w * 3, (px - minx) as usize * TILE, (py - miny) as usize * TILE, byid[m]);
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
            let mut r = Row::new();
            r.insert("kind".into(), "fragment".into()); r.insert("source_file".into(), src.into());
            r.insert("fragment_index".into(), frag_no.to_string());
            r.insert("tile_count".into(), members.len().to_string());
            r.insert("cols".into(), cols.to_string()); r.insert("rows".into(), rowsn.to_string());
            r.insert("width".into(), w.to_string()); r.insert("height".into(), h.to_string());
            r.insert("image".into(), png_b64(w, h, &rgb));
            r.insert("_source_file".into(), full.into()); r.insert("_status".into(), "ok".into());
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
            None => { order.push(t.rgb.clone()); uniq.insert(t.rgb.clone(), (sid, 1)); }
        }
    }
    let mut items: Vec<(Vec<u8>, usize, usize)> = order.into_iter().map(|rgb| { let (id, c) = uniq[&rgb]; (rgb, id, c) }).collect();
    items.sort_by(|a, b| b.2.cmp(&a.2)); // stable, count desc
    for (_, id, count) in items {
        let t = byid[&id];
        let mut r = Row::new();
        r.insert("kind".into(), "tile".into()); r.insert("source_file".into(), src.into());
        r.insert("count".into(), count.to_string()); r.insert("tile_index".into(), t.i.to_string());
        r.insert("width".into(), t.w.to_string()); r.insert("height".into(), t.h.to_string());
        r.insert("key".into(), t.key.clone()); r.insert("image".into(), png_b64(t.w, t.h, &t.rgb));
        r.insert("_source_file".into(), full.into()); r.insert("_status".into(), "ok".into());
        rows.push(r);
    }
    rows
}

pub fn parse_rdpcache(root: &Path) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() { continue; }
        // located by content marker (like the Python find_files_by_content)
        let raw = match std::fs::read(entry.path()) { Ok(d) => d, Err(_) => continue };
        let head = &raw[..raw.len().min(4096)];
        if !head.windows(MAGIC.len()).any(|w| w == MAGIC) { continue; }
        let (tiles, corrupt) = decode_file(entry.path());
        let src = entry.file_name().to_string_lossy().to_string();
        let full = entry.path().to_string_lossy().to_string();
        if let Some(m) = mosaic_row(&src, &full, &tiles) { rows.push(m); }
        rows.extend(tile_rows(&src, &full, &tiles));
        rows.extend(corrupt);
    }
    Ok(rows)
}
