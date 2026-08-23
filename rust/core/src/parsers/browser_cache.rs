//! Chrome/Chromium disk cache (legacy "blockfile" format) parser — port of
//! parsers/browser_cache_parser.py. Walks a profile's `Cache/Cache_Data/index`
//! hash table, resolves each EntryStore's cache addresses to raw stream bytes
//! (block files data_0..3 or external f_###### files), and decodes stream 0
//! (serialized HttpResponseInfo) into the HTTP status + response headers. Pure
//! byte parsing, no external crate. One table `CacheEntries` per account cache.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::sqlite::Row;
use crate::time::fmt_filetime;

pub const CACHE_TABLE: &str = "CacheEntries";
pub const CACHE_FIELD_ORDER: &[&str] = &[
    "request_time",
    "response_time",
    "creation_time",
    "url",
    "status",
    "content_type",
    "content_length",
    "content_encoding",
    "server",
    "date",
    "last_modified",
    "etag",
    "cache_control",
    "location",
    "body_size",
    "body_file",
    "cache_key",
    "all_headers",
    "body_b64",
    "account",
    "_source_file",
    "_status",
    "_error",
];

// Body-extraction caps: read at most RAW_CAP stored bytes and keep the decoded
// body only if it's <= DECODED_CAP — enough for icons, thumbnails, JS/JSON/HTML
// and small images without bloating the sqlite with big media.
const RAW_CAP: usize = 6 * 1024 * 1024;
const DECODED_CAP: usize = 4 * 1024 * 1024;

/// True for content types worth keeping the body of (previewable/text).
fn is_displayable(ct: &str) -> bool {
    let ct = ct.trim();
    ct.starts_with("image/")
        || ct.starts_with("text/")
        || ct.starts_with("application/json")
        || ct.starts_with("application/javascript")
        || ct.starts_with("application/x-javascript")
        || ct.starts_with("application/xml")
        || ct.starts_with("application/xhtml")
}

/// Decode a cached body per its Content-Encoding (Chrome stores it as received).
/// Falls back to the raw bytes if the encoding is unknown or decoding fails.
fn decode_body(raw: &[u8], encoding: &str) -> Vec<u8> {
    use std::io::Read;
    let enc = encoding.to_lowercase();
    if enc.contains("br") {
        let mut out = Vec::new();
        if brotli::Decompressor::new(raw, 4096)
            .read_to_end(&mut out)
            .is_ok()
            && !out.is_empty()
        {
            return out;
        }
    } else if enc.contains("gzip") {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(raw)
            .read_to_end(&mut out)
            .is_ok()
            && !out.is_empty()
        {
            return out;
        }
    } else if enc.contains("deflate") {
        let mut out = Vec::new();
        if flate2::read::ZlibDecoder::new(raw)
            .read_to_end(&mut out)
            .is_ok()
            && !out.is_empty()
        {
            return out;
        }
        let mut out2 = Vec::new();
        if flate2::read::DeflateDecoder::new(raw)
            .read_to_end(&mut out2)
            .is_ok()
            && !out2.is_empty()
        {
            return out2;
        }
    }
    raw.to_vec()
}

const INDEX_MAGIC: u32 = 0xC103_CAC3;
const INDEX_HEADER_SIZE: usize = 368;
const BLOCK_HEADER_SIZE: usize = 8192;
const ENTRY_SIZE: usize = 256;
const MAX_ENTRIES: usize = 2_000_000;
const TIME_LO: i64 = 12_000_000_000_000_000; // ~1981
const TIME_HI: i64 = 16_000_000_000_000_000; // ~2108

fn block_size(file_type: u32) -> Option<usize> {
    match file_type {
        1 => Some(36),
        2 => Some(256),
        3 => Some(1024),
        4 => Some(4096),
        _ => None,
    }
}

fn u32le(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn i32le(b: &[u8], off: usize) -> i32 {
    u32le(b, off) as i32
}
fn u64le(b: &[u8], off: usize) -> u64 {
    if off + 8 > b.len() {
        return 0;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}
fn i64le(b: &[u8], off: usize) -> i64 {
    if off + 8 > b.len() {
        return 0;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    i64::from_le_bytes(a)
}
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn chrome_time(value: i64) -> String {
    if value <= 0 {
        return String::new();
    }
    match value.checked_mul(10) {
        Some(t) => fmt_filetime(t),
        None => String::new(),
    }
}

struct Cache {
    dir: PathBuf,
    blocks: HashMap<String, Vec<u8>>,
}
impl Cache {
    fn new(dir: PathBuf) -> Self {
        Cache {
            dir,
            blocks: HashMap::new(),
        }
    }
    fn block_bytes(&mut self, name: &str) -> Vec<u8> {
        if let Some(v) = self.blocks.get(name) {
            return v.clone();
        }
        let data = std::fs::read(self.dir.join(name)).unwrap_or_default();
        self.blocks.insert(name.to_string(), data.clone());
        data
    }
    fn read(&mut self, addr: u32, size: usize) -> Vec<u8> {
        if addr & 0x8000_0000 == 0 {
            return Vec::new();
        }
        let file_type = (addr >> 28) & 0x7;
        if file_type == 0 {
            let f = self.dir.join(format!("f_{:06x}", addr & 0x0FFF_FFFF));
            let data = std::fs::read(f).unwrap_or_default();
            return if size > 0 {
                data.into_iter().take(size).collect()
            } else {
                data
            };
        }
        let bs = match block_size(file_type) {
            Some(b) => b,
            None => return Vec::new(),
        };
        let file_selector = (addr >> 16) & 0xFF;
        let num_blocks = ((addr >> 24) & 0x3) + 1;
        let block_num = (addr & 0xFFFF) as usize;
        let data = self.block_bytes(&format!("data_{}", file_selector));
        let off = BLOCK_HEADER_SIZE + block_num * bs;
        let length = if size > 0 {
            size
        } else {
            num_blocks as usize * bs
        };
        if off >= data.len() {
            return Vec::new();
        }
        data[off..(off + length).min(data.len())].to_vec()
    }
}

fn scan_times(blob: &[u8]) -> Vec<i64> {
    let mut times = Vec::new();
    let mut off = 0;
    while off + 8 <= blob.len() {
        let v = i64le(blob, off);
        if v > TIME_LO && v < TIME_HI {
            times.push(v);
        }
        off += 4;
    }
    times
}

struct Headers {
    request_time: String,
    response_time: String,
    status: String,
    all_headers: String,
    map: HashMap<String, String>,
}

fn parse_headers(stream0: &[u8]) -> Headers {
    let mut out = Headers {
        request_time: String::new(),
        response_time: String::new(),
        status: String::new(),
        all_headers: String::new(),
        map: HashMap::new(),
    };
    let i = find_sub(stream0, b"HTTP/1.").or_else(|| find_sub(stream0, b"HTTP/2"));
    let head_end = i.unwrap_or(64).min(stream0.len());
    let times = scan_times(&stream0[..head_end]);
    if !times.is_empty() {
        out.request_time = chrome_time(*times.iter().min().unwrap());
        out.response_time = chrome_time(*times.iter().max().unwrap());
    }
    if let Some(i) = i {
        let end = find_sub(&stream0[i..], b"\x00\x00")
            .map(|e| i + e)
            .unwrap_or(stream0.len());
        let blob = &stream0[i..end];
        let mut lines: Vec<String> = Vec::new();
        for (idx, p) in blob.split(|&b| b == 0).enumerate() {
            let s = String::from_utf8_lossy(p).trim().to_string();
            if s.is_empty() {
                continue;
            }
            lines.push(s.clone());
            if idx == 0 {
                let sp: Vec<&str> = s.splitn(3, ' ').collect();
                if sp.len() >= 2 {
                    out.status = if sp.len() > 2 {
                        format!("{} {}", sp[1], sp[2])
                    } else {
                        sp[1].to_string()
                    };
                }
            } else if let Some((k, v)) = s.split_once(':') {
                out.map
                    .insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        out.all_headers = lines.join("\n");
    }
    out
}

fn walk_addresses(cache: &mut Cache, index_bytes: &[u8]) -> Vec<u32> {
    if index_bytes.len() < 32 || u32le(index_bytes, 0) != INDEX_MAGIC {
        return Vec::new();
    }
    let raw = i32le(index_bytes, 28);
    let cap = ((index_bytes.len().saturating_sub(INDEX_HEADER_SIZE)) / 4) as i64;
    let table_len = raw.max(0).min(cap.max(0) as i32);
    let mut addrs: Vec<u32> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    for b in 0..table_len as usize {
        let mut addr = u32le(index_bytes, INDEX_HEADER_SIZE + b * 4);
        while addr != 0
            && (addr & 0x8000_0000) != 0
            && !seen.contains(&addr)
            && addrs.len() < MAX_ENTRIES
        {
            seen.insert(addr);
            addrs.push(addr);
            let entry = cache.read(addr, ENTRY_SIZE);
            if entry.len() < 8 {
                break;
            }
            addr = u32le(&entry, 4);
        }
    }
    addrs
}

fn url_from_key(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let a = key.rfind("http://").map(|x| x as isize).unwrap_or(-1);
    let b = key.rfind("https://").map(|x| x as isize).unwrap_or(-1);
    let pos = a.max(b);
    if pos >= 0 {
        key[pos as usize..].trim().to_string()
    } else {
        key.to_string()
    }
}

fn entry_row(cache: &mut Cache, addr: u32, account: &str, source: &str) -> Option<Row> {
    let buf = cache.read(addr, ENTRY_SIZE);
    if buf.len() < 96 {
        return None;
    }
    let creation_time = u64le(&buf, 24) as i64;
    let key_len = i32le(&buf, 32);
    let long_key = u32le(&buf, 36);
    let data_size = [
        u32le(&buf, 40),
        u32le(&buf, 44),
        u32le(&buf, 48),
        u32le(&buf, 52),
    ];
    let data_addr = [
        u32le(&buf, 56),
        u32le(&buf, 60),
        u32le(&buf, 64),
        u32le(&buf, 68),
    ];
    if key_len <= 0 || key_len > 64 * 1024 {
        return None;
    }
    let key_len = key_len as usize;
    let key_bytes: Vec<u8> = if key_len <= ENTRY_SIZE - 96 {
        buf[96..(96 + key_len).min(buf.len())].to_vec()
    } else {
        cache.read(long_key, key_len)
    };
    let cache_key =
        String::from_utf8_lossy(key_bytes.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
    let url = url_from_key(&cache_key);

    let h = if data_addr[0] != 0 {
        parse_headers(&cache.read(data_addr[0], data_size[0] as usize))
    } else {
        Headers {
            request_time: String::new(),
            response_time: String::new(),
            status: String::new(),
            all_headers: String::new(),
            map: HashMap::new(),
        }
    };
    let body_addr = data_addr[1];
    let body_file = if body_addr != 0 && ((body_addr >> 28) & 0x7) == 0 {
        format!("f_{:06x}", body_addr & 0x0FFF_FFFF)
    } else {
        String::new()
    };
    let hd = |k: &str| h.map.get(k).cloned().unwrap_or_default();

    let mut r = Row::new();
    r.insert("account".into(), account.into());
    r.insert("url".into(), url);
    r.insert("cache_key".into(), cache_key);
    r.insert("creation_time".into(), chrome_time(creation_time));
    r.insert("request_time".into(), h.request_time);
    r.insert("response_time".into(), h.response_time);
    r.insert("status".into(), h.status);
    r.insert("content_type".into(), hd("content-type"));
    r.insert("content_length".into(), hd("content-length"));
    r.insert("content_encoding".into(), hd("content-encoding"));
    r.insert("server".into(), hd("server"));
    r.insert("date".into(), hd("date"));
    r.insert("last_modified".into(), hd("last-modified"));
    r.insert("etag".into(), hd("etag"));
    r.insert("cache_control".into(), hd("cache-control"));
    r.insert("location".into(), hd("location"));
    // Extract the response body (stream 1) for previewable types, decoded per
    // Content-Encoding, base64 so the viewer can show images / read text.
    let ct = hd("content-type").to_lowercase();
    let body_b64 = if body_addr != 0
        && data_size[1] > 0
        && (data_size[1] as usize) <= RAW_CAP
        && is_displayable(&ct)
    {
        let raw = cache.read(body_addr, data_size[1] as usize);
        if raw.is_empty() {
            String::new()
        } else {
            let dec = decode_body(&raw, &hd("content-encoding"));
            if !dec.is_empty() && dec.len() <= DECODED_CAP {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&dec)
            } else {
                String::new()
            }
        }
    } else {
        String::new()
    };

    r.insert(
        "body_size".into(),
        if data_size[1] != 0 {
            data_size[1].to_string()
        } else {
            String::new()
        },
    );
    r.insert("body_file".into(), body_file);
    r.insert("all_headers".into(), h.all_headers);
    r.insert("body_b64".into(), body_b64);
    r.insert("_source_file".into(), source.into());
    Some(r)
}

fn account_of(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, p) in parts.iter().enumerate() {
        if p.to_uppercase() == "BROWSER" && i + 1 < parts.len() {
            return parts[i + 1].clone();
        }
    }
    path.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Parse each `index` path that is a real HTTP blockfile cache. Returns the
/// output name, the consumed cache index, and rows so callers can retain
/// per-evidence-file extraction counts.
pub fn parse_caches(paths: &[PathBuf]) -> Vec<(String, PathBuf, Vec<Row>)> {
    let mut outputs: Vec<(String, PathBuf, Vec<Row>)> = Vec::new();
    let mut taken: HashSet<String> = HashSet::new();
    for index_path in paths {
        let parent_name = index_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if parent_name != "Cache_Data"
            || index_path
                .to_string_lossy()
                .to_lowercase()
                .contains("code cache")
        {
            continue;
        }
        let index_bytes = match std::fs::read(index_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if index_bytes.len() < 4 || u32le(&index_bytes, 0) != INDEX_MAGIC {
            continue;
        }

        let mut cache = Cache::new(index_path.parent().unwrap_or(Path::new(".")).to_path_buf());
        let account = account_of(index_path);
        let source = index_path.to_string_lossy().to_string();
        let mut rows: Vec<Row> = Vec::new();
        for addr in walk_addresses(&mut cache, &index_bytes) {
            if let Some(row) = entry_row(&mut cache, addr, &account, &source) {
                rows.push(row);
            }
        }
        if rows.is_empty() {
            continue;
        }

        let base = format!("{}_Chrome_Cache", account);
        let mut name = base.clone();
        let mut i = 2;
        while taken.contains(&name) {
            name = format!("{}_{}", base, i);
            i += 1;
        }
        taken.insert(name.clone());
        outputs.push((name, index_path.clone(), rows));
    }
    outputs
}
