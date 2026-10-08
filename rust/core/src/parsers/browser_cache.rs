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
    // 1 = body fully read and decoded (an empty body_b64 then means the response
    // really was empty), 0 = not recovered. No per-reason columns.
    "body_recovered",
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
/// `None` means "not recovered": compressed, corrupt, truncated or unsupported
/// bytes are never promoted to a plaintext body (R03). Decoding stops at
/// DECODED_CAP+1 bytes so a compression bomb cannot eat memory before the
/// caller's length check rejects it.
fn decode_body(raw: Vec<u8>, encoding: &str) -> Option<Vec<u8>> {
    let mut data = raw;
    // Servers apply Content-Encoding left to right, so undo it right to left.
    for token in encoding.split(',').rev() {
        let token = token.trim().to_ascii_lowercase();
        let input = std::mem::take(&mut data);
        data = match token.as_str() {
            "" | "identity" | "none" => input,
            // MultiGzDecoder: a concatenated multi-member body must decode whole,
            // not just its first member.
            "gzip" | "x-gzip" => bounded(flate2::read::MultiGzDecoder::new(&input[..]))?,
            // flate2 >= 1.1.10 required: older zio::read accepted a truncated
            // stream at EOF instead of reporting "incomplete deflate stream".
            "deflate" => {
                if has_zlib_header(&input) {
                    bounded(flate2::read::ZlibDecoder::new(&input[..]))?
                } else {
                    bounded(flate2::read::DeflateDecoder::new(&input[..]))?
                }
            }
            "br" => bounded(brotli::Decompressor::new(&input[..], 4096))?,
            "zstd" => bounded(zstd::stream::read::Decoder::new(&input[..]).ok()?)?,
            // sdch / zsdch / dcz …: never claim success for what we cannot decode.
            _ => return None,
        };
        if data.len() > DECODED_CAP {
            // Already cut at the cap: the caller rejects it and we do not feed
            // knowingly truncated bytes into the next stage.
            return Some(data);
        }
    }
    Some(data)
}

fn bounded<R: std::io::Read>(reader: R) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    reader
        .take(DECODED_CAP as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

/// True for a zlib (RFC 1950) wrapper: CM == 8 and the CMF/FLG check value is a
/// multiple of 31. Some servers send raw deflate, so the two paths must be told
/// apart up front — retrying a truncated zlib stream as raw deflate could turn
/// garbage into a "successful" body.
fn has_zlib_header(raw: &[u8]) -> bool {
    raw.len() >= 2
        && raw[0] & 0x0F == 8
        && (u16::from(raw[0]) * 256 + u16::from(raw[1])) % 31 == 0
}

const INDEX_MAGIC: u32 = 0xC103_CAC3;
const INDEX_HEADER_SIZE: usize = 368;
const BLOCK_HEADER_SIZE: usize = 8192;
const ENTRY_SIZE: usize = 256;
// Chromium kMaxInternalKeyLength — keys up to this length sit inside the
// EntryStore (up to 4 blocks); longer ones live at the long_key address.
const MAX_INTERNAL_KEY_LEN: usize = 4 * ENTRY_SIZE - 96 - 1;
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
    /// Block files (data_0..3) are memoized once per cache; only the requested
    /// slice is copied out. Cloning the whole file per access made parsing
    /// O(entries × file size) on large caches.
    fn block_bytes(&mut self, name: &str) -> &[u8] {
        let dir = &self.dir;
        self.blocks
            .entry(name.to_string())
            .or_insert_with(|| std::fs::read(dir.join(name)).unwrap_or_default())
    }
    /// Stored bytes plus whether the declared length was fully present. Silently
    /// truncating a short read or a block-capacity overflow would make partial
    /// bytes look like a good body, so completeness is decided here (R03).
    fn read_stream(&mut self, addr: u32, size: usize) -> Stream {
        // size == 0 means "length unspecified": nothing declared, nothing short.
        if addr & 0x8000_0000 == 0 {
            return Stream {
                bytes: Vec::new(),
                complete: size == 0,
            };
        }
        let file_type = (addr >> 28) & 0x7;
        if file_type == 0 {
            let f = self.dir.join(format!("f_{:06x}", addr & 0x0FFF_FFFF));
            // 외부 캐시 파일(f_######)은 통째로 읽지 않는다 — 엔트리가 주장한
            // 길이와 무관하게 실제 파일은 수백 MiB일 수 있으므로 요청 길이만,
            // 길이 미지정·과대 주장 경로(헤더 등)는 RAW_CAP까지만 읽는다.
            let limit = if size > 0 { size.min(RAW_CAP) } else { RAW_CAP };
            let mut bytes = Vec::new();
            if let Ok(file) = std::fs::File::open(f) {
                use std::io::Read;
                let _ = file.take(limit as u64).read_to_end(&mut bytes);
            }
            let complete = size == 0 || (size <= RAW_CAP && bytes.len() == size);
            return Stream { bytes, complete };
        }
        let bs = match block_size(file_type) {
            Some(b) => b,
            None => {
                return Stream {
                    bytes: Vec::new(),
                    complete: false,
                }
            }
        };
        let file_selector = (addr >> 16) & 0xFF;
        let num_blocks = ((addr >> 24) & 0x3) as usize + 1;
        let block_num = (addr & 0xFFFF) as usize;
        // The address's block count is this stream's capacity; reading past it
        // would append somebody else's blocks to the body.
        let capacity = num_blocks * bs;
        let length = if size > 0 { size } else { capacity };
        let off = BLOCK_HEADER_SIZE + block_num * bs;
        let data = self.block_bytes(&format!("data_{}", file_selector));
        let available = data.len().saturating_sub(off).min(capacity);
        let take = length.min(available);
        let bytes = data[off.min(data.len())..(off + take).min(data.len())].to_vec();
        Stream {
            bytes,
            complete: take == length,
        }
    }
    /// For paths that need no length check (entry / key / headers).
    fn read(&mut self, addr: u32, size: usize) -> Vec<u8> {
        self.read_stream(addr, size).bytes
    }
}

/// Bytes of one cache stream and whether the declared length was met.
struct Stream {
    bytes: Vec<u8>,
    complete: bool,
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

/// Request URL carved out of a cache key (R02). Real keys look like
/// `[Range_]<credential>/<upload_id>/[_dk_[s_|cn_]<top site> <frame site> ]<URL>`,
/// and a URL cannot contain a space, so in a double-keyed (_dk_) key the request
/// URL follows the last space. Scanning for the last `http` instead rewrote
/// requests such as `?r=https://…` into the URL nested in their query.
fn url_from_key(key: &str) -> String {
    let mut rest = key.trim();
    // Range child entries carry a "Range_" prefix and a ":<sig>:<child>" suffix.
    let ranged = rest.strip_prefix("Range_");
    if let Some(stripped) = ranged {
        rest = stripped;
    }
    // `<credential>/<upload_id>/` prefix, stripped only when both are decimal.
    let numeric_prefix = rest
        .split_once('/')
        .filter(|(first, _)| !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|(_, after_first)| {
            after_first
                .split_once('/')
                .filter(|(second, _)| !second.is_empty() && second.bytes().all(|b| b.is_ascii_digit()))
        });
    if let Some((_, after)) = numeric_prefix {
        rest = after;
    }
    // In a double-keyed section (_dk_ / _dk_s_ / _dk_cn_) sites precede the URL.
    if rest.starts_with("_dk_") {
        if let Some(space) = rest.rfind(' ') {
            rest = &rest[space + 1..];
        }
    }
    if ranged.is_some() {
        rest = strip_range_child_suffix(rest);
    }
    rest.to_string()
}

/// Drop only a range child's `:<hex signature>:<child index>` suffix; anything
/// that does not match that shape (a port, for instance) is left alone.
fn strip_range_child_suffix(url: &str) -> &str {
    let (head, child) = match url.rsplit_once(':') {
        Some(parts) => parts,
        None => return url,
    };
    if child.is_empty() || !child.bytes().all(|b| b.is_ascii_digit()) {
        return url;
    }
    match head.rsplit_once(':') {
        Some((base, signature))
            if !signature.is_empty() && signature.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            base
        }
        _ => url,
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
    // Chromium keeps keys up to kMaxInternalKeyLength inline, spilling into the
    // extra blocks of a multi-block EntryStore (long_key == 0); only longer keys
    // live at `long_key`. Reading just the first 256 bytes emptied every key over
    // 160 bytes — 580 Chrome and 2,591 Edge rows had no url/cache_key.
    let key_bytes: Vec<u8> = if key_len <= ENTRY_SIZE - 96 {
        buf[96..(96 + key_len).min(buf.len())].to_vec()
    } else if key_len <= MAX_INTERNAL_KEY_LEN {
        let full = cache.read(addr, 96 + key_len);
        match full.len() {
            n if n > 96 => full[96..].to_vec(),
            _ => Vec::new(),
        }
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
    // Body (stream 1) is kept only for previewable types, decoded per
    // Content-Encoding and base64 encoded. Only fully recovered bytes land in
    // body_b64; short reads, decode failures, unsupported encodings and cap
    // overflows are all "not recovered" and never store compressed bytes (R03).
    let ct = hd("content-type").to_lowercase();
    let declared_body = data_size[1] as usize;
    let (body_b64, body_recovered) = if declared_body == 0 {
        // A response with no body (204 / 304 …) is validly empty, not a failure.
        (String::new(), true)
    } else if body_addr == 0 || declared_body > RAW_CAP || !is_displayable(&ct) {
        (String::new(), false)
    } else {
        let stream = cache.read_stream(body_addr, declared_body);
        if !stream.complete {
            (String::new(), false)
        } else {
            match decode_body(stream.bytes, &hd("content-encoding")) {
                Some(decoded) if decoded.len() <= DECODED_CAP => {
                    use base64::Engine;
                    (
                        base64::engine::general_purpose::STANDARD.encode(&decoded),
                        true,
                    )
                }
                _ => (String::new(), false),
            }
        }
    };

    // Keep 0 distinct from unknown: store the declared length as is (R11).
    r.insert("body_size".into(), data_size[1].to_string());
    r.insert("body_file".into(), body_file);
    r.insert("all_headers".into(), h.all_headers);
    r.insert("body_b64".into(), body_b64);
    r.insert(
        "body_recovered".into(),
        if body_recovered { "1".into() } else { "0".into() },
    );
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

/// 수집 경로에서 브라우저를 판별한다 — 경로 세그먼트가 결정적일 때만 Some.
/// 수집 레이아웃(BROWSER/<계정>/CHROME/…)과 원본 프로필 경로(Google\Chrome,
/// Microsoft\Edge, Naver\Whale)의 세그먼트를 모두 커버한다. 단서가 없으면
/// None — 호출부는 브라우저를 추측하지 않고 미상으로 처리한다(T8 확정).
pub fn browser_of(path: &Path) -> Option<&'static str> {
    for part in path.components() {
        match part.as_os_str().to_string_lossy().to_lowercase().as_str() {
            "chrome" => return Some("Chrome"),
            "edge" => return Some("Edge"),
            "whale" => return Some("Whale"),
            _ => {}
        }
    }
    None
}

/// 후보 검증 결과 — 유효 캐시 index(출력명 배정)와, 캐시 레이아웃에 있었지만
/// 읽기·매직 검증에 실패해 거부된 index(사유 포함)를 구분한다. 거부 파일이
/// "성공한 빈 캐시"로 보이지 않도록 파이프라인이 사유를 보고서에 남긴다.
/// 레이아웃상 비대상(Cache/Cache_Data 밖, Code Cache)은 증거 입력이 아니므로
/// 어느 쪽에도 넣지 않는다.
#[derive(Default)]
pub struct CacheCandidates {
    pub outputs: Vec<(String, PathBuf)>,
    pub rejected: Vec<(PathBuf, String)>,
}

/// Valid blockfile cache indexes among `paths`, each with its assigned output
/// name (`<account>_<브라우저|Unknown>_Cache`, uniquified). Unreadable or
/// non-blockfile indexes are returned as rejected with their reason.
pub fn cache_outputs(paths: &[PathBuf]) -> CacheCandidates {
    let mut result = CacheCandidates::default();
    let mut taken: HashSet<String> = HashSet::new();
    for index_path in paths {
        let parent_name = index_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // 신형 레이아웃(Cache/Cache_Data/index)과 구형 레이아웃(Cache/index,
        // f_* 동거 — 구 Edge·구 Chrome)을 모두 허용한다. 뒤의 블록파일 매직
        // 검사가 엉뚱한 파일의 통과를 막는 안전망이다(T8).
        let layout_ok = parent_name.eq_ignore_ascii_case("Cache_Data")
            || parent_name.eq_ignore_ascii_case("Cache");
        if !layout_ok
            || index_path
                .to_string_lossy()
                .to_lowercase()
                .contains("code cache")
        {
            continue;
        }
        let mut head = [0u8; 4];
        match std::fs::File::open(index_path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
        {
            Ok(()) => {
                if u32::from_le_bytes(head) != INDEX_MAGIC {
                    result.rejected.push((
                        index_path.clone(),
                        "블록파일 캐시 index 매직 불일치".to_string(),
                    ));
                    continue;
                }
            }
            Err(error) => {
                result
                    .rejected
                    .push((index_path.clone(), format!("index 읽기 실패: {error}")));
                continue;
            }
        }
        // 브라우저를 특정할 수 없으면 Chrome으로 단정하지 않고 Unknown으로
        // 표기한다 — 증거 귀속은 근거 있을 때만(T8 확정).
        let base = format!(
            "{}_{}_Cache",
            account_of(index_path),
            browser_of(index_path).unwrap_or("Unknown")
        );
        let mut name = base.clone();
        let mut i = 2;
        while taken.contains(&name) {
            name = format!("{}_{}", base, i);
            i += 1;
        }
        taken.insert(name.clone());
        result.outputs.push((name, index_path.clone()));
    }
    result
}

/// Parse one cache index, handing each entry row to `push` as it is decoded so
/// the caller can stream rows straight into SQLite — the full result set never
/// lives in memory. Returns the number of rows pushed.
pub fn parse_cache_index(
    index_path: &Path,
    push: &mut dyn FnMut(Row) -> anyhow::Result<()>,
) -> anyhow::Result<usize> {
    let index_bytes = std::fs::read(index_path)?;
    if index_bytes.len() < 4 || u32le(&index_bytes, 0) != INDEX_MAGIC {
        anyhow::bail!("not a blockfile cache index");
    }
    let mut cache = Cache::new(index_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    let account = account_of(index_path);
    let source = index_path.to_string_lossy().to_string();
    let mut count = 0usize;
    for addr in walk_addresses(&mut cache, &index_bytes) {
        if let Some(row) = entry_row(&mut cache, addr, &account, &source) {
            push(row)?;
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_body_bounds_decompression_memory() {
        use std::io::Write;
        // 8 MiB of zeros — a highly compressible input that expands past
        // DECODED_CAP (4 MiB). Decoding must stop at cap+1 bytes (memory bound)
        // and the caller's length check rejects that value.
        let plain = vec![0u8; 8 * 1024 * 1024];
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&plain).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode_body(gz, "gzip").unwrap().len(), DECODED_CAP + 1);

        let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zl.write_all(&plain).unwrap();
        let zl = zl.finish().unwrap();
        assert_eq!(decode_body(zl, "deflate").unwrap().len(), DECODED_CAP + 1);

        let mut br = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 5, 22);
            w.write_all(&plain).unwrap();
        }
        assert_eq!(decode_body(br, "br").unwrap().len(), DECODED_CAP + 1);

        let zs = zstd::encode_all(&plain[..], 3).unwrap();
        assert_eq!(decode_body(zs, "zstd").unwrap().len(), DECODED_CAP + 1);

        // A normal body within the cap decodes whole.
        let small = b"hello cache body".repeat(64);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&small).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(decode_body(gz, "gzip").as_deref(), Some(&small[..]));
    }

    #[test]
    fn external_cache_file_read_is_bounded() {
        let root = std::env::temp_dir().join(format!(
            "wina-cache-extfile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        // 실제 외부 파일은 RAW_CAP보다 크다 — 엔트리가 주장한 길이(작음)나
        // 길이 미지정 경로 모두 요청 상한을 넘겨 읽으면 안 된다.
        std::fs::write(root.join("f_000001"), vec![0u8; RAW_CAP + 1024 * 1024]).unwrap();
        let mut cache = Cache::new(root.clone());
        let addr = 0x8000_0001u32; // external file #1
        assert_eq!(cache.read(addr, 100).len(), 100);
        assert_eq!(cache.read(addr, 0).len(), RAW_CAP);
        assert_eq!(cache.read(addr, usize::MAX).len(), RAW_CAP);
        // A stream cut at the cap reports that the declared length was not met.
        assert!(cache.read_stream(addr, 100).complete);
        assert!(!cache.read_stream(addr, usize::MAX).complete);
        let _ = std::fs::remove_dir_all(root);
    }

    /// T8: 구형 레이아웃(Cache/ 바로 밑 index)도 채택되고, 출력명은 경로에서
    /// 판별한 브라우저를 쓰며, 단서 없으면 Chrome 단정 대신 Unknown이 된다.
    #[test]
    fn cache_outputs_name_browser_and_accept_legacy_layout() {
        let root = std::env::temp_dir().join(format!(
            "wina-cache-browser-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // 구형 Edge: Cache/ 바로 밑 index (Cache_Data 폴더 없음 — NY/PC1 ny 계정형).
        let legacy_edge = root.join("BROWSER/ny/EDGE/Cache");
        // 브라우저 단서가 전혀 없는 경로.
        let unknown = root.join("BROWSER/userX/Cache/Cache_Data");
        std::fs::create_dir_all(&legacy_edge).unwrap();
        std::fs::create_dir_all(&unknown).unwrap();
        std::fs::write(legacy_edge.join("index"), INDEX_MAGIC.to_le_bytes()).unwrap();
        std::fs::write(unknown.join("index"), INDEX_MAGIC.to_le_bytes()).unwrap();
        let outputs = cache_outputs(&[legacy_edge.join("index"), unknown.join("index")]).outputs;
        let names: Vec<&str> = outputs.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["ny_Edge_Cache", "userX_Unknown_Cache"]);
        assert_eq!(browser_of(Path::new("BROWSER/a/CHROME/Default/History")), Some("Chrome"));
        assert_eq!(browser_of(Path::new("C:/Users/x/AppData/Local/Naver/Whale/User Data")), Some("Whale"));
        assert_eq!(browser_of(Path::new("BROWSER/a/History")), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cache_outputs_skips_invalid_or_unreadable_indexes() {
        let root = std::env::temp_dir().join(format!(
            "wina-cache-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let good = root.join("BROWSER/userA/CHROME/Cache/Cache_Data");
        let bad = root.join("BROWSER/userB/CHROME/Cache/Cache_Data");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(good.join("index"), INDEX_MAGIC.to_le_bytes()).unwrap();
        std::fs::write(bad.join("index"), b"nope").unwrap();
        let paths = vec![
            good.join("index"),
            bad.join("index"),
            root.join("BROWSER/userC/missing/index"),
        ];
        let candidates = cache_outputs(&paths);
        let outputs = &candidates.outputs;
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, "userA_Chrome_Cache");
        // 캐시 레이아웃의 매직 불일치 index는 사유와 함께 거부 목록에 남고,
        // 레이아웃 밖(비대상) 경로는 어느 목록에도 없다.
        assert_eq!(candidates.rejected.len(), 1);
        assert_eq!(candidates.rejected[0].0, bad.join("index"));
        assert!(candidates.rejected[0].1.contains("매직"));
        // The magic-only index has an empty hash table — zero rows, no error.
        let mut rows = 0usize;
        let counted = parse_cache_index(&outputs[0].1, &mut |_row| {
            rows += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(counted, 0);
        assert_eq!(rows, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- R02: cache key prefix / request URL boundary ----

    /// Only key shapes seen in the real collection (Chrome 3,489 / Edge 8,070
    /// entries). The request URL is the last token after the
    /// `<credential>/<upload_id>/[_dk_…]` prefix; a URL nested in a query must
    /// never replace it.
    #[test]
    fn url_from_key_parses_prefix_and_keeps_nested_urls() {
        // Double key (_dk_), cross-site variants (_dk_s_, _dk_cn_), non-zero id.
        assert_eq!(
            url_from_key(
                "1/0/_dk_https://chatgpt.com https://chatgpt.com https://chatgpt.com/backend-api/wham/usage/credit-usage-events"
            ),
            "https://chatgpt.com/backend-api/wham/usage/credit-usage-events"
        );
        assert_eq!(
            url_from_key(
                "1/0/_dk_s_https://claude.ai https://hcaptcha.com https://newassets.hcaptcha.com/captcha/v1/static/hcaptcha.html"
            ),
            "https://newassets.hcaptcha.com/captcha/v1/static/hcaptcha.html"
        );
        assert_eq!(
            url_from_key("1/0/_dk_cn_https://github.com https://github.com https://github.com/"),
            "https://github.com/"
        );
        assert_eq!(
            url_from_key(
                "1/1790620045052570/_dk_s_https://helpu.kr https://helpu.kr https://helpu.kr/HelpuCustomer_CustomerPage_old/jsign/download.php"
            ),
            "https://helpu.kr/HelpuCustomer_CustomerPage_old/jsign/download.php"
        );
        // Request with a plain URL inside its query: do not cut at the last http.
        assert_eq!(
            url_from_key(
                "1/0/_dk_https://glasswire.com https://glasswire.com https://b.sf-syn.com/badge_img/2987402/light-default?&variant_id=sf&r=https://www.glasswire.com/"
            ),
            "https://b.sf-syn.com/badge_img/2987402/light-default?&variant_id=sf&r=https://www.glasswire.com/"
        );
        assert_eq!(
            url_from_key(
                "1/0/_dk_https://naver.com https://naver.com https://search.pstatic.net/sunny?src=https%3A%2F%2Fwww.gogoip.co.kr%2Fgogoip_icon.ico&type=f30_30_png_expire24"
            ),
            "https://search.pstatic.net/sunny?src=https%3A%2F%2Fwww.gogoip.co.kr%2Fgogoip_icon.ico&type=f30_30_png_expire24"
        );
        // Even with a chrome:// isolation key the last token is the request URL.
        assert_eq!(
            url_from_key(
                "1/0/_dk_chrome://new-tab-page chrome-untrusted://new-tab-page https://www.gstatic.com/feedback/js/help/prod/service/lazy.min.js"
            ),
            "https://www.gstatic.com/feedback/js/help/prod/service/lazy.min.js"
        );
        assert_eq!(
            url_from_key("1/0/_dk_chrome://whats-new chrome://whats-new chrome://whats-new/"),
            "chrome://whats-new/"
        );
        // Keys without a double-key section and without any prefix.
        assert_eq!(
            url_from_key("1/0/https://connect.facebook.net/en_US/fbevents.js"),
            "https://connect.facebook.net/en_US/fbevents.js"
        );
        assert_eq!(
            url_from_key("https://example.test/a?next=https://b.test/c"),
            "https://example.test/a?next=https://b.test/c"
        );
        // Range child entry (Range_…:<signature>:<child index>).
        assert_eq!(
            url_from_key(
                "Range_1/0/_dk_https://claude.ai https://claude.ai https://assets.claude.ai/videos/cowork-login-hero.mp4:2fae9d4cd130f4:2"
            ),
            "https://assets.claude.ai/videos/cowork-login-hero.mp4"
        );
        // A suffix that is not the range shape (a port) stays untouched.
        assert_eq!(
            url_from_key("1/0/_dk_https://a.test https://a.test https://a.test:8443/x"),
            "https://a.test:8443/x"
        );
        assert_eq!(url_from_key(""), "");
    }

    // ---- R03: decoding must prove a complete stream ----

    /// Compressed, corrupt and unsupported bytes never become a successful body;
    /// a validly empty body and the cap boundaries stay distinguishable.
    #[test]
    fn decode_body_requires_successful_full_decode() {
        use std::io::Write;
        let plain = b"cache body plaintext".repeat(32);

        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        assert_eq!(decode_body(gz.clone(), "gzip").as_deref(), Some(&plain[..]));
        // Truncated body: without the gzip trailer this must not pass.
        assert_eq!(decode_body(gz[..gz.len() - 8].to_vec(), "gzip"), None);
        assert_eq!(decode_body(gz[..12].to_vec(), "gzip"), None);
        // Corrupt body.
        assert_eq!(decode_body(b"\x1f\x8b not really gzip".to_vec(), "gzip"), None);
        // Concatenated gzip members must all be decoded, not just the first.
        let two_members = {
            let mut both = gz.clone();
            both.extend_from_slice(&gz);
            both
        };
        let doubled = plain.repeat(2);
        assert_eq!(decode_body(two_members.clone(), "gzip").as_deref(), Some(&doubled[..]));
        // A truncated second member fails the whole body.
        assert_eq!(
            decode_body(two_members[..two_members.len() - 8].to_vec(), "gzip"),
            None
        );

        let zs = zstd::encode_all(&plain[..], 3).unwrap();
        assert_eq!(decode_body(zs.clone(), "zstd").as_deref(), Some(&plain[..]));
        assert_eq!(decode_body(zs[..zs.len() - 4].to_vec(), "zstd"), None);
        assert_eq!(
            decode_body(b"\x28\xb5\x2f\xfd broken zstd frame".to_vec(), "zstd"),
            None
        );
        assert_eq!(decode_body(plain.clone(), "zstd"), None);

        let zl = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        assert_eq!(decode_body(zl.clone(), "deflate").as_deref(), Some(&plain[..]));
        let raw_deflate = {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        assert_eq!(
            decode_body(raw_deflate.clone(), "deflate").as_deref(),
            Some(&plain[..])
        );
        // Only the header picks the path; a failure is never retried elsewhere.
        assert!(has_zlib_header(&zl));
        assert!(!has_zlib_header(&raw_deflate));
        // Truncated zlib / raw deflate: flate2 (>= 1.1.10) reports "incomplete
        // deflate stream" at EOF without StreamEnd and we keep no partial output.
        assert_eq!(decode_body(zl[..zl.len() - 6].to_vec(), "deflate"), None);
        assert_eq!(decode_body(zl[..4].to_vec(), "deflate"), None);
        assert_eq!(
            decode_body(raw_deflate[..raw_deflate.len() - 3].to_vec(), "deflate"),
            None
        );
        assert_eq!(decode_body(b"not deflate at all".to_vec(), "deflate"), None);

        let br = {
            let mut out = Vec::new();
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                w.write_all(&plain).unwrap();
            }
            out
        };
        assert_eq!(decode_body(br.clone(), "br").as_deref(), Some(&plain[..]));
        // A cut brotli stream fails where its input runs out.
        assert_eq!(decode_body(br[..br.len() / 2].to_vec(), "br"), None);

        // Encodings stacked by the server are undone in reverse order.
        let chained = {
            let mut out = Vec::new();
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                w.write_all(&gz).unwrap();
            }
            out
        };
        assert_eq!(decode_body(chained, "gzip, br").as_deref(), Some(&plain[..]));

        // No encoding / identity: the stored bytes are the body.
        assert_eq!(decode_body(plain.clone(), "").as_deref(), Some(&plain[..]));
        assert_eq!(
            decode_body(plain.clone(), "identity").as_deref(),
            Some(&plain[..])
        );
        // Unsupported encodings seen in the real Edge cache (zsdch) stay failures.
        assert_eq!(decode_body(plain.clone(), "zsdch"), None);
        assert_eq!(decode_body(plain.clone(), "sdch"), None);
        assert_eq!(decode_body(plain.clone(), "dcz"), None);
        assert_eq!(decode_body(plain.clone(), "gzip, zsdch"), None);

        // Validly empty: a complete gzip stream whose output is 0 bytes.
        let empty_gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"").unwrap();
            e.finish().unwrap()
        };
        assert_eq!(decode_body(empty_gz, "gzip"), Some(Vec::new()));
        assert_eq!(decode_body(Vec::new(), ""), Some(Vec::new()));

        // Cap boundary: exactly DECODED_CAP passes, more is cut to cap+1 so the
        // caller rejects it.
        let at_cap = vec![b'x'; DECODED_CAP];
        let gz_cap = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&at_cap).unwrap();
            e.finish().unwrap()
        };
        assert_eq!(decode_body(gz_cap, "gzip").unwrap().len(), DECODED_CAP);
        let over_cap = vec![b'x'; DECODED_CAP + 1024];
        let gz_over = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&over_cap).unwrap();
            e.finish().unwrap()
        };
        assert_eq!(decode_body(gz_over, "gzip").unwrap().len(), DECODED_CAP + 1);
        let zs_over = zstd::encode_all(&over_cap[..], 3).unwrap();
        assert_eq!(decode_body(zs_over, "zstd").unwrap().len(), DECODED_CAP + 1);
    }

    /// A declared length that the actual read cannot meet (short file, block
    /// capacity overflow, block outside the file) is never reported complete.
    #[test]
    fn read_stream_reports_short_and_overflowing_reads() {
        let root = synth_dir("wina-cache-stream");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("f_000001"), vec![7u8; 100]).unwrap();
        let mut data3 = vec![0u8; BLOCK_HEADER_SIZE + 1024];
        data3[BLOCK_HEADER_SIZE..].fill(9);
        std::fs::write(root.join("data_3"), &data3).unwrap();
        let mut cache = Cache::new(root.clone());

        // External file: declared 100 == actual, declared 500 > actual, > RAW_CAP.
        let ext = 0x8000_0001u32;
        let exact = cache.read_stream(ext, 100);
        assert_eq!((exact.bytes.len(), exact.complete), (100, true));
        let short = cache.read_stream(ext, 500);
        assert_eq!((short.bytes.len(), short.complete), (100, false));
        let over = cache.read_stream(ext, RAW_CAP + 1);
        assert_eq!((over.bytes.len(), over.complete), (100, false));

        // Block file: 2,000 bytes declared on a one-block (1 KiB) address must
        // stay incomplete instead of borrowing the neighbouring block.
        let block = 0x8000_0000u32 | (3 << 28) | (3 << 16);
        let full = cache.read_stream(block, 1024);
        assert_eq!((full.bytes.len(), full.complete), (1024, true));
        assert!(full.bytes.iter().all(|&b| b == 9));
        let spill = cache.read_stream(block, 2000);
        assert_eq!((spill.bytes.len(), spill.complete), (1024, false));
        // Block number past the end of the file.
        let outside = cache.read_stream(block | 50, 256);
        assert!(outside.bytes.is_empty() && !outside.complete);
        // No stream without the initialized bit; only declared 0 is "validly empty".
        assert!(cache.read_stream(0, 0).complete);
        assert!(!cache.read_stream(0, 10).complete);
        let _ = std::fs::remove_dir_all(root);
    }

    fn synth_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    const SYNTH_T1: i64 = 13_400_000_000_000_000;
    const SYNTH_T2: i64 = 13_400_000_000_100_000;

    /// Shaped like the real stream 0 (serialized HttpResponseInfo): two Chrome
    /// microsecond times, then NUL separated status/header lines, double NUL end.
    fn synth_headers(status: &str, headers: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&SYNTH_T1.to_le_bytes());
        v.extend_from_slice(&SYNTH_T2.to_le_bytes());
        v.extend_from_slice(status.as_bytes());
        v.push(0);
        for h in headers {
            v.extend_from_slice(h.as_bytes());
            v.push(0);
        }
        v.push(0);
        v
    }

    enum SynthBody {
        None,
        External { bytes: Vec<u8>, declared: u32 },
        Block { bytes: Vec<u8>, declared: u32 },
    }

    struct SynthEntry {
        key: String,
        headers: Vec<u8>,
        body: SynthBody,
    }

    /// Minimal blockfile cache: index hash table + data_1 EntryStore blocks (4
    /// per entry so long inline keys span blocks as they do in practice) +
    /// data_3 1 KiB blocks and f_###### external files for the streams.
    fn build_synth_cache(dir: &Path, entries: &[SynthEntry]) {
        std::fs::create_dir_all(dir).unwrap();
        let mut data1 = vec![0u8; BLOCK_HEADER_SIZE + entries.len() * 4 * ENTRY_SIZE];
        let mut data3 = vec![0u8; BLOCK_HEADER_SIZE + entries.len().max(1) * 1024];
        let mut index = vec![0u8; INDEX_HEADER_SIZE + entries.len() * 4];
        index[..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
        index[28..32].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            let block = (i * 4) as u32;
            // file_type 2 (data_1, 256-byte blocks), 4 blocks, selector 1.
            let entry_addr = 0x8000_0000 | (2u32 << 28) | (3u32 << 24) | (1u32 << 16) | block;
            let slot = INDEX_HEADER_SIZE + i * 4;
            index[slot..slot + 4].copy_from_slice(&entry_addr.to_le_bytes());
            std::fs::write(dir.join(format!("f_{:06x}", 0x10 + i)), &e.headers).unwrap();
            let header_addr = 0x8000_0000u32 | (0x10 + i as u32);
            let (body_addr, declared) = match &e.body {
                SynthBody::None => (0u32, 0u32),
                SynthBody::External { bytes, declared } => {
                    std::fs::write(dir.join(format!("f_{:06x}", 0x100 + i)), bytes).unwrap();
                    (0x8000_0000u32 | (0x100 + i as u32), *declared)
                }
                SynthBody::Block { bytes, declared } => {
                    let off = BLOCK_HEADER_SIZE + i * 1024;
                    data3[off..off + bytes.len()].copy_from_slice(bytes);
                    // file_type 3 (data_3, 1 KiB blocks), 1 block, selector 3.
                    (0x8000_0000u32 | (3u32 << 28) | (3u32 << 16) | i as u32, *declared)
                }
            };
            let base = BLOCK_HEADER_SIZE + block as usize * ENTRY_SIZE;
            let mut put32 = |off: usize, v: u32| {
                data1[base + off..base + off + 4].copy_from_slice(&v.to_le_bytes());
            };
            put32(4, 0); // next: end of chain
            put32(24, (SYNTH_T1 as u64 & 0xFFFF_FFFF) as u32);
            put32(28, (SYNTH_T1 as u64 >> 32) as u32);
            put32(32, e.key.len() as u32);
            put32(36, 0); // no long_key: the key continues inside the entry blocks
            put32(40, e.headers.len() as u32);
            put32(44, declared);
            put32(56, header_addr);
            put32(60, body_addr);
            data1[base + 96..base + 96 + e.key.len()].copy_from_slice(e.key.as_bytes());
        }
        std::fs::write(dir.join("index"), &index).unwrap();
        std::fs::write(dir.join("data_1"), &data1).unwrap();
        std::fs::write(dir.join("data_3"), &data3).unwrap();
    }

    /// R02 / R03 / R11 end to end on a synthetic blockfile cache: recovered vs
    /// failed bodies, validly empty bodies, caps, a long inline key, raw headers
    /// with the status reason, a 0 size and the source path.
    #[test]
    fn parse_cache_index_separates_recovered_bodies_from_failures() {
        use std::io::Write;
        let root = synth_dir("wina-cache-synth");
        let dir = root.join("BROWSER/userZ/CHROME/Cache/Cache_Data");
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"<html>recovered</html>").unwrap();
            e.finish().unwrap()
        };
        let zs = zstd::encode_all(&b"{\"ok\":true}"[..], 3).unwrap();
        let long_url = format!("https://long.test/{}.js", "a".repeat(200));
        let entries = vec![
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/page?next=https://b.test/x"
                    .into(),
                headers: synth_headers(
                    "HTTP/1.1 200 OK",
                    &["Content-Type: text/html", "Content-Encoding: gzip", "Server: nginx"],
                ),
                body: SynthBody::External { declared: gz.len() as u32, bytes: gz.clone() },
            },
            SynthEntry {
                key: "1/0/_dk_s_https://a.test https://a.test https://a.test/api.json".into(),
                headers: synth_headers(
                    "HTTP/1.1 200 OK",
                    &["Content-Type: application/json", "Content-Encoding: zstd"],
                ),
                body: SynthBody::External { declared: zs.len() as u32, bytes: zs.clone() },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/corrupt.html".into(),
                headers: synth_headers(
                    "HTTP/1.1 200 OK",
                    &["Content-Type: text/html", "Content-Encoding: gzip"],
                ),
                body: SynthBody::External {
                    // Declared length matches the bytes: decoding is what fails.
                    declared: 18,
                    bytes: b"\x1f\x8bbroken gzip body".to_vec(),
                },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/short.txt".into(),
                headers: synth_headers("HTTP/1.1 200 OK", &["Content-Type: text/plain"]),
                body: SynthBody::External { declared: 500, bytes: vec![b'z'; 100] },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/empty".into(),
                headers: synth_headers(
                    "HTTP/1.1 204 No Content",
                    &["Content-Type: text/plain", "Content-Length: 0"],
                ),
                body: SynthBody::None,
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/app.bin".into(),
                headers: synth_headers(
                    "HTTP/1.1 200 OK",
                    &["Content-Type: application/octet-stream"],
                ),
                body: SynthBody::External { declared: 10, bytes: vec![1u8; 10] },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/spill.txt".into(),
                headers: synth_headers("HTTP/1.1 200 OK", &["Content-Type: text/plain"]),
                body: SynthBody::Block { declared: 2000, bytes: vec![b'q'; 1024] },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/huge.txt".into(),
                headers: synth_headers("HTTP/1.1 200 OK", &["Content-Type: text/plain"]),
                body: SynthBody::External { declared: RAW_CAP as u32 + 1, bytes: vec![b'y'; 10] },
            },
            SynthEntry {
                key: format!("1/0/_dk_https://long.test https://long.test {long_url}"),
                headers: synth_headers(
                    "HTTP/1.1 404 Not Found",
                    &["Content-Type: text/plain", "ETag: \"abc\""],
                ),
                body: SynthBody::External { declared: 4, bytes: b"gone".to_vec() },
            },
            SynthEntry {
                key: "1/0/_dk_https://a.test https://a.test https://a.test/unsupported.txt".into(),
                headers: synth_headers(
                    "HTTP/1.1 200 OK",
                    &["Content-Type: text/plain", "Content-Encoding: zsdch"],
                ),
                body: SynthBody::External { declared: 8, bytes: b"whatever".to_vec() },
            },
        ];
        build_synth_cache(&dir, &entries);
        let index_path = dir.join("index");
        let mut rows: Vec<Row> = Vec::new();
        let count = parse_cache_index(&index_path, &mut |row| {
            rows.push(row);
            Ok(())
        })
        .unwrap();
        assert_eq!(count, entries.len());
        assert_eq!(rows.len(), entries.len());
        let f = |i: usize, k: &str| rows[i].get(k).cloned().unwrap_or_default();
        let body = |i: usize| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(f(i, "body_b64").as_bytes())
                .unwrap()
        };

        // 0: gzip recovered; the request URL keeps the URL inside its query.
        assert_eq!(f(0, "url"), "https://a.test/page?next=https://b.test/x");
        assert_eq!(f(0, "cache_key"), entries[0].key);
        assert_eq!(f(0, "status"), "200 OK");
        assert_eq!(
            f(0, "all_headers"),
            "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Encoding: gzip\nServer: nginx"
        );
        assert_eq!(f(0, "server"), "nginx");
        assert_eq!(f(0, "body_recovered"), "1");
        assert_eq!(body(0), b"<html>recovered</html>");
        assert_eq!(f(0, "body_size"), gz.len().to_string());
        assert_eq!(f(0, "request_time"), chrome_time(SYNTH_T1));
        assert_eq!(f(0, "response_time"), chrome_time(SYNTH_T2));
        assert_eq!(f(0, "creation_time"), chrome_time(SYNTH_T1));
        assert_eq!(f(0, "_source_file"), index_path.to_string_lossy());
        assert_eq!(f(0, "account"), "userZ");

        // 1: zstd recovered (672 real bodies take this path).
        assert_eq!(f(1, "url"), "https://a.test/api.json");
        assert_eq!(f(1, "body_recovered"), "1");
        assert_eq!(body(1), b"{\"ok\":true}");

        // 2 / 3: corrupt compression and a short read fail with an empty body.
        for i in [2usize, 3] {
            assert_eq!(f(i, "body_recovered"), "0", "row {i}");
            assert_eq!(f(i, "body_b64"), "", "row {i}");
        }
        assert_eq!(f(3, "body_size"), "500");

        // 4: validly empty body: recovered, and the size is 0 rather than NULL.
        assert_eq!(f(4, "status"), "204 No Content");
        assert_eq!(f(4, "body_recovered"), "1");
        assert_eq!(f(4, "body_b64"), "");
        assert_eq!(f(4, "body_size"), "0");
        assert_eq!(f(4, "content_length"), "0");

        // 5 / 6 / 7: non-previewable MIME, block overflow, declared > RAW_CAP.
        for i in [5usize, 6, 7] {
            assert_eq!(f(i, "body_recovered"), "0", "row {i}");
            assert_eq!(f(i, "body_b64"), "", "row {i}");
        }
        assert_eq!(f(5, "body_size"), "10");
        assert_eq!(f(6, "body_size"), "2000");
        assert_eq!(f(7, "body_size"), (RAW_CAP + 1).to_string());

        // 8: a key over 160 bytes continued in the entry blocks is read whole.
        assert_eq!(f(8, "cache_key"), entries[8].key);
        assert_eq!(f(8, "url"), long_url);
        assert_eq!(f(8, "status"), "404 Not Found");
        assert_eq!(f(8, "etag"), "\"abc\"");
        assert_eq!(f(8, "body_recovered"), "1");
        assert_eq!(body(8), b"gone");

        // 9: an unsupported encoding never promotes compressed bytes to a body.
        assert_eq!(f(9, "content_encoding"), "zsdch");
        assert_eq!(f(9, "body_recovered"), "0");
        assert_eq!(f(9, "body_b64"), "");

        // Stored columns must stay within the declared order (pipeline DDL).
        for row in &rows {
            for key in row.keys() {
                assert!(CACHE_FIELD_ORDER.contains(&key.as_str()), "{key}");
            }
        }
        assert!(CACHE_FIELD_ORDER.contains(&"body_recovered"));
        let _ = std::fs::remove_dir_all(root);
    }
}
