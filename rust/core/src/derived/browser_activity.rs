//! BrowserActivity storage: one analysis record per observed browser fact,
//! scoped to the browser input it came from. Individual visits, downloads and
//! cached responses are events; a URL summary is a separate record kind
//! (event_type 'url_summary') so an aggregate is never counted as a visit
//! while still having an identity for search, detail and bookmarks.
//!
//! Search terms, download URL chains and cache bodies hang off their record.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _, Result};
use base64::Engine as _;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use super::schema::{self, ChildSpec, DbSpec};
use super::{int, is_sid, nz, text, text_opt, Cell, Ctx, DerivedDb, Record, SourceRef};
use crate::browser_input::{self, BrowserInput};

pub(super) const DB_NAME: &str = "BrowserActivity";
/// Storage contract for this database. Results without it lack individual
/// visits, chains, search terms and per-row cache bodies, so they need a
/// reparse rather than a column backfill.
pub(super) const CONTRACT_VERSION: i64 = 2;

const BROWSER_DIR: &str = "BROWSER";

pub(super) const INPUTS_TABLE: &str = "BrowserInputs";
pub(super) const SUMMARIES_TABLE: &str = "BrowserUrlSummaries";
pub(super) const SEARCH_TERMS_TABLE: &str = "BrowserSearchTerms";
pub(super) const DOWNLOAD_CHAIN_TABLE: &str = "BrowserDownloadChain";
pub(super) const CACHE_DETAILS_TABLE: &str = "BrowserCacheDetails";

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "BrowserInputs" (
  "input_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "input_kind" TEXT NOT NULL,
  "browser" TEXT,
  "profile" TEXT,
  "account_label" TEXT,
  "account" TEXT,
  "account_sid" TEXT,
  "source_file" TEXT,
  "facts_db" TEXT NOT NULL,
  "facts_dataset_id" TEXT NOT NULL,
  PRIMARY KEY(input_id),
  CHECK(ordinal >= 0)
);
-- Aggregate URL evidence. Its analysis record is the BrowserActivity row with
-- event_type 'url_summary', so summary-only inputs still have a searchable,
-- bookmarkable identity; individual visits remain event_type 'visit'.
CREATE TABLE "BrowserUrlSummaries" (
  "summary_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "input_id" TEXT NOT NULL,
  "url_id" TEXT,
  "hidden" INTEGER,
  "last_visit_raw" TEXT,
  "source_dataset_id" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_file" TEXT,
  PRIMARY KEY(summary_id),
  FOREIGN KEY(summary_id) REFERENCES "BrowserActivity"("record_id") ON DELETE CASCADE,
  FOREIGN KEY(input_id) REFERENCES "BrowserInputs"("input_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BrowserUrlSummaries_input" ON "BrowserUrlSummaries"(input_id, url_id);
CREATE TABLE "BrowserActivity" (
  "record_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "timestamp" TEXT,
  "overview_name" TEXT NOT NULL,
  "account" TEXT,
  "account_sid" TEXT,
  "timestamp_kind" TEXT,
  "event_type" TEXT,
  "description" TEXT,
  "input_id" TEXT NOT NULL,
  "browser" TEXT,
  "profile" TEXT,
  "account_label" TEXT,
  "input_kind" TEXT,
  "title" TEXT,
  "url" TEXT,
  "url_raw" TEXT,
  "detail" TEXT,
  "source_url" TEXT,
  "url_summary_id" TEXT,
  "visit_id" TEXT,
  "visit_source" TEXT,
  "from_visit_id" TEXT,
  "from_record_id" TEXT,
  "opener_visit_id" TEXT,
  "opener_record_id" TEXT,
  "transition_raw" TEXT,
  "transition_core" TEXT,
  "transition_qualifiers" TEXT,
  "visit_duration_us" INTEGER,
  "external_referrer_url" TEXT,
  "visit_count" INTEGER,
  "typed_count" INTEGER,
  "download_id" TEXT,
  "download_guid" TEXT,
  "download_state" INTEGER,
  "download_interrupt_reason" INTEGER,
  "danger" TEXT,
  "download_start_time" TEXT,
  "download_end_time" TEXT,
  "download_last_access_time" TEXT,
  "received_bytes" INTEGER,
  "total_bytes" INTEGER,
  "size" TEXT,
  "size_bytes" INTEGER,
  "mime" TEXT,
  "original_mime" TEXT,
  "download_opened" INTEGER CHECK ("download_opened" IN (0,1)),
  "download_path" TEXT,
  "download_path_resolved" TEXT,
  "download_current_path" TEXT,
  "download_current_path_resolved" TEXT,
  "download_referrer" TEXT,
  "download_tab_url" TEXT,
  "download_tab_referrer_url" TEXT,
  "download_site_url" TEXT,
  "download_url_first" TEXT,
  "download_url_final" TEXT,
  "download_chain_count" INTEGER,
  "download_http_method" TEXT,
  "cache_key" TEXT,
  "request_url" TEXT,
  "status" TEXT,
  "http_status" INTEGER,
  "http_reason" TEXT,
  "content_encoding" TEXT,
  "cache_body_recovered" INTEGER CHECK ("cache_body_recovered" IN (0,1)),
  "body_bytes" INTEGER,
  "cache_request_time" TEXT,
  "cache_response_time" TEXT,
  "cache_creation_time" TEXT,
  "ai_referral_provider" TEXT,
  "ai_referral_param" TEXT,
  "ai_service_provider" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'BrowserActivity'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  FOREIGN KEY(input_id) REFERENCES "BrowserInputs"("input_id") ON DELETE CASCADE,
  FOREIGN KEY(url_summary_id) REFERENCES "BrowserUrlSummaries"("summary_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BrowserActivity_time" ON "BrowserActivity"(timestamp, record_id);
CREATE INDEX "idx_BrowserActivity_account" ON "BrowserActivity"(account_sid, timestamp);
CREATE INDEX "idx_BrowserActivity_input" ON "BrowserActivity"(input_id, event_type, timestamp);
CREATE INDEX "idx_BrowserActivity_visit" ON "BrowserActivity"(input_id, visit_id);
CREATE INDEX "idx_BrowserActivity_cache_key" ON "BrowserActivity"(cache_key);
CREATE INDEX "idx_BrowserActivity_url" ON "BrowserActivity"(url);
CREATE TABLE "BrowserSearchTerms" (
  "search_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "input_id" TEXT NOT NULL,
  "summary_id" TEXT,
  "keyword_id" TEXT,
  "url_id" TEXT,
  "term" TEXT,
  "normalized_term" TEXT,
  "url" TEXT,
  "source_dataset_id" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  PRIMARY KEY(search_id),
  FOREIGN KEY(input_id) REFERENCES "BrowserInputs"("input_id") ON DELETE CASCADE,
  FOREIGN KEY(summary_id) REFERENCES "BrowserUrlSummaries"("summary_id") ON DELETE CASCADE
);
CREATE INDEX "idx_BrowserSearchTerms_term" ON "BrowserSearchTerms"(term);
CREATE TABLE "BrowserDownloadChain" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "chain_index" INTEGER,
  "url" TEXT,
  "url_decoded" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "BrowserActivity"("record_id") ON DELETE CASCADE
);
CREATE TABLE "BrowserCacheDetails" (
  "record_id" TEXT NOT NULL,
  "cache_key" TEXT,
  "request_url" TEXT,
  "status_line" TEXT,
  "http_status" INTEGER,
  "http_reason" TEXT,
  "content_type" TEXT,
  "content_encoding" TEXT,
  "content_length" INTEGER,
  "body_size" INTEGER,
  "body_file" TEXT,
  "body_recovered" INTEGER CHECK ("body_recovered" IN (0,1)),
  "body_bytes" INTEGER,
  "body" BLOB,
  "all_headers" TEXT,
  "server" TEXT,
  "date" TEXT,
  "last_modified" TEXT,
  "etag" TEXT,
  "cache_control" TEXT,
  "location" TEXT,
  PRIMARY KEY(record_id),
  FOREIGN KEY(record_id) REFERENCES "BrowserActivity"("record_id") ON DELETE CASCADE
);
CREATE TABLE "source_records" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_dataset_id" TEXT NOT NULL,
  "source_artifact" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_field" TEXT,
  "source_record_key" TEXT,
  "source_file" TEXT,
  "source_label" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "BrowserActivity"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);

CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
"#;

const COLUMNS: &[&str] = &[
    "record_id",
    "host_id",
    "dataset_id",
    "timestamp",
    "overview_name",
    "account",
    "account_sid",
    "timestamp_kind",
    "event_type",
    "description",
    "input_id",
    "browser",
    "profile",
    "account_label",
    "input_kind",
    "title",
    "url",
    "url_raw",
    "detail",
    "source_url",
    "url_summary_id",
    "visit_id",
    "visit_source",
    "from_visit_id",
    "from_record_id",
    "opener_visit_id",
    "opener_record_id",
    "transition_raw",
    "transition_core",
    "transition_qualifiers",
    "visit_duration_us",
    "external_referrer_url",
    "visit_count",
    "typed_count",
    "download_id",
    "download_guid",
    "download_state",
    "download_interrupt_reason",
    "danger",
    "download_start_time",
    "download_end_time",
    "download_last_access_time",
    "received_bytes",
    "total_bytes",
    "size",
    "size_bytes",
    "mime",
    "original_mime",
    "download_opened",
    "download_path",
    "download_path_resolved",
    "download_current_path",
    "download_current_path_resolved",
    "download_referrer",
    "download_tab_url",
    "download_tab_referrer_url",
    "download_site_url",
    "download_url_first",
    "download_url_final",
    "download_chain_count",
    "download_http_method",
    "cache_key",
    "request_url",
    "status",
    "http_status",
    "http_reason",
    "content_encoding",
    "cache_body_recovered",
    "body_bytes",
    "cache_request_time",
    "cache_response_time",
    "cache_creation_time",
    "ai_referral_provider",
    "ai_referral_param",
    "ai_service_provider",
];

const SOURCE_RECORDS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "source_dataset_id",
    "source_artifact",
    "source_db",
    "source_table",
    "source_rowid",
    "source_field",
    "source_record_key",
    "source_file",
    "source_label",
];

const INPUTS_COLUMNS: &[&str] = &[
    "input_id",
    "host_id",
    "dataset_id",
    "ordinal",
    "input_kind",
    "browser",
    "profile",
    "account_label",
    "account",
    "account_sid",
    "source_file",
    "facts_db",
    "facts_dataset_id",
];

const SUMMARIES_COLUMNS: &[&str] = &[
    "summary_id",
    "host_id",
    "dataset_id",
    "input_id",
    "url_id",
    "hidden",
    "last_visit_raw",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const SEARCH_TERMS_COLUMNS: &[&str] = &[
    "search_id",
    "host_id",
    "dataset_id",
    "input_id",
    "summary_id",
    "keyword_id",
    "url_id",
    "term",
    "normalized_term",
    "url",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

const DOWNLOAD_CHAIN_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "chain_index",
    "url",
    "url_decoded",
    "source_rowid",
];

const CACHE_DETAILS_COLUMNS: &[&str] = &[
    "record_id",
    "cache_key",
    "request_url",
    "status_line",
    "http_status",
    "http_reason",
    "content_type",
    "content_encoding",
    "content_length",
    "body_size",
    "body_file",
    "body_recovered",
    "body_bytes",
    "body",
    "all_headers",
    "server",
    "date",
    "last_modified",
    "etag",
    "cache_control",
    "location",
];

const CHILDREN: &[ChildSpec] = &[
    ChildSpec {
        table: "source_records",
        columns: SOURCE_RECORDS_COLUMNS,
    },
    ChildSpec {
        table: INPUTS_TABLE,
        columns: INPUTS_COLUMNS,
    },
    ChildSpec {
        table: SUMMARIES_TABLE,
        columns: SUMMARIES_COLUMNS,
    },
    ChildSpec {
        table: SEARCH_TERMS_TABLE,
        columns: SEARCH_TERMS_COLUMNS,
    },
    ChildSpec {
        table: DOWNLOAD_CHAIN_TABLE,
        columns: DOWNLOAD_CHAIN_COLUMNS,
    },
    ChildSpec {
        table: CACHE_DETAILS_TABLE,
        columns: CACHE_DETAILS_COLUMNS,
    },
];

pub(super) const SPEC: DbSpec = DbSpec {
    name: DB_NAME,
    table: "BrowserActivity",
    columns: COLUMNS,
    children: CHILDREN,
    ddl: DDL,
};

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

fn open_ro(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("브라우저 facts 열기: {}", path.display()))
}

fn table_names(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<HashSet<String>>>()?)
}

fn column_index(statement: &rusqlite::Statement<'_>) -> HashMap<String, usize> {
    statement
        .column_names()
        .iter()
        .enumerate()
        .map(|(index, name)| ((*name).to_string(), index))
        .collect()
}

fn value_string(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ValueRef::Integer(v) => v.to_string(),
        ValueRef::Real(v) => v.to_string(),
        _ => String::new(),
    }
}

/// Read a facts column by name; absent columns read as empty, never as a guess.
fn col(row: &rusqlite::Row<'_>, index: &HashMap<String, usize>, name: &str) -> String {
    match index.get(name) {
        Some(position) => row.get_ref(*position).map(value_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// Chrome/WebKit time = microseconds since 1601-01-01 UTC.
fn chrome_time(value: &str) -> String {
    let microseconds: i64 = match value.trim().parse() {
        Ok(value) => value,
        Err(_) => return String::new(),
    };
    if microseconds <= 0 {
        return String::new();
    }
    match microseconds.checked_mul(10) {
        Some(ticks) => crate::time::fmt_filetime(ticks),
        None => String::new(),
    }
}

/// Percent-decode %XX as UTF-8; '+' stays literal. Used for URLs only —
/// local paths keep their literal '%' (an actual directory can contain one).
fn url_decode(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let bytes = url.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let hex = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(high << 4 | low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn human_bytes(value: &str) -> String {
    let n: i64 = match value.trim().parse() {
        Ok(value) => value,
        Err(_) => return String::new(),
    };
    if n < 0 {
        return String::new();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = n as f64;
    for (index, unit) in units.iter().enumerate() {
        if size < 1024.0 || index == units.len() - 1 {
            return if *unit == "B" {
                format!("{} {}", size as i64, unit)
            } else {
                format!("{size:.1} {unit}")
            };
        }
        size /= 1024.0;
    }
    format!("{n} B")
}

/// Last path segment of a local Windows/POSIX path, without decoding.
fn path_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// Last URL path segment, ignoring query and fragment. A host-only URL has no
/// file name and returns empty.
fn url_basename(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let after_scheme = match path.split_once("://") {
        Some((_, rest)) => rest,
        None => path,
    };
    let Some((_, path)) = after_scheme.split_once('/') else {
        return String::new();
    };
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// "200 OK" -> (200, "OK"). A reason-only or empty status keeps its原文 in
/// `status` and leaves the numeric code NULL.
fn split_status(status: &str) -> (Cell, Cell) {
    let trimmed = status.trim();
    if trimmed.is_empty() {
        return (Cell::Null, Cell::Null);
    }
    let (head, rest) = match trimmed.split_once(' ') {
        Some((head, rest)) => (head, rest.trim()),
        None => (trimmed, ""),
    };
    // "HTTP/1.1 200 OK" keeps the protocol token in the raw status column.
    let (head, rest) = if head.starts_with("HTTP/") {
        match rest.split_once(' ') {
            Some((code, reason)) => (code, reason.trim()),
            None => (rest, ""),
        }
    } else {
        (head, rest)
    };
    match head.parse::<i64>() {
        Ok(code) => (Cell::Int(code), text(rest)),
        Err(_) => (Cell::Null, Cell::Null),
    }
}

const TRANSITION_CORE: &[&str] = &[
    "LINK",
    "TYPED",
    "AUTO_BOOKMARK",
    "AUTO_SUBFRAME",
    "MANUAL_SUBFRAME",
    "GENERATED",
    "START_PAGE",
    "FORM_SUBMIT",
    "RELOAD",
    "KEYWORD",
    "KEYWORD_GENERATED",
];

const TRANSITION_QUALIFIERS: &[(u32, &str)] = &[
    (0x0080_0000, "BLOCKED"),
    (0x0100_0000, "FORWARD_BACK"),
    (0x0200_0000, "FROM_ADDRESS_BAR"),
    (0x0400_0000, "HOME_PAGE"),
    (0x0800_0000, "FROM_API"),
    (0x1000_0000, "CHAIN_START"),
    (0x2000_0000, "CHAIN_END"),
    (0x4000_0000, "CLIENT_REDIRECT"),
    (0x8000_0000, "SERVER_REDIRECT"),
];

/// Chromium page transition: documented core type plus qualifier bits. Unknown
/// values stay NULL instead of being named.
fn split_transition(raw: &str) -> (Cell, Cell) {
    let Some(value) = nz(raw).and_then(|value| value.parse::<i64>().ok()) else {
        return (Cell::Null, Cell::Null);
    };
    let bits = (value as u64 & 0xFFFF_FFFF) as u32;
    let core = TRANSITION_CORE
        .get((bits & 0xFF) as usize)
        .map(|name| Cell::Text((*name).to_string()))
        .unwrap_or(Cell::Null);
    let qualifiers: Vec<&str> = TRANSITION_QUALIFIERS
        .iter()
        .filter(|(mask, _)| bits & mask != 0)
        .map(|(_, name)| *name)
        .collect();
    let qualifiers = if qualifiers.is_empty() {
        Cell::Null
    } else {
        Cell::Text(qualifiers.join(","))
    };
    (core, qualifiers)
}

/// Canonical `utm_source` values that the AI services actually emit. Only an
/// exact value counts: "notchatgpt" or a URL that merely contains a provider
/// name is not an AI referral.
const AI_REFERRAL_VALUES: &[(&str, &str)] = &[
    ("chatgpt", "ChatGPT"),
    ("chatgpt.com", "ChatGPT"),
    ("openai", "ChatGPT"),
    ("openai.com", "ChatGPT"),
    ("claude", "Claude"),
    ("claude.ai", "Claude"),
    ("gemini", "Gemini"),
    ("gemini.google.com", "Gemini"),
    ("bard", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("notebooklm", "NotebookLM"),
    ("notebooklm.google.com", "NotebookLM"),
];

/// AI referral marker: an exact `utm_source` key in the query component with a
/// canonical provider value, compared exactly. A URL carried *inside* a query
/// value, a fragment or path text is not a marker, and an AI service URL is a
/// different fact (see `ai_service_provider`).
fn ai_referral(url: &str) -> Option<(String, &'static str)> {
    let query = url.split('#').next().unwrap_or(url).split_once('?')?.1;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if !url_decode(key).eq_ignore_ascii_case("utm_source") {
            continue;
        }
        // Exact value: surrounding whitespace is part of the recorded value.
        let decoded = url_decode(value).to_ascii_lowercase();
        let provider = AI_REFERRAL_VALUES
            .iter()
            .find(|(candidate, _)| *candidate == decoded)
            .map(|(_, provider)| *provider)?;
        // Keep the matched parameter exactly as it appeared.
        return Some((format!("{key}={value}"), provider));
    }
    None
}

fn set_ai_marks(record: &mut Record, url: &str) {
    if let Some((param, provider)) = ai_referral(url) {
        record.set("ai_referral_param", text(&param));
        record.set("ai_referral_provider", text(provider));
    }
    // The host only proves that the URL belongs to an AI service. It is not
    // evidence of an answer link, and the referral marker is a separate fact.
    if let Some(provider) = crate::ai_activity::ai_provider(url) {
        record.set("ai_service_provider", text(provider));
    }
}

/// Confirm the Windows account from metadata evidence only: a recorded SID must
/// exist in metadata, and a recorded name must match exactly one metadata
/// account. Unmatched or ambiguous labels, and per-row facts values, stay NULL.
fn confirmed_sid(ctx: &Ctx, label: &str) -> Option<String> {
    let label = nz(label)?;
    if is_sid(label) {
        return ctx
            .meta
            .inner
            .account_entry(label)
            .map(|entry| entry.sid.clone());
    }
    ctx.meta
        .inner
        .sid_for_account_name(label)
        .map(str::to_string)
}

fn confirmed_account(ctx: &Ctx, label: &str) -> (Cell, Cell) {
    match confirmed_sid(ctx, label) {
        Some(sid) => (text_opt(ctx.meta.account_name(&sid).as_deref()), text(&sid)),
        None => (Cell::Null, Cell::Null),
    }
}

/// IE visit URLs are stored as "Visited: <account>@<url>"; keep the original in
/// url_raw and show the actual address.
fn ie_visit_url(raw: &str) -> String {
    let value = raw.trim();
    let value = value
        .strip_prefix("Visited:")
        .map(str::trim)
        .unwrap_or(value);
    match value.split_once('@') {
        Some((head, rest)) if !head.contains('/') && !head.contains(':') => rest.to_string(),
        _ => value.to_string(),
    }
}

/// iedownload metadata (" | " segments) carries the original URL.
fn ie_download_url(metadata: &str, fallback: &str) -> String {
    match metadata.rfind("http") {
        Some(at) => metadata[at..]
            .split(" | ")
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        None => fallback.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

struct Input {
    input_id: String,
    kind: &'static str,
    path: PathBuf,
    relative: String,
    generation: String,
    identity: BrowserInput,
}

impl Input {
    /// The recorded input is the only source of a collected account label.
    /// Per-row facts values (e.g. a cache index's parent folder) are not
    /// evidence of an account and stay in facts.
    fn account_label(&self) -> &str {
        self.identity
            .account_label
            .as_deref()
            .and_then(nz)
            .unwrap_or("")
    }

    fn source_file(&self) -> Option<&str> {
        self.identity.source_file.as_deref().and_then(nz)
    }
}

/// Discover inputs by the facts tables they actually contain. Output file names
/// (including collision numbers like `_2`) never decide identity or kind.
fn discover_inputs(ctx: &Ctx) -> Result<Vec<Input>> {
    let dir = ctx.out_dir.join(BROWSER_DIR);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().map(|ext| ext == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };
    files.sort();

    let mut inputs = Vec::with_capacity(files.len());
    for path in files {
        let conn = open_ro(&path)?;
        let tables = table_names(&conn)?;
        let Some(kind) = input_kind(&tables) else {
            continue;
        };
        let identity = read_identity(&conn, &path)?;
        let facts = ctx
            .facts
            .by_path(&path)
            .ok_or_else(|| anyhow!("브라우저 facts가 색인되지 않았습니다: {}", path.display()))?;
        inputs.push(Input {
            input_id: uuid::Uuid::new_v4().to_string(),
            kind,
            path,
            relative: facts.relative.clone(),
            generation: ctx.facts.generation(facts)?,
            identity,
        });
    }
    Ok(inputs)
}

fn input_kind(tables: &HashSet<String>) -> Option<&'static str> {
    if tables.contains("CacheEntries") {
        Some("cache")
    } else if tables.contains("IEWebCache_History") || tables.contains("IEWebCache_Downloads") {
        Some("ie_webcache")
    } else if tables.contains("IEIndexDat_Records") {
        Some("ie_indexdat")
    } else if tables.contains("urls") || tables.contains("visits") || tables.contains("downloads") {
        Some("history")
    } else {
        None
    }
}

/// Identity comes from the parser's recorded input. Facts without it cannot
/// establish which collected browser profile they came from, so generation
/// fails instead of guessing from output names or leaving the input unnamed.
fn read_identity(conn: &Connection, path: &Path) -> Result<BrowserInput> {
    browser_input::read_input(conn).with_context(|| {
        format!(
            "브라우저 입력 정보(_wina_browser_input)가 없습니다 — 다시 파싱해야 합니다: {}",
            path.display()
        )
    })
}

fn write_input_row(ctx: &Ctx, db: &mut DerivedDb, input: &Input, ordinal: usize) -> Result<()> {
    let label = input.identity.account_label.as_deref().unwrap_or("");
    let (account, sid) = confirmed_account(ctx, label);
    db.insert_child(
        INPUTS_TABLE,
        &[
            Cell::Text(input.input_id.clone()),
            Cell::Text(ctx.host_id.to_string()),
            Cell::Text(ctx.dataset_id.to_string()),
            Cell::Int(ordinal as i64),
            text_opt(nz(&input.identity.input_kind).or(Some(input.kind))),
            text_opt(input.identity.browser.as_deref()),
            text_opt(input.identity.profile.as_deref()),
            text_opt(input.identity.account_label.as_deref()),
            account,
            sid,
            text_opt(input.identity.source_file.as_deref()),
            Cell::Text(input.relative.clone()),
            Cell::Text(input.generation.clone()),
        ],
    )
}

/// Every event row carries its input identity so filters and relation walks
/// stay inside one collected browser profile.
fn new_record(ctx: &Ctx, input: &Input, event_type: &str, account_label: &str) -> Record {
    let mut record = ctx.record(spec());
    record.set("input_id", Cell::Text(input.input_id.clone()));
    record.set("event_type", text(event_type));
    record.set("browser", text_opt(input.identity.browser.as_deref()));
    record.set("profile", text_opt(input.identity.profile.as_deref()));
    record.set("account_label", text(account_label));
    record.set(
        "input_kind",
        text_opt(nz(&input.identity.input_kind).or(Some(input.kind))),
    );
    // Confirmed Windows identity only; the collected label stays separate.
    let (account, sid) = confirmed_account(ctx, account_label);
    record.set("account", account);
    record.set("account_sid", sid);
    record
}

fn spec() -> &'static DbSpec {
    schema::spec(DB_NAME).expect("BrowserActivity 스펙이 등록되지 않았습니다")
}

fn source_ref(
    ctx: &Ctx,
    input: &Input,
    table: &str,
    rowid: i64,
    file: Option<&str>,
    label: &str,
) -> Result<Option<SourceRef>> {
    ctx.facts.source_from_row(
        &input.path,
        table,
        rowid,
        file.and_then(nz).or_else(|| input.source_file()),
        Some(label),
    )
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

pub(super) fn build(ctx: &Ctx) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), DB_NAME)?;
    // Results without this stamp lack individual visits, chains, search terms
    // and per-row cache bodies, so they need a reparse, not a backfill.
    db.conn().execute(
        "INSERT INTO _wina_derived_version(name,version) VALUES ('browser_activity',?1)",
        [CONTRACT_VERSION],
    )?;
    for (ordinal, input) in discover_inputs(ctx)?.into_iter().enumerate() {
        write_input_row(ctx, &mut db, &input, ordinal)?;
        match input.kind {
            "history" => history_input(ctx, &mut db, &input)?,
            "cache" => cache_input(ctx, &mut db, &input)?,
            "ie_webcache" => ie_webcache_input(ctx, &mut db, &input)?,
            "ie_indexdat" => ie_indexdat_input(ctx, &mut db, &input)?,
            _ => {}
        }
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// Chromium history: summaries, individual visits, downloads, search terms
// ---------------------------------------------------------------------------

struct Summary {
    summary_id: String,
    url: String,
    url_raw: String,
    title: String,
    rowid: i64,
}

fn history_input(ctx: &Ctx, db: &mut DerivedDb, input: &Input) -> Result<()> {
    let conn = open_ro(&input.path)?;
    let tables = table_names(&conn)?;
    let summaries = if tables.contains("urls") {
        write_summaries(ctx, db, input, &conn)?
    } else {
        HashMap::new()
    };
    if tables.contains("keyword_search_terms") {
        write_search_terms(ctx, db, input, &conn, &summaries)?;
    }
    // Summaries are aggregates with their own record kind; inputs without
    // visits rows contribute no 'visit' events.
    if tables.contains("visits") {
        write_visits(ctx, db, input, &conn, &summaries)?;
    }
    if tables.contains("downloads") {
        write_downloads(ctx, db, input, &conn, &tables)?;
    }
    Ok(())
}

fn write_summaries(
    ctx: &Ctx,
    db: &mut DerivedDb,
    input: &Input,
    conn: &Connection,
) -> Result<HashMap<String, Summary>> {
    let mut summaries: HashMap<String, Summary> = HashMap::new();
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"urls\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let url_id = col(row, &index, "id");
        let url_raw = col(row, &index, "url");
        let url = url_decode(&url_raw);
        let title = col(row, &index, "title");
        let last_visit_raw = col(row, &index, "last_visit_time");
        let last_visit = chrome_time(&last_visit_raw);
        // The aggregate gets its own analysis record so summary-only evidence
        // is searchable and identifiable; it is never an individual visit.
        let mut record = new_record(ctx, input, "url_summary", input.account_label());
        record.timestamp(&last_visit, "URL 마지막 방문 시각(요약)");
        record.set("url", text(&url));
        record.set("url_raw", text(&url_raw));
        record.set("title", text(&title));
        record.set("visit_count", int(&col(row, &index, "visit_count")));
        record.set("typed_count", int(&col(row, &index, "typed_count")));
        set_ai_marks(&mut record, &url_raw);
        record.source(source_ref(ctx, input, "urls", rowid, None, "url")?);
        let summary_id = record.record_id.clone();
        db.write(record)?;
        db.insert_child(
            SUMMARIES_TABLE,
            &[
                Cell::Text(summary_id.clone()),
                Cell::Text(ctx.host_id.to_string()),
                Cell::Text(ctx.dataset_id.to_string()),
                Cell::Text(input.input_id.clone()),
                text(&url_id),
                int(&col(row, &index, "hidden")),
                text(&last_visit_raw),
                Cell::Text(input.generation.clone()),
                Cell::Text(input.relative.clone()),
                Cell::Text("urls".to_string()),
                Cell::Int(rowid),
                text_opt(input.source_file()),
            ],
        )?;
        if let Some(key) = nz(&url_id) {
            summaries.insert(
                key.to_string(),
                Summary {
                    summary_id,
                    url,
                    url_raw,
                    title,
                    rowid,
                },
            );
        }
    }
    Ok(summaries)
}

fn write_search_terms(
    ctx: &Ctx,
    db: &mut DerivedDb,
    input: &Input,
    conn: &Connection,
    summaries: &HashMap<String, Summary>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"keyword_search_terms\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let url_id = col(row, &index, "url_id");
        // A search term only links to a URL from the same input.
        let summary = summaries.get(url_id.trim());
        db.insert_child(
            SEARCH_TERMS_TABLE,
            &[
                Cell::Text(uuid::Uuid::new_v4().to_string()),
                Cell::Text(ctx.host_id.to_string()),
                Cell::Text(ctx.dataset_id.to_string()),
                Cell::Text(input.input_id.clone()),
                text_opt(summary.map(|summary| summary.summary_id.as_str())),
                text(&col(row, &index, "keyword_id")),
                text(&url_id),
                text(&col(row, &index, "term")),
                text(&col(row, &index, "normalized_term")),
                text_opt(summary.map(|summary| summary.url.as_str())),
                Cell::Text(input.generation.clone()),
                Cell::Text(input.relative.clone()),
                Cell::Text("keyword_search_terms".to_string()),
                Cell::Int(rowid),
            ],
        )?;
    }
    Ok(())
}

/// Individual visits are the browsing timeline. Parent/opener links resolve
/// only against visits of the same input.
fn write_visits(
    ctx: &Ctx,
    db: &mut DerivedDb,
    input: &Input,
    conn: &Connection,
    summaries: &HashMap<String, Summary>,
) -> Result<()> {
    let mut ids: HashMap<String, String> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT id FROM \"visits\"")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id = row.get_ref(0).map(value_string).unwrap_or_default();
            if let Some(id) = nz(&id) {
                ids.insert(id.to_string(), uuid::Uuid::new_v4().to_string());
            }
        }
    }

    let label = input.account_label();
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"visits\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let visit_id = col(row, &index, "id");
        let summary = summaries.get(col(row, &index, "url").trim());
        let mut record = new_record(ctx, input, "visit", &label);
        if let Some(record_id) = nz(&visit_id).and_then(|id| ids.get(id)) {
            record.record_id = record_id.clone();
            record.set_at(0, Cell::Text(record_id.clone()));
        }
        record.timestamp(&chrome_time(&col(row, &index, "visit_time")), "방문 시각");
        record.set("visit_id", text(&visit_id));
        record.set("visit_source", text("visits"));
        if let Some(summary) = summary {
            record.set("url_summary_id", text(&summary.summary_id));
            record.set("url", text(&summary.url));
            record.set("url_raw", text(&summary.url_raw));
            record.set("title", text(&summary.title));
        }
        let from_visit = col(row, &index, "from_visit");
        let opener_visit = col(row, &index, "opener_visit");
        record.set("from_visit_id", visit_link(&from_visit));
        record.set("opener_visit_id", visit_link(&opener_visit));
        record.set("from_record_id", linked_record(&from_visit, &ids));
        record.set("opener_record_id", linked_record(&opener_visit, &ids));
        let transition_raw = col(row, &index, "transition");
        let (core, qualifiers) = split_transition(&transition_raw);
        record.set("transition_raw", text(&transition_raw));
        record.set("transition_core", core);
        record.set("transition_qualifiers", qualifiers);
        record.set(
            "visit_duration_us",
            int(&col(row, &index, "visit_duration")),
        );
        record.set(
            "external_referrer_url",
            text(&col(row, &index, "external_referrer_url")),
        );
        if let Some(summary) = summary {
            set_ai_marks(&mut record, &summary.url_raw);
        }
        record.source(source_ref(ctx, input, "visits", rowid, None, "visit")?);
        if let Some(summary) = summary {
            record.source(source_ref(ctx, input, "urls", summary.rowid, None, "url")?);
        }
        db.write(record)?;
    }
    Ok(())
}

/// Chromium stores "no parent" as 0; keep that distinct from a missing value.
fn visit_link(value: &str) -> Cell {
    match nz(value) {
        Some("0") | None => Cell::Null,
        Some(value) => Cell::Text(value.to_string()),
    }
}

fn linked_record(value: &str, ids: &HashMap<String, String>) -> Cell {
    match nz(value) {
        Some("0") | None => Cell::Null,
        Some(value) => text_opt(ids.get(value).map(String::as_str)),
    }
}

struct ChainLink {
    chain_index: String,
    url: String,
    rowid: i64,
}

fn read_chains(conn: &Connection) -> Result<HashMap<String, Vec<ChainLink>>> {
    let mut chains: HashMap<String, Vec<ChainLink>> = HashMap::new();
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"downloads_url_chains\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let id = col(row, &index, "id");
        chains
            .entry(id.trim().to_string())
            .or_default()
            .push(ChainLink {
                chain_index: col(row, &index, "chain_index"),
                url: col(row, &index, "url"),
                rowid,
            });
    }
    for links in chains.values_mut() {
        links.sort_by_key(|link| link.chain_index.parse::<i64>().unwrap_or(i64::MAX));
    }
    Ok(chains)
}

fn write_downloads(
    ctx: &Ctx,
    db: &mut DerivedDb,
    input: &Input,
    conn: &Connection,
    tables: &HashSet<String>,
) -> Result<()> {
    let chains = if tables.contains("downloads_url_chains") {
        read_chains(conn)?
    } else {
        HashMap::new()
    };
    let label = input.account_label();
    // Only a metadata-confirmed account may expand environment paths.
    let sid = confirmed_sid(ctx, label);
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"downloads\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let download_id = col(row, &index, "id");
        let links = chains.get(download_id.trim());
        let first = links.and_then(|links| links.first());
        let last = links.and_then(|links| links.last());

        // Local paths keep their literal text — '%' is a valid path character.
        let target_path = col(row, &index, "target_path");
        let current_path = col(row, &index, "current_path");
        let stored_path = if target_path.trim().is_empty() {
            current_path.clone()
        } else {
            target_path.clone()
        };
        let tab_url = col(row, &index, "tab_url");
        let tab_referrer = col(row, &index, "tab_referrer_url");
        let referrer = col(row, &index, "referrer");
        let site_url = col(row, &index, "site_url");
        // The page that led to the download, distinct from the file's own URL.
        let origin_page = [&tab_url, &tab_referrer, &referrer, &site_url]
            .into_iter()
            .find(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_default();
        // The actual download address is the end of the redirect chain.
        let download_url = match last {
            Some(link) => link.url.clone(),
            None => origin_page.clone(),
        };
        let total_bytes = col(row, &index, "total_bytes");
        let received_bytes = col(row, &index, "received_bytes");
        let size_raw = if total_bytes.trim().is_empty() {
            received_bytes.clone()
        } else {
            total_bytes.clone()
        };

        let mut record = new_record(ctx, input, "download", &label);
        record.timestamp(
            &chrome_time(&col(row, &index, "start_time")),
            "다운로드 시작 시각",
        );
        record.set("title", text(&path_basename(&stored_path)));
        record.set("url", text(&url_decode(&download_url)));
        record.set("url_raw", text(&download_url));
        record.set("detail", text(&stored_path));
        record.set("source_url", text(&url_decode(&origin_page)));
        record.set("download_id", text(&download_id));
        record.set("download_guid", text(&col(row, &index, "guid")));
        record.set("download_state", int(&col(row, &index, "state")));
        record.set(
            "download_interrupt_reason",
            int(&col(row, &index, "interrupt_reason")),
        );
        record.set("danger", text(&col(row, &index, "danger_type")));
        record.set(
            "download_start_time",
            text(&chrome_time(&col(row, &index, "start_time"))),
        );
        record.set(
            "download_end_time",
            text(&chrome_time(&col(row, &index, "end_time"))),
        );
        record.set(
            "download_last_access_time",
            text(&chrome_time(&col(row, &index, "last_access_time"))),
        );
        record.set("received_bytes", int(&received_bytes));
        record.set("total_bytes", int(&total_bytes));
        record.set("size", text(&human_bytes(&size_raw)));
        record.set("size_bytes", int(&size_raw));
        record.set("mime", text(&col(row, &index, "mime_type")));
        record.set(
            "original_mime",
            text(&col(row, &index, "original_mime_type")),
        );
        record.set("download_opened", super::flag(&col(row, &index, "opened")));
        record.set("download_path", text(&target_path));
        record.set(
            "download_path_resolved",
            ctx.meta.resolve_path(&target_path, sid.as_deref()),
        );
        record.set("download_current_path", text(&current_path));
        record.set(
            "download_current_path_resolved",
            ctx.meta.resolve_path(&current_path, sid.as_deref()),
        );
        record.set("download_referrer", text(&referrer));
        record.set("download_tab_url", text(&tab_url));
        record.set("download_tab_referrer_url", text(&tab_referrer));
        record.set("download_site_url", text(&site_url));
        record.set(
            "download_url_first",
            text_opt(first.map(|link| link.url.as_str())),
        );
        record.set(
            "download_url_final",
            text_opt(last.map(|link| link.url.as_str())),
        );
        record.set(
            "download_chain_count",
            match links {
                Some(links) => Cell::Int(links.len() as i64),
                None => Cell::Null,
            },
        );
        record.set(
            "download_http_method",
            text(&col(row, &index, "http_method")),
        );
        set_ai_marks(&mut record, &download_url);
        for link in links.into_iter().flatten() {
            record.child(
                DOWNLOAD_CHAIN_TABLE,
                vec![
                    int(&link.chain_index),
                    text(&link.url),
                    text(&url_decode(&link.url)),
                    Cell::Int(link.rowid),
                ],
            );
        }
        record.source(source_ref(
            ctx,
            input,
            "downloads",
            rowid,
            None,
            "download",
        )?);
        db.write(record)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cache entries and bodies
// ---------------------------------------------------------------------------

fn cache_input(ctx: &Ctx, db: &mut DerivedDb, input: &Input) -> Result<()> {
    let conn = open_ro(&input.path)?;
    // The recovery flag is part of the cache facts contract.
    let has_recovered_flag = conn
        .prepare("SELECT 1 FROM pragma_table_info('CacheEntries') WHERE name='body_recovered'")?
        .exists([])?;
    if !has_recovered_flag {
        return Err(anyhow!(
            "{}: CacheEntries.body_recovered가 없습니다 — 캐시를 다시 파싱해야 본문 복원 여부를 \
             확정할 수 있습니다",
            input.relative
        ));
    }
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"CacheEntries\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let request_url = col(row, &index, "url");
        let label = input.account_label();
        let response_time = col(row, &index, "response_time");
        let creation_time = col(row, &index, "creation_time");
        let request_time = col(row, &index, "request_time");
        let status_line = col(row, &index, "status");
        let (http_status, http_reason) = split_status(&status_line);
        let content_length = col(row, &index, "content_length");
        let body_size = col(row, &index, "body_size");
        let size_raw = if content_length.trim().is_empty() {
            body_size.clone()
        } else {
            content_length.clone()
        };

        let mut record = new_record(ctx, input, "cache", &label);
        // The observation time keeps the facts column it came from.
        for (value, kind) in [
            (&response_time, "캐시 응답 시각"),
            (&creation_time, "캐시 생성 시각"),
            (&request_time, "캐시 요청 시각"),
        ] {
            if nz(value).is_some() {
                record.timestamp(value, kind);
                break;
            }
        }
        let title = url_basename(&request_url);
        record.set(
            "title",
            if title.is_empty() {
                text(&request_url)
            } else {
                text(&title)
            },
        );
        record.set("url", text(&request_url));
        record.set("request_url", text(&request_url));
        record.set("cache_key", text(&col(row, &index, "cache_key")));
        record.set("status", text(&status_line));
        record.set("http_status", http_status.clone());
        record.set("http_reason", http_reason.clone());
        record.set("mime", text(&col(row, &index, "content_type")));
        record.set(
            "content_encoding",
            text(&col(row, &index, "content_encoding")),
        );
        record.set("size", text(&size_raw));
        record.set("size_bytes", int(&size_raw));
        record.set("cache_request_time", text(&request_time));
        record.set("cache_response_time", text(&response_time));
        record.set("cache_creation_time", text(&creation_time));
        set_ai_marks(&mut record, &request_url);
        record.source(source_ref(
            ctx,
            input,
            "CacheEntries",
            rowid,
            Some(&col(row, &index, "_source_file")),
            "cache",
        )?);

        // Exactly this row's body; nothing is matched by URL or cache key.
        let recovered = super::flag(&col(row, &index, "body_recovered"));
        let encoded = index
            .get("body_b64")
            .map(|position| row.get_ref(*position).map(value_string).unwrap_or_default())
            .unwrap_or_default();
        let (body, body_bytes) =
            decode_body(&recovered, &encoded, &col(row, &index, "content_type")).with_context(
                || {
                    format!(
                        "{} CacheEntries rowid {rowid} (cache_key {}): 저장된 본문을 복원하지 \
                     못했습니다 — 캐시를 다시 파싱해야 합니다",
                        input.relative,
                        col(row, &index, "cache_key")
                    )
                },
            )?;
        record.set("cache_body_recovered", recovered.clone());
        record.set("body_bytes", body_bytes.clone());

        let record_id = record.record_id.clone();
        db.write(record)?;
        db.insert_child(
            CACHE_DETAILS_TABLE,
            &[
                Cell::Text(record_id),
                text(&col(row, &index, "cache_key")),
                text(&request_url),
                text(&status_line),
                http_status,
                http_reason,
                text(&col(row, &index, "content_type")),
                text(&col(row, &index, "content_encoding")),
                int(&content_length),
                int(&body_size),
                text(&col(row, &index, "body_file")),
                recovered,
                body_bytes,
                body,
                super::text_raw(&col(row, &index, "all_headers")),
                text(&col(row, &index, "server")),
                text(&col(row, &index, "date")),
                text(&col(row, &index, "last_modified")),
                text(&col(row, &index, "etag")),
                text(&col(row, &index, "cache_control")),
                text(&col(row, &index, "location")),
            ],
        )?;
    }
    Ok(())
}

/// The facts flag decides whether a body exists; a stored body that does not
/// decode, or bytes kept for a row the parser did not recover, is a facts
/// contradiction and fails generation instead of becoming a guessed state.
fn decode_body(recovered: &Cell, encoded: &str, content_type: &str) -> Result<(Cell, Cell)> {
    let encoded = encoded.trim();
    match recovered {
        Cell::Int(1) => {}
        _ if encoded.is_empty() => return Ok((Cell::Null, Cell::Null)),
        _ => {
            return Err(anyhow!(
                "본문이 저장돼 있는데 body_recovered가 1이 아닙니다"
            ))
        }
    }
    // A recovered body may be genuinely empty; that is evidence, not absence.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| anyhow!("body_b64 base64 복원 실패: {error}"))?;
    let length = bytes.len() as i64;
    if is_text_media(content_type) {
        // One decode, one move: text bodies are searchable without a copy.
        return Ok(match String::from_utf8(bytes) {
            Ok(body) => (Cell::Text(body), Cell::Int(length)),
            Err(error) => (Cell::Blob(error.into_bytes()), Cell::Int(length)),
        });
    }
    Ok((Cell::Blob(bytes), Cell::Int(length)))
}

/// Text bodies are stored as text so full-text search works without a copy.
fn is_text_media(content_type: &str) -> bool {
    let value = content_type.to_ascii_lowercase();
    value.starts_with("text/")
        || value.contains("json")
        || value.contains("xml")
        || value.contains("javascript")
        || value.contains("ecmascript")
        || value.contains("x-www-form-urlencoded")
}

// ---------------------------------------------------------------------------
// Internet Explorer / legacy Edge
// ---------------------------------------------------------------------------

fn ie_webcache_input(ctx: &Ctx, db: &mut DerivedDb, input: &Input) -> Result<()> {
    let conn = open_ro(&input.path)?;
    let tables = table_names(&conn)?;
    if tables.contains("IEWebCache_History") {
        let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"IEWebCache_History\"")?;
        let index = column_index(&stmt);
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(0)?;
            let raw = col(row, &index, "url");
            let url = ie_visit_url(&raw);
            let accessed = col(row, &index, "accessed_time");
            if url.trim().is_empty() {
                continue;
            }
            let label = input.account_label();
            let mut record = new_record(ctx, input, "visit", &label);
            record.timestamp(&accessed, "접근 시각");
            record.set("visit_source", text("ie_webcache"));
            record.set("url", text(&url_decode(&url)));
            record.set("url_raw", text(&raw));
            record.set("visit_count", int(&col(row, &index, "access_count")));
            record.set("detail", text(&col(row, &index, "container")));
            set_ai_marks(&mut record, &url);
            record.source(source_ref(
                ctx,
                input,
                "IEWebCache_History",
                rowid,
                Some(&col(row, &index, "_source_file")),
                "visit",
            )?);
            db.write(record)?;
        }
    }
    if tables.contains("IEWebCache_Downloads") {
        let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"IEWebCache_Downloads\"")?;
        let index = column_index(&stmt);
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rowid: i64 = row.get(0)?;
            let accessed = col(row, &index, "accessed_time");
            let modified = col(row, &index, "modified_time");
            let (stamp, kind) = if nz(&accessed).is_some() {
                (accessed.clone(), "접근 시각")
            } else {
                (modified.clone(), "수정 시각")
            };
            let label = input.account_label();
            let raw = col(row, &index, "url");
            let url = ie_download_url(&col(row, &index, "metadata"), &raw);
            let mut record = new_record(ctx, input, "download", &label);
            record.timestamp(&stamp, kind);
            record.set("title", text(&url_basename(&url_decode(&url))));
            record.set("url", text(&url_decode(&url)));
            record.set("url_raw", text(&raw));
            record.set("source_url", text(&url_decode(&url)));
            record.set("detail", text(&col(row, &index, "metadata")));
            set_ai_marks(&mut record, &url);
            record.source(source_ref(
                ctx,
                input,
                "IEWebCache_Downloads",
                rowid,
                Some(&col(row, &index, "_source_file")),
                "download",
            )?);
            db.write(record)?;
        }
    }
    Ok(())
}

fn ie_indexdat_input(ctx: &Ctx, db: &mut DerivedDb, input: &Input) -> Result<()> {
    let conn = open_ro(&input.path)?;
    let mut stmt = conn.prepare("SELECT rowid AS __rowid, * FROM \"IEIndexDat_Records\"")?;
    let index = column_index(&stmt);
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let container = col(row, &index, "container");
        // Accepted IE scope: history containers only.
        if !container.to_lowercase().contains("hist") {
            continue;
        }
        // Redirect entries are not evidence of an individual visit.
        if !matches!(col(row, &index, "record_type").as_str(), "URL" | "LEAK") {
            continue;
        }
        let raw = col(row, &index, "url");
        let url = ie_visit_url(&raw);
        let accessed = col(row, &index, "accessed_time");
        let modified = col(row, &index, "modified_time");
        let (stamp, kind) = if nz(&accessed).is_some() {
            (accessed.clone(), "접근 시각")
        } else {
            (modified.clone(), "수정 시각")
        };
        if url.trim().is_empty() {
            continue;
        }
        let label = input.account_label();
        let mut record = new_record(ctx, input, "visit", &label);
        record.timestamp(&stamp, kind);
        record.set("visit_source", text("ie_indexdat"));
        record.set("url", text(&url_decode(&url)));
        record.set("url_raw", text(&raw));
        record.set("visit_count", int(&col(row, &index, "hits")));
        record.set("detail", text(&container));
        set_ai_marks(&mut record, &url);
        record.source(source_ref(
            ctx,
            input,
            "IEIndexDat_Records",
            rowid,
            Some(&col(row, &index, "_source_file")),
            "visit",
        )?);
        db.write(record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};

    struct Case {
        root: PathBuf,
        out_dir: PathBuf,
        target: PathBuf,
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn case(label: &str) -> Case {
        let root = std::env::temp_dir().join(format!(
            "wina-browser-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let out_dir = root.join("out");
        let target = root.join("target");
        std::fs::create_dir_all(out_dir.join(BROWSER_DIR)).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        Case {
            root,
            out_dir,
            target,
        }
    }

    const HISTORY_DDL: &str = "CREATE TABLE urls(hidden TEXT,id TEXT,last_visit_time TEXT,\
         title TEXT,typed_count TEXT,url TEXT,visit_count TEXT);\
         CREATE TABLE visits(from_visit TEXT,id TEXT,opener_visit TEXT,transition TEXT,\
         url TEXT,visit_duration TEXT,visit_time TEXT,external_referrer_url TEXT);\
         CREATE TABLE downloads(current_path TEXT,danger_type TEXT,end_time TEXT,guid TEXT,\
         http_method TEXT,id TEXT,interrupt_reason TEXT,last_access_time TEXT,mime_type TEXT,\
         opened TEXT,original_mime_type TEXT,received_bytes TEXT,referrer TEXT,site_url TEXT,\
         start_time TEXT,state TEXT,tab_referrer_url TEXT,tab_url TEXT,target_path TEXT,\
         total_bytes TEXT);\
         CREATE TABLE downloads_url_chains(chain_index TEXT,id TEXT,url TEXT);\
         CREATE TABLE keyword_search_terms(keyword_id TEXT,normalized_term TEXT,term TEXT,url_id TEXT);";

    const CACHE_DDL: &str = "CREATE TABLE CacheEntries(request_time TEXT,response_time TEXT,\
         creation_time TEXT,url TEXT,status TEXT,content_type TEXT,content_length TEXT,\
         content_encoding TEXT,server TEXT,date TEXT,last_modified TEXT,etag TEXT,\
         cache_control TEXT,location TEXT,body_size TEXT,body_file TEXT,cache_key TEXT,\
         all_headers TEXT,body_b64 TEXT,body_recovered TEXT,account TEXT,_source_file TEXT);";

    fn facts(case: &Case, name: &str, ddl: &str) -> PathBuf {
        let path = case.out_dir.join(BROWSER_DIR).join(name);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(ddl).unwrap();
        drop(conn);
        stamp_facts_generation(&path, "facts-gen-1").unwrap();
        path
    }

    fn identify(path: &Path, source: &str, kind: &str, browser: Option<&str>) {
        let input = BrowserInput::from_source(Path::new(source), kind, browser);
        browser_input::write_input(path, &input).unwrap();
    }

    fn exec(path: &Path, sql: &str, params: &[&dyn rusqlite::ToSql]) {
        let conn = Connection::open(path).unwrap();
        conn.execute(sql, params).unwrap();
    }

    fn prepare_metadata(case: &Case) {
        std::fs::create_dir_all(case.out_dir.join("_OVERVIEW")).unwrap();
        crate::metadata::build_metadata(&case.out_dir, &case.target, "host-1", "dataset-1")
            .unwrap();
    }

    /// Store a confirmed Windows account exactly as the metadata builder does.
    fn metadata_account(case: &Case, sid: &str, name: &str) {
        let conn =
            Connection::open(case.out_dir.join("_OVERVIEW").join("Metadata.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO metadata(metadata_id,host_id,dataset_id,kind,scope,key,value,\
             resolution_status,account_name,account_sid) \
             VALUES(?1,'host-1','dataset-1','account','account',?2,?3,'resolved',?3,?4)",
            rusqlite::params![format!("meta-{sid}"), sid.to_lowercase(), name, sid],
        )
        .unwrap();
    }

    fn build_prepared(case: &Case) -> Result<usize> {
        let ctx = Ctx {
            out_dir: &case.out_dir,
            target: &case.target,
            host_id: "host-1",
            dataset_id: "dataset-1",
            facts: FactsIndex::load(&case.out_dir).unwrap(),
            meta: MetaLookup::load(&case.out_dir).unwrap(),
        };
        build(&ctx)
    }

    fn generate(case: &Case) -> Result<usize> {
        prepare_metadata(case);
        build_prepared(case)
    }

    fn run(case: &Case) -> Connection {
        generate(case).unwrap();
        Connection::open_with_flags(
            case.out_dir
                .join("_OVERVIEW")
                .join("BrowserActivity.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
    }

    fn cache_row(
        path: &Path,
        url: &str,
        key: &str,
        status: &str,
        content_type: &str,
        body_b64: &str,
        recovered: &str,
    ) {
        exec(
            path,
            "INSERT INTO CacheEntries(request_time,response_time,creation_time,url,status,\
             content_type,content_length,body_size,cache_key,all_headers,body_b64,body_recovered,\
             account,_source_file) VALUES\
             ('','2026-09-30 01:00:00.000','',?1,?2,?3,'','',?4,'HTTP/1.1 200 OK',?5,?6,'',\
             'collected/Cache_Data/index')",
            rusqlite::params![url, status, content_type, key, body_b64, recovered],
        );
    }

    fn b64(value: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    #[test]
    fn colliding_cache_keys_keep_each_input_body() {
        let case = case("cache-collision");
        for (name, source, body) in [
            (
                "Administrator_Chrome_Cache.sqlite",
                "/evidence/BROWSER/Administrator/CHROME/Default/Cache/Cache_Data/index",
                b"chrome body".as_slice(),
            ),
            (
                "Administrator_Edge_Cache.sqlite",
                "/evidence/BROWSER/Administrator/EDGE/Default/Cache/Cache_Data/index",
                b"edge body".as_slice(),
            ),
        ] {
            let path = facts(&case, name, CACHE_DDL);
            identify(&path, source, "cache", None);
            cache_row(
                &path,
                "https://example.test/shared",
                "1/0/_dk_https://example.test https://example.test https://example.test/shared",
                "200 OK",
                "text/plain",
                &b64(body),
                "1",
            );
        }
        let db = run(&case);
        let bodies: Vec<(String, String, String)> = db
            .prepare(
                "SELECT a.browser, a.cache_key, CAST(d.body AS TEXT)
                 FROM BrowserActivity a JOIN BrowserCacheDetails d USING(record_id)
                 ORDER BY a.browser",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0].0, "Chrome");
        assert_eq!(bodies[0].2, "chrome body");
        assert_eq!(bodies[1].0, "Edge");
        assert_eq!(bodies[1].2, "edge body");
        assert_eq!(bodies[0].1, bodies[1].1, "두 입력의 캐시 키는 같다");
        // Each body belongs to its own input, never to the first URL match.
        let inputs: i64 = db
            .query_row(
                "SELECT count(DISTINCT input_id) FROM BrowserActivity",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inputs, 2);
    }

    #[test]
    fn numbered_output_files_never_become_accounts_or_profiles() {
        let case = case("numbered-input");
        let path = facts(&case, "Administrator_Chrome_Cache_2.sqlite", CACHE_DDL);
        identify(
            &path,
            "/evidence/BROWSER/Administrator/CHROME/Profile 2/Cache/Cache_Data/index",
            "cache",
            None,
        );
        cache_row(
            &path,
            "https://example.test/a",
            "key-a",
            "200 OK",
            "text/plain",
            &b64(b"a"),
            "1",
        );
        let db = run(&case);
        let (label, profile, browser, source_file): (String, String, String, String) = db
            .query_row(
                "SELECT i.account_label,i.profile,i.browser,i.source_file FROM BrowserInputs i",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(label, "Administrator");
        assert_eq!(profile, "Profile 2");
        assert_eq!(browser, "Chrome");
        assert_eq!(
            source_file,
            "/evidence/BROWSER/Administrator/CHROME/Profile 2/Cache/Cache_Data/index"
        );
        let row_label: String = db
            .query_row("SELECT account_label FROM BrowserActivity", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(row_label, "Administrator");
    }

    #[test]
    fn inputs_are_discovered_by_tables_not_by_file_name() {
        let case = case("table-discovery");
        let path = facts(&case, "collected-3.sqlite", HISTORY_DDL);
        identify(
            &path,
            r"C:\Users\Analyst\AppData\Local\Google\Chrome\User Data\Default\History",
            "history",
            Some("Chrome"),
        );
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','1','13380000000000000','Example','0','https://example.test/','3')",
            rusqlite::params![],
        );
        exec(
            &path,
            "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
             VALUES('0','10','0','805306368','1','0','13380000000000000','')",
            rusqlite::params![],
        );
        let db = run(&case);
        let (kind, browser, profile): (String, String, String) = db
            .query_row(
                "SELECT input_kind,browser,profile FROM BrowserInputs",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "history");
        assert_eq!(browser, "Chrome");
        assert_eq!(profile, "Default");
        let events: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity WHERE event_type='visit'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(events, 1);
    }

    #[test]
    fn individual_visits_stay_separate_from_url_summary_records() {
        let case = case("visits-vs-summaries");
        let path = facts(&case, "history.sqlite", HISTORY_DDL);
        identify(
            &path,
            r"C:\Users\Analyst\AppData\Local\Microsoft\Edge\User Data\Default\History",
            "history",
            Some("Edge"),
        );
        for (id, url, visits, typed) in [
            ("1", "https://a.test/", "3", "0"),
            ("2", "https://b.test/", "1", ""),
        ] {
            exec(
                &path,
                "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
                 VALUES('0',?1,'13380000000000000','t',?2,?3,?4)",
                rusqlite::params![id, typed, url, visits],
            );
        }
        for (id, url, time) in [
            ("10", "1", "13380000000000000"),
            ("11", "1", "13380000003600000"),
            ("12", "2", "13380000007200000"),
        ] {
            exec(
                &path,
                "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
                 VALUES('0',?1,'0','0',?2,'0',?3,'')",
                rusqlite::params![id, url, time],
            );
        }
        let db = run(&case);
        let visits: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity WHERE event_type='visit'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let summaries: i64 = db
            .query_row("SELECT count(*) FROM BrowserUrlSummaries", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((visits, summaries), (3, 2));
        // Aggregates are their own record kind and never inflate the timeline.
        let summary_records: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity a
                 JOIN BrowserUrlSummaries s ON s.summary_id=a.record_id
                 WHERE a.event_type='url_summary' AND a.visit_id IS NULL
                   AND a.url_summary_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary_records, 2);
        let summary_visits: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity WHERE visit_source='urls'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary_visits, 0);
        let linked: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity a
                 JOIN BrowserUrlSummaries s ON s.summary_id=a.url_summary_id
                 WHERE s.input_id=a.input_id",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(linked, 3);
    }

    #[test]
    fn summary_only_input_keeps_its_own_record_kind_and_counts() {
        let case = case("zero-vs-null");
        let path = facts(&case, "history.sqlite", HISTORY_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/History",
            "history",
            None,
        );
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','1','13380000000000000','t','0','https://a.test/','0')",
            rusqlite::params![],
        );
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','2','','t','','https://b.test/','')",
            rusqlite::params![],
        );
        let db = run(&case);
        let counts: Vec<(
            String,
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<String>,
        )> = db
            .prepare(
                "SELECT s.url_id,a.visit_count,a.typed_count,a.timestamp,a.timestamp_kind
                 FROM BrowserUrlSummaries s JOIN BrowserActivity a ON a.record_id=s.summary_id
                 WHERE a.event_type='url_summary' ORDER BY s.url_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0].1, Some(0));
        assert_eq!(counts[0].2, Some(0));
        assert_eq!(counts[0].4.as_deref(), Some("URL 마지막 방문 시각(요약)"));
        assert_eq!(counts[1].1, None);
        assert_eq!(counts[1].2, None);
        assert_eq!(counts[1].3, None, "시각 미상은 근거 없이 채우지 않는다");
        assert_eq!(counts[1].4, None);
        // The aggregate is never an individual visit.
        let visits: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserActivity WHERE event_type='visit'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(visits, 0);
        // Summary-only evidence still has an analysis record to search and open.
        let searchable: (String, String, String, i64) = db
            .query_row(
                "SELECT a.record_id,a.url,a.title,
                   (SELECT count(*) FROM source_records s
                    WHERE s.record_id=a.record_id AND s.source_table='urls')
                 FROM BrowserActivity a WHERE a.url LIKE '%b.test%'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(searchable.1, "https://b.test/");
        assert_eq!(searchable.2, "t");
        assert_eq!(searchable.3, 1, "요약도 원본 urls 행을 가리킨다");
        let parented: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserUrlSummaries s
                 WHERE s.summary_id=?1",
                rusqlite::params![searchable.0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(parented, 1);
    }

    #[test]
    fn download_keeps_chain_state_and_literal_path() {
        let case = case("download-detail");
        let path = facts(&case, "history.sqlite", HISTORY_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/History",
            "history",
            None,
        );
        exec(
            &path,
            "INSERT INTO downloads(current_path,danger_type,end_time,guid,http_method,id,
             interrupt_reason,last_access_time,mime_type,opened,original_mime_type,received_bytes,
             referrer,site_url,start_time,state,tab_referrer_url,tab_url,target_path,total_bytes)
             VALUES(?1,'0','13380000003600000','guid-1','GET','7','20','0','application/zip','1',
             'application/octet-stream','512','https://ref.test/page','https://host.test/',
             '13380000000000000','4','','https://page.test/from',?2,'1024')",
            &[
                &r"C:\Users\u\Downloads\100%_real.zip.crdownload",
                &r"C:\Users\u\Downloads\100%_real.zip",
            ],
        );
        for (index, url) in [
            ("0", "https://start.test/file.zip"),
            ("1", "https://cdn.test/redirected.zip"),
        ] {
            exec(
                &path,
                "INSERT INTO downloads_url_chains(chain_index,id,url) VALUES(?1,'7',?2)",
                rusqlite::params![index, url],
            );
        }
        let db = run(&case);
        let row: (
            String,
            String,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            String,
            String,
            String,
        ) = db
            .query_row(
                "SELECT download_path,download_current_path,download_path_resolved,download_state,
                 download_interrupt_reason,received_bytes,total_bytes,download_opened,
                 download_url_first,download_url_final,source_url
                 FROM BrowserActivity WHERE event_type='download'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, r"C:\Users\u\Downloads\100%_real.zip");
        assert_eq!(row.1, r"C:\Users\u\Downloads\100%_real.zip.crdownload");
        assert_eq!(row.3, Some(4));
        assert_eq!(row.4, Some(20));
        assert_eq!(row.5, Some(512));
        assert_eq!(row.6, Some(1024));
        assert_eq!(row.7, Some(1));
        assert_eq!(row.8, "https://start.test/file.zip");
        assert_eq!(row.9, "https://cdn.test/redirected.zip");
        assert_eq!(row.10, "https://page.test/from");
        let (end, title, url): (String, String, String) = db
            .query_row(
                "SELECT download_end_time,title,url FROM BrowserActivity WHERE event_type='download'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(!end.is_empty(), "종료 시각 보존");
        assert_eq!(title, "100%_real.zip");
        assert_eq!(url, "https://cdn.test/redirected.zip");
        let chain: Vec<(i64, String)> = db
            .prepare("SELECT chain_index,url FROM BrowserDownloadChain ORDER BY ordinal")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].0, 0);
        assert_eq!(chain[1].1, "https://cdn.test/redirected.zip");
    }

    #[test]
    fn relations_and_search_terms_stay_inside_one_input() {
        let case = case("input-scope");
        let first = facts(&case, "one.sqlite", HISTORY_DDL);
        identify(
            &first,
            "/evidence/BROWSER/u/CHROME/Default/History",
            "history",
            None,
        );
        let second = facts(&case, "two.sqlite", HISTORY_DDL);
        identify(
            &second,
            "/evidence/BROWSER/u/EDGE/Default/History",
            "history",
            None,
        );
        for path in [&first, &second] {
            exec(
                path,
                "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
                 VALUES('0','1','13380000000000000','t','0','https://a.test/','1')",
                rusqlite::params![],
            );
        }
        // Parent visit 20 exists only in the first input.
        exec(
            &first,
            "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
             VALUES('0','20','0','0','1','0','13380000000000000','')",
            rusqlite::params![],
        );
        exec(
            &first,
            // 0x02000001 = TYPED with the FROM_ADDRESS_BAR qualifier.
            "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
             VALUES('20','21','20','33554433','1','5','13380000003600000','https://out.test/')",
            rusqlite::params![],
        );
        exec(
            &second,
            "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
             VALUES('20','30','0','0','1','0','13380000007200000','')",
            rusqlite::params![],
        );
        exec(
            &first,
            "INSERT INTO keyword_search_terms(keyword_id,normalized_term,term,url_id)
             VALUES('2','sample term','Sample Term','1')",
            rusqlite::params![],
        );
        let db = run(&case);
        let child: (String, Option<String>, Option<String>, String, String) = db
            .query_row(
                "SELECT visit_id,from_record_id,opener_record_id,transition_core,transition_qualifiers
                 FROM BrowserActivity WHERE visit_id='21'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        let parent: String = db
            .query_row(
                "SELECT record_id FROM BrowserActivity WHERE visit_id='20'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(child.1.as_deref(), Some(parent.as_str()));
        assert_eq!(child.2.as_deref(), Some(parent.as_str()));
        assert_eq!(child.3, "TYPED");
        assert_eq!(child.4, "FROM_ADDRESS_BAR");
        // The other input has a visit 20 reference but no such visit of its own.
        let foreign: (String, Option<String>) = db
            .query_row(
                "SELECT from_visit_id,from_record_id FROM BrowserActivity WHERE visit_id='30'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(foreign.0, "20");
        assert_eq!(foreign.1, None);
        let search: (String, String, i64) = db
            .query_row(
                "SELECT t.term,t.url,(SELECT count(*) FROM BrowserUrlSummaries s
                   WHERE s.summary_id=t.summary_id AND s.input_id=t.input_id)
                 FROM BrowserSearchTerms t",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(search.0, "Sample Term");
        assert_eq!(search.1, "https://a.test/");
        assert_eq!(search.2, 1);
    }

    #[test]
    fn http_status_splits_and_recovered_empty_body_is_distinguished() {
        let case = case("cache-status");
        let path = facts(&case, "cache.sqlite", CACHE_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/Cache/Cache_Data/index",
            "cache",
            None,
        );
        cache_row(
            &path,
            "https://example.test/ok",
            "k1",
            "200 OK",
            "text/html",
            &b64(b"<html>hit</html>"),
            "1",
        );
        cache_row(
            &path,
            "https://example.test/empty",
            "k2",
            "204 No Content",
            "text/html",
            "",
            "1",
        );
        cache_row(
            &path,
            "https://example.test/meta",
            "k3",
            "",
            "application/octet-stream",
            "",
            "0",
        );
        let db = run(&case);
        let rows: Vec<(
            String,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<i64>,
        )> = db
            .prepare(
                "SELECT cache_key,http_status,http_reason,cache_body_recovered,body_bytes
                 FROM BrowserActivity ORDER BY cache_key",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows[0],
            ("k1".into(), Some(200), Some("OK".into()), Some(1), Some(16))
        );
        assert_eq!(
            rows[1],
            (
                "k2".into(),
                Some(204),
                Some("No Content".into()),
                Some(1),
                Some(0)
            )
        );
        assert_eq!(rows[2], ("k3".into(), None, None, Some(0), None));
        let details: Vec<(String, Option<i64>, Option<String>, Option<String>)> = db
            .prepare(
                "SELECT d.cache_key,length(d.body),typeof(d.body),CAST(d.body AS TEXT)
                 FROM BrowserCacheDetails d ORDER BY d.cache_key",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(details[0].1, Some(16));
        assert_eq!(details[0].3.as_deref(), Some("<html>hit</html>"));
        // A recovered but genuinely empty body is stored, not treated as absent.
        assert_eq!(details[1].1, Some(0));
        assert_eq!(details[1].2.as_deref(), Some("text"));
        assert_eq!(details[2].1, None);
        assert_eq!(details[2].2.as_deref(), Some("null"));
        let headers: String = db
            .query_row(
                "SELECT all_headers FROM BrowserCacheDetails LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(headers, "HTTP/1.1 200 OK");
        // Full-body search runs on the stored overview, not the facts database.
        let hits: i64 = db
            .query_row(
                "SELECT count(*) FROM BrowserCacheDetails WHERE body LIKE '%hit%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hits, 1);
    }

    #[test]
    fn ai_referral_marker_is_query_exact_and_distinct_from_answer_links() {
        let case = case("ai-referral");
        let path = facts(&case, "cache.sqlite", CACHE_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/Cache/Cache_Data/index",
            "cache",
            None,
        );
        cache_row(
            &path,
            "https://shop.test/item?utm_source=chatgpt.com&id=1",
            "k1",
            "200 OK",
            "text/html",
            "",
            "0",
        );
        cache_row(
            &path,
            "https://redirect.test/go?u=https%3A%2F%2Fshop.test%2Fitem%3Futm_source%3Dchatgpt.com",
            "k2",
            "200 OK",
            "text/html",
            "",
            "0",
        );
        cache_row(
            &path,
            "https://chatgpt.com/share/abc",
            "k3",
            "200 OK",
            "text/html",
            "",
            "0",
        );
        for (key, url) in [
            ("k4", "https://shop.test/item?utm_source=notchatgpt"),
            (
                "k5",
                "https://shop.test/item?utm_source=https%3A%2F%2Fevil.test%2F%3Fchatgpt",
            ),
            ("k6", "https://shop.test/item?utm_source=notebook-case"),
            ("k7", "https://shop.test/item#utm_source=chatgpt.com"),
            ("k8", "https://shop.test/chatgpt.com/page"),
        ] {
            cache_row(&path, url, key, "200 OK", "text/html", "", "0");
        }
        // Canonical value that arrived percent-encoded.
        cache_row(
            &path,
            "https://shop.test/item?id=2&utm_source=chatgpt%2Ecom",
            "k9",
            "200 OK",
            "text/html",
            "",
            "0",
        );
        // A padded value is not the canonical value.
        cache_row(
            &path,
            "https://shop.test/item?utm_source=%20chatgpt.com",
            "kb",
            "200 OK",
            "text/html",
            "",
            "0",
        );
        let db = run(&case);
        let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = db
            .prepare(
                "SELECT cache_key,ai_referral_provider,ai_referral_param,ai_service_provider
                 FROM BrowserActivity ORDER BY cache_key",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows[0],
            (
                "k1".into(),
                Some("ChatGPT".into()),
                Some("utm_source=chatgpt.com".into()),
                None
            )
        );
        // A URL inside a query value is not a referral marker.
        assert_eq!(rows[1], ("k2".into(), None, None, None));
        // An AI service URL is a separate fact from an inflow marker; the host
        // alone does not establish that the page is an answer link.
        assert_eq!(rows[2], ("k3".into(), None, None, Some("ChatGPT".into())));
        // Near-miss values, fragments and path text never mark a referral.
        for index in 3..8 {
            assert_eq!(
                rows[index],
                (format!("k{}", index + 1), None, None, None),
                "k{} 는 유입 표식이 아니다",
                index + 1
            );
        }
        assert_eq!(
            rows[8],
            (
                "k9".into(),
                Some("ChatGPT".into()),
                Some("utm_source=chatgpt%2Ecom".into()),
                None
            )
        );
        assert_eq!(
            rows[9],
            ("kb".into(), None, None, None),
            "공백이 붙은 값은 정규 값이 아니다"
        );
    }

    #[test]
    fn untimed_ie_records_remain_queryable_without_inventing_redirect_visits() {
        let case = case("ie-untimed");
        let web = facts(
            &case,
            "web.sqlite",
            "CREATE TABLE IEWebCache_History(accessed_time TEXT,url TEXT,access_count TEXT);\
             CREATE TABLE IEWebCache_Downloads(accessed_time TEXT,modified_time TEXT,url TEXT,metadata TEXT);",
        );
        identify(
            &web,
            "/BROWSER/analyst/IE/WebCacheV01.dat",
            "ie_webcache",
            Some("IE"),
        );
        exec(&web, "INSERT INTO IEWebCache_History VALUES(NULL,'Visited: analyst@https://ie.test/visit','0')", &[]);
        exec(&web, "INSERT INTO IEWebCache_Downloads VALUES(NULL,NULL,'iedownload:{id}','a | https://ie.test/download | b')", &[]);
        let index = facts(
            &case,
            "index.sqlite",
            "CREATE TABLE IEIndexDat_Records(record_type TEXT,accessed_time TEXT,modified_time TEXT,hits TEXT,url TEXT,container TEXT);",
        );
        identify(
            &index,
            "/BROWSER/analyst/IE/History.IE5/index.dat",
            "ie_indexdat",
            Some("IE"),
        );
        exec(&index, "INSERT INTO IEIndexDat_Records VALUES('URL',NULL,NULL,'0','https://ie.test/index','History.IE5')", &[]);
        exec(&index, "INSERT INTO IEIndexDat_Records VALUES('REDR',NULL,NULL,NULL,'https://ie.test/redirect','History.IE5')", &[]);
        let db = run(&case);
        let rows: Vec<(String, String, Option<String>, Option<String>, Option<i64>)> = db
            .prepare("SELECT event_type,url,timestamp,timestamp_kind,visit_count FROM BrowserActivity ORDER BY url")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "download".into(),
                    "https://ie.test/download".into(),
                    None,
                    None,
                    None
                ),
                (
                    "visit".into(),
                    "https://ie.test/index".into(),
                    None,
                    None,
                    Some(0)
                ),
                (
                    "visit".into(),
                    "https://ie.test/visit".into(),
                    None,
                    None,
                    Some(0)
                ),
            ]
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM source_records", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn ie_webcache_preserves_zero_counts_and_source_coordinates() {
        let case = case("ie-scope");
        let webcache = facts(
            &case,
            "ie.sqlite",
            "CREATE TABLE IEWebCache_History(accessed_time TEXT,modified_time TEXT,\
             expiry_time TEXT,access_count TEXT,url TEXT,container TEXT,account TEXT,\
             _source_file TEXT);\
             CREATE TABLE IEWebCache_Downloads(accessed_time TEXT,modified_time TEXT,url TEXT,\
             metadata TEXT,container TEXT,account TEXT,_source_file TEXT);",
        );
        identify(
            &webcache,
            r"C:\Users\Analyst\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat",
            "ie_webcache",
            None,
        );
        exec(
            &webcache,
            "INSERT INTO IEWebCache_History VALUES('2026-09-30 01:00:00.000','','','0',
             'Visited: Analyst@https://ie.test/page','History','Analyst','C:\\WebCacheV01.dat')",
            rusqlite::params![],
        );
        exec(
            &webcache,
            "INSERT INTO IEWebCache_Downloads VALUES('2026-09-30 02:00:00.000','',
             'iedownload:{GUID}','a | https://files.test/setup.exe | b','iedownload','Analyst',
             'C:\\WebCacheV01.dat')",
            rusqlite::params![],
        );
        let db = run(&case);
        let rows: Vec<(String, String, Option<i64>, String)> = db
            .prepare("SELECT event_type,url,visit_count,account_label FROM BrowserActivity ORDER BY timestamp")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "visit");
        assert_eq!(rows[0].1, "https://ie.test/page");
        // A real zero count is stored as 0, not dropped to NULL.
        assert_eq!(rows[0].2, Some(0));
        assert_eq!(rows[0].3, "Analyst");
        assert_eq!(rows[1].0, "download");
        assert_eq!(rows[1].1, "https://files.test/setup.exe");
        let browser: String = db
            .query_row("SELECT browser FROM BrowserInputs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(browser, "IE");
        // Evidence coordinates stay on the exact facts row and collected file.
        let evidence: Vec<(String, String, i64, String, String)> = db
            .prepare(
                "SELECT a.event_type,s.source_table,s.source_rowid,s.source_db,s.source_file
                 FROM BrowserActivity a JOIN source_records s USING(record_id)
                 ORDER BY a.timestamp",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            evidence,
            vec![
                (
                    "visit".into(),
                    "IEWebCache_History".into(),
                    1,
                    "BROWSER/ie.sqlite".into(),
                    r"C:\WebCacheV01.dat".into()
                ),
                (
                    "download".into(),
                    "IEWebCache_Downloads".into(),
                    1,
                    "BROWSER/ie.sqlite".into(),
                    r"C:\WebCacheV01.dat".into()
                ),
            ]
        );
    }

    #[test]
    fn index_dat_visits_keep_history_containers_and_time_evidence() {
        let case = case("ie-indexdat");
        let path = facts(
            &case,
            "indexdat.sqlite",
            "CREATE TABLE IEIndexDat_Records(record_type TEXT,accessed_time TEXT,\
             modified_time TEXT,hits TEXT,url TEXT,filename TEXT,container TEXT,account TEXT,\
             _source_file TEXT);",
        );
        identify(
            &path,
            r"C:\Users\Analyst\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat",
            "ie_indexdat",
            None,
        );
        exec(
            &path,
            "INSERT INTO IEIndexDat_Records VALUES('URL','2026-09-30 03:00:00.000','','7',
             'Visited: Analyst@https://ie.test/history','f','MSHist012026093020261001','Analyst',
             'C:\\index.dat')",
            rusqlite::params![],
        );
        // No access time: the modified time is the only evidenced time.
        exec(
            &path,
            "INSERT INTO IEIndexDat_Records VALUES('URL','','2026-09-30 04:00:00.000','0',
             'https://ie.test/modified','f','History','Analyst','C:\\index.dat')",
            rusqlite::params![],
        );
        // Content container rows stay outside the accepted IE visit scope.
        exec(
            &path,
            "INSERT INTO IEIndexDat_Records VALUES('URL','2026-09-30 05:00:00.000','','1',
             'https://ie.test/cached.png','f','Content','Analyst','C:\\index.dat')",
            rusqlite::params![],
        );
        let db = run(&case);
        let rows: Vec<(String, String, String, String, Option<i64>, String)> = db
            .prepare(
                "SELECT url,url_raw,timestamp,timestamp_kind,visit_count,visit_source
                 FROM BrowserActivity ORDER BY timestamp",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "https://ie.test/history");
        assert_eq!(rows[0].1, "Visited: Analyst@https://ie.test/history");
        assert_eq!(rows[0].3, "접근 시각");
        assert_eq!(rows[0].4, Some(7));
        assert_eq!(rows[0].5, "ie_indexdat");
        assert_eq!(rows[1].0, "https://ie.test/modified");
        assert_eq!(rows[1].2, "2026-09-30 04:00:00.000");
        assert_eq!(rows[1].3, "수정 시각");
        assert_eq!(rows[1].4, Some(0));
        let source: (String, i64, String) = db
            .query_row(
                "SELECT s.source_table,s.source_rowid,s.source_file
                 FROM BrowserActivity a JOIN source_records s USING(record_id)
                 WHERE a.url='https://ie.test/history'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            source,
            ("IEIndexDat_Records".into(), 1, r"C:\index.dat".into())
        );
    }

    #[test]
    fn facts_without_recorded_input_identity_fail_generation() {
        let case = case("missing-identity");
        let path = facts(&case, "analyst_Chrome.sqlite", HISTORY_DDL);
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','1','13380000000000000','t','0','https://a.test/','1')",
            rusqlite::params![],
        );
        let error = format!("{:#}", generate(&case).unwrap_err());
        assert!(
            error.contains("_wina_browser_input"),
            "입력 정보 부재를 알려야 한다: {error}"
        );
        assert!(
            error.contains("analyst_Chrome.sqlite"),
            "출처를 알려야 한다: {error}"
        );
    }

    #[test]
    fn recorded_but_unknown_identity_stays_null_without_guessing() {
        let case = case("unknown-identity");
        let path = facts(&case, "collected.sqlite", HISTORY_DDL);
        // A collected path outside a known browser/profile layout proves nothing.
        identify(&path, "/evidence/exported/history-copy", "history", None);
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','1','13380000000000000','t','0','https://a.test/','1')",
            rusqlite::params![],
        );
        let db = run(&case);
        let (label, browser, profile, source_file, kind): (
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
        ) = db
            .query_row(
                "SELECT account_label,browser,profile,source_file,input_kind FROM BrowserInputs",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(label, None);
        assert_eq!(browser, None);
        assert_eq!(profile, None);
        assert_eq!(source_file, "/evidence/exported/history-copy");
        assert_eq!(kind, "history");
    }

    #[test]
    fn stored_body_without_the_recovered_flag_fails_generation() {
        let case = case("cache-contradiction");
        let path = facts(&case, "cache.sqlite", CACHE_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/Cache/Cache_Data/index",
            "cache",
            None,
        );
        cache_row(
            &path,
            "https://example.test/a",
            "k1",
            "200 OK",
            "text/plain",
            &b64(b"body"),
            "0",
        );
        let error = format!("{:#}", generate(&case).unwrap_err());
        assert!(
            error.contains("body_recovered"),
            "모순을 알려야 한다: {error}"
        );
        assert!(error.contains("k1"), "원본 좌표를 알려야 한다: {error}");
    }

    #[test]
    fn undecodable_stored_body_fails_generation() {
        let case = case("cache-invalid-base64");
        let path = facts(&case, "cache.sqlite", CACHE_DDL);
        identify(
            &path,
            "/evidence/BROWSER/u/CHROME/Default/Cache/Cache_Data/index",
            "cache",
            None,
        );
        cache_row(
            &path,
            "https://example.test/a",
            "k9",
            "200 OK",
            "text/plain",
            "not*base64!",
            "1",
        );
        let error = format!("{:#}", generate(&case).unwrap_err());
        assert!(error.contains("k9"), "원본 좌표를 알려야 한다: {error}");
        assert!(
            error.contains("CacheEntries rowid 1"),
            "행 좌표를 알려야 한다: {error}"
        );
    }

    #[test]
    fn recorded_label_is_confirmed_only_through_metadata_accounts() {
        let case = case("confirmed-account");
        let path = facts(&case, "history.sqlite", HISTORY_DDL);
        identify(
            &path,
            r"C:\Users\Analyst\AppData\Local\Google\Chrome\User Data\Default\History",
            "history",
            Some("Chrome"),
        );
        exec(
            &path,
            "INSERT INTO urls(hidden,id,last_visit_time,title,typed_count,url,visit_count)
             VALUES('0','1','13380000000000000','t','0','https://a.test/','1')",
            rusqlite::params![],
        );
        exec(
            &path,
            "INSERT INTO visits(from_visit,id,opener_visit,transition,url,visit_duration,visit_time,external_referrer_url)
             VALUES('0','10','0','0','1','0','13380000000000000','')",
            rusqlite::params![],
        );
        prepare_metadata(&case);
        metadata_account(&case, "S-1-5-21-11-22-33-1001", "Analyst");
        build_prepared(&case).unwrap();
        let db = Connection::open_with_flags(
            case.out_dir
                .join("_OVERVIEW")
                .join("BrowserActivity.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (label, account, sid): (String, String, String) = db
            .query_row(
                "SELECT account_label,account,account_sid FROM BrowserActivity
                 WHERE event_type='visit'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(label, "Analyst");
        assert_eq!(account, "Analyst");
        assert_eq!(sid, "S-1-5-21-11-22-33-1001");
        let input: (String, String) = db
            .query_row("SELECT account,account_sid FROM BrowserInputs", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(input, ("Analyst".into(), "S-1-5-21-11-22-33-1001".into()));
    }

    #[test]
    fn misleading_facts_account_never_fills_a_null_input_label() {
        let case = case("misleading-account");
        let path = facts(&case, "cache.sqlite", CACHE_DDL);
        // Valid identity whose collected path proves no account.
        identify(&path, "/evidence/exported/index", "cache", None);
        exec(
            &path,
            "INSERT INTO CacheEntries(request_time,response_time,creation_time,url,status,\
             content_type,content_length,body_size,cache_key,all_headers,body_b64,body_recovered,\
             account,_source_file) VALUES('','2026-09-30 01:00:00.000','',\
             'https://example.test/a','200 OK','text/plain','','0','k1','',''
             ,'0','Cache_Data','/evidence/exported/index')",
            rusqlite::params![],
        );
        let db = run(&case);
        let input_label: Option<String> = db
            .query_row("SELECT account_label FROM BrowserInputs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(input_label, None);
        let (label, account, sid): (Option<String>, Option<String>, Option<String>) = db
            .query_row(
                "SELECT account_label,account,account_sid FROM BrowserActivity",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(label, None, "캐시 행의 account는 수집 계정 근거가 아니다");
        assert_eq!(account, None);
        assert_eq!(sid, None);
    }

    #[test]
    fn storage_records_its_contract_version() {
        let case = case("contract-version");
        let db = run(&case);
        let version: i64 = db
            .query_row(
                "SELECT version FROM _wina_derived_version WHERE name='browser_activity'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CONTRACT_VERSION);
    }
}
