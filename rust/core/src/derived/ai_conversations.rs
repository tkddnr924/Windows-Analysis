//! AI conversation overview from browser cache facts (CacheEntries): recovered
//! conversations with messages/attachments, plus body-less list traces.
//!
//! Invariants: one record per input and facts row (no merge/dedup, A03); the
//! collected response and the re-serialized interpretation stay separate (R18);
//! structural node, extracted message and current-branch counts are distinct and
//! stay NULL when unknown (R13, A01); attachments keep payload metadata only -
//! nothing is downloaded (R14).
use std::collections::HashSet;

use anyhow::{anyhow, Context as _, Result};
use rusqlite::Connection;

use super::schema::{self, ChildSpec, DbSpec};
use super::stream::{fact_files, open_ro};
use super::{int_opt, text, text_opt, text_raw, Cell, Ctx, DerivedDb, SourceRef};
use crate::ai_activity::{
    self, AiAttachment, AiConversation, AiConversationList, AiMessage, AiPayload,
};
use crate::browser_input::{self, BrowserInput};
use crate::sqlite::quote_ident;

pub(super) const DB_NAME: &str = ai_activity::AI_TABLE;

const BROWSER_DIR: &str = "BROWSER";
const CACHE_TABLE: &str = crate::parsers::browser_cache::CACHE_TABLE;

/// Child tables kept from the existing display contract.
pub const AI_MESSAGES_TABLE: &str = "AiMessages";
pub const AI_ATTACHMENTS_TABLE: &str = "AiAttachments";
/// Per-record interpretation/search text stays out of list queries (R17).
pub const AI_TEXTS_TABLE: &str = "AiConversationTexts";

const KIND_CONVERSATION: &str = "conversation";
const KIND_LIST_ENTRY: &str = "list_entry";

const TEXT_INTERPRETATION: &str = "interpretation_json";
const TEXT_SEARCH: &str = "search_text";

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "AiConversations" (
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
  "record_kind" TEXT NOT NULL,
  "provider" TEXT,
  "conversation_id" TEXT,
  "service_account" TEXT,
  "title" TEXT,
  "created_at" TEXT,
  "updated_at" TEXT,
  "url" TEXT,
  "browser" TEXT,
  "profile" TEXT,
  -- Collected labels, not confirmed Windows accounts; confirmed identity goes to
  -- account/account_sid only (R10).
  "input_label" TEXT,
  "facts_account_label" TEXT,
  "input_kind" TEXT,
  "source_file" TEXT,
  "body_recovered" INTEGER NOT NULL,
  "message_count" INTEGER,
  "current_branch_message_count" INTEGER,
  "structural_node_count" INTEGER,
  "attachment_count" INTEGER,
  "current_node" TEXT,
  "list_ordinal" INTEGER,
  "list_item_count" INTEGER,
  "list_declared_total" INTEGER,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'AiConversations'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(record_kind IN ('conversation','list_entry')),
  CHECK(body_recovered IN (0,1)),
  CHECK(record_kind = 'conversation' OR body_recovered = 0),
  CHECK(body_recovered = 1 OR (message_count IS NULL
    AND current_branch_message_count IS NULL
    AND structural_node_count IS NULL
    AND attachment_count IS NULL)),
  CHECK(record_kind = 'list_entry' OR (list_ordinal IS NULL
    AND list_item_count IS NULL
    AND list_declared_total IS NULL))
);
CREATE INDEX "idx_AiConversations_time" ON "AiConversations"(timestamp, record_id);
CREATE INDEX "idx_AiConversations_account" ON "AiConversations"(account_sid, timestamp);
CREATE INDEX "idx_AiConversations_conversation" ON "AiConversations"(provider, conversation_id);
CREATE INDEX "idx_AiConversations_kind" ON "AiConversations"(record_kind, timestamp);
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
  FOREIGN KEY(record_id) REFERENCES "AiConversations"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "AiMessages" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "node_id" TEXT,
  "parent_node_id" TEXT,
  "message_id" TEXT,
  "role" TEXT,
  "author_name" TEXT,
  "recipient" TEXT,
  "content_type" TEXT,
  "content" TEXT,
  "created_at" TEXT,
  "on_current_branch" INTEGER,
  "branch_ordinal" INTEGER,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  CHECK ("on_current_branch" IS NULL OR "on_current_branch" IN (0,1)),
  CHECK ("branch_ordinal" IS NULL OR "branch_ordinal" >= 0),
  FOREIGN KEY ("record_id") REFERENCES "AiConversations"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_AiMessages_branch" ON "AiMessages"(record_id, on_current_branch, branch_ordinal);
CREATE TABLE "AiAttachments" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "message_ordinal" INTEGER,
  "attachment_id" TEXT,
  "url" TEXT,
  "file_name" TEXT,
  "mime" TEXT,
  "size_bytes" INTEGER,
  "extracted_text" TEXT,
  "origin" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "AiConversations"("record_id") ON DELETE CASCADE,
  FOREIGN KEY (record_id, message_ordinal) REFERENCES AiMessages(record_id, ordinal)
);
CREATE INDEX "idx_AiAttachments_message" ON "AiAttachments"(record_id, message_ordinal);
CREATE TABLE "AiConversationTexts" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "text_kind" TEXT NOT NULL,
  "text_value" TEXT,
  "byte_length" INTEGER,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  CHECK ("text_kind" IN ('interpretation_json','search_text')),
  CHECK ("text_kind" <> 'interpretation_json' OR "text_value" IS NULL OR json_valid("text_value")),
  FOREIGN KEY ("record_id") REFERENCES "AiConversations"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_AiConversationTexts_kind" ON "AiConversationTexts"(text_kind, record_id);
CREATE TABLE "AiResponseBodies" (
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_file" TEXT,
  "response_body" TEXT NOT NULL,
  "byte_length" INTEGER NOT NULL,
  PRIMARY KEY (source_db, source_table, source_rowid)
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1);
INSERT INTO _wina_derived_version(name,version) VALUES ('ai_conversations',2);
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
    "record_kind",
    "provider",
    "conversation_id",
    "service_account",
    "title",
    "created_at",
    "updated_at",
    "url",
    "browser",
    "profile",
    "input_label",
    "facts_account_label",
    "input_kind",
    "source_file",
    "body_recovered",
    "message_count",
    "current_branch_message_count",
    "structural_node_count",
    "attachment_count",
    "current_node",
    "list_ordinal",
    "list_item_count",
    "list_declared_total",
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

const MESSAGES_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "node_id",
    "parent_node_id",
    "message_id",
    "role",
    "author_name",
    "recipient",
    "content_type",
    "content",
    "created_at",
    "on_current_branch",
    "branch_ordinal",
];

const ATTACHMENTS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "message_ordinal",
    "attachment_id",
    "url",
    "file_name",
    "mime",
    "size_bytes",
    "extracted_text",
    "origin",
];

const TEXTS_COLUMNS: &[&str] = &[
    "record_id",
    "ordinal",
    "text_kind",
    "text_value",
    "byte_length",
];

const CHILDREN: &[ChildSpec] = &[
    ChildSpec {
        table: "source_records",
        columns: SOURCE_RECORDS_COLUMNS,
    },
    ChildSpec {
        table: AI_MESSAGES_TABLE,
        columns: MESSAGES_COLUMNS,
    },
    ChildSpec {
        table: AI_ATTACHMENTS_TABLE,
        columns: ATTACHMENTS_COLUMNS,
    },
    ChildSpec {
        table: AI_TEXTS_TABLE,
        columns: TEXTS_COLUMNS,
    },
];

pub(super) const SPEC: DbSpec = DbSpec {
    name: "AiConversations",
    table: "AiConversations",
    columns: COLUMNS,
    children: CHILDREN,
    ddl: DDL,
};

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

pub(super) fn build(ctx: &Ctx) -> Result<usize> {
    let spec = schema::spec(DB_NAME)
        .ok_or_else(|| anyhow!("{DB_NAME} 파생 계약이 등록되지 않았습니다"))?;
    let mut db = DerivedDb::create(&ctx.overview_dir(), DB_NAME)?;
    // Exact table discovery: numbered inputs (_2) are found by having CacheEntries.
    for path in fact_files(ctx.out_dir, BROWSER_DIR, CACHE_TABLE)? {
        if crate::pipeline::cancelled() {
            break;
        }
        write_cache_input(ctx, &mut db, spec, &path)?;
    }
    db.finish()
}

/// One cache row as stored, before decoding.
struct CacheRow {
    rowid: i64,
    url: String,
    account: String,
    observed: String,
    observed_kind: &'static str,
    body_b64: String,
    body_recovered: bool,
}

fn write_cache_input(
    ctx: &Ctx,
    db: &mut DerivedDb,
    spec: &'static DbSpec,
    path: &std::path::Path,
) -> Result<()> {
    let conn = open_ro(path)?;
    // Input identity comes from the collected path, never from output file names (R10).
    let input = browser_input::read_input(&conn)
        .with_context(|| format!("브라우저 입력 정보: {}", path.display()))?;
    let columns = table_columns(&conn, CACHE_TABLE)?;
    if !columns.contains("url") || !columns.contains("body_b64") {
        return Ok(());
    }
    // Stream rows: bodies (up to 4MiB) are never all buffered.
    let likes: Vec<String> = ai_activity::AI_HOSTS
        .iter()
        .map(|host| format!("%{host}%"))
        .collect();
    let params: Vec<&dyn rusqlite::ToSql> = likes
        .iter()
        .map(|like| like as &dyn rusqlite::ToSql)
        .collect();
    let mut stmt = conn.prepare(&cache_sql(&columns, likes.len()))?;
    let has_flag = columns.contains("body_recovered");
    let mut cursor = stmt.query(params.as_slice())?;
    while let Some(raw) = cursor.next()? {
        if crate::pipeline::cancelled() {
            break;
        }
        let row = cache_row_of(raw, has_flag)?;
        // Unrecovered bodies never become conversations (R03).
        if !row.body_recovered {
            continue;
        }
        let Some(provider) = ai_activity::ai_provider(&row.url) else {
            continue;
        };
        let Some(body) = ai_activity::decode_cache_body(&row.body_b64) else {
            continue;
        };
        let cleaned = ai_activity::strip_anti_hijack(&body);
        let Ok(value) = serde_json::from_str::<serde_json::Value>(cleaned) else {
            continue;
        };
        let Some(payload) = ai_activity::parse_ai_payload(provider, &row.url, &value) else {
            continue;
        };
        let source = ctx.facts.source_from_row(
            path,
            CACHE_TABLE,
            row.rowid,
            input.source_file.as_deref(),
            Some(match payload {
                AiPayload::Conversation(_) => "AI 대화 캐시 응답",
                AiPayload::List(_) => "AI 대화 목록 캐시 응답",
            }),
        )?;
        // Store the collected response once per facts row; N list entries do not
        // copy it N times (coordinate keyed, not content-hash dedup).
        store_response_body(db, source.as_ref(), &body)?;
        match payload {
            AiPayload::Conversation(conversation) => write_conversation(
                ctx,
                db,
                spec,
                &input,
                &row,
                provider,
                &conversation,
                &value,
                &source,
            )?,
            AiPayload::List(list) => {
                write_list_entries(ctx, db, spec, &input, &row, provider, &list, &source)?
            }
        }
    }
    Ok(())
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1)")?;
    let names = stmt
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<HashSet<String>, _>>()?;
    Ok(names)
}

/// AI-host rows in rowid order; missing optional columns degrade to empty text.
fn cache_sql(columns: &HashSet<String>, hosts: usize) -> String {
    let optional = |name: &str| {
        if columns.contains(name) {
            format!("COALESCE({},'')", quote_ident(name))
        } else {
            "''".to_string()
        }
    };
    let predicate = (1..=hosts)
        .map(|index| format!("url LIKE ?{index}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "SELECT rowid, COALESCE(url,''), {account}, {response}, {request}, {creation}, \
         COALESCE(body_b64,''), {recovered} FROM {table} WHERE ({predicate}) ORDER BY rowid",
        account = optional("account"),
        response = optional("response_time"),
        request = optional("request_time"),
        creation = optional("creation_time"),
        // Facts without the flag fall back to "body present".
        recovered = optional("body_recovered"),
        table = quote_ident(CACHE_TABLE),
    )
}

/// Also records which time basis was used as the observation time (R11).
fn cache_row_of(row: &rusqlite::Row<'_>, has_flag: bool) -> rusqlite::Result<CacheRow> {
    let response: String = row.get(3)?;
    let request: String = row.get(4)?;
    let creation: String = row.get(5)?;
    let body_b64: String = row.get(6)?;
    let flag: String = row.get(7)?;
    let (observed, observed_kind) = if !response.is_empty() {
        (response, "캐시 관찰 시각(응답)")
    } else if !request.is_empty() {
        (request, "캐시 관찰 시각(요청)")
    } else if !creation.is_empty() {
        (creation, "캐시 관찰 시각(생성)")
    } else {
        (String::new(), "캐시 관찰 시각")
    };
    let body_recovered = if has_flag {
        flag.trim() == "1"
    } else {
        !body_b64.is_empty()
    };
    Ok(CacheRow {
        rowid: row.get(0)?,
        url: row.get(1)?,
        account: row.get(2)?,
        observed,
        observed_kind,
        body_b64,
        body_recovered,
    })
}

/// A collected label is not a confirmed account: fill account/account_sid only
/// from an evidenced SID or an unambiguous metadata name match (R10).
fn set_confirmed_account(rec: &mut super::Record, label: Option<&str>, meta: &super::MetaLookup) {
    let Some(label) = label.and_then(super::nz) else {
        return;
    };
    if super::is_sid(label) {
        // Only SIDs present in metadata are confirmed accounts.
        if meta.inner.account_entry(label).is_some() {
            rec.account(label, meta);
        }
        return;
    }
    // A folder name alone confirms nothing; ambiguous matches stay NULL.
    let sid = meta.inner.sid_for_account_name(label).map(str::to_string);
    if let Some(sid) = sid {
        rec.account(&sid, meta);
    }
}

/// Common input/account/time values; service account and Windows account are
/// different columns (R10, R14).
fn base_record(
    ctx: &Ctx,
    spec: &'static DbSpec,
    input: &BrowserInput,
    row: &CacheRow,
    provider: &str,
) -> super::Record {
    let mut rec = ctx.record(spec);
    rec.timestamp(&row.observed, row.observed_kind);
    // Only the input label is an identity candidate: the facts account value may
    // be a path fragment written by the cache parser.
    set_confirmed_account(&mut rec, input.account_label.as_deref(), &ctx.meta);
    rec.set("provider", text(provider));
    rec.set("url", text(&row.url));
    rec.set("browser", text_opt(input.browser.as_deref()));
    rec.set("profile", text_opt(input.profile.as_deref()));
    rec.set("input_label", text_opt(input.account_label.as_deref()));
    rec.set("facts_account_label", text(&row.account));
    rec.set("input_kind", text(&input.input_kind));
    // Collected input path, not facts coordinates (R18).
    rec.set("source_file", text_opt(input.source_file.as_deref()));
    rec
}

/// Write the collected response once per facts coordinate; records find it
/// through their source_records coordinates (R18).
fn store_response_body(db: &DerivedDb, source: Option<&SourceRef>, body: &str) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    db.conn().execute(
        "INSERT OR IGNORE INTO \"AiResponseBodies\"
         (source_db, source_table, source_rowid, source_file, response_body, byte_length)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            source.db,
            source.table,
            source.rowid,
            source.file,
            body,
            body.len() as i64
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_conversation(
    ctx: &Ctx,
    db: &mut DerivedDb,
    spec: &'static DbSpec,
    input: &BrowserInput,
    row: &CacheRow,
    provider: &str,
    conversation: &AiConversation,
    value: &serde_json::Value,
    source: &Option<SourceRef>,
) -> Result<()> {
    let mut rec = base_record(ctx, spec, input, row, provider);
    rec.set("record_kind", text(KIND_CONVERSATION));
    rec.set("event_type", text("AI 대화"));
    rec.set("conversation_id", text(&conversation.conversation_id));
    rec.set("service_account", text(&conversation.service_account));
    rec.set("title", text(&conversation.title));
    rec.set("created_at", text(&conversation.created_at));
    rec.set("updated_at", text(&conversation.updated_at));
    rec.set("body_recovered", Cell::Int(1));
    // Extracted message count, distinct from the structural node count (R13).
    rec.set(
        "message_count",
        Cell::Int(conversation.messages.len() as i64),
    );
    rec.set(
        "current_branch_message_count",
        int_opt(
            conversation
                .current_branch_message_count
                .map(|count| count as i64),
        ),
    );
    rec.set(
        "structural_node_count",
        int_opt(conversation.structural_node_count.map(|count| count as i64)),
    );
    rec.set(
        "attachment_count",
        Cell::Int(conversation.attachments.len() as i64),
    );
    rec.set(
        "current_node",
        text_opt(conversation.current_node.as_deref()),
    );

    for message in &conversation.messages {
        rec.child(AI_MESSAGES_TABLE, message_values(message));
    }
    let messages = conversation.messages.len();
    for attachment in &conversation.attachments {
        rec.child(
            AI_ATTACHMENTS_TABLE,
            attachment_values(attachment, messages),
        );
    }
    // Interpretation and search text live in a child table, out of list queries.
    push_text(
        &mut rec,
        TEXT_INTERPRETATION,
        &ai_activity::interpretation_json(value),
    );
    push_text(
        &mut rec,
        TEXT_SEARCH,
        &conversation_search_text(conversation, row),
    );
    rec.source(source.clone());
    db.write(rec)
}

#[allow(clippy::too_many_arguments)]
fn write_list_entries(
    ctx: &Ctx,
    db: &mut DerivedDb,
    spec: &'static DbSpec,
    input: &BrowserInput,
    row: &CacheRow,
    provider: &str,
    list: &AiConversationList,
    source: &Option<SourceRef>,
) -> Result<()> {
    let item_count = list.entries.len() as i64;
    for entry in &list.entries {
        let mut rec = base_record(ctx, spec, input, row, provider);
        rec.set("record_kind", text(KIND_LIST_ENTRY));
        rec.set("event_type", text("AI 대화 목록 흔적"));
        // A missing body is not zero messages (A01).
        rec.set(
            "description",
            text("대화 목록 응답에서만 확인됨 — 본문 미확보"),
        );
        rec.set("conversation_id", text(&entry.conversation_id));
        rec.set("title", text(&entry.title));
        rec.set("created_at", text(&entry.created_at));
        rec.set("updated_at", text(&entry.updated_at));
        rec.set("body_recovered", Cell::Int(0));
        rec.set("list_ordinal", Cell::Int(entry.ordinal as i64));
        rec.set("list_item_count", Cell::Int(item_count));
        rec.set("list_declared_total", int_opt(list.declared_total));
        // Only the per-item interpretation is stored here; the response body is
        // in AiResponseBodies, once per facts row.
        push_text(&mut rec, TEXT_INTERPRETATION, &entry.item_json);
        push_text(&mut rec, TEXT_SEARCH, &list_search_text(entry, row));
        rec.source(source.clone());
        db.write(rec)?;
    }
    Ok(())
}

fn message_values(message: &AiMessage) -> Vec<Cell> {
    vec![
        text_opt(message.node_id.as_deref()),
        text_opt(message.parent_node_id.as_deref()),
        text_opt(message.message_id.as_deref()),
        text_opt(message.role.as_deref()),
        text_opt(message.author_name.as_deref()),
        text_opt(message.recipient.as_deref()),
        text_opt(message.content_type.as_deref()),
        message
            .content
            .as_deref()
            .map(text_raw)
            .unwrap_or(Cell::Null),
        text_opt(message.created_at.as_deref()),
        message
            .on_current_branch
            .map(|value| Cell::Int(i64::from(value)))
            .unwrap_or(Cell::Null),
        int_opt(message.branch_ordinal.map(|value| value as i64)),
    ]
}

fn attachment_values(attachment: &AiAttachment, messages: usize) -> Vec<Cell> {
    // Never link an attachment to a message that does not exist.
    let message_ordinal = attachment
        .message_ordinal
        .filter(|ordinal| *ordinal < messages)
        .map(|ordinal| Cell::Int(ordinal as i64))
        .unwrap_or(Cell::Null);
    vec![
        message_ordinal,
        text_opt(attachment.attachment_id.as_deref()),
        text_opt(attachment.url.as_deref()),
        text_opt(attachment.file_name.as_deref()),
        text_opt(attachment.mime.as_deref()),
        int_opt(attachment.size_bytes),
        attachment
            .extracted_text
            .as_deref()
            .map(text_raw)
            .unwrap_or(Cell::Null),
        text(attachment.origin),
    ]
}

fn push_text(rec: &mut super::Record, kind: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    rec.child(
        AI_TEXTS_TABLE,
        vec![text(kind), text_raw(value), Cell::Int(value.len() as i64)],
    );
}

/// Title, message bodies and attachments in one row, so a child match reduces to
/// a single parent row (R12).
fn conversation_search_text(conversation: &AiConversation, row: &CacheRow) -> String {
    let mut parts: Vec<&str> = vec![
        conversation.title.as_str(),
        conversation.conversation_id.as_str(),
        conversation.service_account.as_str(),
        row.url.as_str(),
    ];
    for message in &conversation.messages {
        if let Some(role) = message.role.as_deref() {
            parts.push(role);
        }
        if let Some(content) = message.content.as_deref() {
            parts.push(content);
        }
    }
    for attachment in &conversation.attachments {
        for value in [
            attachment.file_name.as_deref(),
            attachment.url.as_deref(),
            attachment.extracted_text.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            parts.push(value);
        }
    }
    parts.retain(|part| !part.is_empty());
    parts.join("\n")
}

fn list_search_text(entry: &ai_activity::AiListEntry, row: &CacheRow) -> String {
    [
        entry.title.as_str(),
        entry.conversation_id.as_str(),
        row.url.as_str(),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use rusqlite::OpenFlags;
    use std::path::{Path, PathBuf};

    struct Row<'a> {
        url: &'a str,
        observed: &'a str,
        body: &'a str,
        recovered: &'a str,
    }

    fn row<'a>(url: &'a str, observed: &'a str, body: &'a str) -> Row<'a> {
        Row {
            url,
            observed,
            body,
            recovered: "1",
        }
    }

    fn dirs(label: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "wina-ai-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let out_dir = base.join("out");
        let target = base.join("target");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        (out_dir, target)
    }

    /// One cache facts DB; input identity comes from the collected path.
    fn cache_facts(out_dir: &Path, file: &str, source: &str, rows: &[Row]) -> PathBuf {
        let path = out_dir.join(BROWSER_DIR).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE CacheEntries (request_time TEXT, response_time TEXT, creation_time TEXT,
             url TEXT, status TEXT, content_type TEXT, cache_key TEXT, all_headers TEXT,
             body_b64 TEXT, body_recovered TEXT, account TEXT, _source_file TEXT);",
        )
        .unwrap();
        for row in rows {
            let encoded =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, row.body);
            conn.execute(
                "INSERT INTO CacheEntries (request_time, response_time, creation_time, url,
                 content_type, body_b64, body_recovered, account, _source_file)
                 VALUES ('', ?1, '', ?2, 'application/json', ?3, ?4, 'Administrator', ?5)",
                rusqlite::params![row.observed, row.url, encoded, row.recovered, source],
            )
            .unwrap();
        }
        drop(conn);
        browser_input::write_input(
            &path,
            &BrowserInput::from_source(Path::new(source), "cache", None),
        )
        .unwrap();
        stamp_facts_generation(&path, "facts-gen-1").unwrap();
        path
    }

    fn build_from(out_dir: &Path, target: &Path) -> usize {
        crate::metadata::build_metadata(out_dir, target, "host", "ds").unwrap();
        let ctx = Ctx {
            out_dir,
            target,
            host_id: "host",
            dataset_id: "ds",
            facts: FactsIndex::load(out_dir).unwrap(),
            meta: MetaLookup::load(out_dir).unwrap(),
        };
        build(&ctx).unwrap()
    }

    fn open_db(out_dir: &Path) -> Connection {
        Connection::open_with_flags(
            out_dir.join("_OVERVIEW").join(format!("{DB_NAME}.sqlite")),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
    }

    fn strings(conn: &Connection, sql: &str) -> Vec<String> {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |row| row.get::<_, Option<String>>(0))
            .unwrap()
            .map(|value| value.unwrap().unwrap_or_else(|| "<NULL>".to_string()))
            .collect()
    }

    fn scalar<T: rusqlite::types::FromSql>(conn: &Connection, sql: &str) -> T {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    const CHROME_SOURCE: &str =
        "/evidence/BROWSER/Administrator/CHROME/Default/Cache/Cache_Data/index";
    const EDGE_SOURCE: &str = "/evidence/BROWSER/Administrator/EDGE/Default/Cache/Cache_Data/index";

    /// Branched ChatGPT mapping: message, node and current-branch counts differ
    /// and off-branch messages are kept (R13).
    #[test]
    fn nested_chatgpt_mapping_separates_messages_nodes_and_current_branch() {
        let (out_dir, target) = dirs("branch");
        // Key order is shuffled (n2, root, n1) and n2-old is a regenerated branch.
        let body = r#"{
            "conversation_id":"conv-1","title":"분석 질문","create_time":1751940000,
            "update_time":1751940100,"current_node":"n2",
            "account":{"email_address":"user@example.com"},
            "mapping":{
                "n2":{"id":"n2","parent":"n1","children":[],
                    "message":{"id":"m2","author":{"role":"assistant","name":null},
                        "recipient":"all",
                        "content":{"content_type":"text","parts":["새 답변"]},
                        "create_time":1751940002}},
                "root":{"id":"root","parent":null,"children":["n1"],"message":null},
                "n2-old":{"id":"n2-old","parent":"n1","children":[],
                    "message":{"id":"m2-old","author":{"role":"assistant"},
                        "content":{"content_type":"text","parts":["옛 답변"]},
                        "create_time":1751940003}},
                "n1":{"id":"n1","parent":"root","children":["n2-old","n2"],
                    "message":{"id":"m1","author":{"role":"user"},"recipient":"all",
                        "content":{"content_type":"multimodal_text","parts":["이 화면 봐줘",
                            {"content_type":"image_asset_pointer","asset_pointer":"file-service://file-abc","size_bytes":1234}]},
                        "create_time":1751940001,
                        "metadata":{"attachments":[{"id":"file-abc","name":"shot.png","mimeType":"image/png","size":2048}]}}}
            }
        }"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(
                "https://chatgpt.com/backend-api/conversation/conv-1",
                "2026-07-08 12:00:00.000",
                body,
            )],
        );
        assert_eq!(build_from(&out_dir, &target), 1);
        let conn = open_db(&out_dir);

        // 4 nodes / 3 messages / 2 current-branch messages are different values.
        assert_eq!(
            strings(
                &conn,
                "SELECT record_kind || '|' || message_count || '|' || structural_node_count
                 || '|' || current_branch_message_count || '|' || attachment_count
                 || '|' || current_node || '|' || body_recovered FROM AiConversations"
            ),
            vec!["conversation|3|4|2|2|n2|1"]
        );
        assert_eq!(
            strings(&conn, "SELECT service_account || '|' || conversation_id || '|' || title FROM AiConversations"),
            vec!["user@example.com|conv-1|분석 질문"]
        );
        // Parent, role, recipient, kind and branch flags are all preserved.
        assert_eq!(
            strings(
                &conn,
                "SELECT node_id || '|' || COALESCE(parent_node_id,'-') || '|' || COALESCE(message_id,'-')
                 || '|' || COALESCE(role,'-') || '|' || COALESCE(recipient,'-')
                 || '|' || COALESCE(content_type,'-') || '|' || on_current_branch
                 || '|' || COALESCE(branch_ordinal,-1) FROM AiMessages ORDER BY ordinal"
            ),
            vec![
                "n1|root|m1|user|all|multimodal_text|1|0",
                // Off-branch (pre-regeneration) messages stay as evidence.
                "n2-old|n1|m2-old|assistant|-|text|0|-1",
                "n2|n1|m2|assistant|all|text|1|1",
            ]
        );
        assert_eq!(
            strings(&conn, "SELECT content FROM AiMessages ORDER BY ordinal"),
            vec!["이 화면 봐줘", "옛 답변", "새 답변"]
        );
        // Attachments link by message ordinal and keep payload metadata only.
        assert_eq!(
            strings(
                &conn,
                "SELECT message_ordinal || '|' || COALESCE(attachment_id,'-') || '|' || COALESCE(url,'-')
                 || '|' || COALESCE(file_name,'-') || '|' || COALESCE(mime,'-')
                 || '|' || COALESCE(size_bytes,-1) || '|' || origin FROM AiAttachments ORDER BY ordinal"
            ),
            vec![
                "0|-|file-service://file-abc|-|-|1234|content_part",
                "0|file-abc|-|shot.png|image/png|2048|message_metadata",
            ]
        );
        // Collected response in the coordinate table, interpretation in the child (R18).
        let stored_body: String = scalar(&conn, "SELECT response_body FROM AiResponseBodies");
        assert_eq!(stored_body, body);
        assert_eq!(
            strings(
                &conn,
                "SELECT b.source_db || '|' || b.source_table || '|' || b.source_rowid
                 || '|' || COALESCE(b.source_file,'-') FROM AiResponseBodies b
                 JOIN source_records s ON s.source_db = b.source_db
                 AND s.source_table = b.source_table AND s.source_rowid = b.source_rowid"
            ),
            vec![format!(
                "BROWSER/Administrator_Chrome_Cache.sqlite|CacheEntries|1|{CHROME_SOURCE}"
            )]
        );
        let interpreted: String = scalar(
            &conn,
            "SELECT text_value FROM AiConversationTexts WHERE text_kind='interpretation_json'",
        );
        assert_ne!(interpreted, body);
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT json_valid(text_value) FROM AiConversationTexts
                 WHERE text_kind='interpretation_json'"
            ),
            1
        );
        // Long text is not on the parent row, so list queries stay small (R17).
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM pragma_table_info('AiConversations')
                 WHERE name IN ('raw_json','response_body','search_text')"
            ),
            0
        );
        // Several matching children still reduce to one parent row (R12).
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiConversations p WHERE EXISTS (
                     SELECT 1 FROM AiMessages m WHERE m.record_id = p.record_id
                     AND m.content LIKE '%답변%')"
            ),
            1
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiMessages WHERE content LIKE '%답변%'"
            ),
            2
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Claude array payload: conversation id, service account and attachment
    /// metadata/size/extracted text, without inventing a current branch (R14).
    #[test]
    fn claude_array_payload_keeps_attachment_metadata_and_no_fake_branch() {
        let (out_dir, target) = dirs("claude");
        let body = r#"{
            "uuid":"c-9","name":"클로드 대화",
            "created_at":"2026-07-01T00:00:00Z","updated_at":"2026-07-01T00:05:00Z",
            "account":{"uuid":"acct-uuid","email_address":"u@example.com"},
            "chat_messages":[
                {"uuid":"m1","sender":"human","text":"질문","created_at":"2026-07-01T00:00:01Z",
                 "attachments":[{"file_name":"notes.txt","file_type":"text/plain","file_size":321,
                                 "extracted_content":"민감한 본문 EvidenceNeedle"}]},
                {"uuid":"m2","sender":"assistant","text":"",
                 "content":[{"type":"text","text":"답변 1"},{"type":"text","text":"답변 2"},
                            {"type":"image","url":"https://claude.ai/img/1.png"}],
                 "created_at":"2026-07-01T00:00:02Z",
                 "files_v2":[{"file_name":"report.pdf","file_kind":"document","preview_url":"https://claude.ai/f/1"}]}
            ]
        }"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(
                "https://claude.ai/api/organizations/org-1/chat_conversations/c-9",
                "2026-07-08 12:00:00.000",
                body,
            )],
        );
        assert_eq!(build_from(&out_dir, &target), 1);
        let conn = open_db(&out_dir);
        // The collected folder name stays a label; confirmed account/SID is NULL (R10).
        assert_eq!(
            strings(
                &conn,
                "SELECT provider || '|' || conversation_id || '|' || service_account
                 || '|' || COALESCE(account,'<NULL>') || '|' || COALESCE(account_sid,'<NULL>')
                 || '|' || facts_account_label || '|' || input_label
                 || '|' || message_count || '|' || structural_node_count
                 || '|' || COALESCE(current_branch_message_count,-1) FROM AiConversations"
            ),
            vec!["Claude|c-9|u@example.com|<NULL>|<NULL>|Administrator|Administrator|2|2|-1"]
        );
        // Array payloads carry no branch information - not 0/1.
        assert_eq!(
            strings(
                &conn,
                "SELECT COALESCE(on_current_branch,-1) || '|' || COALESCE(branch_ordinal,-1)
                 FROM AiMessages ORDER BY ordinal"
            ),
            vec!["-1|-1", "-1|-1"]
        );
        assert_eq!(
            strings(&conn, "SELECT content FROM AiMessages ORDER BY ordinal"),
            vec!["질문", "답변 1\n답변 2"]
        );
        assert_eq!(
            strings(
                &conn,
                "SELECT message_ordinal || '|' || COALESCE(file_name,'-') || '|' || COALESCE(mime,'-')
                 || '|' || COALESCE(size_bytes,-1) || '|' || COALESCE(extracted_text,'-')
                 || '|' || COALESCE(url,'-') FROM AiAttachments ORDER BY ordinal"
            ),
            vec![
                "0|notes.txt|text/plain|321|민감한 본문 EvidenceNeedle|-",
                "1|-|-|-1|-|https://claude.ai/img/1.png",
                "1|report.pdf|-|-1|-|https://claude.ai/f/1",
            ]
        );
        // Extracted attachment text is searchable and maps to one parent row.
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiConversations p WHERE EXISTS (
                     SELECT 1 FROM AiConversationTexts t WHERE t.record_id = p.record_id
                     AND t.text_kind='search_text' AND t.text_value LIKE '%EvidenceNeedle%')"
            ),
            1
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// A real-shaped ChatGPT list response (11 items) becomes body-less traces
    /// without inventing message counts (A01).
    #[test]
    fn conversation_list_response_stores_traces_without_inventing_counts() {
        let (out_dir, target) = dirs("list");
        let items: Vec<String> = (1..=11)
            .map(|index| {
                format!(
                    r#"{{"id":"c{index}","title":"대화 {index}",
                        "create_time":"2026-09-{:02}T01:00:00.000000+00:00",
                        "update_time":"2026-09-{:02}T02:00:00.000000+00:00",
                        "mapping":null,"current_node":null,"is_archived":false}}"#,
                    index, index
                )
            })
            .collect();
        let body = format!(
            r#"{{"items":[{}],"total":11,"limit":28,"offset":0}}"#,
            items.join(",")
        );
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(
                "https://chatgpt.com/backend-api/conversations?offset=0&limit=28&order=updated&is_archived=false",
                "2026-09-30 01:00:00.000",
                &body,
            )],
        );
        assert_eq!(build_from(&out_dir, &target), 11);
        let conn = open_db(&out_dir);
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiConversations WHERE record_kind='list_entry'
                 AND body_recovered=0 AND message_count IS NULL
                 AND structural_node_count IS NULL AND list_item_count=11 AND list_declared_total=11"
            ),
            11
        );
        assert_eq!(
            strings(
                &conn,
                "SELECT conversation_id || '|' || title || '|' || created_at || '|' || updated_at
                 || '|' || list_ordinal FROM AiConversations ORDER BY list_ordinal LIMIT 2"
            ),
            vec![
                "c1|대화 1|2026-09-01T01:00:00.000000+00:00|2026-09-01T02:00:00.000000+00:00|0",
                "c2|대화 2|2026-09-02T01:00:00.000000+00:00|2026-09-02T02:00:00.000000+00:00|1",
            ]
        );
        // List traces have no message/attachment children.
        assert_eq!(scalar::<i64>(&conn, "SELECT COUNT(*) FROM AiMessages"), 0);
        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM AiAttachments"),
            0
        );
        // Every item points at the same single cache row.
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(DISTINCT source_rowid || source_db) FROM source_records"
            ),
            1
        );
        assert_eq!(
            strings(&conn, "SELECT DISTINCT source_label FROM source_records"),
            vec!["AI 대화 목록 캐시 응답"]
        );
        // The response is stored once per facts coordinate, not 11 times (R18).
        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM AiResponseBodies"),
            1
        );
        assert_eq!(
            scalar::<String>(&conn, "SELECT response_body FROM AiResponseBodies"),
            body
        );
        // One per-item interpretation per record.
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(DISTINCT text_value) FROM AiConversationTexts
                 WHERE text_kind='interpretation_json'"
            ),
            11
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Same URL in different inputs keeps both snapshots (R01, A03).
    #[test]
    fn same_url_in_two_inputs_keeps_both_body_snapshots() {
        let (out_dir, target) = dirs("snapshots");
        let url = "https://chatgpt.com/backend-api/conversation/same-id";
        let chrome = r#"{"conversation_id":"same-id","title":"크롬 스냅샷","mapping":{
            "n1":{"id":"n1","parent":null,"children":[],
                "message":{"id":"m1","author":{"role":"user"},"content":{"content_type":"text","parts":["크롬 본문"]}}}}}"#;
        let edge = r#"{"conversation_id":"same-id","title":"엣지 스냅샷","mapping":{
            "n1":{"id":"n1","parent":null,"children":[],
                "message":{"id":"m1","author":{"role":"user"},"content":{"content_type":"text","parts":["엣지 본문"]}}}}}"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(url, "2026-07-08 12:00:00.000", chrome)],
        );
        cache_facts(
            &out_dir,
            "Administrator_Edge_Cache.sqlite",
            EDGE_SOURCE,
            &[row(url, "2026-07-08 13:00:00.000", edge)],
        );
        assert_eq!(build_from(&out_dir, &target), 2);
        let conn = open_db(&out_dir);
        // Browser, profile and collected path come from the input, not file names.
        assert_eq!(
            strings(
                &conn,
                "SELECT browser || '|' || profile || '|' || input_label || '|' || input_kind
                 || '|' || source_file || '|' || title FROM AiConversations ORDER BY timestamp"
            ),
            vec![
                format!("Chrome|Default|Administrator|cache|{CHROME_SOURCE}|크롬 스냅샷"),
                format!("Edge|Default|Administrator|cache|{EDGE_SOURCE}|엣지 스냅샷"),
            ]
        );
        // Bodies differ per input; one never replaces the other.
        assert_eq!(
            strings(
                &conn,
                "SELECT m.content FROM AiMessages m JOIN AiConversations c USING(record_id)
                 ORDER BY c.timestamp"
            ),
            vec!["크롬 본문", "엣지 본문"]
        );
        assert_eq!(
            strings(
                &conn,
                "SELECT source_db || '|' || COALESCE(source_file,'-') FROM source_records
                 ORDER BY source_db"
            ),
            vec![
                format!("BROWSER/Administrator_Chrome_Cache.sqlite|{CHROME_SOURCE}"),
                format!("BROWSER/Administrator_Edge_Cache.sqlite|{EDGE_SOURCE}"),
            ]
        );
        // The response body is kept per input coordinate as well.
        assert_eq!(
            strings(
                &conn,
                "SELECT source_db || '|' || response_body FROM AiResponseBodies ORDER BY source_db"
            ),
            vec![
                format!("BROWSER/Administrator_Chrome_Cache.sqlite|{chrome}"),
                format!("BROWSER/Administrator_Edge_Cache.sqlite|{edge}"),
            ]
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Message-less mapping, empty mapping, unknown time, unrecovered body.
    #[test]
    fn empty_mapping_unknown_time_and_unrecovered_bodies_are_not_invented() {
        let (out_dir, target) = dirs("edges");
        let structural_only = r#"{"conversation_id":"only-nodes","mapping":{
            "a":{"id":"a","parent":null,"children":["b"],"message":null},
            "b":{"id":"b","parent":"a","children":["c"],"message":null},
            "c":{"id":"c","parent":"b","children":[],"message":null}}}"#;
        let empty_mapping = r#"{"conversation_id":"empty","mapping":{}}"#;
        let unrecovered = r#"{"conversation_id":"never","mapping":{
            "a":{"id":"a","parent":null,"children":[],
                "message":{"id":"m","author":{"role":"user"},"content":{"content_type":"text","parts":["숨은 본문"]}}}}}"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[
                // Rows without any time must stay reachable (A04).
                row(
                    "https://chatgpt.com/backend-api/conversation/only-nodes",
                    "",
                    structural_only,
                ),
                row(
                    "https://chatgpt.com/backend-api/conversation/empty",
                    "2026-07-08 12:00:00.000",
                    empty_mapping,
                ),
                Row {
                    url: "https://chatgpt.com/backend-api/conversation/never",
                    observed: "2026-07-08 12:30:00.000",
                    body: unrecovered,
                    recovered: "0",
                },
            ],
        );
        assert_eq!(build_from(&out_dir, &target), 2);
        let conn = open_db(&out_dir);
        // 3 structural nodes but 0 messages - node count is not a message count.
        assert_eq!(
            strings(
                &conn,
                "SELECT conversation_id || '|' || message_count || '|' || structural_node_count
                 || '|' || COALESCE(timestamp,'<NULL>') || '|' || COALESCE(timestamp_kind,'<NULL>')
                 FROM AiConversations ORDER BY conversation_id"
            ),
            vec![
                "empty|0|0|2026-07-08 12:00:00.000|캐시 관찰 시각(응답)",
                "only-nodes|0|3|<NULL>|<NULL>",
            ]
        );
        // Unrecovered bodies are not stored as conversations.
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiConversations WHERE conversation_id='never'"
            ),
            0
        );
        assert_eq!(scalar::<i64>(&conn, "SELECT COUNT(*) FROM AiMessages"), 0);
        // No copy of an unrecovered body anywhere.
        assert_eq!(
            scalar::<i64>(&conn, "SELECT COUNT(*) FROM AiResponseBodies"),
            2
        );
        assert_eq!(
            scalar::<i64>(
                &conn,
                "SELECT COUNT(*) FROM AiResponseBodies WHERE response_body LIKE '%숨은 본문%'"
            ),
            0
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Unknown or unresolvable current_node leaves branch counts NULL (R13).
    #[test]
    fn unknown_current_branch_stays_null() {
        let (out_dir, target) = dirs("unknown-branch");
        let missing_node = r#"{"conversation_id":"no-branch","current_node":"gone","mapping":{
            "a":{"id":"a","parent":null,"children":[],
                "message":{"id":"m1","author":{"role":"user"},"content":{"content_type":"text","parts":["질문"]}}}}}"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(
                "https://chatgpt.com/backend-api/conversation/no-branch",
                "2026-07-08 12:00:00.000",
                missing_node,
            )],
        );
        assert_eq!(build_from(&out_dir, &target), 1);
        let conn = open_db(&out_dir);
        assert_eq!(
            strings(
                &conn,
                "SELECT message_count || '|' || COALESCE(current_branch_message_count,-1)
                 || '|' || COALESCE(current_node,'-') FROM AiConversations"
            ),
            vec!["1|-1|gone"]
        );
        assert_eq!(
            strings(
                &conn,
                "SELECT COALESCE(on_current_branch,-1) || '|' || COALESCE(branch_ordinal,-1) FROM AiMessages"
            ),
            vec!["-1|-1"]
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Confirmed account/SID only when the input label uniquely matches metadata;
    /// the facts account value stays a label (R10).
    #[test]
    fn metadata_evidence_confirms_identity_from_input_label_only() {
        let (out_dir, target) = dirs("confirmed-account");
        // Use an account metadata can name (well-known SID).
        let sid = "S-1-5-18";
        let registry = super::super::registry_explorer::fixture::write_hive(
            &out_dir,
            "SOFTWARE.sqlite",
            "C:\\Windows\\System32\\config\\SOFTWARE",
            &[],
        );
        let registry = Connection::open(registry).unwrap();
        let profile = r"C:\Windows\System32\config\systemprofile";
        registry
            .execute(
                "INSERT INTO Registry(last_write,key_path,value_name,value_type,value_data,
                 _recovery,_source_file,entry_kind,key_offset,parent_key_offset,key_name,
                 key_subkey_count,key_value_count,key_read_status,key_read_error,value_offset,
                 value_name_raw,value_type_code,value_data_hex,value_data_text,value_read_status,
                 value_read_error)
                 VALUES ('2026-01-01 00:00:00.000',?1,'ProfileImagePath','REG_SZ',?2,'live',
                 'C:\\Windows\\System32\\config\\SOFTWARE','value','8192','4096','ProfileList',
                 '0','1','ok','','9000','ProfileImagePath','1',?3,?2,'ok','')",
                rusqlite::params![
                    format!(r"\ROOT\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
                    profile,
                    crate::hex::hex_lower(profile.as_bytes()),
                ],
            )
            .unwrap();
        drop(registry);
        let body = r#"{"conversation_id":"acct-1","mapping":{
            "a":{"id":"a","parent":null,"children":[],
                "message":{"id":"m1","author":{"role":"user"},"content":{"content_type":"text","parts":["질문"]}}}}}"#;
        // The collected path label matches the metadata account name.
        let source = "/evidence/BROWSER/LocalSystem/CHROME/Default/Cache/Cache_Data/index";
        let path = cache_facts(
            &out_dir,
            "LocalSystem_Chrome_Cache.sqlite",
            source,
            &[row(
                "https://chatgpt.com/backend-api/conversation/acct-1",
                "2026-07-08 12:00:00.000",
                body,
            )],
        );
        // The facts account value may be a path fragment; it is not identity.
        let facts = Connection::open(&path).unwrap();
        facts
            .execute("UPDATE CacheEntries SET account = 'Cache_Data'", [])
            .unwrap();
        drop(facts);
        stamp_facts_generation(&path, "facts-gen-1").unwrap();
        assert_eq!(build_from(&out_dir, &target), 1);
        let conn = open_db(&out_dir);
        assert_eq!(
            strings(
                &conn,
                "SELECT COALESCE(account,'<NULL>') || '|' || COALESCE(account_sid,'<NULL>')
                 || '|' || facts_account_label || '|' || COALESCE(input_label,'<NULL>')
                 FROM AiConversations"
            ),
            vec![format!("LocalSystem|{sid}|Cache_Data|LocalSystem")]
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Facts without input identity fail as a reparse error instead of guessing.
    #[test]
    fn missing_browser_input_identity_is_a_reparse_error() {
        let (out_dir, target) = dirs("no-input");
        let body = r#"{"conversation_id":"x","mapping":{}}"#;
        let path = cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache.sqlite",
            CHROME_SOURCE,
            &[row(
                "https://chatgpt.com/backend-api/conversation/x",
                "2026-07-08 12:00:00.000",
                body,
            )],
        );
        let facts = Connection::open(&path).unwrap();
        facts
            .execute_batch("DROP TABLE _wina_browser_input")
            .unwrap();
        drop(facts);
        stamp_facts_generation(&path, "facts-gen-1").unwrap();
        crate::metadata::build_metadata(&out_dir, &target, "host", "ds").unwrap();
        let ctx = Ctx {
            out_dir: out_dir.as_path(),
            target: target.as_path(),
            host_id: "host",
            dataset_id: "ds",
            facts: FactsIndex::load(&out_dir).unwrap(),
            meta: MetaLookup::load(&out_dir).unwrap(),
        };
        let error = format!("{:#}", build(&ctx).unwrap_err());
        assert!(error.contains("브라우저 입력 정보"), "{error}");
        assert!(error.contains("reparse"), "{error}");
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// Numbered extra inputs are found by table, not by file name (R01).
    #[test]
    fn numbered_inputs_are_discovered_by_table_not_filename() {
        let (out_dir, target) = dirs("numbered");
        let body = r#"{"conversation_id":"second-profile","title":"두 번째 프로필","mapping":{
            "a":{"id":"a","parent":null,"children":[],
                "message":{"id":"m1","author":{"role":"user"},"content":{"content_type":"text","parts":["프로필 2"]}}}}}"#;
        cache_facts(
            &out_dir,
            "Administrator_Chrome_Cache_2.sqlite",
            "/evidence/BROWSER/Administrator/CHROME/Profile 2/Cache/Cache_Data/index",
            &[row(
                "https://chatgpt.com/backend-api/conversation/second-profile",
                "2026-07-08 12:00:00.000",
                body,
            )],
        );
        // BROWSER facts without a cache table are left alone.
        let history = out_dir
            .join(BROWSER_DIR)
            .join("Administrator_Chrome.sqlite");
        Connection::open(&history)
            .unwrap()
            .execute_batch("CREATE TABLE BrowserHistory(url TEXT)")
            .unwrap();
        stamp_facts_generation(&history, "facts-gen-1").unwrap();
        assert_eq!(build_from(&out_dir, &target), 1);
        let conn = open_db(&out_dir);
        assert_eq!(
            strings(
                &conn,
                "SELECT profile || '|' || conversation_id FROM AiConversations"
            ),
            vec!["Profile 2|second-profile"]
        );
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    /// The stored contract and the registered schema are the same contract.
    #[test]
    fn spec_matches_registered_contract() {
        let spec = schema::spec(DB_NAME).expect("등록된 계약");
        assert_eq!(spec.columns, SPEC.columns);
        assert_eq!(spec.ddl, SPEC.ddl);
        assert_eq!(spec.children.len(), SPEC.children.len());
    }
}
