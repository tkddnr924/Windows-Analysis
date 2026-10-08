//! Stream structured facts into typed overview rows.
//! Missing evidence remains NULL; matching numbers do not establish identity.
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use super::schema::{self, DbSpec};
use super::{flag, int, json_text, nz, text, text_opt, text_raw, Cell, Ctx, DerivedDb};

fn spec_of(name: &str) -> &'static DbSpec {
    schema::spec(name).expect("문서에 없는 파생 DB")
}

fn open_ro(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("원본 열기: {}", path.display()))
}

fn fact_files(out_dir: &Path, category: &str, table: &str) -> Vec<PathBuf> {
    let dir = out_dir.join(category);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().map(|ext| ext == "sqlite").unwrap_or(false))
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    files.retain(|path| has_table(path, table));
    files
}

fn has_table(path: &Path, table: &str) -> bool {
    let Ok(conn) = open_ro(path) else {
        return false;
    };
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |_| Ok(()),
    )
    .is_ok()
}

fn cell_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(v) => Cell::Int(v),
        ValueRef::Real(v) => Cell::Text(v.to_string()),
        ValueRef::Text(v) => text(&String::from_utf8_lossy(v)),
        ValueRef::Blob(v) => Cell::Blob(v.to_vec()),
    }
}

// Evidence text preserves whitespace.
fn raw_cell_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Text(v) => text_raw(&String::from_utf8_lossy(v)),
        other => cell_of(other),
    }
}

fn int_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Integer(v) => Cell::Int(v),
        ValueRef::Text(v) => int(&String::from_utf8_lossy(v)),
        _ => Cell::Null,
    }
}

fn str_of(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Text(v) => String::from_utf8_lossy(v).into_owned(),
        ValueRef::Integer(v) => v.to_string(),
        _ => String::new(),
    }
}

pub(super) fn build_streaming(ctx: &Ctx) -> Result<Vec<(String, usize)>> {
    Ok(vec![
        ("AiConversations".into(), ai_conversations(ctx)?),
        ("WmiSubscriptions".into(), wmi_subscriptions(ctx)?),
        ("FileSystemEntries".into(), file_system_entries(ctx)?),
        ("UsnJournal".into(), usn_journal(ctx)?),
        ("RecycleBin".into(), recycle_bin(ctx)?),
    ])
}

// ---------------------------------------------------------------------------
// AiConversations
// ---------------------------------------------------------------------------

fn ai_conversations(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("AiConversations");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "AiConversations")?;
    crate::ai_activity::build_ai_conversations_stream(ctx.out_dir, &mut |record| {
        let row = &record.row;
        let get = |key: &str| row.get(key).map(String::as_str).unwrap_or("");
        let mut rec = ctx.record(spec);
        rec.timestamp(get("date"), "캐시 관찰 시각");
        rec.set("event_type", text("AI 대화"));
        // Cache account identifies the collected Windows profile.
        rec.account(get("account"), &ctx.meta);
        rec.set("provider", text(get("provider")));
        rec.set("conversation_id", text(get("conversation_id")));
        // Service login identity is distinct from the Windows account.
        rec.set("service_account", text(get("service_account")));
        rec.set("title", text(get("title")));
        rec.set("created_at", text(get("created_at")));
        rec.set("updated_at", text(get("updated_at")));
        rec.set("url", text(get("url")));
        rec.set("raw_json", json_text(get("raw_json")));
        rec.set("message_count", int(get("message_count")));
        for message in &record.messages {
            rec.child(
                "AiMessages",
                vec![
                    text_opt(message.message_id.as_deref()),
                    text_opt(message.role.as_deref()),
                    message
                        .content
                        .as_deref()
                        .map(text_raw)
                        .unwrap_or(Cell::Null),
                    text_opt(message.created_at.as_deref()),
                ],
            );
        }
        let messages = record.messages.len();
        for attachment in &record.attachments {
            // Do not link attachments to nonexistent messages.
            let ordinal = attachment
                .message_ordinal
                .filter(|ordinal| *ordinal < messages)
                .map(|ordinal| Cell::Int(ordinal as i64))
                .unwrap_or(Cell::Null);
            rec.child(
                "AiAttachments",
                vec![
                    ordinal,
                    text_opt(attachment.url.as_deref()),
                    text_opt(attachment.file_name.as_deref()),
                    text_opt(attachment.mime.as_deref()),
                ],
            );
        }
        rec.source(ctx.facts.source_from_record_key(
            get("source_record_key"),
            None,
            nz(get("_source_file")),
            Some("AI 대화 캐시 응답"),
        )?);
        db.write(rec)?;
        Ok(())
    })?;
    db.finish()
}

// ---------------------------------------------------------------------------
// WmiSubscriptions
// ---------------------------------------------------------------------------

fn wmi_object_type(kind: &str) -> &'static str {
    match kind {
        "이벤트 필터" => "filter",
        "이벤트 컨슈머" => "consumer",
        "바인딩" => "binding",
        _ => "",
    }
}

fn wmi_subscriptions(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("WmiSubscriptions");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "WmiSubscriptions")?;
    for path in fact_files(ctx.out_dir, "WMI", crate::parsers::wmi_repository::WMI_TABLE) {
        for row in crate::overview::read_table_with_rowid(&path, crate::parsers::wmi_repository::WMI_TABLE) {
            let get = |key: &str| row.get(key).map(String::as_str).unwrap_or("");
            let object_type = wmi_object_type(get("kind"));
            let consumer_type = get("consumer_type");
            let details = get("details");
            let mut rec = ctx.record(spec);
            // Repository records do not establish registration timestamps.
            rec.set("event_type", text(object_type));
            rec.set("object_type", text(object_type));
            rec.set("namespace", text(get("namespace")));
            rec.set("filter_name", text(get("filter_name")));
            rec.set("query", text_raw(get("query")));
            rec.set("query_language", text(get("query_language")));
            rec.set("consumer_name", text(get("consumer_name")));
            rec.set("consumer_type", text(consumer_type));
            // Unlabeled, possibly truncated tokens cannot prove commands or scripts.
            let description = match (nz(get("name")), nz(details)) {
                (Some(name), Some(details)) => format!("{name} | {details}"),
                (Some(name), None) => name.to_string(),
                (None, Some(details)) => details.to_string(),
                (None, None) => String::new(),
            };
            rec.set("description", text_raw(&description));
            rec.source(ctx.facts.source_from_record_key(
                &format!(
                    "{}::{}::{}",
                    super::stem_of(&path),
                    crate::parsers::wmi_repository::WMI_TABLE,
                    get("__source_rowid")
                ),
                None,
                nz(get("_source_file")),
                Some("WMI 저장소 레코드"),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// FileSystemEntries
// ---------------------------------------------------------------------------

const MFT_SELECT: &str = "SELECT rowid, volume_id, volume_label, volume_serial, drive_letter, \
     ntfs_major_version, ntfs_minor_version, volume_flags, path, file_name, extension, \
     is_directory, in_use, file_size, data, entry, seq, parent_entry, si_created, si_modified, \
     si_mft_modified, si_accessed, owner_id, security_id, fn_created, fn_modified, \
     fn_mft_modified, fn_accessed, _source_file, parent_seq, parent_status, path_status, data_status FROM \"MFT_Records\"";

fn file_system_entries(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("FileSystemEntries");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "FileSystemEntries")?;
    let facts = ctx.out_dir.join("_OVERVIEW").join("MFT_Records.sqlite");
    if !facts.exists() {
        return db.finish();
    }
    // Resolve column positions once, not per record.
    let index = |name: &str| spec.index_of(name).expect("문서 컬럼");
    // Positions must match MFT_SELECT order.
    let positions: Vec<usize> = [
        "volume_id",
        "volume_label",
        "volume_serial",
        "drive_letter",
        "ntfs_major_version",
        "ntfs_minor_version",
        "volume_flags",
        "path",
        "file_name",
        "extension",
        "is_directory",
        "in_use",
        "file_size",
        "data",
        "entry",
        "seq",
        "parent_entry",
        "si_created",
        "si_modified",
        "si_mft_modified",
        "si_accessed",
        "owner_id",
        "security_id",
        "fn_created",
        "fn_modified",
        "fn_mft_modified",
        "fn_accessed",
    ]
    .iter()
    .map(|name| index(name))
    .collect();
    let i_timestamp = index("timestamp");
    let i_timestamp_kind = index("timestamp_kind");
    let i_event_type = index("event_type");

    let conn = open_ro(&facts)?;
    let mut stmt = conn.prepare(MFT_SELECT)
        .context("MFT 저장 필드가 없으면 MFT 아티팩트를 다시 파싱해야 합니다")?;
    let mut query = stmt.query([])?;
    while let Some(row) = query.next()? {
        let rowid: i64 = row.get(0)?;
        let mut rec = ctx.record(spec);
        for (offset, target) in positions.iter().enumerate() {
            let value = row.get_ref(offset + 1)?;
            let cell = match offset {
                // Owner/security IDs are numeric identifiers, not accounts.
                21 | 22 => int_of(value),
                16 => match int_of(value) {
                    Cell::Int(-1) => Cell::Null,
                    other => other,
                },
                // Preserve filename and path whitespace.
                _ => raw_cell_of(value),
            };
            rec.set_at(*target, cell);
        }
        // SI modification is primary; all other timestamps remain available.
        let si_modified = rec.at(index("si_modified")).clone();
        if let Cell::Text(si_modified) = si_modified {
            rec.set_at(i_timestamp, Cell::Text(si_modified));
            rec.set_at(i_timestamp_kind, Cell::Text("SI 수정 시각".into()));
        }
        let is_directory = match rec.at(index("is_directory")) {
            Cell::Int(value) => Some(*value),
            _ => None,
        };
        if let Some(is_directory) = is_directory {
            rec.set_at(
                i_event_type,
                Cell::Text(if is_directory == 1 { "디렉터리" } else { "파일" }.into()),
            );
        }
        let source_file = str_of(row.get_ref(28)?);
        for (offset, name) in ["parent_seq", "parent_status", "path_status", "data_status"].iter().enumerate() {
            rec.set(name, raw_cell_of(row.get_ref(29 + offset)?));
        }
        rec.set("source_file", text_raw(&source_file));
        let input_path = Path::new(&source_file);
        if let Ok(relative) = input_path.strip_prefix(ctx.target) {
            rec.set("source_relative", text_raw(&relative.to_string_lossy()));
        }
        rec.set("input_name", text_raw(source_file.rsplit(['/', '\\']).next().unwrap_or("")));
        if let Some(Cell::Text(path)) = rec.get("path") {
            let key = crate::overview::classify_path(path).key;
            rec.set("path_key", Cell::Text(key));
        }
        rec.source(ctx.facts.source_from_row(
            &facts,
            "MFT_Records",
            rowid,
            nz(&source_file),
            Some("MFT 레코드"),
        )?);
        db.write(rec)?;
    }
    drop(query);
    drop(stmt);
    db.finish()
}

// ---------------------------------------------------------------------------
// UsnJournal
// ---------------------------------------------------------------------------

// Select a recognized reason by priority without discarding the raw reason.
fn usn_event_type(reason: &str) -> Option<&'static str> {
    const PRIORITY: &[(&str, &str)] = &[
        ("FILE_DELETE", "삭제"),
        ("RENAME_OLD_NAME", "이름 변경(이전 이름)"),
        ("RENAME_NEW_NAME", "이름 변경(새 이름)"),
        ("FILE_CREATE", "생성"),
        ("DATA_OVERWRITE", "내용 변경"),
        ("DATA_EXTEND", "내용 변경"),
        ("DATA_TRUNCATION", "내용 변경"),
        ("NAMED_DATA_OVERWRITE", "내용 변경"),
        ("NAMED_DATA_EXTEND", "내용 변경"),
        ("NAMED_DATA_TRUNCATION", "내용 변경"),
        ("SECURITY_CHANGE", "보안 변경"),
        ("BASIC_INFO_CHANGE", "속성 변경"),
        ("STREAM_CHANGE", "스트림 변경"),
        ("CLOSE", "닫기"),
    ];
    let flags: Vec<&str> = reason.split('|').map(str::trim).collect();
    PRIORITY
        .iter()
        .find(|(flag, _)| flags.contains(flag))
        .map(|(_, label)| *label)
}

fn usn_journal(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("UsnJournal");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "UsnJournal")?;
    let table = crate::parsers::usnjrnl::USN_TABLE;
    for path in fact_files(ctx.out_dir, "FILESYSTEM", table) {
        let conn = open_ro(&path)?;
        let mut stmt = conn.prepare(&format!(
            "SELECT rowid, timestamp, filename, reason, file_attributes_mask, usn, source_info, \
             security_id, file_reference, parent_file_reference, _source_file, reason_mask, \
             record_version FROM {}",
            crate::sqlite::quote_ident(table)
        ))?;
        let mut query = stmt.query([])?;
        while let Some(row) = query.next()? {
            let rowid: i64 = row.get(0)?;
            let reason = str_of(row.get_ref(3)?);
            let mut rec = ctx.record(spec);
            rec.timestamp(&str_of(row.get_ref(1)?), "변경 기록 시각");
            rec.set("event_type", text_opt(usn_event_type(&reason)));
            rec.set("file_name", raw_cell_of(row.get_ref(2)?));
            // $J alone cannot establish path, volume, journal ID or account.
            rec.set("usn", cell_of(row.get_ref(5)?));
            rec.set("file_reference", cell_of(row.get_ref(8)?));
            rec.set("parent_reference", cell_of(row.get_ref(9)?));
            rec.set("reason_mask", cell_of(row.get_ref(11)?));
            rec.set("reason", text(&reason));
            rec.set("record_version", int_of(row.get_ref(12)?));
            rec.set("source_info", cell_of(row.get_ref(6)?));
            rec.set("security_id", int_of(row.get_ref(7)?));
            // Preserve raw attribute bits; decoded labels remain in facts.
            rec.set("file_attributes", cell_of(row.get_ref(4)?));
            let source_file = str_of(row.get_ref(10)?);
            rec.source(ctx.facts.source_from_row(
                &path,
                table,
                rowid,
                nz(&source_file),
                Some("USN 변경 레코드"),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// RecycleBin
// ---------------------------------------------------------------------------

fn recycle_bin(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("RecycleBin");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "RecycleBin")?;
    let table = crate::parsers::recyclebin::TABLE;
    for path in fact_files(ctx.out_dir, "RECYCLEBIN", table) {
        for row in crate::overview::read_table_with_rowid(&path, table) {
            let get = |key: &str| row.get(key).map(String::as_str).unwrap_or("");
            let account_sid = get("account_sid");
            let mut rec = ctx.record(spec);
            rec.timestamp(get("timestamp"), "휴지통 이동 시각");
            rec.set("event_type", text("휴지통 이동"));
            rec.set("account_sid", text(account_sid));
            // Use only metadata-confirmed account names.
            rec.set(
                "account",
                match ctx.meta.account_name(account_sid) {
                    Some(name) => text(&name),
                    None => text(get("account")),
                },
            );
            rec.set("format_version", int(get("format_version")));
            rec.set("original_path", text(get("original_path")));
            rec.set("original_drive_letter", text(get("original_drive_letter")));
            rec.set("file_size", int(get("file_size")));
            rec.set("deleted_time_raw", text(get("deleted_time_raw")));
            rec.set("volume_id", text(get("volume_id")));
            rec.set("recycle_name", text(get("recycle_name")));
            rec.set("r_exists", flag(get("r_exists")));
            rec.set("status", text(get("_status")));
            rec.set("error", text(get("_error")));
            rec.source(ctx.facts.source_from_record_key(
                &format!("{}::{}::{}", super::stem_of(&path), table, get("__source_rowid")),
                None,
                nz(get("_source_file")),
                Some("휴지통 $I 메타데이터"),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}
