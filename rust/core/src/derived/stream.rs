//! Stream structured facts into typed overview rows.
//! Missing evidence remains NULL; matching numbers do not establish identity.
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use super::parallel::{table, Task};
use super::schema::{self, DbSpec};
use super::{flag, int, nz, text, text_raw, Cell, Ctx, DerivedDb};

pub(super) fn spec_of(name: &str) -> &'static DbSpec {
    schema::spec(name).expect("문서에 없는 파생 DB")
}

pub(super) fn open_ro(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("원본 열기: {}", path.display()))
}

/// Sorted facts DBs of a category that hold `table`. A missing folder or
/// table is no evidence; listing/open failures are errors.
pub(super) fn fact_files(out_dir: &Path, category: &str, table: &str) -> Result<Vec<PathBuf>> {
    let dir = out_dir.join(category);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("원본 목록: {}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.with_context(|| format!("원본 목록: {}", dir.display()))?.path();
        if path.extension().is_some_and(|ext| ext == "sqlite") && has_table(&path, table)? {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn has_table(path: &Path, table: &str) -> Result<bool> {
    open_ro(path)?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )
        .with_context(|| format!("원본 테이블 확인: {}", path.display()))
}

pub(super) fn cell_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(v) => Cell::Int(v),
        ValueRef::Real(v) => Cell::Text(v.to_string()),
        ValueRef::Text(v) => text(&String::from_utf8_lossy(v)),
        ValueRef::Blob(v) => Cell::Blob(v.to_vec()),
    }
}

// Evidence text preserves whitespace.
pub(super) fn raw_cell_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Text(v) => text_raw(&String::from_utf8_lossy(v)),
        other => cell_of(other),
    }
}

pub(super) fn int_of(value: ValueRef<'_>) -> Cell {
    match value {
        ValueRef::Integer(v) => Cell::Int(v),
        ValueRef::Text(v) => int(&String::from_utf8_lossy(v)),
        _ => Cell::Null,
    }
}

pub(super) fn str_of(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Text(v) => String::from_utf8_lossy(v).into_owned(),
        ValueRef::Integer(v) => v.to_string(),
        _ => String::new(),
    }
}

/// File-backed builders; none reads another overview table.
pub(super) fn tasks<'s>(ctx: &'s Ctx) -> Vec<Task<'s>> {
    vec![
        table("UsnJournal", &[], move || super::usn::build(ctx)),
        table("FileSystemEntries", &[], move || file_system_entries(ctx)),
        table("AiConversations", &[], move || super::ai_conversations::build(ctx)),
        table("WmiSubscriptions", &[], move || wmi_subscriptions(ctx)),
        table("RecycleBin", &[], move || recycle_bin(ctx)),
        table("JumpListEntries", &[], move || jump_list_entries(ctx)),
        table("TimelineActivities", &[], move || timeline_activities(ctx)),
    ]
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
    for path in fact_files(ctx.out_dir, "WMI", crate::parsers::wmi_repository::WMI_TABLE)? {
        for row in crate::overview::read_table_with_rowid(&path, crate::parsers::wmi_repository::WMI_TABLE)? {
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
     fn_mft_modified, fn_accessed, _source_file, parent_seq, parent_status, path_status, data_status, record_status FROM \"MFT_Records\"";

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
        for (offset, name) in ["parent_seq", "parent_status", "path_status", "data_status", "record_status"].iter().enumerate() {
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
// UsnJournal — see derived/usn.rs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RecycleBin
// ---------------------------------------------------------------------------

fn recycle_bin(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("RecycleBin");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "RecycleBin")?;
    let table = crate::parsers::recyclebin::TABLE;
    for path in fact_files(ctx.out_dir, "RECYCLEBIN", table)? {
        for row in crate::overview::read_table_with_rowid(&path, table)? {
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
            rec.set("mft_path", text(get("mft_path")));
            rec.set("mft_entry", int(get("mft_entry")));
            rec.set("mft_seq", int(get("mft_seq")));
            let resident = !get("mft_path").is_empty();
            rec.source(ctx.facts.source_from_record_key(
                &format!("{}::{}::{}", super::stem_of(&path), table, get("__source_rowid")),
                None,
                nz(get("_source_file")),
                Some(if resident { "MFT 상주 $I 메타데이터" } else { "휴지통 $I 메타데이터" }),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// JumpListEntries — every parsed entry, path or not (PathReferences keeps
// only path-bearing entries for path lookups).
// ---------------------------------------------------------------------------

fn jump_list_entries(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("JumpListEntries");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "JumpListEntries")?;
    let table = "JumpList_Entries";
    for path in fact_files(ctx.out_dir, "JUMPLIST", table)? {
        for row in crate::overview::read_table_with_rowid(&path, table)? {
            let get = |key: &str| row.get(key).map(String::as_str).unwrap_or("");
            let mut rec = ctx.record(spec);
            let timestamp_source = get("timestamp_source");
            rec.timestamp(
                get("timestamp"),
                match timestamp_source {
                    "destlist_accessed" => "DestList 마지막 사용 시각",
                    "lnk_accessed" => "LNK 대상 접근 시각",
                    _ => "원본 기록 시각",
                },
            );
            rec.set("event_type", text("점프 목록"));
            // The collection folder names the profile; names resolve via metadata only.
            let account = crate::overview::account_from_source(get("_source_file"));
            rec.account(&account, &ctx.meta);
            let target_path = get("target_path");
            rec.set("jumplist_type", text(get("jumplist_type")));
            rec.set("app_id", text(get("app_id")));
            rec.set("target_path", text_raw(target_path));
            rec.set(
                "target_path_resolved",
                ctx.meta.resolve_path(target_path, super::is_sid(&account).then_some(account.as_str())),
            );
            rec.set("arguments", text_raw(get("arguments")));
            rec.set("working_directory", text_raw(get("working_directory")));
            rec.set("hostname", text_raw(get("hostname")));
            rec.set("machine_id", text_raw(get("machine_id")));
            rec.set("access_count", int(get("access_count")));
            rec.set("lnk_accessed", text(get("lnk_accessed")));
            rec.set("destlist_accessed", text(get("destlist_accessed")));
            rec.set("created_time", text(get("created_time")));
            rec.set("modified_time", text(get("modified_time")));
            rec.set("timestamp_source", text(timestamp_source));
            rec.set("stream_id", text(get("stream_id")));
            rec.set("status", text(get("_status")));
            rec.set("error", text(get("_error")));
            rec.source(ctx.facts.source_from_record_key(
                &format!("{}::{}::{}", super::stem_of(&path), table, get("__source_rowid")),
                None,
                nz(get("_source_file")),
                Some("점프 목록 항목"),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// TimelineActivities — every ActivitiesCache activity; type 5 also feeds
// ExecutionHistory (same source record).
// ---------------------------------------------------------------------------

fn timeline_activities(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("TimelineActivities");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "TimelineActivities")?;
    let table = "Timeline_Activities";
    for path in fact_files(ctx.out_dir, "TIMELINE", table)? {
        for row in crate::overview::read_table_with_rowid(&path, table)? {
            let get = |key: &str| row.get(key).map(String::as_str).unwrap_or("");
            let mut rec = ctx.record(spec);
            // The parser takes StartTime, else LastModifiedTime.
            let timestamp = get("timestamp");
            rec.timestamp(
                timestamp,
                if nz(get("start_time")).is_some() && timestamp == get("start_time") {
                    "활동 시작 시각"
                } else {
                    "활동 마지막 수정 시각"
                },
            );
            rec.set("event_type", text(get("kind")));
            let account = get("account");
            rec.account(account, &ctx.meta);
            let app_path = get("app_path");
            rec.set("activity_type", int(get("activity_type")));
            rec.set("kind", text(get("kind")));
            rec.set("app_name", text_raw(get("app_name")));
            rec.set("app_path", text_raw(app_path));
            rec.set(
                "app_path_resolved",
                ctx.meta.resolve_path(app_path, super::is_sid(account).then_some(account)),
            );
            rec.set("display_text", text_raw(get("display_text")));
            rec.set("content_uri", text_raw(get("content_uri")));
            rec.set("active_duration_s", int(get("active_duration_s")));
            rec.set("start_time", text(get("start_time")));
            rec.set("end_time", text(get("end_time")));
            rec.set("last_modified", text(get("last_modified")));
            rec.set("expiration", text(get("expiration")));
            rec.set("activity_table", text(get("source_table")));
            rec.set("activity_id", text(get("activity_id")));
            rec.set("platform_device_id", text_raw(get("platform_device_id")));
            rec.set("payload", text_raw(get("payload")));
            rec.source(ctx.facts.source_from_record_key(
                &format!("{}::{}::{}", super::stem_of(&path), table, get("__source_rowid")),
                None,
                nz(get("_source_file")),
                Some("Windows 타임라인 활동"),
            )?);
            db.write(rec)?;
        }
    }
    db.finish()
}
