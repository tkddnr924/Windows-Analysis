//! USN journal overview: every raw $J record, CLOSE-delimited display groups,
//! complete reason evidence and conservative rename pairing.
//!
//! Reason flags accumulate while the file stays open and the CLOSE record is the
//! final record of that set; the next change starts a new set (USN_RECORD_V2
//! `Reason`, learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v2).
//! CLOSE is therefore the only evidence-based group boundary besides USN order,
//! unknown values and the end of an input. A group is a display summary of
//! observed records, never a proven operation or a complete file lifecycle — a
//! capture can start in the middle of the journal.
use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use rusqlite::Connection;

use super::schema;
use super::stream::{cell_of, fact_files, int_of, open_ro, raw_cell_of, spec_of, str_of};
use super::{nz, text, text_opt, text_raw, Cell, Ctx, DerivedDb};

/// Raw reason bits, mirroring the $J parser's decode table.
const REASON_FLAGS: &[(u32, &str)] = &[
    (0x1, "DATA_OVERWRITE"),
    (0x2, "DATA_EXTEND"),
    (0x4, "DATA_TRUNCATION"),
    (0x10, "NAMED_DATA_OVERWRITE"),
    (0x20, "NAMED_DATA_EXTEND"),
    (0x40, "NAMED_DATA_TRUNCATION"),
    (0x100, "FILE_CREATE"),
    (0x200, "FILE_DELETE"),
    (0x400, "EA_CHANGE"),
    (0x800, "SECURITY_CHANGE"),
    (0x1000, "RENAME_OLD_NAME"),
    (0x2000, "RENAME_NEW_NAME"),
    (0x4000, "INDEXABLE_CHANGE"),
    (0x8000, "BASIC_INFO_CHANGE"),
    (0x10000, "HARD_LINK_CHANGE"),
    (0x20000, "COMPRESSION_CHANGE"),
    (0x40000, "ENCRYPTION_CHANGE"),
    (0x80000, "OBJECT_ID_CHANGE"),
    (0x100000, "REPARSE_POINT_CHANGE"),
    (0x200000, "STREAM_CHANGE"),
    (0x400000, "TRANSACTED_CHANGE"),
    (0x800000, "INTEGRITY_CHANGE"),
    (0x1000000, "DESIRED_STORAGE_CLASS_CHANGE"),
    (0x80000000, "CLOSE"),
];

const CLOSE_BIT: u64 = 0x8000_0000;
const RENAME_OLD_BIT: u64 = 0x1000;
const RENAME_NEW_BIT: u64 = 0x2000;

const GROUP_SCOPE: &str = "input_id,record_version,file_reference";
const GROUPING_BASIS: &str = "close_delimited_observations";
// Pairing never crosses a CLOSE-delimited group: both sides share its group_id.
const MATCHING_BASIS: &str = "input_id,record_version,file_reference,close_delimited_group,usn_order";

const REPARSE_HINT: &str =
    "USN facts에 record_offset이 없습니다. $J를 다시 파싱해야 합니다(호환 폴백 없음)";

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

/// Length-prefixed decimal key: lexicographic order equals numeric order at any
/// width, so 64/128-bit USN and file references sort without a signed CAST.
fn sort_key(value: &str) -> Option<String> {
    let digits = value.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    if trimmed.len() > 99 {
        return None;
    }
    Some(format!("{:02}{trimmed}", trimmed.len()))
}

fn sort_cell(value: &str) -> Cell {
    sort_key(value).map(Cell::Text).unwrap_or(Cell::Null)
}

/// Decoded bits of a raw mask, including bits this build does not name.
fn decoded_flags(mask: u64) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for bit in 0..64u32 {
        let value = 1u64 << bit;
        if mask & value == 0 {
            continue;
        }
        let hex = format!("0x{value:08X}");
        match REASON_FLAGS.iter().find(|(b, _)| u64::from(*b) == value) {
            Some((_, name)) => out.push(((*name).to_string(), hex, false)),
            None => out.push((format!("UNKNOWN_{hex}"), hex, true)),
        }
    }
    out
}

fn known_mask() -> u64 {
    REASON_FLAGS.iter().fold(0, |acc, (bit, _)| acc | u64::from(*bit))
}

// Select a recognized reason by priority without discarding the raw reason.
fn event_type_of<'a>(names: impl Iterator<Item = &'a str>) -> Option<&'static str> {
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
    let present: Vec<&str> = names.collect();
    PRIORITY
        .iter()
        .find(|(flag, _)| present.contains(flag))
        .map(|(_, label)| *label)
}

/// Prefer the raw mask; fall back to the parser's decoded names when the mask
/// itself is unreadable so an unknown mask never erases the record's meaning.
fn event_type(mask: Option<u64>, reason: &str) -> Option<&'static str> {
    match mask {
        Some(mask) => {
            let flags = decoded_flags(mask);
            event_type_of(flags.iter().map(|(name, _, _)| name.as_str()))
        }
        None => event_type_of(reason.split('|').map(str::trim)),
    }
}

fn rename_role(mask: Option<u64>, reason: &str) -> Option<&'static str> {
    let (old, new) = match mask {
        Some(mask) => (mask & RENAME_OLD_BIT != 0, mask & RENAME_NEW_BIT != 0),
        None => {
            let flags: Vec<&str> = reason.split('|').map(str::trim).collect();
            (
                flags.contains(&"RENAME_OLD_NAME"),
                flags.contains(&"RENAME_NEW_NAME"),
            )
        }
    };
    match (old, new) {
        (true, true) => Some("both"),
        (true, false) => Some("old"),
        (false, true) => Some("new"),
        (false, false) => None,
    }
}

fn insert_sql(table: &str, columns: &[&str]) -> String {
    format!(
        "INSERT INTO {} ({}) VALUES ({})",
        crate::sqlite::quote_ident(table),
        columns
            .iter()
            .map(|c| crate::sqlite::quote_ident(c))
            .collect::<Vec<_>>()
            .join(","),
        (1..=columns.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

// ---------------------------------------------------------------------------
// Pass 1 — every raw record
// ---------------------------------------------------------------------------

const FACTS_COLUMNS: &str = "rowid, timestamp, filename, reason, file_attributes_mask, usn, \
     source_info, security_id, file_reference, parent_file_reference, _source_file, reason_mask, \
     record_version, record_offset";

pub(super) fn build(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("UsnJournal");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "UsnJournal")?;
    let table = crate::parsers::usnjrnl::USN_TABLE;
    // Collected inputs are identified separately from physical volume identity.
    let mut inputs: HashMap<String, String> = HashMap::new();
    for path in fact_files(ctx.out_dir, "FILESYSTEM", table)? {
        let conn = open_ro(&path)?;
        let sql = format!(
            "SELECT {FACTS_COLUMNS} FROM {} ORDER BY rowid",
            crate::sqlite::quote_ident(table)
        );
        let mut stmt = conn.prepare(&sql).context(REPARSE_HINT)?;
        let stem = super::stem_of(&path);
        let mut query = stmt.query([])?;
        while let Some(row) = query.next()? {
            let rowid: i64 = row.get(0)?;
            let source_file = str_of(row.get_ref(10)?);
            let input_key = format!("{stem}\u{0}{source_file}");
            let next_id = inputs.len() + 1;
            let input_id = inputs
                .entry(input_key)
                .or_insert_with(|| format!("usn-{next_id}"))
                .clone();
            let reason = str_of(row.get_ref(3)?);
            let mask_text = str_of(row.get_ref(11)?);
            let mask = mask_text.trim().parse::<u64>().ok();
            let usn = str_of(row.get_ref(5)?);
            let file_reference = str_of(row.get_ref(8)?);
            let parent_reference = str_of(row.get_ref(9)?);

            let mut rec = ctx.record(spec);
            rec.timestamp(&str_of(row.get_ref(1)?), "변경 기록 시각");
            rec.set("event_type", text_opt(event_type(mask, &reason)));
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
            rec.set("input_id", text(&input_id));
            rec.set("source_file", text_raw(&source_file));
            if let Ok(relative) = Path::new(&source_file).strip_prefix(ctx.target) {
                rec.set("source_relative", text_raw(&relative.to_string_lossy()));
            }
            rec.set(
                "input_name",
                text_raw(source_file.rsplit(['/', '\\']).next().unwrap_or("")),
            );
            rec.set("record_offset", cell_of(row.get_ref(13)?));
            rec.set("input_sequence", Cell::Int(rowid));
            rec.set("usn_sort", sort_cell(&usn));
            rec.set("file_reference_sort", sort_cell(&file_reference));
            rec.set("parent_reference_sort", sort_cell(&parent_reference));
            rec.set("rename_role", text_opt(rename_role(mask, &reason)));
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
    let rows = db.finish()?;
    group_records(&ctx.overview_dir().join("UsnJournal.sqlite"))?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Pass 2 — groups, reason flags and rename evidence
// ---------------------------------------------------------------------------

const SCAN_SQL: &str = "SELECT record_id, host_id, dataset_id, input_id, input_name, source_file, \
     source_relative, record_version, file_reference, file_reference_sort, parent_reference, \
     file_name, timestamp, usn, usn_sort, input_sequence, record_offset, reason, reason_mask, \
     event_type, rename_role FROM UsnJournal \
     ORDER BY input_id, ifnull(record_version,-1), ifnull(file_reference_sort,''), \
     ifnull(file_reference,''), ifnull(usn_sort,''), input_sequence";

struct Member {
    record_id: String,
    host_id: String,
    dataset_id: String,
    input_id: String,
    input_name: Option<String>,
    source_file: Option<String>,
    source_relative: Option<String>,
    record_version: Option<i64>,
    file_reference: Option<String>,
    file_reference_sort: Option<String>,
    parent_reference: Option<String>,
    file_name: Option<String>,
    timestamp: Option<String>,
    usn: Option<String>,
    usn_sort: Option<String>,
    input_sequence: Option<i64>,
    record_offset: Option<String>,
    reason: Option<String>,
    reason_mask: Option<String>,
    event_type: Option<String>,
    rename_role: Option<String>,
}

impl Member {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            record_id: row.get(0)?,
            host_id: row.get(1)?,
            dataset_id: row.get(2)?,
            input_id: row.get(3)?,
            input_name: row.get(4)?,
            source_file: row.get(5)?,
            source_relative: row.get(6)?,
            record_version: row.get(7)?,
            file_reference: row.get(8)?,
            file_reference_sort: row.get(9)?,
            parent_reference: row.get(10)?,
            file_name: row.get(11)?,
            timestamp: row.get(12)?,
            usn: row.get(13)?,
            usn_sort: row.get(14)?,
            input_sequence: row.get(15)?,
            record_offset: row.get(16)?,
            reason: row.get(17)?,
            reason_mask: row.get(18)?,
            event_type: row.get(19)?,
            rename_role: row.get(20)?,
        })
    }

    fn same_scope(&self, group: &Group) -> bool {
        self.input_id == group.input_id
            && self.record_version == group.record_version
            && self.file_reference == group.file_reference
    }

    fn mask(&self) -> Option<u64> {
        self.reason_mask
            .as_deref()
            .and_then(|value| value.trim().parse::<u64>().ok())
    }
}

/// One rename segment: an OLD run followed by a NEW run inside one group.
#[derive(Default)]
struct Segment {
    old: Vec<Candidate>,
    new: Vec<Candidate>,
    both: Vec<Candidate>,
}

struct Candidate {
    record_id: String,
    role: &'static str,
    file_name: Option<String>,
    parent_reference: Option<String>,
    usn: Option<String>,
    usn_sort: Option<String>,
    timestamp: Option<String>,
    record_offset: Option<String>,
    input_sequence: Option<i64>,
    reason_mask: Option<String>,
}

struct Group {
    group_id: String,
    file_reference: Option<String>,
    host_id: String,
    dataset_id: String,
    input_id: String,
    input_name: Option<String>,
    record_version: Option<i64>,
    file_reference_sort: Option<String>,
    members: i64,
    union_mask: u64,
    mask_seen: bool,
    first_event_type: Option<String>,
    last_parent_reference: Option<String>,
    last_file_name: Option<String>,
    names: Vec<String>,
    last_timestamp: Option<String>,
    last_usn: Option<String>,
    last_usn_sort: Option<String>,
    last_input_sequence: Option<i64>,
    close_seen: bool,
    segments: Vec<Segment>,
}

struct Writer<'a> {
    conn: &'a Connection,
    group_sql: String,
    member_sql: String,
    flag_sql: String,
    rename_sql: String,
    candidate_sql: String,
}

impl Writer<'_> {
    fn insert(&self, sql: &str, values: &[Cell]) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        stmt.execute(rusqlite::params_from_iter(values.iter()))?;
        Ok(())
    }
}

fn group_records(db_path: &Path) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("UsnJournal 묶음 생성: {}", db_path.display()))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch("BEGIN")?;
    let writer = Writer {
        conn: &conn,
        group_sql: insert_sql("UsnChangeGroups", schema::USN_CHANGE_GROUPS_COLUMNS),
        member_sql: insert_sql("UsnGroupMembers", schema::USN_GROUP_MEMBERS_COLUMNS),
        flag_sql: insert_sql("UsnReasonFlags", schema::USN_REASON_FLAGS_COLUMNS),
        rename_sql: insert_sql("UsnRenameEvents", schema::USN_RENAME_EVENTS_COLUMNS),
        candidate_sql: insert_sql("UsnRenameCandidates", schema::USN_RENAME_CANDIDATES_COLUMNS),
    };
    {
        let mut scan = conn.prepare(SCAN_SQL)?;
        let mut rows = scan.query([])?;
        let mut open: Option<Group> = None;
        while let Some(row) = rows.next()? {
            let member = Member::read(row)?;
            let mask = member.mask();
            // An unreadable USN or file reference leaves no ordering or identity
            // evidence, so such a record is kept as its own group.
            let groupable = member.file_reference.is_some() && member.usn_sort.is_some();
            if let Some(current) = open.as_ref() {
                let boundary = if !member.same_scope(current) {
                    Some("reference_end")
                } else if !groupable {
                    Some("usn_unknown")
                } else if member.usn_sort <= current.last_usn_sort {
                    // Duplicate or decreasing USN cannot establish order.
                    Some("usn_order")
                } else {
                    None
                };
                if let Some(boundary) = boundary {
                    close_group(&writer, open.take().expect("open group"), boundary)?;
                }
            }
            if open.is_none() {
                open = Some(open_group(&writer, &member)?);
            }
            let singleton_reason = if member.file_reference.is_none() {
                Some("file_reference_missing")
            } else if member.usn_sort.is_none() {
                Some("usn_unknown")
            } else {
                None
            };
            {
                let group = open.as_mut().expect("open group");
                add_member(&writer, group, &member, mask)?;
            }
            let closing = if let Some(reason) = singleton_reason {
                Some(reason)
            } else if mask.map(|mask| mask & CLOSE_BIT != 0).unwrap_or(false) {
                Some("close_flag")
            } else {
                None
            };
            if let Some(reason) = closing {
                let mut group = open.take().expect("open group");
                group.close_seen = reason == "close_flag";
                close_group(&writer, group, reason)?;
            }
        }
        if let Some(group) = open.take() {
            close_group(&writer, group, "input_end")?;
        }
    }
    // Members carry the assignment, so the parent rows are linked in one pass
    // after the scan instead of being updated while they are read.
    conn.execute(
        "UPDATE UsnJournal SET \
         group_id = (SELECT m.group_id FROM UsnGroupMembers m WHERE m.record_id = UsnJournal.record_id), \
         group_ordinal = (SELECT m.ordinal FROM UsnGroupMembers m WHERE m.record_id = UsnJournal.record_id)",
        [],
    )?;
    let unlinked: i64 = conn.query_row(
        "SELECT count(*) FROM UsnJournal WHERE group_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if unlinked > 0 {
        return Err(anyhow!("USN 레코드 {unlinked}건이 묶음에 연결되지 않았습니다"));
    }
    conn.execute_batch("COMMIT")?;
    Ok(())
}

fn open_group(writer: &Writer<'_>, member: &Member) -> Result<Group> {
    let group = Group {
        group_id: uuid::Uuid::new_v4().to_string(),
        file_reference: member.file_reference.clone(),
        host_id: member.host_id.clone(),
        dataset_id: member.dataset_id.clone(),
        input_id: member.input_id.clone(),
        input_name: member.input_name.clone(),
        record_version: member.record_version,
        file_reference_sort: member.file_reference_sort.clone(),
        members: 0,
        union_mask: 0,
        mask_seen: false,
        first_event_type: member.event_type.clone(),
        last_parent_reference: None,
        last_file_name: None,
        names: Vec::new(),
        last_timestamp: None,
        last_usn: None,
        last_usn_sort: None,
        last_input_sequence: None,
        close_seen: false,
        segments: Vec::new(),
    };
    writer.insert(
        &writer.group_sql,
        &[
            text(&group.group_id),
            text(&group.host_id),
            text(&group.dataset_id),
            text(&group.input_id),
            group.input_name.as_deref().map(text_raw).unwrap_or(Cell::Null),
            member.source_file.as_deref().map(text_raw).unwrap_or(Cell::Null),
            member.source_relative.as_deref().map(text_raw).unwrap_or(Cell::Null),
            group.record_version.map(Cell::Int).unwrap_or(Cell::Null),
            text_opt(group.file_reference.as_deref()),
            text_opt(group.file_reference_sort.as_deref()),
            text_opt(member.parent_reference.as_deref()),
            Cell::Null,
            member.file_name.as_deref().map(text_raw).unwrap_or(Cell::Null),
            Cell::Null,
            Cell::Null,
            text_opt(member.timestamp.as_deref()),
            Cell::Null,
            text_opt(member.usn.as_deref()),
            text_opt(member.usn_sort.as_deref()),
            Cell::Null,
            Cell::Null,
            member.input_sequence.map(Cell::Int).unwrap_or(Cell::Null),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            text(GROUP_SCOPE),
            text(GROUPING_BASIS),
            Cell::Null,
            Cell::Null,
            Cell::Int(1),
            Cell::Int(0),
        ],
    )?;
    Ok(group)
}

fn add_member(
    writer: &Writer<'_>,
    group: &mut Group,
    member: &Member,
    mask: Option<u64>,
) -> Result<()> {
    let ordinal = group.members;
    writer.insert(
        &writer.member_sql,
        &[
            text(&group.group_id),
            Cell::Int(ordinal),
            text(&member.record_id),
            text(&member.input_id),
            member.input_sequence.map(Cell::Int).unwrap_or(Cell::Null),
            text_opt(member.record_offset.as_deref()),
            text_opt(member.timestamp.as_deref()),
            member.file_name.as_deref().map(text_raw).unwrap_or(Cell::Null),
            text_opt(member.event_type.as_deref()),
            text_opt(member.reason.as_deref()),
            text_opt(member.reason_mask.as_deref()),
            text_opt(member.usn.as_deref()),
            text_opt(member.usn_sort.as_deref()),
        ],
    )?;
    if let Some(mask) = mask {
        for (index, (name, bit, unknown)) in decoded_flags(mask).into_iter().enumerate() {
            writer.insert(
                &writer.flag_sql,
                &[
                    text(&member.record_id),
                    Cell::Int(index as i64),
                    text(&group.group_id),
                    text(&name),
                    text(&bit),
                    Cell::Int(i64::from(unknown)),
                ],
            )?;
        }
        group.union_mask |= mask;
        group.mask_seen = true;
    }
    group.members += 1;
    if let Some(name) = member.file_name.as_deref() {
        if !group.names.iter().any(|existing| existing == name) {
            group.names.push(name.to_string());
        }
    }
    group.last_parent_reference = member.parent_reference.clone();
    group.last_file_name = member.file_name.clone();
    group.last_timestamp = member.timestamp.clone();
    group.last_usn = member.usn.clone();
    group.last_usn_sort = member.usn_sort.clone();
    group.last_input_sequence = member.input_sequence;
    if let Some(role) = member.rename_role.as_deref() {
        collect_rename(group, member, role);
    }
    Ok(())
}

/// A later OLD after a completed NEW run starts the next rename segment, so
/// successive rename cycles never collapse into one lifetime event.
fn collect_rename(group: &mut Group, member: &Member, role: &str) {
    let candidate = Candidate {
        record_id: member.record_id.clone(),
        role: match role {
            "old" => "old",
            "new" => "new",
            _ => "both",
        },
        file_name: member.file_name.clone(),
        parent_reference: member.parent_reference.clone(),
        usn: member.usn.clone(),
        usn_sort: member.usn_sort.clone(),
        timestamp: member.timestamp.clone(),
        record_offset: member.record_offset.clone(),
        input_sequence: member.input_sequence,
        reason_mask: member.reason_mask.clone(),
    };
    let start_new = match group.segments.last() {
        None => true,
        Some(last) => candidate.role != "new" && !last.new.is_empty(),
    };
    if start_new {
        group.segments.push(Segment::default());
    }
    let segment = group.segments.last_mut().expect("segment");
    match candidate.role {
        "old" => segment.old.push(candidate),
        "new" => segment.new.push(candidate),
        _ => segment.both.push(candidate),
    }
}

fn close_group(writer: &Writer<'_>, group: Group, boundary: &str) -> Result<()> {
    let flags = if group.mask_seen {
        decoded_flags(group.union_mask)
    } else {
        Vec::new()
    };
    let union_names = flags
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect::<Vec<_>>()
        .join("|");
    let unknown_mask = group.union_mask & !known_mask();
    let event_type = if group.mask_seen {
        event_type_of(flags.iter().map(|(name, _, _)| name.as_str()))
            .map(|label| Cell::Text(label.to_string()))
            .unwrap_or(Cell::Null)
    } else {
        text_opt(group.first_event_type.as_deref())
    };
    writer.conn.execute(
        "UPDATE UsnChangeGroups SET last_parent_reference=?1, last_file_name=?2, \
         distinct_file_name_count=?3, last_timestamp=?4, last_usn=?5, last_usn_sort=?6, \
         last_input_sequence=?7, member_count=?8, event_type=?9, reason_union_mask=?10, \
         reason_union=?11, unknown_reason_mask=?12, has_unknown_reason=?13, boundary_reason=?14, \
         close_observed=?15 WHERE group_id=?16",
        rusqlite::params![
            group.last_parent_reference,
            group.last_file_name,
            group.names.len() as i64,
            group.last_timestamp,
            group.last_usn,
            group.last_usn_sort,
            group.last_input_sequence,
            group.members,
            event_type,
            if group.mask_seen { Some(group.union_mask.to_string()) } else { None },
            if group.mask_seen { Some(union_names) } else { None },
            if group.mask_seen { Some(unknown_mask.to_string()) } else { None },
            if group.mask_seen { Some(i64::from(unknown_mask != 0)) } else { None },
            boundary,
            i64::from(group.close_seen),
            group.group_id,
        ],
    )?;
    for segment in &group.segments {
        write_rename(writer, &group, segment)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rename evidence
// ---------------------------------------------------------------------------

fn distinct_names<'a>(candidates: &[&'a Candidate]) -> Vec<Option<&'a str>> {
    let mut names = Vec::new();
    for candidate in candidates {
        let name = candidate.file_name.as_deref();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn write_rename(writer: &Writer<'_>, group: &Group, segment: &Segment) -> Result<()> {
    let old_side: Vec<&Candidate> = segment.old.iter().chain(segment.both.iter()).collect();
    let new_side: Vec<&Candidate> = segment.new.iter().chain(segment.both.iter()).collect();
    if old_side.is_empty() && new_side.is_empty() {
        return Ok(());
    }
    let old_names = distinct_names(&old_side);
    let new_names = distinct_names(&new_side);
    let mut reasons: Vec<&str> = Vec::new();
    if !segment.both.is_empty() {
        reasons.push("role_conflict");
    }
    if old_names.len() > 1 {
        reasons.push("multiple_old_names");
    }
    if new_names.len() > 1 {
        reasons.push("multiple_new_names");
    }
    for (side, reason) in [
        (&old_side, "multiple_old_parents"),
        (&new_side, "multiple_new_parents"),
    ] {
        if let Some(first) = side.first() {
            if side.iter().any(|c| c.parent_reference != first.parent_reference) {
                reasons.push(reason);
            }
        }
    }
    let usn_missing = old_side
        .iter()
        .chain(new_side.iter())
        .any(|candidate| candidate.usn_sort.is_none());
    if usn_missing {
        reasons.push("usn_missing");
    }
    if group.file_reference.is_none() {
        reasons.push("file_reference_missing");
    }
    let ordered = !usn_missing
        && match (
            old_side.iter().filter_map(|c| c.usn_sort.as_deref()).max(),
            new_side.iter().filter_map(|c| c.usn_sort.as_deref()).min(),
        ) {
            (Some(last_old), Some(first_new)) => last_old < first_new,
            _ => false,
        };
    if !old_side.is_empty() && !new_side.is_empty() && !usn_missing && !ordered {
        reasons.push("usn_order_unresolved");
    }
    let status = if old_side.is_empty() {
        "missing_old"
    } else if new_side.is_empty() {
        "missing_new"
    } else if reasons.is_empty() {
        "paired"
    } else {
        "ambiguous"
    };
    let status = if group.file_reference.is_none() { "ambiguous" } else { status };
    // A single-named side keeps a representative link; every contributor stays
    // in UsnRenameCandidates either way.
    let old_lead = (old_names.len() == 1).then(|| old_side[0]);
    let new_lead = (new_names.len() == 1).then(|| new_side[0]);
    let rename_id = uuid::Uuid::new_v4().to_string();
    writer.insert(
        &writer.rename_sql,
        &[
            text(&rename_id),
            text(&group.host_id),
            text(&group.dataset_id),
            text(&group.input_id),
            text_opt(group.input_name.as_deref()),
            group.record_version.map(Cell::Int).unwrap_or(Cell::Null),
            text_opt(group.file_reference.as_deref()),
            text_opt(group.file_reference_sort.as_deref()),
            text(status),
            if reasons.is_empty() { Cell::Null } else { text(&reasons.join("|")) },
            text(MATCHING_BASIS),
            old_lead.map(|c| text(&c.record_id)).unwrap_or(Cell::Null),
            new_lead.map(|c| text(&c.record_id)).unwrap_or(Cell::Null),
            text(&group.group_id),
            old_lead.and_then(|c| c.file_name.as_deref()).map(text_raw).unwrap_or(Cell::Null),
            new_lead.and_then(|c| c.file_name.as_deref()).map(text_raw).unwrap_or(Cell::Null),
            old_lead.and_then(|c| c.usn.as_deref()).map(text).unwrap_or(Cell::Null),
            old_lead.and_then(|c| c.usn_sort.as_deref()).map(text).unwrap_or(Cell::Null),
            new_lead.and_then(|c| c.usn.as_deref()).map(text).unwrap_or(Cell::Null),
            new_lead.and_then(|c| c.usn_sort.as_deref()).map(text).unwrap_or(Cell::Null),
            old_lead.and_then(|c| c.timestamp.as_deref()).map(text).unwrap_or(Cell::Null),
            new_lead.and_then(|c| c.timestamp.as_deref()).map(text).unwrap_or(Cell::Null),
            Cell::Int(old_side.len() as i64),
            Cell::Int(new_side.len() as i64),
        ],
    )?;
    for (ordinal, candidate) in segment
        .old
        .iter()
        .chain(segment.new.iter())
        .chain(segment.both.iter())
        .enumerate()
    {
        writer.insert(
            &writer.candidate_sql,
            &[
                text(&rename_id),
                Cell::Int(ordinal as i64),
                text(&candidate.record_id),
                text(&group.group_id),
                text(candidate.role),
                candidate.file_name.as_deref().map(text_raw).unwrap_or(Cell::Null),
                text_opt(candidate.usn.as_deref()),
                text_opt(candidate.usn_sort.as_deref()),
                text_opt(candidate.timestamp.as_deref()),
                text_opt(candidate.record_offset.as_deref()),
                candidate.input_sequence.map(Cell::Int).unwrap_or(Cell::Null),
                text_opt(candidate.reason_mask.as_deref()),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_keys_order_values_beyond_signed_range() {
        let mut keys = [
            sort_key("18446744073709551615").unwrap(),
            sort_key("9").unwrap(),
            sort_key("340282366920938463463374607431768211455").unwrap(),
            sort_key("0").unwrap(),
            sort_key("00042").unwrap(),
        ];
        keys.sort();
        assert_eq!(
            keys,
            [
                sort_key("0").unwrap(),
                sort_key("9").unwrap(),
                sort_key("42").unwrap(),
                sort_key("18446744073709551615").unwrap(),
                sort_key("340282366920938463463374607431768211455").unwrap(),
            ]
        );
        assert_eq!(sort_key(""), None, "미확인 값은 0으로 바꾸지 않는다");
        assert_eq!(sort_key("-1"), None);
        assert_eq!(sort_key("0").as_deref(), Some("010"));
    }

    #[test]
    fn unknown_reason_bits_stay_visible() {
        let flags = decoded_flags(0x100 | 0x0800_0000);
        assert_eq!(flags[0].0, "FILE_CREATE");
        assert_eq!(flags[1], ("UNKNOWN_0x08000000".into(), "0x08000000".into(), true));
    }

    #[test]
    fn desired_storage_class_change_is_a_known_reason() {
        let flags = decoded_flags(0x0100_0000 | CLOSE_BIT);
        assert_eq!(flags[0], ("DESIRED_STORAGE_CLASS_CHANGE".into(), "0x01000000".into(), false));
        assert_eq!((0x0100_0000 | CLOSE_BIT) & !known_mask(), 0);
    }
}
