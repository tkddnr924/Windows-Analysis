//! NTFS $MFT parser (via the `mft` crate), streaming. Per source file two
//! passes: pass 1 builds a lightweight entry->(name,parent) index for path
//! resolution and reads the `$Volume` record; pass 2 re-reads each record,
//! builds its typed row, and inserts it through one prepared statement in
//! batched transactions. Memory stays bounded (index + one open transaction)
//! regardless of record count.
//!
//! Several sources write into one output database: `parse_mft_sources` keeps a
//! separate `volume_id`, path index and path cache per source, so entry/seq
//! numbers that repeat on another volume never mix. A source that fails to
//! parse is rolled back and reported; its rows never reach the output.
//!
//! Schema: the approved 28 columns of `데이터베이스/21. MFT.md` — INTEGER
//! flags/sizes/entry numbers, the unnamed resident `$DATA` body as a BLOB,
//! NULL for anything the evidence does not contain — followed by the four
//! appended state columns. A parent reference is only used when the referenced
//! record exists in the same input, carries the referenced sequence and is a
//! directory, so a reused or stale reference never yields a rooted path;
//! `parent_status`/`path_status` say why, and `data_status` says what the
//! unnamed `$DATA` really carried.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, Result};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::MftParser;
use rusqlite::Connection;

use crate::sqlite::quote_ident;
use crate::time::fmt_kst_ft;

pub const MFT_TABLE: &str = "MFT_Records";
pub const MFT_FIELD_ORDER: &[&str] = &[
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
    "_source_file",
    // Appended behind the approved 28 fields, whose order above is fixed.
    "parent_seq",
    "parent_status",
    "path_status",
    "data_status",
];

const ROOT_ENTRY: u64 = 5;
/// FILE record header flags: 0x01 = allocated (in use), 0x02 = index present,
/// which is what makes a record a directory.
const FLAG_IN_USE: u16 = 0x01;
const FLAG_DIRECTORY: u16 = 0x02;
/// NTFS reserved record 3 is `$Volume`: the label, the NTFS version and the
/// volume state flags live in its attributes, not in the file records.
const VOLUME_ENTRY: u64 = 3;
const VOLUME_RECORD_NAME: &str = "$Volume";

/// Commit every N rows (or once the buffered resident bodies pass the byte
/// budget) so the rollback journal of one transaction stays bounded.
const BATCH_ROWS: usize = 50_000;
const BATCH_BYTES: usize = 64 * 1024 * 1024;

/// One input `$MFT` file's outcome. `record_count` is what actually reached the
/// output table; `error` is set only when the input itself could not be parsed,
/// and in that case the source's rows were rolled back.
#[derive(Debug, Clone)]
pub struct MftSourceReport {
    pub source: PathBuf,
    /// Internal per-source volume key written into every row of this source.
    pub volume_id: String,
    pub record_count: usize,
    pub error: Option<String>,
}

/// Input-format failures are per source (rolled back, reported); storage
/// failures abort the whole run — the output database is no longer trustworthy.
enum SourceFailure {
    Input(String),
    Storage(anyhow::Error),
}

fn storage(error: rusqlite::Error) -> SourceFailure {
    SourceFailure::Storage(anyhow::Error::from(error))
}

/// `$Volume` facts. Everything stays `None` unless the record really carried
/// the attribute — the serial number and the drive letter are not in `$MFT` at
/// all, so they are never filled here.
#[derive(Debug, Default, Clone)]
struct VolumeFacts {
    label: Option<String>,
    ntfs_major: Option<i64>,
    ntfs_minor: Option<i64>,
    flags: Option<String>,
}

/// $STANDARD_INFORMATION values kept for a row.
struct StandardInfo {
    timestamps: [String; 4],
    owner_id: u32,
    security_id: u32,
}

/// Missing or undecodable unnamed DATA remains unavailable.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum DataShape {
    #[default]
    Absent,
    Resident,
    ResidentEmpty,
    NonResident,
}

impl DataShape {
    fn as_str(self) -> &'static str {
        match self {
            DataShape::Absent => "unavailable",
            DataShape::Resident => "resident",
            DataShape::ResidentEmpty => "resident_empty",
            DataShape::NonResident => "nonresident",
        }
    }
}

/// Everything pass 2 needs from one record's attributes.
#[derive(Default)]
struct RecordFacts {
    name: Option<FileNameAttr>,
    standard_info: Option<StandardInfo>,
    /// Size of the unnamed $DATA: non-resident `file_size`, resident `data_size`.
    data_size: Option<u64>,
    /// Body of the unnamed *resident* $DATA. `None` = non-resident or absent;
    /// `Some(empty)` = a real zero-byte resident body.
    data: Option<Vec<u8>>,
    data_shape: DataShape,
}

/// $FILE_NAME namespace priority: Win32/Win32AndDos > POSIX > DOS.
fn namespace_priority(namespace: &FileNamespace) -> i32 {
    match namespace {
        FileNamespace::Win32 | FileNamespace::Win32AndDos => 3,
        FileNamespace::POSIX => 2,
        FileNamespace::DOS => 1,
    }
}

/// Header identity is retained even without a readable FILE_NAME.
struct IndexEntry {
    name: String,
    /// Namespace priority of `name`; -1 when the record had none.
    priority: i32,
    parent: Option<(u64, u16)>,
    sequence: u16,
    is_directory: bool,
}

/// Decode only FILE_NAME; pass 1 never reads resident bodies of base records.
fn index_entry(entry: &mft::MftEntry) -> IndexEntry {
    let mut best: Option<(i32, String, u64, u16)> = None;
    for attr in entry
        .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
        .filter_map(|a| a.ok())
    {
        if let MftAttributeContent::AttrX30(f) = attr.data {
            let priority = namespace_priority(&f.namespace);
            if best.as_ref().map_or(true, |(p, _, _, _)| priority > *p) {
                best = Some((priority, f.name, f.parent.entry, f.parent.sequence));
            }
        }
    }
    let (priority, name, parent) = best.map_or_else(
        || (-1, String::new(), None),
        |(priority, name, entry, sequence)| (priority, name, Some((entry, sequence))),
    );
    IndexEntry {
        name,
        priority,
        parent,
        sequence: entry.header.sequence,
        is_directory: entry.header.flags.bits() & FLAG_DIRECTORY != 0,
    }
}

/// Extension record (attributes moved out via $ATTRIBUTE_LIST): its record
/// number, the base sequence its header points at, and its attributes.
struct Extension {
    record: u64,
    base_sequence: u16,
    facts: RecordFacts,
}

/// Fold an extension record's attributes into its base record's facts.
/// The base keeps what it already carries; $FILE_NAME follows namespace
/// priority; $DATA size/body come from whichever record holds them.
fn absorb(facts: &mut RecordFacts, ext: RecordFacts) {
    if let Some(name) = ext.name {
        let better = facts
            .name
            .as_ref()
            .map_or(true, |cur| namespace_priority(&name.namespace) > namespace_priority(&cur.namespace));
        if better {
            facts.name = Some(name);
        }
    }
    if facts.standard_info.is_none() {
        facts.standard_info = ext.standard_info;
    }
    if facts.data_size.is_none() {
        facts.data_size = ext.data_size;
    }
    if facts.data_shape == DataShape::Absent {
        facts.data_shape = ext.data_shape;
        facts.data = ext.data;
    }
}

/// Best $FILE_NAME, the $STANDARD_INFORMATION values, and the unnamed $DATA
/// size, shape and resident body, in a single attribute pass.
///
/// The size comes from the unnamed $DATA (0x80) attribute — non-resident: its
/// `file_size`; resident (small files stored inline): its `data_size`. The
/// $FILE_NAME size fields are NOT authoritative: NTFS only refreshes them when
/// the filename attribute itself is rewritten, so for most files they sit at 0
/// (or a stale value) even though the file has data. Named $DATA streams are
/// alternate data streams: neither their size nor their body belongs to the
/// file itself, so they are skipped.
fn extract(entry: &mft::MftEntry) -> RecordFacts {
    let mut facts = RecordFacts::default();
    let mut best_priority: i32 = -1;

    for attr in entry.iter_attributes().filter_map(|a| a.ok()) {
        if attr.header.type_code == MftAttributeType::DATA && attr.header.name.is_empty() {
            match &attr.header.residential_header {
                ResidentialHeader::NonResident(nr) => {
                    // Only the segment starting at VCN 0 carries the sizes;
                    // later run segments (often in extension records) hold 0.
                    if facts.data_size.is_none() && nr.vnc_first == 0 {
                        facts.data_size = Some(nr.file_size);
                    }
                    if facts.data_shape == DataShape::Absent {
                        facts.data_shape = DataShape::NonResident;
                    }
                }
                ResidentialHeader::Resident(r) => {
                    if facts.data_size.is_none() {
                        facts.data_size = Some(u64::from(r.data_size));
                    }
                    // A decoded empty body is evidence; an unread body is not.
                    if facts.data.is_none() {
                        if let MftAttributeContent::AttrX80(body) = &attr.data {
                            let bytes = body.data();
                            facts.data_shape = if bytes.is_empty() {
                                DataShape::ResidentEmpty
                            } else {
                                DataShape::Resident
                            };
                            facts.data = Some(bytes.to_vec());
                        }
                    }
                }
            }
            continue;
        }
        match attr.data {
            MftAttributeContent::AttrX10(s) => {
                facts.standard_info = Some(StandardInfo {
                    timestamps: [
                        fmt_kst_ft(s.created),
                        fmt_kst_ft(s.modified),
                        fmt_kst_ft(s.mft_modified),
                        fmt_kst_ft(s.accessed),
                    ],
                    owner_id: s.owner_id,
                    security_id: s.security_id,
                });
            }
            MftAttributeContent::AttrX30(f) => {
                let priority = namespace_priority(&f.namespace);
                if priority > best_priority {
                    best_priority = priority;
                    facts.name = Some(f);
                }
            }
            _ => {}
        }
    }
    facts
}

/// UTF-16LE attribute text ($VOLUME_NAME). Odd trailing byte and padding NULs
/// are dropped; the bytes themselves are not otherwise reinterpreted.
fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\u{0}')
        .to_string()
}

/// Volume facts from reserved record 3. The `mft` crate leaves 0x60/0x70 as raw
/// attributes, so the documented layouts are read here:
/// $VOLUME_NAME = UTF-16LE label; $VOLUME_INFORMATION = 8 reserved bytes, major
/// version u8, minor version u8, flags u16.
/// Returns `None` when the record is not `$Volume` or carries neither
/// attribute — unknown volume metadata stays NULL instead of being guessed.
fn volume_facts(entry: &mft::MftEntry) -> Option<VolumeFacts> {
    let mut facts = VolumeFacts::default();
    let mut has_name = false;
    let mut is_volume_record = false;

    for attr in entry.iter_attributes().filter_map(|a| a.ok()) {
        match (&attr.header.type_code, &attr.data) {
            (MftAttributeType::VolumeName, MftAttributeContent::Raw(raw)) => {
                facts.label = Some(utf16le(&raw.data));
            }
            (MftAttributeType::VolumeInformation, MftAttributeContent::Raw(raw)) => {
                if raw.data.len() >= 12 {
                    facts.ntfs_major = Some(i64::from(raw.data[8]));
                    facts.ntfs_minor = Some(i64::from(raw.data[9]));
                    let bits = u16::from_le_bytes([raw.data[10], raw.data[11]]);
                    facts.flags = Some(format!("0x{:04X}", bits));
                }
            }
            (MftAttributeType::FileName, MftAttributeContent::AttrX30(f)) => {
                has_name = true;
                if f.name.eq_ignore_ascii_case(VOLUME_RECORD_NAME) {
                    is_volume_record = true;
                }
            }
            _ => {}
        }
    }

    if has_name && !is_volume_record {
        return None;
    }
    if facts.label.is_none() && facts.ntfs_major.is_none() {
        return None;
    }
    Some(facts)
}

/// How a record's parent reference checked out, written to `parent_status`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParentStatus {
    /// Record 5 of this input, and really a directory.
    Root,
    /// The referenced record exists in this input, carries the referenced
    /// sequence and is a directory.
    Verified,
    /// No record with that number in this input.
    Missing,
    /// The record is there but at another sequence: the slot was reused, so
    /// the reference points at a file that no longer exists.
    SequenceMismatch,
    /// The referenced record is not a directory and cannot hold children.
    NotDirectory,
    /// A direct self-reference; ancestor loops belong to path_status.
    Cycle,
    /// No $FILE_NAME: the record carries no parent reference at all.
    Unknown,
}

impl ParentStatus {
    fn as_str(self) -> &'static str {
        match self {
            ParentStatus::Root => "root",
            ParentStatus::Verified => "verified",
            ParentStatus::Missing => "missing",
            ParentStatus::SequenceMismatch => "sequence_mismatch",
            ParentStatus::NotDirectory => "not_directory",
            ParentStatus::Cycle => "cycle",
            ParentStatus::Unknown => "unknown",
        }
    }
}

/// How much of the path could be rebuilt from verified links, written to
/// `path_status`. Only `Complete` means every link up to the real root was
/// verified; everything else keeps the `\$Orphan` presentation and says why.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathStatus {
    Complete,
    Orphan,
    SequenceMismatch,
    NotDirectory,
    Cycle,
    Unknown,
}

impl PathStatus {
    fn as_str(self) -> &'static str {
        match self {
            PathStatus::Complete => "complete",
            PathStatus::Orphan => "orphan",
            PathStatus::SequenceMismatch => "sequence_mismatch",
            PathStatus::NotDirectory => "not_directory",
            PathStatus::Cycle => "cycle",
            PathStatus::Unknown => "unknown",
        }
    }

    /// The reason a parent link could not be used, as a path state.
    fn of_parent(status: ParentStatus) -> PathStatus {
        match status {
            ParentStatus::Root | ParentStatus::Verified => PathStatus::Complete,
            ParentStatus::Missing => PathStatus::Orphan,
            ParentStatus::SequenceMismatch => PathStatus::SequenceMismatch,
            ParentStatus::NotDirectory => PathStatus::NotDirectory,
            ParentStatus::Cycle => PathStatus::Cycle,
            ParentStatus::Unknown => PathStatus::Unknown,
        }
    }
}

/// Presentation of a path that could not be rooted. Kept as is; the row's
/// `path_status` carries the reason.
const ORPHAN_PATH: &str = "\\$Orphan";

/// Validate one parent link inside one input: the referenced record must exist
/// here, its own sequence must match the reference (otherwise the slot was
/// reused by another file) and it must be a directory.
fn check_parent(
    index: &HashMap<u64, IndexEntry>,
    record: u64,
    parent: u64,
    sequence: u16,
) -> ParentStatus {
    match index.get(&parent) {
        None => ParentStatus::Missing,
        Some(p) if p.sequence != sequence => ParentStatus::SequenceMismatch,
        Some(_) if parent == record => ParentStatus::Cycle,
        Some(p) if !p.is_directory => ParentStatus::NotDirectory,
        Some(_) => ParentStatus::Verified,
    }
}

/// One resolved directory path. `Rc` so every child reuses the prefix bytes
/// instead of copying the whole parent path per row.
#[derive(Clone)]
struct Resolved {
    path: Rc<str>,
    status: PathStatus,
}

/// Iterative parent-chain resolver with a per-input cache. Iterative on
/// purpose: a crafted $MFT can chain parents arbitrarily deep, which would
/// blow the stack in a recursive walk. Only directories are ever cached, so
/// the cache stays bounded by the input's directory count, and the root is
/// resolved like any other link instead of being seeded past its checks.
struct PathResolver {
    cache: HashMap<u64, Resolved>,
    stack: Vec<u64>,
    seen: HashSet<u64>,
    orphan: Rc<str>,
    root: Rc<str>,
}

impl PathResolver {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            stack: Vec::new(),
            seen: HashSet::new(),
            orphan: Rc::from(ORPHAN_PATH),
            // The root contributes no name; children join onto it directly.
            root: Rc::from(""),
        }
    }

    fn orphaned(&self, status: PathStatus) -> Resolved {
        Resolved {
            path: self.orphan.clone(),
            status,
        }
    }

    /// Path of a directory used as a parent. A chain only terminates at record
    /// 5 when that record is really a directory in this input.
    fn resolve(&mut self, start: u64, index: &HashMap<u64, IndexEntry>) -> Resolved {
        if let Some(hit) = self.cache.get(&start) {
            return hit.clone();
        }
        self.stack.clear();
        self.seen.clear();
        let mut current = start;
        let base = loop {
            if let Some(hit) = self.cache.get(&current) {
                break hit.clone();
            }
            let node = match index.get(&current) {
                Some(node) => node,
                None => break self.orphaned(PathStatus::Orphan),
            };
            if current == ROOT_ENTRY && node.is_directory {
                break Resolved {
                    path: self.root.clone(),
                    status: PathStatus::Complete,
                };
            }
            let Some((parent, sequence)) = node.parent else {
                break self.orphaned(PathStatus::Unknown);
            };
            if !self.seen.insert(current) {
                return self.poison();
            }
            self.stack.push(current);
            match check_parent(index, current, parent, sequence) {
                ParentStatus::Verified => current = parent,
                ParentStatus::Cycle => return self.poison(),
                other => break self.orphaned(PathStatus::of_parent(other)),
            }
        };
        self.unwind(base, index)
    }

    /// A loop: no entry on the walked chain has a usable path. Caching the
    /// whole chain keeps the next record from walking it again.
    fn poison(&mut self) -> Resolved {
        let cycled = self.orphaned(PathStatus::Cycle);
        for entry in self.stack.drain(..) {
            self.cache.insert(entry, cycled.clone());
        }
        cycled
    }

    /// Build the walked chain top-down, caching every directory on the way.
    fn unwind(&mut self, base: Resolved, index: &HashMap<u64, IndexEntry>) -> Resolved {
        let mut current = base;
        while let Some(entry) = self.stack.pop() {
            let name = index.get(&entry).map_or("", |node| node.name.as_str());
            if !name.is_empty() {
                current = Resolved {
                    path: Rc::from(format!("{}\\{}", current.path, name)),
                    status: current.status,
                };
            }
            self.cache.insert(entry, current.clone());
        }
        current
    }
}

/// Internal volume key for one source. Derived from the source path so a given
/// input keeps the same key across runs, and never from the volume label or a
/// serial number — two inputs are only the same volume when they are the same
/// path. Callers combining several databases may requalify it; nothing here
/// claims it is an NTFS volume serial.
fn volume_key(source: &Path, taken: &mut HashSet<String>) -> String {
    let text = source.to_string_lossy();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let base = format!("vol-{:016x}", hash);
    let mut key = base.clone();
    let mut n = 1;
    while !taken.insert(key.clone()) {
        key = format!("{}-{}", base, n);
        n += 1;
    }
    key
}

fn create_schema(conn: &Connection) -> Result<()> {
    let table = quote_ident(MFT_TABLE);
    conn.execute(&format!("DROP TABLE IF EXISTS {}", table), [])?;
    // Keep the existing field order and append reference/state evidence.
    conn.execute_batch(&format!(
        "CREATE TABLE {table} (
  \"volume_id\" TEXT NOT NULL,
  \"volume_label\" TEXT,
  \"volume_serial\" TEXT,
  \"drive_letter\" TEXT,
  \"ntfs_major_version\" INTEGER,
  \"ntfs_minor_version\" INTEGER,
  \"volume_flags\" TEXT,
  \"path\" TEXT,
  \"file_name\" TEXT,
  \"extension\" TEXT,
  \"is_directory\" INTEGER,
  \"in_use\" INTEGER,
  \"file_size\" INTEGER,
  \"data\" BLOB,
  \"entry\" INTEGER,
  \"seq\" INTEGER,
  \"parent_entry\" INTEGER,
  \"si_created\" TEXT,
  \"si_modified\" TEXT,
  \"si_mft_modified\" TEXT,
  \"si_accessed\" TEXT,
  \"owner_id\" TEXT,
  \"security_id\" TEXT,
  \"fn_created\" TEXT,
  \"fn_modified\" TEXT,
  \"fn_mft_modified\" TEXT,
  \"fn_accessed\" TEXT,
  \"_source_file\" TEXT NOT NULL,
  \"parent_seq\" INTEGER,
  \"parent_status\" TEXT,
  \"path_status\" TEXT,
  \"data_status\" TEXT,
  CHECK (is_directory IN (0,1)),
  CHECK (in_use IN (0,1)),
  CHECK (file_size IS NULL OR (typeof(file_size) = 'integer' AND file_size >= 0)),
  CHECK (data IS NULL OR typeof(data) = 'blob'),
  CHECK (parent_seq IS NULL OR (typeof(parent_seq) = 'integer' AND parent_seq >= 0)),
  CHECK (parent_status IS NULL OR parent_status IN
    ('root','verified','missing','sequence_mismatch','not_directory','cycle','unknown')),
  CHECK (path_status IS NULL OR path_status IN
    ('complete','orphan','sequence_mismatch','not_directory','cycle','unknown')),
  CHECK (data_status IS NULL OR data_status IN
    ('resident','resident_empty','nonresident','unavailable','not_applicable'))
)",
        table = table
    ))?;
    Ok(())
}

/// 뷰어의 폴더 자식 페이지 조회·레코드 참조가 대형 MFT에서 요청마다 전수
/// 필터·정렬을 반복하지 않도록, 뷰 가공 준비는 파싱 단계에서 한다는 협약대로
/// 여기서 인덱스를 만든다. 둘 다 volume_id로 시작해 볼륨별로 분리된다.
fn create_indexes(conn: &Connection) -> Result<()> {
    let table = quote_ident(MFT_TABLE);
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS idx_mft_children ON {table}(volume_id, parent_entry, is_directory, file_name COLLATE NOCASE);
         CREATE INDEX IF NOT EXISTS idx_mft_reference ON {table}(volume_id, entry, seq);",
        table = table
    ))?;
    Ok(())
}

fn insert_sql() -> String {
    let columns = MFT_FIELD_ORDER
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (1..=MFT_FIELD_ORDER.len())
        .map(|i| format!("?{}", i))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_ident(MFT_TABLE),
        columns,
        placeholders
    )
}

fn nullable(text: String) -> Option<String> {
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Parse one `$MFT` into the already-created table under `volume_id`.
fn stream_source(
    conn: &Connection,
    source: &Path,
    volume_id: &str,
) -> std::result::Result<usize, SourceFailure> {
    let mut parser =
        MftParser::from_path(source).map_err(|e| SourceFailure::Input(e.to_string()))?;

    // pass 1: entry -> name, raw parent reference and own identity, for path
    // resolution and parent validation, plus $Volume. Extension records are
    // collected whole: their attributes belong to the base record.
    let mut index: HashMap<u64, IndexEntry> = HashMap::new();
    let mut volume = VolumeFacts::default();
    let mut extensions: HashMap<u64, Vec<Extension>> = HashMap::new();
    for entry in parser.iter_entries() {
        if crate::pipeline::cancelled() {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.header.record_number == VOLUME_ENTRY {
            if let Some(facts) = volume_facts(&entry) {
                volume = facts;
            }
        }
        if entry.header.signature == *b"FILE" {
            let base = &entry.header.base_reference;
            // Only an all-zero reference marks a base record ($MFT's own
            // extensions point at entry 0 with a nonzero sequence).
            if base.entry != 0 || base.sequence != 0 {
                extensions.entry(base.entry).or_default().push(Extension {
                    record: entry.header.record_number,
                    base_sequence: base.sequence,
                    facts: extract(&entry),
                });
            }
            index.insert(entry.header.record_number, index_entry(&entry));
        }
    }

    // An extension belongs to its base only when the base slot still holds
    // the same sequence and is not itself an extension; anything else is a
    // leftover of an earlier occupant and stays a row of its own.
    let extension_records: HashSet<u64> = extensions.values().flatten().map(|e| e.record).collect();
    let mut merged: HashSet<u64> = HashSet::new();
    for (base, list) in extensions.iter_mut() {
        let Some(base_sequence) = index.get(base).map(|b| b.sequence) else {
            list.clear();
            continue;
        };
        if extension_records.contains(base) {
            list.clear();
            continue;
        }
        list.retain(|e| e.base_sequence == base_sequence);
        list.sort_by_key(|e| e.record);
        for ext in list.iter() {
            merged.insert(ext.record);
            // A directory's name may live only in an extension: children
            // resolve their paths through it.
            if let Some(f) = &ext.facts.name {
                let priority = namespace_priority(&f.namespace);
                let entry = index.get_mut(base).expect("base checked above");
                if priority > entry.priority {
                    entry.priority = priority;
                    entry.name = f.name.clone();
                    entry.parent = Some((f.parent.entry, f.parent.sequence));
                }
            }
        }
    }
    extensions.retain(|_, list| !list.is_empty());

    let mut resolver = PathResolver::new();
    let source_text = source.to_string_lossy().to_string();

    let sql = insert_sql();
    let mut stmt = conn.prepare(&sql).map_err(storage)?;
    conn.execute_batch("BEGIN").map_err(storage)?;
    let mut total = 0usize;
    let mut pending = 0usize;
    let mut pending_bytes = 0usize;

    // pass 2: build + insert each row.
    for entry in parser.iter_entries() {
        if crate::pipeline::cancelled() {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let header = &entry.header;
        let record = header.record_number;
        if merged.contains(&record) {
            continue;
        }
        let in_use = i64::from(header.flags.bits() & FLAG_IN_USE != 0);
        let is_directory = header.flags.bits() & FLAG_DIRECTORY != 0;
        let mut facts = extract(&entry);
        for ext in extensions.remove(&record).unwrap_or_default() {
            absorb(&mut facts, ext.facts);
        }
        if facts.name.is_none() && facts.standard_info.is_none() {
            continue;
        }

        let (name, parent, parent_seq, fn_size, fn_times) = match &facts.name {
            Some(f) => (
                Some(f.name.clone()),
                Some(f.parent.entry),
                // The sequence the reference was taken at is evidence of its
                // own: keep it even when the reference turns out to be stale.
                Some(f.parent.sequence),
                Some(f.physical_size),
                [
                    fmt_kst_ft(f.created),
                    fmt_kst_ft(f.modified),
                    fmt_kst_ft(f.mft_modified),
                    fmt_kst_ft(f.accessed),
                ],
            ),
            None => (
                None,
                None,
                None,
                None,
                [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
            ),
        };

        // Only directory record 5 is the root; a "." name is insufficient.
        let (parent_status, path_status, path): (ParentStatus, PathStatus, String) =
            if record == ROOT_ENTRY && is_directory {
                (ParentStatus::Root, PathStatus::Complete, "\\".into())
            } else if let (Some(parent_entry), Some(sequence)) = (parent, parent_seq) {
                let status = check_parent(&index, record, parent_entry, sequence);
                let base = match status {
                    ParentStatus::Verified => resolver.resolve(parent_entry, &index),
                    other => resolver.orphaned(PathStatus::of_parent(other)),
                };
                let path = match name.as_deref() {
                    Some(n) if !n.is_empty() => format!("{}\\{}", base.path, n),
                    _ if base.path.is_empty() => "\\".into(),
                    _ => base.path.to_string(),
                };
                (status, base.status, path)
            } else {
                // No FILE_NAME means no parent reference or name.
                (
                    ParentStatus::Unknown,
                    PathStatus::Unknown,
                    ORPHAN_PATH.into(),
                )
            };

        // $DATA is authoritative; fall back to $FILE_NAME only when there is no
        // $DATA attribute at all (e.g. a directory, or a record whose data
        // attribute lives in an extension record). Directories carry no body.
        let size = if is_directory {
            Some(0u64)
        } else {
            facts.data_size.or(fn_size)
        };
        // A size above i64::MAX cannot be an SQLite INTEGER. Store NULL rather
        // than a truncated value that would misstate the evidence.
        let file_size = size.and_then(|v| i64::try_from(v).ok());

        let extension = name.as_deref().map(|n| {
            if is_directory {
                String::new()
            } else {
                match n.rfind('.') {
                    Some(d) if d > 0 => n[d + 1..].to_lowercase(),
                    _ => String::new(),
                }
            }
        });

        let (si_times, owner_id, security_id) = match facts.standard_info {
            Some(info) => (
                info.timestamps,
                Some(info.owner_id.to_string()),
                Some(info.security_id.to_string()),
            ),
            None => (
                [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                None,
                None,
            ),
        };
        let [si_created, si_modified, si_mft_modified, si_accessed] = si_times;
        let [fn_created, fn_modified, fn_mft_modified, fn_accessed] = fn_times;

        // A directory has no body of its own; every other record reports what
        // its unnamed $DATA actually carried.
        let data_status = if is_directory {
            "not_applicable"
        } else {
            facts.data_shape.as_str()
        };
        let body_len = facts.data.as_ref().map_or(0, |b| b.len());
        stmt.execute(rusqlite::params![
            volume_id,
            volume.label,
            // The NTFS serial and the drive letter are not in $MFT: they need
            // collection metadata or a boot sector, so they stay NULL here.
            None::<String>,
            None::<String>,
            volume.ntfs_major,
            volume.ntfs_minor,
            volume.flags,
            &*path,
            name,
            extension,
            i64::from(is_directory),
            in_use,
            file_size,
            facts.data,
            record as i64,
            i64::from(header.sequence),
            parent.map(|p| p as i64),
            nullable(si_created),
            nullable(si_modified),
            nullable(si_mft_modified),
            nullable(si_accessed),
            // NTFS $STANDARD_INFORMATION owner/security IDs are numeric
            // metadata, not account names. Preserve them verbatim; do not
            // resolve them to a SID or a user account here.
            owner_id,
            security_id,
            nullable(fn_created),
            nullable(fn_modified),
            nullable(fn_mft_modified),
            nullable(fn_accessed),
            source_text,
            parent_seq.map(i64::from),
            parent_status.as_str(),
            path_status.as_str(),
            data_status,
        ])
        .map_err(storage)?;

        total += 1;
        pending += 1;
        pending_bytes += body_len;
        if pending >= BATCH_ROWS || pending_bytes >= BATCH_BYTES {
            conn.execute_batch("COMMIT").map_err(storage)?;
            conn.execute_batch("BEGIN").map_err(storage)?;
            pending = 0;
            pending_bytes = 0;
        }
    }
    conn.execute_batch("COMMIT").map_err(storage)?;
    Ok(total)
}

/// Parse every `$MFT` input into one output database. Each source gets its own
/// `volume_id`, path index and path cache; a source whose input cannot be
/// parsed is rolled back and reported instead of aborting the others. Storage
/// failures propagate — a half-written output is not reported as success.
pub fn parse_mft_sources(sources: &[PathBuf], out: &Path) -> Result<Vec<MftSourceReport>> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(out)?;
    // A rollback journal is required (per-source rollback); keep it in memory
    // and skip fsync — the output is a derived artifact, rebuilt on failure.
    conn.pragma_update(None, "journal_mode", "MEMORY").ok();
    conn.pragma_update(None, "synchronous", "OFF").ok();
    create_schema(&conn)?;

    let mut taken: HashSet<String> = HashSet::new();
    let mut reports: Vec<MftSourceReport> = Vec::with_capacity(sources.len());
    for source in sources {
        let volume_id = volume_key(source, &mut taken);
        let report = match stream_source(&conn, source, &volume_id) {
            Ok(record_count) => MftSourceReport {
                source: source.clone(),
                volume_id,
                record_count,
                error: None,
            },
            Err(SourceFailure::Input(message)) => {
                // Roll the open transaction back, then drop whatever earlier
                // batches committed: a reported failure must leave no rows.
                let _ = conn.execute_batch("ROLLBACK");
                conn.execute(
                    &format!(
                        "DELETE FROM {} WHERE volume_id = ?1",
                        quote_ident(MFT_TABLE)
                    ),
                    rusqlite::params![volume_id],
                )?;
                MftSourceReport {
                    source: source.clone(),
                    volume_id,
                    record_count: 0,
                    error: Some(message),
                }
            }
            Err(SourceFailure::Storage(error)) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        reports.push(report);
    }
    create_indexes(&conn)?;
    Ok(reports)
}

/// Single-source entry point (CLI, single-input pipelines). Same work as
/// `parse_mft_sources` with one path; an unparsable input is an error here
/// because there is no report to carry it.
pub fn parse_mft_stream(mft_path: &Path, out: &Path) -> Result<usize> {
    let sources = vec![mft_path.to_path_buf()];
    let report = parse_mft_sources(&sources, out)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("MFT 파싱 보고가 비어 있습니다: {}", mft_path.display()))?;
    match report.error {
        Some(message) => Err(anyhow!(message)),
        None => Ok(report.record_count),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::types::ValueRef;

    const ENTRY_SIZE: usize = 1024;
    const FIRST_ATTR_OFFSET: usize = 56;
    /// 2020-09-13 12:26:40 UTC = 2020-09-13 21:26:40 KST.
    const FT_SI: u64 = 132_444_736_000_000_000;
    /// 2020-09-14 12:26:40 UTC = 2020-09-14 21:26:40 KST.
    const FT_FN: u64 = 132_445_600_000_000_000;
    /// Sequence of the fixture root record (5). Parent references must carry
    /// exactly this sequence to be accepted as a reference to the root.
    const ROOT_SEQ: u16 = 5;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-mft-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(buf: &mut [u8], offset: usize, bytes: &[u8]) {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Resident attribute record: 24-byte header (+ UTF-16LE name) then the
    /// value, which is where the `mft` crate reads it from.
    fn resident_attr(type_code: u32, name: &str, body: &[u8]) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let value_offset = 24 + name_units.len() * 2;
        let length = (value_offset + body.len()).div_ceil(8) * 8;
        let mut attr = vec![0u8; length];
        put(&mut attr, 0, &type_code.to_le_bytes());
        put(&mut attr, 4, &(length as u32).to_le_bytes());
        attr[8] = 0; // resident
        attr[9] = name_units.len() as u8;
        put(
            &mut attr,
            10,
            &(if name_units.is_empty() { 0u16 } else { 24u16 }).to_le_bytes(),
        );
        put(&mut attr, 16, &(body.len() as u32).to_le_bytes());
        put(&mut attr, 20, &(value_offset as u16).to_le_bytes());
        for (i, unit) in name_units.iter().enumerate() {
            put(&mut attr, 24 + i * 2, &unit.to_le_bytes());
        }
        put(&mut attr, value_offset, body);
        attr
    }

    /// Non-resident unnamed $DATA: only the header, the body lives on disk.
    fn nonresident_data_attr(file_size: u64) -> Vec<u8> {
        let length = 72usize;
        let mut attr = vec![0u8; length];
        put(&mut attr, 0, &0x80u32.to_le_bytes());
        put(&mut attr, 4, &(length as u32).to_le_bytes());
        attr[8] = 1; // non-resident
        put(&mut attr, 32, &64u16.to_le_bytes()); // datarun offset
        put(&mut attr, 40, &file_size.to_le_bytes()); // allocated
        put(&mut attr, 48, &file_size.to_le_bytes()); // file size
        put(&mut attr, 56, &file_size.to_le_bytes()); // valid data
        attr
    }

    /// A later run segment of a non-resident unnamed $DATA: NTFS only fills
    /// the size fields in the segment starting at VCN 0.
    fn data_segment(first_vcn: u64, file_size: u64) -> Vec<u8> {
        let mut attr = nonresident_data_attr(file_size);
        put(&mut attr, 16, &first_vcn.to_le_bytes());
        put(&mut attr, 24, &(first_vcn + 1).to_le_bytes());
        attr
    }

    /// Extension record: its header points back at the base record.
    fn extension_record(sequence: u16, base: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut record = mft_record(sequence, 0x01, attrs);
        put(&mut record, 32, &base.to_le_bytes());
        record
    }

    fn standard_info_body(owner_id: u32, security_id: u32) -> Vec<u8> {
        let mut body = vec![0u8; 72];
        put(&mut body, 0, &FT_SI.to_le_bytes()); // created
        // modified / mft_modified / accessed stay 0 (unset FILETIME -> NULL).
        put(&mut body, 48, &owner_id.to_le_bytes());
        put(&mut body, 52, &security_id.to_le_bytes());
        body
    }

    fn file_name_body(parent_ref: u64, namespace: u8, name: &str, physical_size: u64) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut body = vec![0u8; 66 + units.len() * 2];
        put(&mut body, 0, &parent_ref.to_le_bytes());
        put(&mut body, 8, &FT_FN.to_le_bytes()); // created
        // the other three FN timestamps stay unset.
        put(&mut body, 40, &physical_size.to_le_bytes()); // logical
        put(&mut body, 48, &physical_size.to_le_bytes()); // physical
        body[64] = units.len() as u8;
        body[65] = namespace;
        for (i, unit) in units.iter().enumerate() {
            put(&mut body, 66 + i * 2, &unit.to_le_bytes());
        }
        body
    }

    /// 8-byte MFT reference as written in $FILE_NAME: 6-byte entry number plus
    /// the 2-byte sequence the reference was taken at.
    fn mft_ref(entry: u64, sequence: u16) -> u64 {
        entry | ((sequence as u64) << 48)
    }

    /// `parent` is a full reference (see `mft_ref`), not a bare entry number.
    fn file_name_attr(parent: u64, name: &str, physical_size: u64) -> Vec<u8> {
        resident_attr(0x30, "", &file_name_body(parent, 1, name, physical_size))
    }

    fn si() -> Vec<u8> {
        resident_attr(0x10, "", &standard_info_body(0, 256))
    }

    /// One 1024-byte FILE record with a valid update sequence array.
    fn mft_record(sequence: u16, flags: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut record = vec![0u8; ENTRY_SIZE];
        put(&mut record, 0, b"FILE");
        put(&mut record, 4, &48u16.to_le_bytes()); // usa offset
        put(&mut record, 6, &3u16.to_le_bytes()); // usa size (1024/512 + 1)
        put(&mut record, 16, &sequence.to_le_bytes());
        put(&mut record, 18, &1u16.to_le_bytes()); // hard link count
        put(&mut record, 20, &(FIRST_ATTR_OFFSET as u16).to_le_bytes());
        put(&mut record, 22, &flags.to_le_bytes());
        put(&mut record, 28, &(ENTRY_SIZE as u32).to_le_bytes());

        let mut offset = FIRST_ATTR_OFFSET;
        for attr in attrs {
            put(&mut record, offset, attr);
            offset += attr.len();
        }
        put(&mut record, offset, &0xFFFF_FFFFu32.to_le_bytes());
        put(&mut record, 24, &((offset + 4) as u32).to_le_bytes()); // used size

        // Update sequence: the stride ends must hold the sequence value, and
        // are restored from the array entries (zero here).
        put(&mut record, 48, &1u16.to_le_bytes());
        put(&mut record, 510, &1u16.to_le_bytes());
        put(&mut record, 1022, &1u16.to_le_bytes());
        record
    }

    fn empty_record() -> Vec<u8> {
        vec![0u8; ENTRY_SIZE]
    }

    /// Record 0 ($MFT itself) fixes the entry size the parser guesses.
    fn mft_self_record() -> Vec<u8> {
        mft_record(
            1,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "$MFT", 0),
            ],
        )
    }

    fn write_mft(dir: &Path, name: &str, records: &[Vec<u8>]) -> PathBuf {
        let mut bytes = Vec::with_capacity(records.len() * ENTRY_SIZE);
        for record in records {
            assert_eq!(record.len(), ENTRY_SIZE);
            bytes.extend_from_slice(record);
        }
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    fn volume_record(label: &str, major: u8, minor: u8, flags: u16) -> Vec<u8> {
        let mut info = vec![0u8; 12];
        info[8] = major;
        info[9] = minor;
        put(&mut info, 10, &flags.to_le_bytes());
        let label_bytes: Vec<u8> = label
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        mft_record(
            1,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "$Volume", 0),
                resident_attr(0x60, "", &label_bytes),
                resident_attr(0x70, "", &info),
            ],
        )
    }

    /// Entries 1..=4 keep the reserved slots aligned; 3 is $Volume when given.
    fn filler(volume: Option<Vec<u8>>) -> Vec<Vec<u8>> {
        vec![
            empty_record(),
            empty_record(),
            volume.unwrap_or_else(empty_record),
            empty_record(),
        ]
    }

    fn root_record() -> Vec<u8> {
        mft_record(
            ROOT_SEQ,
            0x03,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), ".", 0),
            ],
        )
    }

    /// `$MFT`, the reserved slots, the real root record and then `extra`,
    /// whose records are numbered from 6.
    fn with_root(extra: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.extend(extra);
        records
    }

    fn query_one<T: rusqlite::types::FromSql>(db: &Path, sql: &str) -> T {
        let conn = Connection::open(db).unwrap();
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// (parent_entry, parent_seq, parent_status, path, path_status, data_status).
    type RowState = (Option<i64>, Option<i64>, String, String, String, String);

    fn row_state(db: &Path, filter: &str) -> RowState {
        let conn = Connection::open(db).unwrap();
        conn.query_row(
            &format!(
                "SELECT parent_entry, parent_seq, parent_status, path, path_status, data_status
                 FROM MFT_Records WHERE {filter}"
            ),
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .unwrap()
    }

    #[test]
    fn resident_unnamed_data_is_stored_as_blob_with_integer_size() {
        let dir = temp_dir("resident");
        let body = b"hello world".to_vec();
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(7, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "note.TXT", 0),
                resident_attr(0x80, "", &body),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        let count = parse_mft_stream(&src, &out).unwrap();
        assert!(count >= 3);

        let conn = Connection::open(&out).unwrap();
        let (data, size, ext, is_dir, in_use, owner, security, si_created, si_modified, fn_created): (
            Vec<u8>,
            i64,
            String,
            i64,
            i64,
            String,
            String,
            String,
            Option<String>,
            String,
        ) = conn
            .query_row(
                "SELECT data, file_size, extension, is_directory, in_use, owner_id, security_id, si_created, si_modified, fn_created
                 FROM MFT_Records WHERE file_name = 'note.TXT'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(data, body);
        assert_eq!(size, body.len() as i64);
        assert_eq!(ext, "txt");
        assert_eq!(is_dir, 0);
        assert_eq!(in_use, 1);
        assert_eq!(owner, "7");
        assert_eq!(security, "256");
        assert_eq!(si_created, "2020-09-13 21:26:40.000");
        assert_eq!(si_modified, None);
        assert_eq!(fn_created, "2020-09-14 21:26:40.000");

        // typeof proves the columns are real INTEGER/BLOB, not decimal strings.
        let types: (String, String) = conn
            .query_row(
                "SELECT typeof(file_size), typeof(data) FROM MFT_Records WHERE file_name = 'note.TXT'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(types, ("integer".to_string(), "blob".to_string()));

        let path: String = query_one(
            &out,
            "SELECT path FROM MFT_Records WHERE file_name = 'note.TXT'",
        );
        assert_eq!(path, "\\note.TXT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonresident_data_keeps_size_but_leaves_body_null() {
        let dir = temp_dir("nonresident");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "big.bin", 7),
                nonresident_data_attr(1_048_576),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (size, data_type): (i64, String) = conn
            .query_row(
                "SELECT file_size, typeof(data) FROM MFT_Records WHERE file_name = 'big.bin'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // The $FILE_NAME physical size (7) must not win over the real $DATA size.
        assert_eq!(size, 1_048_576);
        assert_eq!(data_type, "null");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attribute_list_extension_records_belong_to_their_base_record() {
        let dir = temp_dir("attr-list");
        let records = with_root(vec![
            // 6: base file whose $FILE_NAME/$DATA moved to extension 7.
            mft_record(2, 0x01, &[si()]),
            extension_record(1, mft_ref(6, 2), &[file_name_attr(mft_ref(5, ROOT_SEQ), "big.dll", 0), nonresident_data_attr(4096)]),
            // 8: extension written for an earlier occupant of slot 6 (seq 1).
            extension_record(1, mft_ref(6, 1), &[file_name_attr(mft_ref(5, ROOT_SEQ), "old.txt", 0)]),
            // 9: directory whose name lives in extension 10; 11 is its child.
            mft_record(1, 0x03, &[si()]),
            extension_record(1, mft_ref(9, 1), &[file_name_attr(mft_ref(5, ROOT_SEQ), "Dir", 0)]),
            mft_record(1, 0x01, &[si(), file_name_attr(mft_ref(9, 1), "c.txt", 0)]),
            // 12: fragmented $DATA — the VCN>0 segment comes first (13) and
            // carries no size; the VCN 0 segment (14) holds the real one.
            mft_record(1, 0x01, &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "frag.bin", 0)]),
            extension_record(1, mft_ref(12, 1), &[data_segment(5, 0)]),
            extension_record(1, mft_ref(12, 1), &[data_segment(0, 9999)]),
            // 15: extension of record 0 ($MFT, seq 1) — entry 0 with a
            // nonzero sequence is still an extension, never a row.
            extension_record(1, mft_ref(0, 1), &[file_name_attr(mft_ref(5, ROOT_SEQ), "$MFT", 0)]),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let base: (Option<String>, String, Option<i64>, String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT file_name, path, file_size, data_status, si_created, fn_created FROM MFT_Records WHERE entry = 6",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!((base.0.as_deref(), base.1.as_str(), base.2, base.3.as_str()), (Some("big.dll"), "\\big.dll", Some(4096), "nonresident"));
        assert!(base.4.is_some() && base.5.is_some(), "SI from the base, FN from the extension");
        // Merged extensions are not files of their own; a stale one stays as evidence.
        let entries: Vec<i64> = conn
            .prepare("SELECT entry FROM MFT_Records WHERE entry >= 6 ORDER BY entry")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(entries, vec![6, 8, 9, 11, 12]);
        assert_eq!(row_state(&out, "entry = 11").3, "\\Dir\\c.txt");
        assert_eq!(row_state(&out, "entry = 11").4, "complete");
        assert_eq!(query_one::<i64>(&out, "SELECT file_size FROM MFT_Records WHERE entry = 12"), 9999);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_resident_body_is_zero_length_blob_not_null() {
        let dir = temp_dir("empty-body");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "empty.log", 0),
                resident_attr(0x80, "", &[]),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (kind, length, size): (String, i64, i64) = conn
            .query_row(
                "SELECT typeof(data), length(data), file_size FROM MFT_Records WHERE file_name = 'empty.log'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "blob");
        assert_eq!(length, 0);
        assert_eq!(size, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn named_data_stream_is_not_taken_as_the_file_body() {
        let dir = temp_dir("ads");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "host.exe", 4096),
                resident_attr(0x80, "Zone.Identifier", b"[ZoneTransfer]"),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (kind, size): (String, i64) = conn
            .query_row(
                "SELECT typeof(data), file_size FROM MFT_Records WHERE file_name = 'host.exe'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(kind, "null");
        // No unnamed $DATA: the $FILE_NAME size is the only remaining evidence.
        assert_eq!(size, 4096);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn directory_and_unused_record_flags_are_integers() {
        let dir = temp_dir("flags");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x03, // allocated + directory
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "Windows", 0),
            ],
        ));
        records.push(mft_record(
            9,
            0x00, // deleted file record
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(42, 3), "gone.dat", 12),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (is_dir, in_use, size, ext, parent, seq): (i64, i64, i64, String, i64, i64) = conn
            .query_row(
                "SELECT is_directory, in_use, file_size, extension, parent_entry, seq
                 FROM MFT_Records WHERE file_name = 'Windows'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!((is_dir, in_use, size), (1, 1, 0));
        assert_eq!(ext, "");
        assert_eq!((parent, seq), (5, 4));
        // 'Windows' sits under the root with the sequence the root really has.
        assert_eq!(
            row_state(&out, "file_name = 'Windows'"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "verified".into(),
                "\\Windows".into(),
                "complete".into(),
                "not_applicable".into(),
            )
        );

        let (is_dir, in_use, path): (i64, i64, String) = conn
            .query_row(
                "SELECT is_directory, in_use, path FROM MFT_Records WHERE file_name = 'gone.dat'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((is_dir, in_use), (0, 0));
        // Parent 42 is not in this MFT, so the path is orphaned, not invented.
        assert_eq!(path, "\\$Orphan\\gone.dat");
        // The raw reference is kept even though it leads nowhere.
        assert_eq!(
            row_state(&out, "file_name = 'gone.dat'"),
            (
                Some(42),
                Some(3),
                "missing".into(),
                "\\$Orphan\\gone.dat".into(),
                "orphan".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_without_file_name_keeps_unknown_fields_null() {
        let dir = temp_dir("si-only");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[resident_attr(0x10, "", &standard_info_body(3, 42))],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (name, parent, ext, size, fn_created): (
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT file_name, parent_entry, extension, file_size, fn_created
                 FROM MFT_Records WHERE entry = 6",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(name, None);
        // Unknown parent is NULL — never -1 and never 0.
        assert_eq!(parent, None);
        assert_eq!(ext, None);
        assert_eq!(size, None);
        assert_eq!(fn_created, None);
        // No $FILE_NAME means no parent reference at all: nothing is guessed.
        assert_eq!(
            row_state(&out, "entry = 6"),
            (
                None,
                None,
                "unknown".into(),
                "\\$Orphan".into(),
                "unknown".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_record_fills_label_and_ntfs_version_for_every_row() {
        let dir = temp_dir("volume");
        let mut records = vec![mft_self_record()];
        records.extend(filler(Some(volume_record("SYSTEM", 3, 1, 0x0001))));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "a.txt", 0),
                resident_attr(0x80, "", b"x"),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let (label, major, minor, flags): (String, i64, i64, String) = conn
            .query_row(
                "SELECT volume_label, ntfs_major_version, ntfs_minor_version, volume_flags
                 FROM MFT_Records WHERE file_name = 'a.txt'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(label, "SYSTEM");
        assert_eq!((major, minor), (3, 1));
        assert_eq!(flags, "0x0001");

        // Every row of the source carries the same volume facts.
        let distinct: i64 = query_one(
            &out,
            "SELECT COUNT(DISTINCT volume_label) FROM MFT_Records",
        );
        assert_eq!(distinct, 1);

        // Serial and drive letter are not in $MFT: they stay NULL.
        let unknown: i64 = query_one(
            &out,
            "SELECT COUNT(*) FROM MFT_Records WHERE volume_serial IS NOT NULL OR drive_letter IS NOT NULL",
        );
        assert_eq!(unknown, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_volume_record_leaves_volume_fields_null() {
        let dir = temp_dir("no-volume");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let filled: i64 = query_one(
            &out,
            "SELECT COUNT(*) FROM MFT_Records
             WHERE volume_label IS NOT NULL OR ntfs_major_version IS NOT NULL
                OR ntfs_minor_version IS NOT NULL OR volume_flags IS NOT NULL",
        );
        assert_eq!(filled, 0);
        // volume_id is still present: it is an internal key, not volume metadata.
        let keys: i64 = query_one(
            &out,
            "SELECT COUNT(DISTINCT volume_id) FROM MFT_Records",
        );
        assert_eq!(keys, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_source_gets_its_own_volume_id_and_path_index() {
        let dir = temp_dir("multi");
        let build = |label: &str, file: &str| {
            let mut records = vec![mft_self_record()];
            records.extend(filler(Some(volume_record(label, 3, 1, 0x0000))));
            records.push(root_record());
            records.push(mft_record(
                4,
                0x03,
                &[
                    resident_attr(0x10, "", &standard_info_body(0, 256)),
                    file_name_attr(mft_ref(5, ROOT_SEQ), "Data", 0),
                ],
            ));
            records.push(mft_record(
                4,
                0x01,
                &[
                    resident_attr(0x10, "", &standard_info_body(0, 256)),
                    file_name_attr(mft_ref(6, 4), file, 0),
                    resident_attr(0x80, "", file.as_bytes()),
                ],
            ));
            records
        };
        let first = write_mft(&dir.join("c"), "$MFT", &build("SYSTEM", "c.txt"));
        let second = write_mft(&dir.join("d"), "$MFT", &build("DATA", "d.txt"));
        let out = dir.join("MFT_Records.sqlite");
        let reports = parse_mft_sources(&[first.clone(), second.clone()], &out).unwrap();

        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|r| r.error.is_none()));
        assert!(reports.iter().all(|r| r.record_count >= 4));
        assert_ne!(reports[0].volume_id, reports[1].volume_id);
        assert_eq!(reports[0].source, first);
        assert_eq!(reports[1].source, second);

        let conn = Connection::open(&out).unwrap();
        // Same entry numbers on both sources never merge.
        let per_volume: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM MFT_Records WHERE entry = 7 AND volume_id = ?1",
                rusqlite::params![reports[0].volume_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(per_volume, 1);

        let labels: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT DISTINCT volume_label FROM MFT_Records ORDER BY volume_label")
                .unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        };
        assert_eq!(labels, vec!["DATA".to_string(), "SYSTEM".to_string()]);

        // Path resolution stays inside each source: both files sit under \Data.
        let paths: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT path FROM MFT_Records WHERE file_name IN ('c.txt','d.txt') ORDER BY file_name")
                .unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        };
        assert_eq!(
            paths,
            vec!["\\Data\\c.txt".to_string(), "\\Data\\d.txt".to_string()]
        );

        let sources: i64 = query_one(
            &out,
            "SELECT COUNT(DISTINCT _source_file) FROM MFT_Records",
        );
        assert_eq!(sources, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_source_is_reported_without_rows_and_others_survive() {
        let dir = temp_dir("failure");
        let broken = dir.join("broken.mft");
        std::fs::write(&broken, vec![0x41u8; 2048]).unwrap();
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "ok.txt", 0),
            ],
        ));
        let good = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        let reports = parse_mft_sources(&[broken.clone(), good.clone()], &out).unwrap();

        assert_eq!(reports[0].source, broken);
        assert!(reports[0].error.is_some());
        assert_eq!(reports[0].record_count, 0);
        assert!(reports[1].error.is_none());
        assert!(reports[1].record_count >= 3);

        let conn = Connection::open(&out).unwrap();
        let orphans: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM MFT_Records WHERE volume_id = ?1",
                rusqlite::params![reports[0].volume_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0);
        let survivors: i64 = conn
            .query_row("SELECT COUNT(*) FROM MFT_Records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(survivors as usize, reports[1].record_count);

        // The single-file entry point still reports an unparsable input as an error.
        let single = dir.join("single.sqlite");
        assert!(parse_mft_stream(&broken, &single).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn schema_matches_the_approved_28_fields_and_rejects_bad_values() {
        let dir = temp_dir("schema");
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let mut stmt = conn
            .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info('MFT_Records')")
            .unwrap();
        let columns: Vec<(String, String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let names: Vec<&str> = columns.iter().map(|c| c.0.as_str()).collect();
        assert_eq!(names.as_slice(), MFT_FIELD_ORDER);
        // The approved 28 fields keep their order; the new state columns are
        // appended behind them.
        assert_eq!(names.len(), 32);
        assert_eq!(names[27], "_source_file");
        assert_eq!(
            &names[28..],
            &["parent_seq", "parent_status", "path_status", "data_status"]
        );
        let typed: HashMap<&str, &str> = columns
            .iter()
            .map(|c| (c.0.as_str(), c.1.as_str()))
            .collect();
        for integer in [
            "ntfs_major_version",
            "ntfs_minor_version",
            "is_directory",
            "in_use",
            "file_size",
            "entry",
            "seq",
            "parent_entry",
            "parent_seq",
        ] {
            assert_eq!(typed[integer], "INTEGER", "{integer}");
        }
        assert_eq!(typed["data"], "BLOB");
        assert_eq!(typed["owner_id"], "TEXT");
        for text in ["parent_status", "path_status", "data_status"] {
            assert_eq!(typed[text], "TEXT", "{text}");
        }
        for not_null in ["volume_id", "_source_file"] {
            let column = columns.iter().find(|c| c.0 == not_null).unwrap();
            assert_eq!(column.2, 1, "{not_null}");
        }

        let indexes: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='MFT_Records' ORDER BY name")
                .unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            rows
        };
        assert!(indexes.contains(&"idx_mft_children".to_string()));
        assert!(indexes.contains(&"idx_mft_reference".to_string()));

        // Documented CHECKs: flags are 0/1, sizes are non-negative integers.
        assert!(conn
            .execute(
                "INSERT INTO MFT_Records (volume_id, is_directory, _source_file) VALUES ('v', 2, 's')",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO MFT_Records (volume_id, file_size, _source_file) VALUES ('v', -1, 's')",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO MFT_Records (volume_id, file_size, _source_file) VALUES ('v', 'abc', 's')",
                [],
            )
            .is_err());

        // The root record keeps its own row with the root path.
        let root: String = query_one(&out, "SELECT path FROM MFT_Records WHERE entry = 5");
        assert_eq!(root, "\\");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_id_is_stable_for_a_source_and_never_derived_from_the_label() {
        let dir = temp_dir("volume-key");
        let mut records = vec![mft_self_record()];
        records.extend(filler(Some(volume_record("SYSTEM", 3, 1, 0x0000))));
        records.push(root_record());
        let first = write_mft(&dir.join("a"), "$MFT", &records);
        let second = write_mft(&dir.join("b"), "$MFT", &records);

        let out = dir.join("MFT_Records.sqlite");
        let run = parse_mft_sources(&[first.clone(), second.clone()], &out).unwrap();
        let again = parse_mft_sources(&[first.clone()], &dir.join("again.sqlite")).unwrap();

        // Same label, different sources -> different keys.
        assert_ne!(run[0].volume_id, run[1].volume_id);
        // Same source, another run -> same key.
        assert_eq!(run[0].volume_id, again[0].volume_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blob_body_round_trips_binary_bytes_unchanged() {
        let dir = temp_dir("binary");
        let body: Vec<u8> = vec![0x00, 0xFF, 0x80, 0x0A, 0x1B, 0x00, 0x7F];
        let mut records = vec![mft_self_record()];
        records.extend(filler(None));
        records.push(root_record());
        records.push(mft_record(
            4,
            0x01,
            &[
                resident_attr(0x10, "", &standard_info_body(0, 256)),
                file_name_attr(mft_ref(5, ROOT_SEQ), "raw.bin", 0),
                resident_attr(0x80, "", &body),
            ],
        ));
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let stored: Vec<u8> = conn
            .query_row(
                "SELECT data FROM MFT_Records WHERE file_name = 'raw.bin'",
                [],
                |r| match r.get_ref(0)? {
                    ValueRef::Blob(b) => Ok(b.to_vec()),
                    other => panic!("data is not a blob: {:?}", other.data_type()),
                },
            )
            .unwrap();
        assert_eq!(stored, body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unnamed_parents_keep_header_identity_without_inventing_paths() {
        let dir = temp_dir("unnamed-parents");
        let mut records = with_root(vec![
            mft_record(4, 0x03, &[si()]),
            mft_record(1, 0x01, &[si(), file_name_attr(mft_ref(6, 4), "child.txt", 0)]),
            mft_record(1, 0x01, &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "root-child.txt", 0)]),
        ]);
        records[5] = mft_record(ROOT_SEQ, 0x03, &[si()]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();
        assert_eq!(row_state(&out, "entry = 7"), (
            Some(6), Some(4), "verified".into(), "\\$Orphan\\child.txt".into(),
            "unknown".into(), "unavailable".into(),
        ));
        assert_eq!(row_state(&out, "entry = 8"), (
            Some(5), Some(i64::from(ROOT_SEQ)), "verified".into(),
            "\\root-child.txt".into(), "complete".into(), "unavailable".into(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_self_reference_is_a_sequence_mismatch_not_a_cycle() {
        let dir = temp_dir("stale-self");
        let records = with_root(vec![
            mft_record(4, 0x03, &[si(), file_name_attr(mft_ref(6, 3), "Old", 0)]),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();
        assert_eq!(row_state(&out, "entry = 6"), (
            Some(6), Some(3), "sequence_mismatch".into(), "\\$Orphan\\Old".into(),
            "sequence_mismatch".into(), "not_applicable".into(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verified_parent_keeps_its_sequence_and_completes_the_path() {
        let dir = temp_dir("parent-ok");
        let records = with_root(vec![
            mft_record(
                4,
                0x03,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "Users", 0)],
            ),
            mft_record(
                9,
                0x01,
                &[
                    si(),
                    file_name_attr(mft_ref(6, 4), "a.txt", 0),
                    resident_attr(0x80, "", b"hi"),
                ],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        // The referenced sequence is stored verbatim and the parent record
        // really carries it, so the path is a complete rooted path.
        assert_eq!(
            row_state(&out, "file_name = 'a.txt'"),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\Users\\a.txt".into(),
                "complete".into(),
                "resident".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'Users'"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "verified".into(),
                "\\Users".into(),
                "complete".into(),
                "not_applicable".into(),
            )
        );
        // The root keeps its own raw self reference but is reported as root.
        assert_eq!(
            row_state(&out, "entry = 5"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "root".into(),
                "\\".into(),
                "complete".into(),
                "not_applicable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reused_parent_slot_is_rejected_and_the_root_cache_still_checks_sequences() {
        let dir = temp_dir("parent-reused");
        let records = with_root(vec![
            // 6: a real directory with sequence 4.
            mft_record(
                4,
                0x03,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "Users", 0)],
            ),
            // 7: resolves first and fills the root/directory path cache.
            mft_record(
                1,
                0x01,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "good.txt", 0)],
            ),
            // 8: the root slot at another sequence — an obsolete reference.
            mft_record(1, 0x01, &[si(), file_name_attr(mft_ref(5, 9), "stale.txt", 0)]),
            // 9: the directory slot at another sequence — the slot was reused.
            mft_record(
                1,
                0x01,
                &[si(), file_name_attr(mft_ref(6, 11), "reused.txt", 0)],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'good.txt'"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "verified".into(),
                "\\good.txt".into(),
                "complete".into(),
                "unavailable".into(),
            )
        );
        // A warm cache entry for the root must not let a stale reference
        // through: the sequence is checked on every parent link.
        assert_eq!(
            row_state(&out, "file_name = 'stale.txt'"),
            (
                Some(5),
                Some(9),
                "sequence_mismatch".into(),
                "\\$Orphan\\stale.txt".into(),
                "sequence_mismatch".into(),
                "unavailable".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'reused.txt'"),
            (
                Some(6),
                Some(11),
                "sequence_mismatch".into(),
                "\\$Orphan\\reused.txt".into(),
                "sequence_mismatch".into(),
                "unavailable".into(),
            )
        );
        let rooted_orphans: i64 = query_one(
            &out,
            "SELECT COUNT(*) FROM MFT_Records WHERE path_status = 'complete' AND path LIKE '\\$Orphan%'",
        );
        assert_eq!(rooted_orphans, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_parent_record_stays_orphaned() {
        let dir = temp_dir("parent-missing");
        let records = with_root(vec![mft_record(
            1,
            0x01,
            &[si(), file_name_attr(mft_ref(999, 3), "lost.txt", 0)],
        )]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'lost.txt'"),
            (
                Some(999),
                Some(3),
                "missing".into(),
                "\\$Orphan\\lost.txt".into(),
                "orphan".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_root_record_leaves_every_path_incomplete() {
        let dir = temp_dir("root-missing");
        let mut records = with_root(vec![mft_record(
            1,
            0x01,
            &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "x.txt", 0)],
        )]);
        records[5] = empty_record();
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'x.txt'"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "missing".into(),
                "\\$Orphan\\x.txt".into(),
                "orphan".into(),
                "unavailable".into(),
            )
        );
        let complete: i64 = query_one(
            &out,
            "SELECT COUNT(*) FROM MFT_Records WHERE path_status = 'complete'",
        );
        assert_eq!(complete, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_root_slot_that_is_not_a_directory_is_not_a_root() {
        let dir = temp_dir("root-not-dir");
        let mut records = with_root(vec![mft_record(
            1,
            0x01,
            &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "x.txt", 0)],
        )]);
        // Record 5 exists with the right sequence but is a file named '.'.
        records[5] = mft_record(
            ROOT_SEQ,
            0x01,
            &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), ".", 0)],
        );
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'x.txt'"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "not_directory".into(),
                "\\$Orphan\\x.txt".into(),
                "not_directory".into(),
                "unavailable".into(),
            )
        );
        // The reused slot points at itself: a self loop is never a root.
        assert_eq!(
            row_state(&out, "entry = 5"),
            (
                Some(5),
                Some(i64::from(ROOT_SEQ)),
                "cycle".into(),
                "\\$Orphan\\.".into(),
                "cycle".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_directory_parent_is_not_accepted_as_a_parent() {
        let dir = temp_dir("parent-file");
        let records = with_root(vec![
            // 6: a file, not a directory.
            mft_record(
                4,
                0x01,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "host.exe", 0)],
            ),
            // 7: references it with the matching sequence.
            mft_record(
                2,
                0x01,
                &[si(), file_name_attr(mft_ref(6, 4), "child.txt", 0)],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'child.txt'"),
            (
                Some(6),
                Some(4),
                "not_directory".into(),
                "\\$Orphan\\child.txt".into(),
                "not_directory".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_cycles_terminate_without_claiming_a_path() {
        let dir = temp_dir("parent-cycle");
        let records = with_root(vec![
            // 6 <-> 7: two directories that point at each other.
            mft_record(4, 0x03, &[si(), file_name_attr(mft_ref(7, 5), "A", 0)]),
            mft_record(5, 0x03, &[si(), file_name_attr(mft_ref(6, 4), "B", 0)]),
            // 8: a directory that is its own parent.
            mft_record(6, 0x03, &[si(), file_name_attr(mft_ref(8, 6), "Self", 0)]),
            // 9: a file hanging off the cycle.
            mft_record(
                1,
                0x01,
                &[si(), file_name_attr(mft_ref(6, 4), "deep.txt", 0)],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        // Each link on its own is valid; the chain is not.
        assert_eq!(
            row_state(&out, "file_name = 'A'"),
            (
                Some(7),
                Some(5),
                "verified".into(),
                "\\$Orphan\\A".into(),
                "cycle".into(),
                "not_applicable".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'B'"),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\$Orphan\\B".into(),
                "cycle".into(),
                "not_applicable".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'Self'"),
            (
                Some(8),
                Some(6),
                "cycle".into(),
                "\\$Orphan\\Self".into(),
                "cycle".into(),
                "not_applicable".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'deep.txt'"),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\$Orphan\\deep.txt".into(),
                "cycle".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_descendant_of_a_bad_ancestor_never_reports_a_complete_path() {
        let dir = temp_dir("bad-ancestor");
        let records = with_root(vec![
            // 6: references the root at a sequence the root does not have.
            mft_record(4, 0x03, &[si(), file_name_attr(mft_ref(5, 9), "Bad", 0)]),
            // 7, 8: every link below 6 is valid on its own.
            mft_record(5, 0x03, &[si(), file_name_attr(mft_ref(6, 4), "Good", 0)]),
            mft_record(
                1,
                0x01,
                &[si(), file_name_attr(mft_ref(7, 5), "f.txt", 0)],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "file_name = 'Bad'"),
            (
                Some(5),
                Some(9),
                "sequence_mismatch".into(),
                "\\$Orphan\\Bad".into(),
                "sequence_mismatch".into(),
                "not_applicable".into(),
            )
        );
        // The direct parent link is fine, the ancestor is not.
        assert_eq!(
            row_state(&out, "file_name = 'Good'"),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\$Orphan\\Bad\\Good".into(),
                "sequence_mismatch".into(),
                "not_applicable".into(),
            )
        );
        assert_eq!(
            row_state(&out, "file_name = 'f.txt'"),
            (
                Some(7),
                Some(5),
                "verified".into(),
                "\\$Orphan\\Bad\\Good\\f.txt".into(),
                "sequence_mismatch".into(),
                "unavailable".into(),
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn equal_entry_numbers_in_two_inputs_keep_their_own_parents_and_bodies() {
        let dir = temp_dir("two-inputs");
        let build = |dir_name: &str, dir_seq: u16, body: &[u8]| {
            with_root(vec![
                mft_record(
                    dir_seq,
                    0x03,
                    &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), dir_name, 0)],
                ),
                mft_record(
                    3,
                    0x01,
                    &[
                        si(),
                        file_name_attr(mft_ref(6, dir_seq), "same.txt", 0),
                        resident_attr(0x80, "", body),
                    ],
                ),
            ])
        };
        let first = write_mft(&dir.join("c"), "$MFT", &build("C", 4, b"first"));
        let second = write_mft(&dir.join("d"), "$MFT", &build("D", 11, b"second"));
        let out = dir.join("MFT_Records.sqlite");
        let reports = parse_mft_sources(&[first, second], &out).unwrap();

        // Entry 7 exists in both inputs with the same name: each row keeps the
        // parent sequence of its own input.
        assert_eq!(
            row_state(
                &out,
                &format!("entry = 7 AND volume_id = '{}'", reports[0].volume_id)
            ),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\C\\same.txt".into(),
                "complete".into(),
                "resident".into(),
            )
        );
        assert_eq!(
            row_state(
                &out,
                &format!("entry = 7 AND volume_id = '{}'", reports[1].volume_id)
            ),
            (
                Some(6),
                Some(11),
                "verified".into(),
                "\\D\\same.txt".into(),
                "complete".into(),
                "resident".into(),
            )
        );

        let conn = Connection::open(&out).unwrap();
        let body_of = |volume: &str| -> Vec<u8> {
            conn.query_row(
                "SELECT data FROM MFT_Records WHERE entry = 7 AND volume_id = ?1",
                rusqlite::params![volume],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(body_of(&reports[0].volume_id), b"first".to_vec());
        assert_eq!(body_of(&reports[1].volume_id), b"second".to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_status_separates_directory_resident_empty_nonresident_and_unavailable() {
        let dir = temp_dir("data-status");
        let records = with_root(vec![
            mft_record(
                4,
                0x03,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "Dir", 0)],
            ),
            mft_record(
                1,
                0x01,
                &[
                    si(),
                    file_name_attr(mft_ref(5, ROOT_SEQ), "resident.txt", 0),
                    resident_attr(0x80, "", b"abc"),
                ],
            ),
            mft_record(
                1,
                0x01,
                &[
                    si(),
                    file_name_attr(mft_ref(5, ROOT_SEQ), "empty.log", 0),
                    resident_attr(0x80, "", &[]),
                ],
            ),
            mft_record(
                1,
                0x01,
                &[
                    si(),
                    file_name_attr(mft_ref(5, ROOT_SEQ), "big.bin", 0),
                    nonresident_data_attr(4096),
                ],
            ),
            mft_record(
                1,
                0x01,
                &[
                    si(),
                    file_name_attr(mft_ref(5, ROOT_SEQ), "ads.exe", 10),
                    resident_attr(0x80, "Zone.Identifier", b"[ZoneTransfer]"),
                ],
            ),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        let conn = Connection::open(&out).unwrap();
        let state = |name: &str| -> (String, String, Option<i64>) {
            conn.query_row(
                "SELECT data_status, typeof(data), file_size FROM MFT_Records WHERE file_name = ?1",
                rusqlite::params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        };
        assert_eq!(state("Dir"), ("not_applicable".into(), "null".into(), Some(0)));
        assert_eq!(
            state("resident.txt"),
            ("resident".into(), "blob".into(), Some(3))
        );
        // An empty resident body is real evidence, not a missing one.
        assert_eq!(
            state("empty.log"),
            ("resident_empty".into(), "blob".into(), Some(0))
        );
        assert_eq!(
            state("big.bin"),
            ("nonresident".into(), "null".into(), Some(4096))
        );
        // Only a named stream: the body of the file itself was never seen.
        assert_eq!(state("ads.exe"), ("unavailable".into(), "null".into(), Some(10)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_record_five_is_the_root_even_when_another_record_is_named_dot() {
        let dir = temp_dir("root-dot");
        let records = with_root(vec![
            mft_record(
                4,
                0x03,
                &[si(), file_name_attr(mft_ref(5, ROOT_SEQ), "Dir", 0)],
            ),
            mft_record(2, 0x01, &[si(), file_name_attr(mft_ref(6, 4), ".", 0)]),
        ]);
        let src = write_mft(&dir, "$MFT", &records);
        let out = dir.join("MFT_Records.sqlite");
        parse_mft_stream(&src, &out).unwrap();

        assert_eq!(
            row_state(&out, "entry = 7"),
            (
                Some(6),
                Some(4),
                "verified".into(),
                "\\Dir\\.".into(),
                "complete".into(),
                "unavailable".into(),
            )
        );
        let roots: i64 = query_one(&out, "SELECT COUNT(*) FROM MFT_Records WHERE path = '\\'");
        assert_eq!(roots, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
