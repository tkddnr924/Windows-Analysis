//! Typed overview generation with real facts-row and generation provenance.
//! Unknown values remain NULL; retained facts keep their original generation.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rusqlite::types::{ToSqlOutput, Value, ValueRef};
use rusqlite::{Connection, OpenFlags, OptionalExtension, ToSql};

pub mod ancillary;
pub mod schema;

mod builders;
mod stream;
mod path_candidates;

/// Materialize direct evidence before deriving rows that reference it.
pub use ancillary::prepare_ancillary_facts;

use schema::{DbSpec, COMMON_COLUMNS, SOURCE_RECORDS_COLUMNS, SOURCE_RECORDS_TABLE};

/// Facts-generation stamp written before publication.
pub const FACTS_GENERATION_TABLE: &str = "_wina_facts_generation";

pub const OVERVIEW_CONTRACT_VERSION: i64 = 1;

// Bound rollback-journal growth.
const BATCH_ROWS: usize = 20_000;

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

impl ToSql for Cell {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            Cell::Null => ToSqlOutput::Borrowed(ValueRef::Null),
            Cell::Int(v) => ToSqlOutput::Owned(Value::Integer(*v)),
            Cell::Text(v) => ToSqlOutput::Borrowed(ValueRef::Text(v.as_bytes())),
            Cell::Blob(v) => ToSqlOutput::Borrowed(ValueRef::Blob(v.as_slice())),
        })
    }
}

/// Convert legacy builders' empty values to NULL.
pub fn nz(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

pub fn text(value: &str) -> Cell {
    match nz(value) {
        Some(v) => Cell::Text(v.to_string()),
        None => Cell::Null,
    }
}

/// Preserve evidence whitespace; only empty values become NULL.
pub fn text_raw(value: &str) -> Cell {
    if value.is_empty() {
        Cell::Null
    } else {
        Cell::Text(value.to_string())
    }
}

pub fn text_opt(value: Option<&str>) -> Cell {
    value.map(text).unwrap_or(Cell::Null)
}

/// Parse decimal integers without stripping unproven units or separators.
pub fn int(value: &str) -> Cell {
    match nz(value).and_then(|v| v.parse::<i64>().ok()) {
        Some(v) => Cell::Int(v),
        None => Cell::Null,
    }
}

pub fn int_val(value: i64) -> Cell {
    Cell::Int(value)
}

pub fn int_opt(value: Option<i64>) -> Cell {
    value.map(Cell::Int).unwrap_or(Cell::Null)
}

pub fn flag(value: &str) -> Cell {
    match nz(value) {
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "y" | "yes" | "예" => Cell::Int(1),
            "0" | "false" | "n" | "no" | "아니오" => Cell::Int(0),
            _ => Cell::Null,
        },
        None => Cell::Null,
    }
}

pub fn flag_bool(value: bool) -> Cell {
    Cell::Int(if value { 1 } else { 0 })
}

pub fn is_sid(value: &str) -> bool {
    let value = value.trim();
    let Some(rest) = value.strip_prefix("S-").or_else(|| value.strip_prefix("s-")) else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// Invalid JSON remains available in facts, not typed JSON columns.
pub fn json_text(value: &str) -> Cell {
    match nz(value) {
        Some(v) if serde_json::from_str::<serde_json::Value>(v).is_ok() => Cell::Text(v.to_string()),
        _ => Cell::Null,
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Parent identity and ordinal are assigned when written.
#[derive(Debug, Clone)]
pub struct SourceRef {
    pub dataset: String,
    pub artifact: String,
    /// Host-relative database path.
    pub db: String,
    pub table: String,
    pub rowid: i64,
    pub field: Option<String>,
    pub record_key: Option<String>,
    pub file: Option<String>,
    pub label: Option<String>,
}

impl SourceRef {
    fn values(&self, record_id: &str, ordinal: usize) -> Vec<Cell> {
        vec![
            Cell::Text(record_id.to_string()),
            Cell::Int(ordinal as i64),
            Cell::Text(self.dataset.clone()),
            Cell::Text(self.artifact.clone()),
            Cell::Text(self.db.clone()),
            Cell::Text(self.table.clone()),
            Cell::Int(self.rowid),
            text_opt(self.field.as_deref()),
            text_opt(self.record_key.as_deref()),
            text_opt(self.file.as_deref()),
            text_opt(self.label.as_deref()),
        ]
    }
}

// ---------------------------------------------------------------------------
// Facts index and generations
// ---------------------------------------------------------------------------

/// Replace a facts database's generation stamp before publication.
pub fn stamp_facts_generation(db_path: &Path, dataset_id: &str) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("facts 세대 스탬프: {}", db_path.display()))?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (dataset_id TEXT NOT NULL); DELETE FROM {table};",
        table = crate::sqlite::quote_ident(FACTS_GENERATION_TABLE)
    ))?;
    conn.execute(
        &format!(
            "INSERT INTO {} (dataset_id) VALUES (?1)",
            crate::sqlite::quote_ident(FACTS_GENERATION_TABLE)
        ),
        [dataset_id],
    )?;
    Ok(())
}

/// Missing stamps return None and require reparse, never a guessed generation.
pub fn facts_generation(db_path: &Path) -> Result<Option<String>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("facts 세대 조회: {}", db_path.display()))?;
    let mut stmt = match conn.prepare(&format!(
        "SELECT dataset_id FROM {} LIMIT 1",
        crate::sqlite::quote_ident(FACTS_GENERATION_TABLE)
    )) {
        Ok(stmt) => stmt,
        Err(_) => return Ok(None),
    };
    let value: Option<String> = stmt.query_row([], |row| row.get(0)).ok();
    Ok(value.filter(|v| !v.is_empty()))
}

pub fn facts_dataset_id(db_path: &Path) -> Result<String> {
    let relative = db_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    facts_generation(db_path)?.ok_or_else(|| missing_stamp(&relative))
}

/// Resolve builder record keys to actual facts coordinates and generations.
pub struct FactsIndex {
    root: PathBuf,
    by_stem: HashMap<String, FactsDb>,
    generations: parking_lot::Mutex<HashMap<PathBuf, Option<String>>>,
}

#[derive(Debug, Clone)]
pub struct FactsDb {
    pub path: PathBuf,
    pub relative: String,
    pub artifact: String,
}

fn artifact_for_category(category: &str, stem: &str) -> String {
    match category {
        "AMCACHE" => "Amcache",
        "EVENTLOG" => "EventLog",
        "REGISTRY" => "Registry",
        "FILESYSTEM" => "UsnJrnl",
        "JUMPLIST" => "JumpList",
        "SRUM" => "SRUM",
        "TASKSCHEDULER" => "TaskScheduler",
        "RDPCACHE" => "RdpCache",
        "BROWSER" => "Browser",
        "PREFETCH" => "Prefetch",
        "POWERSHELL" => "PowerShell",
        "WER" => "WER",
        "WMI" => "WmiRepository",
        "TIMELINE" => "Timeline",
        "RECYCLEBIN" => "RecycleBin",
        // Supplemental tables identify their actual artifact at the call site.
        ancillary::ANCILLARY_CATEGORY => "Ancillary",
        "_OVERVIEW" if stem.starts_with("MFT_Records") => "MFT",
        other => other,
    }
    .to_string()
}

impl FactsIndex {
    /// Index facts only; MFT_Records is the raw exception under _OVERVIEW.
    pub fn load(root: &Path) -> Result<Self> {
        let mut by_stem: HashMap<String, FactsDb> = HashMap::new();
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) => return Err(anyhow!("산출물 폴더를 읽지 못했습니다: {error}")),
        };
        let mut categories: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect();
        categories.sort();
        for category_dir in categories {
            let category = category_dir
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            let Ok(files) = std::fs::read_dir(&category_dir) else {
                continue;
            };
            let mut files: Vec<PathBuf> = files
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().map(|ext| ext == "sqlite").unwrap_or(false))
                .collect();
            files.sort();
            for file in files {
                let stem = file
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().to_string())
                    .unwrap_or_default();
                if stem.is_empty() {
                    continue;
                }
                if category == "_OVERVIEW" && schema::spec(&stem).is_some() {
                    continue;
                }
                let relative = format!("{category}/{}", file.file_name().unwrap().to_string_lossy());
                by_stem.entry(stem.clone()).or_insert(FactsDb {
                    path: file.clone(),
                    relative,
                    artifact: artifact_for_category(&category, &stem),
                });
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
            by_stem,
            generations: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn by_stem(&self, stem: &str) -> Option<&FactsDb> {
        self.by_stem.get(stem)
    }

    pub fn by_path(&self, path: &Path) -> Option<&FactsDb> {
        let stem = path.file_stem()?.to_string_lossy().to_string();
        self.by_stem
            .get(&stem)
            .filter(|found| found.path.as_path() == path)
    }

    /// Unstamped facts require reparse rather than generation substitution.
    pub fn generation(&self, db: &FactsDb) -> Result<String> {
        let mut cache = self.generations.lock();
        if let Some(found) = cache.get(&db.path) {
            return found.clone().ok_or_else(|| missing_stamp(&db.relative));
        }
        let value = facts_generation(&db.path)?;
        cache.insert(db.path.clone(), value.clone());
        value.ok_or_else(|| missing_stamp(&db.relative))
    }

    /// Resolve supported builder keys without inventing missing facts rows.
    pub fn source_from_record_key(
        &self,
        record_key: &str,
        field: Option<&str>,
        file: Option<&str>,
        label: Option<&str>,
    ) -> Result<Option<SourceRef>> {
        let Some(key) = nz(record_key) else {
            return Ok(None);
        };
        let parts: Vec<&str> = key.split("::").collect();
        let (stem, table, rowid) = match parts.as_slice() {
            [stem, table, rowid] => (*stem, *table, *rowid),
            // EventLog table names are also their database stems.
            [table, rowid] => (*table, *table, *rowid),
            _ => return Ok(None),
        };
        let Ok(rowid) = rowid.parse::<i64>() else {
            return Ok(None);
        };
        let Some(db) = self.by_stem(stem) else {
            return Ok(None);
        };
        Ok(Some(SourceRef {
            dataset: self.generation(db)?,
            artifact: db.artifact.clone(),
            db: db.relative.clone(),
            table: table.to_string(),
            rowid,
            field: field.map(str::to_string),
            record_key: Some(key.to_string()),
            file: file.and_then(nz).map(str::to_string),
            label: label.and_then(nz).map(str::to_string),
        }))
    }

    pub fn source_from_row(
        &self,
        db_path: &Path,
        table: &str,
        rowid: i64,
        file: Option<&str>,
        label: Option<&str>,
    ) -> Result<Option<SourceRef>> {
        let Some(db) = self.by_path(db_path) else {
            return Ok(None);
        };
        Ok(Some(SourceRef {
            dataset: self.generation(db)?,
            artifact: db.artifact.clone(),
            db: db.relative.clone(),
            table: table.to_string(),
            rowid,
            field: None,
            record_key: Some(format!("{}::{}::{}", stem_of(db_path), table, rowid)),
            file: file.and_then(nz).map(str::to_string),
            label: label.and_then(nz).map(str::to_string),
        }))
    }
}

fn missing_stamp(relative: &str) -> anyhow::Error {
    anyhow!(
        "{relative}: facts 세대 스탬프({FACTS_GENERATION_TABLE})가 없습니다 — \
         이 아티팩트를 다시 파싱해야 원본 연결 세대를 확정할 수 있습니다"
    )
}

pub(crate) fn stem_of(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Recreate a derived database using its canonical DDL.
pub fn create_database(overview_dir: &Path, name: &str) -> Result<Connection> {
    let spec = schema::spec(name)
        .ok_or_else(|| anyhow!("알 수 없는 파생 DB 이름입니다: {name}"))?;
    std::fs::create_dir_all(overview_dir)
        .with_context(|| format!("_OVERVIEW 폴더 생성: {}", overview_dir.display()))?;
    let path = overview_dir.join(format!("{name}.sqlite"));
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("이전 파생 삭제: {}", path.display()))?;
    }
    let conn = Connection::open(&path)
        .with_context(|| format!("파생 DB 생성: {}", path.display()))?;
    // Enforce intra-database parent/child references during generation.
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(spec.ddl)
        .with_context(|| format!("{name} DDL 실행"))?;
    Ok(conn)
}

/// Write parents before children and source references.
pub struct DerivedDb {
    spec: &'static DbSpec,
    conn: Connection,
    pending: usize,
    rows: usize,
}

impl DerivedDb {
    pub fn create(overview_dir: &Path, name: &str) -> Result<Self> {
        let spec = schema::spec(name)
            .ok_or_else(|| anyhow!("알 수 없는 파생 DB 이름입니다: {name}"))?;
        let conn = create_database(overview_dir, name)?;
        conn.execute_batch("BEGIN")?;
        Ok(Self {
            spec,
            conn,
            pending: 0,
            rows: 0,
        })
    }

    pub fn spec(&self) -> &'static DbSpec {
        self.spec
    }

    fn insert(&mut self, table: &str, columns: &[&str], values: &[Cell]) -> Result<()> {
        debug_assert_eq!(columns.len(), values.len(), "{table} 컬럼 수 불일치");
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            crate::sqlite::quote_ident(table),
            columns
                .iter()
                .map(|c| crate::sqlite::quote_ident(c))
                .collect::<Vec<_>>()
                .join(","),
            (1..=values.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        {
            let mut stmt = self.conn.prepare_cached(&sql)?;
            stmt.execute(rusqlite::params_from_iter(values.iter()))
                .with_context(|| format!("{table} 행 저장"))?;
        }
        self.pending += 1;
        if self.pending >= BATCH_ROWS {
            self.conn.execute_batch("COMMIT; BEGIN")?;
            self.pending = 0;
        }
        Ok(())
    }

    pub fn insert_main(&mut self, values: &[Cell]) -> Result<()> {
        let (table, columns) = (self.spec.table, self.spec.columns);
        self.insert(table, columns, values)?;
        self.rows += 1;
        Ok(())
    }

    pub fn insert_child(&mut self, table: &str, values: &[Cell]) -> Result<()> {
        let columns = self
            .spec
            .child(table)
            .ok_or_else(|| anyhow!("{}에 없는 자식 테이블입니다: {table}", self.spec.name))?
            .columns;
        self.insert(table, columns, values)
    }

    pub fn insert_sources(&mut self, record_id: &str, sources: &[SourceRef]) -> Result<()> {
        for (ordinal, source) in sources.iter().enumerate() {
            let values = source.values(record_id, ordinal);
            self.insert(SOURCE_RECORDS_TABLE, SOURCE_RECORDS_COLUMNS, &values)?;
        }
        Ok(())
    }

    pub fn write(&mut self, record: Record) -> Result<()> {
        self.insert_main(&record.values)?;
        self.insert_sources(&record.record_id, &record.sources)?;
        for (table, values) in &record.children {
            self.insert_child(table, values)?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<usize> {
        self.conn.execute_batch("COMMIT")?;
        Ok(self.rows)
    }
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

pub struct Record {
    spec: &'static DbSpec,
    pub record_id: String,
    values: Vec<Cell>,
    sources: Vec<SourceRef>,
    children: Vec<(&'static str, Vec<Cell>)>,
}

impl Record {
    pub fn new(spec: &'static DbSpec, host_id: &str, dataset_id: &str) -> Self {
        let record_id = uuid::Uuid::new_v4().to_string();
        let mut values = vec![Cell::Null; spec.columns.len()];
        values[0] = Cell::Text(record_id.clone());
        values[1] = Cell::Text(host_id.to_string());
        values[2] = Cell::Text(dataset_id.to_string());
        values[4] = Cell::Text(spec.table.to_string());
        debug_assert!(spec.columns.starts_with(COMMON_COLUMNS));
        Self {
            spec,
            record_id,
            values,
            sources: Vec::new(),
            children: Vec::new(),
        }
    }

    // A known timestamp requires its meaning under the CHECK constraint.
    pub fn timestamp(&mut self, value: &str, kind: &str) -> &mut Self {
        if let Some(value) = nz(value) {
            self.set("timestamp", Cell::Text(value.to_string()));
            self.set("timestamp_kind", text(kind));
        }
        self
    }

    // Resolve names only through stored metadata, never profile-name guesses.
    pub fn account(&mut self, raw: &str, lookup: &MetaLookup) -> &mut Self {
        let (account, sid) = lookup.split_account(raw);
        self.set("account", text_opt(account.as_deref()));
        self.set("account_sid", text_opt(sid.as_deref()));
        self
    }

    pub fn set(&mut self, column: &str, value: Cell) -> &mut Self {
        match self.spec.index_of(column) {
            Some(index) => self.values[index] = value,
            None => debug_assert!(false, "{}에 없는 컬럼: {column}", self.spec.name),
        }
        self
    }

    pub fn get(&self, column: &str) -> Option<&Cell> {
        self.spec.index_of(column).map(|index| &self.values[index])
    }

    pub fn set_at(&mut self, index: usize, value: Cell) -> &mut Self {
        self.values[index] = value;
        self
    }

    pub fn at(&self, index: usize) -> &Cell {
        &self.values[index]
    }

    pub fn source(&mut self, source: Option<SourceRef>) -> &mut Self {
        if let Some(source) = source {
            self.sources.push(source);
        }
        self
    }

    pub fn child(&mut self, table: &'static str, mut values: Vec<Cell>) -> &mut Self {
        let ordinal = self
            .children
            .iter()
            .filter(|(name, _)| *name == table)
            .count();
        values.insert(0, Cell::Text(self.record_id.clone()));
        values.insert(1, Cell::Int(ordinal as i64));
        self.children.push((table, values));
        self
    }

    pub fn child_count(&self, table: &str) -> usize {
        self.children
            .iter()
            .filter(|(name, _)| *name == table)
            .count()
    }

    pub fn has_sources(&self) -> bool {
        !self.sources.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Metadata lookup
// ---------------------------------------------------------------------------

/// Read metadata generated before the other overview databases.
pub struct MetaLookup {
    inner: crate::metadata::MetadataLookup,
}

impl MetaLookup {
    pub fn load(out_dir: &Path) -> Result<Self> {
        Ok(Self {
            inner: crate::metadata::MetadataLookup::load(out_dir)?,
        })
    }

    pub fn account_name(&self, sid: &str) -> Option<String> {
        self.inner.account(sid).map(str::to_string)
    }

    pub fn resolve_path(&self, raw: &str, sid: Option<&str>) -> Cell {
        match nz(raw).and_then(|raw| self.inner.resolve_path(raw, sid)) {
            Some(resolved) => Cell::Text(resolved),
            None => Cell::Null,
        }
    }

    pub fn metadata_id(&self, kind: &str, scope: &str, key: &str) -> Option<&str> {
        self.inner.metadata_id(kind, scope, &key.to_lowercase())
    }

    // Only an evidenced SID can establish an account's SID.
    pub fn split_account(&self, raw: &str) -> (Option<String>, Option<String>) {
        let Some(raw) = nz(raw) else {
            return (None, None);
        };
        if is_sid(raw) {
            (self.account_name(raw), Some(raw.to_string()))
        } else {
            (Some(raw.to_string()), None)
        }
    }
}

// ---------------------------------------------------------------------------
// Generation context
// ---------------------------------------------------------------------------

pub struct Ctx<'a> {
    pub out_dir: &'a Path,
    pub target: &'a Path,
    pub host_id: &'a str,
    pub dataset_id: &'a str,
    pub facts: FactsIndex,
    pub meta: MetaLookup,
}

impl Ctx<'_> {
    pub fn overview_dir(&self) -> PathBuf {
        self.out_dir.join("_OVERVIEW")
    }

    pub fn record(&self, spec: &'static DbSpec) -> Record {
        Record::new(spec, self.host_id, self.dataset_id)
    }

    pub fn source_of(&self, row: &crate::sqlite::Row, label: &str) -> Result<Option<SourceRef>> {
        let key = row
            .get("record_key")
            .or_else(|| row.get("source_record_key"))
            .map(String::as_str)
            .unwrap_or("");
        let file = row.get("_source_file").map(String::as_str);
        self.facts
            .source_from_record_key(key, None, file, nz(label))
    }
}

// ---------------------------------------------------------------------------
// Complete generation
// ---------------------------------------------------------------------------

fn validate_lineage(out_dir: &Path) -> Result<()> {
    for spec in schema::SPECS {
        let path = out_dir.join("_OVERVIEW").join(format!("{}.sqlite", spec.name));
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let sources = {
            let mut query = conn.prepare(
                "SELECT DISTINCT source_db, source_table, source_dataset_id FROM source_records ORDER BY source_db, source_table",
            )?;
            let rows = query.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut attached: Option<&str> = None;
        let mut attached_generation = String::new();
        for (relative, table, generation) in &sources {
            if attached != Some(relative.as_str()) {
                if Path::new(relative).components().any(|part| !matches!(part, std::path::Component::Normal(_))) {
                    return Err(anyhow!("{}: source DB must be host-relative: {relative}", spec.name));
                }
                let source_path = out_dir.join(relative);
                if !source_path.is_file() {
                    return Err(anyhow!("{}: missing source DB {relative}", spec.name));
                }
                if attached.is_some() {
                    conn.execute_batch("DETACH DATABASE facts")?;
                }
                conn.execute("ATTACH DATABASE ?1 AS facts", [source_path.to_string_lossy().as_ref()])?;
                attached_generation = conn.query_row(
                    "SELECT dataset_id FROM facts._wina_facts_generation", [], |row| row.get(0),
                )?;
                attached = Some(relative.as_str());
            }
            if generation != &attached_generation {
                return Err(anyhow!("{}: source generation mismatch for {relative}", spec.name));
            }
            let missing: Option<(String, i64)> = conn.query_row(
                &format!(
                    "SELECT s.record_id, s.source_rowid FROM source_records s LEFT JOIN facts.{} f ON f.rowid=s.source_rowid WHERE s.source_db=?1 AND s.source_table=?2 AND f.rowid IS NULL LIMIT 1",
                    crate::sqlite::quote_ident(table),
                ),
                rusqlite::params![relative, table], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            if let Some((record_id, rowid)) = missing {
                return Err(anyhow!("{} record {record_id}: missing source {relative}/{table}/{rowid}", spec.name));
            }
        }
        if spec.name == "TargetInfo" {
            let metadata = out_dir.join("_OVERVIEW/Metadata.sqlite");
            conn.execute("ATTACH DATABASE ?1 AS metadata_target", [metadata.to_string_lossy().as_ref()])?;
            let invalid: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM TargetInfo t LEFT JOIN metadata_target.metadata m ON m.metadata_id=t.metadata_id WHERE t.metadata_id IS NOT NULL AND m.metadata_id IS NULL)",
                [], |row| row.get(0),
            )?;
            if invalid {
                return Err(anyhow!("TargetInfo contains a missing metadata reference"));
            }
        }
        if spec.name == "PathReferences" {
            let files = out_dir.join("_OVERVIEW/FileSystemEntries.sqlite");
            conn.execute("ATTACH DATABASE ?1 AS file_target", [files.to_string_lossy().as_ref()])?;
            let invalid: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM PathReferenceCandidates c
                 JOIN PathReferences p ON p.record_id=c.record_id
                 LEFT JOIN file_target.FileSystemEntries f ON f.record_id=c.file_record_id
                   AND f.volume_id=c.volume_id AND f.host_id=p.host_id AND f.dataset_id=p.dataset_id
                 WHERE f.record_id IS NULL)",
                [], |row| row.get(0),
            )?;
            if invalid {
                return Err(anyhow!("Path reference candidate has a missing or foreign file record"));
            }
        }
    }
    Ok(())
}

/// Build all 21 schemas, including empty results; propagate generation failures.
pub fn build_all(
    out_dir: &Path,
    target: &Path,
    host_id: &str,
    dataset_id: &str,
) -> Result<Vec<(String, usize)>> {
    let overview_dir = out_dir.join("_OVERVIEW");
    std::fs::create_dir_all(&overview_dir)?;

    // Other builders depend on stored metadata.
    let metadata_rows = crate::metadata::build_metadata(out_dir, target, host_id, dataset_id)
        .context("Metadata 생성")?;
    let mut report: Vec<(String, usize)> = vec![("Metadata".to_string(), metadata_rows)];

    let ctx = Ctx {
        out_dir,
        target,
        host_id,
        dataset_id,
        facts: FactsIndex::load(out_dir)?,
        meta: MetaLookup::load(out_dir)?,
    };

    // Share event and registry scans across builders.
    let events = crate::overview::EventLogOverviewCache::load(out_dir);
    let registry = crate::overview::RegistryOverviewCache::load(out_dir);

    for (name, rows) in builders::build_event_backed(&ctx, &events)? {
        report.push((name, rows));
    }
    for (name, rows) in builders::build_registry_backed(&ctx, &registry, &events)? {
        report.push((name, rows));
    }
    drop(events);
    drop(registry);
    for (name, rows) in stream::build_streaming(&ctx)? {
        report.push((name, rows));
    }
    path_candidates::build(&ctx)?;

    report.sort_by_key(|(name, _)| {
        schema::SPECS
            .iter()
            .position(|spec| spec.name == *name)
            .unwrap_or(usize::MAX)
    });
    debug_assert_eq!(report.len(), schema::SPECS.len());
    validate_lineage(out_dir)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_database_has_a_spec() {
        assert_eq!(schema::SPECS.len(), 21);
        for spec in schema::SPECS {
            assert!(!spec.columns.is_empty(), "{} 컬럼 없음", spec.name);
            if spec.name != "Metadata" {
                assert!(
                    spec.columns.starts_with(COMMON_COLUMNS),
                    "{} 공통 컬럼 누락",
                    spec.name
                );
            }
            assert!(
                spec.child(SOURCE_RECORDS_TABLE).is_some(),
                "{} source_records 없음",
                spec.name
            );
        }
    }

    #[test]
    fn create_database_applies_documented_ddl() {
        let dir = std::env::temp_dir().join(format!("wina-derived-ddl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let conn = create_database(&dir, "ExecutionHistory").unwrap();
        let version: i64 = conn
            .query_row(
                "SELECT version FROM _wina_derived_version WHERE name='overview_contract'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, OVERVIEW_CONTRACT_VERSION);
        let kind: String = conn
            .query_row(
                "SELECT type FROM pragma_table_info('ExecutionHistory') WHERE name='run_count'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kind, "INTEGER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publication_rejects_missing_source_rows_and_wrong_generations() {
        let (out_dir, target) = fixture("source-validation");
        facts_db(&out_dir, "EVENTLOG/Security.sqlite",
            "CREATE TABLE Security(value TEXT); INSERT INTO Security VALUES ('evidence');");
        build_all(&out_dir, &target, "host", "derived-generation").unwrap();
        let db = Connection::open(out_dir.join("_OVERVIEW/ExecutionHistory.sqlite")).unwrap();
        db.execute_batch(
            "INSERT INTO ExecutionHistory(record_id,host_id,dataset_id,overview_name) VALUES ('r','host','derived-generation','ExecutionHistory');
             INSERT INTO source_records(record_id,ordinal,source_dataset_id,source_artifact,source_db,source_table,source_rowid)
             VALUES ('r',0,'facts-gen-1','EventLog','EVENTLOG/Security.sqlite','Security',99);"
        ).unwrap();
        assert!(validate_lineage(&out_dir).is_err());
        db.execute("UPDATE source_records SET source_rowid=1", []).unwrap();
        validate_lineage(&out_dir).unwrap();
        db.execute("UPDATE source_records SET source_dataset_id='wrong-generation'", []).unwrap();
        assert!(validate_lineage(&out_dir).is_err());
        drop(db);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn unstamped_facts_database_is_an_actionable_error() {
        let dir = std::env::temp_dir().join(format!("wina-facts-stamp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("EVENTLOG")).unwrap();
        let db = dir.join("EVENTLOG").join("Security.sqlite");
        Connection::open(&db)
            .unwrap()
            .execute_batch("CREATE TABLE Security(a TEXT)")
            .unwrap();
        let facts = FactsIndex::load(&dir).unwrap();
        assert!(facts.source_from_record_key("Security::7", None, None, None).is_err());

        stamp_facts_generation(&db, "dataset-1").unwrap();
        let facts = FactsIndex::load(&dir).unwrap();
        let source = facts
            .source_from_record_key("Security::7", None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(source.dataset, "dataset-1");
        assert_eq!(source.db, "EVENTLOG/Security.sqlite");
        assert_eq!(source.table, "Security");
        assert_eq!(source.rowid, 7);
        assert_eq!(source.artifact, "EventLog");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn account_values_never_cross_between_name_and_sid() {
        assert!(is_sid("S-1-5-21-1-2-3-1001"));
        assert!(!is_sid("Administrator"));
        assert!(!is_sid("S-1-5-x"));
    }

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "wina-derived-{label}-{}-{:?}",
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

    fn facts_db(out_dir: &Path, relative: &str, sql: &str) -> PathBuf {
        let path = out_dir.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        stamp_facts_generation(&path, "facts-gen-1").unwrap();
        path
    }

    fn open(out_dir: &Path, name: &str) -> Connection {
        Connection::open_with_flags(
            out_dir.join("_OVERVIEW").join(format!("{name}.sqlite")),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
    }

    #[test]
    fn target_accounts_store_role_matched_events_and_complete_evidence() {
        let (out_dir, target) = fixture("target-account-events");
        let registry = facts_db(&out_dir, "REGISTRY/SOFTWARE.sqlite",
            "CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,
             value_data TEXT,_recovery TEXT,_source_file TEXT);");
        let registry = Connection::open(registry).unwrap();
        for (sid, path) in [("S-1-5-18", r"C:\Windows\System32\config\systemprofile"),
            ("S-1-5-21-11-22-33-1001", r"C:\Users\Ghost")] {
            registry.execute("INSERT INTO Registry VALUES ('2026-01-01 00:00:00.000',?1,
                'ProfileImagePath','REG_SZ',?2,'live','SOFTWARE')",
                rusqlite::params![format!(r"\ROOT\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),path]).unwrap();
        }
        drop(registry);
        let event_path = facts_db(&out_dir, "EVENTLOG/Security.sqlite",
            "CREATE TABLE Security(timestamp TEXT,Channel TEXT,EventID TEXT,LevelName TEXT,
             Level TEXT,Provider TEXT,Computer TEXT,EventRecordID TEXT,ProcessID TEXT,
             ThreadID TEXT,UserID TEXT,EventData TEXT,_record_key TEXT,_status TEXT,
             _error TEXT,_source_file TEXT);");
        let facts = Connection::open(&event_path).unwrap();
        let complete = serde_json::json!({
            "SubjectUserSid":"S-1-5-18","TargetUserSid":"S-1-5-21-11-22-33-1001",
            "CommandLine":format!("start\r\n{} END-OF-EVIDENCE  ", "x".repeat(5000))
        }).to_string();
        let events = [
            ("Security", "4624", "S-1-5-18", complete.as_str()),
            ("Security", "999", "S-1-5-18", " {broken payload  "),
            ("Security", "999", "", r#"{"EventXML":{"SubjectUserName":"DOMAIN\\LocalSystem"}}"#),
            ("Security", "999", "", r#"{"SubjectUserSid":"S-1-5-999","SubjectUserName":"LocalSystem"}"#),
            ("Security", "999", "", r#"{"Message":"S-1-5-18","RuleId":"LocalSystem"}"#),
            ("Microsoft-Windows-TerminalServices-RemoteConnectionManager", "1149", "", r#"{"param1":"LocalSystem"}"#),
            ("Other", "1149", "", r#"{"param1":"LocalSystem"}"#),
            ("Security", "999", "", r#"{"TargetUserName":"Ghost"}"#),
            ("Security", "999", "S-1-5-21-11-22-33-1001", "{}"),
        ];
        for (index, (provider, id, sid, payload)) in events.iter().enumerate() {
            facts.execute("INSERT INTO Security VALUES (?1,'Security',?2,'Information','0',?3,
                'HOST','42','0',NULL,?4,?5,?6,'parsed',NULL,'Security.evtx')",
                rusqlite::params![if index == 8 { None } else { Some("2026-01-01 01:02:03.004") },
                    id,provider,sid,payload,format!("Security::{}",index+1)]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "derived-new").unwrap();
        let db = open(&out_dir, "TargetInfo");
        let hits: Vec<(String,i64)> = db.prepare(
            "SELECT t.account_sid,s.source_rowid FROM TargetAccountEvents e
             JOIN TargetInfo t USING(record_id) JOIN source_records s
             ON s.record_id=e.record_id AND s.ordinal=e.source_ordinal
             ORDER BY t.account_sid,s.source_rowid").unwrap()
            .query_map([], |r| Ok((r.get(0)?,r.get(1)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(hits, vec![("S-1-5-18".into(),1),("S-1-5-18".into(),2),
            ("S-1-5-18".into(),3),("S-1-5-18".into(),6),
            ("S-1-5-21-11-22-33-1001".into(),1),("S-1-5-21-11-22-33-1001".into(),9)]);
        db.execute("ATTACH DATABASE ?1 AS original", [event_path.to_str().unwrap()]).unwrap();
        let mismatches: i64 = db.query_row(
            "SELECT count(*) FROM TargetAccountEvents e JOIN source_records s
             ON s.record_id=e.record_id AND s.ordinal=e.source_ordinal
             JOIN original.Security o ON o.rowid=s.source_rowid
             WHERE e.event_data IS NOT o.EventData OR e.timestamp IS NOT o.timestamp
             OR e.event_record_id<>42 OR e.process_id<>0 OR e.thread_id IS NOT NULL
             OR s.source_dataset_id<>'facts-gen-1' OR s.source_file<>'Security.evtx'",
            [], |r|r.get(0)).unwrap();
        assert_eq!(mismatches, 0);
        let matched: Vec<(i64,String,String,String)> = db.prepare(
            "SELECT s.source_rowid,m.match_kind,m.field,m.value FROM TargetAccountEventMatches m
             JOIN TargetAccountEvents e ON e.record_id=m.record_id AND e.ordinal=m.event_ordinal
             JOIN TargetInfo t ON t.record_id=e.record_id
             JOIN source_records s ON s.record_id=e.record_id AND s.ordinal=e.source_ordinal
             WHERE t.account_sid='S-1-5-18' ORDER BY s.source_rowid,m.field").unwrap()
            .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(matched,vec![(1,"sid".into(),"SubjectUserSid".into(),"S-1-5-18".into()),
            (1,"sid".into(),"UserID".into(),"S-1-5-18".into()),
            (2,"sid".into(),"UserID".into(),"S-1-5-18".into()),
            (3,"name".into(),"EventXML.SubjectUserName".into(),r"DOMAIN\LocalSystem".into()),
            (6,"name".into(),"param1".into(),"LocalSystem".into())]);
        assert_eq!(db.query_row("SELECT count(*) FROM TargetAccountEvents WHERE event_data LIKE '%END-OF-EVIDENCE%'",
            [],|r|r.get::<_,i64>(0)).unwrap(),2);
        assert_eq!(db.query_row("SELECT count(*) FROM pragma_foreign_key_check",
            [],|r|r.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(db.query_row("SELECT account FROM TargetInfo WHERE account_sid='S-1-5-21-11-22-33-1001'",
            [],|r|r.get::<_,Option<String>>(0)).unwrap(),None);
        drop(db);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn filesystem_candidates_preserve_input_body_and_time_provenance() {
        let (out_dir, target) = fixture("filesystem-candidates");
        let mft = out_dir.join("_OVERVIEW/MFT_Records.sqlite");
        crate::parsers::mft::parse_mft_sources(&[], &mft).unwrap();
        stamp_facts_generation(&mft, "mft-generation").unwrap();
        let facts = Connection::open(&mft).unwrap();
        for (volume, drive, body) in [
            ("vol-c", Some("C:"), b"first".as_slice()),
            ("vol-unknown", None, b"second".as_slice()),
            ("vol-d", Some("D:"), b"third".as_slice()),
        ] {
            let source = target.join(volume).join("$MFT");
            facts.execute(
                "INSERT INTO MFT_Records(volume_id,volume_label,drive_letter,path,file_name,
                 is_directory,in_use,file_size,data,entry,seq,parent_entry,_source_file,
                 parent_seq,parent_status,path_status,data_status)
                 VALUES (?1,'same',?2,'\\Docs\\File.txt','File.txt',0,1,?3,?4,42,3,5,?5,
                         1,'verified','complete','resident')",
                rusqlite::params![volume,drive,body.len() as i64,body,source.to_str().unwrap()],
            ).unwrap();
        }
        drop(facts);
        let jump = facts_db(&out_dir,"JUMPLIST/JumpList_Entries.sqlite",
            "CREATE TABLE JumpList_Entries(timestamp TEXT,lnk_accessed TEXT,destlist_accessed TEXT,
             timestamp_source TEXT,access_count TEXT,hostname TEXT,target_path TEXT,_source_file TEXT);");
        let jump = Connection::open(jump).unwrap();
        for path in [r"C:\Docs\File.txt",r"D:\Docs\File.txt",r"C:Docs\File.txt",r"\\server\Docs\File.txt"] {
            jump.execute("INSERT INTO JumpList_Entries VALUES
                ('2026-01-01 12:00:00.000','2026-01-01 12:00:00.000','2026-01-01 12:00:00.000',
                 'destlist_accessed','0','HOST',?1,'JUMPLIST/user/app.automaticDestinations-ms')",
                [path]).unwrap();
        }
        drop(jump);
        build_all(&out_dir,&target,"host","derived-generation").unwrap();
        let db = open(&out_dir,"PathReferences");
        db.execute("ATTACH DATABASE ?1 AS files",
            [out_dir.join("_OVERVIEW/FileSystemEntries.sqlite").to_str().unwrap()]).unwrap();
        let candidates: Vec<(String,String,Vec<u8>,String)> = db.prepare(
            "SELECT p.target_drive_letter,c.volume_id,f.data,c.match_basis
             FROM PathReferenceCandidates c JOIN PathReferences p USING(record_id)
             JOIN files.FileSystemEntries f ON f.record_id=c.file_record_id
             ORDER BY p.target_drive_letter,c.volume_id").unwrap()
            .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(candidates,vec![
            ("C:".into(),"vol-c".into(),b"first".to_vec(),"path_and_drive".into()),
            ("C:".into(),"vol-unknown".into(),b"second".to_vec(),"path".into()),
            ("D:".into(),"vol-d".into(),b"third".to_vec(),"path_and_drive".into()),
            ("D:".into(),"vol-unknown".into(),b"second".to_vec(),"path".into()),
        ]);
        let kinds: Vec<(String,i64,String,String)> = db.prepare(
            "SELECT destlist_accessed,access_count,hostname,timestamp_source FROM PathReferences").unwrap()
            .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(kinds,vec![("2026-01-01 12:00:00.000".into(),0,"HOST".into(),"destlist_accessed".into());4]);
        let files: Vec<(String,String,String,i64)> = db.prepare(
            "SELECT volume_id,source_relative,input_name,parent_seq FROM files.FileSystemEntries ORDER BY volume_id").unwrap()
            .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(files,vec![("vol-c".into(),"vol-c/$MFT".into(),"$MFT".into(),1),
            ("vol-d".into(),"vol-d/$MFT".into(),"$MFT".into(),1),
            ("vol-unknown".into(),"vol-unknown/$MFT".into(),"$MFT".into(),1)]);
        drop(db);
        let db = Connection::open(out_dir.join("_OVERVIEW/PathReferences.sqlite")).unwrap();
        db.execute("UPDATE PathReferenceCandidates SET volume_id='foreign-input'",[]).unwrap();
        assert!(validate_lineage(&out_dir).is_err());
        drop(db);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn build_all_publishes_every_database_even_with_no_evidence() {
        let (out_dir, target) = fixture("empty");
        let report = build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        assert_eq!(report.len(), 21);
        for (index, spec) in schema::SPECS.iter().enumerate() {
            assert_eq!(report[index].0, spec.name, "보고 순서는 문서 순서다");
            let conn = open(&out_dir, spec.name);
            let rows: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM {}", crate::sqlite::quote_ident(spec.table)),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rows, 0, "{}", spec.name);
            conn.query_row("SELECT count(*) FROM source_records", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        }
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn file_system_entries_maps_typed_mft_facts() {
        let (out_dir, target) = fixture("mft");
        facts_db(
            &out_dir,
            "_OVERVIEW/MFT_Records.sqlite",
            "CREATE TABLE MFT_Records (volume_id TEXT NOT NULL, volume_label TEXT, \
             volume_serial TEXT, drive_letter TEXT, ntfs_major_version INTEGER, \
             ntfs_minor_version INTEGER, volume_flags TEXT, path TEXT, file_name TEXT, \
             extension TEXT, is_directory INTEGER, in_use INTEGER, file_size INTEGER, data BLOB, \
             entry INTEGER, seq INTEGER, parent_entry INTEGER, si_created TEXT, si_modified TEXT, \
             si_mft_modified TEXT, si_accessed TEXT, owner_id TEXT, security_id TEXT, \
             fn_created TEXT, fn_modified TEXT, fn_mft_modified TEXT, fn_accessed TEXT, \
             _source_file TEXT NOT NULL,parent_seq INTEGER,parent_status TEXT,path_status TEXT,data_status TEXT);\
             INSERT INTO MFT_Records VALUES ('vol-1','SYSTEM',NULL,NULL,3,1,'0x0',\
             '\\Users\\a.txt','a.txt','txt',0,1,5,x'68656c6c6f',42,3,-1,\
             '2026-01-01 00:00:00.000','2026-01-02 03:04:05.678','2026-01-02 03:04:05.678',\
             '2026-01-03 00:00:00.000','7','9',NULL,NULL,NULL,NULL,'C:\\$MFT',NULL,'unknown','unknown','resident');",
        );
        let report = build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        assert_eq!(
            report
                .iter()
                .find(|(name, _)| name == "FileSystemEntries")
                .unwrap()
                .1,
            1
        );
        let conn = open(&out_dir, "FileSystemEntries");
        let (timestamp, kind, event_type, parent, size, owner, blob_type, blob_len, account): (
            String,
            String,
            String,
            Option<i64>,
            i64,
            i64,
            String,
            i64,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT timestamp, timestamp_kind, event_type, parent_entry, file_size, owner_id, \
                 typeof(data), length(data), account FROM FileSystemEntries",
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
                    ))
                },
            )
            .unwrap();
        assert_eq!(timestamp, "2026-01-02 03:04:05.678");
        assert_eq!(kind, "SI 수정 시각");
        assert_eq!(event_type, "파일");
        assert_eq!(parent, None);
        assert_eq!(size, 5);
        assert_eq!(owner, 7);
        assert_eq!(blob_type, "blob");
        assert_eq!(blob_len, 5);
        assert_eq!(account, None);
        let state: (Option<i64>, String, String, String) = conn.query_row(
            "SELECT parent_seq,parent_status,path_status,data_status FROM FileSystemEntries",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(state,(None,"unknown".into(),"unknown".into(),"resident".into()));
        let (db, table, rowid, dataset, file): (String, String, i64, String, String) = conn
            .query_row(
                "SELECT source_db, source_table, source_rowid, source_dataset_id, source_file \
                 FROM source_records",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(db, "_OVERVIEW/MFT_Records.sqlite");
        assert_eq!(table, "MFT_Records");
        assert_eq!(rowid, 1);
        assert_eq!(dataset, "facts-gen-1", "facts 세대를 그대로 가리킨다");
        assert_eq!(file, "C:\\$MFT");
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn usn_journal_streams_every_input_and_keeps_external_fields_null() {
        let (out_dir, target) = fixture("usn");
        let usn_ddl = "CREATE TABLE UsnJrnl_Records (timestamp TEXT, filename TEXT, reason TEXT, \
             file_attributes TEXT, mft_entry TEXT, parent_mft_entry TEXT, usn TEXT, \
             source_info TEXT, security_id TEXT, file_reference TEXT, \
             parent_file_reference TEXT, reason_mask TEXT, record_version TEXT, file_attributes_mask TEXT, _source_file TEXT);";
        facts_db(
            &out_dir,
            "FILESYSTEM/UsnJrnl_Records.sqlite",
            &format!(
                "{usn_ddl} INSERT INTO UsnJrnl_Records VALUES ('2026-02-03 10:11:12.000','a.txt',\
                 'FILE_DELETE|CLOSE','ARCHIVE','42','5','18446744073709551615','0','264',\
                 '281474976710700','281474976710661','2147484160','2','32','C:\\$Extend\\$UsnJrnl');"
            ),
        );
        facts_db(
            &out_dir,
            "FILESYSTEM/UsnJrnl_Records_2.sqlite",
            &format!(
                "{usn_ddl} INSERT INTO UsnJrnl_Records VALUES ('2026-02-04 10:11:12.000','b.txt',\
                 'FILE_CREATE','ARCHIVE','43','5','9','0','264','1','2','256','3','32','D:\\$Extend\\$UsnJrnl');"
            ),
        );
        let report = build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        assert_eq!(
            report.iter().find(|(name, _)| name == "UsnJournal").unwrap().1,
            2,
            "모든 $J 입력을 흘려 넣는다"
        );
        let conn = open(&out_dir, "UsnJournal");
        let (event_type, usn, reference, security, path, volume, journal, mask, version): (
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<i64>,
        ) = conn
            .query_row(
                "SELECT event_type, usn, file_reference, security_id, path, volume_id, \
                 journal_id, reason_mask, record_version FROM UsnJournal WHERE file_name='a.txt'",
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
                    ))
                },
            )
            .unwrap();
        assert_eq!(event_type, "삭제");
        assert_eq!(usn, "18446744073709551615");
        assert_eq!(reference, "281474976710700");
        assert_eq!(security, 264);
        assert_eq!((path, volume, journal), (None, None, None));
        assert_eq!(mask.as_deref(), Some("2147484160"));
        assert_eq!(version, Some(2));
        let sources: i64 = conn
            .query_row("SELECT count(*) FROM source_records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sources, 2);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn recycle_bin_maps_documented_facts_fields() {
        let (out_dir, target) = fixture("recyclebin");
        facts_db(
            &out_dir,
            "RECYCLEBIN/RecycleBin_Records.sqlite",
            "CREATE TABLE RecycleBin_Records (format_version INTEGER, original_path TEXT, \
             file_size INTEGER, deleted_time_raw TEXT, timestamp TEXT, account_sid TEXT, \
             account TEXT, volume_id TEXT, original_drive_letter TEXT, recycle_name TEXT, \
             r_exists INTEGER, _source_file TEXT NOT NULL, _status TEXT, _error TEXT);\
             INSERT INTO RecycleBin_Records VALUES (2,'C:\\Users\\a\\secret.docx',1234,\
             '133512345678901234','2026-03-04 05:06:07.890','S-1-5-21-1-2-3-1001',NULL,'vol-1',\
             'C:','$RABCDEF.docx',0,'C:\\$Recycle.Bin\\S-1-5-21-1-2-3-1001\\$IABCDEF.docx',\
             'ok',NULL);",
        );
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "RecycleBin");
        let (event_type, kind, version, size, raw, exists, status, error, account, sid): (
            String,
            String,
            i64,
            i64,
            String,
            i64,
            String,
            Option<String>,
            Option<String>,
            String,
        ) = conn
            .query_row(
                "SELECT event_type, timestamp_kind, format_version, file_size, deleted_time_raw, \
                 r_exists, status, error, account, account_sid FROM RecycleBin",
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
                    ))
                },
            )
            .unwrap();
        assert_eq!(event_type, "휴지통 이동");
        assert_eq!(kind, "휴지통 이동 시각");
        assert_eq!(version, 2);
        assert_eq!(size, 1234);
        assert_eq!(raw, "133512345678901234");
        assert_eq!(exists, 0);
        assert_eq!(status, "ok");
        assert_eq!(error, None);
        assert_eq!(account, None);
        assert_eq!(sid, "S-1-5-21-1-2-3-1001");
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn powershell_console_reassembles_commands_without_losing_physical_lines() {
        let (out_dir, target) = fixture("powershell-console-continuation");
        let a = target.join("a.txt");
        let b = target.join("b.txt");
        std::fs::write(&a, "foreach ($x in 1..2) {`\r\n  Add-Risk $x`\r\n}\r\nWrite-Output 'tick'``\r\nnext\r\nblank-tail`\r\n\r\nlast`\r\n").unwrap();
        std::fs::write(&b, "Get-Date\r\n").unwrap();
        let raw = crate::parsers::powershell_history::parse_console_history(&[a, b]).unwrap();
        assert_eq!(raw.len(), 9, "empty physical lines can terminate a continued command");
        let path = facts_db(&out_dir, "POWERSHELL/PowerShell_ConsoleHistory.sqlite",
            "CREATE TABLE PowerShell_ConsoleHistory(line_number TEXT,command TEXT,user TEXT,_source_file TEXT);");
        let facts = Connection::open(path).unwrap();
        for line in &raw {
            facts.execute("INSERT INTO PowerShell_ConsoleHistory VALUES (?1,?2,'same-user',?3)",
                rusqlite::params![line["line_number"],line["command"],line["_source_file"]]).unwrap();
        }
        facts.execute_batch("INSERT INTO PowerShell_ConsoleHistory VALUES
            ('10','gap`','same-user','c.txt'),('12','after','same-user','c.txt');").unwrap();
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "PowerShellHistory");
        let commands: Vec<(String,Option<String>)> = conn.prepare(
            "SELECT command,console_history_status FROM PowerShellHistory ORDER BY command")
            .unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(commands,vec![
            ("Get-Date".into(),None),
            ("Write-Output 'tick'`\nnext".into(),None),
            ("after".into(),None),
            ("blank-tail\n".into(),None),
            ("foreach ($x in 1..2) {\n  Add-Risk $x\n}".into(),None),
            ("gap\n".into(),Some("missing_line".into())),
            ("last\n".into(),Some("incomplete_continuation".into())),
        ]);
        let search: (i64,i64,Option<String>) = conn.query_row(
            "SELECT count(*),min(line_number),max(timestamp) FROM PowerShellHistory
             WHERE command LIKE '%foreach%Add-Risk%}'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(search,(1,1,None));
        let original: Vec<(String,i64,String)> = conn.prepare(
            "SELECT s.source_file,l.line_number,l.command FROM PowerShellConsoleLines l
             JOIN source_records s ON s.record_id=l.record_id AND s.ordinal=l.source_ordinal
             ORDER BY s.source_rowid").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        let mut expected: Vec<_> = raw.iter().map(|r|(
            r["_source_file"].clone(),r["line_number"].parse::<i64>().unwrap(),r["command"].clone())).collect();
        expected.extend([("c.txt".into(),10,"gap`".into()),("c.txt".into(),12,"after".into())]);
        assert_eq!(original,expected);
        let bad_refs: i64 = conn.query_row("SELECT count(*) FROM pragma_foreign_key_check",[],|r|r.get(0)).unwrap();
        assert_eq!(bad_refs,0);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn powershell_storage_preserves_full_text_errors_and_explicit_sessions() {
        let (out_dir, target) = fixture("powershell-text");
        let console_path = facts_db(&out_dir, "POWERSHELL/PowerShell_ConsoleHistory.sqlite",
            "CREATE TABLE PowerShell_ConsoleHistory(line_number TEXT,command TEXT,user TEXT,_source_file TEXT);");
        let console_command = format!("  Write-Output '{}'\n# 후반 검색 토큰  ", "가".repeat(450));
        Connection::open(console_path).unwrap().execute(
            "INSERT INTO PowerShell_ConsoleHistory VALUES ('17',?1,'unknown','ConsoleHost_history.txt')",
            [&console_command]).unwrap();
        let event_path = facts_db(&out_dir, "EVENTLOG/PowerShellTest.sqlite",
            "CREATE TABLE PowerShellTest(timestamp TEXT,Channel TEXT,Provider TEXT,EventID TEXT,
             EventRecordID TEXT,ProcessID TEXT,UserID TEXT,Level TEXT,EventData TEXT,
             _record_key TEXT,_source_file TEXT);");
        let event_command = format!("  CommandInvocation(Write-Output): {}\r\n후반 파이프라인  ", "x".repeat(450));
        let host = "powershell.exe -NoProfile -Command Write-Output 'a=b'\r\n; Write-Output '두 번째 줄'  ";
        let context = format!("        Host ID = host-session-1\r\n        Host Application = {host}\r\n        Engine Version = 5.1\r\n        Runspace ID = runspace-1\r\n        User = DOMAIN\\user\r\n");
        let pipeline = serde_json::json!({"ContextInfo":context,"Payload":event_command}).to_string();
        let error = serde_json::json!({"ContextInfo":context,"Payload":"Error Message = System error.\r\nfull warning"}).to_string();
        let facts = Connection::open(event_path).unwrap();
        for (id, event_id, payload) in [(1,"4103",&pipeline),(2,"4100",&error)] {
            facts.execute("INSERT INTO PowerShellTest VALUES ('2026-10-08 01:02:03.004',
                'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-PowerShell',?1,?2,
                '356','S-1-5-21-1-2-3-500','3',?3,?4,'PowerShell.evtx')",
                rusqlite::params![event_id,id.to_string(),payload,format!("PowerShellTest::{id}")]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "PowerShellHistory");
        let command: String = conn.query_row("SELECT command FROM PowerShellHistory WHERE line_number=17",
            [], |r| r.get(0)).unwrap();
        assert_eq!(command, console_command);
        let untimed: (Option<String>,Option<String>,Option<String>) = conn.query_row(
            "SELECT timestamp,session_id,runspace_id FROM PowerShellHistory WHERE line_number=17",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(untimed, (None,None,None));
        let preserved: (String,String,String,String,String) = conn.query_row(
            "SELECT command,host_application,session_id,runspace_id,event_data FROM PowerShellHistory WHERE event_id=4103",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        assert_eq!(preserved, (event_command,host.into(),"host-session-1".into(),"runspace-1".into(),pipeline));
        let warning: (String,i64,String,String) = conn.query_row(
            "SELECT error_message,event_level,event_data,account_sid FROM PowerShellHistory WHERE event_id=4100",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(warning, ("Error Message = System error.\r\nfull warning".into(),3,error,"S-1-5-21-1-2-3-500".into()));
        let searchable: i64 = conn.query_row("SELECT count(*) FROM PowerShellHistory WHERE command LIKE '%후반%'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(searchable, 2);
        let sources: i64 = conn.query_row("SELECT count(*) FROM source_records WHERE source_dataset_id='facts-gen-1'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(sources, 3);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn powershell_storage_retains_conflicting_fragments_and_all_sources() {
        let (out_dir, target) = fixture("powershell-parts");
        let path = facts_db(&out_dir, "EVENTLOG/PowerShellParts.sqlite",
            "CREATE TABLE PowerShellParts(timestamp TEXT,Channel TEXT,Provider TEXT,EventID TEXT,
             EventRecordID TEXT,ProcessID TEXT,UserID TEXT,EventData TEXT,_record_key TEXT,_source_file TEXT);");
        let facts = Connection::open(path).unwrap();
        for (id, number, body) in [(1,1,"first"),(2,3,"last"),(3,3,"conflict"),(4,1,"first")] {
            let payload = serde_json::json!({"ScriptBlockId":"block-1","MessageNumber":number,
                "MessageTotal":3,"ScriptBlockText":body,"Path":"C:\\evidence.ps1"}).to_string();
            facts.execute("INSERT INTO PowerShellParts VALUES ('2026-10-08 01:02:03.004',
                'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-PowerShell','4104',?1,
                '356','S-1-5-18',?2,?3,'PowerShell.evtx')",
                rusqlite::params![id.to_string(),payload,format!("PowerShellParts::{id}")]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "PowerShellHistory");
        let (expected, observed, missing, conflicts, status): (i64,i64,String,String,String) = conn.query_row(
            "SELECT script_block_expected_parts,script_block_observed_parts,script_block_missing,
             script_block_conflicts,script_block_status FROM PowerShellHistory",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        assert_eq!((expected,observed),(3,4));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&missing).unwrap(),serde_json::json!([{"start":2,"end":2}]));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&conflicts).unwrap(),serde_json::json!([3]));
        assert!(!status.is_empty());
        let parts: Vec<(i64,i64,String,i64,String)> = conn.prepare(
            "SELECT p.message_number,p.message_total,p.script_block,s.source_rowid,s.source_dataset_id
             FROM PowerShellScriptParts p JOIN source_records s
             ON s.record_id=p.record_id AND s.ordinal=p.source_ordinal ORDER BY s.source_rowid")
            .unwrap().query_map([], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(parts,vec![(1,3,"first".into(),1,"facts-gen-1".into()),
            (3,3,"last".into(),2,"facts-gen-1".into()),(3,3,"conflict".into(),3,"facts-gen-1".into()),
            (1,3,"first".into(),4,"facts-gen-1".into())]);
        let fk_errors: i64 = conn.query_row("SELECT count(*) FROM pragma_foreign_key_check",[],|r|r.get(0)).unwrap();
        assert_eq!(fk_errors,0);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn powershell_storage_separates_decoded_text_and_failure_from_original() {
        use base64::Engine;
        let (out_dir, target) = fixture("powershell-decode");
        let path = facts_db(&out_dir, "POWERSHELL/PowerShell_ConsoleHistory.sqlite",
            "CREATE TABLE PowerShell_ConsoleHistory(line_number TEXT,command TEXT,user TEXT,_source_file TEXT);");
        let decoded = "Write-Output '증거'\r\n# preserved";
        let bytes: Vec<u8> = decoded.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let original = format!("  powershell.exe -NoProfile -EncodedCommand \"{encoded}\"  ");
        let facts = Connection::open(path).unwrap();
        for (line,command) in [(1,original.as_str()),(2,"powershell -enc !!!"),(3,"Write-Output 'powershell -enc QQ=='")] {
            facts.execute("INSERT INTO PowerShell_ConsoleHistory VALUES (?1,?2,'user','ConsoleHost_history.txt')",
                rusqlite::params![line,command]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "PowerShellHistory");
        let success: (String,String,String,String,String) = conn.query_row(
            "SELECT h.command,d.encoded_command,d.decoded_command,d.decode_method,d.decode_status
             FROM PowerShellHistory h JOIN PowerShellEncodedCommands d USING(record_id) WHERE h.line_number=1",
            [], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        assert_eq!(success,(original,encoded,decoded.into(),"base64_utf16le".into(),"success".into()));
        let failure: (String,Option<String>,String) = conn.query_row(
            "SELECT d.encoded_command,d.decoded_command,d.decode_status
             FROM PowerShellHistory h JOIN PowerShellEncodedCommands d USING(record_id) WHERE h.line_number=2",
            [], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(failure,("!!!".into(),None,"invalid_base64".into()));
        let false_positive: i64 = conn.query_row(
            "SELECT count(*) FROM PowerShellHistory h JOIN PowerShellEncodedCommands d USING(record_id) WHERE h.line_number=3",
            [],|r|r.get(0)).unwrap();
        assert_eq!(false_positive,0);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn execution_history_keeps_process_events_and_identity_roles() {
        let (out_dir, target) = fixture("execution-events");
        let path = facts_db(&out_dir, "EVENTLOG/Security.sqlite",
            "CREATE TABLE Security(timestamp TEXT, Channel TEXT, Provider TEXT, EventID TEXT,
             EventRecordID TEXT, ProcessID TEXT, ThreadID TEXT, UserID TEXT, EventData TEXT,
             _record_key TEXT, _source_file TEXT);");
        let facts = Connection::open(path).unwrap();
        let payload = serde_json::json!({
            "NewProcessName": "C:\\Windows\\child.exe", "NewProcessId": "0x2bc",
            "ProcessId": "0xe74", "ParentProcessName": "C:\\Windows\\parent.exe",
            "CommandLine": "  \"C:\\Windows\\child.exe\" /run  ",
            "SubjectUserSid": "S-1-5-18", "SubjectUserName": "HOST$",
            "SubjectDomainName": "DOMAIN", "SubjectLogonId": "0x3e7",
            "TargetUserSid": "S-1-5-21-1-2-3-1104", "TargetUserName": "target",
            "TargetDomainName": "DOMAIN", "TargetLogonId": "0x4a5af0",
            "TokenElevationType": "%%1938", "MandatoryLabel": "S-1-16-8192"
        }).to_string();
        let no_target = serde_json::json!({"EventXML": {
            "NewProcessId": "0", "SubjectUserSid": "S-1-5-18",
            "TargetUserSid": "S-1-0-0", "TargetUserName": "-", "CommandLine": ""
        }}).to_string();
        let target_without_sid = serde_json::json!({
            "SubjectUserSid": "S-1-5-18", "TargetUserName": "other"
        }).to_string();
        for (id, provider, channel, eid, data) in [
            (1, "Microsoft-Windows-Security-Auditing", "Security", "4688", payload.as_str()),
            (2, "Microsoft-Windows-Security-Auditing", "Security", "4688", "{}"),
            (3, "Other-Provider", "Security", "4688", payload.as_str()),
            (4, "Microsoft-Windows-Security-Auditing", "Other-Channel", "4688", payload.as_str()),
            (5, "Microsoft-Windows-Security-Auditing", "Security", "4689", payload.as_str()),
            (6, "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", "4104", "{}"),
            (7, "Microsoft-Windows-Security-Auditing", "Security", "4688", &no_target),
            (8, "Microsoft-Windows-Security-Auditing", "Security", "4688", &target_without_sid),
        ] {
            facts.execute("INSERT INTO Security VALUES (?1,?2,?3,?4,?5,'4','400','S-1-5-19',?6,?7,'Security.evtx')",
                rusqlite::params!["2026-10-07 09:00:00.123", channel, provider, eid,
                    id.to_string(), data, format!("Security::{id}")]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "ExecutionHistory");
        let count: i64 = conn.query_row("SELECT count(*) FROM ExecutionHistory", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 4);
        let row = conn.query_row(
            "SELECT program_path,process_id,parent_process_id,parent_process_path,command_line,
             account_sid,subject_user_sid,event_process_id,event_data,timestamp_kind
             FROM ExecutionHistory WHERE event_record_id='1'", [], |r| {
                Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?,r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,r.get::<_, String>(4)?,r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,r.get::<_, String>(7)?,r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?))
            }).unwrap();
        assert_eq!(row.0, "C:\\Windows\\child.exe");
        assert_eq!(row.1, "0x2bc");
        assert_eq!(row.2, "0xe74");
        assert_eq!(row.3, "C:\\Windows\\parent.exe");
        assert_eq!(row.4, "  \"C:\\Windows\\child.exe\" /run  ");
        assert_eq!(row.5, "S-1-5-21-1-2-3-1104");
        assert_eq!(row.6, "S-1-5-18");
        assert_eq!(row.7, "4");
        assert_eq!(row.8, payload);
        assert_eq!(row.9, "프로세스 생성 시각");
        let absent: (Option<String>, Option<String>, Option<String>) = conn.query_row(
            "SELECT program_path,account_sid,command_line FROM ExecutionHistory WHERE event_record_id='2'",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(absent, (None, None, None));
        let creator: (String, String, String, Option<String>) = conn.query_row(
            "SELECT account_role,account_sid,process_id,command_line FROM ExecutionHistory WHERE event_record_id='7'",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(creator, ("creator".into(), "S-1-5-18".into(), "0".into(), None));
        let unknown_target: (String, Option<String>) = conn.query_row(
            "SELECT account_role,account_sid FROM ExecutionHistory WHERE event_record_id='8'",
            [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(unknown_target, ("target".into(), None));
        let refs: Vec<(i64, String)> = conn.prepare(
            "SELECT source_rowid,source_dataset_id FROM source_records ORDER BY source_rowid")
            .unwrap().query_map([], |r| Ok((r.get(0)?,r.get(1)?))).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(refs, vec![(1, "facts-gen-1".into()), (2, "facts-gen-1".into()),
            (7, "facts-gen-1".into()), (8, "facts-gen-1".into())]);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn execution_history_keeps_shell_commands_without_inventing_processes() {
        let (out_dir, target) = fixture("execution-shell");
        let path = facts_db(&out_dir, "EVENTLOG/Shell.sqlite",
            "CREATE TABLE Shell(timestamp TEXT, Channel TEXT, Provider TEXT, EventID TEXT,
             ProcessID TEXT, UserID TEXT, EventData TEXT, _record_key TEXT, _source_file TEXT);");
        let facts = Connection::open(path).unwrap();
        let command = "  \"C:\\Program Files\\도구.exe\" --start  ";
        for (id, eid, payload) in [
            (1, "9707", serde_json::json!({"Command": command})),
            (2, "9708", serde_json::json!({"EventXML": {"Command": command, "PID": 0}})),
            (3, "9708", serde_json::json!({})),
        ] {
            facts.execute(
                "INSERT INTO Shell VALUES (NULL,'Microsoft-Windows-Shell-Core/Operational',
                 'Microsoft-Windows-Shell-Core',?1,'999','S-1-5-19',?2,?3,'Shell.evtx')",
                rusqlite::params![eid, payload.to_string(), format!("Shell::{id}")]).unwrap();
        }
        drop(facts);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "ExecutionHistory");
        let rows: Vec<(Option<String>, Option<String>, Option<String>, String, String, Option<String>)> =
            conn.prepare("SELECT e.command_line,e.process_id,e.program_path,e.event_process_id,
                e.account_role,e.timestamp FROM ExecutionHistory e JOIN source_records s USING(record_id)
                ORDER BY s.source_rowid").unwrap().query_map([], |r| {
                    Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))
                }).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![
            (Some(command.into()), None, None, "999".into(), "event_subject".into(), None),
            (Some(command.into()), Some("0".into()), None, "999".into(), "event_subject".into(), None),
            (None, None, None, "999".into(), "event_subject".into(), None),
        ]);
        drop(conn);
        std::fs::remove_dir_all(out_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn execution_history_moves_prefetch_times_and_volume_to_children() {
        let (out_dir, target) = fixture("prefetch");
        facts_db(
            &out_dir,
            "PREFETCH/Prefetch_Execution.sqlite",
            "CREATE TABLE Prefetch_Execution (last_run_time TEXT, run_time_2 TEXT, \
             run_time_3 TEXT, executable_filename TEXT, prefetch_hash TEXT, run_count TEXT, \
             volume_device_path TEXT, volume_serial_number TEXT, volume_creation_time TEXT, \
             _source_file TEXT);\
             INSERT INTO Prefetch_Execution VALUES ('2026-04-05 06:07:08.900',\
             '2026-04-04 06:07:08.900','','evil.exe','ABCD1234','7',\
             '\\DEVICE\\HARDDISKVOLUME2','1A2B3C4D','2026-01-01 00:00:00.000',\
             'C:\\Windows\\Prefetch\\EVIL.EXE-ABCD1234.pf');",
        );
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "ExecutionHistory");
        let (record_id, event_type, run_count, timestamp): (String, String, i64, String) = conn
            .query_row(
                "SELECT record_id, event_type, run_count, timestamp FROM ExecutionHistory",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(event_type, "Prefetch");
        assert_eq!(run_count, 7);
        assert_eq!(timestamp, "2026-04-05 06:07:08.900");
        let times: Vec<String> = conn
            .prepare("SELECT execution_time FROM ExecutionTimes WHERE record_id=?1 ORDER BY ordinal")
            .unwrap()
            .query_map([&record_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(times, vec!["2026-04-04 06:07:08.900".to_string()]);
        let (device, serial): (String, String) = conn
            .query_row(
                "SELECT device_path, serial_number FROM ExecutionVolumes WHERE record_id=?1",
                [&record_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(device, "\\DEVICE\\HARDDISKVOLUME2");
        assert_eq!(serial, "1A2B3C4D");
        let source: String = conn
            .query_row("SELECT source_file FROM source_records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(source, "C:\\Windows\\Prefetch\\EVIL.EXE-ABCD1234.pf");
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn scheduled_tasks_keep_definitions_and_events_as_separate_rows() {
        let (out_dir, target) = fixture("tasks");
        facts_db(
            &out_dir,
            "TASKSCHEDULER/TaskScheduler_Tasks.sqlite",
            "CREATE TABLE TaskScheduler_Tasks (timestamp TEXT, task_name TEXT, enabled TEXT, \
             hidden TEXT, run_as TEXT, run_level TEXT, actions TEXT, trigger_types TEXT, \
             trigger_start TEXT, actions_json TEXT, triggers_json TEXT, author TEXT, \
             description TEXT, logon_type TEXT, uri TEXT, _source_file TEXT);\
             INSERT INTO TaskScheduler_Tasks VALUES ('2026-05-06 07:08:09.000','Updater','true',\
             'false','SYSTEM','HighestAvailable','cmd.exe /c evil.bat','LogonTrigger',\
             '2026-05-01 00:00:00.000',\
             '[{\"action_type\":\"Exec\",\"command\":\"cmd.exe\",\"arguments\":\"/c evil.bat\",\
             \"working_directory\":null,\"raw\":\"cmd.exe /c evil.bat\"}]',\
             '[{\"trigger_type\":\"LogonTrigger\",\"start_time\":\"2026-05-01 00:00:00.000\",\
             \"end_time\":null,\"enabled\":true,\"raw\":\"<LogonTrigger/>\"}]',\
             'attacker','backdoor','InteractiveToken','\\Updater',\
             'C:\\Windows\\System32\\Tasks\\Updater');",
        );
        facts_db(
            &out_dir,
            "EVENTLOG/TaskScheduler.sqlite",
            "CREATE TABLE TaskScheduler (timestamp TEXT, Provider TEXT, EventID TEXT, \
             EventData TEXT, _record_key TEXT, _source_file TEXT);\
             INSERT INTO TaskScheduler VALUES ('2026-05-07 01:02:03.000',\
             'Microsoft-Windows-TaskScheduler','102','{\"TaskName\":\"\\\\Updater\"}',\
             'TaskScheduler::1','C:\\Windows\\System32\\winevt\\Logs\\TaskScheduler.evtx');",
        );
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();
        let conn = open(&out_dir, "ScheduledTasks");
        let rows: Vec<(String, Option<i64>, String)> = conn
            .prepare("SELECT event_type, event_id, record_id FROM ScheduledTasks ORDER BY event_type")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        let definition = rows.iter().find(|(kind, _, _)| kind == "작업 정의").unwrap();
        let event = rows.iter().find(|(kind, _, _)| kind == "작업 완료").unwrap();
        assert_eq!(definition.1, None);
        assert_eq!(event.1, Some(102));
        let (action_type, command, arguments): (String, String, Option<String>) = conn
            .query_row(
                "SELECT action_type, command, arguments FROM TaskActions WHERE record_id=?1",
                [&definition.2],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(action_type, "Exec");
        assert_eq!(command, "cmd.exe");
        assert_eq!(arguments.as_deref(), Some("/c evil.bat"));
        let (trigger_type, enabled): (String, i64) = conn
            .query_row(
                "SELECT trigger_type, enabled FROM TaskTriggers WHERE record_id=?1",
                [&definition.2],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(trigger_type, "LogonTrigger");
        assert_eq!(enabled, 1);
        let (db, table, rowid): (String, String, i64) = conn
            .query_row(
                "SELECT source_db, source_table, source_rowid FROM source_records WHERE record_id=?1",
                [&event.2],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(db, "EVENTLOG/TaskScheduler.sqlite");
        assert_eq!(table, "TaskScheduler");
        assert_eq!(rowid, 1);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }

    #[test]
    fn hosts_and_mpdetection_rows_point_at_real_raw_rows() {
        let (out_dir, target) = fixture("ancillary");
        let etc = target.join("Windows").join("System32").join("drivers").join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("hosts"),
            "# 주석 줄\n10.0.0.5 payload.example # 설명\n",
        )
        .unwrap();
        let support = target
            .join("ProgramData")
            .join("Microsoft")
            .join("Windows Defender")
            .join("Support");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::write(
            support.join("MPDetection-20260322.log"),
            "2026-03-22T17:20:21.623 DETECTION Trojan:Win32/Evil file:_C:\\temp\\evil.exe\n",
        )
        .unwrap();

        let published = prepare_ancillary_facts(&out_dir, &target, "facts-gen-1").unwrap();
        assert_eq!(published, vec![ancillary::ANCILLARY_DB.to_string()]);
        build_all(&out_dir, &target, "host-1", "ds-1").unwrap();

        let conn = open(&out_dir, "TargetInfo");
        let (name, value, db, table, rowid, artifact, dataset, file): (
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT t.name, t.value, s.source_db, s.source_table, s.source_rowid, \
                 s.source_artifact, s.source_dataset_id, s.source_file \
                 FROM TargetInfo t JOIN source_records s ON s.record_id = t.record_id \
                 WHERE t.category = 'HostsFile'",
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
                    ))
                },
            )
            .unwrap();
        assert_eq!(name, "payload.example");
        assert_eq!(value, "10.0.0.5");
        assert_eq!(db, ancillary::ANCILLARY_DB);
        assert_eq!(table, ancillary::HOSTS_TABLE);
        assert_eq!(rowid, 1);
        assert_eq!(artifact, ancillary::HOSTS_ARTIFACT);
        assert_eq!(dataset, "facts-gen-1");
        assert!(file.ends_with("hosts"), "{file}");

        let conn = open(&out_dir, "Defender");
        let (section, threat, source, table, artifact, rowid): (
            String,
            String,
            String,
            String,
            String,
            i64,
        ) = conn
            .query_row(
                "SELECT d.section, d.threat_name, d.source, s.source_table, s.source_artifact, \
                 s.source_rowid FROM Defender d JOIN source_records s ON s.record_id = d.record_id \
                 WHERE d.source = 'MPDetection'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(section, "threat");
        assert_eq!(threat, "Trojan:Win32/Evil");
        assert_eq!(source, "MPDetection");
        assert_eq!(table, ancillary::DEFENDER_TABLE);
        assert_eq!(artifact, ancillary::DEFENDER_ARTIFACT);
        assert_eq!(rowid, 1);
        let _ = std::fs::remove_dir_all(out_dir.parent().unwrap());
    }
}
