//! SQLite writer with the same semantics as the Python `write_rows_to_sqlite`:
//! every column is TEXT, column order = preferred fields (that are present)
//! followed by the remaining keys sorted alphabetically. One table per call.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

/// A row is an ordered-by-key map of column -> text value. Missing columns are
/// written as "" (matching the Python `.get(f, "")`).
pub type Row = BTreeMap<String, String>;

pub fn write_table(
    db_path: &Path,
    table_name: &str,
    rows: &[Row],
    preferred_order: &[&str],
) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut conn = Connection::open(db_path)?;
    // 스테이징 출력은 실패 시 통째로 폐기되므로 내구성 보장(journal/fsync)이
    // 필요 없다 — StreamWriter와 같은 설정으로 대량 insert를 빠르게 한다.
    conn.pragma_update(None, "journal_mode", "OFF").ok();
    conn.pragma_update(None, "synchronous", "OFF").ok();
    conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", table_name), [])?;
    if rows.is_empty() {
        return Ok(());
    }

    // Union of all keys across rows.
    let mut all_keys: BTreeMap<String, ()> = BTreeMap::new();
    for r in rows {
        for k in r.keys() {
            all_keys.insert(k.clone(), ());
        }
    }
    // preferred (present) first, then the rest in sorted (BTreeMap) order.
    let mut columns: Vec<String> = Vec::new();
    for p in preferred_order {
        if all_keys.contains_key(*p) {
            columns.push((*p).to_string());
        }
    }
    for k in all_keys.keys() {
        if !columns.iter().any(|c| c == k) {
            columns.push(k.clone());
        }
    }

    let cols_sql = columns
        .iter()
        .map(|c| format!("\"{}\" TEXT", c))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!("CREATE TABLE \"{}\" ({})", table_name, cols_sql),
        [],
    )?;

    let placeholders = vec!["?"; columns.len()].join(", ");
    let quoted = columns
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!(
        "INSERT INTO \"{}\" ({}) VALUES ({})",
        table_name, quoted, placeholders
    );

    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(&insert_sql)?;
        for r in rows {
            // Absent column -> SQL NULL (matches Python's None -> NULL); a key
            // present with "" stays an empty TEXT. MFT/registry insert every
            // column, so they are unaffected.
            let vals: Vec<Option<&str>> = columns
                .iter()
                .map(|c| r.get(c).map(|s| s.as_str()))
                .collect();
            stmt.execute(rusqlite::params_from_iter(vals))?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Like `write_table`, but the column set is given explicitly (used for a
/// generic table copy where an all-NULL source column must still exist in the
/// output). Columns are emitted in `preferred_order` order then the remaining
/// given columns sorted — matching the Python writer. Absent keys bind NULL.
pub fn write_table_cols(
    db_path: &Path,
    table_name: &str,
    rows: &[Row],
    all_columns: &[String],
    preferred_order: &[&str],
) -> Result<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut conn = Connection::open(db_path)?;
    conn.pragma_update(None, "journal_mode", "OFF").ok();
    conn.pragma_update(None, "synchronous", "OFF").ok();
    conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", table_name), [])?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut keys: BTreeMap<String, ()> = BTreeMap::new();
    for c in all_columns {
        keys.insert(c.clone(), ());
    }
    let mut columns: Vec<String> = Vec::new();
    for p in preferred_order {
        if keys.contains_key(*p) {
            columns.push((*p).to_string());
        }
    }
    for k in keys.keys() {
        if !columns.iter().any(|c| c == k) {
            columns.push(k.clone());
        }
    }
    let cols_sql = columns
        .iter()
        .map(|c| format!("\"{}\" TEXT", c))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!("CREATE TABLE \"{}\" ({})", table_name, cols_sql),
        [],
    )?;
    let placeholders = vec!["?"; columns.len()].join(", ");
    let quoted = columns
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!(
        "INSERT INTO \"{}\" ({}) VALUES ({})",
        table_name, quoted, placeholders
    );
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(&insert_sql)?;
        for r in rows {
            let vals: Vec<Option<&str>> = columns
                .iter()
                .map(|c| r.get(c).map(|s| s.as_str()))
                .collect();
            stmt.execute(rusqlite::params_from_iter(vals))?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Streaming table writer for parsers whose column universe is known up front
/// (MFT, registry, USN, evtx, per-table SRUM). Rows are buffered and flushed to
/// SQLite in batches so memory stays bounded no matter how many records — the
/// whole result never lives in RAM at once. Column order and NULL-for-absent
/// semantics match `write_table_cols`, so output is identical.
pub struct StreamWriter {
    conn: Connection,
    columns: Vec<String>,
    insert_sql: String,
    buf: Vec<Row>,
    batch: usize,
    /// Approximate bytes buffered. Rows with large values (browser-cache
    /// bodies) flush well before `batch` rows so memory stays bounded.
    buffered_bytes: usize,
    total: usize,
}

/// Flush the row buffer once it holds roughly this many bytes, regardless of
/// row count. Small-row tables (MFT, EventLog) never reach it and keep the
/// row-count batching.
const BATCH_BYTE_LIMIT: usize = 64 * 1024 * 1024;

impl StreamWriter {
    /// `universe` = every column the table can contain; `preferred` = leading
    /// order (present ones first, remaining sorted) — same rule as write_table.
    pub fn create(
        db_path: &Path,
        table_name: &str,
        universe: &[&str],
        preferred: &[&str],
    ) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)?;
        conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", table_name), [])?;
        conn.pragma_update(None, "journal_mode", "OFF").ok();
        conn.pragma_update(None, "synchronous", "OFF").ok();

        let mut keys: BTreeMap<String, ()> = BTreeMap::new();
        for c in universe {
            keys.insert((*c).to_string(), ());
        }
        let mut columns: Vec<String> = Vec::new();
        for p in preferred {
            if keys.contains_key(*p) {
                columns.push((*p).to_string());
            }
        }
        for k in keys.keys() {
            if !columns.iter().any(|c| c == k) {
                columns.push(k.clone());
            }
        }

        let cols_sql = columns
            .iter()
            .map(|c| format!("\"{}\" TEXT", c))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute(
            &format!("CREATE TABLE \"{}\" ({})", table_name, cols_sql),
            [],
        )?;
        let placeholders = vec!["?"; columns.len()].join(", ");
        let quoted = columns
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect::<Vec<_>>()
            .join(", ");
        let insert_sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            table_name, quoted, placeholders
        );
        Ok(Self {
            conn,
            columns,
            insert_sql,
            buf: Vec::new(),
            batch: 50_000,
            buffered_bytes: 0,
            total: 0,
        })
    }

    pub fn push(&mut self, row: Row) -> Result<()> {
        self.buffered_bytes += row
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
        self.buf.push(row);
        if self.buf.len() >= self.batch || self.buffered_bytes >= BATCH_BYTE_LIMIT {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(&self.insert_sql)?;
            for r in &self.buf {
                let vals: Vec<Option<&str>> = self
                    .columns
                    .iter()
                    .map(|c| r.get(c).map(|s| s.as_str()))
                    .collect();
                stmt.execute(rusqlite::params_from_iter(vals))?;
            }
        }
        tx.commit()?;
        self.total += self.buf.len();
        self.buf.clear();
        self.buffered_bytes = 0;
        Ok(())
    }

    pub fn finish(mut self) -> Result<usize> {
        self.flush()?;
        Ok(self.total)
    }
}
