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

/// SQLite 식별자 인용 — 원본에서 온 테이블·열 이름(증거 데이터)에 큰따옴표가
/// 있어도 DROP/CREATE/INSERT가 깨지지 않게 SQLite 규칙(`""`)으로 이스케이프한다.
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// 파생 테이블의 생성 로직 버전을 산출물 안에 남긴다. 뷰어는 스키마(컬럼)만
/// 보고 최신 여부를 판단할 수 없다 — 컬럼이 같아도 편입 대상이 늘어난 경우가
/// 있어(예: ExecutionHistory의 WER 실행 증거) 구 저장본을 최신으로 오판한다.
/// `_wina_` 접두 테이블은 목록·검색에서 이미 숨겨지는 내부 메타다.
pub fn stamp_derived_version(db_path: &Path, name: &str, version: i64) -> Result<()> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _wina_derived_version (name TEXT PRIMARY KEY, version INTEGER)",
        [],
    )?;
    conn.execute(
        "INSERT INTO _wina_derived_version (name, version) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET version = excluded.version",
        rusqlite::params![name, version],
    )?;
    Ok(())
}

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
    conn.execute(&format!("DROP TABLE IF EXISTS {}", quote_ident(table_name)), [])?;
    if rows.is_empty() {
        // 0건 결과도 스키마는 남긴다 — parse_report가 "0행 발행"으로 기록한
        // derived 테이블을 뷰어·검증 도구가 sqlite_master에서 찾을 수 있어야
        // 보고서와 저장소의 계약이 일치한다. 고정 컬럼을 받은 경우에만 가능.
        if !preferred_order.is_empty() {
            let cols_sql = preferred_order
                .iter()
                .map(|c| format!("{} TEXT", quote_ident(c)))
                .collect::<Vec<_>>()
                .join(", ");
            conn.execute(
                &format!("CREATE TABLE {} ({})", quote_ident(table_name), cols_sql),
                [],
            )?;
        }
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
        .map(|c| format!("{} TEXT", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!("CREATE TABLE {} ({})", quote_ident(table_name), cols_sql),
        [],
    )?;

    let placeholders = vec!["?"; columns.len()].join(", ");
    let quoted = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_ident(table_name),
        quoted,
        placeholders
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
    conn.execute(&format!("DROP TABLE IF EXISTS {}", quote_ident(table_name)), [])?;
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
        .map(|c| format!("{} TEXT", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!("CREATE TABLE {} ({})", quote_ident(table_name), cols_sql),
        [],
    )?;
    let placeholders = vec!["?"; columns.len()].join(", ");
    let quoted = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        quote_ident(table_name),
        quoted,
        placeholders
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
        conn.execute(&format!("DROP TABLE IF EXISTS {}", quote_ident(table_name)), [])?;
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
            .map(|c| format!("{} TEXT", quote_ident(c)))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute(
            &format!("CREATE TABLE {} ({})", quote_ident(table_name), cols_sql),
            [],
        )?;
        let placeholders = vec!["?"; columns.len()].join(", ");
        let quoted = columns
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ");
        let insert_sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_ident(table_name),
            quoted,
            placeholders
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rows_with_fixed_columns_create_schema() {
        let root = std::env::temp_dir().join(format!(
            "wina-empty-schema-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("derived.sqlite");
        // 0건 derived 결과도 보고서(0행 발행)와 저장소가 일치해야 한다 —
        // 고정 컬럼이 주어지면 빈 테이블 스키마를 생성한다.
        write_table(&db, "RegistryFindings", &[], &["timestamp", "category"]).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='RegistryFindings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM RegistryFindings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn identifiers_with_quotes_roundtrip_safely() {
        let root = std::env::temp_dir().join(format!(
            "wina-quote-ident-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let db = root.join("quoted.sqlite");
        // 원본 스키마·value name은 증거 데이터다 — 큰따옴표가 든 테이블·열
        // 이름도 저장이 깨지면 안 된다.
        let table = r#"evil"table"#;
        let column = r#"va"lue"#;
        let mut row = Row::new();
        row.insert(column.to_string(), "x".to_string());
        write_table(&db, table, &[row], &[]).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", quote_ident(table)),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let mut writer = StreamWriter::create(&db, table, &[column], &[]).unwrap();
        let mut row = Row::new();
        row.insert(column.to_string(), "y".to_string());
        writer.push(row).unwrap();
        assert_eq!(writer.finish().unwrap(), 1);
        let _ = std::fs::remove_dir_all(root);
    }
}
