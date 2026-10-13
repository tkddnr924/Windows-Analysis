//! EventLogInputs manifest shared by every view's per-log collection
//! observation, so stem resolution and the collection-state vocabulary stay in
//! one place. Event/corrupted counts stay with each view: they describe which
//! facts rows that view incorporated.
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use rusqlite::{Connection, OpenFlags};

use super::{Ctx, SourceRef};
use crate::parsers::eventlog::{
    INPUTS_RELATIVE, INPUTS_TABLE, INPUT_STATUS_DISCOVERY_COMPLETE, INPUT_STATUS_PARSED,
    INPUT_STATUS_READ_FAILED,
};

/// One manifest row for a collected (or unreadable) event log.
pub(super) struct LogInput {
    rowid: i64,
    /// Facts table, or the source file stem when no table was published.
    pub log_name: String,
    pub source_file: Option<String>,
    /// Empty manifest values are stored as NULL.
    pub facts_db: Option<String>,
    pub facts_table: Option<String>,
    status: String,
    /// Stored facts rows, corrupted_chunk rows included.
    pub input_rows: Option<i64>,
    pub error: Option<String>,
}

impl LogInput {
    pub fn parsed(&self) -> bool {
        self.status == INPUT_STATUS_PARSED
    }

    pub fn collection_state(&self) -> &'static str {
        match (self.status.as_str(), self.input_rows) {
            (INPUT_STATUS_READ_FAILED, _) => "read_failed",
            (INPUT_STATUS_PARSED, Some(0)) => "collected_empty",
            (INPUT_STATUS_PARSED, Some(_)) => "collected",
            _ => "unknown",
        }
    }
}

pub(super) struct LogInputs {
    path: PathBuf,
    discovered: bool,
    pub logs: Vec<LogInput>,
}

impl LogInputs {
    /// Manifest rows whose log name satisfies `relevant`, in manifest order.
    /// A missing manifest yields no rows and an undiscovered collection.
    pub fn read(ctx: &Ctx, relevant: impl Fn(&str) -> bool) -> Result<Self> {
        let path = ctx.out_dir.join(INPUTS_RELATIVE);
        let mut inputs = Self { path, discovered: false, logs: Vec::new() };
        if !inputs.path.is_file() {
            return Ok(inputs);
        }
        let conn = Connection::open_with_flags(&inputs.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        inputs.discovered = conn.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {INPUTS_TABLE} WHERE status=?1)"),
            [INPUT_STATUS_DISCOVERY_COMPLETE],
            |row| row.get(0),
        )?;
        let mut query = conn.prepare(&format!(
            "SELECT rowid,source_file,facts_db,facts_table,status,row_count,error FROM {INPUTS_TABLE} \
             WHERE status<>?1 ORDER BY rowid"
        ))?;
        let mut rows = query.query([INPUT_STATUS_DISCOVERY_COMPLETE])?;
        while let Some(row) = rows.next()? {
            let source_file: Option<String> = row.get(1)?;
            let facts_table = row.get::<_, Option<String>>(3)?.filter(|value| !value.is_empty());
            let log_name = facts_table
                .clone()
                .unwrap_or_else(|| file_stem(source_file.as_deref().unwrap_or("")).to_string());
            if !relevant(&log_name) {
                continue;
            }
            inputs.logs.push(LogInput {
                rowid: row.get(0)?,
                log_name,
                source_file,
                facts_db: row.get::<_, Option<String>>(2)?.filter(|value| !value.is_empty()),
                facts_table,
                status: row.get(4)?,
                input_rows: row
                    .get::<_, Option<String>>(5)?
                    .and_then(|value| value.parse::<i64>().ok()),
                error: row.get(6)?,
            });
        }
        Ok(inputs)
    }

    /// Provenance of a manifest row.
    pub fn source(&self, ctx: &Ctx, input: &LogInput) -> Result<SourceRef> {
        ctx.facts
            .source_from_row(
                &self.path,
                INPUTS_TABLE,
                input.rowid,
                input.source_file.as_deref(),
                Some("collection_observation"),
            )?
            .ok_or_else(|| anyhow!("{INPUTS_TABLE} 원본 좌표를 찾지 못했습니다"))
    }

    /// State of an expected log with no manifest row: only a completed
    /// discovery proves it was not collected.
    pub fn absent_state(&self) -> &'static str {
        if self.discovered {
            "not_collected"
        } else {
            "unknown"
        }
    }
}

/// File name without directory or last extension; both separators count
/// because manifests may hold Windows paths. A name without '.' stays whole.
fn file_stem(file: &str) -> &str {
    let base = file.rsplit(['/', '\\']).next().unwrap_or("");
    base.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(base)
}
