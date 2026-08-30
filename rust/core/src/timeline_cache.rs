//! 통합 타임라인 캐시 — 가공 단계에서 뷰어가 그대로 읽는
//! `_master_timeline.cache.json`을 만든다. 뷰어의 buildMasterTimeline과 같은
//! 구성(타임라인 대상 6종)과 필터를 적용하고, 표시 문구(summary/subtitle)와
//! 태그는 뷰어가 로드 시 스펙 함수로 채운다(문구·태그 정의는 TS 한 곳 유지).
//!
//! 대상: _OVERVIEW/ExecutionHistory · _OVERVIEW/ScheduledTasks ·
//! _OVERVIEW/BrowserActivity(visit/download만) · JUMPLIST/JumpList_Entries ·
//! WER/WER_Reports · EVENTLOG/*(EventID != "0"). 시각 없는 행은 제외, 최신순 정렬.
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};

type RowMap = Map<String, Value>;

/// 한 소스 테이블을 읽어 (timestamp, 직렬화된 entry) 목록에 누적한다.
fn collect_table(
    db_path: &Path,
    table: &str,
    category: &str,
    full_path: &str,
    filter: &dyn Fn(&RowMap) -> bool,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    if !db_path.is_file() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    // 캐시 대상 파일에 해당 테이블이 없으면(예: 빈 DB) 조용히 건너뛴다.
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return Ok(());
    }
    let mut stmt = conn.prepare(&format!("SELECT rowid, * FROM \"{}\"", table))?;
    let columns: Vec<String> = stmt
        .column_names()
        .iter()
        .skip(1)
        .map(|name| name.to_string())
        .collect();
    let columns_json = Value::Array(columns.iter().cloned().map(Value::String).collect());
    let mut rows = stmt.query([])?;
    while let Some(sqlite_row) = rows.next()? {
        let rowid: i64 = sqlite_row.get(0)?;
        let mut row = RowMap::new();
        for (index, column) in columns.iter().enumerate() {
            let value = match sqlite_row.get_ref(index + 1)? {
                rusqlite::types::ValueRef::Null => String::new(),
                rusqlite::types::ValueRef::Integer(v) => v.to_string(),
                rusqlite::types::ValueRef::Real(v) => v.to_string(),
                rusqlite::types::ValueRef::Text(v) => String::from_utf8_lossy(v).to_string(),
                rusqlite::types::ValueRef::Blob(_) => String::new(),
            };
            row.insert(column.clone(), Value::String(value));
        }
        let timestamp = row
            .get("timestamp")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        // 시각이 없는 행은 타임라인에 놓을 자리가 없다.
        if timestamp.is_empty() || !filter(&row) {
            continue;
        }
        let mut entry = RowMap::new();
        entry.insert("timestamp".into(), Value::String(timestamp.clone()));
        entry.insert("category".into(), Value::String(category.to_string()));
        entry.insert("table".into(), Value::String(table.to_string()));
        entry.insert("summary".into(), Value::String(String::new()));
        entry.insert("subtitle".into(), Value::String(String::new()));
        entry.insert("rowid".into(), Value::from(rowid));
        entry.insert("fullPath".into(), Value::String(full_path.to_string()));
        entry.insert("row".into(), Value::Object(row));
        entry.insert("columns".into(), columns_json.clone());
        // tags는 의도적으로 비워 둔다(undefined) — 뷰어가 로드 시 스펙으로 계산.
        entries.push((timestamp, serde_json::to_vec(&Value::Object(entry))?));
    }
    Ok(())
}

/// 스테이징 트리에서 타임라인 캐시를 만들어 스테이징 루트에 기록한다.
/// 반환값은 기록한 엔트리 수. 캐시는 발행 시 호스트 루트로 이동한다.
pub fn build_master_timeline_cache(
    stage_dir: &Path,
    live_dir: &Path,
    built_for_run_at: &str,
) -> Result<usize> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let include_all = |_: &RowMap| true;
    let live = |category: &str, file: &str| {
        live_dir
            .join(category)
            .join(format!("{}.sqlite", file))
            .to_string_lossy()
            .to_string()
    };

    for stem in ["ExecutionHistory", "ScheduledTasks"] {
        collect_table(
            &stage_dir.join("_OVERVIEW").join(format!("{}.sqlite", stem)),
            stem,
            "_OVERVIEW",
            &live("_OVERVIEW", stem),
            &include_all,
            &mut entries,
        )?;
    }
    // 캐시 응답 행은 방문 증거가 아니다 — visit/download만 포함(뷰어 규칙과 동일).
    let browser_filter = |row: &RowMap| {
        matches!(
            row.get("kind").and_then(|value| value.as_str()),
            Some("visit") | Some("download")
        )
    };
    collect_table(
        &stage_dir.join("_OVERVIEW").join("BrowserActivity.sqlite"),
        "BrowserActivity",
        "_OVERVIEW",
        &live("_OVERVIEW", "BrowserActivity"),
        &browser_filter,
        &mut entries,
    )?;
    collect_table(
        &stage_dir.join("JUMPLIST").join("JumpList_Entries.sqlite"),
        "JumpList_Entries",
        "JUMPLIST",
        &live("JUMPLIST", "JumpList_Entries"),
        &include_all,
        &mut entries,
    )?;
    // WER: 크래시 보고서의 EventTime(크래시 발생 시각) — 악성코드 크래시·
    // 익스플로잇 실패 시각의 유일한 타임라인 공급원(T6에서 WER만 편입 확정,
    // RegistryFindings·CacheEntries·레지스트리 하이브 last_write는 제외 유지).
    collect_table(
        &stage_dir.join("WER").join("WER_Reports.sqlite"),
        "WER_Reports",
        "WER",
        &live("WER", "WER_Reports"),
        &include_all,
        &mut entries,
    )?;
    // EventLog: 원본 .evtx당 한 파일, 테이블 이름 = 파일 stem. EventID 0 제외.
    let eventlog_filter = |row: &RowMap| {
        row.get("EventID")
            .and_then(|value| value.as_str())
            .map(|id| id.trim() != "0")
            .unwrap_or(true)
    };
    let eventlog_dir = stage_dir.join("EVENTLOG");
    if let Ok(read_dir) = std::fs::read_dir(&eventlog_dir) {
        let mut files: Vec<_> = read_dir
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "sqlite"))
            .collect();
        files.sort();
        for path in files {
            let stem = path
                .file_stem()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default();
            collect_table(
                &path,
                &stem,
                "EVENTLOG",
                &live("EVENTLOG", &stem),
                &eventlog_filter,
                &mut entries,
            )?;
        }
    }

    // 타임스탬프는 파서가 이미 YYYY-MM-DD hh:mm:ss.fff로 기록 — 문자열 비교가
    // 곧 시간 순서다. 뷰어와 동일하게 최신순.
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    let out_path = stage_dir.join("_master_timeline.cache.json");
    let file = std::fs::File::create(&out_path)?;
    let mut writer = std::io::BufWriter::new(file);
    write!(
        writer,
        "{{\"builtForRunAt\":{},\"entries\":[",
        serde_json::to_string(built_for_run_at)?
    )?;
    for (index, (_, bytes)) in entries.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }
        writer.write_all(bytes)?;
    }
    writer.write_all(b"]}")?;
    writer.flush()?;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_timestamped_rows_and_writes_cache() {
        let root = std::env::temp_dir().join(format!(
            "wina-timeline-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let stage = root.join("stage");
        std::fs::create_dir_all(stage.join("_OVERVIEW")).unwrap();
        let db = stage.join("_OVERVIEW/ScheduledTasks.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "CREATE TABLE \"ScheduledTasks\" (\"timestamp\" TEXT, \"task_name\" TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ScheduledTasks VALUES ('2026-08-01 09:30:00.000', 'MyTask'), ('', 'NoTime')",
            [],
        )
        .unwrap();
        drop(conn);

        let live = root.join("live");
        let count = build_master_timeline_cache(&stage, &live, "run-at").unwrap();
        assert_eq!(count, 1, "one timestamped row must be collected");
        let cache: serde_json::Value = serde_json::from_slice(
            &std::fs::read(stage.join("_master_timeline.cache.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(cache["builtForRunAt"], "run-at");
        let entry = &cache["entries"][0];
        assert_eq!(entry["timestamp"], "2026-08-01 09:30:00.000");
        assert_eq!(entry["table"], "ScheduledTasks");
        assert_eq!(entry["rowid"], 1);
        assert!(entry.get("tags").is_none());
        assert_eq!(entry["row"]["task_name"], "MyTask");
        let _ = std::fs::remove_dir_all(root);
    }
}
