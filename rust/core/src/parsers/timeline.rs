//! Windows Timeline (ActivitiesCache.db) 파서. 계정별 앱 실행·포커스 시간·
//! 문서 활동이 남는 평범한 SQLite(Activity, ActivityOperation)다.
//!
//! 실수집본에서 확인된 두 가지 주의점:
//! - 스키마 2종: 신형은 StartTime/EndTime 컬럼이 있고 구형은 LastModifiedTime
//!   뿐이다 — 컬럼 존재 여부를 보고 동적으로 읽는다.
//! - `-wal`/`-shm`이 함께 수집된다. immutable 모드로 열면 WAL의 행을 놓치므로
//!   임시 폴더에 db+wal+shm을 복사한 뒤 일반 모드로 연다.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rusqlite::Connection;
use serde_json::Value;

use crate::finder;
use crate::sqlite::Row;
use crate::time::fmt_unix;

pub const TIMELINE_TABLE: &str = "Timeline_Activities";
pub const TIMELINE_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "kind",
    "app_name",
    "app_path",
    "display_text",
    "content_uri",
    "active_duration_s",
    "activity_type",
    "start_time",
    "end_time",
    "last_modified",
    "expiration",
    "account",
    "source_table",
    "activity_id",
    "platform_device_id",
    "payload",
    "_source_file",
];

pub fn timeline_sources(target: &Path) -> Vec<PathBuf> {
    finder::by_name(target, &["ActivitiesCache.db"])
}

/// ActivityType 숫자의 기능 명칭 (Windows Timeline 문서화된 유형).
fn kind_label(activity_type: i64) -> String {
    match activity_type {
        2 => "알림".into(),
        3 => "모바일 백업".into(),
        5 => "실행/열기".into(),
        6 => "사용(포커스)".into(),
        10 => "클립보드".into(),
        16 => "복사/붙여넣기".into(),
        11 | 12 | 15 => "시스템".into(),
        other => format!("기타({other})"),
    }
}

/// 경로에서 계정 이름 추출 — `.../TIMELINE/<계정>/ConnectedDevicesPlatform/...`
/// 배치에서 ConnectedDevicesPlatform 바로 앞 구성 요소가 계정이다.
fn account_from_path(path: &Path) -> String {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("ConnectedDevicesPlatform") && i > 0 {
            return parts[i - 1].clone();
        }
    }
    String::new()
}

/// 16바이트 GUID 블롭 -> 표준 표기 (앞 3필드는 리틀엔디언).
fn guid_string(blob: &[u8]) -> String {
    if blob.len() != 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        blob[3], blob[2], blob[1], blob[0], blob[5], blob[4], blob[7], blob[6],
        blob[8], blob[9], blob[10], blob[11], blob[12], blob[13], blob[14], blob[15]
    )
}

/// AppId JSON 배열에서 실행 파일 경로에 가장 가까운 항목을 고른다.
fn best_app_id(raw: &str) -> String {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(raw) else {
        return String::new();
    };
    let priority = ["x_exe_path", "windows_win32", "packageId", "windows_universal"];
    for wanted in priority {
        for entry in &entries {
            if entry.get("platform").and_then(Value::as_str) == Some(wanted) {
                if let Some(app) = entry.get("application").and_then(Value::as_str) {
                    if !app.is_empty() {
                        return app.to_string();
                    }
                }
            }
        }
    }
    entries
        .iter()
        .filter_map(|entry| entry.get("application").and_then(Value::as_str))
        .find(|app| !app.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

fn payload_str(payload: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = payload.get(*key) {
            match v {
                Value::String(s) if !s.is_empty() => return s.clone(),
                Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    String::new()
}

fn columns_of(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .and_then(|mut stmt| {
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .unwrap_or_default()
}

fn read_activity_table(
    conn: &Connection,
    table: &str,
    account: &str,
    source: &str,
    rows: &mut Vec<Row>,
) {
    let columns = columns_of(conn, table);
    if columns.is_empty() {
        return;
    }
    let has = |name: &str| columns.iter().any(|c| c == name);
    let opt = |name: &str| if has(name) { format!("\"{name}\"") } else { "NULL".into() };
    let sql = format!(
        "SELECT Id, AppId, ActivityType, Payload, LastModifiedTime, ExpirationTime, PlatformDeviceId, {}, {} FROM \"{table}\"",
        opt("StartTime"),
        opt("EndTime"),
    );
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return;
    };
    let mapped = stmt.query_map([], |r| {
        let id: Vec<u8> = r.get(0).unwrap_or_default();
        let app_id: String = r.get(1).unwrap_or_default();
        let activity_type: i64 = r.get(2).unwrap_or_default();
        let payload: Vec<u8> = r.get(3).unwrap_or_default();
        let last_modified: i64 = r.get(4).unwrap_or_default();
        let expiration: i64 = r.get(5).unwrap_or_default();
        let device: String = r.get(6).unwrap_or_default();
        let start: i64 = r.get(7).unwrap_or_default();
        let end: i64 = r.get(8).unwrap_or_default();
        Ok((id, app_id, activity_type, payload, last_modified, expiration, device, start, end))
    });
    let Ok(mapped) = mapped else { return };
    for item in mapped.flatten() {
        let (id, app_id_raw, activity_type, payload_raw, last_modified, expiration, device, start, end) = item;
        let payload_text = String::from_utf8_lossy(&payload_raw).into_owned();
        let payload_json: Value = serde_json::from_str(&payload_text).unwrap_or(Value::Null);
        let app_path = best_app_id(&app_id_raw);
        let display = payload_str(&payload_json, &["displayText"]);
        let app_name = {
            let named = payload_str(&payload_json, &["appDisplayName"]);
            if !named.is_empty() {
                named
            } else if !display.is_empty() {
                display.clone()
            } else {
                app_path
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
        };
        let timestamp = if start > 0 { fmt_unix(start) } else { fmt_unix(last_modified) };
        let mut row = Row::new();
        row.insert("timestamp".into(), timestamp);
        row.insert("kind".into(), kind_label(activity_type));
        row.insert("app_name".into(), app_name);
        row.insert("app_path".into(), app_path);
        row.insert("display_text".into(), display);
        row.insert(
            "content_uri".into(),
            payload_str(&payload_json, &["activationUri", "contentUri"]),
        );
        row.insert(
            "active_duration_s".into(),
            payload_str(&payload_json, &["activeDurationSeconds"]),
        );
        row.insert("activity_type".into(), activity_type.to_string());
        row.insert("start_time".into(), fmt_unix(start));
        row.insert("end_time".into(), fmt_unix(end));
        row.insert("last_modified".into(), fmt_unix(last_modified));
        row.insert("expiration".into(), fmt_unix(expiration));
        row.insert("account".into(), account.into());
        row.insert("source_table".into(), source.into());
        row.insert("activity_id".into(), guid_string(&id));
        row.insert("platform_device_id".into(), device);
        row.insert("payload".into(), payload_text);
        rows.push(row);
    }
}

pub fn parse_timeline_from(paths: &[PathBuf]) -> Result<Vec<Row>> {
    // 같은 프로세스의 동시 호출(병렬 테스트 등)이 임시 폴더를 공유하지 않게
    // 전역 카운터로 유일한 이름을 만든다.
    static STAGING_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let mut rows = Vec::new();
    let mut seen_dirs = BTreeSet::new();
    for path in paths {
        // WAL의 행까지 읽기 위해 db+wal+shm을 임시 폴더로 복사해 일반 모드로 연다.
        let seq = STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = std::env::temp_dir().join(format!(
            "wina-timeline-{}-{seq}",
            std::process::id()
        ));
        if std::fs::create_dir_all(&staging).is_err() {
            continue;
        }
        seen_dirs.insert(staging.clone());
        let local = staging.join("ActivitiesCache.db");
        if std::fs::copy(path, &local).is_err() {
            continue;
        }
        for suffix in ["-wal", "-shm"] {
            let side = PathBuf::from(format!("{}{suffix}", path.display()));
            if side.exists() {
                let _ = std::fs::copy(&side, staging.join(format!("ActivitiesCache.db{suffix}")));
            }
        }
        let Ok(conn) = Connection::open(&local) else {
            continue;
        };
        let account = account_from_path(path);
        let source_file = path.to_string_lossy().into_owned();
        let before = rows.len();
        read_activity_table(&conn, "Activity", &account, "Activity", &mut rows);
        read_activity_table(&conn, "ActivityOperation", &account, "ActivityOperation", &mut rows);
        for row in rows.iter_mut().skip(before) {
            row.insert("_source_file".into(), source_file.clone());
        }
        drop(conn);
    }
    for dir in seen_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
    // 계정 → 시각 순으로 정렬해 표가 바로 읽히게 한다.
    rows.sort_by(|a, b| {
        let key = |r: &Row| {
            (
                r.get("account").cloned().unwrap_or_default(),
                r.get("timestamp").cloned().unwrap_or_default(),
            )
        };
        key(a).cmp(&key(b))
    });
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(dir: &Path, with_start: bool) -> PathBuf {
        let path = dir.join("ActivitiesCache.db");
        let conn = Connection::open(&path).unwrap();
        let extra = if with_start {
            ", StartTime INTEGER, EndTime INTEGER"
        } else {
            ""
        };
        conn.execute(
            &format!(
                "CREATE TABLE Activity (Id BLOB, AppId TEXT, ActivityType INTEGER, Payload BLOB, LastModifiedTime INTEGER, ExpirationTime INTEGER, PlatformDeviceId TEXT{extra})"
            ),
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE ActivityOperation (Id BLOB, AppId TEXT, ActivityType INTEGER, Payload BLOB, LastModifiedTime INTEGER, ExpirationTime INTEGER, PlatformDeviceId TEXT)",
            [],
        )
        .unwrap();
        let app_id = r#"[{"application":"C:\\Tools\\proc.exe","platform":"x_exe_path"},{"application":"pkg","platform":"packageId"}]"#;
        let payload = r#"{"displayText":"proc.exe","appDisplayName":"Proc Tool","activationUri":"ms-shellactivity:","activeDurationSeconds":42}"#;
        if with_start {
            conn.execute(
                "INSERT INTO Activity VALUES (?1, ?2, 5, ?3, 1747900000, 0, 'dev1', 1747890000, 1747890042)",
                rusqlite::params![vec![0u8; 16], app_id, payload.as_bytes()],
            )
            .unwrap();
        } else {
            conn.execute(
                "INSERT INTO Activity (Id, AppId, ActivityType, Payload, LastModifiedTime, ExpirationTime, PlatformDeviceId) VALUES (?1, ?2, 6, ?3, 1747900000, 0, 'dev1')",
                rusqlite::params![vec![1u8; 16], app_id, payload.as_bytes()],
            )
            .unwrap();
        }
        path
    }

    #[test]
    fn new_schema_uses_start_time_and_maps_app_fields() {
        let dir = std::env::temp_dir().join(format!("wina-tl-new-{}", std::process::id()));
        let base = dir.join("TIMELINE").join("analyst").join("ConnectedDevicesPlatform");
        std::fs::create_dir_all(&base).unwrap();
        let db = make_db(&base, true);
        let rows = parse_timeline_from(&[db]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["kind"], "실행/열기");
        assert_eq!(row["app_name"], "Proc Tool");
        assert_eq!(row["app_path"], "C:\\Tools\\proc.exe");
        assert_eq!(row["account"], "analyst");
        assert_eq!(row["active_duration_s"], "42");
        // timestamp는 StartTime 기준 (LastModifiedTime이 아니라)
        assert_eq!(row["timestamp"], row["start_time"]);
        assert!(!row["timestamp"].is_empty());
    }

    #[test]
    fn old_schema_falls_back_to_last_modified() {
        let dir = std::env::temp_dir().join(format!("wina-tl-old-{}", std::process::id()));
        let base = dir.join("TIMELINE").join("svc").join("ConnectedDevicesPlatform").join("L.svc");
        std::fs::create_dir_all(&base).unwrap();
        let db = make_db(&base, false);
        let rows = parse_timeline_from(&[db]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["kind"], "사용(포커스)");
        assert_eq!(row["account"], "svc");
        assert_eq!(row["start_time"], "");
        assert_eq!(row["timestamp"], row["last_modified"]);
        assert!(!row["timestamp"].is_empty());
    }
}
