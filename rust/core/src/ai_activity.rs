//! AI 대화 파생(_OVERVIEW/AiConversations) — 파싱 단계에서 BROWSER 캐시
//! facts(CacheEntries)의 AI 호스트 JSON 본문을 판별해 대화 메타데이터·원문을
//! 저장한다. GUI는 이 파생 테이블만 기간·페이지 조건으로 조회한다 — 화면
//! 진입마다 원본을 재해석하던 방식과 500행/2,000건 상한을 대체한다.
//!
//! 지원 브라우저(Chrome·Edge·Whale·Unknown)의 캐시 산출물을 모두 훑는다 —
//! 어느 브라우저로 AI 서비스를 썼든 대화가 남는다. 원본 CacheEntries의
//! record_key(파일::테이블::rowid)를 보존해 북마크·원본 상세와 연결된다.
use std::path::{Path, PathBuf};

use crate::sqlite::Row;

pub const AI_TABLE: &str = "AiConversations";
/// 고정 컬럼 (0건 스키마 생성용). date = 캐시 관찰 시각(기간 필터 기준).
pub const AI_KEYS: &[&str] = &[
    "date",
    "provider",
    "account",
    "title",
    "created_at",
    "updated_at",
    "url",
    "raw_json",
    "source_record_key",
    "_source_file",
];

/// AI provider hosts we look for in the cache.
pub const AI_HOSTS: &[&str] = &[
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "gemini.google.com",
    "bard.google.com",
];

pub fn ai_provider(url: &str) -> Option<&'static str> {
    let host = url.split('/').nth(2).unwrap_or("").to_ascii_lowercase();
    if host == "chatgpt.com" || host == "chat.openai.com" {
        Some("ChatGPT")
    } else if host == "claude.ai" {
        Some("Claude")
    } else if host == "gemini.google.com" || host == "bard.google.com" {
        Some("Gemini")
    } else {
        None
    }
}

/// Accept only cache responses that are known to contain a complete conversation
/// payload. AI hosts emit many JSON responses (settings, stream state, assets),
/// which must not be presented as a conversation to an analyst.
pub fn is_ai_conversation_payload(
    provider: &str,
    url: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let endpoint = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    match provider {
        // The individual endpoint (not `/stream_status` or `/textdocs`) carries
        // the complete ChatGPT tree under `mapping`.
        "ChatGPT" => {
            endpoint
                .split("/backend-api/conversation/")
                .nth(1)
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
                && object
                    .get("mapping")
                    .is_some_and(serde_json::Value::is_object)
        }
        // Claude's complete chat endpoint stores actual turn objects. Other
        // organization/skills JSON is intentionally excluded.
        "Claude" => {
            endpoint.contains("/chat_conversations/")
                && (object
                    .get("chat_messages")
                    .is_some_and(serde_json::Value::is_array)
                    || object
                        .get("messages")
                        .is_some_and(serde_json::Value::is_array))
        }
        // Gemini conversations are returned by this concrete conversation API;
        // pages, widget responses and account JSON are not conversation records.
        "Gemini" => {
            endpoint.contains("BardFrontendService/GetConversation")
                && (object
                    .get("conversation")
                    .is_some_and(serde_json::Value::is_object)
                    || object
                        .get("messages")
                        .is_some_and(serde_json::Value::is_array))
        }
        _ => false,
    }
}

pub fn json_time_field(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> String {
    names
        .iter()
        .find_map(|name| object.get(*name))
        .and_then(|value| match value {
            serde_json::Value::String(value) if !value.is_empty() => Some(value.clone()),
            serde_json::Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// 지원 브라우저 캐시 facts 파일들 — `<계정>_<브라우저>_Cache[uniq].sqlite`.
fn cache_fact_files(out_dir: &Path) -> Vec<PathBuf> {
    let dir = out_dir.join("BROWSER");
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension().map(|x| x == "sqlite").unwrap_or(false)
                    && p.file_stem()
                        .map(|s| s.to_string_lossy().contains("_Cache"))
                        .unwrap_or(false)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
}

/// 캐시 facts를 훑어 유효한 AI 대화 행을 `push`로 스트리밍한다(전량 — 상한
/// 없음). 개별 파일·행의 문제는 대화가 아닌 것으로 건너뛴다(facts는 이미
/// 검증·발행된 산출물이라 여기서의 실패는 판별 탈락이지 증거 손실이 아니다).
pub fn build_ai_conversations(out_dir: &Path) -> Vec<Row> {
    let mut rows = Vec::new();
    for db in cache_fact_files(out_dir) {
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) else {
            continue;
        };
        let file_stem = db
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let ai_like: Vec<String> = AI_HOSTS.iter().map(|h| format!("%{}%", h)).collect();
        let placeholders: String = ai_like
            .iter()
            .enumerate()
            .map(|(i, _)| format!("url LIKE ?{}", i + 1))
            .collect::<Vec<_>>()
            .join(" OR ");
        let sql = format!(
            "SELECT rowid, url, account, COALESCE(NULLIF(response_time, ''), NULLIF(request_time, ''), NULLIF(creation_time, ''), ''), body_b64 FROM {} \
             WHERE body_b64 IS NOT NULL AND body_b64 != '' \
             AND content_type LIKE '%json%' AND ({})",
            crate::sqlite::quote_ident("CacheEntries"),
            placeholders
        );
        let params: Vec<&dyn rusqlite::ToSql> =
            ai_like.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let Ok(mut stmt) = conn.prepare(&sql) else {
            continue;
        };
        let mapped = stmt.query_map(params.as_slice(), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            ))
        });
        let Ok(mapped) = mapped else { continue };
        for item in mapped.flatten() {
            if crate::pipeline::cancelled() {
                return rows;
            }
            let (rowid, url, account, observed, body_b64) = item;
            let Ok(bytes) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body_b64)
            else {
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };
            // Strip anti-hijack prefix.
            let cleaned = text.trim_start_matches(|c: char| {
                c == ')' || c == ']' || c == '\'' || c == '\n' || c == '\r' || c == ' '
            });
            let Ok(value) = serde_json::from_str::<serde_json::Value>(cleaned) else {
                continue;
            };
            let Some(object) = value.as_object() else {
                continue;
            };
            let Some(provider) = ai_provider(&url) else {
                continue;
            };
            if !is_ai_conversation_payload(provider, &url, object) {
                continue;
            }
            let title = object
                .get("title")
                .or_else(|| object.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = json_time_field(object, &["create_time", "created_at"]);
            let updated_at = json_time_field(object, &["update_time", "updated_at"]);
            let raw_json = serde_json::to_string_pretty(&value).unwrap_or(cleaned.to_string());
            let mut row = Row::new();
            row.insert("date".into(), observed);
            row.insert("provider".into(), provider.to_string());
            row.insert("account".into(), account);
            row.insert("title".into(), title);
            row.insert("created_at".into(), created_at);
            row.insert("updated_at".into(), updated_at);
            row.insert("url".into(), url);
            row.insert("raw_json".into(), raw_json);
            row.insert(
                "source_record_key".into(),
                format!("{file_stem}::CacheEntries::{rowid}"),
            );
            row.insert("_source_file".into(), db.to_string_lossy().to_string());
            rows.push(row);
        }
    }
    // 관찰 시각 내림차순 + URL 안정 정렬 — 조회 페이지네이션의 재현성 근거.
    rows.sort_by(|a, b| {
        b.get("date")
            .cmp(&a.get("date"))
            .then_with(|| a.get("url").cmp(&b.get("url")))
    });
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_db(dir: &Path, name: &str, rows: &[(&str, &str, &str)]) {
        let db = dir.join(name);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "CREATE TABLE CacheEntries (url TEXT, account TEXT, response_time TEXT, request_time TEXT, creation_time TEXT, content_type TEXT, body_b64 TEXT)",
            [],
        )
        .unwrap();
        for (url, time, body) in rows {
            let encoded =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, body);
            conn.execute(
                "INSERT INTO CacheEntries VALUES (?1, 'acct', ?2, '', '', 'application/json', ?3)",
                rusqlite::params![url, time, encoded],
            )
            .unwrap();
        }
    }

    /// Edge·Whale 캐시 산출물의 대화도 파생에 포함된다 — Chrome 한정이 아니다.
    #[test]
    fn conversations_come_from_every_supported_browser_cache() {
        let root = std::env::temp_dir().join(format!(
            "wina-ai-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let browser = root.join("BROWSER");
        std::fs::create_dir_all(&browser).unwrap();
        let convo = r#"{"title":"t","mapping":{"a":{}},"create_time":1751940000}"#;
        cache_db(
            &browser,
            "u_Chrome_Cache.sqlite",
            &[("https://chatgpt.com/backend-api/conversation/abc", "2026-07-08 12:00:00.000", convo)],
        );
        cache_db(
            &browser,
            "u_Edge_Cache.sqlite",
            &[("https://chatgpt.com/backend-api/conversation/def", "2026-07-08 13:00:00.000", convo)],
        );
        cache_db(
            &browser,
            "u_Whale_Cache.sqlite",
            &[
                ("https://chatgpt.com/backend-api/conversation/ghi", "2026-07-08 14:00:00.000", convo),
                // 대화가 아닌 JSON은 제외된다.
                ("https://chatgpt.com/backend-api/settings", "2026-07-08 14:30:00.000", r#"{"ok":true}"#),
            ],
        );
        let rows = build_ai_conversations(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(rows.len(), 3);
        // 관찰 시각 내림차순 정렬.
        let dates: Vec<&str> = rows.iter().map(|r| r["date"].as_str()).collect();
        assert_eq!(
            dates,
            vec![
                "2026-07-08 14:00:00.000",
                "2026-07-08 13:00:00.000",
                "2026-07-08 12:00:00.000"
            ]
        );
        assert_eq!(rows[0]["source_record_key"], "u_Whale_Cache::CacheEntries::1");
        assert_eq!(rows[0]["provider"], "ChatGPT");
    }
}
