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
    // 서비스가 부여한 대화 id — payload 또는 요청 URL에 실제로 있을 때만 채운다.
    "conversation_id",
    // Windows 계정(캐시 facts의 account) — AI 서비스 계정과 다른 값이다.
    "account",
    // AI 서비스 쪽 계정 식별자(payload에 있을 때만).
    "service_account",
    "title",
    "created_at",
    "updated_at",
    "url",
    "raw_json",
    // 목록은 raw_json을 전송하지 않는다 — 메시지 수만 파생 시점에 세어 둔다.
    "message_count",
    "source_record_key",
    "_source_file",
];

/// 대화 payload의 메시지 개수 — 목록은 원문을 받지 않으므로 파생 시점에
/// 세어 둔다. 제공자마다 배열 키가 달라 알려진 키를 순서대로 본다.
fn count_ai_messages(value: &serde_json::Value) -> usize {
    let object = match value.as_object() {
        Some(object) => object,
        None => return 0,
    };
    for key in ["messages", "chat_messages", "conversation", "mapping"] {
        match object.get(key) {
            Some(serde_json::Value::Array(items)) => return items.len(),
            Some(serde_json::Value::Object(map)) => return map.len(),
            _ => {}
        }
    }
    0
}

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

/// 대화 payload에서 읽어낸 메시지 1건. 모든 값은 원문 그대로이고, 없는
/// 필드는 None이다 — 빈 문자열로 채워 증거를 만들어내지 않는다.
#[derive(Debug, Default, Clone)]
pub struct AiMessage {
    pub message_id: Option<String>,
    pub role: Option<String>,
    pub content: Option<String>,
    /// 원문 시각 문자열 또는 숫자의 문자열 표현 — 변환하지 않는다.
    pub created_at: Option<String>,
}

/// payload에 실제로 적힌 첨부(파일·이미지) 1건.
#[derive(Debug, Default, Clone)]
pub struct AiAttachment {
    /// 소속 메시지의 0부터 시작하는 순번. 대화 전체 첨부면 None.
    pub message_ordinal: Option<usize>,
    pub url: Option<String>,
    pub file_name: Option<String>,
    pub mime: Option<String>,
}

/// 대화 1건 = 평면 행 + 그 대화의 메시지·첨부 자식 행.
#[derive(Debug, Clone)]
pub struct AiConversationRecord {
    /// 기존 AI_KEYS 기반 평면 행.
    pub row: Row,
    pub messages: Vec<AiMessage>,
    pub attachments: Vec<AiAttachment>,
}

/// 객체에서 주어진 키 순서로 비어 있지 않은 문자열(또는 숫자)을 찾는다.
/// 없으면 None — 증거에 없는 값을 빈 문자열로 만들지 않는다.
fn json_str_field(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    for name in names {
        match object.get(*name) {
            Some(serde_json::Value::String(value)) if !value.is_empty() => {
                return Some(value.clone())
            }
            Some(serde_json::Value::Number(value)) => return Some(value.to_string()),
            _ => {}
        }
    }
    None
}

const ATTACHMENT_URL_KEYS: &[&str] = &[
    "url",
    "asset_pointer",
    "file_url",
    "preview_url",
    "download_url",
];
const ATTACHMENT_NAME_KEYS: &[&str] = &["file_name", "fileName", "name"];
const ATTACHMENT_MIME_KEYS: &[&str] = &["mime_type", "mimeType", "mime"];

/// 첨부 후보 객체에서 실제로 있는 필드만 담는다. 확장자나 종류(file_kind)로
/// MIME을 지어내지 않는다 — 셋 다 없으면 첨부로 보지 않는다.
fn ai_attachment_from(
    object: &serde_json::Map<String, serde_json::Value>,
    message_ordinal: Option<usize>,
) -> Option<AiAttachment> {
    let url =
        json_str_field(object, ATTACHMENT_URL_KEYS).or_else(|| match object.get("image_url") {
            Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
            Some(serde_json::Value::Object(map)) => json_str_field(map, &["url"]),
            _ => None,
        });
    let file_name = json_str_field(object, ATTACHMENT_NAME_KEYS);
    let mime = json_str_field(object, ATTACHMENT_MIME_KEYS);
    if url.is_none() && file_name.is_none() && mime.is_none() {
        return None;
    }
    Some(AiAttachment {
        message_ordinal,
        url,
        file_name,
        mime,
    })
}

/// `names` 키에 있는 배열을 첨부 목록으로 읽는다.
fn collect_attachments(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    message_ordinal: Option<usize>,
    out: &mut Vec<AiAttachment>,
) {
    for name in names {
        let Some(serde_json::Value::Array(items)) = object.get(*name) else {
            continue;
        };
        for item in items {
            if let Some(map) = item.as_object() {
                if let Some(attachment) = ai_attachment_from(map, message_ordinal) {
                    out.push(attachment);
                }
            }
        }
    }
}

/// ChatGPT `content.parts` — 문자열 파트만 본문으로 잇고(`\n`), 이미지·파일
/// 파트는 문자열화하지 않고 첨부로 돌린다.
fn chatgpt_content(
    content: &serde_json::Value,
    ordinal: usize,
    attachments: &mut Vec<AiAttachment>,
) -> Option<String> {
    let object = content.as_object()?;
    let mut texts: Vec<String> = Vec::new();
    match object.get("parts") {
        Some(serde_json::Value::Array(parts)) => {
            for part in parts {
                match part {
                    serde_json::Value::String(value) => {
                        if !value.is_empty() {
                            texts.push(value.clone());
                        }
                    }
                    serde_json::Value::Object(map) => match map.get("text") {
                        Some(serde_json::Value::String(value)) if !value.is_empty() => {
                            texts.push(value.clone());
                        }
                        _ => {
                            if let Some(attachment) = ai_attachment_from(map, Some(ordinal)) {
                                attachments.push(attachment);
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
        // parts가 없는 content(code 등)는 자체 text 필드만 읽는다.
        _ => {
            if let Some(text) = json_str_field(object, &["text"]) {
                texts.push(text);
            }
        }
    }
    if texts.is_empty() {
        None
    } else {
        Some(texts.join("\n"))
    }
}

/// Claude·Gemini 메시지 본문 — `text`(문자열)가 있으면 그대로, 없으면
/// `content`/`parts` 블록 중 text 블록만 `\n`으로 잇는다. text가 아닌 블록은
/// URL·파일명·MIME이 있을 때만 첨부로 넘어간다.
fn generic_content(
    message: &serde_json::Map<String, serde_json::Value>,
    ordinal: usize,
    attachments: &mut Vec<AiAttachment>,
) -> Option<String> {
    if let Some(serde_json::Value::String(text)) = message.get("text") {
        if !text.is_empty() {
            return Some(text.clone());
        }
    }
    match message.get("content").or_else(|| message.get("parts")) {
        Some(serde_json::Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(serde_json::Value::Array(items)) => {
            let mut texts: Vec<String> = Vec::new();
            for item in items {
                match item {
                    serde_json::Value::String(value) => {
                        if !value.is_empty() {
                            texts.push(value.clone());
                        }
                    }
                    serde_json::Value::Object(map) => match map.get("text") {
                        Some(serde_json::Value::String(value)) if !value.is_empty() => {
                            texts.push(value.clone());
                        }
                        _ => {
                            if let Some(attachment) = ai_attachment_from(map, Some(ordinal)) {
                                attachments.push(attachment);
                            }
                        }
                    },
                    _ => {}
                }
            }
            if texts.is_empty() {
                None
            } else {
                Some(texts.join("\n"))
            }
        }
        Some(serde_json::Value::Object(map)) => json_str_field(map, &["text"]),
        _ => None,
    }
}

/// 발신자 — Claude는 `sender`, Gemini·기타는 `role`/`author`를 쓴다.
fn generic_role(message: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    if let Some(role) = json_str_field(message, &["sender", "role"]) {
        return Some(role);
    }
    match message.get("author") {
        Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(serde_json::Value::Object(map)) => json_str_field(map, &["role", "name"]),
        _ => None,
    }
}

/// ChatGPT `mapping` 노드를 대화 구조대로 편다. 루트(parent가 없거나 mapping에
/// 없는 노드)에서 `children` 순서대로 깊이 우선 — 분기(재생성)된 노드도 증거
/// 이므로 버리지 않는다. 어디에서도 닿지 않는 노드는 payload의 키 순서로 뒤에
/// 붙인다(serde_json의 preserve_order 기능이 켜져 있어 Map의 키 순서가 곧
/// 원문 순서이며, 따라서 결과는 결정적이다).
fn chatgpt_messages(
    object: &serde_json::Map<String, serde_json::Value>,
    messages: &mut Vec<AiMessage>,
    attachments: &mut Vec<AiAttachment>,
) {
    use std::collections::HashSet;
    let Some(mapping) = object.get("mapping").and_then(|v| v.as_object()) else {
        return;
    };
    let mut roots: Vec<&str> = Vec::new();
    for (key, node) in mapping.iter() {
        let is_root = match node.get("parent").and_then(|v| v.as_str()) {
            Some(parent) => !mapping.contains_key(parent),
            None => true,
        };
        if is_root {
            roots.push(key.as_str());
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut order: Vec<&str> = Vec::with_capacity(mapping.len());
    let mut stack: Vec<&str> = roots.into_iter().rev().collect();
    while let Some(key) = stack.pop() {
        if !seen.insert(key) {
            continue;
        }
        order.push(key);
        let children = mapping
            .get(key)
            .and_then(|node| node.get("children"))
            .and_then(|v| v.as_array());
        if let Some(children) = children {
            for child in children.iter().rev() {
                if let Some(child) = child.as_str() {
                    if mapping.contains_key(child) && !seen.contains(child) {
                        stack.push(child);
                    }
                }
            }
        }
    }
    // 구조에서 닿지 않은 노드도 증거다 — payload 키 순서로 뒤에 붙인다.
    for key in mapping.keys() {
        if seen.insert(key.as_str()) {
            order.push(key.as_str());
        }
    }
    for key in order {
        let Some(node) = mapping.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        // message가 null인 노드(루트 등)는 메시지가 아니다.
        let Some(message) = node.get("message").and_then(|v| v.as_object()) else {
            continue;
        };
        let ordinal = messages.len();
        let role = match message.get("author") {
            Some(serde_json::Value::Object(author)) => json_str_field(author, &["role", "name"]),
            Some(serde_json::Value::String(author)) if !author.is_empty() => Some(author.clone()),
            _ => json_str_field(message, &["role"]),
        };
        let content = message
            .get("content")
            .and_then(|content| chatgpt_content(content, ordinal, attachments));
        collect_attachments(message, &["attachments"], Some(ordinal), attachments);
        if let Some(metadata) = message.get("metadata").and_then(|v| v.as_object()) {
            collect_attachments(metadata, &["attachments"], Some(ordinal), attachments);
        }
        let message_id = json_str_field(message, &["id"]).or_else(|| {
            // message.id가 없으면 mapping 키(= 노드 id)가 실제 식별자다.
            (!key.is_empty()).then(|| key.to_string())
        });
        messages.push(AiMessage {
            message_id,
            role,
            content,
            created_at: json_str_field(message, &["create_time", "created_at"]),
        });
    }
}

/// 배열형 메시지(Claude `chat_messages`/`messages`, Gemini `messages` 등)를
/// payload 순서 그대로 읽는다.
fn array_messages(
    items: &[serde_json::Value],
    messages: &mut Vec<AiMessage>,
    attachments: &mut Vec<AiAttachment>,
) {
    for item in items {
        let Some(message) = item.as_object() else {
            continue;
        };
        let ordinal = messages.len();
        let content = generic_content(message, ordinal, attachments);
        collect_attachments(message, &["attachments", "files"], Some(ordinal), attachments);
        messages.push(AiMessage {
            message_id: json_str_field(message, &["uuid", "id", "message_id"]),
            role: generic_role(message),
            content,
            created_at: json_str_field(message, &["created_at", "create_time", "timestamp"]),
        });
    }
}

/// 제공자별 메시지·첨부 추출. 걸어 볼 구조가 없으면 아무것도 만들지 않는다.
fn extract_ai_messages(
    provider: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    messages: &mut Vec<AiMessage>,
    attachments: &mut Vec<AiAttachment>,
) {
    match provider {
        "ChatGPT" => chatgpt_messages(object, messages, attachments),
        "Claude" => {
            for key in ["chat_messages", "messages"] {
                if let Some(serde_json::Value::Array(items)) = object.get(key) {
                    array_messages(items, messages, attachments);
                    break;
                }
            }
        }
        "Gemini" => {
            // conversation이 객체면 그 안의 배열을, 아니면 최상위 배열을 본다.
            let nested = object.get("conversation").and_then(|v| v.as_object());
            let container = nested.unwrap_or(object);
            for key in ["messages", "turns"] {
                if let Some(serde_json::Value::Array(items)) = container.get(key) {
                    array_messages(items, messages, attachments);
                    break;
                }
            }
            if messages.is_empty() && nested.is_some() {
                if let Some(serde_json::Value::Array(items)) = object.get("messages") {
                    array_messages(items, messages, attachments);
                }
            }
        }
        _ => {}
    }
    // 메시지에 속하지 않는 대화 전체 첨부.
    collect_attachments(object, &["attachments", "files"], None, attachments);
}

/// 서비스가 부여한 대화 id — payload의 실제 필드를 먼저 보고, 없으면 판별에
/// 쓴 요청 URL의 id 구간을 쓴다. 둘 다 없으면 빈 문자열(추정하지 않는다).
fn conversation_id(
    provider: &str,
    url: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let payload = match provider {
        "ChatGPT" => json_str_field(object, &["conversation_id", "id"]),
        "Claude" => json_str_field(object, &["uuid", "conversation_id", "id"]),
        _ => json_str_field(object, &["conversation_id", "id"]),
    };
    if let Some(id) = payload {
        return id;
    }
    let endpoint = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    let from_url = match provider {
        "ChatGPT" => endpoint
            .split("/backend-api/conversation/")
            .nth(1)
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .map(str::to_string),
        "Claude" => endpoint
            .split("/chat_conversations/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        // Gemini는 경로에 대화 id가 없다 — 질의 문자열에 명시된 경우만 쓴다.
        "Gemini" => url
            .split(|c: char| c == '?' || c == '&')
            .skip(1)
            .find_map(|pair| pair.strip_prefix("conversation_id="))
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        _ => None,
    };
    from_url.unwrap_or_default()
}

/// AI 서비스 쪽 계정 식별자 — payload의 계정/사용자 객체에 있을 때만.
/// Windows 계정(`account` 컬럼)과는 다른 값이다.
fn service_account(object: &serde_json::Map<String, serde_json::Value>) -> String {
    const IDENTITY: &[&str] = &[
        "email_address",
        "email",
        "username",
        "display_name",
        "name",
        "uuid",
        "id",
    ];
    for key in ["account", "user", "owner", "creator"] {
        match object.get(key) {
            Some(serde_json::Value::String(value)) if !value.is_empty() => return value.clone(),
            Some(serde_json::Value::Object(map)) => {
                if let Some(value) = json_str_field(map, IDENTITY) {
                    return value;
                }
            }
            _ => {}
        }
    }
    json_str_field(object, &["account_email", "user_email"]).unwrap_or_default()
}

/// 캐시 facts를 훑어 유효한 AI 대화 1건(평면 행 + 메시지·첨부)을 `push`로 즉시
/// 넘긴다(전량 — 상한 없음, 원문 JSON과 자식 행을 대화 단위로만 들고 있는
/// 스트리밍). 표시 순서(관찰 시각 내림차순 + URL)는 저장 후 SQLite 정렬
/// 재작성이 맡는다. 개별 파일·행의 문제는 대화가 아닌 것으로 건너뛴다(facts는
/// 이미 검증·발행된 산출물이라 여기서의 실패는 판별 탈락이지 증거 손실이
/// 아니다). 반환: 넘긴 대화 수.
pub fn build_ai_conversations_stream(
    out_dir: &Path,
    push: &mut dyn FnMut(AiConversationRecord) -> anyhow::Result<()>,
) -> anyhow::Result<usize> {
    let mut count = 0usize;
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
                return Ok(count);
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
            let conversation_id = conversation_id(provider, &url, object);
            let service_account = service_account(object);
            let mut messages: Vec<AiMessage> = Vec::new();
            let mut attachments: Vec<AiAttachment> = Vec::new();
            extract_ai_messages(provider, object, &mut messages, &mut attachments);
            // 걸어낸 메시지가 있으면 그 개수가 곧 증거 개수다. 구조를 걸을 수
            // 없는 payload만 기존 배열 길이 세기로 남긴다.
            let message_count = if messages.is_empty() {
                count_ai_messages(&value)
            } else {
                messages.len()
            };
            let raw_json = serde_json::to_string_pretty(&value).unwrap_or(cleaned.to_string());
            let mut row = Row::new();
            row.insert("date".into(), observed);
            row.insert("provider".into(), provider.to_string());
            row.insert("conversation_id".into(), conversation_id);
            row.insert("account".into(), account);
            row.insert("service_account".into(), service_account);
            row.insert("title".into(), title);
            row.insert("created_at".into(), created_at);
            row.insert("updated_at".into(), updated_at);
            row.insert("url".into(), url);
            row.insert("message_count".into(), message_count.to_string());
            row.insert("raw_json".into(), raw_json);
            row.insert(
                "source_record_key".into(),
                format!("{file_stem}::CacheEntries::{rowid}"),
            );
            row.insert("_source_file".into(), db.to_string_lossy().to_string());
            // 대화 1건 단위로 넘기고 바로 버린다 — 전체를 모으지 않는다.
            push(AiConversationRecord {
                row,
                messages,
                attachments,
            })?;
            count += 1;
        }
    }
    Ok(count)
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

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wina-ai-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("BROWSER")).unwrap();
        root
    }

    fn collect(root: &Path) -> Vec<AiConversationRecord> {
        let mut records: Vec<AiConversationRecord> = Vec::new();
        build_ai_conversations_stream(root, &mut |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        records
    }

    /// Edge·Whale 캐시 산출물의 대화도 파생에 포함된다 — Chrome 한정이 아니다.
    #[test]
    fn conversations_come_from_every_supported_browser_cache() {
        let root = temp_root("browsers");
        let browser = root.join("BROWSER");
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
        let mut rows: Vec<Row> = collect(&root).into_iter().map(|r| r.row).collect();
        // 저장 단계의 SQL 정렬과 같은 규칙으로 정렬해 기존 검증을 유지한다.
        rows.sort_by(|a, b| {
            b.get("date")
                .cmp(&a.get("date"))
                .then_with(|| a.get("url").cmp(&b.get("url")))
        });
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
        // payload에 대화 id가 없으면 요청 URL의 id 구간을 쓴다.
        assert_eq!(rows[0]["conversation_id"], "ghi");
        // AI 서비스 계정 정보가 없는 payload는 빈 값으로 남는다.
        assert_eq!(rows[0]["service_account"], "");
    }

    /// ChatGPT mapping은 키 순서가 아니라 parent/children 구조대로 펴지며,
    /// 이미지 파트·metadata 첨부는 본문이 아니라 첨부로 분리된다.
    #[test]
    fn chatgpt_mapping_payload_yields_ordered_messages_and_attachments() {
        let root = temp_root("chatgpt");
        // 키 순서를 일부러 뒤섞어 둔다(n2 → root → n1).
        let convo = r#"{
            "conversation_id":"conv-1",
            "title":"분석 질문",
            "create_time":1751940000,
            "current_node":"n2",
            "mapping":{
                "n2":{"id":"n2","parent":"n1","children":[],
                    "message":{"id":"m2","author":{"role":"assistant"},
                        "content":{"content_type":"text","parts":["답변 앞","답변 뒤"]},
                        "create_time":1751940002}},
                "root":{"id":"root","parent":null,"children":["n1"],"message":null},
                "n1":{"id":"n1","parent":"root","children":["n2"],
                    "message":{"id":"m1","author":{"role":"user"},
                        "content":{"content_type":"multimodal_text","parts":["이 화면 봐줘",
                            {"content_type":"image_asset_pointer","asset_pointer":"file-service://file-abc"}]},
                        "create_time":1751940001,
                        "metadata":{"attachments":[{"id":"file-abc","name":"shot.png","mimeType":"image/png"}]}}}
            }
        }"#;
        cache_db(
            &root.join("BROWSER"),
            "u_Chrome_Cache.sqlite",
            &[(
                "https://chatgpt.com/backend-api/conversation/conv-1",
                "2026-07-08 12:00:00.000",
                convo,
            )],
        );
        let records = collect(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.row["conversation_id"], "conv-1");
        // message가 null인 루트 노드는 메시지가 아니다.
        assert_eq!(record.messages.len(), 2);
        assert_eq!(record.row["message_count"], "2");
        let roles: Vec<&str> = record
            .messages
            .iter()
            .map(|m| m.role.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(roles, vec!["user", "assistant"]);
        let ids: Vec<&str> = record
            .messages
            .iter()
            .map(|m| m.message_id.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(ids, vec!["m1", "m2"]);
        assert_eq!(record.messages[0].content.as_deref(), Some("이 화면 봐줘"));
        // 분리된 텍스트 파트만 개행으로 잇는다.
        assert_eq!(
            record.messages[1].content.as_deref(),
            Some("답변 앞\n답변 뒤")
        );
        assert_eq!(record.messages[0].created_at.as_deref(), Some("1751940001"));
        // 이미지 파트 + metadata 첨부 모두 0번 메시지 소속이다.
        assert_eq!(record.attachments.len(), 2);
        assert_eq!(record.attachments[0].message_ordinal, Some(0));
        assert_eq!(
            record.attachments[0].url.as_deref(),
            Some("file-service://file-abc")
        );
        // 확장자로 MIME을 지어내지 않는다.
        assert_eq!(record.attachments[0].mime, None);
        assert_eq!(record.attachments[1].message_ordinal, Some(0));
        assert_eq!(record.attachments[1].file_name.as_deref(), Some("shot.png"));
        assert_eq!(record.attachments[1].mime.as_deref(), Some("image/png"));
    }

    /// Claude payload는 uuid가 대화 id이고, 서비스 계정은 account 객체에서 온다.
    #[test]
    fn claude_chat_messages_payload_yields_conversation_id_and_messages() {
        let root = temp_root("claude");
        let convo = r#"{
            "uuid":"c-9",
            "name":"클로드 대화",
            "created_at":"2026-07-01T00:00:00Z",
            "updated_at":"2026-07-01T00:05:00Z",
            "account":{"uuid":"acct-uuid","email_address":"u@example.com"},
            "chat_messages":[
                {"uuid":"m1","sender":"human","text":"질문","created_at":"2026-07-01T00:00:01Z",
                 "attachments":[{"file_name":"notes.txt","file_kind":"document","extracted_content":"..."}]},
                {"uuid":"m2","sender":"assistant","text":"",
                 "content":[{"type":"text","text":"답변 1"},{"type":"text","text":"답변 2"},
                            {"type":"image","url":"https://claude.ai/img/1.png"}],
                 "created_at":"2026-07-01T00:00:02Z"}
            ]
        }"#;
        cache_db(
            &root.join("BROWSER"),
            "u_Chrome_Cache.sqlite",
            &[(
                "https://claude.ai/api/organizations/org-1/chat_conversations/c-9",
                "2026-07-08 12:00:00.000",
                convo,
            )],
        );
        let records = collect(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.row["provider"], "Claude");
        assert_eq!(record.row["conversation_id"], "c-9");
        assert_eq!(record.row["title"], "클로드 대화");
        // Windows 계정과 AI 서비스 계정은 다른 컬럼이다.
        assert_eq!(record.row["account"], "acct");
        assert_eq!(record.row["service_account"], "u@example.com");
        assert_eq!(record.row["message_count"], "2");
        assert_eq!(record.messages.len(), 2);
        assert_eq!(record.messages[0].message_id.as_deref(), Some("m1"));
        assert_eq!(record.messages[0].role.as_deref(), Some("human"));
        assert_eq!(record.messages[0].content.as_deref(), Some("질문"));
        assert_eq!(
            record.messages[0].created_at.as_deref(),
            Some("2026-07-01T00:00:01Z")
        );
        assert_eq!(record.messages[1].role.as_deref(), Some("assistant"));
        // text 블록만 이어 붙이고 image 블록은 본문이 되지 않는다.
        assert_eq!(
            record.messages[1].content.as_deref(),
            Some("답변 1\n답변 2")
        );
        assert_eq!(record.attachments.len(), 2);
        assert_eq!(record.attachments[0].message_ordinal, Some(0));
        assert_eq!(record.attachments[0].file_name.as_deref(), Some("notes.txt"));
        // file_kind는 MIME이 아니다 — 비워 둔다.
        assert_eq!(record.attachments[0].mime, None);
        assert_eq!(record.attachments[1].message_ordinal, Some(1));
        assert_eq!(
            record.attachments[1].url.as_deref(),
            Some("https://claude.ai/img/1.png")
        );
    }
}
