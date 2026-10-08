//! Interpret AI cache responses: conversation bodies and body-less conversation
//! list traces. Storage lives in `derived::ai_conversations`.
//!
//! Only values present in the payload are kept; structural node count, extracted
//! message count and current-branch count stay distinct.
use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

pub const AI_TABLE: &str = "AiConversations";

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

/// Kind of AI evidence a cache response carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiPayloadKind {
    /// Response containing the message structure.
    Conversation,
    /// List response with titles/ids/times only; body not acquired.
    ConversationList,
}

/// Accept only cache responses that are known to carry conversation evidence.
/// AI hosts emit many JSON responses (settings, stream state, assets), which
/// must not be presented as a conversation to an analyst.
pub fn classify_ai_payload(
    provider: &str,
    url: &str,
    object: &Map<String, Value>,
) -> Option<AiPayloadKind> {
    let endpoint = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    match provider {
        "ChatGPT" => {
            // The individual endpoint (not `/stream_status` or `/textdocs`)
            // carries the complete tree under `mapping`.
            let single = endpoint
                .split("/backend-api/conversation/")
                .nth(1)
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
                && object.get("mapping").is_some_and(Value::is_object);
            if single {
                return Some(AiPayloadKind::Conversation);
            }
            // List response: conversation metadata without any body.
            let list = endpoint.ends_with("/backend-api/conversations")
                && object.get("items").is_some_and(Value::is_array);
            list.then_some(AiPayloadKind::ConversationList)
        }
        // Claude's complete chat endpoint stores actual turn objects. Other
        // organization/skills JSON is intentionally excluded.
        "Claude" => {
            let conversation = endpoint.contains("/chat_conversations/")
                && (object.get("chat_messages").is_some_and(Value::is_array)
                    || object.get("messages").is_some_and(Value::is_array));
            conversation.then_some(AiPayloadKind::Conversation)
        }
        // Gemini conversations are returned by this concrete conversation API;
        // pages, widget responses and account JSON are not conversation records.
        "Gemini" => {
            let conversation = endpoint.contains("BardFrontendService/GetConversation")
                && (object.get("conversation").is_some_and(Value::is_object)
                    || object.get("messages").is_some_and(Value::is_array));
            conversation.then_some(AiPayloadKind::Conversation)
        }
        _ => None,
    }
}

pub fn is_ai_conversation_payload(provider: &str, url: &str, object: &Map<String, Value>) -> bool {
    classify_ai_payload(provider, url, object) == Some(AiPayloadKind::Conversation)
}

pub fn json_time_field(object: &Map<String, Value>, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| object.get(*name))
        .and_then(|value| match value {
            Value::String(value) if !value.is_empty() => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

/// One message read from a conversation payload; absent fields stay None.
#[derive(Debug, Default, Clone)]
pub struct AiMessage {
    /// Structural node id (ChatGPT mapping key); absent for array payloads.
    pub node_id: Option<String>,
    /// Structural parent, needed to reproduce branches.
    pub parent_node_id: Option<String>,
    /// Service-assigned message id.
    pub message_id: Option<String>,
    pub role: Option<String>,
    /// author.name (tool name etc.).
    pub author_name: Option<String>,
    /// ChatGPT recipient, used for tool-call display.
    pub recipient: Option<String>,
    /// content.content_type and similar display kind.
    pub content_type: Option<String>,
    pub content: Option<String>,
    /// Original time string or numeric literal; never converted.
    pub created_at: Option<String>,
    /// On the current_node ancestry; None when the branch is unknown.
    pub on_current_branch: Option<bool>,
    /// Display order within the current branch; None off-branch/unknown.
    pub branch_ordinal: Option<usize>,
}

/// One attachment recorded in the payload. Links/metadata are not file contents;
/// nothing is downloaded.
#[derive(Debug, Default, Clone)]
pub struct AiAttachment {
    /// Owning message ordinal; None for conversation-level attachments.
    pub message_ordinal: Option<usize>,
    pub attachment_id: Option<String>,
    pub url: Option<String>,
    pub file_name: Option<String>,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
    /// Extracted text already present in the payload.
    pub extracted_text: Option<String>,
    /// Where the attachment was found in the payload.
    pub origin: &'static str,
}

/// One conversation whose body was recovered.
#[derive(Debug, Default, Clone)]
pub struct AiConversation {
    pub conversation_id: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    /// AI service identity; different from the Windows account.
    pub service_account: String,
    pub current_node: Option<String>,
    /// Structural nodes incl. message-less ones; not a message count.
    pub structural_node_count: Option<usize>,
    /// Messages shown on the current branch; None when unresolvable.
    pub current_branch_message_count: Option<usize>,
    /// Every extracted message, including off-branch ones.
    pub messages: Vec<AiMessage>,
    pub attachments: Vec<AiAttachment>,
}

/// One conversation known only from a list response (no body).
#[derive(Debug, Clone)]
pub struct AiListEntry {
    pub ordinal: usize,
    pub conversation_id: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    /// Re-serialized interpretation of this item, distinct from the response.
    pub item_json: String,
}

/// One conversation list response.
#[derive(Debug, Clone)]
pub struct AiConversationList {
    pub entries: Vec<AiListEntry>,
    /// Total reported by the response itself, when present.
    pub declared_total: Option<i64>,
}

#[derive(Debug, Clone)]
pub enum AiPayload {
    Conversation(Box<AiConversation>),
    List(AiConversationList),
}

/// Cache body (base64) to UTF-8; None on failure - broken bytes never become a body.
pub fn decode_cache_body(body_b64: &str) -> Option<String> {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body_b64).ok()?;
    String::from_utf8(bytes).ok()
}

/// Strip the anti-hijack prefix (`)]}'` and friends).
pub fn strip_anti_hijack(text: &str) -> &str {
    text.trim_start_matches(|c: char| {
        c == ')' || c == ']' || c == '\'' || c == '\n' || c == '\r' || c == ' '
    })
}

/// Re-serialized interpretation, kept distinct from the collected response.
pub fn interpretation_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Interpret a response as AI evidence; None when it is neither.
pub fn parse_ai_payload(provider: &str, url: &str, value: &Value) -> Option<AiPayload> {
    let object = value.as_object()?;
    match classify_ai_payload(provider, url, object)? {
        AiPayloadKind::Conversation => Some(AiPayload::Conversation(Box::new(parse_conversation(
            provider, url, object,
        )))),
        AiPayloadKind::ConversationList => Some(AiPayload::List(parse_conversation_list(object))),
    }
}

fn parse_conversation(provider: &str, url: &str, object: &Map<String, Value>) -> AiConversation {
    let mut conversation = AiConversation {
        conversation_id: conversation_id(provider, url, object),
        title: json_str_field(object, &["title", "name"]).unwrap_or_default(),
        created_at: json_time_field(object, &["create_time", "created_at"]),
        updated_at: json_time_field(object, &["update_time", "updated_at"]),
        service_account: service_account(object),
        ..AiConversation::default()
    };
    extract_ai_messages(provider, object, &mut conversation);
    // Conversation-level attachments not owned by a message.
    collect_attachments(
        object,
        &["attachments", "files", "files_v2"],
        None,
        "conversation",
        &mut conversation.attachments,
    );
    conversation
}

/// ChatGPT list response (`items`): titles/ids/times only, no invented messages.
fn parse_conversation_list(object: &Map<String, Value>) -> AiConversationList {
    let mut entries: Vec<AiListEntry> = Vec::new();
    if let Some(Value::Array(items)) = object.get("items") {
        for (ordinal, item) in items.iter().enumerate() {
            let Some(item) = item.as_object() else {
                continue;
            };
            let conversation_id =
                json_str_field(item, &["id", "conversation_id"]).unwrap_or_default();
            let title = json_str_field(item, &["title", "name"]).unwrap_or_default();
            if conversation_id.is_empty() && title.is_empty() {
                continue;
            }
            entries.push(AiListEntry {
                ordinal,
                conversation_id,
                title,
                created_at: json_time_field(item, &["create_time", "created_at"]),
                updated_at: json_time_field(item, &["update_time", "updated_at"]),
                item_json: interpretation_json(&Value::Object(item.clone())),
            });
        }
    }
    AiConversationList {
        entries,
        declared_total: object.get("total").and_then(Value::as_i64),
    }
}

/// First non-empty string (or number) for the given keys; None otherwise.
fn json_str_field(object: &Map<String, Value>, names: &[&str]) -> Option<String> {
    for name in names {
        match object.get(*name) {
            Some(Value::String(value)) if !value.is_empty() => return Some(value.clone()),
            Some(Value::Number(value)) => return Some(value.to_string()),
            _ => {}
        }
    }
    None
}

/// Numeric (or numeric string) field; units are never invented.
fn json_int_field(object: &Map<String, Value>, names: &[&str]) -> Option<i64> {
    for name in names {
        match object.get(*name) {
            Some(Value::Number(value)) => {
                if let Some(value) = value.as_i64() {
                    return Some(value);
                }
            }
            Some(Value::String(value)) => {
                if let Ok(value) = value.trim().parse::<i64>() {
                    return Some(value);
                }
            }
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
// file_kind (document etc.) is not a MIME type; file_type is Claude's real MIME.
const ATTACHMENT_MIME_KEYS: &[&str] = &["mime_type", "mimeType", "mime", "file_type"];
const ATTACHMENT_SIZE_KEYS: &[&str] = &["file_size", "size_bytes", "size", "fileSizeBytes"];
const ATTACHMENT_TEXT_KEYS: &[&str] = &["extracted_content", "extracted_text", "file_text"];
const ATTACHMENT_ID_KEYS: &[&str] = &["file_id", "id", "uuid"];

/// Keep only fields the object actually has; never derive MIME from an extension
/// or file_kind.
///
/// `strict` is for content blocks, where tool calls and other non-attachment
/// objects appear: a bare name must not become an attachment.
fn ai_attachment_from(
    object: &Map<String, Value>,
    message_ordinal: Option<usize>,
    origin: &'static str,
    strict: bool,
) -> Option<AiAttachment> {
    let url =
        json_str_field(object, ATTACHMENT_URL_KEYS).or_else(|| match object.get("image_url") {
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            Some(Value::Object(map)) => json_str_field(map, &["url"]),
            _ => None,
        });
    let file_name = json_str_field(object, ATTACHMENT_NAME_KEYS);
    let mime = json_str_field(object, ATTACHMENT_MIME_KEYS);
    let extracted_text = json_str_field(object, ATTACHMENT_TEXT_KEYS);
    let evidenced = if strict {
        url.is_some() || mime.is_some() || extracted_text.is_some()
    } else {
        url.is_some() || file_name.is_some() || mime.is_some() || extracted_text.is_some()
    };
    if !evidenced {
        return None;
    }
    Some(AiAttachment {
        message_ordinal,
        attachment_id: json_str_field(object, ATTACHMENT_ID_KEYS),
        url,
        file_name,
        mime,
        size_bytes: json_int_field(object, ATTACHMENT_SIZE_KEYS),
        extracted_text,
        origin,
    })
}

/// Read arrays under `names` as attachments.
fn collect_attachments(
    object: &Map<String, Value>,
    names: &[&str],
    message_ordinal: Option<usize>,
    origin: &'static str,
    out: &mut Vec<AiAttachment>,
) {
    for name in names {
        let Some(Value::Array(items)) = object.get(*name) else {
            continue;
        };
        for item in items {
            if let Some(map) = item.as_object() {
                if let Some(attachment) = ai_attachment_from(map, message_ordinal, origin, false) {
                    out.push(attachment);
                }
            }
        }
    }
}

/// ChatGPT `content.parts`: join string parts with `\n`; image/file parts become
/// attachments instead of text.
fn chatgpt_content(
    content: &Value,
    ordinal: usize,
    attachments: &mut Vec<AiAttachment>,
) -> Option<String> {
    let object = content.as_object()?;
    let mut texts: Vec<String> = Vec::new();
    match object.get("parts") {
        Some(Value::Array(parts)) => {
            for part in parts {
                match part {
                    Value::String(value) => {
                        if !value.is_empty() {
                            texts.push(value.clone());
                        }
                    }
                    Value::Object(map) => match map.get("text") {
                        Some(Value::String(value)) if !value.is_empty() => {
                            texts.push(value.clone());
                        }
                        _ => {
                            if let Some(attachment) =
                                ai_attachment_from(map, Some(ordinal), "content_part", true)
                            {
                                attachments.push(attachment);
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
        // content without parts (code etc.) only has its own text field.
        _ => {
            if let Some(text) = json_str_field(object, &["text"]) {
                texts.push(text);
            }
        }
    }
    (!texts.is_empty()).then(|| texts.join("\n"))
}

/// Claude/Gemini message body: `text` when present, else the text blocks of
/// `content`/`parts`. Non-text blocks become attachments only with URL, MIME or
/// extracted text.
fn generic_content(
    message: &Map<String, Value>,
    ordinal: usize,
    attachments: &mut Vec<AiAttachment>,
) -> Option<String> {
    if let Some(Value::String(text)) = message.get("text") {
        if !text.is_empty() {
            return Some(text.clone());
        }
    }
    match message.get("content").or_else(|| message.get("parts")) {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(Value::Array(items)) => {
            let mut texts: Vec<String> = Vec::new();
            for item in items {
                match item {
                    Value::String(value) => {
                        if !value.is_empty() {
                            texts.push(value.clone());
                        }
                    }
                    Value::Object(map) => match map.get("text") {
                        Some(Value::String(value)) if !value.is_empty() => {
                            texts.push(value.clone());
                        }
                        _ => {
                            if let Some(attachment) =
                                ai_attachment_from(map, Some(ordinal), "content_part", true)
                            {
                                attachments.push(attachment);
                            }
                        }
                    },
                    _ => {}
                }
            }
            (!texts.is_empty()).then(|| texts.join("\n"))
        }
        Some(Value::Object(map)) => json_str_field(map, &["text"]),
        _ => None,
    }
}

/// Sender: Claude uses `sender`, others `role`/`author`.
fn generic_role(message: &Map<String, Value>) -> Option<String> {
    if let Some(role) = json_str_field(message, &["sender", "role"]) {
        return Some(role);
    }
    match message.get("author") {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(Value::Object(map)) => json_str_field(map, &["role", "name"]),
        _ => None,
    }
}

/// Walk parents from current_node. A repeated node (cyclic payload) stops the
/// walk: no infinite loop and no invented relation.
fn current_branch<'a>(
    mapping: &'a Map<String, Value>,
    current_node: Option<&'a str>,
) -> Option<Vec<&'a str>> {
    let start = current_node?;
    if !mapping.contains_key(start) {
        return None;
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut chain: Vec<&str> = Vec::new();
    let mut cursor = Some(start);
    while let Some(key) = cursor {
        if !seen.insert(key) {
            break;
        }
        chain.push(key);
        cursor = mapping
            .get(key)
            .and_then(|node| node.get("parent"))
            .and_then(Value::as_str)
            .filter(|parent| mapping.contains_key(*parent));
    }
    chain.reverse();
    Some(chain)
}

/// Flatten ChatGPT `mapping` along its structure: depth-first from roots (no
/// parent, or a parent outside mapping) in `children` order, keeping branched
/// (regenerated) nodes. Unreachable nodes follow in payload key order, which is
/// the original order (serde_json preserve_order), so results are deterministic.
fn chatgpt_messages(object: &Map<String, Value>, conversation: &mut AiConversation) {
    let Some(mapping) = object.get("mapping").and_then(Value::as_object) else {
        return;
    };
    // Structural nodes include message-less ones; not a message count.
    conversation.structural_node_count = Some(mapping.len());
    let current_node = object
        .get("current_node")
        .and_then(Value::as_str)
        .filter(|node| !node.is_empty());
    conversation.current_node = current_node.map(str::to_string);
    let branch = current_branch(mapping, current_node);
    // Only current-branch nodes that carry a message get a display order.
    let mut branch_order: HashMap<&str, usize> = HashMap::new();
    if let Some(branch) = branch.as_ref() {
        for key in branch {
            if mapping
                .get(*key)
                .and_then(|node| node.get("message"))
                .is_some_and(Value::is_object)
            {
                let next = branch_order.len();
                branch_order.insert(*key, next);
            }
        }
        conversation.current_branch_message_count = Some(branch_order.len());
    }

    let mut roots: Vec<&str> = Vec::new();
    for (key, node) in mapping.iter() {
        let is_root = match node.get("parent").and_then(Value::as_str) {
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
            .and_then(Value::as_array);
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
    // Nodes unreachable from the structure are evidence too; append in key order.
    for key in mapping.keys() {
        if seen.insert(key.as_str()) {
            order.push(key.as_str());
        }
    }

    for key in order {
        let Some(node) = mapping.get(key).and_then(Value::as_object) else {
            continue;
        };
        // Nodes with a null message (root etc.) are not messages.
        let Some(message) = node.get("message").and_then(Value::as_object) else {
            continue;
        };
        let ordinal = conversation.messages.len();
        let (role, author_name) = match message.get("author") {
            Some(Value::Object(author)) => (
                json_str_field(author, &["role"]),
                json_str_field(author, &["name"]),
            ),
            Some(Value::String(author)) if !author.is_empty() => (Some(author.clone()), None),
            _ => (json_str_field(message, &["role"]), None),
        };
        let content_type = message
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| json_str_field(content, &["content_type"]));
        let content = message
            .get("content")
            .and_then(|content| chatgpt_content(content, ordinal, &mut conversation.attachments));
        collect_attachments(
            message,
            &["attachments"],
            Some(ordinal),
            "message_attachments",
            &mut conversation.attachments,
        );
        if let Some(metadata) = message.get("metadata").and_then(Value::as_object) {
            collect_attachments(
                metadata,
                &["attachments"],
                Some(ordinal),
                "message_metadata",
                &mut conversation.attachments,
            );
        }
        conversation.messages.push(AiMessage {
            node_id: Some(key.to_string()),
            parent_node_id: node
                .get("parent")
                .and_then(Value::as_str)
                .filter(|parent| !parent.is_empty())
                .map(str::to_string),
            message_id: json_str_field(message, &["id"]),
            role,
            author_name,
            recipient: json_str_field(message, &["recipient"]),
            content_type,
            content,
            created_at: json_str_field(message, &["create_time", "created_at"]),
            on_current_branch: branch.as_ref().map(|branch| branch.contains(&key)),
            branch_ordinal: branch_order.get(key).copied(),
        });
    }
}

/// Array messages (Claude `chat_messages`/`messages`, Gemini `messages`) in
/// payload order. Arrays carry no branch structure, so branch flags stay unset.
fn array_messages(items: &[Value], conversation: &mut AiConversation) {
    for item in items {
        let Some(message) = item.as_object() else {
            continue;
        };
        let ordinal = conversation.messages.len();
        let content = generic_content(message, ordinal, &mut conversation.attachments);
        collect_attachments(
            message,
            &["attachments", "files", "files_v2"],
            Some(ordinal),
            "message_files",
            &mut conversation.attachments,
        );
        conversation.messages.push(AiMessage {
            node_id: None,
            parent_node_id: json_str_field(message, &["parent_message_uuid", "parent"]),
            message_id: json_str_field(message, &["uuid", "id", "message_id"]),
            role: generic_role(message),
            author_name: message
                .get("author")
                .and_then(Value::as_object)
                .and_then(|author| json_str_field(author, &["name"])),
            recipient: json_str_field(message, &["recipient"]),
            content_type: json_str_field(message, &["type", "content_type"]),
            content,
            created_at: json_str_field(message, &["created_at", "create_time", "timestamp"]),
            on_current_branch: None,
            branch_ordinal: None,
        });
    }
}

/// Per-provider message/attachment extraction; nothing is built without a structure.
fn extract_ai_messages(
    provider: &str,
    object: &Map<String, Value>,
    conversation: &mut AiConversation,
) {
    match provider {
        "ChatGPT" => chatgpt_messages(object, conversation),
        "Claude" => {
            for key in ["chat_messages", "messages"] {
                if let Some(Value::Array(items)) = object.get(key) {
                    conversation.structural_node_count = Some(items.len());
                    array_messages(items, conversation);
                    break;
                }
            }
        }
        "Gemini" => {
            // Use the nested conversation object's array, else the top-level one.
            let nested = object.get("conversation").and_then(Value::as_object);
            let container = nested.unwrap_or(object);
            for key in ["messages", "turns"] {
                if let Some(Value::Array(items)) = container.get(key) {
                    conversation.structural_node_count = Some(items.len());
                    array_messages(items, conversation);
                    break;
                }
            }
            if conversation.messages.is_empty() && nested.is_some() {
                if let Some(Value::Array(items)) = object.get("messages") {
                    conversation.structural_node_count = Some(items.len());
                    array_messages(items, conversation);
                }
            }
        }
        _ => {}
    }
}

/// Service conversation id: payload field first, else the id segment of the
/// matched request URL; empty when neither exists.
fn conversation_id(provider: &str, url: &str, object: &Map<String, Value>) -> String {
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
        // Gemini has no id in the path; use the query string only when present.
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

/// AI service identity, only from the payload's account/user object. Different
/// from the Windows account.
fn service_account(object: &Map<String, Value>) -> String {
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
            Some(Value::String(value)) if !value.is_empty() => return value.clone(),
            Some(Value::Object(map)) => {
                if let Some(value) = json_str_field(map, IDENTITY) {
                    return value;
                }
            }
            _ => {}
        }
    }
    json_str_field(object, &["account_email", "user_email"]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str, body: &str) -> AiPayload {
        let provider = ai_provider(url).expect("provider");
        let value: Value = serde_json::from_str(strip_anti_hijack(body)).expect("json");
        parse_ai_payload(provider, url, &value).expect("payload")
    }

    fn conversation(url: &str, body: &str) -> AiConversation {
        match parse(url, body) {
            AiPayload::Conversation(conversation) => *conversation,
            AiPayload::List(_) => panic!("대화가 아니라 목록으로 해석됐다"),
        }
    }

    /// Cyclic parent chains still terminate and keep off-branch messages.
    #[test]
    fn cyclic_mapping_parents_do_not_hang_or_lose_messages() {
        let body = r#"{
            "mapping":{
                "a":{"parent":"b","children":["b"],"message":{"id":"m-a","author":{"role":"user"},
                     "content":{"content_type":"text","parts":["ㄱ"]}}},
                "b":{"parent":"a","children":["a"],"message":{"id":"m-b","author":{"role":"assistant"},
                     "content":{"content_type":"text","parts":["ㄴ"]}}}
            },
            "current_node":"a"
        }"#;
        let conversation =
            conversation("https://chatgpt.com/backend-api/conversation/cycle-1", body);
        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.structural_node_count, Some(2));
        // Walks a to b, then stops at the cycle.
        assert_eq!(conversation.current_branch_message_count, Some(2));
    }

    /// A list response is a trace, not a conversation body.
    #[test]
    fn conversation_list_endpoint_is_not_a_conversation_body() {
        let body = r#"{"items":[
            {"id":"c1","title":"첫 대화","create_time":"2026-09-01T00:00:00Z","update_time":"2026-09-02T00:00:00Z"},
            {"id":"c2","title":"둘째 대화","create_time":"2026-09-03T00:00:00Z"}
        ],"total":11}"#;
        let payload = parse(
            "https://chatgpt.com/backend-api/conversations?offset=0&limit=28&order=updated",
            body,
        );
        let AiPayload::List(list) = payload else {
            panic!("목록이 아니라 대화로 해석됐다");
        };
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.declared_total, Some(11));
        assert_eq!(list.entries[1].conversation_id, "c2");
        // A missing update time is not invented.
        assert_eq!(list.entries[1].updated_at, "");
        assert!(list.entries[0].item_json.contains("\"title\""));
    }

    /// Tool-call blocks with only a name are not attachments.
    #[test]
    fn tool_blocks_without_file_evidence_are_not_attachments() {
        let body = r#"{
            "uuid":"c-1",
            "chat_messages":[
                {"uuid":"m1","sender":"assistant",
                 "content":[{"type":"tool_use","id":"t1","name":"bash"},
                            {"type":"text","text":"결과"}]}
            ]
        }"#;
        let conversation = conversation(
            "https://claude.ai/api/organizations/o/chat_conversations/c-1",
            body,
        );
        assert_eq!(conversation.messages.len(), 1);
        assert_eq!(conversation.messages[0].content.as_deref(), Some("결과"));
        assert!(conversation.attachments.is_empty());
    }
}
