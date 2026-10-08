//! Task Scheduler evidence parser: XML task definitions (Vista+) and legacy
//! XP/2003 `.job` binaries (MS-TSCH). One facts row per discovered input file.
//!
//! Boundaries kept here (viewer11 R04~R08, A02/A03):
//!
//! * Discovery and parsing use the same [`detect_format`] decision, so a valid
//!   task XML is never handed to the binary reader because of its file name.
//! * Only a `Task` root element in the task namespace is a task definition;
//!   every field is read from a *direct* child path, so XML embedded in a
//!   `Data` element can never be mistaken for the definition.
//! * Unknown/extension triggers, actions and settings are preserved verbatim
//!   instead of being rejected against the original XSD.
//! * `.job` pointers, string lengths and the trigger array are bounds-checked.
//!   A truncated file keeps what was actually read plus the error and its byte
//!   offset; it never becomes an empty-but-valid task.
//! * Original bytes, decoded text, encoding, decode replacements, byte length
//!   and the SHA-256 of the file are stored, so the overview can show the full
//!   original without reading the evidence file again.
use std::path::Path;

use anyhow::{bail, Result};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use rayon::prelude::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::sqlite::Row;
use crate::time::kst_offset;

pub const TASK_TABLE: &str = "TaskScheduler_Tasks";
pub const TASK_NAMESPACE: &str = "schemas.microsoft.com/windows/2004/02/mit/task";
/// Full namespace URI of a task definition root element.
pub const TASK_NAMESPACE_URI: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";

pub const TASK_FIELD_ORDER: &[&str] = &[
    "timestamp",
    "task_name",
    "enabled",
    "hidden",
    "run_as",
    "run_level",
    "actions",
    "trigger_types",
    "trigger_start",
    "actions_json",
    "triggers_json",
    "author",
    "description",
    "logon_type",
    "uri",
    // --- format / decoding provenance (R07, R08) ---
    "source_format",
    "format_basis",
    "encoding",
    "decode_status",
    "decode_replacements",
    "raw_size",
    "raw_sha256",
    "raw_text",
    "raw_bytes_hex",
    // --- timestamp meaning (R04) ---
    "timestamp_meaning",
    "registration_date_raw",
    "registration_date",
    "job_last_run_raw",
    "job_last_run",
    // --- structured definition (A02, A03, R05) ---
    "task_version",
    "task_namespace",
    "root_children",
    "registration_json",
    "principals_json",
    "run_as_element",
    "settings_json",
    "settings_raw",
    "actions_context",
    "data_raw",
    "job_header_json",
    // --- parse status (R06, R12) ---
    "_status",
    "_error",
    "_error_location",
    "_source_file",
];

/// Row status values. `partial` keeps everything that was readable.
pub const STATUS_PARSED: &str = "parsed";
pub const STATUS_PARTIAL: &str = "partial";
pub const STATUS_UNREADABLE: &str = "unreadable_file";
pub const STATUS_INVALID_FORMAT: &str = "invalid_format";

// ---------------------------------------------------------------------------
// Content identity. Task evidence needs a stable hash of the *original bytes*
// so re-registration and repeated collections stay distinguishable (A08).
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::hex::hex_lower(&hasher.finalize())
}

/// Stream a file through SHA-256: returns (byte length, digest) without
/// holding the whole file in memory — collected executables can be large.
pub fn sha256_file(path: &Path) -> std::io::Result<(u64, String)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((size, crate::hex::hex_lower(&hasher.finalize())))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// format_timestamp(value, source_tz=KST): honour an embedded offset/Z, else
/// assume KST; output KST "YYYY-MM-DD HH:MM:SS.fff". Empty in -> empty out.
fn fmt_task_time(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let kst = kst_offset();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt
            .with_timezone(&kst)
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string();
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            let dt: DateTime<FixedOffset> = kst
                .from_local_datetime(&ndt)
                .single()
                .unwrap_or_else(|| DateTime::from_naive_utc_and_offset(ndt, kst));
            return dt
                .with_timezone(&kst)
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string();
        }
    }
    s.to_string() // unparseable -> str(value), like Python
}

fn leaf(uri: &str) -> String {
    uri.trim_end_matches('\\')
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Direct child element with this local name (never a deeper descendant):
/// `Data` payloads may embed their own XML with colliding element names.
fn child<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

/// Text of a direct child element.
fn child_text(node: roxmltree::Node, name: &str) -> String {
    child(node, name)
        .and_then(|n| n.text())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 증거에 값이 없으면 JSON null. 빈 문자열("")을 만들어 내지 않는다.
fn json_opt(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

/// xs:boolean 텍스트 → true/false. 값이 없거나 해석 불가면 null.
fn json_bool(s: &str) -> Value {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Value::Bool(true),
        "false" | "0" => Value::Bool(false),
        _ => Value::Null,
    }
}

/// 액션/트리거 요소의 원본 XML 조각. roxmltree의 positions 기능이 주는 바이트
/// 범위를 그대로 잘라 쓴다(범위를 쓸 수 없으면 표시용 조각으로 대체).
fn node_raw(src: &str, node: roxmltree::Node, fallback: &str) -> String {
    match src.get(node.range()) {
        Some(s) => s.to_string(),
        None => fallback.to_string(),
    }
}

/// actions_json/triggers_json 직렬화 규칙:
/// 부모 요소(Actions/Triggers)가 아예 없었으면 빈 문자열,
/// 부모는 있는데 자식이 하나도 없었으면 "[]". 두 경우를 구분해 둔다.
fn json_array(parent_present: bool, items: &[Value]) -> String {
    if !parent_present {
        return String::new();
    }
    serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string())
}

fn json_object(map: Map<String, Value>) -> String {
    serde_json::to_string(&Value::Object(map)).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

pub struct DecodedText {
    pub text: String,
    /// `utf-16le-bom` | `utf-16be-bom` | `utf-8-bom` | `utf-8`
    pub encoding: &'static str,
    /// Count of U+FFFD produced by lossy decoding (0 = exact).
    pub replacements: usize,
}

impl DecodedText {
    pub fn status(&self) -> &'static str {
        if self.replacements == 0 {
            "decoded"
        } else {
            "decoded_with_replacement"
        }
    }
}

/// Decode a task file to UTF-8 (task XML is usually UTF-16LE with a BOM).
pub fn decode_text(raw: &[u8]) -> DecodedText {
    let count = |text: &str| text.chars().filter(|c| *c == '\u{FFFD}').count();
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        let replacements = count(&text) + usize::from(raw[2..].len() % 2 != 0);
        return DecodedText {
            text,
            encoding: "utf-16le-bom",
            replacements,
        };
    }
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&units);
        let replacements = count(&text) + usize::from(raw[2..].len() % 2 != 0);
        return DecodedText {
            text,
            encoding: "utf-16be-bom",
            replacements,
        };
    }
    let lossy = String::from_utf8_lossy(raw);
    let replacements = count(&lossy);
    match lossy.strip_prefix('\u{feff}') {
        Some(rest) => DecodedText {
            text: rest.to_string(),
            encoding: "utf-8-bom",
            replacements,
        },
        None => DecodedText {
            text: lossy.into_owned(),
            encoding: "utf-8",
            replacements,
        },
    }
}

// ---------------------------------------------------------------------------
// Format detection — one decision for discovery and parsing (R07)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskFormat {
    Xml,
    Job,
}

impl TaskFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskFormat::Xml => "xml",
            TaskFormat::Job => "job",
        }
    }
}

/// Decide a candidate's format from its leading bytes and name. XML wins over
/// the `.job` extension so a renamed task definition is still parsed as XML.
pub fn detect_format(head: &[u8], path: &Path) -> Option<(TaskFormat, &'static str)> {
    let utf8 = TASK_NAMESPACE.as_bytes();
    let utf16: Vec<u8> = TASK_NAMESPACE.bytes().flat_map(|b| [b, 0]).collect();
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if has(utf8) {
        return Some((TaskFormat::Xml, "task_namespace_utf8"));
    }
    if has(&utf16) {
        return Some((TaskFormat::Xml, "task_namespace_utf16"));
    }
    if has_job_extension(path) && is_job_header(head) {
        return Some((TaskFormat::Job, "job_extension_and_file_version"));
    }
    None
}

/// First 4 KB of a file — enough for both format signatures.
fn read_head(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut head = Vec::new();
    Read::take(file, 4096).read_to_end(&mut head)?;
    Ok(head)
}

// ---------------------------------------------------------------------------
// XML task definition
// ---------------------------------------------------------------------------

/// Structured result of one task XML document. Also used for the task XML
/// carried inside Security 4698/4699/4700/4701/4702 payloads.
pub struct ParsedTaskXml {
    pub task_version: String,
    pub namespace: String,
    /// Direct child element names in document order (R05 evidence).
    pub root_children: Vec<String>,
    pub uri: String,
    pub registration_date: String,
    pub author: String,
    pub description: String,
    pub enabled: String,
    pub hidden: String,
    pub run_as: String,
    /// `UserId` | `GroupId` — which element the run-as value came from (R14).
    pub run_as_element: String,
    pub run_level: String,
    pub logon_type: String,
    pub actions_context: String,
    pub registration_json: String,
    pub principals_json: String,
    pub settings_json: String,
    pub settings_raw: String,
    pub data_raw: String,
    pub actions_json: String,
    pub triggers_json: String,
    pub actions_display: String,
    pub trigger_types: String,
    pub trigger_start: String,
}

/// Strip an XML declaration so roxmltree never sees `encoding="UTF-16"` on an
/// already-decoded UTF-8 string.
fn strip_declaration(text: &str) -> &str {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if let Some(rest) = trimmed.strip_prefix("<?xml") {
        if let Some(end) = rest.find("?>") {
            return trimmed[5 + end + 2..].trim_start();
        }
    }
    trimmed
}

/// Parse task XML text. Fails when the document root is not a `Task` element
/// in the task namespace, so nested XML inside `Data` is never mistaken for a
/// definition (R05).
pub fn parse_task_xml(text: &str) -> Result<ParsedTaskXml> {
    let content = strip_declaration(text);
    let doc = roxmltree::Document::parse(content)?;
    let root = doc.root_element();
    let namespace = root.tag_name().namespace().unwrap_or("").to_string();
    if root.tag_name().name() != "Task" {
        bail!(
            "task XML root element is <{}>, not <Task>",
            root.tag_name().name()
        );
    }
    if !namespace.is_empty() && namespace != TASK_NAMESPACE_URI {
        bail!("task XML root namespace is unexpected: {namespace}");
    }

    let root_children: Vec<String> = root
        .children()
        .filter(|n| n.is_element())
        .map(|n| n.tag_name().name().to_string())
        .collect();

    let reg = child(root, "RegistrationInfo");
    let settings = child(root, "Settings");
    let principals = child(root, "Principals");
    let actions_el = child(root, "Actions");
    let triggers_el = child(root, "Triggers");
    let data_el = child(root, "Data");

    let uri = reg.map(|r| child_text(r, "URI")).unwrap_or_default();
    let date = reg.map(|r| child_text(r, "Date")).unwrap_or_default();
    let author = reg.map(|r| child_text(r, "Author")).unwrap_or_default();
    let description = reg.map(|r| child_text(r, "Description")).unwrap_or_default();
    let enabled = settings.map(|s| child_text(s, "Enabled")).unwrap_or_default();
    let hidden = settings.map(|s| child_text(s, "Hidden")).unwrap_or_default();

    // --- RegistrationInfo: every declared child, raw text preserved.
    let mut registration = Map::new();
    if let Some(reg) = reg {
        for element in reg.children().filter(|n| n.is_element()) {
            registration.insert(
                element.tag_name().name().to_string(),
                json_opt(element.text().unwrap_or("").trim()),
            );
        }
        registration.insert(
            "raw".into(),
            Value::String(node_raw(content, reg, "RegistrationInfo")),
        );
    }

    // --- Principals: keep each principal and the element the identity came from.
    let mut principal_items: Vec<Value> = Vec::new();
    let (mut run_as, mut run_as_element, mut run_level, mut logon_type) = (
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    );
    if let Some(principals) = principals {
        for element in principals.children().filter(|n| n.is_element()) {
            let user = child_text(element, "UserId");
            let group = child_text(element, "GroupId");
            let privileges: Vec<Value> = child(element, "RequiredPrivileges")
                .map(|node| {
                    node.children()
                        .filter(|n| n.is_element())
                        .map(|n| Value::String(n.text().unwrap_or("").trim().to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let item = json!({
                "element": element.tag_name().name(),
                "id": json_opt(element.attribute("id").unwrap_or("").trim()),
                "user_id": json_opt(&user),
                "group_id": json_opt(&group),
                "display_name": json_opt(&child_text(element, "DisplayName")),
                "logon_type": json_opt(&child_text(element, "LogonType")),
                "run_level": json_opt(&child_text(element, "RunLevel")),
                "process_token_sid_type": json_opt(&child_text(element, "ProcessTokenSidType")),
                "required_privileges": privileges,
                "raw": node_raw(content, element, element.tag_name().name()),
            });
            if run_as.is_empty() {
                if !user.is_empty() {
                    run_as = user.clone();
                    run_as_element = "UserId".into();
                } else if !group.is_empty() {
                    run_as = group.clone();
                    run_as_element = "GroupId".into();
                }
                run_level = child_text(element, "RunLevel");
                logon_type = child_text(element, "LogonType");
            }
            principal_items.push(item);
        }
    }

    // --- Settings: declared values only, nested groups kept as objects.
    let mut settings_map = Map::new();
    let mut settings_raw = String::new();
    if let Some(settings) = settings {
        settings_raw = node_raw(content, settings, "Settings");
        for element in settings.children().filter(|n| n.is_element()) {
            let name = element.tag_name().name().to_string();
            let nested: Vec<roxmltree::Node> =
                element.children().filter(|n| n.is_element()).collect();
            let value = if nested.is_empty() {
                json_opt(element.text().unwrap_or("").trim())
            } else {
                let mut group = Map::new();
                for inner in nested {
                    group.insert(
                        inner.tag_name().name().to_string(),
                        json_opt(inner.text().unwrap_or("").trim()),
                    );
                }
                Value::Object(group)
            };
            settings_map.insert(name, value);
        }
    }

    // --- Actions: display fragment plus structured evidence.
    let mut action_parts: Vec<String> = Vec::new();
    let mut action_objs: Vec<Value> = Vec::new();
    let mut actions_context = String::new();
    if let Some(actions) = actions_el {
        actions_context = actions.attribute("Context").unwrap_or("").trim().to_string();
        for act in actions.children().filter(|c| c.is_element()) {
            let name = act.tag_name().name().to_string();
            if name.is_empty() {
                continue;
            }
            let mut item = Map::new();
            item.insert("action_type".into(), Value::String(name.clone()));
            item.insert(
                "action_id".into(),
                json_opt(act.attribute("id").unwrap_or("").trim()),
            );
            let frag = match name.as_str() {
                "Exec" => {
                    let cmd = child_text(act, "Command");
                    let args = child_text(act, "Arguments");
                    let wd = child_text(act, "WorkingDirectory");
                    item.insert("command".into(), json_opt(&cmd));
                    item.insert("arguments".into(), json_opt(&args));
                    item.insert("working_directory".into(), json_opt(&wd));
                    format!("{cmd} {args}").trim().to_string()
                }
                "ComHandler" => {
                    // A COM class is not a command: keep it in its own field so
                    // command search and path resolution never see a CLSID.
                    let class_id = child_text(act, "ClassId");
                    let data = child(act, "Data");
                    item.insert("class_id".into(), json_opt(&class_id));
                    item.insert(
                        "com_data".into(),
                        match data {
                            Some(node) => Value::String(node_raw(content, node, "Data")),
                            None => Value::Null,
                        },
                    );
                    format!("COM:{class_id}")
                }
                _ => {
                    // SendEmail / ShowMessage / extensions: keep every declared
                    // child verbatim rather than dropping the action's content.
                    let mut detail = Map::new();
                    for inner in act.children().filter(|n| n.is_element()) {
                        detail.insert(
                            inner.tag_name().name().to_string(),
                            json_opt(inner.text().unwrap_or("").trim()),
                        );
                    }
                    if !detail.is_empty() {
                        item.insert("detail".into(), Value::Object(detail));
                    }
                    name.clone()
                }
            };
            item.insert("raw".into(), Value::String(node_raw(content, act, &frag)));
            action_parts.push(frag);
            action_objs.push(Value::Object(item));
        }
    }

    // --- Triggers: full structure, unknown types preserved (R05).
    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    let mut trigger_objs: Vec<Value> = Vec::new();
    if let Some(triggers) = triggers_el {
        for trig in triggers.children().filter(|c| c.is_element()) {
            let name = trig.tag_name().name().to_string();
            trigger_types.push(name.clone());
            let sb = child_text(trig, "StartBoundary");
            if trigger_start.is_empty() && !sb.is_empty() {
                trigger_start = sb.clone();
            }
            let eb = child_text(trig, "EndBoundary");
            let en = child_text(trig, "Enabled");
            let repetition = child(trig, "Repetition").map(|node| {
                json!({
                    "interval": json_opt(&child_text(node, "Interval")),
                    "duration": json_opt(&child_text(node, "Duration")),
                    "stop_at_duration_end": json_bool(&child_text(node, "StopAtDurationEnd")),
                    "raw": node_raw(content, node, "Repetition"),
                })
            });
            // Calendar/extension schedule bodies: keep the element name and raw.
            let schedule = trig
                .children()
                .filter(|n| n.is_element())
                .find(|n| n.tag_name().name().starts_with("ScheduleBy"))
                .map(|node| {
                    json!({
                        "kind": node.tag_name().name(),
                        "raw": node_raw(content, node, node.tag_name().name()),
                    })
                });
            let mut item = Map::new();
            item.insert("trigger_type".into(), Value::String(name.clone()));
            item.insert(
                "trigger_id".into(),
                json_opt(trig.attribute("id").unwrap_or("").trim()),
            );
            item.insert("start_time".into(), json_opt(&fmt_task_time(&sb)));
            item.insert("start_time_raw".into(), json_opt(&sb));
            item.insert("end_time".into(), json_opt(&fmt_task_time(&eb)));
            item.insert("end_time_raw".into(), json_opt(&eb));
            item.insert("enabled".into(), json_bool(&en));
            item.insert(
                "execution_time_limit".into(),
                json_opt(&child_text(trig, "ExecutionTimeLimit")),
            );
            item.insert("delay".into(), json_opt(&child_text(trig, "Delay")));
            item.insert(
                "random_delay".into(),
                json_opt(&child_text(trig, "RandomDelay")),
            );
            item.insert("repetition".into(), repetition.unwrap_or(Value::Null));
            item.insert("schedule".into(), schedule.unwrap_or(Value::Null));
            item.insert(
                "subscription".into(),
                json_opt(&child_text(trig, "Subscription")),
            );
            item.insert("state_name".into(), json_opt(&child_text(trig, "StateName")));
            item.insert("user_id".into(), json_opt(&child_text(trig, "UserId")));
            item.insert(
                "session_change_type".into(),
                json_opt(&child_text(trig, "StateChange")),
            );
            item.insert(
                "raw".into(),
                Value::String(node_raw(content, trig, &name)),
            );
            trigger_objs.push(Value::Object(item));
        }
    }

    Ok(ParsedTaskXml {
        task_version: root.attribute("version").unwrap_or("").trim().to_string(),
        namespace,
        root_children,
        uri,
        registration_date: date,
        author,
        description,
        enabled,
        hidden,
        run_as,
        run_as_element,
        run_level,
        logon_type,
        actions_context,
        registration_json: json_object(registration),
        principals_json: serde_json::to_string(&principal_items).unwrap_or_default(),
        // No Settings element at all stays empty, like actions/triggers, so a
        // consumer never applies schema defaults to a task that declared none.
        settings_json: if settings.is_some() {
            json_object(settings_map)
        } else {
            String::new()
        },
        settings_raw,
        data_raw: data_el
            .map(|node| node_raw(content, node, "Data"))
            .unwrap_or_default(),
        actions_json: json_array(actions_el.is_some(), &action_objs),
        triggers_json: json_array(triggers_el.is_some(), &trigger_objs),
        actions_display: action_parts
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" | "),
        trigger_types: trigger_types.join(", "),
        trigger_start,
    })
}

fn parse_task(path: &Path, raw: &[u8]) -> Row {
    let decoded = decode_text(raw);
    let parsed = match parse_task_xml(&decoded.text) {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut row = error_row(path, STATUS_INVALID_FORMAT, &error.to_string(), None);
            store_decoding(&mut row, decoded);
            return row;
        }
    };

    let task_name = {
        let l = leaf(&parsed.uri);
        if l.is_empty() {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            l
        }
    };

    let mut row = Row::new();
    let registration_date = fmt_task_time(&parsed.registration_date);
    row.insert("timestamp".into(), registration_date.clone());
    row.insert("task_name".into(), task_name);
    row.insert("enabled".into(), parsed.enabled);
    row.insert("hidden".into(), parsed.hidden);
    row.insert("run_as".into(), parsed.run_as);
    row.insert("run_level".into(), parsed.run_level);
    row.insert("actions".into(), parsed.actions_display);
    row.insert("trigger_types".into(), parsed.trigger_types);
    row.insert(
        "trigger_start".into(),
        fmt_task_time(&parsed.trigger_start),
    );
    row.insert("actions_json".into(), parsed.actions_json);
    row.insert("triggers_json".into(), parsed.triggers_json);
    row.insert("author".into(), parsed.author);
    row.insert("description".into(), parsed.description);
    row.insert("logon_type".into(), parsed.logon_type);
    row.insert("uri".into(), parsed.uri);
    row.insert(
        "timestamp_meaning".into(),
        if registration_date.is_empty() {
            "none".into()
        } else {
            "registration_date".to_string()
        },
    );
    row.insert(
        "registration_date_raw".into(),
        parsed.registration_date.clone(),
    );
    row.insert("registration_date".into(), registration_date);
    row.insert("task_version".into(), parsed.task_version);
    row.insert("task_namespace".into(), parsed.namespace);
    row.insert("root_children".into(), parsed.root_children.join(", "));
    row.insert("registration_json".into(), parsed.registration_json);
    row.insert("principals_json".into(), parsed.principals_json);
    row.insert("run_as_element".into(), parsed.run_as_element);
    row.insert("settings_json".into(), parsed.settings_json);
    row.insert("settings_raw".into(), parsed.settings_raw);
    row.insert("actions_context".into(), parsed.actions_context);
    row.insert("data_raw".into(), parsed.data_raw);
    store_decoding(&mut row, decoded);
    row
}

fn store_decoding(row: &mut Row, decoded: DecodedText) {
    row.insert("encoding".into(), decoded.encoding.into());
    row.insert("decode_status".into(), decoded.status().into());
    row.insert("raw_text".into(), decoded.text);
    row.insert(
        "decode_replacements".into(),
        decoded.replacements.to_string(),
    );
}

// ---------------------------------------------------------------------------
// XP/2003 .job (MS-TSCH binary task) — FIXDLEN_DATA (0x44) + length-prefixed
// UTF-16LE strings + the 48-byte TASK_TRIGGER array. Every pointer and length
// is bounds-checked and failures keep their byte offset (R06).
// ---------------------------------------------------------------------------

const JOB_FLAG_DISABLED: u32 = 0x4;
const JOB_FLAG_HIDDEN: u32 = 0x200;
const JOB_FIXED_LEN: usize = 0x44;
const JOB_TRIGGER_LEN: usize = 48;
// TASK_TRIGGER.rgFlags(오프셋 0x1C) — MS-TSCH에 문서화된 비트만 사용한다.
const JOB_TRIGGER_FLAG_HAS_END_DATE: u32 = 0x1;
const JOB_TRIGGER_FLAG_DISABLED: u32 = 0x4;

fn job_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

fn job_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Collected read errors with the byte offset that failed.
#[derive(Default)]
struct JobFaults {
    items: Vec<String>,
    location: Option<usize>,
}

impl JobFaults {
    fn add(&mut self, offset: usize, message: &str) {
        self.items.push(format!("0x{offset:X}: {message}"));
        self.location.get_or_insert(offset);
    }
}

/// Length-prefixed Unicode string: u16 character count (including the
/// terminating NUL) followed by UTF-16LE. Out-of-range lengths are reported
/// instead of silently producing an empty value.
fn job_lpstring(b: &[u8], off: usize, faults: &mut JobFaults, label: &str) -> (String, usize) {
    if off + 2 > b.len() {
        faults.add(off, &format!("{label} 길이 워드가 파일 끝을 넘습니다"));
        return (String::new(), b.len());
    }
    let chars = job_u16(b, off) as usize;
    let start = off + 2;
    let end = start + chars * 2;
    if chars == 0 {
        return (String::new(), start);
    }
    if end > b.len() {
        faults.add(
            start,
            &format!("{label} 문자열 {chars}자가 파일 끝({} 바이트)을 넘습니다", b.len()),
        );
        // Keep what is actually present rather than discarding the evidence.
        let units: Vec<u16> = b[start..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        return (String::from_utf16_lossy(&units), b.len());
    }
    let units: Vec<u16> = b[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    (String::from_utf16_lossy(&units), end)
}

/// MS-TSCH TASK_TRIGGER Type 필드 → 이름 (XML TriggerType과 구분되는 구형 명명).
fn job_trigger_name(t: u32) -> String {
    match t {
        0 => "ONCE".into(),
        1 => "DAILY".into(),
        2 => "WEEKLY".into(),
        3 => "MONTHLYDATE".into(),
        4 => "MONTHLYDOW".into(),
        5 => "ON_IDLE".into(),
        6 => "AT_SYSTEMSTART".into(),
        7 => "AT_LOGON".into(),
        other => format!("TYPE_{other}"),
    }
}

/// .job 헤더 판별: FileVersion(offset 2)==1 이고 고정부를 담을 길이.
fn is_job_header(head: &[u8]) -> bool {
    head.len() >= JOB_FIXED_LEN + 2 && job_u16(head, 2) == 1
}

fn has_job_extension(path: &Path) -> bool {
    path.extension()
        .map(|e| e.to_string_lossy().eq_ignore_ascii_case("job"))
        .unwrap_or(false)
}

/// .job 하나 → TASK_FIELD_ORDER 행. run_as/run_level/logon_type은 .job 파일에
/// 저장되지 않는 정보라 빈 값(계정은 별도 LSA 시크릿에 보관되던 구조).
fn parse_job(path: &Path, b: &[u8]) -> Result<Row> {
    if !is_job_header(b) {
        bail!("not a .job task (file version != 1)");
    }
    let mut faults = JobFaults::default();

    let flags = job_u32(b, 0x30);
    // Last Run Time: SYSTEMTIME(로컬 시간) — year 0이면 실행 이력 없음.
    let (yr, mo, dy) = (job_u16(b, 0x34), job_u16(b, 0x36), job_u16(b, 0x3A));
    let (hh, mi, ss, ms) = (
        job_u16(b, 0x3C),
        job_u16(b, 0x3E),
        job_u16(b, 0x40),
        job_u16(b, 0x42),
    );
    let last_run = if yr == 0 {
        String::new()
    } else {
        format!("{yr:04}-{mo:02}-{dy:02} {hh:02}:{mi:02}:{ss:02}.{ms:03}")
    };
    let last_run_raw = if yr == 0 {
        String::new()
    } else {
        format!("SYSTEMTIME {yr:04}-{mo:02}-{dy:02}T{hh:02}:{mi:02}:{ss:02}.{ms:03} (local)")
    };

    // 가변부: 헤더가 가리키는 AppName 길이 워드 오프셋부터 문자열 5개 연속.
    let app_off = job_u16(b, 0x14) as usize;
    if app_off < JOB_FIXED_LEN || app_off >= b.len() {
        faults.add(
            0x14,
            &format!("Application Name 오프셋 0x{app_off:X}가 파일 범위 밖입니다"),
        );
    }
    let start = app_off.min(b.len());
    let (application, next) = job_lpstring(b, start, &mut faults, "AppName");
    let (parameters, next) = job_lpstring(b, next, &mut faults, "Parameters");
    let (working_dir, next) = job_lpstring(b, next, &mut faults, "WorkingDirectory");
    let (author, next) = job_lpstring(b, next, &mut faults, "Author");
    let (comment, after_comment) = job_lpstring(b, next, &mut faults, "Comment");

    // User Data / Reserved Data: length-prefixed byte blobs after Comment.
    let mut cursor = after_comment;
    let blob = |label: &str, faults: &mut JobFaults, cursor: &mut usize| -> String {
        if *cursor + 2 > b.len() {
            faults.add(*cursor, &format!("{label} 길이 워드가 파일 끝을 넘습니다"));
            *cursor = b.len();
            return String::new();
        }
        let size = job_u16(b, *cursor) as usize;
        let start = *cursor + 2;
        let end = start + size;
        if end > b.len() {
            faults.add(start, &format!("{label} {size}바이트가 파일 끝을 넘습니다"));
            *cursor = b.len();
            return crate::hex::hex_lower(&b[start.min(b.len())..]);
        }
        *cursor = end;
        crate::hex::hex_lower(&b[start..end])
    };
    let user_data = blob("User Data", &mut faults, &mut cursor);
    let reserved_data = blob("Reserved Data", &mut faults, &mut cursor);

    // 트리거 배열: 헤더의 Trigger Offset이 count u16을 가리킨다.
    let trig_off = job_u16(b, 0x16) as usize;
    let mut trig_count = 0usize;
    if trig_off + 2 > b.len() {
        faults.add(
            0x16,
            &format!("Trigger 오프셋 0x{trig_off:X}가 파일 범위 밖입니다"),
        );
    } else {
        trig_count = job_u16(b, trig_off) as usize;
    }
    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    let mut trigger_objs: Vec<Value> = Vec::new();
    for i in 0..trig_count {
        let o = trig_off + 2 + i * JOB_TRIGGER_LEN;
        if o + JOB_TRIGGER_LEN > b.len() {
            faults.add(
                o,
                &format!("트리거 {}/{trig_count} 레코드가 파일 끝을 넘습니다", i + 1),
            );
            break;
        }
        let name = job_trigger_name(job_u32(b, o + 0x20));
        trigger_types.push(name.clone());
        let (by, bm, bd) = (job_u16(b, o + 4), job_u16(b, o + 6), job_u16(b, o + 8));
        let (sh, sm) = (job_u16(b, o + 0x10), job_u16(b, o + 0x12));
        let start = if by != 0 {
            format!("{by:04}-{bm:02}-{bd:02} {sh:02}:{sm:02}:00.000")
        } else {
            String::new()
        };
        if trigger_start.is_empty() {
            trigger_start = start.clone();
        }
        // 종료일은 HAS_END_DATE 플래그가 선 경우에만 유효하다. 구조에 종료 '시각'
        // 필드가 없으므로 날짜까지만 적고 시각을 지어내지 않는다.
        let rg_flags = job_u32(b, o + 0x1C);
        let (ey, em, ed) = (
            job_u16(b, o + 0x0A),
            job_u16(b, o + 0x0C),
            job_u16(b, o + 0x0E),
        );
        let end = if rg_flags & JOB_TRIGGER_FLAG_HAS_END_DATE != 0 && ey != 0 {
            format!("{ey:04}-{em:02}-{ed:02}")
        } else {
            String::new()
        };
        let declared = job_u16(b, o) as usize;
        if declared != JOB_TRIGGER_LEN {
            faults.add(
                o,
                &format!("트리거 cbTriggerSize {declared}가 48이 아닙니다"),
            );
        }
        // raw: 48바이트 TASK_TRIGGER 레코드 원문(헥스).
        let raw = crate::hex::hex_lower(&b[o..o + JOB_TRIGGER_LEN]).to_uppercase();
        trigger_objs.push(json!({
            "trigger_type": name,
            "trigger_id": Value::Null,
            "start_time": json_opt(&start),
            "start_time_raw": json_opt(&start),
            "end_time": json_opt(&end),
            "end_time_raw": json_opt(&end),
            "enabled": Value::Bool(rg_flags & JOB_TRIGGER_FLAG_DISABLED == 0),
            "repetition": json!({
                "interval_minutes": job_u16(b, o + 0x18),
                "duration_minutes": job_u16(b, o + 0x1A),
                "raw": crate::hex::hex_lower(&b[o + 0x18..o + 0x1C]),
            }),
            "raw": raw,
        }));
    }

    // .job은 액션이 항상 정확히 하나(AppName/Parameters/WorkingDirectory).
    let action_display = format!("{application} {parameters}").trim().to_string();
    let action_objs = vec![json!({
        "action_type": "Exec",
        "command": json_opt(&application),
        "arguments": json_opt(&parameters),
        "working_directory": json_opt(&working_dir),
        "raw": action_display.clone(),
    })];

    let header = json!({
        "product_version": job_u16(b, 0x00),
        "file_version": job_u16(b, 0x02),
        "uuid": crate::hex::hex_lower(b.get(0x04..0x14).unwrap_or_default()),
        "app_name_offset": app_off,
        "trigger_offset": trig_off,
        "trigger_count": trig_count,
        "error_retry_count": job_u16(b, 0x18),
        "error_retry_interval": job_u16(b, 0x1A),
        "idle_deadline": job_u16(b, 0x1C),
        "idle_wait": job_u16(b, 0x1E),
        "priority": job_u32(b, 0x20),
        "maximum_run_time": job_u32(b, 0x24),
        "exit_code": job_u32(b, 0x28),
        "status": job_u32(b, 0x2C),
        "flags": flags,
        "running_instance_count": job_u16(b, JOB_FIXED_LEN),
        "user_data_hex": json_opt(&user_data),
        "reserved_data_hex": json_opt(&reserved_data),
    });

    let mut row = Row::new();
    row.insert("timestamp".into(), last_run.clone());
    row.insert(
        "task_name".into(),
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    );
    row.insert(
        "enabled".into(),
        if flags & JOB_FLAG_DISABLED != 0 {
            "false".into()
        } else {
            "true".to_string()
        },
    );
    row.insert(
        "hidden".into(),
        if flags & JOB_FLAG_HIDDEN != 0 {
            "true".into()
        } else {
            "false".to_string()
        },
    );
    row.insert("actions".into(), action_display);
    row.insert("trigger_types".into(), trigger_types.join(", "));
    row.insert("trigger_start".into(), trigger_start);
    // .job은 액션/트리거 구조가 항상 존재한다(트리거 0개면 "[]").
    row.insert("actions_json".into(), json_array(true, &action_objs));
    row.insert("triggers_json".into(), json_array(true, &trigger_objs));
    row.insert("author".into(), author);
    row.insert("description".into(), comment);
    row.insert("timestamp_meaning".into(), {
        if last_run.is_empty() {
            "none".into()
        } else {
            "job_last_run".to_string()
        }
    });
    row.insert("job_last_run".into(), last_run);
    row.insert("job_last_run_raw".into(), last_run_raw);
    row.insert("job_header_json".into(), header.to_string());
    row.insert("encoding".into(), "binary".into());
    row.insert("decode_status".into(), "binary".into());
    row.insert("decode_replacements".into(), "0".into());
    if !faults.items.is_empty() {
        row.insert("_status".into(), STATUS_PARTIAL.into());
        row.insert("_error".into(), faults.items.join(" | "));
        if let Some(location) = faults.location {
            row.insert("_error_location".into(), format!("0x{location:X}"));
        }
    }
    Ok(row)
}

// ---------------------------------------------------------------------------
// Discovery and row production
// ---------------------------------------------------------------------------

/// Walk `root` and retain every file whose header identifies it as a task
/// definition (XML) or a legacy `.job`. Unreadable candidates stay as errors —
/// "undecidable" is not "not a target".
pub fn task_sources(root: &Path) -> crate::finder::Found {
    let (paths, walk_errors) = crate::finder::walk_files(root);
    let checked: Vec<(Option<std::path::PathBuf>, Option<String>)> = paths
        .par_iter()
        .map(|path| match read_head(path) {
            // Read only the first 4 KB to test the signature — never the whole
            // file. A target can hold huge unrelated files (images, dumps).
            Ok(head) => (
                detect_format(&head, path).map(|_| path.clone()),
                None,
            ),
            Err(error) => (
                None,
                Some(format!("{}: 내용 판별용 앞부분 읽기 실패: {error}", path.display())),
            ),
        })
        .collect();
    let mut errors = walk_errors;
    let mut sources = Vec::new();
    for (path, error) in checked {
        if let Some(path) = path {
            sources.push(path);
        }
        if let Some(error) = error {
            errors.push(error);
        }
    }
    sources.sort();
    crate::finder::Found {
        paths: sources,
        errors,
    }
}

fn error_row(path: &Path, status: &str, error: &str, raw: Option<&[u8]>) -> Row {
    let mut row = Row::new();
    row.insert("timestamp".into(), String::new());
    row.insert(
        "task_name".into(),
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    );
    row.insert("timestamp_meaning".into(), "none".into());
    row.insert("_source_file".into(), path.to_string_lossy().to_string());
    row.insert("_status".into(), status.into());
    row.insert("_error".into(), error.to_string());
    if let Some(raw) = raw {
        row.insert("raw_size".into(), raw.len().to_string());
        row.insert("raw_sha256".into(), sha256_hex(raw));
        row.insert("raw_bytes_hex".into(), crate::hex::hex_lower(raw));
    }
    row
}

/// Parse already-discovered task files (one row per file; unreadable files
/// keep an error row so every evidence input stays represented).
pub fn parse_tasks_from(paths: &[std::path::PathBuf]) -> Vec<Row> {
    paths
        .par_iter()
        .map(|path| {
            let raw = match std::fs::read(path) {
                Ok(raw) => raw,
                Err(error) => {
                    return error_row(path, STATUS_UNREADABLE, &error.to_string(), None)
                }
            };
            let head = &raw[..raw.len().min(4096)];
            let Some((format, basis)) = detect_format(head, path) else {
                return error_row(
                    path,
                    STATUS_INVALID_FORMAT,
                    "작업 XML 네임스페이스도 .job 헤더도 확인되지 않았습니다",
                    Some(&raw),
                );
            };
            let parsed = match format {
                TaskFormat::Xml => Ok(parse_task(path, &raw)),
                TaskFormat::Job => parse_job(path, &raw),
            };
            let mut row = match parsed {
                Ok(row) => row,
                Err(error) => error_row(path, STATUS_INVALID_FORMAT, &error.to_string(), None),
            };
            row.insert("source_format".into(), format.as_str().into());
            row.insert("format_basis".into(), basis.into());
            row.insert("raw_size".into(), raw.len().to_string());
            row.insert("raw_sha256".into(), sha256_hex(&raw));
            row.insert("raw_bytes_hex".into(), crate::hex::hex_lower(&raw));
            row.entry("_status".into())
                .or_insert_with(|| STATUS_PARSED.to_string());
            row.insert("_source_file".into(), path.to_string_lossy().to_string());
            row
        })
        .collect()
}

pub fn parse_tasks_with_sources(root: &Path) -> Result<(Vec<std::path::PathBuf>, Vec<Row>)> {
    let sources = task_sources(root).paths;
    let rows = parse_tasks_from(&sources);
    Ok((sources, rows))
}

pub fn parse_tasks(root: &Path) -> Result<Vec<Row>> {
    Ok(parse_tasks_with_sources(root)?.1)
}

#[cfg(test)]
mod job_tests {
    use super::*;

    fn put_u16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn lpstr(s: &str) -> Vec<u8> {
        if s.is_empty() {
            return 0u16.to_le_bytes().to_vec();
        }
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.push(0);
        let mut b = (units.len() as u16).to_le_bytes().to_vec();
        b.extend(units.iter().flat_map(|u| u.to_le_bytes()));
        b
    }

    /// MS-TSCH 레이아웃 합성 .job: 고정부 + 문자열 5개 + AT_LOGON 트리거 1개.
    fn synthetic_job(flags: u32, last_run_year: u16) -> Vec<u8> {
        let mut var = Vec::new();
        var.extend(0u16.to_le_bytes()); // Running Instance Count
        let app_rel = var.len();
        var.extend(lpstr("C:\\WINDOWS\\system32\\evil.exe"));
        var.extend(lpstr("-run"));
        var.extend(lpstr("C:\\WINDOWS")); // WorkingDirectory
        var.extend(lpstr("attacker"));
        var.extend(lpstr("legacy at job"));
        var.extend(0u16.to_le_bytes()); // User Data size 0
        var.extend(0u16.to_le_bytes()); // Reserved Data size 0
        let trig_rel = var.len();
        var.extend(1u16.to_le_bytes()); // trigger count
        let mut trig = vec![0u8; JOB_TRIGGER_LEN];
        put_u16(&mut trig, 0, JOB_TRIGGER_LEN as u16);
        put_u16(&mut trig, 4, 2004); // Begin Year
        put_u16(&mut trig, 6, 7); // Begin Month
        put_u16(&mut trig, 8, 15); // Begin Day
        put_u16(&mut trig, 0x10, 9); // Start Hour
        put_u16(&mut trig, 0x12, 30); // Start Minute
        put_u32(&mut trig, 0x20, 7); // AT_LOGON
        var.extend(&trig);

        let mut b = vec![0u8; JOB_FIXED_LEN];
        put_u16(&mut b, 0x00, 0x0501); // Product Version (XP)
        put_u16(&mut b, 0x02, 1); // File Version
        put_u16(&mut b, 0x14, (JOB_FIXED_LEN + app_rel) as u16);
        put_u16(&mut b, 0x16, (JOB_FIXED_LEN + trig_rel) as u16);
        put_u32(&mut b, 0x28, 0x80070002); // Exit Code
        put_u32(&mut b, 0x30, flags);
        if last_run_year != 0 {
            put_u16(&mut b, 0x34, last_run_year);
            put_u16(&mut b, 0x36, 3); // month
            put_u16(&mut b, 0x3A, 5); // day
            put_u16(&mut b, 0x3C, 14);
            put_u16(&mut b, 0x3E, 45);
            put_u16(&mut b, 0x40, 1);
            put_u16(&mut b, 0x42, 250);
        }
        b.extend(var);
        b
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-job-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parse_file(path: &Path) -> Row {
        parse_tasks_from(&[path.to_path_buf()]).remove(0)
    }

    #[test]
    fn parses_job_fields_and_trigger() {
        let dir = temp_dir("basic");
        let path = dir.join("At1.job");
        std::fs::write(&path, synthetic_job(0, 2004)).unwrap();
        let row = parse_file(&path);
        assert_eq!(row.get("task_name").map(String::as_str), Some("At1.job"));
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("C:\\WINDOWS\\system32\\evil.exe -run")
        );
        assert_eq!(row.get("author").map(String::as_str), Some("attacker"));
        assert_eq!(
            row.get("description").map(String::as_str),
            Some("legacy at job")
        );
        assert_eq!(row.get("trigger_types").map(String::as_str), Some("AT_LOGON"));
        assert_eq!(
            row.get("trigger_start").map(String::as_str),
            Some("2004-07-15 09:30:00.000")
        );
        assert_eq!(
            row.get("timestamp").map(String::as_str),
            Some("2004-03-05 14:45:01.250")
        );
        // R04: .job의 대표 시각은 등록 시각이 아니라 마지막 실행 시각이다.
        assert_eq!(
            row.get("timestamp_meaning").map(String::as_str),
            Some("job_last_run")
        );
        assert_eq!(
            row.get("job_last_run").map(String::as_str),
            Some("2004-03-05 14:45:01.250")
        );
        assert_eq!(row.get("registration_date").map(String::as_str), None);
        assert_eq!(row.get("enabled").map(String::as_str), Some("true"));
        assert_eq!(row.get("hidden").map(String::as_str), Some("false"));
        assert_eq!(row.get("source_format").map(String::as_str), Some("job"));
        assert_eq!(row.get("_status").map(String::as_str), Some(STATUS_PARSED));
        // R06/R08: 헤더 전체와 원본 바이트·해시가 남는다.
        let header: Value = serde_json::from_str(row.get("job_header_json").unwrap()).unwrap();
        assert_eq!(header["exit_code"], 0x8007_0002u32);
        assert_eq!(header["file_version"], 1);
        assert_eq!(header["trigger_count"], 1);
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(
            row.get("raw_size").map(String::as_str),
            Some(raw.len().to_string().as_str())
        );
        assert!(row
            .get("raw_sha256")
            .is_some_and(|hash| hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn job_emits_structured_action_and_trigger_json() {
        let dir = temp_dir("json");
        let path = dir.join("At3.job");
        std::fs::write(&path, synthetic_job(0, 2004)).unwrap();
        let row = parse_file(&path);

        let acts: Value = serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts.as_array().unwrap().len(), 1);
        assert_eq!(acts[0]["action_type"], "Exec");
        assert_eq!(acts[0]["command"], "C:\\WINDOWS\\system32\\evil.exe");
        assert_eq!(acts[0]["arguments"], "-run");
        assert_eq!(acts[0]["working_directory"], "C:\\WINDOWS");
        assert_eq!(acts[0]["raw"], "C:\\WINDOWS\\system32\\evil.exe -run");

        let trigs: Value = serde_json::from_str(row.get("triggers_json").unwrap()).unwrap();
        assert_eq!(trigs.as_array().unwrap().len(), 1);
        assert_eq!(trigs[0]["trigger_type"], "AT_LOGON");
        assert_eq!(trigs[0]["start_time"], "2004-07-15 09:30:00.000");
        // HAS_END_DATE 플래그가 없으므로 종료일은 null.
        assert!(trigs[0]["end_time"].is_null());
        assert_eq!(trigs[0]["enabled"], true);
        // raw = 48바이트 TASK_TRIGGER 헥스(cbTriggerSize=0x0030 선행).
        assert_eq!(trigs[0]["raw"].as_str().unwrap().len(), JOB_TRIGGER_LEN * 2);
        assert!(trigs[0]["raw"].as_str().unwrap().starts_with("3000"));

        // 기존 표시 컬럼은 그대로.
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("C:\\WINDOWS\\system32\\evil.exe -run")
        );
        assert_eq!(
            row.get("trigger_start").map(String::as_str),
            Some("2004-07-15 09:30:00.000")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disabled_hidden_flags_and_never_run() {
        let dir = temp_dir("flags");
        let path = dir.join("At2.job");
        std::fs::write(&path, synthetic_job(JOB_FLAG_DISABLED | JOB_FLAG_HIDDEN, 0)).unwrap();
        let row = parse_file(&path);
        assert_eq!(row.get("enabled").map(String::as_str), Some("false"));
        assert_eq!(row.get("hidden").map(String::as_str), Some("true"));
        assert_eq!(row.get("timestamp").map(String::as_str), Some(""));
        assert_eq!(row.get("timestamp_meaning").map(String::as_str), Some("none"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn discovery_accepts_job_and_rejects_fake_extension() {
        let dir = temp_dir("discover");
        std::fs::write(dir.join("Real.job"), synthetic_job(0, 2004)).unwrap();
        // 확장자만 .job인 쓰레기(FileVersion != 1)는 제외돼야 한다.
        std::fs::write(dir.join("Fake.job"), vec![0xFFu8; 0x100]).unwrap();
        let sources = task_sources(&dir).paths;
        let names: Vec<String> = sources
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        assert_eq!(names, vec!["Real.job".to_string()]);
        let rows = parse_tasks_from(&sources);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("trigger_types").map(String::as_str),
            Some("AT_LOGON")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R06: 포인터·길이 절단은 빈 정상 값이 아니라 부분 복구 + 오류 위치다.
    #[test]
    fn truncated_strings_and_triggers_keep_error_location() {
        let dir = temp_dir("truncated");
        let full = synthetic_job(0, 2004);
        let path = dir.join("Cut.job");
        // 문자열 5개와 트리거 개수까지는 남기고 트리거 레코드 중간에서 자른다.
        let cut = full.len() - 40;
        std::fs::write(&path, &full[..cut]).unwrap();
        let row = parse_file(&path);
        assert_eq!(row.get("_status").map(String::as_str), Some(STATUS_PARTIAL));
        let error = row.get("_error").cloned().unwrap_or_default();
        assert!(error.contains("파일 끝"), "{error}");
        assert!(row
            .get("_error_location")
            .is_some_and(|location| location.starts_with("0x")));
        // 읽을 수 있었던 명령·작성자는 보존하고 잘린 트리거만 비운다.
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("C:\\WINDOWS\\system32\\evil.exe -run")
        );
        assert_eq!(row.get("author").map(String::as_str), Some("attacker"));
        assert_eq!(row.get("trigger_types").map(String::as_str), Some(""));
        // 잘린 파일에서도 원본 바이트·해시는 남는다.
        assert_eq!(
            row.get("raw_size").map(String::as_str),
            Some(cut.to_string().as_str())
        );

        // 트리거 배열 오프셋이 파일 밖을 가리키는 경우.
        let mut broken = full.clone();
        put_u16(&mut broken, 0x16, 0xFFF0);
        let path = dir.join("BadTrigger.job");
        std::fs::write(&path, &broken).unwrap();
        let row = parse_file(&path);
        assert_eq!(row.get("_status").map(String::as_str), Some(STATUS_PARTIAL));
        assert!(row.get("_error").unwrap().contains("Trigger 오프셋"));
        assert_eq!(row.get("trigger_types").map(String::as_str), Some(""));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R07: 유효한 작업 XML은 파일명이 .job이어도 XML로 파싱한다.
    #[test]
    fn xml_named_job_is_parsed_as_xml() {
        let dir = temp_dir("xmljob");
        let path = dir.join("Masquerade.job");
        std::fs::write(&path, super::xml_tests::TWO_EXEC_TWO_TRIGGERS).unwrap();
        let sources = task_sources(&dir).paths;
        assert_eq!(sources.len(), 1);
        let row = parse_file(&path);
        assert_eq!(row.get("source_format").map(String::as_str), Some("xml"));
        assert_eq!(row.get("_status").map(String::as_str), Some(STATUS_PARSED));
        assert_eq!(
            row.get("uri").map(String::as_str),
            Some("\\Microsoft\\Windows\\Evil\\Pwn")
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod xml_tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wina-taskxml-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_task(dir: &Path, name: &str, xml: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, xml).unwrap();
        p
    }

    fn parse_file(path: &Path) -> Row {
        parse_tasks_from(&[path.to_path_buf()]).remove(0)
    }

    pub(super) const TWO_EXEC_TWO_TRIGGERS: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-02T03:04:05</Date>
    <Author>attacker</Author>
    <URI>\Microsoft\Windows\Evil\Pwn</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2024-03-01T09:00:00</StartBoundary>
      <EndBoundary>2024-03-02T10:00:00</EndBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <LogonTrigger>
      <StartBoundary>2024-04-05T06:07:08</StartBoundary>
      <Enabled>false</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c whoami</Arguments>
      <WorkingDirectory>C:\Temp</WorkingDirectory>
    </Exec>
    <Exec>
      <Command>powershell.exe</Command>
    </Exec>
  </Actions>
</Task>
"#;

    #[test]
    fn xml_actions_and_triggers_json() {
        let dir = temp_dir("pair");
        let path = write_task(&dir, "Pwn", TWO_EXEC_TWO_TRIGGERS);
        let row = parse_file(&path);

        // 기존 표시 컬럼은 값이 변하지 않아야 한다.
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("C:\\Windows\\System32\\cmd.exe /c whoami | powershell.exe")
        );
        assert_eq!(
            row.get("trigger_types").map(String::as_str),
            Some("TimeTrigger, LogonTrigger")
        );
        assert_eq!(
            row.get("trigger_start").map(String::as_str),
            Some("2024-03-01 09:00:00.000")
        );
        // R04: XML 대표 시각은 등록 날짜다.
        assert_eq!(
            row.get("timestamp_meaning").map(String::as_str),
            Some("registration_date")
        );
        assert_eq!(
            row.get("registration_date_raw").map(String::as_str),
            Some("2024-01-02T03:04:05")
        );
        assert_eq!(row.get("task_version").map(String::as_str), Some("1.4"));
        assert_eq!(row.get("actions_context").map(String::as_str), Some("Author"));
        assert_eq!(
            row.get("root_children").map(String::as_str),
            Some("RegistrationInfo, Triggers, Actions")
        );

        let acts: Value = serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts.as_array().unwrap().len(), 2);
        assert_eq!(acts[0]["action_type"], "Exec");
        assert_eq!(acts[0]["command"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(acts[0]["arguments"], "/c whoami");
        assert_eq!(acts[0]["working_directory"], "C:\\Temp");
        assert!(acts[0]["raw"].as_str().unwrap().starts_with("<Exec>"));
        assert!(acts[0]["raw"].as_str().unwrap().ends_with("</Exec>"));
        assert_eq!(acts[1]["command"], "powershell.exe");
        // 증거에 없는 값은 "" 가 아니라 null.
        assert!(acts[1]["arguments"].is_null());
        assert!(acts[1]["working_directory"].is_null());

        let trigs: Value = serde_json::from_str(row.get("triggers_json").unwrap()).unwrap();
        assert_eq!(trigs.as_array().unwrap().len(), 2);
        assert_eq!(trigs[0]["trigger_type"], "TimeTrigger");
        assert_eq!(trigs[0]["start_time"], "2024-03-01 09:00:00.000");
        assert_eq!(trigs[0]["start_time_raw"], "2024-03-01T09:00:00");
        assert_eq!(trigs[0]["end_time"], "2024-03-02 10:00:00.000");
        assert_eq!(trigs[0]["enabled"], true);
        assert!(trigs[0]["raw"].as_str().unwrap().starts_with("<TimeTrigger>"));
        // 두 번째 트리거의 고유한 StartBoundary가 보존된다(표시 컬럼은 첫 번째만 보관).
        assert_eq!(trigs[1]["trigger_type"], "LogonTrigger");
        assert_eq!(trigs[1]["start_time"], "2024-04-05 06:07:08.000");
        assert!(trigs[1]["end_time"].is_null());
        assert_eq!(trigs[1]["enabled"], false);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn com_handler_action_and_empty_vs_missing_arrays() {
        let dir = temp_dir("empty");
        // Actions는 있으나 자식이 없고, Triggers 요소 자체가 없는 태스크.
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\NoKids</URI></RegistrationInfo>
  <Actions Context="Author"></Actions>
</Task>"#;
        let row = parse_file(&write_task(&dir, "NoKids", xml));
        assert_eq!(row.get("actions_json").map(String::as_str), Some("[]"));
        assert_eq!(row.get("triggers_json").map(String::as_str), Some(""));
        assert_eq!(row.get("actions").map(String::as_str), Some(""));

        let com = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Com</URI></RegistrationInfo>
  <Triggers></Triggers>
  <Actions Context="Author">
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
      <Data><![CDATA[payload]]></Data>
    </ComHandler>
  </Actions>
</Task>"#;
        let row = parse_file(&write_task(&dir, "Com", com));
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("COM:{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(row.get("triggers_json").map(String::as_str), Some("[]"));
        let acts: Value = serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts[0]["action_type"], "ComHandler");
        // A03: ClassId와 Data는 별도 필드로 남고 command로 둔갑하지 않는다.
        assert_eq!(acts[0]["class_id"], "{11111111-2222-3333-4444-555555555555}");
        assert!(acts[0]["com_data"].as_str().unwrap().contains("payload"));
        assert!(acts[0].get("command").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R05: Data 안의 중첩 XML을 정의로 오추출하지 않는다.
    #[test]
    fn nested_data_xml_never_overrides_definition() {
        let dir = temp_dir("nested");
        let xml = r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Outer</URI><Author>outer-author</Author></RegistrationInfo>
  <Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Triggers><BootTrigger><Delay>PT30S</Delay></BootTrigger></Triggers>
  <Actions Context="Author"><Exec><Command>outer.exe</Command></Exec></Actions>
  <Data>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo><URI>\Inner</URI><Author>inner-author</Author></RegistrationInfo>
      <Settings><Enabled>false</Enabled><Hidden>true</Hidden></Settings>
      <Actions><Exec><Command>inner.exe</Command></Exec></Actions>
    </Task>
  </Data>
</Task>"#;
        let row = parse_file(&write_task(&dir, "Nested", xml));
        assert_eq!(row.get("uri").map(String::as_str), Some("\\Outer"));
        assert_eq!(row.get("author").map(String::as_str), Some("outer-author"));
        assert_eq!(row.get("enabled").map(String::as_str), Some("true"));
        assert_eq!(row.get("hidden").map(String::as_str), Some("false"));
        assert_eq!(row.get("actions").map(String::as_str), Some("outer.exe"));
        assert_eq!(row.get("run_as").map(String::as_str), Some("S-1-5-18"));
        assert_eq!(row.get("run_as_element").map(String::as_str), Some("UserId"));
        // 중첩 XML은 Data 원문으로만 남는다.
        assert!(row.get("data_raw").unwrap().contains("inner.exe"));
        let acts: Value = serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts.as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R05: 루트가 Task가 아니거나 네임스페이스가 다르면 정의가 아니다.
    #[test]
    fn wrong_root_or_namespace_is_invalid_format() {
        let dir = temp_dir("root");
        let wrapped = r#"<Wrapper xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Task><RegistrationInfo><URI>\Fake</URI></RegistrationInfo></Task>
</Wrapper>"#;
        let row = parse_file(&write_task(&dir, "Wrapped", wrapped));
        assert_eq!(
            row.get("_status").map(String::as_str),
            Some(STATUS_INVALID_FORMAT)
        );
        assert!(row.get("_error").unwrap().contains("Wrapper"));
        assert_eq!(row.get("uri").map(String::as_str), None);
        // 원본은 그대로 보존한다.
        assert!(row.get("raw_sha256").is_some_and(|hash| hash.len() == 64));
        assert_eq!(row.get("raw_text").map(String::as_str), Some(wrapped));
        assert_eq!(row.get("encoding").map(String::as_str), Some("utf-8"));
        assert_eq!(row.get("decode_status").map(String::as_str), Some("decoded"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R05: 구형 XSD에 없는 확장 트리거·설정도 거부하지 않고 보존한다.
    #[test]
    fn extension_triggers_and_settings_are_preserved() {
        let dir = temp_dir("ext");
        let xml = r#"<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Ext</URI></RegistrationInfo>
  <Triggers>
    <WnfStateChangeTrigger><StateName>418e1c3a3b831d41</StateName><Data>0100</Data></WnfStateChangeTrigger>
    <EventTrigger><Subscription>&lt;QueryList&gt;&lt;Query Id="0"/&gt;&lt;/QueryList&gt;</Subscription><Delay>PT1M</Delay></EventTrigger>
    <TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Repetition><Interval>PT1H</Interval><Duration>P1D</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition></TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <MaintenanceSettings><Period>P7D</Period><Deadline>P14D</Deadline></MaintenanceSettings>
    <RestartOnFailure><Interval>PT10M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions><Exec><Command>x.exe</Command></Exec></Actions>
</Task>"#;
        let row = parse_file(&write_task(&dir, "Ext", xml));
        assert_eq!(row.get("_status").map(String::as_str), Some(STATUS_PARSED));
        let trigs: Value = serde_json::from_str(row.get("triggers_json").unwrap()).unwrap();
        assert_eq!(trigs[0]["trigger_type"], "WnfStateChangeTrigger");
        assert_eq!(trigs[0]["state_name"], "418e1c3a3b831d41");
        assert!(trigs[1]["subscription"]
            .as_str()
            .unwrap()
            .contains("QueryList"));
        assert_eq!(trigs[1]["delay"], "PT1M");
        assert_eq!(trigs[2]["repetition"]["interval"], "PT1H");
        assert_eq!(trigs[2]["repetition"]["stop_at_duration_end"], true);
        let settings: Value = serde_json::from_str(row.get("settings_json").unwrap()).unwrap();
        assert_eq!(settings["MultipleInstancesPolicy"], "IgnoreNew");
        assert_eq!(settings["MaintenanceSettings"]["Period"], "P7D");
        assert_eq!(settings["RestartOnFailure"]["Count"], "3");
        assert!(row.get("settings_raw").unwrap().contains("MaintenanceSettings"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R08: UTF-16LE 원본의 전체 원문·인코딩·해시를 보존한다.
    #[test]
    fn utf16_source_keeps_text_bytes_and_hash() {
        let dir = temp_dir("utf16");
        let mut raw: Vec<u8> = vec![0xFF, 0xFE];
        raw.extend(
            TWO_EXEC_TWO_TRIGGERS
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes()),
        );
        let path = dir.join("Utf16Task");
        std::fs::write(&path, &raw).unwrap();
        let row = parse_file(&path);
        assert_eq!(row.get("encoding").map(String::as_str), Some("utf-16le-bom"));
        assert_eq!(row.get("decode_status").map(String::as_str), Some("decoded"));
        assert_eq!(row.get("decode_replacements").map(String::as_str), Some("0"));
        assert!(row.get("raw_text").unwrap().contains("<Command>"));
        assert_eq!(
            row.get("raw_bytes_hex").map(String::as_str),
            Some(crate::hex::hex_lower(&raw).as_str())
        );
        // Fixed digests computed independently (python hashlib) over the file
        // bytes and over the decoded text: the stored hash is the *original
        // bytes*, never the decoded UTF-8 string.
        assert_eq!(
            row.get("raw_sha256").map(String::as_str),
            Some("5b92fc86882d29ede5966059fb1a6e6bc5f2349d15381402e606187b7ef4e125")
        );
        assert_ne!(
            row.get("raw_sha256").map(String::as_str),
            Some("eb56a5cf8ec6e2f09a7f76e773c6a07b58806c3a1c8237c78ff563cfea45b798")
        );
        assert_eq!(raw.len(), 1774);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R14: GroupId 주체를 개별 사용자 계정으로 만들지 않는다.
    #[test]
    fn group_principal_keeps_its_element() {
        let dir = temp_dir("group");
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Group</URI></RegistrationInfo>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Actions><Exec><Command>g.exe</Command></Exec></Actions>
</Task>"#;
        let row = parse_file(&write_task(&dir, "Group", xml));
        assert_eq!(row.get("run_as").map(String::as_str), Some("S-1-5-32-545"));
        assert_eq!(row.get("run_as_element").map(String::as_str), Some("GroupId"));
        let principals: Value = serde_json::from_str(row.get("principals_json").unwrap()).unwrap();
        assert_eq!(principals[0]["group_id"], "S-1-5-32-545");
        assert!(principals[0]["user_id"].is_null());
        let _ = std::fs::remove_dir_all(dir);
    }
}
