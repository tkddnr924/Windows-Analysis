//! Task Scheduler per-task XML parser. Files have no extension and arbitrary
//! names; they're located by the task XML namespace in their content (like the
//! Python parser). One row per task, mirroring the Python field extraction.
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use rayon::prelude::*;

use crate::sqlite::Row;
use crate::time::kst_offset;

pub const TASK_TABLE: &str = "TaskScheduler_Tasks";
pub const TASK_NAMESPACE: &str = "schemas.microsoft.com/windows/2004/02/mit/task";
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
    "_source_file",
];

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

// First descendant (document order, self included) with this local tag name.
fn find<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<roxmltree::Node<'a, 'a>> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}
fn text(node: roxmltree::Node, name: &str) -> String {
    find(node, name)
        .and_then(|n| n.text())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// 증거에 값이 없으면 JSON null. 빈 문자열("")을 만들어 내지 않는다.
fn json_opt(s: &str) -> serde_json::Value {
    if s.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(s.to_string())
    }
}

/// xs:boolean 텍스트 → true/false. 값이 없거나 해석 불가면 null.
fn json_bool(s: &str) -> serde_json::Value {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => serde_json::Value::Bool(true),
        "false" | "0" => serde_json::Value::Bool(false),
        _ => serde_json::Value::Null,
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
fn json_array(parent_present: bool, items: &[serde_json::Value]) -> String {
    if !parent_present {
        return String::new();
    }
    serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string())
}

/// Decode a task file to a UTF-8 string (task XML is usually UTF-16LE w/ BOM).
fn read_text(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let u: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let u: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        let s = String::from_utf8_lossy(raw);
        s.strip_prefix('\u{feff}')
            .map(|x| x.to_string())
            .unwrap_or_else(|| s.into_owned())
    }
}

fn parse_task(path: &Path) -> Result<Row> {
    let raw = std::fs::read(path)?;
    let mut content = read_text(&raw);
    // roxmltree takes UTF-8; drop an `encoding="UTF-16"` XML declaration so it
    // doesn't reject the (now UTF-8) string.
    if content.starts_with("<?xml") {
        if let Some(end) = content.find("?>") {
            content.replace_range(..end + 2, "");
        }
    }
    let content = content.trim_start();
    let doc = roxmltree::Document::parse(content)?;
    let root = doc.root_element();

    let reg = find(root, "RegistrationInfo");
    let settings = find(root, "Settings");
    let principals = find(root, "Principals");
    let actions_el = find(root, "Actions");
    let triggers_el = find(root, "Triggers");

    let uri = reg.map(|r| text(r, "URI")).unwrap_or_default();
    let date = reg.map(|r| text(r, "Date")).unwrap_or_default();
    let author = reg.map(|r| text(r, "Author")).unwrap_or_default();
    let description = reg.map(|r| text(r, "Description")).unwrap_or_default();
    let enabled = settings.map(|s| text(s, "Enabled")).unwrap_or_default();
    let hidden = settings.map(|s| text(s, "Hidden")).unwrap_or_default();

    let (mut run_as, mut run_level, mut logon_type) = (String::new(), String::new(), String::new());
    if let Some(pr) = principals.and_then(|p| find(p, "Principal")) {
        run_as = {
            let u = text(pr, "UserId");
            if u.is_empty() {
                text(pr, "GroupId")
            } else {
                u
            }
        };
        run_level = text(pr, "RunLevel");
        logon_type = text(pr, "LogonType");
    }

    // 표시용 조각(actions 컬럼)과 구조화 증거(actions_json)를 함께 만든다.
    let mut action_parts: Vec<String> = Vec::new();
    let mut action_objs: Vec<serde_json::Value> = Vec::new();
    if let Some(ae) = actions_el {
        for act in ae.children().filter(|c| c.is_element()) {
            let name = act.tag_name().name().to_string();
            if name.is_empty() {
                continue;
            }
            // frag = 기존 표시 문자열 조각(= raw 대체값), 나머지는 구조화 필드.
            let (frag, command, arguments, workdir) = match name.as_str() {
                "Exec" => {
                    let cmd = text(act, "Command");
                    let args = text(act, "Arguments");
                    let wd = text(act, "WorkingDirectory");
                    (format!("{} {}", cmd, args).trim().to_string(), cmd, args, wd)
                }
                "ComHandler" => {
                    let class_id = text(act, "ClassId");
                    (
                        format!("COM:{class_id}"),
                        class_id,
                        String::new(),
                        String::new(),
                    )
                }
                // Exec/ComHandler 외(SendEmail, ShowMessage…)는 요소 이름만 남는다.
                _ => (name.clone(), String::new(), String::new(), String::new()),
            };
            action_parts.push(frag.clone());
            action_objs.push(serde_json::json!({
                "action_type": name,
                "command": json_opt(&command),
                "arguments": json_opt(&arguments),
                "working_directory": json_opt(&workdir),
                "raw": node_raw(content, act, &frag),
            }));
        }
    }

    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    let mut trigger_objs: Vec<serde_json::Value> = Vec::new();
    if let Some(te) = triggers_el {
        for trig in te.children().filter(|c| c.is_element()) {
            let name = trig.tag_name().name().to_string();
            trigger_types.push(name.clone());
            // trigger_start는 기존대로 "첫 StartBoundary"만 유지하고,
            // 트리거별 경계/활성 여부는 triggers_json에 그대로 보존한다.
            let sb = text(trig, "StartBoundary");
            if trigger_start.is_empty() && !sb.is_empty() {
                trigger_start = sb.clone();
            }
            let eb = text(trig, "EndBoundary");
            let en = text(trig, "Enabled");
            let raw = node_raw(content, trig, &name);
            trigger_objs.push(serde_json::json!({
                "trigger_type": name,
                "start_time": json_opt(&fmt_task_time(&sb)),
                "end_time": json_opt(&fmt_task_time(&eb)),
                "enabled": json_bool(&en),
                "raw": raw,
            }));
        }
    }

    let task_name = {
        let l = leaf(&uri);
        if l.is_empty() {
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            l
        }
    };

    let mut row = Row::new();
    row.insert("timestamp".into(), fmt_task_time(&date));
    row.insert("task_name".into(), task_name);
    row.insert("enabled".into(), enabled);
    row.insert("hidden".into(), hidden);
    row.insert("run_as".into(), run_as);
    row.insert("run_level".into(), run_level);
    row.insert(
        "actions".into(),
        action_parts
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" | "),
    );
    row.insert("trigger_types".into(), trigger_types.join(", "));
    row.insert("trigger_start".into(), fmt_task_time(&trigger_start));
    row.insert(
        "actions_json".into(),
        json_array(actions_el.is_some(), &action_objs),
    );
    row.insert(
        "triggers_json".into(),
        json_array(triggers_el.is_some(), &trigger_objs),
    );
    row.insert("author".into(), author);
    row.insert("description".into(), description);
    row.insert("logon_type".into(), logon_type);
    row.insert("uri".into(), uri);
    row.insert("_source_file".into(), path.to_string_lossy().to_string());
    Ok(row)
}

// ---------------------------------------------------------------------------
// XP/2003 .job (MS-TSCH 바이너리 태스크) — T4. 고정부(FIXDLEN_DATA 0x44바이트)
// + 길이 접두 UTF-16LE 문자열(AppName/Parameters/WorkingDir/Author/Comment)
// + 48바이트 트리거 배열. 출력은 XML 태스크와 동일한 TASK_FIELD_ORDER 행.
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

/// 길이 접두 유니코드 문자열: u16 문자 수(종단 NUL 포함) + UTF-16LE.
/// 반환: (문자열, 다음 오프셋). 길이 0이면 길이 워드만 소비한다.
fn job_lpstring(b: &[u8], off: usize) -> (String, usize) {
    let chars = job_u16(b, off) as usize;
    let start = off + 2;
    let end = start + chars * 2;
    if chars == 0 || end > b.len() {
        return (String::new(), if chars == 0 { start } else { b.len() });
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
/// 파일명 확장자와 함께 쓴다(내용 오탐 방지).
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
fn parse_job(path: &Path) -> Result<Row> {
    let b = std::fs::read(path)?;
    if !is_job_header(&b) {
        anyhow::bail!("not a .job task (file version != 1)");
    }

    let flags = job_u32(&b, 0x30);
    // Last Run Time: SYSTEMTIME(로컬 시간) — year 0이면 실행 이력 없음.
    let (yr, mo, dy) = (job_u16(&b, 0x34), job_u16(&b, 0x36), job_u16(&b, 0x3A));
    let (hh, mi, ss, ms) = (
        job_u16(&b, 0x3C),
        job_u16(&b, 0x3E),
        job_u16(&b, 0x40),
        job_u16(&b, 0x42),
    );
    let last_run = if yr == 0 {
        String::new()
    } else {
        format!("{yr:04}-{mo:02}-{dy:02} {hh:02}:{mi:02}:{ss:02}.{ms:03}")
    };

    // 가변부: 헤더가 가리키는 AppName 길이 워드 오프셋부터 문자열 5개 연속.
    let app_off = job_u16(&b, 0x14) as usize;
    let (application, next) = job_lpstring(&b, app_off);
    let (parameters, next) = job_lpstring(&b, next);
    let (working_dir, next) = job_lpstring(&b, next);
    let (author, next) = job_lpstring(&b, next);
    let (comment, _) = job_lpstring(&b, next);

    // 트리거 배열: 헤더의 Trigger Offset이 count u16을 가리킨다.
    let trig_off = job_u16(&b, 0x16) as usize;
    let trig_count = job_u16(&b, trig_off) as usize;
    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    let mut trigger_objs: Vec<serde_json::Value> = Vec::new();
    for i in 0..trig_count.min(64) {
        let o = trig_off + 2 + i * JOB_TRIGGER_LEN;
        if o + JOB_TRIGGER_LEN > b.len() {
            break;
        }
        let name = job_trigger_name(job_u32(&b, o + 0x20));
        trigger_types.push(name.clone());
        let (by, bm, bd) = (job_u16(&b, o + 4), job_u16(&b, o + 6), job_u16(&b, o + 8));
        let (sh, sm) = (job_u16(&b, o + 0x10), job_u16(&b, o + 0x12));
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
        let rg_flags = job_u32(&b, o + 0x1C);
        let (ey, em, ed) = (
            job_u16(&b, o + 0x0A),
            job_u16(&b, o + 0x0C),
            job_u16(&b, o + 0x0E),
        );
        let end = if rg_flags & JOB_TRIGGER_FLAG_HAS_END_DATE != 0 && ey != 0 {
            format!("{ey:04}-{em:02}-{ed:02}")
        } else {
            String::new()
        };
        // raw: 48바이트 TASK_TRIGGER 레코드 원문(헥스). XML 경로의 원본 XML 조각에 대응.
        let raw: String = b[o..o + JOB_TRIGGER_LEN]
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect();
        trigger_objs.push(serde_json::json!({
            "trigger_type": name,
            "start_time": json_opt(&start),
            "end_time": json_opt(&end),
            "enabled": serde_json::Value::Bool(rg_flags & JOB_TRIGGER_FLAG_DISABLED == 0),
            "raw": raw,
        }));
    }

    // .job은 액션이 항상 정확히 하나(AppName/Parameters/WorkingDirectory).
    let action_display = format!("{} {}", application, parameters).trim().to_string();
    let action_objs = vec![serde_json::json!({
        "action_type": "Exec",
        "command": json_opt(&application),
        "arguments": json_opt(&parameters),
        "working_directory": json_opt(&working_dir),
        "raw": action_display.clone(),
    })];

    let mut row = Row::new();
    row.insert("timestamp".into(), last_run);
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
    row.insert("_source_file".into(), path.to_string_lossy().to_string());
    Ok(row)
}

/// Walk `root` and retain every file whose header identifies it as a task XML
/// source. The source list is distinct from parsed rows because a valid task
/// file can still produce zero usable fields.
pub fn task_sources(root: &Path) -> crate::finder::Found {
    let (paths, walk_errors) = crate::finder::walk_files(root);
    let utf8 = TASK_NAMESPACE.as_bytes().to_vec();
    let utf16: Vec<u8> = TASK_NAMESPACE.bytes().flat_map(|b| [b, 0]).collect();
    // 판별용 헤더를 읽지 못한 파일은 "비대상"이 아니라 판정 불가 — 실패로
    // 모아 반환한다 (탐색 계약).
    let checked: Vec<(Option<std::path::PathBuf>, Option<String>)> = paths
        .par_iter()
        .map(|path| {
            // Read only the first 4 KB to test for the task namespace — never the
            // whole file. A target can hold huge unrelated files (images, dumps);
            // slurping each one just to check its header made discovery crawl.
            let mut head = Vec::new();
            match std::fs::File::open(path) {
                Ok(f) => {
                    use std::io::Read;
                    if Read::take(f, 4096).read_to_end(&mut head).is_err() {
                        return (
                            None,
                            Some(format!("{}: 내용 판별용 앞부분 읽기 실패", path.display())),
                        );
                    }
                }
                Err(error) => return (None, Some(format!("{}: {error}", path.display()))),
            }
            let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
            let is_xml_task = has(&utf8) || has(&utf16);
            // XP/2003 .job은 XML 네임스페이스가 없다 — 확장자 + 헤더로 판별.
            let is_job = has_job_extension(path) && is_job_header(&head);
            ((is_xml_task || is_job).then(|| path.clone()), None)
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

/// Parse already-discovered task XML files (one row per file; unreadable files
/// keep an error row so every evidence input stays represented).
pub fn parse_tasks_from(paths: &[std::path::PathBuf]) -> Vec<Row> {
    paths
        .par_iter()
        .map(|path| {
            let parsed = if has_job_extension(path) {
                parse_job(path)
            } else {
                parse_task(path)
            };
            match parsed {
                Ok(r) => r,
                Err(e) => {
                    let mut row = Row::new();
                    row.insert("timestamp".into(), String::new());
                    row.insert(
                        "task_name".into(),
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                    );
                    row.insert("_source_file".into(), path.to_string_lossy().to_string());
                    row.insert("_status".into(), "unreadable_file".into());
                    row.insert("_error".into(), e.to_string());
                    row
                }
            }
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

    #[test]
    fn parses_job_fields_and_trigger() {
        let dir = temp_dir("basic");
        let path = dir.join("At1.job");
        std::fs::write(&path, synthetic_job(0, 2004)).unwrap();
        let row = parse_job(&path).unwrap();
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
        assert_eq!(row.get("enabled").map(String::as_str), Some("true"));
        assert_eq!(row.get("hidden").map(String::as_str), Some("false"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn job_emits_structured_action_and_trigger_json() {
        let dir = temp_dir("json");
        let path = dir.join("At3.job");
        std::fs::write(&path, synthetic_job(0, 2004)).unwrap();
        let row = parse_job(&path).unwrap();

        let acts: serde_json::Value =
            serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts.as_array().unwrap().len(), 1);
        assert_eq!(acts[0]["action_type"], "Exec");
        assert_eq!(acts[0]["command"], "C:\\WINDOWS\\system32\\evil.exe");
        assert_eq!(acts[0]["arguments"], "-run");
        assert_eq!(acts[0]["working_directory"], "C:\\WINDOWS");
        assert_eq!(acts[0]["raw"], "C:\\WINDOWS\\system32\\evil.exe -run");

        let trigs: serde_json::Value =
            serde_json::from_str(row.get("triggers_json").unwrap()).unwrap();
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
        std::fs::write(
            &path,
            synthetic_job(JOB_FLAG_DISABLED | JOB_FLAG_HIDDEN, 0),
        )
        .unwrap();
        let row = parse_job(&path).unwrap();
        assert_eq!(row.get("enabled").map(String::as_str), Some("false"));
        assert_eq!(row.get("hidden").map(String::as_str), Some("true"));
        assert_eq!(row.get("timestamp").map(String::as_str), Some(""));
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

    const TWO_EXEC_TWO_TRIGGERS: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
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
        let row = parse_task(&path).unwrap();

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

        let acts: serde_json::Value =
            serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
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

        let trigs: serde_json::Value =
            serde_json::from_str(row.get("triggers_json").unwrap()).unwrap();
        assert_eq!(trigs.as_array().unwrap().len(), 2);
        assert_eq!(trigs[0]["trigger_type"], "TimeTrigger");
        assert_eq!(trigs[0]["start_time"], "2024-03-01 09:00:00.000");
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
        let row = parse_task(&write_task(&dir, "NoKids", xml)).unwrap();
        assert_eq!(row.get("actions_json").map(String::as_str), Some("[]"));
        assert_eq!(row.get("triggers_json").map(String::as_str), Some(""));
        assert_eq!(row.get("actions").map(String::as_str), Some(""));

        let com = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Com</URI></RegistrationInfo>
  <Triggers></Triggers>
  <Actions Context="Author">
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
    </ComHandler>
  </Actions>
</Task>"#;
        let row = parse_task(&write_task(&dir, "Com", com)).unwrap();
        assert_eq!(
            row.get("actions").map(String::as_str),
            Some("COM:{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(row.get("triggers_json").map(String::as_str), Some("[]"));
        let acts: serde_json::Value =
            serde_json::from_str(row.get("actions_json").unwrap()).unwrap();
        assert_eq!(acts[0]["action_type"], "ComHandler");
        assert_eq!(acts[0]["command"], "{11111111-2222-3333-4444-555555555555}");
        assert!(acts[0]["arguments"].is_null());
        assert!(acts[0]["working_directory"].is_null());
        let _ = std::fs::remove_dir_all(dir);
    }
}
