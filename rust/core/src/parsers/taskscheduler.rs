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

    let mut action_parts: Vec<String> = Vec::new();
    if let Some(ae) = actions_el {
        for act in ae.children().filter(|c| c.is_element()) {
            match act.tag_name().name() {
                "Exec" => {
                    let cmd = text(act, "Command");
                    let args = text(act, "Arguments");
                    action_parts.push(format!("{} {}", cmd, args).trim().to_string());
                }
                "ComHandler" => action_parts.push(format!("COM:{}", text(act, "ClassId"))),
                other if !other.is_empty() => action_parts.push(other.to_string()),
                _ => {}
            }
        }
    }

    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    if let Some(te) = triggers_el {
        for trig in te.children().filter(|c| c.is_element()) {
            trigger_types.push(trig.tag_name().name().to_string());
            if trigger_start.is_empty() {
                let sb = text(trig, "StartBoundary");
                if !sb.is_empty() {
                    trigger_start = sb;
                }
            }
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
    let (_working_dir, next) = job_lpstring(&b, next);
    let (author, next) = job_lpstring(&b, next);
    let (comment, _) = job_lpstring(&b, next);

    // 트리거 배열: 헤더의 Trigger Offset이 count u16을 가리킨다.
    let trig_off = job_u16(&b, 0x16) as usize;
    let trig_count = job_u16(&b, trig_off) as usize;
    let mut trigger_types: Vec<String> = Vec::new();
    let mut trigger_start = String::new();
    for i in 0..trig_count.min(64) {
        let o = trig_off + 2 + i * JOB_TRIGGER_LEN;
        if o + JOB_TRIGGER_LEN > b.len() {
            break;
        }
        trigger_types.push(job_trigger_name(job_u32(&b, o + 0x20)));
        if trigger_start.is_empty() {
            let (by, bm, bd) = (job_u16(&b, o + 4), job_u16(&b, o + 6), job_u16(&b, o + 8));
            let (sh, sm) = (job_u16(&b, o + 0x10), job_u16(&b, o + 0x12));
            if by != 0 {
                trigger_start = format!("{by:04}-{bm:02}-{bd:02} {sh:02}:{sm:02}:00.000");
            }
        }
    }

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
    row.insert(
        "actions".into(),
        format!("{} {}", application, parameters).trim().to_string(),
    );
    row.insert("trigger_types".into(), trigger_types.join(", "));
    row.insert("trigger_start".into(), trigger_start);
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
