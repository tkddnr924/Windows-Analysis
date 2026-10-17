//! Scheduled task storage — viewer11 R01~R16 / A01~A08.
//!
//! One typed record per evidence item: a collected task definition, a
//! TaskScheduler operational/service event, or a Security task-audit event.
//! Side tables hold TaskCache registry entries, the collector's live snapshot,
//! collected file evidence and per-log collection observations.
//!
//! Boundaries kept here:
//!
//! * Definitions and events are separate records. A shared name or a close
//!   timestamp never merges them, and a definition never inherits run counts.
//! * `account` is the record's representative identity with `account_role`
//!   saying what that identity is (task principal, event actor, run user).
//!   A group principal keeps `run_as_kind = 'group'` and is never turned into
//!   a user account.
//! * Declared values and Task Scheduler schema defaults live in separate
//!   `TaskSettings` rows (`value_source`), so an unwritten `Enabled` stays
//!   NULL on the record.
//! * Scheduler completion is not business success: 102/201 keep their own
//!   result label and the raw result code; non-zero codes are preserved, not
//!   collapsed into one meaning.
//! * TaskCache, the collector snapshot and collected executables are compared
//!   with an explicit basis and status; a name match is never an identity.
//!
//! Published references for the semantics encoded below:
//!
//! * Task monitoring events (100/102/111/129/200~203/323~331) —
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd315533(v=ws.10)>
//! * Registration events (106/113/115/116/140/141/406) —
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd315590(v=ws.10)>
//! * Launch/condition events (101/103/104/107~130/142/145/204/205/305/322~332) —
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd363625(v=ws.10)>
//! * Event trigger subscription failure (150) —
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd315709(v=ws.10)>
//! * Security 4698 fields (subject vs task content) —
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698>
//! * Settings schema defaults —
//!   <https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-settingstype-complextype>

mod observations;
mod registry;
mod supplemental;

use std::collections::HashMap;

use anyhow::Result;
use serde_json::Value;

use super::schema::{ChildSpec, DbSpec};
use super::{Cell, Ctx, DerivedDb, Record, SourceRef};
use crate::overview::{self, EventLogOverviewCache};
use crate::sqlite::Row;

pub(crate) use supplemental::prepare_inputs;

const DEFINITION_FACTS: &str = "TASKSCHEDULER/TaskScheduler_Tasks.sqlite";
const DEFINITION_TABLE: &str = "TaskScheduler_Tasks";
const TASK_PROVIDER: &str = "Microsoft-Windows-TaskScheduler";
const SECURITY_PROVIDER: &str = "Microsoft-Windows-Security-Auditing";

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn value(raw: &str) -> Cell {
    if raw.trim().is_empty() {
        Cell::Null
    } else {
        Cell::Text(raw.to_string())
    }
}

/// Keep evidence whitespace; only a truly empty value becomes NULL.
fn raw_value(raw: &str) -> Cell {
    if raw.is_empty() {
        Cell::Null
    } else {
        Cell::Text(raw.to_string())
    }
}

fn int_value(raw: &str) -> Cell {
    match raw.trim().parse::<i64>() {
        Ok(value) => Cell::Int(value),
        Err(_) => Cell::Null,
    }
}

/// `\Microsoft\Windows\Foo`, `Microsoft\Windows\Foo` and a trailing separator
/// are the same logical task path (R03). The original stays in `uri`.
fn normalize_task_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('\\');
    format!("\\{}", trimmed.trim_start_matches('\\')).to_lowercase()
}

fn leaf_name(path: &str) -> String {
    path.trim_end_matches('\\')
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

fn json_array(raw: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) => items,
        _ => Vec::new(),
    }
}

fn json_object(raw: &str) -> serde_json::Map<String, Value> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

fn bool_cell(value: &Value, key: &str) -> Cell {
    match value.get(key).and_then(Value::as_bool) {
        Some(flag) => Cell::Int(i64::from(flag)),
        None => Cell::Null,
    }
}

/// Prefer nested EventXML fields, then top-level EventData.
fn ed(map: &serde_json::Map<String, Value>, name: &str) -> String {
    if let Some(Value::Object(inner)) = map.get("EventXML") {
        let value = overview::jget(inner, name);
        if !value.is_empty() {
            return value;
        }
    }
    overview::jget(map, name)
}

/// Same lookup, then a nested search. Maintenance records wrap their fields in
/// a named `EventData` group, so the value can sit one level down; the
/// returned value is still the recorded one, never rewritten.
fn ed_any(map: &serde_json::Map<String, Value>, name: &str) -> String {
    let direct = ed(map, name);
    if !direct.is_empty() {
        return direct;
    }
    fn walk(map: &serde_json::Map<String, Value>, name: &str) -> String {
        for (key, item) in map {
            if key == "#attributes" {
                continue;
            }
            if let Value::Object(inner) = item {
                if let Some(Value::String(text)) = inner.get(name) {
                    return text.clone();
                }
                let found = walk(inner, name);
                if !found.is_empty() {
                    return found;
                }
            }
        }
        String::new()
    }
    walk(map, name)
}

// ---------------------------------------------------------------------------
// Review signals (R13) — one storage-side rule set so list badges, filters and
// counts cannot disagree, and a page never has to be visited to classify.
// ---------------------------------------------------------------------------

/// Script hosts and loaders that analysts review on a scheduled task. Being on
/// this list is a review signal, never a malicious determination.
const REVIEW_COMMANDS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
];

struct ReviewSignal {
    signal: &'static str,
    basis: String,
    evidence: String,
    action_ordinal: Option<i64>,
}

fn command_leaf(command: &str) -> String {
    command
        .trim()
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Task Scheduler event catalogue
// ---------------------------------------------------------------------------

struct EventMeaning {
    event_type: &'static str,
    category: &'static str,
    /// Documented reason the instance was launched, when the ID states one.
    launch_reason: &'static str,
    result: &'static str,
    result_basis: &'static str,
}

const fn meaning(
    event_type: &'static str,
    category: &'static str,
    launch_reason: &'static str,
    result: &'static str,
    result_basis: &'static str,
) -> EventMeaning {
    EventMeaning {
        event_type,
        category,
        launch_reason,
        result,
        result_basis,
    }
}

/// Documented operational meanings. Every entry comes from the Microsoft event
/// message cited in the module header; unlisted IDs stay generic.
fn operational_meaning(event_id: &str) -> Option<EventMeaning> {
    Some(match event_id {
        "100" => meaning("작업 시작", "run", "", "", ""),
        "101" => meaning(
            "작업 시작 실패",
            "failure",
            "",
            "시작 실패",
            "event_101_failed_to_start_task",
        ),
        "102" => meaning(
            "작업 완료",
            "completion",
            "",
            "스케줄러 완료",
            "event_102_scheduler_finished_instance",
        ),
        "103" => meaning(
            "작업 인스턴스 시작 실패",
            "failure",
            "",
            "시작 실패",
            "event_103_failed_to_start_instance",
        ),
        "104" => meaning(
            "작업 로그온 실패",
            "failure",
            "",
            "로그온 실패",
            "event_104_failed_to_log_on",
        ),
        "106" => meaning("작업 등록", "registration", "", "", ""),
        "107" => meaning("작업 실행 시작", "launch", "시간 트리거", "", ""),
        "108" => meaning("작업 실행 시작", "launch", "이벤트 트리거", "", ""),
        "109" => meaning("작업 실행 시작", "launch", "등록 트리거", "", ""),
        "110" => meaning("작업 실행 시작", "launch", "사용자 요청", "", ""),
        "111" => meaning(
            "작업 종료",
            "stop",
            "",
            "실행 시간 제한 초과 종료",
            "event_111_terminated_exceeding_time_allocated",
        ),
        "112" => meaning(
            "작업 미시작",
            "condition",
            "",
            "네트워크 없음으로 미시작",
            "event_112_network_unavailable",
        ),
        "113" => meaning(
            "작업 등록(일부 트리거 미작동)",
            "registration",
            "",
            "일부 트리거 미작동",
            "event_113_registered_with_invalid_triggers",
        ),
        "114" => meaning("작업 실행 시작", "launch", "예정 시각 경과 후 실행", "", ""),
        "115" => meaning(
            "작업 트랜잭션 롤백 실패",
            "registration",
            "",
            "롤백 실패",
            "event_115_rollback_failed",
        ),
        "116" => meaning(
            "작업 자격 증명 저장 실패",
            "registration",
            "",
            "자격 증명 저장 실패",
            "event_116_credentials_not_stored",
        ),
        "117" => meaning("작업 실행 시작", "launch", "유휴 조건", "", ""),
        "118" => meaning("작업 실행 시작", "launch", "시스템 시작", "", ""),
        "119" => meaning("작업 실행 시작", "launch", "사용자 로그온", "", ""),
        "120" => meaning("작업 실행 시작", "launch", "콘솔 연결", "", ""),
        "121" => meaning("작업 실행 시작", "launch", "콘솔 연결 해제", "", ""),
        "122" => meaning("작업 실행 시작", "launch", "원격 연결", "", ""),
        "123" => meaning("작업 실행 시작", "launch", "원격 연결 해제", "", ""),
        "124" => meaning("작업 실행 시작", "launch", "컴퓨터 잠금", "", ""),
        "125" => meaning("작업 실행 시작", "launch", "컴퓨터 잠금 해제", "", ""),
        "126" => meaning(
            "작업 실행 실패(재시작 시도)",
            "failure",
            "",
            "실행 실패",
            "event_126_failed_to_execute_retrying",
        ),
        "127" => meaning(
            "작업 실행 실패(종료 경합)",
            "failure",
            "",
            "실행 실패",
            "event_127_shutdown_race_condition",
        ),
        "128" => meaning(
            "작업 미시작",
            "condition",
            "",
            "종료 시각 초과로 미시작",
            "event_128_past_task_end_time",
        ),
        "129" => meaning("프로세스 생성", "run", "", "", ""),
        "130" => meaning(
            "작업 시작 실패",
            "failure",
            "",
            "서비스 사용 중으로 시작 실패",
            "event_130_service_busy",
        ),
        "140" => meaning("작업 등록 정보 변경", "registration", "", "", ""),
        "141" => meaning("작업 등록 삭제", "registration", "", "", ""),
        "142" => meaning("작업 사용 안 함", "registration", "", "", ""),
        "145" => meaning("작업 실행 위한 절전 해제", "run", "", "", ""),
        "150" => meaning(
            "이벤트 트리거 구독 실패",
            "registration",
            "",
            "구독 실패",
            "event_150_event_trigger_subscription_failed",
        ),
        "200" => meaning("동작 시작", "action", "", "", ""),
        "201" => meaning(
            "동작 완료",
            "action",
            "",
            "동작 완료",
            "event_201_action_completed",
        ),
        "202" => meaning(
            "작업 완료 실패",
            "action",
            "",
            "완료 실패",
            "event_202_failed_to_complete_with_action",
        ),
        "203" => meaning(
            "동작 시작 실패",
            "action",
            "",
            "동작 시작 실패",
            "event_203_failed_to_launch_action",
        ),
        "204" => meaning(
            "이벤트 트리거 값 조회 실패",
            "action",
            "",
            "트리거 값 조회 실패",
            "event_204_failed_to_retrieve_trigger_values",
        ),
        "205" => meaning(
            "이벤트 패턴 대조 실패",
            "action",
            "",
            "패턴 대조 실패",
            "event_205_failed_to_match_event_pattern",
        ),
        "305" => meaning(
            "작업 엔진 전달 실패",
            "failure",
            "",
            "엔진 전달 실패",
            "event_305_not_sent_to_task_engine",
        ),
        "322" => meaning(
            "작업 미시작",
            "condition",
            "",
            "동일 인스턴스 실행 중으로 미시작",
            "event_322_instance_already_running",
        ),
        "323" => meaning(
            "작업 중지",
            "stop",
            "",
            "새 인스턴스 시작 위해 중지",
            "event_323_stopped_to_launch_new_instance",
        ),
        "324" => meaning(
            "작업 대기열 등록",
            "condition",
            "",
            "실행 중 인스턴스 완료 대기",
            "event_324_queued_until_instance_completes",
        ),
        "325" => meaning(
            "작업 대기열 등록",
            "condition",
            "",
            "실행 요청 대기열 등록",
            "event_325_launch_request_queued",
        ),
        "326" => meaning(
            "작업 미시작",
            "condition",
            "",
            "배터리 전원으로 미시작",
            "event_326_running_on_batteries",
        ),
        "327" => meaning(
            "작업 중지",
            "stop",
            "",
            "배터리 전환으로 중지",
            "event_327_switching_to_battery_power",
        ),
        "328" => meaning(
            "작업 중지",
            "stop",
            "",
            "유휴 상태 종료로 중지",
            "event_328_no_longer_idle",
        ),
        "329" => meaning(
            "작업 중지",
            "stop",
            "",
            "시간 초과로 중지",
            "event_329_task_timed_out",
        ),
        "330" => meaning(
            "작업 중지",
            "stop",
            "",
            "사용자 요청으로 중지",
            "event_330_stopped_as_requested_by_user",
        ),
        "331" => meaning(
            "시간 제한 적용 실패",
            "stop",
            "",
            "시간 제한 장치 생성 실패",
            "event_331_timeout_mechanism_failure",
        ),
        "332" => meaning(
            "작업 미시작",
            "condition",
            "",
            "사용자 미로그온으로 미시작",
            "event_332_user_not_logged_on",
        ),
        "406" => meaning(
            "자격 증명 저장소 초기화 실패",
            "registration",
            "",
            "자격 증명 저장소 초기화 실패",
            "event_406_credentials_store_init_failed",
        ),
        _ => return None,
    })
}

/// Security task-audit events (4698~4702). The subject is the actor, never the
/// task's run-as principal.
fn audit_meaning(event_id: &str) -> Option<(&'static str, &'static str)> {
    Some(match event_id {
        "4698" => ("작업 생성 감사", "TaskContent"),
        "4699" => ("작업 삭제 감사", ""),
        "4700" => ("작업 사용 감사", ""),
        "4701" => ("작업 사용 중지 감사", ""),
        "4702" => ("작업 변경 감사", "TaskContentNew"),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

/// Task paths of the definitions written in this run, for explicit comparison
/// by the registry / snapshot / file evidence side tables.
#[derive(Default)]
pub(super) struct DefinitionIndex {
    by_path: HashMap<String, Vec<String>>,
    /// (record_id, ordinal, raw command, resolved command)
    commands: Vec<(String, i64, String, Option<String>)>,
    /// (record_id, ordinal, ComHandler ClassId as written) — A03 comparison.
    com_handlers: Vec<(String, i64, String)>,
}

impl DefinitionIndex {
    fn add(&mut self, path: &str, record_id: &str) {
        self.by_path
            .entry(normalize_task_path(path))
            .or_default()
            .push(record_id.to_string());
    }

    /// Unique match only; ambiguity is reported, never silently resolved.
    fn match_path(&self, path: &str) -> (Option<String>, &'static str) {
        match self.by_path.get(&normalize_task_path(path)) {
            Some(ids) if ids.len() == 1 => (Some(ids[0].clone()), "matched_definition"),
            Some(ids) if ids.len() > 1 => (None, "ambiguous_definition"),
            _ => (None, "definition_not_collected"),
        }
    }

    pub(super) fn commands(&self) -> &[(String, i64, String, Option<String>)] {
        &self.commands
    }

    pub(super) fn com_handlers(&self) -> &[(String, i64, String)] {
        &self.com_handlers
    }
}

fn source_for_definition(ctx: &Ctx, row: &Row) -> Result<Option<SourceRef>> {
    let rowid = g(row, "__source_rowid");
    if rowid.is_empty() {
        return Ok(None);
    }
    ctx.facts.source_from_record_key(
        &format!("{DEFINITION_TABLE}::{DEFINITION_TABLE}::{rowid}"),
        None,
        super::nz(g(row, "_source_file")),
        Some("작업 정의"),
    )
}

/// Settings elements with a documented schema default (settingsType).
const SETTING_DEFAULTS: &[(&str, &str)] = &[
    ("AllowStartOnDemand", "true"),
    ("MultipleInstancesPolicy", "IgnoreNew"),
    ("DisallowStartIfOnBatteries", "true"),
    ("StopIfGoingOnBatteries", "true"),
    ("AllowHardTerminate", "true"),
    ("StartWhenAvailable", "false"),
    ("RunOnlyIfNetworkAvailable", "false"),
    ("WakeToRun", "false"),
    ("Enabled", "true"),
    ("Hidden", "false"),
    ("DeleteExpiredTaskAfter", "PT0S"),
    ("ExecutionTimeLimit", "PT72H"),
    ("Priority", "7"),
    ("RunOnlyIfIdle", "false"),
    ("UseUnifiedSchedulingEngine", "false"),
    ("DisallowStartOnRemoteAppSession", "false"),
];

struct TaskXmlParts<'a> {
    actions_json: &'a str,
    triggers_json: &'a str,
    settings_json: &'a str,
    principals_json: &'a str,
}

/// Write the structured children of one task definition (file or event
/// payload) and return the review signals found in its commands.
fn write_task_children(
    rec: &mut Record,
    ctx: &Ctx,
    parts: TaskXmlParts<'_>,
    hidden_declared: Option<bool>,
    // UserId principal SID: its own environment resolves user variables.
    user_sid: Option<&str>,
    index: &mut DefinitionIndex,
) -> Vec<ReviewSignal> {
    let mut signals: Vec<ReviewSignal> = Vec::new();
    let record_id = rec.record_id.clone();

    for (ordinal, action) in json_array(parts.actions_json).into_iter().enumerate() {
        let command = field(&action, "command");
        let arguments = field(&action, "arguments");
        let resolved = ctx.meta.resolve_path(&command, user_sid);
        let resolved_text = match &resolved {
            Cell::Text(text) => Some(text.clone()),
            _ => None,
        };
        let detail = action.get("detail").cloned().unwrap_or(Value::Null);
        rec.child(
            "TaskActions",
            vec![
                value(&field(&action, "action_type")),
                value(&field(&action, "action_id")),
                value(&command),
                resolved,
                value(&arguments),
                value(&field(&action, "working_directory")),
                value(&field(&action, "class_id")),
                raw_value(&field(&action, "com_data")),
                if detail.is_null() {
                    Cell::Null
                } else {
                    Cell::Text(detail.to_string())
                },
                raw_value(&field(&action, "raw")),
            ],
        );
        let class_id = field(&action, "class_id");
        if !class_id.is_empty() {
            index
                .com_handlers
                .push((record_id.clone(), ordinal as i64, class_id));
        }
        if !command.is_empty() {
            index.commands.push((
                record_id.clone(),
                ordinal as i64,
                command.clone(),
                resolved_text.clone(),
            ));
            let leaf = command_leaf(resolved_text.as_deref().unwrap_or(&command));
            if REVIEW_COMMANDS.contains(&leaf.as_str()) {
                signals.push(ReviewSignal {
                    signal: "script_host_command",
                    basis: format!("action command file name is {leaf}"),
                    evidence: command.clone(),
                    action_ordinal: Some(ordinal as i64),
                });
            }
        }
        let lowered = arguments.to_ascii_lowercase();
        if lowered.contains("-enc") || lowered.contains("/enc") || lowered.contains("encodedcommand")
        {
            signals.push(ReviewSignal {
                signal: "encoded_command_argument",
                basis: "action arguments contain an encoded-command switch".into(),
                evidence: arguments.clone(),
                action_ordinal: Some(ordinal as i64),
            });
        }
    }

    for trigger in json_array(parts.triggers_json) {
        let [interval, duration, stop_at_end] =
            repetition_cells(&trigger.get("repetition").cloned().unwrap_or(Value::Null));
        let schedule = trigger.get("schedule").cloned().unwrap_or(Value::Null);
        rec.child(
            "TaskTriggers",
            vec![
                value(&field(&trigger, "trigger_type")),
                value(&field(&trigger, "trigger_id")),
                bool_cell(&trigger, "enabled"),
                value(&field(&trigger, "start_time")),
                value(&field(&trigger, "start_time_raw")),
                value(&field(&trigger, "end_time")),
                value(&field(&trigger, "end_time_raw")),
                interval,
                duration,
                stop_at_end,
                value(&field(&trigger, "execution_time_limit")),
                value(&field(&trigger, "delay")),
                value(&field(&trigger, "random_delay")),
                value(&field(&schedule, "kind")),
                raw_value(&field(&schedule, "raw")),
                raw_value(&field(&trigger, "subscription")),
                value(&field(&trigger, "state_name")),
                value(&field(&trigger, "user_id")),
                value(&field(&trigger, "session_change_type")),
                raw_value(&field(&trigger, "raw")),
            ],
        );
    }

    let declared = json_object(parts.settings_json);
    for (name, item) in &declared {
        match item {
            Value::Object(group) => {
                for (inner, inner_value) in group {
                    rec.child(
                        "TaskSettings",
                        vec![
                            value(name),
                            Cell::Text(format!("{name}/{inner}")),
                            value(inner),
                            match inner_value {
                                Value::String(text) => value(text),
                                Value::Null => Cell::Null,
                                other => Cell::Text(other.to_string()),
                            },
                            Cell::Text("declared".into()),
                        ],
                    );
                }
            }
            other => {
                rec.child(
                    "TaskSettings",
                    vec![
                        value(name),
                        Cell::Text(name.clone()),
                        value(name),
                        match other {
                            Value::String(text) => value(text),
                            Value::Null => Cell::Null,
                            other => Cell::Text(other.to_string()),
                        },
                        Cell::Text("declared".into()),
                    ],
                );
            }
        }
    }
    // Schema defaults are interpretation, kept apart from the file's values.
    if !parts.settings_json.is_empty() {
        for (name, default) in SETTING_DEFAULTS {
            if declared.contains_key(*name) {
                continue;
            }
            rec.child(
                "TaskSettings",
                vec![
                    value(name),
                    Cell::Text((*name).to_string()),
                    value(name),
                    Cell::Text((*default).to_string()),
                    Cell::Text("schema_default".into()),
                ],
            );
        }
    }

    for principal in json_array(parts.principals_json) {
        let user = field(&principal, "user_id");
        let group = field(&principal, "group_id");
        let (kind, identity) = if !user.is_empty() {
            ("user", user.clone())
        } else if !group.is_empty() {
            ("group", group.clone())
        } else {
            ("unknown", String::new())
        };
        let (name, sid) = ctx.meta.split_account(&identity);
        let privileges = principal
            .get("required_privileges")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        rec.child(
            "TaskPrincipals",
            vec![
                value(&field(&principal, "id")),
                value(&field(&principal, "element")),
                value(&user),
                value(&group),
                Cell::Text(kind.into()),
                // A group SID resolves to no user name by design (R14).
                if kind == "group" {
                    Cell::Null
                } else {
                    super::text_opt(name.as_deref())
                },
                super::text_opt(sid.as_deref()),
                value(&field(&principal, "logon_type")),
                value(&field(&principal, "run_level")),
                value(&field(&principal, "display_name")),
                value(&field(&principal, "process_token_sid_type")),
                value(&privileges),
                raw_value(&field(&principal, "raw")),
            ],
        );
    }

    if hidden_declared == Some(true) {
        signals.push(ReviewSignal {
            signal: "hidden_declared",
            basis: "definition declares Hidden=true".into(),
            evidence: "true".into(),
            action_ordinal: None,
        });
    }
    signals
}

fn write_signals(rec: &mut Record, signals: &[ReviewSignal]) {
    for signal in signals {
        rec.child(
            "TaskReviewSignals",
            vec![
                Cell::Text(signal.signal.to_string()),
                Cell::Text(signal.basis.clone()),
                value(&signal.evidence),
                super::int_opt(signal.action_ordinal),
            ],
        );
    }
    rec.set("review_signal_count", Cell::Int(signals.len() as i64));
    rec.set(
        "review_signals",
        if signals.is_empty() {
            Cell::Null
        } else {
            Cell::Text(review_signal_summary(signals))
        },
    );
}

/// Distinct signal kinds in first-seen order; counts live in review_signal_count.
fn review_signal_summary(signals: &[ReviewSignal]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for signal in signals {
        if !names.contains(&signal.signal) {
            names.push(signal.signal);
        }
    }
    names.join(", ")
}

/// Repetition cells for XML (ISO 8601 keys) and .job (minute counts) triggers.
fn repetition_cells(repetition: &Value) -> [Cell; 3] {
    let minutes = |key| repetition.get(key).and_then(Value::as_u64);
    if let Some(interval) = minutes("interval_minutes") {
        // A .job trigger with a zero interval does not repeat.
        if interval == 0 {
            return [Cell::Null, Cell::Null, Cell::Null];
        }
        let duration = minutes("duration_minutes").map_or(Cell::Null, |m| Cell::Text(format!("PT{m}M")));
        return [Cell::Text(format!("PT{interval}M")), duration, Cell::Null];
    }
    [
        value(&field(repetition, "interval")),
        value(&field(repetition, "duration")),
        bool_cell(repetition, "stop_at_duration_end"),
    ]
}

/// Everything the view and the case-wide search must match on, in one column,
/// so a parent search never needs a facts lookup (R02).
fn search_text(parts: &[&str]) -> Cell {
    let joined: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|part| !part.trim().is_empty())
        .collect();
    if joined.is_empty() {
        Cell::Null
    } else {
        Cell::Text(joined.join(" \u{1} "))
    }
}

/// Columns this contract needs from the TaskScheduler facts table. An older
/// facts generation is reported as a reparse requirement instead of silently
/// publishing records that claim full original preservation.
const REQUIRED_DEFINITION_COLUMNS: &[&str] = &[
    "source_format",
    "format_basis",
    "encoding",
    "decode_status",
    "raw_size",
    "raw_sha256",
    "raw_text",
    "raw_bytes_hex",
    "timestamp_meaning",
    "registration_date",
    "job_last_run",
    "settings_json",
    "principals_json",
    "run_as_element",
    "root_children",
];

/// `Ok(false)` means there is no collected task facts table at all, which is a
/// valid empty result; a table that exists with the old columns is an error.
fn definition_facts_usable(path: &std::path::Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [DEFINITION_TABLE],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(false);
    }
    let mut query = conn.prepare(&format!(
        "SELECT name FROM pragma_table_info({})",
        crate::sqlite::quote_ident(DEFINITION_TABLE)
    ))?;
    let columns: Vec<String> = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let missing: Vec<&str> = REQUIRED_DEFINITION_COLUMNS
        .iter()
        .copied()
        .filter(|name| !columns.iter().any(|column| column == name))
        .collect();
    if missing.is_empty() {
        return Ok(true);
    }
    Err(anyhow::anyhow!(
        "{DEFINITION_FACTS}: 이전 세대 TaskScheduler facts입니다 — 누락 컬럼({}) 때문에 \
         작업 원문·형식·상태를 보존할 수 없습니다. TaskScheduler를 다시 파싱해야 합니다",
        missing.join(", ")
    ))
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

fn write_definitions(
    ctx: &Ctx,
    db: &mut DerivedDb,
    index: &mut DefinitionIndex,
) -> Result<usize> {
    let facts = ctx.out_dir.join(DEFINITION_FACTS);
    let mut written = 0usize;
    if !definition_facts_usable(&facts)? {
        return Ok(written);
    }
    for row in overview::read_table_with_rowid(&facts, DEFINITION_TABLE)? {
        let uri = g(&row, "uri");
        let author = g(&row, "author");
        let task_path = if uri.is_empty() { g(&row, "task_name") } else { uri };
        let normalized = normalize_task_path(task_path);
        let mut rec = ctx.record(&SPEC);

        let meaning = g(&row, "timestamp_meaning");
        let kind = match meaning {
            "registration_date" => "작업 등록 시각(XML RegistrationInfo/Date)",
            "job_last_run" => "마지막 실행 시각(.job LastRunTime)",
            _ => "",
        };
        rec.timestamp(g(&row, "timestamp"), kind);
        rec.set(
            "timestamp_state",
            Cell::Text(
                if g(&row, "timestamp").trim().is_empty() {
                    "unrecorded"
                } else {
                    "recorded"
                }
                .into(),
            ),
        );
        rec.set("timestamp_meaning", value(meaning));
        rec.set("evidence_kind", Cell::Text("task_definition".into()));
        rec.set("event_type", Cell::Text("작업 정의".into()));

        // Representative identity = the definition's run-as principal.
        let run_as = g(&row, "run_as");
        let run_as_element = g(&row, "run_as_element");
        let run_as_kind = match run_as_element {
            "UserId" => "user",
            "GroupId" => "group",
            _ if run_as.is_empty() => "unknown",
            _ => "unspecified_element",
        };
        if run_as_kind == "group" {
            // A group is not an account: keep the SID, never a user name.
            rec.set("account", Cell::Null);
            rec.set(
                "account_sid",
                if super::is_sid(run_as) {
                    value(run_as)
                } else {
                    Cell::Null
                },
            );
        } else {
            rec.account(run_as, &ctx.meta);
        }
        rec.set("account_role", Cell::Text("task_principal".into()));
        rec.set("run_as", value(run_as));
        rec.set(
            "run_as_sid",
            if super::is_sid(run_as) {
                value(run_as)
            } else {
                Cell::Null
            },
        );
        rec.set("run_as_kind", Cell::Text(run_as_kind.into()));
        rec.set("run_as_element", value(run_as_element));
        rec.set("run_level", value(g(&row, "run_level")));
        rec.set("logon_type", value(g(&row, "logon_type")));

        rec.set("task_name", value(g(&row, "task_name")));
        rec.set("task_path", value(task_path));
        rec.set("task_path_normalized", value(&normalized));
        rec.set("uri", value(uri));
        rec.set(
            "task_name_basis",
            Cell::Text(if uri.is_empty() { "file_name" } else { "uri" }.into()),
        );
        // R03: compare normalized paths; the original URI stays untouched.
        let path_is_microsoft = normalized.starts_with("\\microsoft\\");
        let author_is_microsoft = author.to_lowercase().contains("microsoft");
        rec.set(
            "is_microsoft",
            Cell::Int(i64::from(path_is_microsoft || author_is_microsoft)),
        );
        rec.set(
            "microsoft_basis",
            Cell::Text(
                match (path_is_microsoft, author_is_microsoft) {
                    (true, true) => "task_path_and_author",
                    (true, false) => "task_path_prefix",
                    (false, true) => "author_value",
                    (false, false) => "none",
                }
                .into(),
            ),
        );

        let enabled = super::flag(g(&row, "enabled"));
        let hidden = super::flag(g(&row, "hidden"));
        let hidden_declared = match hidden {
            Cell::Int(value) => Some(value == 1),
            _ => None,
        };
        rec.set(
            "enabled_state",
            Cell::Text(
                if g(&row, "enabled").trim().is_empty() {
                    "not_declared"
                } else {
                    "declared"
                }
                .into(),
            ),
        );
        rec.set(
            "hidden_state",
            Cell::Text(
                if g(&row, "hidden").trim().is_empty() {
                    "not_declared"
                } else {
                    "declared"
                }
                .into(),
            ),
        );
        rec.set("enabled", enabled);
        rec.set("hidden", hidden);
        rec.set("author", value(author));
        rec.set("task_description", value(g(&row, "description")));

        rec.set("source_format", value(g(&row, "source_format")));
        rec.set("format_basis", value(g(&row, "format_basis")));
        rec.set("encoding", value(g(&row, "encoding")));
        rec.set("decode_status", value(g(&row, "decode_status")));
        rec.set("decode_replacements", int_value(g(&row, "decode_replacements")));
        rec.set("raw_size", int_value(g(&row, "raw_size")));
        rec.set("raw_sha256", value(g(&row, "raw_sha256")));
        rec.set("raw_content", raw_value(g(&row, "raw_text")));
        rec.set("raw_bytes_hex", value(g(&row, "raw_bytes_hex")));
        rec.set("registration_date", value(g(&row, "registration_date")));
        rec.set(
            "registration_date_raw",
            value(g(&row, "registration_date_raw")),
        );
        rec.set("job_last_run", value(g(&row, "job_last_run")));
        rec.set("job_last_run_raw", value(g(&row, "job_last_run_raw")));
        rec.set("task_version", value(g(&row, "task_version")));
        rec.set("task_namespace", value(g(&row, "task_namespace")));
        rec.set("root_children", value(g(&row, "root_children")));
        rec.set("actions_context", value(g(&row, "actions_context")));
        rec.set("data_raw", raw_value(g(&row, "data_raw")));
        rec.set("job_header_json", super::json_text(g(&row, "job_header_json")));
        let status = g(&row, "_status");
        rec.set(
            "parse_status",
            Cell::Text(
                if status.is_empty() {
                    crate::parsers::taskscheduler::STATUS_PARSED
                } else {
                    status
                }
                .into(),
            ),
        );
        rec.set("parse_error", value(g(&row, "_error")));
        rec.set("parse_error_location", value(g(&row, "_error_location")));
        // Parsing problems stay visible in the common description too.
        if let Some(error) = super::nz(g(&row, "_error")) {
            rec.set("description", Cell::Text(error.to_string()));
        }
        rec.set("source_file", value(g(&row, "_source_file")));

        index.add(task_path, &rec.record_id);
        let actions_json = g(&row, "actions_json").to_string();
        let triggers_json = g(&row, "triggers_json").to_string();
        let signals = write_task_children(
            &mut rec,
            ctx,
            TaskXmlParts {
                actions_json: &actions_json,
                triggers_json: &triggers_json,
                settings_json: g(&row, "settings_json"),
                principals_json: g(&row, "principals_json"),
            },
            hidden_declared,
            (run_as_kind == "user" && super::is_sid(run_as)).then_some(run_as),
            index,
        );
        write_signals(&mut rec, &signals);

        let actions = json_array(&actions_json);
        let triggers = json_array(&triggers_json);
        rec.set("action_count", Cell::Int(actions.len() as i64));
        rec.set("trigger_count", Cell::Int(triggers.len() as i64));
        rec.set(
            "setting_count",
            Cell::Int(rec.child_count("TaskSettings") as i64),
        );
        rec.set(
            "principal_count",
            Cell::Int(rec.child_count("TaskPrincipals") as i64),
        );
        rec.set("action_summary", value(g(&row, "actions")));
        rec.set("trigger_type_summary", value(g(&row, "trigger_types")));

        let command_text: Vec<String> = actions
            .iter()
            .map(|action| {
                format!(
                    "{} {} {}",
                    field(action, "command"),
                    field(action, "arguments"),
                    field(action, "class_id")
                )
            })
            .collect();
        let trigger_text: Vec<String> = triggers
            .iter()
            .map(|trigger| {
                format!(
                    "{} {}",
                    field(trigger, "trigger_type"),
                    field(trigger, "raw")
                )
            })
            .collect();
        let account_display = match rec.get("account") {
            Some(Cell::Text(text)) => text.clone(),
            _ => String::new(),
        };
        rec.set(
            "search_text",
            search_text(&[
                g(&row, "task_name"),
                task_path,
                run_as,
                author,
                g(&row, "description"),
                &command_text.join(" "),
                &trigger_text.join(" "),
                &account_display,
                if super::is_sid(run_as) { run_as } else { "" },
            ]),
        );

        rec.source(source_for_definition(ctx, &row)?);
        db.write(rec)?;
        written += 1;
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// `payload_raw` must come from the facts row itself: a stored TEXT '' payload
/// is evidence of an empty EventData element and is not the same as a missing
/// one, so the raw value and its state are stored separately.
fn common_event_fields(rec: &mut Record, row: &Row) {
    rec.set("event_id", super::int(g(row, "EventID")));
    rec.set("provider", value(g(row, "Provider")));
    rec.set("channel", value(g(row, "Channel")));
    rec.set("computer", value(g(row, "Computer")));
    rec.set("event_record_id", value(g(row, "EventRecordID")));
    rec.set("level_name", value(g(row, "LevelName")));
    rec.set("keywords_raw", value(g(row, "Keywords")));
    rec.set("process_id", value(g(row, "ProcessID")));
    rec.set("thread_id", value(g(row, "ThreadID")));
    rec.set("system_user_sid", value(g(row, "UserID")));
    rec.set("activity_id", value(g(row, "ActivityID")));
    rec.set("related_activity_id", value(g(row, "RelatedActivityID")));
    rec.set(
        "event_data_raw",
        row.get("EventData")
            .map(|payload| Cell::Text(payload.clone()))
            .unwrap_or(Cell::Null),
    );
    rec.set(
        "payload_state",
        Cell::Text(
            match row.get("EventData") {
                None => "absent",
                Some(payload) if payload.is_empty() => "present_empty",
                Some(_) => "present",
            }
            .into(),
        ),
    );
    rec.set("record_key", value(g(row, "_record_key")));
    rec.set("source_file", value(g(row, "_source_file")));
    // Facts row status; payload-level parse results are applied afterwards.
    if let Some(status) = super::nz(g(row, "_status")) {
        rec.set("parse_status", Cell::Text(status.to_string()));
    }
    if let Some(error) = super::nz(g(row, "_error")) {
        rec.set("parse_error", Cell::Text(error.to_string()));
    }
}

/// Keep every payload field so detail, search and filters never fall back to
/// the facts database.
fn write_event_fields(rec: &mut Record, payload: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut flat: Vec<(String, String)> = Vec::new();
    for (name, item) in payload {
        match item {
            Value::Object(inner) => {
                for (key, nested) in inner {
                    flat.push((
                        format!("{name}/{key}"),
                        match nested {
                            Value::String(text) => text.clone(),
                            Value::Null => String::new(),
                            other => other.to_string(),
                        },
                    ));
                }
            }
            Value::String(text) => flat.push((name.clone(), text.clone())),
            Value::Null => flat.push((name.clone(), String::new())),
            other => flat.push((name.clone(), other.to_string())),
        }
    }
    let mut searchable = Vec::with_capacity(flat.len());
    for (name, item) in flat {
        searchable.push(format!("{name}={item}"));
        rec.child(
            "TaskEventFields",
            vec![Cell::Text(name), raw_value(&item)],
        );
    }
    searchable
}

/// Result codes are evidence: keep the raw text, the decoded integer and the
/// notation, and never translate a non-zero value into a single meaning.
fn set_result_code(rec: &mut Record, raw: &str) {
    if raw.trim().is_empty() {
        return;
    }
    let text = raw.trim();
    let (parsed, format) = if let Some(hex) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
    {
        (
            u64::from_str_radix(hex, 16).ok().map(|v| v as i64),
            "hex",
        )
    } else {
        (text.parse::<i64>().ok(), "decimal")
    };
    rec.set("result_code_raw", Cell::Text(text.to_string()));
    rec.set("result_code", super::int_opt(parsed));
    rec.set("result_code_format", Cell::Text(format.into()));
}

fn write_operational_events(
    ctx: &Ctx,
    db: &mut DerivedDb,
    events: &EventLogOverviewCache,
) -> Result<usize> {
    let mut written = 0usize;
    for row in events.rows() {
        // Maintenance channel (automatic maintenance state, e.g. 800) names no
        // task run; excluded by user decision 2026-10-14.
        if g(row, "Provider") != TASK_PROVIDER
            || g(row, "Channel").to_ascii_lowercase().contains("maintenance")
        {
            continue;
        }
        let event_id = g(row, "EventID");
        let payload_raw = g(row, "EventData");
        let payload = overview::parse_eventdata(payload_raw);
        // Operational records name the task in `TaskName`; the Maintenance
        // channel records it in `Task` as a recorded name (e.g. the
        // `NT TASK\…` form). The recorded value is kept verbatim — no prefix
        // is stripped and no definition is merged into it.
        let (task_basis, task) = {
            let primary = ed_any(&payload, "TaskName");
            if !primary.is_empty() {
                ("TaskName", primary)
            } else {
                let secondary = ed_any(&payload, "Task");
                if secondary.is_empty() {
                    ("", String::new())
                } else {
                    ("Task", secondary)
                }
            }
        };
        let mut rec = ctx.record(&SPEC);
        let meaning = operational_meaning(event_id);
        let (event_type, category, launch_reason, result, result_basis) = match &meaning {
            Some(meaning) => (
                meaning.event_type,
                meaning.category,
                meaning.launch_reason,
                meaning.result,
                meaning.result_basis,
            ),
            // Undocumented IDs keep the payload and say nothing about success.
            None => ("작업 스케줄러 이벤트", "other", "", "", ""),
        };
        rec.timestamp(g(row, "timestamp"), "작업 이벤트 기록 시각");
        rec.set(
            "timestamp_state",
            Cell::Text(
                if g(row, "timestamp").trim().is_empty() {
                    "unrecorded"
                } else {
                    "recorded"
                }
                .into(),
            ),
        );
        rec.set("timestamp_meaning", Cell::Text("event_recorded".into()));
        rec.set(
            "evidence_kind",
            Cell::Text(
                if task.is_empty() {
                    "scheduler_service_event"
                } else {
                    "task_event"
                }
                .into(),
            ),
        );
        rec.set("event_type", Cell::Text(event_type.into()));
        rec.set("event_category", Cell::Text(category.into()));
        rec.set("launch_reason", value(launch_reason));
        rec.set("result", value(result));
        rec.set("result_basis", value(result_basis));
        set_result_code(
            &mut rec,
            &[
                ed(&payload, "ResultCode"),
                ed(&payload, "ReturnCode"),
                ed(&payload, "ErrorValue"),
                ed(&payload, "ErrorCode"),
            ]
            .into_iter()
            .find(|value| !value.is_empty())
            .unwrap_or_default(),
        );

        rec.set("task_name_basis", value(task_basis));
        if !task.is_empty() {
            rec.set("task_name", Cell::Text(leaf_name(&task)));
            rec.set("task_path", Cell::Text(task.clone()));
            // Normalisation only folds separator/case differences; a recorded
            // `NT TASK\…` name keeps that prefix, so it never matches a
            // definition path by accident.
            rec.set(
                "task_path_normalized",
                Cell::Text(normalize_task_path(&task)),
            );
        }

        // Identity roles: the registering user differs from the run user.
        let user_name = ed(&payload, "UserName");
        let user_context = ed(&payload, "UserContext");
        let actor = if matches!(category, "registration") {
            user_name.clone()
        } else {
            String::new()
        };
        let run_user = if actor.is_empty() {
            [user_context.clone(), user_name.clone()]
                .into_iter()
                .find(|value| !value.is_empty())
                .unwrap_or_default()
        } else {
            user_context.clone()
        };
        if !actor.is_empty() {
            rec.account(&actor, &ctx.meta);
            rec.set("account_role", Cell::Text("event_actor".into()));
            rec.set("actor_account", value(&actor));
            if super::is_sid(&actor) {
                rec.set("actor_sid", value(&actor));
            }
        } else if !run_user.is_empty() {
            rec.account(&run_user, &ctx.meta);
            rec.set("account_role", Cell::Text("event_run_user".into()));
        }
        rec.set("run_user_raw", value(&run_user));
        if super::is_sid(&run_user) {
            rec.set("run_user_sid", value(&run_user));
        }

        rec.set("instance_id", value(&ed(&payload, "InstanceId")));
        rec.set("task_instance_id", value(&ed(&payload, "TaskInstanceId")));
        rec.set("action_name", value(&ed(&payload, "ActionName")));
        rec.set("engine_pid", value(&ed(&payload, "EnginePID")));
        rec.set(
            "reported_process_id",
            value(&[ed(&payload, "ProcessID"), ed(&payload, "Pid")]
                .into_iter()
                .find(|value| !value.is_empty())
                .unwrap_or_default()),
        );
        rec.set(
            "queued_instance_id",
            value(&ed(&payload, "QueuedTaskInstanceId")),
        );
        // 129 reports the created process image; 200 reports the action name.
        let detail = match event_id {
            "129" => ed(&payload, "Path"),
            "200" | "201" | "203" => ed(&payload, "ActionName"),
            _ => String::new(),
        };
        rec.set("description", value(&detail));

        common_event_fields(&mut rec, row);
        let searchable = write_event_fields(&mut rec, &payload);
        write_signals(&mut rec, &[]);
        rec.set(
            "search_text",
            search_text(&[
                &task,
                &actor,
                &run_user,
                event_type,
                result,
                &detail,
                &searchable.join(" "),
            ]),
        );
        rec.source(ctx.facts.source_from_record_key(
            g(row, "_record_key"),
            Some("EventData"),
            super::nz(g(row, "_source_file")),
            Some(event_type),
        )?);
        db.write(rec)?;
        written += 1;
    }
    Ok(written)
}

fn write_audit_events(
    ctx: &Ctx,
    db: &mut DerivedDb,
    events: &EventLogOverviewCache,
    index: &mut DefinitionIndex,
) -> Result<usize> {
    let mut written = 0usize;
    for row in events.rows() {
        if g(row, "Provider") != SECURITY_PROVIDER {
            continue;
        }
        let event_id = g(row, "EventID");
        let Some((event_type, content_field)) = audit_meaning(event_id) else {
            continue;
        };
        let payload_raw = g(row, "EventData");
        let payload = overview::parse_eventdata(payload_raw);
        let task = ed(&payload, "TaskName");
        let mut rec = ctx.record(&SPEC);
        rec.timestamp(g(row, "timestamp"), "작업 감사 이벤트 기록 시각");
        rec.set(
            "timestamp_state",
            Cell::Text(
                if g(row, "timestamp").trim().is_empty() {
                    "unrecorded"
                } else {
                    "recorded"
                }
                .into(),
            ),
        );
        rec.set("timestamp_meaning", Cell::Text("event_recorded".into()));
        rec.set("evidence_kind", Cell::Text("audit_event".into()));
        rec.set("event_type", Cell::Text(event_type.into()));
        rec.set("event_category", Cell::Text("audit".into()));
        if !task.is_empty() {
            rec.set("task_name_basis", Cell::Text("TaskName".into()));
            rec.set("task_name", Cell::Text(leaf_name(&task)));
            rec.set("task_path", Cell::Text(task.clone()));
            rec.set(
                "task_path_normalized",
                Cell::Text(normalize_task_path(&task)),
            );
        }

        // Subject = the account that performed the audited operation.
        let subject_sid = ed(&payload, "SubjectUserSid");
        let subject_name = ed(&payload, "SubjectUserName");
        let subject_domain = ed(&payload, "SubjectDomainName");
        rec.account(
            if super::is_sid(&subject_sid) {
                &subject_sid
            } else {
                &subject_name
            },
            &ctx.meta,
        );
        if !subject_name.is_empty() {
            rec.set("account", value(&subject_name));
        }
        rec.set("account_role", Cell::Text("event_actor".into()));
        rec.set("actor_account", value(&subject_name));
        if super::is_sid(&subject_sid) {
            rec.set("actor_sid", value(&subject_sid));
            rec.set("account_sid", value(&subject_sid));
        }
        rec.set("actor_domain", value(&subject_domain));
        rec.set("actor_logon_id", value(&ed(&payload, "SubjectLogonId")));
        rec.set(
            "reported_process_id",
            value(&ed(&payload, "ClientProcessId")),
        );

        // Facts status first; the audited XML result below then refines it.
        common_event_fields(&mut rec, row);
        let facts_ok = matches!(super::nz(g(row, "_status")), None | Some("ok"));

        // The audited task XML travels with the event; parse it into the same
        // children as a collected definition, but keep it a separate record.
        let mut signals = Vec::new();
        let content = if content_field.is_empty() {
            String::new()
        } else {
            ed(&payload, content_field)
        };
        if !content.trim().is_empty() {
            rec.set("raw_content", raw_value(&content));
            rec.set("source_format", Cell::Text("xml_event_payload".into()));
            rec.set(
                "raw_sha256",
                Cell::Text(crate::parsers::taskscheduler::sha256_hex(content.as_bytes())),
            );
            rec.set("raw_size", Cell::Int(content.len() as i64));
            match crate::parsers::taskscheduler::parse_task_xml(&content) {
                Ok(parsed) => {
                    if facts_ok {
                        rec.set("parse_status", Cell::Text("parsed".into()));
                    }
                    rec.set("task_version", value(&parsed.task_version));
                    rec.set("task_namespace", value(&parsed.namespace));
                    rec.set("root_children", value(&parsed.root_children.join(", ")));
                    rec.set("actions_context", value(&parsed.actions_context));
                    rec.set("author", value(&parsed.author));
                    rec.set("task_description", value(&parsed.description));
                    rec.set("registration_date_raw", value(&parsed.registration_date));
                    rec.set("run_as", value(&parsed.run_as));
                    rec.set("run_as_element", value(&parsed.run_as_element));
                    rec.set("run_level", value(&parsed.run_level));
                    rec.set("logon_type", value(&parsed.logon_type));
                    rec.set(
                        "run_as_kind",
                        Cell::Text(
                            match parsed.run_as_element.as_str() {
                                "UserId" => "user",
                                "GroupId" => "group",
                                _ => "unknown",
                            }
                            .into(),
                        ),
                    );
                    rec.set("enabled", super::flag(&parsed.enabled));
                    rec.set("hidden", super::flag(&parsed.hidden));
                    let hidden_declared = match super::flag(&parsed.hidden) {
                        Cell::Int(value) => Some(value == 1),
                        _ => None,
                    };
                    rec.set("data_raw", raw_value(&parsed.data_raw));
                    signals = write_task_children(
                        &mut rec,
                        ctx,
                        TaskXmlParts {
                            actions_json: &parsed.actions_json,
                            triggers_json: &parsed.triggers_json,
                            settings_json: &parsed.settings_json,
                            principals_json: &parsed.principals_json,
                        },
                        hidden_declared,
                        (parsed.run_as_element == "UserId" && super::is_sid(&parsed.run_as)).then_some(parsed.run_as.as_str()),
                        index,
                    );
                    rec.set("action_summary", value(&parsed.actions_display));
                    rec.set("trigger_type_summary", value(&parsed.trigger_types));
                    rec.set(
                        "action_count",
                        Cell::Int(rec.child_count("TaskActions") as i64),
                    );
                    rec.set(
                        "trigger_count",
                        Cell::Int(rec.child_count("TaskTriggers") as i64),
                    );
                    rec.set(
                        "setting_count",
                        Cell::Int(rec.child_count("TaskSettings") as i64),
                    );
                    rec.set(
                        "principal_count",
                        Cell::Int(rec.child_count("TaskPrincipals") as i64),
                    );
                }
                Err(error) => {
                    rec.set("parse_status", Cell::Text("invalid_format".into()));
                    rec.set("parse_error", Cell::Text(error.to_string()));
                }
            }
        }

        let searchable = write_event_fields(&mut rec, &payload);
        write_signals(&mut rec, &signals);
        rec.set(
            "search_text",
            search_text(&[
                &task,
                &subject_name,
                &subject_sid,
                event_type,
                &searchable.join(" "),
            ]),
        );
        rec.source(ctx.facts.source_from_record_key(
            g(row, "_record_key"),
            Some("EventData"),
            super::nz(g(row, "_source_file")),
            Some(event_type),
        )?);
        db.write(rec)?;
        written += 1;
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(super) fn build(ctx: &Ctx, events: &EventLogOverviewCache) -> Result<usize> {
    let mut db = DerivedDb::create(&ctx.overview_dir(), SPEC.name)?;
    let mut index = DefinitionIndex::default();
    let mut rows = write_definitions(ctx, &mut db, &mut index)?;
    rows += write_operational_events(ctx, &mut db, events)?;
    rows += write_audit_events(ctx, &mut db, events, &mut index)?;
    registry::populate(ctx, &db, &index)?;
    registry::populate_com(ctx, &db, &index)?;
    supplemental::populate(ctx, &db, &index)?;
    observations::populate(ctx, &db, events)?;
    db.finish()?;
    Ok(rows)
}

/// Compare a collected path with the definitions of this run.
pub(super) fn match_definition(index: &DefinitionIndex, path: &str) -> (Option<String>, String) {
    let (id, status) = index.match_path(path);
    (id, status.to_string())
}

const DDL: &str = r#"PRAGMA foreign_keys=ON;
CREATE TABLE "ScheduledTasks" (
  "record_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "timestamp" TEXT,
  "overview_name" TEXT NOT NULL,
  "account" TEXT,
  "account_sid" TEXT,
  "timestamp_kind" TEXT,
  "event_type" TEXT,
  "description" TEXT,
  "evidence_kind" TEXT NOT NULL,
  "timestamp_state" TEXT NOT NULL,
  "timestamp_meaning" TEXT,
  "task_name" TEXT,
  "task_path" TEXT,
  "task_path_normalized" TEXT,
  "task_name_basis" TEXT,
  "uri" TEXT,
  "is_microsoft" INTEGER CHECK ("is_microsoft" IN (0,1)),
  "microsoft_basis" TEXT,
  "run_as" TEXT,
  "run_as_sid" TEXT,
  "run_as_kind" TEXT,
  "run_as_element" TEXT,
  "run_level" TEXT,
  "logon_type" TEXT,
  "enabled" INTEGER CHECK ("enabled" IN (0,1)),
  "enabled_state" TEXT,
  "hidden" INTEGER CHECK ("hidden" IN (0,1)),
  "hidden_state" TEXT,
  "author" TEXT,
  "task_description" TEXT,
  "account_role" TEXT,
  "actor_account" TEXT,
  "actor_sid" TEXT,
  "actor_domain" TEXT,
  "actor_logon_id" TEXT,
  "run_user_raw" TEXT,
  "run_user_sid" TEXT,
  "instance_id" TEXT,
  "task_instance_id" TEXT,
  "action_name" TEXT,
  "engine_pid" TEXT,
  "reported_process_id" TEXT,
  "queued_instance_id" TEXT,
  "event_category" TEXT,
  "launch_reason" TEXT,
  "result" TEXT,
  "result_basis" TEXT,
  "result_code" INTEGER,
  "result_code_raw" TEXT,
  "result_code_format" TEXT,
  "event_id" INTEGER,
  "provider" TEXT,
  "channel" TEXT,
  "computer" TEXT,
  "event_record_id" TEXT,
  "level_name" TEXT,
  "keywords_raw" TEXT,
  "process_id" TEXT,
  "thread_id" TEXT,
  "system_user_sid" TEXT,
  "activity_id" TEXT,
  "related_activity_id" TEXT,
  "event_data_raw" TEXT,
  "payload_state" TEXT,
  "record_key" TEXT,
  "source_file" TEXT,
  "source_format" TEXT,
  "format_basis" TEXT,
  "encoding" TEXT,
  "decode_status" TEXT,
  "decode_replacements" INTEGER,
  "raw_size" INTEGER,
  "raw_sha256" TEXT,
  "raw_content" TEXT,
  "raw_bytes_hex" TEXT,
  "registration_date" TEXT,
  "registration_date_raw" TEXT,
  "job_last_run" TEXT,
  "job_last_run_raw" TEXT,
  "task_version" TEXT,
  "task_namespace" TEXT,
  "root_children" TEXT,
  "actions_context" TEXT,
  "data_raw" TEXT,
  "job_header_json" TEXT CHECK ("job_header_json" IS NULL OR json_valid("job_header_json")),
  "parse_status" TEXT,
  "parse_error" TEXT,
  "parse_error_location" TEXT,
  "action_count" INTEGER,
  "trigger_count" INTEGER,
  "setting_count" INTEGER,
  "principal_count" INTEGER,
  "action_summary" TEXT,
  "trigger_type_summary" TEXT,
  "review_signal_count" INTEGER,
  "review_signals" TEXT,
  "search_text" TEXT,
  PRIMARY KEY(record_id),
  CHECK(overview_name = 'ScheduledTasks'),
  CHECK(timestamp IS NULL OR timestamp_kind IS NOT NULL),
  CHECK(timestamp_state IN ('recorded','unrecorded')),
  CHECK(evidence_kind IN ('task_definition','task_event','scheduler_service_event','audit_event'))
);
-- Untimed rows must page and sort without being excluded (R01).
CREATE INDEX "idx_ScheduledTasks_time" ON "ScheduledTasks"(timestamp IS NULL, timestamp, record_id);
CREATE INDEX "idx_ScheduledTasks_account" ON "ScheduledTasks"(account_sid, timestamp, record_id);
CREATE INDEX "idx_ScheduledTasks_path" ON "ScheduledTasks"(task_path_normalized, record_id);
CREATE INDEX "idx_ScheduledTasks_kind" ON "ScheduledTasks"(evidence_kind, event_category, timestamp);
CREATE INDEX "idx_ScheduledTasks_filters" ON "ScheduledTasks"(is_microsoft, enabled, hidden, record_id);
CREATE INDEX "idx_ScheduledTasks_review" ON "ScheduledTasks"(review_signal_count, record_id);
CREATE INDEX "idx_ScheduledTasks_status" ON "ScheduledTasks"(parse_status, record_id);
CREATE TABLE "source_records" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "source_dataset_id" TEXT NOT NULL,
  "source_artifact" TEXT NOT NULL,
  "source_db" TEXT NOT NULL,
  "source_table" TEXT NOT NULL,
  "source_rowid" INTEGER NOT NULL,
  "source_field" TEXT,
  "source_record_key" TEXT,
  "source_file" TEXT,
  "source_label" TEXT,
  PRIMARY KEY(record_id, ordinal),
  CHECK(ordinal >= 0),
  FOREIGN KEY(record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX idx_source_lookup ON source_records(source_db, source_table, source_rowid, source_field);
CREATE TABLE "TaskActions" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "action_type" TEXT,
  "action_id" TEXT,
  "command" TEXT,
  "command_resolved" TEXT,
  "arguments" TEXT,
  "working_directory" TEXT,
  "class_id" TEXT,
  "com_data" TEXT,
  "detail_json" TEXT CHECK ("detail_json" IS NULL OR json_valid("detail_json")),
  "raw_action" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskActions_command" ON "TaskActions"(command, record_id);
CREATE INDEX "idx_TaskActions_class" ON "TaskActions"(class_id, record_id);
CREATE TABLE "TaskTriggers" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "trigger_type" TEXT,
  "trigger_id" TEXT,
  "enabled" INTEGER CHECK ("enabled" IN (0,1)),
  "start_time" TEXT,
  "start_time_raw" TEXT,
  "end_time" TEXT,
  "end_time_raw" TEXT,
  "repetition_interval" TEXT,
  "repetition_duration" TEXT,
  "repetition_stop_at_end" INTEGER CHECK ("repetition_stop_at_end" IN (0,1)),
  "execution_time_limit" TEXT,
  "delay" TEXT,
  "random_delay" TEXT,
  "schedule_kind" TEXT,
  "schedule_raw" TEXT,
  "subscription" TEXT,
  "state_name" TEXT,
  "user_id" TEXT,
  "session_change_type" TEXT,
  "raw_trigger" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskTriggers_type" ON "TaskTriggers"(trigger_type, record_id);
CREATE TABLE "TaskSettings" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "setting_group" TEXT,
  "setting_path" TEXT,
  "setting_name" TEXT,
  "value_raw" TEXT,
  "value_source" TEXT NOT NULL,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  CHECK (value_source IN ('declared','schema_default')),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskSettings_name" ON "TaskSettings"(setting_name, value_source, record_id);
CREATE TABLE "TaskPrincipals" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "principal_id" TEXT,
  "principal_element" TEXT,
  "user_id" TEXT,
  "group_id" TEXT,
  "principal_kind" TEXT,
  "account" TEXT,
  "account_sid" TEXT,
  "logon_type" TEXT,
  "run_level" TEXT,
  "display_name" TEXT,
  "process_token_sid_type" TEXT,
  "required_privileges" TEXT,
  "raw_principal" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE TABLE "TaskEventFields" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "field_name" TEXT,
  "field_value" TEXT,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskEventFields_name" ON "TaskEventFields"(field_name, record_id);
CREATE TABLE "TaskReviewSignals" (
  "record_id" TEXT NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "signal" TEXT NOT NULL,
  "basis" TEXT NOT NULL,
  "evidence_value" TEXT,
  "action_ordinal" INTEGER,
  PRIMARY KEY ("record_id", ordinal),
  CHECK (ordinal >= 0),
  FOREIGN KEY ("record_id") REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskReviewSignals_signal" ON "TaskReviewSignals"(signal, record_id);
CREATE TABLE "TaskRegistryEntries" (
  "entry_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "guid" TEXT,
  "registry_path" TEXT,
  "key_last_write" TEXT,
  "tree_path" TEXT,
  "task_uri" TEXT,
  "task_path_normalized" TEXT,
  "security_descriptor" TEXT,
  "hash_hex" TEXT,
  "id_value" TEXT,
  "index_value" TEXT,
  "schema_value" TEXT,
  "version_value" TEXT,
  "triggers_hex" TEXT,
  "actions_hex" TEXT,
  "dynamic_info_hex" TEXT,
  "user_sid" TEXT,
  "matched_record_id" TEXT,
  "match_status" TEXT NOT NULL,
  "match_basis" TEXT,
  "tree_node_state" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(entry_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL)),
  FOREIGN KEY(matched_record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE SET NULL
);
CREATE INDEX "idx_TaskRegistryEntries_match" ON "TaskRegistryEntries"(task_path_normalized, scope);
CREATE TABLE "TaskComRegistrations" (
  "registration_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "record_id" TEXT NOT NULL,
  "action_ordinal" INTEGER,
  "class_id" TEXT NOT NULL,
  "hive" TEXT,
  "hive_scope" TEXT,
  "registry_view" TEXT,
  "key_path" TEXT,
  "server_kind" TEXT,
  "class_name" TEXT,
  "server_path_raw" TEXT,
  "server_path_resolved" TEXT,
  "threading_model" TEXT,
  "key_last_write" TEXT,
  "match_status" TEXT NOT NULL,
  "match_basis" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(registration_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL)),
  FOREIGN KEY(record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskComRegistrations_class" ON "TaskComRegistrations"(class_id, record_id);
CREATE INDEX "idx_TaskComRegistrations_server" ON "TaskComRegistrations"(server_path_raw, class_id);
CREATE TABLE "TaskLiveSnapshot" (
  "snapshot_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "entry_index" INTEGER,
  "name" TEXT,
  "task_path_normalized" TEXT,
  "task_description" TEXT,
  "command" TEXT,
  "triggers_text" TEXT,
  "account_reported" TEXT,
  "signature_reported" TEXT,
  "signer" TEXT,
  "sign_timestamp" TEXT,
  "signer2" TEXT,
  "sign_timestamp2" TEXT,
  "raw_json" TEXT,
  "matched_record_id" TEXT,
  "match_status" TEXT NOT NULL,
  "match_basis" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(snapshot_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL)),
  FOREIGN KEY(matched_record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE SET NULL
);
CREATE TABLE "TaskFileEvidence" (
  "evidence_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "record_id" TEXT,
  "action_ordinal" INTEGER,
  "evidence_kind" TEXT NOT NULL,
  "collected_path" TEXT,
  "collected_name" TEXT,
  "collected_size" INTEGER,
  "collected_sha256" TEXT,
  "command_raw" TEXT,
  "command_resolved" TEXT,
  "match_status" TEXT NOT NULL,
  "match_basis" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  "source_file" TEXT,
  PRIMARY KEY(evidence_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL)),
  FOREIGN KEY(record_id) REFERENCES "ScheduledTasks"("record_id") ON DELETE CASCADE
);
CREATE INDEX "idx_TaskFileEvidence_record" ON "TaskFileEvidence"(record_id, evidence_kind);
CREATE TABLE "TaskLogObservations" (
  "observation_id" TEXT NOT NULL,
  "host_id" TEXT NOT NULL,
  "dataset_id" TEXT NOT NULL,
  "observation_kind" TEXT NOT NULL,
  "log_name" TEXT,
  "source_file" TEXT,
  "facts_db" TEXT,
  "facts_table" TEXT,
  "facts_generation" TEXT,
  "collection_state" TEXT NOT NULL,
  "input_row_count" INTEGER,
  "event_count" INTEGER,
  "task_event_count" INTEGER,
  "corrupted_count" INTEGER,
  "untimed_count" INTEGER,
  "first_observed_time" TEXT,
  "last_observed_time" TEXT,
  "error" TEXT,
  "source_dataset_id" TEXT,
  "source_db" TEXT,
  "source_table" TEXT,
  "source_rowid" INTEGER,
  PRIMARY KEY(observation_id),
  CHECK((source_dataset_id IS NULL AND source_db IS NULL AND source_table IS NULL AND source_rowid IS NULL)
     OR (source_dataset_id IS NOT NULL AND source_db IS NOT NULL AND source_table IS NOT NULL AND source_rowid IS NOT NULL))
);
CREATE TABLE _wina_derived_version (name TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO _wina_derived_version(name,version) VALUES ('overview_contract',1),('scheduled_tasks',4);
"#;

const MAIN: &[&str] = &[
    "record_id",
    "host_id",
    "dataset_id",
    "timestamp",
    "overview_name",
    "account",
    "account_sid",
    "timestamp_kind",
    "event_type",
    "description",
    "evidence_kind",
    "timestamp_state",
    "timestamp_meaning",
    "task_name",
    "task_path",
    "task_path_normalized",
    "task_name_basis",
    "uri",
    "is_microsoft",
    "microsoft_basis",
    "run_as",
    "run_as_sid",
    "run_as_kind",
    "run_as_element",
    "run_level",
    "logon_type",
    "enabled",
    "enabled_state",
    "hidden",
    "hidden_state",
    "author",
    "task_description",
    "account_role",
    "actor_account",
    "actor_sid",
    "actor_domain",
    "actor_logon_id",
    "run_user_raw",
    "run_user_sid",
    "instance_id",
    "task_instance_id",
    "action_name",
    "engine_pid",
    "reported_process_id",
    "queued_instance_id",
    "event_category",
    "launch_reason",
    "result",
    "result_basis",
    "result_code",
    "result_code_raw",
    "result_code_format",
    "event_id",
    "provider",
    "channel",
    "computer",
    "event_record_id",
    "level_name",
    "keywords_raw",
    "process_id",
    "thread_id",
    "system_user_sid",
    "activity_id",
    "related_activity_id",
    "event_data_raw",
    "payload_state",
    "record_key",
    "source_file",
    "source_format",
    "format_basis",
    "encoding",
    "decode_status",
    "decode_replacements",
    "raw_size",
    "raw_sha256",
    "raw_content",
    "raw_bytes_hex",
    "registration_date",
    "registration_date_raw",
    "job_last_run",
    "job_last_run_raw",
    "task_version",
    "task_namespace",
    "root_children",
    "actions_context",
    "data_raw",
    "job_header_json",
    "parse_status",
    "parse_error",
    "parse_error_location",
    "action_count",
    "trigger_count",
    "setting_count",
    "principal_count",
    "action_summary",
    "trigger_type_summary",
    "review_signal_count",
    "review_signals",
    "search_text",
];

const SOURCE_RECORDS: &[&str] = &[
    "record_id",
    "ordinal",
    "source_dataset_id",
    "source_artifact",
    "source_db",
    "source_table",
    "source_rowid",
    "source_field",
    "source_record_key",
    "source_file",
    "source_label",
];

const TASK_ACTIONS: &[&str] = &[
    "record_id",
    "ordinal",
    "action_type",
    "action_id",
    "command",
    "command_resolved",
    "arguments",
    "working_directory",
    "class_id",
    "com_data",
    "detail_json",
    "raw_action",
];

const TASK_TRIGGERS: &[&str] = &[
    "record_id",
    "ordinal",
    "trigger_type",
    "trigger_id",
    "enabled",
    "start_time",
    "start_time_raw",
    "end_time",
    "end_time_raw",
    "repetition_interval",
    "repetition_duration",
    "repetition_stop_at_end",
    "execution_time_limit",
    "delay",
    "random_delay",
    "schedule_kind",
    "schedule_raw",
    "subscription",
    "state_name",
    "user_id",
    "session_change_type",
    "raw_trigger",
];

const TASK_SETTINGS: &[&str] = &[
    "record_id",
    "ordinal",
    "setting_group",
    "setting_path",
    "setting_name",
    "value_raw",
    "value_source",
];

const TASK_PRINCIPALS: &[&str] = &[
    "record_id",
    "ordinal",
    "principal_id",
    "principal_element",
    "user_id",
    "group_id",
    "principal_kind",
    "account",
    "account_sid",
    "logon_type",
    "run_level",
    "display_name",
    "process_token_sid_type",
    "required_privileges",
    "raw_principal",
];

const TASK_EVENT_FIELDS: &[&str] = &["record_id", "ordinal", "field_name", "field_value"];

const TASK_REVIEW_SIGNALS: &[&str] = &[
    "record_id",
    "ordinal",
    "signal",
    "basis",
    "evidence_value",
    "action_ordinal",
];

const TASK_REGISTRY_ENTRIES: &[&str] = &[
    "entry_id",
    "host_id",
    "dataset_id",
    "scope",
    "guid",
    "registry_path",
    "key_last_write",
    "tree_path",
    "task_uri",
    "task_path_normalized",
    "security_descriptor",
    "hash_hex",
    "id_value",
    "index_value",
    "schema_value",
    "version_value",
    "triggers_hex",
    "actions_hex",
    "dynamic_info_hex",
    "user_sid",
    "matched_record_id",
    "match_status",
    "match_basis",
    "tree_node_state",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const TASK_COM_REGISTRATIONS: &[&str] = &[
    "registration_id",
    "host_id",
    "dataset_id",
    "record_id",
    "action_ordinal",
    "class_id",
    "hive",
    "hive_scope",
    "registry_view",
    "key_path",
    "server_kind",
    "class_name",
    "server_path_raw",
    "server_path_resolved",
    "threading_model",
    "key_last_write",
    "match_status",
    "match_basis",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const TASK_LIVE_SNAPSHOT: &[&str] = &[
    "snapshot_id",
    "host_id",
    "dataset_id",
    "entry_index",
    "name",
    "task_path_normalized",
    "task_description",
    "command",
    "triggers_text",
    "account_reported",
    "signature_reported",
    "signer",
    "sign_timestamp",
    "signer2",
    "sign_timestamp2",
    "raw_json",
    "matched_record_id",
    "match_status",
    "match_basis",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const TASK_FILE_EVIDENCE: &[&str] = &[
    "evidence_id",
    "host_id",
    "dataset_id",
    "record_id",
    "action_ordinal",
    "evidence_kind",
    "collected_path",
    "collected_name",
    "collected_size",
    "collected_sha256",
    "command_raw",
    "command_resolved",
    "match_status",
    "match_basis",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
    "source_file",
];

const TASK_LOG_OBSERVATIONS: &[&str] = &[
    "observation_id",
    "host_id",
    "dataset_id",
    "observation_kind",
    "log_name",
    "source_file",
    "facts_db",
    "facts_table",
    "facts_generation",
    "collection_state",
    "input_row_count",
    "event_count",
    "task_event_count",
    "corrupted_count",
    "untimed_count",
    "first_observed_time",
    "last_observed_time",
    "error",
    "source_dataset_id",
    "source_db",
    "source_table",
    "source_rowid",
];

pub(super) const SPEC: DbSpec = DbSpec {
    name: "ScheduledTasks",
    table: "ScheduledTasks",
    columns: MAIN,
    children: &[
        ChildSpec { table: "source_records", columns: SOURCE_RECORDS },
        ChildSpec { table: "TaskActions", columns: TASK_ACTIONS },
        ChildSpec { table: "TaskTriggers", columns: TASK_TRIGGERS },
        ChildSpec { table: "TaskSettings", columns: TASK_SETTINGS },
        ChildSpec { table: "TaskPrincipals", columns: TASK_PRINCIPALS },
        ChildSpec { table: "TaskEventFields", columns: TASK_EVENT_FIELDS },
        ChildSpec { table: "TaskReviewSignals", columns: TASK_REVIEW_SIGNALS },
        ChildSpec { table: "TaskRegistryEntries", columns: TASK_REGISTRY_ENTRIES },
        ChildSpec { table: "TaskLiveSnapshot", columns: TASK_LIVE_SNAPSHOT },
        ChildSpec { table: "TaskComRegistrations", columns: TASK_COM_REGISTRATIONS },
        ChildSpec { table: "TaskFileEvidence", columns: TASK_FILE_EVIDENCE },
        ChildSpec { table: "TaskLogObservations", columns: TASK_LOG_OBSERVATIONS },
    ],
    ddl: DDL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derived::{stamp_facts_generation, FactsIndex, MetaLookup};
    use crate::parsers::taskscheduler;
    use rusqlite::Connection;

    const MICROSOFT_TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>Microsoft\Windows\Maintenance\Run</URI>
    <Author>Microsoft Corporation</Author>
    <Description>정기 점검</Description>
  </RegistrationInfo>
  <Triggers><BootTrigger><Delay>PT1M</Delay></BootTrigger></Triggers>
  <Principals><Principal id="Author"><GroupId>S-1-5-32-545</GroupId></Principal></Principals>
  <Settings><Hidden>true</Hidden><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c sync -EncodedCommand ZQA=</Arguments></Exec>
    <ComHandler><ClassId>{AAAAAAAA-1111-2222-3333-444444444444}</ClassId><Data>blob</Data></ComHandler>
  </Actions>
</Task>"#;

    const DATED_TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Custom\Updater</URI><Date>2026-02-03T04:05:06</Date><Author>LAB\analyst</Author></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2026-02-04T01:00:00</StartBoundary></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions><Exec><Command>C:\dist\BackupAgent.exe</Command></Exec></Actions>
</Task>"#;

    struct Case {
        root: std::path::PathBuf,
        target: std::path::PathBuf,
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Build a host output folder whose TaskScheduler facts come from the real
    /// parser, so the facts/derived contract is exercised end to end.
    fn case(label: &str, tasks: &[(&str, &str)]) -> Case {
        let root = std::env::temp_dir().join(format!("wina-task-{label}-{}", uuid::Uuid::new_v4()));
        let target = root.join("target");
        let task_dir = target.join("NonVolatile/TASKS_SYSTEM32/Tasks");
        std::fs::create_dir_all(&task_dir).unwrap();
        for (name, xml) in tasks {
            let mut raw: Vec<u8> = vec![0xFF, 0xFE];
            raw.extend(xml.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
            std::fs::write(task_dir.join(name), raw).unwrap();
        }
        let (_, rows) = taskscheduler::parse_tasks_with_sources(&target).unwrap();
        let facts = root.join(DEFINITION_FACTS);
        std::fs::create_dir_all(facts.parent().unwrap()).unwrap();
        crate::sqlite::write_fixed_table(
            &facts,
            DEFINITION_TABLE,
            rows,
            taskscheduler::TASK_FIELD_ORDER,
        )
        .unwrap();
        stamp_facts_generation(&facts, "facts-old").unwrap();
        super::super::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        Case { root, target }
    }

    fn ctx_of(case: &Case) -> Ctx<'_> {
        Ctx {
            out_dir: &case.root,
            target: &case.target,
            host_id: "host",
            dataset_id: "new",
            facts: FactsIndex::load(&case.root).unwrap(),
            meta: MetaLookup::load(&case.root).unwrap(),
        }
    }

    fn open(case: &Case) -> Connection {
        Connection::open(case.root.join("_OVERVIEW/ScheduledTasks.sqlite")).unwrap()
    }

    fn empty_events() -> EventLogOverviewCache {
        EventLogOverviewCache::from_rows_for_tests(Vec::new())
    }

    fn event(id: &str, provider: &str, index: usize, time: &str, payload: &str) -> Row {
        Row::from([
            ("Provider".into(), provider.into()),
            (
                "Channel".into(),
                if provider == SECURITY_PROVIDER {
                    "Security".into()
                } else {
                    "Microsoft-Windows-TaskScheduler/Operational".to_string()
                },
            ),
            ("Computer".into(), "HOST".into()),
            ("EventID".into(), id.into()),
            ("EventRecordID".into(), index.to_string()),
            ("timestamp".into(), time.into()),
            ("EventData".into(), payload.into()),
            (
                "_record_key".into(),
                format!(
                    "{}::{index}",
                    if provider == SECURITY_PROVIDER {
                        "Security"
                    } else {
                        "Microsoft-Windows-TaskScheduler%4Operational"
                    }
                ),
            ),
            ("_source_file".into(), "log.evtx".into()),
        ])
    }

    /// Event facts must exist for provenance; create the table the keys point at.
    fn event_facts(case: &Case, stem: &str, rows: usize) {
        let dir = case.root.join("EVENTLOG");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{stem}.sqlite"));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE {} (EventData TEXT);",
            crate::sqlite::quote_ident(stem)
        ))
        .unwrap();
        for _ in 0..rows {
            conn.execute(
                &format!("INSERT INTO {} VALUES('{{}}')", crate::sqlite::quote_ident(stem)),
                [],
            )
            .unwrap();
        }
        drop(conn);
        stamp_facts_generation(&path, "events-old").unwrap();
    }

    #[test]
    fn definition_keeps_untimed_rows_declared_values_and_full_original() {
        let case = case(
            "definition",
            &[("Run", MICROSOFT_TASK), ("Updater", DATED_TASK)],
        );
        let ctx = ctx_of(&case);
        assert_eq!(build(&ctx, &empty_events()).unwrap(), 2);
        let db = open(&case);

        // R01/R04: no registration date stays NULL and keeps its own state.
        let (timestamp, state, meaning): (Option<String>, String, Option<String>) = db
            .query_row(
                "SELECT timestamp,timestamp_state,timestamp_meaning FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(timestamp, None);
        assert_eq!(state, "unrecorded");
        assert_eq!(meaning.as_deref(), Some("none"));
        let (kind, date): (String, String) = db
            .query_row(
                "SELECT timestamp_kind,registration_date_raw FROM ScheduledTasks WHERE task_name='Updater'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(kind.contains("등록"));
        assert_eq!(date, "2026-02-03T04:05:06");

        // R03: a URI without the leading separator is still a Microsoft path.
        let (is_microsoft, basis, normalized, uri): (i64, String, String, String) = db
            .query_row(
                "SELECT is_microsoft,microsoft_basis,task_path_normalized,uri FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(is_microsoft, 1);
        assert_eq!(basis, "task_path_and_author");
        assert_eq!(normalized, "\\microsoft\\windows\\maintenance\\run");
        assert_eq!(uri, "Microsoft\\Windows\\Maintenance\\Run");

        // Declared vs not declared, never overwritten by a schema default.
        let (enabled, enabled_state): (Option<i64>, String) = db
            .query_row(
                "SELECT enabled,enabled_state FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((enabled, enabled_state.as_str()), (None, "not_declared"));
        let default: (String, String) = db
            .query_row(
                "SELECT value_raw,value_source FROM TaskSettings s JOIN ScheduledTasks t USING(record_id)
                 WHERE t.task_name='Run' AND s.setting_name='Enabled'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(default, ("true".into(), "schema_default".into()));
        let declared: (String, String) = db
            .query_row(
                "SELECT value_raw,value_source FROM TaskSettings s JOIN ScheduledTasks t USING(record_id)
                 WHERE t.task_name='Run' AND s.setting_name='Hidden'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(declared, ("true".into(), "declared".into()));

        // R14: a group principal is not an account.
        let (account, account_sid, kind, element): (Option<String>, Option<String>, String, String) = db
            .query_row(
                "SELECT account,account_sid,run_as_kind,run_as_element FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(account, None);
        assert_eq!(account_sid.as_deref(), Some("S-1-5-32-545"));
        assert_eq!((kind.as_str(), element.as_str()), ("group", "GroupId"));
        let principal: (String, Option<String>) = db
            .query_row(
                "SELECT p.principal_kind,p.account FROM TaskPrincipals p JOIN ScheduledTasks t USING(record_id)
                 WHERE t.task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(principal, ("group".into(), None));

        // A03: COM handler keeps its class id out of the command column.
        let com: (Option<String>, String, Option<String>) = db
            .query_row(
                "SELECT command,class_id,com_data FROM TaskActions a JOIN ScheduledTasks t USING(record_id)
                 WHERE t.task_name='Run' AND a.action_type='ComHandler'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(com.0, None);
        assert_eq!(com.1, "{AAAAAAAA-1111-2222-3333-444444444444}");
        assert!(com.2.unwrap().contains("blob"));

        // R13: review signals are stored, counted and summarised once.
        let (count, names): (i64, String) = db
            .query_row(
                "SELECT review_signal_count,review_signals FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 3);
        assert!(names.contains("script_host_command"));
        assert!(names.contains("encoded_command_argument"));
        assert!(names.contains("hidden_declared"));
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM TaskReviewSignals",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );

        // R02: parent search covers command, arguments, trigger and description.
        for needle in ["cmd.exe", "EncodedCommand", "BootTrigger", "정기 점검"] {
            let hits: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM ScheduledTasks WHERE search_text LIKE '%'||?1||'%'",
                    [needle],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(hits, 1, "{needle}");
        }

        // R08: the overview holds the whole original and its identity.
        let (format, encoding, size, hash, content): (String, String, i64, String, String) = db
            .query_row(
                "SELECT source_format,encoding,raw_size,raw_sha256,raw_content FROM ScheduledTasks WHERE task_name='Run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(format, "xml");
        assert_eq!(encoding, "utf-16le-bom");
        assert_eq!(hash.len(), 64);
        assert!(size > 0);
        assert!(content.contains("<ComHandler>"));

        // Original facts generation survives; no FK damage.
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM source_records WHERE source_dataset_id<>'facts-old'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn legacy_facts_schema_requires_reparse() {
        let case = case("legacy", &[("Run", MICROSOFT_TASK)]);
        let facts = case.root.join(DEFINITION_FACTS);
        let conn = Connection::open(&facts).unwrap();
        conn.execute_batch(
            "DROP TABLE TaskScheduler_Tasks;
             CREATE TABLE TaskScheduler_Tasks(timestamp TEXT, task_name TEXT, uri TEXT, actions_json TEXT);
             INSERT INTO TaskScheduler_Tasks VALUES('', 'Run', '\\Run', '[]');",
        )
        .unwrap();
        drop(conn);
        let ctx = ctx_of(&case);
        let error = build(&ctx, &empty_events()).unwrap_err().to_string();
        assert!(error.contains("다시 파싱"), "{error}");
        assert!(error.contains("raw_sha256"), "{error}");
    }

    #[test]
    fn no_input_still_publishes_typed_schema() {
        let root = std::env::temp_dir().join(format!("wina-task-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        super::super::create_database(&root.join("_OVERVIEW"), "Metadata").unwrap();
        let case = Case {
            target: root.join("target"),
            root,
        };
        std::fs::create_dir_all(&case.target).unwrap();
        let ctx = ctx_of(&case);
        assert_eq!(build(&ctx, &empty_events()).unwrap(), 0);
        let db = open(&case);
        for table in [
            "ScheduledTasks",
            "TaskActions",
            "TaskTriggers",
            "TaskSettings",
            "TaskPrincipals",
            "TaskEventFields",
            "TaskReviewSignals",
            "TaskRegistryEntries",
            "TaskLiveSnapshot",
            "TaskFileEvidence",
            "source_records",
        ] {
            let rows: i64 = db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
        // The definition input itself is still reported as not collected.
        let state: String = db
            .query_row(
                "SELECT collection_state FROM TaskLogObservations WHERE observation_kind='task_definition_input'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "not_collected");
    }

    // RD-02: an invalid audited task XML keeps its payload status even though
    // the facts row itself reads `_status=ok`.
    #[test]
    fn audited_xml_parse_failure_is_not_overwritten_by_facts_status() {
        let case = case("audit-invalid", &[]);
        event_facts(&case, "Security", 1);
        let mut row = event(
            "4698",
            SECURITY_PROVIDER,
            1,
            "2026-02-07 04:00:00.000",
            &serde_json::json!({
                "SubjectUserName": "analyst",
                "TaskName": "\\Custom\\Broken",
                "TaskContent": "<Task><Actions><Exec>",
            })
            .to_string(),
        );
        row.insert("_status".into(), "ok".into());
        let events = EventLogOverviewCache::from_rows_for_tests(vec![row]);
        let ctx = ctx_of(&case);
        assert_eq!(build(&ctx, &events).unwrap(), 1);
        let (status, error): (String, Option<String>) = open(&case)
            .query_row(
                "SELECT parse_status,parse_error FROM ScheduledTasks WHERE event_id=4698",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(error.is_some(), "the XML failure must be recorded");
        assert_eq!(status, "invalid_format");
    }

    #[test]
    fn events_keep_roles_results_and_payload_fields() {
        let case = case("events", &[("Updater", DATED_TASK)]);
        event_facts(&case, "Microsoft-Windows-TaskScheduler%4Operational", 6);
        event_facts(&case, "Microsoft-Windows-TaskScheduler%4Maintenance", 1);
        event_facts(&case, "Security", 1);
        let events = EventLogOverviewCache::from_rows_for_tests(vec![
            event(
                "102",
                TASK_PROVIDER,
                1,
                "2026-02-05 01:00:00.000",
                r#"{"TaskName":"\\Custom\\Updater","UserContext":"SYSTEM","InstanceId":"{1}"}"#,
            ),
            event(
                "201",
                TASK_PROVIDER,
                2,
                "2026-02-05 01:00:05.000",
                r#"{"TaskName":"\\Custom\\Updater","ActionName":"C:\\dist\\BackupAgent.exe","ResultCode":"2147942402","TaskInstanceId":"{1}"}"#,
            ),
            event(
                "141",
                TASK_PROVIDER,
                3,
                "2026-02-06 02:00:00.000",
                r#"{"TaskName":"\\Custom\\Updater","UserName":"LAB\\analyst"}"#,
            ),
            event(
                "999",
                TASK_PROVIDER,
                4,
                "2026-02-06 03:00:00.000",
                r#"{"TaskName":"\\Custom\\Updater","Unusual":"keep me"}"#,
            ),
            event(
                "4698",
                SECURITY_PROVIDER,
                1,
                "2026-02-07 04:00:00.000",
                &serde_json::json!({
                    "SubjectUserSid": "S-1-5-21-1-2-3-1001",
                    "SubjectUserName": "analyst",
                    "SubjectDomainName": "LAB",
                    "SubjectLogonId": "0x364eb",
                    "TaskName": "\\Custom\\Audited",
                    "TaskContent": DATED_TASK,
                })
                .to_string(),
            ),
            // A stored empty payload and a missing one are different evidence.
            event("400", TASK_PROVIDER, 5, "2026-02-08 05:00:00.000", ""),
            {
                let mut row = event("400", TASK_PROVIDER, 6, "2026-02-08 06:00:00.000", "");
                row.remove("EventData");
                row
            },
            // Maintenance channel (automatic maintenance state) is not stored.
            {
                let mut row = event(
                    "808",
                    TASK_PROVIDER,
                    1,
                    "2026-02-09 07:00:00.000",
                    r#"{"MaintenanceTaskWakeupRequested":{"Task":"NT TASK\\Custom\\Updater"}}"#,
                );
                row.insert(
                    "Channel".into(),
                    "Microsoft-Windows-TaskScheduler/Maintenance".into(),
                );
                row.insert(
                    "_record_key".into(),
                    "Microsoft-Windows-TaskScheduler%4Maintenance::1".into(),
                );
                row
            },
        ]);
        let ctx = ctx_of(&case);
        assert_eq!(build(&ctx, &events).unwrap(), 8);
        let db = open(&case);

        // R10: scheduler completion and action completion are different facts.
        let completion: (String, String, String) = db
            .query_row(
                "SELECT event_type,result,result_basis FROM ScheduledTasks WHERE event_id=102",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(completion.0, "작업 완료");
        assert_eq!(completion.1, "스케줄러 완료");
        assert_eq!(completion.2, "event_102_scheduler_finished_instance");
        let action: (String, i64, String, String) = db
            .query_row(
                "SELECT result,result_code,result_code_raw,result_code_format FROM ScheduledTasks WHERE event_id=201",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(action.0, "동작 완료");
        assert_eq!(action.1, 2147942402);
        assert_eq!(action.2, "2147942402");
        assert_eq!(action.3, "decimal");

        // R09/R14: the deleting user is an actor, the run user is not.
        let actor: (String, String, Option<String>) = db
            .query_row(
                "SELECT account_role,actor_account,run_user_raw FROM ScheduledTasks WHERE event_id=141",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(actor.0, "event_actor");
        assert_eq!(actor.1, "LAB\\analyst");
        assert_eq!(actor.2, None);
        let run_user: (String, String) = db
            .query_row(
                "SELECT account_role,run_user_raw FROM ScheduledTasks WHERE event_id=102",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(run_user, ("event_run_user".into(), "SYSTEM".into()));

        // Undocumented IDs keep every payload field without a invented meaning.
        let unknown: (String, Option<String>) = db
            .query_row(
                "SELECT event_type,result FROM ScheduledTasks WHERE event_id=999",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unknown, ("작업 스케줄러 이벤트".into(), None));
        assert_eq!(
            db.query_row(
                "SELECT field_value FROM TaskEventFields f JOIN ScheduledTasks t USING(record_id)
                 WHERE t.event_id=999 AND f.field_name='Unusual'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "keep me"
        );

        // A01: the audited task XML becomes children of its own record and the
        // subject stays the actor, not the task's principal.
        let audit: (String, String, String, String, i64) = db
            .query_row(
                "SELECT event_type,account,account_sid,account_role,action_count FROM ScheduledTasks WHERE event_id=4698",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(audit.0, "작업 생성 감사");
        assert_eq!(audit.1, "analyst");
        assert_eq!(audit.2, "S-1-5-21-1-2-3-1001");
        assert_eq!(audit.3, "event_actor");
        assert_eq!(audit.4, 1);
        let audited_command: String = db
            .query_row(
                "SELECT command FROM TaskActions a JOIN ScheduledTasks t USING(record_id) WHERE t.event_id=4698",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audited_command, "C:\\dist\\BackupAgent.exe");
        // The definition row is still its own record.
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM ScheduledTasks WHERE evidence_kind='task_definition'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        // Maintenance channel records are excluded.
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM ScheduledTasks WHERE event_id=808",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        // A present-but-empty payload stays TEXT '', a missing one stays NULL.
        let states: Vec<(String, Option<String>)> = db
            .prepare(
                "SELECT payload_state,event_data_raw FROM ScheduledTasks WHERE event_id=400 ORDER BY timestamp",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            states,
            vec![
                ("present_empty".to_string(), Some(String::new())),
                ("absent".to_string(), None),
            ]
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn taskcache_entries_report_matches_and_missing_definitions() {
        let case = case("taskcache", &[("Updater", DATED_TASK)]);
        let registry = case.root.join("REGISTRY/SOFTWARE.sqlite");
        std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID-1}','URI','RegSz','\Custom\Updater',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID-1}','Hash','RegBinary','aabb','aabb','value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID-1}','SecurityDescriptor','RegSz','D:P(A;;FA;;;SY)',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Custom\Updater','Id','RegSz','{GUID-1}',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Ghost','Id','RegSz','{GUID-2}',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Boot\{GUID-1}','','','',NULL,'key','SOFTWARE');"#).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        let ctx = ctx_of(&case);
        build(&ctx, &empty_events()).unwrap();
        let db = open(&case);

        let matched: (String, Option<String>, String, String) = db
            .query_row(
                "SELECT scope,matched_record_id,match_status,security_descriptor FROM TaskRegistryEntries WHERE scope='tasks'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(matched.0, "tasks");
        assert!(matched.1.is_some());
        assert_eq!(matched.2, "matched_definition");
        assert_eq!(matched.3, "D:P(A;;FA;;;SY)");
        // A tree entry whose GUID has no Tasks key is reported, not judged.
        let ghost: String = db
            .query_row(
                "SELECT tree_node_state FROM TaskRegistryEntries WHERE tree_path='Ghost'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ghost, "tasks_key_missing");
        let generation: String = db
            .query_row(
                "SELECT source_dataset_id FROM TaskRegistryEntries WHERE scope='tasks'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generation, "registry-old");
    }

    /// A03: ComHandler ClassId ↔ same-host COM registrations, as candidates.
    #[test]
    fn com_handler_class_ids_link_to_registered_servers() {
        const ORPHAN_COM_TASK: &str = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Custom\Orphan</URI></RegistrationInfo>
  <Actions><ComHandler><ClassId>{BBBBBBBB-9999-8888-7777-666666666666}</ClassId></ComHandler></Actions>
</Task>"#;
        let case = case("com", &[("Run", MICROSOFT_TASK), ("Orphan", ORPHAN_COM_TASK)]);
        let registry = case.root.join("REGISTRY/SOFTWARE.sqlite");
        std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
        let ddl = "CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);";
        let rows = r#"
        INSERT INTO Registry VALUES('2026-03-01','\ROOT\Classes\CLSID\{AAAAAAAA-1111-2222-3333-444444444444}','(default)','RegSz','Demo Class',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-03-02','\ROOT\Classes\CLSID\{AAAAAAAA-1111-2222-3333-444444444444}\InprocServer32','(default)','RegSz','C:\Windows\System32\demo.dll',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-03-02','\ROOT\Classes\CLSID\{AAAAAAAA-1111-2222-3333-444444444444}\InprocServer32','ThreadingModel','RegSz','Both',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-03-02','\ROOT\Classes\Wow6432Node\CLSID\{AAAAAAAA-1111-2222-3333-444444444444}\InprocServer32','(default)','RegSz','C:\Windows\SysWOW64\demo.dll',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-03-02','\ROOT\Classes\CLSID\{CCCCCCCC-0000-0000-0000-000000000000}\InprocServer32','(default)','RegSz','C:\Windows\System32\other.dll',NULL,'value','SOFTWARE');"#;
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(&format!("{ddl}{rows}")).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        // RegBack copies must never become evidence.
        let regback = case.root.join("REGISTRY/SOFTWARE_RegBack.sqlite");
        let conn = Connection::open(&regback).unwrap();
        conn.execute_batch(&format!("{ddl}{rows}")).unwrap();
        drop(conn);
        stamp_facts_generation(&regback, "registry-old").unwrap();

        let ctx = ctx_of(&case);
        build(&ctx, &empty_events()).unwrap();
        let db = open(&case);

        let registrations: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, String)> = db
            .prepare(
                "SELECT class_id,server_kind,registry_view,server_path_raw,threading_model,match_status
                 FROM TaskComRegistrations ORDER BY registry_view, server_kind, class_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(registrations.len(), 4, "{registrations:?}");
        // Class root, native server and WOW view are separate candidates.
        assert!(registrations.iter().any(|row| row.1.is_none()
            && row.0 == "{AAAAAAAA-1111-2222-3333-444444444444}"
            && row.5 == "matched_registration"));
        assert!(registrations.iter().any(|row| row.1.as_deref() == Some("InprocServer32")
            && row.2.as_deref() == Some("native")
            && row.3.as_deref() == Some("C:\\Windows\\System32\\demo.dll")
            && row.4.as_deref() == Some("Both")));
        assert!(registrations.iter().any(|row| row.2.as_deref() == Some("wow6432node")
            && row.3.as_deref() == Some("C:\\Windows\\SysWOW64\\demo.dll")));
        // A ClassId without a collected registration is explicit, not silent.
        let orphan: (String, Option<String>, Option<String>) = db
            .query_row(
                "SELECT match_status,key_path,hive FROM TaskComRegistrations
                 WHERE class_id='{BBBBBBBB-9999-8888-7777-666666666666}'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(orphan, ("no_registration_found".into(), None, None));
        // Only the task's own ClassIds are stored, and never from RegBack.
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM TaskComRegistrations WHERE class_id LIKE '{CCCC%' OR hive LIKE '%RegBack%'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        // The link points at the COM action of the definition record.
        let link: (i64, String) = db
            .query_row(
                "SELECT c.action_ordinal, t.task_name FROM TaskComRegistrations c
                 JOIN ScheduledTasks t USING(record_id)
                 WHERE c.class_id='{AAAAAAAA-1111-2222-3333-444444444444}' AND c.server_kind='InprocServer32'
                   AND c.registry_view='native'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(link, (1, "Run".into()));
        assert_eq!(
            db.query_row(
                "SELECT source_dataset_id FROM TaskComRegistrations WHERE match_status='matched_registration' LIMIT 1",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "registry-old"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn collector_snapshot_and_exec_copies_stay_reported_evidence() {
        let case = case("snapshot", &[("Updater", DATED_TASK)]);
        let volatile = case.target.join("Volatile");
        std::fs::create_dir_all(&volatile).unwrap();
        let json = serde_json::json!({
            "title": ["Name","Description","Command","Triggers","Account","Signature","Signer","SignTimeStamp","Signer2","SignTimeStamp2"],
            "0": ["Custom\\Updater","","\"C:\\dist\\BackupAgent.exe\"","[한번] 2026-02-04T01:00:00","SYSTEM","FALSE","","","",""],
            "1": ["Only\\Live","","C:\\tmp\\other.exe","","","TRUE","Vendor","2026-01-01 00:00:00","",""]
        })
        .to_string();
        let mut raw: Vec<u8> = vec![0xFF, 0xFE];
        raw.extend(json.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
        std::fs::write(volatile.join("tasks.json"), raw).unwrap();
        let exec = case.target.join("NonVolatile/TASKS_SYSTEM32/Exec");
        std::fs::create_dir_all(&exec).unwrap();
        std::fs::write(exec.join("BackupAgent.exe"), b"MZ-collected").unwrap();
        std::fs::write(exec.join("unrelated.exe"), b"MZ-other").unwrap();

        let published = prepare_inputs(&case.root, &case.target, "new").unwrap();
        assert_eq!(published, vec![supplemental::SUPPLEMENTAL_DB.to_string()]);
        let ctx = ctx_of(&case);
        build(&ctx, &empty_events()).unwrap();
        let db = open(&case);

        // A05: the collector's report is stored as reported, with its own status.
        let matched: (String, String, Option<String>, String) = db
            .query_row(
                "SELECT name,signature_reported,matched_record_id,match_status FROM TaskLiveSnapshot WHERE name='Custom\\Updater'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(matched.1, "FALSE");
        assert!(matched.2.is_some());
        assert_eq!(matched.3, "matched_definition");
        let only_live: (String, Option<String>) = db
            .query_row(
                "SELECT match_status,matched_record_id FROM TaskLiveSnapshot WHERE name='Only\\Live'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(only_live, ("definition_not_collected".into(), None));

        // A06: a collected copy is linked by file name only, and says so.
        let copy: (String, String, i64, String) = db
            .query_row(
                "SELECT collected_name,match_status,collected_size,collected_sha256 FROM TaskFileEvidence
                 WHERE collected_name='BackupAgent.exe'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(copy.1, "file_name_match_only");
        assert_eq!(copy.2, 12);
        // Independently computed digest of the collected bytes (python hashlib).
        assert_eq!(
            copy.3,
            "27ef27c7d7b4fa6f6ea9a42eec89a13bf01e6cfd0a69c9a5b7304cb906b17a88"
        );
        let unmatched: (String, Option<String>) = db
            .query_row(
                "SELECT match_status,record_id FROM TaskFileEvidence WHERE collected_name='unrelated.exe'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unmatched, ("no_matching_action".into(), None));

        // A07: inputs are observed even when an event log never arrived.
        let kinds: Vec<(String, String)> = db
            .prepare("SELECT log_name,collection_state FROM TaskLogObservations WHERE observation_kind='supplemental_input' ORDER BY log_name")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            kinds,
            vec![
                ("collected_task_executables".to_string(), "collected".to_string()),
                ("collector_tasks_json".to_string(), "collected".to_string()),
            ]
        );
        let operational: String = db
            .query_row(
                "SELECT collection_state FROM TaskLogObservations
                 WHERE log_name='Microsoft-Windows-TaskScheduler%4Operational'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(operational, "unknown");
    }

    #[test]
    fn command_paths_resolve_with_the_task_user_environment() {
        const USER_TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-21-9-1009</UserId></Principal></Principals>
  <Actions><Exec><Command>%localappdata%\Microsoft\OneDrive\Updater.exe</Command></Exec></Actions>
</Task>"#;
        const GROUP_TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Users"><GroupId>S-1-5-32-545</GroupId></Principal></Principals>
  <Actions><Exec><Command>%localappdata%\x.exe</Command></Exec><Exec><Command>%windir%\y.exe</Command></Exec></Actions>
</Task>"#;
        let case = case("userenv", &[("UserTask", USER_TASK), ("GroupTask", GROUP_TASK)]);
        let meta = Connection::open(case.root.join("_OVERVIEW/Metadata.sqlite")).unwrap();
        meta.execute_batch(
            "INSERT INTO metadata(metadata_id,host_id,dataset_id,kind,scope,key,value,resolution_status) VALUES
             ('m1','host','new','env','s-1-5-21-9-1009','localappdata','C:\\Users\\jait\\AppData\\Local','resolved'),
             ('m2','host','new','env','machine','windir','C:\\Windows','resolved');",
        )
        .unwrap();
        drop(meta);
        let ctx = ctx_of(&case);
        build(&ctx, &empty_events()).unwrap();
        let db = open(&case);
        let resolved = |task: &str| -> Vec<Option<String>> {
            db.prepare("SELECT a.command_resolved FROM TaskActions a JOIN ScheduledTasks t USING(record_id) WHERE t.task_name=?1 ORDER BY a.ordinal")
                .unwrap()
                .query_map([task], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        // The user principal's own environment resolves %localappdata%.
        assert_eq!(resolved("UserTask"), vec![Some("C:\\Users\\jait\\AppData\\Local\\Microsoft\\OneDrive\\Updater.exe".to_string())]);
        // A group principal has no user environment: user variables stay unresolved, machine ones resolve.
        assert_eq!(resolved("GroupTask"), vec![None, Some("C:\\Windows\\y.exe".to_string())]);
    }

    #[test]
    fn every_documented_launch_condition_event_has_a_meaning() {
        for id in 322..=332 {
            assert!(operational_meaning(&id.to_string()).is_some(), "event {id}");
        }
        assert_eq!(operational_meaning("325").unwrap().category, "condition");
    }

    #[test]
    fn job_repetition_minutes_become_trigger_durations() {
        let job = serde_json::json!({"interval_minutes": 15, "duration_minutes": 60, "raw": "0f003c00"});
        let cells = repetition_cells(&job);
        assert!(matches!(&cells[0], Cell::Text(t) if t == "PT15M"));
        assert!(matches!(&cells[1], Cell::Text(t) if t == "PT60M"));
        // No interval means the .job trigger does not repeat.
        let none = repetition_cells(&serde_json::json!({"interval_minutes": 0, "duration_minutes": 0}));
        assert!(matches!(none[0], Cell::Null) && matches!(none[1], Cell::Null));
        let xml = serde_json::json!({"interval": "PT5M", "duration": "P1D", "stop_at_duration_end": true});
        let cells = repetition_cells(&xml);
        assert!(matches!(&cells[0], Cell::Text(t) if t == "PT5M"));
        assert!(matches!(&cells[1], Cell::Text(t) if t == "P1D"));
    }

    #[test]
    fn execution_time_limit_has_its_schema_default() {
        assert!(SETTING_DEFAULTS.contains(&("ExecutionTimeLimit", "PT72H")));
    }

    #[test]
    fn review_signal_summary_lists_each_kind_once() {
        let signal = |name| ReviewSignal {
            signal: name,
            basis: String::new(),
            evidence: String::new(),
            action_ordinal: None,
        };
        let signals = [
            signal("script_host_command"),
            signal("encoded_command_argument"),
            signal("script_host_command"),
        ];
        assert_eq!(
            review_signal_summary(&signals),
            "script_host_command, encoded_command_argument"
        );
    }

    #[test]
    fn tree_state_does_not_replace_definition_match() {
        let case = case("treestate", &[("Updater", DATED_TASK)]);
        let registry = case.root.join("REGISTRY/SOFTWARE.sqlite");
        std::fs::create_dir_all(registry.parent().unwrap()).unwrap();
        let conn = Connection::open(&registry).unwrap();
        conn.execute_batch(r#"CREATE TABLE Registry(last_write TEXT,key_path TEXT,value_name TEXT,value_type TEXT,value_data TEXT,value_data_hex TEXT,entry_kind TEXT,_source_file TEXT);
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Custom\Updater','Id','RegSz','{GUID-9}',NULL,'value','SOFTWARE');
        INSERT INTO Registry VALUES('2026-02-03','\ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Custom','SD','RegBinary','00','00','value','SOFTWARE');"#).unwrap();
        drop(conn);
        stamp_facts_generation(&registry, "registry-old").unwrap();
        let ctx = ctx_of(&case);
        build(&ctx, &empty_events()).unwrap();
        let db = open(&case);
        let row: (Option<String>, String, Option<String>) = db
            .query_row(
                "SELECT matched_record_id,match_status,tree_node_state FROM TaskRegistryEntries WHERE tree_path='Custom\\Updater'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(row.0.is_some());
        assert_eq!(row.1, "matched_definition");
        assert_eq!(row.2.as_deref(), Some("tasks_key_missing"));
        let folder: String = db
            .query_row(
                "SELECT tree_node_state FROM TaskRegistryEntries WHERE tree_path='Custom'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(folder, "folder_node");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_target_is_reported_as_scan_failure() {
        use std::os::unix::fs::PermissionsExt;
        let case = case("scanfail", &[("Updater", DATED_TASK)]);
        let locked = case.target.join("Locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = prepare_inputs(&case.root, &case.target, "new");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.unwrap();
        let conn = Connection::open(case.root.join(supplemental::SUPPLEMENTAL_DB)).unwrap();
        let rows: Vec<(String, String, Option<String>)> = conn
            .prepare("SELECT input_kind,status,error FROM TaskSupplementalInputs ORDER BY input_kind")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (kind, status, error) in rows {
            assert_eq!(status, "scan_failed", "{kind}");
            assert!(error.unwrap().contains("Locked"), "{kind}");
        }
    }
}
