//! Map existing analysis logic into typed overview rows and real provenance.
//! Structured child records come from facts, never split display strings.
use anyhow::Result;

use super::ancillary;
use super::schema::{self, DbSpec};
use super::{
    int, json_text, nz, text, text_raw, Cell, Ctx, DerivedDb, SourceRef,
};
use crate::overview::{self, EventLogOverviewCache, RegistryOverviewCache};
use crate::sqlite::Row;

fn g<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn spec_of(name: &str) -> &'static DbSpec {
    schema::spec(name).expect("문서에 없는 파생 DB")
}

// Prefer nested EventXML fields, then top-level EventData.
fn ed_field(map: &serde_json::Map<String, serde_json::Value>, name: &str) -> String {
    if let Some(serde_json::Value::Object(inner)) = map.get("EventXML") {
        let value = overview::jget(inner, name);
        if !value.is_empty() {
            return value;
        }
    }
    overview::jget(map, name)
}

fn source_of(
    ctx: &Ctx,
    row: &Row,
    key_field: &str,
    file_field: &str,
    label: &str,
) -> Result<Option<SourceRef>> {
    ctx.facts.source_from_record_key(
        g(row, key_field),
        None,
        nz(g(row, file_field)),
        nz(label),
    )
}

// Supplemental tables share a database, but retain distinct artifact names.
fn with_artifact(source: Option<SourceRef>, artifact: &str) -> Option<SourceRef> {
    source.map(|mut source| {
        source.artifact = artifact.to_string();
        source
    })
}

fn source_from_parts(
    ctx: &Ctx,
    relative: &str,
    table: &str,
    rowid: &str,
    file: Option<&str>,
    label: &str,
) -> Result<Option<SourceRef>> {
    let (Some(relative), Some(rowid)) = (nz(relative), nz(rowid)) else {
        return Ok(None);
    };
    let stem = std::path::Path::new(relative)
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_default();
    ctx.facts
        .source_from_record_key(&format!("{stem}::{table}::{rowid}"), None, file, nz(label))
}

// User-scoped expansion requires a SID, not an inferred account identity.
fn sid_of(raw: &str) -> Option<&str> {
    if super::is_sid(raw) {
        nz(raw)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Event-backed overviews
// ---------------------------------------------------------------------------

pub(super) fn build_event_backed(
    ctx: &Ctx,
    events: &EventLogOverviewCache,
) -> Result<Vec<(String, usize)>> {
    Ok(vec![
        ("ScheduledTasks".into(), super::scheduled_tasks::build(ctx, events)?),
        ("ServiceHistory".into(), super::service_history::build(ctx, events)?),
        ("SmbHistory".into(), super::smb_history::build(ctx, events)?),
        (
            "RemoteDesktopHistory".into(),
            super::remote_access::build(ctx, events)?,
        ),
        ("BitsHistory".into(), super::bits_history::build(ctx, events)?),
        ("FirewallHistory".into(), super::firewall_history::build(ctx, events)?),
        ("PowerShellHistory".into(), powershell_history(ctx, events)?),
        ("WerReports".into(), super::wer_reports::build(ctx, events)?),
        ("Defender".into(), super::defender::build(ctx, events)?),
        ("RdpCache".into(), rdp_cache(ctx)?),
    ])
}

// --- PowerShellHistory ------------------------------------------------------

fn powershell_history(ctx: &Ctx, events: &EventLogOverviewCache) -> Result<usize> {
    let spec = spec_of("PowerShellHistory");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "PowerShellHistory")?;
    for row in overview::build_powershell_history_with_events(ctx.out_dir, events) {
        let kind = g(&row, "kind");
        let account = g(&row, "account");
        let mut rec = ctx.record(spec);
        rec.timestamp(g(&row, "timestamp"), "이벤트 기록 시각");
        rec.set("event_type", text(kind));
        rec.set("description", text(g(&row, "script_block_status")));
        rec.set("console_history_status", text(g(&row, "console_history_status")));
        if let Some(status) = nz(g(&row, "console_history_status")) {
            rec.set("description", text(status));
        }
        let sid = sid_of(g(&row, "account_sid"));
        rec.account(sid.unwrap_or(account), &ctx.meta);
        rec.set("process", text(g(&row, "process")));
        rec.set("process_id", int(g(&row, "process_id")));
        rec.set("command", text_raw(g(&row, "command")));
        rec.set("script_block", text_raw(g(&row, "script_block")));
        rec.set("host_application", text_raw(g(&row, "host_application")));
        rec.set("event_id", int(g(&row, "event_id")));
        rec.set("provider", text(g(&row, "provider")));
        let script_path = g(&row, "script_path");
        rec.set("script_path", text(script_path));
        rec.set(
            "script_path_resolved",
            ctx.meta.resolve_path(script_path, sid.or_else(|| sid_of(account))),
        );
        rec.set("line_number", int(g(&row, "line_number")));
        rec.set("session_id", text(g(&row, "session_id")));
        rec.set("script_block_id", text(g(&row, "script_block_id")));
        rec.set("runspace_id", text(g(&row, "runspace_id")));
        for field in ["context_info", "error_message", "event_data"] {
            rec.set(field, text_raw(g(&row, field)));
        }
        for field in ["event_channel", "event_record_id", "script_block_status"] {
            rec.set(field, text(g(&row, field)));
        }
        for field in ["event_level", "script_block_expected_parts", "script_block_observed_parts"] {
            rec.set(field, int(g(&row, field)));
        }
        for field in ["script_block_missing", "script_block_conflicts", "script_block_anomalies"] {
            rec.set(field, json_text(g(&row, field)));
        }
        if let Some(parts) = row.get("script_block_parts") {
            let parts: Vec<Row> = serde_json::from_str(parts)?;
            for part in parts {
                let source = source_of(ctx, &part, "record_key", "_source_file", kind)?
                    .ok_or_else(|| anyhow::anyhow!("4104 조각의 원본 출처가 없습니다"))?;
                let source_ordinal = rec.sources.len() as i64;
                rec.source(Some(source));
                rec.child("PowerShellScriptParts", vec![
                    Cell::Int(source_ordinal),
                    text(g(&part, "timestamp")),
                    int(g(&part, "message_number")),
                    int(g(&part, "message_total")),
                    text_raw(g(&part, "script_block")),
                    text_raw(g(&part, "event_data")),
                    text(g(&part, "event_record_id")),
                ]);
            }
        } else if let Some(lines) = row.get("console_lines") {
            let lines: Vec<Row> = serde_json::from_str(lines)?;
            for line in lines {
                let source = source_of(ctx, &line, "record_key", "_source_file", kind)?
                    .ok_or_else(|| anyhow::anyhow!("콘솔 원본 줄의 출처가 없습니다"))?;
                let source_ordinal = rec.sources.len() as i64;
                rec.source(Some(source));
                rec.child("PowerShellConsoleLines", vec![
                    Cell::Int(source_ordinal),
                    int(g(&line, "line_number")),
                    Cell::Text(g(&line, "command").to_string()),
                ]);
            }
        } else {
            rec.source(source_of(ctx, &row, "record_key", "_source_file", kind)?);
        }
        for decoded in crate::powershell_decode::decode_commands(
            g(&row, "command"), g(&row, "host_application"),
        ) {
            rec.child("PowerShellEncodedCommands", vec![
                text(decoded.source_field),
                Cell::Text(decoded.encoded_command),
                decoded.decoded_command.map(Cell::Text).unwrap_or(Cell::Null),
                text(decoded.decode_method),
                text(decoded.decode_status),
                decoded.decode_error.map(Cell::Text).unwrap_or(Cell::Null),
            ]);
        }
        db.write(rec)?;
    }
    db.finish()
}

// --- RdpCache ---------------------------------------------------------------

fn rdp_cache(ctx: &Ctx) -> Result<usize> {
    let spec = spec_of("RdpCache");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "RdpCache")?;
    let facts = ctx.out_dir.join("RDPCACHE").join("RdpBitmapCache.sqlite");
    for row in overview::read_table_with_rowid(&facts, "RdpBitmapCache") {
        if g(&row, "kind") != "fragment" {
            continue;
        }
        let mut rec = ctx.record(spec);
        rec.set("event_type", text("fragment"));
        rec.account(g(&row, "account"), &ctx.meta);
        rec.set("source_file", text(g(&row, "source_file")));
        rec.set("fragment_index", int(g(&row, "fragment_index")));
        rec.set("tile_count", int(g(&row, "tile_count")));
        rec.set("width", int(g(&row, "width")));
        rec.set("height", int(g(&row, "height")));
        rec.set("rows", int(g(&row, "rows")));
        rec.set("cols", int(g(&row, "cols")));
        rec.set("image", text(g(&row, "image")));
        rec.set("status", text(g(&row, "_status")));
        rec.source(source_from_parts(
            ctx,
            "RDPCACHE/RdpBitmapCache.sqlite",
            "RdpBitmapCache",
            g(&row, "__source_rowid"),
            nz(g(&row, "_source_file")),
            "RDP 캐시 조각",
        )?);
        db.write(rec)?;
    }
    db.finish()
}

// ---------------------------------------------------------------------------
// Registry- and file-backed overviews
// ---------------------------------------------------------------------------

pub(super) fn build_registry_backed(
    ctx: &Ctx,
    registry: &RegistryOverviewCache,
    events: &EventLogOverviewCache,
) -> Result<Vec<(String, usize)>> {
    Ok(vec![
        ("ExecutionHistory".into(), execution_history(ctx, registry, events)?),
        ("RegistryFindings".into(), registry_findings(ctx, registry)?),
        ("TargetInfo".into(), target_info(ctx, registry, events)?),
        ("PathReferences".into(), path_references(ctx, registry)?),
        ("BrowserActivity".into(), super::browser_activity::build(ctx)?),
    ])
}

// --- ExecutionHistory -------------------------------------------------------

fn execution_history(ctx: &Ctx, registry: &RegistryOverviewCache, events: &EventLogOverviewCache) -> Result<usize> {
    let spec = spec_of("ExecutionHistory");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "ExecutionHistory")?;
    for row in overview::build_execution_history_with_registry(ctx.out_dir, registry, events)? {
        let evidence = g(&row, "source_artifact");
        let account = g(&row, "user");
        let program_path = g(&row, "program_path");
        let mut rec = ctx.record(spec);
        let time_kind = match evidence {
            "Amcache_Programs" | "Amcache_Files" => "Amcache 키 마지막 기록 시각",
            "UserAssist" | "BAM" | "Prefetch" => "마지막 실행 시각",
            "SRUM" => "리소스 사용 최초 관측 시각",
            "Timeline" => "활동 시작 시각",
            "WER" => "프로세스 시작 시각",
            _ => "실행 흔적 시각",
        };
        rec.timestamp(g(&row, "timestamp"), time_kind);
        rec.set("event_type", text(evidence));
        rec.account(account, &ctx.meta);
        rec.set("program_name", text(g(&row, "program_name")));
        rec.set("program_path", text(program_path));
        rec.set(
            "program_path_resolved",
            ctx.meta.resolve_path(program_path, sid_of(account)),
        );
        rec.set("run_count", int(g(&row, "run_count")));
        rec.set("focus_count", int(g(&row, "focus_count")));
        rec.set("focus_time_ms", int(g(&row, "focus_time_ms")));
        rec.set("publisher", text(g(&row, "publisher")));
        rec.set("sha1", text(g(&row, "sha1")));
        rec.set("prefetch_hash", text(g(&row, "prefetch_hash")));
        // Keep additional evidenced Prefetch execution times in source order.
        for slot in ["run_time_2", "run_time_3", "run_time_4", "run_time_5", "run_time_6", "run_time_7", "run_time_8"] {
            if let Some(value) = nz(g(&row, slot)) {
                rec.child("ExecutionTimes", vec![text(value)]);
            }
        }
        let device = g(&row, "volume_device_path");
        let serial = g(&row, "volume_serial_number");
        let created = g(&row, "volume_creation_time");
        if nz(device).is_some() || nz(serial).is_some() || nz(created).is_some() {
            rec.child(
                "ExecutionVolumes",
                vec![text(device), text(serial), text(created)],
            );
        }
        rec.source(ctx.facts.source_from_record_key(
            g(&row, "record_key"),
            None,
            nz(g(&row, "source_file")),
            nz(evidence),
        )?);
        db.write(rec)?;
    }
    execution_events(ctx, events, &mut db)?;
    db.finish()
}

fn execution_events(ctx: &Ctx, events: &EventLogOverviewCache, db: &mut DerivedDb) -> Result<()> {
    for row in events.rows() {
        let (event_type, time_kind, description) = match (g(row, "Provider"), g(row, "Channel"), g(row, "EventID")) {
            ("Microsoft-Windows-Security-Auditing", "Security", "4688") =>
                ("Security 4688", "프로세스 생성 시각", "새 프로세스 생성"),
            ("Microsoft-Windows-Shell-Core", "Microsoft-Windows-Shell-Core/Operational", "9707") =>
                ("Shell-Core 9707", "시작 명령 처리 시작 시각", "Run 키 명령 처리 시작"),
            _ => continue,
        };
        let data = overview::parse_eventdata(g(row, "EventData"));
        let mut rec = ctx.record(spec_of("ExecutionHistory"));
        rec.timestamp(g(row, "timestamp"), time_kind);
        rec.set("event_type", text(event_type));
        rec.set("description", text(description));
        rec.set("event_id", int(g(row, "EventID")));
        for (column, key) in [
            ("event_provider", "Provider"), ("event_channel", "Channel"),
            ("event_record_id", "EventRecordID"), ("event_process_id", "ProcessID"),
            ("event_thread_id", "ThreadID"), ("event_user_sid", "UserID"),
            ("event_computer", "Computer"), ("event_data", "EventData"),
        ] {
            rec.set(column, text_raw(g(row, key)));
        }
        if g(row, "EventID") == "4688" {
            let path = ed_field(&data, "NewProcessName");
            rec.set("program_name", text(path.rsplit(['\\', '/']).next().unwrap_or("")));
            rec.set("program_path", text_raw(&path));
            for (column, key) in [
                ("command_line", "CommandLine"), ("process_id", "NewProcessId"),
                ("parent_process_id", "ProcessId"), ("parent_process_path", "ParentProcessName"),
                ("subject_user_sid", "SubjectUserSid"), ("subject_user_name", "SubjectUserName"),
                ("subject_domain_name", "SubjectDomainName"), ("subject_logon_id", "SubjectLogonId"),
                ("target_user_sid", "TargetUserSid"), ("target_user_name", "TargetUserName"),
                ("target_domain_name", "TargetDomainName"), ("target_logon_id", "TargetLogonId"),
            ] {
                rec.set(column, text_raw(&ed_field(&data, key)));
            }
            let target_sid = ed_field(&data, "TargetUserSid");
            let target_name = ed_field(&data, "TargetUserName");
            let subject_sid = ed_field(&data, "SubjectUserSid");
            let valid_sid = |sid: &str| super::is_sid(sid) && !sid.eq_ignore_ascii_case("S-1-0-0");
            let has_target = valid_sid(&target_sid)
                || nz(&target_name).is_some_and(|name| name != "-");
            let sid = if has_target { &target_sid } else { &subject_sid };
            rec.set("account_role", text(if has_target { "target" } else { "creator" }));
            if valid_sid(sid) {
                rec.account(sid, &ctx.meta);
                rec.set("program_path_resolved", ctx.meta.resolve_path(&path, Some(sid)));
            } else {
                rec.set("program_path_resolved", ctx.meta.resolve_path(&path, None));
            }
        } else {
            rec.set("command_line", text_raw(&ed_field(&data, "Command")));
            // 9708 (processing stop) is not stored (user decision 2026-10-12).
            rec.set("account_role", text("event_subject"));
            if let Some(sid) = sid_of(g(row, "UserID")) {
                rec.account(sid, &ctx.meta);
            }
        }
        rec.source(ctx.facts.source_from_record_key(
            g(row, "_record_key"), None, nz(g(row, "_source_file")), Some(event_type),
        )?);
        db.write(rec)?;
    }
    Ok(())
}

// --- RegistryFindings -------------------------------------------------------

fn registry_findings(ctx: &Ctx, registry: &RegistryOverviewCache) -> Result<usize> {
    let spec = spec_of("RegistryFindings");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "RegistryFindings")?;
    for row in overview::build_registry_findings_with_registry(registry) {
        let subtype = g(&row, "subtype");
        let command = g(&row, "command");
        let account = g(&row, "user");
        let mut rec = ctx.record(spec);
        rec.timestamp(g(&row, "timestamp"), "키 기록 시각");
        rec.set("event_type", text(subtype));
        rec.account(account, &ctx.meta);
        rec.set("category", text(g(&row, "category")));
        rec.set("name", text(g(&row, "name")));
        rec.set("value", text_raw(g(&row, "value")));
        rec.set("status", text(g(&row, "status")));
        rec.set("detail", text(g(&row, "detail")));
        rec.set("key_path", text(g(&row, "key_path")));
        rec.set("source", text(g(&row, "source")));
        rec.set("command", text(command));
        rec.set(
            "command_resolved",
            ctx.meta.resolve_path(command, sid_of(account)),
        );
        rec.set("subtype", text(subtype));
        rec.set("properties", json_text(g(&row, "properties")));
        rec.source(source_of(ctx, &row, "record_key", "_source_file", g(&row, "category"))?);
        db.write(rec)?;
    }
    db.finish()
}

// --- TargetInfo -------------------------------------------------------------

// Unproven TargetInfo-to-metadata associations remain NULL.
fn metadata_ref(category: &str, name: &str) -> Option<(&'static str, String)> {
    match category {
        "Account" => Some(("account", name.to_lowercase())),
        "NetworkInterface" => Some(("network", name.to_lowercase())),
        "SystemInfo" => {
            let key = match name {
                "ComputerName" => "computer_name",
                "TimeZone" => "timezone_id",
                "ProductName" => "os_name",
                "CurrentVersion" => "os_version",
                "CurrentBuild" | "CurrentBuildNumber" => "os_build",
                _ => return None,
            };
            Some(("host", key.to_string()))
        }
        _ => None,
    }
}

/// A stored Account parent and the child ordinals already written for it.
/// Event children stream straight into the database, so no parent ever holds
/// the events it owns.
struct AccountParent {
    record_id: String,
    sid: String,
    /// Confirmed metadata name; empty when metadata never resolved one.
    name: String,
    sources: usize,
    events: usize,
    matches: usize,
}

// Account rows carry their SID in `name`; a non-SID row identifies no account.
fn account_parent(ctx: &Ctx, record_id: String, name: &str, sources: usize) -> Option<AccountParent> {
    let sid = sid_of(name)?;
    Some(AccountParent {
        record_id,
        name: ctx.meta.account_name(sid).unwrap_or_default(),
        sid: sid.to_string(),
        sources,
        events: 0,
        matches: 0,
    })
}

// Stream matched events and their provenance without retaining per-account payloads.
fn account_activity(
    ctx: &Ctx,
    events: &EventLogOverviewCache,
    accounts: &mut [AccountParent],
    db: &mut DerivedDb,
) -> Result<()> {
    if accounts.is_empty() {
        return Ok(());
    }
    for row in events.rows() {
        // One parse per event; the account set only filters its evidence.
        let evidence = crate::account_events::extract(
            g(row, "Provider"),
            g(row, "EventID"),
            g(row, "UserID"),
            g(row, "EventData"),
        );
        if evidence.is_empty() {
            continue;
        }
        let record_key = g(row, "_record_key");
        let channel = g(row, "Channel");
        let log = record_key.split("::").next().unwrap_or("");
        let mut source = None;
        for account in accounts.iter_mut() {
            let matched = crate::account_events::matching(&evidence, &account.sid, &account.name);
            if matched.is_empty() {
                continue;
            }
            let source = match &source {
                Some(source) => source,
                None => source.insert(ctx.facts.source_from_record_key(
                    record_key,
                    None,
                    nz(g(row, "_source_file")),
                    nz(channel).or(nz(log)),
                )?.ok_or_else(|| anyhow::anyhow!(
                    "Account event has no resolvable facts reference: {record_key}"
                ))?),
            };
            let source_ordinal = account.sources;
            account.sources += 1;
            db.insert_child(
                schema::SOURCE_RECORDS_TABLE,
                &source.values(&account.record_id, source_ordinal),
            )?;
            let event_ordinal = account.events;
            account.events += 1;
            db.insert_child(
                schema::TARGET_ACCOUNT_EVENTS_TABLE,
                &[
                    Cell::Text(account.record_id.clone()),
                    Cell::Int(event_ordinal as i64),
                    Cell::Int(source_ordinal as i64),
                    text(g(row, "timestamp")),
                    text_raw(channel),
                    int(g(row, "EventID")),
                    text_raw(g(row, "LevelName")),
                    int(g(row, "Level")),
                    text_raw(g(row, "Provider")),
                    text_raw(g(row, "Computer")),
                    int(g(row, "EventRecordID")),
                    int(g(row, "ProcessID")),
                    int(g(row, "ThreadID")),
                    text_raw(g(row, "UserID")),
                    // Malformed payloads stay whole — matching used UserID.
                    text_raw(g(row, "EventData")),
                    text_raw(g(row, "_status")),
                    text_raw(g(row, "_error")),
                ],
            )?;
            for hit in matched {
                let ordinal = account.matches;
                account.matches += 1;
                db.insert_child(
                    schema::TARGET_ACCOUNT_EVENT_MATCHES_TABLE,
                    &[
                        Cell::Text(account.record_id.clone()),
                        Cell::Int(ordinal as i64),
                        Cell::Int(event_ordinal as i64),
                        Cell::Text(hit.role.to_string()),
                        Cell::Text(if hit.is_sid { "sid" } else { "name" }.to_string()),
                        Cell::Text(hit.field.clone()),
                        Cell::Text(hit.value.clone()),
                    ],
                )?;
            }
        }
    }
    Ok(())
}

fn target_info(
    ctx: &Ctx,
    registry: &RegistryOverviewCache,
    events: &EventLogOverviewCache,
) -> Result<usize> {
    let spec = spec_of("TargetInfo");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "TargetInfo")?;
    let rows = overview::build_target_info_with_registry(registry);
    let mut accounts: Vec<AccountParent> = Vec::new();
    for row in rows {
        let category = g(&row, "category");
        let name = g(&row, "name");
        let mut rec = ctx.record(spec);
        let kind = match category {
            "Account" => "마지막 로그온 시각",
            "Network" => "마지막 연결 시각",
            _ => "확인 시각",
        };
        rec.timestamp(g(&row, "timestamp"), kind);
        rec.set("event_type", text(category));
        rec.set("category", text(category));
        rec.set("name", text(name));
        rec.set("value", text(g(&row, "value")));
        if category == "Account" {
            rec.account(name, &ctx.meta);
        }
        if let Some((kind, key)) = metadata_ref(category, name) {
            rec.set(
                "metadata_id",
                super::text_opt(ctx.meta.metadata_id(kind, "machine", &key)),
            );
        }
        let source = source_of(ctx, &row, "record_key", "_source_file", g(&row, "source_artifact"))?;
        // Event children continue the ordinals this parent's own sources use.
        let parent = (category == "Account").then(|| {
            account_parent(ctx, rec.record_id.clone(), name, usize::from(source.is_some()))
        });
        rec.source(source);
        db.write(rec)?;
        if let Some(parent) = parent.flatten() {
            accounts.push(parent);
        }
    }
    // Materialized hosts facts provide real rowid provenance.
    let ancillary_db = ancillary::ancillary_path(ctx.out_dir);
    for row in overview::read_table_with_rowid(&ancillary_db, ancillary::HOSTS_TABLE) {
        let mut rec = ctx.record(spec);
        rec.set("event_type", text("HostsFile"));
        rec.set("category", text("HostsFile"));
        rec.set("name", text(g(&row, "host_name")));
        rec.set("value", text(g(&row, "ip")));
        rec.set("description", text(g(&row, "raw_line")));
        rec.source(with_artifact(
            source_from_parts(
                ctx,
                ancillary::ANCILLARY_DB,
                ancillary::HOSTS_TABLE,
                g(&row, "__source_rowid"),
                nz(g(&row, "_source_file")),
                "hosts 파일 행",
            )?,
            ancillary::HOSTS_ARTIFACT,
        ));
        db.write(rec)?;
    }
    account_activity(ctx, events, &mut accounts, &mut db)?;
    db.finish()
}

// --- PathReferences ---------------------------------------------------------

fn path_references(ctx: &Ctx, registry: &RegistryOverviewCache) -> Result<usize> {
    let spec = spec_of("PathReferences");
    let mut db = DerivedDb::create(&ctx.overview_dir(), "PathReferences")?;
    for row in overview::build_path_references(ctx.out_dir, registry) {
        let kind = g(&row, "kind");
        let account = g(&row, "account");
        let target_path = g(&row, "target_path");
        let mut rec = ctx.record(spec);
        // Preserve which artifact supplied the representative timestamp.
        let timestamp_source = g(&row, "timestamp_source");
        let timestamp_kind = match timestamp_source {
            "destlist_accessed" => "DestList 마지막 사용 시각",
            "lnk_accessed" => "LNK 대상 접근 시각",
            _ => "원본 기록 시각",
        };
        rec.timestamp(g(&row, "timestamp"), timestamp_kind);
        rec.set("event_type", text(kind));
        rec.account(account, &ctx.meta);
        rec.set("path", text_raw(g(&row, "path")));
        rec.set("path_kind", text(g(&row, "path_kind")));
        rec.set("label", text_raw(g(&row, "label")));
        rec.set("target_path", text_raw(target_path));
        rec.set(
            "target_path_resolved",
            ctx.meta.resolve_path(target_path, sid_of(account)),
        );
        rec.set("target_drive_letter", text(g(&row, "target_drive_letter")));
        rec.set("app_id", text(g(&row, "app_id")));
        rec.set("jumplist_type", text(g(&row, "jumplist_type")));
        rec.set("arguments", text_raw(g(&row, "arguments")));
        rec.set("working_directory", text_raw(g(&row, "working_directory")));
        rec.set("machine_id", text_raw(g(&row, "machine_id")));
        rec.set("created_time", text(g(&row, "created_time")));
        rec.set("modified_time", text(g(&row, "modified_time")));
        // Usage evidence is independent of the representative timestamp.
        rec.set("access_count", int(g(&row, "access_count")));
        rec.set("lnk_accessed", text(g(&row, "lnk_accessed")));
        rec.set("destlist_accessed", text(g(&row, "destlist_accessed")));
        rec.set("timestamp_source", text(timestamp_source));
        rec.set("hostname", text_raw(g(&row, "hostname")));
        // JumpList carries coordinates; Shellbag carries a hive record key.
        let source = if nz(g(&row, "source_relative")).is_some() {
            source_from_parts(
                ctx,
                g(&row, "source_relative"),
                g(&row, "source_table"),
                g(&row, "source_rowid"),
                nz(g(&row, "_source_file")),
                kind,
            )?
        } else {
            source_of(ctx, &row, "record_key", "_source_file", kind)?
        };
        rec.source(source);
        db.write(rec)?;
    }
    super::artifact_paths::write(ctx, &mut db)?;
    db.finish()
}

