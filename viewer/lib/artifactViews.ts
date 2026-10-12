import { tagsForBoolean, tagsForDangerType, tagsForEventLevel, tagsForNameMismatch, tagsForPath, type Tag } from "./tagging";
import { resolveKnownFolderPath } from "@/lib/knownFolders";
import { MACHINE_SCOPE_LABEL, MACHINE_SCOPE_USER } from "@/lib/accountIdentity";
import { displayRegistryKeyPath } from "@/lib/registryPath";
import { executableNote } from "./executableCatalog";
import { ACCOUNT_ROLE_LABELS } from "./executionHistory";
import { lookupEventCatalog, parseEventData, extractEventField, extractPsClassicField, tagsForSecurityEvent, EVENT_QUICK_FIELDS, LOGON_TYPE_LABELS } from "./eventCatalog";

export type FieldKind = "text" | "path" | "code" | "hash" | "bytes" | "json" | "badge" | "privileges" | "accountSid" | "account" | "byteSize" | "durationMs" | "cacheData";

export interface FieldSpec {
  key: string;
  label?: string;
  kind?: FieldKind;
  /** Keep an evidence field visible even when this record has no value. */
  showWhenEmpty?: boolean;
  /** Evidence-specific fallback when an original source does not carry this field. */
  emptyLabel?: string;
  /** Field-level bookmarking is only enabled where the source contract
   * identifies a stable row + field (currently MFT SI/FN timestamps). */
  bookmarkable?: boolean;
  badgeColors?: Record<string, string>;
  /** 값과 무관하게 쓰는 고정 배지 색 — 문구가 가변적인 상태 표식용
   * (badgeColors의 정확 일치 매핑이 안 통하는 경우). */
  badgeColor?: string;
  /** Remap a raw coded value (e.g. "1") to a human label before display —
   * badge color lookups use the remapped label, not the raw code. */
  valueLabels?: Record<string, string>;
  /** Derive the display value from the whole row instead of reading
   * row[key] directly — used for values buried inside a JSON blob column
   * (e.g. a field nested in EventLog's EventData). When present, this
   * takes priority over row[key]; `key` still doubles as the React key
   * and copy-button source. */
  compute?: (row: Record<string, string>) => string | null | undefined;
}

export interface ComputedColumnSpec {
  key: string;
  label: string;
  compute: (row: Record<string, string>) => string;
  size?: number;
}

export interface TimelineFieldSpec {
  key: string;
  label: string;
}

export interface LinkSpec {
  key: string;
  label: string;
  targetFile: string;
  targetColumn: string;
}

export interface DetailSectionSpec {
  heading: string | ((row: Record<string, string>) => string);
  fields: FieldSpec[];
  /**
   * Keeps evidence-dense, repeated values (for example Prefetch run times)
   * out of the way until an analyst asks to inspect them.  The same section
   * definition is consumed by every RowDetailPanel, regardless of the view
   * that opened it.
   */
  collapsible?: {
    defaultExpanded?: boolean;
    summary?: (row: Record<string, string>, fieldCount: number) => string;
  };
}

/**
 * 상세 전용 자식 표(docs-01: ExecutionTimes·TaskActions·BitsFiles 등) 한 개.
 * 목록·검색에는 올리지 않고, 행 상세를 열 때만 그 행의 record_id로 조회한다.
 */
export interface ChildTableSpec {
  /** 같은 결과 DB 안의 자식 표 이름. */
  table: string;
  heading: string;
  /** 자식 행 한 건에서 보여 줄 컬럼. 비면 받은 컬럼을 그대로 보여 준다. */
  fields?: FieldSpec[];
  /** 자식 행 한 건을 한 줄로 요약한다. 없으면 필드 목록으로 표시한다. */
  summary?: (row: Record<string, string>) => string;
}

export interface ArtifactViewSpec {
  title: (row: Record<string, string>) => string;
  /** Optional compact title for the cross-artifact timeline. Detail panels
   * continue to use `title`, so their evidence framing can differ safely. */
  timelineTitle?: (row: Record<string, string>) => string;
  /** Optional secondary line for the cross-artifact timeline. This is kept
   * separate from detail-panel `subtitle` when their evidence roles differ. */
  timelineSubtitle?: (row: Record<string, string>) => string;
  subtitle?: (row: Record<string, string>) => string;
  /** Suppress the generic overview time when the artifact includes it in its
   * own concise evidence summary. */
  overviewTime?: "show" | "hide";
  badges?: FieldSpec[];
  tags?: (row: Record<string, string>) => Tag[];
  timelineFields?: TimelineFieldSpec[];
  /** The timeline's evidence source when its points are not generic activity
   * timestamps (for example, the three timestamps in an LNK header). */
  timelineHeading?: string;
  /**
   * Name of the row's leading time column, ONLY when this artifact belongs
   * in the cross-artifact Master Timeline. Absent on purpose for tables with
   * no meaningful single timestamp (e.g. Prefetch_LoadedFiles) and for the
   * _OVERVIEW correlation tables (already-derived summaries — including them
   * would double-count the same events alongside their raw source rows).
   */
  timelineField?: string;
  /** Optional record-level admission rule for the master timeline. This keeps
   * a mixed overview table usable without promoting every source record into
   * the chronological investigation view. */
  timelineInclude?: (row: Record<string, string>) => boolean;
  /** Related evidence rendered as an immediately loaded, queryable detail section. */
  embeddedLinks?: LinkSpec[];
  links?: LinkSpec[];
  sections: DetailSectionSpec[];
  /** 이 행에 딸린 상세 전용 자식 표. 행 상세에서만 조회한다. */
  childTables?: ChildTableSpec[];
  /**
   * Column order for the TABLE view — separate from CSV column order on
   * disk. The CSV always leads with time (that's the right convention for
   * the data file), but a table where 8 timestamp columns bury
   * `executable_filename` off-screen defeats the point of a table you
   * scan at a glance. List the columns that answer "what happened" here;
   * they're pulled to the front, everything else follows in file order.
   */
  priorityColumns?: string[];
  /**
   * Restrict the TABLE view to ONLY these columns (in this order). Other
   * columns stay in each row's data — so links, filter tabs, and the detail
   * panel still work — but aren't shown as table columns. Use when a curated
   * overview should surface just a few fields; leave unset to show all.
   */
  visibleColumns?: string[];
  /**
   * Quick success/failure-style tabs above the table that filter one column
   * to a fixed value. `value` omitted = the "전체"(all) tab. Great for an
   * overview table with a `result` column (성공/실패/정보).
   */
  filterTabs?: { column: string; tabs: { label: string; value?: string }[] };
  /**
   * Render this table as a session-grouped FLOW view (SessionFlowView)
   * instead of a flat data table — rows are clustered into sessions by
   * peer + account + time proximity so the connect→logon→disconnect
   * sequence reads as a flow. Used for RemoteDesktopHistory.
   */
  flowView?: boolean;
  /**
   * Render this overview table with a bespoke, non-tabular component instead
   * of a DataTable — the string names which one (see CUSTOM_VIEWS in page.tsx).
   * Overview correlations (TargetInfo, ...) read as summaries/dashboards, not
   * spreadsheets, so each gets a purpose-built view.
   */
  customView?: "targetInfo" | "executionHistory" | "powershellFlow" | "defender" | "registryFindings" | "rdpCache" | "browserHistory" | "smb" | "bits" | "service" | "firewall" | "scheduledTasks" | "wer" | "mft" | "usnJrnl";
  /**
   * In the sidebar, present this table split by this column: instead of one
   * row for the whole table, the category lists one entry per distinct value
   * (e.g. EventLog_Events by "_source_file" → Security.evtx, Application.evtx,
   * ...) plus a "전체" entry for the merged table. Clicking a split entry opens
   * the table filtered to that value. Purely a browsing convenience; the
   * underlying table is unchanged.
   */
  sidebarGroupColumn?: string;
  /**
   * Display transform for the raw sidebarGroupColumn values (which may be full
   * paths or opaque keys) — e.g. a full .evtx path → its "Security.evtx"
   * basename. The raw value is still what the click filters on.
   */
  sidebarGroupLabel?: (value: string) => string;
  /**
   * Synthetic table columns computed from the full row rather than read
   * directly off a CSV column — inserted right after the detail column,
   * ahead of every real column, so a derived "what happened" summary is
   * the first thing scanned instead of being buried behind raw fields.
   */
  computedColumns?: ComputedColumnSpec[];
}

// Shows both the raw number and its meaning, e.g. "캐시된 자격 증명 (타입 11)" —
// the number matters to analysts (it's what other tools/docs reference).
function formatLogonType(lt: string): string {
  const label = LOGON_TYPE_LABELS[lt];
  return label ? `${label} (타입 ${lt})` : `타입 ${lt}`;
}

// Logon events (4624 success / 4625 failure / 4648 explicit-cred) carry a
// LogonType inside EventData that decides what the logon actually WAS —
// network(3), RDP(10), console(2), etc. Returns "" for non-logon events or
// when the type is absent, so callers can treat it as "no qualifier".
function logonTypeLabel(r: Record<string, string>): string {
  if (!["4624", "4625", "4648"].includes(r.EventID)) return "";
  const lt = extractEventField(r, "LogonType");
  return lt ? formatLogonType(lt) : "";
}

function eventLogTimelineTitle(r: Record<string, string>): string {
  const catalog = lookupEventCatalog(r.Provider, r.EventID);
  const base = catalog ? `Event ${r.EventID} · ${catalog.label}` : `Event ${r.EventID}`;
  // On logon events the LogonType is the single most important qualifier
  // (network vs RDP vs console), so fold it straight into the timeline event.
  const logonType = logonTypeLabel(r);
  return logonType ? `${base} · ${logonType}` : base;
}

// Registry findings already retain their parser explanation in `detail` for
// the raw-field view. In the analyst-facing detail we expose that explanation
// only when the parser actually marked the finding for attention, and make it
// available as the tag hover text rather than duplicating it as a prose row.
// Informational and normal configuration rows intentionally stay untagged.
function tagsForRegistryFinding(r: Record<string, string>): Tag[] {
  if (!r.detail) return [];
  if (r.status === "의심") {
    return [{ label: "의심", severity: "danger", description: r.detail }];
  }
  if (r.status === "주의") {
    return [{ label: "주의", severity: "warning", description: r.detail }];
  }
  return [];
}

// Event ID 0 is emitted by several application providers for their own
// heartbeat/status messages. It is kept in the raw EventLog table so the
// evidence remains complete, but it has no stable investigation meaning on
// the cross-artifact timeline (where it can dominate the chronology).
function includeEventLogTimeline(r: Record<string, string>): boolean {
  return r.EventID.trim() !== "0";
}

function edField(jsonKey: string, label: string, opts: Partial<FieldSpec> = {}): FieldSpec {
  return {
    key: `EventData.${jsonKey}`,
    label,
    compute: (r) => {
      const data = parseEventData(r.EventData);
      const v = data?.[jsonKey];
      return v === undefined || v === null || v === "" ? undefined : String(v);
    },
    ...opts,
  };
}

const STATUS_COLORS: Record<string, string> = {
  ok: "#3fb950",
  live: "#3fb950",
  corrupted: "#f85149",
  corrupted_chunk: "#f85149",
  corrupted_record: "#f85149",
  unreadable_file: "#f85149",
  carved_deleted_cell: "#d29922",
};

const LEVEL_COLORS: Record<string, string> = {
  Critical: "#f85149",
  Error: "#f85149",
  Warning: "#d29922",
  Information: "#4fc1ff",
  Verbose: "#8a8a8a",
};

const BOOL_COLORS: Record<string, string> = {
  true: "#3fb950",
  True: "#3fb950",
  false: "#8a8a8a",
  False: "#8a8a8a",
};

const DIRECTION_COLORS: Record<string, string> = {
  inbound: "#d29922",
  outbound: "#4fc1ff",
};

const RDP_RESULT_COLORS: Record<string, string> = {
  "성공": "#3fb950",
  "실패": "#f85149",
  "정보": "#8a8a8a",
};

function basename(path: string | undefined): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

// JumpList collections preserve the source user in the path directly below
// either LNK or JUMPLIST. This mirrors the evidence-backed extraction used by
// the Tauri path-reference command; if the collection layout is absent, the
// value stays hidden instead of guessing an account.
function accountFromJumpListSource(path: string | undefined): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  for (let index = 0; index + 1 < parts.length; index += 1) {
    const collection = parts[index].toUpperCase();
    if (collection === "LNK" || collection === "JUMPLIST") return parts[index + 1];
  }
  return "";
}

type ExecutionEvidence = "amcache" | "userAssist" | "srum" | "bam" | "prefetch" | "processCreation" | "shellCore" | "other";

// 실행 이력 파생 행의 증거 종류는 event_type에 들어 있다(저장 계약 docs-01:
// 기존 source_artifact 값을 그대로 쓴다). 원본 연결은 source_records에 있고,
// 화면 분기를 위해 조인하지 않는다.
function executionEvidence(row: Record<string, string>): ExecutionEvidence {
  const source = (row.event_type || "").toLowerCase();
  if (source.startsWith("amcache")) return "amcache";
  if (source === "userassist") return "userAssist";
  if (source === "srum") return "srum";
  if (source === "bam") return "bam";
  if (source === "prefetch") return "prefetch";
  if (source === "security 4688") return "processCreation";
  if (source.startsWith("shell-core ")) return "shellCore";
  return "other";
}

function executionSourceLabel(row: Record<string, string>): string {
  switch (executionEvidence(row)) {
    case "amcache": return "Amcache";
    case "userAssist": return "UserAssist";
    case "srum": return "SRUM";
    case "bam": return "BAM";
    case "prefetch": return "Prefetch";
    // All EventLog channels share one label; event_type stays in 기록 정보.
    case "processCreation":
    case "shellCore": return "EventLog";
    default: return row.event_type || "ExecutionHistory";
  }
}

function executionValue(source: ExecutionEvidence, key: string, row: Record<string, string>): string {
  return executionEvidence(row) === source ? row[key] || "" : "";
}

function tagsForMissingAmcachePublisher(publisher: string | undefined): Tag[] {
  if (publisher?.trim()) return [];
  return [{
    label: "게시자 정보 없음",
    severity: "warning",
    description: "Amcache 레코드에 게시자(서명 메타데이터) 값이 없습니다. 서명·파일 평판과 함께 실행 파일의 출처를 추가 확인해야 합니다.",
  }];
}

// Windows Error Reporting (Application / Event 1001): the crash is described by
// EventName + the P1..P10 bucket parameters, whose meaning depends on EventName
// (APPCRASH: P1=app, P2=version, P4=faulting module, …). These helpers pull the
// human-relevant bits so the detail view names the crashed program and reason
// instead of a wall of P-fields.
function isWerEvent(r: Record<string, string>): boolean {
  return /Error Reporting/i.test(r.Provider || "") || (!!extractEventField(r, "EventName") && !!extractEventField(r, "P1"));
}
function werAppPath(r: Record<string, string>): string | undefined {
  const d = parseEventData(r.EventData);
  if (!d) return undefined;
  // A P-field sometimes carries the faulting exe's full path; ignore the WER
  // report temp folder (…\WER\…), which is bookkeeping, not the program.
  for (const v of Object.values(d)) {
    const s = String(v);
    if (/^[a-z]:\\.+\.(exe|dll|sys)$/i.test(s) && !/\\WER\\/i.test(s)) return s;
  }
  return undefined;
}
function werReason(r: Record<string, string>): string | undefined {
  const d = parseEventData(r.EventData);
  if (!d) return undefined;
  const resp = String(d.Response ?? "");
  const p3 = String(d.P3 ?? "");
  const p4 = String(d.P4 ?? "");
  const parts: string[] = [];
  if (resp && !/사용할 수 없|not ?available|^n\/?a$/i.test(resp)) parts.push(resp);
  if (p3) parts.push(p3);
  if (p4) parts.push(p4); // often an HRESULT like 0x80070002
  return parts.length ? parts.join(" · ") : undefined;
}

// UserAssist 값 이름은 ROT13으로 인코딩된 실행 파일 경로다.
function rot13(value: string): string {
  return value.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}
// 실행 파일 카탈로그 참고 태그 — 승격된 원본 레코드(Amcache·Prefetch·
// Registry·SRUM)에서도 실행 이력과 동일하게 표시한다.
function executableNoteTags(name: string | undefined): Tag[] {
  const note = name ? executableNote(name) : "";
  return note ? [{ label: note, severity: "info", description: "실행 파일 카탈로그 참고 — 공격자가 자주 쓰는 도구입니다. 실행 자체가 악성이라는 뜻은 아닙니다." }] : [];
}

function userAssistProgram(r: Record<string, string>): string {
  if (!/userassist/i.test(r.key_path || "") || !r.value_name) return "";
  const decoded = rot13(r.value_name);
  // GUID 접두({...}\...)는 알려진 폴더 표기 — 그대로 두되 경로로 읽히게 한다.
  return decoded;
}

// 저장 계약(docs-01)의 플래그는 0/1이고 미확인은 NULL이다. 화면은 모르는 값을
// 한쪽으로 단정하지 않고 "확인 불가"로 남긴다.
const MFT_DIRECTORY_LABELS: Record<string, string> = { "1": "디렉터리", "0": "파일" };
const MFT_IN_USE_LABELS: Record<string, string> = { "1": "사용 중 (할당됨)", "0": "미사용 (삭제됨)" };
const RECYCLE_R_EXISTS_LABELS: Record<string, string> = { "1": "수집본에 $R 있음", "0": "수집본에 $R 없음" };

// 볼륨 값은 파일마다 따로 있는 값이 아니라 $Volume 레코드의 값을 그 볼륨의
// 파일 행에 연결한 것이다. volume_id는 결과 안에서 볼륨 문맥을 구분하는 내부
// 키일 뿐, 실제로 같은 볼륨이라는 증거가 아니다(docs-01).
const MFT_VOLUME_FIELDS: FieldSpec[] = [
  { key: "volume_id", label: "볼륨 문맥(내부 키)", showWhenEmpty: true, emptyLabel: "확인된 볼륨 문맥 없음" },
  { key: "volume_label", label: "볼륨 레이블", showWhenEmpty: true, emptyLabel: "$Volume 근거 없음" },
  { key: "volume_serial", label: "볼륨 일련번호", showWhenEmpty: true, emptyLabel: "별도 증거 없음" },
  { key: "drive_letter", label: "드라이브 문자", showWhenEmpty: true, emptyLabel: "수집 메타데이터 근거 없음" },
  { key: "ntfs_major_version", label: "NTFS 주 버전" },
  { key: "ntfs_minor_version", label: "NTFS 부 버전" },
  { key: "volume_flags", label: "볼륨 상태 플래그" },
];

const VIEWS: Record<string, ArtifactViewSpec> = {
  // Windows Error Reporting — every report field lives in one `report` JSON
  // column; WerView parses it into fault-signature / loaded-modules sections.
  WER_Reports: {
    customView: "wer",
    title: (r) => r.AppName || "(WER)",
    // timestamp = 보고서의 EventTime(크래시 발생 시각). 악성코드 크래시·
    // 익스플로잇 실패 시각의 유일한 타임라인 공급원이라 편입한다 (T6 확정:
    // WER만 편입, RegistryFindings·CacheEntries·하이브 last_write는 제외 유지).
    timelineField: "timestamp",
    timelineTitle: (r) => r.AppName || basename(r.AppPath) || "(WER)",
    timelineSubtitle: (r) => [r.EventType, r.AppPath].filter(Boolean).join(" · "),
    priorityColumns: ["timestamp", "EventType", "AppName", "AppPath", "TargetAppId", "ReportIdentifier"],
    sections: [{ heading: "보고서", fields: [{ key: "EventType" }, { key: "AppPath" }, { key: "ReportIdentifier" }, { key: "app_pid", label: "프로세스 ID (PID)" }, { key: "app_start_time", label: "프로세스 시작 시각" }, { key: "app_uptime", label: "실행 유지 시간" }, { key: "fault_module", label: "오류 모듈" }, { key: "exception_code", label: "예외 코드" }, { key: "report", kind: "json" }] }],
  },
  // 오류 보고 통합 파생(_OVERVIEW/WerReports) — Report.wer 산출물과 EventLog
  // 오류 보고(1001)를 한 화면으로 합친다. 구성 원본(WER_Reports·EventLog)이
  // 각자 타임라인에 이미 편입돼 있으므로 여기서는 편입하지 않는다(중복 방지).
  WerReports: {
    customView: "wer",
    title: (r) => r.app_name || "(WER)",
    priorityColumns: ["timestamp", "error_type", "app_name", "app_path", "target_app_id", "report_identifier", "source"],
    sections: [{ heading: "보고서", fields: [
      { key: "error_type", label: "오류 유형" },
      { key: "app_name", label: "프로그램" },
      { key: "app_path", label: "프로그램 경로", kind: "path" },
      { key: "app_path_resolved", label: "프로그램 경로 (환경변수 해석)", kind: "path" },
      { key: "target_app_id", label: "대상 앱 ID" },
      { key: "report_identifier", label: "보고서 ID" },
      { key: "source", label: "출처" },
      { key: "app_pid", label: "프로세스 ID (PID)" },
      { key: "app_start_time", label: "프로세스 시작 시각" },
      // 단위가 확인된 값과 원문을 섞지 않는다(docs-01).
      { key: "app_uptime_ms", label: "실행 유지 시간", kind: "durationMs" },
      { key: "app_uptime", label: "실행 유지 시간 원문" },
      { key: "fault_module", label: "오류 모듈" },
      { key: "exception_code", label: "예외 코드" },
      { key: "report", label: "보고서 원문", kind: "json" },
    ] }],
  },
  // Windows Timeline (ActivitiesCache.db) — 계정별 앱 실행·포커스·문서 활동.
  // 실행/열기(type 5)는 실행 이력(ExecutionHistory)에도 합류한다.
  Timeline_Activities: {
    title: (r) => r.app_name || r.display_text || "(Timeline)",
    subtitle: (r) => r.kind || "",
    timelineField: "timestamp",
    // 실행/열기(type 5)는 ExecutionHistory로 승격되어 이미 타임라인에 있다 —
    // 여기서 제외해 한 사건이 두 번 보이지 않게 한다(사전 캐시와 동일 규칙).
    timelineInclude: (r) => r.activity_type !== "5",
    priorityColumns: ["timestamp", "kind", "app_name", "app_path", "display_text", "content_uri", "active_duration_s", "account"],
    sections: [
      { heading: "활동 정보", fields: [
        { key: "kind", label: "활동 유형", kind: "badge" },
        { key: "app_name", label: "앱 이름" },
        { key: "resolved_app_path", label: "실행 경로 (변환)", kind: "path", compute: (r) => resolveKnownFolderPath(r.app_path || "") ?? "" },
        { key: "app_path", label: "원본 경로", kind: "path" },
        { key: "display_text", label: "표시 텍스트" },
        { key: "content_uri", label: "콘텐츠 URI" },
        { key: "active_duration_s", label: "사용 시간 (초)" },
        { key: "account", label: "계정", kind: "account" },
      ]},
      { heading: "시각", fields: [
        { key: "start_time", label: "시작" },
        { key: "end_time", label: "종료" },
        { key: "last_modified", label: "마지막 수정" },
        { key: "expiration", label: "만료" },
      ]},
      { heading: "원본", fields: [
        { key: "source_table", label: "원본 테이블" },
        { key: "activity_type", label: "ActivityType" },
        { key: "activity_id", label: "활동 ID" },
        { key: "platform_device_id", label: "장치 ID" },
        { key: "payload", label: "페이로드", kind: "json" },
      ]},
    ],
  },
  // $UsnJrnl:$J 원본 facts — 화면은 파생 UsnJournal을 쓰고, 이 표는 원본
  // 레코드 열람용으로 남는다. 타임라인은 파생에서만 받는다(중복 방지).
  UsnJrnl_Records: {
    title: (r) => r.filename || "(USN)",
    subtitle: (r) => r.reason || "",
    priorityColumns: ["timestamp", "filename", "reason", "file_attributes", "mft_entry", "parent_mft_entry", "usn"],
    sections: [
      { heading: "변경 이벤트", fields: [
        { key: "filename", label: "파일명", kind: "path" },
        { key: "reason", label: "변경 사유", kind: "code" },
        { key: "file_attributes", label: "파일 속성" },
        { key: "source_info", label: "소스 정보" },
      ]},
      { heading: "NTFS 참조", fields: [
        { key: "usn", label: "USN" },
        { key: "mft_entry", label: "MFT 엔트리" },
        { key: "parent_mft_entry", label: "부모 MFT 엔트리" },
        { key: "file_reference", label: "파일 참조 번호" },
        { key: "parent_file_reference", label: "부모 파일 참조 번호" },
        { key: "security_id", label: "보안 ID" },
      ]},
    ],
  },
  // NTFS 변경 저널 파생(_OVERVIEW/UsnJournal) — 수십만 행 규모라 UsnJrnlView가
  // 서버 페이지네이션(usnjrnl_page)으로 직접 조회한다. path·volume_id·
  // journal_id·계정은 $J 본문에 없는 값이라 근거가 없으면 NULL로 둔다.
  UsnJournal: {
    customView: "usnJrnl",
    title: (r) => r.file_name || "(USN)",
    subtitle: (r) => r.reason || "",
    timelineField: "timestamp",
    timelineTitle: (r) => r.file_name || "(USN)",
    timelineSubtitle: (r) => r.event_type || r.reason || "",
    priorityColumns: ["timestamp", "event_type", "file_name", "reason", "file_attributes", "usn"],
    sections: [
      { heading: "변경 이벤트", fields: [
        { key: "file_name", label: "파일명", kind: "path" },
        { key: "path", label: "전체 경로", kind: "path", showWhenEmpty: true, emptyLabel: "$J에 없는 값 — 외부 근거 없음" },
        { key: "event_type", label: "변경 종류" },
        { key: "reason", label: "변경 사유", kind: "code" },
        { key: "reason_mask", label: "변경 사유 원문 비트마스크" },
        { key: "renamed_from", label: "이전 이름", kind: "path" },
        { key: "group_count", label: "묶인 기록 수" },
        { key: "file_attributes", label: "파일 속성" },
        { key: "source_info", label: "소스 정보" },
      ]},
      { heading: "NTFS 참조", fields: [
        { key: "usn", label: "USN" },
        { key: "record_version", label: "레코드 버전" },
        { key: "file_reference", label: "파일 참조 원문" },
        { key: "parent_reference", label: "부모 참조 원문" },
        { key: "security_id", label: "보안 ID (SID 아님)" },
        { key: "volume_id", label: "볼륨 문맥", showWhenEmpty: true, emptyLabel: "확인된 볼륨 문맥 없음" },
        { key: "journal_id", label: "저널 식별자", showWhenEmpty: true, emptyLabel: "$Max 등 별도 근거 없음" },
      ]},
    ],
  },
  // WMI Repository (OBJECTS.DATA) 원본 facts — 시그니처 스캔 결과. 전용 뷰는
  // 삭제했고 원본 데이터 목록·검색·북마크 상세에서 이 규칙으로 표시한다.
  WMI_Persistence: {
    title: (r) => r.name || "(WMI)",
    subtitle: (r) => r.kind || "",
    priorityColumns: ["kind", "name", "consumer_type", "filter_name", "consumer_name", "query", "query_language", "namespace", "details"],
    sections: [
      { heading: "구독 구성", fields: [
        { key: "kind", label: "구분", kind: "badge" },
        { key: "filter_name", label: "필터 이름" },
        { key: "consumer_name", label: "컨슈머 이름" },
        { key: "consumer_type", label: "컨슈머 유형" },
      ]},
      { heading: "필터 조건", fields: [
        { key: "query", label: "WQL 쿼리", kind: "code" },
        { key: "query_language", label: "쿼리 언어" },
        { key: "namespace", label: "네임스페이스" },
      ]},
      { heading: "컨슈머 값", fields: [
        { key: "details", label: "세부 값", kind: "code" },
      ]},
    ],
  },
  // WMI 이벤트 구독 파생(_OVERVIEW/WmiSubscriptions) — 필터·컨슈머·바인딩.
  // 리포지터리에는 시각이 없어 timestamp는 NULL이고 타임라인에 넣지 않는다.
  // 전용 뷰는 2026-10-07 사용자 확정으로 삭제했고, 이 표시 규칙은 검색 결과·
  // 북마크 등 공통 상세에서 계속 쓴다.
  WmiSubscriptions: {
    title: (r) => r.filter_name || r.consumer_name || r.object_path || "(WMI)",
    subtitle: (r) => r.object_type || "",
    priorityColumns: ["object_type", "filter_name", "consumer_name", "consumer_type", "query", "namespace", "command"],
    sections: [
      { heading: "구독 구성", fields: [
        { key: "object_type", label: "구분", kind: "badge" },
        { key: "namespace", label: "네임스페이스" },
        { key: "object_path", label: "객체 경로" },
        { key: "filter_name", label: "필터 이름" },
        { key: "consumer_name", label: "컨슈머 이름" },
        { key: "consumer_type", label: "컨슈머 클래스" },
        { key: "creator_sid", label: "생성자 SID", kind: "accountSid" },
      ]},
      { heading: "필터 조건", fields: [
        { key: "query", label: "WQL 쿼리", kind: "code" },
        { key: "query_language", label: "쿼리 언어" },
        { key: "event_namespace", label: "이벤트 네임스페이스" },
      ]},
      { heading: "컨슈머 동작", fields: [
        { key: "command", label: "명령", kind: "code" },
        { key: "command_resolved", label: "명령 (환경변수 해석)", kind: "code" },
        { key: "script_text", label: "스크립트", kind: "code" },
        { key: "script_engine", label: "스크립트 엔진" },
      ]},
      { heading: "바인딩", fields: [
        { key: "filter_ref", label: "바인딩 필터 경로" },
        { key: "consumer_ref", label: "바인딩 컨슈머 경로" },
      ]},
    ],
  },
  // $MFT 원본 facts(28개 필드) — 화면용 탐색기는 파생 FileSystemEntries를
  // 쓰고, 이 표는 원본 레코드 열람용으로 남는다. 플래그는 0/1이고 미확인은
  // NULL이다(Y/N 아님).
  MFT_Records: {
    title: (r) => r.file_name || (r.path ? r.path.split("\\").filter(Boolean).pop() ?? r.path : "") || "(MFT)",
    subtitle: (r) => r.path || "",
    priorityColumns: ["path", "file_name", "file_size", "extension", "is_directory", "in_use", "entry", "seq", "parent_entry", "volume_id"],
    sections: [{ heading: "MFT 레코드", fields: [
      { key: "path", label: "경로", kind: "path" }, { key: "file_size", label: "크기 (Bytes)", kind: "byteSize" },
      { key: "extension", label: "확장자" },
      { key: "is_directory", label: "디렉터리", valueLabels: MFT_DIRECTORY_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "in_use", label: "할당 상태", valueLabels: MFT_IN_USE_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "entry", label: "엔트리" }, { key: "seq", label: "시퀀스" },
      { key: "parent_entry", label: "부모 엔트리", showWhenEmpty: true, emptyLabel: "부모 미확인" },
      { key: "parent_seq", label: "부모 시퀀스", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
    ]}, { heading: "볼륨", fields: MFT_VOLUME_FIELDS },
    { heading: "$STANDARD_INFORMATION (0x10)", fields: [
      { key: "si_created", label: "생성", showWhenEmpty: true }, { key: "si_modified", label: "수정", showWhenEmpty: true },
      { key: "si_mft_modified", label: "MFT 수정", showWhenEmpty: true }, { key: "si_accessed", label: "접근", showWhenEmpty: true },
      { key: "owner_id", label: "할당량 소유자 ID", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
      { key: "security_id", label: "보안 ID ($Secure)", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
    ]}, { heading: "$FILE_NAME (0x30)", fields: [
      { key: "fn_created", label: "생성", showWhenEmpty: true }, { key: "fn_modified", label: "수정", showWhenEmpty: true },
      { key: "fn_mft_modified", label: "MFT 수정", showWhenEmpty: true }, { key: "fn_accessed", label: "접근", showWhenEmpty: true },
    ]}],
  },

  // 파일 시스템 파생(_OVERVIEW/FileSystemEntries) — Explorer 방식 탐색기
  // (MftView가 SQLite를 지연 조회한다. 수십만~백만 행 규모). 타임라인에는
  // 넣지 않는다: 레코드마다 시각이 8개이고, 편입하면 파일 시스템 기록이
  // 사건 연대기를 덮어 버린다.
  FileSystemEntries: {
    customView: "mft",
    title: (r) => r.file_name || (r.path ? r.path.split("\\").filter(Boolean).pop() ?? r.path : "") || "(파일 시스템)",
    subtitle: (r) => r.path || "",
    priorityColumns: ["path", "file_name", "file_size", "extension", "is_directory", "in_use", "entry", "seq", "parent_entry", "volume_id"],
    sections: [{ heading: "파일 시스템 레코드", fields: [
      // 크기는 기본 Bytes로 표기하고 상세에서 KB/MB/GB 토글 변환 (브라우저
      // 다운로드 크기와 동일 위젯, 2026-09-01 사용자 요청).
      { key: "path", label: "경로", kind: "path" }, { key: "file_size", label: "크기 (Bytes)", kind: "byteSize" },
      { key: "extension", label: "확장자" },
      // 0/1/NULL — 미확인을 "파일"로 단정하지 않는다(docs-01).
      { key: "is_directory", label: "디렉터리", valueLabels: MFT_DIRECTORY_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "in_use", label: "할당 상태", valueLabels: MFT_IN_USE_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "entry", label: "엔트리" }, { key: "seq", label: "시퀀스" },
      { key: "parent_entry", label: "부모 엔트리", showWhenEmpty: true, emptyLabel: "부모 미확인" },
      { key: "parent_seq", label: "부모 시퀀스", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
      { key: "event_type", label: "항목 종류" },
    ]}, { heading: "볼륨", fields: MFT_VOLUME_FIELDS },
    { heading: "$STANDARD_INFORMATION (0x10)", fields: [
      { key: "si_created", label: "생성", showWhenEmpty: true, bookmarkable: true }, { key: "si_modified", label: "수정", showWhenEmpty: true, bookmarkable: true },
      { key: "si_mft_modified", label: "MFT 수정", showWhenEmpty: true, bookmarkable: true }, { key: "si_accessed", label: "접근", showWhenEmpty: true, bookmarkable: true },
      { key: "owner_id", label: "할당량 소유자 ID", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
      { key: "security_id", label: "보안 ID ($Secure)", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
    ]}, { heading: "$FILE_NAME (0x30)", fields: [
      { key: "fn_created", label: "생성", showWhenEmpty: true, bookmarkable: true }, { key: "fn_modified", label: "수정", showWhenEmpty: true, bookmarkable: true },
      { key: "fn_mft_modified", label: "MFT 수정", showWhenEmpty: true, bookmarkable: true }, { key: "fn_accessed", label: "접근", showWhenEmpty: true, bookmarkable: true },
    ]}],
  },

  // 휴지통 원본 facts(RECYCLEBIN/RecycleBin_Records) — 수집된 $I 한 건.
  RecycleBin_Records: {
    title: (r) => (r.original_path ? r.original_path.split("\\").filter(Boolean).pop() ?? r.original_path : "") || r.recycle_name || "(휴지통)",
    subtitle: (r) => r.original_path || "",
    priorityColumns: ["timestamp", "original_path", "file_size", "recycle_name", "r_exists", "account_sid", "_status"],
    sections: [{ heading: "$I 레코드", fields: [
      { key: "original_path", label: "원래 경로", kind: "path" },
      { key: "file_size", label: "원래 크기 (Bytes)", kind: "byteSize" },
      { key: "deleted_time_raw", label: "삭제 시각 원문 (FILETIME)" },
      { key: "format_version", label: "$I 형식 버전" },
      { key: "recycle_name", label: "대응 이름" },
      { key: "r_exists", label: "$R 수집 여부", valueLabels: RECYCLE_R_EXISTS_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "account_sid", label: "계정 SID", kind: "accountSid" },
      { key: "_status", label: "파싱 상태" },
      { key: "_error", label: "실패 사유" },
    ]}],
  },

  // 휴지통 파생(_OVERVIEW/RecycleBin) — $I 한 건이 한 행. $R의 경로·종류·
  // 본문은 저장하지 않으므로 화면에도 없다. r_exists는 수집본에 대응 $R이
  // 있었는지만 말한다(영구 삭제·복구 가능 여부의 증거가 아니다).
  RecycleBin: {
    title: (r) => (r.original_path ? r.original_path.split("\\").filter(Boolean).pop() ?? r.original_path : "") || r.recycle_name || "(휴지통)",
    subtitle: (r) => r.original_path || "",
    timelineField: "timestamp",
    timelineTitle: (r) => (r.original_path ? r.original_path.split("\\").filter(Boolean).pop() ?? r.original_path : "") || r.recycle_name || "(휴지통)",
    timelineSubtitle: (r) => r.original_path || "",
    tags: (r) => tagsForPath(r.original_path),
    priorityColumns: ["timestamp", "original_path", "file_size", "account", "recycle_name", "r_exists", "status"],
    sections: [{ heading: "휴지통 기록", fields: [
      { key: "original_path", label: "원래 경로", kind: "path" },
      { key: "original_drive_letter", label: "원래 드라이브 문자", showWhenEmpty: true, emptyLabel: "경로에 없음" },
      { key: "file_size", label: "원래 크기 (Bytes)", kind: "byteSize" },
      { key: "deleted_time_raw", label: "삭제 시각 원문 (FILETIME)" },
      { key: "format_version", label: "$I 형식 버전" },
      { key: "recycle_name", label: "대응 이름" },
      // 1/0/NULL — 확인 불가를 "없음"으로 단정하지 않는다(docs-01).
      { key: "r_exists", label: "$R 수집 여부", valueLabels: RECYCLE_R_EXISTS_LABELS, showWhenEmpty: true, emptyLabel: "확인 불가" },
      { key: "volume_id", label: "볼륨 문맥", showWhenEmpty: true, emptyLabel: "확인된 볼륨 문맥 없음" },
    ]}, { heading: "계정", fields: [
      { key: "account", label: "계정", kind: "account", showWhenEmpty: true, emptyLabel: "계정명 미확인" },
      { key: "account_sid", label: "계정 SID", kind: "accountSid" },
    ]}, { heading: "파싱", fields: [
      { key: "status", label: "상태" },
      { key: "error", label: "실패 사유" },
    ]}],
  },

  // --- 종합 분석 (_OVERVIEW/): 저장 계약(docs-01)의 파생 테이블. 한 행의
  // 원본 근거는 그 DB의 source_records에 있고, 상세 패널이 그것으로 원본
  // 레코드를 되짚는다.
  TargetInfo: {
    customView: "targetInfo",
    title: (r) => r.name || "(no name)",
    subtitle: (r) => r.category || "",
    badges: [{ key: "category", kind: "badge" }],
    priorityColumns: ["category", "name", "value", "timestamp"],
    sections: [{ heading: "값", fields: [
      { key: "value" },
      { key: "timestamp" },
      { key: "event_type", label: "분류" },
    ]}],
  },

  // TargetInfo renders a compact host-oriented dashboard. Network interfaces
  // open this dedicated shared-drawer definition so the list can stay IP-only
  // without losing any recovered TCP/IP evidence fields. 값은 Metadata.sqlite의
  // network 항목과 그 자식 표(주소·게이트웨이·DNS)에서 온다.
  TargetInfo_NetworkInterface: {
    title: () => "네트워크 어댑터",
    subtitle: (r) => r.value || "",
    overviewTime: "hide",
    priorityColumns: ["value", "addresses", "gateways", "dns_servers", "dhcp_server", "domain"],
    sections: [
      { heading: "네트워크 인터페이스", fields: [
        { key: "interface_name", label: "인터페이스 이름" },
        { key: "addresses", label: "IP 주소" },
        { key: "subnet_masks", label: "서브넷 마스크" },
        { key: "gateways", label: "기본 게이트웨이" },
        { key: "mac_address", label: "MAC 주소" },
      ]},
      { heading: "네트워크 구성", fields: [
        { key: "dns_servers", label: "DNS 서버" },
        { key: "dhcp_server", label: "DHCP 서버" },
        { key: "dhcp_enabled", label: "DHCP 사용", valueLabels: { "1": "사용", "0": "사용 안 함" }, showWhenEmpty: true, emptyLabel: "확인 불가" },
        { key: "network_profile", label: "네트워크 프로필" },
        { key: "domain", label: "도메인" },
      ]},
      { heading: "DHCP 임대", fields: [
        { key: "lease_obtained", label: "임대 시작" },
        { key: "lease_terminates", label: "임대 만료" },
      ]},
      { heading: "식별 정보", fields: [
        { key: "interface_id", label: "인터페이스 식별자" },
        { key: "observed_at", label: "확인된 관측 시각" },
        { key: "resolution_status", label: "확인 상태" },
      ]},
    ],
  },

  // NetworkList profile evidence is distinct from the TCP/IP interface
  // configuration above. 수집되지 않은 레지스트리 값을 추정하지 않는다.
  TargetInfo_NetworkProfile: {
    title: () => "연결한 네트워크",
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    priorityColumns: ["value", "timestamp"],
    sections: [{ heading: "레지스트리 NetworkList 프로필", fields: [
      { key: "value", label: "프로필 이름" },
      { key: "timestamp", label: "마지막 연결 시각" },
      { key: "name", label: "항목 이름" },
    ]}],
  },

  ExecutionHistory: {
    customView: "executionHistory",
    // Feed the master timeline from this curated stream, not the raw execution
    // artifacts: it's the only place SRUM (first sighting), BAM and UserAssist
    // get a normalized timestamp, and it already merges + dedups Amcache/
    // Prefetch. The raw Amcache/Prefetch specs drop their own timelineField so
    // those don't double-count here. AppCompatCache/ShimCache is deliberately
    // excluded (file-mtime, not run time — v0.9.35); it stays in
    // RegistryFindings with that caveat.
    timelineField: "timestamp",
    title: (r) => `ExecutionHistory:${executionSourceLabel(r)}`,
    // Shell-Core keeps only the raw command (no program name/path is inferred).
    timelineTitle: (r) => r.program_name || basename(r.program_path) || r.command_line || "(이름 없음)",
    // The timeline keeps the evidence source and path visible while the detail
    // drawer has one concise timestamp in its evidence overview.
    timelineSubtitle: (r) => [executionSourceLabel(r), r.program_path].filter(Boolean).join(" · "),
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    tags: (r) => {
      const base = executionEvidence(r) === "amcache"
        ? tagsForPath(r.program_path).concat(tagsForMissingAmcachePublisher(r.publisher))
        : tagsForPath(r.program_path);
      const note = executableNote(r.program_name || basename(r.program_path));
      return note ? base.concat([{ label: note, severity: "info", description: "실행 파일 카탈로그 참고 — 공격자가 자주 쓰는 도구입니다. 실행 자체가 악성이라는 뜻은 아닙니다." }]) : base;
    },
    priorityColumns: ["timestamp", "program_name", "program_path", "run_count", "event_type"],
    sections: [
      { heading: "Amcache 프로그램 정보", fields: [
        { key: "program_name", label: "프로그램 이름", compute: (r) => executionValue("amcache", "program_name", r) },
        { key: "program_path", label: "프로그램 경로", kind: "path", compute: (r) => executionValue("amcache", "program_path", r) },
        { key: "publisher", label: "게시자", compute: (r) => executionValue("amcache", "publisher", r) },
        { key: "sha1", label: "SHA-1", kind: "hash", compute: (r) => executionValue("amcache", "sha1", r) },
      ]},
      { heading: "UserAssist 실행 정보", fields: [
        { key: "program_name", label: "실행 항목", compute: (r) => executionValue("userAssist", "program_name", r) },
        // KNOWNFOLDERID GUID 접두 경로는 실제 경로로 변환해 함께 보여 준다.
        { key: "program_path", label: "실행 경로 (변환)", kind: "path", compute: (r) => resolveKnownFolderPath(executionValue("userAssist", "program_path", r)) ?? "" },
        { key: "program_path", label: "원본 경로", kind: "path", compute: (r) => executionValue("userAssist", "program_path", r) },
        { key: "account", label: "실행 계정", kind: "account", compute: (r) => executionValue("userAssist", "account", r) },
        { key: "run_count", label: "실행 횟수", compute: (r) => executionValue("userAssist", "run_count", r) },
        { key: "focus_count", label: "포커스 횟수", compute: (r) => executionValue("userAssist", "focus_count", r) },
        { key: "focus_time_ms", label: "포커스 시간", kind: "durationMs", compute: (r) => executionValue("userAssist", "focus_time_ms", r) },
      ]},
      { heading: "SRUM 사용 정보", fields: [
        { key: "program_name", label: "응용 프로그램", compute: (r) => executionValue("srum", "program_name", r) },
        { key: "program_path", label: "응용 프로그램 경로", kind: "path", compute: (r) => executionValue("srum", "program_path", r) },
        { key: "account", label: "사용자", kind: "account", compute: (r) => executionValue("srum", "account", r) },
      ]},
      { heading: "BAM 실행 정보", fields: [
        { key: "program_name", label: "실행 파일", compute: (r) => executionValue("bam", "program_name", r) },
        { key: "program_path", label: "실행 경로", kind: "path", compute: (r) => executionValue("bam", "program_path", r) },
        { key: "account_sid", label: "실행 계정", kind: "accountSid", compute: (r) => executionValue("bam", "account_sid", r) },
      ]},
      { heading: "Prefetch 실행 정보", fields: [
        { key: "program_name", label: "실행 파일", compute: (r) => executionValue("prefetch", "program_name", r) },
        { key: "run_count", label: "실행 횟수", compute: (r) => executionValue("prefetch", "run_count", r) },
      ]},
      { heading: "프로세스 생성 정보", fields: [
        { key: "program_name", label: "새 프로세스 이름", compute: (r) => executionValue("processCreation", "program_name", r) },
        { key: "program_path", label: "새 프로세스 경로 (NewProcessName)", kind: "path", compute: (r) => executionValue("processCreation", "program_path", r) },
        { key: "command_line", label: "명령줄 (CommandLine)", kind: "code", compute: (r) => executionValue("processCreation", "command_line", r) },
        { key: "process_id", label: "새 프로세스 ID (NewProcessId)", compute: (r) => executionValue("processCreation", "process_id", r) },
        { key: "parent_process_path", label: "생성 요청 프로세스 (ParentProcessName)", kind: "path" },
        { key: "parent_process_id", label: "생성 요청 프로세스 ID (ProcessId)" },
      ]},
      { heading: "시작 명령 정보", fields: [
        { key: "command_line", label: "Run 키 명령 (Command)", kind: "code", compute: (r) => executionValue("shellCore", "command_line", r) },
        { key: "process_id", label: "프로세스 ID (PID)", compute: (r) => executionValue("shellCore", "process_id", r) },
      ]},
      // account/account_sid are the common account; account_role says whose it is.
      { heading: "이벤트 계정", fields: [
        { key: "account_role", label: "계정 역할", valueLabels: ACCOUNT_ROLE_LABELS },
        { key: "account", label: "계정", kind: "account", compute: (r) => r.account_role ? r.account : "" },
        { key: "account_sid", label: "계정 SID", kind: "accountSid", compute: (r) => r.account_role ? r.account_sid : "" },
      ]},
      { heading: "생성 요청자 (Subject)", fields: [
        { key: "subject_user_name", label: "계정 이름 (SubjectUserName)", kind: "account" },
        { key: "subject_domain_name", label: "도메인 (SubjectDomainName)" },
        { key: "subject_user_sid", label: "SID (SubjectUserSid)", kind: "accountSid" },
        { key: "subject_logon_id", label: "로그온 ID (SubjectLogonId)" },
      ]},
      { heading: "대상 계정 (Target)", fields: [
        { key: "target_user_name", label: "계정 이름 (TargetUserName)", kind: "account" },
        { key: "target_domain_name", label: "도메인 (TargetDomainName)" },
        { key: "target_user_sid", label: "SID (TargetUserSid)", kind: "accountSid" },
        { key: "target_logon_id", label: "로그온 ID (TargetLogonId)" },
      ]},
      { heading: "실행 정보", fields: [
        { key: "program_name", label: "항목 이름", compute: (r) => executionEvidence(r) === "other" ? r.program_name : "" },
        { key: "program_path", label: "항목 경로", kind: "path", compute: (r) => executionEvidence(r) === "other" ? r.program_path : "" },
        { key: "program_path_resolved", label: "항목 경로 (환경변수 해석)", kind: "path" },
      ]},
      { heading: "이벤트 정보", collapsible: { defaultExpanded: false, summary: (r) => `EventID ${r.event_id} · RecordID ${r.event_record_id || "-"}` }, fields: [
        { key: "event_id", label: "Event ID" },
        { key: "event_provider", label: "제공자 (Provider)" },
        { key: "event_channel", label: "채널 (Channel)" },
        { key: "event_record_id", label: "EventRecordID" },
        { key: "event_process_id", label: "기록 프로세스 ID (System.ProcessID)" },
        { key: "event_thread_id", label: "기록 스레드 ID (System.ThreadID)" },
        { key: "event_user_sid", label: "System.UserID", kind: "accountSid" },
        { key: "event_computer", label: "Computer" },
        { key: "event_data", label: "EventData 원문", kind: "json" },
      ]},
    ],
    // 대표 시각 외의 실행 시각과 볼륨 정보는 자식 표에 있다 — 한 행에 8개
    // 시각 컬럼을 늘어놓지 않고, 상세에서 있는 값만 조회해 보여 준다.
    childTables: [
      {
        table: "ExecutionTimes",
        heading: "이전 실행 시각",
        summary: (r) => r.execution_time || "",
      },
      {
        table: "ExecutionVolumes",
        heading: "볼륨 정보",
        fields: [
          { key: "device_path", label: "볼륨 경로", kind: "path" },
          { key: "serial_number", label: "볼륨 일련 번호", kind: "hash" },
          { key: "created_at", label: "볼륨 생성 시각" },
        ],
      },
    ],
    embeddedLinks: [{ key: "prefetch_hash", label: "Prefetch에 기록된 참조 파일", targetFile: "Prefetch_LoadedFiles", targetColumn: "prefetch_hash" }],
  },

  ScheduledTasks: {
    customView: "scheduledTasks",
    // The overview identifies the evidence type first; the task's own name is
    // kept in the information section, consistently for every task record.
    title: () => "ScheduledTasks",
    timelineTitle: (r) => r.task_name || "(이름 없음)",
    // The evidence overview stays intentionally terse: task type + the raw
    // registration timestamp. The action itself belongs in TaskActions below.
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    tags: (r) => tagsForPath(r.task_path),
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "event_type", "task_name", "task_path", "run_as", "result"],
    sections: [{ heading: "작업 스케줄러 정보", fields: [
      { key: "event_type", label: "기록 종류", kind: "badge" },
      { key: "task_name", label: "작업 이름" },
      { key: "task_path", label: "작업 경로" },
      { key: "run_as", label: "실행 계정", kind: "account" },
      { key: "run_as_sid", label: "실행 계정 SID", kind: "accountSid" },
      { key: "run_level", label: "실행 권한" },
      { key: "logon_type", label: "로그온 유형" },
      {
        key: "enabled",
        label: "작업 상태",
        kind: "badge",
        // 저장 계약의 플래그는 0/1이고 미확인은 NULL이다 — 모르는 값을
        // "비활성화됨"으로 단정하지 않는다.
        valueLabels: { "1": "활성화됨", "0": "비활성화됨" },
        showWhenEmpty: true,
        emptyLabel: "설정 정보 없음",
        badgeColors: { "활성화됨": "#3fb950", "비활성화됨": "#8a8a8a" },
      },
      {
        key: "hidden",
        label: "표시 정책",
        kind: "badge",
        valueLabels: { "1": "숨김 처리됨", "0": "일반 표시" },
        showWhenEmpty: true,
        emptyLabel: "설정 정보 없음",
        badgeColors: { "숨김 처리됨": "#d29922", "일반 표시": "#4fc1ff" },
      },
      { key: "is_microsoft", label: "Microsoft 기본 작업", valueLabels: { "1": "예", "0": "아니오" } },
      { key: "author", label: "작성자" },
      { key: "uri", label: "URI" },
      { key: "task_description", label: "작업 설명" },
      { key: "description", label: "설명" },
    ]},
    // 작업 이벤트(100/102/129/200 등) 행이 같은 표에 함께 저장된다 — 정의 행과
    // 달리 이벤트 ID·결과를 갖는다. "정의만 있고 언제 돌았는지 모름"은 이벤트
    // 행으로 확인한다.
    { heading: "이벤트", fields: [
      { key: "result", label: "결과", kind: "badge", badgeColors: { "성공": "#3fb950", "실패": "#f85149" } },
      { key: "event_id", label: "이벤트 ID" },
      { key: "provider", label: "공급자" },
    ]}],
    // 실행 명령·트리거는 정의 행의 자식 표다(원문도 함께 보존된다).
    childTables: [
      {
        table: "TaskActions",
        heading: "실행 명령",
        fields: [
          { key: "action_type", label: "동작 유형" },
          { key: "command", label: "명령", kind: "code" },
          { key: "command_resolved", label: "명령 (환경변수 해석)", kind: "code" },
          { key: "arguments", label: "인수", kind: "code" },
          { key: "working_directory", label: "작업 디렉터리", kind: "path" },
          { key: "raw_action", label: "원문", kind: "code" },
        ],
      },
      {
        table: "TaskTriggers",
        heading: "트리거",
        fields: [
          { key: "trigger_type", label: "트리거 유형" },
          { key: "start_time", label: "시작 경계" },
          { key: "end_time", label: "종료 경계" },
          { key: "enabled", label: "사용", valueLabels: { "1": "사용", "0": "사용 안 함" } },
          { key: "raw_trigger", label: "원문", kind: "code" },
        ],
      },
    ],
  },

  BrowserActivity: {
    customView: "browserHistory",
    // Browser records use an evidence-type title, not a page title or URL:
    // those vary by source and belong in the browser-specific fields below.
    title: (r) => `BrowserActivity:${r.event_type === "download" ? "Download" : r.event_type === "cache" ? "Cache" : "Visit"}`,
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    // The timeline already owns the timestamp column. Show the actual URL as
    // the event and keep its type on the secondary line; never reuse the
    // concise detail-panel evidence title here.
    timelineTitle: (r) => r.url || r.url_raw || r.title || "(URL 없음)",
    timelineSubtitle: (r) => r.event_type === "download" ? "Download" : r.event_type === "cache" ? "Cache" : "Visit",
    // BrowserActivity retains cache rows for the browser evidence view, but a
    // cache response is not a defensible browsing event. The master timeline
    // therefore contains only actual visits and downloads.
    timelineField: "timestamp",
    timelineInclude: (r) => r.event_type === "visit" || r.event_type === "download",
    tags: (r) => tagsForDangerType(r.danger).concat(r.event_type === "download" ? tagsForPath(r.detail) : []),
    priorityColumns: ["account", "event_type", "browser", "timestamp", "title", "url", "size_bytes", "source_url"],
    sections: [{
      heading: (r) => `브라우저 ${r.event_type === "download" ? "다운로드" : r.event_type === "cache" ? "캐시" : "접근"}`,
      fields: [
      { key: "title", label: "방문 Title", compute: (r) => r.title || "" },
      { key: "browser", label: "브라우저" },
      {
        key: "url_raw",
        label: "URL 원본",
        kind: "path",
        compute: (r) => r.event_type === "cache" ? r.url : r.url_raw || r.url,
      },
      { key: "account", label: "브라우저 접근 계정", kind: "account" },
      {
        key: "url",
        label: "URL (디코딩)",
        kind: "path",
        compute: (r) => {
          const value = r.url || "";
          try { return decodeURIComponent(value); } catch { return value; }
        },
      },
      { key: "visit_count", label: "방문 횟수", compute: (r) => r.event_type === "visit" ? r.visit_count : "" },
      // 주소창에 URL을 직접 입력해 이동한 횟수 — 링크 경유 방문과 달리
      // "의도적으로 찾아간 사이트"임을 입증하는 값(T7).
      { key: "typed_count", label: "주소창 직접 입력 횟수", compute: (r) => r.event_type === "visit" ? r.typed_count : "" },
      { key: "detail", label: "저장 경로", kind: "path", compute: (r) => r.event_type === "download" ? r.detail : "" },
      { key: "download_path", label: "다운로드 저장 경로", kind: "path" },
      { key: "download_path_resolved", label: "다운로드 저장 경로 (환경변수 해석)", kind: "path" },
      {
        key: "size_bytes",
        label: "크기 (Bytes)",
        kind: "byteSize",
        compute: (r) => r.event_type === "download" || r.event_type === "cache" ? r.size_bytes || r.size : "",
      },
      { key: "mime", label: "다운로드 파일 유형", compute: (r) => r.event_type === "download" ? r.mime : "" },
      { key: "http_status", label: "HTTP 상태" },
      {
        key: "cache_file_type",
        label: "파일 유형",
        compute: (r) => {
          if (r.event_type !== "cache") return "";
          if (r.mime) return r.mime;
          const path = (r.url || "").split(/[?#]/)[0];
          const extension = path.includes(".") ? path.slice(path.lastIndexOf(".") + 1).toLowerCase() : "";
          return extension ? `.${extension}` : "알 수 없음";
        },
      },
      { key: "cache_data", label: "캐시 데이터", kind: "cacheData", compute: (r) => r.event_type === "cache" ? "cache" : "" },
    ]}],
  },

  // Chrome disk-cache entries (browser_cache_parser) — a normal table, but with
  // the decoded HTTP response surfaced: status/type up front, full response
  // headers as a code block in the detail panel.
  CacheEntries: {
    title: (r) => basename(r.url) || r.url || "(no url)",
    subtitle: (r) => r.url || "",
    badges: [{ key: "status", kind: "badge" }],
    priorityColumns: ["response_time", "url", "status", "content_type", "content_length", "server", "account"],
    sections: [
      { heading: "HTTP 응답", fields: [
        { key: "status", label: "상태" },
        { key: "content_type", label: "Content-Type" },
        { key: "content_length", label: "Content-Length" },
        { key: "content_encoding", label: "Content-Encoding" },
        { key: "server", label: "Server" },
        { key: "date", label: "Date" },
        { key: "last_modified", label: "Last-Modified" },
        { key: "etag", label: "ETag" },
        { key: "cache_control", label: "Cache-Control" },
        { key: "location", label: "Location" },
      ]},
      { heading: "원본 응답 헤더", fields: [{ key: "all_headers", label: "헤더", kind: "code" }] },
      { heading: "시간 · 본문", fields: [
        { key: "request_time", label: "요청 시각" },
        { key: "response_time", label: "응답 시각" },
        { key: "creation_time", label: "캐시 생성" },
        { key: "body_size", label: "본문 크기(bytes)" },
        { key: "body_file", label: "본문 파일" },
        { key: "cache_key", label: "캐시 키" },
      ]},
    ],
  },

  // IE10+/레거시 Edge WebCacheV##.dat 방문 기록 (컨테이너: History/MSHist…).
  // Url은 "Visited: 사용자@URL" 원문 그대로 — 가공하지 않는다.
  IEWebCache_History: {
    title: (r) => r.url || "(no url)",
    subtitle: (r) => r.container || "",
    priorityColumns: ["accessed_time", "url", "access_count", "container", "account"],
    sections: [
      { heading: "상세", fields: [
        { key: "accessed_time", label: "접근 시각" },
        { key: "modified_time", label: "수정 시각" },
        { key: "expiry_time", label: "만료 시각" },
        { key: "access_count", label: "접근 횟수" },
        { key: "url", label: "URL", kind: "path" },
        { key: "container", label: "컨테이너" },
        { key: "account", label: "계정", kind: "account" },
      ]},
    ],
  },

  // WebCache iedownload 컨테이너 — metadata는 다운로드 레코드 블롭에서 추출한
  // UTF-16 문자열(원본 URL·저장 경로 등)이다.
  IEWebCache_Downloads: {
    title: (r) => r.url || "(no url)",
    subtitle: (r) => r.metadata || "",
    priorityColumns: ["accessed_time", "url", "metadata", "account"],
    sections: [
      { heading: "상세", fields: [
        { key: "accessed_time", label: "접근 시각" },
        { key: "modified_time", label: "수정 시각" },
        { key: "url", label: "URL", kind: "path" },
        { key: "metadata", label: "레코드 내 문자열(저장 경로 등)", kind: "code" },
        { key: "container", label: "컨테이너" },
        { key: "account", label: "계정", kind: "account" },
      ]},
    ],
  },

  // IE5~9 index.dat (XP/Vista/Win7). History.IE5 일별 컨테이너(MSHist…)의
  // 시각은 로컬 시간으로 기록되는 것으로 알려져 있음 — 표기는 원시 FILETIME
  // 기준(파서 주석 참조).
  IEIndexDat_Records: {
    title: (r) => r.url || "(no url)",
    subtitle: (r) => r.container || "",
    badges: [{ key: "record_type", kind: "badge" }],
    priorityColumns: ["accessed_time", "record_type", "url", "hits", "container", "account"],
    sections: [
      { heading: "상세", fields: [
        { key: "record_type", label: "레코드 종류" },
        { key: "accessed_time", label: "접근 시각" },
        { key: "modified_time", label: "수정 시각" },
        { key: "hits", label: "접근 횟수" },
        { key: "url", label: "URL", kind: "path" },
        { key: "filename", label: "캐시 파일명" },
        { key: "container", label: "컨테이너" },
        { key: "account", label: "계정", kind: "account" },
      ]},
    ],
  },

  RegistryFindings: {
    customView: "registryFindings",
    title: (r) => r.name || "(no name)",
    // The overview is intentionally terse: the registry path and status are
    // evidence fields below, while attention-only status appears once at the
    // bottom as a hoverable analysis tag.
    tags: tagsForRegistryFinding,
    priorityColumns: ["category", "status", "name", "value", "timestamp", "detail", "account", "source"],
    sections: [{ heading: "상세", fields: [
      { key: "category", label: "분류" },
      // Registry-derived findings inherit the source key's LastWrite time.
      // ShimCache is different: its timestamp is the cache entry's FILETIME,
      // not proof of a registry key write.
      { key: "timestamp", label: "레지스트리 키 마지막 기록 시각", compute: (r) => r.subtype === "ShimCache" || r.subtype === "MsiInstall" ? "" : r.timestamp },
      { key: "timestamp", label: "ShimCache 캐시 항목 시각", compute: (r) => r.subtype === "ShimCache" ? r.timestamp : "" },
      // MSI InstallDate는 날짜만 있는 값이라 자정(00:00:00.000)으로 저장된다.
      { key: "timestamp", label: "설치 날짜", compute: (r) => r.subtype === "MsiInstall" ? r.timestamp : "" },
      { key: "value", label: "버전", compute: (r) => r.subtype === "MsiInstall" ? r.value : "" },
      { key: "detail", label: "제조사", compute: (r) => r.subtype === "MsiInstall" ? r.detail : "" },
      { key: "properties", label: "InstallProperties 전체", kind: "json" },
      { key: "value", label: "값", compute: (r) => r.subtype === "MsiInstall" ? "" : r.value },
      { key: "value_type", label: "값 형식" },
      { key: "command", label: "명령" },
      { key: "command_resolved", label: "명령 (환경변수 해석)" },
      // SOFTWARE·SYSTEM 하이브 항목은 사용자 계정이 아니라 컴퓨터 전역 설정이다.
      { key: "account", label: "사용자", kind: "account", compute: (r) => (r.account === MACHINE_SCOPE_USER ? `${MACHINE_SCOPE_LABEL} (HKLM)` : r.account) },
      { key: "account_sid", label: "사용자 SID", kind: "accountSid" },
      // 하이브 루트 키 이름을 라이브 마운트 지점으로 바꿔 읽히게 한다.
      { key: "key_path", label: "키 경로", compute: (r) => displayRegistryKeyPath(r.key_path, r.source) },
      { key: "source", label: "하이브" },
    ]}],
  },

  Defender: {
    customView: "defender",
    title: (r) => r.title || "(no name)",
    subtitle: (r) => r.detail || "",
    badges: [{ key: "section", kind: "badge" }],
    priorityColumns: ["section", "timestamp", "title", "detail", "severity", "action", "account"],
    sections: [{ heading: "상세", fields: [
      { key: "severity", label: "심각도" },
      { key: "category", label: "분류" },
      { key: "threat_name", label: "위협 이름" },
      { key: "target_path", label: "대상 경로", kind: "path" },
      { key: "detection_type", label: "탐지 유형" },
      { key: "action", label: "조치" },
      { key: "action_time", label: "조치 시각" },
      { key: "remediation", label: "복구 결과" },
      // Defender가 요구한 후속 조치(재부팅 필요 등).
      { key: "additional_actions", label: "추가 조치" },
      { key: "process", label: "프로세스" },
      { key: "account", label: "사용자", kind: "account" },
      { key: "detection_user", label: "탐지 당시 사용자 원문", kind: "account" },
      { key: "origin", label: "유입 경로" },
      { key: "source", label: "탐지원" },
      { key: "detail", label: "경로/내용" },
      { key: "result", label: "결과" },
      { key: "event_id", label: "이벤트 ID" },
      { key: "raw_line", label: "원본 라인", kind: "code" },
    ]}],
  },

  RdpBitmapCache: {
    customView: "rdpCache",
    title: (r) => (r.kind === "mosaic" ? `${r.source_file} (모자이크)` : `${r.source_file} 타일 ${r.tile_index}`),
    subtitle: (r) => (r.width && r.height ? `${r.width}×${r.height}` : ""),
    sections: [{ heading: "타일", fields: [
      { key: "kind", label: "종류" },
      { key: "source_file", label: "캐시 파일" },
      { key: "tile_index", label: "타일 번호" },
      { key: "width", label: "너비" },
      { key: "height", label: "높이" },
      { key: "key", label: "키" },
    ]}],
  },

  // Processed overview: the stitched/reconstructed RDP cache images (fragments
  // + mosaic), split out of the raw RdpBitmapCache table into 종합 분석.
  RdpCache: {
    customView: "rdpCache",
    title: (r) => `${r.source_file} 복원 조각 ${r.fragment_index}`,
    subtitle: (r) => (r.cols && r.rows ? `${r.cols}×${r.rows} 타일` : ""),
    sections: [{ heading: "복원 조각", fields: [
      { key: "event_type", label: "종류" },
      { key: "source_file", label: "캐시 파일" },
      { key: "fragment_index", label: "조각 번호" },
      { key: "tile_count", label: "타일 수" },
      { key: "cols", label: "가로 타일" },
      { key: "rows", label: "세로 타일" },
      { key: "width", label: "너비" },
      { key: "height", label: "높이" },
      { key: "status", label: "복원 상태" },
    ]}],
  },

  RemoteDesktopHistory: {
    title: (r) => r.remote_address || "(주소 없음)",
    subtitle: (r) => r.description || "",
    badges: [
      { key: "direction", kind: "badge", badgeColors: DIRECTION_COLORS },
      { key: "result", label: "결과", kind: "badge", badgeColors: RDP_RESULT_COLORS },
    ],
    // Shown as a session-grouped flow instead of a flat table.
    flowView: true,
    // (kept for when the raw table is viewed directly) Only these five are
    // worth scanning; provider/event_id/result stay in the data.
    visibleColumns: ["timestamp", "direction", "remote_address", "account", "description"],
    filterTabs: {
      column: "result",
      tabs: [
        { label: "전체" },
        { label: "성공", value: "성공" },
        { label: "실패", value: "실패" },
      ],
    },
    priorityColumns: ["timestamp", "direction", "remote_address", "account", "description"],
    sections: [{ heading: "상세", fields: [
      { key: "account", label: "계정", kind: "account" },
      { key: "account_sid", label: "계정 SID", kind: "accountSid" },
      { key: "remote_computer", label: "원격 컴퓨터" },
      { key: "remote_port", label: "원격 포트" },
      { key: "local_address", label: "로컬 주소" },
      { key: "logon_type", label: "로그온 유형" },
      { key: "logon_id", label: "로그온 ID" },
      { key: "session_id", label: "세션 ID" },
      { key: "start_time", label: "시작 시각" },
      { key: "end_time", label: "종료 시각" },
      { key: "event_type", label: "기록 종류" },
      { key: "description", label: "설명" },
      { key: "result", label: "결과" },
      { key: "event_id", label: "이벤트 ID" },
      { key: "provider", label: "공급자" },
    ]}],
  },

  // SMB / network-logon activity, both directions: inbound (SMBServer/Security
  // 551·1009 and, when Security auditing is on, 4624/4625 LogonType 3) and
  // outbound (SmbClient/Security 31010 etc. — this host reaching out to remote
  // shares, the lateral-movement direction). Same session-flow view as RDP —
  // repeated failures from one IP collapse into a burst, which reads as a
  // brute-force / lateral-movement attempt.
  SmbHistory: {
    customView: "smb",
    title: (r) => r.remote_address || "(주소 없음)",
    subtitle: (r) => r.description || "",
    badges: [
      { key: "direction", kind: "badge", badgeColors: DIRECTION_COLORS },
      { key: "result", label: "결과", kind: "badge", badgeColors: RDP_RESULT_COLORS },
    ],
    visibleColumns: ["timestamp", "remote_address", "account", "result", "description"],
    filterTabs: {
      column: "result",
      tabs: [
        { label: "전체" },
        { label: "실패", value: "실패" },
        { label: "성공", value: "성공" },
      ],
    },
    priorityColumns: ["timestamp", "remote_address", "account", "result", "description"],
    sections: [{ heading: "상세", fields: [
      { key: "remote_address", label: "클라이언트 주소" },
      { key: "remote_port", label: "클라이언트 포트" },
      { key: "account", label: "계정", kind: "account" },
      { key: "account_sid", label: "계정 SID", kind: "accountSid" },
      { key: "share_name", label: "공유 이름" },
      { key: "share_path", label: "공유 경로", kind: "path" },
      { key: "target_file", label: "대상 파일", kind: "path" },
      { key: "access_rights", label: "요청 권한" },
      { key: "access_mask", label: "요청 권한 원문" },
      { key: "event_type", label: "기록 종류" },
      { key: "description", label: "설명" },
      { key: "result", label: "결과" },
      { key: "event_id", label: "이벤트 ID" },
      { key: "provider", label: "공급자" },
    ]}],
  },


  // 서비스 이력 파생(_OVERVIEW/ServiceHistory) — System 채널 Service Control
  // Manager 이벤트를 서비스 단위로 모은다. 원본(EventLog)이 이미 타임라인에
  // 편입돼 있으므로 여기서는 편입하지 않는다(중복 방지).
  ServiceHistory: {
    customView: "service",
    title: (r) => r.service_name || r.description || "(서비스 정보 없음)",
    subtitle: (r) => r.image_path || "",
    visibleColumns: ["timestamp", "service_name", "image_path", "description", "state", "result"],
    priorityColumns: ["timestamp", "service_name", "image_path", "description", "state", "result"],
    sections: [
      { heading: "서비스", fields: [
        { key: "service_name", label: "서비스 이름" },
        { key: "service_key", label: "서비스 짧은 이름" },
        { key: "image_path", label: "실행 파일 경로", kind: "path" },
        { key: "image_path_resolved", label: "실행 파일 경로 (환경변수 해석)", kind: "path" },
        { key: "service_account", label: "실행 계정", kind: "account" },
        { key: "service_account_sid", label: "실행 계정 SID", kind: "accountSid" },
        { key: "service_type", label: "서비스 유형" },
      ]},
      { heading: "기록", fields: [
        { key: "event_type", label: "기록 종류" },
        { key: "description", label: "설명" },
        { key: "state", label: "상태" },
        { key: "start_type_before", label: "이전 시작 유형" },
        { key: "start_type_after", label: "시작 유형" },
        { key: "detail", label: "상세" },
        { key: "result", label: "결과" },
        { key: "event_id", label: "이벤트 ID" },
        { key: "provider", label: "공급자" },
      ]},
    ],
  },

  BitsHistory: {
    customView: "bits",
    title: (r) => r.job_name || "(작업 이름 없음)",
    subtitle: (r) => r.url || "",
    visibleColumns: ["timestamp", "job_name", "url", "account", "result", "description"],
    priorityColumns: ["timestamp", "job_name", "url", "account", "result", "description"],
    sections: [
      { heading: "작업", fields: [
        { key: "job_name", label: "작업 이름" },
        { key: "job_id", label: "작업 ID" },
        { key: "url", label: "전송 URL", kind: "path" },
        { key: "local_path", label: "저장 경로", kind: "path" },
        { key: "local_path_resolved", label: "저장 경로 (환경변수 해석)", kind: "path" },
        { key: "account", label: "계정", kind: "account" },
        { key: "process", label: "요청 프로세스", kind: "path" },
      ]},
      { heading: "전송", fields: [
        { key: "bytes_transferred", label: "전송한 크기", kind: "bytes" },
        { key: "bytes_total", label: "전체 크기", kind: "bytes" },
        { key: "status", label: "상태 코드" },
      ]},
      { heading: "상세", fields: [
        { key: "event_type", label: "기록 종류" },
        { key: "description", label: "설명" },
        { key: "result", label: "결과" },
        { key: "event_id", label: "이벤트 ID" },
      ]},
    ],
    // 한 작업이 옮긴 파일 목록은 BitsFiles 자식 표에 있다 — 부모 행에 합치지
    // 않고 상세에서만 조회한다(docs-01).
    childTables: [{
      table: "BitsFiles",
      heading: "전송 파일",
      fields: [
        { key: "url", label: "URL", kind: "path" },
        { key: "local_path", label: "저장 경로", kind: "path" },
        { key: "local_path_resolved", label: "저장 경로 (환경변수 해석)", kind: "path" },
        { key: "bytes_transferred", label: "전송한 크기", kind: "bytes" },
        { key: "bytes_total", label: "전체 크기", kind: "bytes" },
      ],
    }],
  },

  FirewallHistory: {
    customView: "firewall",
    title: (r) => r.rule_name || r.detail || "(규칙 이름 없음)",
    subtitle: (r) => r.detail || "",
    visibleColumns: ["timestamp", "event_type", "rule_name", "direction", "action", "app_path", "account"],
    priorityColumns: ["timestamp", "event_type", "rule_name", "direction", "action", "app_path", "account", "detail"],
    sections: [
      { heading: "규칙", fields: [
        { key: "rule_name", label: "규칙 이름" },
        { key: "rule_id", label: "규칙 ID" },
        { key: "direction", label: "방향" },
        { key: "action", label: "동작" },
        { key: "protocol", label: "프로토콜" },
        { key: "protocol_number", label: "프로토콜 번호" },
        { key: "local_address", label: "로컬 주소" },
        { key: "remote_address", label: "원격 주소" },
        { key: "local_ports", label: "로컬 포트" },
        { key: "remote_ports", label: "원격 포트" },
        { key: "profiles", label: "적용 프로필" },
        { key: "app_path", label: "대상 프로그램", kind: "path" },
        { key: "app_path_resolved", label: "대상 프로그램 (환경변수 해석)", kind: "path" },
        { key: "service", label: "대상 서비스" },
      ]},
      { heading: "변경 주체", fields: [
        { key: "account", label: "계정", kind: "account" },
        { key: "account_sid", label: "계정 SID", kind: "accountSid" },
        { key: "modifying_app", label: "변경 프로그램", kind: "path" },
      ]},
      { heading: "상세", fields: [
        { key: "event_type", label: "유형" },
        { key: "detail", label: "설명" },
        { key: "event_id", label: "이벤트 ID" },
        { key: "provider", label: "공급자" },
      ]},
    ],
  },
  PowerShellHistory: {
    customView: "powershellFlow",
    // ScriptBlock and HostApplication can be arbitrarily long. Keep the
    // shared drawer's evidence title stable; both values are first-class
    // fields in the execution section below.
    title: (r) => r.command || r.event_type || "(명령 없음)",
    subtitle: (r) => [r.account, r.process].filter(Boolean).join(" · "),
    badges: [
      { key: "event_type", kind: "badge" },
      { key: "event_id", label: "이벤트 ID", kind: "badge" },
    ],
    tags: (r) => tagsForPath(r.script_path),
    // (kept for when the raw table is viewed directly, but the flow view is
    // the default) — the five fields the analyst actually scans.
    visibleColumns: ["timestamp", "event_type", "account", "process", "command"],
    priorityColumns: ["timestamp", "event_type", "account", "process", "command"],
    sections: [
      { heading: "실행 정보", fields: [
        { key: "account", label: "수행 계정", kind: "account" },
        { key: "account_sid", label: "수행 계정 SID", kind: "accountSid" },
        { key: "process", label: "수행 프로세스" },
        { key: "process_id", label: "프로세스 ID" },
        { key: "host_application", label: "호스트 애플리케이션", kind: "code", showWhenEmpty: true, emptyLabel: "기록되지 않음" },
        { key: "script_path", label: "스크립트 경로", kind: "path" },
        { key: "script_path_resolved", label: "스크립트 경로 (환경변수 해석)", kind: "path" },
        { key: "line_number", label: "줄 번호" },
      ]},
      { heading: "명령어", fields: [{ key: "command", kind: "code" }] },
      { heading: "코드 블록 (ScriptBlock)", fields: [
        // 분할 4104의 재조합 결과·조각 누락 표식은 공통 description에 남는다 —
        // 잘린 본문을 완전한 원문으로 오인하지 않도록 상세 상단에 보여 준다.
        { key: "description", label: "재조합 상태" },
        { key: "script_block", kind: "code" },
        { key: "script_block_id", label: "ScriptBlock ID" },
      ] },
      { heading: "이벤트", fields: [
        { key: "event_id", label: "이벤트 ID" },
        { key: "provider", label: "공급자" },
        { key: "session_id", label: "세션 ID" },
        { key: "runspace_id", label: "Runspace ID" },
      ]},
    ],
  },





  Amcache_Programs: {
    title: (r) => r.Name || "(no name)",
    subtitle: (r) => [r.Version, r.Publisher].filter(Boolean).join(" · "),
    badges: [
      { key: "_recovery", kind: "badge", badgeColors: STATUS_COLORS },
      { key: "StoreAppType", kind: "badge" },
    ],
    // HiddenArp=1 means the program was deliberately hidden from Add/Remove
    // Programs — a real self-concealment technique, not just noise.
    tags: (r) => tagsForBoolean(r.HiddenArp, { label: "제어판에서 숨김(HiddenArp)", severity: "danger", description: "제어판 '프로그램 추가/제거' 목록에서 의도적으로 숨겨진 프로그램입니다. 사용자 눈에 띄지 않게 하려는 자기은폐(self-concealment) 기법으로, 정상 소프트웨어에서는 드뭅니다." }).concat(executableNoteTags(r.Name)),
    links: [
      { key: "ProgramId", label: "이 프로그램이 설치한 파일 보기", targetFile: "Amcache_Files", targetColumn: "program_id" },
    ],
    // No timelineField: Amcache reaches the master timeline via ExecutionHistory
    // (avoids double-counting the same entries there and here).
    priorityColumns: ["timestamp", "Name", "Version", "Publisher", "InstallDate"],
    sections: [
      { heading: "설치 정보", fields: [
        { key: "timestamp", label: "레지스트리 키 시각" },
        { key: "InstallDate" },
        { key: "MsiInstallDate" },
        { key: "Source" },
      ]},
      { heading: "누가/어디서", fields: [
        { key: "UserSid", label: "설치한 계정(SID)", kind: "account" },
        { key: "RootDirPath", kind: "path" },
        { key: "UninstallString", kind: "code" },
        { key: "RegistryKeyPath", kind: "path" },
      ]},
      // ProgramInstanceId / MsiPackageCode are low-value GUIDs — dropped from
      // the curated view (still in "전체 필드 보기").
      { heading: "식별자", fields: [
        { key: "ProgramId", kind: "hash" },
        { key: "PackageFullName" },
        { key: "MsiProductCode", kind: "hash" },
      ]},
    ],
  },

  Amcache_Files: {
    title: (r) => r.name || basename(r.lower_case_long_path) || "(no name)",
    subtitle: (r) => [r.product_name, r.version].filter(Boolean).join(" · "),
    badges: [
      { key: "binary_type", kind: "badge" },
      { key: "is_os_component", label: "OS 구성요소", kind: "badge", badgeColors: { True: "#3fb950", False: "#8a8a8a" } },
    ],
    // Filename-vs-internal-name mismatch is a classic masquerading signal
    // on top of the general suspicious-path check.
    // 구형(Win7/2008R2, Root\File) 포맷 행은 full_path/created/last_modified
    // 컬럼으로 식별된다(신형 스키마엔 없는 컬럼). 구형엔 HiddenArp·내부
    // 파일명·링크 시각이 존재하지 않아 관련 배지·태그가 절대 발화하지
    // 않으므로, "특이사항 없음"과 "판정 불가"를 화면에서 구분하게 알린다.
    tags: (r) => tagsForPath(r.lower_case_long_path).concat(executableNoteTags(r.name || basename(r.lower_case_long_path)))
      .concat(tagsForNameMismatch(r.name, r.original_file_name))
      .concat(tagsForMissingAmcachePublisher(r.publisher))
      .concat(r.full_path || r.created || r.last_modified ? [{
        label: "구형 Amcache 포맷",
        severity: "info" as const,
        description: "이 하이브는 구형(Win7/2008R2, Root\\File) 포맷입니다. 신형 포맷의 내부(원본) 파일명·링크(빌드) 시각·제어판 숨김(HiddenArp) 정보는 이 포맷에 존재하지 않아 관련 배지·판정이 표시되지 않습니다 — 특이사항이 없어서가 아니라 판정 자체가 불가능한 항목입니다.",
      }] : []),
    // No timelineField: reaches the master timeline via ExecutionHistory.
    priorityColumns: ["timestamp", "name", "lower_case_long_path", "product_name", "publisher", "size"],
    sections: [
      { heading: "시간", fields: [
        { key: "timestamp", label: "레지스트리 키 시각" },
        { key: "link_date", label: "링크(빌드) 시각" },
        // 구형(Root\File) 포맷 전용 — 신형 데이터에는 컬럼이 없어 자동으로
        // 숨겨진다. 파서가 FILETIME을 KST로 변환해 둔 실제 증거 시각인데
        // 스펙 밖이라 "전체 필드 보기"에만 묻혀 있던 것을 승격.
        { key: "created", label: "파일 생성 시각 (구형 포맷)" },
        { key: "last_modified", label: "파일 수정 시각 (구형 포맷)" },
      ]},
      { heading: "경로", fields: [
        { key: "lower_case_long_path", kind: "path" },
        { key: "original_file_name", label: "내부(원본) 파일명" },
      ]},
      { heading: "정보", fields: [
        { key: "publisher" },
        { key: "product_name" },
        { key: "size", kind: "bytes" },
      ]},
      // SHA1 is high value (malware lookup); program_id is just the link key
      // (already offered as a link above), so it's dropped from the fields.
      { heading: "해시 / 식별자", fields: [
        { key: "SHA1", kind: "hash" },
        { key: "file_id", kind: "hash" },
      ]},
    ],
  },

  // EventLog is now one table per source .evtx (Security, System, ...), each
  // resolved to this shared spec by resolveArtifactView() via its columns —
  // so the per-file logs still get the full catalog/tags/detail view.
  // 원본 레지스트리 레코드 — 실행 이력·레지스트리 특이사항의 북마크가
  // 원본 레코드로 승격되면 이 스펙으로 열린다(생 덤프 방지).
  // UserAssist 값 이름은 ROT13 인코딩이라 해독해 프로그램 이름으로 보여준다.
  Registry: {
    title: (r) => {
      const decoded = userAssistProgram(r);
      if (decoded) return decoded.split("\\").filter(Boolean).pop() || decoded;
      // BAM처럼 값 이름이 실행 파일 경로면 파일명만 제목으로 쓴다.
      if (/[\\/]/.test(r.value_name || "")) return basename(r.value_name) || r.value_name;
      return r.value_name || "Registry";
    },
    subtitle: (r) => (userAssistProgram(r) ? `UserAssist · ${r.last_write || ""}`.trim() : r.last_write || ""),
    tags: (r) => {
      const decoded = userAssistProgram(r);
      const name = decoded ? decoded.split("\\").filter(Boolean).pop() : basename(r.value_name);
      return executableNoteTags(name);
    },
    overviewTime: "hide",
    priorityColumns: ["last_write", "key_path", "value_name", "value_data"],
    sections: [
      { heading: "레지스트리 원본 레코드", fields: [
        { key: "_ua_program", label: "실행 프로그램 (UserAssist 해독)", kind: "path", compute: (r) => userAssistProgram(r) || undefined },
        { key: "last_write", label: "레지스트리 키 마지막 기록 시각" },
        { key: "key_path", label: "키 경로", kind: "path", compute: (r) => displayRegistryKeyPath(r.key_path, r._source_file) },
        { key: "value_name", label: "값 이름" },
        { key: "value_type", label: "값 유형", kind: "badge" },
        { key: "value_data", label: "값 데이터", kind: "code" },
        { key: "_recovery", label: "레코드 상태", kind: "badge" },
        { key: "_source_file", label: "원본 하이브", kind: "path" },
      ]},
    ],
  },

  // SRUM 원본 레코드 — 실행 이력의 SRUM(첫 관찰) 항목이 승격되는 대상.
  SRUM_ApplicationResourceUsage: {
    title: (r) => basename(r.app) || "SRUM",
    subtitle: (r) => (r.app ? `SRUM · ${r.timestamp || ""}`.trim() : r.timestamp || ""),
    tags: (r) => executableNoteTags(basename(r.app)),
    overviewTime: "hide",
    priorityColumns: ["timestamp", "app", "user"],
    sections: [
      { heading: "SRUM 애플리케이션 리소스 사용", fields: [
        { key: "timestamp", label: "기록 시각" },
        { key: "app", label: "애플리케이션", kind: "path" },
        { key: "user", label: "사용자", kind: "account" },
        { key: "ForegroundCycleTime", label: "포그라운드 CPU 사이클" },
        { key: "BackgroundCycleTime", label: "백그라운드 CPU 사이클" },
        { key: "_source_file", label: "원본 파일", kind: "path" },
      ]},
    ],
  },

  EventLog_Events: {
    // Detail framing names the evidence type only. The timeline has its own
    // event title below, so EventLog's internal source table never leaks as
    // an analyst-facing title such as "EventLogs".
    title: () => "EventLog",
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    timelineTitle: eventLogTimelineTitle,
    timelineSubtitle: (r) => [r.Provider, r.Channel].filter(Boolean).join(" · "),
    // Level (Critical/Error) is a generic OS signal; tagsForSecurityEvent
    // adds the IR-specific ones — RDP/network logon type, SMB share access,
    // service/scheduled-task persistence, audit log clearing, suspicious
    // PowerShell, group-membership changes, etc. Anything not in the
    // curated catalog simply yields no extra tag, it isn't hidden.
    tags: (r) => {
      const base = tagsForEventLevel(r.LevelName).concat(tagsForSecurityEvent(r.Provider, r.EventID, r.EventData));
      const catalog = lookupEventCatalog(r.Provider, r.EventID);
      return catalog ? base.concat([{ label: catalog.label, severity: "info", description: `이벤트 카탈로그 · ${catalog.category}` }]) : base;
    },
    timelineField: "timestamp",
    timelineInclude: includeEventLogTimeline,
    computedColumns: [
      { key: "_ir_label", label: "이벤트 설명", size: 240, compute: (r) => lookupEventCatalog(r.Provider, r.EventID)?.label ?? "" },
      { key: "_ir_category_col", label: "구분", size: 100, compute: (r) => lookupEventCatalog(r.Provider, r.EventID)?.category ?? "" },
      ...EVENT_QUICK_FIELDS.map((f) => ({
        key: `_ed_${f.jsonKey}`,
        label: f.label,
        size: 160,
        compute: (r: Record<string, string>) => {
          const raw = extractEventField(r, f.jsonKey);
          return f.valueLabels?.[raw] ?? raw;
        },
      })),
    ],
    priorityColumns: ["timestamp", "Provider", "EventID", "LevelName", "Channel", "Computer"],
    sections: [
      { heading: "이벤트 로그", fields: [
        { key: "Channel", label: "채널" },
        { key: "Provider", label: "공급자" },
        { key: "EventID", label: "Event ID" },
        { key: "LevelName", label: "수준", kind: "badge", badgeColors: LEVEL_COLORS },
        {
          key: "_logon_type_field",
          label: "로그온 유형",
          kind: "badge",
          compute: (r) => {
            const lt = extractEventField(r, "LogonType");
            return lt ? formatLogonType(lt) : undefined;
          },
        },
        // Writer SID as an account label (name from the host account directory).
        { key: "UserID", label: "계정", kind: "account" },
      ]},
      // Every field below renders only when the event actually carries it, so a
      // single section adapts per Event ID: BITS shows its URL/파일, a logon
      // shows accounts/IP, a service-install shows the image path, and so on.
      { heading: "이벤트 데이터", fields: [
        // Accounts / logon / remote access / SMB / persistence
        edField("TargetUserName", "대상 계정", { kind: "account" }),
        edField("TargetDomainName", "대상 도메인"),
        edField("SubjectUserName", "수행 계정", { kind: "account" }),
        edField("WorkstationName", "워크스테이션"),
        edField("IpAddress", "원격 IP"),
        edField("IpPort", "원격 포트"),
        edField("ShareName", "공유 이름(SMB)", { kind: "path" }),
        edField("RelativeTargetName", "접근한 파일(SMB)", { kind: "path" }),
        edField("ServiceName", "서비스 이름"),
        edField("ImagePath", "서비스 실행 파일", { kind: "path" }),
        edField("TaskName", "예약 작업 이름"),
        edField("PrivilegeList", "부여된 권한", { kind: "privileges" }),
        edField("FailureReason", "실패 사유"),
        edField("Status", "상태 코드"),
        edField("ScriptBlockText", "PowerShell 스크립트 원문", { kind: "code" }),
        // Windows Error Reporting (Application 1001) — crash details
        { key: "_wer_name", label: "이벤트 이름 (오류 유형)", compute: (r) => (isWerEvent(r) ? extractEventField(r, "EventName") || undefined : undefined) },
        { key: "_wer_app", label: "오류 발생 프로그램", compute: (r) => (isWerEvent(r) ? extractEventField(r, "P1") || undefined : undefined) },
        { key: "_wer_path", label: "오류 발생 프로그램 경로", kind: "path", compute: (r) => (isWerEvent(r) ? werAppPath(r) : undefined) },
        { key: "_wer_reason", label: "오류 원인", compute: (r) => (isWerEvent(r) ? werReason(r) : undefined) },
        // BITS transfer (Bits-Client) — download job details
        edField("url", "URL", { kind: "path" }),
        edField("name", "작업 이름"),
        edField("Id", "작업 ID", { kind: "hash" }),
        edField("fileTime", "파일 시각"),
        edField("fileLength", "파일 크기(byte)"),
        edField("bytesTotal", "전체 바이트"),
        edField("bytesTransferred", "전송된 바이트"),
        edField("peer", "피어"),
        // Firewall rule changes
        edField("RuleName", "방화벽 규칙"),
        edField("ApplicationPath", "대상 프로그램", { kind: "path" }),
      ]},
      // Classic Windows PowerShell events (400/403/500/600/800) pack their
      // detail into a tab-delimited `Key=Value` text blob, so the JSON section
      // below is unreadable at a glance. Surface the investigation-relevant
      // fields here; each hides when absent, and the whole section disappears
      // for any non-classic event (every field resolves empty).
      { heading: "PowerShell 실행 정보 (파싱)", fields: [
        { key: "_ps_host_application", label: "HostApplication", kind: "code", compute: (r) => extractPsClassicField(r, "HostApplication") },
        { key: "_ps_script_name", label: "ScriptName", kind: "path", compute: (r) => extractPsClassicField(r, "ScriptName") },
        { key: "_ps_command_line", label: "CommandLine", kind: "code", compute: (r) => extractPsClassicField(r, "CommandLine") },
        { key: "_ps_user_id", label: "UserId (계정)", kind: "account", compute: (r) => extractPsClassicField(r, "UserId") },
        { key: "_ps_host_name", label: "HostName", compute: (r) => extractPsClassicField(r, "HostName") },
        { key: "_ps_host_version", label: "HostVersion", compute: (r) => extractPsClassicField(r, "HostVersion") },
        { key: "_ps_engine_version", label: "EngineVersion", compute: (r) => extractPsClassicField(r, "EngineVersion") },
        { key: "_ps_runspace_id", label: "RunspaceId", kind: "hash", compute: (r) => extractPsClassicField(r, "RunspaceId") },
        { key: "_ps_pipeline_id", label: "PipelineId", compute: (r) => extractPsClassicField(r, "PipelineId") },
        { key: "_ps_host_id", label: "HostId", kind: "hash", compute: (r) => extractPsClassicField(r, "HostId") },
        { key: "_ps_sequence_number", label: "SequenceNumber", compute: (r) => extractPsClassicField(r, "SequenceNumber") },
      ]},
      { heading: "원본 (EventData)", fields: [{ key: "EventData", kind: "json" }] },
      { heading: "오류", fields: [{ key: "_error", kind: "code" }] },
    ],
  },

  JumpList_Entries: {
    // Evidence overview follows the shared detail rule: the evidence type and
    // its primary time only. Target path, collection type, and parsing state
    // are evidence fields, so they belong in the sections below.
    title: () => "JumpList",
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    // The timeline describes the observed target, while the detail drawer
    // intentionally keeps its evidence-type-only overview above.
    timelineTitle: (r) => basename(r.target_path) || r.app_id || "JumpList 항목",
    timelineSubtitle: (r) => r.target_path || "",
    tags: (r) => tagsForPath(r.target_path),
    timelineFields: [
      { key: "created_time", label: "LNK 생성" },
      { key: "modified_time", label: "LNK 수정" },
      { key: "timestamp", label: "마지막 사용" },
    ],
    timelineHeading: "사용 시간 흐름",
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "target_path", "jumplist_type", "arguments"],
    sections: [
      { heading: "사용 기록 (DestList)", fields: [
        { key: "timestamp", label: "마지막 사용 시각" },
        { key: "access_count", label: "사용 횟수" },
        { key: "hostname", label: "호스트명" },
      ]},
      { heading: "LNK 헤더 시간", fields: [
        { key: "lnk_accessed", label: "LNK 헤더 접근 시각" },
        { key: "created_time", label: "LNK 헤더 생성 시각" },
        { key: "modified_time", label: "LNK 헤더 수정 시각" },
      ]},
      { heading: "대상 및 실행 정보", fields: [
        { key: "target_path", label: "대상 경로", kind: "path" },
        { key: "arguments", label: "실행 인수", kind: "code" },
        { key: "working_directory", label: "작업 디렉터리", kind: "path" },
      ]},
      { heading: "JumpList 출처", fields: [
        { key: "_source_account", label: "수집 사용자", kind: "account", compute: (r) => accountFromJumpListSource(r._source_file) || undefined },
        { key: "app_id", label: "App ID", kind: "hash" },
        { key: "jumplist_type", label: "JumpList 유형", kind: "badge" },
        { key: "stream_id", label: "LNK 스트림 / 엔트리 ID" },
        { key: "machine_id", label: "Distributed Link Tracker Machine ID" },
      ]},
      { heading: "파싱 상태", fields: [{ key: "_error", label: "파싱 오류", kind: "code" }] },
    ],
  },

  Prefetch_Execution: {
    title: (r) => r.executable_filename || "(no exe)",
    subtitle: (r) => (r.run_count ? `실행 ${r.run_count}회` : ""),
    tags: (r) => executableNoteTags(r.executable_filename),
    badges: [{ key: "_status", kind: "badge", badgeColors: STATUS_COLORS }],
    embeddedLinks: [{ key: "prefetch_hash", label: "Prefetch에 기록된 참조 파일", targetFile: "Prefetch_LoadedFiles", targetColumn: "prefetch_hash" }],
    // No timelineField: Prefetch reaches the master timeline via ExecutionHistory.
    priorityColumns: ["last_run_time", "executable_filename", "run_count"],
    sections: [
      { heading: "Prefetch 실행 시간", collapsible: {
        defaultExpanded: false,
        summary: (r, count) => `${r.last_run_time || "시간 정보 없음"} · ${count}건`,
      }, fields: [
        { key: "last_run_time", label: "최근 실행 시각" },
        { key: "run_time_2", label: "이전 실행 1" },
        { key: "run_time_3", label: "이전 실행 2" },
        { key: "run_time_4", label: "이전 실행 3" },
        { key: "run_time_5", label: "이전 실행 4" },
        { key: "run_time_6", label: "이전 실행 5" },
        { key: "run_time_7", label: "이전 실행 6" },
        { key: "run_time_8", label: "이전 실행 7" },
      ]},
      { heading: "볼륨", fields: [
        { key: "volume_device_path" },
        { key: "volume_serial_number", kind: "hash" },
        { key: "volume_creation_time" },
      ]},
      // format_version is a parser detail, not investigative — dropped.
      { heading: "식별자", fields: [
        { key: "prefetch_hash", kind: "hash" },
      ]},
      { heading: "오류", fields: [{ key: "_error", kind: "code" }] },
    ],
  },

  Prefetch_LoadedFiles: {
    title: (r) => basename(r.loaded_filename) || "(no file)",
    subtitle: (r) => r.executable_filename || "",
    links: [{ key: "executable_filename", label: "이 실행 파일의 실행 기록 보기", targetFile: "Prefetch_Execution", targetColumn: "executable_filename" }],
    priorityColumns: ["executable_filename", "loaded_filename"],
    sections: [{ heading: "상세", fields: [
      { key: "loaded_filename", kind: "path" },
      { key: "file_reference" },
    ]}],
  },




  TaskScheduler_Tasks: {
    title: (r) => r.task_name || r.uri || "(작업)",
    subtitle: (r) => r.uri || r.actions || "",
    badges: [
      { key: "enabled", label: "사용", kind: "badge", badgeColors: BOOL_COLORS },
      { key: "hidden", label: "숨김", kind: "badge", badgeColors: { true: "#d29922", false: "#8a8a8a" } },
      { key: "run_level", kind: "badge" },
    ],
    // A hidden task, and a task whose action runs from a suspicious path, are
    // both classic persistence signals.
    tags: (r) =>
      tagsForBoolean(r.hidden, {
        label: "숨겨진 작업(Hidden)",
        severity: "warning",
        description: "이 예약 작업은 Task Scheduler UI에 숨겨지도록 설정되어 있습니다. 정상 작업도 일부 숨김을 쓰지만, 공격자가 지속성 확보용 작업을 감추는 수법이기도 하니 실행 명령을 확인하세요.",
      }).concat(tagsForPath(r.actions)),
    // Only these 7 in the table; everything else lives in the detail panel.
    visibleColumns: ["timestamp", "task_name", "actions", "enabled", "hidden", "run_as", "run_level"],
    priorityColumns: ["timestamp", "task_name", "actions", "enabled", "hidden", "run_as", "run_level"],
    sections: [
      { heading: "실행 동작", fields: [{ key: "actions", kind: "code" }] },
      { heading: "실행 주체", fields: [
        { key: "run_as", label: "실행 계정", kind: "account" },
        { key: "run_level", label: "권한 수준" },
        { key: "logon_type", label: "로그온 유형" },
      ]},
      { heading: "트리거", fields: [
        { key: "trigger_types", label: "트리거 종류" },
        { key: "trigger_start", label: "시작 경계" },
      ]},
      { heading: "등록 정보", fields: [
        { key: "timestamp", label: "등록 시각" },
        { key: "enabled", label: "사용 여부" },
        { key: "hidden", label: "숨김" },
        { key: "author", label: "작성자" },
        { key: "description", label: "설명" },
        { key: "uri", label: "전체 경로(URI)", kind: "path" },
      ]},
    ],
  },



};

export function getArtifactView(fileBaseName: string): ArtifactViewSpec | null {
  return VIEWS[fileBaseName] ?? null;
}

// Resolve a table to its view spec. Prefer an exact name match; otherwise, if
// the table's columns look like an EventLog record (every .evtx is now its own
// table with an arbitrary name — Security, System, Microsoft-Windows-…), fall
// back to the shared EventLog spec so per-file logs keep the rich catalog/tag
// view instead of rendering as a plain column dump.
export function resolveArtifactView(fileBaseName: string, columns?: string[]): ArtifactViewSpec | null {
  const exact = VIEWS[fileBaseName];
  if (exact) return exact;
  if (columns && columns.includes("EventID") && columns.includes("Provider") && columns.includes("EventData")) {
    return VIEWS.EventLog_Events;
  }
  return null;
}
