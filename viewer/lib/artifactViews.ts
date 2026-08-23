import { tagsForBoolean, tagsForDangerType, tagsForEventLevel, tagsForNameMismatch, tagsForPath, type Tag } from "./tagging";
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
  customView?: "targetInfo" | "executionHistory" | "powershellFlow" | "defender" | "registryFindings" | "rdpCache" | "browserHistory" | "smb" | "scheduledTasks" | "wer" | "mft";
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

type ExecutionEvidence = "amcache" | "userAssist" | "srum" | "bam" | "prefetch" | "other";

function executionEvidence(row: Record<string, string>): ExecutionEvidence {
  const source = (row.source_artifact || "").toLowerCase();
  if (source.startsWith("amcache")) return "amcache";
  if (source === "userassist") return "userAssist";
  if (source === "srum") return "srum";
  if (source === "bam") return "bam";
  if (source === "prefetch") return "prefetch";
  return "other";
}

function executionSourceLabel(row: Record<string, string>): string {
  switch (executionEvidence(row)) {
    case "amcache": return "Amcache";
    case "userAssist": return "UserAssist";
    case "srum": return "SRUM";
    case "bam": return "BAM";
    case "prefetch": return "Prefetch";
    default: return row.source_artifact || "ExecutionHistory";
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

// A SID with a human label where one is knowable from the SID alone (built-in /
// service accounts, and the built-in Administrator RID 500). Mapping an
// arbitrary S-1-5-21-…-<RID≥1000> user SID to its account name needs the
// registry profile list, which isn't available to this row-only formatter.
const WELL_KNOWN_SID: Record<string, string> = {
  "S-1-5-18": "LocalSystem",
  "S-1-5-19": "LocalService",
  "S-1-5-20": "NetworkService",
  "S-1-1-0": "Everyone",
  "S-1-5-7": "Anonymous",
  "S-1-5-11": "Authenticated Users",
  "S-1-5-32-544": "Administrators",
  "S-1-5-32-545": "Users",
};
function sidLabel(sid: string | undefined): string {
  if (!sid) return "";
  const wk = WELL_KNOWN_SID[sid];
  if (wk) return `${sid} (${wk})`;
  const rid = sid.match(/-(\d+)$/)?.[1];
  if (/^S-1-5-21-/.test(sid) && rid === "500") return `${sid} (Administrator)`;
  return sid;
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

const VIEWS: Record<string, ArtifactViewSpec> = {
  // Windows Error Reporting — every report field lives in one `report` JSON
  // column; WerView parses it into fault-signature / loaded-modules sections.
  WER_Reports: {
    customView: "wer",
    title: (r) => r.AppName || "(WER)",
    subtitle: (r) => r.EventType || "",
    badges: [{ key: "EventType", kind: "badge" }],
    priorityColumns: ["timestamp", "EventType", "AppName", "AppPath", "TargetAppId", "ReportIdentifier"],
    sections: [{ heading: "보고서", fields: [{ key: "EventType" }, { key: "AppPath" }, { key: "ReportIdentifier" }, { key: "report", kind: "json" }] }],
  },
  // $MFT — Explorer-style browse (MftView queries SQLite lazily, since the
  // table can hold ~1M rows). No timelineField: each record carries eight
  // timestamps, bookmarked individually, rather than one event time.
  MFT_Records: {
    customView: "mft",
    title: (r) => r.file_name || (r.path ? r.path.split("\\").filter(Boolean).pop() ?? r.path : "") || "(MFT)",
    subtitle: (r) => r.path || "",
    priorityColumns: ["path", "file_name", "file_size", "extension", "is_directory", "in_use", "entry", "seq", "parent_entry", "owner_id", "security_id"],
    sections: [{ heading: "MFT 레코드", fields: [
      { key: "path", label: "경로", kind: "path" }, { key: "file_size", label: "크기", kind: "bytes" },
      { key: "extension", label: "확장자" }, { key: "is_directory", label: "디렉터리" }, { key: "in_use", label: "할당 상태" },
      { key: "entry", label: "엔트리" }, { key: "seq", label: "시퀀스" }, { key: "parent_entry", label: "부모 엔트리" },
    ]}, { heading: "$STANDARD_INFORMATION (0x10)", fields: [
      { key: "si_created", label: "생성", showWhenEmpty: true, bookmarkable: true }, { key: "si_modified", label: "수정", showWhenEmpty: true, bookmarkable: true },
      { key: "si_mft_modified", label: "MFT 수정", showWhenEmpty: true, bookmarkable: true }, { key: "si_accessed", label: "접근", showWhenEmpty: true, bookmarkable: true },
      { key: "owner_id", label: "할당량 소유자 ID", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
      { key: "security_id", label: "보안 ID ($Secure)", showWhenEmpty: true, emptyLabel: "원본 정보 없음" },
    ]}, { heading: "$FILE_NAME (0x30)", fields: [
      { key: "fn_created", label: "생성", showWhenEmpty: true, bookmarkable: true }, { key: "fn_modified", label: "수정", showWhenEmpty: true, bookmarkable: true },
      { key: "fn_mft_modified", label: "MFT 수정", showWhenEmpty: true, bookmarkable: true }, { key: "fn_accessed", label: "접근", showWhenEmpty: true, bookmarkable: true },
    ]}],
  },

  // --- 종합 분석 (_OVERVIEW/): cross-artifact correlation tables built by
  // common/correlate.py — one row here can come from several different
  // source artifacts, tagged via `source_artifact`. These summarize;
  // `links`/`event_record_id` send you back to the full raw record for
  // detail (e.g. RemoteAccessHistory -> EventLog_Events).
  TargetInfo: {
    customView: "targetInfo",
    title: (r) => r.name || "(no name)",
    subtitle: (r) => r.category || "",
    badges: [{ key: "category", kind: "badge" }],
    priorityColumns: ["category", "name", "value", "timestamp", "source_artifact"],
    sections: [{ heading: "값", fields: [
      { key: "value" },
      { key: "timestamp" },
      { key: "source_artifact", label: "출처" },
    ]}],
  },

  // TargetInfo renders a compact host-oriented dashboard. Network interfaces
  // open this dedicated shared-drawer definition so the list can stay IP-only
  // without losing any recovered TCP/IP evidence fields.
  TargetInfo_NetworkInterface: {
    title: () => "네트워크 어댑터",
    subtitle: (r) => r.value || "",
    overviewTime: "hide",
    priorityColumns: ["value", "subnet_mask", "gateway", "dns_server", "dhcp_server", "domain"],
    sections: [
      { heading: "네트워크 인터페이스", fields: [
        { key: "value", label: "IP 주소" },
        { key: "subnet_mask", label: "서브넷 마스크" },
        { key: "gateway", label: "기본 게이트웨이" },
      ]},
      { heading: "네트워크 구성", fields: [
        { key: "dns_server", label: "DNS 서버" },
        { key: "dhcp_server", label: "DHCP 서버" },
        { key: "dhcp_enabled", label: "DHCP 사용" },
        { key: "domain", label: "도메인" },
      ]},
      { heading: "DHCP 임대", fields: [
        { key: "lease_obtained", label: "임대 시작" },
        { key: "lease_terminates", label: "임대 만료" },
      ]},
      { heading: "식별 정보", fields: [
        { key: "name", label: "인터페이스 GUID" },
        { key: "source_artifact", label: "수집 아티팩트" },
      ]},
    ],
  },

  // NetworkList profile evidence is distinct from the TCP/IP interface
  // configuration above. The parser currently preserves the profile name,
  // last-connected time, and source artifact — no uncollected registry value
  // is inferred here.
  TargetInfo_NetworkProfile: {
    title: () => "연결한 네트워크",
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    priorityColumns: ["value", "timestamp", "source_artifact"],
    sections: [{ heading: "레지스트리 NetworkList 프로필", fields: [
      { key: "value", label: "프로필 이름" },
      { key: "timestamp", label: "마지막 연결 시각" },
      { key: "source_artifact", label: "수집 아티팩트" },
    ]}],
  },

  ExecutionHistory: {
    customView: "executionHistory",
    // Feed the master timeline from this curated stream, not the raw execution
    // artifacts: it's the only place SRUM (first sighting), AppCompatCache/
    // ShimCache, BAM and UserAssist get a normalized timestamp, and it already
    // merges + dedups Amcache/Prefetch. The raw Amcache/Prefetch specs drop
    // their own timelineField so those don't double-count here.
    timelineField: "timestamp",
    title: (r) => `ExecutionHistory:${executionSourceLabel(r)}`,
    timelineTitle: (r) => r.program_name || basename(r.program_path) || "(이름 없음)",
    // The timeline keeps the evidence source and path visible while the detail
    // drawer has one concise timestamp in its evidence overview.
    timelineSubtitle: (r) => [executionSourceLabel(r), r.program_path].filter(Boolean).join(" · "),
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    tags: (r) => executionEvidence(r) === "amcache"
      ? tagsForPath(r.program_path).concat(tagsForMissingAmcachePublisher(r.publisher))
      : tagsForPath(r.program_path),
    priorityColumns: ["timestamp", "program_name", "program_path", "run_count", "source_artifact"],
    sections: [
      { heading: "Amcache 프로그램 정보", fields: [
        { key: "program_name", label: "프로그램 이름", compute: (r) => executionValue("amcache", "program_name", r) },
        { key: "program_path", label: "프로그램 경로", kind: "path", compute: (r) => executionValue("amcache", "program_path", r) },
        { key: "publisher", label: "게시자", compute: (r) => executionValue("amcache", "publisher", r) },
        { key: "sha1", label: "SHA-1", kind: "hash", compute: (r) => executionValue("amcache", "sha1", r) },
      ]},
      { heading: "UserAssist 실행 정보", fields: [
        { key: "program_name", label: "실행 항목", compute: (r) => executionValue("userAssist", "program_name", r) },
        { key: "program_path", label: "원본 경로", kind: "path", compute: (r) => executionValue("userAssist", "program_path", r) },
        { key: "user", label: "실행 계정", kind: "account", compute: (r) => executionValue("userAssist", "user", r) },
        { key: "run_count", label: "실행 횟수", compute: (r) => executionValue("userAssist", "run_count", r) },
        { key: "focus_count", label: "포커스 횟수", compute: (r) => executionValue("userAssist", "focus_count", r) },
        { key: "focus_time_ms", label: "포커스 시간", kind: "durationMs", compute: (r) => executionValue("userAssist", "focus_time_ms", r) },
      ]},
      { heading: "SRUM 사용 정보", fields: [
        { key: "program_name", label: "응용 프로그램", compute: (r) => executionValue("srum", "program_name", r) },
        { key: "program_path", label: "응용 프로그램 경로", kind: "path", compute: (r) => executionValue("srum", "program_path", r) },
        { key: "user", label: "사용자", kind: "account", compute: (r) => executionValue("srum", "user", r) },
      ]},
      { heading: "BAM 실행 정보", fields: [
        { key: "program_name", label: "실행 파일", compute: (r) => executionValue("bam", "program_name", r) },
        { key: "program_path", label: "실행 경로", kind: "path", compute: (r) => executionValue("bam", "program_path", r) },
        { key: "user", label: "실행 계정", kind: "accountSid", compute: (r) => executionValue("bam", "user", r) },
      ]},
      { heading: "Prefetch 실행 정보", fields: [
        { key: "program_name", label: "실행 파일", compute: (r) => executionValue("prefetch", "program_name", r) },
        { key: "run_count", label: "실행 횟수", compute: (r) => executionValue("prefetch", "run_count", r) },
      ]},
      { heading: "Prefetch 실행 시간", collapsible: {
        defaultExpanded: false,
        summary: (r, count) => `${executionValue("prefetch", "timestamp", r) || "시간 정보 없음"} · ${count}건`,
      }, fields: [
        { key: "timestamp", label: "최근 실행 시각", compute: (r) => executionValue("prefetch", "timestamp", r) },
        { key: "run_time_2", label: "이전 실행 1", compute: (r) => executionValue("prefetch", "run_time_2", r) },
        { key: "run_time_3", label: "이전 실행 2", compute: (r) => executionValue("prefetch", "run_time_3", r) },
        { key: "run_time_4", label: "이전 실행 3", compute: (r) => executionValue("prefetch", "run_time_4", r) },
        { key: "run_time_5", label: "이전 실행 4", compute: (r) => executionValue("prefetch", "run_time_5", r) },
        { key: "run_time_6", label: "이전 실행 5", compute: (r) => executionValue("prefetch", "run_time_6", r) },
        { key: "run_time_7", label: "이전 실행 6", compute: (r) => executionValue("prefetch", "run_time_7", r) },
        { key: "run_time_8", label: "이전 실행 7", compute: (r) => executionValue("prefetch", "run_time_8", r) },
      ]},
      { heading: "Prefetch 볼륨 정보", fields: [
        { key: "volume_device_path", label: "볼륨 경로", kind: "path", compute: (r) => executionValue("prefetch", "volume_device_path", r) },
        { key: "volume_serial_number", label: "볼륨 일련 번호", kind: "hash", compute: (r) => executionValue("prefetch", "volume_serial_number", r) },
        { key: "volume_creation_time", label: "볼륨 생성 시각", compute: (r) => executionValue("prefetch", "volume_creation_time", r) },
      ]},
      { heading: "실행 정보", fields: [
        { key: "program_name", label: "항목 이름", compute: (r) => executionEvidence(r) === "other" ? r.program_name : "" },
        { key: "program_path", label: "항목 경로", kind: "path", compute: (r) => executionEvidence(r) === "other" ? r.program_path : "" },
        { key: "source_artifact", label: "원본 아티팩트", compute: (r) => executionEvidence(r) === "other" ? r.source_artifact : "" },
      ]},
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
    // registration timestamp. The action itself belongs in "실행 명령" below.
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    tags: (r) => tagsForPath(r.actions),
    timelineField: "timestamp",
    sections: [{ heading: "작업 스케줄러 정보", fields: [
      { key: "task_name", label: "작업 이름" },
      { key: "run_as", label: "실행 계정", kind: "accountSid" },
      { key: "actions", label: "실행 명령", kind: "code" },
      {
        key: "enabled",
        label: "작업 상태",
        kind: "badge",
        compute: (r) => {
          const value = (r.enabled || "").trim().toLowerCase();
          if (["1", "true", "yes", "enabled"].includes(value)) return "활성화됨";
          if (["0", "false", "no", "disabled"].includes(value)) return "비활성화됨";
          return value ? r.enabled : "설정 정보 없음";
        },
        badgeColors: { "활성화됨": "#3fb950", "비활성화됨": "#8a8a8a", "설정 정보 없음": "#8a8a8a" },
      },
      {
        key: "hidden",
        label: "표시 정책",
        kind: "badge",
        compute: (r) => {
          const value = (r.hidden || "").trim().toLowerCase();
          if (["1", "true", "yes"].includes(value)) return "숨김 처리됨";
          if (["0", "false", "no"].includes(value)) return "일반 표시";
          return value ? r.hidden : "설정 정보 없음";
        },
        badgeColors: { "숨김 처리됨": "#d29922", "일반 표시": "#4fc1ff", "설정 정보 없음": "#8a8a8a" },
      },
      {
        key: "trigger_types",
        label: "트리거 정보",
        compute: (r) => [r.trigger_types, r.trigger_start && `시작 경계 ${r.trigger_start}`].filter(Boolean).join(" · "),
      },
      { key: "description", label: "설명" },
    ]}],
  },

  BrowserActivity: {
    customView: "browserHistory",
    // Browser records use an evidence-type title, not a page title or URL:
    // those vary by source and belong in the browser-specific fields below.
    title: (r) => `BrowserActivity:${r.kind === "download" ? "Download" : r.kind === "cache" ? "Cache" : "Visit"}`,
    subtitle: (r) => r.timestamp || "",
    overviewTime: "hide",
    // The timeline already owns the timestamp column. Show the actual URL as
    // the event and keep its type on the secondary line; never reuse the
    // concise detail-panel evidence title here.
    timelineTitle: (r) => r.url || r.url_raw || r.title || "(URL 없음)",
    timelineSubtitle: (r) => r.kind === "download" ? "Download" : r.kind === "cache" ? "Cache" : "Visit",
    // BrowserActivity retains cache rows for the browser evidence view, but a
    // cache response is not a defensible browsing event. The master timeline
    // therefore contains only actual visits and downloads.
    timelineField: "timestamp",
    timelineInclude: (r) => r.kind === "visit" || r.kind === "download",
    tags: (r) => tagsForDangerType(r.danger).concat(r.kind === "download" ? tagsForPath(r.detail) : []),
    priorityColumns: ["account", "kind", "timestamp", "title", "url", "size_bytes", "source_url"],
    sections: [{
      heading: (r) => `브라우저 ${r.kind === "download" ? "다운로드" : r.kind === "cache" ? "캐시" : "접근"}`,
      fields: [
      { key: "title", label: "방문 Title", compute: (r) => r.title || "" },
      {
        key: "url_raw",
        label: "URL 원본",
        kind: "path",
        compute: (r) => r.kind === "cache" ? r.url : r.url_raw || r.url,
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
      { key: "visit_count", label: "방문 횟수", compute: (r) => r.kind === "visit" ? r.visit_count : "" },
      { key: "detail", label: "저장 경로", kind: "path", compute: (r) => r.kind === "download" ? r.detail : "" },
      {
        key: "size_bytes",
        label: "크기 (Bytes)",
        kind: "byteSize",
        compute: (r) => r.kind === "download" || r.kind === "cache" ? r.size_bytes || r.size : "",
      },
      { key: "mime", label: "다운로드 파일 유형", compute: (r) => r.kind === "download" ? r.mime : "" },
      {
        key: "cache_file_type",
        label: "파일 유형",
        compute: (r) => {
          if (r.kind !== "cache") return "";
          if (r.mime) return r.mime;
          const path = (r.url || "").split(/[?#]/)[0];
          const extension = path.includes(".") ? path.slice(path.lastIndexOf(".") + 1).toLowerCase() : "";
          return extension ? `.${extension}` : "알 수 없음";
        },
      },
      { key: "cache_data", label: "캐시 데이터", kind: "cacheData", compute: (r) => r.kind === "cache" ? "cache" : "" },
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

  RegistryFindings: {
    customView: "registryFindings",
    title: (r) => r.name || "(no name)",
    // The overview is intentionally terse: the registry path and status are
    // evidence fields below, while attention-only status appears once at the
    // bottom as a hoverable analysis tag.
    tags: tagsForRegistryFinding,
    priorityColumns: ["category", "status", "name", "value", "timestamp", "detail", "user", "source"],
    sections: [{ heading: "상세", fields: [
      { key: "category", label: "분류" },
      // Registry-derived findings inherit the source key's LastWrite time.
      // ShimCache is different: its timestamp is the cache entry's FILETIME,
      // not proof of a registry key write.
      { key: "timestamp", label: "레지스트리 키 마지막 기록 시각", compute: (r) => r.subtype === "ShimCache" ? "" : r.timestamp },
      { key: "timestamp", label: "ShimCache 캐시 항목 시각", compute: (r) => r.subtype === "ShimCache" ? r.timestamp : "" },
      { key: "value", label: "값" },
      { key: "command", label: "명령" },
      { key: "user", label: "사용자" },
      { key: "key_path", label: "키 경로" },
      { key: "source", label: "하이브" },
    ]}],
  },

  Defender: {
    customView: "defender",
    title: (r) => r.title || "(no name)",
    subtitle: (r) => r.detail || "",
    badges: [{ key: "section", kind: "badge" }],
    links: [{ key: "record_key", label: "원본 이벤트 로그 보기", targetFile: "EventLog_Events", targetColumn: "_record_key" }],
    priorityColumns: ["section", "timestamp", "title", "detail", "severity", "action", "user"],
    sections: [{ heading: "상세", fields: [
      { key: "severity", label: "심각도" },
      { key: "category", label: "분류" },
      { key: "action", label: "조치" },
      { key: "action_time", label: "조치 시각" },
      { key: "process", label: "프로세스" },
      { key: "user", label: "사용자" },
      { key: "source", label: "탐지원" },
      { key: "detail", label: "경로/내용" },
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
    title: (r) => (r.kind === "mosaic" ? `${r.source_file} (모자이크)` : `${r.source_file} 복원 조각 ${r.fragment_index}`),
    subtitle: (r) => (r.cols && r.rows ? `${r.cols}×${r.rows} 타일` : ""),
    sections: [{ heading: "복원 조각", fields: [
      { key: "kind", label: "종류" },
      { key: "source_file", label: "캐시 파일" },
      { key: "fragment_index", label: "조각 번호" },
      { key: "tile_count", label: "타일 수" },
      { key: "cols", label: "가로 타일" },
      { key: "rows", label: "세로 타일" },
    ]}],
  },

  RemoteDesktopHistory: {
    title: (r) => r.remote_address || "(주소 없음)",
    subtitle: (r) => r.description || "",
    badges: [
      { key: "direction", kind: "badge", badgeColors: DIRECTION_COLORS },
      { key: "result", label: "결과", kind: "badge", badgeColors: RDP_RESULT_COLORS },
    ],
    links: [{ key: "record_key", label: "이벤트 로그 원본 보기", targetFile: "EventLog_Events", targetColumn: "_record_key" }],
    // Shown as a session-grouped flow instead of a flat table.
    flowView: true,
    // (kept for when the raw table is viewed directly) Only these five are
    // worth scanning; provider/event_id/result/record_key stay in the data.
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
      { key: "account", label: "계정" },
      { key: "description", label: "설명" },
      { key: "result", label: "결과" },
      { key: "event_id", label: "이벤트 ID" },
      { key: "provider", label: "공급자" },
    ]}],
  },

  // Inbound SMB / network-logon activity (SMBServer/Security 551·1009 and, when
  // Security auditing is on, 4624/4625 LogonType 3). Same session-flow view as
  // RDP — repeated failures from one IP collapse into a burst, which reads as a
  // brute-force / lateral-movement attempt.
  SmbHistory: {
    customView: "smb",
    title: (r) => r.remote_address || "(주소 없음)",
    subtitle: (r) => r.description || "",
    badges: [
      { key: "direction", kind: "badge", badgeColors: DIRECTION_COLORS },
      { key: "result", label: "결과", kind: "badge", badgeColors: RDP_RESULT_COLORS },
    ],
    links: [{ key: "record_key", label: "이벤트 로그 원본 보기", targetFile: "EventLog_Events", targetColumn: "_record_key" }],
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
      { key: "account", label: "계정" },
      { key: "description", label: "설명" },
      { key: "result", label: "결과" },
      { key: "event_id", label: "이벤트 ID" },
      { key: "provider", label: "공급자" },
    ]}],
  },

  PowerShellHistory: {
    customView: "powershellFlow",
    // ScriptBlock and HostApplication can be arbitrarily long. Keep the
    // shared drawer's evidence title stable; both values are first-class
    // fields in the execution section below.
    title: (r) => r.command || r.kind || "(명령 없음)",
    subtitle: (r) => [r.account, r.process].filter(Boolean).join(" · "),
    badges: [
      { key: "kind", kind: "badge" },
      { key: "event_id", label: "이벤트 ID", kind: "badge" },
    ],
    tags: (r) => tagsForPath(r.script_path),
    links: [{ key: "record_key", label: "이벤트 로그 원본 보기", targetFile: "EventLog_Events", targetColumn: "_record_key" }],
    // (kept for when the raw table is viewed directly, but the flow view is
    // the default) — the five fields the analyst actually scans.
    visibleColumns: ["timestamp", "kind", "account", "process", "command"],
    priorityColumns: ["timestamp", "kind", "account", "process", "command"],
    sections: [
      { heading: "실행 정보", fields: [
        { key: "account", label: "수행 계정" },
        { key: "process", label: "수행 프로세스" },
        { key: "process_id", label: "프로세스 ID" },
        { key: "host_application", label: "호스트 애플리케이션", kind: "code", showWhenEmpty: true, emptyLabel: "기록되지 않음" },
        { key: "script_path", label: "스크립트 경로", kind: "path" },
      ]},
      { heading: "명령어", fields: [{ key: "command", kind: "code" }] },
      { heading: "코드 블록 (ScriptBlock)", fields: [{ key: "script_block", kind: "code" }] },
      { heading: "이벤트", fields: [
        { key: "event_id", label: "이벤트 ID" },
        { key: "provider", label: "공급자" },
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
    tags: (r) => tagsForBoolean(r.HiddenArp, { label: "제어판에서 숨김(HiddenArp)", severity: "danger", description: "제어판 '프로그램 추가/제거' 목록에서 의도적으로 숨겨진 프로그램입니다. 사용자 눈에 띄지 않게 하려는 자기은폐(self-concealment) 기법으로, 정상 소프트웨어에서는 드뭅니다." }),
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
        { key: "UserSid", label: "설치한 계정(SID)" },
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
    tags: (r) => tagsForPath(r.lower_case_long_path)
      .concat(tagsForNameMismatch(r.name, r.original_file_name))
      .concat(tagsForMissingAmcachePublisher(r.publisher)),
    links: [{ key: "program_id", label: "이 파일을 설치한 프로그램 보기", targetFile: "Amcache_Programs", targetColumn: "ProgramId" }],
    // No timelineField: reaches the master timeline via ExecutionHistory.
    priorityColumns: ["timestamp", "name", "lower_case_long_path", "product_name", "publisher", "size"],
    sections: [
      { heading: "시간", fields: [
        { key: "timestamp", label: "레지스트리 키 시각" },
        { key: "link_date", label: "링크(빌드) 시각" },
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
    tags: (r) => tagsForEventLevel(r.LevelName).concat(tagsForSecurityEvent(r.Provider, r.EventID, r.EventData)),
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
        // Writer SID → account: labels built-in/service SIDs (LocalSystem, …)
        // and the built-in Administrator; a plain user SID shows as-is.
        { key: "UserID", label: "UserID (계정)", compute: (r) => sidLabel(r.UserID) },
      ]},
      // Every field below renders only when the event actually carries it, so a
      // single section adapts per Event ID: BITS shows its URL/파일, a logon
      // shows accounts/IP, a service-install shows the image path, and so on.
      { heading: "이벤트 데이터", fields: [
        // Accounts / logon / remote access / SMB / persistence
        edField("TargetUserName", "대상 계정"),
        edField("TargetDomainName", "대상 도메인"),
        edField("SubjectUserName", "수행 계정"),
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
        { key: "_ps_user_id", label: "UserId (계정)", compute: (r) => extractPsClassicField(r, "UserId") },
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
      { key: "timestamp", label: "LNK 접근" },
    ],
    timelineHeading: "LNK 헤더 시간 흐름",
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "target_path", "jumplist_type", "arguments"],
    sections: [
      { heading: "LNK 헤더 시간", fields: [
        { key: "timestamp", label: "LNK 헤더 접근 시각" },
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
        { key: "run_as", label: "실행 계정" },
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
