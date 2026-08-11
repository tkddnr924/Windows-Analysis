import { tagsForBoolean, tagsForEventLevel, tagsForNameMismatch, tagsForPath, type Tag } from "./tagging";
import { lookupEventCatalog, parseEventData, extractEventField, tagsForSecurityEvent, EVENT_QUICK_FIELDS, LOGON_TYPE_LABELS } from "./eventCatalog";

export type FieldKind = "text" | "path" | "code" | "hash" | "bytes" | "json" | "badge" | "privileges";

export interface FieldSpec {
  key: string;
  label?: string;
  kind?: FieldKind;
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

export interface ArtifactViewSpec {
  title: (row: Record<string, string>) => string;
  subtitle?: (row: Record<string, string>) => string;
  badges?: FieldSpec[];
  tags?: (row: Record<string, string>) => Tag[];
  timelineFields?: TimelineFieldSpec[];
  /**
   * Name of the row's leading time column, ONLY when this artifact belongs
   * in the cross-artifact Master Timeline. Absent on purpose for tables with
   * no meaningful single timestamp (e.g. Prefetch_LoadedFiles) and for the
   * _OVERVIEW correlation tables (already-derived summaries — including them
   * would double-count the same events alongside their raw source rows).
   */
  timelineField?: string;
  links?: LinkSpec[];
  sections: { heading: string; fields: FieldSpec[] }[];
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
  customView?: "targetInfo" | "executionHistory" | "powershellFlow" | "defender" | "registryFindings" | "rdpCache" | "browserHistory";
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

const VIEWS: Record<string, ArtifactViewSpec> = {
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

  ExecutionHistory: {
    customView: "executionHistory",
    // Feed the master timeline from this curated stream, not the raw execution
    // artifacts: it's the only place SRUM (first sighting), AppCompatCache/
    // ShimCache, BAM and UserAssist get a normalized timestamp, and it already
    // merges + dedups Amcache/Prefetch. The raw Amcache/Prefetch specs drop
    // their own timelineField so those don't double-count here.
    timelineField: "timestamp",
    title: (r) => r.program_name || basename(r.program_path) || "(no name)",
    // Lead with the source (SRUM / AppCompatCache / Amcache / BAM / UserAssist)
    // so the merged execution entries stay distinguishable in the timeline.
    subtitle: (r) => [r.source_artifact, r.program_path].filter(Boolean).join(" · "),
    badges: [{ key: "source_artifact", label: "출처", kind: "badge" }],
    tags: (r) => tagsForPath(r.program_path),
    priorityColumns: ["timestamp", "program_name", "program_path", "run_count", "source_artifact"],
    sections: [
      { heading: "실행/사용 통계", fields: [
        { key: "run_count", label: "실행 횟수" },
        { key: "focus_count", label: "포커스 횟수" },
        { key: "focus_time_ms", label: "포커스 시간(ms)" },
      ]},
      { heading: "정보", fields: [
        { key: "publisher" },
        { key: "sha1", kind: "hash" },
      ]},
    ],
  },

  BrowserActivity: {
    customView: "browserHistory",
    title: (r) => r.title || r.url || "(no url)",
    subtitle: (r) => r.url || "",
    badges: [{ key: "kind", kind: "badge" }],
    priorityColumns: ["account", "kind", "timestamp", "title", "url", "size", "source_url"],
    sections: [{ heading: "상세", fields: [
      { key: "account", label: "계정" },
      { key: "kind", label: "종류" },
      { key: "url", label: "URL(디코딩)" },
      { key: "url_raw", label: "URL(원본)" },
      { key: "visit_count", label: "방문 횟수" },
      { key: "detail", label: "저장 경로" },
      { key: "source_url", label: "출처" },
      { key: "size", label: "크기" },
      { key: "mime", label: "유형" },
    ]}],
  },

  RegistryFindings: {
    customView: "registryFindings",
    title: (r) => r.name || "(no name)",
    subtitle: (r) => r.value || "",
    badges: [{ key: "status", kind: "badge" }],
    priorityColumns: ["category", "status", "name", "value", "detail", "user", "source"],
    sections: [{ heading: "상세", fields: [
      { key: "category", label: "분류" },
      { key: "status", label: "상태" },
      { key: "value", label: "값" },
      { key: "detail", label: "설명" },
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

  PowerShellHistory: {
    customView: "powershellFlow",
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

  UserAssist_Execution: {
    title: (r) => basename(r.program_path) || r.program_path || "(no name)",
    subtitle: (r) => r.user || "",
    tags: (r) => tagsForPath(r.program_path),
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "program_path", "run_count", "focus_count", "user"],
    sections: [
      { heading: "실행/사용 통계", fields: [
        { key: "run_count", label: "실행 횟수" },
        { key: "focus_count", label: "포커스 횟수" },
        { key: "focus_time_ms", label: "포커스 시간(ms)" },
      ]},
      { heading: "경로", fields: [{ key: "program_path", kind: "path" }] },
    ],
  },

  RemoteAccess_RDPClientHistory: {
    title: (r) => r.server || "(no server)",
    subtitle: (r) => r.username_hint || "",
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "server", "username_hint", "user"],
    sections: [{ heading: "상세", fields: [
      { key: "username_hint", label: "사용자 힌트" },
      { key: "cert_hash", kind: "hash" },
    ]}],
  },

  Registry_NetworkProfiles: {
    title: (r) => r.profile_name || "(no name)",
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "profile_name"],
    sections: [{ heading: "상세", fields: [{ key: "profile_name", label: "네트워크 이름" }] }],
  },

  Registry_NetworkInterfaces: {
    title: (r) => r.ip_address || "(no ip)",
    subtitle: (r) => [r.default_gateway && `GW ${r.default_gateway}`, r.domain].filter(Boolean).join(" · "),
    badges: [{ key: "dhcp_enabled", label: "DHCP", kind: "badge" }],
    priorityColumns: ["ip_address", "subnet_mask", "default_gateway", "dns_server", "dhcp_server", "domain", "lease_obtained"],
    sections: [
      { heading: "주소", fields: [
        { key: "ip_address", label: "IP 주소" },
        { key: "subnet_mask", label: "서브넷 마스크" },
        { key: "default_gateway", label: "기본 게이트웨이" },
      ]},
      { heading: "DNS / 도메인", fields: [
        { key: "dns_server", label: "DNS 서버" },
        { key: "dhcp_server", label: "DHCP 서버" },
        { key: "domain", label: "도메인" },
        { key: "dhcp_enabled", label: "DHCP 사용" },
      ]},
      { heading: "DHCP 임대", fields: [
        { key: "lease_obtained", label: "임대 시작" },
        { key: "lease_terminates", label: "임대 만료" },
      ]},
      { heading: "식별자", fields: [
        { key: "interface_guid", label: "인터페이스 GUID", kind: "hash" },
        { key: "control_set", label: "ControlSet" },
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
      { key: "UserSid", label: "설치한 계정의 프로필 정보 보기", targetFile: "Registry_UserProfiles", targetColumn: "sid" },
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
    tags: (r) => tagsForPath(r.lower_case_long_path).concat(tagsForNameMismatch(r.name, r.original_file_name)),
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
    title: (r) => {
      const catalog = lookupEventCatalog(r.Provider, r.EventID);
      const base = catalog ? `Event ${r.EventID} · ${catalog.label}` : `Event ${r.EventID}`;
      // On logon events the LogonType is the single most important qualifier
      // (network vs RDP vs console), so fold it straight into the title.
      const logonType = logonTypeLabel(r);
      return logonType ? `${base} · ${logonType}` : base;
    },
    subtitle: (r) => r.Provider || "",
    badges: [
      { key: "LevelName", kind: "badge", badgeColors: LEVEL_COLORS },
      { key: "_status", kind: "badge", badgeColors: STATUS_COLORS },
      {
        key: "_ir_category",
        label: "구분",
        kind: "badge",
        compute: (r) => lookupEventCatalog(r.Provider, r.EventID)?.category,
      },
      {
        key: "_logon_type",
        label: "로그온 유형",
        kind: "badge",
        compute: (r) => logonTypeLabel(r) || undefined,
      },
    ],
    // Level (Critical/Error) is a generic OS signal; tagsForSecurityEvent
    // adds the IR-specific ones — RDP/network logon type, SMB share access,
    // service/scheduled-task persistence, audit log clearing, suspicious
    // PowerShell, group-membership changes, etc. Anything not in the
    // curated catalog simply yields no extra tag, it isn't hidden.
    tags: (r) => tagsForEventLevel(r.LevelName).concat(tagsForSecurityEvent(r.Provider, r.EventID, r.EventData)),
    links: [{ key: "UserID", label: "이 계정(SID)의 프로필 정보 보기", targetFile: "Registry_UserProfiles", targetColumn: "sid" }],
    timelineField: "timestamp",
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
      // EventRecordID / ProcessID / ThreadID are low-value at a glance, so
      // they're left out of this curated view — "전체 필드 보기" still shows
      // them. LogonType leads because it's the headline fact for logon events.
      { heading: "기본 정보", fields: [
        {
          key: "EventData.LogonType",
          label: "로그온 유형",
          kind: "badge",
          compute: (r) => {
            const lt = extractEventField(r, "LogonType");
            return lt ? formatLogonType(lt) : undefined;
          },
        },
        { key: "Channel" },
        { key: "Computer" },
        { key: "UserID" },
      ]},
      { heading: "보안 이벤트 상세 (로그온/원격 접속/SMB/영속성)", fields: [
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
      ]},
      { heading: "이벤트 데이터 (원본)", fields: [{ key: "EventData", kind: "json" }] },
      { heading: "오류", fields: [{ key: "_error", kind: "code" }] },
    ],
  },

  JumpList_Entries: {
    title: (r) => basename(r.target_path) || r.app_id || "(no target)",
    subtitle: (r) => r.target_path || "",
    badges: [
      { key: "jumplist_type", kind: "badge" },
      { key: "_status", kind: "badge", badgeColors: STATUS_COLORS },
    ],
    tags: (r) => tagsForPath(r.target_path),
    timelineFields: [
      { key: "created_time", label: "생성" },
      { key: "modified_time", label: "수정" },
      { key: "timestamp", label: "마지막 접근" },
    ],
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "target_path", "jumplist_type", "arguments"],
    sections: [
      { heading: "시간", fields: [
        { key: "timestamp", label: "마지막 접근 시각" },
        { key: "created_time" },
        { key: "modified_time" },
      ]},
      { heading: "실행 정보", fields: [
        { key: "target_path", kind: "path" },
        { key: "arguments", kind: "code" },
        { key: "working_directory", kind: "path" },
      ]},
      // machine_id / stream_id are internal jumplist bookkeeping — dropped;
      // app_id stays (it identifies the source application).
      { heading: "식별자", fields: [
        { key: "app_id", kind: "hash" },
      ]},
      { heading: "오류", fields: [{ key: "_error", kind: "code" }] },
    ],
  },

  Prefetch_Execution: {
    title: (r) => r.executable_filename || "(no exe)",
    subtitle: (r) => (r.run_count ? `실행 ${r.run_count}회` : ""),
    badges: [{ key: "_status", kind: "badge", badgeColors: STATUS_COLORS }],
    links: [{ key: "executable_filename", label: "이 실행 파일이 로드한 DLL/파일 보기", targetFile: "Prefetch_LoadedFiles", targetColumn: "executable_filename" }],
    timelineFields: [
      { key: "run_time_8", label: "8회 전" },
      { key: "run_time_7", label: "7회 전" },
      { key: "run_time_6", label: "6회 전" },
      { key: "run_time_5", label: "5회 전" },
      { key: "run_time_4", label: "4회 전" },
      { key: "run_time_3", label: "3회 전" },
      { key: "run_time_2", label: "2회 전" },
      { key: "last_run_time", label: "최근 실행" },
    ],
    // No timelineField: Prefetch reaches the master timeline via ExecutionHistory.
    priorityColumns: ["last_run_time", "executable_filename", "run_count"],
    sections: [
      { heading: "최근 실행 시각 (최신순)", fields: [
        { key: "last_run_time" },
        { key: "run_time_2" },
        { key: "run_time_3" },
        { key: "run_time_4" },
        { key: "run_time_5" },
        { key: "run_time_6" },
        { key: "run_time_7" },
        { key: "run_time_8" },
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

  Registry_Run: {
    title: (r) => r.value_name || "(no name)",
    subtitle: (r) => r.key_path || "",
    badges: [
      { key: "hive", kind: "badge" },
      { key: "run_type", kind: "badge" },
    ],
    tags: (r) => tagsForPath(r.value_data),
    timelineField: "key_last_write",
    priorityColumns: ["key_last_write", "value_name", "value_data", "run_type"],
    sections: [
      { heading: "시간", fields: [{ key: "key_last_write" }] },
      { heading: "명령", fields: [
        { key: "value_data", kind: "code" },
        { key: "key_path", kind: "path" },
      ]},
    ],
  },

  Registry_InstalledPrograms: {
    title: (r) => r.display_name || "(no name)",
    subtitle: (r) => [r.display_version, r.publisher].filter(Boolean).join(" · "),
    tags: (r) => tagsForPath(r.install_location).concat(tagsForPath(r.uninstall_string)),
    timelineField: "install_date",
    priorityColumns: ["install_date", "display_name", "display_version", "publisher"],
    sections: [
      { heading: "날짜", fields: [
        { key: "install_date" },
        { key: "key_last_write" },
      ]},
      { heading: "위치", fields: [
        { key: "install_location", kind: "path" },
        { key: "uninstall_string", kind: "code" },
        { key: "estimated_size_kb", label: "예상 크기(KB)" },
      ]},
      { heading: "레지스트리 키", fields: [{ key: "registry_key", kind: "path" }] },
    ],
  },

  Registry_UserProfiles: {
    title: (r) => basename(r.profile_image_path) || r.sid || "(no profile)",
    subtitle: (r) => r.sid || "",
    timelineFields: [
      { key: "load_time", label: "로드(로그온)" },
      { key: "unload_time", label: "언로드(로그오프)" },
    ],
    timelineField: "load_time",
    priorityColumns: ["load_time", "profile_image_path", "unload_time", "sid"],
    sections: [
      { heading: "시간", fields: [
        { key: "load_time", label: "마지막 로드(로그온)" },
        { key: "unload_time", label: "마지막 언로드(로그오프)" },
      ]},
      { heading: "상세", fields: [
        { key: "profile_image_path", kind: "path" },
        { key: "state" },
      ]},
    ],
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

  Registry_Accounts: {
    title: (r) => r.username || (r.rid ? `RID ${r.rid}` : "(계정)"),
    subtitle: (r) => [r.rid && `RID ${r.rid}`, r.disabled === "예" ? "비활성" : ""].filter(Boolean).join(" · "),
    badges: [{ key: "disabled", label: "비활성", kind: "badge", badgeColors: { 예: "#f85149", 아니오: "#3fb950" } }],
    // Account creation lands on the master timeline (a created backdoor account
    // is a common persistence step).
    timelineField: "account_created",
    priorityColumns: ["account_created", "username", "rid", "last_login", "login_count", "disabled", "special_account", "groups"],
    sections: [
      { heading: "계정", fields: [
        { key: "username", label: "사용자 이름" },
        { key: "full_name", label: "전체 이름" },
        { key: "rid", label: "RID" },
        { key: "home_directory", label: "홈 디렉토리", kind: "path" },
        { key: "disabled", label: "비활성 여부" },
        { key: "special_account", label: "SpecialAccount" },
      ]},
      { heading: "시간", fields: [
        { key: "account_created", label: "계정 생성" },
        { key: "last_login", label: "마지막 로그온" },
        { key: "password_last_set", label: "암호 마지막 설정" },
        { key: "last_failed_login", label: "비밀번호 오류 일시" },
      ]},
      { heading: "통계 / 권한", fields: [
        { key: "login_count", label: "로그온 횟수" },
        { key: "failed_login_count", label: "비밀번호 오류 횟수" },
        { key: "groups", label: "그룹" },
        { key: "account_flags", label: "계정 플래그" },
      ]},
    ],
  },

  Registry_SystemInfo: {
    title: (r) => r.name || "(no name)",
    subtitle: (r) => r.category || "",
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "name", "value", "category"],
    sections: [{ heading: "값", fields: [
      { key: "value" },
      { key: "timestamp" },
      { key: "source_path", kind: "path" },
    ]}],
  },

  Registry_USBDevices: {
    title: (r) => r.friendly_name || r.device_class || "(no device)",
    subtitle: (r) => r.device_class || "",
    timelineField: "key_last_write",
    priorityColumns: ["key_last_write", "friendly_name", "device_class", "service"],
    sections: [{ heading: "상세", fields: [
      { key: "key_last_write" },
      { key: "control_set" },
      { key: "instance_id", kind: "hash" },
      { key: "service" },
    ]}],
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
