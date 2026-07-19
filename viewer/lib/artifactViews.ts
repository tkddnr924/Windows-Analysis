import { tagsForBoolean, tagsForDangerType, tagsForEventLevel, tagsForNameMismatch, tagsForPath, type Tag } from "./tagging";
import { lookupEventCatalog, parseEventData, extractEventField, tagsForSecurityEvent, EVENT_QUICK_FIELDS, LOGON_TYPE_LABELS } from "./eventCatalog";

export type FieldKind = "text" | "path" | "code" | "hash" | "bytes" | "json" | "badge";

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
   * Synthetic table columns computed from the full row rather than read
   * directly off a CSV column — inserted right after the detail column,
   * ahead of every real column, so a derived "what happened" summary is
   * the first thing scanned instead of being buried behind raw fields.
   */
  computedColumns?: ComputedColumnSpec[];
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

// Chromium DownloadItem::DownloadState.
const DOWNLOAD_STATE_LABELS: Record<string, string> = {
  "0": "진행 중",
  "1": "완료",
  "2": "취소됨",
  "3": "중단됨",
};

const DOWNLOAD_STATE_COLORS: Record<string, string> = {
  "완료": "#3fb950",
  "취소됨": "#8a8a8a",
  "중단됨": "#d29922",
  "진행 중": "#4fc1ff",
};

const DIRECTION_COLORS: Record<string, string> = {
  "outbound(RDP client)": "#4fc1ff",
  inbound: "#d29922",
};

const ACTIVITY_TYPE_COLORS: Record<string, string> = {
  "방문": "#4fc1ff",
  "다운로드": "#3fb950",
  "로그인 저장": "#d29922",
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
    title: (r) => r.program_name || basename(r.program_path) || "(no name)",
    subtitle: (r) => r.program_path || "",
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

  RemoteAccessHistory: {
    title: (r) => r.remote_address || "(no address)",
    subtitle: (r) => r.detail || "",
    badges: [
      { key: "direction", kind: "badge", badgeColors: DIRECTION_COLORS },
      { key: "source_artifact", label: "출처", kind: "badge" },
    ],
    links: [{ key: "record_key", label: "이벤트 로그 원본 보기", targetFile: "EventLog_Events", targetColumn: "_record_key" }],
    priorityColumns: ["timestamp", "direction", "remote_address", "account", "detail"],
    sections: [{ heading: "상세", fields: [
      { key: "account", label: "계정" },
      { key: "detail" },
    ]}],
  },

  BrowserTimeline: {
    title: (r) => r.title_or_target || "(no title)",
    subtitle: (r) => r.url || "",
    badges: [
      { key: "activity_type", label: "구분", kind: "badge", badgeColors: ACTIVITY_TYPE_COLORS },
      { key: "browser", kind: "badge" },
    ],
    priorityColumns: ["timestamp", "activity_type", "title_or_target", "url", "browser"],
    sections: [{ heading: "URL", fields: [{ key: "url", kind: "path" }] }],
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

  Amcache_Programs: {
    title: (r) => r.Name || "(no name)",
    subtitle: (r) => [r.Version, r.Publisher].filter(Boolean).join(" · "),
    badges: [
      { key: "_recovery", kind: "badge", badgeColors: STATUS_COLORS },
      { key: "StoreAppType", kind: "badge" },
    ],
    // HiddenArp=1 means the program was deliberately hidden from Add/Remove
    // Programs — a real self-concealment technique, not just noise.
    tags: (r) => tagsForBoolean(r.HiddenArp, { label: "제어판에서 숨김(HiddenArp)", severity: "danger" }),
    links: [
      { key: "ProgramId", label: "이 프로그램이 설치한 파일 보기", targetFile: "Amcache_Files", targetColumn: "program_id" },
      { key: "UserSid", label: "설치한 계정의 프로필 정보 보기", targetFile: "Registry_UserProfiles", targetColumn: "sid" },
    ],
    timelineField: "timestamp",
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
      { heading: "식별자", fields: [
        { key: "ProgramId", kind: "hash" },
        { key: "ProgramInstanceId", kind: "hash" },
        { key: "PackageFullName" },
        { key: "MsiProductCode", kind: "hash" },
        { key: "MsiPackageCode", kind: "hash" },
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
    timelineField: "timestamp",
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
      { heading: "해시 / 식별자", fields: [
        { key: "SHA1", kind: "hash" },
        { key: "file_id", kind: "hash" },
        { key: "program_id", kind: "hash" },
      ]},
    ],
  },

  EventLog_Events: {
    title: (r) => {
      const catalog = lookupEventCatalog(r.Provider, r.EventID);
      return catalog ? `Event ${r.EventID} · ${catalog.label}` : `Event ${r.EventID}`;
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
      { heading: "기본 정보", fields: [
        { key: "Channel" },
        { key: "Computer" },
        { key: "EventRecordID" },
        { key: "ProcessID" },
        { key: "ThreadID" },
        { key: "UserID" },
      ]},
      { heading: "보안 이벤트 상세 (로그온/원격 접속/SMB/영속성)", fields: [
        edField("LogonType", "로그온 유형", { kind: "badge", valueLabels: LOGON_TYPE_LABELS }),
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
        edField("PrivilegeList", "부여된 권한", { kind: "code" }),
        edField("FailureReason", "실패 사유"),
        edField("Status", "상태 코드"),
        edField("ScriptBlockText", "PowerShell 스크립트 원문", { kind: "code" }),
      ]},
      { heading: "이벤트 데이터 (원본)", fields: [{ key: "EventData", kind: "json" }] },
      { heading: "오류", fields: [{ key: "_error", kind: "code" }] },
    ],
  },

  History_Visits: {
    title: (r) => r.title || r.url || "(no title)",
    subtitle: (r) => r.url || "",
    badges: [
      { key: "browser", kind: "badge" },
      { key: "transition_type", kind: "badge" },
    ],
    links: [{ key: "url", label: "이 URL의 방문 요약 보기", targetFile: "History_Urls", targetColumn: "url" }],
    timelineField: "timestamp",
    priorityColumns: ["timestamp", "title", "url", "transition_type", "browser"],
    sections: [
      { heading: "방문 정보", fields: [
        { key: "visit_duration_sec", label: "체류 시간(초)" },
        { key: "from_visit" },
        { key: "visit_id" },
      ]},
      { heading: "URL", fields: [{ key: "url", kind: "path" }] },
    ],
  },

  History_Urls: {
    title: (r) => r.title || r.url || "(no title)",
    subtitle: (r) => r.url || "",
    badges: [{ key: "browser", kind: "badge" }],
    links: [{ key: "url", label: "이 URL의 방문 기록 전부 보기", targetFile: "History_Visits", targetColumn: "url" }],
    timelineField: "last_visit_time",
    priorityColumns: ["last_visit_time", "title", "url", "visit_count", "browser"],
    sections: [
      { heading: "통계", fields: [
        { key: "visit_count" },
        { key: "typed_count" },
        { key: "hidden" },
      ]},
      { heading: "URL", fields: [{ key: "url", kind: "path" }] },
    ],
  },

  History_Downloads: {
    title: (r) => basename(r.target_path) || "(no file)",
    subtitle: (r) => r.tab_url || "",
    badges: [
      { key: "browser", kind: "badge" },
      { key: "state", kind: "badge", valueLabels: DOWNLOAD_STATE_LABELS, badgeColors: DOWNLOAD_STATE_COLORS },
    ],
    // Chromium's own Safe Browsing verdict (danger_type) is a direct
    // signal, not a heuristic — surface it the same way as a path check.
    tags: (r) => tagsForPath(r.target_path).concat(tagsForDangerType(r.danger_type)),
    timelineFields: [
      { key: "start_time", label: "시작" },
      { key: "end_time", label: "종료" },
      { key: "last_access_time", label: "마지막 접근" },
    ],
    timelineField: "start_time",
    priorityColumns: ["end_time", "target_path", "tab_url", "total_bytes", "browser"],
    sections: [
      { heading: "시간", fields: [{ key: "start_time" }, { key: "end_time" }, { key: "last_access_time" }] },
      { heading: "파일", fields: [
        { key: "target_path", kind: "path" },
        { key: "current_path", kind: "path" },
        { key: "received_bytes", kind: "bytes" },
        { key: "total_bytes", kind: "bytes" },
        { key: "mime_type" },
        { key: "danger_type", label: "브라우저 위험 판정 코드" },
      ]},
      { heading: "출처", fields: [
        { key: "tab_url", kind: "path" },
        { key: "referrer", kind: "path" },
      ]},
    ],
  },

  History_KeywordSearchTerms: {
    title: (r) => r.term || "(no term)",
    subtitle: (r) => r.browser || "",
    sections: [{ heading: "검색", fields: [
      { key: "url", kind: "path" },
      { key: "normalized_term" },
    ]}],
  },

  LoginData_Logins: {
    title: (r) => r.origin_url || "(no origin)",
    subtitle: (r) => r.username_value || "",
    badges: [
      { key: "browser", kind: "badge" },
      { key: "has_password", kind: "badge", badgeColors: BOOL_COLORS },
    ],
    timelineFields: [
      { key: "date_created", label: "생성" },
      { key: "date_last_used", label: "마지막 사용" },
      { key: "date_password_modified", label: "비밀번호 변경" },
    ],
    timelineField: "date_created",
    priorityColumns: ["date_last_used", "origin_url", "username_value", "browser", "has_password"],
    sections: [
      { heading: "날짜", fields: [
        { key: "date_created" },
        { key: "date_last_used" },
        { key: "date_password_modified" },
      ]},
      { heading: "상세", fields: [
        { key: "signon_realm", kind: "path" },
        { key: "times_used" },
        { key: "blacklisted_by_user" },
        { key: "password_type" },
      ]},
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
      { heading: "식별자", fields: [
        { key: "app_id", kind: "hash" },
        { key: "machine_id" },
        { key: "stream_id" },
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
    timelineField: "last_run_time",
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
      { heading: "식별자", fields: [
        { key: "prefetch_hash", kind: "hash" },
        { key: "format_version" },
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
      { key: "prefetch_hash", kind: "hash" },
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
        { key: "flags" },
        { key: "state" },
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
