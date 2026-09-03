"use client";

import { type CSSProperties, useEffect, useMemo, useState } from "react";
import Checkbox from "@mui/material/Checkbox";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BugReportOutlinedIcon from "@mui/icons-material/BugReportOutlined";
import HourglassEmptyOutlinedIcon from "@mui/icons-material/HourglassEmptyOutlined";
import type { FetchLinkedRows, TimelineEntry, TimelineFacets, TimelinePageRow, TimelineQuery } from "@/lib/types";
import { rangeActive as globalRangeActive, type TimeRange } from "@/lib/timeRange";
import { EXECUTION_SOURCE_LABELS, BROWSER_KIND_LABEL } from "@/lib/timelineKeys";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import LanguageOutlinedIcon from "@mui/icons-material/LanguageOutlined";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import EventNoteOutlinedIcon from "@mui/icons-material/EventNoteOutlined";
import TimelineOutlinedIcon2 from "@mui/icons-material/TimelineOutlined";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import TimelineOutlinedIcon from "@mui/icons-material/TimelineOutlined";
import ViewListOutlinedIcon from "@mui/icons-material/ViewListOutlined";
import { resolveArtifactView } from "@/lib/artifactViews";
import RowDetailPanel from "./RowDetailPanel";
import type { AccountDirectory } from "@/lib/accountIdentity";
import PaginationControls from "@/components/PaginationControls";
import { HeaderSearchInput, SortDropdown, ViewHeader } from "@/components/FilterControls";

const ROW_HEIGHT = 52;
const PAGE_SIZE = 10;
// Bookmark context stays neutral, distinct from navigation blue and from
// severity colours used by investigative evidence.
const BOOKMARK_TEXT = "var(--text)";
const BOOKMARK_MUTED_TEXT = "var(--text-dim)";
const BOOKMARK_ACCENT = "var(--bookmark-control)";

export type ArtifactChipTone = {
  border: string;
  background: string;
  color: string;
};

// Artifact identity uses its own restrained hue. Investigation state still
// owns the warning/danger palette, so a purple JumpList chip never implies a
// finding and an amber TaskScheduler chip never implies an alert.
const ARTIFACT_CHIP_TONES: Record<string, ArtifactChipTone> = {
  AMCACHE: { border: "#65d7c6", background: "rgba(15, 159, 139, 0.14)", color: "#65d7c6" },
  EVENTLOG: { border: "#aebdff", background: "rgba(97, 118, 216, 0.14)", color: "#aebdff" },
  JUMPLIST: { border: "#f0add7", background: "rgba(183, 97, 155, 0.14)", color: "#f0add7" },
  PREFETCH: { border: "#f3bd7b", background: "rgba(189, 118, 46, 0.14)", color: "#f3bd7b" },
  REGISTRY: { border: "#c9b8ff", background: "rgba(138, 106, 211, 0.14)", color: "#c9b8ff" },
  SRUM: { border: "#75d4f4", background: "rgba(25, 142, 181, 0.14)", color: "#75d4f4" },
  WER: { border: "#ffabb2", background: "rgba(197, 93, 103, 0.14)", color: "#ffabb2" },
  TASKSCHEDULER: { border: "#eacb75", background: "rgba(173, 138, 48, 0.14)", color: "#eacb75" },
  POWERSHELL: { border: "#b7b0ff", background: "rgba(112, 101, 199, 0.14)", color: "#b7b0ff" },
  RDPCACHE: { border: "#8fcaff", background: "rgba(65, 140, 199, 0.14)", color: "#8fcaff" },
  // Browser evidence is deliberately plum, away from the blue execution
  // history colour used in the same dense timeline.
  BROWSER: { border: "#e1b8f2", background: "rgba(165, 108, 196, 0.15)", color: "#e1b8f2" },
  FILESYSTEM: { border: "#8cdbad", background: "rgba(65, 158, 114, 0.14)", color: "#8cdbad" },
  EXECUTIONHISTORY: { border: "#9fd2fb", background: "rgba(76, 140, 190, 0.14)", color: "#9fd2fb" },
  TARGETINFO: { border: "#b4c9dc", background: "rgba(103, 131, 158, 0.14)", color: "#b4c9dc" },
  MFTEXPLORER: { border: "#91d9bd", background: "rgba(60, 152, 122, 0.14)", color: "#91d9bd" },
  REMOTEDESKTOP: { border: "#a2d0fb", background: "rgba(83, 138, 189, 0.14)", color: "#a2d0fb" },
  REGISTRYFINDINGS: { border: "#cfb8f7", background: "rgba(150, 113, 201, 0.14)", color: "#cfb8f7" },
  SMBHISTORY: { border: "#88dce2", background: "rgba(37, 143, 154, 0.14)", color: "#88dce2" },
  DEFENDER: { border: "#f0ada0", background: "rgba(181, 100, 86, 0.14)", color: "#f0ada0" },
};

const DEFAULT_ARTIFACT_CHIP_TONE: ArtifactChipTone = {
  border: "#647992",
  background: "rgba(100, 121, 146, 0.14)",
  color: "#b6c3d3",
};

const TABLE_ARTIFACT_KEYS: Record<string, string> = {
  JUMPLISTENTRIES: "JUMPLIST",
  SCHEDULEDTASKS: "TASKSCHEDULER",
  EXECUTIONHISTORY: "EXECUTIONHISTORY",
  TARGETINFO: "TARGETINFO",
  MFTRECORDS: "MFTEXPLORER",
  REMOTEDESKTOP: "REMOTEDESKTOP",
  REGISTRYFINDINGS: "REGISTRYFINDINGS",
  POWERSHELLHISTORY: "POWERSHELL",
  SMBHISTORY: "SMBHISTORY",
  BROWSERACTIVITY: "BROWSER",
};

const toolbarButtonStyle: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: 5,
  minHeight: 30,
  padding: "5px 9px",
  background: "var(--bg-elevated)",
  color: "var(--text-dim)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  fontSize: 12,
  fontWeight: 650,
  whiteSpace: "nowrap",
};

function normalizedArtifactKey(value: string): string {
  return value.replace(/[^a-z0-9]/gi, "").toUpperCase();
}

/**
 * Overview tables are stored under _OVERVIEW, which is not a visual artifact
 * identity. Use their table name instead. EventLog is intentionally the one
 * exception: Security/System/Application and every other source log share one
 * recognizable EventLog colour.
 */
export function artifactChipTone(category: string, table: string): ArtifactChipTone {
  const categoryKey = normalizedArtifactKey(category);
  const key = categoryKey === "EVENTLOG"
    ? "EVENTLOG"
    : ARTIFACT_CHIP_TONES[categoryKey]
      ? categoryKey
      : TABLE_ARTIFACT_KEYS[normalizedArtifactKey(table)] ?? normalizedArtifactKey(table);
  return ARTIFACT_CHIP_TONES[key] ?? DEFAULT_ARTIFACT_CHIP_TONE;
}

function artifactDisplayName(category: string, table: string): string {
  if (normalizedArtifactKey(category) === "EVENTLOG") return "EventLog";
  if (normalizedArtifactKey(table) === "JUMPLISTENTRIES") return "JumpList";
  return table;
}

// Evidence rows retain an initial text snapshot, but a running development
// session must render the current definition. This keeps Fast Refresh useful
// for timeline wording/layout changes without rebuilding evidence rows or
// resetting the analyst's filters and scroll position.
function currentTimelinePresentation(entry: TimelineEntry): { summary: string; subtitle: string; note: string } {
  const spec = resolveArtifactView(entry.table, entry.columns);
  if (!spec) return { summary: entry.summary, subtitle: entry.subtitle, note: "" };
  let summary = (spec.timelineTitle ?? spec.title)(entry.row);
  let note = "";
  // EventLog 카탈로그 설명("Event N · 설명")은 실행 이력의 도구 설명과 같은
  // 배지로 분리해 보여준다.
  if (/event/i.test(`${entry.category} ${entry.table}`)) {
    const match = /^Event (\S+) · (.+)$/.exec(summary);
    if (match) {
      summary = `Event ${match[1]}`;
      note = match[2];
    }
  }
  return { summary, subtitle: (spec.timelineSubtitle ?? spec.subtitle)?.(entry.row) ?? "", note };
}

// 카드 타일 아이콘 — 아티팩트 정체성을 색+아이콘으로 드러낸다.
function timelineTileIcon(category: string, table: string) {
  const key = `${category} ${table}`;
  if (/sched/i.test(key)) return TaskOutlinedIcon;
  if (/exec/i.test(key)) return BoltOutlinedIcon;
  if (/browser/i.test(key)) return LanguageOutlinedIcon;
  if (/jump/i.test(key)) return DescriptionOutlinedIcon;
  if (/event/i.test(key)) return EventNoteOutlinedIcon;
  return TimelineOutlinedIcon2;
}

function ArtifactFilterCheckbox({
  label,
  checked,
  indeterminate = false,
  tone,
  depth = 0,
  onChange,
  style,
}: {
  label: string;
  checked: boolean;
  indeterminate?: boolean;
  tone: ArtifactChipTone;
  depth?: number;
  onChange: () => void;
  style?: CSSProperties;
}) {
  return (
      <label
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          minHeight: 32,
          padding: depth ? "4px 7px 4px 8px" : "4px 7px 4px 9px",
          borderRadius: "var(--radius-sm)",
          background: "transparent",
          color: checked || indeterminate ? "var(--text)" : "var(--text-faint)",
          width: "100%",
          minWidth: 0,
          cursor: "pointer",
          userSelect: "none",
          transition: "background .12s ease",
          ...style,
        }}
        onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
      >
        <span
          aria-hidden="true"
          style={{ width: 9, height: 9, flexShrink: 0, borderRadius: "50%", background: checked || indeterminate ? tone.border : "transparent", border: `2px solid ${tone.border}`, opacity: checked || indeterminate ? 1 : 0.45, boxSizing: "border-box" }}
        />
        <span style={{ minWidth: 0, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: depth ? 12 : 12.5, fontWeight: depth ? 550 : 650 }}>
          {label}
        </span>
      <Checkbox
        size="small"
        checked={checked}
        indeterminate={indeterminate}
        onChange={onChange}
        sx={{
          p: "2px",
          mr: "1px",
          color: "var(--text-faint)",
          "&.Mui-checked, &.MuiCheckbox-indeterminate": { color: tone.border },
        }}
      />
    </label>
  );
}

interface MasterTimelineProps {
  /** 이 호스트의 sqlite 타임라인을 페이지 쿼리로 조회한다. */
  hostDir: string;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
  /** Resolves direct and source-linked bookmarks for an entry. */
  isBookmarked: (entry: TimelineEntry) => boolean;
  onToggleBookmark: (entry: TimelineEntry) => void;
  /** Global incident-window filter from the sidebar. */
  globalTimeRange: TimeRange;
  accountDirectory?: AccountDirectory;
}

// 페이지 행을 렌더용 엔트리로 — 기존 row 기반 표현·태그·상세 로직을
// 현재 페이지 행에만 그대로 재사용한다.
function pageRowToEntry(r: TimelinePageRow): TimelineEntry {
  // 원본 행은 백엔드가 이 페이지 분만 원본 파일에서 읽어 붙여 준다(타임라인
  // DB에 사본을 두지 않는다). 원본을 못 읽은 행은 빈 값 — 시각·카테고리는 표시된다.
  const row = (r.row ?? {}) as Record<string, string>;
  const columns = Object.keys(row);
  const spec = resolveArtifactView(r.sourceTable, columns);
  return {
    timestamp: r.ts,
    category: r.category,
    table: r.sourceTable,
    summary: "",
    subtitle: "",
    tags: spec?.tags?.(row) ?? [],
    rowid: r.rowidSrc,
    fullPath: r.fullPath,
    row,
    columns,
  };
}

export default function MasterTimeline({ hostDir, onNavigate, onFetchLinkedRows, isBookmarked, onToggleBookmark, globalTimeRange, accountDirectory }: MasterTimelineProps) {
  const [page, setPage] = useState(0);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [hiddenTables, setHiddenTables] = useState<Set<string>>(new Set());
  const [hiddenExecutionSources, setHiddenExecutionSources] = useState<Set<string>>(new Set());
  const [hiddenBrowserKinds, setHiddenBrowserKinds] = useState<Set<string>>(new Set());
  const [showArtifactMenu, setShowArtifactMenu] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [facets, setFacets] = useState<TimelineFacets | null>(null);
  const [pageData, setPageData] = useState<{ rows: TimelineEntry[]; total: number }>({ rows: [], total: 0 });
  const [loading, setLoading] = useState(true);
  // 페이지·패싯 조회 실패를 "데이터 없음"으로 보여주면 증거 부재로 오인된다.
  const [queryError, setQueryError] = useState<string | null>(null);
  // 재시도용 — 조회 조건이 그대로여도 effect를 다시 돌린다.
  const [reloadNonce, setReloadNonce] = useState(0);

  // 검색어 디바운스 — 타이핑마다 쿼리하지 않는다.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(timer);
  }, [search]);

  // 아티팩트 필터 메뉴용 패싯(그룹·소스·건수) — 호스트당 1회.
  useEffect(() => {
    let cancelled = false;
    void window.api
      .masterTimelineFacets(hostDir)
      .then((f) => {
        if (!cancelled) setFacets(f);
      })
      .catch((error) => {
        if (!cancelled) setQueryError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
  }, [hostDir, reloadNonce]);

  const globalActive = globalRangeActive(globalTimeRange);
  // Set은 렌더마다 새 참조라 deps로 못 쓴다 — 정렬된 문자열 키로 안정화한다.
  const hiddenTablesKey = [...hiddenTables].sort().join(",");
  const hiddenExecKey = [...hiddenExecutionSources].sort().join(",");
  const hiddenBrowserKey = [...hiddenBrowserKinds].sort().join(",");

  // 필터·정렬·검색·페이지·기간이 바뀔 때마다 백엔드에서 그 페이지만 조회한다.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const query: TimelineQuery = {
      search: debouncedSearch.trim(),
      hiddenSourceTables: [...hiddenTables],
      hiddenExecSources: [...hiddenExecutionSources],
      hiddenBrowserKinds: [...hiddenBrowserKinds],
      onlySuspicious,
      start: globalActive ? globalTimeRange.start : "",
      end: globalActive ? globalTimeRange.end : "",
      sortDesc: sortDir === "desc",
      offset: page * PAGE_SIZE,
      limit: PAGE_SIZE,
    };
    void window.api
      .masterTimelinePage(hostDir, query)
      .then((res) => {
        if (cancelled) return;
        setPageData({ rows: res.rows.map(pageRowToEntry), total: res.total });
        setQueryError(null);
        setLoading(false);
      })
      .catch((error) => {
        if (cancelled) return;
        // 빈 결과로 대체하지 않는다 — 조회 실패와 "기록 없음"은 다른 사실이다.
        setQueryError(error instanceof Error ? error.message : String(error));
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostDir, page, sortDir, hiddenTablesKey, hiddenExecKey, hiddenBrowserKey, onlySuspicious, debouncedSearch, globalActive, globalTimeRange.start, globalTimeRange.end, reloadNonce]);

  // EventLog is a single analyst-facing artifact even though it is stored as
  // several per-source tables (Security, System, Application, ...).
  // 필터 메뉴는 백엔드 패싯(그룹·소스·건수)으로 구동한다 — 전체 행을
  // 순회하지 않는다. EventLog 계열은 'EVENTLOG' 한 그룹으로 묶는다.
  const artifactControls = useMemo(() => {
    const m = new Map<string, { label: string; category: string; tables: string[] }>();
    for (const t of facets?.tables ?? []) {
      const isEventLog = normalizedArtifactKey(t.category) === "EVENTLOG";
      const key = isEventLog ? "EVENTLOG" : t.sourceTable;
      const previous = m.get(key);
      if (previous) previous.tables.push(t.sourceTable);
      else m.set(key, { label: artifactDisplayName(t.category, t.sourceTable), category: t.category, tables: [t.sourceTable] });
    }
    return [...m.values()]
      .map((item) => ({ ...item, tables: [...new Set(item.tables)] }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [facets]);

  const allArtifactTables = useMemo(
    () => [...new Set(artifactControls.flatMap(({ tables }) => tables))],
    [artifactControls],
  );
  const executionSources = useMemo(
    () =>
      (facets?.execSources ?? [])
        .map((f) => f.key)
        .sort((a, b) => (EXECUTION_SOURCE_LABELS[a] ?? a).localeCompare(EXECUTION_SOURCE_LABELS[b] ?? b)),
    [facets],
  );
  const browserKinds = useMemo<Array<[string, number]>>(() => {
    const order: Array<string> = ["visit", "download", "cache", "other"];
    return (facets?.browserKinds ?? [])
      .map((f) => [f.key, f.count] as [string, number])
      .sort((a, b) => {
        const ai = order.indexOf(a[0]);
        const bi = order.indexOf(b[0]);
        if (ai === -1 || bi === -1) return a[0].localeCompare(b[0]);
        return ai - bi;
      });
  }, [facets]);
  const artifactTableCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const t of facets?.tables ?? []) map.set(t.sourceTable, (map.get(t.sourceTable) ?? 0) + t.count);
    return map;
  }, [facets]);

  // 필터가 모든 소스 테이블을 숨긴 상태 — 결과 0을 그 안내로 구분한다.
  const allArtifactsHidden =
    allArtifactTables.length > 0 && allArtifactTables.every((table) => hiddenTables.has(table));

  function toggleTables(tables: string[]) {
    const allVisible = tables.every((table) => !hiddenTables.has(table));
    setHiddenTables((previous) => {
      const next = new Set(previous);
      for (const table of tables) {
        if (allVisible) next.add(table);
        else next.delete(table);
      }
      return next;
    });
  }

  function showAllArtifacts() {
    setHiddenTables(new Set());
    setHiddenExecutionSources(new Set());
    setHiddenBrowserKinds(new Set());
  }

  function hideAllArtifacts() {
    setHiddenTables(new Set(allArtifactTables));
    setHiddenExecutionSources(new Set(executionSources));
    setHiddenBrowserKinds(new Set(browserKinds.map(([kind]) => kind)));
  }

  function toggleExecutionGroup() {
    const tableHidden = hiddenTables.has("ExecutionHistory");
    const allSourcesVisible = !tableHidden && executionSources.every((source) => !hiddenExecutionSources.has(source));
    if (allSourcesVisible) {
      setHiddenTables((previous) => new Set(previous).add("ExecutionHistory"));
      return;
    }
    setHiddenTables((previous) => {
      const next = new Set(previous);
      next.delete("ExecutionHistory");
      return next;
    });
    setHiddenExecutionSources((previous) => {
      const next = new Set(previous);
      executionSources.forEach((source) => next.delete(source));
      return next;
    });
  }

  function toggleExecutionSource(source: string) {
    const tableHidden = hiddenTables.has("ExecutionHistory");
    if (tableHidden) {
      setHiddenTables((previous) => {
        const next = new Set(previous);
        next.delete("ExecutionHistory");
        return next;
      });
      setHiddenExecutionSources(new Set(executionSources.filter((candidate) => candidate !== source)));
      return;
    }
    setHiddenExecutionSources((previous) => {
      const next = new Set(previous);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return next;
    });
  }

  function toggleBrowserKind(kind: string) {
    const tableHidden = hiddenTables.has("BrowserActivity");
    if (tableHidden) {
      setHiddenTables((previous) => {
        const next = new Set(previous);
        next.delete("BrowserActivity");
        return next;
      });
      setHiddenBrowserKinds((previous) => {
        const next = new Set(previous);
        next.delete(kind);
        return next;
      });
      return;
    }
    setHiddenBrowserKinds((previous) => {
      const next = new Set(previous);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });
  }

  // 결과는 백엔드에서 이미 검색·필터·정렬·페이지된 경량 행이다(전량 상주 없음).
  const rows = pageData.rows;
  const total = pageData.total;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = rows;
  const pageStart = total === 0 ? 0 : safePage * PAGE_SIZE + 1;
  const pageEnd = Math.min(total, safePage * PAGE_SIZE + PAGE_SIZE);
  // 필터·정렬·검색·기간이 바뀌면 첫 페이지로 — 쿼리 effect도 같은 값에 반응한다.
  useEffect(() => {
    setPage(0);
  }, [sortDir, hiddenTablesKey, hiddenExecKey, hiddenBrowserKey, globalActive, globalTimeRange.start, globalTimeRange.end, onlySuspicious, debouncedSearch]);

  // 첫 조회(표시할 데이터가 아직 없음)에만 전체 화면 로딩을 띄운다. 페이지
  // 이동·필터 변경 등 재조회는 기존 목록을 유지한 채 살짝 어둡게만 한다.
  if (loading && rows.length === 0) {
    return (
      <div
        role="status"
        aria-live="polite"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "var(--text-dim)",
          gap: 10,
          fontSize: 14,
        }}
      >
        <CircularProgress
          size={19}
          thickness={4.5}
          aria-label="통합 타임라인을 불러오는 중"
          sx={{ color: "var(--accent)" }}
        />
        <span>타임라인을 불러오는 중...</span>
      </div>
    );
  }

  const hasArtifactFilters = hiddenTables.size > 0 || hiddenExecutionSources.size > 0 || hiddenBrowserKinds.size > 0;

  return (
    <div className="dfir-view" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={TimelineOutlinedIcon} title="통합 타임라인" meta={`${total.toLocaleString()}건`}>
          <HeaderSearchInput value={search} onChange={setSearch} placeholder="이름 · 경로 · 내용 검색" ariaLabel="통합 타임라인 검색" width={300} />
          <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
          <button className="nm-btn" onClick={() => setOnlySuspicious((value) => !value)} title="의심 태그가 붙은 항목만 표시" aria-pressed={onlySuspicious} style={{ ...toolbarButtonStyle, background: onlySuspicious ? "var(--danger-subtle)" : "var(--bg-elevated)", color: onlySuspicious ? "var(--danger)" : "var(--text-dim)", borderColor: onlySuspicious ? "var(--danger)" : "var(--border)" }}>
            <ReportProblemOutlinedIcon sx={{ fontSize: 16 }} />의심 항목
          </button>
            <div style={{ position: "relative" }}>
            <button className="nm-btn" onClick={() => setShowArtifactMenu((value) => !value)} title="표시할 아티팩트 선택" aria-expanded={showArtifactMenu} style={{ ...toolbarButtonStyle, background: hasArtifactFilters ? "var(--accent-subtle)" : "var(--bg-elevated)", color: hasArtifactFilters ? "var(--accent)" : "var(--text-dim)", borderColor: hasArtifactFilters ? "var(--accent)" : "var(--border)" }}>
              <ViewListOutlinedIcon sx={{ fontSize: 16 }} />아티팩트
            </button>
            {showArtifactMenu && (
              <>
                <div onClick={() => setShowArtifactMenu(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
                <div style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 41, width: 400, maxHeight: 420, overflowY: "auto", overflowX: "hidden", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "3px 4px 8px", borderBottom: "1px solid var(--border-subtle)" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-dim)" }}>표시할 아티팩트</span>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
                      <button type="button" onClick={showAllArtifacts} style={{ fontSize: 11.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 650 }}>전체 선택</button>
                      <button type="button" onClick={hideAllArtifacts} style={{ fontSize: 11.5, background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontWeight: 650 }}>전체 해제</button>
                    </div>
                  </div>
                  <div style={{ display: "grid", gap: 2, paddingTop: 7 }}>
                    {artifactControls.map(({ label, category, tables }) => {
                      const tone = artifactChipTone(category, tables[0]);
                      const isExecutionHistory = tables.length === 1 && tables[0] === "ExecutionHistory";
                      const isBrowserActivity = tables.length === 1 && tables[0] === "BrowserActivity";
                      if (!isExecutionHistory) {
                        if (isBrowserActivity && browserKinds.length > 0) {
                          const tableHidden = hiddenTables.has("BrowserActivity");
                          const visibleKindCount = browserKinds.filter(([kind]) => !hiddenBrowserKinds.has(kind)).length;
                          const checked = !tableHidden && visibleKindCount === browserKinds.length;
                          const indeterminate = visibleKindCount > 0 && visibleKindCount < browserKinds.length;
                          return (
                            <div
                              key={label}
                              style={{
                                display: "grid",
                                gap: 2,
                                }}
                            >
                              <ArtifactFilterCheckbox
                                key={`${label}-parent`}
                                label={`${label} (${browserKinds.reduce((acc, [, count]) => acc + count, 0)})`}
                                checked={checked}
                                indeterminate={indeterminate}
                                tone={tone}
                                onChange={() => {
                                  if (!tableHidden && checked) {
                                    setHiddenTables((previous) => new Set(previous).add("BrowserActivity"));
                                    setHiddenBrowserKinds(new Set(browserKinds.map(([kind]) => kind)));
                                  } else {
                                    setHiddenTables((previous) => {
                                      const next = new Set(previous);
                                      next.delete("BrowserActivity");
                                      return next;
                                    });
                                    setHiddenBrowserKinds(new Set());
                                  }
                                }}
                              />
                              <div style={{ display: "grid", gap: 2, minWidth: 0, margin: "0 2px 4px 12px", paddingLeft: 8, borderLeft: `2px solid color-mix(in srgb, ${tone.border} 45%, var(--border))` }}>
                                {browserKinds.map(([kind, count]) => (
                                  <ArtifactFilterCheckbox
                                    key={kind}
                                    label={`${BROWSER_KIND_LABEL[kind] ?? kind} (${count})`}
                                    checked={!tableHidden && !hiddenBrowserKinds.has(kind)}
                                    tone={tone}
                                    depth={1}
                                    onChange={() => toggleBrowserKind(kind)}
                                  />
                                ))}
                              </div>
                            </div>
                          );
                        }
                        const visible = tables.some((table) => !hiddenTables.has(table));
                        if (tables.length > 1) {
                          const visibleCount = tables.filter((table) => !hiddenTables.has(table)).length;
                          const checked = visibleCount > 0 && visibleCount === tables.length;
                          const indeterminate = visibleCount > 0 && visibleCount < tables.length;
                          return (
                            <div key={label} style={{ display: "grid", gap: 2, minWidth: 0 }}>
                              <ArtifactFilterCheckbox
                                key={`${label}-parent`}
                                label={`${label} (${tables.reduce((acc, table) => acc + (artifactTableCounts.get(table) ?? 0), 0)})`}
                                checked={checked}
                                indeterminate={indeterminate}
                                tone={tone}
                                onChange={() => toggleTables(tables)}
                              />
                              <div style={{ display: "grid", gap: 2, minWidth: 0, margin: "0 2px 4px 12px", paddingLeft: 8, borderLeft: `2px solid color-mix(in srgb, ${tone.border} 45%, var(--border))` }}>
                                {tables
                                  .map((table) => ({ table, count: artifactTableCounts.get(table) ?? 0 }))
                                  .sort((a, b) => a.table.localeCompare(b.table))
                                  .map(({ table, count }) => (
                                    <ArtifactFilterCheckbox
                                      key={table}
                                      label={`${table} (${count})`}
                                      checked={!hiddenTables.has(table)}
                                      tone={tone}
                                      depth={1}
                                      onChange={() => toggleTables([table])}
                                                                          />
                                  ))}
                              </div>
                            </div>
                          );
                        }
                        return <ArtifactFilterCheckbox key={label} label={label} checked={visible} tone={tone} onChange={() => toggleTables(tables)} />;
                      }

                      const tableHidden = hiddenTables.has("ExecutionHistory");
                      const visibleSourceCount = tableHidden ? 0 : executionSources.filter((source) => !hiddenExecutionSources.has(source)).length;
                      const checked = executionSources.length > 0 && visibleSourceCount === executionSources.length;
                      const indeterminate = visibleSourceCount > 0 && !checked;
                      return (
                        <div key={label} style={{ display: "grid", gap: 4 }}>
                          <ArtifactFilterCheckbox
                            label={label}
                            checked={checked}
                            indeterminate={indeterminate}
                            tone={tone}
                            onChange={toggleExecutionGroup}
                          />
                          <div style={{ display: "grid", gap: 4, borderLeft: "2px solid var(--border)", marginLeft: 2, paddingLeft: 8, paddingBottom: 2 }}>
                            {executionSources.map((source) => (
                              <ArtifactFilterCheckbox
                                key={source}
                                label={EXECUTION_SOURCE_LABELS[source] ?? source}
                                checked={!tableHidden && !hiddenExecutionSources.has(source)}
                                tone={tone}
                                depth={1}
                                onChange={() => toggleExecutionSource(source)}
                                style={{
                                  border: "1px solid var(--border-subtle)",
                                  borderRadius: "var(--radius-sm)",
                                  marginLeft: 0,
                                  paddingLeft: 10,
                                }}
                              />
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </div>
        
      </ViewHeader>

      {queryError ? (
        <div role="alert" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 10, flex: 1, minHeight: 0, padding: 24, textAlign: "center", fontSize: 13 }}>
          <span style={{ fontWeight: 700, color: "var(--text)" }}>타임라인을 조회하지 못했습니다</span>
          <span style={{ color: "var(--text-dim)", fontSize: 12.5, maxWidth: 560, wordBreak: "break-word" }}>{queryError}</span>
          <span style={{ color: "var(--text-faint)", fontSize: 12 }}>기록이 없다는 뜻이 아닙니다 — 조회 자체가 실패했습니다.</span>
          <button type="button" onClick={() => { setQueryError(null); setLoading(true); setReloadNonce((value) => value + 1); }} style={{ padding: "5px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", color: "var(--text)", cursor: "pointer", fontSize: 12.5 }}>다시 시도</button>
        </div>
      ) : total === 0 ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", gap: 8 }}>
          <HourglassEmptyOutlinedIcon sx={{ fontSize: 28, color: "var(--text-faint)" }} />
          <span>{allArtifactsHidden ? "표시할 아티팩트를 선택하세요." : globalActive ? "사고 기간에 해당하는 기록이 없습니다." : "표시할 시간 기록이 없습니다."}</span>
        </div>
      ) : (
      <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 14px 4px", opacity: loading ? 0.55 : 1, transition: "opacity .15s ease" }}>
        {pageRows.map((entry, indexInPage) => {
          const absoluteIndex = safePage * PAGE_SIZE + indexInPage;
          const presentation = currentTimelinePresentation(entry);
          const dangerTag = entry.tags.find((t) => t.severity === "danger");
          const warningTag = entry.tags.find((t) => t.severity === "warning");
          const bookmarked = isBookmarked(entry);
          const chipTone = artifactChipTone(entry.category, entry.table);
          const TileIcon = timelineTileIcon(entry.category, entry.table);
          return (
            <div
              key={`${entry.fullPath}:${entry.rowid}:${absoluteIndex}`}
              className={bookmarked ? "dfir-bookmarked-row" : undefined}
              onClick={() => setSelectedEntry(entry)}
              style={{
                minHeight: 62,
                marginBottom: 8,
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "9px 14px",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                background: "var(--bg-panel)",
                cursor: "pointer",
                transition: "background .15s ease, border-color .15s ease",
              }}
              onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-panel)"; }}
            >
              <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${chipTone.border} 15%, transparent)` }}>
                <TileIcon sx={{ fontSize: 17, color: chipTone.border }} />
              </span>
              <span
                style={{
                  flexShrink: 0,
                  maxWidth: 170,
                  fontSize: 11.5,
                  fontWeight: 700,
                  padding: "1px 8px",
                  border: `1px solid ${chipTone.border}`,
                  borderRadius: "var(--radius-sm)",
                  // 라벨은 아웃라인 스타일 — 아티팩트 정체성은 테두리·글자
                  // 색으로 드러낸다.
                  background: "transparent",
                  color: chipTone.border,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  textAlign: "center",
                }}
              >
                {artifactDisplayName(entry.category, entry.table)}
              </span>
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                  <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 650, color: bookmarked ? BOOKMARK_TEXT : undefined }}>{presentation.summary}</span>
                  {presentation.note && <span title={presentation.note} style={{ flexShrink: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#5bc8c0", border: "1px solid #5bc8c0", borderRadius: "var(--radius-sm)", padding: "1px 7px", fontSize: 11, fontWeight: 650 }}>{presentation.note}</span>}
                </div>
                {presentation.subtitle && (
                  <div
                    style={{
                      fontSize: 11.5,
                      color: bookmarked ? BOOKMARK_MUTED_TEXT : "var(--text-faint)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {presentation.subtitle}
                  </div>
                )}
              </span>
              <span style={{ flexShrink: 0, width: 172, textAlign: "right", fontFamily: "var(--mono)", fontSize: 12.5, color: bookmarked ? BOOKMARK_MUTED_TEXT : entry.timestamp ? "var(--text-time)" : "var(--text-faint)", whiteSpace: "nowrap" }}>
                {entry.timestamp || "(시간 정보 없음)"}
              </span>
              {(dangerTag || warningTag) && (
                <Tooltip
                  arrow
                  placement="left"
                  title={
                    <div style={{ display: "grid", gap: 7, maxWidth: 420, padding: "2px 0" }}>
                      {entry.tags.map((tag) => (
                        <div key={`${tag.severity}-${tag.label}`}>
                          <div style={{ fontSize: 12, fontWeight: 750, color: tag.severity === "danger" ? "#ff9ba4" : "#f1c66c" }}>{tag.label}</div>
                          {tag.description && <div style={{ marginTop: 2, fontSize: 11.5, lineHeight: 1.48, color: "#d8e2ee" }}>{tag.description}</div>}
                        </div>
                      ))}
                    </div>
                  }
                >
                  <span
                    style={{ display: "inline-flex", flexShrink: 0, color: dangerTag ? "var(--danger)" : "var(--warning)", cursor: "help" }}
                    aria-label={`의심 항목: ${entry.tags.map((tag) => tag.label).join(", ")}`}
                  >
                    <ReportProblemOutlinedIcon sx={{ fontSize: 17 }} />
                  </span>
                </Tooltip>
              )}
              <button
                type="button"
                className={bookmarked ? "dfir-bookmark-control" : undefined}
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleBookmark(entry);
                }}
                title={bookmarked ? "북마크 해제" : "북마크에 추가"}
                aria-label={bookmarked ? "북마크 해제" : "북마크에 추가"}
                style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", flexShrink: 0, padding: 3, background: "transparent", border: "none", cursor: "pointer", color: bookmarked ? BOOKMARK_ACCENT : "var(--text-faint)" }}
              >
                {bookmarked ? <BookmarkIcon sx={{ fontSize: 18 }} /> : <BookmarkBorderIcon sx={{ fontSize: 18 }} />}
              </button>
            </div>
          );
        })}
      </div>
      <footer style={{ flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", minHeight: 44, padding: "6px 16px", borderTop: "1px solid var(--border)" }}>
        <PaginationControls ariaLabel="통합 타임라인 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${total.toLocaleString()})`} />
      </footer>
      </div>
      )}

      {selectedEntry && (
        <RowDetailPanel
          row={selectedEntry.row}
          columns={selectedEntry.columns}
          focusedColumn={null}
          fileBaseName={selectedEntry.table}
          onClose={() => setSelectedEntry(null)}
          onNavigate={(targetFile, targetColumn, value) => {
            setSelectedEntry(null);
            onNavigate(targetFile, targetColumn, value);
          }}
          onFetchLinkedRows={onFetchLinkedRows}
          accountDirectory={accountDirectory}
          isBookmarked={isBookmarked(selectedEntry)}
          onToggleBookmark={() => onToggleBookmark(selectedEntry)}
        />
      )}
    </div>
  );
}
