"use client";

import { type CSSProperties, useEffect, useMemo, useState } from "react";
import Checkbox from "@mui/material/Checkbox";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BugReportOutlinedIcon from "@mui/icons-material/BugReportOutlined";
import HourglassEmptyOutlinedIcon from "@mui/icons-material/HourglassEmptyOutlined";
import type { FetchLinkedRows, TimelineEntry } from "@/lib/types";
import { inRange, rangeActive as globalRangeActive, type TimeRange } from "@/lib/timeRange";
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

type ArtifactChipTone = {
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
function artifactChipTone(category: string, table: string): ArtifactChipTone {
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

const EXECUTION_SOURCE_LABELS: Record<string, string> = {
  amcache: "Amcache",
  userassist: "UserAssist",
  prefetch: "Prefetch",
  srum: "SRUM",
  bam: "BAM",
  other: "기타",
};

function executionSourceKey(row: Record<string, string>): string {
  const source = (row.source_artifact || "").trim().toLowerCase();
  if (source.startsWith("amcache")) return "amcache";
  if (source === "userassist") return "userassist";
  if (source === "prefetch") return "prefetch";
  if (source === "srum") return "srum";
  if (source === "bam") return "bam";
  return "other";
}

function browserActivityKindKey(row: Record<string, string>): string {
  const kind = (row.kind || "").trim().toLowerCase();
  if (kind === "visit" || kind === "download" || kind === "cache") return kind;
  return "other";
}

const BROWSER_KIND_LABEL: Record<string, string> = {
  visit: "BrowserActivity:Visit",
  download: "BrowserActivity:Download",
  cache: "BrowserActivity:Cache",
  other: "BrowserActivity:기타",
};

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
  entries: TimelineEntry[] | null;
  loading: boolean;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
  /** Resolves direct and source-linked bookmarks for an entry. */
  isBookmarked: (entry: TimelineEntry) => boolean;
  onToggleBookmark: (entry: TimelineEntry) => void;
  /** Global incident-window filter from the sidebar. */
  globalTimeRange: TimeRange;
  accountDirectory?: AccountDirectory;
}

export default function MasterTimeline({ entries, loading, onNavigate, onFetchLinkedRows, isBookmarked, onToggleBookmark, globalTimeRange, accountDirectory }: MasterTimelineProps) {
  const [page, setPage] = useState(0);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [hiddenTables, setHiddenTables] = useState<Set<string>>(new Set());
  const [hiddenExecutionSources, setHiddenExecutionSources] = useState<Set<string>>(new Set());
  const [hiddenBrowserKinds, setHiddenBrowserKinds] = useState<Set<string>>(new Set());
  const [showArtifactMenu, setShowArtifactMenu] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [search, setSearch] = useState("");
  const allRows = entries ?? [];

  // EventLog is a single analyst-facing artifact even though it is stored as
  // several per-source tables (Security, System, Application, ...).
  const artifactControls = useMemo(() => {
    const m = new Map<string, { label: string; category: string; tables: string[] }>();
    for (const entry of allRows) {
      const isEventLog = normalizedArtifactKey(entry.category) === "EVENTLOG";
      const key = isEventLog ? "EVENTLOG" : entry.table;
      const previous = m.get(key);
      if (previous) previous.tables.push(entry.table);
      else m.set(key, { label: artifactDisplayName(entry.category, entry.table), category: entry.category, tables: [entry.table] });
    }
    return [...m.values()]
      .map((item) => ({ ...item, tables: [...new Set(item.tables)] }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [allRows]);

  const allArtifactTables = useMemo(
    () => [...new Set(artifactControls.flatMap(({ tables }) => tables))],
    [artifactControls],
  );
  const executionSources = useMemo(
    () => [...new Set(allRows
      .filter((entry) => entry.table === "ExecutionHistory")
      .map((entry) => executionSourceKey(entry.row)))].sort((a, b) => (EXECUTION_SOURCE_LABELS[a] ?? a).localeCompare(EXECUTION_SOURCE_LABELS[b] ?? b)),
    [allRows],
  );
  const browserKinds = useMemo(() => {
    const map = new Map<string, number>();
    for (const entry of allRows) {
      if (entry.table !== "BrowserActivity") continue;
      const kind = browserActivityKindKey(entry.row);
      map.set(kind, (map.get(kind) ?? 0) + 1);
    }
    const order: Array<string> = ["visit", "download", "cache", "other"];
    return [...map.entries()].sort((a, b) => {
      const ai = order.indexOf(a[0]);
      const bi = order.indexOf(b[0]);
      if (ai === -1 || bi === -1) return a[0].localeCompare(b[0]);
      return ai - bi;
    });
  }, [allRows]);
  const artifactTableCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const entry of allRows) {
      map.set(entry.table, (map.get(entry.table) ?? 0) + 1);
    }
    return map;
  }, [allRows]);

  function isEntryHidden(entry: TimelineEntry) {
    if (hiddenTables.has(entry.table)) return true;
    if (entry.table === "ExecutionHistory" && hiddenExecutionSources.has(executionSourceKey(entry.row))) return true;
    if (entry.table === "BrowserActivity" && hiddenBrowserKinds.has(browserActivityKindKey(entry.row))) return true;
    return false;
  }

  const allArtifactsHidden = allRows.length > 0 && allRows.every(isEntryHidden);

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

  const globalActive = globalRangeActive(globalTimeRange);
  useEffect(() => setPage(0), [search, onlySuspicious, hiddenTables]);
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = allRows.filter((e) => {
      if (isEntryHidden(e)) return false;
      if (onlySuspicious && e.tags.length === 0) return false;
      if (globalActive && !inRange(e.timestamp, globalTimeRange)) return false;
      if (needle) {
        const haystack = [e.table, e.category, ...Object.values(e.row)].join("\u0000").toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
    // Timestamps are pre-formatted YYYY-MM-DD hh:mm:ss.fff, so string compare
    // is chronological. Rows with no timestamp always sink to the bottom
    // regardless of direction (they can't be placed on the timeline).
    return [...filtered].sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      const cmp = a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allRows, sortDir, hiddenTables, hiddenExecutionSources, hiddenBrowserKinds, globalActive, globalTimeRange, onlySuspicious, search]);

  // 페이지 단위 표시(10건). 필터·정렬이 바뀌면 첫 페이지로 돌아간다.
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = rows.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);
  const pageStart = rows.length === 0 ? 0 : safePage * PAGE_SIZE + 1;
  const pageEnd = Math.min(rows.length, safePage * PAGE_SIZE + PAGE_SIZE);
  useEffect(() => {
    setPage(0);
  }, [sortDir, hiddenTables, hiddenExecutionSources, hiddenBrowserKinds, globalTimeRange, onlySuspicious]);

  if (loading) {
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
        <span>모든 아티팩트를 시간순으로 모으는 중...</span>
      </div>
    );
  }

  const hasArtifactFilters = hiddenTables.size > 0 || hiddenExecutionSources.size > 0 || hiddenBrowserKinds.size > 0;

  return (
    <div className="dfir-view" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={TimelineOutlinedIcon} title="통합 타임라인" meta={`${rows.length.toLocaleString()}건`}>
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

      {rows.length === 0 ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", gap: 8 }}>
          <HourglassEmptyOutlinedIcon sx={{ fontSize: 28, color: "var(--text-faint)" }} />
          <span>{allArtifactsHidden ? "표시할 아티팩트를 선택하세요." : globalActive ? "사고 기간에 해당하는 기록이 없습니다." : "표시할 시간 기록이 없습니다."}</span>
        </div>
      ) : (
      <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 14px 4px" }}>
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
        <PaginationControls ariaLabel="통합 타임라인 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${rows.length.toLocaleString()})`} />
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

      <footer
        aria-label="통합 타임라인 상태"
        style={{
          display: "flex",
          alignItems: "center",
          minHeight: 30,
          padding: "0 14px",
          borderTop: "1px solid var(--border)",
          background: "var(--bg-panel)",
          color: "var(--text-faint)",
          fontSize: 11.5,
          fontWeight: 600,
          flexShrink: 0,
        }}
      >
        <span>통합 타임라인 {rows.length.toLocaleString()}건</span>
        {rows.length !== allRows.length && (
          <span style={{ marginLeft: 8, color: "var(--text-dim)" }}>전체 {allRows.length.toLocaleString()}건</span>
        )}
      </footer>
    </div>
  );
}
