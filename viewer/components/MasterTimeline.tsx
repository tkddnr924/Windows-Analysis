"use client";

import { type CSSProperties, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
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
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import TimelineOutlinedIcon from "@mui/icons-material/TimelineOutlined";
import ViewListOutlinedIcon from "@mui/icons-material/ViewListOutlined";
import { resolveArtifactView } from "@/lib/artifactViews";
import RowDetailPanel from "./RowDetailPanel";

const ROW_HEIGHT = 52;
// A bookmark is an analyst decision, not another weak status tint. On the
// dark timeline it gets one pale evidence-paper surface so it is findable at
// a glance without competing with red/yellow investigative severity.
const BOOKMARK_ROW = "#f1e2bb";
const BOOKMARK_ROW_HOVER = "#f8ebc9";
const BOOKMARK_TEXT = "#202934";
const BOOKMARK_MUTED_TEXT = "#111820";
const BOOKMARK_ACCENT = "#ba7c00";

type ArtifactChipTone = {
  border: string;
  background: string;
  color: string;
};

// Artifact identity uses its own restrained hue. Investigation state still
// owns the warning/danger palette, so a purple JumpList chip never implies a
// finding and an amber TaskScheduler chip never implies an alert.
const ARTIFACT_CHIP_TONES: Record<string, ArtifactChipTone> = {
  AMCACHE: { border: "#0f9f8b", background: "rgba(15, 159, 139, 0.14)", color: "#65d7c6" },
  EVENTLOG: { border: "#6176d8", background: "rgba(97, 118, 216, 0.14)", color: "#aebdff" },
  JUMPLIST: { border: "#b7619b", background: "rgba(183, 97, 155, 0.14)", color: "#f0add7" },
  PREFETCH: { border: "#bd762e", background: "rgba(189, 118, 46, 0.14)", color: "#f3bd7b" },
  REGISTRY: { border: "#8a6ad3", background: "rgba(138, 106, 211, 0.14)", color: "#c9b8ff" },
  SRUM: { border: "#198eb5", background: "rgba(25, 142, 181, 0.14)", color: "#75d4f4" },
  WER: { border: "#c55d67", background: "rgba(197, 93, 103, 0.14)", color: "#ffabb2" },
  TASKSCHEDULER: { border: "#ad8a30", background: "rgba(173, 138, 48, 0.14)", color: "#eacb75" },
  POWERSHELL: { border: "#7065c7", background: "rgba(112, 101, 199, 0.14)", color: "#b7b0ff" },
  RDPCACHE: { border: "#418cc7", background: "rgba(65, 140, 199, 0.14)", color: "#8fcaff" },
  // Browser evidence is deliberately plum, away from the blue execution
  // history colour used in the same dense timeline.
  BROWSER: { border: "#a56cc4", background: "rgba(165, 108, 196, 0.15)", color: "#e1b8f2" },
  FILESYSTEM: { border: "#419e72", background: "rgba(65, 158, 114, 0.14)", color: "#8cdbad" },
  EXECUTIONHISTORY: { border: "#4c8cbe", background: "rgba(76, 140, 190, 0.14)", color: "#9fd2fb" },
  TARGETINFO: { border: "#67839e", background: "rgba(103, 131, 158, 0.14)", color: "#b4c9dc" },
  MFTEXPLORER: { border: "#3c987a", background: "rgba(60, 152, 122, 0.14)", color: "#91d9bd" },
  REMOTEDESKTOP: { border: "#538abd", background: "rgba(83, 138, 189, 0.14)", color: "#a2d0fb" },
  REGISTRYFINDINGS: { border: "#9671c9", background: "rgba(150, 113, 201, 0.14)", color: "#cfb8f7" },
  SMBHISTORY: { border: "#258f9a", background: "rgba(37, 143, 154, 0.14)", color: "#88dce2" },
  DEFENDER: { border: "#b56456", background: "rgba(181, 100, 86, 0.14)", color: "#f0ada0" },
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
function currentTimelinePresentation(entry: TimelineEntry): { summary: string; subtitle: string } {
  const spec = resolveArtifactView(entry.table, entry.columns);
  if (!spec) return { summary: entry.summary, subtitle: entry.subtitle };
  return {
    summary: (spec.timelineTitle ?? spec.title)(entry.row),
    subtitle: (spec.timelineSubtitle ?? spec.subtitle)?.(entry.row) ?? "",
  };
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
          padding: depth ? "4px 7px 4px 16px" : "5px 6px 5px 9px",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-sm)",
          background: checked || indeterminate ? "var(--bg-panel)" : "var(--bg-input)",
          boxShadow: checked || indeterminate ? `inset 2px 0 0 ${tone.border}` : "none",
          color: checked || indeterminate ? "var(--text)" : "var(--text-faint)",
          width: "100%",
          cursor: "pointer",
          userSelect: "none",
          ...style,
        }}
      >
        {depth ? (
          <span
            aria-hidden="true"
            style={{
              width: 8,
              height: 8,
              borderBottom: "2px solid var(--border-subtle)",
              borderLeft: "2px solid var(--border-subtle)",
              marginLeft: -6,
              marginRight: 3,
            }}
          />
        ) : null}
        <span style={{ minWidth: 0, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: depth ? 11.5 : 12.5, fontWeight: depth ? 550 : 650 }}>
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
}

export default function MasterTimeline({ entries, loading, onNavigate, onFetchLinkedRows, isBookmarked, onToggleBookmark, globalTimeRange }: MasterTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [hiddenTables, setHiddenTables] = useState<Set<string>>(new Set());
  const [hiddenExecutionSources, setHiddenExecutionSources] = useState<Set<string>>(new Set());
  const [hiddenBrowserKinds, setHiddenBrowserKinds] = useState<Set<string>>(new Set());
  const [showArtifactMenu, setShowArtifactMenu] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
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
  const rows = useMemo(() => {
    const filtered = allRows.filter((e) => {
      if (isEntryHidden(e)) return false;
      if (onlySuspicious && e.tags.length === 0) return false;
      if (globalActive && !inRange(e.timestamp, globalTimeRange)) return false;
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
  }, [allRows, sortDir, hiddenTables, hiddenExecutionSources, hiddenBrowserKinds, globalActive, globalTimeRange, onlySuspicious]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 15,
  });

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

  const virtualRows = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom = virtualRows.length > 0 ? totalHeight - virtualRows[virtualRows.length - 1].end : 0;
  const hasArtifactFilters = hiddenTables.size > 0 || hiddenExecutionSources.size > 0 || hiddenBrowserKinds.size > 0;

  return (
    <div className="dfir-view" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <header style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 54, padding: "0 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0 }}>
        <TimelineOutlinedIcon sx={{ fontSize: 20, color: "var(--accent)" }} />
        <h1 style={{ margin: 0, fontSize: 16, letterSpacing: "-0.02em" }}>통합 타임라인</h1>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto" }}>
          <button onClick={() => setSortDir((direction) => direction === "asc" ? "desc" : "asc")} title="정렬 순서 변경" style={toolbarButtonStyle}>
            <SortOutlinedIcon sx={{ fontSize: 16 }} />{sortDir === "asc" ? "오래된 순" : "최근 순"}
          </button>
          <button onClick={() => setOnlySuspicious((value) => !value)} title="의심 태그가 붙은 항목만 표시" aria-pressed={onlySuspicious} style={{ ...toolbarButtonStyle, background: onlySuspicious ? "var(--danger-subtle)" : "var(--bg-elevated)", color: onlySuspicious ? "var(--danger)" : "var(--text-dim)", borderColor: onlySuspicious ? "var(--danger)" : "var(--border)" }}>
            <ReportProblemOutlinedIcon sx={{ fontSize: 16 }} />의심 항목
          </button>
            <div style={{ position: "relative" }}>
            <button onClick={() => setShowArtifactMenu((value) => !value)} title="표시할 아티팩트 선택" aria-expanded={showArtifactMenu} style={{ ...toolbarButtonStyle, background: hasArtifactFilters ? "var(--accent-subtle)" : "var(--bg-elevated)", color: hasArtifactFilters ? "var(--accent)" : "var(--text-dim)", borderColor: hasArtifactFilters ? "var(--accent)" : "var(--border)" }}>
              <ViewListOutlinedIcon sx={{ fontSize: 16 }} />아티팩트
            </button>
            {showArtifactMenu && (
              <>
                <div onClick={() => setShowArtifactMenu(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
                <div style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 41, width: 290, maxHeight: 380, overflowY: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "3px 4px 8px", borderBottom: "1px solid var(--border-subtle)" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-dim)" }}>표시할 아티팩트</span>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
                      <button type="button" onClick={showAllArtifacts} style={{ fontSize: 11.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 650 }}>전체 선택</button>
                      <button type="button" onClick={hideAllArtifacts} style={{ fontSize: 11.5, background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontWeight: 650 }}>전체 해제</button>
                    </div>
                  </div>
                  <div style={{ display: "grid", gap: 5, paddingTop: 8 }}>
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
                                gap: 4,
                                padding: "4px 4px 4px 4px",
                                border: "1px solid var(--border)",
                                borderRadius: "var(--radius-sm)",
                                background: "var(--bg-input)",
                                boxShadow: "inset 0 0 0 1px var(--border-subtle), 0 0 0 1px rgba(0, 0, 0, 0.12)",
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
                                style={{
                                  paddingLeft: 10,
                                  borderRadius: "var(--radius-sm)",
                                  border: "1px solid var(--border)",
                                  boxShadow: checked || indeterminate ? `inset 2px 0 0 ${tone.border}` : "inset 0 0 0 1px var(--border-subtle)",
                                }}
                              />
                              <div style={{ display: "grid", gap: 4, paddingLeft: 12, paddingBottom: 4, borderLeft: "2px solid var(--border)", marginLeft: 2 }}>
                                {browserKinds.map(([kind, count]) => (
                                  <ArtifactFilterCheckbox
                                    key={kind}
                                    label={`${BROWSER_KIND_LABEL[kind] ?? kind} (${count})`}
                                    checked={!tableHidden && !hiddenBrowserKinds.has(kind)}
                                    tone={tone}
                                    depth={1}
                                    onChange={() => toggleBrowserKind(kind)}
                                    style={{
                                      borderLeft: "none",
                                      borderRadius: "var(--radius-sm)",
                                      border: "1px solid var(--border-subtle)",
                                      paddingLeft: 10,
                                      marginLeft: 0,
                                    }}
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
                            <div
                              key={label}
                              style={{
                                display: "grid",
                                gap: 4,
                                padding: "4px 0 0 0",
                                border: "1px solid var(--border)",
                                borderRadius: "var(--radius-sm)",
                                background: "var(--bg-input)",
                                boxShadow: "inset 0 0 0 1px var(--border-subtle)",
                              }}
                            >
                              <ArtifactFilterCheckbox
                                key={`${label}-parent`}
                                label={`${label} (${tables.reduce((acc, table) => acc + (artifactTableCounts.get(table) ?? 0), 0)})`}
                                checked={checked}
                                indeterminate={indeterminate}
                                tone={tone}
                                onChange={() => toggleTables(tables)}
                                style={{
                                  paddingLeft: 10,
                                  border: "1px solid var(--border)",
                                  boxShadow: checked || indeterminate ? `inset 2px 0 0 ${tone.border}` : "inset 0 0 0 1px var(--border-subtle)",
                                }}
                              />
                              <div style={{ display: "grid", gap: 4, padding: "2px 0 4px 10px", borderLeft: "2px solid var(--border)", marginLeft: 2 }}>
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
                                      style={{ border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", marginLeft: 0, paddingLeft: 10 }}
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
                            style={{
                              paddingLeft: 10,
                              borderRadius: "var(--radius-sm)",
                              border: "1px solid var(--border)",
                              boxShadow: checked || indeterminate ? `inset 2px 0 0 ${tone.border}` : "inset 0 0 0 1px var(--border-subtle)",
                            }}
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
        </div>
      </header>

      {rows.length === 0 ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", gap: 8 }}>
          <HourglassEmptyOutlinedIcon sx={{ fontSize: 28, color: "var(--text-faint)" }} />
          <span>{allArtifactsHidden ? "표시할 아티팩트를 선택하세요." : globalActive ? "사고 기간에 해당하는 기록이 없습니다." : "표시할 시간 기록이 없습니다."}</span>
        </div>
      ) : (
      <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        <div style={{ height: paddingTop }} />
        {virtualRows.map((virtualRow) => {
          const entry = rows[virtualRow.index];
          const presentation = currentTimelinePresentation(entry);
          const dangerTag = entry.tags.find((t) => t.severity === "danger");
          const warningTag = entry.tags.find((t) => t.severity === "warning");
          const bookmarked = isBookmarked(entry);
          const chipTone = artifactChipTone(entry.category, entry.table);
          return (
            <div
              key={virtualRow.key}
              onClick={() => setSelectedEntry(entry)}
              style={{
                height: ROW_HEIGHT,
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "0 14px",
                borderBottom: "1px solid var(--border-subtle)",
                cursor: "pointer",
                background: bookmarked ? BOOKMARK_ROW : virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)",
                boxShadow: bookmarked ? `inset 4px 0 0 ${BOOKMARK_ACCENT}` : undefined,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = bookmarked ? BOOKMARK_ROW_HOVER : "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = bookmarked ? BOOKMARK_ROW : virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)")}
            >
              <span style={{ flexShrink: 0, width: 178, fontFamily: "var(--mono)", fontSize: 12.5, color: bookmarked ? BOOKMARK_MUTED_TEXT : entry.timestamp ? "var(--text-time)" : "var(--text-faint)" }}>
                {entry.timestamp || "(시간 정보 없음)"}
              </span>
              <span
                style={{
                  flexShrink: 0,
                  width: 144,
                  fontSize: 11,
                  fontWeight: 650,
                  padding: "3px 7px",
                  border: `1px solid ${chipTone.border}`,
                  borderRadius: "var(--radius-md)",
                  // Artifact labels use the same filled identity treatment in
                  // normal and bookmarked rows. Bookmark state belongs to the
                  // row surface and left accent, never to artifact identity.
                  background: chipTone.border,
                  color: "#ffffff",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  textAlign: "center",
                }}
              >
                {artifactDisplayName(entry.category, entry.table)}
              </span>
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden" }}>
                <div style={{ fontSize: 13.5, fontWeight: 650, color: bookmarked ? BOOKMARK_TEXT : undefined, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {presentation.summary}
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
        <div style={{ height: paddingBottom }} />
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
