"use client";

import { useEffect, useMemo, useState } from "react";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import SearchIcon from "@mui/icons-material/Search";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import TimelineIcon from "@mui/icons-material/Timeline";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import ManageSearchOutlinedIcon from "@mui/icons-material/ManageSearchOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import LanguageOutlinedIcon from "@mui/icons-material/LanguageOutlined";
import PhotoLibraryOutlinedIcon from "@mui/icons-material/PhotoLibraryOutlined";
import type { Case, Host, CategoryEntry, ResultFileEntry } from "@/lib/types";
import { EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import DateTimeInput from "./DateTimeInput";

const timeInputStyle: React.CSSProperties = {
  width: "100%",
  padding: "5px 8px",
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text)",
  fontSize: 11.5,
  fontFamily: "var(--mono)",
  colorScheme: "dark",
};

// Maps a run-list artifact name to its output CATEGORY folder (upper-cased),
// so the sidebar can show every artifact that ran — including ones that found
// no source files (no folder on disk) — as a "데이터 없음" placeholder.
// Category defaults to the artifact name; only UsnJrnl files under FileSystem.
const ARTIFACT_CATEGORY: Record<string, string> = {
  UsnJrnl: "FILESYSTEM",
  // MFT is a 종합 분석 item (_OVERVIEW/MFT_Records.sqlite → "파일 시스템 정보"),
  // not a raw category — map it there so it never shows as an empty "MFT"
  // placeholder in the 원본 데이터 list.
  MFT: "_OVERVIEW",
  // Both browser artifacts write into the shared BROWSER output folder, so the
  // run-list placeholder must resolve there too — otherwise BrowserHistory /
  // BrowserCache show as empty "데이터 없음" rows next to the real BROWSER folder.
  BrowserHistory: "BROWSER",
  BrowserCache: "BROWSER",
};

function categoryForArtifact(name: string): string {
  return ARTIFACT_CATEGORY[name] ?? name.toUpperCase();
}

// Friendlier display labels for raw categories whose folder name reads
// awkwardly. POWERSHELL holds only the PSReadLine console history (the
// PowerShell *event logs* live under EVENTLOG), so label it accordingly.
const CATEGORY_LABELS: Record<string, string> = {
  POWERSHELL: "ConsoleHistory",
};

function EmptyCategoryRow({ name, label }: { name: string; label?: string }) {
  return (
    <div
      title="이 아티팩트는 실행됐지만 대상에서 원본 파일을 찾지 못했습니다"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        padding: "8px 10px",
        fontSize: 12.5,
        fontWeight: 600,
        color: "var(--text-faint)",
        opacity: 0.5,
        userSelect: "none",
        cursor: "default",
      }}
    >
      <span>{label ?? name}</span>
      <span style={{ marginLeft: "auto", fontSize: 10.5, fontWeight: 400 }}>데이터 없음</span>
    </div>
  );
}

// Friendlier labels for overview tables whose raw name reads awkwardly.
// Curated display order for the 종합 분석(_OVERVIEW) tables (by sqlite/table
// name). Anything not listed (e.g. BrowserActivity) sorts after these.
const OVERVIEW_ORDER: string[] = [
  "TargetInfo",
  "MFT_Records",
  "RemoteDesktopHistory",
  "ExecutionHistory",
  "Defender",
  "RegistryFindings",
  "PowerShellHistory",
  "SmbHistory",
  "ScheduledTasks",
  "RdpCache",
];

// 종합 분석(_OVERVIEW) tables receive analyst-facing Korean display labels.
const OVERVIEW_TABLE_NAMES: Record<string, string> = {
  TargetInfo: "호스트 정보",
  ExecutionHistory: "실행 이력",
  Defender: "Microsoft Defender 활동",
  RegistryFindings: "레지스트리 특이사항",
  BrowserActivity: "브라우저 활동",
  RemoteDesktopHistory: "원격 접근 이력 (RDP)",
  SmbHistory: "SMB 접속 이력",
  PowerShellHistory: "파워셸 실행 이력",
  RdpCache: "RDP Cache",
  ScheduledTasks: "작업 스케줄러",
  MFT_Records: "파일 시스템 정보",
};

function OverviewTableIcon({ name }: { name: string }) {
  const props = { sx: { fontSize: 18, color: "var(--text-faint)", flexShrink: 0 } };
  switch (name) {
    case "TargetInfo": return <InfoOutlinedIcon {...props} />;
    // This icon identifies a file-system evidence view, rather than decorating
    // the navigation label.
    case "MFT_Records": return <FolderOpenOutlinedIcon {...props} />;
    case "RemoteDesktopHistory": return <DesktopWindowsOutlinedIcon {...props} />;
    case "ExecutionHistory": return <BoltOutlinedIcon {...props} />;
    case "RegistryFindings": return <ManageSearchOutlinedIcon {...props} />;
    case "PowerShellHistory": return <TerminalOutlinedIcon {...props} />;
    case "SmbHistory": return <DnsOutlinedIcon {...props} />;
    case "ScheduledTasks": return <TaskOutlinedIcon {...props} />;
    // Keep the navigation glyph identical to the RDP Cache view header; the
    // remote session ledger itself uses the desktop glyph above.
    case "RdpCache": return <PhotoLibraryOutlinedIcon {...props} />;
    case "BrowserActivity": return <LanguageOutlinedIcon {...props} />;
    default: return <LanguageOutlinedIcon {...props} />;
  }
}

function sameEntry(a: ResultFileEntry | null, b: ResultFileEntry): boolean {
  return !!a && a.fullPath === b.fullPath && a.tableName === b.tableName;
}

function FileRow({
  entry,
  label,
  selected,
  indent,
  leading,
  count,
  prominent = false,
  onSelectFile,
}: {
  entry: ResultFileEntry;
  label: string;
  selected: boolean;
  indent: number;
  leading?: React.ReactNode;
  count?: number;
  /** Host-analysis navigation uses the same tab scale as Dashboard/Timeline. */
  prominent?: boolean;
  onSelectFile: (file: ResultFileEntry) => void;
}) {
  return (
    <div
      onClick={() => onSelectFile(entry)}
      title={`${entry.relativePath} · ${entry.tableName}`}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 6,
        padding: `${prominent ? 10 : 7}px 10px ${prominent ? 10 : 7}px ${indent}px`,
        cursor: "pointer",
        background: selected
          ? "linear-gradient(135deg, rgba(74, 146, 218, 0.31), rgba(37, 78, 118, 0.38))"
          : "transparent",
        borderLeft: `3px solid ${selected ? "var(--accent)" : "transparent"}`,
        boxShadow: selected
          ? "inset 3px 3px 7px rgba(3, 8, 14, 0.45), inset -2px -2px 6px rgba(142, 188, 230, 0.12), 0 1px 0 rgba(142, 188, 230, 0.12)"
          : "none",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
      onMouseEnter={(e) => {
        if (!selected) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span style={{ display: "flex", alignItems: "center", gap: 7, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : "var(--text-dim)", fontSize: prominent ? 14 : 13.5, fontWeight: selected ? 700 : prominent ? 600 : 400 }}>
        {leading}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
      </span>
      <span style={{ color: "var(--text-faint)", fontSize: 11.5, flexShrink: 0 }}>{(count ?? entry.rowCount).toLocaleString()}</span>
    </div>
  );
}

// One source .sqlite. A single-table file is a plain clickable row; a
// multi-table file (registry dump, browser History, Amcache, SRUM) is an
// expandable node listing its tables.
function FileNode({
  fileName,
  label,
  tables,
  selectedFile,
  indent,
  leading,
  prominent = false,
  onSelectFile,
}: {
  fileName: string;
  label?: string;
  tables: ResultFileEntry[];
  selectedFile: ResultFileEntry | null;
  indent: number;
  leading?: React.ReactNode;
  prominent?: boolean;
  onSelectFile: (file: ResultFileEntry) => void;
}) {
  const [open, setOpen] = useState(false);

  if (tables.length === 1) {
    return (
      <FileRow entry={tables[0]} label={label ?? fileName} selected={sameEntry(selectedFile, tables[0])} indent={indent} leading={leading} prominent={prominent} onSelectFile={onSelectFile} />
    );
  }

  const total = tables.reduce((n, t) => n + t.rowCount, 0);
  const anySelected = tables.some((t) => sameEntry(selectedFile, t));
  return (
    <div>
      <div
        onClick={() => setOpen((v) => !v)}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 6,
          padding: `${prominent ? 10 : 7}px 10px ${prominent ? 10 : 7}px ${indent}px`,
          cursor: "pointer",
          userSelect: "none",
          color: anySelected ? "var(--text)" : "var(--text-dim)",
          whiteSpace: "nowrap",
          overflow: "hidden",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 5, overflow: "hidden", textOverflow: "ellipsis" }}>
          {open ? <KeyboardArrowDownIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} /> : <KeyboardArrowRightIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} />}
          {leading}
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", fontSize: prominent ? 14 : 13.5, fontWeight: prominent ? 600 : 400 }}>{fileName}</span>
          <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{tables.length}</span>
        </span>
        <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{total.toLocaleString()}</span>
      </div>
      {open &&
        tables.map((t) => (
          <FileRow key={t.tableName} entry={t} label={t.tableName} selected={sameEntry(selectedFile, t)} indent={indent + 16} prominent={prominent} onSelectFile={onSelectFile} />
        ))}
    </div>
  );
}

interface CategoryNodeProps {
  category: CategoryEntry;
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  /** Friendly label to show instead of the raw folder name (e.g. "_OVERVIEW" -> "종합 분석"). */
  displayName?: string;
  /** Pinned sections (the curated cross-artifact overview) are always
   * expanded and visually distinguished from the raw per-artifact tree. */
  pinned?: boolean;
  hideHeader?: boolean;
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned, hideHeader, onNavigate }: CategoryNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [files, setFiles] = useState<ResultFileEntry[] | null>(null);

  useEffect(() => {
    window.api.listResultFiles(category.fullPath).then(setFiles);
  }, [category.fullPath]);

  // Group the per-table entries back by their source file, so one .sqlite is
  // one node (expandable when it holds several tables).
  const byFile = useMemo(() => {
    if (!files) return null;
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of files) {
      if (!map.has(file.fileName)) map.set(file.fileName, []);
      map.get(file.fileName)!.push(file);
    }
    // 종합 분석(_OVERVIEW) follows a curated analyst order; everything else is
    // alphabetical. Files not in the list fall to the end (still alphabetical).
    const rank = (name: string) => {
      const i = OVERVIEW_ORDER.indexOf(name);
      return i === -1 ? OVERVIEW_ORDER.length : i;
    };
    return [...map.entries()].sort((a, b) =>
      pinned ? (rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0])) : a[0].localeCompare(b[0]),
    );
  }, [files, pinned]);

  const isExpanded = pinned || expanded;
  return (
    <div>
      {!hideHeader && <div
        onClick={() => !pinned && setExpanded((e) => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "10px 10px",
          cursor: pinned ? "default" : "pointer",
          fontWeight: 600,
          fontSize: 13.5,
          userSelect: "none",
          color: pinned ? "var(--accent)" : "var(--text)",
        }}
      >
        {!pinned && (expanded ? <KeyboardArrowDownIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} /> : <KeyboardArrowRightIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} />)}
        <span>{displayName ?? category.name}</span>
        <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{byFile ? byFile.length : ""}</span>
      </div>}
      {isExpanded && byFile && (
        <div style={{ paddingBottom: pinned ? 4 : 0 }}>
          {byFile.length === 0 && (
            <div style={{ padding: "4px 10px 8px 28px", color: "var(--text-faint)", fontSize: 12 }}>결과 없음</div>
          )}
          {byFile.map(([fileName, tables]) => (
            <FileNode
              key={fileName}
              fileName={fileName}
              label={pinned ? OVERVIEW_TABLE_NAMES[fileName] : undefined}
              tables={tables}
              selectedFile={selectedFile}
              indent={pinned ? 12 : 26}
              leading={pinned ? <OverviewTableIcon name={fileName} /> : undefined}
              prominent={pinned}
              onSelectFile={onSelectFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface PinnedNavRowProps {
  icon: React.ReactNode;
  label: string;
  count?: number;
  selected: boolean;
  onClick: () => void;
  /** When true the row shows a spinner and is not clickable (background work
   * — e.g. the master timeline — is still building). */
  busy?: boolean;
}

function PinnedNavRow({ icon, label, count, selected, onClick, busy }: PinnedNavRowProps) {
  return (
    <div
      onClick={busy ? undefined : onClick}
      title={busy ? "백그라운드에서 준비 중…" : undefined}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 12px",
        cursor: busy ? "progress" : "pointer",
        fontSize: 14,
        fontWeight: selected ? 700 : 600,
        background: selected
          ? "linear-gradient(135deg, rgba(74, 146, 218, 0.34), rgba(36, 75, 113, 0.42))"
          : "transparent",
        borderLeft: `3px solid ${selected ? "var(--accent)" : "transparent"}`,
        boxShadow: selected
          ? "inset 4px 4px 9px rgba(3, 8, 14, 0.50), inset -3px -3px 7px rgba(142, 188, 230, 0.13), 0 1px 0 rgba(142, 188, 230, 0.14)"
          : "none",
        color: busy ? "var(--text-faint)" : selected ? "var(--text)" : "var(--text-dim)",
      }}
      onMouseEnter={(e) => {
        if (!selected && !busy) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span style={{ display: "flex", color: selected ? "var(--accent)" : "var(--text-faint)" }}>{icon}</span>
      <span>{label}</span>
      {busy ? (
        <span className="wa-spin" style={{ marginLeft: "auto" }} />
      ) : (
        count !== undefined && <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{count}</span>
      )}
    </div>
  );
}

interface SidebarProps {
  activeCase: Case;
  activeHost: Host;
  onSelectHost: (h: Host) => void;
  onBackToHosts: () => void;
  onRefresh: () => void;
  categories: CategoryEntry[];
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  activeVirtualTab: "timeline" | "bookmarks" | "connections" | "search" | null;
  onSelectDashboard: () => void;
  onSelectTimeline: () => void;
  onSelectBookmarks: () => void;
  onSelectConnections: () => void;
  onSelectSearch: () => void;
  bookmarkCount: number;
  timeRange: TimeRange;
  onTimeRangeChange: (range: TimeRange) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
}

export default function Sidebar({
  activeCase,
  activeHost,
  onSelectHost,
  onBackToHosts,
  onRefresh,
  categories,
  selectedFile,
  onSelectFile,
  activeVirtualTab,
  onSelectDashboard,
  onSelectTimeline,
  onSelectBookmarks,
  onSelectConnections,
  onSelectSearch,
  bookmarkCount,
  timeRange,
  onTimeRangeChange,
  onNavigate,
}: SidebarProps) {
  const [rawDataExpanded, setRawDataExpanded] = useState(false);
  const hasTimeRange = rangeActive(timeRange);
  const overviewCategory = categories.find((c) => c.name === "_OVERVIEW");
  const rawCategories = categories.filter((c) => c.name !== "_OVERVIEW");

  // Every artifact that ran, mapped to its category, in run order — so the
  // "원본 데이터" list is 1:1 with the run list. Categories with real output
  // render as normal nodes; ones that ran but produced no data (no folder)
  // render as a greyed "데이터 없음" placeholder. Any present category not in
  // the run list (e.g. from an older parse) is appended after.
  const presentByName = new Map(rawCategories.map((c) => [c.name, c]));
  const orderedNames: string[] = [];
  const seenNames = new Set<string>();
  for (const artifact of activeHost.artifactsRun ?? []) {
    const cat = categoryForArtifact(artifact);
    if (cat === "_OVERVIEW" || seenNames.has(cat)) continue;
    seenNames.add(cat);
    orderedNames.push(cat);
  }
  const leftoverCategories = rawCategories.filter((c) => !seenNames.has(c.name));
  const hasRawSection = orderedNames.length > 0 || leftoverCategories.length > 0;

  return (
    <div
      className="dfir-sidebar"
      style={{
        width: 300,
        flexShrink: 0,
        borderRight: "1px solid var(--border)",
        background: "var(--bg-panel)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      <div style={{ padding: 12, borderBottom: "1px solid var(--border)" }}>
        {/* Current host control. The internal session case is intentionally not shown. */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, fontSize: 11.5 }}>
          <button onClick={onBackToHosts} title="호스트 목록" style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600, padding: 0 }}>
            호스트 등록
          </button>
          <button onClick={onRefresh} title="케이스·호스트·분석 결과를 다시 불러옵니다" style={{ marginLeft: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--text-dim)", borderRadius: "var(--radius-sm)", cursor: "pointer", fontSize: 11, padding: "3px 7px" }}>
            새로고침
          </button>
        </div>
        {/* host selector — switch between machines in this case */}
        <div>
          <select
            value={activeHost.id}
            onChange={(e) => {
              const found = activeCase.hosts.find((h) => h.id === e.target.value);
              if (found) onSelectHost(found);
            }}
            style={{
              width: "100%",
              padding: "7px 10px",
              background: "var(--bg-input)",
              color: "var(--text)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              appearance: "none",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            {activeCase.hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.name}
              </option>
            ))}
          </select>
        </div>
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)" }}>
          {activeHost.lastRunAt ? `마지막 실행: ${activeHost.lastRunAt}` : "아직 파싱되지 않음"}
        </div>
        {(
          <div style={{ marginTop: 10 }}>
            <div className="sidebar-time-range-head" style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 62px", alignItems: "center", minHeight: 24, gap: 6, marginBottom: 5 }}>
              <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                기간 필터 (사고 시점)
              </span>
              <span style={{ display: "flex", justifyContent: "flex-end", minWidth: 0 }}>
                {hasTimeRange && <button type="button" onClick={() => onTimeRangeChange(EMPTY_TIME_RANGE)} title="기간 초기화" aria-label="기간 초기화" style={{ minWidth: 42, padding: 0, fontSize: 10.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}>초기화</button>}
              </span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <DateTimeInput
                value={timeRange.start}
                onChange={(v) => onTimeRangeChange({ ...timeRange, start: v })}
                style={timeInputStyle}
                ariaLabel="시작 시각"
                placeholder="시작 (YYYY-MM-DD HH:mm:ss)"
              />
              <DateTimeInput
                value={timeRange.end}
                onChange={(v) => onTimeRangeChange({ ...timeRange, end: v })}
                style={timeInputStyle}
                ariaLabel="종료 시각"
                placeholder="종료 (YYYY-MM-DD HH:mm:ss)"
              />
            </div>
            <div aria-live={hasTimeRange ? "polite" : undefined} aria-hidden={!hasTimeRange} style={{ minHeight: 16, marginTop: 5, fontSize: 10.5, color: "var(--accent)" }}>{hasTimeRange ? "이 기간으로 모든 데이터를 거릅니다" : null}</div>
          </div>
        )}
      </div>
      <div style={{ overflowY: "auto", flex: 1 }}>
        {categories.length === 0 && (
          <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5, lineHeight: 1.6 }}>
            결과가 없습니다.
            <br />
            아직 파싱하지 않았을 수 있습니다.
          </div>
        )}
        <>
          {/* Integrated analysis spans every host in the current session. */}
          <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ padding: "12px 14px 6px", fontSize: 11.5, fontWeight: 750, letterSpacing: 0.6, color: "var(--text-faint)", textTransform: "uppercase" }}>통합 분석</div>
            <PinnedNavRow
              icon={<SearchIcon sx={{ fontSize: 19 }} />}
              label="전체 검색"
              selected={activeVirtualTab === "search"}
              onClick={onSelectSearch}
            />
            <PinnedNavRow
              icon={<AccountTreeIcon sx={{ fontSize: 19 }} />}
              label="호스트 연결"
              selected={activeVirtualTab === "connections"}
              onClick={onSelectConnections}
            />
            <PinnedNavRow
              icon={<BookmarkBorderIcon sx={{ fontSize: 19 }} />}
              label="분석 정보"
              count={bookmarkCount}
              selected={activeVirtualTab === "bookmarks"}
              onClick={onSelectBookmarks}
            />
          </div>
          {/* 호스트 분석 — the currently open host */}
          <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ padding: "12px 14px 6px", fontSize: 11.5, fontWeight: 750, letterSpacing: 0.6, color: "var(--text-faint)", textTransform: "uppercase" }}>호스트 분석</div>
            <PinnedNavRow
              icon={<DashboardOutlinedIcon sx={{ fontSize: 19 }} />}
              label="대시보드"
              selected={!activeVirtualTab && !selectedFile}
              onClick={onSelectDashboard}
            />
            <PinnedNavRow
              icon={<TimelineIcon sx={{ fontSize: 19 }} />}
              label="통합 타임라인"
              selected={activeVirtualTab === "timeline"}
              onClick={onSelectTimeline}
            />
            {overviewCategory && (
              <CategoryNode
                category={overviewCategory}
                pinned
                hideHeader
                selectedFile={selectedFile}
                onSelectFile={onSelectFile}
              />
            )}
          </div>
        </>
        {hasRawSection && (
          <button
            onClick={() => setRawDataExpanded((expanded) => !expanded)}
            aria-expanded={rawDataExpanded}
            style={{ width: "100%", display: "flex", alignItems: "center", gap: 4, padding: "10px 8px 6px", border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer", fontSize: 10.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.8, textAlign: "left" }}
          >
            {rawDataExpanded ? <KeyboardArrowDownIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} /> : <KeyboardArrowRightIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} />}
            원본 데이터
          </button>
        )}
        {rawDataExpanded && orderedNames.map((name) => {
          const category = presentByName.get(name);
          return category ? (
            <CategoryNode key={category.fullPath} category={category} displayName={CATEGORY_LABELS[category.name]} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
          ) : (
            <EmptyCategoryRow key={name} name={name} label={CATEGORY_LABELS[name]} />
          );
        })}
        {rawDataExpanded && leftoverCategories.map((category) => (
          <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}
