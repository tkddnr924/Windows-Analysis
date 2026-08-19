"use client";

import { useEffect, useMemo, useState } from "react";
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

export const CATEGORY_ICONS: Record<string, string> = {
  AMCACHE: "📦",
  EVENTLOG: "📋",
  JUMPLIST: "🔗",
  PREFETCH: "⚡",
  REGISTRY: "🗂️",
  SRUM: "📊",
  WER: "💥",
  TASKSCHEDULER: "⏰",
  POWERSHELL: "💻",
  RDPCACHE: "🖼️",
  BROWSER: "🌐",
  FILESYSTEM: "🗄️",
};

// Maps a run-list artifact name to its output CATEGORY folder (upper-cased),
// so the sidebar can show every artifact that ran — including ones that found
// no source files (no folder on disk) — as a "데이터 없음" placeholder.
// Category defaults to the artifact name; only UsnJrnl files under FileSystem.
const ARTIFACT_CATEGORY: Record<string, string> = {
  UsnJrnl: "FILESYSTEM",
  // MFT is a 종합 분석 item (_OVERVIEW/MFT_Records.sqlite → "MFT Explorer"),
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
      <span style={{ width: 10, display: "inline-block" }} />
      {CATEGORY_ICONS[name] && <span>{CATEGORY_ICONS[name]}</span>}
      <span>{label ?? name}</span>
      <span style={{ marginLeft: "auto", fontSize: 10.5, fontWeight: 400 }}>데이터 없음</span>
    </div>
  );
}

const OVERVIEW_TABLE_ICONS: Record<string, string> = {
  TargetInfo: "🖥️",
  ExecutionHistory: "⚡",
  Defender: "🛡️",
  RegistryFindings: "🔎",
  BrowserActivity: "🌐",
  RemoteDesktopHistory: "🖥️",
  SmbHistory: "📁",
  PowerShellHistory: "💻",
  RdpCache: "🖼️",
  ScheduledTasks: "⏰",
  MFT_Records: "🗂️",
};

// Friendlier labels for overview tables whose raw name reads awkwardly.
// 종합 분석(_OVERVIEW) items are labeled in English; the rest of the UI stays
// Korean. Every overview table gets an explicit English name here.
const OVERVIEW_TABLE_NAMES: Record<string, string> = {
  TargetInfo: "Target Info",
  ExecutionHistory: "Execution History",
  Defender: "Defender",
  RegistryFindings: "Registry Findings",
  BrowserActivity: "Browser Activity",
  RemoteDesktopHistory: "Remote Desktop",
  SmbHistory: "SMB History",
  PowerShellHistory: "PowerShell History",
  RdpCache: "RDP Cache",
  ScheduledTasks: "Scheduled Tasks",
  MFT_Records: "MFT Explorer",
};

function sameEntry(a: ResultFileEntry | null, b: ResultFileEntry): boolean {
  return !!a && a.fullPath === b.fullPath && a.tableName === b.tableName;
}

function FileRow({
  entry,
  label,
  selected,
  indent,
  icon,
  count,
  onSelectFile,
}: {
  entry: ResultFileEntry;
  label: string;
  selected: boolean;
  indent: number;
  icon?: string;
  count?: number;
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
        padding: `5px 10px 5px ${indent}px`,
        cursor: "pointer",
        background: selected ? "var(--bg-selected)" : "transparent",
        borderLeft: `2px solid ${selected ? "var(--accent)" : "transparent"}`,
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
      <span style={{ display: "flex", alignItems: "center", gap: 5, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : "var(--text-dim)" }}>
        {icon && <span style={{ flexShrink: 0, fontSize: 12 }}>{icon}</span>}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
      </span>
      <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{(count ?? entry.rowCount).toLocaleString()}</span>
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
  icon,
  onSelectFile,
}: {
  fileName: string;
  label?: string;
  tables: ResultFileEntry[];
  selectedFile: ResultFileEntry | null;
  indent: number;
  icon?: string;
  onSelectFile: (file: ResultFileEntry) => void;
}) {
  const [open, setOpen] = useState(false);

  if (tables.length === 1) {
    return (
      <FileRow entry={tables[0]} label={label ?? fileName} selected={sameEntry(selectedFile, tables[0])} indent={indent} icon={icon} onSelectFile={onSelectFile} />
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
          padding: `5px 10px 5px ${indent}px`,
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
          <span style={{ width: 10, display: "inline-block", fontSize: 9, color: "var(--text-faint)" }}>{open ? "▾" : "▸"}</span>
          {icon && <span style={{ flexShrink: 0, fontSize: 12 }}>{icon}</span>}
          <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{fileName}</span>
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>{tables.length}</span>
        </span>
        <span style={{ color: "var(--text-faint)", fontSize: 11, flexShrink: 0 }}>{total.toLocaleString()}</span>
      </div>
      {open &&
        tables.map((t) => (
          <FileRow key={t.tableName} entry={t} label={t.tableName} selected={sameEntry(selectedFile, t)} indent={indent + 16} onSelectFile={onSelectFile} />
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
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned, onNavigate }: CategoryNodeProps) {
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
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [files]);

  const isExpanded = pinned || expanded;
  const icon = pinned ? undefined : CATEGORY_ICONS[category.name];

  return (
    <div
      style={
        pinned
          ? { background: "linear-gradient(180deg, rgba(88,166,255,0.07), rgba(88,166,255,0.02))", borderBottom: "1px solid var(--border-subtle)" }
          : undefined
      }
    >
      <div
        onClick={() => !pinned && setExpanded((e) => !e)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "8px 10px",
          cursor: pinned ? "default" : "pointer",
          fontWeight: 600,
          fontSize: 12.5,
          userSelect: "none",
          color: pinned ? "var(--accent)" : "var(--text)",
        }}
      >
        {!pinned && (
          <span style={{ width: 10, display: "inline-block", fontSize: 9, color: "var(--text-faint)" }}>{expanded ? "▾" : "▸"}</span>
        )}
        {icon && <span>{icon}</span>}
        {pinned && <span style={{ fontSize: 12 }}>✦</span>}
        <span>{displayName ?? category.name}</span>
        <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{byFile ? byFile.length : ""}</span>
      </div>
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
              indent={pinned ? 20 : 26}
              icon={pinned ? OVERVIEW_TABLE_ICONS[fileName] : undefined}
              onSelectFile={onSelectFile}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface PinnedNavRowProps {
  icon: string;
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
        gap: 8,
        padding: "9px 12px",
        cursor: busy ? "progress" : "pointer",
        fontSize: 12.5,
        fontWeight: 600,
        background: selected ? "var(--bg-selected)" : "transparent",
        borderLeft: `2px solid ${selected ? "var(--accent)" : "transparent"}`,
        color: busy ? "var(--text-faint)" : selected ? "var(--text)" : "var(--text-dim)",
      }}
      onMouseEnter={(e) => {
        if (!selected && !busy) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span>{icon}</span>
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
  onBackToCases: () => void;
  onBackToHosts: () => void;
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
  onBackToCases,
  onBackToHosts,
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
        {/* breadcrumb: case name (click → back to host list / case list) */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, fontSize: 11.5 }}>
          <button onClick={onBackToCases} title="케이스 목록" style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600, padding: 0 }}>
            🗂️ {activeCase.name}
          </button>
          <span style={{ color: "var(--text-faint)" }}>/</span>
          <button onClick={onBackToHosts} title="호스트 목록" style={{ background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600, padding: 0 }}>
            호스트 목록
          </button>
        </div>
        {/* host selector — switch between machines in this case */}
        <div style={{ position: "relative" }}>
          <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 13, pointerEvents: "none" }}>
            🖥️
          </span>
          <select
            value={activeHost.id}
            onChange={(e) => {
              const found = activeCase.hosts.find((h) => h.id === e.target.value);
              if (found) onSelectHost(found);
            }}
            style={{
              width: "100%",
              padding: "7px 10px 7px 32px",
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
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)", display: "flex", alignItems: "center", gap: 5 }}>
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              flexShrink: 0,
              background: activeHost.lastRunStatus === "ok" ? "var(--success)" : activeHost.lastRunStatus === "error" ? "var(--danger)" : "var(--text-faint)",
            }}
          />
          {activeHost.lastRunAt ? `마지막 실행: ${activeHost.lastRunAt}` : "아직 파싱되지 않음"}
        </div>
        {(
          <div style={{ marginTop: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
              <span style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.6 }}>
                기간 필터 (사고 시점)
              </span>
              {rangeActive(timeRange) && (
                <button
                  onClick={() => onTimeRangeChange(EMPTY_TIME_RANGE)}
                  title="기간 초기화"
                  style={{ marginLeft: "auto", fontSize: 10.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}
                >
                  초기화 ×
                </button>
              )}
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
            {rangeActive(timeRange) && (
              <div style={{ marginTop: 5, fontSize: 10.5, color: "var(--accent)" }}>이 기간으로 모든 데이터를 거릅니다</div>
            )}
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
          {/* 케이스 분석 — spans every host in the case */}
          <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ padding: "8px 14px 4px", fontSize: 10.5, fontWeight: 700, letterSpacing: 0.5, color: "var(--text-faint)", textTransform: "uppercase" }}>케이스 분석</div>
            <PinnedNavRow
              icon="🔍"
              label="전체 검색"
              selected={activeVirtualTab === "search"}
              onClick={onSelectSearch}
            />
            <PinnedNavRow
              icon="🔗"
              label="호스트 연결"
              selected={activeVirtualTab === "connections"}
              onClick={onSelectConnections}
            />
            <PinnedNavRow
              icon="🔖"
              label="북마크"
              count={bookmarkCount}
              selected={activeVirtualTab === "bookmarks"}
              onClick={onSelectBookmarks}
            />
          </div>
          {/* 호스트 분석 — the currently open host */}
          <div style={{ borderBottom: "1px solid var(--border-subtle)" }}>
            <div style={{ padding: "8px 14px 4px", fontSize: 10.5, fontWeight: 700, letterSpacing: 0.5, color: "var(--text-faint)", textTransform: "uppercase" }}>호스트 분석</div>
            <PinnedNavRow
              icon="🏠"
              label="대시보드"
              selected={!activeVirtualTab && !selectedFile}
              onClick={onSelectDashboard}
            />
            <PinnedNavRow
              icon="🕐"
              label="통합 타임라인"
              selected={activeVirtualTab === "timeline"}
              onClick={onSelectTimeline}
            />
          </div>
        </>
        {overviewCategory && (
          <CategoryNode
            category={overviewCategory}
            displayName="종합 분석"
            pinned
            selectedFile={selectedFile}
            onSelectFile={onSelectFile}
          />
        )}
        {hasRawSection && (
          <div style={{ padding: "10px 10px 4px", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: 0.8 }}>
            원본 데이터
          </div>
        )}
        {orderedNames.map((name) => {
          const category = presentByName.get(name);
          return category ? (
            <CategoryNode key={category.fullPath} category={category} displayName={CATEGORY_LABELS[category.name]} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
          ) : (
            <EmptyCategoryRow key={name} name={name} label={CATEGORY_LABELS[name]} />
          );
        })}
        {leftoverCategories.map((category) => (
          <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}
