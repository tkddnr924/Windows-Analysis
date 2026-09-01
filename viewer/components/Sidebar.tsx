"use client";
import FilterAltOutlinedIcon from "@mui/icons-material/FilterAltOutlined";
import CheckIcon from "@mui/icons-material/Check";

import { useEffect, useMemo, useState } from "react";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import SearchIcon from "@mui/icons-material/Search";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import TimelineIcon from "@mui/icons-material/Timeline";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import ManageSearchOutlinedIcon from "@mui/icons-material/ManageSearchOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import LanguageOutlinedIcon from "@mui/icons-material/LanguageOutlined";
import PhotoLibraryOutlinedIcon from "@mui/icons-material/PhotoLibraryOutlined";
import DeviceHubOutlinedIcon from "@mui/icons-material/DeviceHubOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
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
  IEWebCache: "BROWSER",
  IEIndexDat: "BROWSER",
  WmiRepository: "WMI",
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

/// 승격 분석 항목(WER·WMI·USN)의 결과 없음 표시 — 개요 테이블의 "0건에도
/// 스키마 발행" 통일 정책(2026-08-31)과 같은 취지로, 결과가 없어도 항목이
/// 사라지지 않고 "해당 활동 없음"이 확인 가능한 정보로 남는다 (2026-09-01
/// 사용자 확정).
function EmptyPinnedRow({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div
      title="이번 파싱에서 이 항목의 결과가 없습니다"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 12px",
        fontSize: 14,
        fontWeight: 600,
        color: "var(--text-faint)",
        opacity: 0.5,
        userSelect: "none",
        cursor: "default",
        borderLeft: "3px solid transparent",
      }}
    >
      {icon}
      <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{label}</span>
      <span style={{ fontSize: 10.5, fontWeight: 500 }}>데이터 없음</span>
    </div>
  );
}

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
  "BitsHistory",
  "FirewallHistory",
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
  BitsHistory: "BITS 전송 이력",
  FirewallHistory: "방화벽 이력",
  PowerShellHistory: "파워셸 실행 이력",
  RdpCache: "RDP Cache",
  ScheduledTasks: "작업 스케줄러",
  MFT_Records: "파일 시스템 정보",
};

// 호스트 분석 소그룹 — 분석 관점별 묶음 (2026-08-31 사용자 확정, RDP Cache는
// 네트워크 그룹 맨 아래). "@USN"/"@WER"/"@WMI"는 승격된 개별 항목이고
// 나머지는 _OVERVIEW 테이블 이름. 목록에 없는 테이블은 그룹 뒤에 그대로
// 나열되는 안전망을 둔다 (새 테이블이 추가돼도 사라지지 않게).
const ANALYSIS_GROUPS: { title: string; items: string[] }[] = [
  { title: "파일 시스템", items: ["MFT_Records", "@USN"] },
  { title: "실행 흔적", items: ["ExecutionHistory", "PowerShellHistory", "ScheduledTasks", "@WMI"] },
  { title: "네트워크 · 원격", items: ["RemoteDesktopHistory", "SmbHistory", "BitsHistory", "FirewallHistory", "BrowserActivity", "RdpCache"] },
  { title: "시스템 · 보안", items: ["RegistryFindings", "Defender", "@WER"] },
];

function OverviewTableIcon({ name }: { name: string }) {
  const props = { sx: { fontSize: 18, color: "var(--text-faint)", flexShrink: 0 } };
  switch (name) {
    case "TargetInfo": return <InfoOutlinedIcon {...props} />;
    // This icon identifies a file-system evidence view, rather than decorating
    // the navigation label.
    case "MFT_Records": return <FolderOpenOutlinedIcon {...props} />;
    case "RemoteDesktopHistory": return <DesktopWindowsOutlinedIcon {...props} />;
    case "ExecutionHistory": return <BoltOutlinedIcon {...props} />;
    // Defender 뷰 헤더와 동일한 방패 아이콘.
    case "Defender": return <ShieldOutlinedIcon {...props} />;
    case "RegistryFindings": return <ManageSearchOutlinedIcon {...props} />;
    case "PowerShellHistory": return <TerminalOutlinedIcon {...props} />;
    case "SmbHistory": return <DnsOutlinedIcon {...props} />;
    case "BitsHistory": return <CloudDownloadOutlinedIcon {...props} />;
    case "FirewallHistory": return <SecurityOutlinedIcon {...props} />;
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
  // 0건 항목도 목록에 남되(0건 스키마 정책) 흐림 + "데이터 없음"으로 상태를
  // 보여준다 — 열람(빈 화면 확인)은 그대로 가능하다 (2026-09-01 사용자 확정).
  const empty = entry.rowCount === 0;
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
      <span style={{ display: "flex", alignItems: "center", gap: 7, overflow: "hidden", textOverflow: "ellipsis", color: selected ? "var(--text)" : empty ? "var(--text-faint)" : "var(--text-dim)", opacity: empty && !selected ? 0.55 : 1, fontSize: prominent ? 14 : 13.5, fontWeight: selected ? 700 : prominent ? 600 : 400 }}>
        {leading}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
      </span>
      {empty && <span style={{ flexShrink: 0, color: "var(--text-faint)", opacity: selected ? 1 : 0.7, fontSize: 10.5, fontWeight: 500 }}>데이터 없음</span>}
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
  /** 이 파일 이름은 목록에서 숨긴다(고정 항목으로 승격된 경우). */
  hideFileName?: string;
  /** 이미 조회된 파일 목록 — 있으면 다시 조회하지 않는다(비싼 COUNT 절약). */
  preloadedFiles?: ResultFileEntry[];
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned, hideHeader, hideFileName, preloadedFiles, onNavigate }: CategoryNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [files, setFiles] = useState<ResultFileEntry[] | null>(null);

  useEffect(() => {
    if (preloadedFiles) {
      setFiles(preloadedFiles);
      return;
    }
    window.api.listResultFiles(category.fullPath).then(setFiles);
  }, [category.fullPath, preloadedFiles]);

  // Group the per-table entries back by their source file, so one .sqlite is
  // one node (expandable when it holds several tables).
  const byFile = useMemo(() => {
    if (!files) return null;
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of files) {
      if (hideFileName && file.name === hideFileName) continue;
      // 뷰 백데이터 테이블(파일 시스템 교차 참조, AI 대화 파생 등)은 독립
      // 화면이 없다 — 내비게이션에 노출하지 않는다.
      if (file.fileName === "PathReferences" || file.fileName === "AiConversations") continue;
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
  categories: CategoryEntry[];
  selectedFile: ResultFileEntry | null;
  onSelectFile: (file: ResultFileEntry) => void;
  activeVirtualTab: "timeline" | "bookmarks" | "connections" | "search" | null;
  /** 호스트 오픈 시 한 번 조회한 _OVERVIEW 파일 목록(비싼 COUNT 포함) 공유. */
  overviewFiles?: ResultFileEntry[] | null;
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
  categories,
  selectedFile,
  onSelectFile,
  activeVirtualTab,
  overviewFiles,
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
  // 호스트 정보(TargetInfo)는 호스트 분석 최상단 고정 항목으로 승격 —
  // 종합 분석 목록에서는 숨겨 중복 표시를 피한다.
  const [fetchedOverviewFiles, setFetchedOverviewFiles] = useState<ResultFileEntry[] | null>(null);
  useEffect(() => {
    if (overviewFiles || !overviewCategory) {
      setFetchedOverviewFiles(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(overviewCategory.fullPath).then((files) => {
      if (!cancelled) setFetchedOverviewFiles(files);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [overviewFiles, overviewCategory?.fullPath]);
  const effectiveOverviewFiles = overviewFiles ?? fetchedOverviewFiles;
  const targetInfoEntry = effectiveOverviewFiles?.find((file) => file.name === "TargetInfo") ?? null;
  // 소그룹 렌더용 — 종합 분석 테이블을 파일 단위로 묶는다 (CategoryNode와
  // 같은 규칙: TargetInfo는 승격돼 제외, PathReferences·AiConversations는
  // 독립 화면이 없는 백데이터라 제외).
  const overviewByFile = useMemo(() => {
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of effectiveOverviewFiles ?? []) {
      // WerReports는 "@WER"(오류 보고) 승격 항목이 열므로 일반 목록에서 제외.
      if (file.name === "TargetInfo" || file.fileName === "PathReferences" || file.fileName === "AiConversations" || file.fileName === "WerReports") continue;
      if (!map.has(file.fileName)) map.set(file.fileName, []);
      map.get(file.fileName)!.push(file);
    }
    return map;
  }, [effectiveOverviewFiles]);
  const groupedNames = useMemo(() => new Set(ANALYSIS_GROUPS.flatMap((group) => group.items)), []);
  const leftoverOverview = [...overviewByFile.keys()].filter((name) => !groupedNames.has(name)).sort((a, b) => a.localeCompare(b));
  // 소그룹 접힘 상태 — 시작 시 전부 접힘 (2026-08-31 사용자 확정).
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(
    () => new Set(ANALYSIS_GROUPS.map((group) => group.title)),
  );
  // WER(오류 보고)은 전용 뷰가 있는 분석 항목이라 호스트 분석 목록으로 승격 —
  // 원본 데이터 목록에서는 빼서 중복 표시를 피한다.
  const werCategory = categories.find((c) => c.name === "WER");
  const [werEntry, setWerEntry] = useState<ResultFileEntry | null>(null);
  useEffect(() => {
    if (!werCategory) {
      setWerEntry(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(werCategory.fullPath).then((files) => {
      if (!cancelled) setWerEntry(files.find((file) => file.name === "WER_Reports") ?? files[0] ?? null);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [werCategory?.fullPath]);
  // 재파싱본은 통합 파생(_OVERVIEW/WerReports: Report.wer + EventLog 오류
  // 보고 1001)을 우선해 연다. 파생이 없는 구 파싱본은 WER 카테고리 산출물로
  // 열어 기존 동작을 유지한다.
  const werOverviewEntry = effectiveOverviewFiles?.find((file) => file.fileName === "WerReports") ?? null;
  const effectiveWerEntry =
    (werOverviewEntry && werOverviewEntry.rowCount > 0 ? werOverviewEntry : null) ??
    (werEntry && werEntry.rowCount > 0 ? werEntry : null);
  // USN 저널(FILESYSTEM/UsnJrnl_Records)도 전용 뷰가 있는 분석 항목이라
  // 호스트 분석 목록으로 승격한다.
  const fsCategory = categories.find((c) => c.name === "FILESYSTEM");
  const [usnEntry, setUsnEntry] = useState<ResultFileEntry | null>(null);
  useEffect(() => {
    if (!fsCategory) {
      setUsnEntry(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(fsCategory.fullPath).then((files) => {
      if (!cancelled) setUsnEntry(files.find((file) => file.name === "UsnJrnl_Records") ?? files[0] ?? null);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fsCategory?.fullPath]);
  // WMI 이벤트 구독도 전용 뷰가 있는 분석 항목이라 같은 방식으로 승격한다.
  const wmiCategory = categories.find((c) => c.name === "WMI");
  const [wmiEntry, setWmiEntry] = useState<ResultFileEntry | null>(null);
  useEffect(() => {
    if (!wmiCategory) {
      setWmiEntry(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(wmiCategory.fullPath).then((files) => {
      if (!cancelled) setWmiEntry(files.find((file) => file.name === "WMI_Persistence") ?? files[0] ?? null);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wmiCategory?.fullPath]);
  const rawCategories = categories.filter((c) => c.name !== "_OVERVIEW" && c.name !== "WER" && c.name !== "WMI" && c.name !== "FILESYSTEM");

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
    if (cat === "_OVERVIEW" || cat === "WER" || cat === "WMI" || cat === "FILESYSTEM" || seenNames.has(cat)) continue;
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
          <button className="nm-btn" onClick={onBackToHosts} title="호스트 목록" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--accent)", cursor: "pointer", fontWeight: 600, fontSize: 11, padding: "3px 10px", borderRadius: "var(--radius-md)" }}>
            호스트 등록
          </button>
        </div>
        {/* host selector — switch between machines in this case */}
        <HostPicker hosts={activeCase.hosts} activeHost={activeHost} onSelectHost={onSelectHost} />
        <div
          className="sidebar-time-range-head"
          style={{ marginTop: 10, padding: "8px 9px 9px", background: "var(--bg-elevated)", border: `1px solid ${hasTimeRange ? "color-mix(in srgb, var(--accent) 48%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)" }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6, minHeight: 22, marginBottom: 7 }}>
            <FilterAltOutlinedIcon sx={{ fontSize: 15, color: hasTimeRange ? "var(--accent)" : "var(--text-faint)" }} />
            <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, fontWeight: 700, letterSpacing: 0.4, color: hasTimeRange ? "var(--accent)" : "var(--text-dim)" }}>
              기간 필터
            </span>
            {hasTimeRange && (
              <button type="button" className="nm-btn" onClick={() => onTimeRangeChange(EMPTY_TIME_RANGE)} title="기간 초기화" aria-label="기간 초기화" style={{ padding: "2px 9px", fontSize: 10.5, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--accent)", cursor: "pointer", fontWeight: 650 }}>
                초기화
              </button>
            )}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "30px minmax(0, 1fr)", alignItems: "center", rowGap: 5, columnGap: 6 }}>
            <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--text-faint)" }}>시작</span>
            <DateTimeInput
              value={timeRange.start}
              onChange={(v) => onTimeRangeChange({ ...timeRange, start: v })}
              style={timeInputStyle}
              ariaLabel="시작 시각"
              placeholder="YYYY-MM-DD HH:mm:ss"
            />
            <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--text-faint)" }}>종료</span>
            <DateTimeInput
              value={timeRange.end}
              onChange={(v) => onTimeRangeChange({ ...timeRange, end: v })}
              style={timeInputStyle}
              ariaLabel="종료 시각"
              placeholder="YYYY-MM-DD HH:mm:ss"
            />
          </div>
          {hasTimeRange && (
            <div aria-live="polite" style={{ marginTop: 7, fontSize: 10.5, fontWeight: 600, color: "var(--accent)" }}>모든 보기에 적용 중</div>
          )}
        </div>
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
            {targetInfoEntry && (
              <PinnedNavRow
                icon={<InfoOutlinedIcon sx={{ fontSize: 19 }} />}
                label="호스트 정보"
                selected={sameEntry(selectedFile, targetInfoEntry)}
                onClick={() => onSelectFile(targetInfoEntry)}
              />
            )}
            <PinnedNavRow
              icon={<TimelineIcon sx={{ fontSize: 19 }} />}
              label="통합 타임라인"
              selected={activeVirtualTab === "timeline"}
              onClick={onSelectTimeline}
            />
            {ANALYSIS_GROUPS.map((group) => {
              const rows: React.ReactNode[] = [];
              for (const item of group.items) {
                // 결과가 없어도 항목은 남긴다(회색 "데이터 없음") — 개요
                // 테이블 0건 스키마 정책과 표시 일관성 (2026-09-01 확정).
                if (item === "@USN") {
                  if (usnEntry) rows.push(<PinnedNavRow key="usn" icon={<HistoryOutlinedIcon sx={{ fontSize: 19 }} />} label="USN 저널" selected={sameEntry(selectedFile, usnEntry)} onClick={() => onSelectFile(usnEntry)} />);
                  else rows.push(<EmptyPinnedRow key="usn" icon={<HistoryOutlinedIcon sx={{ fontSize: 19 }} />} label="USN 저널" />);
                  continue;
                }
                if (item === "@WER") {
                  const entry = effectiveWerEntry;
                  if (entry) rows.push(<PinnedNavRow key="wer" icon={<ReportProblemOutlinedIcon sx={{ fontSize: 19 }} />} label="오류 보고 (WER)" selected={sameEntry(selectedFile, entry)} onClick={() => onSelectFile(entry)} />);
                  else rows.push(<EmptyPinnedRow key="wer" icon={<ReportProblemOutlinedIcon sx={{ fontSize: 19 }} />} label="오류 보고 (WER)" />);
                  continue;
                }
                if (item === "@WMI") {
                  if (wmiEntry) rows.push(<PinnedNavRow key="wmi" icon={<DeviceHubOutlinedIcon sx={{ fontSize: 19 }} />} label="WMI 이벤트 구독" selected={sameEntry(selectedFile, wmiEntry)} onClick={() => onSelectFile(wmiEntry)} />);
                  else rows.push(<EmptyPinnedRow key="wmi" icon={<DeviceHubOutlinedIcon sx={{ fontSize: 19 }} />} label="WMI 이벤트 구독" />);
                  continue;
                }
                const tables = overviewByFile.get(item);
                if (tables?.length) {
                  rows.push(<FileNode key={item} fileName={item} label={OVERVIEW_TABLE_NAMES[item] ?? item} tables={tables} selectedFile={selectedFile} indent={12} leading={<OverviewTableIcon name={item} />} prominent onSelectFile={onSelectFile} />);
                }
              }
              if (rows.length === 0) return null;
              const open = !collapsedGroups.has(group.title);
              return (
                <div key={group.title}>
                  <button
                    type="button"
                    onClick={() => setCollapsedGroups((previous) => { const next = new Set(previous); if (next.has(group.title)) next.delete(group.title); else next.add(group.title); return next; })}
                    aria-expanded={open}
                    style={{ width: "100%", minHeight: 40, display: "flex", alignItems: "center", gap: 8, padding: "10px 12px 10px 9px", border: "none", borderLeft: "3px solid transparent", borderRadius: 0, background: "transparent", color: open ? "var(--text)" : "var(--text-dim)", cursor: "pointer", fontSize: 13.5, fontWeight: 650, letterSpacing: 0.2, textAlign: "left" }}
                    onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                    onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
                  >
                    {open ? <KeyboardArrowDownIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} /> : <KeyboardArrowRightIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />}
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{group.title}</span>
                    <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{rows.length}</span>
                  </button>
                  {open && (
                    <div style={{ margin: "0 0 6px 17px", paddingLeft: 3, borderLeft: "1px solid var(--border)" }}>{rows}</div>
                  )}
                </div>
              );
            })}
            {leftoverOverview.map((name) => {
              const tables = overviewByFile.get(name);
              return tables?.length ? (
                <FileNode key={name} fileName={name} label={OVERVIEW_TABLE_NAMES[name] ?? name} tables={tables} selectedFile={selectedFile} indent={12} leading={<OverviewTableIcon name={name} />} prominent onSelectFile={onSelectFile} />
              ) : null;
            })}
            <div style={{ height: 4 }} />
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

/// 케이스 내 호스트 전환 드롭다운 — OS 기본 select 대신 앱 스타일 패널.
function HostPicker({ hosts, activeHost, onSelectHost }: { hosts: Host[]; activeHost: Host; onSelectHost: (host: Host) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <button
        type="button"
        className="nm-btn"
        aria-expanded={open}
        aria-label="호스트 전환"
        onClick={() => setOpen((value) => !value)}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, minHeight: 34, padding: "6px 10px", background: "var(--bg-input)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer", fontWeight: 600, fontSize: 13, textAlign: "left" }}
      >
        <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: activeHost.lastRunStatus === "ok" ? "var(--success)" : activeHost.lastRunStatus ? "var(--warning)" : "var(--text-faint)" }} />
        <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{activeHost.name}</span>
        <KeyboardArrowDownIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0, transform: open ? "rotate(180deg)" : "none", transition: "transform .12s ease" }} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 60 }} />
          <div role="listbox" aria-label="호스트 목록" style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, zIndex: 61, maxHeight: 340, overflowY: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: 5 }}>
            {hosts.map((host) => {
              const current = host.id === activeHost.id;
              return (
                <button
                  key={host.id}
                  type="button"
                  role="option"
                  aria-selected={current}
                  onClick={() => { setOpen(false); if (!current) onSelectHost(host); }}
                  style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, minHeight: 34, padding: "5px 9px", background: current ? "var(--accent-subtle)" : "transparent", border: "none", borderRadius: "var(--radius-sm)", color: current ? "var(--accent)" : "var(--text)", cursor: "pointer", fontSize: 12.5, fontWeight: current ? 700 : 550, textAlign: "left" }}
                  onMouseEnter={(event) => { if (!current) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { if (!current) event.currentTarget.style.background = "transparent"; }}
                >
                  <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", flexShrink: 0, background: host.lastRunStatus === "ok" ? "var(--success)" : host.lastRunStatus ? "var(--warning)" : "var(--text-faint)" }} />
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{host.name}</span>
                  {current && <CheckIcon sx={{ fontSize: 15, flexShrink: 0 }} />}
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

