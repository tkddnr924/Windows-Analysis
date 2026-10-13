"use client";
import { OVERVIEW_TABLE_NAMES } from "@/lib/overviewLabels";
import OverviewTableIcon from "@/components/OverviewTableIcon";
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
import HomeOutlinedIcon from "@mui/icons-material/HomeOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import type { Case, Host, CategoryEntry, ResultFileEntry } from "@/lib/types";
import { EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import { browsableResultFiles } from "@/lib/resultTables";
import DateTimeInput from "./DateTimeInput";

const timeInputStyle: React.CSSProperties = {
  width: "100%",
  padding: "5px 8px",
  background: "var(--bg-input)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
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
  // MFT is a 종합 분석 item (_OVERVIEW/FileSystemEntries → "파일 시스템 정보"),
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
  RECYCLEBIN: "휴지통",
};

/// 승격 분석 항목(WER·USN)의 결과 없음 표시 — 개요 테이블의 "0건에도
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
  "FileSystemEntries",
  "RecycleBin",
  "RemoteDesktopHistory",
  "ExecutionHistory",
  "Defender",
  "RegistryExplorer",
  "PowerShellHistory",
  "SmbHistory",
  "BitsHistory",
  "FirewallHistory",
  "ServiceHistory",
  "ScheduledTasks",
  "RdpCache",
];


// 호스트 분석 소그룹 — 분석 관점별 묶음 (2026-08-31 사용자 확정, RDP Cache는
// 네트워크 그룹 맨 아래). "@USN"/"@WER"는 승격된 개별 항목이고
// 나머지는 _OVERVIEW 테이블 이름. 목록에 없는 테이블은 그룹 뒤에 그대로
// 나열되는 안전망을 둔다 (새 테이블이 추가돼도 사라지지 않게).
const ANALYSIS_GROUPS: { title: string; items: string[] }[] = [
  { title: "파일 시스템", items: ["FileSystemEntries", "@USN", "RecycleBin"] },
  { title: "실행 흔적", items: ["ExecutionHistory", "PowerShellHistory", "ServiceHistory", "ScheduledTasks"] },
  { title: "네트워크 · 원격", items: ["RemoteDesktopHistory", "SmbHistory", "BitsHistory", "FirewallHistory", "BrowserActivity", "RdpCache"] },
  { title: "시스템 · 보안", items: ["RegistryExplorer", "Defender", "@WER"] },
];


function sameEntry(a: ResultFileEntry | null, b: ResultFileEntry): boolean {
  return !!a && a.fullPath === b.fullPath && a.tableName === b.tableName;
}

function FileRow({
  entry,
  label,
  selected,
  indent,
  leading,
  prominent = false,
  onSelectFile,
}: {
  entry: ResultFileEntry;
  label: string;
  selected: boolean;
  indent: number;
  leading?: React.ReactNode;
  /** Host-analysis navigation uses the same tab scale as Dashboard/Timeline. */
  prominent?: boolean;
  onSelectFile: (file: ResultFileEntry) => void;
}) {
  // 0건 항목도 목록에 남되(0건 스키마 정책) 흐림 + "데이터 없음"으로 상태를
  // 보여준다. 선택은 되지 않는다 — 같은 "데이터 없음" 표기인데 원본 파일이
  // 없는 항목(EmptyPinnedRow·EmptyCategoryRow)은 눌리지 않고 0건 테이블만
  // 눌리던 차이를 없앤다 (2026-09-03 사용자 확정 — 2026-09-01의 "열람은
  // 그대로 가능" 결정을 대체).
  const failed = entry.readError !== undefined;
  const empty = failed || entry.rowCount === 0;
  const active = selected && !empty;
  return (
    <div
      onClick={empty ? undefined : () => onSelectFile(entry)}
      title={failed ? entry.readError : empty ? "데이터 없음 — 추출된 레코드가 없습니다" : `${entry.relativePath} · ${entry.tableName}`}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 6,
        padding: `${prominent ? 10 : 7}px 10px ${prominent ? 10 : 7}px ${indent}px`,
        cursor: empty ? "default" : "pointer",
        userSelect: empty ? "none" : undefined,
        background: active
          ? "linear-gradient(135deg, rgba(74, 146, 218, 0.31), rgba(37, 78, 118, 0.38))"
          : "transparent",
        borderLeft: `3px solid ${active ? "var(--accent)" : "transparent"}`,
        boxShadow: active
          ? "inset 3px 3px 7px rgba(3, 8, 14, 0.45), inset -2px -2px 6px rgba(142, 188, 230, 0.12), 0 1px 0 rgba(142, 188, 230, 0.12)"
          : "none",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
      onMouseEnter={(e) => {
        if (!active && !empty) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = "transparent";
      }}
    >
      <span style={{ display: "flex", alignItems: "center", gap: 7, overflow: "hidden", textOverflow: "ellipsis", color: active ? "var(--text)" : empty ? "var(--text-faint)" : "var(--text-dim)", opacity: empty ? 0.55 : 1, fontSize: prominent ? 14 : 13.5, fontWeight: active ? 700 : prominent ? 600 : 400 }}>
        {leading}
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
      </span>
      {empty && <span style={{ flexShrink: 0, color: failed ? "var(--danger)" : "var(--text-faint)", opacity: 0.7, fontSize: 10.5, fontWeight: 500 }}>{failed ? "읽기 실패" : "데이터 없음"}</span>}
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
  /** 이 파일 이름은 목록에서 숨긴다(고정 항목으로 승격된 경우). */
  hideFileName?: string;
  /** 이미 조회된 파일 목록 — 있으면 다시 조회하지 않는다(비싼 COUNT 절약). */
  preloadedFiles?: ResultFileEntry[];
}

function SidebarErrorRow({ message, detail, onRetry, indent = 14 }: { message: string; detail: string; onRetry: () => void; indent?: number }) {
  return (
    <div role="alert" title={detail} style={{ display: "flex", alignItems: "center", gap: 8, padding: `6px 10px 8px ${indent}px`, color: "var(--danger)", fontSize: 12 }}>
      <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{message}</span>
      <button type="button" onClick={onRetry} style={{ marginLeft: "auto", flexShrink: 0, fontSize: 11.5, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 650 }}>다시 시도</button>
    </div>
  );
}

function CategoryNode({ category, selectedFile, onSelectFile, displayName, pinned, hideHeader, hideFileName, preloadedFiles }: CategoryNodeProps) {
  const [expanded, setExpanded] = useState(false);
  const [files, setFiles] = useState<ResultFileEntry[] | null>(null);
  const [filesError, setFilesError] = useState<string | null>(null);
  const [filesNonce, setFilesNonce] = useState(0);

  useEffect(() => {
    // 상세 전용 자식 표(source_records·ExecutionTimes…)는 열람 대상이 아니다.
    setFilesError(null);
    if (preloadedFiles) {
      setFiles(browsableResultFiles(preloadedFiles));
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(category.fullPath)
      .then((list) => {
        if (!cancelled) setFiles(browsableResultFiles(list));
      })
      .catch((error) => {
        if (!cancelled) setFilesError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
  }, [category.fullPath, preloadedFiles, filesNonce]);

  // Group the per-table entries back by their source file, so one .sqlite is
  // one node (expandable when it holds several tables).
  const byFile = useMemo(() => {
    if (!files) return null;
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of files) {
      if (hideFileName && file.name === hideFileName) continue;
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
      {isExpanded && filesError && (
        <SidebarErrorRow message="목록을 불러오지 못했습니다" detail={filesError} indent={28} onRetry={() => setFilesNonce((value) => value + 1)} />
      )}
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
}

function PinnedNavRow({ icon, label, count, selected, onClick }: PinnedNavRowProps) {
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 12px",
        cursor: "pointer",
        fontSize: 14,
        fontWeight: selected ? 700 : 600,
        background: selected
          ? "linear-gradient(135deg, rgba(74, 146, 218, 0.34), rgba(36, 75, 113, 0.42))"
          : "transparent",
        borderLeft: `3px solid ${selected ? "var(--accent)" : "transparent"}`,
        boxShadow: selected
          ? "inset 4px 4px 9px rgba(3, 8, 14, 0.50), inset -3px -3px 7px rgba(142, 188, 230, 0.13), 0 1px 0 rgba(142, 188, 230, 0.14)"
          : "none",
        color: selected ? "var(--text)" : "var(--text-dim)",
      }}
      onMouseEnter={(e) => {
        if (!selected) e.currentTarget.style.background = "var(--bg-hover)";
      }}
      onMouseLeave={(e) => {
        if (!selected) e.currentTarget.style.background = "transparent";
      }}
    >
      <span style={{ display: "flex", color: selected ? "var(--accent)" : "var(--text-faint)" }}>{icon}</span>
      <span>{label}</span>
      {count !== undefined && <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 11.5 }}>{count}</span>}
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
}: SidebarProps) {
  const [rawDataExpanded, setRawDataExpanded] = useState(false);
  const hasTimeRange = rangeActive(timeRange);
  const overviewCategory = categories.find((c) => c.name === "_OVERVIEW");
  // 호스트 정보(TargetInfo)는 호스트 분석 최상단 고정 항목으로 승격 —
  // 종합 분석 목록에서는 숨겨 중복 표시를 피한다.
  const [fetchedOverviewFiles, setFetchedOverviewFiles] = useState<ResultFileEntry[] | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [overviewNonce, setOverviewNonce] = useState(0);
  useEffect(() => {
    setOverviewError(null);
    if (overviewFiles || !overviewCategory) {
      setFetchedOverviewFiles(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(overviewCategory.fullPath)
      .then((files) => {
        if (!cancelled) setFetchedOverviewFiles(files);
      })
      .catch((error) => {
        if (!cancelled) setOverviewError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [overviewFiles, overviewCategory?.fullPath, overviewNonce]);
  const effectiveOverviewFiles = overviewFiles ?? fetchedOverviewFiles;
  const targetInfoEntry = effectiveOverviewFiles?.find((file) => file.name === "TargetInfo") ?? null;
  // 분석 메뉴는 ANALYSIS_GROUPS에 정한 뷰만 보여 준다(사용자 확정). _OVERVIEW에
  // 있는 다른 DB(백데이터·원본 facts·화면 없는 파생)는 자동으로 노출하지 않는다.
  const overviewByFile = useMemo(() => {
    const map = new Map<string, ResultFileEntry[]>();
    for (const file of browsableResultFiles(effectiveOverviewFiles ?? [])) {
      if (!map.has(file.fileName)) map.set(file.fileName, []);
      map.get(file.fileName)!.push(file);
    }
    return map;
  }, [effectiveOverviewFiles]);
  // 소그룹 접힘 상태 — 시작 시 전부 접힘 (2026-08-31 사용자 확정).
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(
    () => new Set(ANALYSIS_GROUPS.map((group) => group.title)),
  );
  // WER(오류 보고)은 전용 뷰가 있는 분석 항목(@WER)이고, WER 원본 산출물은
  // 다른 아티팩트처럼 원본 데이터 목록에도 남는다.
  const werCategory = categories.find((c) => c.name === "WER");
  const [werEntry, setWerEntry] = useState<ResultFileEntry | null>(null);
  const [werError, setWerError] = useState<string | null>(null);
  const [werNonce, setWerNonce] = useState(0);
  useEffect(() => {
    setWerError(null);
    if (!werCategory) {
      setWerEntry(null);
      return;
    }
    let cancelled = false;
    window.api.listResultFiles(werCategory.fullPath)
      .then((files) => {
        if (!cancelled) setWerEntry(files.find((file) => file.name === "WER_Reports") ?? files[0] ?? null);
      })
      .catch((error) => {
        if (!cancelled) setWerError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [werCategory?.fullPath, werNonce]);
  // 재파싱본은 통합 파생(_OVERVIEW/WerReports: Report.wer + EventLog 오류
  // 보고 1001)을 우선해 연다. 파생이 없는 구 파싱본은 WER 카테고리 산출물로
  // 열어 기존 동작을 유지한다.
  const werOverviewEntry = effectiveOverviewFiles?.find((file) => file.fileName === "WerReports") ?? null;
  const effectiveWerEntry =
    (werOverviewEntry && werOverviewEntry.rowCount > 0 ? werOverviewEntry : null) ??
    (werEntry && werEntry.rowCount > 0 ? werEntry : null);
  // USN 저널은 화면용 파생(_OVERVIEW/UsnJournal)을 연다 — 원본 facts
  // (FILESYSTEM/UsnJrnl_Records)는 원본 데이터 목록에 그대로 남는다.
  const usnEntry = effectiveOverviewFiles?.find((file) => file.fileName === "UsnJournal") ?? null;
  // WMI 전용 뷰 삭제(2026-10-07 사용자 확정) 이후 _OVERVIEW/WmiSubscriptions를
  // 여는 승격 항목은 없다. 원본 데이터 목록은 파싱한 아티팩트 산출물을 모두
  // 보여 준다(_OVERVIEW 파생은 위 분석 메뉴의 정해진 뷰로만 연다).
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
  // Raw parser facts written under _OVERVIEW (e.g. $MFT → MFT_Records) are raw
  // data too; the derived flag comes from the DB itself, not a name list.
  const overviewRawByFile = new Map<string, ResultFileEntry[]>();
  for (const file of effectiveOverviewFiles ?? []) {
    if (file.derived !== false) continue;
    if (!overviewRawByFile.has(file.fileName)) overviewRawByFile.set(file.fileName, []);
    overviewRawByFile.get(file.fileName)!.push(file);
  }
  const hasRawSection = orderedNames.length > 0 || leftoverCategories.length > 0 || overviewRawByFile.size > 0;

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
          <button type="button" className="nm-btn" onClick={onBackToHosts} title="홈" style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--accent)", cursor: "pointer", fontWeight: 600, fontSize: 11, padding: "3px 10px", borderRadius: "var(--radius)" }}>
            <HomeOutlinedIcon sx={{ fontSize: 16 }} />
            홈
          </button>
        </div>
        {/* host selector — switch between machines in this case */}
        <HostPicker hosts={activeCase.hosts} activeHost={activeHost} onSelectHost={onSelectHost} />
        <div
          className="sidebar-time-range-head"
          style={{ marginTop: 10, padding: "8px 9px 9px", background: "var(--bg-elevated)", border: `1px solid ${hasTimeRange ? "color-mix(in srgb, var(--accent) 48%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)" }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6, minHeight: 22, marginBottom: 7 }}>
            <FilterAltOutlinedIcon sx={{ fontSize: 15, color: hasTimeRange ? "var(--accent)" : "var(--text-faint)" }} />
            <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, fontWeight: 700, letterSpacing: 0.4, color: hasTimeRange ? "var(--accent)" : "var(--text-dim)" }}>
              기간 필터
            </span>
            {hasTimeRange && (
              <button type="button" className="nm-btn" onClick={() => onTimeRangeChange(EMPTY_TIME_RANGE)} title="기간 초기화" aria-label="기간 초기화" style={{ padding: "2px 9px", fontSize: 10.5, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--accent)", cursor: "pointer", fontWeight: 650 }}>
                초기화
              </button>
            )}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "30px minmax(0, 1fr)", alignItems: "center", rowGap: 5, columnGap: 6 }}>
            <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--text-faint)" }}>시작</span>
            <DateTimeInput
              value={timeRange.start}
              onChange={(v) => onTimeRangeChange({ ...timeRange, start: v })}
              edge="start"
              style={timeInputStyle}
              ariaLabel="시작 시각"
              placeholder="YYYY-MM-DD HH:mm:ss"
            />
            <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--text-faint)" }}>종료</span>
            <DateTimeInput
              value={timeRange.end}
              onChange={(v) => onTimeRangeChange({ ...timeRange, end: v })}
              edge="end"
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
            {overviewError && (
              <SidebarErrorRow message="분석 목록을 불러오지 못했습니다" detail={overviewError} onRetry={() => setOverviewNonce((value) => value + 1)} />
            )}
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
                  if (entry) rows.push(<PinnedNavRow key="wer" icon={<ReportProblemOutlinedIcon sx={{ fontSize: 19 }} />} label="오류 보고" selected={sameEntry(selectedFile, entry)} onClick={() => onSelectFile(entry)} />);
                  else if (werError) rows.push(<SidebarErrorRow key="wer" message="오류 보고를 불러오지 못했습니다" detail={werError} onRetry={() => setWerNonce((value) => value + 1)} />);
                  else rows.push(<EmptyPinnedRow key="wer" icon={<ReportProblemOutlinedIcon sx={{ fontSize: 19 }} />} label="오류 보고" />);
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
                  </button>
                  {open && (
                    <div style={{ margin: "0 0 6px 17px", paddingLeft: 3, borderLeft: "1px solid var(--border)" }}>{rows}</div>
                  )}
                </div>
              );
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
            <CategoryNode key={category.fullPath} category={category} displayName={CATEGORY_LABELS[category.name]} selectedFile={selectedFile} onSelectFile={onSelectFile} />
          ) : (
            <EmptyCategoryRow key={name} name={name} label={CATEGORY_LABELS[name]} />
          );
        })}
        {rawDataExpanded && leftoverCategories.map((category) => (
          <CategoryNode key={category.fullPath} category={category} selectedFile={selectedFile} onSelectFile={onSelectFile} />
        ))}
        {rawDataExpanded && [...overviewRawByFile.entries()].map(([name, tables]) => (
          <FileNode key={`raw-${name}`} fileName={name} label={OVERVIEW_TABLE_NAMES[name] ?? name} tables={tables} selectedFile={selectedFile} indent={12} leading={<OverviewTableIcon name={name} />} onSelectFile={onSelectFile} />
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
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, minHeight: 34, padding: "6px 10px", background: "var(--bg-input)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontWeight: 600, fontSize: 13, textAlign: "left" }}
      >
        <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: activeHost.lastRunStatus === "ok" ? "var(--success)" : activeHost.lastRunStatus ? "var(--warning)" : "var(--text-faint)" }} />
        <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{activeHost.name}</span>
        <KeyboardArrowDownIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0, transform: open ? "rotate(180deg)" : "none", transition: "transform .12s ease" }} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 60 }} />
          <div role="listbox" aria-label="호스트 목록" style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, zIndex: 61, maxHeight: 340, overflowY: "auto", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)", padding: 5 }}>
            {hosts.map((host) => {
              const current = host.id === activeHost.id;
              return (
                <button
                  key={host.id}
                  type="button"
                  role="option"
                  aria-selected={current}
                  onClick={() => { setOpen(false); if (!current) onSelectHost(host); }}
                  style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, minHeight: 34, padding: "5px 9px", background: current ? "var(--accent-subtle)" : "transparent", border: "none", borderRadius: "var(--radius)", color: current ? "var(--accent)" : "var(--text)", cursor: "pointer", fontSize: 12.5, fontWeight: current ? 700 : 550, textAlign: "left" }}
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

