"use client";

import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import ClearOutlinedIcon from "@mui/icons-material/ClearOutlined";
import FilterListOutlinedIcon from "@mui/icons-material/FilterListOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import Checkbox from "@mui/material/Checkbox";
import IconButton from "@mui/material/IconButton";
import Popover from "@mui/material/Popover";
import Tooltip from "@mui/material/Tooltip";
import RowDetailPanel from "./RowDetailPanel";
import { tagsForPath, type Tag } from "@/lib/tagging";
import { inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { CsvData, FetchLinkedRows } from "@/lib/types";

interface ExecutionHistoryViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange: TimeRange;
}

type Row = Record<string, string>;
type SortKey = "risk" | "recent" | "oldest";

const EXECUTABLE_RE = /\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi)$/i;
const ROW_HEIGHT = 62;
const SORT_LABEL: Record<SortKey, string> = { risk: "주의 항목 우선", recent: "최근순", oldest: "오래된순" };
const SOURCE_LABELS: Record<string, string> = {
  Amcache: "Amcache", Prefetch: "Prefetch", UserAssist: "UserAssist", SRUM: "SRUM", BAM: "BAM", AppCompatCache: "ShimCache",
};

interface Entry {
  rowid: number;
  name: string;
  path: string;
  publisher: string;
  runCount: string;
  timestamp: string;
  source: string;
  user: string;
  tags: Tag[];
  unsigned: boolean;
  risk: number;
  winPath: boolean;
  row: Row;
}

function sourceLabel(source: string): string { return (SOURCE_LABELS[source] ?? source) || "출처 없음"; }
function basename(path: string): string {
  const clean = (path || "").replace(/[\\/]+$/, "");
  return clean.split(/[\\/]/).at(-1) || path;
}
function isWindowsSystemPath(path: string): boolean {
  const value = (path || "").toLowerCase();
  return /^[a-z]:\\windows(\\|$)/.test(value)
    || value.startsWith("\\windows\\") || value.startsWith("%systemroot%") || value.startsWith("\\systemroot\\")
    || /\\device\\harddiskvolume\d+\\windows\\/.test(value)
    || /(^|\\)windows\\(system32|syswow64|winsxs)\\/.test(value);
}
function buildEntry(row: Row): Entry {
  const path = row.program_path || "";
  const name = row.program_name || basename(path) || "(이름 없음)";
  const publisher = (row.publisher || "").trim();
  const source = /^Amcache/.test(row.source_artifact || "") ? "Amcache" : row.source_artifact || "";
  const executable = EXECUTABLE_RE.test(name) || EXECUTABLE_RE.test(path);
  // Publisher metadata is an Amcache field. Other execution artifacts do not
  // collect it, so absence there is not a signature warning.
  const unsigned = source === "Amcache" && executable && !publisher;
  const tags = tagsForPath(path);
  const risk = Math.max(unsigned ? 1 : 0, ...tags.map((tag) => tag.severity === "danger" ? 2 : 1));
  return {
    rowid: Number((row as Record<string, unknown>).__rowid), name, path, publisher, runCount: row.run_count || "", timestamp: row.timestamp || "",
    source, user: row.user || "", tags, unsigned, risk,
    winPath: isWindowsSystemPath(path), row,
  };
}

function FilterButton({ active, children, onClick }: { active: boolean; children: React.ReactNode; onClick: () => void }) {
  return <button type="button" onClick={onClick} style={{ minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius-sm)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--accent-subtle)" : "var(--bg-input)", color: active ? "var(--text)" : "var(--text-dim)", fontSize: 12, fontWeight: active ? 650 : 500, cursor: "pointer", whiteSpace: "nowrap" }}>{children}</button>;
}

const artifactTagStyle: React.CSSProperties = { flexShrink: 0, padding: "2px 6px", borderRadius: "var(--radius-sm)", color: "#fff", fontSize: 10.5, fontWeight: 700, lineHeight: 1.3 };
const warningLabelStyle: React.CSSProperties = { flexShrink: 0, padding: "2px 6px", borderRadius: "var(--radius-sm)", color: "var(--warning)", background: "var(--warning-subtle)", border: "1px solid color-mix(in srgb, var(--warning) 42%, transparent)", fontSize: 10.5, fontWeight: 650, lineHeight: 1.3 };

function EvidenceLabel({ entry }: { entry: Entry }) {
  if (entry.unsigned) return <span style={warningLabelStyle}>게시자 정보 없음</span>;
  if (entry.publisher) return <span style={{ color: "var(--text-dim)" }}>{entry.publisher}</span>;
  if (entry.runCount) return <span style={{ color: "var(--text-dim)" }}>실행 {entry.runCount}회</span>;
  return <span style={{ color: "var(--text-faint)" }}>추가 실행 정보 없음</span>;
}

export default function ExecutionHistoryView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange }: ExecutionHistoryViewProps) {
  const [disabledSources, setDisabledSources] = useState<Set<string>>(new Set());
  const [onlyRisk, setOnlyRisk] = useState(false);
  const [onlyUnsigned, setOnlyUnsigned] = useState(false);
  const [excludeWindows, setExcludeWindows] = useState(false);
  const [sort, setSort] = useState<SortKey>("oldest");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Entry | null>(null);
  const [sourceAnchor, setSourceAnchor] = useState<HTMLElement | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const all = useMemo(() => (data.rows as Row[]).map(buildEntry), [data.rows]);
  const sources = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of all) counts.set(entry.source, (counts.get(entry.source) ?? 0) + 1);
    return [...counts.entries()].sort(([left], [right]) => sourceLabel(left).localeCompare(sourceLabel(right)));
  }, [all]);
  const activeSourceCount = sources.filter(([source]) => !disabledSources.has(source)).length;
  const filtersActive = disabledSources.size > 0 || onlyRisk || onlyUnsigned || excludeWindows || Boolean(search.trim());
  const inGlobalRange = useMemo(() => all.filter((entry) => !rangeActive(timeRange) || inRange(entry.timestamp, timeRange)), [all, timeRange]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return inGlobalRange.filter((entry) => {
      if (disabledSources.has(entry.source) || (excludeWindows && entry.winPath) || (onlyRisk && entry.risk === 0) || (onlyUnsigned && !entry.unsigned)) return false;
      return !needle || [entry.name, entry.path, entry.publisher, entry.user, entry.source].some((value) => value.toLowerCase().includes(needle));
    }).sort((left, right) => {
      if (sort === "risk" && left.risk !== right.risk) return right.risk - left.risk;
      const compare = (left.timestamp || "").localeCompare(right.timestamp || "");
      return sort === "oldest" ? compare : -compare;
    });
  }, [disabledSources, excludeWindows, inGlobalRange, onlyRisk, onlyUnsigned, search, sort]);
  const virtualizer = useVirtualizer({ count: filtered.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_HEIGHT, overscan: 12 });
  const allSourcesSelected = sources.length > 0 && activeSourceCount === sources.length;
  const sourceSelectionPartial = activeSourceCount > 0 && !allSourcesSelected;
  const clearFilters = () => { setDisabledSources(new Set()); setOnlyRisk(false); setOnlyUnsigned(false); setExcludeWindows(false); setSearch(""); };

  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
    <div style={{ padding: "18px 20px 12px", display: "flex", alignItems: "center", gap: 12 }}>
      <h1 className="dfir-page-title" style={{ margin: 0, fontSize: 20 }}>실행 이력</h1>
      <span style={{ color: "var(--text-faint)", fontSize: 12 }}>실행 및 프로그램 존재 증거</span>
    </div>

    <div style={{ margin: "0 20px 12px", padding: 9, display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", boxShadow: "var(--shadow-card)" }}>
      <Tooltip title="출처 필터"><button type="button" onClick={(event) => setSourceAnchor(event.currentTarget)} aria-haspopup="dialog" aria-expanded={Boolean(sourceAnchor)} style={{ height: 30, display: "inline-flex", alignItems: "center", gap: 5, padding: "0 8px", border: `1px solid ${disabledSources.size > 0 ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", color: disabledSources.size > 0 ? "var(--text)" : "var(--text-dim)", background: disabledSources.size > 0 ? "var(--accent-subtle)" : "var(--bg-input)", cursor: "pointer" }}><FilterListOutlinedIcon sx={{ fontSize: 17 }} /><span style={{ fontSize: 12, fontWeight: 600 }}>출처</span></button></Tooltip>
      <FilterButton active={onlyRisk} onClick={() => setOnlyRisk((value) => !value)}>주의 항목</FilterButton>
      <FilterButton active={onlyUnsigned} onClick={() => setOnlyUnsigned((value) => !value)}>게시자 정보 없음</FilterButton>
      <FilterButton active={excludeWindows} onClick={() => setExcludeWindows((value) => !value)}>Windows 경로 제외</FilterButton>
      <span style={{ width: 1, height: 20, background: "var(--border)", margin: "0 2px" }} />
      <span style={{ color: "var(--text-faint)", fontSize: 11.5, padding: "0 1px" }}>정렬</span>
      {(Object.keys(SORT_LABEL) as SortKey[]).map((key) => <FilterButton key={key} active={sort === key} onClick={() => setSort(key)}>{SORT_LABEL[key]}</FilterButton>)}
      <div style={{ flex: 1, minWidth: 10 }} />
      {filtersActive && <Tooltip title="화면 내 필터 초기화"><IconButton aria-label="화면 내 필터 초기화" size="small" onClick={clearFilters} sx={{ color: "var(--text-dim)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)" }}><ClearOutlinedIcon sx={{ fontSize: 17 }} /></IconButton></Tooltip>}
      <div style={{ position: "relative", width: 245, maxWidth: "100%" }}><SearchOutlinedIcon sx={{ position: "absolute", top: 7, left: 8, color: "var(--text-faint)", fontSize: 17, pointerEvents: "none" }} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="이름 · 경로 · 계정 검색" aria-label="실행 이력 검색" style={{ width: "100%", height: 30, padding: "5px 9px 5px 31px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12.5 }} /></div>
    </div>

    <Popover open={Boolean(sourceAnchor)} anchorEl={sourceAnchor} onClose={() => setSourceAnchor(null)} anchorOrigin={{ vertical: "bottom", horizontal: "left" }} transformOrigin={{ vertical: "top", horizontal: "left" }} slotProps={{ paper: { sx: { mt: 0.75, width: 270, bgcolor: "var(--bg-panel)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)" } } }}>
      <div style={{ padding: "10px 10px 7px", display: "flex", alignItems: "center", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ fontSize: 12.5, fontWeight: 700 }}>실행 이력 출처</span><span style={{ marginLeft: "auto", color: "var(--text-faint)", fontSize: 11.5 }}>{activeSourceCount}개 선택</span></div>
      <label style={{ minHeight: 36, padding: "0 8px", display: "flex", alignItems: "center", gap: 6, cursor: "pointer", borderBottom: "1px solid var(--border-subtle)" }}><Checkbox size="small" checked={allSourcesSelected} indeterminate={sourceSelectionPartial} onChange={() => setDisabledSources(allSourcesSelected ? new Set(sources.map(([source]) => source)) : new Set())} sx={{ p: "3px", color: "var(--text-faint)", "&.Mui-checked, &.MuiCheckbox-indeterminate": { color: "var(--accent)" } }} /><span style={{ fontSize: 12, fontWeight: 650 }}>전체 선택</span></label>
      <div style={{ padding: "4px 0 6px" }}>{sources.map(([source]) => {
        const checked = !disabledSources.has(source);
        return <label key={source} style={{ minHeight: 34, padding: "0 8px 0 22px", display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}><Checkbox size="small" checked={checked} onChange={() => setDisabledSources((previous) => { const next = new Set(previous); if (next.has(source)) next.delete(source); else next.add(source); return next; })} sx={{ p: "3px", color: "var(--text-faint)", "&.Mui-checked": { color: "var(--accent)" } }} /><span style={{ fontSize: 12, color: checked ? "var(--text)" : "var(--text-faint)" }}>{sourceLabel(source)}</span></label>;
      })}</div>
    </Popover>

    <div style={{ minHeight: 0, flex: 1, margin: "0 20px", display: "flex", flexDirection: "column", overflow: "hidden", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", boxShadow: "var(--shadow-card)" }}>
      <div style={{ display: "grid", gridTemplateColumns: "174px minmax(185px, .85fr) minmax(290px, 1.5fr) 104px 120px minmax(155px, .7fr) 34px", gap: 12, alignItems: "center", minHeight: 34, padding: "0 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700, letterSpacing: ".02em" }}><span>시간</span><span>실행 항목</span><span>경로</span><span>출처</span><span>계정</span><span>증거</span><span aria-label="북마크" /></div>
      <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {filtered.length === 0 ? <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>{rangeActive(timeRange) && inGlobalRange.length === 0 ? "기간 필터 내 실행 이력 없음" : all.length === 0 ? "실행 이력 없음" : "검색·필터 조건에 일치하는 실행 이력 없음"}</div> : <div style={{ height: virtualizer.getTotalSize(), minWidth: 980, position: "relative" }}>{virtualizer.getVirtualItems().map((virtualRow) => {
          const entry = filtered[virtualRow.index];
          const bookmarked = bookmarkedRowids?.has(entry.rowid) ?? false;
          const selectedRow = selected?.rowid === entry.rowid && selected.source === entry.source;
          return <div key={virtualRow.key} style={{ position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)`, display: "grid", gridTemplateColumns: "minmax(0, 1fr) 34px", gap: 12, alignItems: "center", padding: "0 12px", borderBottom: "1px solid var(--border-subtle)", borderLeft: bookmarked ? "3px solid var(--warning)" : "3px solid transparent", background: selectedRow ? "var(--bg-selected)" : bookmarked ? "color-mix(in srgb, var(--warning) 12%, var(--bg-panel))" : "transparent", color: "var(--text)" }} onMouseEnter={(event) => { if (!selectedRow) event.currentTarget.style.background = bookmarked ? "color-mix(in srgb, var(--warning) 17%, var(--bg-panel))" : "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!selectedRow) event.currentTarget.style.background = bookmarked ? "color-mix(in srgb, var(--warning) 12%, var(--bg-panel))" : "transparent"; }}>
            <div role="button" tabIndex={0} aria-label={`${entry.name} 상세 보기`} onClick={() => setSelected(entry)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(entry); } }} style={{ minWidth: 0, height: "100%", display: "grid", gridTemplateColumns: "174px minmax(185px, .85fr) minmax(290px, 1.5fr) 104px 120px minmax(155px, .7fr)", gap: 12, alignItems: "center", cursor: "pointer", outlineOffset: -3 }}>
            <span style={{ color: "var(--text-time)", fontSize: 12.5, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>{entry.timestamp || "시간 정보 없음"}</span>
            <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}><span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13, fontWeight: 650 }}>{entry.name}</span>{entry.tags.map((tag) => <span key={tag.label} title={tag.description} style={{ ...artifactTagStyle, background: tag.severity === "danger" ? "var(--danger)" : "var(--warning)" }}>{tag.label}</span>)}</span>
            <span title={entry.path || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{entry.path || "경로 정보 없음"}</span>
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{sourceLabel(entry.source)}</span>
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: entry.user ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12 }}>{entry.user || "계정 정보 없음"}</span>
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5 }}><EvidenceLabel entry={entry} /></span>
            </div>
            <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}><span><IconButton aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark} size="small" onClick={() => onToggleBookmark?.(entry.rowid)} sx={{ color: bookmarked ? "var(--warning)" : "var(--text-faint)", borderRadius: "var(--radius-sm)" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}</IconButton></span></Tooltip>
          </div>;
        })}</div>}
      </div>
    </div>
    <div style={{ display: "flex", alignItems: "center", minHeight: 30, margin: "0 20px", color: "var(--text-faint)", fontSize: 11.5 }}>표시 {filtered.length.toLocaleString()}건 · {SORT_LABEL[sort]}</div>

    {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName="ExecutionHistory" onClose={() => setSelected(null)} onNavigate={(fileName, column, value) => { setSelected(null); onNavigate(fileName, column, value); }} onFetchLinkedRows={onFetchLinkedRows} isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
  </div>;
}
