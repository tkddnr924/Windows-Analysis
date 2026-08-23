"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import ArrowDownwardOutlinedIcon from "@mui/icons-material/ArrowDownwardOutlined";
import ArrowUpwardOutlinedIcon from "@mui/icons-material/ArrowUpwardOutlined";
import FolderSharedOutlinedIcon from "@mui/icons-material/FolderSharedOutlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import ManageSearchOutlinedIcon from "@mui/icons-material/ManageSearchOutlined";
import PlayCircleOutlineOutlinedIcon from "@mui/icons-material/PlayCircleOutlineOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import VpnKeyOutlinedIcon from "@mui/icons-material/VpnKeyOutlined";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import RowDetailPanel from "./RowDetailPanel";
import { tagsForPath } from "@/lib/tagging";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import type { CsvData } from "@/lib/types";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";

type Row = Record<string, string>;
type CategoryMeta = { icon: typeof KeyOutlinedIcon; label: string };
type TimeOrder = "asc" | "desc";

interface Props {
  data: CsvData;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

const ROW_HEIGHT = 58;
const ALL_ITEMS = "전체 항목";
const TAB_FIELD: Record<string, string> = { "자동 실행": "user", "기타 레지스트리": "subtype" };
const CATEGORY_ORDER = ["자격 증명 보호", "공유 폴더", "SQL 인증", "자동 실행", "기타 레지스트리"];
const CATEGORY_META: Record<string, CategoryMeta> = {
  [ALL_ITEMS]: { icon: ManageSearchOutlinedIcon, label: ALL_ITEMS },
  "자격 증명 보호": { icon: VpnKeyOutlinedIcon, label: "자격 증명 보호" },
  "공유 폴더": { icon: FolderSharedOutlinedIcon, label: "공유 폴더" },
  "SQL 인증": { icon: StorageOutlinedIcon, label: "SQL 인증" },
  "자동 실행": { icon: PlayCircleOutlineOutlinedIcon, label: "자동 실행" },
  "기타 레지스트리": { icon: ManageSearchOutlinedIcon, label: "실행 흔적" },
};
const LEGACY_RUN_MRU_TITLE = "Run 대화상자 입력 (RunMRU)";
const LEGACY_TYPED_PATHS_TITLE = "탐색기 주소 입력 (TypedPaths)";
const TYPED_PATH_LABEL = "TypedPath";
const SHIM_CACHE_LABEL = "ShimCache (AppcompatCache)";

function rowId(row: Row): number { return Number((row as Record<string, unknown>).__rowid); }
function categoryMeta(category: string): CategoryMeta { return CATEGORY_META[category] ?? { icon: KeyOutlinedIcon, label: category }; }
function looksLikePath(value: string): boolean { return /^[a-zA-Z]:\\|^\\\\/.test(value); }
function statusTone(status: string) {
  if (status === "의심") return { bg: "var(--danger)", fg: "#fff", border: "var(--danger)" };
  if (status === "주의") return { bg: "var(--warning)", fg: "#fff", border: "var(--warning)" };
  if (status === "정상") return { bg: "var(--success)", fg: "#fff", border: "var(--success)" };
  return { bg: "var(--tag-neutral-bg)", fg: "var(--tag-neutral-fg)", border: "var(--border)" };
}
function registryRow(row: Row): Row {
  // Missing publisher is not inferred here. This display-only attention state
  // applies only to autorun paths whose collected command matches a path tag.
  let normalized = row.name === LEGACY_RUN_MRU_TITLE ? { ...row, name: "RunMRU" } : row;
  // Preserve existing evidence databases while presenting the artifact names
  // consistently with newly parsed rows. The original path stays in `value`.
  if (normalized.subtype === "TypedPaths" || normalized.name === LEGACY_TYPED_PATHS_TITLE) {
    normalized = { ...normalized, name: TYPED_PATH_LABEL };
  }
  if (normalized.subtype === "ShimCache") {
    normalized = { ...normalized, name: SHIM_CACHE_LABEL };
  }
  return normalized.category === "자동 실행" && tagsForPath(normalized.command || normalized.value).length > 0
    ? { ...normalized, status: "의심" }
    : normalized;
}

function sortByRegistryTime(rows: Row[], order: TimeOrder): Row[] {
  const tieBreak = (a: { row: Row; index: number }, b: { row: Row; index: number }) =>
    (a.row.category ?? "").localeCompare(b.row.category ?? "", "ko") ||
    (a.row.name ?? "").localeCompare(b.row.name ?? "", "ko") ||
    (a.row.key_path ?? "").localeCompare(b.row.key_path ?? "", "ko") ||
    a.index - b.index;
  return rows
    .map((row, index) => ({ row, index, timestamp: row.timestamp?.trim() ?? "" }))
    .sort((a, b) => {
      // Untimed configuration must remain available, but never masquerades as
      // the earliest/latest evidence record.
      if (!a.timestamp || !b.timestamp) {
        if (!a.timestamp && !b.timestamp) return tieBreak(a, b);
        return a.timestamp ? -1 : 1;
      }
      const comparison = a.timestamp.localeCompare(b.timestamp);
      return (order === "asc" ? comparison : -comparison) || tieBreak(a, b);
    })
    .map(({ row }) => row);
}

export default function RegistryFindingsView({ data, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [selectedCategory, setSelectedCategory] = useState(ALL_ITEMS);
  const [selectedTab, setSelectedTab] = useState("전체");
  const [search, setSearch] = useState("");
  const [timeOrder, setTimeOrder] = useState<TimeOrder>("desc");
  const [detail, setDetail] = useState<Row | null>(null);
  const rangeOn = rangeActive(timeRange);
  const allRows = useMemo(() => (data.rows as Row[]).map(registryRow), [data.rows]);
  const groups = useMemo(() => {
    const byCategory = new Map<string, Row[]>();
    for (const row of allRows) {
      const category = row.category || "기타";
      byCategory.set(category, [...(byCategory.get(category) ?? []), row]);
    }
    const known = CATEGORY_ORDER.filter((category) => byCategory.has(category));
    const unknown = [...byCategory.keys()].filter((category) => !CATEGORY_ORDER.includes(category)).sort((a, b) => a.localeCompare(b));
    return [...known, ...unknown].map((category) => ({ category, rows: byCategory.get(category) ?? [] }));
  }, [allRows]);

  useEffect(() => {
    const selectedIsData = selectedCategory === ALL_ITEMS || groups.some((group) => group.category === selectedCategory);
    if (!selectedIsData) setSelectedCategory(ALL_ITEMS);
  }, [groups, selectedCategory]);
  useEffect(() => setSelectedTab("전체"), [selectedCategory]);

  const currentGroup = selectedCategory === ALL_ITEMS
    ? { category: ALL_ITEMS, rows: allRows }
    : groups.find((group) => group.category === selectedCategory);
  const tabField = currentGroup ? TAB_FIELD[currentGroup.category] : undefined;
  const tabs = useMemo(() => !currentGroup || !tabField ? [] : [...new Set(currentGroup.rows.map((row) => row[tabField] || "(기타)"))], [currentGroup, tabField]);
  const { rows, untimedExcluded } = useMemo(() => {
    if (!currentGroup) return { rows: [], untimedExcluded: 0 };
    const needle = search.trim().toLowerCase();
    const filtered = currentGroup.rows.filter((row) => {
      if (tabField && selectedTab !== "전체" && (row[tabField] || "(기타)") !== selectedTab) return false;
      return !needle || [row.name, row.value, row.key_path, row.command, row.detail, row.source, row.user, row.subtype]
        .some((value) => (value || "").toLowerCase().includes(needle));
    });
    const untimedExcluded = rangeOn
      ? filtered.filter((row) => !row.timestamp?.trim()).length
      : 0;
    const timeScoped = rangeOn
      ? filtered.filter((row) => inRange(row.timestamp?.trim() ?? "", timeRange))
      : filtered;
    return { rows: sortByRegistryTime(timeScoped, timeOrder), untimedExcluded };
  }, [currentGroup, rangeOn, search, selectedTab, tabField, timeOrder, timeRange]);
  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 20px" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
      <h1 className="dfir-page-title" style={{ margin: 0, fontSize: 20 }}>레지스트리 특이사항</h1>
      {rangeOn && <span style={{ color: "var(--accent)", fontSize: 11.5 }}>기간 필터 적용</span>}
    </div>
    <div style={{ minHeight: 0, flex: 1, display: "grid", gridTemplateColumns: "210px minmax(0, 1fr)", overflow: "hidden", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", boxShadow: "var(--shadow-card)" }}>
      <CategoryNavigation groups={groups} selected={selectedCategory} onSelect={setSelectedCategory} />
      <section style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <RegistryToolbar search={search} onSearch={setSearch} tabs={tabs} activeTab={selectedTab} onTab={setSelectedTab} tabField={tabField} timeOrder={timeOrder} onTimeOrder={setTimeOrder} />
        <RegistryLedger rows={rows} untimedExcluded={untimedExcluded} category={selectedCategory} onSelect={setDetail} bookmarkedRowids={bookmarkedRowids} onToggleBookmark={onToggleBookmark} accountDirectory={accountDirectory} />
      </section>
    </div>
    {detail && <RowDetailPanel row={detail} columns={data.columns} focusedColumn={null} fileBaseName="RegistryFindings" onClose={() => setDetail(null)} onNavigate={() => {}} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowId(detail)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowId(detail)) : undefined} />}
  </div>;
}

function CategoryNavigation({ groups, selected, onSelect }: { groups: { category: string; rows: Row[] }[]; selected: string; onSelect: (category: string) => void }) {
  return <nav aria-label="레지스트리 범주" style={{ minHeight: 0, overflow: "auto", padding: 7, borderRight: "1px solid var(--border)" }}>
    <div style={{ padding: "5px 7px 8px", color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700 }}>레지스트리 범주</div>
    <CategoryButton category={ALL_ITEMS} active={selected === ALL_ITEMS} onClick={() => onSelect(ALL_ITEMS)} />
    {groups.map(({ category }) => <CategoryButton key={category} category={category} active={selected === category} onClick={() => onSelect(category)} />)}
  </nav>;
}

function CategoryButton({ category, active, onClick }: { category: string; active: boolean; onClick: () => void }) {
  const meta = categoryMeta(category);
  const Icon = meta.icon;
  return <button type="button" onClick={onClick} style={{ width: "100%", minHeight: 35, padding: "0 8px", display: "flex", alignItems: "center", gap: 8, border: 0, borderLeft: `3px solid ${active ? "var(--accent)" : "transparent"}`, borderRadius: "var(--radius-sm)", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--text)" : "var(--text-dim)", cursor: "pointer", textAlign: "left" }}>
    <Icon sx={{ fontSize: 16, flexShrink: 0, color: active ? "var(--accent)" : "inherit" }} />
    <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: active ? 700 : 550 }}>{meta.label}</span>
  </button>;
}

function RegistryToolbar({ search, onSearch, tabs, activeTab, onTab, tabField, timeOrder, onTimeOrder }: { search: string; onSearch: (value: string) => void; tabs: string[]; activeTab: string; onTab: (value: string) => void; tabField?: string; timeOrder: TimeOrder; onTimeOrder: (value: TimeOrder) => void }) {
  return <div style={{ flexShrink: 0, padding: "9px 10px", display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap", borderBottom: "1px solid var(--border)" }}>
    <div style={{ position: "relative", width: 250, maxWidth: "100%" }}>
      <SearchOutlinedIcon sx={{ position: "absolute", left: 8, top: 7, fontSize: 17, color: "var(--text-faint)", pointerEvents: "none" }} />
      <input value={search} onChange={(event) => onSearch(event.target.value)} aria-label="레지스트리 검색" placeholder="키 경로 · 값 · 이름 검색" style={{ width: "100%", height: 30, padding: "5px 8px 5px 31px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12.5 }} />
    </div>
    {tabField && tabs.length > 1 && <><span style={{ width: 1, height: 20, background: "var(--border)" }} />{["전체", ...tabs].map((tab) => <button key={tab} type="button" onClick={() => onTab(tab)} style={{ minHeight: 28, padding: "3px 8px", border: `1px solid ${activeTab === tab ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", background: activeTab === tab ? "var(--accent-subtle)" : "var(--bg-input)", color: activeTab === tab ? "var(--text)" : "var(--text-dim)", fontSize: 11.5, cursor: "pointer" }}>{tab === "(시스템)" ? "시스템" : tab}</button>)}</>}
    <button type="button" aria-pressed={timeOrder === "asc"} aria-label={`기록 시각: ${timeOrder === "desc" ? "최신순" : "오래된순"}. 정렬 순서 변경`} title={timeOrder === "desc" ? "오래된순으로 정렬" : "최신순으로 정렬"} onClick={() => onTimeOrder(timeOrder === "desc" ? "asc" : "desc")} style={{ marginLeft: "auto", minHeight: 30, padding: "4px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-input)", color: "var(--text-dim)", fontSize: 11.5, whiteSpace: "nowrap", display: "inline-flex", alignItems: "center", gap: 5, cursor: "pointer" }}>
      {timeOrder === "desc" ? <ArrowDownwardOutlinedIcon sx={{ fontSize: 15 }} /> : <ArrowUpwardOutlinedIcon sx={{ fontSize: 15 }} />}
      기록 시각: {timeOrder === "desc" ? "최신순" : "오래된순"}
    </button>
    <span aria-live="polite" aria-atomic="true" style={visuallyHidden}>기록 시각 {timeOrder === "desc" ? "최신순" : "오래된순"}</span>
  </div>;
}

function RegistryLedger({ rows, untimedExcluded, category, onSelect, bookmarkedRowids, onToggleBookmark, accountDirectory }: { rows: Row[]; untimedExcluded: number; category: string; onSelect: (row: Row) => void; bookmarkedRowids?: Set<number>; onToggleBookmark?: (rowid: number) => void; accountDirectory?: AccountDirectory }) {
  const Icon = categoryMeta(category).icon;
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
  }, [rows]);
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_HEIGHT, overscan: 12 });
  const grid = "48px minmax(185px, .8fr) minmax(240px, 1.2fr) minmax(120px, .55fr) minmax(185px, .9fr) 170px 34px";
  if (!rows.length) return <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>{untimedExcluded > 0 ? `시간 정보 없음 ${untimedExcluded.toLocaleString()}건을 기간 필터에서 제외해 일치하는 레지스트리 항목이 없습니다.` : "검색·탭·기간 조건에 일치하는 레지스트리 항목 없음"}</div>;
  return <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
    {untimedExcluded > 0 && <div aria-live="polite" style={{ flexShrink: 0, padding: "6px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 11.5 }}>시간 정보 없음 {untimedExcluded.toLocaleString()}건은 기간 필터에서 제외했습니다.</div>}
    <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
    <div style={{ minWidth: 1050 }}>
      <div style={{ display: "grid", gridTemplateColumns: grid, gap: 12, minHeight: 34, alignItems: "center", padding: "0 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span>상태</span><span>항목</span><span>값 / 명령</span><span>사용자</span><span>레지스트리 키</span><span>시간</span><span aria-label="북마크" /></div>
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>{virtualizer.getVirtualItems().map((virtualRow) => {
        const row = rows[virtualRow.index];
        const stableKey = rowId(row);
        const bookmarked = bookmarkedRowids?.has(rowId(row)) ?? false;
        const tone = statusTone(row.status);
        const value = row.command || row.value;
        return <div key={stableKey || virtualRow.key} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)`, display: "grid", gridTemplateColumns: "minmax(0, 1fr) 34px", gap: 12, alignItems: "center", padding: "0 12px", borderBottom: "1px solid var(--border-subtle)", borderLeft: "3px solid transparent", background: "transparent" }}>
          <div role="button" tabIndex={0} aria-label={`${row.name || "레지스트리 항목"} 상세 보기`} onClick={() => onSelect(row)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(row); } }} style={{ minWidth: 0, height: "100%", display: "grid", gridTemplateColumns: "48px minmax(185px, .8fr) minmax(240px, 1.2fr) minmax(120px, .55fr) minmax(185px, .9fr) 170px", gap: 12, alignItems: "center", cursor: "pointer", outlineOffset: -3 }}>
            <span><span style={{ display: "inline-flex", padding: "2px 6px", borderRadius: "var(--radius-sm)", background: tone.bg, color: tone.fg, border: `1px solid ${tone.border}`, fontSize: 10.5, fontWeight: 700 }}>{row.status || "정보"}</span></span>
            <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}><Icon sx={{ fontSize: 15, flexShrink: 0, color: "var(--text-faint)" }} /><span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 12.5, fontWeight: 650 }}>{row.name || "값 이름 없음"}</span></span>
            <span title={value || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: looksLikePath(value) ? "var(--accent)" : "var(--text-dim)", fontFamily: looksLikePath(value) ? "var(--mono)" : "var(--sans)", fontSize: 12 }}>{value || "값 없음"}</span>
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{resolveAccountDisplay(row.user, accountDirectory) || "계정 정보 없음"}</span>
            <span title={row.key_path || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11 }}>{row.key_path || "키 경로 없음"}</span>
            <span style={{ color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontSize: 11.5, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>{row.timestamp || "시간 정보 없음"}</span>
          </div>
          <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}><span><IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark} size="small" onClick={() => onToggleBookmark?.(rowId(row))} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius-sm)" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}</IconButton></span></Tooltip>
        </div>;
      })}</div>
    </div>
    </div>
  </div>;
}

const visuallyHidden: React.CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  border: 0,
};
