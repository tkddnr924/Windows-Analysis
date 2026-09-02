"use client";
import FormatListBulletedOutlinedIcon from "@mui/icons-material/FormatListBulletedOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { DateRangeDropdown, HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

import { useEffect, useMemo, useRef, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import ArrowDownwardOutlinedIcon from "@mui/icons-material/ArrowDownwardOutlined";
import ArrowUpwardOutlinedIcon from "@mui/icons-material/ArrowUpwardOutlined";
import FolderSharedOutlinedIcon from "@mui/icons-material/FolderSharedOutlined";
import GppMaybeOutlinedIcon from "@mui/icons-material/GppMaybeOutlined";
import SettingsRemoteOutlinedIcon from "@mui/icons-material/SettingsRemoteOutlined";
import Inventory2OutlinedIcon from "@mui/icons-material/Inventory2Outlined";
import KeyOutlinedIcon from "@mui/icons-material/KeyOutlined";
import ManageSearchOutlinedIcon from "@mui/icons-material/ManageSearchOutlined";
import PlayCircleOutlineOutlinedIcon from "@mui/icons-material/PlayCircleOutlineOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import VpnKeyOutlinedIcon from "@mui/icons-material/VpnKeyOutlined";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import RowDetailPanel from "./RowDetailPanel";
import PaginationControls from "@/components/PaginationControls";
import { tagsForPath } from "@/lib/tagging";
import { displayRegistryKeyPath } from "@/lib/registryPath";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import type { CsvData } from "@/lib/types";
import { MACHINE_SCOPE_LABEL, MACHINE_SCOPE_USER, resolveUserDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { visuallyHidden } from "@/lib/viewShared";

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

const ALL_ITEMS = "전체 항목";
const PAGE = 10;
const TAB_FIELD: Record<string, string> = { "자동 실행": "user", "보안 설정": "subtype", "원격 접속": "subtype", "기타 레지스트리": "subtype" };
const CATEGORY_ORDER = ["자격 증명 보호", "보안 설정", "공유 폴더", "SQL 인증", "자동 실행", "원격 접속", "Sysinternals 도구", "설치 프로그램 (MSI)", "기타 레지스트리"];
const CATEGORY_META: Record<string, CategoryMeta> = {
  [ALL_ITEMS]: { icon: ManageSearchOutlinedIcon, label: ALL_ITEMS },
  "자격 증명 보호": { icon: VpnKeyOutlinedIcon, label: "자격 증명 보호" },
  "보안 설정": { icon: GppMaybeOutlinedIcon, label: "보안 설정" },
  "공유 폴더": { icon: FolderSharedOutlinedIcon, label: "공유 폴더" },
  "SQL 인증": { icon: StorageOutlinedIcon, label: "SQL 인증" },
  "자동 실행": { icon: PlayCircleOutlineOutlinedIcon, label: "자동 실행" },
  "원격 접속": { icon: SettingsRemoteOutlinedIcon, label: "원격 접속" },
  "Sysinternals 도구": { icon: TerminalOutlinedIcon, label: "Sysinternals 도구" },
  "설치 프로그램 (MSI)": { icon: Inventory2OutlinedIcon, label: "설치 프로그램" },
  "기타 레지스트리": { icon: ManageSearchOutlinedIcon, label: "실행 흔적" },
};
const LEGACY_RUN_MRU_TITLE = "Run 대화상자 입력 (RunMRU)";
const LEGACY_TYPED_PATHS_TITLE = "탐색기 주소 입력 (TypedPaths)";
const TYPED_PATH_LABEL = "TypedPath";
const SHIM_CACHE_LABEL = "ShimCache (AppcompatCache)";

function rowId(row: Row): number { return Number((row as Record<string, unknown>).__rowid); }
function categoryMeta(category: string): CategoryMeta { return CATEGORY_META[category] ?? { icon: KeyOutlinedIcon, label: category }; }
function looksLikePath(value: string): boolean { return /^[a-zA-Z]:\\|^\\\\/.test(value); }
function statusColor(status: string): string {
  if (status === "의심") return "var(--danger)";
  if (status === "주의") return "var(--warning)";
  if (status === "정상") return "var(--success)";
  return "var(--text-dim)";
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

export default function RegistryFindingsView({ data, bookmarkedRowids, onToggleBookmark, accountDirectory }: Props) {
  const [selectedCategory, setSelectedCategory] = useState(ALL_ITEMS);
  const [selectedTab, setSelectedTab] = useState("전체");
  const [search, setSearch] = useState("");
  const [timeOrder, setTimeOrder] = useState<TimeOrder>("desc");
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<Row | null>(null);
  // 레지스트리 특이사항은 전역 기간 필터(사고 시점)를 따르지 않는다 —
  // 레지스트리 시각은 마지막 기록 시각이라 사고 창과 어긋나는 일이 많다.
  // 대신 뷰 자체의 날짜 필터를 쓴다.
  const [localRange, setLocalRange] = useState<TimeRange>(EMPTY_TIME_RANGE);
  const rangeOn = rangeActive(localRange);
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
  const allAccounts = useMemo(
    () => [...new Set(allRows.map((row) => (row.user || "").trim()))].sort((a, b) => a.localeCompare(b)),
    [allRows],
  );
  const { rows, untimedExcluded } = useMemo(() => {
    if (!currentGroup) return { rows: [], untimedExcluded: 0 };
    const needle = search.trim().toLowerCase();
    const filtered = currentGroup.rows.filter((row) => {
      if (hiddenAccounts.has((row.user || "").trim())) return false;
      if (tabField && selectedTab !== "전체" && (row[tabField] || "(기타)") !== selectedTab) return false;
      return !needle || [row.name, row.value, row.key_path, displayRegistryKeyPath(row.key_path, row.source), row.command, row.detail, row.source, row.user, row.subtype]
        .some((value) => (value || "").toLowerCase().includes(needle));
    });
    const untimedExcluded = rangeOn
      ? filtered.filter((row) => !row.timestamp?.trim()).length
      : 0;
    const timeScoped = rangeOn
      ? filtered.filter((row) => inRange(row.timestamp?.trim() ?? "", localRange))
      : filtered;
    return { rows: sortByRegistryTime(timeScoped, timeOrder), untimedExcluded };
  }, [currentGroup, hiddenAccounts, localRange, rangeOn, search, selectedTab, tabField, timeOrder]);
  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
    <ViewHeader icon={ManageSearchOutlinedIcon} title="레지스트리 특이사항" meta={`${rows.length.toLocaleString()}건${rows.length !== allRows.length ? ` / 전체 ${allRows.length.toLocaleString()}건` : ""}`} right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "기간 필터 적용" : "전체 기간"}</span>}>
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="키 경로 · 값 · 이름 검색" ariaLabel="레지스트리 검색" width={300} />
        <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
        <SortDropdown value={timeOrder === "desc" ? "desc" : "asc"} onChange={(next) => setTimeOrder(next as TimeOrder)} />
        <DateRangeDropdown start={localRange.start} end={localRange.end} onChange={(next) => setLocalRange(next)} onReset={() => setLocalRange(EMPTY_TIME_RANGE)} />
        {tabField && tabs.length > 1 && (
          <SelectDropdown
            icon={<FormatListBulletedOutlinedIcon sx={{ fontSize: 15 }} />}
            label="하위 항목"
            options={["전체", ...tabs].map((tab) => ({ value: tab, label: tab === MACHINE_SCOPE_USER ? MACHINE_SCOPE_LABEL : tab }))}
            value={selectedTab}
            onChange={setSelectedTab}
          />
        )}
      
      </ViewHeader>
    <div style={{ minHeight: 0, flex: 1, display: "grid", gridTemplateColumns: "minmax(170px, 15%) minmax(0, 1fr)", overflow: "hidden" }}>
      <CategoryNavigation groups={groups} selected={selectedCategory} onSelect={setSelectedCategory} />
      <section style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
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
  return <button type="button" onClick={onClick} className={active ? "nm-btn" : undefined} style={{ width: "100%", minHeight: 36, marginBottom: 2, padding: "0 10px", display: "flex", alignItems: "center", justifyContent: "flex-start", gap: 8, border: active ? "1px solid color-mix(in srgb, var(--accent) 45%, var(--border))" : "1px solid transparent", borderRadius: "var(--radius-md)", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--text)" : "var(--text-dim)", cursor: "pointer", textAlign: "left" }}>
    <Icon sx={{ fontSize: 16, flexShrink: 0, color: active ? "var(--accent)" : "inherit" }} />
    <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: active ? 700 : 550 }}>{meta.label}</span>
  </button>;
}


function RegistryLedger({ rows, untimedExcluded, category, onSelect, bookmarkedRowids, onToggleBookmark, accountDirectory }: { rows: Row[]; untimedExcluded: number; category: string; onSelect: (row: Row) => void; bookmarkedRowids?: Set<number>; onToggleBookmark?: (rowid: number) => void; accountDirectory?: AccountDirectory }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [page, setPage] = useState(0);
  useEffect(() => {
    setPage(0);
    scrollRef.current?.scrollTo({ top: 0 });
  }, [rows]);
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = rows.slice(safePage * PAGE, (safePage + 1) * PAGE);
  if (!rows.length) return <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>{untimedExcluded > 0 ? `시간 정보 없음 ${untimedExcluded.toLocaleString()}건을 기간 필터에서 제외해 일치하는 레지스트리 항목이 없습니다.` : "검색·탭·기간 조건에 일치하는 레지스트리 항목 없음"}</div>;
  return <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
    {untimedExcluded > 0 && <div aria-live="polite" style={{ flexShrink: 0, padding: "6px 14px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 11.5 }}>시간 정보 없음 {untimedExcluded.toLocaleString()}건은 기간 필터에서 제외했습니다.</div>}
    <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 12px 4px" }}>
      {pageRows.map((row, index) => {
        const stableKey = rowId(row);
        const bookmarked = bookmarkedRowids?.has(rowId(row)) ?? false;
        const tone = statusColor(row.status);
        const value = row.command || row.value;
        const userLabel = resolveUserDisplay(row.user, accountDirectory) || "계정 정보 없음";
        // 하이브 루트 키 이름 대신 라이브 마운트 지점(HKLM\SOFTWARE·HKCU…)으로 보여준다.
        const keyPath = displayRegistryKeyPath(row.key_path, row.source);
        // 행 전체(여백 포함)가 상세 열기 클릭 대상 — 북마크는 전파 차단.
        return <div key={stableKey || `${safePage}-${index}`} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => onSelect(row)} style={{ borderRadius: "var(--radius-md)", minHeight: 62, marginBottom: 8, display: "flex", alignItems: "center", gap: 12, padding: "0 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "var(--text)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }} onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
          <div role="button" tabIndex={0} aria-label={`${row.name || "레지스트리 항목"} 상세 보기`} onClick={() => onSelect(row)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(row); } }} style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, padding: "10px 0", cursor: "pointer", outlineOffset: -3 }}>
            <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
              <KeyOutlinedIcon sx={{ fontSize: 17, color: tone }} />
            </span>
            <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
              <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 7, overflow: "hidden" }}>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 13.5, fontWeight: 700 }}>{row.name || "값 이름 없음"}</span>
                <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: tone, border: `1px solid ${tone}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{row.status || "정보"}</span>
              </span>
              <span title={value || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: value ? (looksLikePath(value) ? "var(--accent)" : "var(--text-dim)") : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12 }}>{value || "값 없음"}</span>
            </span>
            <span style={{ width: 122, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: userLabel === "계정 정보 없음" ? "var(--text-faint)" : "var(--text-dim)", fontSize: 12 }}>{userLabel}</span>
            <span title={keyPath || undefined} style={{ width: 230, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5, direction: "rtl", textAlign: "left" }}>{keyPath || "키 경로 없음"}</span>
          </div>
          <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}><span><IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark} size="small" onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark?.(rowId(row)); }} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius-sm)" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}</IconButton></span></Tooltip>
        </div>;
      })}
    </div>
    <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "6px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
      <PaginationControls ariaLabel="레지스트리 항목 페이지" page={safePage} pageCount={pageCount} onChange={(next) => { setPage(next); scrollRef.current?.scrollTo({ top: 0 }); }} summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, rows.length).toLocaleString()} / ${rows.length.toLocaleString()})`} />
    </div>
  </div>;
}
