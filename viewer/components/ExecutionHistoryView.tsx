"use client";
import TuneOutlinedIcon from "@mui/icons-material/TuneOutlined";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { FilterDropdown, HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

import { useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import PaginationControls from "@/components/PaginationControls";
import ClearOutlinedIcon from "@mui/icons-material/ClearOutlined";
import FilterListOutlinedIcon from "@mui/icons-material/FilterListOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import Checkbox from "@mui/material/Checkbox";
import IconButton from "@mui/material/IconButton";
import Popover from "@mui/material/Popover";
import Tooltip from "@mui/material/Tooltip";
import RowDetailPanel from "./RowDetailPanel";
import { tagsForPath, type Tag } from "@/lib/tagging";
import { resolveKnownFolderPath } from "@/lib/knownFolders";
import { inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { basename } from "@/lib/viewShared";
import { executableNote } from "@/lib/executableCatalog";
import { executionDisplay, executionSearchValues, executionSource, isWindowsSystemPath, type ExecutionDisplay } from "@/lib/executionHistory";
import { artifactChipTone } from "./MasterTimeline";

interface ExecutionHistoryViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange: TimeRange;
  accountDirectory?: AccountDirectory;
}

type Row = Record<string, string>;
type SortKey = "risk" | "recent" | "oldest";

const EXECUTABLE_RE = /\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi)$/i;
const EXEC_PAGE_SIZE = 10;
const SORT_LABEL: Record<SortKey, string> = { risk: "주의 항목 우선", recent: "최근순", oldest: "오래된순" };
const SOURCE_LABELS: Record<string, string> = {
  Amcache: "Amcache", Prefetch: "Prefetch", UserAssist: "UserAssist", SRUM: "SRUM", BAM: "BAM", AppCompatCache: "ShimCache", Timeline: "Timeline", WER: "WER",
};

interface Entry {
  rowid: number;
  name: string;
  path: string;
  publisher: string;
  runCount: string;
  timestamp: string;
  source: string;
  account: string;
  display: ExecutionDisplay;
  search: string[];
  tags: Tag[];
  unsigned: boolean;
  risk: number;
  winPath: boolean;
  row: Row;
}

function sourceLabel(source: string): string { return (SOURCE_LABELS[source] ?? source) || "출처 없음"; }

function accountDisplayLabel(row: Row, accountDirectory?: AccountDirectory): string {
  // 계정명은 metadata 조회값(account)이고, 확인되지 않았으면 SID를 그대로
  // 보여 준다(docs-01). 다른 이름 컬럼을 추측해 채우지 않는다.
  const name = (row.account || "").trim();
  if (name) return name;
  const sid = (row.account_sid || "").trim();
  if (!sid) return "계정 정보 없음";
  return resolveAccountDisplay(sid, accountDirectory);
}
function buildEntry(row: Row): Entry {
  const path = row.program_path || "";
  const name = row.program_name || (path ? basename(path) : "");
  const publisher = (row.publisher || "").trim();
  const source = executionSource(row);
  const executable = EXECUTABLE_RE.test(name) || EXECUTABLE_RE.test(path);
  // Publisher metadata is an Amcache field. Other execution artifacts do not
  // collect it, so absence there is not a signature warning.
  const unsigned = source === "Amcache" && executable && !publisher;
  const tags = tagsForPath(path);
  const risk = Math.max(unsigned ? 1 : 0, ...tags.map((tag) => tag.severity === "danger" ? 2 : 1));
  return {
    rowid: Number((row as Record<string, unknown>).__rowid), name, path, publisher, runCount: row.run_count || "", timestamp: row.timestamp || "",
    source, account: (row.account || row.account_sid || ""),
    display: executionDisplay(row, name), search: executionSearchValues(row).map((value) => value.toLowerCase()),
    // Check the path as listed: UserAssist stores KNOWNFOLDERID prefixes ({1AC14E77…} = System32).
    tags, unsigned, risk, winPath: isWindowsSystemPath(resolveKnownFolderPath(path) ?? path), row,
  };
}


const artifactTagStyle: React.CSSProperties = { flexShrink: 0, padding: "1px 7px", borderRadius: "var(--radius)", fontSize: 11, fontWeight: 700, lineHeight: 1.4, whiteSpace: "nowrap" };
export default function ExecutionHistoryView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange, accountDirectory }: ExecutionHistoryViewProps) {
  const [disabledSources, setDisabledSources] = useState<Set<string>>(new Set());
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [onlyRisk, setOnlyRisk] = useState(false);
  const [onlyUnsigned, setOnlyUnsigned] = useState(false);
  const [excludeWindows, setExcludeWindows] = useState(false);
  const [sort, setSort] = useState<SortKey>("oldest");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Entry | null>(null);
  // 시간 정보가 없는 항목은 본 테이블과 분리해 접이식 구역으로 보여준다.
  const [untimedOpen, setUntimedOpen] = useState(false);
  const [untimedPage, setUntimedPage] = useState(0);
  const [page, setPage] = useState(0);
  const [sourceAnchor, setSourceAnchor] = useState<HTMLElement | null>(null);
  const [conditionOpen, setConditionOpen] = useState(false);

  const all = useMemo(() => (data.rows as Row[]).map(buildEntry), [data.rows]);
  const sources = useMemo(() => {
    const counts = new Map<string, number>();
    for (const entry of all) counts.set(entry.source, (counts.get(entry.source) ?? 0) + 1);
    return [...counts.entries()].sort(([left], [right]) => sourceLabel(left).localeCompare(sourceLabel(right)));
  }, [all]);
  const activeSourceCount = sources.filter(([source]) => !disabledSources.has(source)).length;
  const filtersActive = disabledSources.size > 0 || hiddenAccounts.size > 0 || onlyRisk || onlyUnsigned || excludeWindows || Boolean(search.trim());
  // Same rule as SMB/remote access: an active range drops untimed entries.
  const inGlobalRange = useMemo(
    () => !rangeActive(timeRange) ? all : all.filter((entry) => entry.timestamp && inRange(entry.timestamp, timeRange)),
    [all, timeRange],
  );
  const allAccounts = useMemo(
    () => [...new Set(inGlobalRange.map((entry) => (entry.account || "").trim()))].sort((a, b) => a.localeCompare(b)),
    [inGlobalRange],
  );
  const { filtered, untimed } = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const kept = inGlobalRange.filter((entry) => {
      if (disabledSources.has(entry.source) || (excludeWindows && entry.winPath) || (onlyRisk && entry.risk === 0) || (onlyUnsigned && !entry.unsigned)) return false;
      if (hiddenAccounts.has((entry.account || "").trim())) return false;
      return !needle || entry.search.some((value) => value.includes(needle));
    });
    const timed = kept.filter((entry) => entry.timestamp).sort((left, right) => {
      if (sort === "risk" && left.risk !== right.risk) return right.risk - left.risk;
      const compare = left.timestamp.localeCompare(right.timestamp);
      return sort === "oldest" ? compare : -compare;
    });
    // Untimed entries only exist here when no range is active.
    const untimed = kept
      .filter((entry) => !entry.timestamp)
      .sort((left, right) => left.display.title.localeCompare(right.display.title));
    return { filtered: timed, untimed };
  }, [disabledSources, excludeWindows, hiddenAccounts, inGlobalRange, onlyRisk, onlyUnsigned, search, sort]);
  useEffect(() => setUntimedPage(0), [disabledSources, excludeWindows, hiddenAccounts, onlyRisk, onlyUnsigned, search]);
  // 다른 뷰와 동일하게 10건씩 페이지네이션 — 필터·정렬·검색이 바뀌면 첫 페이지로.
  useEffect(() => setPage(0), [disabledSources, excludeWindows, hiddenAccounts, onlyRisk, onlyUnsigned, search, sort, timeRange]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / EXEC_PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = filtered.slice(safePage * EXEC_PAGE_SIZE, safePage * EXEC_PAGE_SIZE + EXEC_PAGE_SIZE);
  const pageStart = filtered.length === 0 ? 0 : safePage * EXEC_PAGE_SIZE + 1;
  const pageEnd = Math.min(filtered.length, safePage * EXEC_PAGE_SIZE + EXEC_PAGE_SIZE);
  const allSourcesSelected = sources.length > 0 && activeSourceCount === sources.length;
  const sourceSelectionPartial = activeSourceCount > 0 && !allSourcesSelected;
  const clearFilters = () => { setDisabledSources(new Set()); setHiddenAccounts(new Set()); setOnlyRisk(false); setOnlyUnsigned(false); setExcludeWindows(false); setSearch(""); };
  const renderRow = (entry: Entry) => {
    const bookmarked = bookmarkedRowids?.has(entry.rowid) ?? false;
    const selectedRow = selected?.rowid === entry.rowid && selected.source === entry.source;
    const accountLabel = accountDisplayLabel(entry.row, accountDirectory);
    const tileColor = entry.risk >= 2 ? "var(--danger)" : entry.risk === 1 ? "var(--warning)" : "var(--text-dim)";
    const tone = artifactChipTone(entry.source, entry.source);
    return (
      /* 행 전체가 상세 열기 클릭 대상 — 북마크는 전파 차단. */
      <div key={`${entry.source}:${entry.rowid}`} className={bookmarked ? `dfir-bookmarked-row${selectedRow ? " dfir-bookmarked-row--selected" : ""}` : undefined} onClick={() => setSelected(entry)} style={{ borderRadius: "var(--radius)", minHeight: 62, marginBottom: 8, display: "flex", alignItems: "center", gap: 12, padding: "0 14px", border: `1px solid ${selectedRow ? "var(--accent)" : "var(--border)"}`, background: selectedRow ? "var(--bg-selected)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }} onMouseEnter={(event) => { if (!selectedRow && !bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!selectedRow && !bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
        <div role="button" tabIndex={0} aria-label={`${entry.display.title} 상세 보기`} onClick={() => setSelected(entry)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(entry); } }} style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, cursor: "pointer", outlineOffset: -3 }}>
          <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tileColor} 14%, transparent)` }}>
            <BoltOutlinedIcon sx={{ fontSize: 17, color: tileColor }} />
          </span>
          <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
            <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}>
              <span title={entry.display.titleIsCommand ? entry.display.title : undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: entry.display.titleIsCommand ? 13 : 13.5, fontWeight: 700, fontFamily: entry.display.titleIsCommand ? "var(--mono)" : undefined }}>{entry.display.title}</span>
              {entry.tags.map((tag) => { const tagColor = tag.severity === "danger" ? "var(--danger)" : "var(--warning)"; return <span key={tag.label} title={tag.description} style={{ ...artifactTagStyle, color: tagColor, border: `1px solid ${tagColor}` }}>{tag.label}</span>; })}
              {executableNote(entry.name) && <span title={executableNote(entry.name)} style={{ flexShrink: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#5bc8c0", border: "1px solid #5bc8c0", borderRadius: "var(--radius)", padding: "1px 7px", fontSize: 11, fontWeight: 650 }}>{executableNote(entry.name)}</span>}
            </span>
            {!entry.display.titleIsCommand && <span title={entry.display.detail || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: entry.display.detail ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12, fontFamily: entry.display.detailIsPath ? "var(--mono)" : undefined }}>{(entry.display.detailIsPath ? resolveKnownFolderPath(entry.display.detail) : null) ?? (entry.display.detail || "경로 정보 없음")}</span>}
          </span>
          {/* Badge: EventLog rows show the provider (event ID dropped); filter key stays EventLog. */}
          <span style={{ width: 116, flexShrink: 0, display: "flex", alignItems: "center" }}>
            <span title={entry.row.event_type || undefined} style={{ ...artifactTagStyle, maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", fontSize: 11.5, fontWeight: 650, color: tone.color, border: `1px solid ${tone.border}`, background: tone.background }}>{entry.source === "EventLog" ? (entry.row.event_type || "EventLog").replace(/\s+\d+$/, "") : sourceLabel(entry.source)}</span>
          </span>
          <span style={{ width: 148, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: accountLabel === "계정 정보 없음" ? "var(--text-faint)" : "var(--text-dim)" }}>{accountLabel}</span>
          <span style={{ width: 172, flexShrink: 0, textAlign: "right", color: "var(--text-time)", fontSize: 12.5, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>{entry.timestamp}</span>
        </div>
        <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}><span><IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark} size="small" onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark?.(entry.rowid); }} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius)" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 17 }} />}</IconButton></span></Tooltip>
      </div>
    );
  };

  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
    <ViewHeader icon={BoltOutlinedIcon} title="실행 이력" meta={`${(filtered.length + untimed.length).toLocaleString()}건`} right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeActive(timeRange) ? "전역 기간 필터 적용" : "전체 기간"}</span>}>
      <HeaderSearchInput value={search} onChange={setSearch} placeholder="이름 · 경로 · 명령줄 · 계정 검색" ariaLabel="실행 이력 검색" width={280} />
      <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
      <SelectDropdown
        icon={<SortOutlinedIcon sx={{ fontSize: 15 }} />}
        label="정렬"
        options={(Object.keys(SORT_LABEL) as SortKey[]).map((key) => ({ value: key, label: SORT_LABEL[key] }))}
        value={sort}
        defaultValue="oldest"
        onChange={(next) => setSort(next as SortKey)}
      />
      <FilterDropdown icon={<TuneOutlinedIcon sx={{ fontSize: 15 }} />} label="표시 조건" valueLabel={onlyRisk || onlyUnsigned || excludeWindows ? "· 적용 중" : undefined} active={onlyRisk || onlyUnsigned || excludeWindows} minWidth={218} open={conditionOpen} onToggle={setConditionOpen}>
        {[
          { label: "주의 항목만", checked: onlyRisk, toggle: () => setOnlyRisk((value) => !value) },
          { label: "게시자 정보 없음만", checked: onlyUnsigned, toggle: () => setOnlyUnsigned((value) => !value) },
          { label: "Windows 경로 제외", checked: excludeWindows, toggle: () => setExcludeWindows((value) => !value) },
        ].map((condition) => (
          <button key={condition.label} type="button" aria-pressed={condition.checked} onClick={condition.toggle} style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "4px 9px", background: "transparent", border: "none", borderRadius: "var(--radius)", color: condition.checked ? "var(--text)" : "var(--text-faint)", cursor: "pointer", fontSize: 12.5, fontWeight: condition.checked ? 650 : 500, textAlign: "left" }}
            onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}>
            <span aria-hidden="true" style={{ color: condition.checked ? "var(--accent)" : "var(--text-faint)", fontSize: 13 }}>{condition.checked ? "☑" : "☐"}</span>
            {condition.label}
          </button>
        ))}
      </FilterDropdown>
      <Tooltip title="출처 필터"><button type="button" className="nm-btn" onClick={(event) => setSourceAnchor(event.currentTarget)} aria-haspopup="dialog" aria-expanded={Boolean(sourceAnchor)} style={{ minHeight: 31, display: "inline-flex", alignItems: "center", gap: 5, padding: "4px 11px", border: `1px solid ${disabledSources.size > 0 ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", color: disabledSources.size > 0 ? "var(--accent)" : "var(--text-dim)", background: disabledSources.size > 0 ? "var(--accent-subtle)" : "var(--bg-elevated)", cursor: "pointer", fontSize: 12, fontWeight: disabledSources.size > 0 ? 650 : 500 }}><FilterListOutlinedIcon sx={{ fontSize: 16 }} />출처</button></Tooltip>
      {filtersActive && <Tooltip title="화면 내 필터 초기화"><IconButton aria-label="화면 내 필터 초기화" size="small" onClick={clearFilters} sx={{ color: "var(--text-dim)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}><ClearOutlinedIcon sx={{ fontSize: 17 }} /></IconButton></Tooltip>}
    
      </ViewHeader>

    <Popover open={Boolean(sourceAnchor)} anchorEl={sourceAnchor} onClose={() => setSourceAnchor(null)} anchorOrigin={{ vertical: "bottom", horizontal: "left" }} transformOrigin={{ vertical: "top", horizontal: "left" }} slotProps={{ paper: { sx: { mt: 0.75, width: 270, bgcolor: "var(--bg-panel)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)" } } }}>
      <div style={{ padding: "10px 10px 7px", display: "flex", alignItems: "center", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ fontSize: 12.5, fontWeight: 700 }}>실행 이력 출처</span><span style={{ marginLeft: "auto", color: "var(--text-faint)", fontSize: 11.5 }}>{activeSourceCount}개 선택</span></div>
      <label style={{ minHeight: 36, padding: "0 8px", display: "flex", alignItems: "center", gap: 6, cursor: "pointer", borderBottom: "1px solid var(--border-subtle)" }}><Checkbox size="small" checked={allSourcesSelected} indeterminate={sourceSelectionPartial} onChange={() => setDisabledSources(allSourcesSelected ? new Set(sources.map(([source]) => source)) : new Set())} sx={{ p: "3px", color: "var(--text-faint)", "&.Mui-checked, &.MuiCheckbox-indeterminate": { color: "var(--accent)" } }} /><span style={{ fontSize: 12, fontWeight: 650 }}>전체 선택</span></label>
      <div style={{ padding: "4px 0 6px" }}>{sources.map(([source]) => {
        const checked = !disabledSources.has(source);
        return <label key={source} style={{ minHeight: 34, padding: "0 8px 0 22px", display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}><Checkbox size="small" checked={checked} onChange={() => setDisabledSources((previous) => { const next = new Set(previous); if (next.has(source)) next.delete(source); else next.add(source); return next; })} sx={{ p: "3px", color: "var(--text-faint)", "&.Mui-checked": { color: "var(--accent)" } }} /><span style={{ fontSize: 12, color: checked ? "var(--text)" : "var(--text-faint)" }}>{sourceLabel(source)}</span></label>;
      })}</div>
    </Popover>

    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "12px 14px 4px" }}>
      {untimed.length > 0 && (
        /* Same card rows as the main list (time column empty); lighter group background (page < card < group) sets it apart. */
        <section style={{ minWidth: 900, marginBottom: 12, border: "1px solid color-mix(in srgb, var(--text-faint) 45%, transparent)", borderRadius: "var(--radius)", background: "var(--bg-elevated)" }}>
          <button
            type="button"
            onClick={() => setUntimedOpen((open) => !open)}
            aria-expanded={untimedOpen}
            style={{ width: "100%", minHeight: 40, display: "flex", alignItems: "center", gap: 8, padding: "0 14px", background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, textAlign: "left" }}
          >
            {untimedOpen ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17 }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 17 }} />}
            <strong style={{ color: "var(--text)", fontWeight: 700 }}>시간 정보 없음</strong>
            <span style={{ color: "var(--text-faint)" }}>{untimed.length.toLocaleString()}건</span>
          </button>
          {untimedOpen && (
            <div style={{ padding: "4px 10px 2px", borderTop: "1px solid var(--border-subtle)" }}>
              <div style={{ paddingTop: 8 }}>{untimed.slice(untimedPage * EXEC_PAGE_SIZE, untimedPage * EXEC_PAGE_SIZE + EXEC_PAGE_SIZE).map(renderRow)}</div>
              <div style={{ display: "flex", justifyContent: "center", padding: "2px 0 8px" }}>
                <PaginationControls ariaLabel="시간 정보 없음 페이지" page={untimedPage} pageCount={Math.max(1, Math.ceil(untimed.length / EXEC_PAGE_SIZE))} onChange={setUntimedPage} summary={`(${Math.min(untimed.length, untimedPage * EXEC_PAGE_SIZE + 1).toLocaleString()}–${Math.min(untimed.length, untimedPage * EXEC_PAGE_SIZE + EXEC_PAGE_SIZE).toLocaleString()} / ${untimed.length.toLocaleString()})`} />
              </div>
            </div>
          )}
        </section>
      )}
      {filtered.length === 0 ? (
        <div style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13 }}>{rangeActive(timeRange) && inGlobalRange.length === 0 ? "기간 필터 내 실행 이력 없음" : all.length === 0 ? "실행 이력 없음" : "검색·필터 조건에 일치하는 실행 이력 없음"}</div>
      ) : (
        <div style={{ minWidth: 900 }}>{pageRows.map(renderRow)}</div>
      )}
    </div>
    {filtered.length > 0 && (
      <footer style={{ flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", minHeight: 44, padding: "6px 16px", borderTop: "1px solid var(--border)" }}>
        <PaginationControls ariaLabel="실행 이력 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${filtered.length.toLocaleString()})`} />
      </footer>
    )}

    {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName="ExecutionHistory" onClose={() => setSelected(null)} onNavigate={(fileName, column, value) => { setSelected(null); onNavigate(fileName, column, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
  </div>;
}
