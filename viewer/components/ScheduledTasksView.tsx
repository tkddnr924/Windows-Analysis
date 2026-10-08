"use client";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";

import { useContext, useEffect, useMemo, useState, type CSSProperties } from "react";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import RowDetailPanel from "./RowDetailPanel";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import { tagsForPath, type Tag } from "@/lib/tagging";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import PaginationControls from "@/components/PaginationControls";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

const TABLE = "ScheduledTasks";
const PAGE = 10;

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

type Row = Record<string, string>;
type FilterKey = "all" | "user" | "review" | "hidden";

interface Entry {
  row: Row;
  rowid: number;
  name: string;
  taskPath: string;
  /** 기록 종류 — 작업 정의 행과 작업 이벤트 행이 같은 표에 함께 있다. */
  eventType: string;
  result: string;
  runAs: string;
  isMicrosoft: boolean;
  enabled: boolean | null;
  hidden: boolean;
  tags: Tag[];
  review: boolean;
}

function truthValue(value: string | undefined): boolean | null {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === "1") return true;
  if (normalized === "0") return false;
  return null;
}

function buildEntry(row: Row): Entry {
  // 실행 명령은 TaskActions 자식 표에 있다(저장 계약 docs-01) — 목록은 보이는
  // 쪽만 따로 조회하므로, 경로 기반 위험 태그는 그 조회 결과로 붙인다.
  const hidden = truthValue(row.hidden) === true;
  return {
    row,
    rowid: Number((row as Record<string, unknown>).__rowid),
    name: row.task_name || "(작업 이름 없음)",
    taskPath: row.task_path || "",
    eventType: row.event_type || "",
    result: row.result || "",
    runAs: row.run_as || row.run_as_sid || "",
    isMicrosoft: row.is_microsoft === "1",
    enabled: truthValue(row.enabled),
    hidden,
    tags: [],
    review: hidden,
  };
}

function FilterButton({ active, children, onClick }: { active: boolean; children: React.ReactNode; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} style={{
      height: 30, padding: "0 10px", borderRadius: "var(--radius)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
      background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)",
      fontSize: 11.5, fontWeight: active ? 700 : 500, cursor: "pointer", whiteSpace: "nowrap",
    }}>
      {children}
    </button>
  );
}

function Signal({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "warning" | "danger" | "success" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : tone === "success" ? "var(--success)" : "var(--text-dim)";
  return <span style={{ color, fontSize: 11.5, fontWeight: 700, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{children}</span>;
}

function taskState(entry: Entry): React.ReactNode {
  const signals: React.ReactNode[] = [];
  if (entry.enabled === true) signals.push(<Signal key="enabled" tone="success">활성</Signal>);
  if (entry.enabled === false) signals.push(<Signal key="disabled">비활성</Signal>);
  if (entry.hidden) signals.push(<Signal key="hidden" tone="warning">숨김</Signal>);
  if (entry.tags.some((tag) => tag.severity === "danger")) signals.push(<Signal key="danger" tone="danger">검토</Signal>);
  else if (entry.tags.length > 0) signals.push(<Signal key="warning" tone="warning">검토</Signal>);
  return signals.length ? <span style={{ display: "inline-flex", gap: 5, flexWrap: "wrap" }}>{signals}</span> : null;
}

// 카드 타일 색 — 위험 신호가 한눈에 보이게 상태로 결정한다.
function entryColor(entry: Entry): string {
  if (entry.tags.some((tag) => tag.severity === "danger")) return "var(--danger)";
  if (entry.review) return "var(--warning)";
  if (entry.enabled === true) return "var(--success)";
  return "var(--text-dim)";
}

function cellStyle(extra?: CSSProperties): CSSProperties {
  return { minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...extra };
}

export default function ScheduledTasksView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<FilterKey>("all");
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  // 시간순 정렬 — 기본은 오래된 순(오름차순).
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [enabledFilter, setEnabledFilter] = useState<"all" | "enabled" | "disabled">("all");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Entry | null>(null);
  // 등록 시각이 없는 작업은 본 목록과 분리해 접이식 구역으로 보여준다
  // (실행 이력·파워셸 실행 이력의 "시간 정보 없음" 패턴).
  const [untimedOpen, setUntimedOpen] = useState(false);
  const [untimedPage, setUntimedPage] = useState(0);

  const all = useMemo(() => (data.rows as Row[]).map(buildEntry), [data.rows]);
  const rangeOn = rangeActive(timeRange);
  const counts = useMemo(() => ({
    total: all.length,
    user: all.filter((entry) => !entry.isMicrosoft).length,
    review: all.filter((entry) => entry.review).length,
    hidden: all.filter((entry) => entry.hidden).length,
    enabled: all.filter((entry) => entry.enabled === true).length,
    disabled: all.filter((entry) => entry.enabled === false).length,
  }), [all]);

  const allAccounts = useMemo(
    () => [...new Set(all.map((entry) => entry.runAs))].sort((a, b) => a.localeCompare(b)),
    [all],
  );
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return all
      .filter((entry) => {
        if (rangeOn && !inRange(entry.row.timestamp || "", timeRange)) return false;
        if (filter === "user" && entry.isMicrosoft) return false;
        if (hiddenAccounts.has(entry.runAs)) return false;
        if (filter === "review" && !entry.review) return false;
        if (filter === "hidden" && !entry.hidden) return false;
        if (enabledFilter === "enabled" && entry.enabled !== true) return false;
        if (enabledFilter === "disabled" && entry.enabled !== false) return false;
        if (!query) return true;
        // 실행 명령은 자식 표라 전체 검색 대상이 아니다 — 보이는 행의 명령은
        // 아래에서 따로 조회해 보여 주고, 상세에는 전체가 나온다.
        return [entry.name, entry.taskPath, entry.runAs, entry.eventType, entry.row.author || ""].some((value) => value.toLowerCase().includes(query));
      })
      .sort((left, right) => {
        // 등록 시각 기준 정렬 — 시각 없는 작업은 방향과 무관하게 뒤로.
        const leftTime = left.row.timestamp || "";
        const rightTime = right.row.timestamp || "";
        if (!leftTime || !rightTime) return leftTime ? -1 : rightTime ? 1 : left.name.localeCompare(right.name);
        const compare = leftTime.localeCompare(rightTime);
        return (sortDir === "asc" ? compare : -compare) || left.name.localeCompare(right.name);
      });
  }, [all, enabledFilter, filter, hiddenAccounts, rangeOn, search, sortDir, timeRange]);

  const untimed = useMemo(() => filtered.filter((entry) => !(entry.row.timestamp || "").trim()), [filtered]);
  const timed = useMemo(() => filtered.filter((entry) => (entry.row.timestamp || "").trim()), [filtered]);

  useEffect(() => setPage(0), [enabledFilter, filter, hiddenAccounts, rangeOn, search, timeRange]);
  useEffect(() => setUntimedPage(0), [untimed.length]);
  const pageCount = Math.max(1, Math.ceil(timed.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = timed.slice(safePage * PAGE, (safePage + 1) * PAGE);
  const pageStart = timed.length ? safePage * PAGE + 1 : 0;
  const pageEnd = Math.min((safePage + 1) * PAGE, timed.length);

  // 보이는 행의 실행 명령만 TaskActions에서 조회한다 — 목록 전체를 조인하지
  // 않고, 조회된 명령으로만 경로 위험 태그를 붙인다(없는 값을 지어내지 않음).
  const scope = useContext(RecordScopeContext);
  const [actionsByRowid, setActionsByRowid] = useState<Record<number, string>>({});
  const pageRowidKey = pageRows.map((entry) => entry.rowid).join(",");
  useEffect(() => {
    if (!scope?.fullPath) return;
    const missing = pageRows.filter((entry) => Number.isFinite(entry.rowid) && actionsByRowid[entry.rowid] === undefined);
    if (missing.length === 0) return;
    let alive = true;
    Promise.all(missing.map(async (entry) => {
      const actionRows = await window.api.readRecordChildren(scope.fullPath, scope.tableName, entry.rowid, "TaskActions").catch(() => []);
      const text = actionRows
        .map((action) => [action.command, action.arguments].filter(Boolean).join(" "))
        .filter(Boolean)
        .join(" · ");
      return [entry.rowid, text] as const;
    })).then((loaded) => {
      if (alive) setActionsByRowid((previous) => ({ ...previous, ...Object.fromEntries(loaded) }));
    });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, pageRowidKey, actionsByRowid]);

  const renderEntry = (entry: Entry) => {
          const bookmarked = bookmarkedRowids?.has(entry.rowid) ?? false;
          const canBookmark = onToggleBookmark && Number.isFinite(entry.rowid);
          const actions = actionsByRowid[entry.rowid] ?? "";
          const commandTags = actions ? tagsForPath(actions) : [];
          const tileColor = entryColor({ ...entry, tags: commandTags, review: entry.review || commandTags.length > 0 });
          return (
            // 행 전체(여백 포함)가 상세 열기 클릭 대상 — 북마크는 전파 차단.
            <div key={Number.isFinite(entry.rowid) ? entry.rowid : entry.name} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(entry)} style={{ borderRadius: "var(--radius)", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }}
              onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
              <button type="button" onClick={() => setSelected(entry)} aria-label={`${entry.name} 상세 보기`} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, padding: 0, border: 0, background: "transparent", color: "inherit", textAlign: "left", cursor: "pointer", outlineOffset: 2 }}>
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tileColor} 15%, transparent)` }}>
                  <TaskOutlinedIcon sx={{ fontSize: 17, color: tileColor }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                    <span title={entry.name} style={cellStyle({ color: "var(--text)", fontSize: 13.5, fontWeight: 700 })}>{entry.name}</span>
                    {taskState({ ...entry, tags: commandTags })}
                  </span>
                  <span title={actions || "동작 정보 없음"} style={cellStyle({ color: actions ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" })}>{actions || (entry.taskPath || "동작 정보 없음")}</span>
                </span>
                <span title={entry.runAs || "계정 정보 없음"} style={cellStyle({ width: 150, flexShrink: 0, color: entry.runAs ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12 })}>{entry.runAs || "계정 정보 없음"}</span>
                <span title={entry.eventType || "기록 종류 없음"} style={cellStyle({ width: 138, flexShrink: 0, color: entry.eventType ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12 })}>{[entry.eventType, entry.result].filter(Boolean).join(" · ") || "기록 종류 없음"}</span>
                <time style={cellStyle({ width: 176, flexShrink: 0, textAlign: "right", color: entry.row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" })}>{entry.row.timestamp || "시간 정보 없음"}</time>
              </button>
              {canBookmark && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark(entry.rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크"} title={bookmarked ? "북마크 해제" : "북마크"} style={{ flexShrink: 0, width: 28, height: 28, display: "grid", placeItems: "center", border: 0, background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 18 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 18 }} />}</button>}
            </div>
          );
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader icon={TaskOutlinedIcon} title="작업 스케줄러" meta={rangeOn ? `등록 시각 기준 ${filtered.length.toLocaleString()}건` : `등록 작업 ${counts.total.toLocaleString()}건`}>
          <HeaderSearchInput value={search} onChange={setSearch} placeholder="작업 이름 · 경로 · 계정 · 기록 종류 검색" ariaLabel="작업 스케줄러 검색" width={300} />
          <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
          <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
          <SelectDropdown
            icon={<VisibilityOutlinedIcon sx={{ fontSize: 15 }} />}
            label="표시"
            options={[
              { value: "all", label: "전체", count: counts.total },
              { value: "user", label: "비-Microsoft 작업", count: counts.user },
              { value: "review", label: "검토 신호", count: counts.review, color: "var(--warning)" },
              { value: "hidden", label: "숨김", count: counts.hidden, color: "var(--warning)" },
            ]}
            value={filter}
            defaultValue="all"
            onChange={(next) => setFilter(next as FilterKey)}
          />
          <SelectDropdown
            label="상태"
            options={[
              { value: "all", label: "전체", count: counts.total },
              { value: "enabled", label: "활성", count: counts.enabled, color: "var(--success)" },
              { value: "disabled", label: "비활성", count: counts.disabled },
            ]}
            value={enabledFilter}
            defaultValue="all"
            onChange={(next) => setEnabledFilter(next as "all" | "enabled" | "disabled")}
          />
        
      </ViewHeader>

      <section aria-label="예약 작업 목록" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {untimed.length > 0 && (
          <div style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
            <button
              type="button"
              onClick={() => setUntimedOpen((open) => !open)}
              aria-expanded={untimedOpen}
              style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, padding: "8px 12px", background: "transparent", border: "none", borderRadius: 0, color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, textAlign: "left" }}
            >
              <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17, transform: untimedOpen ? "none" : "rotate(-90deg)", transition: "transform .15s ease" }} />
              <strong style={{ color: "var(--text)" }}>시간 정보 없음</strong>
              <span style={{ color: "var(--text-faint)" }}>{untimed.length.toLocaleString()}건 · 등록 시각 없는 작업</span>
            </button>
            {untimedOpen && (
              <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "10px 10px 2px" }}>
                {untimed.slice(untimedPage * PAGE, (untimedPage + 1) * PAGE).map(renderEntry)}
                {untimed.length > PAGE && (
                  <div style={{ display: "flex", justifyContent: "center", padding: "2px 0 8px" }}>
                    <PaginationControls ariaLabel="시간 정보 없음 작업 페이지" page={untimedPage} pageCount={Math.max(1, Math.ceil(untimed.length / PAGE))} onChange={setUntimedPage} summary={`(${(untimedPage * PAGE + 1).toLocaleString()}–${Math.min((untimedPage + 1) * PAGE, untimed.length).toLocaleString()} / ${untimed.length.toLocaleString()})`} />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        {pageRows.map(renderEntry)}
        {!pageRows.length && !untimed.length && <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{rangeOn ? "기간 필터 내 데이터 없음" : "조건에 맞는 작업이 없습니다."}</div>}
      </section>

      <footer className="scheduler-footer" style={{ flexShrink: 0, display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto minmax(0, 1fr)", alignItems: "center", minHeight: 46, gap: 12, padding: "0 20px", borderTop: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 11.5 }}>
        <span title={timed.length ? `표시 ${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${timed.length.toLocaleString()}건` : "표시할 작업 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{timed.length ? `표시 ${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${timed.length.toLocaleString()}건` : "표시할 작업 없음"}{filtered.length !== counts.total && <span style={{ marginLeft: 7, color: "var(--text-faint)" }}>전체 {counts.total.toLocaleString()}건</span>}</span>
        <PaginationControls ariaLabel="작업 스케줄러 페이지" page={safePage} pageCount={pageCount} onChange={setPage} />
        <span className="scheduler-footer-spacer" aria-hidden="true" />
      </footer>

      {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(file, column, value) => { setSelected(null); onNavigate(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
    </div>
  );
}

