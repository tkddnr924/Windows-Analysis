"use client";
// 작업 스케줄러 (docs-11) — _OVERVIEW ScheduledTasks 전량(부모 전량 로드 예외 유지)을
// 저장 요약(action_summary·trigger_type_summary·review_signals·parse_status)으로 그린다.
// 목록에서 자식 표를 조회하지 않는다(R01/R13/R15).
import { useContext, useEffect, useMemo, useState, type CSSProperties } from "react";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import TaskOutlinedIcon from "@mui/icons-material/TaskOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import RowDetailPanel from "./RowDetailPanel";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, IconTile, NoMatch, isBookmarked, loadErrorNote, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import { HeaderSearchInput, MultiSelectDropdown, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { DEFAULT_TASK_FILTER, REVIEW_SIGNAL_LABELS, filterTasks, resolvedActionSummaries, hasReview, isParseProblem, reviewSignalList, splitByTime, taskAccountKey, taskCounts, type TaskFilter } from "@/lib/scheduledTasks";
import { optionsOf, pageWindow, rowidOf } from "@/lib/eventCards";

const TABLE = "ScheduledTasks";
const COMPANIONS = ["TaskActions"];

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

function Signal({ children, tone = "neutral", title }: { children: React.ReactNode; tone?: "neutral" | "warning" | "danger" | "success"; title?: string }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : tone === "success" ? "var(--success)" : "var(--text-dim)";
  return <span title={title} style={{ color, fontSize: 11.5, fontWeight: 700, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{children}</span>;
}

function cellStyle(extra?: CSSProperties): CSSProperties {
  return { minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...extra };
}

/** Card tone from stored signals only. */
function toneOf(row: Row): string {
  if (isParseProblem(row) || row.result === "실패") return "var(--danger)";
  if (hasReview(row)) return "var(--warning)";
  if (row.enabled === "1") return "var(--success)";
  return "var(--text-dim)";
}

export default function ScheduledTasksView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<TaskFilter>(DEFAULT_TASK_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Row | null>(null);
  const [untimedOpen, setUntimedOpen] = useState(false);
  const [untimedPage, setUntimedPage] = useState(0);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<TaskFilter>) => setFilter((previous) => ({ ...previous, ...patch }));
  // One read of TaskActions for resolved command paths (docs-24); the stored
  // raw summary stays the fallback and hover text.
  const scope = useContext(RecordScopeContext);
  const companion = useCompanionTables(scope?.fullPath, COMPANIONS);
  const actionLines = useMemo(() => resolvedActionSummaries(companion.tables.TaskActions?.rows ?? []), [companion.tables.TaskActions]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const counts = useMemo(() => taskCounts(data.rows), [data.rows]);
  const filtered = useMemo(() => filterTasks(data.rows, filter, inPeriod, rangeOn), [data.rows, filter, inPeriod, rangeOn]);
  const { timed, untimed } = useMemo(() => splitByTime(filtered, sortDir), [filtered, sortDir]);

  const accountText = (row: Row) => {
    const key = taskAccountKey(row);
    // Stored representative name first (docs-11 R14), then the directory.
    return row.account || (key && resolveAccountDisplay(key, accountDirectory)) || row.run_as || key;
  };
  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const accountOptions = useMemo(() => optionsOf(data.rows, taskAccountKey, (key, row) => row.account || resolveAccountDisplay(key, accountDirectory) || row.run_as || key, "(계정 없음)"), [data.rows, accountDirectory]);

  useEffect(() => { setPage(0); setUntimedPage(0); }, [filter, rangeOn, timeRange, sortDir]);
  const list = pageWindow(timed.length, page);
  const untimedList = pageWindow(untimed.length, untimedPage);

  const renderRow = (row: Row) => {
    const bookmarked = isBookmarked(row, bookmarks);
    const tone = toneOf(row);
    const isEvent = Boolean(row.event_id);
    const signals = reviewSignalList(row);
    const account = accountText(row);
    const resolved = actionLines.get(row.record_id);
    const detailLine = isEvent ? [row.event_type, row.launch_reason, row.result_code_raw].filter(Boolean).join(" · ") : resolved?.text || row.action_summary || row.task_path || "";
    const detailTitle = !isEvent && resolved && resolved.raw !== resolved.text ? resolved.raw : detailLine;
    return (
      <div key={row.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(row)}
        style={{ borderRadius: "var(--radius)", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", cursor: "pointer" }}
        onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
        <button type="button" onClick={(event) => { event.stopPropagation(); setSelected(row); }} aria-label={`${row.task_name || row.event_type} 상세 보기`} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, padding: 0, border: 0, background: "transparent", color: "inherit", textAlign: "left", cursor: "pointer" }}>
          <IconTile icon={TaskOutlinedIcon} tone={tone} />
          <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
            <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
              <span title={row.task_path || row.task_name} style={cellStyle({ color: "var(--text)", fontSize: 13.5, fontWeight: 700 })}>{row.task_name || row.event_type}</span>
              <span style={{ display: "inline-flex", gap: 5, flexShrink: 0 }}>
                {row.enabled === "1" && <Signal tone="success">활성</Signal>}
                {row.enabled === "0" && <Signal>비활성</Signal>}
                {signals.map((signal) => <Signal key={signal} tone="warning">{REVIEW_SIGNAL_LABELS[signal] ?? signal}</Signal>)}
                {isParseProblem(row) && <Signal tone="danger" title={row.parse_error}>{row.parse_status}</Signal>}
                {row.result && <Signal tone={row.result === "실패" ? "danger" : row.result === "성공" ? "success" : "neutral"}>{row.result}</Signal>}
              </span>
            </span>
            <span style={{ display: "flex", gap: 8, minWidth: 0, fontSize: 12 }}>
              {detailLine && <span title={detailTitle} style={cellStyle({ color: "var(--text-dim)", fontFamily: isEvent ? undefined : "var(--mono)" })}>{detailLine}</span>}
              {!isEvent && row.trigger_type_summary && <span title={row.trigger_type_summary} style={cellStyle({ flexShrink: 0, maxWidth: 260, color: "var(--text-faint)" })}>{row.trigger_type_summary}</span>}
            </span>
          </span>
          {account && <span title={[row.run_as_sid || row.account_sid, row.run_as].filter(Boolean).join(" · ")} style={cellStyle({ width: 150, flexShrink: 0, color: "var(--text-dim)", fontSize: 12 })}>{account}</span>}
          <time title={row.timestamp_kind || undefined} style={cellStyle({ width: 176, flexShrink: 0, textAlign: "right", color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" })}>{row.timestamp || ""}</time>
        </button>
        <BookmarkButton row={row} bookmarks={bookmarks} size={18} />
      </div>
    );
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader icon={TaskOutlinedIcon} title="작업 스케줄러" meta={`${filtered.length.toLocaleString()} / ${counts.total.toLocaleString()}건`} right={loadErrorNote(companion.failed)}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="작업 · 명령 · 인수 · 트리거 · 설명 · 계정 · SID" ariaLabel="작업 스케줄러 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
        <SelectDropdown
          icon={<VisibilityOutlinedIcon sx={{ fontSize: 15 }} />}
          label="표시"
          options={[
            { value: "all", label: "전체", count: counts.total },
            { value: "user", label: "비-Microsoft 작업", count: counts.user },
            { value: "review", label: "검토 신호", count: counts.review, color: "var(--warning)" },
            { value: "hidden", label: "숨김", count: counts.hidden, color: "var(--warning)" },
            ...(counts.parse ? [{ value: "parse", label: "파싱 문제", count: counts.parse, color: "var(--danger)" }] : []),
          ]}
          value={filter.show}
          defaultValue="all"
          onChange={(show) => update({ show })}
        />
        <SelectDropdown
          label="상태"
          options={[
            { value: "all", label: "전체", count: counts.total },
            { value: "enabled", label: "활성", count: counts.enabled, color: "var(--success)" },
            { value: "disabled", label: "비활성", count: counts.disabled },
          ]}
          value={filter.state}
          defaultValue="all"
          onChange={(state) => update({ state })}
        />
      </ViewHeader>

      <section aria-label="예약 작업 목록" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {untimed.length > 0 && (
          <div style={{ marginBottom: 10, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
            <button type="button" onClick={() => setUntimedOpen((open) => !open)} aria-expanded={untimedOpen}
              style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, padding: "8px 12px", background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, textAlign: "left" }}>
              <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17, transform: untimedOpen ? "none" : "rotate(-90deg)", transition: "transform .15s ease" }} />
              <strong style={{ color: "var(--text)" }}>시간 정보 없음</strong>
              <span style={{ color: "var(--text-faint)" }}>{untimed.length.toLocaleString()}건</span>
            </button>
            {untimedOpen && (
              <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "10px 10px 2px" }}>
                {untimed.slice(untimedList.start, untimedList.end).map(renderRow)}
                {untimedList.pageCount > 1 && (
                  <div style={{ display: "flex", justifyContent: "center", padding: "2px 0 8px" }}>
                    <PaginationControls ariaLabel="시간 정보 없음 작업 페이지" page={untimedList.page} pageCount={untimedList.pageCount} onChange={setUntimedPage} summary={untimedList.summary} />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        {timed.slice(list.start, list.end).map(renderRow)}
        {!timed.length && !untimed.length && <NoMatch total={data.rows.length} />}
      </section>

      <footer className="scheduler-footer" style={{ flexShrink: 0, display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto minmax(0, 1fr)", alignItems: "center", minHeight: 46, gap: 12, padding: "0 20px", borderTop: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 11.5 }}>
        <span style={cellStyle()}>{timed.length ? `${(list.start + 1).toLocaleString()}–${list.end.toLocaleString()} / ${timed.length.toLocaleString()}` : ""}</span>
        <PaginationControls ariaLabel="작업 스케줄러 페이지" page={list.page} pageCount={list.pageCount} onChange={setPage} />
        <span className="scheduler-footer-spacer" aria-hidden="true" />
      </footer>

      {selected && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(file, column, value) => { setSelected(null); onNavigate(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={Number.isFinite(rowidOf(selected)) ? bookmarkedRowids?.has(rowidOf(selected)) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(selected)) ? () => onToggleBookmark(rowidOf(selected)) : undefined} />}
    </div>
  );
}
