"use client";
// BITS 전송 이력 (docs-15) — _OVERVIEW BitsHistory 전량(전량 로드 예외)을 저장된
// job_group_key 카드로 묶는다. 작업 ID가 없는 사건은 이름이 같아도 개별 카드(R03).
// 작업 요약 수는 같은 파일 BitsJobs 저장값.
import { useContext, useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { DEFAULT_BITS_FILTER, bitsAccountKey, buildBitsCards, urlLabel, type BitsCard, type BitsFilter } from "@/lib/bitsHistory";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "BitsHistory";
const PAGE = 10;
const EVENT_PAGE = 10;
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)" };

type Row = Record<string, string>;
const rowidOf = (row: Row) => Number((row as Record<string, unknown>).__rowid);

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

function Pill({ color = "var(--text-dim)", title, children }: { color?: string; title?: string; children: React.ReactNode }) {
  return <span title={title} style={{ flexShrink: 0, color, fontWeight: 700, fontSize: 11.5, padding: "1px 7px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}

function optionsOf(rows: Row[], pick: (row: Row) => string, label: (value: string, row: Row) => string = (value) => value) {
  const tally = new Map<string, { label: string; count: number }>();
  for (const row of rows) {
    const value = pick(row);
    const entry = tally.get(value) ?? { label: value ? label(value, row) : "(없음)", count: 0 };
    entry.count += 1;
    tally.set(value, entry);
  }
  return [...tally.entries()].sort(([, a], [, b]) => a.label.localeCompare(b.label)).map(([value, entry]) => ({ value, label: entry.label, count: entry.count }));
}

function bytes(value: string | undefined): string {
  if (value === undefined || value === "") return "";
  const n = Number(value);
  if (!Number.isFinite(n)) return value;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = n;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return unit === 0 ? `${n.toLocaleString()} B` : `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}

/** transferred / total; no ratio when total is NULL or 0 (R07). */
function bytesText(row: Row): string {
  if (!row.bytes_transferred && !row.bytes_total) return "";
  const total = Number(row.bytes_total);
  if (!row.bytes_total || !total) return bytes(row.bytes_transferred);
  return `${bytes(row.bytes_transferred)} / ${bytes(row.bytes_total)}`;
}

const shortType = (eventType: string) => eventType.replace(/^BITS /, "");
const pathOf = (row: Row) => row.local_path_resolved || row.local_path || "";
const basename = (path: string) => path.split(/[\\/]/).pop() || path;

function eventSummary(row: Row): string {
  return [
    row.url ? urlLabel(row.url) : pathOf(row),
    row.url && pathOf(row),
    bytesText(row),
    row.hr_severity && row.hr_severity !== "success" && row.hr_hex,
    row.error_code_hex,
    row.command_line,
  ].filter(Boolean).join(" · ");
}

export default function BitsView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const scope = useContext(RecordScopeContext);
  const [filter, setFilter] = useState<BitsFilter>(DEFAULT_BITS_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Row | null>(null);
  const [jobs, setJobs] = useState<Map<string, Row>>(new Map());
  const update = (patch: Partial<BitsFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  useEffect(() => {
    setJobs(new Map());
    if (!scope?.fullPath) return;
    let alive = true;
    window.api.readResultFile(scope.fullPath, "BitsJobs")
      .then((result) => { if (alive) setJobs(new Map(result.rows.map((row) => [row.job_key, row]))); })
      .catch(() => {});
    return () => { alive = false; };
  }, [scope?.fullPath, data]);
  useEffect(() => { setExpanded(new Set()); setEventPages({}); }, [data]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildBitsCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  useEffect(() => setPage(0), [filter, rangeOn, timeRange, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);
  const jobCount = cards.filter((card) => card.isJob).length;

  const accountLabel = (row: Row) => {
    const sid = row.account_sid || row.owner_sid || row.owner_sid_candidate;
    return row.account || (sid && resolveAccountDisplay(sid, accountDirectory)) || row.owner_raw || sid || "";
  };
  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const resultOptions = useMemo(() => optionsOf(data.rows, (row) => row.result ?? "").map((option) => ({ ...option, color: RESULT_COLOR[option.value] })), [data.rows]);
  const accountOptions = useMemo(() => optionsOf(data.rows.filter((row) => bitsAccountKey(row)), bitsAccountKey, (_value, row) => accountLabel(row)), [data.rows, accountDirectory]);

  const pageCount = Math.max(1, Math.ceil(cards.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageCards = cards.slice(safePage * PAGE, (safePage + 1) * PAGE);
  const toggle = (key: string) => setExpanded((previous) => {
    const next = new Set(previous);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  const bookmarkButton = (row: Row) => {
    const rowid = rowidOf(row);
    if (!onToggleBookmark || !Number.isFinite(rowid)) return null;
    const bookmarked = bookmarkedRowids?.has(rowid) ?? false;
    return <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(e) => { e.stopPropagation(); onToggleBookmark(rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, flexShrink: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>;
  };

  const eventRow = (card: BitsCard<Row>, row: Row, position: number) => {
    const bookmarked = bookmarkedRowids?.has(rowidOf(row)) ?? false;
    const color = RESULT_COLOR[row.result];
    return (
      <div key={row.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(row)}
        onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
        style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: position === 0 ? "none" : "1px solid var(--border-subtle)", cursor: "pointer", opacity: card.matched.has(row.record_id) ? 1 : 0.55 }}>
        <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(row); }} aria-label={`${row.timestamp} ${row.event_type} 상세 보기`} title={[row.url, pathOf(row), row.description].filter(Boolean).join("\n") || undefined}
          style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{row.timestamp}</span>
          <span style={{ width: 120, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{shortType(row.event_type)}</span>
          <span style={{ width: 34, flexShrink: 0, color: color ?? "var(--text-faint)", fontSize: 12, fontWeight: 700 }}>{color ? row.result : ""}</span>
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{eventSummary(row)}</span>
          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
        </button>
        {bookmarkButton(row)}
      </div>
    );
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={CloudDownloadOutlinedIcon} title="BITS 전송 이력" meta={`작업 ${jobCount.toLocaleString()} · 작업 ID 없는 기록 ${(cards.length - jobCount).toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="작업 · 작업 ID · URL · 경로 · 프로세스 · 계정 · SID" ariaLabel="BITS 전송 이력 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={resultOptions} selected={filter.results} onChange={(results) => update({ results })} />
        {accountOptions.length > 0 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <div role="status" style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {pageCards.map((card) => {
          const first = card.events[0];
          const last = card.events[card.events.length - 1];
          const job = jobs.get(card.key);
          const name = card.isJob ? card.events.find((row) => row.job_name)?.job_name || first.job_id : first.event_type;
          const owner = card.events.find((row) => row.owner_raw || row.account);
          const urls = [...new Set(card.events.map((row) => row.url).filter(Boolean))];
          const paths = [...new Set(card.events.map(pathOf).filter(Boolean))];
          const process = card.events.find((row) => row.process)?.process ?? "";
          const transfer = [...card.events].reverse().find((row) => row.event_id === "60" && (row.bytes_transferred || row.bytes_total));
          const line = card.isJob
            ? [urls[0] && `${urlLabel(urls[0])}${urls.length > 1 ? ` 외 ${urls.length - 1}` : ""}`, paths[0] && `${paths[0]}${paths.length > 1 ? ` 외 ${paths.length - 1}` : ""}`, process && basename(process)].filter(Boolean).join(" · ")
            : eventSummary(first);
          const failures = Number(job?.transfer_error_count || 0) + Number(job?.failure_result_count || 0);
          const tone = failures > 0 ? "var(--danger)" : "var(--text-dim)";
          const Icon = card.isJob ? CloudDownloadOutlinedIcon : ReportProblemOutlinedIcon;
          const open = card.isJob && expanded.has(card.key);
          const bookmarked = !card.isJob && (bookmarkedRowids?.has(rowidOf(first)) ?? false);
          const eventPageCount = Math.max(1, Math.ceil(card.events.length / EVENT_PAGE));
          const eventPage = Math.min(eventPages[card.key] ?? 0, eventPageCount - 1);
          const pagedEvents = card.events.slice(eventPage * EVENT_PAGE, (eventPage + 1) * EVENT_PAGE);
          const from = first.timestamp;
          const to = card.isJob ? last.timestamp : "";
          const sameDay = to && to.slice(0, 10) === from.slice(0, 10);
          return (
            <section key={card.key} aria-label={name} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${tone} 42%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center" }}>
                <button type="button" onClick={() => (card.isJob ? toggle(card.key) : setSelected(first))} aria-expanded={card.isJob ? open : undefined} aria-label={card.isJob ? undefined : `${name} 상세 보기`}
                  onMouseEnter={(event) => { if (!open && !bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent"; }}
                  style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, minHeight: line || card.isJob ? 60 : 46, padding: line || card.isJob ? "11px 14px" : "6px 14px", border: "none", background: open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
                    <Icon sx={{ fontSize: 17, color: tone }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }}>{name}</span>
                      {owner && <span title={owner.owner_raw || undefined} style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{accountLabel(owner)}</span>}
                    </span>
                    {(line || card.isJob) && (
                      <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                        {line && <span title={card.isJob ? [...urls, ...paths, process, first.job_id && `작업 ID ${first.job_id}`].filter(Boolean).join("\n") : [first.url, first.description].filter(Boolean).join("\n") || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{line}</span>}
                        {card.isJob && <>
                          {line && <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>}
                          <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>기록 {card.matched.size === card.events.length ? card.events.length.toLocaleString() : `${card.matched.size.toLocaleString()} / ${card.events.length.toLocaleString()}`}</span>
                        </>}
                      </span>
                    )}
                  </span>
                  {card.isJob && job && (
                    <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>
                      {transfer && bytesText(transfer) && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12, marginRight: 4 }}>{bytesText(transfer)}</span>}
                      {Number(job.job_completed_count) > 0 && <Pill color="var(--success)">완료</Pill>}
                      {Number(job.job_cancelled_count) > 0 && <Pill>취소</Pill>}
                      {failures > 0 && <Pill color="var(--danger)">오류 {failures}</Pill>}
                    </span>
                  )}
                  <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                    {from}{to && to !== from && <><span style={{ color: "var(--text-faint)" }}> → </span>{sameDay ? to.slice(11) : to}</>}
                  </span>
                  {card.isJob && <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />}
                </button>
                {!card.isJob && <span style={{ paddingRight: 10 }}>{bookmarkButton(first)}</span>}
              </div>
              {open && (
                <div role="region" aria-label="작업 기록" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {pagedEvents.map((row, position) => eventRow(card, row, position))}
                  {eventPageCount > 1 && (
                    <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "4px 0 6px" }}>
                      <PaginationControls ariaLabel={`${name} 기록 페이지`} page={eventPage} pageCount={eventPageCount} onChange={(next) => setEventPages((previous) => ({ ...previous, [card.key]: next }))}
                        summary={`(${(eventPage * EVENT_PAGE + 1).toLocaleString()}–${Math.min((eventPage + 1) * EVENT_PAGE, card.events.length).toLocaleString()} / ${card.events.length.toLocaleString()})`} />
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })}
        {cards.length > 0 && (
          <PaginationControls ariaLabel="BITS 항목 페이지" page={safePage} pageCount={pageCount} onChange={setPage}
            summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, cards.length).toLocaleString()} / ${cards.length.toLocaleString()})`} />
        )}
      </main>

      {selected && (
        <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowidOf(selected)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowidOf(selected)) : undefined} />
      )}
    </div>
  );
}
