"use client";
// 오류 보고 (docs-16) — _OVERVIEW WerReports 전량(전량 로드 예외). 같은 파일의
// WerRelations(보고 식별자 일치)로 이어진 기록만 한 카드로 묶고 원본 사건은
// 합치거나 지우지 않는다. 관계가 없는 기록은 1건 카드.
import { useContext, useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import LayersOutlinedIcon from "@mui/icons-material/LayersOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import StyleOutlinedIcon from "@mui/icons-material/StyleOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { CLASS_LABELS, DEFAULT_WER_FILTER, exceptionLabel, STAGE_LABELS, buildWerCards, type WerCard, type WerFilter } from "@/lib/werReports";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "WerReports";
const PAGE = 10;
const EVENT_PAGE = 10;
// Representative record order: report file, provider event, report event.
const REPRESENTATIVE = ["report_written", "app_error_event", "app_hang_event", "report_generated", "collected_dump"];

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

function Pill({ children }: { children: React.ReactNode }) {
  return <span style={{ flexShrink: 0, color: "var(--text-dim)", fontWeight: 700, fontSize: 11.5, padding: "1px 7px", borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 15%, transparent)", whiteSpace: "nowrap" }}>{children}</span>;
}

function optionsOf(rows: Row[], pick: (row: Row) => string, label: (value: string) => string = (value) => value) {
  const tally = new Map<string, { label: string; count: number }>();
  for (const row of rows) {
    const value = pick(row);
    const entry = tally.get(value) ?? { label: value ? label(value) : "(없음)", count: 0 };
    entry.count += 1;
    tally.set(value, entry);
  }
  return [...tally.entries()].sort(([, a], [, b]) => a.label.localeCompare(b.label)).map(([value, entry]) => ({ value, label: entry.label, count: entry.count }));
}

const pathOf = (row: Row) => row.app_path_resolved || row.app_path || "";
// 1001 P1 is the app only for mapped signature schemas (e.g. LiveKernelEvent P1 is a code).
const appNameOf = (row: Row) => (row.reporting_stage === "report_generated" && row.signature_schema_status !== "mapped" ? "" : row.app_name || "");

/** Stored fault fields as one line. */
function faultSummary(row: Row): string {
  const module = row.module_name && row.module_name !== row.app_name ? row.module_name : "";
  return [
    module,
    row.exception_code && `예외 ${exceptionLabel(row.exception_code)}${row.exception_offset ? ` @ ${row.exception_offset}` : ""}`,
    row.hang_type_text && `응답 없음 ${row.hang_type_text}`,
    row.hresult && `HRESULT ${row.hresult}`,
    row.install_status && `설치 상태 ${row.install_status}`,
    row.app_pid && `PID ${row.app_pid}`,
  ].filter(Boolean).join(" · ");
}

function recordSummary(row: Row): string {
  return [
    faultSummary(row),
    row.report_description,
    row.store_location,
    row.report_status_hex && `상태 ${row.report_status_hex}`,
  ].filter(Boolean).join(" · ");
}

export default function WerView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const scope = useContext(RecordScopeContext);
  const [filter, setFilter] = useState<WerFilter>(DEFAULT_WER_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Row | null>(null);
  const [relations, setRelations] = useState<Row[]>([]);
  const update = (patch: Partial<WerFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  useEffect(() => {
    setRelations([]);
    if (!scope?.fullPath) return;
    let alive = true;
    window.api.readResultFile(scope.fullPath, "WerRelations")
      .then((result) => { if (alive) setRelations(result.rows); })
      .catch(() => {});
    return () => { alive = false; };
  }, [scope?.fullPath, data]);
  useEffect(() => { setExpanded(new Set()); setEventPages({}); }, [data]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildWerCards(data.rows, relations, filter, inPeriod, rangeOn, sortDir), [data.rows, relations, filter, inPeriod, rangeOn, sortDir]);
  useEffect(() => setPage(0), [filter, rangeOn, timeRange, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);

  const typeOptions = useMemo(() => optionsOf(data.rows, (row) => row.error_type ?? ""), [data.rows]);
  const classOptions = useMemo(() => optionsOf(data.rows, (row) => row.error_class ?? "", (value) => CLASS_LABELS[value] ?? value), [data.rows]);
  const stageOptions = useMemo(() => optionsOf(data.rows, (row) => row.reporting_stage ?? "", (value) => STAGE_LABELS[value] ?? value), [data.rows]);

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

  const eventRow = (card: WerCard<Row>, row: Row, position: number) => {
    const bookmarked = bookmarkedRowids?.has(rowidOf(row)) ?? false;
    return (
      <div key={row.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(row)}
        onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
        style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: position === 0 ? "none" : "1px solid var(--border-subtle)", cursor: "pointer", opacity: card.matched.has(row.record_id) ? 1 : 0.55 }}>
        <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(row); }} aria-label={`${row.timestamp} ${row.error_type} 상세 보기`} title={[row.report_identifier, row.report_id, row.integrator_report_id, row.store_path].filter(Boolean).join("\n") || undefined}
          style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{row.timestamp}</span>
          <span style={{ width: 120, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{STAGE_LABELS[row.reporting_stage] ?? row.reporting_stage}</span>
          <span style={{ width: 150, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: "var(--text-dim)" }}>{row.error_type}</span>
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{recordSummary(row)}</span>
          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
        </button>
        {bookmarkButton(row)}
      </div>
    );
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={ReportProblemOutlinedIcon} title="오류 보고" meta={`묶음 ${cards.length.toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="앱 · 경로 · 모듈 · 예외 · 보고 ID · 계정" ariaLabel="오류 보고 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="유형" ariaLabel="오류 유형" options={typeOptions} selected={filter.types} onChange={(types) => update({ types })} />
        <MultiSelectDropdown icon={<StyleOutlinedIcon sx={{ fontSize: 15 }} />} label="분류" ariaLabel="분류" options={classOptions} selected={filter.classes} onChange={(classes) => update({ classes })} />
        <MultiSelectDropdown icon={<LayersOutlinedIcon sx={{ fontSize: 15 }} />} label="기록" ariaLabel="기록 단계" options={stageOptions} selected={filter.stages} onChange={(stages) => update({ stages })} />
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <div role="status" style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {pageCards.map((card) => {
          const first = card.events[0];
          const last = card.events[card.events.length - 1];
          const rep = REPRESENTATIVE.map((stage) => card.events.find((row) => row.reporting_stage === stage)).find(Boolean) ?? first;
          const name = card.events.map(appNameOf).find(Boolean) || rep.friendly_event_name || rep.error_type;
          const types = [...new Set(card.events.map((row) => row.error_type).filter(Boolean))];
          const path = card.events.map(pathOf).find(Boolean) ?? "";
          const fault = card.events.map(faultSummary).find(Boolean) ?? "";
          const line = [path, fault || rep.report_description].filter(Boolean).join(" · ");
          const stages = new Map<string, number>();
          for (const row of card.events) if (card.matched.has(row.record_id)) stages.set(row.reporting_stage, (stages.get(row.reporting_stage) ?? 0) + 1);
          const grouped = card.events.length > 1;
          const open = grouped && expanded.has(card.key);
          const bookmarked = !grouped && (bookmarkedRowids?.has(rowidOf(first)) ?? false);
          const eventPageCount = Math.max(1, Math.ceil(card.events.length / EVENT_PAGE));
          const eventPage = Math.min(eventPages[card.key] ?? 0, eventPageCount - 1);
          const pagedEvents = card.events.slice(eventPage * EVENT_PAGE, (eventPage + 1) * EVENT_PAGE);
          const from = first.timestamp;
          const to = grouped ? last.timestamp : "";
          const sameDay = to && to.slice(0, 10) === from.slice(0, 10);
          return (
            <section key={card.key} aria-label={name} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ marginBottom: 10, border: `1px solid ${open ? "color-mix(in srgb, var(--text-dim) 42%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center" }}>
                <button type="button" onClick={() => (grouped ? toggle(card.key) : setSelected(first))} aria-expanded={grouped ? open : undefined} aria-label={grouped ? undefined : `${name} 상세 보기`}
                  onMouseEnter={(event) => { if (!open && !bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = open ? "color-mix(in srgb, var(--text-dim) 6%, transparent)" : "transparent"; }}
                  style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? "color-mix(in srgb, var(--text-dim) 6%, transparent)" : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 15%, transparent)" }}>
                    <ReportProblemOutlinedIcon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }}>{name}</span>
                      <span title={rep.error_class_basis || undefined} style={{ flexShrink: 0, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 11.5 }}>{[CLASS_LABELS[rep.error_class] ?? rep.error_class, ...types.filter((type) => type !== name)].filter(Boolean).join(" · ")}</span>
                    </span>
                    {(line || grouped) && (
                      <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                        {line && <span title={[path, rep.module_path, rep.report_description].filter(Boolean).join("\n") || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{line}</span>}
                        {grouped && <>
                          {line && <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>}
                          <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>기록 {card.matched.size === card.events.length ? card.events.length.toLocaleString() : `${card.matched.size.toLocaleString()} / ${card.events.length.toLocaleString()}`}</span>
                        </>}
                      </span>
                    )}
                  </span>
                  <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>
                    {[...stages].map(([stage, count]) => <Pill key={stage}>{STAGE_LABELS[stage] ?? stage}{count > 1 ? ` ${count}` : ""}</Pill>)}
                  </span>
                  <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                    {from}{to && to !== from && <><span style={{ color: "var(--text-faint)" }}> → </span>{sameDay ? to.slice(11) : to}</>}
                  </span>
                  {grouped && <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />}
                </button>
                {!grouped && <span style={{ paddingRight: 10 }}>{bookmarkButton(first)}</span>}
              </div>
              {open && (
                <div role="region" aria-label="관련 기록" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
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
          <PaginationControls ariaLabel="오류 보고 페이지" page={safePage} pageCount={pageCount} onChange={setPage}
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
