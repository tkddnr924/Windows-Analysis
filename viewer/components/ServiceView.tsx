"use client";
// 서비스 이력 (docs-12) — _OVERVIEW ServiceHistory 전량(전량 로드 예외)을 저장된
// group_key 카드로 묶는다. 카드 이름·대표 경로·경로 이력은 ServiceIdentities/
// ServicePaths 저장값, 이벤트 조건은 카드 안 일치/전체 수로 보여 준다.
import { useContext, useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import MiscellaneousServicesOutlinedIcon from "@mui/icons-material/MiscellaneousServicesOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PlayCircleOutlineOutlinedIcon from "@mui/icons-material/PlayCircleOutlineOutlined";
import ToggleOnOutlinedIcon from "@mui/icons-material/ToggleOnOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { inRange, EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { DEFAULT_SERVICE_FILTER, buildServiceCards, serviceAccountKey, type ServiceFilter } from "@/lib/serviceHistory";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "ServiceHistory";
// 목록·카드 안 이벤트 모두 10건 페이지(문서 보존 조건).
const PAGE = 10;
const EVENT_PAGE = 10;
const RESULT_COLOR: Record<string, string> = { 실패: "var(--danger)", 성공: "var(--success)" };

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

function CountPill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ color, fontWeight: 700, fontSize: 11.5, padding: "1px 7px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}

/** Stored-value option list with counts (empty value → "(없음)"). */
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

export default function ServiceView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const scope = useContext(RecordScopeContext);
  const [filter, setFilter] = useState<ServiceFilter>(DEFAULT_SERVICE_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Row | null>(null);
  const [identities, setIdentities] = useState<Map<string, Row>>(new Map());
  const [paths, setPaths] = useState<Map<string, Row[]>>(new Map());
  const update = (patch: Partial<ServiceFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  // Card-level stored summaries from the same _OVERVIEW file.
  useEffect(() => {
    setIdentities(new Map());
    setPaths(new Map());
    if (!scope?.fullPath) return;
    let alive = true;
    window.api.readResultFile(scope.fullPath, "ServiceIdentities")
      .then((result) => { if (alive) setIdentities(new Map(result.rows.map((row) => [row.group_key, row]))); })
      .catch(() => {});
    window.api.readResultFile(scope.fullPath, "ServicePaths")
      .then((result) => {
        if (!alive) return;
        const byGroup = new Map<string, Row[]>();
        for (const row of result.rows) byGroup.set(row.group_key, [...(byGroup.get(row.group_key) ?? []), row]);
        for (const list of byGroup.values()) list.sort((a, b) => Number(a.path_ordinal) - Number(b.path_ordinal));
        setPaths(byGroup);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, [scope?.fullPath, data]);
  useEffect(() => { setExpanded(new Set()); setEventPages({}); }, [data]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildServiceCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  useEffect(() => setPage(0), [filter, rangeOn, timeRange, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);

  const accountLabel = (sid: string, name: string) => name || (sid && resolveAccountDisplay(sid, accountDirectory)) || sid;
  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const resultOptions = useMemo(() => optionsOf(data.rows, (row) => row.result ?? ""), [data.rows]);
  const stateOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.state), (row) => row.state), [data.rows]);
  const startTypeOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.start_type_after), (row) => row.start_type_after), [data.rows]);
  const serviceAccountOptions = useMemo(() => optionsOf(data.rows.filter((row) => serviceAccountKey(row)), serviceAccountKey, (_value, row) => accountLabel(row.service_account_sid, row.service_account_name_resolved || row.service_account)), [data.rows, accountDirectory]);

  const pageCount = Math.max(1, Math.ceil(cards.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageCards = cards.slice(safePage * PAGE, (safePage + 1) * PAGE);
  const toggle = (key: string) => setExpanded((previous) => {
    const next = new Set(previous);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={MiscellaneousServicesOutlinedIcon} title="서비스 이력" meta={`서비스 ${cards.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="서비스 · 키 · 경로 · 실행 계정 · 상세 · SID" ariaLabel="서비스 이력 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={resultOptions.map((option) => ({ ...option, color: RESULT_COLOR[option.value] }))} selected={filter.results} onChange={(results) => update({ results })} />
        {stateOptions.length > 0 && <MultiSelectDropdown icon={<PlayCircleOutlineOutlinedIcon sx={{ fontSize: 15 }} />} label="상태" ariaLabel="상태" options={stateOptions} selected={filter.states} onChange={(states) => update({ states })} />}
        {startTypeOptions.length > 0 && <MultiSelectDropdown icon={<ToggleOnOutlinedIcon sx={{ fontSize: 15 }} />} label="시작 유형" ariaLabel="시작 유형" options={startTypeOptions} selected={filter.startTypes} onChange={(startTypes) => update({ startTypes })} />}
        {serviceAccountOptions.length > 0 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="실행 계정" ariaLabel="실행 계정" options={serviceAccountOptions} selected={filter.serviceAccounts} onChange={(serviceAccounts) => update({ serviceAccounts })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <div role="status" style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {pageCards.map((card) => {
          const identity = identities.get(card.key);
          const first = card.events[0];
          const isRecord = (identity?.group_key_kind ?? first.group_key_kind) === "record";
          // R13: record-kind cards never show the internal group key as a name.
          const name = isRecord ? first.event_type || first.description : identity?.display_name || first.group_display_name || first.service_name || first.service_key || "";
          const serviceKey = isRecord ? "" : identity?.service_key || first.service_key || "";
          const groupPaths = paths.get(card.key) ?? [];
          const latestPath = groupPaths[groupPaths.length - 1];
          const pathText = latestPath ? latestPath.image_path_resolved || latestPath.image_path : identity?.latest_image_path || "";
          const pathRaw = latestPath?.image_path || identity?.latest_image_path || "";
          const install = [...card.events].reverse().find((event) => event.service_account || event.service_account_sid);
          const serviceAccount = install ? accountLabel(install.service_account_sid, install.service_account_name_resolved || install.service_account) : "";
          const counts = { install: 0, startType: 0, state: 0, failure: 0 };
          for (const event of card.events) {
            if (!card.matched.has(event.record_id)) continue;
            if (event.event_id === "7045" || event.event_id === "4697") counts.install += 1;
            else if (event.event_id === "7040") counts.startType += 1;
            else if (event.event_id === "7036") counts.state += 1;
            if (event.result === "실패") counts.failure += 1;
          }
          const timed = card.events.filter((event) => event.timestamp);
          const firstTime = timed.length ? (sortDir === "asc" ? timed[0] : timed[timed.length - 1]).timestamp : "";
          const lastTime = timed.length ? (sortDir === "asc" ? timed[timed.length - 1] : timed[0]).timestamp : "";
          const open = expanded.has(card.key);
          const tone = counts.failure > 0 ? "var(--danger)" : "var(--text-dim)";
          const eventPageCount = Math.max(1, Math.ceil(card.events.length / EVENT_PAGE));
          const eventPage = Math.min(eventPages[card.key] ?? 0, eventPageCount - 1);
          const pagedEvents = card.events.slice(eventPage * EVENT_PAGE, (eventPage + 1) * EVENT_PAGE);
          return (
            <section key={card.key} aria-label={name || serviceKey} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${tone} 42%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <button type="button" onClick={() => toggle(card.key)} aria-expanded={open}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent"; }}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
                  <MiscellaneousServicesOutlinedIcon sx={{ fontSize: 17, color: tone }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "baseline", gap: 6, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }}>{name}</span>
                    {serviceKey && serviceKey !== name && <span style={{ flexShrink: 0, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{serviceKey}</span>}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    {pathText && <>
                      <span title={pathRaw !== pathText ? pathRaw : undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{pathText}</span>
                      {groupPaths.length > 1 && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontWeight: 700 }}>경로 {groupPaths.length}</span>}
                      <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    </>}
                    {serviceAccount && <>
                      <span title={install?.service_account_sid || undefined} style={{ flexShrink: 0 }}>{serviceAccount}</span>
                      <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    </>}
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {card.matched.size === card.events.length ? card.events.length.toLocaleString() : `${card.matched.size.toLocaleString()} / ${card.events.length.toLocaleString()}`}</span>
                  </span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>
                  {counts.install > 0 && <CountPill color="var(--accent)">설치 {counts.install}</CountPill>}
                  {counts.startType > 0 && <CountPill color="var(--text-dim)">시작 유형 {counts.startType}</CountPill>}
                  {counts.state > 0 && <CountPill color="var(--text-dim)">상태 {counts.state}</CountPill>}
                  {counts.failure > 0 && <CountPill color="var(--danger)">실패 {counts.failure}</CountPill>}
                </span>
                <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {firstTime}{lastTime && lastTime !== firstTime && <><span style={{ color: "var(--text-faint)" }}> → </span>{lastTime.slice(0, 10) === firstTime.slice(0, 10) ? lastTime.slice(11) : lastTime}</>}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label="서비스 이벤트" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {groupPaths.length > 1 && (
                    <div aria-label="경로 이력" style={{ display: "grid", gridTemplateColumns: "auto minmax(0, 1fr)", gap: 14, padding: "12px 14px 12px 60px", borderBottom: "1px solid var(--border-subtle)" }}>
                      <span style={{ fontSize: 11.5, color: "var(--text-faint)", paddingTop: 2 }}>실행 경로 {groupPaths.length}</span>
                      <ol style={{ listStyle: "none", margin: 0, padding: 0, minWidth: 0 }}>
                        {groupPaths.map((path, index) => {
                          const latest = index === groupPaths.length - 1;
                          const shown = path.image_path_resolved || path.image_path;
                          const cut = Math.max(shown.lastIndexOf("\\"), shown.lastIndexOf("/")) + 1;
                          const color = "var(--text-faint)";
                          return (
                            <li key={path.path_id} title={[path.image_path_resolved && path.image_path, path.first_observed_time !== path.last_observed_time && `${path.first_observed_time} → ${path.last_observed_time}`].filter(Boolean).join("\n") || undefined}
                              style={{ position: "relative", display: "flex", alignItems: "baseline", gap: 10, paddingLeft: 20, paddingBottom: latest ? 0 : 10 }}>
                              <span aria-hidden="true" style={{ position: "absolute", left: 3, top: 5, width: 9, height: 9, borderRadius: "50%", background: color, boxShadow: `0 0 0 3px color-mix(in srgb, ${color} 20%, transparent)` }} />
                              {!latest && <span aria-hidden="true" style={{ position: "absolute", left: 7, top: 16, bottom: 0, width: 1, background: "var(--border)" }} />}
                              <span style={{ flex: 1, minWidth: 0, fontFamily: "var(--mono)", fontSize: 12.5, wordBreak: "break-all" }}>
                                <span style={{ color: "var(--text-faint)" }}>{shown.slice(0, cut)}</span>
                                <span style={{ color: "var(--text)", fontWeight: 700 }}>{shown.slice(cut)}</span>
                              </span>
                              {Number(path.observation_count) > 1 && <span style={{ flexShrink: 0, fontSize: 11.5, color: "var(--text-faint)" }}>×{path.observation_count}</span>}
                              <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-time)" }}>{path.first_observed_time}</span>
                            </li>
                          );
                        })}
                      </ol>
                    </div>
                  )}
                  {pagedEvents.map((event, index) => {
                    const rowid = rowidOf(event);
                    const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                    const resultColor = RESULT_COLOR[event.result] ?? "var(--text-faint)";
                    const change = event.start_type_before && event.start_type_after ? `${event.start_type_before} → ${event.start_type_after}` : event.start_type_after;
                    const extra = [event.state, change, event.error_code_raw && `오류 ${event.error_code_hex || event.error_code_raw}`, event.detail].filter(Boolean).join(" · ");
                    const matched = card.matched.has(event.record_id);
                    return (
                      <div key={event.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(event)}
                        onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
                        onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
                        style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", cursor: "pointer", opacity: matched ? 1 : 0.55 }}>
                        <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(event); }} aria-label={`${event.timestamp} ${event.event_type} 상세 보기`}
                          style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                          <span style={{ color: event.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{event.timestamp}</span>
                          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: resultColor }} />
                          <span style={{ flexShrink: 0, color: resultColor, fontSize: 12, fontWeight: 700, width: 34 }}>{event.result}</span>
                          <span title={event.description} style={{ width: 230, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{event.event_type || event.description}</span>
                          <span title={extra || undefined} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{extra}</span>
                          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.event_id}</span>
                        </button>
                        {onToggleBookmark && Number.isFinite(rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(e) => { e.stopPropagation(); onToggleBookmark(rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                  {eventPageCount > 1 && (
                    <div style={{ borderTop: "1px solid var(--border-subtle)", padding: "4px 0 6px" }}>
                      <PaginationControls ariaLabel={`${name} 이벤트 페이지`} page={eventPage} pageCount={eventPageCount} onChange={(next) => setEventPages((previous) => ({ ...previous, [card.key]: next }))}
                        summary={`(${(eventPage * EVENT_PAGE + 1).toLocaleString()}–${Math.min((eventPage + 1) * EVENT_PAGE, card.events.length).toLocaleString()} / ${card.events.length.toLocaleString()})`} />
                    </div>
                  )}
                </div>
              )}
            </section>
          );
        })}
        {cards.length > 0 && (
          <PaginationControls ariaLabel="서비스 페이지" page={safePage} pageCount={pageCount} onChange={setPage}
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
