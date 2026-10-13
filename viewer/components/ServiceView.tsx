"use client";
// 서비스 이력 (docs-12) — _OVERVIEW ServiceHistory 전량(전량 로드 예외)을 저장된
// group_key 카드로 묶는다. 카드 이름·대표 경로·경로 이력은 ServiceIdentities/
// ServicePaths 저장값, 이벤트 조건은 카드 안 일치/전체 수로 보여 준다.
import { useContext, useMemo, useState } from "react";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import MiscellaneousServicesOutlinedIcon from "@mui/icons-material/MiscellaneousServicesOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PlayCircleOutlineOutlinedIcon from "@mui/icons-material/PlayCircleOutlineOutlined";
import ToggleOnOutlinedIcon from "@mui/icons-material/ToggleOnOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { CardMain, CardName, CardShell, CountText, EventRow, IconTile, NoMatch, PagedEvents, Pill, PillRow, Sep, TimeCell, TimeSpan, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { inRange, EMPTY_TIME_RANGE, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { DEFAULT_SERVICE_FILTER, buildServiceCards, serviceAccountKey, type ServiceFilter } from "@/lib/serviceHistory";
import { chronological } from "@/lib/eventOrder";
import { RESULT_COLOR, optionsOf, pageWindow, resultColor, rowidOf, timeSpan } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "ServiceHistory";
const COMPANIONS = ["ServiceIdentities", "ServicePaths"];

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

export default function ServiceView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const scope = useContext(RecordScopeContext);
  const [filter, setFilter] = useState<ServiceFilter>(DEFAULT_SERVICE_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<ServiceFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  // Card-level stored summaries from the same _OVERVIEW file.
  const companion = useCompanionTables(scope?.fullPath, COMPANIONS);
  const identities = useMemo(() => new Map((companion.tables.ServiceIdentities?.rows ?? []).map((row) => [row.group_key, row])), [companion.tables.ServiceIdentities]);
  const paths = useMemo(() => {
    const byGroup = new Map<string, Row[]>();
    for (const row of companion.tables.ServicePaths?.rows ?? []) byGroup.set(row.group_key, [...(byGroup.get(row.group_key) ?? []), row]);
    for (const list of byGroup.values()) list.sort((a, b) => Number(a.path_ordinal) - Number(b.path_ordinal));
    return byGroup;
  }, [companion.tables.ServicePaths]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildServiceCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);

  const accountLabel = (sid: string, name: string) => name || (sid && resolveAccountDisplay(sid, accountDirectory)) || sid;
  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const resultOptions = useMemo(() => optionsOf(data.rows, (row) => row.result ?? "").map((option) => ({ ...option, color: RESULT_COLOR[option.value] })), [data.rows]);
  const stateOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.state), (row) => row.state), [data.rows]);
  const startTypeOptions = useMemo(() => optionsOf(data.rows.filter((row) => row.start_type_after), (row) => row.start_type_after), [data.rows]);
  const serviceAccountOptions = useMemo(() => optionsOf(data.rows.filter((row) => serviceAccountKey(row)), serviceAccountKey, (_value, row) => accountLabel(row.service_account_sid, row.service_account_name_resolved || row.service_account)), [data.rows, accountDirectory]);

  const list = pageWindow(cards.length, cardState.page);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={MiscellaneousServicesOutlinedIcon} title="서비스 이력" meta={`서비스 ${cards.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`} right={loadErrorNote(companion.failed)}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="서비스 · 키 · 경로 · 실행 계정 · 상세 · SID" ariaLabel="서비스 이력 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={resultOptions} selected={filter.results} onChange={(results) => update({ results })} />
        {stateOptions.length > 0 && <MultiSelectDropdown icon={<PlayCircleOutlineOutlinedIcon sx={{ fontSize: 15 }} />} label="상태" ariaLabel="상태" options={stateOptions} selected={filter.states} onChange={(states) => update({ states })} />}
        {startTypeOptions.length > 0 && <MultiSelectDropdown icon={<ToggleOnOutlinedIcon sx={{ fontSize: 15 }} />} label="시작 유형" ariaLabel="시작 유형" options={startTypeOptions} selected={filter.startTypes} onChange={(startTypes) => update({ startTypes })} />}
        {serviceAccountOptions.length > 0 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="실행 계정" ariaLabel="실행 계정" options={serviceAccountOptions} selected={filter.serviceAccounts} onChange={(serviceAccounts) => update({ serviceAccounts })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <NoMatch total={data.rows.length} />}
        {cards.slice(list.start, list.end).map((card) => {
          const identity = identities.get(card.key);
          const ordered = chronological(card.events);
          const first = ordered[0];
          const isRecord = (identity?.group_key_kind ?? first.group_key_kind) === "record";
          // R13: record-kind cards never show the internal group key as a name.
          const name = isRecord ? first.event_type || first.description : identity?.display_name || first.group_display_name || first.service_name || first.service_key || "";
          const serviceKey = isRecord ? "" : identity?.service_key || first.service_key || "";
          const groupPaths = paths.get(card.key) ?? [];
          const latestPath = groupPaths[groupPaths.length - 1];
          const pathText = latestPath ? latestPath.image_path_resolved || latestPath.image_path : identity?.latest_image_path || "";
          const pathRaw = latestPath?.image_path || identity?.latest_image_path || "";
          const install = [...ordered].reverse().find((event) => event.service_account || event.service_account_sid);
          const serviceAccount = install ? accountLabel(install.service_account_sid, install.service_account_name_resolved || install.service_account) : "";
          const counts = { install: 0, startType: 0, state: 0, failure: 0 };
          for (const event of card.events) {
            if (!card.matched.has(event.record_id)) continue;
            if (event.event_id === "7045" || event.event_id === "4697") counts.install += 1;
            else if (event.event_id === "7040") counts.startType += 1;
            else if (event.event_id === "7036") counts.state += 1;
            if (event.result === "실패") counts.failure += 1;
          }
          const span = timeSpan(card.events);
          const open = cardState.isOpen(card.key);
          const tone = counts.failure > 0 ? "var(--danger)" : "var(--text-dim)";
          return (
            <CardShell key={card.key} label={name || serviceKey} tone={tone} mark={<IconTile icon={MiscellaneousServicesOutlinedIcon} tone={tone} />} expandable open={open} onActivate={() => cardState.toggle(card.key)} regionLabel="서비스 이벤트"
              body={<>
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
                <PagedEvents events={card.events} page={cardState.eventPage(card.key)} onPage={(next) => cardState.setEventPage(card.key, next)} label={`${name} 이벤트 페이지`}
                  render={(event, index) => {
                    const color = resultColor(event.result);
                    const change = event.start_type_before && event.start_type_after ? `${event.start_type_before} → ${event.start_type_after}` : event.start_type_after;
                    const extra = [event.state, change, event.error_code_raw && `오류 ${event.error_code_hex || event.error_code_raw}`, event.detail].filter(Boolean).join(" · ");
                    return (
                      <EventRow key={event.record_id} row={event} index={index} matched={card.matched.has(event.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(event)} openLabel={`${event.timestamp} ${event.event_type} 상세 보기`}>
                        <TimeCell value={event.timestamp} />
                        <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: color }} />
                        <span style={{ flexShrink: 0, color, fontSize: 12, fontWeight: 700, width: 34 }}>{event.result}</span>
                        <span title={event.description} style={{ width: 230, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{event.event_type || event.description}</span>
                        <span title={extra || undefined} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{extra}</span>
                        <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.event_id}</span>
                      </EventRow>
                    );
                  }} />
              </>}>
              <CardMain
                title={<>
                  <CardName>{name}</CardName>
                  {serviceKey && serviceKey !== name && <span style={{ flexShrink: 0, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{serviceKey}</span>}
                </>}
                sub={<>
                  {pathText && <>
                    <span title={pathRaw !== pathText ? pathRaw : undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{pathText}</span>
                    {groupPaths.length > 1 && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontWeight: 700 }}>경로 {groupPaths.length}</span>}
                    <Sep />
                  </>}
                  {serviceAccount && <>
                    <span title={install?.service_account_sid || undefined} style={{ flexShrink: 0 }}>{serviceAccount}</span>
                    <Sep />
                  </>}
                  <CountText unit="이벤트" matched={card.matched.size} total={card.events.length} />
                </>} />
              <PillRow>
                {counts.install > 0 && <Pill color="var(--accent)">설치 {counts.install}</Pill>}
                {counts.startType > 0 && <Pill>시작 유형 {counts.startType}</Pill>}
                {counts.state > 0 && <Pill>상태 {counts.state}</Pill>}
                {counts.failure > 0 && <Pill color="var(--danger)">실패 {counts.failure}</Pill>}
              </PillRow>
              <TimeSpan from={span.from} to={span.to} />
            </CardShell>
          );
        })}
        {cards.length > 0 && <PaginationControls ariaLabel="서비스 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
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
