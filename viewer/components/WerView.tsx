"use client";
// 오류 보고 (docs-16) — _OVERVIEW WerReports 전량(전량 로드 예외). 같은 파일의
// WerRelations(보고 식별자 일치)로 이어진 기록만 한 카드로 묶고 원본 사건은
// 합치거나 지우지 않는다. 관계가 없는 기록은 1건 카드.
import { useContext, useMemo, useState } from "react";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import LayersOutlinedIcon from "@mui/icons-material/LayersOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import StyleOutlinedIcon from "@mui/icons-material/StyleOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, CardMain, CardName, CardShell, CountText, EventRow, IconTile, NoMatch, PagedEvents, Pill, PillRow, Sep, TimeCell, TimeSpan, isBookmarked, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { CLASS_LABELS, DEFAULT_WER_FILTER, exceptionLabel, STAGE_LABELS, buildWerCards, type WerFilter } from "@/lib/werReports";
import { chronological } from "@/lib/eventOrder";
import { optionsOf, pageWindow, rowidOf, timeSpan } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "WerReports";
const COMPANIONS = ["WerRelations"];
const TONE = "var(--text-dim)";
// Representative record order: report file, provider event, report event.
const REPRESENTATIVE = ["report_written", "app_error_event", "app_hang_event", "report_generated", "collected_dump"];

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

const pathOf = (row: Row) => row.app_path_resolved || row.app_path || "";

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
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<WerFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const companion = useCompanionTables(scope?.fullPath, COMPANIONS);
  const relations = companion.tables.WerRelations?.rows;

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildWerCards(data.rows, relations ?? [], filter, inPeriod, rangeOn, sortDir), [data.rows, relations, filter, inPeriod, rangeOn, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);

  const typeOptions = useMemo(() => optionsOf(data.rows, (row) => row.error_type ?? ""), [data.rows]);
  const classOptions = useMemo(() => optionsOf(data.rows, (row) => row.error_class ?? "", (value) => CLASS_LABELS[value] ?? value), [data.rows]);
  const stageOptions = useMemo(() => optionsOf(data.rows, (row) => row.reporting_stage ?? "", (value) => STAGE_LABELS[value] ?? value), [data.rows]);

  const list = pageWindow(cards.length, cardState.page);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={ReportProblemOutlinedIcon} title="오류 보고" meta={`묶음 ${cards.length.toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`} right={loadErrorNote(companion.failed)}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="앱 · 경로 · 모듈 · 예외 · 보고 ID · 계정" ariaLabel="오류 보고 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="유형" ariaLabel="오류 유형" options={typeOptions} selected={filter.types} onChange={(types) => update({ types })} />
        <MultiSelectDropdown icon={<StyleOutlinedIcon sx={{ fontSize: 15 }} />} label="분류" ariaLabel="분류" options={classOptions} selected={filter.classes} onChange={(classes) => update({ classes })} />
        <MultiSelectDropdown icon={<LayersOutlinedIcon sx={{ fontSize: 15 }} />} label="기록" ariaLabel="기록 단계" options={stageOptions} selected={filter.stages} onChange={(stages) => update({ stages })} />
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <NoMatch total={data.rows.length} />}
        {cards.slice(list.start, list.end).map((card) => {
          // Representatives and range follow time, not the display direction.
          const ordered = chronological(card.events);
          const first = ordered[0];
          const rep = REPRESENTATIVE.map((stage) => ordered.find((row) => row.reporting_stage === stage)).find(Boolean) ?? first;
          const name = ordered.map((row) => row.app_name || "").find(Boolean) || rep.friendly_event_name || rep.error_type;
          const types = [...new Set(ordered.map((row) => row.error_type).filter(Boolean))];
          const path = ordered.map(pathOf).find(Boolean) ?? "";
          const fault = ordered.map(faultSummary).find(Boolean) ?? "";
          const line = [path, fault || rep.report_description].filter(Boolean).join(" · ");
          const stages = new Map<string, number>();
          for (const row of card.events) if (card.matched.has(row.record_id)) stages.set(row.reporting_stage, (stages.get(row.reporting_stage) ?? 0) + 1);
          const grouped = card.events.length > 1;
          const span = timeSpan(card.events);
          return (
            <CardShell key={card.key} label={name} tone={TONE} mark={<IconTile icon={ReportProblemOutlinedIcon} tone={TONE} />}
              expandable={grouped} open={grouped && cardState.isOpen(card.key)} onActivate={() => (grouped ? cardState.toggle(card.key) : setSelected(first))} buttonLabel={grouped ? undefined : `${name} 상세 보기`}
              bookmarked={!grouped && isBookmarked(first, bookmarks)} side={!grouped && <BookmarkButton row={first} bookmarks={bookmarks} />} regionLabel="관련 기록"
              body={<PagedEvents events={card.events} page={cardState.eventPage(card.key)} onPage={(next) => cardState.setEventPage(card.key, next)} label={`${name} 기록 페이지`}
                render={(row, index) => (
                  <EventRow key={row.record_id} row={row} index={index} matched={card.matched.has(row.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(row)} openLabel={`${row.timestamp} ${row.error_type} 상세 보기`} title={[row.report_identifier, row.report_id, row.integrator_report_id, row.store_path].filter(Boolean).join("\n") || undefined}>
                    <TimeCell value={row.timestamp} />
                    <span style={{ width: 120, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{STAGE_LABELS[row.reporting_stage] ?? row.reporting_stage}</span>
                    <span style={{ width: 150, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: "var(--text-dim)" }}>{row.error_type}</span>
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{recordSummary(row)}</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
                  </EventRow>
                )} />}>
              <CardMain
                title={<>
                  <CardName>{name}</CardName>
                  <span title={rep.error_class_basis || undefined} style={{ flexShrink: 0, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 11.5 }}>{[CLASS_LABELS[rep.error_class] ?? rep.error_class, ...types.filter((type) => type !== name)].filter(Boolean).join(" · ")}</span>
                </>}
                sub={(line || grouped) && <>
                  {line && <span title={[path, rep.module_path, rep.report_description].filter(Boolean).join("\n") || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{line}</span>}
                  {grouped && <>
                    {line && <Sep />}
                    <CountText unit="기록" matched={card.matched.size} total={card.events.length} />
                  </>}
                </>} />
              <PillRow>{[...stages].map(([stage, count]) => <Pill key={stage}>{STAGE_LABELS[stage] ?? stage}{count > 1 ? ` ${count}` : ""}</Pill>)}</PillRow>
              <TimeSpan from={span.from} to={span.to} />
            </CardShell>
          );
        })}
        {cards.length > 0 && <PaginationControls ariaLabel="오류 보고 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
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
