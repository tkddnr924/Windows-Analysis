"use client";
// BITS 전송 이력 (docs-15) — _OVERVIEW BitsHistory 전량(전량 로드 예외)을 저장된
// job_group_key 카드로 묶는다. 작업 ID가 없는 사건은 이름이 같아도 개별 카드(R03).
// 작업 요약 수는 같은 파일 BitsJobs 저장값.
import { useContext, useMemo, useState } from "react";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, CardMain, CardName, CardShell, CountText, EventRow, IconTile, NoMatch, PagedEvents, Pill, PillRow, Sep, TimeCell, TimeSpan, isBookmarked, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { RecordScopeContext } from "@/lib/recordScope";
import { DEFAULT_BITS_FILTER, bitsAccountKey, buildBitsCards, urlLabel, type BitsFilter } from "@/lib/bitsHistory";
import { chronological } from "@/lib/eventOrder";
import { RESULT_COLOR, optionsOf, pageWindow, rowidOf, timeSpan } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "BitsHistory";
const COMPANIONS = ["BitsJobs"];

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
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<BitsFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const companion = useCompanionTables(scope?.fullPath, COMPANIONS);
  const jobs = useMemo(() => new Map((companion.tables.BitsJobs?.rows ?? []).map((row) => [row.job_key, row])), [companion.tables.BitsJobs]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildBitsCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);
  const jobCount = cards.filter((card) => card.isJob).length;

  const accountLabel = (row: Row) => {
    const sid = row.account_sid || row.owner_sid || row.owner_sid_candidate;
    return row.account || (sid && resolveAccountDisplay(sid, accountDirectory)) || row.owner_raw || sid || "";
  };
  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const resultOptions = useMemo(() => optionsOf(data.rows, (row) => row.result ?? "").map((option) => ({ ...option, color: RESULT_COLOR[option.value] })), [data.rows]);
  const accountOptions = useMemo(() => optionsOf(data.rows.filter((row) => bitsAccountKey(row)), bitsAccountKey, (_value, row) => accountLabel(row)), [data.rows, accountDirectory]);

  const list = pageWindow(cards.length, cardState.page);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={CloudDownloadOutlinedIcon} title="BITS 전송 이력" meta={`작업 ${jobCount.toLocaleString()} · 작업 ID 없는 기록 ${(cards.length - jobCount).toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`} right={loadErrorNote(companion.failed)}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="작업 · 작업 ID · URL · 경로 · 프로세스 · 계정 · SID" ariaLabel="BITS 전송 이력 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={resultOptions} selected={filter.results} onChange={(results) => update({ results })} />
        {accountOptions.length > 0 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />}
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <NoMatch total={data.rows.length} />}
        {cards.slice(list.start, list.end).map((card) => {
          // Representatives and range follow time, not the display direction.
          const ordered = chronological(card.events);
          const first = ordered[0];
          const job = jobs.get(card.key);
          const name = card.isJob ? ordered.find((row) => row.job_name)?.job_name || first.job_id : first.event_type;
          const owner = ordered.find((row) => row.owner_raw || row.account);
          const urls = [...new Set(ordered.map((row) => row.url).filter(Boolean))];
          const paths = [...new Set(ordered.map(pathOf).filter(Boolean))];
          const process = ordered.find((row) => row.process)?.process ?? "";
          const transfer = [...ordered].reverse().find((row) => row.event_id === "60" && (row.bytes_transferred || row.bytes_total));
          const line = card.isJob
            ? [urls[0] && `${urlLabel(urls[0])}${urls.length > 1 ? ` 외 ${urls.length - 1}` : ""}`, paths[0] && `${paths[0]}${paths.length > 1 ? ` 외 ${paths.length - 1}` : ""}`, process && basename(process)].filter(Boolean).join(" · ")
            : eventSummary(first);
          const failures = Number(job?.transfer_error_count || 0) + Number(job?.failure_result_count || 0);
          const tone = failures > 0 ? "var(--danger)" : "var(--text-dim)";
          const span = timeSpan(card.events);
          return (
            <CardShell key={card.key} label={name} tone={tone} mark={<IconTile icon={card.isJob ? CloudDownloadOutlinedIcon : ReportProblemOutlinedIcon} tone={tone} />}
              expandable={card.isJob} open={card.isJob && cardState.isOpen(card.key)} onActivate={() => (card.isJob ? cardState.toggle(card.key) : setSelected(first))} buttonLabel={card.isJob ? undefined : `${name} 상세 보기`}
              bookmarked={!card.isJob && isBookmarked(first, bookmarks)} side={!card.isJob && <BookmarkButton row={first} bookmarks={bookmarks} />} compact={!line && !card.isJob} regionLabel="작업 기록"
              body={<PagedEvents events={card.events} page={cardState.eventPage(card.key)} onPage={(next) => cardState.setEventPage(card.key, next)} label={`${name} 기록 페이지`}
                render={(row, index) => {
                  const color = RESULT_COLOR[row.result];
                  return (
                    <EventRow key={row.record_id} row={row} index={index} matched={card.matched.has(row.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(row)} openLabel={`${row.timestamp} ${row.event_type} 상세 보기`} title={[row.url, pathOf(row), row.description].filter(Boolean).join("\n") || undefined}>
                      <TimeCell value={row.timestamp} />
                      <span style={{ width: 120, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{shortType(row.event_type)}</span>
                      <span style={{ width: 34, flexShrink: 0, color: color ?? "var(--text-faint)", fontSize: 12, fontWeight: 700 }}>{color ? row.result : ""}</span>
                      <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{eventSummary(row)}</span>
                      <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
                    </EventRow>
                  );
                }} />}>
              <CardMain
                title={<>
                  <CardName>{name}</CardName>
                  {owner && <span title={owner.owner_raw || undefined} style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{accountLabel(owner)}</span>}
                </>}
                sub={(line || card.isJob) && <>
                  {line && <span title={card.isJob ? [...urls, ...paths, process, first.job_id && `작업 ID ${first.job_id}`].filter(Boolean).join("\n") : [first.url, first.description].filter(Boolean).join("\n") || undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{line}</span>}
                  {card.isJob && <>
                    {line && <Sep />}
                    <CountText unit="기록" matched={card.matched.size} total={card.events.length} />
                  </>}
                </>} />
              {card.isJob && job && (
                <PillRow>
                  {transfer && bytesText(transfer) && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12, marginRight: 4 }}>{bytesText(transfer)}</span>}
                  {Number(job.job_completed_count) > 0 && <Pill color="var(--success)">완료</Pill>}
                  {Number(job.job_cancelled_count) > 0 && <Pill>취소</Pill>}
                  {failures > 0 && <Pill color="var(--danger)">오류 {failures}</Pill>}
                </PillRow>
              )}
              <TimeSpan from={span.from} to={span.to} />
            </CardShell>
          );
        })}
        {cards.length > 0 && <PaginationControls ariaLabel="BITS 항목 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
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
