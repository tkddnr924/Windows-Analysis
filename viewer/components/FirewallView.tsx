"use client";
// 방화벽 이력 (docs-14) — _OVERVIEW FirewallHistory 전량(전량 로드 예외)을 저장된
// rule_id 카드로 묶는다. 규칙 없는 사건은 레코드 1건 카드. 미확인 이벤트 의미는
// 저장된 event_type 그대로 두고 추가/변경/삭제를 만들지 않는다.
import { useMemo, useState } from "react";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import BlockOutlinedIcon from "@mui/icons-material/BlockOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import PowerSettingsNewOutlinedIcon from "@mui/icons-material/PowerSettingsNewOutlined";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import { BookmarkButton, CardMain, CardName, CardShell, CountText, EventRow, IconTile, NoMatch, PagedEvents, Pill, PillRow, Sep, TimeCell, TimeSpan, isBookmarked, useCardState, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_FIREWALL_FILTER, buildFirewallCards, ruleDisplayName, type FirewallFilter } from "@/lib/firewallHistory";
import { chronological } from "@/lib/eventOrder";
import { optionsOf, pageWindow, rowidOf, timeSpan } from "@/lib/eventCards";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "FirewallHistory";
const TONE = "var(--text-dim)";

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

// Stored event_family → source log label.
const FAMILY_LABELS: Record<string, string> = {
  firewall_channel: "방화벽 로그", security_audit: "보안 로그", wfp_operational: "WFP 로그", ike_operational: "IKE 로그",
  connection_security_channel: "연결 보안 로그", connection_security_verbose_channel: "연결 보안 로그(상세)",
};
const familyLabel = (row: Row) => FAMILY_LABELS[row.event_family] ?? row.channel ?? "";

function iconOf(row: Row): React.ElementType {
  if (row.event_scope === "service_lifecycle_audit") return PowerSettingsNewOutlinedIcon;
  if (row.event_id === "2011") return BlockOutlinedIcon;
  if (row.event_family === "wfp_operational") return LanOutlinedIcon;
  return SecurityOutlinedIcon;
}

/** Stored payload as `name value` pairs (fallback when no typed column applies). */
function payloadPairs(raw: string): string {
  if (!raw) return "";
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "";
    return Object.entries(parsed).map(([key, value]) => `${key} ${typeof value === "object" ? JSON.stringify(value) : String(value)}`).join(" · ");
  } catch {
    return "";
  }
}

const shortType = (eventType: string) => eventType.replace(/^방화벽 이벤트 /, "이벤트 ");
const appOf = (row: Row) => row.app_path_resolved || row.app_path || "";
const protocolOf = (row: Row) => row.protocol || "";
const hasAddress = (value: string | undefined) => Boolean(value) && value !== "*";

/** Stored rule fields of one event as a short line (raw values only). */
function ruleSummary(row: Row): string {
  return [
    [row.direction, row.action].filter(Boolean).join(" "),
    protocolOf(row),
    row.local_ports && `로컬 ${row.local_ports}`,
    row.remote_ports && `원격 ${row.remote_ports}`,
    hasAddress(row.remote_addresses) && `원격 주소 ${row.remote_addresses}`,
    hasAddress(row.local_addresses) && `로컬 주소 ${row.local_addresses}`,
    row.profiles,
  ].filter(Boolean).join(" · ");
}

/** Non-rule event summary from stored columns. */
function eventSummary(row: Row): string {
  return [
    appOf(row),
    protocolOf(row) && [protocolOf(row), row.local_port || row.remote_port].filter(Boolean).join(" "),
    row.remote_address && `상대 ${row.remote_address}`,
    row.interface_name,
    row.old_profile && row.new_profile ? `${row.old_profile} → ${row.new_profile}` : row.new_profile,
    row.setting_type && [row.setting_type, row.setting_value_string].filter(Boolean).join(" = "),
    row.store_type && `Store Type ${row.store_type}`,
  ].filter(Boolean).join(" · ");
}

export default function FirewallView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<FirewallFilter>(DEFAULT_FIREWALL_FILTER);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange, sortDir]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<FirewallFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildFirewallCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);
  const ruleCount = cards.filter((card) => card.isRule).length;

  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const directionOptions = useMemo(() => optionsOf(data.rows, (row) => row.direction ?? ""), [data.rows]);
  const actionOptions = useMemo(() => optionsOf(data.rows, (row) => row.action ?? ""), [data.rows]);
  const protocolOptions = useMemo(() => optionsOf(data.rows, (row) => row.protocol_number ?? "", (value, row) => (row.protocol ? `${row.protocol} (${value})` : value)), [data.rows]);

  const list = pageWindow(cards.length, cardState.page);
  const actorTitle = (row: Row) => [row.account && `변경 주체 ${row.account}`, row.account_sid, row.modifying_app && `변경 앱 ${row.modifying_app}`, row.description].filter(Boolean).join("\n") || undefined;

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={SecurityOutlinedIcon} title="방화벽 이력" meta={`규칙 ${ruleCount.toLocaleString()} · 기타 ${(cards.length - ruleCount).toLocaleString()} · 일치 기록 ${matchedEvents.toLocaleString()} / ${data.rows.length.toLocaleString()}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="규칙 · 규칙 ID · 앱 · 포트 · 계정 · SID" ariaLabel="방화벽 이력 검색" width={300} />
        <MultiSelectDropdown icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={kindOptions} selected={filter.kinds} onChange={(kinds) => update({ kinds })} />
        <MultiSelectDropdown icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />} label="방향" ariaLabel="방향" options={directionOptions} selected={filter.directions} onChange={(directions) => update({ directions })} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="동작" ariaLabel="동작" options={actionOptions} selected={filter.actions} onChange={(actions) => update({ actions })} />
        <MultiSelectDropdown icon={<LanOutlinedIcon sx={{ fontSize: 15 }} />} label="프로토콜" ariaLabel="프로토콜" options={protocolOptions} selected={filter.protocols} onChange={(protocols) => update({ protocols })} />
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {cards.length === 0 && <NoMatch total={data.rows.length} />}
        {cards.slice(list.start, list.end).map((card) => {
          // Representatives and range follow time, not the display direction.
          const ordered = chronological(card.events);
          const first = ordered[0];
          // Representative rule fields: latest event that carries a direction.
          const definition = [...ordered].reverse().find((row) => row.direction || row.action) ?? first;
          const rawName = card.isRule ? ordered.find((row) => row.rule_name)?.rule_name ?? "" : "";
          const name = card.isRule ? ruleDisplayName(rawName) || first.rule_id : first.event_type;
          const context = card.isRule ? definition.embedded_context : "";
          const app = appOf(definition) || definition.service;
          const line = card.isRule ? [app, ruleSummary(definition)].filter(Boolean).join(" · ") : [eventSummary(first) || (first.event_definition_state === "unconfirmed" ? payloadPairs(first.event_data_raw) : ""), first.account].filter(Boolean).join(" · ");
          const source = familyLabel(first);
          const typeCounts = new Map<string, number>();
          for (const row of card.events) if (card.matched.has(row.record_id)) typeCounts.set(shortType(row.event_type), (typeCounts.get(shortType(row.event_type)) ?? 0) + 1);
          const span = timeSpan(card.events);
          return (
            <CardShell key={card.key} label={name} tone={TONE} mark={<IconTile icon={card.isRule ? SecurityOutlinedIcon : iconOf(first)} tone={TONE} />}
              expandable={card.isRule} open={card.isRule && cardState.isOpen(card.key)} onActivate={() => (card.isRule ? cardState.toggle(card.key) : setSelected(first))} buttonLabel={card.isRule ? undefined : `${name} 상세 보기`}
              bookmarked={!card.isRule && isBookmarked(first, bookmarks)} side={!card.isRule && <BookmarkButton row={first} bookmarks={bookmarks} />} compact={!line && !card.isRule} regionLabel="규칙 기록"
              body={<PagedEvents events={card.events} page={cardState.eventPage(card.key)} onPage={(next) => cardState.setEventPage(card.key, next)} label={`${name} 기록 페이지`}
                render={(row, index) => (
                  <EventRow key={row.record_id} row={row} index={index} matched={card.matched.has(row.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(row)} openLabel={`${row.timestamp} ${row.event_type} 상세 보기`} title={actorTitle(row)}>
                    <TimeCell value={row.timestamp} />
                    <span style={{ width: 130, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{shortType(row.event_type)}</span>
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{row.rule_id ? ruleSummary(row) : eventSummary(row)}</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
                  </EventRow>
                )} />}>
              <CardMain
                title={<>
                  <CardName title={rawName !== name ? rawName : undefined}>{name}</CardName>
                  {source && <span title={first.channel || undefined} style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{source}</span>}
                  {context && context !== name && context !== rawName && <span style={{ flexShrink: 0, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 11.5 }}>{context}</span>}
                </>}
                sub={(line || card.isRule) && <>
                  {line && <span title={card.isRule ? [definition.app_path !== app ? definition.app_path : "", definition.rule_id].filter(Boolean).join("\n") : actorTitle(first)} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{line}</span>}
                  {card.isRule && <>
                    {line && <Sep />}
                    <CountText unit="기록" matched={card.matched.size} total={card.events.length} />
                  </>}
                </>} />
              {card.isRule && <PillRow>{[...typeCounts].map(([type, count]) => <Pill key={type}>{type}{count > 1 ? ` ${count}` : ""}</Pill>)}</PillRow>}
              <TimeSpan from={span.from} to={span.to} />
            </CardShell>
          );
        })}
        {cards.length > 0 && <PaginationControls ariaLabel="방화벽 항목 페이지" page={list.page} pageCount={list.pageCount} onChange={cardState.setPage} summary={list.summary} />}
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
