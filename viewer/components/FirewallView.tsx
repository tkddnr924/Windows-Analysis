"use client";
// 방화벽 이력 (docs-14) — _OVERVIEW FirewallHistory 전량(전량 로드 예외)을 저장된
// rule_id 카드로 묶는다. 규칙 없는 사건은 레코드 1건 카드. 미확인 이벤트 의미는
// 저장된 event_type 그대로 두고 추가/변경/삭제를 만들지 않는다.
import { useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import BlockOutlinedIcon from "@mui/icons-material/BlockOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import PowerSettingsNewOutlinedIcon from "@mui/icons-material/PowerSettingsNewOutlined";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_FIREWALL_FILTER, buildFirewallCards, ruleDisplayName, type FirewallCard, type FirewallFilter } from "@/lib/firewallHistory";
import RowDetailPanel from "./RowDetailPanel";

const TABLE = "FirewallHistory";
const PAGE = 10;
const EVENT_PAGE = 10;

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

function Pill({ title, children }: { title?: string; children: React.ReactNode }) {
  return <span title={title} style={{ flexShrink: 0, color: "var(--text-dim)", fontWeight: 700, fontSize: 11.5, padding: "1px 7px", borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 15%, transparent)", whiteSpace: "nowrap" }}>{children}</span>;
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
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [selected, setSelected] = useState<Row | null>(null);
  const update = (patch: Partial<FirewallFilter>) => setFilter((previous) => ({ ...previous, ...patch }));
  useEffect(() => { setExpanded(new Set()); setEventPages({}); }, [data]);

  const rangeOn = rangeActive(timeRange);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const cards = useMemo(() => buildFirewallCards(data.rows, filter, inPeriod, rangeOn, sortDir), [data.rows, filter, inPeriod, rangeOn, sortDir]);
  useEffect(() => setPage(0), [filter, rangeOn, timeRange, sortDir]);
  const matchedEvents = cards.reduce((sum, card) => sum + card.matched.size, 0);
  const ruleCount = cards.filter((card) => card.isRule).length;

  const kindOptions = useMemo(() => optionsOf(data.rows, (row) => row.event_type ?? ""), [data.rows]);
  const directionOptions = useMemo(() => optionsOf(data.rows, (row) => row.direction ?? ""), [data.rows]);
  const actionOptions = useMemo(() => optionsOf(data.rows, (row) => row.action ?? ""), [data.rows]);
  const protocolOptions = useMemo(() => optionsOf(data.rows, (row) => row.protocol_number ?? "", (value, row) => (row.protocol ? `${row.protocol} (${value})` : value)), [data.rows]);

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
  const actorTitle = (row: Row) => [row.account && `변경 주체 ${row.account}`, row.account_sid, row.modifying_app && `변경 앱 ${row.modifying_app}`, row.description].filter(Boolean).join("\n") || undefined;

  const eventRow = (card: FirewallCard<Row>, row: Row, position: number) => {
    const bookmarked = bookmarkedRowids?.has(rowidOf(row)) ?? false;
    const text = row.rule_id ? ruleSummary(row) : eventSummary(row);
    return (
      <div key={row.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(row)}
        onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
        style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: position === 0 ? "none" : "1px solid var(--border-subtle)", cursor: "pointer", opacity: card.matched.has(row.record_id) ? 1 : 0.55 }}>
        <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(row); }} aria-label={`${row.timestamp} ${row.event_type} 상세 보기`} title={actorTitle(row)}
          style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{row.timestamp}</span>
          <span style={{ width: 130, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5 }}>{shortType(row.event_type)}</span>
          <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{text}</span>
          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{row.event_id}</span>
        </button>
        {bookmarkButton(row)}
      </div>
    );
  };

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
        {cards.length === 0 && <div role="status" style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {pageCards.map((card) => {
          const first = card.events[0];
          const last = card.events[card.events.length - 1];
          // Representative rule fields: latest event that carries a direction.
          const definition = [...card.events].reverse().find((row) => row.direction || row.action) ?? first;
          const rawName = card.isRule ? card.events.find((row) => row.rule_name)?.rule_name ?? "" : "";
          const name = card.isRule ? ruleDisplayName(rawName) || first.rule_id : first.event_type;
          const context = card.isRule ? definition.embedded_context : "";
          const app = appOf(definition) || definition.service;
          const line = card.isRule ? [app, ruleSummary(definition)].filter(Boolean).join(" · ") : [eventSummary(first) || (first.event_definition_state === "unconfirmed" ? payloadPairs(first.event_data_raw) : ""), first.account].filter(Boolean).join(" · ");
          const Icon = card.isRule ? SecurityOutlinedIcon : iconOf(first);
          const source = familyLabel(first);
          const typeCounts = new Map<string, number>();
          for (const row of card.events) if (card.matched.has(row.record_id)) typeCounts.set(shortType(row.event_type), (typeCounts.get(shortType(row.event_type)) ?? 0) + 1);
          const open = card.isRule && expanded.has(card.key);
          const bookmarked = !card.isRule && (bookmarkedRowids?.has(rowidOf(first)) ?? false);
          const eventPageCount = Math.max(1, Math.ceil(card.events.length / EVENT_PAGE));
          const eventPage = Math.min(eventPages[card.key] ?? 0, eventPageCount - 1);
          const pagedEvents = card.events.slice(eventPage * EVENT_PAGE, (eventPage + 1) * EVENT_PAGE);
          const from = first.timestamp;
          const to = card.isRule ? last.timestamp : "";
          const sameDay = to && to.slice(0, 10) === from.slice(0, 10);
          return (
            <section key={card.key} aria-label={name} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ marginBottom: 10, border: `1px solid ${open ? "color-mix(in srgb, var(--text-dim) 42%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center" }}>
                <button type="button" onClick={() => (card.isRule ? toggle(card.key) : setSelected(first))} aria-expanded={card.isRule ? open : undefined} aria-label={card.isRule ? undefined : `${name} 상세 보기`}
                  onMouseEnter={(event) => { if (!open && !bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = open ? "color-mix(in srgb, var(--text-dim) 6%, transparent)" : "transparent"; }}
                  style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 12, minHeight: line || card.isRule ? 60 : 46, padding: line || card.isRule ? "11px 14px" : "6px 14px", border: "none", background: open ? "color-mix(in srgb, var(--text-dim) 6%, transparent)" : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--text-dim) 15%, transparent)" }}>
                    <Icon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                      <span title={rawName !== name ? rawName : undefined} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700 }}>{name}</span>
                      {source && <span title={first.channel || undefined} style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5 }}>{source}</span>}
                      {context && context !== name && context !== rawName && <span style={{ flexShrink: 0, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 11.5 }}>{context}</span>}
                    </span>
                    {(line || card.isRule) && (
                      <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                        {line && <span title={card.isRule ? [definition.app_path !== app ? definition.app_path : "", definition.rule_id].filter(Boolean).join("\n") : actorTitle(first)} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{line}</span>}
                        {card.isRule && <>
                          {line && <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>}
                          <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>기록 {card.matched.size === card.events.length ? card.events.length.toLocaleString() : `${card.matched.size.toLocaleString()} / ${card.events.length.toLocaleString()}`}</span>
                        </>}
                      </span>
                    )}
                  </span>
                  {card.isRule && <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>{[...typeCounts].map(([type, count]) => <Pill key={type}>{type}{count > 1 ? ` ${count}` : ""}</Pill>)}</span>}
                  <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                    {from}{to && to !== from && <><span style={{ color: "var(--text-faint)" }}> → </span>{sameDay ? to.slice(11) : to}</>}
                  </span>
                  {card.isRule && <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />}
                </button>
                {!card.isRule && <span style={{ paddingRight: 10 }}>{bookmarkButton(first)}</span>}
              </div>
              {open && (
                <div role="region" aria-label="규칙 기록" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
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
          <PaginationControls ariaLabel="방화벽 항목 페이지" page={safePage} pageCount={pageCount} onChange={setPage}
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
