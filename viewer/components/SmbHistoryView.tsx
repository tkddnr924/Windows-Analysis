"use client";
// SMB 접속 이력 (docs-09) — _OVERVIEW SmbHistory 전량을 저장된 상대 주소로 묶고,
// 관련 기록·로그 관측·환경은 접속 건수와 분리된 탭으로 보여 준다.
import { useContext, useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CallMadeIcon from "@mui/icons-material/CallMade";
import CallReceivedIcon from "@mui/icons-material/CallReceived";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, ViewHeader } from "@/components/FilterControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, formatEvidenceTimestamp, inRange, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { hostCandidates } from "@/lib/remoteAccess";
import { DEFAULT_SMB_FILTER, SMB_DIRECTION_LABELS, buildContextItems, buildSmbGroups, groupShares, smbResultCounts, type SmbFilter } from "@/lib/smbHistory";
import SmbEnvironmentPanel from "./SmbEnvironmentPanel";
import SmbContextPanel from "./SmbContextPanel";
import { RecordScopeContext } from "@/lib/recordScope";
import RowDetailPanel from "./RowDetailPanel";

type Row = Record<string, string>;
type HostRef = { id: string; name: string };
type Tab = "access" | "context" | "environment";

interface Props {
  fileName: string;
  /** _OVERVIEW/SmbHistory.sqlite */
  dbPath: string;
  /** Full stored event table (docs-09 keeps full load). */
  data: CsvData;
  hostDir?: string;
  /** Every registered host per IP (R14). */
  ipHosts?: Record<string, HostRef[]>;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

const EMPTY: CsvData = { columns: [], rows: [], rowCount: 0 };
const DIRECTION_COLOR: Record<string, string> = { inbound: "#f2a86f", outbound: "#9b7ef8" };
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)", 정보: "var(--text-faint)" };
const rowidOf = (row: Row) => Number((row as Record<string, unknown>).__rowid);
const time = (value: string | undefined) => (value ? formatEvidenceTimestamp(value) : "시각 미상");

const tabButton = (selected: boolean): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "4px 10px", borderRadius: "var(--radius)", border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`, background: selected ? "var(--accent-subtle)" : "var(--bg-elevated)", color: selected ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 12, fontWeight: selected ? 700 : 500 });

function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ flexShrink: 0, color, fontSize: 11.5, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 14%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}

/** Display name (directory-resolved, else UPN/SID when nameless) · domain (R03). */
function accountText(row: Row, directory?: AccountDirectory): string {
  const name = resolveAccountDisplay(row.account ?? "", directory) || row.account || row.account_upn || row.account_sid || "";
  return [name, row.account_domain].filter(Boolean).join(" · ");
}

function DirectionMark({ direction }: { direction: string }) {
  const color = DIRECTION_COLOR[direction] ?? "var(--text-faint)";
  const Icon = direction === "inbound" ? CallReceivedIcon : direction === "outbound" ? CallMadeIcon : DnsOutlinedIcon;
  return <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 16%, transparent)` }}><Icon sx={{ fontSize: 17, color }} /></span>;
}

export default function SmbHistoryView({ fileName, dbPath, data, hostDir, ipHosts = {}, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const outerScope = useContext(RecordScopeContext);
  const [tab, setTab] = useState<Tab>("access");
  const [filter, setFilter] = useState<SmbFilter>(DEFAULT_SMB_FILTER);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<{ row: Row; table: "SmbHistory" | "SmbContext" } | null>(null);
  const [context, setContext] = useState<CsvData>(EMPTY);
  const [relations, setRelations] = useState<CsvData>(EMPTY);
  const [environment, setEnvironment] = useState<CsvData>(EMPTY);
  const [loadError, setLoadError] = useState(false);
  const update = (patch: Partial<SmbFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  useEffect(() => {
    let alive = true;
    setLoadError(false);
    const load = (table: string, set: (value: CsvData) => void) => window.api.readResultFile(dbPath, table)
      .then((result) => { if (alive) set(result); })
      .catch(() => { if (alive) { set(EMPTY); setLoadError(true); } });
    void load("SmbContext", setContext);
    void load("SmbRelations", setRelations);
    void load("SmbEnvironment", setEnvironment);
    return () => { alive = false; };
  }, [dbPath]);
  useEffect(() => setExpanded(new Set()), [data]);

  const periodSet = Boolean(timeRange.start || timeRange.end);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const groups = useMemo(() => buildSmbGroups(data.rows, filter, inPeriod, periodSet), [data.rows, filter, inPeriod, periodSet]);
  const counts = useMemo(() => smbResultCounts(data.rows, filter, inPeriod, periodSet), [data.rows, filter, inPeriod, periodSet]);
  const matchedEvents = groups.reduce((sum, group) => sum + group.matched.size, 0);
  const contextItems = useMemo(() => buildContextItems(data.rows, context.rows, relations.rows, inPeriod, periodSet), [data.rows, context.rows, relations.rows, inPeriod, periodSet]);
  const accountLabel = (row: Row) => accountText(row, accountDirectory);
  const accountOptions = useMemo(() => {
    const byKey = new Map<string, { label: string; count: number }>();
    for (const row of data.rows) {
      const key = row.account_key ?? "";
      const entry = byKey.get(key) ?? { label: key ? accountText(row, accountDirectory) || key : "(계정 없음)", count: 0 };
      entry.count += 1;
      byKey.set(key, entry);
    }
    return [...byKey.entries()].sort(([, a], [, b]) => a.label.localeCompare(b.label)).map(([value, entry]) => ({ value, label: entry.label, count: entry.count }));
  }, [data.rows, accountDirectory]);

  const toggle = (key: string) => setExpanded((previous) => {
    const next = new Set(previous);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  const meta = tab === "access" ? `묶음 ${groups.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()}`
    : tab === "context" ? `${contextItems.length.toLocaleString()}건` : `${environment.rows.length.toLocaleString()}건`;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={DnsOutlinedIcon} title="SMB 접속 이력" meta={meta}
        right={loadError ? <span role="alert" style={{ color: "var(--warning)", fontSize: 11.5 }}>일부 표를 불러오지 못했습니다</span> : undefined}>
        {tab === "access" && <>
          <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="주소 · 공유 · 파일 · 권한 · 계정 · SID · EID" ariaLabel="SMB 접속 이력 검색" width={300} />
          <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).map(([value, count]) => ({ value, label: value || "(없음)", count, color: RESULT_COLOR[value] }))} selected={filter.results} onChange={(results) => update({ results })} />
          <MultiSelectDropdown icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />} label="방향" ariaLabel="방향" options={["inbound", "outbound"].map((value) => ({ value, label: SMB_DIRECTION_LABELS[value], count: data.rows.filter((row) => row.direction === value).length, color: DIRECTION_COLOR[value] }))} selected={filter.directions} onChange={(directions) => update({ directions })} />
          <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />
        </>}
      </ViewHeader>

      <div role="tablist" aria-label="SMB 기록 유형" style={{ flexShrink: 0, display: "flex", gap: 6, padding: "10px 14px 0", flexWrap: "wrap" }}>
        {([["access", "접속", data.rows.length], ["context", "관련 기록", context.rows.length], ["environment", "환경", environment.rows.length]] as const).map(([key, title, total]) => (
          <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => setTab(key)} style={tabButton(tab === key)}>{title} {total.toLocaleString()}</button>
        ))}
      </div>

      <div role="tabpanel" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {tab === "access" && <div role="list" aria-label="SMB 상대 주소 묶음">
          {groups.length === 0 && <div role="status" style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
          {groups.map((group) => {
            const open = expanded.has(group.key);
            const directions = new Map<string, number>();
            for (const event of group.events) if (event.direction === "inbound" || event.direction === "outbound") directions.set(event.direction, (directions.get(event.direction) ?? 0) + 1);
            const single = directions.size === 1 ? [...directions.keys()][0] : "";
            const dirColor = DIRECTION_COLOR[single] ?? "var(--text-faint)";
            const candidates = hostCandidates(group.address, ipHosts);
            const accounts = [...new Set(group.events.map(accountLabel).filter(Boolean))];
            const shares = groupShares(group);
            const smbConfirmed = group.events.some((event) => event.protocol === "smb");
            const matchedByResult = new Map<string, number>();
            for (const event of group.events) if (group.matched.has(event.record_id)) matchedByResult.set(event.result ?? "", (matchedByResult.get(event.result ?? "") ?? 0) + 1);
            const timed = group.events.filter((event) => event.timestamp);
            const firstTime = timed[0]?.timestamp ?? "";
            const lastTime = timed[timed.length - 1]?.timestamp ?? "";
            const groupAccount = accounts.length === 1 ? accounts[0] : "";
            return (
              <section role="listitem" key={group.key} aria-label={group.address || groupAccount || "SMB 기록"} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${dirColor} 48%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
                <button type="button" onClick={() => toggle(group.key)} aria-expanded={open}
                  onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent"; }}
                  style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                  <DirectionMark direction={single} />
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, flexWrap: "wrap" }}>
                      {group.address
                        ? <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{group.address}</span>
                        : <span style={{ fontSize: 13.5, fontWeight: 700 }}>{groupAccount || group.events[0].description}</span>}
                      {candidates.map((host) => <span key={host.id} title="등록 호스트 후보" style={{ fontSize: 12, fontWeight: 700, color: "var(--host-registered-text)" }}>{host.name}</span>)}
                    </span>
                    <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                      {group.address && accounts.length > 0 && <>
                        <span title={accounts.join(", ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{accounts.join(", ")}</span>
                        <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                      </>}
                      {shares.length > 0 && <>
                        <span title={shares.join(", ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{shares.join(", ")}</span>
                        <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                      </>}
                      <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {group.matched.size === group.events.length ? group.events.length : `${group.matched.size} / ${group.events.length}`}</span>
                    </span>
                  </span>
                  <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end" }}>
                    {[...directions.entries()].map(([direction, count]) => <Pill key={direction} color={DIRECTION_COLOR[direction]}>{SMB_DIRECTION_LABELS[direction]}{directions.size > 1 ? ` ${count}` : ""}</Pill>)}
                    {smbConfirmed && <Pill color="var(--accent)">SMB</Pill>}
                    {[...matchedByResult.entries()].map(([result, count]) => <Pill key={result} color={RESULT_COLOR[result] ?? "var(--text-faint)"}>{result || "(없음)"} {count}</Pill>)}
                  </span>
                  <span style={{ flexShrink: 0, color: firstTime ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                    {time(firstTime)}{lastTime && lastTime !== firstTime && <><span style={{ color: "var(--text-faint)" }}> → </span>{lastTime.slice(0, 10) === firstTime.slice(0, 10) ? time(lastTime).slice(11) : time(lastTime)}</>}
                  </span>
                  <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
                </button>
                {open && (
                  <div role="region" aria-label="묶음 이벤트" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                    {group.events.map((event, index) => {
                      const rowid = rowidOf(event);
                      const bookmarked = Number.isSafeInteger(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                      const matched = group.matched.has(event.record_id);
                      const eventAccount = accountLabel(event);
                      return (
                        <div key={event.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected({ row: event, table: "SmbHistory" })}
                          onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
                          onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
                          style={{ display: "flex", alignItems: "center", gap: 10, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", fontSize: 13, cursor: "pointer", opacity: matched ? 1 : 0.55 }}>
                          <button type="button" onClick={(e) => { e.stopPropagation(); setSelected({ row: event, table: "SmbHistory" }); }} aria-label={`${time(event.timestamp)} ${event.description || "이벤트"} 상세 보기`}
                            style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: "inherit" }}>
                            <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: event.timestamp ? "var(--text-time)" : "var(--text-faint)", width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{time(event.timestamp)}</span>
                            <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[event.result] ?? "var(--text-faint)" }} />
                            <span style={{ flexShrink: 0, width: 28, fontSize: 11.5, fontWeight: 700, color: RESULT_COLOR[event.result] ?? "var(--text-faint)" }}>{event.result}</span>
                            <span title={event.description} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.description}</span>
                            {event.share_name && <span title={[event.share_name, event.target_file].filter(Boolean).join(" ")} style={{ flexShrink: 1, minWidth: 0, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }}>{[event.share_name, event.target_file].filter(Boolean).join(" ")}</span>}
                            {event.workstation_name && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{event.workstation_name}</span>}
                            {eventAccount && eventAccount !== groupAccount && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12 }}>{eventAccount}</span>}
                            <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>{event.event_id}</span>
                          </button>
                          {onToggleBookmark && Number.isSafeInteger(rowid) && (
                            <button type="button" onClick={(e) => { e.stopPropagation(); onToggleBookmark(rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크"} title={bookmarked ? "북마크 해제" : "북마크에 추가"} className={bookmarked ? "dfir-bookmark-control" : undefined}
                              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", cursor: "pointer", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)" }}>
                              {bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            );
          })}
        </div>}

        {tab === "context" && <SmbContextPanel items={contextItems} accountText={accountLabel} onOpen={(row, table) => setSelected({ row, table })} />}

        {tab === "environment" && <SmbEnvironmentPanel rows={environment.rows} />}
      </div>

      {selected?.table === "SmbHistory" && (
        <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName={fileName} hostDir={hostDir}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowidOf(selected.row)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowidOf(selected.row)) : undefined} />
      )}
      {selected?.table === "SmbContext" && (
        <RecordScopeContext.Provider value={outerScope ? { ...outerScope, fullPath: dbPath, tableName: "SmbContext" } : { fullPath: dbPath, tableName: "SmbContext" }}>
          <RowDetailPanel row={selected.row} columns={context.columns} focusedColumn={null} fileBaseName="SmbContext" hostDir={hostDir}
            onClose={() => setSelected(null)}
            onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
            onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} />
        </RecordScopeContext.Provider>
      )}
    </div>
  );
}
