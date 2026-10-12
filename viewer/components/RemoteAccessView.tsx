"use client";
// 원격 접근 이력 (docs-08) — _OVERVIEW RemoteDesktopHistory 전량과 저장된
// RemoteAccessSegments로 묶는다. 구간이 없는 이벤트는 시간·주소로 합치지 않는다.
import { useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CallMadeIcon from "@mui/icons-material/CallMade";
import CallReceivedIcon from "@mui/icons-material/CallReceived";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import HelpOutlineOutlinedIcon from "@mui/icons-material/HelpOutlineOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import LoginOutlinedIcon from "@mui/icons-material/LoginOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PublicOutlinedIcon from "@mui/icons-material/PublicOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, ViewHeader } from "@/components/FilterControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, formatEvidenceTimestamp, inRange, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_FILTER, DIRECTION_LABELS, ID_SPACE_LABELS, SCOPE_LABELS, STAGE_LABELS, accountKeyOf, buildGroups, hostCandidates, label, resultCounts, type RemoteFilter } from "@/lib/remoteAccess";
import RowDetailPanel from "./RowDetailPanel";

type Row = Record<string, string>;
type HostRef = { id: string; name: string };

interface Props {
  fileName: string;
  /** _OVERVIEW/RemoteDesktopHistory.sqlite */
  dbPath: string;
  /** Full stored event table (docs-08 keeps full load). */
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

const DIRECTION_COLOR: Record<string, string> = { inbound: "#f2a86f", outbound: "#9b7ef8" };
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)", 정보: "var(--text-faint)" };
const rowidOf = (row: Row) => Number((row as Record<string, unknown>).__rowid);

function Pill({ color, children, title }: { color: string; children: React.ReactNode; title?: string }) {
  return <span title={title} style={{ flexShrink: 0, color, fontSize: 11.5, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 14%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}

function DirectionMark({ direction }: { direction: string }) {
  const color = DIRECTION_COLOR[direction] ?? "var(--text-faint)";
  const Icon = direction === "inbound" ? CallReceivedIcon : direction === "outbound" ? CallMadeIcon : HelpOutlineOutlinedIcon;
  return <span aria-hidden="true" title={label(DIRECTION_LABELS, direction)} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 16%, transparent)` }}><Icon sx={{ fontSize: 17, color }} /></span>;
}

const time = (value: string | undefined) => (value ? formatEvidenceTimestamp(value) : "시각 미상");

export default function RemoteAccessView({ fileName, dbPath, data, hostDir, ipHosts = {}, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<RemoteFilter>(DEFAULT_FILTER);
  const [segments, setSegments] = useState<Map<string, Row>>(new Map());
  const [segmentError, setSegmentError] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Row | null>(null);
  const update = (patch: Partial<RemoteFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  useEffect(() => {
    let alive = true;
    setSegmentError(false);
    window.api.readResultFile(dbPath, "RemoteAccessSegments")
      .then((result) => { if (alive) setSegments(new Map(result.rows.map((row) => [row.segment_id, row]))); })
      .catch(() => { if (alive) { setSegments(new Map()); setSegmentError(true); } });
    return () => { alive = false; };
  }, [dbPath]);
  // Expansion keys belong to one result generation (R16).
  useEffect(() => setExpanded(new Set()), [data]);

  const periodSet = Boolean(timeRange.start || timeRange.end);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const groups = useMemo(() => buildGroups(data.rows, segments, filter, inPeriod, periodSet), [data.rows, segments, filter, inPeriod, periodSet]);
  const counts = useMemo(() => resultCounts(data.rows, filter, inPeriod, periodSet), [data.rows, filter, inPeriod, periodSet]);
  const matchedEvents = groups.reduce((sum, group) => sum + group.matched.size, 0);
  const option = (values: (string | undefined)[], labels?: Record<string, string>) => {
    const tally = new Map<string, number>();
    for (const value of values) tally.set(value ?? "", (tally.get(value ?? "") ?? 0) + 1);
    return [...tally.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([value, count]) => ({ value, label: value ? labels?.[value] ?? value : "(없음)", count }));
  };
  const accountOptions = useMemo(() => {
    const byKey = new Map<string, { label: string; count: number }>();
    for (const row of data.rows) {
      const key = accountKeyOf(row);
      const entry = byKey.get(key) ?? { label: key ? [resolveAccountDisplay(row.account ?? "", accountDirectory) || row.account || key, row.account_domain].filter(Boolean).join(" · ") : "(계정 없음)", count: 0 };
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

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={DesktopWindowsOutlinedIcon} title="원격 접근 이력 (RDP)" meta={`묶음 ${groups.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()}`}
        right={segmentError ? <span role="alert" style={{ color: "var(--warning)", fontSize: 11.5 }}>구간 정보를 불러오지 못했습니다</span> : undefined}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="주소 · 컴퓨터 · 계정 · SID · 설명" ariaLabel="원격 접근 검색" width={300} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).map(([value, count]) => ({ value, label: value || "(없음)", count, color: RESULT_COLOR[value] }))} selected={filter.results} onChange={(results) => update({ results })} />
        <MultiSelectDropdown icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />} label="방향" ariaLabel="방향" options={["inbound", "outbound"].map((value) => ({ value, label: DIRECTION_LABELS[value], count: data.rows.filter((row) => row.direction === value).length, color: DIRECTION_COLOR[value] }))} selected={filter.directions} onChange={(directions) => update({ directions })} />
        <MultiSelectDropdown icon={<PublicOutlinedIcon sx={{ fontSize: 15 }} />} label="범위" ariaLabel="접근 범위" options={["remote", "local"].map((value) => ({ value, label: SCOPE_LABELS[value], count: data.rows.filter((row) => row.access_scope === value).length }))} selected={filter.scopes} onChange={(scopes) => update({ scopes })} />
        <MultiSelectDropdown icon={<LoginOutlinedIcon sx={{ fontSize: 15 }} />} label="로그온 유형" ariaLabel="로그온 유형" options={option(data.rows.map((row) => row.logon_type))} selected={filter.logonTypes} onChange={(logonTypes) => update({ logonTypes })} />
        <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />
      </ViewHeader>

      <div role="list" aria-label="원격 접근 묶음" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {groups.length === 0 && <div role="status" style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {groups.map((group) => {
          const open = expanded.has(group.key);
          const segment = group.segment;
          const first = group.events[0];
          const last = group.events[group.events.length - 1];
          const direction = segment?.direction ?? first.direction ?? "";
          const scope = segment?.access_scope ?? first.access_scope ?? "";
          const address = segment?.remote_address || group.events.find((event) => event.remote_address)?.remote_address || "";
          const candidates = hostCandidates(address, ipHosts);
          const accountRaw = segment?.account || group.events.find((event) => event.account)?.account || "";
          const accountText = resolveAccountDisplay(accountRaw, accountDirectory) || accountRaw;
          const dirColor = DIRECTION_COLOR[direction] ?? "var(--text-faint)";
          const matchedByResult = new Map<string, number>();
          for (const event of group.events) if (group.matched.has(event.record_id)) matchedByResult.set(event.result ?? "", (matchedByResult.get(event.result ?? "") ?? 0) + 1);
          const source = segment ? `${label(ID_SPACE_LABELS, segment.id_space)} ${segment.id_value ?? ""}`.trim() : "단독 이벤트";
          const firstTime = segment?.first_observed_time || first.timestamp;
          const lastTime = segment?.last_observed_time || last.timestamp;
          return (
            <section role="listitem" key={group.key} aria-label={`${address || "주소 없음"} ${source}`} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${dirColor} 48%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <button type="button" onClick={() => toggle(group.key)} aria-expanded={open}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent"; }}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                <DirectionMark direction={direction} />
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  {/* No stored address (e.g. LOCAL console) → the account leads. */}
                  <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, flexWrap: "wrap" }}>
                    {address
                      ? <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{address}</span>
                      : accountText && <span style={{ fontSize: 13.5, fontWeight: 700 }}>{accountText}</span>}
                    {candidates.map((host) => <span key={host.id} title="등록 호스트 후보" style={{ fontSize: 12, fontWeight: 700, color: "var(--host-registered-text)" }}>{host.name}</span>)}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    {address && accountText && <>
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{accountText}</span>
                      <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    </>}
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>{source}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {group.matched.size === group.events.length ? group.events.length : `${group.matched.size} / ${group.events.length}`}</span>
                  </span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end" }}>
                  {(direction === "inbound" || direction === "outbound") && <Pill color={dirColor}>{label(DIRECTION_LABELS, direction)}</Pill>}
                  {scope === "local" && <Pill color="var(--text-dim)">{label(SCOPE_LABELS, scope)}</Pill>}
                  {[...matchedByResult.entries()].map(([result, count]) => <Pill key={result} color={RESULT_COLOR[result] ?? "var(--text-faint)"}>{result || "(없음)"} {count}</Pill>)}
                  {Number(segment?.reconnect_count) > 0 && <Pill color="var(--text-dim)">재연결 {segment?.reconnect_count}</Pill>}
                  {Number(segment?.disconnect_count) > 0 && <Pill color="var(--text-dim)">끊김 {segment?.disconnect_count}</Pill>}
                  {segment?.identity_varied && <Pill color="var(--warning)" title={segment.identity_varied}>식별값 변동</Pill>}
                </span>
                <span style={{ flexShrink: 0, color: firstTime ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {time(firstTime)}{lastTime && lastTime !== firstTime && <><span style={{ color: "var(--text-faint)" }}> → </span>{firstTime && lastTime.slice(0, 10) === firstTime.slice(0, 10) ? time(lastTime).slice(11) : time(lastTime)}</>}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label="묶음 이벤트" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {group.events.map((event, index) => {
                    const rowid = rowidOf(event);
                    const bookmarked = Number.isSafeInteger(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                    const matched = group.matched.has(event.record_id);
                    return (
                      <div key={event.record_id} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(event)}
                        onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
                        onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
                        style={{ display: "flex", alignItems: "center", gap: 10, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", fontSize: 13, cursor: "pointer", opacity: matched ? 1 : 0.55 }}>
                        <button type="button" onClick={(e) => { e.stopPropagation(); setSelected(event); }} aria-label={`${time(event.timestamp)} ${event.description || "이벤트"} 상세 보기`}
                          style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: "inherit" }}>
                          <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: event.timestamp ? "var(--text-time)" : "var(--text-faint)", width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{time(event.timestamp)}</span>
                          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[event.result] ?? "var(--text-faint)" }} />
                          <span style={{ flexShrink: 0, width: 28, fontSize: 11.5, fontWeight: 700, color: RESULT_COLOR[event.result] ?? "var(--text-faint)" }}>{event.result}</span>
                          <span style={{ flexShrink: 0, width: 72, fontSize: 11.5, color: "var(--text-dim)" }}>{label(STAGE_LABELS, event.stage)}</span>
                          <span title={event.description} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.description}</span>
                          {event.account && event.account !== accountRaw && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12 }}>{resolveAccountDisplay(event.account, accountDirectory) || event.account}</span>}
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
      </div>

      {selected && (
        <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={fileName} hostDir={hostDir}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(rowidOf(selected)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(rowidOf(selected)) : undefined} />
      )}
    </div>
  );
}
