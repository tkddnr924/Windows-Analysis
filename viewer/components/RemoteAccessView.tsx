"use client";
// 원격 접근 이력 (docs-08) — _OVERVIEW RemoteDesktopHistory 전량과 저장된
// RemoteAccessSegments로 묶는다. 구간이 없는 이벤트는 시간·주소로 합치지 않는다.
import { useMemo, useState } from "react";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import HelpOutlineOutlinedIcon from "@mui/icons-material/HelpOutlineOutlined";
import LoginOutlinedIcon from "@mui/icons-material/LoginOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PublicOutlinedIcon from "@mui/icons-material/PublicOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, ViewHeader } from "@/components/FilterControls";
import { CardMain, CardShell, CountText, DirectionMark, EventRow, NoMatch, Pill, PillRow, Sep, TimeCell, TimeSpan, evidenceTime, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_FILTER, DIRECTION_LABELS, FACET_VALUE, ID_SPACE_LABELS, SCOPE_LABELS, STAGE_LABELS, buildGroups, facetCounts, hostCandidates, label, type RemoteFacet, type RemoteFilter } from "@/lib/remoteAccess";
import { DIRECTION_COLOR, RESULT_COLOR, facetOptions, resultColor, rowidOf, timeSpan, valueLabels } from "@/lib/eventCards";
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

const COMPANIONS = ["RemoteAccessSegments"];

export default function RemoteAccessView({ fileName, dbPath, data, hostDir, ipHosts = {}, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<RemoteFilter>(DEFAULT_FILTER);
  const [selected, setSelected] = useState<Row | null>(null);
  const cardState = useCardState([filter, timeRange]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<RemoteFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const companion = useCompanionTables(dbPath, COMPANIONS);
  const segments = useMemo(() => new Map((companion.tables.RemoteAccessSegments?.rows ?? []).map((row) => [row.segment_id, row])), [companion.tables.RemoteAccessSegments]);

  const periodSet = Boolean(timeRange.start || timeRange.end);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const groups = useMemo(() => buildGroups(data.rows, segments, filter, inPeriod, periodSet), [data.rows, segments, filter, inPeriod, periodSet]);
  const matchedEvents = groups.reduce((sum, group) => sum + group.matched.size, 0);
  // Options are the stored values (plus current selections); counts follow every other condition and the period.
  const labels = useMemo(() => ({
    results: valueLabels(data.rows, FACET_VALUE.results),
    directions: valueLabels(data.rows, FACET_VALUE.directions, (value) => label(DIRECTION_LABELS, value)),
    scopes: valueLabels(data.rows, FACET_VALUE.scopes, (value) => label(SCOPE_LABELS, value)),
    logonTypes: valueLabels(data.rows, FACET_VALUE.logonTypes),
    accounts: valueLabels(data.rows, FACET_VALUE.accounts, (value, row) => [resolveAccountDisplay(row.account ?? "", accountDirectory) || row.account || value, row.account_domain].filter(Boolean).join(" · "), "(계정 없음)"),
  }), [data.rows, accountDirectory]);
  const option = (facet: RemoteFacet, colors?: Record<string, string>) => facetOptions(labels[facet], facetCounts(data.rows, filter, facet, inPeriod, periodSet), filter[facet], colors);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={DesktopWindowsOutlinedIcon} title="원격 접근 이력 (RDP)" meta={`묶음 ${groups.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()}`}
        right={loadErrorNote(companion.failed, "구간 정보를 불러오지 못했습니다")}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="주소 · 컴퓨터 · 계정 · SID · 설명" ariaLabel="원격 접근 검색" width={300} />
        <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={option("results", RESULT_COLOR)} selected={filter.results} onChange={(results) => update({ results })} />
        <MultiSelectDropdown icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />} label="방향" ariaLabel="방향" options={option("directions", DIRECTION_COLOR)} selected={filter.directions} onChange={(directions) => update({ directions })} />
        <MultiSelectDropdown icon={<PublicOutlinedIcon sx={{ fontSize: 15 }} />} label="범위" ariaLabel="접근 범위" options={option("scopes")} selected={filter.scopes} onChange={(scopes) => update({ scopes })} />
        <MultiSelectDropdown icon={<LoginOutlinedIcon sx={{ fontSize: 15 }} />} label="로그온 유형" ariaLabel="로그온 유형" options={option("logonTypes")} selected={filter.logonTypes} onChange={(logonTypes) => update({ logonTypes })} />
        <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={option("accounts")} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />
      </ViewHeader>

      <div role="list" aria-label="원격 접근 묶음" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {groups.length === 0 && <NoMatch total={data.rows.length} />}
        {groups.map((group) => {
          const segment = group.segment;
          const first = group.events[0];
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
          const span = timeSpan(group.events);
          const firstTime = segment?.first_observed_time || span.from;
          const lastTime = segment?.last_observed_time || span.to;
          return (
            <CardShell key={group.key} listItem label={`${address || "주소 없음"} ${source}`} tone={dirColor} mark={<DirectionMark direction={direction} fallback={HelpOutlineOutlinedIcon} title={label(DIRECTION_LABELS, direction)} />}
              expandable open={cardState.isOpen(group.key)} onActivate={() => cardState.toggle(group.key)} regionLabel="묶음 이벤트"
              body={group.events.map((event, index) => {
                const color = resultColor(event.result);
                return (
                  <EventRow key={event.record_id} row={event} index={index} matched={group.matched.has(event.record_id)} bookmarks={bookmarks} onOpen={() => setSelected(event)} openLabel={`${evidenceTime(event.timestamp)} ${event.description || "이벤트"} 상세 보기`}>
                    <TimeCell value={event.timestamp} text={evidenceTime(event.timestamp)} />
                    <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: color }} />
                    <span style={{ flexShrink: 0, width: 28, fontSize: 11.5, fontWeight: 700, color }}>{event.result}</span>
                    <span style={{ flexShrink: 0, width: 72, fontSize: 11.5, color: "var(--text-dim)" }}>{label(STAGE_LABELS, event.stage)}</span>
                    <span title={event.description} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.description}</span>
                    {event.account && event.account !== accountRaw && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12 }}>{resolveAccountDisplay(event.account, accountDirectory) || event.account}</span>}
                    <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>{event.event_id}</span>
                  </EventRow>
                );
              })}>
              {/* No stored address (e.g. LOCAL console) → the account leads. */}
              <CardMain wrap
                title={<>
                  {address
                    ? <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{address}</span>
                    : accountText && <span style={{ fontSize: 13.5, fontWeight: 700 }}>{accountText}</span>}
                  {candidates.map((host) => <span key={host.id} title="등록 호스트 후보" style={{ fontSize: 12, fontWeight: 700, color: "var(--host-registered-text)" }}>{host.name}</span>)}
                </>}
                sub={<>
                  {address && accountText && <>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{accountText}</span>
                    <Sep />
                  </>}
                  <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>{source}</span>
                  <Sep />
                  <CountText unit="이벤트" matched={group.matched.size} total={group.events.length} />
                </>} />
              <PillRow>
                {(direction === "inbound" || direction === "outbound") && <Pill color={dirColor}>{label(DIRECTION_LABELS, direction)}</Pill>}
                {scope === "local" && <Pill>{label(SCOPE_LABELS, scope)}</Pill>}
                {[...matchedByResult.entries()].map(([result, count]) => <Pill key={result} color={resultColor(result)}>{result || "(없음)"} {count}</Pill>)}
                {Number(segment?.reconnect_count) > 0 && <Pill>재연결 {segment?.reconnect_count}</Pill>}
                {Number(segment?.disconnect_count) > 0 && <Pill>끊김 {segment?.disconnect_count}</Pill>}
                {segment?.identity_varied && <Pill color="var(--warning)" title={segment.identity_varied}>식별값 변동</Pill>}
              </PillRow>
              <TimeSpan from={firstTime} to={lastTime} format={evidenceTime} />
            </CardShell>
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
