"use client";
// SMB 접속 이력 (docs-09) — _OVERVIEW SmbHistory 전량을 저장된 상대 주소로 묶고,
// 관련 기록·환경은 접속 건수와 분리된 탭으로 보여 준다.
import { useContext, useMemo, useState } from "react";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import { HeaderSearchInput, MultiSelectDropdown, ViewHeader } from "@/components/FilterControls";
import { CardMain, CardShell, CountText, DirectionMark, EventRow, NoMatch, Pill, PillRow, Sep, TimeCell, TimeSpan, evidenceTime, loadErrorNote, useCardState, useCompanionTables, type Bookmarks } from "@/components/EventCards";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, type TimeRange } from "@/lib/timeRange";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { hostCandidates } from "@/lib/remoteAccess";
import { DEFAULT_SMB_FILTER, SMB_DIRECTION_LABELS, SMB_FACET_VALUE, buildContextItems, buildSmbGroups, groupShares, smbFacetCounts, type SmbFacet, type SmbFilter } from "@/lib/smbHistory";
import { DIRECTION_COLOR, RESULT_COLOR, facetOptions, resultColor, rowidOf, timeSpan, valueLabels } from "@/lib/eventCards";
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

const COMPANIONS = ["SmbContext", "SmbRelations", "SmbEnvironment"];
const EMPTY: CsvData = { columns: [], rows: [], rowCount: 0 };

const tabButton = (selected: boolean): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "4px 10px", borderRadius: "var(--radius)", border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`, background: selected ? "var(--accent-subtle)" : "var(--bg-elevated)", color: selected ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 12, fontWeight: selected ? 700 : 500 });

/** Display name (directory-resolved, else UPN/SID when nameless) · domain (R03). */
function accountText(row: Row, directory?: AccountDirectory): string {
  const name = resolveAccountDisplay(row.account ?? "", directory) || row.account || row.account_upn || row.account_sid || "";
  return [name, row.account_domain].filter(Boolean).join(" · ");
}

export default function SmbHistoryView({ fileName, dbPath, data, hostDir, ipHosts = {}, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const outerScope = useContext(RecordScopeContext);
  const [tab, setTab] = useState<Tab>("access");
  const [filter, setFilter] = useState<SmbFilter>(DEFAULT_SMB_FILTER);
  const [selected, setSelected] = useState<{ row: Row; table: "SmbHistory" | "SmbContext" } | null>(null);
  const cardState = useCardState([filter, timeRange]);
  const bookmarks: Bookmarks = { bookmarkedRowids, onToggleBookmark };
  const update = (patch: Partial<SmbFilter>) => setFilter((previous) => ({ ...previous, ...patch }));

  const companion = useCompanionTables(dbPath, COMPANIONS);
  const context = companion.tables.SmbContext ?? EMPTY;
  const relations = companion.tables.SmbRelations ?? EMPTY;
  const environment = companion.tables.SmbEnvironment ?? EMPTY;

  const periodSet = Boolean(timeRange.start || timeRange.end);
  const inPeriod = useMemo(() => (timestamp: string) => inRange(timestamp, timeRange), [timeRange]);
  const groups = useMemo(() => buildSmbGroups(data.rows, filter, inPeriod, periodSet), [data.rows, filter, inPeriod, periodSet]);
  const matchedEvents = groups.reduce((sum, group) => sum + group.matched.size, 0);
  const contextItems = useMemo(() => buildContextItems(data.rows, context.rows, relations.rows, inPeriod, periodSet), [data.rows, context.rows, relations.rows, inPeriod, periodSet]);
  const accountLabel = (row: Row) => accountText(row, accountDirectory);
  // Options are the stored values (plus current selections); counts follow every other condition and the period.
  const labels = useMemo(() => ({
    results: valueLabels(data.rows, SMB_FACET_VALUE.results),
    directions: valueLabels(data.rows, SMB_FACET_VALUE.directions, (value) => SMB_DIRECTION_LABELS[value] ?? value),
    accounts: valueLabels(data.rows, SMB_FACET_VALUE.accounts, (value, row) => accountText(row, accountDirectory) || value, "(계정 없음)"),
  }), [data.rows, accountDirectory]);
  const option = (facet: SmbFacet, colors?: Record<string, string>) => facetOptions(labels[facet], smbFacetCounts(data.rows, filter, facet, inPeriod, periodSet), filter[facet], colors);

  // Tab badges count what each panel renders under the current conditions.
  const tabs: [Tab, string, number][] = [["access", "접속", matchedEvents], ["context", "관련 기록", contextItems.length], ["environment", "환경", environment.rows.length]];
  const meta = tab === "access" ? `묶음 ${groups.length.toLocaleString()} · 일치 이벤트 ${matchedEvents.toLocaleString()}`
    : tab === "context" ? `${contextItems.length.toLocaleString()}건` : `${environment.rows.length.toLocaleString()}건`;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={DnsOutlinedIcon} title="SMB 접속 이력" meta={meta} right={loadErrorNote(companion.failed)}>
        {tab === "access" && <>
          <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="주소 · 공유 · 파일 · 권한 · 계정 · SID · EID" ariaLabel="SMB 접속 이력 검색" width={300} />
          <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="결과" ariaLabel="결과" options={option("results", RESULT_COLOR)} selected={filter.results} onChange={(results) => update({ results })} />
          <MultiSelectDropdown icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />} label="방향" ariaLabel="방향" options={option("directions", DIRECTION_COLOR)} selected={filter.directions} onChange={(directions) => update({ directions })} />
          <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={option("accounts")} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />
        </>}
      </ViewHeader>

      <div role="tablist" aria-label="SMB 기록 유형" style={{ flexShrink: 0, display: "flex", gap: 6, padding: "10px 14px 0", flexWrap: "wrap" }}>
        {tabs.map(([key, title, total]) => (
          <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => setTab(key)} style={tabButton(tab === key)}>{title} {total.toLocaleString()}</button>
        ))}
      </div>

      <div role="tabpanel" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {tab === "access" && <div role="list" aria-label="SMB 상대 주소 묶음">
          {groups.length === 0 && <NoMatch total={data.rows.length} />}
          {groups.map((group) => {
            const directions = new Map<string, number>();
            for (const event of group.events) if (event.direction === "inbound" || event.direction === "outbound") directions.set(event.direction, (directions.get(event.direction) ?? 0) + 1);
            const single = directions.size === 1 ? [...directions.keys()][0] : "";
            const candidates = hostCandidates(group.address, ipHosts);
            const accounts = [...new Set(group.events.map(accountLabel).filter(Boolean))];
            const shares = groupShares(group);
            const smbConfirmed = group.events.some((event) => event.protocol === "smb");
            const matchedByResult = new Map<string, number>();
            for (const event of group.events) if (group.matched.has(event.record_id)) matchedByResult.set(event.result ?? "", (matchedByResult.get(event.result ?? "") ?? 0) + 1);
            const span = timeSpan(group.events);
            const groupAccount = accounts.length === 1 ? accounts[0] : "";
            return (
              <CardShell key={group.key} listItem label={group.address || groupAccount || "SMB 기록"} tone={DIRECTION_COLOR[single] ?? "var(--text-faint)"} mark={<DirectionMark direction={single} fallback={DnsOutlinedIcon} />}
                expandable open={cardState.isOpen(group.key)} onActivate={() => cardState.toggle(group.key)} regionLabel="묶음 이벤트"
                body={group.events.map((event, index) => {
                  const eventAccount = accountLabel(event);
                  const color = resultColor(event.result);
                  return (
                    <EventRow key={event.record_id} row={event} index={index} matched={group.matched.has(event.record_id)} bookmarks={bookmarks} onOpen={() => setSelected({ row: event, table: "SmbHistory" })} openLabel={`${evidenceTime(event.timestamp)} ${event.description || "이벤트"} 상세 보기`}>
                      <TimeCell value={event.timestamp} text={evidenceTime(event.timestamp)} />
                      <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: color }} />
                      <span style={{ flexShrink: 0, width: 28, fontSize: 11.5, fontWeight: 700, color }}>{event.result}</span>
                      <span title={event.description} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.description}</span>
                      {event.share_name && <span title={[event.share_name, event.target_file].filter(Boolean).join(" ")} style={{ flexShrink: 1, minWidth: 0, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }}>{[event.share_name, event.target_file].filter(Boolean).join(" ")}</span>}
                      {event.workstation_name && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{event.workstation_name}</span>}
                      {eventAccount && eventAccount !== groupAccount && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12 }}>{eventAccount}</span>}
                      <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>{event.event_id}</span>
                    </EventRow>
                  );
                })}>
                <CardMain wrap
                  title={<>
                    {group.address
                      ? <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{group.address}</span>
                      : <span style={{ fontSize: 13.5, fontWeight: 700 }}>{groupAccount || group.events[0].description}</span>}
                    {candidates.map((host) => <Pill key={host.id} color="var(--accent)" title="등록 호스트">{host.name}</Pill>)}
                  </>}
                  sub={<>
                    {group.address && accounts.length > 0 && <>
                      <span title={accounts.join(", ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{accounts.join(", ")}</span>
                      <Sep />
                    </>}
                    {shares.length > 0 && <>
                      <span title={shares.join(", ")} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{shares.join(", ")}</span>
                      <Sep />
                    </>}
                    <CountText unit="이벤트" matched={group.matched.size} total={group.events.length} />
                  </>} />
                <PillRow>
                  {[...directions.entries()].map(([direction, count]) => <Pill key={direction} color={DIRECTION_COLOR[direction]}>{SMB_DIRECTION_LABELS[direction]}{directions.size > 1 ? ` ${count}` : ""}</Pill>)}
                  {smbConfirmed && <Pill color="var(--accent)">SMB</Pill>}
                  {[...matchedByResult.entries()].map(([result, count]) => <Pill key={result} color={resultColor(result)}>{result || "(없음)"} {count}</Pill>)}
                </PillRow>
                <TimeSpan from={span.from} to={span.to} format={evidenceTime} />
              </CardShell>
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
