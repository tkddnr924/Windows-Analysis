"use client";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { formatEvidenceTimestamp, inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { tsMs } from "@/lib/viewShared";

const TABLE_NAME = "PowerShellHistory";
const SESSION_GAP_MS = 30 * 60 * 1000;

type PsKind = "스크립트 블록" | "파이프라인" | "명령 실행";

interface PsEvent {
  row: Record<string, string>;
  rowid: number;
  timestamp: string;
  account: string;
  process: string;
  processId: string;
  command: string;
  scriptBlock: string;
  hostApplication: string;
  kind: PsKind | string;
}

interface PsSession {
  key: string;
  account: string;
  process: string;
  processId: string;
  start: string;
  end: string;
  events: PsEvent[];
}


function firstLine(value: string, limit = 220): string {
  const line = value.split(/\r?\n/).find((item) => item.trim())?.trim() ?? value.trim();
  return line.length > limit ? `${line.slice(0, limit)}…` : line;
}

function eventEvidence(event: PsEvent): { label: string; value: string } {
  if (event.scriptBlock) return { label: "스크립트", value: firstLine(event.scriptBlock) };
  if (event.command) return { label: "명령", value: firstLine(event.command) };
  if (event.hostApplication) return { label: "HostApplication", value: firstLine(event.hostApplication) };
  return { label: "기록", value: "표시할 실행 문자열이 없습니다." };
}


function clusterSessions(data: CsvData, timeRange: TimeRange): PsSession[] {
  const events: PsEvent[] = data.rows
    .map((row) => ({
      row,
      rowid: Number((row as unknown as Record<string, unknown>).__rowid),
      timestamp: row.timestamp ?? "",
      account: row.account ?? "",
      process: row.process ?? "",
      processId: row.process_id ?? "",
      command: row.command ?? "",
      scriptBlock: row.script_block ?? "",
      hostApplication: row.host_application ?? "",
      kind: row.kind ?? "",
    }))
    .filter((event) => event.timestamp && inRange(event.timestamp, timeRange))
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp));

  const byIdentity = new Map<string, PsEvent[]>();
  for (const event of events) {
    const key = `${event.account}||${event.processId || event.process}`;
    const group = byIdentity.get(key) ?? [];
    group.push(event);
    byIdentity.set(key, group);
  }

  const sessions: PsSession[] = [];
  for (const group of byIdentity.values()) {
    let current: PsSession | null = null;
    let previousMs = Number.NaN;
    for (const event of group) {
      const currentMs = tsMs(event.timestamp);
      const hasGap = Number.isFinite(currentMs) && Number.isFinite(previousMs) && currentMs - previousMs > SESSION_GAP_MS;
      if (!current || hasGap) {
        current = { key: `${sessions.length}`, account: event.account, process: event.process, processId: event.processId, start: event.timestamp, end: event.timestamp, events: [] };
        sessions.push(current);
      }
      if (!current.process && event.process) current.process = event.process;
      if (!current.account && event.account) current.account = event.account;
      current.events.push(event);
      current.end = event.timestamp;
      previousMs = currentMs;
    }
  }
  return sessions.sort((left, right) => left.start.localeCompare(right.start));
}

interface PowerShellFlowViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

const FILTERS: { label: string; value?: PsKind }[] = [
  { label: "전체" },
  { label: "스크립트 블록", value: "스크립트 블록" },
  { label: "파이프라인", value: "파이프라인" },
  { label: "명령 실행", value: "명령 실행" },
];

export default function PowerShellFlowView({
  data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory,
}: PowerShellFlowViewProps) {
  const [kindFilter, setKindFilter] = useState<PsKind | undefined>();
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);

  const allSessions = useMemo(() => clusterSessions(data, timeRange), [data, timeRange]);
  const sessions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return allSessions.flatMap((session) => {
      const events = session.events.filter((event) => {
        if (kindFilter && event.kind !== kindFilter) return false;
        if (hiddenAccounts.has(event.account)) return false;
        if (!needle) return true;
        return [event.account, event.process, event.processId, event.command, event.scriptBlock, event.hostApplication]
          .some((value) => value.toLowerCase().includes(needle));
      });
      return events.length ? [{ ...session, events, start: events[0].timestamp, end: events[events.length - 1].timestamp }] : [];
    });
  }, [allSessions, hiddenAccounts, kindFilter, query]);
  const eventCount = useMemo(() => sessions.reduce((count, session) => count + session.events.length, 0), [sessions]);
  const allAccounts = useMemo(
    () => [...new Set(allSessions.flatMap((session) => session.events.map((event) => event.account)))].sort((a, b) => a.localeCompare(b)),
    [allSessions],
  );

  function toggle(sessionKey: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(sessionKey)) next.delete(sessionKey);
      else next.add(sessionKey);
      return next;
    });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0, background: "var(--bg)" }}>
      <ViewHeader icon={TerminalOutlinedIcon} title="파워셸 실행 이력" meta={`세션 ${sessions.length.toLocaleString()} · 원본 기록 ${eventCount.toLocaleString()}`}>
          <HeaderSearchInput value={query} onChange={setQuery} placeholder="명령 · 스크립트 · HostApplication · 계정 검색" ariaLabel="PowerShell 실행 증거 검색" width={330} />
          <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
          <SelectDropdown
            icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
            label="유형"
            options={FILTERS.map((filter) => ({ value: filter.value ?? "all", label: filter.label }))}
            value={kindFilter ?? "all"}
            onChange={(next) => setKindFilter(next === "all" ? undefined : (next as PsKind))}
          />
        
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {sessions.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {allSessions.length === 0 ? "기간 내 파워셸 실행 이력이 없습니다." : "검색 또는 필터 조건에 맞는 실행 이력이 없습니다."}
          </div>
        ) : sessions.map((session) => {
          const open = expanded.has(session.key);
          const recordsId = `powershell-session-records-${session.key}`;
          const kindCounts = new Map<string, number>();
          for (const event of session.events) {
            const kindKey = event.kind || eventEvidence(event).label;
            kindCounts.set(kindKey, (kindCounts.get(kindKey) ?? 0) + 1);
          }
          const accountLabel = resolveAccountDisplay(session.account, accountDirectory) || "계정 정보 없음";
          const sameDay = session.start.slice(0, 10) === session.end.slice(0, 10);
          return (
            <section key={session.key} style={{ marginBottom: 10, border: `1px solid ${open ? "color-mix(in srgb, var(--accent) 48%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
              <button
                type="button"
                className="ps-session-summary"
                onClick={() => toggle(session.key)}
                aria-expanded={open}
                aria-controls={recordsId}
                aria-label={`${session.process || "powershell.exe"} ${session.processId ? `PID ${session.processId} ` : ""}세션의 원본 기록 ${session.events.length}건 ${open ? "접기" : "펼치기"}`}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? "color-mix(in srgb, var(--accent) 7%, transparent)" : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .18s ease", outlineOffset: -2 }}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? "color-mix(in srgb, var(--accent) 7%, transparent)" : "transparent"; }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "var(--accent-subtle)" }}>
                  <TerminalOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{session.process || "powershell.exe"}</span>
                    {session.processId && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>PID {session.processId}</span>}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: session.account ? "var(--text-dim)" : "var(--text-faint)" }}>{accountLabel}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>기록 {session.events.length.toLocaleString()}건</span>
                  </span>
                </span>
                <span className="ps-session-kinds" style={{ display: "flex", alignItems: "center", gap: 5, flexShrink: 0 }}>
                  {[...kindCounts.entries()].map(([kindLabel, count]) => {
                    const kindColor = kindLabel === "스크립트 블록" ? "var(--accent)" : kindLabel === "파이프라인" ? "var(--warning)" : kindLabel === "명령 실행" ? "var(--success)" : "var(--text-dim)";
                    return <span key={kindLabel} style={{ fontSize: 11.5, fontWeight: 700, color: kindColor, border: `1px solid ${kindColor}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{kindLabel} {count.toLocaleString()}</span>;
                  })}
                </span>
                <span className="ps-session-range" style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {formatEvidenceTimestamp(session.start)} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? formatEvidenceTimestamp(session.end).slice(11) : formatEvidenceTimestamp(session.end)}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div id={recordsId} role="region" aria-label={`원본 기록 ${session.events.length}건`} className="ps-session-records" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {session.events.map((event, eventIndex) => {
                    const evidence = eventEvidence(event);
                    const bookmarked = Number.isFinite(event.rowid) && (bookmarkedRowids?.has(event.rowid) ?? false);
                    const hostApplicationSecondary = evidence.label !== "HostApplication" ? firstLine(event.hostApplication, 180) : "";
                    const kindLabel = event.kind || evidence.label;
                    const kindColor = kindLabel === "스크립트 블록" ? "var(--accent)" : kindLabel === "파이프라인" ? "var(--warning)" : kindLabel === "명령 실행" ? "var(--success)" : "var(--text-dim)";
                    return (
                      <div key={`${event.rowid}-${event.timestamp}`} className={bookmarked ? "dfir-bookmarked-row ps-session-event" : "ps-session-event"} style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 8, minHeight: 46, padding: "8px 14px 8px 60px", borderTop: eventIndex === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", transition: "background .15s ease" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "transparent"; }}>
                        <button type="button" className="ps-session-child" onClick={() => setSelected(event.row)} aria-label={`${formatEvidenceTimestamp(event.timestamp)} ${kindLabel} 상세 보기`} style={{ flex: 1, display: "grid", gridTemplateColumns: "158px 104px minmax(0, 1fr)", gap: 10, alignItems: "center", minWidth: 0, padding: 0, color: "var(--text)", cursor: "pointer", border: "none", background: "transparent", textAlign: "left", outlineOffset: 2 }}>
                          <span className="ps-session-child-time" style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(event.timestamp)}</span>
                          <span className="ps-session-child-type" style={{ justifySelf: "start", fontSize: 11.5, fontWeight: 700, color: kindColor, border: `1px solid ${kindColor}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{kindLabel}</span>
                          <span className="ps-session-child-content" style={{ minWidth: 0, display: "grid", gap: 3 }}>
                            <span title={evidence.value} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: evidence.label === "HostApplication" ? "var(--accent)" : "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5 }}>{evidence.value}</span>
                            {hostApplicationSecondary && <span title={event.hostApplication} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11 }}>HostApplication · {hostApplicationSecondary}</span>}
                          </span>
                        </button>
                        {onToggleBookmark && Number.isFinite(event.rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={() => onToggleBookmark(event.rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </main>
      {selected && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE_NAME} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
    </div>
  );
}
