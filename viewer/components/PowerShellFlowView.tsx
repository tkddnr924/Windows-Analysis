"use client";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { formatEvidenceTimestamp, inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

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

function tsMs(timestamp: string): number {
  return timestamp ? new Date(timestamp.replace(" ", "T")).getTime() : Number.NaN;
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
}

const FILTERS: { label: string; value?: PsKind }[] = [
  { label: "전체" },
  { label: "스크립트 블록", value: "스크립트 블록" },
  { label: "파이프라인", value: "파이프라인" },
  { label: "명령 실행", value: "명령 실행" },
];

export default function PowerShellFlowView({
  data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE,
}: PowerShellFlowViewProps) {
  const [kindFilter, setKindFilter] = useState<PsKind | undefined>();
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);

  const allSessions = useMemo(() => clusterSessions(data, timeRange), [data, timeRange]);
  const sessions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return allSessions.flatMap((session) => {
      const events = session.events.filter((event) => {
        if (kindFilter && event.kind !== kindFilter) return false;
        if (!needle) return true;
        return [event.account, event.process, event.processId, event.command, event.scriptBlock, event.hostApplication]
          .some((value) => value.toLowerCase().includes(needle));
      });
      return events.length ? [{ ...session, events, start: events[0].timestamp, end: events[events.length - 1].timestamp }] : [];
    });
  }, [allSessions, kindFilter, query]);
  const eventCount = useMemo(() => sessions.reduce((count, session) => count + session.events.length, 0), [sessions]);

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
      <header style={{ flexShrink: 0, padding: "12px 16px 10px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, minHeight: 25, flexWrap: "wrap" }}>
          <strong style={{ fontSize: 15, color: "var(--text)" }}>파워셸 실행 이력</strong>
          <span style={{ color: "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" }}>{sessions.length.toLocaleString()}개 세션 · {eventCount.toLocaleString()}건</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 9, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 260px", maxWidth: 430 }}>
            <input value={query} onChange={(event) => setQuery(event.target.value)} onFocus={(event) => { event.currentTarget.style.borderColor = "var(--accent)"; event.currentTarget.style.boxShadow = "0 0 0 2px var(--accent-subtle)"; }} onBlur={(event) => { event.currentTarget.style.borderColor = "var(--border)"; event.currentTarget.style.boxShadow = "none"; }} placeholder="명령 · 스크립트 · HostApplication · 계정 검색" aria-label="PowerShell 실행 증거 검색" style={{ width: "100%", height: 31, padding: "0 31px 0 10px", fontSize: 12, fontFamily: "var(--mono)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", color: "var(--text)", background: "var(--bg-elevated)", outline: "none" }} />
            {query && <button type="button" onClick={() => setQuery("")} aria-label="검색어 지우기" style={{ position: "absolute", right: 5, top: "50%", transform: "translateY(-50%)", display: "inline-flex", padding: 2, color: "var(--text-faint)", border: "none", background: "transparent", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 16 }} /></button>}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
            {FILTERS.map((filter) => {
              const active = kindFilter === filter.value;
              return <button key={filter.label} type="button" onClick={() => setKindFilter(filter.value)} aria-pressed={active} style={{ height: 30, padding: "0 10px", fontSize: 11.5, fontWeight: active ? 700 : 550, color: active ? "var(--accent)" : "var(--text-dim)", background: active ? "var(--accent-subtle)" : "transparent", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", cursor: "pointer" }}>{filter.label}</button>;
            })}
          </div>
        </div>
      </header>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
        <div style={{ minWidth: 730, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", overflow: "hidden", background: "var(--bg-panel)" }}>
          {sessions.length > 0 && <div style={{ display: "grid", gridTemplateColumns: "32px minmax(150px, .72fr) minmax(110px, .46fr) minmax(210px, 1.4fr) 164px 54px", gap: 8, alignItems: "center", padding: "8px 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span /><span>실행 프로세스</span><span>계정</span><span>명령 / 스크립트</span><span>시간</span><span style={{ textAlign: "right" }}>이벤트</span></div>}
          {sessions.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>{allSessions.length === 0 ? "기간 내 파워셸 실행 이력이 없습니다." : "검색 또는 필터 조건에 맞는 실행 이력이 없습니다."}</div> : sessions.map((session) => {
            const open = expanded.has(session.key);
            const summary = eventEvidence(session.events[0]);
            return <section key={session.key} style={{ borderTop: "1px solid var(--border-subtle)" }}>
              <button type="button" onClick={() => toggle(session.key)} aria-expanded={open} style={{ width: "100%", display: "grid", gridTemplateColumns: "32px minmax(150px, .72fr) minmax(110px, .46fr) minmax(210px, 1.4fr) 164px 54px", gap: 8, alignItems: "center", padding: "10px 12px", color: "var(--text)", border: "none", background: "transparent", cursor: "pointer", textAlign: "left", outlineOffset: -2 }} onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}>
                {open ? <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} />}
                <span style={{ minWidth: 0 }}><span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 700 }}>{session.process || "powershell.exe"}</span>{session.processId && <span style={{ display: "block", marginTop: 2, color: "var(--text-faint)", fontSize: 10.5, fontFamily: "var(--mono)" }}>PID {session.processId}</span>}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: session.account ? "var(--text)" : "var(--text-faint)", fontSize: 12 }}>{session.account || "계정 정보 없음"}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11.5 }}><span style={{ marginRight: 7, color: summary.label === "HostApplication" ? "var(--accent)" : "var(--text-faint)", fontFamily: "inherit", fontSize: 10.5 }}>{summary.label}</span>{summary.value}</span>
                <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 10.5, lineHeight: 1.4, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(session.start)}<br />{formatEvidenceTimestamp(session.end)}</span>
                <span style={{ display: "block", textAlign: "right", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{session.events.length}건</span>
              </button>
              {open && <div style={{ borderTop: "1px solid var(--border-subtle)", background: "color-mix(in srgb, var(--bg-elevated) 34%, transparent)" }}>
                <div style={{ display: "grid", gridTemplateColumns: "160px 104px minmax(190px, 1fr) minmax(220px, .9fr) 32px", gap: 8, padding: "6px 12px 6px 44px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 10, fontWeight: 700 }}><span>시간</span><span>기록 유형</span><span>명령 / 스크립트</span><span>HostApplication</span><span /></div>
                {session.events.map((event) => {
                  const evidence = eventEvidence(event);
                  const bookmarked = Number.isFinite(event.rowid) && (bookmarkedRowids?.has(event.rowid) ?? false);
                  const rowBackground = bookmarked ? "color-mix(in srgb, var(--warning) 14%, transparent)" : "transparent";
                  return <div key={`${event.rowid}-${event.timestamp}`} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 32px", gap: 8, alignItems: "center", minHeight: 35, padding: "6px 12px 6px 44px", background: rowBackground, boxShadow: bookmarked ? "inset 3px 0 0 var(--warning)" : undefined }} onMouseEnter={(mouseEvent) => { mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { mouseEvent.currentTarget.style.background = rowBackground; }}>
                    <div role="button" tabIndex={0} onClick={() => setSelected(event.row)} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelected(event.row); } }} style={{ display: "grid", gridTemplateColumns: "160px 104px minmax(190px, 1fr) minmax(220px, .9fr)", gap: 8, alignItems: "center", minWidth: 0, color: "var(--text)", cursor: "pointer", outlineOffset: 2 }}>
                      <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 11.5, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(event.timestamp)}</span>
                      <span style={{ color: "var(--text-dim)", fontSize: 11.5 }}>{event.kind || "기타"}</span>
                      <span title={evidence.value} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: evidence.label === "HostApplication" ? "var(--accent)" : "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11.5 }}><span style={{ color: "var(--text-faint)", fontFamily: "inherit", marginRight: 7 }}>{evidence.label}</span>{evidence.value}</span>
                      <span title={event.hostApplication || "HostApplication 기록 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: event.hostApplication ? "var(--accent)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.hostApplication || "—"}</span>
                    </div>
                    {onToggleBookmark && Number.isFinite(event.rowid) && <button type="button" onClick={() => onToggleBookmark(event.rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 26, height: 26, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--warning)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                  </div>;
                })}
              </div>}
            </section>;
          })}
        </div>
      </main>
      {selected && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE_NAME} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
    </div>
  );
}
