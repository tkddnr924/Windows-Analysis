"use client";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import PaginationControls from "@/components/PaginationControls";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

import { useEffect, useMemo, useRef, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import OpenInFullOutlinedIcon from "@mui/icons-material/OpenInFullOutlined";
import ConsoleHistoryModal from "./ConsoleHistoryModal";
import { artifactChipTone } from "./MasterTimeline";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import TerminalOutlinedIcon from "@mui/icons-material/TerminalOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { formatEvidenceTimestamp, inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { groupBySessionId, toPsEvent, type PsEvent } from "@/lib/powershellSessions";

const TABLE_NAME = "PowerShellHistory";
const CONSOLE_TONE = artifactChipTone("_OVERVIEW", "PowerShellHistory");
// Fixed order for known kinds; unknown stored kinds are appended.
const KIND_ORDER = ["스크립트 블록", "파이프라인", "명령 실행", "실행 경고", "엔진 시작", "엔진 종료", "콘솔 시작", "원격 공급자 시작", "콘솔 히스토리"];

// 4100 carries Windows event Level: 2 = Error (red), otherwise warning.
function kindColor(kind: string, level?: string): string {
  if (kind === "실행 경고") return level === "2" ? "var(--danger)" : "var(--warning)";
  return kind === "스크립트 블록" ? "var(--accent)" : kind === "파이프라인" ? "var(--warning)" : kind === "명령 실행" ? "var(--success)" : "var(--text-dim)";
}

function firstLine(value: string, limit = 220): string {
  const line = value.split(/\r?\n/).find((item) => item.trim())?.trim() ?? value.trim();
  return line.length > limit ? `${line.slice(0, limit)}…` : line;
}

// Session events always carry one of these (see allSessions filter).
function eventEvidence(event: PsEvent): { label: string; value: string } {
  if (event.scriptBlock) return { label: "스크립트", value: firstLine(event.scriptBlock) };
  if (event.command) return { label: "명령", value: firstLine(event.command) };
  return { label: "HostApplication", value: firstLine(event.hostApplication) };
}

interface PowerShellFlowViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
  /** PowerShellHistory.sqlite 경로 — 상세 열람 시 절단 없는 전체 행을 다시 받는다. */
  dbPath?: string;
}

export default function PowerShellFlowView({
  data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory, dbPath,
}: PowerShellFlowViewProps) {
  const [kindFilter, setKindFilter] = useState<string | undefined>();
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  // 목록 로드는 script_block/host_application을 앞부분 미리보기로만 받는다
  // (대량 4104 호스트의 웹뷰 메모리 보호). 상세는 원본 행 전체를 다시 받아
  // 코드 블록이 절단 없이 표시되게 한다 — 실패하면 미리보기 행으로 연다.
  // 늦게 도착한 이전 요청 응답이 더 최근 선택을 덮지 않도록 최신 요청만 반영.
  const detailSeq = useRef(0);
  const openDetail = (row: Record<string, string>) => {
    const rowid = Number((row as Record<string, unknown>).__rowid);
    const seq = ++detailSeq.current;
    if (dbPath && Number.isFinite(rowid)) {
      window.api.resultRow(dbPath, TABLE_NAME, rowid)
        .then((full) => { if (seq === detailSeq.current) setSelected(full.row ? { ...full.row, __rowid: String(rowid) } as Record<string, string> : row); })
        .catch(() => { if (seq === detailSeq.current) setSelected(row); });
    } else {
      setSelected(row);
    }
  };
  // ConsoleHost_history (untimed) opens per account in its own document modal.
  const [consoleAccount, setConsoleAccount] = useState<string | null>(null);
  // 세션 카드를 펼쳤을 때 보이는 원본 이벤트도 같은 10건 단위다.
  const [eventPages, setEventPages] = useState<Record<string, number>>({});
  const [page, setPage] = useState(0);

  // 목록 IPC의 script_block/host_application은 앞 1,000자 미리보기 — 그 뒤의
  // IOC까지 놓치지 않도록, 검색어가 있으면 서버에서 원문 컬럼을 매칭한 rowid
  // 집합을 받아 화면 필터에 합류시킨다.
  // Tagged with its query so a stale response never joins a newer search.
  const [serverMatches, setServerMatches] = useState<{ query: string; rowids: Set<number> } | null>(null);
  const searchSeq = useRef(0);
  useEffect(() => {
    const needle = query.trim();
    const seq = ++searchSeq.current;
    if (!needle || !dbPath) {
      setServerMatches(null);
      return;
    }
    const timer = setTimeout(() => {
      window.api.powershellSearchRowids(dbPath, needle)
        .then((rowids) => { if (seq === searchSeq.current) setServerMatches({ query: needle, rowids: new Set(rowids) }); })
        .catch(() => { if (seq === searchSeq.current) setServerMatches({ query: needle, rowids: new Set() }); });
    }, 250);
    return () => clearTimeout(timer);
  }, [query, dbPath]);

  // The view answers "what was run": records without command, script or host
  // command line (e.g. 40961 console start) are not listed.
  const allSessions = useMemo(
    () => groupBySessionId((data.rows as Record<string, string>[]).map(toPsEvent).filter((event) => event.timestamp && inRange(event.timestamp, timeRange) && (event.scriptBlock || event.command || event.hostApplication))),
    [data.rows, timeRange],
  );
  const activeMatches = serverMatches && serverMatches.query === query.trim() ? serverMatches.rowids : null;
  const kinds = useMemo(() => {
    const present = new Set([
      ...allSessions.flatMap((session) => session.events.map((event) => event.kind)),
      ...(data.rows as Record<string, string>[]).filter((row) => !(row.timestamp ?? "").trim()).map((row) => row.event_type ?? ""),
    ].filter(Boolean));
    return [...KIND_ORDER.filter((kind) => present.has(kind)), ...[...present].filter((kind) => !KIND_ORDER.includes(kind)).sort()];
  }, [allSessions, data.rows]);
  // Results before powershell_history=3 lack the console/script status columns.
  const stale = data.columns.length > 0 && !data.columns.includes("console_history_status");
  const untimed = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (data.rows as Record<string, string>[])
      .filter((row) => !(row.timestamp ?? "").trim())
      .filter((row) => {
        if (kindFilter && (row.event_type ?? "") !== kindFilter) return false;
        if (hiddenAccounts.has(row.account ?? "")) return false;
        if (!needle) return true;
        if (activeMatches?.has(Number((row as Record<string, unknown>).__rowid))) return true;
        return [row.account, row.command, row.event_type].some((value) => (value ?? "").toLowerCase().includes(needle));
      })
      .sort((a, b) => (a.account ?? "").localeCompare(b.account ?? "") || (Number(a.line_number) || 0) - (Number(b.line_number) || 0));
  }, [data.rows, kindFilter, hiddenAccounts, query, activeMatches]);
  const sessions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return allSessions.flatMap((session) => {
      const events = session.events.filter((event) => {
        if (kindFilter && event.kind !== kindFilter) return false;
        if (hiddenAccounts.has(event.account)) return false;
        if (!needle) return true;
        if (activeMatches?.has(event.rowid)) return true;
        return [event.account, event.process, event.processId, event.command, event.scriptBlock, event.hostApplication]
          .some((value) => value.toLowerCase().includes(needle));
      });
      return events.length ? [{ ...session, events, start: events[0].timestamp, end: events[events.length - 1].timestamp }] : [];
    });
  }, [allSessions, hiddenAccounts, kindFilter, query, activeMatches]);
  const eventCount = useMemo(() => sessions.reduce((count, session) => count + session.events.length, 0), [sessions]);
  const allAccounts = useMemo(
    () => [...new Set(allSessions.flatMap((session) => session.events.map((event) => event.account)))].sort((a, b) => a.localeCompare(b)),
    [allSessions],
  );
  // 세션 목록도 다른 뷰처럼 10건씩 페이지네이션 — 필터·검색이 바뀌면 첫 페이지로.
  const PS_PAGE_SIZE = 10;
  useEffect(() => {
    setPage(0);
    setEventPages({});
  }, [hiddenAccounts, kindFilter, query, activeMatches, timeRange]);
  const pageCount = Math.max(1, Math.ceil(sessions.length / PS_PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageSessions = sessions.slice(safePage * PS_PAGE_SIZE, safePage * PS_PAGE_SIZE + PS_PAGE_SIZE);
  const pageStart = sessions.length === 0 ? 0 : safePage * PS_PAGE_SIZE + 1;
  const pageEnd = Math.min(sessions.length, safePage * PS_PAGE_SIZE + PS_PAGE_SIZE);
  const consoleByAccount = useMemo(() => {
    const groups = new Map<string, Record<string, string>[]>();
    for (const row of untimed) {
      const key = row.account ?? "";
      const group = groups.get(key);
      if (group) group.push(row);
      else groups.set(key, [row]);
    }
    return [...groups.entries()];
  }, [untimed]);
  // The modal shows the account's whole history file, not the filtered subset.
  const consoleRows = useMemo(() => {
    if (consoleAccount === null) return null;
    return (data.rows as Record<string, string>[])
      .filter((row) => !(row.timestamp ?? "").trim() && (row.account ?? "") === consoleAccount)
      .sort((a, b) => (Number(a.line_number) || 0) - (Number(b.line_number) || 0));
  }, [data.rows, consoleAccount]);
  const consoleListed = consoleAccount !== null && consoleByAccount.some(([account]) => account === consoleAccount);
  useEffect(() => {
    if (consoleAccount !== null && !consoleListed) setConsoleAccount(null);
  }, [consoleAccount, consoleListed]);

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
      <ViewHeader icon={TerminalOutlinedIcon} title="파워셸 실행 이력" meta={`원본 기록 ${eventCount.toLocaleString()} · Host ID 세션 ${sessions.filter((session) => session.sessionId).length.toLocaleString()}`}>
          <HeaderSearchInput value={query} onChange={setQuery} placeholder="명령 · 스크립트 · HostApplication · 오류 · 해독 명령 · 계정 검색" ariaLabel="PowerShell 실행 증거 검색" width={330} />
          <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
          <SelectDropdown
            icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
            label="유형"
            options={[{ value: "all", label: "전체" }, ...kinds.map((kind) => ({ value: kind, label: kind }))]}
            value={kindFilter ?? "all"}
            onChange={(next) => setKindFilter(next === "all" ? undefined : next)}
          />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {stale && <div style={{ marginBottom: 10, padding: "6px 8px", borderLeft: "2px solid var(--warning)", background: "var(--warning-subtle)", color: "var(--warning)", fontSize: 12 }}>이전 파싱 결과입니다. 스크립트 조각·해독 명령·콘솔 원본 줄을 보려면 호스트를 다시 파싱하세요.</div>}
        {consoleByAccount.map(([account, rows]) => (
          <button
            key={`console-${account}`}
            type="button"
            onClick={() => setConsoleAccount(account)}
            aria-label={`${resolveAccountDisplay(account, accountDirectory) || "계정 정보 없음"} 콘솔 히스토리 ${rows.length}개 명령 열기`}
            // Untimed history file, not an event session: PowerShell artifact tone.
            style={{ width: "100%", marginBottom: 10, display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: `1px solid ${CONSOLE_TONE.border}`, borderRadius: "var(--radius)", background: CONSOLE_TONE.background, color: "var(--text)", cursor: "pointer", textAlign: "left" }}
            onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = CONSOLE_TONE.background; }}
          >
            <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: CONSOLE_TONE.background }}>
              <HistoryOutlinedIcon sx={{ fontSize: 18, color: CONSOLE_TONE.color }} />
            </span>
            <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>콘솔 히스토리</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 12 }}>{`${resolveAccountDisplay(account, accountDirectory) || "계정 정보 없음"} · ${rows.length.toLocaleString()}개 명령 · PSReadLine (ConsoleHost_history)`}</span>
            </span>
            <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 12 }}>시간 정보 없음</span>
            <OpenInFullOutlinedIcon aria-hidden="true" sx={{ fontSize: 16, color: "var(--text-faint)", flexShrink: 0 }} />
          </button>
        ))}
        {sessions.length === 0 && untimed.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {allSessions.length === 0 ? "기간 내 파워셸 실행 이력이 없습니다." : "검색 또는 필터 조건에 맞는 실행 이력이 없습니다."}
          </div>
        ) : pageSessions.map((session) => {
          const open = expanded.has(session.key);
          // 세션마다 독립 페이지 상태. 필터로 이벤트 수가 줄면 보정한다.
          const eventPageCount = Math.max(1, Math.ceil(session.events.length / PS_PAGE_SIZE));
          const eventSafePage = Math.min(eventPages[session.key] ?? 0, eventPageCount - 1);
          const eventPageRows = session.events.slice(eventSafePage * PS_PAGE_SIZE, (eventSafePage + 1) * PS_PAGE_SIZE);
          const recordsId = `powershell-session-records-${session.key}`;
          const kindCounts = new Map<string, number>();
          for (const event of session.events) {
            const kindKey = event.kind || eventEvidence(event).label;
            kindCounts.set(kindKey, (kindCounts.get(kindKey) ?? 0) + 1);
          }
          const accountLabel = resolveAccountDisplay(session.account, accountDirectory) || "계정 정보 없음";
          const sameDay = session.start.slice(0, 10) === session.end.slice(0, 10);
          // A record without a Host ID is never grouped: show it as one row.
          if (!session.sessionId) {
            const event = session.events[0];
            const evidence = eventEvidence(event);
            const color = kindColor(event.kind, event.row.event_level);
            const bookmarked = Number.isFinite(event.rowid) && (bookmarkedRowids?.has(event.rowid) ?? false);
            return (
              <section key={session.key} className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => openDetail(event.row)} style={{ marginBottom: 10, display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", cursor: "pointer" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-panel)"; }}>
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "var(--accent-subtle)" }}>
                  <TerminalOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
                </span>
                <button type="button" onClick={(clickEvent) => { clickEvent.stopPropagation(); openDetail(event.row); }} aria-label={`${formatEvidenceTimestamp(event.timestamp)} ${event.kind} 상세 보기`} style={{ flex: 1, minWidth: 0, display: "grid", gap: 3, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
                  <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{event.process || "powershell.exe"}</span>
                    {event.processId && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>PID {event.processId}</span>}
                    {event.row.description && <span title={event.row.description} style={{ flexShrink: 0, alignSelf: "center", fontSize: 10.5, fontWeight: 700, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius)", padding: "0 6px", whiteSpace: "nowrap" }}>불완전</span>}
                  </span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 12 }}>{resolveAccountDisplay(event.account, accountDirectory) || "계정 정보 없음"}</span>
                </button>
                <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{event.kind || evidence.label}</span>
                <span style={{ flexShrink: 0, width: 172, textAlign: "right", color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(event.timestamp)}</span>
                {onToggleBookmark && Number.isFinite(event.rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark(event.rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
              </section>
            );
          }
          return (
            <section key={session.key} style={{ marginBottom: 10, border: `1px solid ${open ? "color-mix(in srgb, var(--accent) 48%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
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
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius)", background: "var(--accent-subtle)" }}>
                  <TerminalOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{session.process || "powershell.exe"}</span>
                    {session.processId && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>PID {session.processId}</span>}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-faint)", fontSize: 12 }}>
                    <span style={{ flexShrink: 0, whiteSpace: "nowrap" }}>{`${accountLabel} · 기록 ${session.events.length.toLocaleString()}건`}</span>
                    <span aria-hidden="true">·</span>
                    <span title={`Host ID ${session.sessionId}`} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 11.5 }}>Host ID {session.sessionId}</span>
                  </span>
                </span>
                <span className="ps-session-kinds" style={{ display: "flex", alignItems: "center", gap: 5, flexShrink: 0 }}>
                  {[...kindCounts.entries()].map(([kindLabel, count]) => {
                    const color = kindColor(kindLabel, session.events.find((event) => event.kind === kindLabel)?.row.event_level);
                    return <span key={kindLabel} style={{ fontSize: 11.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{kindLabel} {count.toLocaleString()}</span>;
                  })}
                </span>
                <span className="ps-session-range" style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {formatEvidenceTimestamp(session.start)} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? formatEvidenceTimestamp(session.end).slice(11) : formatEvidenceTimestamp(session.end)}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div id={recordsId} role="region" aria-label={`원본 기록 ${session.events.length}건`} className="ps-session-records" style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {eventPageRows.map((event, eventIndex) => {
                    const evidence = eventEvidence(event);
                    const bookmarked = Number.isFinite(event.rowid) && (bookmarkedRowids?.has(event.rowid) ?? false);
                    const hostApplicationSecondary = evidence.label !== "HostApplication" ? firstLine(event.hostApplication, 180) : "";
                    const kindLabel = event.kind || evidence.label;
                    const color = kindColor(kindLabel, event.row.event_level);
                    return (
                      // 행 전체(여백 포함)가 상세 열기 클릭 대상 — 북마크는 전파 차단.
                      <div key={`${event.rowid}-${event.timestamp}`} className={bookmarked ? "dfir-bookmarked-row ps-session-event" : "ps-session-event"} onClick={() => openDetail(event.row)} style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 8, minHeight: 46, padding: "8px 14px 8px 60px", borderTop: eventIndex === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", cursor: "pointer", transition: "background .15s ease" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "transparent"; }}>
                        <button type="button" className="ps-session-child" onClick={(clickEvent) => { clickEvent.stopPropagation(); openDetail(event.row); }} aria-label={`${formatEvidenceTimestamp(event.timestamp)} ${kindLabel} 상세 보기`} style={{ flex: 1, display: "grid", gridTemplateColumns: "158px 104px minmax(0, 1fr)", gap: 10, alignItems: "center", minWidth: 0, padding: 0, color: "var(--text)", cursor: "pointer", border: "none", background: "transparent", textAlign: "left", outlineOffset: 2 }}>
                          <span className="ps-session-child-time" style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(event.timestamp)}</span>
                          <span className="ps-session-child-type" style={{ justifySelf: "start", fontSize: 11.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "1px 8px", whiteSpace: "nowrap" }}>{kindLabel}</span>
                          <span className="ps-session-child-content" style={{ minWidth: 0, display: "grid", gap: 3 }}>
                            <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}>
                              {/* 분할 4104 재조합이 불완전한 행 — 잘린 본문이 완전한
                                  원문으로 읽히지 않게 목록에서 바로 경고한다. */}
                              {event.row.description && <span title={event.row.description} style={{ flexShrink: 0, fontSize: 10.5, fontWeight: 700, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius)", padding: "0 6px", whiteSpace: "nowrap" }}>불완전</span>}
                              <span title={evidence.value} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: evidence.label === "HostApplication" ? "var(--accent)" : "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5 }}>{evidence.value}</span>
                            </span>
                            {hostApplicationSecondary && <span title={event.hostApplication} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11 }}>HostApplication · {hostApplicationSecondary}</span>}
                          </span>
                        </button>
                        {onToggleBookmark && Number.isFinite(event.rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark(event.rowid); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                  {/* 카드 안 원본 레코드도 10건 고정 — 한 세션에 4104가 수천 건
                      쌓여도 카드를 여는 것만으로 화면이 멈추지 않는다. */}
                  <div style={{ padding: "6px 14px 8px 60px" }}>
                    <PaginationControls
                      ariaLabel={`${session.key} 원본 기록 페이지`}
                      page={eventSafePage}
                      pageCount={eventPageCount}
                      onChange={(next) => setEventPages((previous) => ({ ...previous, [session.key]: next }))}
                      summary={`(${session.events.length === 0 ? 0 : (eventSafePage * PS_PAGE_SIZE + 1).toLocaleString()}–${Math.min(session.events.length, (eventSafePage + 1) * PS_PAGE_SIZE).toLocaleString()} / ${session.events.length.toLocaleString()})`}
                    />
                  </div>
                </div>
              )}
            </section>
          );
        })}
      </main>
      {sessions.length > 0 && (
        <footer style={{ flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", minHeight: 44, padding: "6px 16px", borderTop: "1px solid var(--border)" }}>
          <PaginationControls ariaLabel="파워셸 세션 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${pageStart.toLocaleString()}–${pageEnd.toLocaleString()} / ${sessions.length.toLocaleString()})`} />
        </footer>
      )}
      {selected && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE_NAME} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
      {consoleRows && consoleAccount !== null && <ConsoleHistoryModal account={resolveAccountDisplay(consoleAccount, accountDirectory) || "계정 정보 없음"} rows={consoleRows} onClose={() => setConsoleAccount(null)} />}
    </div>
  );
}
