"use client";

import { useEffect, useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import ArrowBackOutlinedIcon from "@mui/icons-material/ArrowBackOutlined";
import ArrowForwardOutlinedIcon from "@mui/icons-material/ArrowForwardOutlined";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import TimelineOutlinedIcon from "@mui/icons-material/TimelineOutlined";
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import type { Bookmark, FetchLinkedRows, Host, ResultRow } from "@/lib/types";
import { getArtifactView, resolveArtifactView } from "@/lib/artifactViews";
import { formatEvidenceTimestamp, type TimeRange } from "@/lib/timeRange";
import TagList from "./TagList";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { pathBelongsToHost, visuallyHidden } from "@/lib/viewShared";

interface BookmarksViewProps {
  bookmarks: Bookmark[];
  hosts: Host[];
  hostIpMap: Record<string, { id: string; name: string }>;
  currentHostId: string | null;
  timeRange: TimeRange;
  onRemove: (bookmark: Bookmark) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
  accountDirectoryForHost?: (hostId: string) => AccountDirectory | undefined;
}

type RowLoad = { status: "ready"; data: ResultRow } | { status: "error" };

type BookmarkEntry = {
  bookmark: Bookmark;
  columns: string[];
  load: RowLoad | undefined;
  row?: Record<string, string>;
  spec: ReturnType<typeof getArtifactView>;
  eventTime: string;
  /** The evidence meaning of eventTime when it is not the artifact default. */
  eventTimeLabel?: string;
  host: { id: string; name: string };
};

type SequenceEntry = BookmarkEntry & {
  peer: string;
  peerHostId: string;
  peerHostName: string;
  isLoopback: boolean;
  direction: "inbound" | "outbound" | "unknown";
};

type SequenceParticipant = { key: string; label: string };

const MAX_CONCURRENT_ROW_LOOKUPS = 4;

function hostDirFromResultPath(fullPath: string): string | undefined {
  const normalized = fullPath.replace(/\\/g, "/");
  const match = normalized.match(/^(.*)\/(?:ANALYSIS_OVERVIEW|BROWSER)\//i);
  return match?.[1];
}

function bookmarkKey(bookmark: Bookmark): string {
  return `${bookmark.fullPath}\u0000${bookmark.tableName}#${bookmark.rowid}`;
}


function hostForBookmark(bookmark: Bookmark, hosts: Host[]): { id: string; name: string } {
  if (bookmark.hostId || bookmark.hostName) {
    return { id: bookmark.hostId ?? "", name: bookmark.hostName || bookmark.hostId || "알 수 없는 호스트" };
  }
  const host = hosts.find((candidate) => pathBelongsToHost(bookmark.fullPath, candidate.dir));
  return { id: host?.id ?? "", name: host?.name ?? "알 수 없는 호스트" };
}

function fieldLabel(field: string): string {
  const labels: Record<string, string> = {
    si_created: "SI 생성 시각", si_modified: "SI 수정 시각", si_mft_modified: "SI MFT 수정 시각", si_accessed: "SI 접근 시각",
    fn_created: "FN 생성 시각", fn_modified: "FN 수정 시각", fn_mft_modified: "FN MFT 수정 시각", fn_accessed: "FN 접근 시각",
    created: "계정 생성 시각", last_login: "최근 로그인 시각", password_last_set: "암호 변경 시각", last_failed_login: "로그인 실패 시각",
  };
  return labels[field] ?? "선택한 시각";
}

const EVIDENCE_TIMESTAMP = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?$/;

/**
 * Whole-row Registry bookmarks have no generic `timestamp` field.  Their
 * `last_write` is a key-level Registry timestamp, so it is useful for the
 * bookmark time axis but must never be presented as an application/BAM run.
 * A field bookmark deliberately keeps its selected field as the only source
 * of time; falling back would change the analyst's selection.
 */
function resolveBookmarkEventTime(
  bookmark: Bookmark,
  row: Record<string, string>,
  spec: ReturnType<typeof getArtifactView>,
): { value: string; label?: string } {
  if (bookmark.field) return { value: row[bookmark.field] || "", label: fieldLabel(bookmark.field) };

  const defaultTime = row[spec?.timelineField ?? "timestamp"] || row.timestamp || "";
  if (defaultTime) return { value: defaultTime };

  if (bookmark.tableName === "Registry" && EVIDENCE_TIMESTAMP.test(row.last_write || "")) {
    return { value: row.last_write, label: "레지스트리 키 마지막 기록 시각" };
  }
  return { value: "" };
}

function eventTitle(entry: BookmarkEntry): string {
  if (!entry.row) return entry.load?.status === "error" ? "원본 행을 불러오지 못했습니다" : "원본 행을 확인하는 중입니다";
  return entry.spec?.title(entry.row) || "등록된 분석 항목";
}

function eventSubtitle(entry: BookmarkEntry): string {
  if (!entry.row) return entry.load?.status === "error" ? "일시적인 조회 오류입니다. 다시 시도할 수 있습니다." : "원본 증거 행을 조회하고 있습니다.";
  return entry.spec?.subtitle?.(entry.row) || "";
}

function ControlButton({ active, onClick, children, ariaLabel }: { active: boolean; onClick: () => void; children: React.ReactNode; ariaLabel: string }) {
  return <button type="button" onClick={onClick} aria-label={ariaLabel} aria-pressed={active} style={{ minHeight: 28, padding: "3px 9px", borderRadius: "var(--radius-sm)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", fontSize: 11.5, fontWeight: active ? 700 : 600, cursor: "pointer", whiteSpace: "nowrap" }}>{children}</button>;
}

function RowStatus({ entry }: { entry: BookmarkEntry }) {
  if (!entry.load) return <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-faint)", fontSize: 11.5 }}><CircularProgress size={12} thickness={5} aria-label="원본 행 확인 중" />원본 행 확인 중</span>;
  if (entry.load.status === "error") return <span role="status" style={{ color: "var(--danger)", fontSize: 11.5 }}>원본 행 조회 실패</span>;
  if (!entry.row) return <span role="status" style={{ color: "var(--warning)", fontSize: 11.5 }}>원본 행을 찾을 수 없음</span>;
  return null;
}

function EntryOpenButton({ entry, onOpen }: { entry: BookmarkEntry; onOpen: (entry: BookmarkEntry) => void }) {
  const tags = entry.row && entry.spec?.tags ? entry.spec.tags(entry.row) : [];
  if (!entry.row) return <div style={{ minWidth: 0, padding: "8px 10px" }}><div style={{ color: "var(--text-dim)", fontWeight: 650, fontSize: 12.5 }}>{eventTitle(entry)}</div><div style={{ marginTop: 3 }}><RowStatus entry={entry} /></div></div>;
  return (
    <button type="button" onClick={() => onOpen(entry)} aria-label={`${eventTitle(entry)} 상세 보기`} style={{ display: "block", minWidth: 0, width: "100%", padding: "8px 10px", border: "none", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}><span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 700, color: "var(--text)", fontSize: 12.5 }}>{eventTitle(entry)}</span>{entry.bookmark.field && <span style={{ flexShrink: 0, color: "var(--bookmark-control)", fontSize: 10.5 }}>{fieldLabel(entry.bookmark.field)}</span>}</div>
      {eventSubtitle(entry) && <div style={{ minWidth: 0, marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 11.5 }}>{eventSubtitle(entry)}</div>}
      {entry.bookmark.note && <div style={{ minWidth: 0, marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 11.5 }}>메모: {entry.bookmark.note}</div>}
      {tags.length > 0 && <div style={{ marginTop: 5 }}><TagList tags={tags} /></div>}
    </button>
  );
}

export default function BookmarksView({ bookmarks, hosts, hostIpMap, currentHostId, timeRange, onRemove, onNavigate, onFetchLinkedRows, accountDirectoryForHost }: BookmarksViewProps) {
  const [detail, setDetail] = useState<{ bookmark: Bookmark; row: Record<string, string>; columns: string[] } | null>(null);
  const [rowCache, setRowCache] = useState<Record<string, RowLoad>>({});
  const [lookupAttempt, setLookupAttempt] = useState(0);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [viewMode, setViewMode] = useState<"timeline" | "sequence">("timeline");

  useEffect(() => {
    const missing = [...new Map(bookmarks.filter((bookmark) => rowCache[bookmarkKey(bookmark)] === undefined).map((bookmark) => [bookmarkKey(bookmark), bookmark])).values()];
    if (missing.length === 0) return;
    let cancelled = false;
    const resolved: [string, RowLoad][] = [];
    let nextIndex = 0;
    const worker = async () => {
      while (!cancelled) {
        const bookmark = missing[nextIndex++];
        if (!bookmark) return;
        try { resolved.push([bookmarkKey(bookmark), { status: "ready", data: await window.api.resultRow(bookmark.fullPath, bookmark.tableName, bookmark.rowid) }]); }
        catch { resolved.push([bookmarkKey(bookmark), { status: "error" }]); }
      }
    };
    void Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_ROW_LOOKUPS, missing.length) }, worker)).then(() => {
      if (!cancelled && resolved.length > 0) setRowCache((previous) => ({ ...previous, ...Object.fromEntries(resolved) }));
    });
    return () => { cancelled = true; };
    // `rowCache` is deliberately excluded: entries queue once per attempt;
    // retry clears only failed keys and advances `lookupAttempt`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bookmarks, lookupAttempt]);

  const entries = useMemo<BookmarkEntry[]>(() => bookmarks.map((bookmark) => {
    const load = rowCache[bookmarkKey(bookmark)];
    const row = load?.status === "ready" ? load.data.row ?? undefined : undefined;
    const columns = load?.status === "ready" ? load.data.columns : [];
    const spec = resolveArtifactView(bookmark.tableName, columns) ?? getArtifactView(bookmark.tableName);
    const time = row ? resolveBookmarkEventTime(bookmark, row, spec) : { value: "" };
    return { bookmark, columns, load, row, spec, eventTime: time.value, eventTimeLabel: time.label, host: hostForBookmark(bookmark, hosts) };
  }), [bookmarks, hosts, rowCache]);

  const { timedEntries, undatedEntries, unresolvedEntries } = useMemo(() => {
    // 북마크는 분석가가 직접 고른 증거다 — 기간 필터(사고 시점)와 무관하게
    // 항상 전부 표시한다.
    const timed = entries.filter((entry) => Boolean(entry.eventTime));
    const undated = entries.filter((entry) => entry.load?.status === "ready" && !entry.eventTime);
    const unresolved = entries.filter((entry) => !entry.load || entry.load.status === "error");
    const compare = (left: BookmarkEntry, right: BookmarkEntry) => sortDir === "asc" ? left.eventTime.localeCompare(right.eventTime) : right.eventTime.localeCompare(left.eventTime);
    return { timedEntries: timed.sort(compare), undatedEntries: undated, unresolvedEntries: unresolved };
  }, [entries, sortDir, timeRange]);

  const sequenceEntries = useMemo<SequenceEntry[]>(() => timedEntries.map((entry) => {
    const peer = (entry.row?.remote_address ?? "").trim();
    const isLoopback = isLocalLoopbackPeer(peer);
    const peerHost = peer && !isLoopback ? hostIpMap[peer] : undefined;
    const rawDirection = entry.row?.direction?.toLowerCase();
    const direction: SequenceEntry["direction"] = peer && rawDirection === "inbound" ? "inbound" : peer && rawDirection === "outbound" ? "outbound" : "unknown";
    return { ...entry, peer, peerHostId: peerHost?.id ?? "", peerHostName: isLoopback ? `로컬 루프백 (${peer})` : peerHost?.name ?? peer, isLoopback, direction };
  }).sort((left, right) => left.eventTime.localeCompare(right.eventTime)), [hostIpMap, timedEntries]);

  const failedCount = entries.filter((entry) => entry.load?.status === "error").length;
  const emptyForRange = timedEntries.length === 0 && undatedEntries.length === 0 && unresolvedEntries.length === 0;
  const openDetail = (entry: BookmarkEntry) => { if (entry.row) setDetail({ bookmark: entry.bookmark, row: entry.row, columns: entry.columns }); };
  const retryFailedRows = () => {
    setRowCache((previous) => Object.fromEntries(Object.entries(previous).filter(([, value]) => value.status !== "error")));
    setLookupAttempt((attempt) => attempt + 1);
  };

  if (bookmarks.length === 0) return <main className="dfir-view" aria-labelledby="analysis-info-title" style={{ display: "grid", placeItems: "center", flex: 1, minHeight: 0, padding: 24 }}><div style={{ display: "grid", justifyItems: "center", gap: 8, color: "var(--text-faint)", textAlign: "center" }}><BookmarkBorderOutlinedIcon sx={{ fontSize: 30, color: "var(--text-dim)" }} aria-hidden="true" /><strong id="analysis-info-title" style={{ color: "var(--text)", fontSize: 14 }}>분석 정보가 없습니다</strong><span style={{ fontSize: 12 }}>분석 중 확인이 필요한 행을 북마크하면 이곳에서 시간과 호스트 기준으로 검토할 수 있습니다.</span></div></main>;

  return (
    <main className="dfir-view" aria-labelledby="analysis-info-title" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <header style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0 }}>
        <BookmarkBorderOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} aria-hidden="true" /><strong id="analysis-info-title" style={{ fontSize: 14, color: "var(--text)" }}>분석 정보</strong><span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{bookmarks.length.toLocaleString()}건</span><span style={{ color: "var(--text-faint)", fontSize: 11.5, borderLeft: "1px solid var(--border)", paddingLeft: 10 }}>북마크 전체</span>
        <div style={{ display: "flex", gap: 4, marginLeft: "auto" }} role="group" aria-label="정렬 순서"><ControlButton active={sortDir === "asc"} onClick={() => setSortDir("asc")} ariaLabel="시간 오름차순 정렬">오래된순</ControlButton><ControlButton active={sortDir === "desc"} onClick={() => setSortDir("desc")} ariaLabel="시간 내림차순 정렬">최근순</ControlButton></div>
        <div style={{ display: "flex", gap: 4 }} role="group" aria-label="분석 정보 표시 방식"><ControlButton active={viewMode === "timeline"} onClick={() => setViewMode("timeline")} ariaLabel="시간 원장 보기"><TimelineOutlinedIcon sx={{ fontSize: 15, verticalAlign: "-3px", marginRight: "4px" }} />시간 원장</ControlButton><ControlButton active={viewMode === "sequence"} onClick={() => setViewMode("sequence")} ariaLabel="호스트 흐름 보기"><AccountTreeOutlinedIcon sx={{ fontSize: 15, verticalAlign: "-3px", marginRight: "4px" }} />호스트 흐름</ControlButton></div>
      </header>

      {failedCount > 0 && <div role="alert" style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0, padding: "7px 14px", borderBottom: "1px solid color-mix(in srgb, var(--danger) 42%, var(--border))", background: "color-mix(in srgb, var(--danger) 7%, var(--bg-panel))", color: "var(--text)", fontSize: 12 }}>원본 행 {failedCount}건을 불러오지 못했습니다.<button type="button" onClick={retryFailedRows} style={{ display: "inline-flex", alignItems: "center", gap: 4, marginLeft: "auto", minHeight: 26, padding: "2px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "transparent", color: "var(--text-dim)", cursor: "pointer", fontSize: 11.5 }}><RefreshOutlinedIcon sx={{ fontSize: 14 }} />다시 시도</button></div>}
      {emptyForRange ? <div role="status" style={{ display: "grid", placeItems: "center", flex: 1, minHeight: 0, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 시간 정보가 있는 북마크가 없습니다.</div> : viewMode === "timeline" ? <TimelineLedger entries={timedEntries} undatedEntries={undatedEntries} unresolvedEntries={unresolvedEntries} currentHostId={currentHostId} onOpen={openDetail} onRemove={onRemove} /> : <HostFlowLedger entries={sequenceEntries} undatedEntries={undatedEntries} unresolvedEntries={unresolvedEntries} currentHostId={currentHostId} onOpen={openDetail} onRemove={onRemove} accountDirectoryForHost={accountDirectoryForHost} />}
      {detail && <RowDetailPanel row={detail.row} columns={detail.columns} focusedColumn={null} fileBaseName={detail.bookmark.tableName} onClose={() => setDetail(null)} onNavigate={(file, column, value) => { setDetail(null); onNavigate(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDirFromResultPath(detail.bookmark.fullPath)} accountDirectory={accountDirectoryForHost?.(hostForBookmark(detail.bookmark, hosts).id)} isBookmarked onToggleBookmark={() => { onRemove(detail.bookmark); setDetail(null); }} />}
    </main>
  );
}

function TimelineLedger({ entries, undatedEntries, unresolvedEntries, currentHostId, onOpen, onRemove }: { entries: BookmarkEntry[]; undatedEntries: BookmarkEntry[]; unresolvedEntries: BookmarkEntry[]; currentHostId: string | null; onOpen: (entry: BookmarkEntry) => void; onRemove: (bookmark: Bookmark) => void }) {
  return <section aria-label="북마크 시간 원장" style={{ flex: 1, minHeight: 0, overflow: "auto" }}><div style={{ minWidth: 760 }}><div aria-hidden="true" style={{ display: "grid", gridTemplateColumns: "184px minmax(132px, .5fr) minmax(260px, 1.6fr) 44px", gap: 10, padding: "8px 14px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span>시각</span><span>호스트</span><span>분석 항목</span><span style={{ textAlign: "center" }}>제거</span></div>{entries.map((entry) => <TimelineRow key={entry.bookmark.id} entry={entry} currentHostId={currentHostId} onOpen={onOpen} onRemove={onRemove} />)}{undatedEntries.length > 0 && <LedgerGroup label="시간 정보 없음" entries={undatedEntries} currentHostId={currentHostId} onOpen={onOpen} onRemove={onRemove} bordered={entries.length > 0} />}{unresolvedEntries.length > 0 && <LedgerGroup label="원본 행 확인 필요" entries={unresolvedEntries} currentHostId={currentHostId} onOpen={onOpen} onRemove={onRemove} bordered={entries.length > 0 || undatedEntries.length > 0} />}</div></section>;
}

function LedgerGroup({ label, entries, currentHostId, onOpen, onRemove, bordered }: { label: string; entries: BookmarkEntry[]; currentHostId: string | null; onOpen: (entry: BookmarkEntry) => void; onRemove: (bookmark: Bookmark) => void; bordered: boolean }) {
  return <div style={{ borderTop: bordered ? "1px solid var(--border)" : "none" }}><div style={{ padding: "9px 14px 6px", color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700 }}>{label} · {entries.length}건</div>{entries.map((entry) => <TimelineRow key={entry.bookmark.id} entry={entry} currentHostId={currentHostId} onOpen={onOpen} onRemove={onRemove} />)}</div>;
}

function TimelineRow({ entry, currentHostId, onOpen, onRemove }: { entry: BookmarkEntry; currentHostId: string | null; onOpen: (entry: BookmarkEntry) => void; onRemove: (bookmark: Bookmark) => void }) {
  const isRegistryLastWrite = entry.eventTimeLabel === "레지스트리 키 마지막 기록 시각";
  return <article className="dfir-bookmarked-row" style={{ display: "grid", gridTemplateColumns: "184px minmax(132px, .5fr) minmax(260px, 1.6fr) 44px", gap: 10, alignItems: "stretch", minHeight: 56, padding: "0 14px", borderBottom: "1px solid var(--border-subtle)" }}><div style={{ alignSelf: "center", minWidth: 0 }}><time style={{ display: "block", fontFamily: "var(--mono)", fontSize: 11.5, color: entry.eventTime ? "var(--text-time)" : "var(--text-faint)", whiteSpace: "nowrap" }}>{entry.eventTime ? formatEvidenceTimestamp(entry.eventTime) : "시간 정보 없음"}</time>{isRegistryLastWrite && <span style={{ display: "block", marginTop: 2, color: "var(--text-faint)", fontSize: 10.5, whiteSpace: "nowrap" }}>레지스트리 키 마지막 기록 시각</span>}</div><span style={{ alignSelf: "center", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: entry.host.id === currentHostId ? "var(--accent)" : "var(--text-dim)", fontSize: 12 }}>{entry.host.name}</span><EntryOpenButton entry={entry} onOpen={onOpen} /><button type="button" onClick={() => onRemove(entry.bookmark)} aria-label={`${eventTitle(entry)} 북마크 제거`} style={{ alignSelf: "center", display: "grid", placeItems: "center", width: 28, height: 28, border: "1px solid transparent", borderRadius: "var(--radius-sm)", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><DeleteOutlineOutlinedIcon sx={{ fontSize: 16 }} /></button></article>;
}

function participantKeyForHost(host: { id: string; name: string }): string {
  return host.id ? `host:${host.id}` : `host-name:${host.name}`;
}

/**
 * A loopback address is local evidence, never an external participant. Accept
 * bracketed/port-qualified display forms as well as common localhost names so
 * a parser's formatting cannot accidentally create a peer lane.
 */
export function isLocalLoopbackPeer(value: string): boolean {
  const raw = value.trim().toLocaleLowerCase();
  if (!raw) return false;
  const hostName = /^[a-z][a-z0-9.-]*:\d+$/.test(raw) ? raw.replace(/:\d+$/, "") : raw;
  if (hostName === "localhost" || hostName === "localhost.localdomain") return true;
  const bracketed = raw.match(/^\[([^\]]+)](?::\d+)?$/)?.[1] ?? raw;
  const withoutZone = bracketed.replace(/%[\w.-]+$/, "");
  const address = /^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(withoutZone)
    ? withoutZone.replace(/:\d+$/, "")
    : withoutZone;
  return /^127(?:\.\d{1,3}){3}$/.test(address)
    || address === "::1"
    || address === "0:0:0:0:0:0:0:1"
    || /^::ffff:127(?:\.\d{1,3}){3}$/.test(address);
}

function sequenceDirectionLabel(direction: SequenceEntry["direction"]): string {
  if (direction === "inbound") return "인바운드";
  if (direction === "outbound") return "아웃바운드";
  return "방향 정보 없음";
}

function sequenceParticipants(entries: SequenceEntry[], currentHostId: string | null): SequenceParticipant[] {
  const registered = new Map<string, SequenceParticipant>();
  const unmatchedPeers = new Map<string, SequenceParticipant>();
  for (const entry of entries) {
    const sourceKey = participantKeyForHost(entry.host);
    registered.set(sourceKey, { key: sourceKey, label: entry.host.name });
    if (entry.peer && !entry.isLoopback && entry.peerHostId) {
      const peer = { id: entry.peerHostId, name: entry.peerHostName };
      registered.set(participantKeyForHost(peer), { key: participantKeyForHost(peer), label: peer.name });
    } else if (entry.peer && !entry.isLoopback) {
      unmatchedPeers.set(`peer:${entry.peer}`, { key: `peer:${entry.peer}`, label: entry.peerHostName || entry.peer });
    }
  }
  const registeredSorted = [...registered.values()].sort((left, right) => left.label.localeCompare(right.label, "ko"));
  const currentKey = currentHostId ? `host:${currentHostId}` : "";
  const current = registered.get(currentKey);
  return [...(current ? [current] : []), ...registeredSorted.filter((participant) => participant.key !== currentKey), ...[...unmatchedPeers.values()].sort((left, right) => left.label.localeCompare(right.label, "ko"))];
}

function HostFlowLedger({ entries, undatedEntries, unresolvedEntries, currentHostId, onOpen, onRemove, accountDirectoryForHost }: { entries: SequenceEntry[]; undatedEntries: BookmarkEntry[]; unresolvedEntries: BookmarkEntry[]; currentHostId: string | null; onOpen: (entry: BookmarkEntry) => void; onRemove: (bookmark: Bookmark) => void; accountDirectoryForHost?: (hostId: string) => AccountDirectory | undefined }) {
  const participants = sequenceParticipants(entries, currentHostId);
  if (entries.length === 0 && undatedEntries.length === 0 && unresolvedEntries.length === 0) return <div role="status" style={{ display: "grid", placeItems: "center", flex: 1, minHeight: 0, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 시간 정보가 있는 북마크가 없습니다.</div>;
  const timeGutter = 196;
  const laneWidth = 220;
  const canvasWidth = Math.max(680, participants.length * laneWidth);
  const canvasHeight = Math.max(150, 48 + entries.length * 64);
  return <section aria-label="호스트 흐름 시퀀스 다이어그램" style={{ flex: 1, minHeight: 0, overflow: "auto" }}><div style={{ minWidth: timeGutter + canvasWidth, paddingBottom: 10 }}>
    <div style={{ position: "sticky", top: 0, zIndex: 3, display: "grid", gridTemplateColumns: `${timeGutter}px ${canvasWidth}px`, borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
      <div aria-hidden="true" style={{ display: "flex", alignItems: "flex-end", padding: "0 10px 10px 14px", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}>시간 축</div>
      <div aria-label="시퀀스 참여 호스트" style={{ position: "relative", height: 54 }}>{participants.map((participant, index) => <div key={participant.key} style={{ position: "absolute", left: `${((index + .5) / Math.max(participants.length, 1)) * 100}%`, bottom: 9, width: laneWidth - 18, transform: "translateX(-50%)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: participant.key === `host:${currentHostId}` ? "var(--accent)" : "var(--text-dim)", fontSize: 12, fontWeight: 700, textAlign: "center" }}>{participant.label}</div>)}</div>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: `${timeGutter}px ${canvasWidth}px`, minHeight: canvasHeight }}>
      <div aria-label="시간순 이벤트" style={{ position: "relative", borderRight: "1px solid var(--border)" }}>{entries.map((entry, index) => <div key={entry.bookmark.id} style={{ position: "absolute", top: 48 + index * 64 - 12, right: 8, left: 14, minHeight: 24 }}><time style={{ position: "absolute", left: 0, right: 30, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 10.5, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(entry.eventTime)}</time>{entry.eventTimeLabel === "레지스트리 키 마지막 기록 시각" && <span style={{ position: "absolute", top: 15, left: 0, right: 30, color: "var(--text-faint)", fontSize: 9.5, whiteSpace: "nowrap" }}>레지스트리 키 마지막 기록 시각</span>}<button type="button" onClick={() => onRemove(entry.bookmark)} aria-label={`${eventTitle(entry)} 북마크 제거`} style={{ position: "absolute", right: 0, top: -5, display: "grid", placeItems: "center", width: 24, height: 24, padding: 0, border: "1px solid transparent", borderRadius: "var(--radius-sm)", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><DeleteOutlineOutlinedIcon sx={{ fontSize: 15 }} /></button></div>)}</div>
      <div role="list" aria-label="시간순 호스트 메시지" style={{ position: "relative", minHeight: canvasHeight }}>{participants.map((participant, index) => <span aria-hidden="true" key={participant.key} style={{ position: "absolute", top: 0, bottom: 0, left: `${((index + .5) / Math.max(participants.length, 1)) * 100}%`, borderLeft: "1px solid var(--border)", background: participant.key === `host:${currentHostId}` ? "color-mix(in srgb, var(--accent) 5%, transparent)" : "transparent" }} />)}{entries.map((entry, index) => <SequenceCanvasEvent key={entry.bookmark.id} entry={entry} index={index} participants={participants} onOpen={onOpen} accountDirectory={accountDirectoryForHost?.(entry.host.id)} />)}</div>
    </div>
    {(undatedEntries.length > 0 || unresolvedEntries.length > 0) && <div style={{ marginTop: 10, borderTop: "1px solid var(--border)" }}><div style={{ padding: "9px 14px 6px", color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700 }}>시간 축에 배치할 수 없는 항목</div>{[...undatedEntries, ...unresolvedEntries].map((entry) => <TimelineRow key={entry.bookmark.id} entry={entry} currentHostId={currentHostId} onOpen={onOpen} onRemove={onRemove} />)}</div>}
  </div></section>;
}


function SequenceCanvasEvent({ entry, index, participants, onOpen, accountDirectory }: { entry: SequenceEntry; index: number; participants: SequenceParticipant[]; onOpen: (entry: BookmarkEntry) => void; accountDirectory?: AccountDirectory }) {
  const sourceKey = participantKeyForHost(entry.host);
  const peerKey = entry.peer && !entry.isLoopback ? (entry.peerHostId ? `host:${entry.peerHostId}` : `peer:${entry.peer}`) : "";
  const sourceIndex = participants.findIndex((participant) => participant.key === sourceKey);
  const peerIndex = participants.findIndex((participant) => participant.key === peerKey);
  const hasDirectedPeer = (entry.direction === "inbound" || entry.direction === "outbound") && Boolean(entry.peer) && sourceIndex >= 0 && peerIndex >= 0 && sourceIndex !== peerIndex;
  const fromIndex = entry.direction === "inbound" ? peerIndex : sourceIndex;
  const toIndex = entry.direction === "inbound" ? sourceIndex : peerIndex;
  const connectorText = hasDirectedPeer ? `${participants[fromIndex]?.label}에서 ${participants[toIndex]?.label}로 ${entry.direction === "inbound" ? "인바운드" : "아웃바운드"} 연결` : entry.isLoopback ? `루프백 주소 ${entry.peer} · 원본 방향: ${sequenceDirectionLabel(entry.direction)}` : entry.peer && sourceIndex === peerIndex ? "동일 호스트 기록" : entry.peer && entry.direction === "unknown" ? "상대 호스트는 있으나 연결 방향 정보 없음" : "연결 방향 또는 상대 호스트 정보 없음";
  const start = hasDirectedPeer ? ((fromIndex + .5) / participants.length) * 100 : ((Math.max(sourceIndex, 0) + .5) / Math.max(participants.length, 1)) * 100;
  const end = hasDirectedPeer ? ((toIndex + .5) / participants.length) * 100 : start;
  const movesRight = start < end;
  const lineLeft = Math.min(start, end);
  const lineWidth = Math.abs(end - start);
  const labelLeft = hasDirectedPeer ? Math.min(94, lineLeft + Math.max(2, lineWidth / 2)) : Math.min(94, start + 2);
  const rawAccount = entry.row?.account || entry.row?.user || entry.row?.username || "";
  const account = resolveAccountDisplay(rawAccount, accountDirectory);
  const result = entry.row?.result || entry.row?.status || "";
  const eventLabel = [eventTitle(entry), account, result].filter((value, position, all) => Boolean(value) && all.indexOf(value) === position).join(" · ");
  const top = 48 + index * 64;
  return <div role="listitem" style={{ position: "absolute", top: top - 26, left: 0, right: 0, height: 58 }}>
    <button type="button" onClick={() => onOpen(entry)} aria-label={`${formatEvidenceTimestamp(entry.eventTime)} ${connectorText}. ${eventTitle(entry)} 상세 보기`} style={{ position: "absolute", inset: 0, width: "100%", padding: 0, border: "none", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
      {hasDirectedPeer ? <span aria-hidden="true" style={{ position: "absolute", left: `${lineLeft}%`, top: 26, width: `${lineWidth}%`, borderTop: "2px solid var(--accent)", color: "var(--accent)" }}>{movesRight ? <ArrowForwardOutlinedIcon sx={{ position: "absolute", right: -8, top: -10, fontSize: 18, background: "var(--bg-panel)" }} /> : <ArrowBackOutlinedIcon sx={{ position: "absolute", left: -8, top: -10, fontSize: 18, background: "var(--bg-panel)" }} />}</span> : entry.isLoopback ? <span aria-hidden="true" style={{ position: "absolute", left: `calc(${start}% - 9px)`, top: 18, width: 16, height: 15, border: "2px solid var(--accent)", borderTop: "none", borderRadius: "0 0 10px 10px", background: "var(--bg-panel)" }} /> : <span aria-hidden="true" style={{ position: "absolute", left: `calc(${start}% - 5px)`, top: 21, width: 10, height: 10, border: "2px solid var(--text-faint)", borderRadius: "50%", background: "var(--bg-panel)" }} />}
      <span aria-hidden="true" style={{ position: "absolute", left: `${labelLeft}%`, top: 0, width: "min(300px, 42%)", padding: "2px 6px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", background: "var(--bg-panel)", color: hasDirectedPeer ? "var(--text)" : "var(--text-dim)", fontSize: 11.5, fontWeight: 650 }}>{eventLabel}</span>
      <span style={visuallyHidden}>{connectorText}</span>
    </button>
    <span aria-hidden="true" style={{ position: "absolute", left: `${labelLeft}%`, top: 35, width: "min(300px, 42%)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: hasDirectedPeer ? "var(--accent)" : "var(--text-faint)", fontSize: 10.5 }}>{connectorText}</span>
  </div>;
}
