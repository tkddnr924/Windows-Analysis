"use client";
import PaginationControls from "@/components/PaginationControls";
import { ViewHeader } from "@/components/FilterControls";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";

import { useEffect, useRef, useState } from "react";
import OpenInNewOutlinedIcon from "@mui/icons-material/OpenInNewOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import type { FetchLinkedRows, Host, ResultRow, SearchHit } from "@/lib/types";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { formatEvidenceTimestamp, rangeActive, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { pathBelongsToHost } from "@/lib/viewShared";

interface Props {
  hosts: Host[];
  currentHostId: string | null;
  timeRange: TimeRange;
  isBookmarked: (hit: SearchHit) => boolean;
  onOpenSource: (hit: SearchHit) => void;
  onToggleBookmark: (hit: SearchHit) => void;
  onFetchLinkedRows: FetchLinkedRows;
  accountDirectoryForHost?: (hostId: string) => AccountDirectory | undefined;
}

type DetailState = { hit: SearchHit; result?: ResultRow; error?: "fetch" | "missing" };
const PAGE_SIZE = 10;


function hostDirForHit(hit: SearchHit, hosts: Host[]): string | undefined {
  // The backend-provided host id is authoritative. The path relation is only
  // a backward-compatible fallback for saved records without that id.
  const exactHost = hosts.find((host) => host.id === hit.hostId);
  if (exactHost) return exactHost.dir;
  if (hit.hostId) return undefined;
  return hosts.find((host) => pathBelongsToHost(hit.fullPath, host.dir))?.dir;
}

function Button({ children, onClick, disabled = false, primary = false, ariaLabel }: { children: React.ReactNode; onClick: () => void; disabled?: boolean; primary?: boolean; ariaLabel?: string }) {
  return <button type="button" className="nm-btn" onClick={onClick} disabled={disabled} aria-label={ariaLabel} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 5, minHeight: 30, padding: "4px 9px", border: `1px solid ${primary ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: primary ? "var(--accent-subtle)" : "var(--bg-elevated)", color: primary ? "var(--accent)" : "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.55 : 1, fontSize: 11.5, fontWeight: primary ? 700 : 600 }}>{children}</button>;
}

export default function CaseSearchView({ hosts, currentHostId, timeRange, isBookmarked, onOpenSource, onToggleBookmark, onFetchLinkedRows, accountDirectoryForHost }: Props) {
  const [query, setQuery] = useState("");
  const [ran, setRan] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [sourceFailures, setSourceFailures] = useState<string[]>([]);
  const [resultRangeKey, setResultRangeKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorRangeKey, setErrorRangeKey] = useState<string | null>(null);
  const [detail, setDetail] = useState<DetailState | null>(null);
  const requestId = useRef(0);
  const detailRequestId = useRef(0);

  const searchRange = rangeActive(timeRange) ? { start: timeRange.start, end: timeRange.end } : undefined;
  const rangeKey = `${timeRange.start || ""}\u0000${timeRange.end || ""}`;

  async function runSearch(searchText: string, targetPage = 0) {
    const normalized = searchText.trim();
    if (normalized.length < 2) return;
    const request = ++requestId.current;
    const requestedRangeKey = rangeKey;
    setLoading(true);
    setError(null);
    setErrorRangeKey(null);
    try {
      const result = await window.api.searchCase(normalized, hosts.map((host) => ({ id: host.id, name: host.name, dir: host.dir })), targetPage * PAGE_SIZE, PAGE_SIZE, searchRange);
      if (request !== requestId.current) return;
      setHits(result.hits);
      setNextOffset(result.nextOffset);
      setSourceFailures(result.sourceFailures);
      setRan(normalized);
      setPage(targetPage);
      setResultRangeKey(requestedRangeKey);
    } catch {
      if (request !== requestId.current) return;
      setError("검색 결과를 불러오지 못했습니다. 다시 시도하세요.");
      setErrorRangeKey(requestedRangeKey);
    } finally {
      if (request === requestId.current) setLoading(false);
    }
  }

  function startSearch() {
    void runSearch(query, 0);
  }

  function retrySearch() {
    void runSearch(ran || query, page);
  }

  // A global incident-window change must never relabel results produced for a
  // different range. Hide that ledger immediately, then restart the last
  // successful query from its first page using the new bounds.
  useEffect(() => {
    if (!ran || resultRangeKey === rangeKey) return;
    void runSearch(ran, 0);
  }, [rangeKey, ran, resultRangeKey]);

  async function openDetail(hit: SearchHit) {
    const request = ++detailRequestId.current;
    setDetail({ hit });
    try {
      const result = await window.api.resultRow(hit.fullPath, hit.tableName, hit.rowid);
      if (request !== detailRequestId.current) return;
      setDetail(result.row ? { hit, result } : { hit, error: "missing" });
    } catch {
      if (request === detailRequestId.current) setDetail({ hit, error: "fetch" });
    }
  }

  function closeDetail() {
    detailRequestId.current += 1;
    setDetail(null);
  }

  const resultMatchesCurrentRange = !ran || resultRangeKey === rangeKey;
  const visibleHits = resultMatchesCurrentRange ? hits : [];
  const visibleSourceFailures = resultMatchesCurrentRange ? sourceFailures : [];
  const visibleError = error && errorRangeKey === rangeKey ? error : null;
  const rangeRefreshing = Boolean(ran && !resultMatchesCurrentRange && !visibleError);
  const noResults = ran && resultMatchesCurrentRange && !loading && hits.length === 0 && !visibleError;
  return (
    <main className="dfir-view" aria-labelledby="case-search-title" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={SearchOutlinedIcon} title="케이스 전체 검색" titleId="case-search-title" right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeActive(timeRange) ? "전역 기간 필터 적용" : "전체 기간"}</span>}>
        <label style={{ flex: "0 1 380px", minWidth: 230 }}><input value={query} autoFocus onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") startSearch(); }} aria-label="케이스 전체 검색어" placeholder="IP · 계정 · 파일명 · 명령 검색 (2자 이상)" style={{ width: "100%", minHeight: 31, padding: "5px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-elevated)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5 }} /></label>
        <Button onClick={startSearch} disabled={loading || query.trim().length < 2} primary>{loading ? <CircularProgress size={14} thickness={5} aria-label="검색 중" /> : "검색"}</Button>
      
      </ViewHeader>

      {visibleSourceFailures.length > 0 && <div role="alert" style={{ padding: "8px 14px", borderBottom: "1px solid color-mix(in srgb, var(--warning) 42%, var(--border))", background: "color-mix(in srgb, var(--warning) 7%, var(--bg-panel))", color: "var(--text-dim)", fontSize: 12 }}>일부 원본을 검색하지 못했습니다: {visibleSourceFailures.join(", ")}. 표시된 결과는 성공적으로 읽은 원본만 포함합니다.</div>}
      {visibleError && <div role="alert" style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 14px", borderBottom: "1px solid color-mix(in srgb, var(--danger) 42%, var(--border))", background: "color-mix(in srgb, var(--danger) 7%, var(--bg-panel))", color: "var(--text)", fontSize: 12 }}>{visibleError}<span style={{ marginLeft: "auto" }}><Button onClick={retrySearch}><RefreshOutlinedIcon sx={{ fontSize: 15 }} />다시 시도</Button></span></div>}

      {ran && resultMatchesCurrentRange && (visibleHits.length > 0 || !loading) && <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 14px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 11.5 }}><span><strong style={{ color: "var(--text-dim)" }}>&quot;{ran}&quot;</strong> 검색 결과 · {hits.length === 0 ? "0건" : `${(page * PAGE_SIZE + 1).toLocaleString()}–${(page * PAGE_SIZE + hits.length).toLocaleString()}건 표시`}{nextOffset !== null ? " · 다음 페이지 있음" : ""}</span></div>}

      <section aria-label="검색 결과 원장" style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {!ran && !loading && <EmptyState><SearchOutlinedIcon sx={{ fontSize: 28, color: "var(--text-faint)" }} />검색어를 입력한 뒤 검색을 실행하세요.</EmptyState>}
        {(loading || rangeRefreshing) && visibleHits.length === 0 && <EmptyState><CircularProgress size={18} thickness={5} aria-label="케이스 전체 검색 중" />{rangeRefreshing ? "변경된 기간 필터로 검색 결과를 갱신하는 중입니다." : "모든 호스트의 원본을 검색하는 중입니다."}</EmptyState>}
        {noResults && <EmptyState><SearchOutlinedIcon sx={{ fontSize: 28, color: "var(--text-faint)" }} />일치하는 결과가 없습니다.</EmptyState>}
        {visibleHits.length > 0 && <div style={{ minWidth: 760, padding: "12px 14px 4px", opacity: loading ? 0.55 : 1, transition: "opacity .15s ease" }}>
          {visibleHits.map((hit, index) => <SearchLedgerRow key={`${hit.hostId}\u0000${hit.fullPath}\u0000${hit.tableName}\u0000${hit.rowid}\u0000${index}`} hit={hit} bookmarked={isBookmarked(hit)} currentHostId={currentHostId} onOpen={() => void openDetail(hit)} onOpenSource={() => onOpenSource(hit)} />)}
          <div style={{ display: "flex", justifyContent: "center", padding: "4px 0 12px" }}>
            <PaginationControls ariaLabel="검색 결과 페이지" page={page} pageCount={page + 1 + (nextOffset !== null ? 1 : 0)} disabled={loading} onChange={(next) => void runSearch(ran, next)} summary={`(${(page * PAGE_SIZE + 1).toLocaleString()}–${(page * PAGE_SIZE + hits.length).toLocaleString()})`} />
          </div>
        </div>}
      </section>

      {detail && !detail.result && <DetailStatus detail={detail} onClose={closeDetail} onRetry={() => void openDetail(detail.hit)} />}
      {detail?.result && <RowDetailPanel row={detail.result.row!} columns={detail.result.columns} focusedColumn={detail.hit.matchColumn || null} fileBaseName={detail.hit.tableName} onClose={closeDetail} onNavigate={() => {}} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDirForHit(detail.hit, hosts)} accountDirectory={accountDirectoryForHost?.(detail.hit.hostId)} isBookmarked={isBookmarked(detail.hit)} onToggleBookmark={() => onToggleBookmark(detail.hit)} />}
    </main>
  );
}

function SearchLedgerRow({ hit, bookmarked, currentHostId, onOpen, onOpenSource }: { hit: SearchHit; bookmarked: boolean; currentHostId: string | null; onOpen: () => void; onOpenSource: () => void }) {
  const hostColor = hit.hostId === currentHostId ? "var(--accent)" : "var(--text-dim)";
  return (
    <article className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", transition: "background .15s ease, border-color .15s ease" }}
      onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
      <button type="button" onClick={onOpen} aria-label={`${hit.hostName} ${hit.fileName} 검색 결과 상세 보기`} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
        <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "var(--accent-subtle)" }}>
          <SearchOutlinedIcon sx={{ fontSize: 17, color: "var(--accent)" }} />
        </span>
        <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
          <span title={hit.matchValue} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 650 }}>{hit.matchValue || "값 없음"}</span>
          <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 12 }}>{hit.fileName || hit.tableName} · {hit.matchColumn || "일치 필드 없음"}</span>
        </span>
        <span style={{ flexShrink: 0, maxWidth: 130, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, fontWeight: 700, color: hostColor, border: `1px solid ${hostColor}`, borderRadius: "var(--radius-sm)", padding: "1px 8px" }}>{hit.hostName || "알 수 없는 호스트"}</span>
        <time style={{ flexShrink: 0, width: 172, textAlign: "right", color: hit.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12.5, whiteSpace: "nowrap" }}>{hit.timestamp ? formatEvidenceTimestamp(hit.timestamp) : "시간 정보 없음"}</time>
      </button>
      <span style={{ flexShrink: 0 }}><Button onClick={onOpenSource} ariaLabel={`${hit.fileName || hit.tableName} 원본 위치 열기`}><OpenInNewOutlinedIcon sx={{ fontSize: 15 }} /></Button></span>
    </article>
  );
}

function DetailStatus({ detail, onClose, onRetry }: { detail: DetailState; onClose: () => void; onRetry: () => void }) {
  const loading = !detail.error;
  const message = loading ? "원본 행을 불러오는 중입니다." : detail.error === "missing" ? "원본 행을 찾을 수 없습니다. 결과가 다시 파싱되었을 수 있습니다." : "원본 행을 불러오지 못했습니다.";
  // Keep this non-modal: a source-row fetch must not block the rest of the
  // analysis workspace. The common RowDetailPanel opens as soon as it resolves.
  return <aside role={loading ? "status" : "alert"} aria-live="polite" aria-label="검색 결과 상세 불러오기" style={{ position: "fixed", zIndex: 70, right: 18, bottom: 18, width: "min(420px, calc(100vw - 36px))", padding: 14, border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", background: "var(--bg-panel)", boxShadow: "var(--shadow-panel)" }}><div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-dim)", fontSize: 12.5 }}>{loading && <CircularProgress size={17} thickness={5} aria-label="원본 행 로딩" />}{message}</div><div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginTop: 14 }}>{!loading && <Button onClick={onRetry}><RefreshOutlinedIcon sx={{ fontSize: 15 }} />다시 시도</Button>}<Button onClick={onClose}>닫기</Button></div></aside>;
}

function EmptyState({ children }: { children: React.ReactNode }) {
  return <div role="status" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 9, minHeight: 220, padding: 24, color: "var(--text-faint)", fontSize: 13, textAlign: "center" }}>{children}</div>;
}

const singleLine: React.CSSProperties = { minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 };
