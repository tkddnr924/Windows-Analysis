"use client";
import CloudDownloadOutlinedIcon from "@mui/icons-material/CloudDownloadOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { bareAccount } from "@/lib/viewShared";

const TABLE = "BitsHistory";
const PAGE = 10;
const RESULT_COLOR: Record<string, string> = {
  성공: "var(--success)",
  실패: "var(--danger)",
};

interface Row {
  __rowid?: number;
  timestamp?: string;
  job_name?: string;
  job_id?: string;
  url?: string;
  account?: string;
  process?: string;
  bytes_transferred?: string;
  bytes_total?: string;
  status?: string;
  result?: string;
  description?: string;
  event_id?: string;
  record_key?: string;
}

interface Job {
  key: string;
  name: string;
  urls: string[];
  accounts: string[];
  attempts: number;
  fail: number;
  success: number;
  first: string;
  last: string;
  events: Row[];
}

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

type ResultFilter = "all" | "fail" | "success";

function fmtBytes(raw: string | undefined): string {
  const n = Number(raw);
  if (!raw || !Number.isFinite(n) || n < 0) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * BITS transfer events are grouped into their download job (job GUID first,
 * falling back to the job name) so an analyst reads one job = one card, with
 * the raw create→transfer→complete events preserved in the expansion.
 */
export default function BitsView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
  accountDirectory,
}: Props) {
  const [query, setQuery] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [sortDir, setSortDir] = useState("asc");
  const [page, setPage] = useState(0);
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);

  const jobs = useMemo(() => {
    const byKey = new Map<string, Job>();
    for (const raw of data.rows as Row[]) {
      const timestamp = raw.timestamp ?? "";
      if (!inRange(timestamp, timeRange)) continue;
      if (hiddenAccounts.has(bareAccount(raw.account ?? ""))) continue;

      const key = raw.job_id || raw.job_name || "(작업 정보 없음)";
      const job = byKey.get(key) ?? {
        key,
        name: raw.job_name || "",
        urls: [],
        accounts: [],
        attempts: 0,
        fail: 0,
        success: 0,
        first: timestamp,
        last: timestamp,
        events: [],
      };
      if (!byKey.has(key)) byKey.set(key, job);

      job.attempts += 1;
      if (!job.name && raw.job_name) job.name = raw.job_name;
      if (raw.result === "실패") job.fail += 1;
      if (raw.result === "성공") job.success += 1;
      if (raw.url && !job.urls.includes(raw.url)) job.urls.push(raw.url);
      const account = bareAccount(raw.account ?? "");
      if (account && !job.accounts.includes(account)) job.accounts.push(account);
      if (timestamp) {
        if (!job.first || timestamp < job.first) job.first = timestamp;
        if (!job.last || timestamp > job.last) job.last = timestamp;
      }
      job.events.push(raw);
    }

    return [...byKey.values()].map((job) => ({
      ...job,
      events: job.events.sort((left, right) => (left.timestamp ?? "").localeCompare(right.timestamp ?? "")),
    }));
  }, [data.rows, timeRange, hiddenAccounts]);

  const allAccounts = useMemo(
    () => [...new Set((data.rows as Row[]).map((raw) => bareAccount(raw.account ?? "")))].filter(Boolean).sort((a, b) => a.localeCompare(b)),
    [data.rows],
  );

  const shownJobs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = jobs.filter((job) => {
      if (resultFilter === "fail" && job.fail === 0) return false;
      if (resultFilter === "success" && job.success === 0) return false;
      if (!needle) return true;
      return (
        job.name.toLowerCase().includes(needle) ||
        job.urls.some((url) => url.toLowerCase().includes(needle)) ||
        job.accounts.some((account) => account.toLowerCase().includes(needle))
      );
    });
    return filtered.sort((left, right) => {
      const compared = (left.first || "￿").localeCompare(right.first || "￿");
      return sortDir === "asc" ? compared : -compared;
    });
  }, [jobs, query, resultFilter, sortDir]);

  const eventCount = useMemo(() => shownJobs.reduce((count, job) => count + job.attempts, 0), [shownJobs]);
  const pageCount = Math.max(1, Math.ceil(shownJobs.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pagedJobs = shownJobs.slice(safePage * PAGE, safePage * PAGE + PAGE);

  function toggle(key: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0, background: "var(--bg)" }}>
      <ViewHeader icon={CloudDownloadOutlinedIcon} title="BITS 전송 이력" meta={`${shownJobs.length.toLocaleString()}개 작업 · ${eventCount.toLocaleString()}건`}>
        <HeaderSearchInput value={query} onChange={(next) => { setPage(0); setQuery(next); }} placeholder="작업 · URL · 계정 검색" ariaLabel="BITS 전송 이력 검색" width={300} />
        <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
        <SortDropdown value={sortDir} onChange={setSortDir} />
        <SelectDropdown
          icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />}
          label="결과"
          options={[
            { value: "all", label: "전체" },
            { value: "success", label: "성공", color: "var(--success)" },
            { value: "fail", label: "실패", color: "var(--danger)" },
          ]}
          value={resultFilter}
          onChange={(next) => { setPage(0); setResultFilter(next as ResultFilter); }}
        />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {shownJobs.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {jobs.length === 0 ? "기간 내 BITS 전송 이력이 없습니다." : "검색 또는 필터 조건에 맞는 BITS 전송 이력이 없습니다."}
          </div>
        ) : pagedJobs.map((job) => {
          const open = expanded.has(job.key);
          // 카드 타일 색으로 전송 결과 신호: 실패만 있으면 danger, 성공이
          // 섞이면 success, 결과 이벤트가 없으면 중립.
          const jobColor = job.fail > 0 && job.success === 0 ? "var(--danger)" : job.success > 0 ? "var(--success)" : "var(--text-dim)";
          const urlLabel = job.urls.length ? job.urls[0] : "URL 정보 없음";
          const accountsLabel = job.accounts.length ? job.accounts.map((account) => resolveAccountDisplay(account, accountDirectory)).join(", ") : "계정 정보 없음";
          const sameDay = job.first.slice(0, 10) === job.last.slice(0, 10);
          return (
            <section key={job.key} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${jobColor} 42%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
              <button
                type="button"
                onClick={() => toggle(job.key)}
                aria-expanded={open}
                aria-label={`${job.name || "이름 없는 작업"} 전송 이벤트 ${job.attempts}건 ${open ? "접기" : "펼치기"}`}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${jobColor} 6%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .18s ease", outlineOffset: -2 }}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${jobColor} 6%, transparent)` : "transparent"; }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${jobColor} 15%, transparent)` }}>
                  <CloudDownloadOutlinedIcon sx={{ fontSize: 17, color: jobColor }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: job.name ? "var(--text)" : "var(--text-faint)" }}>{job.name || "(작업 이름 없음)"}</span>
                    {job.urls.length > 1 && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>URL {job.urls.length}개</span>}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    <span title={urlLabel} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", color: job.urls.length ? "var(--text-dim)" : "var(--text-faint)" }}>{urlLabel}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span title={accountsLabel} style={{ flexShrink: 0, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: job.accounts.length ? "var(--text-dim)" : "var(--text-faint)" }}>{accountsLabel}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {job.attempts.toLocaleString()}건</span>
                  </span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, fontSize: 12 }}>
                  {job.success > 0 && <ResultPill color="var(--success)">성공 {job.success.toLocaleString()}</ResultPill>}
                  {job.fail > 0 && <ResultPill color="var(--danger)">실패 {job.fail.toLocaleString()}</ResultPill>}
                  {job.success === 0 && job.fail === 0 && <span style={{ color: "var(--text-faint)" }}>결과 정보 없음</span>}
                </span>
                <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {job.first ? (<>{job.first} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? job.last.slice(11) : job.last}</>) : "시간 정보 없음"}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label={`원본 이벤트 ${job.attempts}건`} style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {job.events.map((event, index) => {
                    const rowid = Number((event as Record<string, unknown>).__rowid);
                    const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                    const resultColor = RESULT_COLOR[event.result ?? ""] ?? "var(--text-faint)";
                    const bytes = fmtBytes(event.bytes_transferred);
                    return (
                      <div key={`${rowid}-${event.timestamp}-${index}`} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", transition: "background .15s ease" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "transparent"; }}>
                        <div role="button" tabIndex={0} onClick={() => setSelected(event as Record<string, string>)} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelected(event as Record<string, string>); } }} style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, color: "var(--text)", cursor: "pointer", outlineOffset: 2 }}>
                          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{event.timestamp || "시간 정보 없음"}</span>
                          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: resultColor }} />
                          <span style={{ flexShrink: 0, color: resultColor, fontSize: 12, fontWeight: 700, width: 34 }}>{event.result || "정보"}</span>
                          <span title={event.description || "상세 정보 없음"} style={{ width: 170, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 12.5 }}>{event.description || "상세 정보 없음"}</span>
                          <span title={event.url || ""} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: event.url ? "var(--text-dim)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 12 }}>{event.url || ""}</span>
                          {bytes && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{bytes}</span>}
                          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.event_id ? `EID ${event.event_id}` : ""}</span>
                        </div>
                        {onToggleBookmark && Number.isFinite(rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={() => onToggleBookmark(rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
        {shownJobs.length > 0 && (
          <PaginationControls
            ariaLabel="BITS 작업 페이지"
            page={safePage}
            pageCount={pageCount}
            onChange={setPage}
            summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, shownJobs.length).toLocaleString()} / ${shownJobs.length.toLocaleString()})`}
          />
        )}
      </main>

      {selected && spec && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
    </div>
  );
}

function ResultPill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ color, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}
