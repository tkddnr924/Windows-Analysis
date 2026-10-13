"use client";
// 브라우저 활동과 AI 대화 (docs-07) — _OVERVIEW BrowserActivity·AiConversations와
// 자식표만 읽는다. 수집 History·캐시 파일과 facts는 다시 열지 않는다.
import { useEffect, useMemo, useState } from "react";
import AutoAwesomeOutlinedIcon from "@mui/icons-material/AutoAwesomeOutlined";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import CalendarMonthOutlinedIcon from "@mui/icons-material/CalendarMonthOutlined";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import CloseIcon from "@mui/icons-material/Close";
import DownloadOutlinedIcon from "@mui/icons-material/DownloadOutlined";
import FirstPageIcon from "@mui/icons-material/FirstPage";
import Inventory2Icon from "@mui/icons-material/Inventory2";
import Inventory2OutlinedIcon from "@mui/icons-material/Inventory2Outlined";
import LanguageOutlinedIcon from "@mui/icons-material/LanguageOutlined";
import LastPageIcon from "@mui/icons-material/LastPage";
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import ListAltOutlinedIcon from "@mui/icons-material/ListAltOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PsychologyOutlinedIcon from "@mui/icons-material/PsychologyOutlined";
import SmartToyOutlinedIcon from "@mui/icons-material/SmartToyOutlined";
import SortIcon from "@mui/icons-material/SortOutlined";
import SummarizeOutlinedIcon from "@mui/icons-material/SummarizeOutlined";
import TextsmsOutlinedIcon from "@mui/icons-material/TextsmsOutlined";
import TravelExploreOutlinedIcon from "@mui/icons-material/TravelExploreOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import type { AiPage, AiRecord, BrowserDomainPage, BrowserFilter, BrowserInputInfo, BrowserPage, BrowserSummary } from "@/lib/types";
import { EMPTY_TIME_RANGE, toBound, type TimeRange } from "@/lib/timeRange";
import { KIND_LABELS, attachmentsByMessage, browserScopes, messageThread } from "@/lib/browserView";
import RowDetailPanel from "./RowDetailPanel";
import { useModalDialog } from "@/lib/useModalDialog";
import PaginationControls from "@/components/PaginationControls";
import { HeaderSearchInput, MultiSelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

type Row = Record<string, string>;
type DayMode = { kind: "day"; day: string } | { kind: "all" } | { kind: "untimed" };
type AiPanel = "conversation" | "list_entry" | "referral";

interface Props {
  /** _OVERVIEW/BrowserActivity.sqlite */
  dbPath: string;
  /** _OVERVIEW/AiConversations.sqlite (absent in older results). */
  aiDbPath?: string | null;
  hostDir?: string;
  timeRange?: TimeRange;
  isRowBookmarked?: (row: Row) => boolean;
  /** The row carries its representative time into the bookmark. */
  onToggleBookmark?: (row: Row) => void;
  isAiRowBookmarked?: (row: Row) => boolean;
  onToggleAiBookmark?: (row: Row) => void;
}

const PAGE_SIZE = 10;
const AI_PAGE_SIZE = 10;
const DOMAIN_PAGE_SIZE = 10;
const DEFAULT_KINDS = ["visit", "download", "cache"];
const DOW = ["일", "월", "화", "수", "목", "금", "토"];
const rowidOf = (row: Row) => Number((row as Record<string, unknown>).__rowid);
const pad = (value: number) => String(value).padStart(2, "0");

function shiftMonth(value: { y: number; m: number }, delta: number) {
  let m = value.m + delta;
  let y = value.y;
  if (m < 1) { m = 12; y -= 1; }
  if (m > 12) { m = 1; y += 1; }
  return { y, m };
}

function calendarGrid(y: number, m: number): (number | null)[] {
  const cells: (number | null)[] = [];
  for (let index = 0; index < new Date(y, m - 1, 1).getDay(); index += 1) cells.push(null);
  for (let day = 1; day <= new Date(y, m, 0).getDate(); day += 1) cells.push(day);
  while (cells.length % 7 !== 0) cells.push(null);
  return cells;
}

// Neutral category marks, not provider brand assets.
function providerIcon(provider: string | undefined) {
  const normalized = (provider ?? "").toLowerCase();
  return normalized === "chatgpt" ? PsychologyOutlinedIcon : normalized === "gemini" ? AutoAwesomeOutlinedIcon : normalized === "claude" ? TextsmsOutlinedIcon : SmartToyOutlinedIcon;
}

const navigationButton: React.CSSProperties = { display: "inline-flex", alignItems: "center", justifyContent: "center", width: 26, height: 26, padding: 0, borderRadius: "var(--radius)", background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--text-dim)", cursor: "pointer" };
const pageButton = (disabled: boolean): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 2, minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.42 : 1, fontSize: 12 });
const chip = (tone: string): React.CSSProperties => ({ flexShrink: 0, display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10.5, fontWeight: 650, color: tone, background: `color-mix(in srgb, ${tone} 12%, transparent)`, borderRadius: 999, padding: "1px 7px", whiteSpace: "nowrap" });
const controlButton = (selected: boolean): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius)", border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`, background: selected ? "var(--accent-subtle)" : "var(--bg-elevated)", color: selected ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 12, fontWeight: selected ? 700 : 500 });
const card: React.CSSProperties = { minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" };

export default function BrowserActivityView({ dbPath, aiDbPath, hostDir = "", timeRange = EMPTY_TIME_RANGE, isRowBookmarked, onToggleBookmark, isAiRowBookmarked, onToggleAiBookmark }: Props) {
  const [inputs, setInputs] = useState<BrowserInputInfo[]>([]);
  const [scopeKeys, setScopeKeys] = useState<string[]>([]);
  const [kinds, setKinds] = useState<string[]>(DEFAULT_KINDS);
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState("asc");
  const [dayMode, setDayMode] = useState<DayMode | null>(null);
  const [month, setMonth] = useState<{ y: number; m: number } | null>(null);
  const [summary, setSummary] = useState<BrowserSummary | null>(null);
  const [data, setData] = useState<BrowserPage>({ rows: [], rowCount: 0 });
  const [page, setPage] = useState(0);
  const [mainTab, setMainTab] = useState<"records" | "ai">("records");
  const [aiPanel, setAiPanel] = useState<AiPanel>("conversation");
  const [aiUntimed, setAiUntimed] = useState(false);
  const [aiData, setAiData] = useState<AiPage>({ rows: [], rowCount: 0, kinds: [] });
  // Per-kind counts under the current filter, independent of the open panel.
  const [aiKinds, setAiKinds] = useState<AiPage["kinds"]>([]);
  const [aiUntimedKinds, setAiUntimedKinds] = useState<AiPage["kinds"]>([]);
  const [referrals, setReferrals] = useState<BrowserPage>({ rows: [], rowCount: 0 });
  const [aiPage, setAiPage] = useState(0);
  const [detail, setDetail] = useState<Row | null>(null);
  const [aiOpen, setAiOpen] = useState<string | null>(null);
  const [domainsOpen, setDomainsOpen] = useState(false);
  const [downloadsOpen, setDownloadsOpen] = useState(false);
  const [errors, setErrors] = useState<Record<string, string | undefined>>({});
  const [reload, setReload] = useState(0);
  const fail = (key: string, message: string) => setErrors((previous) => ({ ...previous, [key]: message }));
  const clear = (key: string) => setErrors((previous) => (previous[key] ? { ...previous, [key]: undefined } : previous));

  const scopes = useMemo(() => browserScopes(inputs), [inputs]);
  const inputIds = useMemo(() => scopes.filter((scope) => scopeKeys.includes(scope.key)).flatMap((scope) => scope.inputIds), [scopes, scopeKeys]);
  const start = toBound(timeRange.start, "start") || undefined;
  const end = toBound(timeRange.end, "end") || undefined;
  const scopeFilter = useMemo<BrowserFilter>(() => ({ inputIds, kinds, start, end }), [inputIds, kinds, start, end]);
  const days = useMemo(() => summary?.days.map((day) => day.value) ?? [], [summary]);
  const dayCounts = useMemo(() => new Map((summary?.days ?? []).map((day) => [day.value, day.count])), [summary]);
  const mode: DayMode = dayMode ?? (days.length ? { kind: "day", day: days[days.length - 1] } : { kind: "all" });
  const pageFilter = useMemo<BrowserFilter>(() => ({
    ...scopeFilter,
    search: search.trim() || undefined,
    day: mode.kind === "day" ? mode.day : undefined,
    untimed: mode.kind === "untimed",
  }), [scopeFilter, search, mode.kind, mode.kind === "day" ? mode.day : ""]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const timeout = window.setTimeout(() => setSearch(searchDraft), 280);
    return () => window.clearTimeout(timeout);
  }, [searchDraft]);
  useEffect(() => {
    let alive = true;
    window.api.browserScope(dbPath).then((result) => { if (alive) { setInputs(result); clear("scope"); } }).catch(() => { if (alive) fail("scope", "브라우저 입력을 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [dbPath, reload]);

  useEffect(() => {
    let alive = true;
    window.api.browserSummary(dbPath, scopeFilter).then((result) => { if (alive) { setSummary(result); clear("summary"); } }).catch(() => { if (alive) fail("summary", "브라우저 요약을 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [dbPath, scopeFilter, reload]);

  // A selected day that left the scope falls back to the latest day.
  useEffect(() => {
    if (dayMode?.kind === "day" && summary && !dayCounts.has(dayMode.day)) setDayMode(null);
  }, [dayMode, summary, dayCounts]);

  useEffect(() => setPage(0), [pageFilter, sort]);
  useEffect(() => {
    let alive = true;
    window.api.browserPage(dbPath, pageFilter, page * PAGE_SIZE, PAGE_SIZE, sort === "desc")
      .then((result) => { if (alive) { setData(result); clear("page"); } })
      .catch(() => { if (alive) fail("page", "브라우저 기록을 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [dbPath, pageFilter, page, sort, reload]);

  // AI lists follow the header search and the global period.
  useEffect(() => setAiPage(0), [aiPanel, aiUntimed, search, start, end, inputIds]);
  useEffect(() => {
    if (!aiDbPath) return;
    let alive = true;
    const base = { search: search.trim() || undefined, start, end };
    window.api.aiPage(aiDbPath, { ...base, untimed: true, offset: 0, limit: 1 })
      .then((result) => { if (alive) { setAiUntimedKinds(result.kinds); clear("aiUntimed"); } })
      .catch(() => { if (alive) fail("aiUntimed", "AI 시각 미상 건수를 불러오지 못했습니다."); });
    window.api.aiPage(aiDbPath, { ...base, untimed: aiUntimed, offset: 0, limit: 1 })
      .then((result) => { if (alive) { setAiKinds(result.kinds); clear("aiKinds"); } })
      .catch(() => { if (alive) fail("aiKinds", "AI 종류별 건수를 불러오지 못했습니다."); });
    if (aiPanel === "referral") return () => { alive = false; };
    window.api.aiPage(aiDbPath, { ...base, kind: aiPanel, untimed: aiUntimed, offset: aiPage * AI_PAGE_SIZE, limit: AI_PAGE_SIZE })
      .then((result) => { if (alive) { setAiData(result); clear("ai"); } })
      .catch(() => { if (alive) fail("ai", "AI 대화를 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [aiDbPath, aiPanel, aiUntimed, aiPage, search, start, end, reload]);
  useEffect(() => {
    let alive = true;
    window.api.browserPage(dbPath, { inputIds, start, end, search: search.trim() || undefined, referral: true }, aiPanel === "referral" ? aiPage * AI_PAGE_SIZE : 0, AI_PAGE_SIZE, true)
      .then((result) => { if (alive) { setReferrals(result); clear("referral"); } })
      .catch(() => { if (alive) fail("referral", "AI 유입 표식을 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [dbPath, inputIds, start, end, search, aiPanel, aiPage, reload]);

  const openRecord = (row: Row) => {
    if (!hostDir) { setDetail(row); return; }
    window.api.browserRecord(hostDir, row.record_id).then((record) => { setDetail(record.row); clear("detail"); }).catch(() => fail("detail", "기록 상세를 불러오지 못했습니다."));
  };

  const activeDay = mode.kind === "day" ? mode.day : "";
  const calendarMonth = month ?? (activeDay ? { y: Number(activeDay.slice(0, 4)), m: Number(activeDay.slice(5, 7)) } : days.length ? { y: Number(days[days.length - 1].slice(0, 4)), m: Number(days[days.length - 1].slice(5, 7)) } : { y: new Date().getFullYear(), m: new Date().getMonth() + 1 });
  const dayIndex = days.indexOf(activeDay);
  const previousDay = dayIndex > 0 ? days[dayIndex - 1] : "";
  const nextDay = dayIndex >= 0 && dayIndex < days.length - 1 ? days[dayIndex + 1] : "";
  const chooseDay = (day: string) => { setDayMode({ kind: "day", day }); setMonth(null); };
  const pageCount = Math.max(1, Math.ceil(data.rowCount / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const kindCount = (kind: string) => summary?.kinds.find((entry) => entry.value === kind)?.count;
  const aiKindCount = (kind: string) => aiKinds.find((entry) => entry.value === kind)?.count ?? 0;
  const aiTotal = aiKinds.reduce((sum, entry) => sum + entry.count, 0);
  const aiUntimedCount = aiUntimedKinds.find((entry) => entry.value === aiPanel)?.count ?? 0;
  const selectedKindTotal = (summary?.kinds ?? []).filter((entry) => kinds.includes(entry.value)).reduce((sum, entry) => sum + entry.count, 0);
  const errorMessages = Object.values(errors).filter((message): message is string => Boolean(message));
  const ledgerLabel = mode.kind === "day" ? mode.day : mode.kind === "untimed" ? "시각 미상" : "기간 전체";
  const aiRows = aiPanel === "referral" ? referrals.rows : aiData.rows;
  const aiRowCount = aiPanel === "referral" ? referrals.rowCount : aiData.rowCount;

  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
    <main style={{ flex: "1 1 auto", minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg)" }}>
      <ViewHeader icon={LanguageOutlinedIcon} title="브라우저 활동" meta={`입력 ${inputs.length} · 기록 ${selectedKindTotal.toLocaleString()}`}
        right={errorMessages.length > 0 ? <span role="alert" style={{ display: "inline-flex", alignItems: "center", gap: 7, minWidth: 0, color: "var(--warning)", fontSize: 11.5 }}><span>{errorMessages.join(" ")}</span><button className="nm-btn" type="button" onClick={() => { setErrors({}); setReload((value) => value + 1); }} style={{ flexShrink: 0, padding: "3px 7px", borderRadius: "var(--radius)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>다시 시도</button></span> : undefined}>
        <HeaderSearchInput value={searchDraft} onChange={setSearchDraft} placeholder="URL · 제목 · 경로 · 계정 · 검색어 · 대화" ariaLabel="브라우저 기록 검색" width={320} />
        <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="범위" ariaLabel="브라우저 범위" options={scopes.map((scope) => ({ value: scope.key, label: `${scope.label}${scope.owner ? ` · ${scope.owner}` : ""}`, count: scope.recordCount }))} selected={scopeKeys} onChange={(next) => { setScopeKeys(next); setDayMode(null); }} />
        <MultiSelectDropdown icon={<Inventory2OutlinedIcon sx={{ fontSize: 15 }} />} label="종류" ariaLabel="기록 종류" options={Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label, count: kindCount(value) }))} selected={kinds} onChange={(next) => { setKinds(next); setDayMode(null); }} />
        <SortDropdown value={sort} onChange={setSort} />
      </ViewHeader>

      <div style={{ flex: 1, minHeight: 0, display: "grid", gap: 10, padding: 14, gridTemplateColumns: "minmax(280px, 25%) minmax(0, 1fr)", overflow: "hidden" }}>
        <div style={{ minHeight: 0, display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
          <aside aria-label="활동 날짜 선택" style={{ flexShrink: 0, padding: 12, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ display: "flex", gap: 3 }}>
                <button className="nm-btn" onClick={() => setMonth({ y: calendarMonth.y - 1, m: calendarMonth.m })} title="이전 해" aria-label="이전 해" style={navigationButton}><FirstPageIcon sx={{ fontSize: 16 }} /></button>
                <button className="nm-btn" onClick={() => setMonth(shiftMonth(calendarMonth, -1))} title="이전 달" aria-label="이전 달" style={navigationButton}><ChevronLeftIcon sx={{ fontSize: 17 }} /></button>
              </div>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 7, fontSize: 13.5, fontWeight: 700 }}><CalendarMonthOutlinedIcon sx={{ fontSize: 16, color: "var(--accent)" }} />{calendarMonth.y}.{pad(calendarMonth.m)}</span>
              <div style={{ display: "flex", gap: 3 }}>
                <button className="nm-btn" onClick={() => setMonth(shiftMonth(calendarMonth, 1))} title="다음 달" aria-label="다음 달" style={navigationButton}><ChevronRightIcon sx={{ fontSize: 17 }} /></button>
                <button className="nm-btn" onClick={() => setMonth({ y: calendarMonth.y + 1, m: calendarMonth.m })} title="다음 해" aria-label="다음 해" style={navigationButton}><LastPageIcon sx={{ fontSize: 16 }} /></button>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 10 }}>
              <button className="nm-btn" onClick={() => previousDay && chooseDay(previousDay)} disabled={!previousDay} style={{ ...pageButton(!previousDay), flex: 1, padding: "3px 4px" }}><ChevronLeftIcon sx={{ fontSize: 15 }} />이전 활동일</button>
              <button className="nm-btn" onClick={() => days.length && chooseDay(days[days.length - 1])} disabled={!days.length} style={{ ...pageButton(!days.length), padding: "3px 7px" }}>최근</button>
              <button className="nm-btn" onClick={() => nextDay && chooseDay(nextDay)} disabled={!nextDay} style={{ ...pageButton(!nextDay), flex: 1, padding: "3px 4px" }}>다음 활동일<ChevronRightIcon sx={{ fontSize: 15 }} /></button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 2, textAlign: "center" }}>
              {DOW.map((day, index) => <div key={day} style={{ fontSize: 10.5, color: index === 0 ? "var(--danger)" : index === 6 ? "var(--accent)" : "var(--text-faint)", padding: "2px 0" }}>{day}</div>)}
              {calendarGrid(calendarMonth.y, calendarMonth.m).map((cell, index) => {
                if (!cell) return <div key={index} />;
                const day = `${calendarMonth.y}-${pad(calendarMonth.m)}-${pad(cell)}`;
                const count = dayCounts.get(day) ?? 0;
                const selected = day === activeDay;
                return <button key={index} onClick={() => count > 0 && chooseDay(day)} disabled={count === 0} title={count ? `${day} · ${count.toLocaleString()}건` : ""} aria-pressed={selected} style={{ aspectRatio: "1", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", fontSize: 12, borderRadius: "var(--radius)", border: "1px solid transparent", cursor: count ? "pointer" : "default", background: selected ? "var(--accent)" : count ? "var(--accent-subtle)" : "transparent", color: selected ? "#fff" : count ? "var(--accent)" : "var(--text-faint)", fontWeight: count ? 700 : 400 }}>{cell}{count > 0 && <span style={{ fontSize: 8, opacity: 0.8 }}>{count}</span>}</button>;
              })}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
              <button className="nm-btn" type="button" aria-pressed={mode.kind === "all"} onClick={() => setDayMode({ kind: "all" })} style={{ ...controlButton(mode.kind === "all"), flex: 1, justifyContent: "center" }}>기간 전체</button>
              <button className="nm-btn" type="button" aria-pressed={mode.kind === "untimed"} disabled={!summary?.untimed} onClick={() => setDayMode({ kind: "untimed" })} style={{ ...controlButton(mode.kind === "untimed"), flex: 1, justifyContent: "center", opacity: summary?.untimed ? 1 : 0.45 }}>시각 미상 {(summary?.untimed ?? 0).toLocaleString()}</button>
            </div>
          </aside>

          <section aria-label="방문 도메인" style={{ ...card, flex: 1 }}>
            <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, padding: "11px 12px 9px", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ fontSize: 13, fontWeight: 700 }}>방문 도메인</span>
              <span style={{ fontSize: 11, color: "var(--text-faint)" }}>방문 {(summary?.visitTotal ?? 0).toLocaleString()} · 도메인 {(summary?.domainTotal ?? 0).toLocaleString()}</span>
              <button className="nm-btn" onClick={() => setDomainsOpen(true)} disabled={!summary?.domainTotal} style={{ marginLeft: "auto", ...pageButton(!summary?.domainTotal), minHeight: 26, padding: "2px 7px" }}>전체 보기</button>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "2px 12px 8px" }}>
              {!summary?.topDomains.length ? <div style={{ padding: "12px 0 2px", color: "var(--text-faint)", fontSize: 12 }}>방문 없음</div> : summary.topDomains.map((item) => (
                <div key={item.domain} title={item.domain} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", minHeight: 34, padding: "5px 0", borderBottom: "1px solid var(--border-subtle)" }}>
                  <span style={{ minWidth: 0, fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.domain}</span>
                  <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "nowrap" }}>{item.visitCount.toLocaleString()}회</span>
                </div>
              ))}
            </div>
          </section>

          <section aria-label="다운로드" style={{ ...card, flex: 1 }}>
            <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, padding: "11px 12px 9px", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ fontSize: 13, fontWeight: 700 }}>다운로드</span>
              <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{(summary?.downloadTotal ?? 0).toLocaleString()}건</span>
              <button className="nm-btn" onClick={() => setDownloadsOpen(true)} disabled={!summary?.downloadTotal} style={{ marginLeft: "auto", ...pageButton(!summary?.downloadTotal), minHeight: 26, padding: "2px 7px" }}>전체 보기</button>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "0 12px" }}>
              {!summary?.downloads.length ? <div style={{ padding: "12px 0", color: "var(--text-faint)", fontSize: 12 }}>다운로드 없음</div> : summary.downloads.map((row) => {
                const bookmarked = isRowBookmarked?.(row) ?? false;
                return (
                  <button key={row.record_id} type="button" className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => openRecord(row)} title={row.title || row.url} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", width: "100%", minHeight: 36, padding: "5px 0", border: "none", borderBottom: "1px solid var(--border-subtle)", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
                    <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}>
                      <DownloadOutlinedIcon sx={{ flexShrink: 0, fontSize: 15, color: "var(--warning)" }} />
                      <span style={{ minWidth: 0, fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || row.url || "(이름 없음)"}</span>
                      {bookmarked && <BookmarkIcon aria-label="북마크됨" sx={{ flexShrink: 0, fontSize: 13, color: "var(--bookmark-control)" }} />}
                    </span>
                    <span style={{ color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "nowrap" }}>{row.timestamp ? row.timestamp.slice(0, 16) : "시각 미상"}</span>
                  </button>
                );
              })}
            </div>
          </section>
        </div>

        <section aria-label="브라우저 기록과 AI 대화" style={{ minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div role="tablist" aria-label="기록 유형" style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 6, padding: "2px 2px 9px", flexWrap: "wrap" }}>
            <button className="nm-btn" role="tab" aria-selected={mainTab === "records"} onClick={() => setMainTab("records")} style={controlButton(mainTab === "records")}><LanguageOutlinedIcon sx={{ fontSize: 15 }} />브라우저 기록 {data.rowCount.toLocaleString()}</button>
            <button className="nm-btn" role="tab" aria-selected={mainTab === "ai"} onClick={() => setMainTab("ai")} style={controlButton(mainTab === "ai")}><SmartToyOutlinedIcon sx={{ fontSize: 15 }} />AI 대화 {aiTotal.toLocaleString()} · 유입 {referrals.rowCount.toLocaleString()}</button>
            {mainTab === "records" && <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-dim)", fontWeight: 650 }}>{ledgerLabel}</span>}
          </div>

          {mainTab === "records" ? <>
            <div role="list" aria-label="브라우저 기록" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "2px 2px 0" }}>
              {data.rowCount === 0 && <div role="status" style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>{search.trim() ? "일치하는 기록 없음" : "기록 없음"}</div>}
              {data.rows.map((row) => <ActivityRow key={row.record_id} row={row} bookmarked={isRowBookmarked?.(row) ?? false} onOpen={() => openRecord(row)} onToggleBookmark={onToggleBookmark && Number.isSafeInteger(rowidOf(row)) ? () => onToggleBookmark(row) : undefined} />)}
            </div>
            <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "8px 2px 2px" }}>
              <PaginationControls ariaLabel="브라우저 기록 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${data.rowCount === 0 ? 0 : (safePage * PAGE_SIZE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE_SIZE, data.rowCount).toLocaleString()} / ${data.rowCount.toLocaleString()})`} />
            </div>
          </> : <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
            <div role="tablist" aria-label="AI 기록 유형" style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 4, padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", flexWrap: "wrap" }}>
              <button className="nm-btn" role="tab" aria-selected={aiPanel === "conversation"} onClick={() => setAiPanel("conversation")} style={controlButton(aiPanel === "conversation")}><TextsmsOutlinedIcon sx={{ fontSize: 15 }} />대화 본문 {aiKindCount("conversation").toLocaleString()}</button>
              <button className="nm-btn" role="tab" aria-selected={aiPanel === "list_entry"} onClick={() => setAiPanel("list_entry")} style={controlButton(aiPanel === "list_entry")}><ListAltOutlinedIcon sx={{ fontSize: 15 }} />목록 흔적 {aiKindCount("list_entry").toLocaleString()}</button>
              <button className="nm-btn" role="tab" aria-selected={aiPanel === "referral"} onClick={() => setAiPanel("referral")} style={controlButton(aiPanel === "referral")}><TravelExploreOutlinedIcon sx={{ fontSize: 15 }} />AI 유입 표식 {referrals.rowCount.toLocaleString()}</button>
              {aiPanel !== "referral" && (aiUntimedCount > 0 || aiUntimed) && <button className="nm-btn" type="button" aria-pressed={aiUntimed} onClick={() => setAiUntimed((value) => !value)} style={{ ...controlButton(aiUntimed), marginLeft: "auto" }}>시각 미상 {aiUntimedCount.toLocaleString()}</button>}
            </div>
            <div role="tabpanel" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
              {!aiDbPath && aiPanel !== "referral" ? <div role="status" style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>AI 대화 기록 없음</div>
                : aiRowCount === 0 ? <div role="status" style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>기록 없음</div>
                : aiRows.map((row) => aiPanel === "referral"
                  ? <ReferralRow key={row.record_id} row={row} bookmarked={isRowBookmarked?.(row) ?? false} onOpen={() => openRecord(row)} />
                  : <AiRow key={row.record_id} row={row} bookmarked={isAiRowBookmarked?.(row) ?? false} onOpen={() => setAiOpen(row.record_id)} onToggleBookmark={onToggleAiBookmark && Number.isSafeInteger(rowidOf(row)) ? () => onToggleAiBookmark(row) : undefined} />)}
            </div>
            {aiRowCount > AI_PAGE_SIZE && <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "6px 0 8px", borderTop: "1px solid var(--border-subtle)" }}>
              <PaginationControls ariaLabel="AI 기록 페이지" page={aiPage} pageCount={Math.max(1, Math.ceil(aiRowCount / AI_PAGE_SIZE))} onChange={setAiPage} summary={`(${(aiPage * AI_PAGE_SIZE + 1).toLocaleString()}–${Math.min((aiPage + 1) * AI_PAGE_SIZE, aiRowCount).toLocaleString()} / ${aiRowCount.toLocaleString()})`} />
            </div>}
          </div>}
        </section>
      </div>
    </main>
    {detail && <RowDetailPanel row={detail} columns={Object.keys(detail).filter((key) => !key.startsWith("__"))} focusedColumn={null} fileBaseName="BrowserActivity" onClose={() => setDetail(null)} onNavigate={() => {}} hostDir={hostDir} isBookmarked={isRowBookmarked?.(detail) ?? false} onToggleBookmark={onToggleBookmark && Number.isSafeInteger(rowidOf(detail)) ? () => onToggleBookmark(detail) : undefined} />}
    {aiOpen && aiDbPath && <AiConversationModal dbPath={aiDbPath} recordId={aiOpen} onOpenRecord={setAiOpen} isBookmarked={isAiRowBookmarked} onToggleBookmark={onToggleAiBookmark} onClose={() => setAiOpen(null)} />}
    {domainsOpen && <DomainsModal dbPath={dbPath} filter={scopeFilter} visitTotal={summary?.visitTotal ?? 0} onClose={() => setDomainsOpen(false)} />}
    {downloadsOpen && <DownloadsModal dbPath={dbPath} filter={{ inputIds, start, end, kinds: ["download"] }} isRowBookmarked={isRowBookmarked} onOpenRow={(row) => { setDownloadsOpen(false); openRecord(row); }} onClose={() => setDownloadsOpen(false)} />}
  </div>;
}

const KIND_STYLE: Record<string, { Icon: typeof LinkOutlinedIcon; color: string }> = {
  visit: { Icon: LinkOutlinedIcon, color: "var(--accent)" },
  url_summary: { Icon: SummarizeOutlinedIcon, color: "var(--text-dim)" },
  download: { Icon: DownloadOutlinedIcon, color: "var(--warning)" },
  cache: { Icon: Inventory2OutlinedIcon, color: "var(--text-dim)" },
};

function BookmarkToggle({ bookmarked, onToggle }: { bookmarked: boolean; onToggle?: () => void }) {
  if (!onToggle) return null;
  return <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(event) => { event.stopPropagation(); onToggle(); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderIcon sx={{ fontSize: 17 }} />}</button>;
}

function RowShell({ bookmarked, onOpen, label, children, trailing }: { bookmarked: boolean; onOpen: () => void; label: string; children: React.ReactNode; trailing?: React.ReactNode }) {
  return <div role="listitem" className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={onOpen} onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }} style={{ borderRadius: "var(--radius)", display: "flex", alignItems: "center", gap: 10, minHeight: 58, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", background: "var(--bg-panel)", cursor: "pointer", transition: "background .15s ease" }}>
    <div role="button" tabIndex={0} aria-label={label} onClick={(event) => { event.stopPropagation(); onOpen(); }} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onOpen(); } }} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, outlineOffset: -2 }}>{children}</div>
    {trailing}
  </div>;
}

function KindMark({ kind, recovered }: { kind: string; recovered: boolean }) {
  const style = KIND_STYLE[kind] ?? KIND_STYLE.visit;
  const Icon = kind === "cache" && recovered ? Inventory2Icon : style.Icon;
  const color = kind === "cache" && recovered ? "var(--success)" : style.color;
  return <span aria-hidden="true" title={KIND_LABELS[kind] ?? kind} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius)", background: `color-mix(in srgb, ${color} 15%, transparent)` }}><Icon sx={{ fontSize: 16, color }} /></span>;
}

function TimeCell({ row }: { row: Row }) {
  return <span title={row.timestamp_kind || undefined} style={{ flexShrink: 0, width: 168, textAlign: "right", fontSize: 12.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{row.timestamp || "시각 미상"}</span>;
}

function ActivityRow({ row, bookmarked, onOpen, onToggleBookmark }: { row: Row; bookmarked: boolean; onOpen: () => void; onToggleBookmark?: () => void }) {
  const kind = row.event_type;
  const isCache = kind === "cache";
  const title = row.title || (kind === "download" ? "(이름 없음)" : row.url) || "(제목 없음)";
  const url = kind === "download" ? row.url || row.source_url : row.url;
  const facts = kind === "download" ? row.size : isCache ? (row.mime || "").split(";")[0].trim() : kind === "url_summary" && row.visit_count ? `방문 ${row.visit_count}` : "";
  const owner = row.account || row.account_label;
  return <RowShell bookmarked={bookmarked} onOpen={onOpen} label={`${title} 상세 보기`} trailing={<BookmarkToggle bookmarked={bookmarked} onToggle={onToggleBookmark} />}>
    <KindMark kind={kind} recovered={row.cache_body_recovered === "1"} />
    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
      <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
        <span title={title} style={{ minWidth: 0, maxWidth: "50ch", fontSize: 13, fontWeight: isCache ? 550 : 700, color: isCache ? "var(--text-dim)" : "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</span>
        {kind === "url_summary" && <span style={chip("var(--text-dim)")}>URL 요약</span>}
        {row.ai_referral_provider && <span style={chip("var(--warning)")}>AI 유입 · {row.ai_referral_provider}</span>}
        {row.ai_service_provider && <span style={chip("var(--accent)")}>{row.ai_service_provider}</span>}
      </span>
      <span title={row.url_raw || url} style={{ minWidth: 0, maxWidth: "60ch", fontSize: 11.5, color: isCache ? "var(--text-faint)" : "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{url || "—"}</span>
    </span>
    {facts && <span title={facts} style={{ flexShrink: 0, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{facts}</span>}
    <span title={[row.browser, row.profile, row.account_label].filter(Boolean).join(" · ")} style={{ flexShrink: 0, display: "grid", justifyItems: "end", maxWidth: 140, fontSize: 11.5 }}>
      <span style={{ maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: owner ? "var(--text-dim)" : "var(--text-faint)" }}>{owner || "—"}</span>
      <span style={{ maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 10.5 }}>{[row.browser, row.profile].filter(Boolean).join(" · ")}</span>
    </span>
    <TimeCell row={row} />
  </RowShell>;
}

function ReferralRow({ row, bookmarked, onOpen }: { row: Row; bookmarked: boolean; onOpen: () => void }) {
  return <RowShell bookmarked={bookmarked} onOpen={onOpen} label={`${row.title || row.url} 상세 보기`}>
    <KindMark kind={row.event_type} recovered={false} />
    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
      <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
        <span style={{ minWidth: 0, fontSize: 13, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || row.url || "(제목 없음)"}</span>
        <span style={chip("var(--warning)")}>{row.ai_referral_provider}{row.ai_referral_param ? ` · ${row.ai_referral_param}` : ""}</span>
      </span>
      <span title={row.url} style={{ minWidth: 0, fontSize: 11.5, color: "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.url}</span>
    </span>
    <TimeCell row={row} />
  </RowShell>;
}

const count = (value: string | undefined) => (value === undefined || value === null || value === "" ? "—" : Number(value).toLocaleString());

function AiRow({ row, bookmarked, onOpen, onToggleBookmark }: { row: Row; bookmarked: boolean; onOpen: () => void; onToggleBookmark?: () => void }) {
  const ProviderIcon = providerIcon(row.provider);
  const isList = row.record_kind === "list_entry";
  return <RowShell bookmarked={bookmarked} onOpen={onOpen} label={`${row.title || "대화"} 열기`} trailing={<BookmarkToggle bookmarked={bookmarked} onToggle={onToggleBookmark} />}>
    <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--accent) 15%, transparent)" }}><ProviderIcon sx={{ fontSize: 16, color: "var(--accent)" }} /></span>
    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
      <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
        <span title={row.title} style={{ minWidth: 0, fontSize: 13, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || "(제목 없음)"}</span>
        <span style={chip("var(--accent)")}>{row.provider || "AI"}</span>
        {!isList && <span style={chip("var(--text-dim)")}>메시지 {count(row.message_count)} · 현재 분기 {count(row.current_branch_message_count)}</span>}
        {!isList && row.attachment_count && row.attachment_count !== "0" && <span style={chip("var(--text-dim)")}>첨부 {count(row.attachment_count)}</span>}
      </span>
      <span style={{ minWidth: 0, fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{[row.conversation_id, row.service_account].filter(Boolean).join(" · ") || "—"}</span>
    </span>
    <span title={[row.browser, row.profile, row.input_label].filter(Boolean).join(" · ")} style={{ flexShrink: 0, maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, color: row.account ? "var(--text-dim)" : "var(--text-faint)" }}>{row.account || row.input_label || "—"}</span>
    <TimeCell row={row} />
  </RowShell>;
}

function ModalShell({ label, width, onClose, header, children, footer }: { label: string; width: number; onClose: () => void; header: React.ReactNode; children: React.ReactNode; footer?: React.ReactNode }) {
  const dialogRef = useModalDialog(onClose);
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(1,4,9,0.6)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={label} onClick={(event) => event.stopPropagation()} style={{ display: "flex", flexDirection: "column", width, maxWidth: "100%", maxHeight: "88vh", minHeight: 0, overflow: "hidden", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)" }}>
      <header style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 10, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        {header}
        <button data-dialog-autofocus type="button" onClick={onClose} aria-label="닫기" style={{ marginLeft: "auto", display: "inline-flex", padding: 4, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      {children}
      {footer && <footer style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "8px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>{footer}</footer>}
    </div>
  </div>;
}

function DomainsModal({ dbPath, filter, visitTotal, onClose }: { dbPath: string; filter: BrowserFilter; visitTotal: number; onClose: () => void }) {
  const [page, setPage] = useState(0);
  const [ascending, setAscending] = useState(false);
  const [data, setData] = useState<BrowserDomainPage>({ domains: [], total: 0 });
  useEffect(() => {
    let alive = true;
    window.api.browserDomains(dbPath, filter, page * DOMAIN_PAGE_SIZE, DOMAIN_PAGE_SIZE, ascending).then((result) => { if (alive) setData(result); }).catch(() => {});
    return () => { alive = false; };
  }, [dbPath, filter, page, ascending]);
  const pageCount = Math.max(1, Math.ceil(data.total / DOMAIN_PAGE_SIZE));
  return <ModalShell label="방문 도메인 전체" width={820} onClose={onClose}
    header={<><LanguageOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} /><span style={{ fontSize: 14, fontWeight: 700 }}>방문 도메인</span><span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>도메인 {data.total.toLocaleString()} · 방문 {visitTotal.toLocaleString()}</span>
      <button type="button" className="nm-btn" onClick={() => { setAscending((value) => !value); setPage(0); }} style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 5, minHeight: 29, padding: "3px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 600 }}><SortIcon sx={{ fontSize: 15 }} />{ascending ? "적은 순" : "많은 순"}</button></>}
    footer={<PaginationControls ariaLabel="방문 도메인 페이지" page={page} pageCount={pageCount} onChange={setPage} summary={`(${data.total === 0 ? 0 : (page * DOMAIN_PAGE_SIZE + 1).toLocaleString()}–${Math.min((page + 1) * DOMAIN_PAGE_SIZE, data.total).toLocaleString()} / ${data.total.toLocaleString()})`} />}>
    <div style={{ minHeight: 0, overflow: "auto", padding: "10px 14px" }}>
      {data.domains.map((domain) => (
        <div key={domain.domain} style={{ display: "flex", alignItems: "center", gap: 12, minHeight: 50, marginBottom: 6, padding: "6px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)" }}>
          <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
            <span style={{ minWidth: 0, fontFamily: "var(--mono)", fontSize: 13, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{domain.domain}</span>
            <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>URL {domain.urlCount.toLocaleString()}</span>
          </span>
          <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700 }}>{domain.visitCount.toLocaleString()}회</span>
        </div>
      ))}
    </div>
  </ModalShell>;
}

function DownloadsModal({ dbPath, filter, isRowBookmarked, onOpenRow, onClose }: { dbPath: string; filter: BrowserFilter; isRowBookmarked?: (row: Row) => boolean; onOpenRow: (row: Row) => void; onClose: () => void }) {
  const [page, setPage] = useState(0);
  const [data, setData] = useState<BrowserPage>({ rows: [], rowCount: 0 });
  useEffect(() => {
    let alive = true;
    window.api.browserPage(dbPath, filter, page * PAGE_SIZE, PAGE_SIZE, true).then((result) => { if (alive) setData(result); }).catch(() => {});
    return () => { alive = false; };
  }, [dbPath, filter, page]);
  const pageCount = Math.max(1, Math.ceil(data.rowCount / PAGE_SIZE));
  return <ModalShell label="다운로드 전체" width={860} onClose={onClose}
    header={<><DownloadOutlinedIcon sx={{ fontSize: 18, color: "var(--warning)" }} /><span style={{ fontSize: 14, fontWeight: 700 }}>다운로드</span><span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{data.rowCount.toLocaleString()}건</span></>}
    footer={<PaginationControls ariaLabel="다운로드 페이지" page={page} pageCount={pageCount} onChange={setPage} summary={`(${data.rowCount === 0 ? 0 : (page * PAGE_SIZE + 1).toLocaleString()}–${Math.min((page + 1) * PAGE_SIZE, data.rowCount).toLocaleString()} / ${data.rowCount.toLocaleString()})`} />}>
    <div role="list" style={{ minHeight: 0, overflow: "auto", padding: "10px 14px" }}>
      {data.rows.map((row) => <ActivityRow key={row.record_id} row={row} bookmarked={isRowBookmarked?.(row) ?? false} onOpen={() => onOpenRow(row)} />)}
    </div>
  </ModalShell>;
}

// ---- AI conversation ----------------------------------------------------------

const RESPONSE_CHUNK = 1024 * 1024;

function roleInfo(role: string | undefined, provider: string | undefined) {
  const normalized = (role ?? "").trim().toLowerCase();
  if (/assistant|model|claude|gpt/.test(normalized)) return { kind: "assistant" as const, label: provider || "AI", color: "var(--accent)", Icon: SmartToyOutlinedIcon };
  if (/system|tool/.test(normalized)) return { kind: "system" as const, label: role || "system", color: "var(--text-faint)", Icon: AutoAwesomeOutlinedIcon };
  return { kind: "user" as const, label: role || "user", color: "var(--text-dim)", Icon: PersonOutlineIcon };
}

function MetaGrid({ items }: { items: [string, string | undefined | null][] }) {
  return <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: "6px 18px" }}>
    {items.filter(([, value]) => value !== undefined && value !== null && value !== "").map(([label, value]) => (
      <div key={label} style={{ minWidth: 0 }}>
        <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 2 }}>{label}</div>
        <div title={value ?? ""} style={{ fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
      </div>
    ))}
  </div>;
}

function ResponseBody({ dbPath, source }: { dbPath: string; source: Row }) {
  const [text, setText] = useState<string | null>(null);
  // Characters (SQLite length) once loaded; stored byte_length is shown before.
  const [total, setTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const load = () => {
    setLoading(true);
    setFailed(false);
    window.api.aiResponseBody(dbPath, source.source_db, source.source_table, Number(source.source_rowid), [...(text ?? "")].length, RESPONSE_CHUNK)
      .then((chunk) => { setText((previous) => (previous ?? "") + chunk.data); setTotal(chunk.total); })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  };
  const loaded = [...(text ?? "")].length;
  return <div style={{ display: "grid", gap: 6 }}>
    {text !== null && <pre style={{ margin: 0, padding: 10, maxHeight: "48vh", overflow: "auto", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.55, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{text}</pre>}
    {(total === null || loaded < total) && <button type="button" disabled={loading} onClick={load} style={{ ...pageButton(false), justifySelf: "start", color: "var(--accent)" }}>{loading ? "불러오는 중…" : total === null ? `원문 열기 · ${Number(source.response_length).toLocaleString()} bytes` : `나머지 불러오기 · ${loaded.toLocaleString()} / ${total.toLocaleString()}자`}</button>}
    {failed && <span role="alert" style={{ color: "var(--danger)", fontSize: 11.5 }}>원문을 불러오지 못했습니다</span>}
  </div>;
}

function AiConversationModal({ dbPath, recordId, onOpenRecord, isBookmarked, onToggleBookmark, onClose }: { dbPath: string; recordId: string; onOpenRecord: (recordId: string) => void; isBookmarked?: (row: Row) => boolean; onToggleBookmark?: (row: Row) => void; onClose: () => void }) {
  const [record, setRecord] = useState<AiRecord | null>(null);
  const [failed, setFailed] = useState(false);
  const [tab, setTab] = useState<"messages" | "attachments" | "interpretation" | "sources" | "snapshots">("messages");
  const [thread, setThread] = useState<"current" | "all">("current");
  const [needle, setNeedle] = useState("");
  useEffect(() => {
    let alive = true;
    setRecord(null);
    setFailed(false);
    window.api.aiRecord(dbPath, recordId).then((result) => { if (alive) setRecord(result); }).catch(() => { if (alive) setFailed(true); });
    return () => { alive = false; };
  }, [dbPath, recordId]);
  const row = record?.row;
  const messages = useMemo(() => (record ? messageThread(record.messages, thread) : []), [record, thread]);
  const byMessage = useMemo(() => attachmentsByMessage(record?.attachments ?? []), [record]);
  const query = needle.trim().toLowerCase();
  const shown = query ? messages.filter((message) => (message.content ?? "").toLowerCase().includes(query)) : messages;
  const hasBranches = (record?.messages ?? []).some((message) => message.on_current_branch === "0");
  const ProviderIcon = providerIcon(row?.provider);
  const bookmarked = row ? isBookmarked?.(row) ?? false : false;
  const rowid = row ? rowidOf(row) : Number.NaN;
  const tabs: [typeof tab, string, number | null][] = [
    ["messages", "대화", record?.messages.length ?? 0],
    ["attachments", "첨부", record?.attachments.length ?? 0],
    ["interpretation", "해석 JSON", null],
    ["sources", "수집 원문", record?.sources.length ?? 0],
    ["snapshots", "다른 스냅샷", record?.snapshots.length ?? 0],
  ];
  return <ModalShell label="AI 대화 상세" width={860} onClose={onClose}
    header={<>
      <ProviderIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
      <span style={{ minWidth: 0, flex: 1, fontSize: 14, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row?.title || "(제목 없음)"}</span>
      {row && <span style={chip(row.record_kind === "list_entry" ? "var(--text-dim)" : "var(--accent)")}>{row.record_kind === "list_entry" ? "목록 흔적" : "본문 스냅샷"}</span>}
      {row && onToggleBookmark && Number.isSafeInteger(rowid) && <BookmarkToggle bookmarked={bookmarked} onToggle={() => onToggleBookmark(row)} />}
    </>}>
    {failed ? <div role="alert" style={{ padding: 18, color: "var(--danger)", fontSize: 12.5 }}>불러오지 못했습니다</div>
      : !record || !row ? <div role="status" style={{ display: "flex", alignItems: "center", gap: 8, padding: 18, color: "var(--text-dim)", fontSize: 12.5 }}><CircularProgress size={15} thickness={4} />불러오는 중</div>
      : <>
        <div style={{ flexShrink: 0, padding: "10px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
          <MetaGrid items={[
            [row.timestamp_kind || "대표 시각", row.timestamp || "시각 미상"],
            ["대화 생성", row.created_at],
            ["대화 갱신", row.updated_at],
            ["서비스", row.provider],
            ["서비스 계정", row.service_account],
            ["대화 ID", row.conversation_id],
            ["계정", row.account],
            ["입력", [row.browser, row.profile, row.input_label, row.input_kind].filter(Boolean).join(" · ")],
            ["메시지 · 현재 분기 · 구조 노드", row.record_kind === "conversation" ? `${count(row.message_count)} · ${count(row.current_branch_message_count)} · ${count(row.structural_node_count)}` : undefined],
            ["첨부", row.record_kind === "conversation" ? count(row.attachment_count) : undefined],
            ["목록 위치", row.record_kind === "list_entry" ? `${row.list_ordinal !== undefined && row.list_ordinal !== null ? Number(row.list_ordinal) + 1 : "—"} / ${count(row.list_item_count)} (선언 ${count(row.list_declared_total)})` : undefined],
          ]} />
          {row.url && <div title={row.url} style={{ marginTop: 8, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.url}</div>}
        </div>
        <div role="tablist" aria-label="AI 대화 정보" style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 4, padding: "8px 16px", borderBottom: "1px solid var(--border-subtle)", flexWrap: "wrap" }}>
          {tabs.map(([key, label, total]) => <button key={key} type="button" role="tab" aria-selected={tab === key} onClick={() => setTab(key)} style={controlButton(tab === key)}>{label}{total !== null ? ` ${total.toLocaleString()}` : ""}</button>)}
          {tab === "messages" && record.messages.length > 0 && <>
            {hasBranches && <span role="group" aria-label="분기" style={{ marginLeft: "auto", display: "inline-flex", gap: 2 }}>
              <button type="button" aria-pressed={thread === "current"} onClick={() => setThread("current")} style={controlButton(thread === "current")}>현재 분기</button>
              <button type="button" aria-pressed={thread === "all"} onClick={() => setThread("all")} style={controlButton(thread === "all")}>전체 노드</button>
            </span>}
            <input value={needle} onChange={(event) => setNeedle(event.target.value)} placeholder="대화 내 검색" aria-label="대화 내 검색" style={{ marginLeft: hasBranches ? 6 : "auto", width: 160, padding: "5px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)", fontSize: 12 }} />
          </>}
        </div>
        <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 16, background: tab === "messages" ? "var(--bg)" : undefined }}>
          {tab === "messages" && (record.messages.length === 0
            ? <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>메시지 없음</div>
            : shown.length === 0 ? <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>일치하는 메시지 없음</div>
            : <div aria-label="대화 메시지" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {shown.map((message) => {
                const info = roleInfo(message.role, row.provider);
                const isUser = info.kind === "user";
                const RoleIcon = info.Icon;
                const files = byMessage.get(message.ordinal ?? "") ?? [];
                return <article key={message.ordinal} aria-label={`${info.label} ${message.created_at ?? ""}`} style={{ display: "flex", flexDirection: isUser ? "row-reverse" : "row", alignItems: "flex-start", gap: 8, opacity: message.offBranch ? 0.6 : 1 }}>
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, flexShrink: 0, marginTop: 17, borderRadius: "50%", background: `color-mix(in srgb, ${info.color} 15%, transparent)` }}><RoleIcon sx={{ fontSize: 15, color: info.color }} /></span>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: isUser ? "flex-end" : "flex-start", gap: 4, minWidth: 0, maxWidth: "82%" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, color: info.color, fontSize: 11, fontWeight: 700, flexWrap: "wrap" }}>
                      <span>{info.label}</span>
                      {message.author_name && <span style={{ color: "var(--text-faint)", fontWeight: 500 }}>{message.author_name}</span>}
                      {message.recipient && message.recipient !== "all" && <span style={{ color: "var(--text-faint)", fontWeight: 500 }}>→ {message.recipient}</span>}
                      {message.content_type && message.content_type !== "text" && <span style={chip("var(--text-faint)")}>{message.content_type}</span>}
                      {message.offBranch && <span style={chip("var(--warning)")}>다른 분기</span>}
                      {message.created_at && <time style={{ color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 400 }}>{message.created_at}</time>}
                    </div>
                    <div style={{ width: "fit-content", maxWidth: "100%", minWidth: 0, padding: "9px 13px", border: `1px solid ${isUser ? "color-mix(in srgb, var(--accent) 38%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius)", background: isUser ? "color-mix(in srgb, var(--accent) 13%, transparent)" : "var(--bg-elevated)", color: "var(--text)", fontSize: 12.5, lineHeight: 1.6, overflow: "hidden" }}><ChatMessageBody text={message.content ?? ""} /></div>
                    {files.map((file) => <span key={file.ordinal} style={{ ...chip("var(--text-dim)"), maxWidth: "100%" }} title={file.url || undefined}>첨부 · {file.file_name || file.attachment_id || "(이름 없음)"}{file.mime ? ` · ${file.mime}` : ""}</span>)}
                  </div>
                </article>;
              })}
            </div>)}
          {tab === "attachments" && (record.attachments.length === 0 ? <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>첨부 없음</div>
            : <div style={{ display: "grid", gap: 8 }}>{record.attachments.map((file) => (
              <div key={file.ordinal} style={{ padding: "9px 11px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", display: "grid", gap: 6 }}>
                <MetaGrid items={[["파일 이름", file.file_name], ["첨부 ID", file.attachment_id], ["MIME", file.mime], ["크기", file.size_bytes ? `${Number(file.size_bytes).toLocaleString()} bytes` : undefined], ["메시지", file.message_ordinal !== undefined && file.message_ordinal !== null ? `#${file.message_ordinal}` : undefined], ["출처", file.origin]]} />
                {file.url && <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--accent)", wordBreak: "break-all" }}>{file.url}</div>}
                {file.extracted_text && <pre style={{ margin: 0, padding: 8, maxHeight: 220, overflow: "auto", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 11.5, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{file.extracted_text}</pre>}
              </div>
            ))}</div>)}
          {tab === "interpretation" && (record.interpretation
            ? <pre style={{ margin: 0, padding: 10, background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.55, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{record.interpretation}</pre>
            : <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>해석 JSON 없음</div>)}
          {tab === "sources" && (record.sources.length === 0 ? <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>출처 없음</div>
            : <div style={{ display: "grid", gap: 10 }}>{record.sources.map((source) => (
              <div key={source.ordinal} style={{ display: "grid", gap: 8, padding: "9px 11px", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
                <MetaGrid items={[["수집 입력 파일", source.source_file], ["facts 좌표", `${source.source_db} · ${source.source_table} #${source.source_rowid}`], ["필드", source.source_field]]} />
                {source.response_length ? <ResponseBody dbPath={dbPath} source={source} /> : <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>수집 원문 없음</span>}
              </div>
            ))}</div>)}
          {tab === "snapshots" && (record.snapshots.length === 0 ? <div role="status" style={{ color: "var(--text-faint)", fontSize: 12.5 }}>다른 스냅샷 없음</div>
            : <div role="list">{record.snapshots.map((snapshot) => <AiRow key={snapshot.record_id} row={snapshot} bookmarked={isBookmarked?.(snapshot) ?? false} onOpen={() => { setTab("messages"); onOpenRecord(snapshot.record_id); }} />)}</div>)}
        </div>
      </>}
  </ModalShell>;
}

// Light markdown: **bold** and `code` only.
function inlineMarkdown(text: string): React.ReactNode[] {
  return text.split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g).filter(Boolean).map((token, index) => {
    if (token.startsWith("**") && token.endsWith("**")) return <strong key={index}>{token.slice(2, -2)}</strong>;
    if (token.startsWith("`") && token.endsWith("`")) return <code key={index} style={{ padding: "1px 5px", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{token.slice(1, -1)}</code>;
    return <span key={index}>{token}</span>;
  });
}

// Display-only whitespace cleanup outside code fences; the stored text is unchanged.
function cleanAiText(text: string): string {
  return text
    .split(/(```[\s\S]*?```)/g)
    .map((part) => (part.startsWith("```") ? part : part.replace(/[ \t]+$/gm, "").replace(/[ \t]{3,}/g, " ").replace(/\n{3,}/g, "\n\n")))
    .join("")
    .trim();
}

function ChatMessageBody({ text }: { text: string }) {
  const parts = cleanAiText(text).split(/(```[\s\S]*?```)/g).filter(Boolean);
  return <>{parts.map((part, index) => {
    if (part.startsWith("```") && part.endsWith("```")) return <pre key={index} style={{ maxWidth: "100%", margin: index === 0 ? 0 : "8px 0 0", padding: "8px 10px", overflow: "auto", background: "var(--bg)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.5, whiteSpace: "pre" }}>{part.replace(/^```[^\n]*\n?/, "").replace(/```$/, "")}</pre>;
    return <span key={index} style={{ display: "block", minWidth: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", wordBreak: "break-word" }}>{part.split(/\n/).map((line, lineIndex) => {
      const heading = /^#{1,6}\s+(.*)$/.exec(line);
      return <span key={lineIndex}>{lineIndex > 0 && "\n"}{heading ? <span style={{ display: "inline-block", fontSize: 13, fontWeight: 700 }}>{inlineMarkdown(heading[1])}</span> : inlineMarkdown(line)}</span>;
    })}</span>;
  })}</>;
}
