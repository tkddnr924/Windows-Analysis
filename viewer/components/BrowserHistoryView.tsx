"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import BookmarkBorderIcon from "@mui/icons-material/BookmarkBorder";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import AutoAwesomeOutlinedIcon from "@mui/icons-material/AutoAwesomeOutlined";
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
import LinkIcon from "@mui/icons-material/Link";
import LinkOutlinedIcon from "@mui/icons-material/LinkOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PsychologyOutlinedIcon from "@mui/icons-material/PsychologyOutlined";
import SmartToyOutlinedIcon from "@mui/icons-material/SmartToyOutlined";
import TextsmsOutlinedIcon from "@mui/icons-material/TextsmsOutlined";
import type { AiConversation, BrowserActivityInsights, BrowserActivitySummary, BrowserDomainStatsPage, CsvData } from "@/lib/types";
import { EMPTY_TIME_RANGE, toBound, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

type Row = Record<string, string>;
type AiMessage = { role: string; text: string; time?: string };
type DisplayAiConversation = AiConversation & { messages: AiMessage[]; raw: string };
type BrowserLoadKey = "summary" | "insights" | "domains" | "accounts" | "page" | "conversations" | "referrals";
type BrowserLoadErrors = Partial<Record<BrowserLoadKey, string>>;

interface Props {
  dbPath: string;
  tableName: string;
  hostDir?: string;
  timeRange?: TimeRange;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
}

const PAGE_SIZE = 10;
const AI_PAGE_SIZE = 10;
const DOMAIN_PAGE_SIZE = 50;
const DOW = ["일", "월", "화", "수", "목", "금", "토"];
const rowidOf = (row: Row) => Number((row as Record<string, unknown>).__rowid);
const pad = (value: number) => String(value).padStart(2, "0");

/**
 * AI provider payloads mix Unix epoch seconds, ISO-8601 instants, and the
 * parser's local evidence timestamps. Keep the source value intact in the
 * payload, but render every usable value in the viewer-wide fixed KST form.
 */
function formatKstDate(date: Date): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)?.value ?? "00";
  return `${part("year")}-${part("month")}-${part("day")} ${part("hour")}:${part("minute")}:${part("second")}.${String(date.getUTCMilliseconds()).padStart(3, "0")}`;
}

function isValidLocalTimestamp(year: number, month: number, day: number, hour: number, minute: number, second: number, millisecond: number): boolean {
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 || millisecond > 999) return false;
  // Set the year separately so years 0000–0099 are not implicitly mapped to
  // 1900–1999 by Date.UTC. UTC is only used as a calendar validator here;
  // parser timestamps themselves are not timezone-converted.
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millisecond);
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day
    && date.getUTCHours() === hour
    && date.getUTCMinutes() === minute
    && date.getUTCSeconds() === second
    && date.getUTCMilliseconds() === millisecond;
}

function formatAiPayloadTime(value: unknown): string {
  // Evidence-table timestamps are already KST and deliberately have no zone;
  // normalize their precision without treating them as a browser-local Date.
  if (typeof value === "string") {
    const local = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$/);
    if (local) {
      const milliseconds = Number((local[7] ?? "").slice(0, 3).padEnd(3, "0"));
      if (isValidLocalTimestamp(Number(local[1]), Number(local[2]), Number(local[3]), Number(local[4]), Number(local[5]), Number(local[6]), milliseconds)) {
        return `${local[1]}-${local[2]}-${local[3]} ${local[4]}:${local[5]}:${local[6]}.${String(milliseconds).padStart(3, "0")}`;
      }
      return "";
    }
  }

  const numeric = typeof value === "number" ? value : typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()) ? Number(value) : NaN;
  if (Number.isFinite(numeric) && numeric > 1_000_000_000) {
    // Providers normally use epoch seconds; accepting milliseconds as well
    // makes cached payload variants display consistently without changing data.
    const milliseconds = numeric >= 1_000_000_000_000 ? numeric : numeric * 1000;
    const date = new Date(Math.round(milliseconds));
    return Number.isNaN(date.getTime()) ? "" : formatKstDate(date);
  }

  if (typeof value === "string" && value.trim()) {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return formatKstDate(date);
  }
  return "";
}

function parseAiJson(value: unknown): { title: string; createdAt: string; updatedAt: string; messages: AiMessage[] } {
  const object = value as Record<string, unknown>;
  if (!object || typeof object !== "object") return { title: "", createdAt: "", updatedAt: "", messages: [] };
  const messages: AiMessage[] = [];
  const title = String(object.title ?? object.name ?? "");
  const createdAt = formatAiPayloadTime(object.create_time ?? object.created_at ?? "");
  const updatedAt = formatAiPayloadTime(object.update_time ?? object.updated_at ?? "");
  const mapping = object.mapping as Record<string, { message?: { author?: { role?: string }; content?: { parts?: unknown[]; text?: string }; create_time?: number } }> | undefined;
  if (mapping && typeof mapping === "object") {
    Object.values(mapping).map((node) => node.message).filter((message): message is NonNullable<typeof message> => Boolean(message?.author?.role)).sort((a, b) => (a.create_time ?? 0) - (b.create_time ?? 0)).forEach((message) => {
      const parts = message.content?.parts;
      const text = Array.isArray(parts) ? parts.map((part) => typeof part === "string" ? part : JSON.stringify(part)).join("\n") : (message.content?.text ?? "");
      if (text.trim()) messages.push({ role: message.author?.role || "?", text, time: formatAiPayloadTime(message.create_time) });
    });
  }
  const chatMessages = object.chat_messages as Array<{ sender?: string; role?: string; text?: string; content?: unknown; created_at?: string }> | undefined;
  if (Array.isArray(chatMessages)) chatMessages.forEach((message) => {
    const text = message.text || (Array.isArray(message.content) ? (message.content as Array<{ text?: string }>).map((part) => part.text ?? "").join("\n") : "");
    if (text.trim()) messages.push({ role: message.sender || message.role || "?", text, time: formatAiPayloadTime(message.created_at) });
  });
  const generic = (object.messages ?? object.contents ?? object.turns) as unknown;
  if (Array.isArray(generic)) generic.forEach((item) => {
    if (!item || typeof item !== "object") return;
    const message = item as Record<string, unknown>;
    const author = message.author as Record<string, unknown> | undefined;
    const role = String(message.role ?? message.sender ?? author?.role ?? "?");
    const content = message.content;
    let text = typeof message.text === "string" ? message.text : typeof content === "string" ? content : "";
    const parts = message.parts ?? (content && typeof content === "object" ? (content as Record<string, unknown>).parts : undefined);
    if (!text && Array.isArray(parts)) text = parts.map((part) => typeof part === "string" ? part : part && typeof part === "object" ? String((part as Record<string, unknown>).text ?? "") : "").filter(Boolean).join("\n");
    if (text.trim()) messages.push({ role, text, time: formatAiPayloadTime(message.created_at) });
  });
  return { title, createdAt, updatedAt, messages };
}

function ProviderMark({ provider }: { provider: string }) {
  // These are neutral MUI category marks, not provider brand assets or logos.
  const normalized = provider.toLowerCase();
  const Icon = normalized === "chatgpt" ? PsychologyOutlinedIcon : normalized === "gemini" ? AutoAwesomeOutlinedIcon : normalized === "claude" ? TextsmsOutlinedIcon : SmartToyOutlinedIcon;
  return <span title={`${provider || "AI"} 대화`} style={{ display: "inline-flex", alignItems: "center", gap: 5, minWidth: 0, color: "var(--accent)", fontSize: 11.5, fontWeight: 700 }}><Icon sx={{ fontSize: 16, flexShrink: 0 }} /><span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{provider || "AI"}</span></span>;
}

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

const navigationButton: React.CSSProperties = { display: "inline-flex", alignItems: "center", justifyContent: "center", width: 26, height: 26, padding: 0, borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", border: "1px solid var(--border)", color: "var(--text-dim)", cursor: "pointer" };
const pageButton = (disabled: boolean): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 2, minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.42 : 1, fontSize: 12 });

export default function BrowserHistoryView({ dbPath, tableName, hostDir = "", timeRange = EMPTY_TIME_RANGE, bookmarkedRowids, onToggleBookmark }: Props) {
  const [account, setAccount] = useState("(전체)");
  const [selectedDay, setSelectedDay] = useState("");
  const [showAllPeriod, setShowAllPeriod] = useState(false);
  const [month, setMonth] = useState<{ y: number; m: number } | null>(null);
  const [kinds, setKinds] = useState<Set<string>>(new Set(["visit", "download", "cache"]));
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [data, setData] = useState<CsvData>({ columns: [], rows: [], rowCount: 0 });
  const [summary, setSummary] = useState<BrowserActivitySummary>({ accounts: [], days: [], total: 0 });
  const [insights, setInsights] = useState<BrowserActivityInsights>({ visitTotal: 0, topVisitedDomains: [], downloadTotal: 0, downloads: [] });
  const [allAccounts, setAllAccounts] = useState<string[]>([]);
  const [domainStatsOpen, setDomainStatsOpen] = useState(false);
  const [domainStatsPage, setDomainStatsPage] = useState(0);
  const [domainStats, setDomainStats] = useState<BrowserDomainStatsPage>({ domains: [], total: 0 });
  const [domainStatsOpener, setDomainStatsOpener] = useState<HTMLElement | null>(null);
  const [detail, setDetail] = useState<Row | null>(null);
  const [aiConversations, setAiConversations] = useState<AiConversation[]>([]);
  const [aiTotal, setAiTotal] = useState(0);
  const [aiSourceFailures, setAiSourceFailures] = useState<string[]>([]);
  const [aiSourceCount, setAiSourceCount] = useState(0);
  const [aiSourcesRead, setAiSourcesRead] = useState(0);
  const [aiPage, setAiPage] = useState(0);
  const [aiReferrals, setAiReferrals] = useState<Row[]>([]);
  const [aiReferralTotal, setAiReferralTotal] = useState(0);
  const [aiReferralPage, setAiReferralPage] = useState(0);
  const [aiConvo, setAiConvo] = useState<DisplayAiConversation | null>(null);
  const [aiConvoOpener, setAiConvoOpener] = useState<HTMLElement | null>(null);
  const [aiPanel, setAiPanel] = useState<"conversations" | "referrals">("conversations");
  // Keep the last successful evidence page visible when a background query
  // fails. Clearing it to an empty result incorrectly looks like “no data”.
  const [loadErrors, setLoadErrors] = useState<BrowserLoadErrors>({});
  const [reloadNonce, setReloadNonce] = useState(0);
  const dayCounts = useMemo(() => new Map(summary.days.filter((day) => day.value).map((day) => [day.value, day.count])), [summary.days]);
  const activeDays = useMemo(() => [...dayCounts.keys()].sort(), [dayCounts]);
  const effectiveDay = showAllPeriod ? "" : selectedDay || activeDays.at(-1) || "";

  useEffect(() => {
    let active = true;
    window.api.browserActivitySummary(dbPath, tableName, { account, kinds: [...kinds], start: toBound(timeRange.start, "start") || undefined, end: toBound(timeRange.end, "end") || undefined, offset: 0, limit: PAGE_SIZE })
      .then((result) => { if (active) { setSummary(result); setLoadErrors((errors) => ({ ...errors, summary: undefined })); } }).catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, summary: "브라우저 요약을 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [dbPath, tableName, account, kinds, timeRange, reloadNonce]);
  useEffect(() => {
    let active = true;
    window.api.browserActivityInsights(
      dbPath,
      tableName,
      account === "(전체)" ? undefined : account,
      toBound(timeRange.start, "start") || undefined,
      toBound(timeRange.end, "end") || undefined,
    ).then((result) => { if (active) { setInsights(result); setLoadErrors((errors) => ({ ...errors, insights: undefined })); } })
      .catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, insights: "도메인·다운로드 통계를 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [dbPath, tableName, account, timeRange, reloadNonce]);
  useEffect(() => setDomainStatsPage(0), [dbPath, tableName, account, timeRange]);
  useEffect(() => {
    if (!domainStatsOpen) return;
    let active = true;
    window.api.browserActivityDomains(
      dbPath,
      tableName,
      account === "(전체)" ? undefined : account,
      toBound(timeRange.start, "start") || undefined,
      toBound(timeRange.end, "end") || undefined,
      domainStatsPage * DOMAIN_PAGE_SIZE,
      DOMAIN_PAGE_SIZE,
    ).then((result) => { if (active) { setDomainStats(result); setLoadErrors((errors) => ({ ...errors, domains: undefined })); } })
      .catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, domains: "전체 도메인 통계를 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [domainStatsOpen, dbPath, tableName, account, timeRange, domainStatsPage, reloadNonce]);
  useEffect(() => {
    let active = true;
    window.api.browserActivitySummary(dbPath, tableName, { kinds: ["visit", "download", "cache"], offset: 0, limit: 1 })
      .then((result) => { if (active) { setAllAccounts(result.accounts); setLoadErrors((errors) => ({ ...errors, accounts: undefined })); } }).catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, accounts: "브라우저 계정 목록을 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [dbPath, tableName, reloadNonce]);
  useEffect(() => {
    if (showAllPeriod) return;
    if (summary.days.length === 0) {
      if (selectedDay) setSelectedDay("");
      return;
    }
    if (!summary.days.some((day) => day.value === selectedDay)) setSelectedDay(summary.days[summary.days.length - 1].value);
  }, [selectedDay, showAllPeriod, summary.days]);
  useEffect(() => setPage(0), [effectiveDay, showAllPeriod, account, kinds, search, timeRange]);
  useEffect(() => {
    let active = true;
    window.api.browserActivityPage(dbPath, tableName, { account, kinds: [...kinds], day: showAllPeriod ? undefined : effectiveDay || undefined, search: search || undefined, start: toBound(timeRange.start, "start") || undefined, end: toBound(timeRange.end, "end") || undefined, offset: page * PAGE_SIZE, limit: PAGE_SIZE })
      .then((result) => { if (active) { setData(result); setLoadErrors((errors) => ({ ...errors, page: undefined })); } }).catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, page: "브라우저 기록을 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [dbPath, tableName, account, kinds, effectiveDay, showAllPeriod, search, timeRange, page, reloadNonce]);
  useEffect(() => {
    if (!hostDir) { setAiConversations([]); setAiTotal(0); setAiSourceFailures([]); setAiSourceCount(0); setAiSourcesRead(0); return; }
    let active = true;
    window.api.aiConversations(hostDir, { start: toBound(timeRange.start, "start") || undefined, end: toBound(timeRange.end, "end") || undefined, offset: aiPage * AI_PAGE_SIZE, limit: AI_PAGE_SIZE })
      .then((result) => { if (active) { setAiConversations(result.conversations); setAiTotal(result.total); setAiSourceFailures(result.sourceFailures); setAiSourceCount(result.sourceCount); setAiSourcesRead(result.sourcesRead); setLoadErrors((errors) => ({ ...errors, conversations: undefined })); } }).catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, conversations: "AI 대화 내역을 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [hostDir, timeRange, aiPage, reloadNonce]);
  useEffect(() => setAiPage(0), [hostDir, timeRange]);
  useEffect(() => {
    let active = true;
    window.api.aiReferrals(dbPath, tableName, toBound(timeRange.start, "start") || undefined, toBound(timeRange.end, "end") || undefined, aiReferralPage * AI_PAGE_SIZE, AI_PAGE_SIZE)
      .then((result) => { if (active) { setAiReferrals(result.rows); setAiReferralTotal(result.rowCount); setLoadErrors((errors) => ({ ...errors, referrals: undefined })); } }).catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, referrals: "AI 공유 링크를 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [dbPath, tableName, timeRange, aiReferralPage, reloadNonce]);
  useEffect(() => setAiReferralPage(0), [dbPath, tableName, timeRange]);

  const accounts = useMemo(() => ["(전체)", ...allAccounts.filter(Boolean)], [allAccounts]);
  const activeDay = effectiveDay;
  const calendarMonth = month ?? (activeDay ? { y: Number(activeDay.slice(0, 4)), m: Number(activeDay.slice(5, 7)) } : { y: 2000, m: 1 });
  const dayIndex = activeDays.indexOf(activeDay);
  const previousDay = dayIndex > 0 ? activeDays[dayIndex - 1] : "";
  const nextDay = dayIndex >= 0 && dayIndex < activeDays.length - 1 ? activeDays[dayIndex + 1] : "";
  const pageCount = Math.max(1, Math.ceil(data.rowCount / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  // Older BrowserActivity overview databases predate the derived recovery
  // marker. Keep those cache rows neutral and show one scoped reparse notice
  // instead of implying that a missing flag means no response body exists.
  const cacheRecoveryMarkerNeedsReparse = kinds.has("cache") && data.columns.length > 0 && !data.columns.includes("cache_body_recovered");
  const loadErrorMessages = Object.values(loadErrors).filter((message): message is string => Boolean(message));
  const aiAllSourcesUnreadable = aiSourceCount > 0 && aiSourcesRead === 0;
  const closeAiConversation = () => {
    const opener = aiConvoOpener;
    setAiConvo(null);
    setAiConvoOpener(null);
    requestAnimationFrame(() => opener?.focus());
  };
  const conversations = useMemo<DisplayAiConversation[]>(() => aiConversations.map((conversation) => {
    let parsed = { title: "", createdAt: "", updatedAt: "", messages: [] as AiMessage[] };
    try { parsed = parseAiJson(JSON.parse(conversation.rawJson)); } catch { /* Raw JSON remains readable in the modal. */ }
    return { ...conversation, messages: parsed.messages, raw: conversation.rawJson, title: conversation.title || parsed.title, createdAt: conversation.createdAt || parsed.createdAt, updatedAt: conversation.updatedAt || parsed.updatedAt };
  }), [aiConversations]);
  const closeDomainStats = () => {
    const opener = domainStatsOpener;
    setDomainStatsOpen(false);
    setDomainStatsOpener(null);
    requestAnimationFrame(() => opener?.focus());
  };
  const chooseDay = (day: string) => { setShowAllPeriod(false); setSelectedDay(day); setMonth(null); };
  const controlButton = (selected = false): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius-sm)", border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`, background: selected ? "var(--accent-subtle)" : "var(--bg-elevated)", color: selected ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 12, fontWeight: selected ? 700 : 500 });
  const kindChoices = [{ key: "visit", label: "방문", Icon: LinkOutlinedIcon }, { key: "download", label: "다운로드", Icon: DownloadOutlinedIcon }, { key: "cache", label: "캐시", Icon: Inventory2OutlinedIcon }];

  // Browser cache bodies can take a measurable time to fetch even on the
  // blocking worker. Keep their common detail surface docked like the MFT
  // inspector, rather than using a modal drawer/backdrop that intercepts the
  // browser ledger while a body is loading.
  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
    <main style={{ flex: "1 1 auto", minWidth: 0, minHeight: 0, overflow: "auto", padding: "24px 28px" }}>
    <header style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, flexWrap: "wrap" }}><LanguageOutlinedIcon sx={{ fontSize: 23, color: "var(--accent)" }} /><h1 style={{ margin: 0, fontSize: 21, letterSpacing: "-0.025em" }}>브라우저 활동</h1><span style={{ fontSize: 12, color: "var(--text-faint)" }}>방문 · 다운로드 · 캐시 기록</span>{loadErrorMessages.length > 0 && <span role="alert" style={{ display: "inline-flex", alignItems: "center", gap: 7, marginLeft: "auto", minWidth: 0, color: "var(--warning)", fontSize: 11.5 }}><span>{loadErrorMessages.join(" ")}</span><button type="button" onClick={() => { setLoadErrors({}); setReloadNonce((value) => value + 1); }} style={{ flexShrink: 0, padding: "3px 7px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>다시 시도</button></span>}</header>
    <section aria-label="브라우저 활동 필터" style={{ display: "flex", gap: 6, flexWrap: "wrap", paddingBottom: 14, borderBottom: "1px solid var(--border)" }}>
      {accounts.map((value) => <button key={value} onClick={() => { setShowAllPeriod(false); setAccount(value); setSelectedDay(""); setMonth(null); }} style={controlButton(account === value)}>{value !== "(전체)" && <PersonOutlineIcon sx={{ fontSize: 15 }} />}{value}</button>)}
      <span aria-hidden="true" style={{ width: 1, alignSelf: "stretch", background: "var(--border)", margin: "0 2px" }} />
      {kindChoices.map(({ key, label, Icon }) => { const selected = kinds.has(key); return <button key={key} onClick={() => { setShowAllPeriod(false); setKinds((previous) => { const next = new Set(previous); if (next.has(key)) next.delete(key); else next.add(key); return next.size ? next : previous; }); }} style={controlButton(selected)} aria-pressed={selected}><Icon sx={{ fontSize: 15 }} />{label}</button>; })}
    </section>

    <section style={{ display: "grid", gridTemplateColumns: "minmax(248px, 292px) minmax(0, 1fr)", alignItems: "start", marginTop: 16, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <section aria-label="기간 기반 브라우저 분석" className="browser-insights-grid" style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", borderBottom: "1px solid var(--border)" }}>
        <div className="browser-insights-first" style={{ minWidth: 0, padding: "13px 14px", borderRight: "1px solid var(--border)" }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, marginBottom: 8 }}><span style={{ fontSize: 13.5, fontWeight: 700 }}>방문 도메인 통계</span><span style={{ fontSize: 11, color: "var(--text-faint)" }}>상위 8개 · 방문 {insights.visitTotal.toLocaleString()}회</span><button onClick={(event) => { setDomainStatsOpener(event.currentTarget); setDomainStatsOpen(true); }} style={{ marginLeft: "auto", ...pageButton(false), minHeight: 26, padding: "2px 7px" }}>전체 도메인 보기</button></div>
          <div style={{ fontSize: 10.5, color: "var(--text-faint)", paddingBottom: 6, borderBottom: "1px solid var(--border-subtle)" }}>선택 계정 · 기간 필터 기준</div>
          {insights.topVisitedDomains.length === 0 ? <div style={{ padding: "14px 0 2px", color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 방문 도메인이 없습니다.</div> : insights.topVisitedDomains.map((item) => <div key={item.domain} title={item.domain} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", minHeight: 38, padding: "6px 0", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ minWidth: 0, color: "var(--text)", fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.domain}</span><span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "nowrap" }}>{item.visitCount.toLocaleString()}회</span></div>)}
        </div>
        <div style={{ minWidth: 0, padding: "13px 14px" }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0, marginBottom: 8 }}><span style={{ fontSize: 13.5, fontWeight: 700 }}>다운로드 이력</span><span style={{ fontSize: 11, color: "var(--text-faint)" }}>최근 8건 · 전체 {insights.downloadTotal.toLocaleString()}건</span><button onClick={() => { setKinds(new Set(["download"])); setShowAllPeriod(true); setSelectedDay(""); }} style={{ marginLeft: "auto", ...pageButton(false), minHeight: 26, padding: "2px 7px" }}>전체 다운로드</button></div>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 164px", gap: 10, paddingBottom: 6, borderBottom: "1px solid var(--border-subtle)", fontSize: 10.5, color: "var(--text-faint)" }}><span>파일</span><span>시각</span></div>
          {insights.downloads.length === 0 ? <div style={{ padding: "14px 0 2px", color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 다운로드 기록이 없습니다.</div> : insights.downloads.map((row) => <button key={String(row.__rowid)} onClick={() => setDetail(row)} title={row.title || "다운로드 상세 보기"} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 164px", gap: 10, alignItems: "center", width: "100%", minHeight: 38, padding: "6px 0", border: "none", borderBottom: "1px solid var(--border-subtle)", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}><span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}><DownloadOutlinedIcon sx={{ flexShrink: 0, fontSize: 15, color: "var(--warning)" }} /><span title={row.title} style={{ minWidth: 0, color: "var(--text)", fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || "파일 이름 없음"}</span>{row.size && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{row.size}</span>}</span><time style={{ color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</time></button>)}
        </div>
      </section>
      <aside aria-label="활동 날짜 선택" style={{ padding: 14, borderRight: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}><div style={{ display: "flex", gap: 3 }}><button onClick={() => setMonth({ y: calendarMonth.y - 1, m: calendarMonth.m })} title="이전 해" aria-label="이전 해" style={navigationButton}><FirstPageIcon sx={{ fontSize: 16 }} /></button><button onClick={() => setMonth(shiftMonth(calendarMonth, -1))} title="이전 달" aria-label="이전 달" style={navigationButton}><ChevronLeftIcon sx={{ fontSize: 17 }} /></button></div><button onClick={() => activeDay && chooseDay(activeDay)} title="가장 최근 활동일" style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 13.5, fontWeight: 700, background: "transparent", border: "none", color: "var(--text)", cursor: "pointer" }}><CalendarMonthOutlinedIcon sx={{ fontSize: 16, color: "var(--accent)" }} />{calendarMonth.y}년 {calendarMonth.m}월</button><div style={{ display: "flex", gap: 3 }}><button onClick={() => setMonth(shiftMonth(calendarMonth, 1))} title="다음 달" aria-label="다음 달" style={navigationButton}><ChevronRightIcon sx={{ fontSize: 17 }} /></button><button onClick={() => setMonth({ y: calendarMonth.y + 1, m: calendarMonth.m })} title="다음 해" aria-label="다음 해" style={navigationButton}><LastPageIcon sx={{ fontSize: 16 }} /></button></div></div>
        <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 10 }}><button onClick={() => previousDay && chooseDay(previousDay)} disabled={!previousDay} style={{ ...pageButton(!previousDay), flex: 1, padding: "3px 4px" }}><ChevronLeftIcon sx={{ fontSize: 15 }} />이전 활동일</button><button onClick={() => activeDay && chooseDay(activeDay)} title="최근 활동일" style={{ ...pageButton(!activeDay), padding: "3px 7px" }}>최근</button><button onClick={() => nextDay && chooseDay(nextDay)} disabled={!nextDay} style={{ ...pageButton(!nextDay), flex: 1, padding: "3px 4px" }}>다음 활동일<ChevronRightIcon sx={{ fontSize: 15 }} /></button></div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 2, textAlign: "center" }}>{DOW.map((day, index) => <div key={day} style={{ fontSize: 10.5, color: index === 0 ? "var(--danger)" : index === 6 ? "var(--accent)" : "var(--text-faint)", padding: "2px 0" }}>{day}</div>)}{calendarGrid(calendarMonth.y, calendarMonth.m).map((cell, index) => {
          if (!cell) return <div key={index} />;
          const day = `${calendarMonth.y}-${pad(calendarMonth.m)}-${pad(cell)}`;
          const count = dayCounts.get(day) ?? 0;
          const selected = day === activeDay;
          return <button key={index} onClick={() => count > 0 && chooseDay(day)} disabled={count === 0} title={count ? `${day} · ${count.toLocaleString()}건` : ""} style={{ aspectRatio: "1", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", fontSize: 12, borderRadius: "var(--radius-sm)", border: "1px solid transparent", cursor: count ? "pointer" : "default", background: selected ? "var(--accent)" : count ? "var(--accent-subtle)" : "transparent", color: selected ? "#fff" : count ? "var(--accent)" : "var(--text-faint)", fontWeight: count ? 700 : 400 }}>{cell}{count > 0 && <span style={{ fontSize: 8, opacity: 0.8 }}>{count}</span>}</button>;
        })}</div><div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 10 }}>활동 기록이 있는 날짜 {dayCounts.size}일</div>
      </aside>
      <section aria-label="선택한 날짜의 브라우저 기록" style={{ minWidth: 0, padding: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}><span style={{ fontSize: 13.5, fontWeight: 700 }}>{showAllPeriod ? `기간 내 다운로드 · ${data.rowCount.toLocaleString()}건` : activeDay ? `${activeDay} · ${data.rowCount.toLocaleString()}건` : "활동 기록 없음"}</span><div style={{ marginLeft: "auto", position: "relative" }}><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="도메인 · URL · 제목 검색" aria-label="선택한 날짜의 브라우저 기록 검색" style={{ width: 280, maxWidth: "70vw", minHeight: 30, padding: "5px 28px 5px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12 }} />{search && <button onClick={() => setSearch("")} title="검색어 지우기" aria-label="검색어 지우기" style={{ position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)", display: "inline-flex", background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 15 }} /></button>}</div></div>
        {cacheRecoveryMarkerNeedsReparse && <div role="status" style={{ marginBottom: 8, padding: "7px 9px", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", background: "var(--bg-elevated)", fontSize: 11.5 }}>현재 브라우저 개요에는 복구 본문 상태가 없습니다. 재파싱 후 복구된 캐시 아이콘이 표시됩니다.</div>}
        <div style={{ borderTop: "1px solid var(--border)", overflow: "hidden" }}><div style={{ display: "grid", gridTemplateColumns: "108px minmax(0, 1fr) minmax(92px, 0.18fr) 32px", gap: 10, padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: 10.5, color: "var(--text-faint)", fontWeight: 700 }}><span>시각</span><span>기록</span><span>계정</span><span aria-label="북마크" /></div>{data.rowCount === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>{search.trim() ? `“${search.trim()}” 검색 결과가 없습니다.` : activeDay ? "선택한 날짜의 기록이 없습니다." : "기간 필터 내 데이터 없음"}</div>}{data.rows.map((row, index, rows) => <ActivityRow key={`${row.__rowid}-${index}`} row={row} final={index === rows.length - 1} bookmarked={bookmarkedRowids?.has(rowidOf(row)) ?? false} onOpen={() => setDetail(row)} onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(row)) ? () => onToggleBookmark(rowidOf(row)) : undefined} />)}</div>
        {pageCount > 1 && <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginTop: 10 }}><button onClick={() => setPage(0)} disabled={safePage === 0} title="첫 페이지" aria-label="첫 페이지" style={pageButton(safePage === 0)}><FirstPageIcon sx={{ fontSize: 16 }} /></button><button onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pageButton(safePage === 0)}><ChevronLeftIcon sx={{ fontSize: 16 }} />이전</button><span style={{ fontSize: 12, color: "var(--text-dim)", minWidth: 120, textAlign: "center" }}>{safePage + 1} / {pageCount} 쪽 <span style={{ color: "var(--text-faint)" }}>({(safePage * PAGE_SIZE + 1).toLocaleString()}–{Math.min((safePage + 1) * PAGE_SIZE, data.rowCount).toLocaleString()} / {data.rowCount.toLocaleString()})</span></span><button onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pageButton(safePage >= pageCount - 1)}>다음<ChevronRightIcon sx={{ fontSize: 16 }} /></button><button onClick={() => setPage(pageCount - 1)} disabled={safePage >= pageCount - 1} title="마지막 페이지" aria-label="마지막 페이지" style={pageButton(safePage >= pageCount - 1)}><LastPageIcon sx={{ fontSize: 16 }} /></button></div>}
      </section>
    <div aria-label="AI 대화 내역" style={{ gridColumn: "1 / -1", minWidth: 0, borderTop: "1px solid var(--border)", background: "var(--bg-panel)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 14px", borderBottom: "1px solid var(--border)", flexWrap: "wrap" }}><SmartToyOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} /><span style={{ fontSize: 14, fontWeight: 700 }}>AI 대화 내역</span><span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>대화 {aiTotal.toLocaleString()}건 · 공유 링크 {aiReferralTotal.toLocaleString()}건</span>{aiSourceFailures.length > 0 && <span role="status" title={aiSourceFailures.join("\n")} style={{ marginLeft: "auto", color: "var(--warning)", fontSize: 11.5 }}>캐시 원본 {aiSourceFailures.length.toLocaleString()}개를 읽지 못했습니다</span>}</div>
      {aiAllSourcesUnreadable ? <div role="alert" style={{ display: "flex", alignItems: "center", gap: 10, padding: 18, color: "var(--warning)", fontSize: 12.5 }}>AI 대화 캐시 원본을 읽지 못했습니다.<button type="button" onClick={() => setReloadNonce((value) => value + 1)} style={{ padding: "3px 7px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>다시 시도</button></div> : aiTotal === 0 && aiReferralTotal === 0 ? <div style={{ padding: 18, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 데이터 없음</div> : <>
        <div role="tablist" aria-label="AI 대화 데이터 유형" style={{ display: "flex", gap: 4, padding: "8px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
          <button role="tab" aria-selected={aiPanel === "conversations"} onClick={() => setAiPanel("conversations")} style={controlButton(aiPanel === "conversations")}><SmartToyOutlinedIcon sx={{ fontSize: 15 }} />대화 {aiTotal.toLocaleString()}건</button>
          <button role="tab" aria-selected={aiPanel === "referrals"} onClick={() => setAiPanel("referrals")} style={controlButton(aiPanel === "referrals")}><LinkIcon sx={{ fontSize: 15 }} />공유 링크 {aiReferralTotal.toLocaleString()}건</button>
        </div>
        {aiPanel === "conversations" ? <div role="tabpanel" aria-label="AI 대화 목록"><div style={{ display: "grid", gridTemplateColumns: "minmax(124px, .55fr) minmax(0, 1.7fr) minmax(96px, .4fr) 164px 52px", gap: 10, padding: "8px 14px", borderBottom: "1px solid var(--border-subtle)", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)" }}><span>서비스</span><span>대화 제목</span><span>계정</span><span>캐시 관찰 시각</span><span style={{ textAlign: "right" }}>메시지</span></div>{aiTotal === 0 ? <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 대화 데이터 없음</div> : conversations.map((conversation, index) => <button key={`${conversation.url}-${index}`} onClick={(event) => { setAiConvoOpener(event.currentTarget); setAiConvo(conversation); }} title="대화 내용 보기" style={{ display: "grid", gridTemplateColumns: "minmax(124px, .55fr) minmax(0, 1.7fr) minmax(96px, .4fr) 164px 52px", gap: 10, alignItems: "center", width: "100%", minHeight: 44, padding: "8px 14px", background: "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", color: "inherit", cursor: "pointer", textAlign: "left" }}><ProviderMark provider={conversation.provider} /><span title={conversation.title || conversation.url} style={{ minWidth: 0, fontSize: 12.5, fontWeight: 650, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.title || "제목 없음"}</span><span title={conversation.account} style={{ minWidth: 0, fontSize: 11, color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.account || "—"}</span><time style={{ minWidth: 0, fontSize: 10.5, color: "var(--text-time)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(conversation.date) || "시간 정보 없음"}</time><span style={{ textAlign: "right", whiteSpace: "nowrap", fontSize: 11, color: "var(--text-dim)" }}>{conversation.messages.length || "—"}</span></button>)}<div style={{ padding: "0 14px 12px" }}><SimplePager page={aiPage} total={aiTotal} onPage={setAiPage} /></div></div> : <div role="tabpanel" aria-label="AI 공유 링크 목록"><div style={{ display: "grid", gridTemplateColumns: "164px minmax(0, 1fr)", gap: 10, padding: "8px 14px", borderBottom: "1px solid var(--border-subtle)", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)" }}><span>시각</span><span>공유 링크</span></div>{aiReferralTotal === 0 ? <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 공유 링크 없음</div> : aiReferrals.map((row) => <button key={String(row.__rowid)} onClick={() => setDetail(row)} title={row.url || row.title} style={{ display: "grid", gridTemplateColumns: "164px minmax(0, 1fr)", gap: 10, alignItems: "center", width: "100%", padding: "8px 14px", background: "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", color: "inherit", cursor: "pointer", textAlign: "left" }}><span style={{ fontSize: 10.5, color: "var(--text-time)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</span><span style={{ minWidth: 0, display: "grid", gridTemplateRows: "18px 16px", rowGap: 2 }}><span title={row.title || row.url} style={{ minWidth: 0, fontSize: 12, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || row.url || "제목 없음"}</span><span title={row.url} style={{ minWidth: 0, fontSize: 10.5, color: "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.url || "주소 정보 없음"}</span></span></button>)}<div style={{ padding: "0 14px 12px" }}><SimplePager page={aiReferralPage} total={aiReferralTotal} onPage={setAiReferralPage} /></div></div>}
      </>}
    </div>
    </section>
    </main>
    {detail && <aside aria-label="선택한 브라우저 기록 상세" style={{ flex: "0 1 min(440px, 42vw)", width: "min(440px, 42vw)", minWidth: 0, minHeight: 0, borderLeft: "1px solid var(--border)", background: "var(--bg-panel)" }}><RowDetailPanel row={detail} columns={Object.keys(detail).filter((key) => key !== "__rowid")} focusedColumn={null} fileBaseName="BrowserActivity" variant="docked" onClose={() => setDetail(null)} onNavigate={() => {}} hostDir={hostDir} isBookmarked={bookmarkedRowids?.has(rowidOf(detail)) ?? false} onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(detail)) ? () => onToggleBookmark(rowidOf(detail)) : undefined} /></aside>}
    {aiConvo && <AiConversationModal conversation={aiConvo} onClose={closeAiConversation} />}
    {domainStatsOpen && <DomainStatsModal page={domainStatsPage} data={domainStats} visitTotal={insights.visitTotal} onPage={setDomainStatsPage} onClose={closeDomainStats} />}
  </div>;
}

function ActivityRow({ row, final, bookmarked, onOpen, onToggleBookmark }: { row: Row; final: boolean; bookmarked: boolean; onOpen: () => void; onToggleBookmark?: () => void }) {
  const isDownload = row.kind === "download";
  const isCache = row.kind === "cache";
  const hasRecoveredCacheBody = isCache && row.cache_body_recovered === "1";
  const Icon = isDownload ? DownloadOutlinedIcon : hasRecoveredCacheBody ? Inventory2Icon : isCache ? Inventory2OutlinedIcon : LinkOutlinedIcon;
  const color = isDownload ? "var(--warning)" : hasRecoveredCacheBody ? "var(--success)" : isCache ? "var(--text-faint)" : "var(--accent)";
  const title = row.title || (isDownload ? "파일 이름 없음" : row.url) || "제목 없음";
  const url = isDownload ? row.source_url || row.url : row.url;
  const facts = isDownload && row.size ? row.size : isCache ? [row.status, row.mime, row.size].filter(Boolean).join(" · ") : row.visit_count ? `${row.visit_count}회` : "";
  const activate = (event: React.KeyboardEvent<HTMLDivElement>) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onOpen(); } };
  return <div onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { event.currentTarget.style.background = bookmarked ? "var(--accent-subtle)" : "transparent"; }} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 32px", alignItems: "stretch", borderBottom: final ? "none" : "1px solid var(--border-subtle)", borderLeft: `3px solid ${bookmarked ? "var(--accent)" : "transparent"}`, background: bookmarked ? "var(--accent-subtle)" : "transparent" }}>
    <div role="button" tabIndex={0} onClick={onOpen} onKeyDown={activate} style={{ display: "grid", gridTemplateColumns: "178px minmax(0, 1fr) minmax(92px, 0.18fr)", gap: 10, alignItems: "center", minWidth: 0, padding: "8px 0 8px 9px", cursor: "pointer", outlineOffset: -2 }}>
      <span title={row.timestamp || "시간 정보 없음"} style={{ fontSize: 11.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</span>
      <div style={{ minWidth: 0, display: "grid", gridTemplateRows: "18px 16px", rowGap: 2 }}><div style={{ display: "flex", minWidth: 0, gap: 6, alignItems: "center" }}><Icon aria-label={isDownload ? "다운로드" : hasRecoveredCacheBody ? "캐시 · 복구된 본문 있음" : isCache ? "캐시" : "방문"} titleAccess={hasRecoveredCacheBody ? "캐시 · 복구된 본문 있음" : undefined} sx={{ flexShrink: 0, fontSize: 16, color }} /><span title={title} style={{ minWidth: 0, flex: 1, fontSize: 12.5, fontWeight: isCache ? 500 : 650, color: isCache ? "var(--text-dim)" : "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</span>{facts && <span title={facts} style={{ flexShrink: 1, minWidth: 0, fontSize: 10.5, color: isDownload ? "var(--warning)" : "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{facts}</span>}</div><div title={row.url_raw || url} style={{ minWidth: 0, paddingLeft: 22, fontSize: 10.5, lineHeight: "16px", color: isCache ? "var(--text-faint)" : "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{url || "주소 정보 없음"}</div></div>
      <span style={{ minWidth: 0, fontSize: 11, color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.account || "—"}</span>
    </div>
    {onToggleBookmark && <button onClick={onToggleBookmark} title={bookmarked ? "북마크 해제" : "북마크에 추가"} aria-label={bookmarked ? "북마크 해제" : "북마크에 추가"} style={{ display: "inline-flex", alignSelf: "center", justifyContent: "center", padding: 2, background: "transparent", border: "none", color: bookmarked ? "var(--accent)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderIcon sx={{ fontSize: 17 }} />}</button>}
  </div>;
}

function SimplePager({ page, total, onPage }: { page: number; total: number; onPage: (page: number) => void }) {
  const pages = Math.ceil(total / AI_PAGE_SIZE);
  if (pages < 2) return null;
  return <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 8, marginTop: 10 }}><button onClick={() => onPage(Math.max(0, page - 1))} disabled={page === 0} style={pageButton(page === 0)}><ChevronLeftIcon sx={{ fontSize: 16 }} />이전</button><span style={{ fontSize: 12, color: "var(--text-dim)" }}>{page + 1} / {pages} 쪽</span><button onClick={() => onPage(Math.min(pages - 1, page + 1))} disabled={page >= pages - 1} style={pageButton(page >= pages - 1)}>다음<ChevronRightIcon sx={{ fontSize: 16 }} /></button></div>;
}

function DomainStatsModal({ page, data, visitTotal, onPage, onClose }: { page: number; data: BrowserDomainStatsPage; visitTotal: number; onPage: (page: number) => void; onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const pageCount = Math.max(1, Math.ceil(data.total / DOMAIN_PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const first = data.total === 0 ? 0 : safePage * DOMAIN_PAGE_SIZE + 1;
  const last = Math.min((safePage + 1) * DOMAIN_PAGE_SIZE, data.total);
  useEffect(() => {
    closeButtonRef.current?.focus();
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const trapFocus = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
    if (!focusable?.length) return;
    const firstElement = focusable[0];
    const lastElement = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === firstElement) { event.preventDefault(); lastElement.focus(); }
    if (!event.shiftKey && document.activeElement === lastElement) { event.preventDefault(); firstElement.focus(); }
  };
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(1,4,9,0.6)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="전체 방문 도메인 통계" onClick={(event) => event.stopPropagation()} onKeyDown={trapFocus} style={{ display: "flex", flexDirection: "column", width: 820, maxWidth: "100%", maxHeight: "85vh", minHeight: 0, overflow: "hidden", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)" }}>
      <header style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 10, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        <LanguageOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
        <span style={{ fontSize: 14, fontWeight: 700 }}>전체 방문 도메인</span>
        <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>도메인 {data.total.toLocaleString()}개 · 방문 {visitTotal.toLocaleString()}회</span>
        <button ref={closeButtonRef} onClick={onClose} title="닫기" aria-label="닫기" style={{ marginLeft: "auto", display: "inline-flex", flexShrink: 0, padding: 2, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 118px 100px", gap: 12, flexShrink: 0, padding: "8px 16px", borderBottom: "1px solid var(--border-subtle)", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)" }}><span>도메인</span><span style={{ textAlign: "right" }}>서로 다른 URL</span><span style={{ textAlign: "right" }}>방문 횟수</span></div>
      <main style={{ minHeight: 0, overflow: "auto" }}>{data.total === 0 ? <div style={{ padding: 18, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 방문 도메인이 없습니다.</div> : data.domains.map((domain) => <div key={domain.domain} title={domain.domain} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 118px 100px", gap: 12, alignItems: "center", minHeight: 36, padding: "6px 16px", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ minWidth: 0, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{domain.domain}</span><span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, textAlign: "right", whiteSpace: "nowrap" }}>{domain.urlCount.toLocaleString()}</span><span style={{ color: "var(--text)", fontFamily: "var(--mono)", fontSize: 11.5, textAlign: "right", whiteSpace: "nowrap" }}>{domain.visitCount.toLocaleString()}회</span></div>)}</main>
      <footer style={{ flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "10px 16px", borderTop: "1px solid var(--border-subtle)" }}>
        <button onClick={() => onPage(safePage - 1)} disabled={safePage === 0} style={pageButton(safePage === 0)}><ChevronLeftIcon sx={{ fontSize: 16 }} />이전</button>
        <span style={{ minWidth: 154, color: "var(--text-dim)", fontSize: 12, textAlign: "center" }}>{safePage + 1} / {pageCount} 쪽 <span style={{ color: "var(--text-faint)" }}>({first.toLocaleString()}–{last.toLocaleString()} / {data.total.toLocaleString()})</span></span>
        <button onClick={() => onPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pageButton(safePage >= pageCount - 1)}>다음<ChevronRightIcon sx={{ fontSize: 16 }} /></button>
      </footer>
    </div>
  </div>;
}

function AiConversationModal({ conversation, onClose }: { conversation: DisplayAiConversation; onClose: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeButtonRef.current?.focus();
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const metadata = [
    ["캐시 관찰 시각", formatAiPayloadTime(conversation.date) || "시간 정보 없음"],
    ["대화 생성 시각", formatAiPayloadTime(conversation.createdAt) || "정보 없음"],
    ["대화 갱신 시각", formatAiPayloadTime(conversation.updatedAt) || "정보 없음"],
    ["계정", conversation.account || "정보 없음"],
  ];
  const roleInfo = (role: string) => {
    const normalized = role.trim().toLowerCase();
    if (/^(assistant|claude|gpt|model|ai)$/.test(normalized) || /assistant|claude|gpt|model/.test(normalized)) return { kind: "assistant" as const, label: `${conversation.provider || "AI"} 응답`, color: "var(--accent)", Icon: SmartToyOutlinedIcon };
    if (/system|tool/.test(normalized)) return { kind: "system" as const, label: "시스템", color: "var(--text-faint)", Icon: AutoAwesomeOutlinedIcon };
    return { kind: "user" as const, label: "사용자", color: "var(--text-dim)", Icon: PersonOutlineIcon };
  };
  const trapFocus = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
    if (!focusable?.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  };

  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(1,4,9,0.6)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="AI 대화 상세" onClick={(event) => event.stopPropagation()} onKeyDown={trapFocus} style={{ display: "flex", flexDirection: "column", width: 760, maxWidth: "100%", maxHeight: "85vh", minHeight: 0, overflow: "hidden", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)" }}>
      <header style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 10, padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <ProviderMark provider={conversation.provider} />
        <span style={{ minWidth: 0, flex: 1, fontSize: 14, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.title || "제목 없음"}</span>
        {conversation.messages.length > 0 && <button onClick={() => setShowRaw((value) => !value)} style={pageButton(false)}>{showRaw ? "대화 보기" : "원본 JSON"}</button>}
        <button ref={closeButtonRef} onClick={onClose} title="닫기" aria-label="닫기" style={{ display: "inline-flex", flexShrink: 0, padding: 2, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      <div style={{ flexShrink: 0, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "6px 18px", padding: "10px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
        {metadata.map(([label, value]) => <div key={label} style={{ minWidth: 0 }}><div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 2 }}>{label}</div><div title={value} style={{ fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div></div>)}
      </div>
      <div title={conversation.url} style={{ flexShrink: 0, minWidth: 0, padding: "7px 16px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.url}</div>
      <main aria-label="대화 메시지" style={{ minHeight: 0, overflow: "auto", padding: 16 }}>
        {showRaw ? <pre style={{ margin: 0, padding: 10, maxHeight: "62vh", overflow: "auto", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.55, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{conversation.raw}</pre> : conversation.messages.length === 0 ? <div style={{ padding: "18px 0", color: "var(--text-faint)", fontSize: 12.5 }}>표시할 대화 메시지를 추출하지 못했습니다. 원본 JSON에서 확인할 수 있습니다.</div> : <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {conversation.messages.map((message, index) => {
            const info = roleInfo(message.role);
            const roleIsUser = info.kind === "user";
            const roleIsSystem = info.kind === "system";
            const RoleIcon = info.Icon;
            if (roleIsSystem) return <div key={index} style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-faint)", fontSize: 11.5 }}><span style={{ height: 1, flex: 1, background: "var(--border-subtle)" }} /><RoleIcon sx={{ fontSize: 14, color: info.color }} /><span>{info.label}{message.time ? ` · ${message.time}` : ""}</span><span style={{ height: 1, flex: 1, background: "var(--border-subtle)" }} /></div>;
            return <article key={index} aria-label={`${info.label}${message.time ? ` ${message.time}` : ""}`} style={{ display: "flex", flexDirection: "column", alignItems: roleIsUser ? "flex-end" : "flex-start", gap: 4 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 5, color: info.color, fontSize: 11, fontWeight: 700 }}><RoleIcon sx={{ fontSize: 15 }} /><span>{info.label}</span>{message.time && <time style={{ color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 400 }}>{message.time}</time>}</div>
              <div style={{ width: "fit-content", maxWidth: "88%", minWidth: 0, padding: "10px 12px", border: `1px solid ${roleIsUser ? "var(--border)" : "var(--accent)"}`, borderLeftWidth: roleIsUser ? 1 : 3, borderRadius: "var(--radius-sm)", background: roleIsUser ? "var(--bg-input)" : "var(--bg-elevated)", color: "var(--text)", fontSize: 12.5, lineHeight: 1.6, overflow: "hidden" }}><ChatMessageBody text={message.text} /></div>
            </article>;
          })}
        </div>}
      </main>
    </div>
  </div>;
}

function ChatMessageBody({ text }: { text: string }) {
  const parts = text.split(/(```[\s\S]*?```)/g).filter(Boolean);
  return <>{parts.map((part, index) => {
    const isCode = part.startsWith("```") && part.endsWith("```");
    if (isCode) return <pre key={index} style={{ maxWidth: "100%", margin: index === 0 ? 0 : "8px 0 0", padding: "8px 10px", overflow: "auto", background: "var(--bg)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.5, whiteSpace: "pre" }}>{part.replace(/^```[^\n]*\n?/, "").replace(/```$/, "")}</pre>;
    return <span key={index} style={{ display: "block", minWidth: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", wordBreak: "break-word" }}>{part}</span>;
  })}</>;
}
