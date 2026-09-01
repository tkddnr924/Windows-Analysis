"use client";
import SortIcon2 from "@mui/icons-material/SortOutlined";

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
import PaginationControls from "@/components/PaginationControls";
import { FilterDropdown, HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

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
const DOMAIN_PAGE_SIZE = 10;
const ACTIVITY_LEDGER_CONTENT_COLUMNS = "178px minmax(0, 1fr) minmax(92px, 0.18fr)";
const ACTIVITY_LEDGER_COLUMNS = `${ACTIVITY_LEDGER_CONTENT_COLUMNS} 32px`;
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
  const mapping = object.mapping as Record<string, { parent?: string; message?: { author?: { role?: string }; recipient?: string; content?: { content_type?: string; parts?: unknown[]; text?: string }; create_time?: number } }> | undefined;
  if (mapping && typeof mapping === "object") {
    // ChatGPT의 정본 순서는 mapping 트리(current_node→parent 체인)다. 원본
    // create_time은 사용자 메시지가 그 답변보다 늦게 찍히는 경우가 있어
    // 정렬 기준으로 쓰면 질문·답변 순서가 뒤집힌다. 체인을 못 만드는
    // 페이로드에서만 create_time 정렬로 대신한다.
    // 채팅 버블에는 ChatGPT 화면에 실제 표시됐던 것만 올린다 — 도구 실행
    // 결과(role=tool), 도구로 보낸 내부 명령(recipient≠all), 텍스트가 아닌
    // 노드(thoughts·code 등)는 숨긴다. 숨긴 내용은 원본 JSON 보기에 남는다.
    const displayed = (message: NonNullable<NonNullable<(typeof mapping)[string]>["message"]>) => {
      if (!message.author?.role || message.author.role === "tool") return false;
      if (message.recipient && message.recipient !== "all") return false;
      if (message.content?.content_type && message.content.content_type !== "text") return false;
      return true;
    };
    const visited = new Set<string>();
    const chain: NonNullable<(typeof mapping)[string]["message"]>[] = [];
    let nodeId = typeof object.current_node === "string" ? object.current_node : "";
    while (nodeId && mapping[nodeId] && !visited.has(nodeId)) {
      visited.add(nodeId);
      const nodeMessage = mapping[nodeId].message;
      if (nodeMessage && displayed(nodeMessage)) chain.push(nodeMessage);
      nodeId = typeof mapping[nodeId].parent === "string" ? mapping[nodeId].parent! : "";
    }
    chain.reverse();
    const ordered = chain.length > 0
      ? chain
      : Object.values(mapping).map((node) => node.message).filter((message): message is NonNullable<typeof message> => Boolean(message && displayed(message))).sort((a, b) => (a.create_time ?? 0) - (b.create_time ?? 0));
    ordered.forEach((message) => {
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

// 공유 링크의 utm_source 값으로 어떤 AI 서비스에서 온 링크인지 판별한다.
function referralProvider(url: string | undefined): string {
  if (!url) return "";
  const match = /[?&#]utm_source=([^&#]+)/i.exec(url);
  if (!match) return "";
  const source = decodeURIComponent(match[1]).toLowerCase();
  if (source.includes("chatgpt") || source.includes("openai")) return "ChatGPT";
  if (source.includes("notebook")) return "NotebookLM";
  if (source.includes("gemini") || source.includes("bard")) return "Gemini";
  if (source.includes("claude")) return "Claude";
  if (source.includes("copilot")) return "Copilot";
  if (source.includes("perplexity")) return "Perplexity";
  return source;
}

// These are neutral MUI category marks, not provider brand assets or logos.
function providerIcon(provider: string) {
  const normalized = provider.toLowerCase();
  return normalized === "chatgpt" ? PsychologyOutlinedIcon : normalized === "gemini" ? AutoAwesomeOutlinedIcon : normalized === "claude" ? TextsmsOutlinedIcon : SmartToyOutlinedIcon;
}

function ProviderMark({ provider }: { provider: string }) {
  const Icon = providerIcon(provider);
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
  const [domainSortAsc, setDomainSortAsc] = useState(false);
  // 전체 다운로드 팝업 — 전체 도메인 보기와 같은 모달 패턴.
  const [downloadsOpen, setDownloadsOpen] = useState(false);
  const [kindsOpen, setKindsOpen] = useState(false);
  const [downloadsOpener, setDownloadsOpener] = useState<HTMLElement | null>(null);
  const [downloadsPage, setDownloadsPage] = useState(0);
  const [downloadsData, setDownloadsData] = useState<{ rows: Row[]; rowCount: number }>({ rows: [], rowCount: 0 });
  // 우측 하단 큰 카드의 탭 — 날짜 기록 / AI 대화 내역.
  const [mainTab, setMainTab] = useState<"records" | "ai">("records");
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
      domainSortAsc,
    ).then((result) => { if (active) { setDomainStats(result); setLoadErrors((errors) => ({ ...errors, domains: undefined })); } })
      .catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, domains: "전체 도메인 통계를 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [domainStatsOpen, dbPath, tableName, account, timeRange, domainStatsPage, domainSortAsc, reloadNonce]);
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
  useEffect(() => {
    if (!downloadsOpen) return;
    let active = true;
    window.api.browserActivityPage(dbPath, tableName, { account, kinds: ["download"], start: toBound(timeRange.start, "start") || undefined, end: toBound(timeRange.end, "end") || undefined, offset: downloadsPage * PAGE_SIZE, limit: PAGE_SIZE })
      .then((result) => { if (active) setDownloadsData({ rows: result.rows, rowCount: result.rowCount }); })
      .catch(() => { if (active) setLoadErrors((errors) => ({ ...errors, downloadsModal: "다운로드 목록을 불러오지 못했습니다. 다시 시도하세요." })); });
    return () => { active = false; };
  }, [downloadsOpen, dbPath, tableName, account, timeRange, downloadsPage, reloadNonce]);

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
  const closeDownloads = () => {
    const opener = downloadsOpener;
    setDownloadsOpen(false);
    setDownloadsOpener(null);
    requestAnimationFrame(() => opener?.focus());
  };
  const openDownloads = (opener: HTMLElement) => {
    setDetail(null);
    opener.focus();
    setDownloadsOpener(opener);
    setDownloadsPage(0);
    setDownloadsOpen(true);
  };
  const closeDomainStats = () => {
    const opener = domainStatsOpener;
    setDomainStatsOpen(false);
    setDomainStatsOpener(null);
    requestAnimationFrame(() => opener?.focus());
  };
  const openDomainStats = (opener: HTMLElement) => {
    // Keep one modal owner at a time. This also prevents competing Escape and
    // focus-restoration handlers if a future control can be invoked from a
    // record detail surface.
    setDetail(null);
    opener.focus();
    setDomainStatsOpener(opener);
    setDomainStatsPage(0);
    setDomainStatsOpen(true);
  };
  const openAiConversation = (conversation: DisplayAiConversation, opener: HTMLElement) => {
    setDetail(null);
    opener.focus();
    setAiConvoOpener(opener);
    setAiConvo(conversation);
  };
  const chooseDay = (day: string) => { setShowAllPeriod(false); setSelectedDay(day); setMonth(null); };
  const openDetail = (row: Row, opener: HTMLElement) => {
    // Native buttons focus themselves, but the main activity rows are
    // keyboard-enabled ledger rows. Set the trigger explicitly so the shared
    // modal contract can always restore focus to the exact record on close.
    opener.focus();
    setDetail(row);
  };
  const closeDetail = () => setDetail(null);
  const controlButton = (selected = false): React.CSSProperties => ({ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "4px 9px", borderRadius: "var(--radius-sm)", border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`, background: selected ? "var(--accent-subtle)" : "var(--bg-elevated)", color: selected ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 12, fontWeight: selected ? 700 : 500 });
  const kindChoices = [{ key: "visit", label: "방문", Icon: LinkOutlinedIcon }, { key: "download", label: "다운로드", Icon: DownloadOutlinedIcon }, { key: "cache", label: "캐시", Icon: Inventory2OutlinedIcon }];

  // Browser cache body recovery stays asynchronous, while the common detail
  // drawer remains a standard modal. Its fixed backdrop does not participate
  // in this view's flex layout, so opening it never shifts the browser ledger.
  return <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", overflow: "hidden" }}>
    <main style={{ flex: "1 1 auto", minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg)" }}>
    <ViewHeader icon={LanguageOutlinedIcon} title="브라우저 활동" meta="방문 · 다운로드 · 캐시 기록" right={loadErrorMessages.length > 0 ? <span role="alert" style={{ display: "inline-flex", alignItems: "center", gap: 7, minWidth: 0, color: "var(--warning)", fontSize: 11.5 }}><span>{loadErrorMessages.join(" ")}</span><button className="nm-btn" type="button" onClick={() => { setLoadErrors({}); setReloadNonce((value) => value + 1); }} style={{ flexShrink: 0, padding: "3px 7px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>다시 시도</button></span> : undefined}>
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="도메인 · URL · 제목 검색" ariaLabel="브라우저 기록 검색" width={300} />
        <SelectDropdown
          icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />}
          label="계정"
          options={accounts.map((value) => ({ value, label: value }))}
          value={account}
          defaultValue="(전체)"
          onChange={(next) => { setShowAllPeriod(false); setAccount(next); setSelectedDay(""); setMonth(null); }}
        />
        <FilterDropdown icon={<Inventory2OutlinedIcon sx={{ fontSize: 15 }} />} label="종류" valueLabel={kinds.size === 3 ? undefined : `· ${kindChoices.filter(({ key }) => kinds.has(key)).map(({ label }) => label).join("·")}`} active={kinds.size !== 3} minWidth={190} open={kindsOpen} onToggle={setKindsOpen}>
          {kindChoices.map(({ key, label, Icon }) => {
            const selected = kinds.has(key);
            return (
              <button key={key} type="button" aria-pressed={selected} onClick={() => { setShowAllPeriod(false); setKinds((previous) => { const next = new Set(previous); if (next.has(key)) next.delete(key); else next.add(key); return next.size ? next : previous; }); }} style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "4px 9px", background: "transparent", border: "none", borderRadius: "var(--radius-sm)", color: selected ? "var(--text)" : "var(--text-faint)", cursor: "pointer", fontSize: 12.5, fontWeight: selected ? 650 : 500, textAlign: "left" }}
                onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}>
                <span aria-hidden="true" style={{ color: selected ? "var(--accent)" : "var(--text-faint)", fontSize: 13 }}>{selected ? "☑" : "☐"}</span>
                <Icon sx={{ fontSize: 15 }} />
                {label}
              </button>
            );
          })}
        </FilterDropdown>
      
      </ViewHeader>

    {/* 스크롤 없이 한 화면에 들어오는 대시보드 — 각 카드가 내부 스크롤을 가진다. */}
    <div style={{ flex: 1, minHeight: 0, display: "grid", gap: 10, padding: 14, gridTemplateColumns: "minmax(280px, 25%) minmax(0, 1fr)", overflow: "hidden" }}>
      <div style={{ minHeight: 0, display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
        <aside aria-label="활동 날짜 선택" style={{ flexShrink: 0, padding: 12, border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}><div style={{ display: "flex", gap: 3 }}><button className="nm-btn" onClick={() => setMonth({ y: calendarMonth.y - 1, m: calendarMonth.m })} title="이전 해" aria-label="이전 해" style={navigationButton}><FirstPageIcon sx={{ fontSize: 16 }} /></button><button className="nm-btn" onClick={() => setMonth(shiftMonth(calendarMonth, -1))} title="이전 달" aria-label="이전 달" style={navigationButton}><ChevronLeftIcon sx={{ fontSize: 17 }} /></button></div><button className="nm-btn" onClick={() => activeDay && chooseDay(activeDay)} title="가장 최근 활동일" style={{ display: "inline-flex", alignItems: "center", gap: 7, minHeight: 32, padding: "5px 14px", fontSize: 13.5, fontWeight: 700, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", cursor: "pointer", whiteSpace: "nowrap" }}><CalendarMonthOutlinedIcon sx={{ fontSize: 16, color: "var(--accent)" }} />{calendarMonth.y}년 {calendarMonth.m}월</button><div style={{ display: "flex", gap: 3 }}><button className="nm-btn" onClick={() => setMonth(shiftMonth(calendarMonth, 1))} title="다음 달" aria-label="다음 달" style={navigationButton}><ChevronRightIcon sx={{ fontSize: 17 }} /></button><button className="nm-btn" onClick={() => setMonth({ y: calendarMonth.y + 1, m: calendarMonth.m })} title="다음 해" aria-label="다음 해" style={navigationButton}><LastPageIcon sx={{ fontSize: 16 }} /></button></div></div>
          <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 10 }}><button className="nm-btn" onClick={() => previousDay && chooseDay(previousDay)} disabled={!previousDay} style={{ ...pageButton(!previousDay), flex: 1, padding: "3px 4px" }}><ChevronLeftIcon sx={{ fontSize: 15 }} />이전 활동일</button><button className="nm-btn" onClick={() => activeDay && chooseDay(activeDay)} title="최근 활동일" style={{ ...pageButton(!activeDay), padding: "3px 7px" }}>최근</button><button className="nm-btn" onClick={() => nextDay && chooseDay(nextDay)} disabled={!nextDay} style={{ ...pageButton(!nextDay), flex: 1, padding: "3px 4px" }}>다음 활동일<ChevronRightIcon sx={{ fontSize: 15 }} /></button></div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 2, textAlign: "center" }}>{DOW.map((day, index) => <div key={day} style={{ fontSize: 10.5, color: index === 0 ? "var(--danger)" : index === 6 ? "var(--accent)" : "var(--text-faint)", padding: "2px 0" }}>{day}</div>)}{calendarGrid(calendarMonth.y, calendarMonth.m).map((cell, index) => {
            if (!cell) return <div key={index} />;
            const day = `${calendarMonth.y}-${pad(calendarMonth.m)}-${pad(cell)}`;
            const count = dayCounts.get(day) ?? 0;
            const selected = day === activeDay;
            return <button key={index} onClick={() => count > 0 && chooseDay(day)} disabled={count === 0} title={count ? `${day} · ${count.toLocaleString()}건` : ""} style={{ aspectRatio: "1", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", fontSize: 12, borderRadius: "var(--radius-sm)", border: "1px solid transparent", cursor: count ? "pointer" : "default", background: selected ? "var(--accent)" : count ? "var(--accent-subtle)" : "transparent", color: selected ? "#fff" : count ? "var(--accent)" : "var(--text-faint)", fontWeight: count ? 700 : 400 }}>{cell}{count > 0 && <span style={{ fontSize: 8, opacity: 0.8 }}>{count}</span>}</button>;
          })}</div>
          <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 9 }}>활동 기록이 있는 날짜 {dayCounts.size}일</div>
        </aside>

        <section aria-label="방문 도메인 통계" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden" }}>
          <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, minWidth: 0, padding: "11px 12px 9px", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ fontSize: 13, fontWeight: 700 }}>방문 도메인 통계</span><span style={{ fontSize: 11, color: "var(--text-faint)" }}>방문 {insights.visitTotal.toLocaleString()}회</span><button className="nm-btn" onClick={(event) => openDomainStats(event.currentTarget)} style={{ marginLeft: "auto", ...pageButton(false), minHeight: 26, padding: "2px 7px" }}>전체 보기</button></div>
          <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "2px 12px 8px" }}>
            {insights.topVisitedDomains.length === 0 ? <div style={{ padding: "12px 0 2px", color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 방문 도메인이 없습니다.</div> : insights.topVisitedDomains.map((item) => <div key={item.domain} title={item.domain} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", minHeight: 36, padding: "5px 0", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ minWidth: 0, color: "var(--text)", fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.domain}</span><span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 11, whiteSpace: "nowrap" }}>{item.visitCount.toLocaleString()}회</span></div>)}
          </div>
        </section>

        <section aria-label="다운로드 이력" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden" }}>
          <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, minWidth: 0, padding: "11px 12px 9px", borderBottom: "1px solid var(--border-subtle)" }}><span style={{ fontSize: 13, fontWeight: 700 }}>다운로드 이력</span><span style={{ fontSize: 11, color: "var(--text-faint)" }}>최근 {insights.downloads.length}건 · 전체 {insights.downloadTotal.toLocaleString()}건</span><button className="nm-btn" onClick={(event) => openDownloads(event.currentTarget)} style={{ marginLeft: "auto", ...pageButton(false), minHeight: 26, padding: "2px 7px" }}>전체 다운로드</button></div>
          <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "0 12px" }}>
            {insights.downloads.length === 0 ? <div style={{ padding: "12px 0", color: "var(--text-faint)", fontSize: 12 }}>기간 필터 내 다운로드 기록이 없습니다.</div> : insights.downloads.map((row) => <button key={String(row.__rowid)} onClick={(event) => openDetail(row, event.currentTarget)} title={row.title || "다운로드 상세 보기"} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", width: "100%", minHeight: 36, padding: "5px 0", border: "none", borderBottom: "1px solid var(--border-subtle)", background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}><span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}><DownloadOutlinedIcon sx={{ flexShrink: 0, fontSize: 15, color: "var(--warning)" }} /><span title={row.title} style={{ minWidth: 0, color: "var(--text)", fontSize: 12, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || "파일 이름 없음"}</span>{row.size && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{row.size}</span>}</span><time style={{ color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, whiteSpace: "nowrap", textAlign: "right" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</time></button>)}
          </div>
        </section>

      </div>

      <div style={{ minHeight: 0, display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
        <section aria-label="브라우저 기록과 AI 대화" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div role="tablist" aria-label="기록 유형" style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 6, padding: "2px 2px 9px", flexWrap: "wrap" }}>
            <button className="nm-btn" role="tab" aria-selected={mainTab === "records"} onClick={() => setMainTab("records")} style={controlButton(mainTab === "records")}><LanguageOutlinedIcon sx={{ fontSize: 15 }} />브라우저 기록 {data.rowCount.toLocaleString()}건</button>
            <button className="nm-btn" role="tab" aria-selected={mainTab === "ai"} onClick={() => setMainTab("ai")} style={controlButton(mainTab === "ai")}><SmartToyOutlinedIcon sx={{ fontSize: 15 }} />AI 대화 {aiTotal.toLocaleString()} · 링크 {aiReferralTotal.toLocaleString()}</button>
            {mainTab === "records" && <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-dim)", fontWeight: 650 }}>{showAllPeriod ? "기간 내 다운로드" : activeDay || "활동 기록 없음"}</span>}
            {mainTab === "ai" && aiSourceFailures.length > 0 && <span role="status" title={aiSourceFailures.join("\n")} style={{ marginLeft: "auto", color: "var(--warning)", fontSize: 11.5 }}>캐시 원본 {aiSourceFailures.length.toLocaleString()}개를 읽지 못했습니다</span>}
          </div>

          {mainTab === "records" ? <>
            {cacheRecoveryMarkerNeedsReparse && <div role="status" style={{ flexShrink: 0, margin: "8px 12px 0", padding: "7px 9px", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", background: "var(--bg-elevated)", fontSize: 11.5 }}>현재 브라우저 개요에는 복구 본문 상태가 없습니다. 재파싱 후 복구된 캐시 아이콘이 표시됩니다.</div>}
            <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "2px 2px 0" }}>
              {data.rowCount === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>{search.trim() ? `“${search.trim()}” 검색 결과가 없습니다.` : activeDay ? "선택한 날짜의 기록이 없습니다." : "기간 필터 내 데이터 없음"}</div>}
              {data.rows.map((row, index, rows) => <ActivityRow key={`${row.__rowid}-${index}`} row={row} final={index === rows.length - 1} bookmarked={bookmarkedRowids?.has(rowidOf(row)) ?? false} onOpen={(opener) => openDetail(row, opener)} onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(row)) ? () => onToggleBookmark(rowidOf(row)) : undefined} />)}
            </div>
            <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "8px 2px 2px" }}>
              <PaginationControls ariaLabel="브라우저 활동 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${data.rowCount === 0 ? 0 : (safePage * PAGE_SIZE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE_SIZE, data.rowCount).toLocaleString()} / ${data.rowCount.toLocaleString()})`} />
            </div>
          </> : <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
            {aiAllSourcesUnreadable ? <div role="alert" style={{ display: "flex", alignItems: "center", gap: 10, padding: 18, color: "var(--warning)", fontSize: 12.5 }}>AI 대화 캐시 원본을 읽지 못했습니다.<button className="nm-btn" type="button" onClick={() => setReloadNonce((value) => value + 1)} style={{ padding: "3px 7px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>다시 시도</button></div> : aiTotal === 0 && aiReferralTotal === 0 ? <div style={{ padding: 18, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 데이터 없음</div> : <>
              <div role="tablist" aria-label="AI 대화 데이터 유형" style={{ display: "flex", gap: 4, padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)" }}>
                <button className="nm-btn" role="tab" aria-selected={aiPanel === "conversations"} onClick={() => setAiPanel("conversations")} style={controlButton(aiPanel === "conversations")}><SmartToyOutlinedIcon sx={{ fontSize: 15 }} />대화 {aiTotal.toLocaleString()}건</button>
                <button className="nm-btn" role="tab" aria-selected={aiPanel === "referrals"} onClick={() => setAiPanel("referrals")} style={controlButton(aiPanel === "referrals")}><LinkIcon sx={{ fontSize: 15 }} />공유 링크 {aiReferralTotal.toLocaleString()}건</button>
              </div>
              {aiPanel === "conversations" ? <div role="tabpanel" aria-label="AI 대화 목록" style={{ padding: 12 }}>
                {aiTotal === 0 ? <div style={{ padding: 16, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 대화 데이터 없음</div> : conversations.map((conversation, index) => {
                  const ProviderIcon = providerIcon(conversation.provider);
                  return (
                    <button key={`${conversation.url}-${index}`} type="button" onClick={(event) => openAiConversation(conversation, event.currentTarget)} title="대화 내용 보기"
                      onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                      onMouseLeave={(event) => { event.currentTarget.style.background = "var(--bg-panel)"; }}
                      style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 58, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", color: "inherit", cursor: "pointer", textAlign: "left", transition: "background .15s ease" }}>
                      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--accent) 15%, transparent)" }}>
                        <ProviderIcon sx={{ fontSize: 16, color: "var(--accent)" }} />
                      </span>
                      <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
                        <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                          <span title={conversation.title || conversation.url} style={{ minWidth: 0, fontSize: 13, fontWeight: 700, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.title || "제목 없음"}</span>
                          <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{conversation.provider || "AI"}</span>
                          {conversation.messages.length > 0 && <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>메시지 {conversation.messages.length.toLocaleString()}개</span>}
                        </span>
                        <span title={conversation.url} style={{ minWidth: 0, fontSize: 11.5, color: "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.url || "주소 정보 없음"}</span>
                      </span>
                      <span title={conversation.account} style={{ flexShrink: 0, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: conversation.account ? "var(--text-dim)" : "var(--text-faint)" }}>{conversation.account || "계정 정보 없음"}</span>
                      <time style={{ flexShrink: 0, fontSize: 12, color: "var(--text-time)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(conversation.date) || "시간 정보 없음"}</time>
                    </button>
                  );
                })}
                {aiTotal > 0 && <PaginationControls ariaLabel="AI 대화 페이지" page={aiPage} pageCount={Math.max(1, Math.ceil(aiTotal / AI_PAGE_SIZE))} onChange={setAiPage} summary={`(${(aiPage * AI_PAGE_SIZE + 1).toLocaleString()}–${Math.min((aiPage + 1) * AI_PAGE_SIZE, aiTotal).toLocaleString()} / ${aiTotal.toLocaleString()})`} />}
              </div> : <div role="tabpanel" aria-label="AI 공유 링크 목록" style={{ padding: 12 }}>
                {aiReferralTotal === 0 ? <div style={{ padding: 16, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 공유 링크 없음</div> : aiReferrals.map((row, index) => {
                  const provider = referralProvider(row.url);
                  const ReferralIcon = provider ? providerIcon(provider) : LinkIcon;
                  const referralBookmarked = bookmarkedRowids?.has(rowidOf(row)) ?? false;
                  return (
                  <button key={`${String(row.__rowid)}-${index}`} type="button" className={referralBookmarked ? "dfir-bookmarked-row" : undefined} onClick={(event) => openDetail(row, event.currentTarget)} title={row.url || row.title}
                    onMouseEnter={(event) => { if (!referralBookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
                    onMouseLeave={(event) => { if (!referralBookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}
                    style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 58, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", color: "inherit", cursor: "pointer", textAlign: "left", transition: "background .15s ease" }}>
                    <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--accent) 15%, transparent)" }}>
                      <ReferralIcon sx={{ fontSize: 16, color: "var(--accent)" }} />
                    </span>
                    <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
                      <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                        <span title={row.title || row.url} style={{ minWidth: 0, fontSize: 13, fontWeight: 700, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || row.url || "제목 없음"}</span>
                        {provider && <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", fontSize: 11.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{provider}</span>}
                      </span>
                      <span title={row.url} style={{ minWidth: 0, fontSize: 11.5, color: "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.url || "주소 정보 없음"}</span>
                    </span>
                    <time style={{ flexShrink: 0, fontSize: 12, color: "var(--text-time)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</time>
                  </button>
                  );
                })}
                {aiReferralTotal > 0 && <PaginationControls ariaLabel="AI 공유 링크 페이지" page={aiReferralPage} pageCount={Math.max(1, Math.ceil(aiReferralTotal / AI_PAGE_SIZE))} onChange={setAiReferralPage} summary={`(${(aiReferralPage * AI_PAGE_SIZE + 1).toLocaleString()}–${Math.min((aiReferralPage + 1) * AI_PAGE_SIZE, aiReferralTotal).toLocaleString()} / ${aiReferralTotal.toLocaleString()})`} />}
              </div>}
            </>}
          </div>}
        </section>
      </div>
    </div>
    </main>
    {detail && !aiConvo && !domainStatsOpen && <RowDetailPanel row={detail} columns={Object.keys(detail).filter((key) => key !== "__rowid")} focusedColumn={null} fileBaseName="BrowserActivity" onClose={closeDetail} onNavigate={() => {}} hostDir={hostDir} isBookmarked={bookmarkedRowids?.has(rowidOf(detail)) ?? false} onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(detail)) ? () => onToggleBookmark(rowidOf(detail)) : undefined} />}
    {aiConvo && <AiConversationModal conversation={aiConvo} onClose={closeAiConversation} />}
    {domainStatsOpen && <DomainStatsModal page={domainStatsPage} data={domainStats} visitTotal={insights.visitTotal} sortAsc={domainSortAsc} onSortAsc={(next) => { setDomainSortAsc(next); setDomainStatsPage(0); }} onPage={setDomainStatsPage} onClose={closeDomainStats} />}
    {downloadsOpen && <DownloadsModal page={downloadsPage} rows={downloadsData.rows} total={downloadsData.rowCount} onPage={setDownloadsPage} onOpenRow={(row, opener) => { openDetail(row, opener); }} onClose={closeDownloads} />}
  </div>;
}

function ActivityRow({ row, final: _final, bookmarked, onOpen, onToggleBookmark }: { row: Row; final: boolean; bookmarked: boolean; onOpen: (opener: HTMLElement) => void; onToggleBookmark?: () => void }) {
  const isDownload = row.kind === "download";
  const isCache = row.kind === "cache";
  const hasRecoveredCacheBody = isCache && row.cache_body_recovered === "1";
  const Icon = isDownload ? DownloadOutlinedIcon : hasRecoveredCacheBody ? Inventory2Icon : isCache ? Inventory2OutlinedIcon : LinkOutlinedIcon;
  const color = isDownload ? "var(--warning)" : hasRecoveredCacheBody ? "var(--success)" : isCache ? "var(--text-dim)" : "var(--accent)";
  const kindLabel = isDownload ? "다운로드" : isCache ? "캐시" : "방문";
  const title = row.title || (isDownload ? "파일 이름 없음" : row.url) || "제목 없음";
  const url = isDownload ? row.source_url || row.url : row.url;
  // 부가 표기: 다운로드=크기, 캐시=MIME 타입만(상태·크기·charset·방문 횟수는
  // 행에서 생략 — 상세에서 확인).
  const facts = isDownload && row.size ? row.size : isCache ? (row.mime || "").split(";")[0].trim() : "";
  const activate = (event: React.KeyboardEvent<HTMLDivElement>) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onOpen(event.currentTarget); } };
  // 행 전체(여백 포함)가 상세 열기 클릭 대상 — 북마크는 전파 차단.
  return <div className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={(event) => onOpen(event.currentTarget)} onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }} style={{ borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", gap: 10, minHeight: 58, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", background: "var(--bg-panel)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }}>
    <div role="button" tabIndex={0} onClick={(event) => onOpen(event.currentTarget)} onKeyDown={activate} aria-label={`${title} 상세 보기`} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, cursor: "pointer", outlineOffset: -2 }}>
      <span aria-hidden="true" title={hasRecoveredCacheBody ? "캐시 · 복구된 본문 있음" : kindLabel} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
        <Icon sx={{ fontSize: 16, color }} />
      </span>
      <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
        <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
          {/* 제목·URL은 50ch에서 조기 말줄임 — 긴 값이 행을 꽉 채워 오른쪽
              계정·시각과 붙는 것을 막고 사이 여백을 확보한다(전문은 title 툴팁). */}
          <span title={title} style={{ minWidth: 0, maxWidth: "50ch", fontSize: 13, fontWeight: isCache ? 550 : 700, color: isCache ? "var(--text-dim)" : "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</span>
        </span>
        <span title={row.url_raw || url} style={{ minWidth: 0, maxWidth: "50ch", fontSize: 11.5, color: isCache ? "var(--text-faint)" : "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{url || "주소 정보 없음"}</span>
      </span>
      {/* 부가 표기(MIME·횟수·크기)는 행 오른쪽, 계정 앞에 정렬. */}
      {facts && <span title={facts} style={{ flexShrink: 0, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{facts}</span>}
      <span title={row.account} style={{ flexShrink: 0, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: row.account ? "var(--text-dim)" : "var(--text-faint)" }}>{row.account || "계정 정보 없음"}</span>
      <span title={row.timestamp || "시간 정보 없음"} style={{ flexShrink: 0, width: 168, textAlign: "right", fontSize: 12.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</span>
    </div>
    {onToggleBookmark && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={(clickEvent) => { clickEvent.stopPropagation(); onToggleBookmark(); }} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkIcon sx={{ fontSize: 17 }} /> : <BookmarkBorderIcon sx={{ fontSize: 17 }} />}</button>}
  </div>;
}
function DownloadsModal({ page, rows, total, onPage, onOpenRow, onClose }: { page: number; rows: Row[]; total: number; onPage: (page: number) => void; onOpenRow: (row: Row, opener: HTMLElement) => void; onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const first = total === 0 ? 0 : safePage * PAGE_SIZE + 1;
  const last = Math.min((safePage + 1) * PAGE_SIZE, total);
  useEffect(() => {
    closeButtonRef.current?.focus();
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  return <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(1,4,9,0.6)" }}>
    <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="전체 다운로드 이력" onClick={(event) => event.stopPropagation()} style={{ display: "flex", flexDirection: "column", width: 860, maxWidth: "100%", maxHeight: "85vh", minHeight: 0, overflow: "hidden", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)" }}>
      <header style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 10, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        <DownloadOutlinedIcon sx={{ fontSize: 18, color: "var(--warning)" }} />
        <span style={{ fontSize: 14, fontWeight: 700 }}>전체 다운로드</span>
        <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>전체 {total.toLocaleString()}건 · 선택 계정 · 기간 필터 기준</span>
        <button ref={closeButtonRef} type="button" onClick={onClose} aria-label="닫기" style={{ marginLeft: "auto", display: "inline-flex", padding: 4, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "10px 14px" }}>
        {total === 0 ? <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 다운로드 기록이 없습니다.</div> : rows.map((row) => (
          <button key={String(row.__rowid)} onClick={(event) => onOpenRow(row, event.currentTarget)} title={row.title || "다운로드 상세 보기"} style={{ display: "flex", alignItems: "center", gap: 12, width: "100%", minHeight: 54, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-elevated)", color: "inherit", cursor: "pointer", textAlign: "left", transition: "background .15s ease" }}
            onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = "var(--bg-elevated)"; }}>
            <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--warning) 15%, transparent)" }}>
              <DownloadOutlinedIcon sx={{ fontSize: 16, color: "var(--warning)" }} />
            </span>
            <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                <span title={row.title} style={{ minWidth: 0, fontSize: 13, fontWeight: 700, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.title || "파일 이름 없음"}</span>
                {row.size && <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{row.size}</span>}
              </span>
              <span title={row.source_url || row.url} style={{ minWidth: 0, fontSize: 11.5, color: "var(--accent)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.source_url || row.url || "주소 정보 없음"}</span>
            </span>
            <span title={row.account} style={{ flexShrink: 0, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: row.account ? "var(--text-dim)" : "var(--text-faint)" }}>{row.account || "계정 정보 없음"}</span>
            <span style={{ flexShrink: 0, width: 168, textAlign: "right", fontSize: 12.5, color: row.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{formatAiPayloadTime(row.timestamp) || "시간 정보 없음"}</span>
          </button>
        ))}
      </div>
      <footer style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "8px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
        <PaginationControls ariaLabel="전체 다운로드 페이지" page={safePage} pageCount={pageCount} onChange={onPage} summary={`(${first.toLocaleString()}–${last.toLocaleString()} / ${total.toLocaleString()})`} />
      </footer>
    </div>
  </div>;
}

function DomainStatsModal({ page, data, visitTotal, sortAsc, onSortAsc, onPage, onClose }: { page: number; data: BrowserDomainStatsPage; visitTotal: number; sortAsc: boolean; onSortAsc: (asc: boolean) => void; onPage: (page: number) => void; onClose: () => void }) {
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
        <button type="button" className="nm-btn" onClick={() => onSortAsc(!sortAsc)} title="방문 횟수 정렬 순서 변경" style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 5, minHeight: 29, padding: "3px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 600, whiteSpace: "nowrap" }}>
          <SortIcon2 sx={{ fontSize: 15 }} />횟수 · {sortAsc ? "적은 순" : "많은 순"}
        </button>
        <button ref={closeButtonRef} onClick={onClose} title="닫기" aria-label="닫기" style={{ display: "inline-flex", flexShrink: 0, padding: 2, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      <main style={{ minHeight: 0, overflow: "auto", padding: "10px 14px" }}>{data.total === 0 ? <div style={{ padding: 18, color: "var(--text-faint)", fontSize: 12.5 }}>기간 필터 내 방문 도메인이 없습니다.</div> : data.domains.map((domain) => (
        <div key={domain.domain} title={domain.domain} style={{ display: "flex", alignItems: "center", gap: 12, minHeight: 52, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-elevated)" }}>
          <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 32, height: 32, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "var(--accent-subtle)" }}>
            <LanguageOutlinedIcon sx={{ fontSize: 16, color: "var(--accent)" }} />
          </span>
          <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
            <span style={{ minWidth: 0, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, fontWeight: 650, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{domain.domain}</span>
            <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>서로 다른 URL {domain.urlCount.toLocaleString()}개</span>
          </span>
          <span style={{ flexShrink: 0, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700, whiteSpace: "nowrap" }}>{domain.visitCount.toLocaleString()}회</span>
        </div>
      ))}</main>
      <footer style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "8px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
        <PaginationControls ariaLabel="전체 방문 도메인 페이지" page={safePage} pageCount={pageCount} onChange={onPage} summary={`(${first.toLocaleString()}–${last.toLocaleString()} / ${data.total.toLocaleString()})`} />
      </footer>
    </div>
  </div>;
}

function AiConversationModal({ conversation, onClose }: { conversation: DisplayAiConversation; onClose: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const [search, setSearch] = useState("");
  const searchQuery = search.trim().toLowerCase();
  const visibleMessages = searchQuery
    ? conversation.messages.filter((message) => message.text.toLowerCase().includes(searchQuery))
    : conversation.messages;
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
        {conversation.messages.length > 0 && !showRaw && <div style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 7 }}>
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="대화 내 검색" aria-label="대화 내 검색" style={{ width: 170, padding: "5px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", fontSize: 12 }} />
          {searchQuery && <span role="status" style={{ color: visibleMessages.length > 0 ? "var(--text-faint)" : "var(--danger)", fontSize: 11.5, whiteSpace: "nowrap" }}>{visibleMessages.length.toLocaleString()}개 일치</span>}
        </div>}
        {conversation.messages.length > 0 && <button className="nm-btn" onClick={() => setShowRaw((value) => !value)} style={pageButton(false)}>{showRaw ? "대화 보기" : "원본 JSON"}</button>}
        <button ref={closeButtonRef} onClick={onClose} title="닫기" aria-label="닫기" style={{ display: "inline-flex", flexShrink: 0, padding: 2, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}><CloseIcon sx={{ fontSize: 18 }} /></button>
      </header>
      <div style={{ flexShrink: 0, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "6px 18px", padding: "10px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
        {metadata.map(([label, value]) => <div key={label} style={{ minWidth: 0 }}><div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 2 }}>{label}</div><div title={value} style={{ fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div></div>)}
      </div>
      <div title={conversation.url} style={{ flexShrink: 0, minWidth: 0, padding: "7px 16px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{conversation.url}</div>
      <main aria-label="대화 메시지" style={{ minHeight: 0, overflow: "auto", padding: 16, background: "var(--bg)" }}>
        {showRaw ? <pre style={{ margin: 0, padding: 10, maxHeight: "62vh", overflow: "auto", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.55, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{conversation.raw}</pre> : conversation.messages.length === 0 ? <div style={{ padding: "18px 0", color: "var(--text-faint)", fontSize: 12.5 }}>표시할 대화 메시지를 추출하지 못했습니다. 원본 JSON에서 확인할 수 있습니다.</div> : visibleMessages.length === 0 ? <div style={{ padding: "18px 0", color: "var(--text-faint)", fontSize: 12.5 }}>검색어와 일치하는 메시지가 없습니다.</div> : <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {visibleMessages.map((message, index) => {
            const info = roleInfo(message.role);
            const roleIsUser = info.kind === "user";
            const roleIsSystem = info.kind === "system";
            const RoleIcon = info.Icon;
            if (roleIsSystem) return <div key={index} style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-faint)", fontSize: 11.5 }}><span style={{ height: 1, flex: 1, background: "var(--border-subtle)" }} /><RoleIcon sx={{ fontSize: 14, color: info.color }} /><span>{info.label}{message.time ? ` · ${message.time}` : ""}</span><span style={{ height: 1, flex: 1, background: "var(--border-subtle)" }} /></div>;
            return <article key={index} aria-label={`${info.label}${message.time ? ` ${message.time}` : ""}`} style={{ display: "flex", flexDirection: roleIsUser ? "row-reverse" : "row", alignItems: "flex-start", gap: 8 }}>
              <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, flexShrink: 0, marginTop: 17, borderRadius: "50%", background: `color-mix(in srgb, ${roleIsUser ? "var(--text-dim)" : "var(--accent)"} 15%, transparent)` }}><RoleIcon sx={{ fontSize: 15, color: info.color }} /></span>
              <div style={{ display: "flex", flexDirection: "column", alignItems: roleIsUser ? "flex-end" : "flex-start", gap: 4, minWidth: 0, maxWidth: "82%" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 5, color: info.color, fontSize: 11, fontWeight: 700 }}><span>{info.label}</span>{message.time && <time style={{ color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 400 }}>{message.time}</time>}</div>
                <div style={{ width: "fit-content", maxWidth: "100%", minWidth: 0, padding: "9px 13px", border: `1px solid ${roleIsUser ? "color-mix(in srgb, var(--accent) 38%, var(--border))" : "var(--border)"}`, borderRadius: roleIsUser ? "12px 4px 12px 12px" : "4px 12px 12px 12px", background: roleIsUser ? "color-mix(in srgb, var(--accent) 13%, transparent)" : "var(--bg-elevated)", color: "var(--text)", fontSize: 12.5, lineHeight: 1.6, overflow: "hidden" }}><ChatMessageBody text={message.text} /></div>
              </div>
            </article>;
          })}
        </div>}
      </main>
    </div>
  </div>;
}

// 채팅 본문의 마크다운 경량 렌더링 — **굵게**, `인라인 코드`만 서식으로 바꾼다.
// 완전한 마크다운 파서가 아니라 캐시에서 복원한 원문을 읽기 좋게 하는 수준.
function inlineMarkdown(text: string): React.ReactNode[] {
  return text.split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g).filter(Boolean).map((token, index) => {
    if (token.startsWith("**") && token.endsWith("**")) return <strong key={index}>{token.slice(2, -2)}</strong>;
    if (token.startsWith("`") && token.endsWith("`")) return <code key={index} style={{ padding: "1px 5px", background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: 4, fontFamily: "var(--mono)", fontSize: 11.5 }}>{token.slice(1, -1)}</code>;
    return <span key={index}>{token}</span>;
  });
}

// 표시용 정리 — 원문(raw JSON)은 모달에 그대로 남고, 채팅 버블에서만 과도한
// 띄어쓰기·연속 빈 줄을 줄인다. 코드 펜스 안은 서식 자체가 의미라 건드리지
// 않는다.
function cleanAiText(text: string): string {
  return text
    .split(/(```[\s\S]*?```)/g)
    .map((part) => {
      if (part.startsWith("```")) return part;
      return part
        .replace(/[ \t]+$/gm, "")
        .replace(/[ \t]{3,}/g, " ")
        .replace(/\n{3,}/g, "\n\n");
    })
    .join("")
    .trim();
}

function ChatMessageBody({ text }: { text: string }) {
  const parts = cleanAiText(text).split(/(```[\s\S]*?```)/g).filter(Boolean);
  return <>{parts.map((part, index) => {
    const isCode = part.startsWith("```") && part.endsWith("```");
    if (isCode) return <pre key={index} style={{ maxWidth: "100%", margin: index === 0 ? 0 : "8px 0 0", padding: "8px 10px", overflow: "auto", background: "var(--bg)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 11.5, lineHeight: 1.5, whiteSpace: "pre" }}>{part.replace(/^```[^\n]*\n?/, "").replace(/```$/, "")}</pre>;
    // 텍스트 구간은 줄 단위로 나눠 "#·##·### 제목" 줄만 굵은 블록으로 승격한다.
    return <span key={index} style={{ display: "block", minWidth: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere", wordBreak: "break-word" }}>{part.split(/\n/).map((line, lineIndex) => {
      const heading = /^#{1,6}\s+(.*)$/.exec(line);
      const content = heading ? <span style={{ display: "inline-block", fontSize: 13, fontWeight: 700 }}>{inlineMarkdown(heading[1])}</span> : inlineMarkdown(line);
      return <span key={lineIndex}>{lineIndex > 0 && "\n"}{content}</span>;
    })}</span>;
  })}</>;
}
