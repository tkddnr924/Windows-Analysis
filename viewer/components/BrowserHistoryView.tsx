"use client";

import { useEffect, useMemo, useState } from "react";
import type { CsvData, CacheEntry } from "@/lib/types";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";

type Row = Record<string, string>;

// --- cached-body helpers ---------------------------------------------------

function b64ToText(b64: string): string {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  } catch { return ""; }
}
function isImageType(ct: string): boolean { return /^image\//i.test(ct.trim()); }
function isTextType(ct: string): boolean {
  const c = ct.trim().toLowerCase();
  return c.startsWith("text/") || c.includes("json") || c.includes("javascript") || c.includes("xml");
}
function prettyJson(s: string): string {
  // Some APIs prefix JSON with an anti-hijack token like ")]}'".
  const cleaned = s.replace(/^\)\]\}'?\s*/, "");
  try { return JSON.stringify(JSON.parse(cleaned), null, 2); } catch { return s; }
}

// --- AI conversation extraction (best-effort across providers) -------------

const AI_HOSTS = ["chatgpt.com", "chat.openai.com", "openai.com", "claude.ai", "anthropic.com", "gemini.google.com", "bard.google.com"];

interface AiMessage { role: string; text: string; time?: string }
interface AiConversation { provider: string; title: string; date: string; url: string; messages: AiMessage[]; raw: string }

function hostOf(url: string): string { try { return new URL(url).hostname.toLowerCase(); } catch { return ""; } }

/** Pull chat messages out of a provider's conversation JSON. Handles ChatGPT's
 * `mapping` graph and Claude's `chat_messages` array; falls back to nothing
 * (the raw JSON is still shown). */
function parseAiJson(obj: unknown): { title: string; date: string; messages: AiMessage[] } {
  const out: AiMessage[] = [];
  let title = "";
  let date = "";
  const o = obj as Record<string, unknown>;
  if (o && typeof o === "object") {
    title = (o.title as string) || (o.name as string) || "";
    date = (o.create_time as string) || (o.created_at as string) || (o.update_time as string) || "";
    // ChatGPT: mapping { id: { message: { author:{role}, content:{parts:[...]}, create_time } } }
    const mapping = o.mapping as Record<string, { message?: { author?: { role?: string }; content?: { parts?: unknown[]; text?: string }; create_time?: number } }> | undefined;
    if (mapping && typeof mapping === "object") {
      const nodes = Object.values(mapping)
        .map((n) => n?.message)
        .filter((m): m is NonNullable<typeof m> => !!m && !!m.author?.role)
        .sort((a, b) => (a.create_time ?? 0) - (b.create_time ?? 0));
      for (const m of nodes) {
        const parts = m.content?.parts;
        const text = Array.isArray(parts) ? parts.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join("\n") : (m.content?.text ?? "");
        if (text && text.trim()) out.push({ role: m.author!.role || "?", text });
      }
    }
    // Claude: chat_messages: [{ sender/role, text, created_at }]
    const cm = o.chat_messages as Array<{ sender?: string; role?: string; text?: string; content?: unknown; created_at?: string }> | undefined;
    if (Array.isArray(cm)) {
      for (const m of cm) {
        let text = m.text ?? "";
        if (!text && Array.isArray(m.content)) text = (m.content as Array<{ text?: string }>).map((c) => c.text ?? "").join("\n");
        if (text && text.trim()) out.push({ role: m.sender || m.role || "?", text, time: m.created_at });
      }
    }
  }
  return { title, date, messages: out };
}

function extractAiConversations(entries: CacheEntry[]): AiConversation[] {
  const out: AiConversation[] = [];
  for (const e of entries) {
    const host = hostOf(e.url);
    if (!AI_HOSTS.some((h) => host.endsWith(h))) continue;
    if (!e.contentType.toLowerCase().includes("json")) continue;
    const text = b64ToText(e.bodyB64);
    if (!text) continue;
    const cleaned = text.replace(/^\)\]\}'?\s*/, "");
    let obj: unknown;
    try { obj = JSON.parse(cleaned); } catch { continue; }
    const { title, date, messages } = parseAiJson(obj);
    // Only surface JSON that actually looks like a conversation.
    if (messages.length === 0 && !/conversation|chat|message/i.test(e.url)) continue;
    const provider = host.includes("claude") || host.includes("anthropic") ? "Claude"
      : host.includes("openai") || host.includes("chatgpt") ? "ChatGPT"
      : host.includes("gemini") || host.includes("bard") ? "Gemini" : host;
    out.push({ provider, title: title || "(제목 없음)", date: date || e.responseTime || "", url: e.url, messages, raw: prettyJson(text) });
  }
  return out;
}

interface Props {
  data: CsvData;
  /** Host folder — used to load cached response bodies (image/text previews +
   * AI-conversation detection). */
  hostDir?: string;
  /** Global incident-window filter from the sidebar; applied to every row. */
  timeRange?: TimeRange;
  /** Rowids (of this table) currently bookmarked, + the toggle — same
   * bookmarking every other view has, keyed on each row's __rowid. */
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
}

const rowidOf = (r: Record<string, string>): number => Number((r as Record<string, unknown>).__rowid);

const DOW = ["일", "월", "화", "수", "목", "금", "토"];

// "YYYY-MM-DD HH:MM:SS.fff" -> "YYYY-MM-DD"
const dayOf = (ts: string) => (ts ? ts.slice(0, 10) : "");

const miniBtn: React.CSSProperties = { marginTop: 6, fontSize: 11, padding: "2px 8px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--accent)", cursor: "pointer" };
const sortChip = (active: boolean): React.CSSProperties => ({ fontSize: 11, padding: "3px 10px", borderRadius: 999, cursor: "pointer", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, whiteSpace: "nowrap" });

// "2.2 MB" / "218166" / "1,024 KB" -> bytes, for size sorting.
function parseBytes(s: string): number {
  if (!s) return 0;
  const m = s.trim().match(/^([\d.,]+)\s*(TB|GB|MB|KB|B)?/i);
  if (!m) return 0;
  const n = parseFloat(m[1].replace(/,/g, "")) || 0;
  const mult: Record<string, number> = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
  return n * (mult[(m[2] || "B").toUpperCase()] ?? 1);
}

// Full-list modal used by the "더 보기" buttons — a scrollable list with an
// optional sort toolbar in the header.
function ListModal({ title, toolbar, onClose, children }: { title: string; toolbar?: React.ReactNode; onClose: () => void; children: React.ReactNode }) {
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 720, maxWidth: "100%", maxHeight: "82vh", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 18px", borderBottom: "1px solid var(--border)", flexWrap: "wrap" }}>
          <span style={{ fontSize: 14, fontWeight: 700 }}>{title}</span>
          {toolbar}
          <button onClick={onClose} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        <div style={{ padding: "10px 18px 18px", overflow: "auto" }}>{children}</div>
      </div>
    </div>
  );
}

// Host of a URL — used for the domain ranking. Falls back to a regex for
// odd/relative values; returns "" for file paths and unparseable strings.
function domainOf(url: string): string {
  if (!url) return "";
  try {
    return new URL(url).hostname || "";
  } catch {
    const m = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i);
    return m ? m[1] : "";
  }
}

// Find JWTs anywhere in a string (header.payload.signature, base64url). Scans
// both the raw and URL-decoded form since tokens often ride in query params.
const JWT_RE = /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
function findJwts(...texts: string[]): string[] {
  const out = new Set<string>();
  for (const t of texts) {
    if (!t) continue;
    let dec = t;
    try { dec = decodeURIComponent(t); } catch { /* keep raw */ }
    for (const s of new Set([t, dec])) {
      const mm = s.match(JWT_RE);
      if (mm) mm.forEach((x) => out.add(x));
    }
  }
  return [...out];
}
function b64urlDecode(s: string): string {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  try {
    // handle UTF-8 payloads
    return decodeURIComponent(Array.from(atob(t), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
  } catch {
    try { return atob(t); } catch { return ""; }
  }
}
function decodeJwt(token: string): { header: string; payload: string } | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const pretty = (raw: string) => { try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw || "(디코드 실패)"; } };
  return { header: pretty(b64urlDecode(parts[0])), payload: pretty(b64urlDecode(parts[1])) };
}

export default function BrowserHistoryView({ data, hostDir = "", timeRange = EMPTY_TIME_RANGE, bookmarkedRowids, onToggleBookmark }: Props) {
  const [cacheEntries, setCacheEntries] = useState<CacheEntry[]>([]);
  const [aiConvo, setAiConvo] = useState<AiConversation | null>(null);
  const [account, setAccount] = useState<string>("(전체)");
  const [selectedDay, setSelectedDay] = useState<string>("");
  const [month, setMonth] = useState<{ y: number; m: number } | null>(null);
  const [kinds, setKinds] = useState<Set<string>>(new Set(["visit", "download", "cache"]));
  const [detail, setDetail] = useState<Row | null>(null);
  const [page, setPage] = useState(0);
  const [modal, setModal] = useState<null | "domains" | "downloads">(null);
  const [domainSort, setDomainSort] = useState<"desc" | "asc">("desc");
  const [dlSort, setDlSort] = useState<"date" | "size" | "name">("date");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!hostDir) { setCacheEntries([]); return; }
    let alive = true;
    window.api.cacheEntries(hostDir).then((e) => { if (alive) setCacheEntries(e); }).catch(() => {});
    return () => { alive = false; };
  }, [hostDir]);

  // url(lowercased) -> cache entry, so a cache row's detail can show its body.
  const cacheByUrl = useMemo(() => {
    const m = new Map<string, CacheEntry>();
    for (const e of cacheEntries) if (e.url) m.set(e.url.toLowerCase(), e);
    return m;
  }, [cacheEntries]);

  // AI chat conversations found in the cache (chatgpt/claude/... JSON bodies).
  const aiConversations = useMemo(() => extractAiConversations(cacheEntries), [cacheEntries]);

  const KINDS = [
    { k: "visit", label: "🔗 방문" },
    { k: "download", label: "⬇ 다운로드" },
    { k: "cache", label: "📦 리소스(캐시)" },
  ];
  const PAGE_SIZE = 10; // rows per page

  const accounts = useMemo(() => {
    const s = new Set<string>();
    for (const r of data.rows) if (r.account) s.add(r.account);
    return ["(전체)", ...[...s].sort()];
  }, [data.rows]);

  // Rows for the chosen account, with a parsed day; downloads + visits together.
  const rangeOn = rangeActive(timeRange);
  const scoped = useMemo(
    () =>
      data.rows.filter(
        (r) =>
          (account === "(전체)" || r.account === account) &&
          r.timestamp &&
          kinds.has(r.kind || "visit") &&
          (!rangeOn || inRange(r.timestamp, timeRange))
      ),
    [data.rows, account, kinds, rangeOn, timeRange]
  );

  // day -> count, for the calendar dots.
  const dayCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of scoped) {
      const d = dayOf(r.timestamp);
      if (d) m.set(d, (m.get(d) ?? 0) + 1);
    }
    return m;
  }, [scoped]);

  // Period statistics — computed over the filtered scope (account + kind +
  // sidebar time range), independent of the selected calendar day. So the
  // stats reflect exactly what the current filters select.
  const stats = useMemo(() => {
    const domainMap = new Map<string, number>();
    const dayMap = new Map<string, number>();
    const downloads: Row[] = [];
    for (const r of scoped) {
      const d = domainOf(r.url || r.url_raw || "");
      if (d) domainMap.set(d, (domainMap.get(d) ?? 0) + 1);
      const day = dayOf(r.timestamp);
      if (day) dayMap.set(day, (dayMap.get(day) ?? 0) + 1);
      if (r.kind === "download") downloads.push(r);
    }
    const domains = [...domainMap.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const days = [...dayMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    downloads.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
    return { domains, days, downloads };
  }, [scoped]);

  useEffect(() => { setModal(null); }, [account, kinds, rangeOn]);

  // Sorted list of days that have activity — drives latest-day default and the
  // "이전/다음 활동일" jump buttons (skip straight to a day with records).
  const activeDays = useMemo(() => [...dayCounts.keys()].sort(), [dayCounts]);
  const latestDay = activeDays.length ? activeDays[activeDays.length - 1] : "";

  const activeDay = selectedDay || latestDay;
  const view = month ?? (activeDay ? { y: +activeDay.slice(0, 4), m: +activeDay.slice(5, 7) } : monthNow());

  const dayIdx = activeDays.indexOf(activeDay);
  const gotoDay = (d: string) => { setSelectedDay(d); setMonth(null); };
  const prevDay = dayIdx > 0 ? activeDays[dayIdx - 1] : "";
  const nextDay = dayIdx >= 0 && dayIdx < activeDays.length - 1 ? activeDays[dayIdx + 1] : "";

  const dayRows = useMemo(
    () => scoped.filter((r) => dayOf(r.timestamp) === activeDay).sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || "")),
    [scoped, activeDay]
  );

  // Search runs LAST — after the period (time-range) filter and the calendar-day
  // filter have narrowed the set — matching the domain, full URL, or title.
  const searchedRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return dayRows;
    return dayRows.filter((r) => {
      const url = (r.url || r.url_raw || "").toLowerCase();
      return url.includes(q) || domainOf(r.url || r.url_raw || "").toLowerCase().includes(q) || (r.title || "").toLowerCase().includes(q);
    });
  }, [dayRows, search]);

  // Reset to the first page whenever the day / account / kind / search changes.
  useEffect(() => setPage(0), [activeDay, account, kinds, search]);
  const pageCount = Math.max(1, Math.ceil(searchedRows.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pagedRows = searchedRows.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  const grid = useMemo(() => calendarGrid(view.y, view.m), [view]);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "18px 22px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 2 }}>
        <span style={{ fontSize: 22, fontWeight: 700 }}>🌐 브라우저 활동</span>
        <span style={{ fontSize: 13, color: "var(--text-dim)" }}>일자를 선택하면 그날의 기록을 시간순으로 봅니다</span>
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 14 }}>URL은 평문으로 디코딩해 표시합니다.</div>

      {/* account chips */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
        {accounts.map((a) => (
          <button
            key={a}
            onClick={() => { setAccount(a); setSelectedDay(""); setMonth(null); }}
            style={{
              fontSize: 12, padding: "4px 12px", borderRadius: "var(--radius-lg)", cursor: "pointer", fontWeight: account === a ? 700 : 500,
              background: account === a ? "var(--accent-subtle)" : "transparent",
              color: account === a ? "var(--accent)" : "var(--text-dim)",
              border: `1px solid ${account === a ? "var(--accent)" : "var(--border)"}`,
            }}
          >
            {a === "(전체)" ? a : `👤 ${a}`}
          </button>
        ))}
        <span style={{ width: 1, alignSelf: "stretch", background: "var(--border)", margin: "0 4px" }} />
        {KINDS.map(({ k, label }) => {
          const on = kinds.has(k);
          return (
            <button
              key={k}
              onClick={() => setKinds((prev) => { const n = new Set(prev); if (n.has(k)) n.delete(k); else n.add(k); return n.size ? n : prev; })}
              style={{
                fontSize: 12, padding: "4px 10px", borderRadius: "var(--radius-lg)", cursor: "pointer", fontWeight: on ? 700 : 500,
                background: on ? "var(--bg-elevated)" : "transparent",
                color: on ? "var(--text)" : "var(--text-faint)",
                border: `1px solid ${on ? "var(--border)" : "var(--border-subtle)"}`,
                opacity: on ? 1 : 0.6,
              }}
            >
              {label}
            </button>
          );
        })}
      </div>

      {/* period statistics — follows the account/kind/time-range filters */}
      {scoped.length > 0 && (
        <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 16, alignItems: "flex-start" }}>
          {/* most-accessed domains */}
          <div style={{ flex: "1 1 300px", minWidth: 280, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, boxShadow: "var(--shadow-card)" }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 8 }}>🌐 접근 도메인 <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{stats.domains.length}개</span></div>
            {(() => {
              const max = stats.domains[0]?.[1] ?? 1;
              return (
                <>
                  {stats.domains.slice(0, 5).map(([dom, n]) => (
                    <div key={dom} style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0" }}>
                      <span style={{ flex: 1, minWidth: 0, position: "relative", fontSize: 11.5, fontFamily: "var(--mono)" }}>
                        <span style={{ position: "absolute", inset: 0, background: "var(--accent-subtle)", width: `${Math.round((n / max) * 100)}%`, borderRadius: 3 }} />
                        <span style={{ position: "relative", color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "block", padding: "2px 6px" }}>{dom}</span>
                      </span>
                      <span style={{ flexShrink: 0, fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>{n.toLocaleString()}</span>
                    </div>
                  ))}
                  {stats.domains.length > 5 && (
                    <button onClick={() => setModal("domains")} style={miniBtn}>
                      +{stats.domains.length - 5}개 더 보기
                    </button>
                  )}
                </>
              );
            })()}
          </div>

          {/* downloads */}
          <div style={{ flex: "1 1 300px", minWidth: 280, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, boxShadow: "var(--shadow-card)" }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 8 }}>⬇ 다운로드 <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{stats.downloads.length}건</span></div>
            {stats.downloads.length === 0 && <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>기록 없음</div>}
            {stats.downloads.slice(0, 5).map((r, i) => (
              <div key={i} onClick={() => setDetail(r)} title="클릭하면 상세" style={{ display: "flex", gap: 8, padding: "3px 0", cursor: "pointer", borderBottom: "1px solid var(--border-subtle)" }}>
                <span style={{ flexShrink: 0, fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{(r.timestamp || "").slice(5, 16)}</span>
                <span style={{ flex: 1, minWidth: 0, fontSize: 11.5, color: "var(--warning)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{r.title || r.url}</span>
                {r.size && <span style={{ flexShrink: 0, fontSize: 10.5, color: "var(--text-faint)" }}>{r.size}</span>}
              </div>
            ))}
            {stats.downloads.length > 5 && (
              <button onClick={() => setModal("downloads")} style={miniBtn}>
                +{stats.downloads.length - 5}건 더 보기
              </button>
            )}
          </div>

          {/* per-day activity graph */}
          <div style={{ flex: "1 1 320px", minWidth: 300, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, boxShadow: "var(--shadow-card)" }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 8 }}>📊 기간별 활동 <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{stats.days.length}일</span></div>
            {(() => {
              const max = Math.max(1, ...stats.days.map(([, n]) => n));
              return (
                <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 84, overflowX: "auto", paddingBottom: 2 }}>
                  {stats.days.map(([day, n]) => (
                    <div
                      key={day}
                      onClick={() => gotoDay(day)}
                      title={`${day} · ${n.toLocaleString()}건`}
                      style={{ flex: "1 0 8px", minWidth: 6, display: "flex", flexDirection: "column", justifyContent: "flex-end", height: "100%", cursor: "pointer" }}
                    >
                      <div style={{ height: `${Math.round((n / max) * 100)}%`, background: day === activeDay ? "var(--accent)" : "var(--accent-subtle)", borderRadius: "2px 2px 0 0", minHeight: 2 }} />
                    </div>
                  ))}
                </div>
              );
            })()}
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 4 }}>
              <span>{stats.days[0]?.[0] ?? ""}</span>
              <span>{stats.days[stats.days.length - 1]?.[0] ?? ""}</span>
            </div>
          </div>
        </div>
      )}

      <div style={{ display: "flex", gap: 18, alignItems: "flex-start", flexWrap: "wrap" }}>
        {/* calendar */}
        <div style={{ flex: "0 0 300px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, boxShadow: "var(--shadow-card)" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
            <div style={{ display: "flex", gap: 3 }}>
              <button onClick={() => setMonth({ y: view.y - 1, m: view.m })} title="이전 해" style={navBtn}>«</button>
              <button onClick={() => setMonth(shift(view, -1))} title="이전 달" style={navBtn}>‹</button>
            </div>
            <button onClick={() => latestDay && gotoDay(latestDay)} title="최근 활동일로" style={{ fontSize: 13.5, fontWeight: 700, background: "transparent", border: "none", color: "var(--text)", cursor: "pointer" }}>
              {view.y}년 {view.m}월
            </button>
            <div style={{ display: "flex", gap: 3 }}>
              <button onClick={() => setMonth(shift(view, +1))} title="다음 달" style={navBtn}>›</button>
              <button onClick={() => setMonth({ y: view.y + 1, m: view.m })} title="다음 해" style={navBtn}>»</button>
            </div>
          </div>
          {/* jump between days that actually have activity */}
          <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 10 }}>
            <button onClick={() => prevDay && gotoDay(prevDay)} disabled={!prevDay} style={{ ...jumpBtn, opacity: prevDay ? 1 : 0.4 }}>◀ 이전 활동일</button>
            <button onClick={() => latestDay && gotoDay(latestDay)} title="최근" style={{ ...jumpBtn, flex: "0 0 auto", padding: "3px 8px" }}>최근</button>
            <button onClick={() => nextDay && gotoDay(nextDay)} disabled={!nextDay} style={{ ...jumpBtn, opacity: nextDay ? 1 : 0.4 }}>다음 활동일 ▶</button>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 2, textAlign: "center" }}>
            {DOW.map((d, i) => (
              <div key={d} style={{ fontSize: 10.5, color: i === 0 ? "var(--danger)" : i === 6 ? "var(--accent)" : "var(--text-faint)", padding: "2px 0" }}>{d}</div>
            ))}
            {grid.map((cell, i) => {
              if (!cell) return <div key={i} />;
              const ds = `${view.y}-${pad(view.m)}-${pad(cell)}`;
              const count = dayCounts.get(ds) ?? 0;
              const isSel = ds === activeDay;
              return (
                <button
                  key={i}
                  onClick={() => count > 0 && setSelectedDay(ds)}
                  disabled={count === 0}
                  title={count ? `${count}건` : ""}
                  style={{
                    aspectRatio: "1", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
                    fontSize: 12, borderRadius: "var(--radius-sm)", border: "1px solid transparent",
                    cursor: count ? "pointer" : "default",
                    background: isSel ? "var(--accent)" : count ? "var(--accent-subtle)" : "transparent",
                    color: isSel ? "#fff" : count ? "var(--accent)" : "var(--text-faint)",
                    fontWeight: count ? 700 : 400,
                  }}
                >
                  {cell}
                  {count > 0 && <span style={{ fontSize: 8, opacity: 0.8 }}>{count}</span>}
                </button>
              );
            })}
          </div>
          <div style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 10 }}>
            활동 있는 날 {dayCounts.size}일 · 파란 날짜 클릭
          </div>
        </div>

        {/* day timeline */}
        <div style={{ flex: 1, minWidth: 320 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 13.5, fontWeight: 700 }}>
              {activeDay ? `🗓️ ${activeDay} · ${searchedRows.length.toLocaleString()}건` : "활동 기록 없음"}
              {search.trim() && <span style={{ color: "var(--text-faint)", fontWeight: 400 }}> / {dayRows.length.toLocaleString()}건 중</span>}
            </span>
            <div style={{ marginLeft: "auto", position: "relative" }}>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="이 날짜에서 도메인·URL·제목 검색"
                style={{ width: 280, padding: "5px 26px 5px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12 }}
              />
              {search && (
                <button onClick={() => setSearch("")} title="지우기" style={{ position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)", background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer", fontSize: 14 }}>×</button>
              )}
            </div>
          </div>
          <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
            {searchedRows.length === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>{search.trim() ? `"${search.trim()}" 검색 결과가 없습니다.` : "선택한 날짜의 기록이 없습니다."}</div>}
            {pagedRows.map((r, i, arr) => {
              const isDl = r.kind === "download";
              const isCache = r.kind === "cache";
              const icon = isDl ? "⬇" : isCache ? "📦" : "🔗";
              const accent = isDl ? "var(--warning)" : isCache ? "var(--border)" : "transparent";
              return (
                <div
                  key={i}
                  onClick={() => setDetail(r)}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  style={{ display: "flex", gap: 10, padding: isCache ? "5px 14px" : "8px 14px", borderBottom: i < arr.length - 1 ? "1px solid var(--border-subtle)" : "none", borderLeft: `3px solid ${accent}`, opacity: isCache ? 0.82 : 1, cursor: "pointer" }}
                >
                  <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", width: 60 }}>{(r.timestamp || "").slice(11, 19)}</span>
                  <span style={{ flexShrink: 0, fontSize: isCache ? 11 : 13 }}>{icon}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "baseline", flexWrap: "wrap" }}>
                      <span style={{ fontSize: isCache ? 12 : 12.5, fontWeight: isCache ? 500 : 600, color: isCache ? "var(--text-dim)" : "var(--text)", wordBreak: "break-all" }}>{r.title || (isDl ? "(파일)" : r.url)}</span>
                      {account === "(전체)" && r.account && <span style={{ fontSize: 10, color: "var(--text-faint)" }}>👤 {r.account}</span>}
                      {isDl && r.size && <span style={{ fontSize: 10.5, color: "var(--warning)" }}>{r.size}</span>}
                      {isCache && (r.status || r.mime) && <span style={{ fontSize: 10, color: "var(--text-faint)" }}>{[r.status, r.mime, r.size].filter(Boolean).join(" · ")}</span>}
                      {r.visit_count && !isDl && !isCache && <span style={{ fontSize: 10, color: "var(--text-faint)" }}>{r.visit_count}회</span>}
                    </div>
                    <div title={r.url_raw} style={{ fontSize: isCache ? 10.5 : 11, color: isCache ? "var(--text-faint)" : "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{isDl ? r.source_url || r.url : r.url}</div>
                    {isDl && r.detail && <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>💾 {r.detail}</div>}
                  </div>
                  {onToggleBookmark && Number.isFinite(rowidOf(r)) && (
                    <span
                      onClick={(e) => { e.stopPropagation(); onToggleBookmark(rowidOf(r)); }}
                      title={bookmarkedRowids?.has(rowidOf(r)) ? "북마크 해제" : "북마크에 추가"}
                      style={{ flexShrink: 0, alignSelf: "center", cursor: "pointer", fontSize: 14, color: bookmarkedRowids?.has(rowidOf(r)) ? "var(--warning)" : "var(--text-faint)" }}
                    >
                      {bookmarkedRowids?.has(rowidOf(r)) ? "★" : "☆"}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
          {pageCount > 1 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginTop: 10 }}>
              <button onClick={() => setPage(0)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>«</button>
              <button onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>‹ 이전</button>
              <span style={{ fontSize: 12, color: "var(--text-dim)", minWidth: 120, textAlign: "center" }}>
                {safePage + 1} / {pageCount} 쪽 <span style={{ color: "var(--text-faint)" }}>({(safePage * PAGE_SIZE + 1).toLocaleString()}–{Math.min((safePage + 1) * PAGE_SIZE, searchedRows.length).toLocaleString()} / {searchedRows.length.toLocaleString()})</span>
              </span>
              <button onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>다음 ›</button>
              <button onClick={() => setPage(pageCount - 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>»</button>
            </div>
          )}
        </div>
      </div>

      {aiConversations.length > 0 && (
        <div style={{ marginTop: 24, borderTop: "1px solid var(--border)", paddingTop: 16 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
            <span style={{ fontSize: 15, fontWeight: 700 }}>🤖 AI 대화 확인</span>
            <span style={{ fontSize: 12, color: "var(--text-faint)" }}>캐시에서 발견한 ChatGPT/Claude 등 대화 {aiConversations.length}건</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {aiConversations.map((c, i) => (
              <div key={i} onClick={() => setAiConvo(c)} title="클릭하면 대화 내용 보기"
                style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", cursor: "pointer" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-panel)")}
              >
                <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-lg)", padding: "1px 8px" }}>{c.provider}</span>
                <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", width: 150 }}>{c.date || "-"}</span>
                <span style={{ flex: 1, minWidth: 0, fontSize: 12.5, color: "var(--text)", wordBreak: "break-all" }}>{c.title}</span>
                {c.messages.length > 0 && <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)" }}>{c.messages.length}개 메시지</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {detail && (
        <DetailModal
          row={detail}
          cacheBody={detail.kind === "cache" ? cacheByUrl.get((detail.url || "").toLowerCase()) : undefined}
          onClose={() => setDetail(null)}
          isBookmarked={bookmarkedRowids?.has(rowidOf(detail)) ?? false}
          onToggleBookmark={onToggleBookmark && Number.isFinite(rowidOf(detail)) ? () => onToggleBookmark(rowidOf(detail)) : undefined}
        />
      )}

      {aiConvo && <AiConvoModal convo={aiConvo} onClose={() => setAiConvo(null)} />}

      {modal === "domains" && (
        <ListModal title={`🌐 접근 도메인 (${stats.domains.length}개)`} onClose={() => setModal(null)}
          toolbar={
            <div style={{ display: "flex", gap: 4 }}>
              <button onClick={() => setDomainSort("desc")} style={sortChip(domainSort === "desc")}>횟수 많은순 ↓</button>
              <button onClick={() => setDomainSort("asc")} style={sortChip(domainSort === "asc")}>횟수 적은순 ↑</button>
            </div>
          }
        >
          {(() => {
            const list = domainSort === "asc" ? [...stats.domains].reverse() : stats.domains;
            const max = stats.domains[0]?.[1] ?? 1;
            return list.map(([dom, n]) => (
              <div key={dom} style={{ display: "flex", alignItems: "center", gap: 10, padding: "4px 0" }}>
                <span style={{ flex: 1, minWidth: 0, position: "relative", fontSize: 12, fontFamily: "var(--mono)" }}>
                  <span style={{ position: "absolute", inset: 0, background: "var(--accent-subtle)", width: `${Math.round((n / max) * 100)}%`, borderRadius: 3 }} />
                  <span style={{ position: "relative", color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "block", padding: "3px 8px" }}>{dom}</span>
                </span>
                <span style={{ flexShrink: 0, fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>{n.toLocaleString()}</span>
              </div>
            ));
          })()}
        </ListModal>
      )}

      {modal === "downloads" && (
        <ListModal title={`⬇ 다운로드 (${stats.downloads.length}건)`} onClose={() => setModal(null)}
          toolbar={
            <div style={{ display: "flex", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--text-faint)", alignSelf: "center", marginRight: 2 }}>정렬</span>
              <button onClick={() => setDlSort("date")} style={sortChip(dlSort === "date")}>일자</button>
              <button onClick={() => setDlSort("size")} style={sortChip(dlSort === "size")}>크기</button>
              <button onClick={() => setDlSort("name")} style={sortChip(dlSort === "name")}>이름</button>
            </div>
          }
        >
          {[...stats.downloads].sort((a, b) => {
            if (dlSort === "size") return parseBytes(b.size) - parseBytes(a.size);
            if (dlSort === "name") return (a.title || a.url || "").localeCompare(b.title || b.url || "");
            return (a.timestamp || "").localeCompare(b.timestamp || "");
          }).map((r, i) => (
            <div key={i} onClick={() => { setDetail(r); setModal(null); }} title="클릭하면 상세"
              style={{ display: "flex", gap: 10, padding: "6px 0", cursor: "pointer", borderBottom: "1px solid var(--border-subtle)" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", width: 128 }}>{r.timestamp || ""}</span>
              <span style={{ flex: 1, minWidth: 0, fontSize: 12, color: "var(--warning)", wordBreak: "break-all" }}>{r.title || r.url}</span>
              {r.size && <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{r.size}</span>}
            </div>
          ))}
        </ListModal>
      )}
    </div>
  );
}

const navBtn: React.CSSProperties = { fontSize: 15, minWidth: 24, height: 24, padding: 0, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", cursor: "pointer" };
const jumpBtn: React.CSSProperties = { flex: 1, fontSize: 11, padding: "3px 6px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: "pointer", whiteSpace: "nowrap" };
const pgBtn = (disabled: boolean): React.CSSProperties => ({ fontSize: 12, padding: "4px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1, whiteSpace: "nowrap" });

const KIND_LABEL: Record<string, string> = { visit: "🔗 방문", download: "⬇ 다운로드", cache: "📦 리소스(캐시)" };
const jwtPre: React.CSSProperties = { margin: 0, padding: 8, background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", fontFamily: "var(--mono)", fontSize: 11.5, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text)" };

function DetailModal({ row, cacheBody, onClose, isBookmarked, onToggleBookmark }: { row: Row; cacheBody?: CacheEntry; onClose: () => void; isBookmarked?: boolean; onToggleBookmark?: () => void }) {
  const isDl = row.kind === "download";
  const isCache = row.kind === "cache";
  const jwts = findJwts(row.url || "", row.url_raw || "", row.source_url || "");
  const [showJwt, setShowJwt] = useState(false);
  const fields: [string, string][] = [
    ["종류", KIND_LABEL[row.kind] || row.kind],
    ["계정", row.account],
    ["시각", row.timestamp],
    ["제목", row.title],
    ["URL", row.url],
    ["URL(원본)", row.url_raw && row.url_raw !== row.url ? row.url_raw : ""],
    ...(!isDl && !isCache ? ([["방문 횟수", row.visit_count], ["입력 횟수", row.typed_count]] as [string, string][]) : []),
    ...(isDl ? ([["출처 페이지", row.source_url], ["저장 경로", row.detail], ["크기", row.size], ["유형", row.mime]] as [string, string][]) : []),
    ...(isCache ? ([["상태", row.status], ["Content-Type", row.mime], ["크기", row.size]] as [string, string][]) : []),
  ];
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 620, maxWidth: "100%", maxHeight: "82vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--border)" }}>
          <span style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>{row.title || row.url || "(기록)"}</span>
          {onToggleBookmark && (
            <button
              onClick={onToggleBookmark}
              title={isBookmarked ? "북마크 해제" : "북마크에 추가"}
              style={{ marginLeft: "auto", background: isBookmarked ? "var(--warning-subtle)" : "var(--bg-elevated)", border: `1px solid ${isBookmarked ? "var(--warning)" : "var(--border)"}`, color: isBookmarked ? "var(--warning)" : "var(--text-dim)", fontSize: 12, fontWeight: 600, padding: "3px 10px", borderRadius: "var(--radius-sm)", cursor: "pointer", whiteSpace: "nowrap" }}
            >
              {isBookmarked ? "★ 북마크됨" : "☆ 북마크"}
            </button>
          )}
          <button onClick={onClose} style={{ marginLeft: onToggleBookmark ? 8 : "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        <div style={{ padding: "10px 18px 18px" }}>
          {fields.filter(([, v]) => v).map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ flex: "0 0 108px", color: "var(--text-faint)", fontSize: 12 }}>{k}</span>
              <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, fontFamily: k.startsWith("URL") || k.includes("경로") ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}

          {/* Cached response body: show the actual content — image preview, or
              text/JSON/JS/HTML (pretty-printed for JSON). */}
          {isCache && cacheBody && cacheBody.bodyB64 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-dim)", marginBottom: 6 }}>📦 캐시된 실제 데이터</div>
              {isImageType(cacheBody.contentType) ? (
                <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: 8, background: "var(--bg)", textAlign: "center" }}>
                  <img
                    src={`data:${cacheBody.contentType.split(";")[0]};base64,${cacheBody.bodyB64}`}
                    alt="cached"
                    style={{ maxWidth: "100%", maxHeight: 360, imageRendering: "auto" }}
                  />
                </div>
              ) : isTextType(cacheBody.contentType) ? (
                <pre style={{ ...jwtPre, maxHeight: 360, overflow: "auto" }}>
                  {(() => {
                    const t = b64ToText(cacheBody.bodyB64);
                    return cacheBody.contentType.toLowerCase().includes("json") ? prettyJson(t) : t;
                  })()}
                </pre>
              ) : (
                <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>미리보기를 지원하지 않는 형식입니다.</div>
              )}
            </div>
          )}

          {/* JWT: URLs (esp. token=… login links) often carry a JWT. Offer to decode it. */}
          {jwts.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <button
                onClick={() => setShowJwt((v) => !v)}
                style={{ fontSize: 12, fontWeight: 600, padding: "5px 12px", background: showJwt ? "var(--accent-subtle)" : "var(--bg-elevated)", color: "var(--accent)", border: `1px solid ${showJwt ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", cursor: "pointer" }}
              >
                🔑 JWT 디코드 {jwts.length > 1 ? `(${jwts.length}개)` : ""}
              </button>
              {showJwt && jwts.map((tok, i) => {
                const dec = decodeJwt(tok);
                return (
                  <div key={i} style={{ marginTop: 8, border: "1px solid var(--border)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
                    <div style={{ padding: "5px 10px", background: "var(--bg-elevated)", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{tok}</div>
                    {dec && (
                      <div style={{ padding: 10 }}>
                        <div style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 2 }}>HEADER</div>
                        <pre style={jwtPre}>{dec.header}</pre>
                        <div style={{ fontSize: 11, color: "var(--text-faint)", margin: "8px 0 2px" }}>PAYLOAD</div>
                        <pre style={jwtPre}>{dec.payload}</pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AiConvoModal({ convo, onClose }: { convo: AiConversation; onClose: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const roleColor = (role: string) => /assistant|claude|gpt|model|ai/i.test(role) ? "var(--accent)" : "var(--success)";
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 760, maxWidth: "100%", maxHeight: "85vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--border)", position: "sticky", top: 0, background: "var(--bg-panel)" }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-lg)", padding: "1px 8px" }}>{convo.provider}</span>
          <span style={{ fontSize: 14, fontWeight: 700, wordBreak: "break-all" }}>{convo.title}</span>
          {convo.messages.length > 0 && (
            <button onClick={() => setShowRaw((v) => !v)} style={{ marginLeft: "auto", fontSize: 11.5, padding: "3px 10px", background: showRaw ? "var(--accent-subtle)" : "var(--bg-elevated)", color: "var(--accent)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", cursor: "pointer" }}>{showRaw ? "대화 보기" : "원본 JSON"}</button>
          )}
          <button onClick={onClose} style={{ marginLeft: convo.messages.length > 0 ? 8 : "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        <div style={{ fontSize: 11, color: "var(--text-faint)", padding: "6px 18px", fontFamily: "var(--mono)", wordBreak: "break-all", borderBottom: "1px solid var(--border-subtle)" }}>{convo.date} · {convo.url}</div>
        <div style={{ padding: 16 }}>
          {showRaw || convo.messages.length === 0 ? (
            <pre style={{ ...jwtPre, maxHeight: "62vh", overflow: "auto" }}>{convo.raw}</pre>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {convo.messages.map((m, i) => (
                <div key={i} style={{ borderLeft: `3px solid ${roleColor(m.role)}`, paddingLeft: 12 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: roleColor(m.role), marginBottom: 3 }}>{m.role}{m.time ? ` · ${m.time}` : ""}</div>
                  <div style={{ fontSize: 12.5, color: "var(--text)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{m.text}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function pad(n: number): string { return String(n).padStart(2, "0"); }
function monthNow(): { y: number; m: number } { return { y: 2000, m: 1 }; } // no activity → arbitrary; grid still renders
function shift(v: { y: number; m: number }, d: number): { y: number; m: number } {
  let m = v.m + d, y = v.y;
  if (m < 1) { m = 12; y -= 1; }
  if (m > 12) { m = 1; y += 1; }
  return { y, m };
}
// Grid of 42 cells (6 weeks); null for leading/trailing blanks, day-number otherwise.
function calendarGrid(y: number, m: number): (number | null)[] {
  const first = new Date(y, m - 1, 1).getDay(); // 0=Sun
  const days = new Date(y, m, 0).getDate();
  const cells: (number | null)[] = [];
  for (let i = 0; i < first; i++) cells.push(null);
  for (let d = 1; d <= days; d++) cells.push(d);
  while (cells.length % 7 !== 0) cells.push(null);
  return cells;
}
