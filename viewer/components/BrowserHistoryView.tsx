"use client";

import { useEffect, useMemo, useState } from "react";
import type { CsvData } from "@/lib/types";

type Row = Record<string, string>;

interface Props {
  data: CsvData;
}

const DOW = ["일", "월", "화", "수", "목", "금", "토"];

// "YYYY-MM-DD HH:MM:SS.fff" -> "YYYY-MM-DD"
const dayOf = (ts: string) => (ts ? ts.slice(0, 10) : "");

export default function BrowserHistoryView({ data }: Props) {
  const [account, setAccount] = useState<string>("(전체)");
  const [selectedDay, setSelectedDay] = useState<string>("");
  const [month, setMonth] = useState<{ y: number; m: number } | null>(null);
  const [kinds, setKinds] = useState<Set<string>>(new Set(["visit", "download", "cache"]));
  const [detail, setDetail] = useState<Row | null>(null);
  const [page, setPage] = useState(0);

  const KINDS = [
    { k: "visit", label: "🔗 방문" },
    { k: "download", label: "⬇ 다운로드" },
    { k: "cache", label: "📦 리소스(캐시)" },
  ];
  const PAGE_SIZE = 300; // rows per page (a busy day can hold thousands of cache hits)

  const accounts = useMemo(() => {
    const s = new Set<string>();
    for (const r of data.rows) if (r.account) s.add(r.account);
    return ["(전체)", ...[...s].sort()];
  }, [data.rows]);

  // Rows for the chosen account, with a parsed day; downloads + visits together.
  const scoped = useMemo(
    () => data.rows.filter((r) => (account === "(전체)" || r.account === account) && r.timestamp && kinds.has(r.kind || "visit")),
    [data.rows, account, kinds]
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

  // Reset to the first page whenever the day / account / kind filter changes.
  useEffect(() => setPage(0), [activeDay, account, kinds]);
  const pageCount = Math.max(1, Math.ceil(dayRows.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pagedRows = dayRows.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

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
          <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 8 }}>
            {activeDay ? `🗓️ ${activeDay} · ${dayRows.length}건` : "활동 기록 없음"}
          </div>
          <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
            {dayRows.length === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>선택한 날짜의 기록이 없습니다.</div>}
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
                </div>
              );
            })}
          </div>
          {pageCount > 1 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginTop: 10 }}>
              <button onClick={() => setPage(0)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>«</button>
              <button onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>‹ 이전</button>
              <span style={{ fontSize: 12, color: "var(--text-dim)", minWidth: 120, textAlign: "center" }}>
                {safePage + 1} / {pageCount} 쪽 <span style={{ color: "var(--text-faint)" }}>({(safePage * PAGE_SIZE + 1).toLocaleString()}–{Math.min((safePage + 1) * PAGE_SIZE, dayRows.length).toLocaleString()} / {dayRows.length.toLocaleString()})</span>
              </span>
              <button onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>다음 ›</button>
              <button onClick={() => setPage(pageCount - 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>»</button>
            </div>
          )}
        </div>
      </div>

      {detail && <DetailModal row={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

const navBtn: React.CSSProperties = { fontSize: 15, minWidth: 24, height: 24, padding: 0, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", cursor: "pointer" };
const jumpBtn: React.CSSProperties = { flex: 1, fontSize: 11, padding: "3px 6px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: "pointer", whiteSpace: "nowrap" };
const pgBtn = (disabled: boolean): React.CSSProperties => ({ fontSize: 12, padding: "4px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1, whiteSpace: "nowrap" });

const KIND_LABEL: Record<string, string> = { visit: "🔗 방문", download: "⬇ 다운로드", cache: "📦 리소스(캐시)" };

function DetailModal({ row, onClose }: { row: Row; onClose: () => void }) {
  const isDl = row.kind === "download";
  const isCache = row.kind === "cache";
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
          <button onClick={onClose} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        <div style={{ padding: "10px 18px 18px" }}>
          {fields.filter(([, v]) => v).map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ flex: "0 0 108px", color: "var(--text-faint)", fontSize: 12 }}>{k}</span>
              <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, fontFamily: k.startsWith("URL") || k.includes("경로") ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
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
