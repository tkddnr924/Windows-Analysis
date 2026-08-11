"use client";

import { useMemo, useState } from "react";
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

  const accounts = useMemo(() => {
    const s = new Set<string>();
    for (const r of data.rows) if (r.account) s.add(r.account);
    return ["(전체)", ...[...s].sort()];
  }, [data.rows]);

  // Rows for the chosen account, with a parsed day; downloads + visits together.
  const scoped = useMemo(
    () => data.rows.filter((r) => (account === "(전체)" || r.account === account) && r.timestamp),
    [data.rows, account]
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

  // Default the calendar + selection to the most recent day with activity.
  const latestDay = useMemo(() => {
    let max = "";
    for (const d of dayCounts.keys()) if (d > max) max = d;
    return max;
  }, [dayCounts]);

  const activeDay = selectedDay || latestDay;
  const view = month ?? (activeDay ? { y: +activeDay.slice(0, 4), m: +activeDay.slice(5, 7) } : monthNow());

  const dayRows = useMemo(
    () => scoped.filter((r) => dayOf(r.timestamp) === activeDay).sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || "")),
    [scoped, activeDay]
  );

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
      </div>

      <div style={{ display: "flex", gap: 18, alignItems: "flex-start", flexWrap: "wrap" }}>
        {/* calendar */}
        <div style={{ flex: "0 0 300px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, boxShadow: "var(--shadow-card)" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
            <button onClick={() => setMonth(shift(view, -1))} style={navBtn}>‹</button>
            <span style={{ fontSize: 13.5, fontWeight: 700 }}>{view.y}년 {view.m}월</span>
            <button onClick={() => setMonth(shift(view, +1))} style={navBtn}>›</button>
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
            {dayRows.map((r, i) => {
              const isDl = r.kind === "download";
              return (
                <div key={i} style={{ display: "flex", gap: 10, padding: "8px 14px", borderBottom: i < dayRows.length - 1 ? "1px solid var(--border-subtle)" : "none", borderLeft: `3px solid ${isDl ? "var(--warning)" : "transparent"}` }}>
                  <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", width: 60 }}>{(r.timestamp || "").slice(11, 19)}</span>
                  <span style={{ flexShrink: 0, fontSize: 13 }}>{isDl ? "⬇" : "🔗"}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "baseline", flexWrap: "wrap" }}>
                      <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", wordBreak: "break-all" }}>{r.title || (isDl ? "(파일)" : r.url)}</span>
                      {account === "(전체)" && r.account && <span style={{ fontSize: 10, color: "var(--text-faint)" }}>👤 {r.account}</span>}
                      {isDl && r.size && <span style={{ fontSize: 10.5, color: "var(--warning)" }}>{r.size}</span>}
                      {r.visit_count && !isDl && <span style={{ fontSize: 10, color: "var(--text-faint)" }}>{r.visit_count}회</span>}
                    </div>
                    <div title={r.url_raw} style={{ fontSize: 11, color: "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{isDl ? r.source_url || r.url : r.url}</div>
                    {isDl && r.detail && <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>💾 {r.detail}</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

const navBtn: React.CSSProperties = { fontSize: 16, width: 26, height: 26, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", cursor: "pointer" };

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
