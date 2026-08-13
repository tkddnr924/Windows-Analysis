"use client";

import { useMemo, useState } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

// SMB is not a session protocol like RDP — it's a stream of per-attempt auth
// records, overwhelmingly failures (SMBServer/Security 551). So instead of the
// RDP session flow, group by SOURCE IP: one card per client address with its
// attempt volume, accounts tried and time span. A single IP with thousands of
// failures is a brute-force / password-spray source, which this surfaces at a
// glance.

const TABLE = "SmbHistory";

interface Row {
  __rowid?: number;
  timestamp?: string;
  remote_address?: string;
  account?: string;
  result?: string;
  description?: string;
  event_id?: string;
  record_key?: string;
}

interface Peer {
  ip: string;
  attempts: number;
  fail: number;
  success: number;
  accounts: string[];
  first: string;
  last: string;
  events: Row[];
}

function bareAccount(name: string): string {
  if (!name) return "";
  const tail = name.replace(/\//g, "\\").split("\\").pop() ?? name;
  return tail.split("@")[0].trim();
}

interface Props {
  fileName: string;
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

export default function SmbHistoryView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE }: Props) {
  const [query, setQuery] = useState("");
  const [failOnly, setFailOnly] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);

  const { peers, totals } = useMemo(() => {
    const byIp = new Map<string, Peer>();
    let attempts = 0, fail = 0, success = 0;
    for (const raw of data.rows as Row[]) {
      const ts = raw.timestamp ?? "";
      if (ts && !inRange(ts, timeRange)) continue;
      const ip = raw.remote_address || "(주소 없음)";
      let p = byIp.get(ip);
      if (!p) {
        p = { ip, attempts: 0, fail: 0, success: 0, accounts: [], first: ts, last: ts, events: [] };
        byIp.set(ip, p);
      }
      p.attempts++;
      attempts++;
      if (raw.result === "실패") { p.fail++; fail++; }
      else if (raw.result === "성공") { p.success++; success++; }
      const acct = bareAccount(raw.account ?? "");
      if (acct && !p.accounts.includes(acct)) p.accounts.push(acct);
      if (ts) {
        if (!p.first || ts < p.first) p.first = ts;
        if (!p.last || ts > p.last) p.last = ts;
      }
      p.events.push(raw);
    }
    const peers = [...byIp.values()].sort((a, b) => b.attempts - a.attempts);
    return { peers, totals: { attempts, fail, success, ips: peers.length } };
  }, [data.rows, timeRange]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return peers.filter((p) => {
      if (failOnly && p.fail === 0) return false;
      if (q && !p.ip.toLowerCase().includes(q) && !p.accounts.some((a) => a.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [peers, query, failOnly]);

  function toggle(ip: string) {
    setExpanded((prev) => {
      const n = new Set(prev);
      if (n.has(ip)) n.delete(ip);
      else n.add(ip);
      return n;
    });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 3 }}>
          <span style={{ fontSize: 16, fontWeight: 700 }}>📁 SMB 접속 시도 (소스 IP별)</span>
          <span style={{ fontSize: 12, color: "var(--text-faint)" }}>인바운드 네트워크 인증 — 반복 실패는 브루트포스/패스워드 스프레이 신호입니다.</span>
        </div>
        {/* summary tiles */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, margin: "10px 0 4px" }}>
          <Stat label="소스 IP" value={totals.ips.toLocaleString()} />
          <Stat label="총 시도" value={totals.attempts.toLocaleString()} />
          <Stat label="실패" value={totals.fail.toLocaleString()} tone="danger" />
          <Stat label="성공" value={totals.success.toLocaleString()} tone={totals.success ? "danger" : "ok"} />
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}>
          <div style={{ position: "relative", flex: "0 1 260px", minWidth: 160 }}>
            <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)" }}>🔍</span>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="IP · 계정 검색"
              style={{ width: "100%", padding: "6px 10px 6px 28px", fontSize: 12.5, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }} />
          </div>
          <button onClick={() => setFailOnly((v) => !v)} style={{ ...chipBtn, borderColor: failOnly ? "var(--danger)" : "var(--border)", color: failOnly ? "var(--danger)" : "var(--text-dim)", background: failOnly ? "color-mix(in srgb, var(--danger) 14%, transparent)" : "var(--bg-elevated)" }}>
            {failOnly ? "☑" : "☐"} 실패만
          </button>
          <span style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--text-faint)" }}>{shown.length.toLocaleString()} / {peers.length.toLocaleString()} IP</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
        {shown.length === 0 && <div style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>표시할 SMB 접속 시도가 없습니다.</div>}
        {shown.map((p) => {
          const open = expanded.has(p.ip);
          const heavy = p.attempts >= 100; // a lot of attempts from one IP = likely automated
          const accent = p.success > 0 ? "var(--danger)" : p.fail > 0 ? "var(--warning)" : "var(--text-faint)";
          return (
            <div key={p.ip} style={{ flexShrink: 0, border: "1px solid var(--border)", borderLeft: `3px solid ${accent}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div onClick={() => toggle(p.ip)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", cursor: "pointer", flexWrap: "wrap" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                <span style={{ fontSize: 10, color: "var(--text-faint)", width: 10 }}>{open ? "▾" : "▸"}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700 }}>{p.ip}</span>
                {heavy && <span style={{ fontSize: 10, fontWeight: 700, color: "var(--danger)", background: "color-mix(in srgb, var(--danger) 15%, transparent)", borderRadius: 4, padding: "1px 6px" }}>대량 시도</span>}
                <span style={{ fontSize: 12.5, color: "var(--text-dim)" }}>{p.attempts.toLocaleString()}회 시도</span>
                <span style={{ display: "flex", gap: 6, fontSize: 11 }}>
                  {p.fail > 0 && <Pill color="var(--danger)">실패 {p.fail.toLocaleString()}</Pill>}
                  {p.success > 0 && <Pill color="var(--danger)">성공 {p.success.toLocaleString()}</Pill>}
                </span>
                <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-time)", fontFamily: "var(--mono)" }}>{p.first?.slice(0, 16)} ~ {p.last?.slice(11, 16) || p.last}</span>
                {p.accounts.length > 0 && (
                  <div style={{ flexBasis: "100%", fontSize: 11, color: "var(--text-faint)", marginLeft: 20 }}>
                    👤 시도 계정: {p.accounts.slice(0, 8).join(", ")}{p.accounts.length > 8 ? ` 외 ${p.accounts.length - 8}` : ""}
                  </div>
                )}
              </div>
              {open && (
                <div style={{ borderTop: "1px solid var(--border)", background: "color-mix(in srgb, var(--bg-elevated) 40%, transparent)", maxHeight: 320, overflow: "auto" }}>
                  {p.events.slice(0, 500).map((ev, i) => {
                    const rid = Number((ev as Record<string, unknown>).__rowid);
                    const bm = (bookmarkedRowids?.has(rid) ?? false) && Number.isFinite(rid);
                    const bmBg = bm ? "color-mix(in srgb, var(--warning) 14%, transparent)" : "transparent";
                    return (
                    <div key={i} onClick={() => setSelected(ev as Record<string, string>)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 12px 5px 30px", cursor: "pointer", fontSize: 12, background: bmBg, boxShadow: bm ? "inset 3px 0 0 var(--warning)" : undefined }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")} onMouseLeave={(e) => (e.currentTarget.style.background = bmBg)}>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-time)", width: 168, flexShrink: 0 }}>{ev.timestamp}</span>
                      <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: ev.result === "실패" ? "var(--danger)" : ev.result === "성공" ? "var(--success)" : "var(--text-faint)" }} />
                      <span style={{ color: "var(--text-dim)", flex: 1 }}>{ev.description}</span>
                      {ev.account && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>👤 {bareAccount(ev.account)}</span>}
                      {onToggleBookmark && Number.isFinite(rid) && (
                        <span onClick={(e) => { e.stopPropagation(); onToggleBookmark(rid); }} title={bm ? "북마크 해제" : "북마크에 추가"} style={{ cursor: "pointer", color: bm ? "var(--warning)" : "var(--text-faint)" }}>{bm ? "★" : "☆"}</span>
                      )}
                    </div>
                    );
                  })}
                  {p.events.length > 500 && <div style={{ padding: "6px 30px", fontSize: 11, color: "var(--text-faint)" }}>… 외 {(p.events.length - 500).toLocaleString()}건 (원본 테이블에서 전체 확인)</div>}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {selected && spec && (
        <RowDetailPanel
          row={selected}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName={TABLE}
          onClose={() => setSelected(null)}
          onNavigate={(tf, tc, v) => { setSelected(null); onNavigate(tf, tc, v); }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined}
        />
      )}
    </div>
  );
}

const chipBtn: React.CSSProperties = { padding: "6px 11px", fontSize: 12, fontWeight: 600, borderRadius: "var(--radius-md)", cursor: "pointer", border: "1px solid var(--border)" };

function Stat({ label, value, tone }: { label: string; value: string; tone?: "danger" | "ok" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "ok" ? "var(--success)" : "var(--text)";
  return (
    <div style={{ minWidth: 92, padding: "6px 12px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)" }}>
      <div style={{ fontSize: 10.5, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 16, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}
function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ color, fontWeight: 700, padding: "1px 7px", borderRadius: 999, background: `color-mix(in srgb, ${color} 15%, transparent)` }}>{children}</span>;
}
