"use client";

import { useMemo, useState } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

// A gap longer than this between consecutive events of the same peer starts a
// new session. RDP sessions cluster their connect/logon/reconnect/disconnect
// events within a short window; 10 minutes keeps a burst together without
// merging unrelated activity hours apart.
const SESSION_GAP_MS = 10 * 60 * 1000;

const DIRECTION_LABEL: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드" };
const DIRECTION_COLOR: Record<string, string> = { inbound: "var(--warning)", outbound: "var(--accent)" };
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)", 정보: "var(--text-faint)" };

// Providers report the account differently — bare "Administrator" from
// TerminalServices, "HOST\Administrator" from Security-Auditing. Strip any
// DOMAIN\/HOST\ prefix (and UPN @suffix) so the same user reads consistently.
function bareAccount(name: string): string {
  if (!name) return "";
  const tail = name.replace(/\//g, "\\").split("\\").pop() ?? name;
  return tail.split("@")[0].trim();
}

interface FlowEvent {
  row: Record<string, string>;
  rowid: number;
  timestamp: string;
  direction: string;
  remote_address: string;
  account: string;
  description: string;
  result: string;
}

interface Session {
  key: string;
  direction: string;
  remote_address: string;
  account: string;
  start: string;
  end: string;
  events: FlowEvent[];
  success: number;
  fail: number;
}

// "YYYY-MM-DD HH:MM:SS.fff" (KST) — parsed as local; only relative deltas are
// used for gap detection, so the fixed offset cancels out.
function tsMs(ts: string): number {
  return ts ? new Date(ts.replace(" ", "T")).getTime() : NaN;
}

function clusterSessions(data: CsvData, timeRange: TimeRange): Session[] {
  const events: FlowEvent[] = data.rows
    .map((row) => ({
      row,
      rowid: Number((row as unknown as Record<string, unknown>).__rowid),
      timestamp: row.timestamp ?? "",
      direction: row.direction ?? "",
      remote_address: row.remote_address ?? "",
      account: bareAccount(row.account ?? ""),
      description: row.description ?? "",
      result: row.result ?? "",
    }))
    .filter((e) => e.timestamp && inRange(e.timestamp, timeRange))
    .sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));

  const sessions: Session[] = [];
  let cur: Session | null = null;
  let lastMs = NaN;

  for (const e of events) {
    const t = tsMs(e.timestamp);
    const addrConflict = Boolean(e.remote_address && cur?.remote_address && e.remote_address !== cur.remote_address);
    const isNew =
      !cur || cur.direction !== e.direction || addrConflict || (Number.isFinite(t) && Number.isFinite(lastMs) && t - lastMs > SESSION_GAP_MS);

    if (isNew || !cur) {
      cur = {
        key: `${sessions.length}`,
        direction: e.direction,
        remote_address: e.remote_address,
        account: e.account,
        start: e.timestamp,
        end: e.timestamp,
        events: [],
        success: 0,
        fail: 0,
      };
      sessions.push(cur);
    }

    if (!cur.remote_address && e.remote_address) cur.remote_address = e.remote_address;
    if (!cur.account && e.account) cur.account = e.account;
    cur.events.push(e);
    cur.end = e.timestamp;
    if (e.result === "성공") cur.success += 1;
    if (e.result === "실패") cur.fail += 1;
    lastMs = t;
  }

  return sessions;
}

interface SessionFlowViewProps {
  fileName: string;
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

type ResultFilter = "all" | "success" | "fail";

export default function SessionFlowView({
  fileName,
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
}: SessionFlowViewProps) {
  const [dirFilter, setDirFilter] = useState<string | undefined>(undefined);
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);

  const isSmb = fileName === "SmbHistory";
  const spec = getArtifactView(fileName);
  const allSessions = useMemo(() => clusterSessions(data, timeRange), [data, timeRange]);

  const sessions = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allSessions.filter((s) => {
      if (dirFilter && s.direction !== dirFilter) return false;
      if (resultFilter === "success" && s.success === 0) return false;
      if (resultFilter === "fail" && s.fail === 0) return false;
      if (q && !s.remote_address.toLowerCase().includes(q) && !s.account.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [allSessions, dirFilter, resultFilter, query]);

  const totals = useMemo(() => {
    let inbound = 0, outbound = 0, success = 0, fail = 0;
    for (const s of allSessions) {
      if (s.direction === "inbound") inbound++;
      else if (s.direction === "outbound") outbound++;
      success += s.success;
      fail += s.fail;
    }
    return { inbound, outbound, success, fail };
  }, [allSessions]);

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const dirTabs = [
    { label: "전체", value: undefined as string | undefined },
    { label: `인바운드 ${totals.inbound}`, value: "inbound" },
    { label: `아웃바운드 ${totals.outbound}`, value: "outbound" },
  ];
  const resultTabs: { label: string; value: ResultFilter; color?: string }[] = [
    { label: "모든 결과", value: "all" },
    { label: "성공 포함", value: "success", color: "var(--success)" },
    { label: "실패 포함", value: "fail", color: "var(--danger)" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      {/* toolbar */}
      <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0, display: "flex", flexDirection: "column", gap: 9 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <strong style={{ fontSize: 13.5 }}>{isSmb ? "📁 SMB 연결 (네트워크 인증)" : "🖥️ 원격 데스크톱 세션 흐름"}</strong>
          <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>
            {sessions.length.toLocaleString()} / {allSessions.length.toLocaleString()}개 세션
          </span>
          <span style={{ marginLeft: "auto", display: "flex", gap: 10, fontSize: 11, color: "var(--text-faint)" }}>
            <span style={{ color: "var(--success)" }}>● 성공 {totals.success.toLocaleString()}</span>
            <span style={{ color: "var(--danger)" }}>● 실패 {totals.fail.toLocaleString()}</span>
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {/* IP / account search */}
          <div style={{ position: "relative", flex: "1 1 220px", maxWidth: 340 }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)", pointerEvents: "none" }}>🔍</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="IP 또는 계정 검색"
              style={{
                width: "100%",
                padding: "6px 26px 6px 30px",
                fontSize: 12.5,
                fontFamily: "var(--mono)",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                color: "var(--text)",
                outline: "none",
              }}
            />
            {query && (
              <span onClick={() => setQuery("")} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", cursor: "pointer", color: "var(--text-faint)", fontSize: 13 }}>
                ✕
              </span>
            )}
          </div>

          <FilterChips options={dirTabs.map((t) => ({ label: t.label, value: t.value }))} value={dirFilter} onChange={(v) => setDirFilter(v as string | undefined)} />
          <FilterChips options={resultTabs} value={resultFilter} onChange={(v) => setResultFilter((v as ResultFilter) ?? "all")} />
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
        {sessions.length === 0 && (
          <div style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>
            {allSessions.length === 0 ? "세션이 없습니다." : "조건에 맞는 세션이 없습니다."}
          </div>
        )}
        {sessions.map((s) => {
          const open = expanded.has(s.key);
          const dirColor = DIRECTION_COLOR[s.direction] ?? "var(--border)";
          return (
            <div
              key={s.key}
              style={{
                flexShrink: 0,
                border: "1px solid var(--border)",
                borderLeft: `3px solid ${dirColor}`,
                borderRadius: "var(--radius-md)",
                background: "var(--bg-panel)",
                overflow: "hidden",
                transition: "border-color .12s",
              }}
            >
              <div
                onClick={() => toggle(s.key)}
                style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", cursor: "pointer" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <span style={{ fontSize: 10, color: "var(--text-faint)", width: 10 }}>{open ? "▾" : "▸"}</span>
                <span
                  style={{
                    fontSize: 10.5,
                    fontWeight: 700,
                    padding: "2px 9px",
                    borderRadius: 999,
                    color: dirColor,
                    background: `color-mix(in srgb, ${dirColor} 14%, transparent)`,
                    border: `1px solid ${dirColor}`,
                    whiteSpace: "nowrap",
                  }}
                >
                  {DIRECTION_LABEL[s.direction] ?? s.direction}
                </span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 600, minWidth: 120 }}>{s.remote_address || "(주소 없음)"}</span>
                {s.account && (
                  <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--text)", padding: "1px 8px", borderRadius: 999, background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)" }}>
                    👤 {s.account}
                  </span>
                )}
                <span style={{ fontSize: 11.5, color: "var(--text-time)", fontFamily: "var(--mono)" }}>
                  {s.start.slice(0, 19)} <span style={{ opacity: 0.6 }}>~ {s.end.slice(11, 19) || s.end}</span>
                </span>
                <span style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center", fontSize: 10.5 }}>
                  {s.success > 0 && <Pill color="var(--success)">성공 {s.success}</Pill>}
                  {s.fail > 0 && <Pill color="var(--danger)">실패 {s.fail}</Pill>}
                  <span style={{ color: "var(--text-faint)" }}>{s.events.length}건</span>
                </span>
              </div>
              {open && (
                <div style={{ borderTop: "1px solid var(--border)", padding: "4px 0", background: "color-mix(in srgb, var(--bg-elevated) 40%, transparent)" }}>
                  {s.events.map((ev, i) => {
                    const bm = (bookmarkedRowids?.has(ev.rowid) ?? false) && Number.isFinite(ev.rowid);
                    const bmBg = bm ? "color-mix(in srgb, var(--warning) 14%, transparent)" : "transparent";
                    return (
                    <div
                      key={i}
                      onClick={() => setSelected(ev.row)}
                      style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 12px 5px 30px", cursor: "pointer", fontSize: 12, background: bmBg, boxShadow: bm ? "inset 3px 0 0 var(--warning)" : undefined }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = bmBg)}
                    >
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-time)", width: 168, flexShrink: 0 }}>{ev.timestamp}</span>
                      <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[ev.result] ?? "var(--text-faint)" }} />
                      <span style={{ flex: 1 }}>{ev.description}</span>
                      {ev.account && ev.account !== s.account && <span style={{ color: "var(--text-dim)", fontSize: 11 }}>👤 {ev.account}</span>}
                      {onToggleBookmark && Number.isFinite(ev.rowid) && (
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleBookmark(ev.rowid);
                          }}
                          title={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크에 추가"}
                          style={{ cursor: "pointer", color: bookmarkedRowids?.has(ev.rowid) ? "var(--warning)" : "var(--text-faint)" }}
                        >
                          {bookmarkedRowids?.has(ev.rowid) ? "★" : "☆"}
                        </span>
                      )}
                    </div>
                    );
                  })}
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
          fileBaseName={fileName}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => {
            setSelected(null);
            onNavigate(targetFile, targetColumn, value);
          }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined}
        />
      )}
    </div>
  );
}

function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span style={{ color, fontWeight: 700, padding: "1px 7px", borderRadius: 999, background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
      {children}
    </span>
  );
}

function FilterChips<T>({ options, value, onChange }: { options: { label: string; value: T; color?: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div style={{ display: "inline-flex", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: 2, gap: 2 }}>
      {options.map((o) => {
        const active = value === o.value;
        const accent = o.color ?? "var(--accent)";
        return (
          <button
            key={String(o.value)}
            onClick={() => onChange(o.value)}
            style={{
              fontSize: 11.5,
              padding: "4px 10px",
              background: active ? `color-mix(in srgb, ${accent} 18%, transparent)` : "transparent",
              color: active ? accent : "var(--text-dim)",
              border: "none",
              borderRadius: "var(--radius-sm)",
              cursor: "pointer",
              fontWeight: active ? 700 : 500,
              whiteSpace: "nowrap",
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
