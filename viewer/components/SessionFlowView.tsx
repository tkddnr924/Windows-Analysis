"use client";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { formatEvidenceTimestamp, inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

// A gap longer than this between consecutive events of the same peer starts a
// new session. RDP sessions cluster their connect/logon/reconnect/disconnect
// events within a short window; 10 minutes keeps a burst together without
// merging unrelated activity hours apart.
const SESSION_GAP_MS = 10 * 60 * 1000;

const DIRECTION_LABEL: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드" };
const DIRECTION_COLOR: Record<string, string> = { inbound: "#7387a5", outbound: "var(--accent)" };
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
  /** IP -> host for the whole case, so a remote IP that is a registered host
   * shows the host name. Empty until the case network map is loaded. */
  hostIpMap?: Record<string, { id: string; name: string }>;
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
  hostIpMap = {},
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
      if (q && !s.remote_address.toLowerCase().includes(q) && !s.account.toLowerCase().includes(q) && !(hostIpMap[s.remote_address]?.name.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [allSessions, dirFilter, resultFilter, query, hostIpMap]);

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
    { label: "인바운드", value: "inbound" },
    { label: "아웃바운드", value: "outbound" },
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
          <strong style={{ fontSize: 15, color: "var(--text)" }}>{isSmb ? "SMB 연결 이력" : "원격 접근 이력 (RDP)"}</strong>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {/* IP / account search */}
          <div style={{ position: "relative", flex: "1 1 220px", maxWidth: 340 }}>
            <SearchOutlinedIcon aria-hidden="true" sx={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", fontSize: 17, color: "var(--text-faint)", pointerEvents: "none" }} />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="IP 또는 계정 검색"
              aria-label="IP 또는 계정 검색"
              onFocus={(e) => { e.currentTarget.style.outline = "2px solid var(--accent)"; e.currentTarget.style.outlineOffset = "2px"; }}
              onBlur={(e) => { e.currentTarget.style.outline = "none"; }}
              style={{
                width: "100%",
                padding: "6px 32px 6px 30px",
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
              <button aria-label="검색어 지우기" onClick={() => setQuery("")} style={{ position: "absolute", right: 5, top: "50%", transform: "translateY(-50%)", display: "inline-flex", padding: 2, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 16 }} /></button>
            )}
          </div>

          <FilterChips options={dirTabs.map((t) => ({ label: t.label, value: t.value }))} value={dirFilter} onChange={(v) => setDirFilter(v as string | undefined)} />
          <FilterChips options={resultTabs} value={resultFilter} onChange={(v) => setResultFilter((v as ResultFilter) ?? "all")} />
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-panel)", overflow: "hidden" }}>
        {sessions.length > 0 && <div style={{ display: "grid", gridTemplateColumns: "28px 78px minmax(150px,1.5fr) minmax(90px,.8fr) 236px 96px 54px", gap: 8, padding: "7px 10px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span /><span>방향</span><span>종단점 / 호스트</span><span>계정</span><span>시작 / 종료</span><span>결과</span><span>이벤트</span></div>}
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
                borderTop: "1px solid var(--border-subtle)",
                borderLeft: `3px solid ${dirColor}`,
              }}
            >
              <button
                type="button"
                onClick={() => toggle(s.key)}
                aria-expanded={open}
                style={{ width: "100%", display: "grid", gridTemplateColumns: "28px 78px minmax(150px,1.5fr) minmax(90px,.8fr) 236px 96px 54px", alignItems: "center", gap: 8, padding: "9px 10px", cursor: "pointer", textAlign: "left", color: "var(--text)", border: "none", background: "transparent", borderLeft: "none", outlineOffset: -2 }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                onFocus={(e) => { e.currentTarget.style.outline = "2px solid var(--accent)"; }}
                onBlur={(e) => { e.currentTarget.style.outline = "none"; }}
              >
                {open ? <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} />}
                <span
                  style={{
                    fontSize: 10.5,
                    fontWeight: 700,
                    padding: "2px 9px",
                    borderRadius: "var(--radius-sm)",
                    color: dirColor,
                    background: `color-mix(in srgb, ${dirColor} 14%, transparent)`,
                    border: `1px solid ${dirColor}`,
                    whiteSpace: "nowrap",
                  }}
                >
                  {DIRECTION_LABEL[s.direction] ?? s.direction}
                </span>
                <span style={{ display: "inline-flex", alignItems: "baseline", gap: 6, minWidth: 120 }}>
                  {hostIpMap[s.remote_address] ? (
                    <>
                      <span style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text)" }}>{hostIpMap[s.remote_address].name}</span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>{s.remote_address}</span>
                    </>
                  ) : (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 600 }}>{s.remote_address || "(주소 없음)"}</span>
                  )}
                </span>
                {s.account && (
                  <span style={{ fontSize: 11.5, fontWeight: 600, color: "var(--text)" }}>{s.account}</span>
                )}
                <span style={{ fontSize: 11.5, color: "var(--text-time)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>
                  {formatEvidenceTimestamp(s.start)} <span style={{ opacity: 0.6 }}>~ {formatEvidenceTimestamp(s.end)}</span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", fontSize: 10.5 }}>
                  {s.success > 0 && <Pill color="var(--success)">성공 {s.success}</Pill>}
                  {s.fail > 0 && <Pill color="var(--danger)">실패 {s.fail}</Pill>}
                </span>
                <span style={{ color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11 }}>{s.events.length}건</span>
              </button>
              {open && (
                <div style={{ borderTop: "1px solid var(--border-subtle)", background: "color-mix(in srgb, var(--bg-elevated) 40%, transparent)" }}>
                  {s.events.map((ev, i) => {
                    const bm = (bookmarkedRowids?.has(ev.rowid) ?? false) && Number.isFinite(ev.rowid);
                    const bmBg = bm ? "color-mix(in srgb, var(--warning) 14%, transparent)" : "transparent";
                    return (
                    <div
                      key={i}
                      role="button"
                      tabIndex={0}
                      onClick={() => setSelected(ev.row)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelected(ev.row);
                        }
                      }}
                      style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 12px 5px 30px", cursor: "pointer", fontSize: 12, background: bmBg, boxShadow: bm ? "inset 3px 0 0 var(--warning)" : undefined }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = bmBg)}
                      onFocus={(e) => { e.currentTarget.style.outline = "2px solid var(--accent)"; e.currentTarget.style.outlineOffset = "-2px"; }}
                      onBlur={(e) => { e.currentTarget.style.outline = "none"; }}
                    >
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-time)", width: 236, flexShrink: 0 }}>{formatEvidenceTimestamp(ev.timestamp)}</span>
                      <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[ev.result] ?? "var(--text-faint)" }} />
                      <span style={{ flex: 1 }}>{ev.description}</span>
                      {ev.account && ev.account !== s.account && <span style={{ color: "var(--text-dim)", fontSize: 11 }}>{ev.account}</span>}
                      {onToggleBookmark && Number.isFinite(ev.rowid) && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleBookmark(ev.rowid);
                          }}
                          title={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크에 추가"}
                          aria-label={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크"}
                          style={{ display: "inline-flex", padding: 1, border: "none", background: "transparent", cursor: "pointer", color: bookmarkedRowids?.has(ev.rowid) ? "var(--warning)" : "var(--text-faint)" }}
                        >
                          {bookmarkedRowids?.has(ev.rowid) ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}
                        </button>
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
