"use client";

import { useMemo, useState } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

const TABLE_NAME = "RemoteDesktopHistory";
// A gap longer than this between consecutive events of the same peer starts a
// new session. RDP sessions cluster their connect/logon/reconnect/disconnect
// events within a short window; 10 minutes keeps a burst together without
// merging unrelated activity hours apart.
const SESSION_GAP_MS = 10 * 60 * 1000;

const DIRECTION_LABEL: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드" };
const DIRECTION_COLOR: Record<string, string> = { inbound: "var(--warning)", outbound: "var(--accent)" };
const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)", 정보: "var(--text-faint)" };

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
      account: row.account ?? "",
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);

  const spec = getArtifactView(TABLE_NAME);
  const allSessions = useMemo(() => clusterSessions(data, timeRange), [data, timeRange]);
  const sessions = useMemo(
    () => (dirFilter ? allSessions.filter((s) => s.direction === dirFilter) : allSessions),
    [allSessions, dirFilter]
  );

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

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "9px 14px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-panel)",
          flexShrink: 0,
          flexWrap: "wrap",
          rowGap: 6,
        }}
      >
        <strong style={{ fontSize: 13 }}>🖥️ 원격 데스크톱 세션 흐름</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{sessions.length.toLocaleString()}개 세션</span>
        <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
          {dirTabs.map((t) => {
            const active = dirFilter === t.value;
            return (
              <button
                key={t.label}
                onClick={() => setDirFilter(t.value)}
                style={{
                  fontSize: 12,
                  padding: "4px 12px",
                  background: active ? "var(--accent-subtle)" : "transparent",
                  color: active ? "var(--accent)" : "var(--text-dim)",
                  border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                  borderRadius: "var(--radius-lg)",
                  cursor: "pointer",
                  fontWeight: active ? 700 : 500,
                }}
              >
                {t.label}
              </button>
            );
          })}
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
        {sessions.length === 0 && (
          <div style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>세션이 없습니다.</div>
        )}
        {sessions.map((s) => {
          const open = expanded.has(s.key);
          return (
            <div key={s.key} style={{ flexShrink: 0, border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden" }}>
              <div
                onClick={() => toggle(s.key)}
                style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", cursor: "pointer" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <span style={{ fontSize: 10, color: "var(--text-faint)", width: 10 }}>{open ? "▾" : "▸"}</span>
                <span
                  style={{
                    fontSize: 10.5,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: "var(--radius-lg)",
                    color: DIRECTION_COLOR[s.direction] ?? "var(--text-dim)",
                    border: `1px solid ${DIRECTION_COLOR[s.direction] ?? "var(--border)"}`,
                    whiteSpace: "nowrap",
                  }}
                >
                  {DIRECTION_LABEL[s.direction] ?? s.direction}
                </span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, minWidth: 120 }}>
                  {s.remote_address || "(주소 없음)"}
                </span>
                {s.account && <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{s.account}</span>}
                <span style={{ fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>
                  {s.start} ~ {s.end.slice(11) || s.end}
                </span>
                <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", fontSize: 11 }}>
                  {s.success > 0 && <span style={{ color: "var(--success)" }}>성공 {s.success}</span>}
                  {s.fail > 0 && <span style={{ color: "var(--danger)" }}>실패 {s.fail}</span>}
                  <span style={{ color: "var(--text-faint)" }}>{s.events.length}건</span>
                </span>
              </div>
              {open && (
                <div style={{ borderTop: "1px solid var(--border)", padding: "4px 0" }}>
                  {s.events.map((ev, i) => (
                    <div
                      key={i}
                      onClick={() => setSelected(ev.row)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "5px 12px 5px 30px",
                        cursor: "pointer",
                        fontSize: 12,
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-dim)", width: 168, flexShrink: 0 }}>
                        {ev.timestamp}
                      </span>
                      <span style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[ev.result] ?? "var(--text-faint)" }} />
                      <span style={{ flex: 1 }}>{ev.description}</span>
                      {ev.account && ev.account !== s.account && (
                        <span style={{ color: "var(--text-faint)", fontSize: 11 }}>{ev.account}</span>
                      )}
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
                  ))}
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
          fileBaseName={TABLE_NAME}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => {
            setSelected(null);
            onNavigate(targetFile, targetColumn, value);
          }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined}
          onToggleBookmark={
            onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined
          }
        />
      )}
    </div>
  );
}
