"use client";

import { useMemo, useState } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

const TABLE_NAME = "PowerShellHistory";
// Commands run inside one powershell.exe instance cluster together; a gap
// longer than this (same account + PID) starts a new session. PIDs are reused
// over time, so the gap guard keeps two unrelated sessions that happen to
// share a recycled PID from merging.
const SESSION_GAP_MS = 30 * 60 * 1000;

// One dot color per event kind, so a session's command list shows at a glance
// which entries carry actual code (script blocks) vs. pipeline/classic records.
const KIND_COLOR: Record<string, string> = {
  "스크립트 블록": "var(--accent)",
  파이프라인: "var(--text-dim)",
  "명령 실행": "var(--warning)",
};

interface PsEvent {
  row: Record<string, string>;
  rowid: number;
  timestamp: string;
  account: string;
  process: string;
  processId: string;
  command: string;
  scriptBlock: string;
  kind: string;
}

interface PsSession {
  key: string;
  account: string;
  process: string;
  processId: string;
  start: string;
  end: string;
  events: PsEvent[];
  codeBlocks: number;
}

// "YYYY-MM-DD HH:MM:SS.fff" (KST) — parsed as local; only relative deltas feed
// gap detection, so the fixed offset cancels out.
function tsMs(ts: string): number {
  return ts ? new Date(ts.replace(" ", "T")).getTime() : NaN;
}

function clusterSessions(data: CsvData, timeRange: TimeRange, kindFilter?: string): PsSession[] {
  const events: PsEvent[] = data.rows
    .map((row) => ({
      row,
      rowid: Number((row as unknown as Record<string, unknown>).__rowid),
      timestamp: row.timestamp ?? "",
      account: row.account ?? "",
      process: row.process ?? "",
      processId: row.process_id ?? "",
      command: row.command ?? "",
      scriptBlock: row.script_block ?? "",
      kind: row.kind ?? "",
    }))
    .filter((e) => e.timestamp && inRange(e.timestamp, timeRange) && (!kindFilter || e.kind === kindFilter))
    .sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));

  // Group by the running identity (account + process instance), then split
  // each group into sessions on a time gap. Grouping first (rather than a
  // single sequential sweep) keeps interleaved runspaces from tangling.
  const byIdentity = new Map<string, PsEvent[]>();
  for (const e of events) {
    const key = `${e.account}||${e.processId || e.process}`;
    if (!byIdentity.has(key)) byIdentity.set(key, []);
    byIdentity.get(key)!.push(e);
  }

  const sessions: PsSession[] = [];
  for (const [, group] of byIdentity) {
    let cur: PsSession | null = null;
    let lastMs = NaN;
    for (const e of group) {
      const t = tsMs(e.timestamp);
      const gap = Number.isFinite(t) && Number.isFinite(lastMs) && t - lastMs > SESSION_GAP_MS;
      if (!cur || gap) {
        cur = {
          key: `${sessions.length}`,
          account: e.account,
          process: e.process,
          processId: e.processId,
          start: e.timestamp,
          end: e.timestamp,
          events: [],
          codeBlocks: 0,
        };
        sessions.push(cur);
      }
      if (!cur.process && e.process) cur.process = e.process;
      cur.events.push(e);
      cur.end = e.timestamp;
      if (e.scriptBlock) cur.codeBlocks += 1;
      lastMs = t;
    }
  }

  return sessions.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
}

interface PowerShellFlowViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

export default function PowerShellFlowView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
}: PowerShellFlowViewProps) {
  const [kindFilter, setKindFilter] = useState<string | undefined>(undefined);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);

  const spec = getArtifactView(TABLE_NAME);
  const sessions = useMemo(() => clusterSessions(data, timeRange, kindFilter), [data, timeRange, kindFilter]);
  const totalCommands = useMemo(() => sessions.reduce((n, s) => n + s.events.length, 0), [sessions]);

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const kindTabs = [
    { label: "전체", value: undefined as string | undefined },
    { label: "스크립트 블록", value: "스크립트 블록" },
    { label: "파이프라인", value: "파이프라인" },
    { label: "명령 실행", value: "명령 실행" },
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
        <strong style={{ fontSize: 13 }}>💻 PowerShell 실행 기록</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>
          {sessions.length.toLocaleString()}개 세션 · 명령 {totalCommands.toLocaleString()}건
        </span>
        <div style={{ display: "flex", gap: 6, marginLeft: "auto", flexWrap: "wrap" }}>
          {kindTabs.map((t) => {
            const active = kindFilter === t.value;
            return (
              <button
                key={t.label}
                onClick={() => setKindFilter(t.value)}
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
          <div style={{ color: "var(--text-faint)", textAlign: "center", padding: 24 }}>PowerShell 실행 기록이 없습니다.</div>
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
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, minWidth: 110 }}>
                  {s.process || "powershell"}
                </span>
                {s.processId && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>PID {s.processId}</span>}
                {s.account && <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{s.account}</span>}
                <span style={{ fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>
                  {s.start} ~ {s.end.slice(11) || s.end}
                </span>
                <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center", fontSize: 11 }}>
                  {s.codeBlocks > 0 && <span style={{ color: "var(--accent)" }}>{"</>"} {s.codeBlocks}</span>}
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
                      <span
                        title={ev.kind}
                        style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: KIND_COLOR[ev.kind] ?? "var(--text-faint)" }}
                      />
                      <span
                        style={{
                          flex: 1,
                          minWidth: 0,
                          fontFamily: "var(--mono)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          color: ev.command ? undefined : "var(--text-faint)",
                        }}
                      >
                        {ev.command || (ev.scriptBlock ? "코드 블록 (상세에서 확인)" : "-")}
                      </span>
                      {ev.scriptBlock && (
                        <span title="코드 블록 있음" style={{ flexShrink: 0, fontSize: 10.5, color: "var(--accent)", fontFamily: "var(--mono)" }}>
                          {"</>"}
                        </span>
                      )}
                      {onToggleBookmark && Number.isFinite(ev.rowid) && (
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleBookmark(ev.rowid);
                          }}
                          title={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크에 추가"}
                          style={{ flexShrink: 0, cursor: "pointer", color: bookmarkedRowids?.has(ev.rowid) ? "var(--warning)" : "var(--text-faint)" }}
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
