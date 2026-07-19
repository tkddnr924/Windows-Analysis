"use client";

import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TimelineEntry } from "@/lib/types";
import { CATEGORY_ICONS } from "./Sidebar";
import RowDetailPanel from "./RowDetailPanel";

const ROW_HEIGHT = 52;

interface MasterTimelineProps {
  entries: TimelineEntry[] | null;
  loading: boolean;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
}

// <input type="datetime-local"> yields "YYYY-MM-DDThh:mm" (no seconds) — pad
// it out to the parser's "YYYY-MM-DD hh:mm:ss.fff" format so a plain string
// compare against entry.timestamp is a correct chronological comparison.
function toRangeBound(datetimeLocal: string, edge: "start" | "end"): string {
  if (!datetimeLocal) return "";
  const [date, time = "00:00"] = datetimeLocal.split("T");
  return edge === "start" ? `${date} ${time}:00.000` : `${date} ${time}:59.999`;
}

export default function MasterTimeline({ entries, loading, onNavigate }: MasterTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [rangeStart, setRangeStart] = useState("");
  const [rangeEnd, setRangeEnd] = useState("");
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null);
  const allRows = entries ?? [];

  const startBound = toRangeBound(rangeStart, "start");
  const endBound = toRangeBound(rangeEnd, "end");
  const rangeActive = Boolean(startBound || endBound);

  const rows = useMemo(() => {
    if (!rangeActive) return allRows;
    return allRows.filter((e) => {
      if (!e.timestamp) return false;
      if (startBound && e.timestamp < startBound) return false;
      if (endBound && e.timestamp > endBound) return false;
      return true;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allRows, startBound, endBound]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 15,
  });

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)", gap: 8 }}>
        <span>모든 아티팩트를 시간순으로 모으는 중...</span>
      </div>
    );
  }

  const virtualRows = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length > 0 ? virtualRows[0].start : 0;
  const paddingBottom = virtualRows.length > 0 ? totalHeight - virtualRows[virtualRows.length - 1].end : 0;

  const inputStyle: React.CSSProperties = {
    padding: "5px 8px",
    background: "var(--bg-input)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-sm)",
    color: "var(--text)",
    fontSize: 12,
    fontFamily: "var(--mono)",
    colorScheme: "dark",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minWidth: 0 }}>
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
        <strong style={{ fontSize: 13 }}>🕐 통합 타임라인</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>
          {rangeActive
            ? `${rows.length.toLocaleString()} / ${allRows.length.toLocaleString()}건`
            : `${allRows.length.toLocaleString()}건 · 모든 아티팩트를 시간순으로 병합`}
        </span>

        <div style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto" }}>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>기간</span>
          <input
            type="datetime-local"
            value={rangeStart}
            onChange={(e) => setRangeStart(e.target.value)}
            style={inputStyle}
          />
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>~</span>
          <input
            type="datetime-local"
            value={rangeEnd}
            onChange={(e) => setRangeEnd(e.target.value)}
            style={inputStyle}
          />
          {rangeActive && (
            <button
              onClick={() => {
                setRangeStart("");
                setRangeEnd("");
              }}
              style={{
                fontSize: 11,
                padding: "3px 9px",
                background: "var(--accent-subtle)",
                color: "var(--accent)",
                border: "1px solid var(--accent)",
                borderRadius: "var(--radius-lg)",
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              기간 초기화 ×
            </button>
          )}
        </div>
      </div>

      {rows.length === 0 ? (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-faint)", gap: 8 }}>
          <span style={{ fontSize: 32 }}>🕐</span>
          <span>{rangeActive ? "선택한 기간에 해당하는 기록이 없습니다." : "표시할 시간 기록이 없습니다."}</span>
        </div>
      ) : (
      <div ref={scrollRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: paddingTop }} />
        {virtualRows.map((virtualRow) => {
          const entry = rows[virtualRow.index];
          const dangerTag = entry.tags.find((t) => t.severity === "danger");
          const warningTag = entry.tags.find((t) => t.severity === "warning");
          return (
            <div
              key={virtualRow.key}
              onClick={() => setSelectedEntry(entry)}
              style={{
                height: ROW_HEIGHT,
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "0 14px",
                borderBottom: "1px solid var(--border-subtle)",
                cursor: "pointer",
                background: virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = virtualRow.index % 2 === 0 ? "transparent" : "rgba(255,255,255,0.02)")}
            >
              <span
                style={{
                  flexShrink: 0,
                  width: 168,
                  fontFamily: "var(--mono)",
                  fontSize: 12,
                  color: entry.timestamp ? "var(--text-dim)" : "var(--text-faint)",
                }}
              >
                {entry.timestamp || "(시간 정보 없음)"}
              </span>
              <span style={{ flexShrink: 0, fontSize: 14 }} title={entry.category}>
                {CATEGORY_ICONS[entry.category] ?? "📄"}
              </span>
              <span
                style={{
                  flexShrink: 0,
                  fontSize: 10.5,
                  fontWeight: 600,
                  padding: "2px 7px",
                  borderRadius: "var(--radius-lg)",
                  background: "var(--bg-elevated)",
                  color: "var(--text-faint)",
                  whiteSpace: "nowrap",
                }}
              >
                {entry.table}
              </span>
              <span style={{ flex: 1, minWidth: 0, overflow: "hidden" }}>
                <div style={{ fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {entry.summary}
                </div>
                {entry.subtitle && (
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-faint)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {entry.subtitle}
                  </div>
                )}
              </span>
              {(dangerTag || warningTag) && (
                <span
                  style={{ flexShrink: 0, color: dangerTag ? "var(--danger)" : "var(--warning)" }}
                  title={entry.tags.map((t) => t.label).join(", ")}
                >
                  {dangerTag ? "⛔" : "⚠"}
                </span>
              )}
            </div>
          );
        })}
        <div style={{ height: paddingBottom }} />
      </div>
      )}

      {selectedEntry && (
        <RowDetailPanel
          row={selectedEntry.row}
          columns={selectedEntry.columns}
          focusedColumn={null}
          fileBaseName={selectedEntry.table}
          onClose={() => setSelectedEntry(null)}
          onNavigate={(targetFile, targetColumn, value) => {
            setSelectedEntry(null);
            onNavigate(targetFile, targetColumn, value);
          }}
        />
      )}
    </div>
  );
}
