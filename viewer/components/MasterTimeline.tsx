"use client";

import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FetchLinkedRows, TimelineEntry } from "@/lib/types";
import { inRange, rangeActive as globalRangeActive, toBound, type TimeRange } from "@/lib/timeRange";
import { CATEGORY_ICONS } from "./Sidebar";
import RowDetailPanel from "./RowDetailPanel";
import DateTimeInput from "./DateTimeInput";

const ROW_HEIGHT = 52;

interface MasterTimelineProps {
  entries: TimelineEntry[] | null;
  loading: boolean;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
  /** Keys of bookmarked rows, formatted `${fullPath}#${rowid}`. */
  bookmarkedKeys: Set<string>;
  onToggleBookmark: (entry: TimelineEntry) => void;
  /** Global incident-window filter from the sidebar. */
  globalTimeRange: TimeRange;
}

export default function MasterTimeline({ entries, loading, onNavigate, onFetchLinkedRows, bookmarkedKeys, onToggleBookmark, globalTimeRange }: MasterTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [rangeStart, setRangeStart] = useState("");
  const [rangeEnd, setRangeEnd] = useState("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [hiddenTables, setHiddenTables] = useState<Set<string>>(new Set());
  const [showArtifactMenu, setShowArtifactMenu] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<TimelineEntry | null>(null);
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const allRows = entries ?? [];

  const startBound = toBound(rangeStart, "start");
  const endBound = toBound(rangeEnd, "end");
  const rangeActive = Boolean(startBound || endBound);

  // Distinct artifact tables present, with total counts — drives the filter
  // popup. Counts come from the full set (not range-filtered) so the list is
  // stable as the user narrows the time range.
  const tableCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of allRows) m.set(e.table, (m.get(e.table) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [allRows]);

  function toggleTable(table: string) {
    setHiddenTables((prev) => {
      const next = new Set(prev);
      if (next.has(table)) next.delete(table);
      else next.add(table);
      return next;
    });
  }

  const globalActive = globalRangeActive(globalTimeRange);
  const rows = useMemo(() => {
    const filtered = allRows.filter((e) => {
      if (hiddenTables.has(e.table)) return false;
      if (onlySuspicious && e.tags.length === 0) return false;
      if (globalActive && !inRange(e.timestamp, globalTimeRange)) return false;
      if (rangeActive) {
        if (!e.timestamp) return false;
        if (startBound && e.timestamp < startBound) return false;
        if (endBound && e.timestamp > endBound) return false;
      }
      return true;
    });
    // Timestamps are pre-formatted YYYY-MM-DD hh:mm:ss.fff, so string compare
    // is chronological. Rows with no timestamp always sink to the bottom
    // regardless of direction (they can't be placed on the timeline).
    return [...filtered].sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      const cmp = a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allRows, startBound, endBound, sortDir, hiddenTables, rangeActive, globalActive, globalTimeRange, onlySuspicious]);

  // Earliest/latest timestamp among the rows actually shown — drives the
  // status bar's range readout. Rows without a timestamp are ignored here.
  const timeSpan = useMemo(() => {
    let min = "";
    let max = "";
    let missing = 0;
    for (const e of rows) {
      if (!e.timestamp) {
        missing += 1;
        continue;
      }
      if (!min || e.timestamp < min) min = e.timestamp;
      if (!max || e.timestamp > max) max = e.timestamp;
    }
    return { min, max, missing };
  }, [rows]);

  // Activity histogram — bucket the table/range-filtered rows over their span
  // so activity spikes (and where suspicious events cluster) are visible at a
  // glance. Independent of the "의심만"/sort state so the shape stays stable.
  const HISTO_BUCKETS = 72;
  const histogram = useMemo(() => {
    const base = allRows.filter((e) => {
      if (hiddenTables.has(e.table)) return false;
      if (globalActive && !inRange(e.timestamp, globalTimeRange)) return false;
      if (rangeActive) {
        if (startBound && e.timestamp < startBound) return false;
        if (endBound && e.timestamp > endBound) return false;
      }
      return !!e.timestamp;
    });
    if (base.length === 0) return null;
    const ms = (t: string) => Date.parse(t.replace(" ", "T"));
    let tmin = Infinity;
    let tmax = -Infinity;
    for (const e of base) {
      const t = ms(e.timestamp);
      if (!Number.isNaN(t)) {
        if (t < tmin) tmin = t;
        if (t > tmax) tmax = t;
      }
    }
    if (!Number.isFinite(tmin) || !Number.isFinite(tmax)) return null;
    const span = Math.max(1, tmax - tmin);
    const buckets = Array.from({ length: HISTO_BUCKETS }, () => ({ total: 0, sus: 0 }));
    for (const e of base) {
      const t = ms(e.timestamp);
      if (Number.isNaN(t)) continue;
      let idx = Math.floor(((t - tmin) / span) * HISTO_BUCKETS);
      if (idx >= HISTO_BUCKETS) idx = HISTO_BUCKETS - 1;
      if (idx < 0) idx = 0;
      buckets[idx].total += 1;
      if (e.tags.length > 0) buckets[idx].sus += 1;
    }
    const peak = Math.max(1, ...buckets.map((b) => b.total));
    return { buckets, peak };
  }, [allRows, hiddenTables, startBound, endBound, rangeActive, globalActive, globalTimeRange]);

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
    width: 168,
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
        <strong style={{ fontSize: 13 }}>🕐 통합 타임라인</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>
          {rangeActive || hiddenTables.size > 0
            ? `${rows.length.toLocaleString()} / ${allRows.length.toLocaleString()}건`
            : `${allRows.length.toLocaleString()}건 · 모든 아티팩트를 시간순으로 병합`}
        </span>

        <button
          onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
          title="정렬 순서 변경"
          style={{
            fontSize: 11.5,
            padding: "4px 10px",
            background: "var(--bg-elevated)",
            color: "var(--text-dim)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            cursor: "pointer",
            fontWeight: 600,
            whiteSpace: "nowrap",
          }}
        >
          {sortDir === "asc" ? "▲ 과거→최근" : "▼ 최근→과거"}
        </button>

        <button
          onClick={() => setOnlySuspicious((v) => !v)}
          title="의심 태그가 붙은 항목만 표시"
          style={{
            fontSize: 11.5,
            padding: "4px 10px",
            background: onlySuspicious ? "var(--danger-subtle)" : "var(--bg-elevated)",
            color: onlySuspicious ? "var(--danger)" : "var(--text-dim)",
            border: `1px solid ${onlySuspicious ? "var(--danger)" : "var(--border)"}`,
            borderRadius: "var(--radius-lg)",
            cursor: "pointer",
            fontWeight: 600,
            whiteSpace: "nowrap",
          }}
        >
          ⚠ 의심만
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto" }}>
          <div style={{ position: "relative" }}>
            <button
              onClick={() => setShowArtifactMenu((v) => !v)}
              title="통합 타임라인에 표시할 아티팩트 선택"
              style={{
                fontSize: 11.5,
                padding: "4px 10px",
                background: hiddenTables.size > 0 ? "var(--accent-subtle)" : "var(--bg-elevated)",
                color: hiddenTables.size > 0 ? "var(--accent)" : "var(--text-dim)",
                border: `1px solid ${hiddenTables.size > 0 ? "var(--accent)" : "var(--border)"}`,
                borderRadius: "var(--radius-lg)",
                cursor: "pointer",
                fontWeight: 600,
                whiteSpace: "nowrap",
              }}
            >
              ▤ 아티팩트{hiddenTables.size > 0 ? ` (${tableCounts.length - hiddenTables.size}/${tableCounts.length})` : ""}
            </button>
            {showArtifactMenu && (
              <>
                <div onClick={() => setShowArtifactMenu(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />
                <div
                  style={{
                    position: "absolute",
                    top: "calc(100% + 4px)",
                    right: 0,
                    zIndex: 41,
                    width: 300,
                    maxHeight: 380,
                    overflowY: "auto",
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-md)",
                    boxShadow: "var(--shadow-panel)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      padding: "8px 12px",
                      borderBottom: "1px solid var(--border)",
                      position: "sticky",
                      top: 0,
                      background: "var(--bg-elevated)",
                    }}
                  >
                    <span style={{ fontSize: 11.5, fontWeight: 700, color: "var(--text-dim)" }}>표시할 아티팩트</span>
                    <button onClick={() => setHiddenTables(new Set())} style={{ marginLeft: "auto", fontSize: 11, background: "transparent", border: "none", color: "var(--accent)", cursor: "pointer", fontWeight: 600 }}>
                      전체
                    </button>
                    <button onClick={() => setHiddenTables(new Set(tableCounts.map(([t]) => t)))} style={{ fontSize: 11, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer", fontWeight: 600 }}>
                      해제
                    </button>
                  </div>
                  {tableCounts.map(([table, count]) => {
                    const checked = !hiddenTables.has(table);
                    return (
                      <label
                        key={table}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          padding: "6px 12px",
                          cursor: "pointer",
                          fontSize: 12,
                        }}
                      >
                        <input type="checkbox" checked={checked} onChange={() => toggleTable(table)} />
                        <span style={{ flex: 1, color: checked ? "var(--text)" : "var(--text-faint)", wordBreak: "break-all" }}>{table}</span>
                        <span style={{ color: "var(--text-faint)", fontSize: 11 }}>{count.toLocaleString()}</span>
                      </label>
                    );
                  })}
                </div>
              </>
            )}
          </div>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>기간</span>
          <DateTimeInput
            value={rangeStart}
            onChange={setRangeStart}
            style={inputStyle}
            ariaLabel="시작 시각"
            placeholder="YYYY-MM-DD HH:mm:ss"
          />
          <span style={{ color: "var(--text-faint)", fontSize: 11 }}>~</span>
          <DateTimeInput
            value={rangeEnd}
            onChange={setRangeEnd}
            style={inputStyle}
            ariaLabel="종료 시각"
            placeholder="YYYY-MM-DD HH:mm:ss"
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

      {histogram && (
        <div
          title="시간대별 활동량 (빨강: 의심 항목 포함)"
          style={{ display: "flex", alignItems: "flex-end", gap: 1, height: 42, padding: "8px 14px 4px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0 }}
        >
          {histogram.buckets.map((b, i) => {
            const h = b.total === 0 ? 0 : Math.max(2, Math.round((b.total / histogram.peak) * 28));
            const hasSus = b.sus > 0;
            return (
              <div key={i} title={`${b.total.toLocaleString()}건${b.sus ? ` · 의심 ${b.sus}` : ""}`} style={{ flex: 1, height: 28, display: "flex", alignItems: "flex-end" }}>
                <div style={{ width: "100%", height: h, background: hasSus ? "var(--danger)" : "var(--accent)", opacity: hasSus ? 0.9 : 0.5, borderRadius: 1 }} />
              </div>
            );
          })}
        </div>
      )}

      {rows.length === 0 ? (
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", gap: 8 }}>
          <span style={{ fontSize: 32 }}>🕐</span>
          <span>{rangeActive ? "선택한 기간에 해당하는 기록이 없습니다." : "표시할 시간 기록이 없습니다."}</span>
        </div>
      ) : (
      <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        <div style={{ height: paddingTop }} />
        {virtualRows.map((virtualRow) => {
          const entry = rows[virtualRow.index];
          const dangerTag = entry.tags.find((t) => t.severity === "danger");
          const warningTag = entry.tags.find((t) => t.severity === "warning");
          const bookmarked = bookmarkedKeys.has(`${entry.fullPath}#${entry.rowid}`);
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
                  title={entry.tags.map((t) => (t.description ? `${t.label} — ${t.description}` : t.label)).join("\n\n")}
                >
                  {dangerTag ? "⛔" : "⚠"}
                </span>
              )}
              <span
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleBookmark(entry);
                }}
                title={bookmarked ? "북마크 해제" : "북마크에 추가"}
                style={{ flexShrink: 0, cursor: "pointer", fontSize: 14, color: bookmarked ? "var(--warning)" : "var(--text-faint)" }}
              >
                {bookmarked ? "★" : "☆"}
              </span>
            </div>
          );
        })}
        <div style={{ height: paddingBottom }} />
      </div>
      )}

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "5px 14px",
          borderTop: "1px solid var(--border)",
          background: "var(--bg-panel)",
          flexShrink: 0,
          fontSize: 11.5,
          fontFamily: "var(--mono)",
          color: "var(--text-faint)",
          whiteSpace: "nowrap",
          overflow: "hidden",
        }}
      >
        <span>
          총 <strong style={{ color: "var(--text-dim)" }}>{allRows.length.toLocaleString()}</strong>건
        </span>
        <span>
          표시 <strong style={{ color: "var(--text-dim)" }}>{rows.length.toLocaleString()}</strong>건
          {rangeActive || hiddenTables.size > 0 ? " (필터 적용됨)" : ""}
        </span>
        <span>
          아티팩트 <strong style={{ color: "var(--text-dim)" }}>{tableCounts.length - hiddenTables.size}</strong>/{tableCounts.length}종
        </span>
        {timeSpan.missing > 0 && <span>시간 정보 없음 {timeSpan.missing.toLocaleString()}건</span>}
        {timeSpan.min && (
          <span style={{ marginLeft: "auto", color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis" }}>
            {timeSpan.min} ~ {timeSpan.max}
          </span>
        )}
        <span style={{ marginLeft: timeSpan.min ? 0 : "auto" }}>{sortDir === "asc" ? "▲ 과거→최근" : "▼ 최근→과거"}</span>
      </div>

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
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={bookmarkedKeys.has(`${selectedEntry.fullPath}#${selectedEntry.rowid}`)}
          onToggleBookmark={() => onToggleBookmark(selectedEntry)}
        />
      )}
    </div>
  );
}
