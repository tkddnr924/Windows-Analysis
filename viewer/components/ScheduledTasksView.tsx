"use client";

import { useEffect, useMemo, useState } from "react";
import RowDetailPanel from "./RowDetailPanel";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import { tagsForPath, type Tag } from "@/lib/tagging";
import type { CsvData, FetchLinkedRows } from "@/lib/types";

const TABLE = "ScheduledTasks";

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

type Row = Record<string, string>;

// Scheduled tasks are prime persistence: an attacker's backdoor often lives as
// a task running a script from a writable path, as SYSTEM, hidden. This view
// leads with user/third-party tasks (built-in Microsoft tasks are noise) and
// flags suspicious action paths, hidden tasks, and SYSTEM run level.

const RISK_DOT: Record<number, string> = { 0: "transparent", 1: "var(--warning)", 2: "var(--danger)" };
const rowidOf = (r: Row): number => Number((r as Record<string, unknown>).__rowid);
const isTrue = (v: string) => v === "1" || v?.toLowerCase?.() === "true" || v === "사용" || v === "예";

interface Entry {
  row: Row;
  rowid: number;
  name: string;
  actions: string;
  trigger: string;
  runAs: string;
  isMs: boolean;
  hidden: boolean;
  system: boolean;
  tags: Tag[];
  risk: number;
}

function build(r: Row): Entry {
  const actions = r.actions || "";
  const tags = tagsForPath(actions);
  const hidden = isTrue(r.hidden);
  const system = /system|s-1-5-18/i.test(r.run_as || "") || (r.run_level || "").toLowerCase().includes("highest");
  let risk = 0;
  for (const t of tags) risk = Math.max(risk, t.severity === "danger" ? 2 : 1);
  if (hidden) risk = Math.max(risk, 1);
  return {
    row: r, rowid: rowidOf(r), name: r.task_name || "(이름 없음)", actions,
    trigger: r.trigger_types || "", runAs: r.run_as || "",
    isMs: r.is_microsoft === "1", hidden, system, tags, risk,
  };
}

type FilterKey = "all" | "user" | "risk" | "hidden";
const PAGE = 12;

function Tile({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div style={{ minWidth: 104, padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderLeft: `3px solid ${accent ?? "var(--border)"}`, borderRadius: "var(--radius-md)" }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 800, color: accent ?? "var(--text)" }}>{value}</div>
    </div>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} style={{ padding: "4px 11px", borderRadius: 999, border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", fontSize: 12, cursor: "pointer", whiteSpace: "nowrap" }}>
      {children}
    </button>
  );
}

function Badge({ text, color }: { text: string; color: string }) {
  return <span style={{ fontSize: 10, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: 4, padding: "0 5px", whiteSpace: "nowrap" }}>{text}</span>;
}

export default function ScheduledTasksView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE }: Props) {
  const [filter, setFilter] = useState<FilterKey>("user");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Entry | null>(null);

  const all = useMemo(() => (data.rows as Row[]).map(build), [data.rows]);
  const stats = useMemo(() => ({
    total: all.length,
    user: all.filter((e) => !e.isMs).length,
    hidden: all.filter((e) => e.hidden).length,
    system: all.filter((e) => e.system).length,
    risk: all.filter((e) => e.risk > 0).length,
  }), [all]);

  const rangeOn = rangeActive(timeRange);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let rows = all.filter((e) => {
      // Global incident-window filter: a task's registration date (when it was
      // created) must fall in the window — surfaces persistence created during
      // the incident. Tasks with no registration date drop out when active.
      if (rangeOn && !inRange(e.row.timestamp || "", timeRange)) return false;
      if (filter === "user" && e.isMs) return false;
      if (filter === "risk" && e.risk === 0) return false;
      if (filter === "hidden" && !e.hidden) return false;
      if (q && !(e.name.toLowerCase().includes(q) || e.actions.toLowerCase().includes(q) || (e.row.author || "").toLowerCase().includes(q))) return false;
      return true;
    });
    // Suspicious first, then user tasks, then by name.
    rows = [...rows].sort((a, b) => b.risk - a.risk || Number(a.isMs) - Number(b.isMs) || a.name.localeCompare(b.name));
    return rows;
  }, [all, filter, search, rangeOn, timeRange]);

  useEffect(() => setPage(0), [filter, search, rangeOn, timeRange]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const paged = filtered.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "16px 20px 0" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <span style={{ fontSize: 16, fontWeight: 700 }}>⏰ 작업 스케줄러</span>
          {rangeOn && <span style={{ fontSize: 11.5, padding: "2px 9px", borderRadius: 999, border: "1px solid var(--accent)", background: "color-mix(in srgb, var(--accent) 12%, transparent)", color: "var(--text-dim)" }}>기간 필터 적용됨 · 등록일 기준 {filtered.length.toLocaleString()} / {all.length.toLocaleString()}</span>}
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <Tile label="전체 작업" value={stats.total.toLocaleString()} />
          <Tile label="사용자 작업" value={stats.user.toLocaleString()} accent={stats.user ? "var(--accent)" : undefined} />
          <Tile label="의심" value={stats.risk.toLocaleString()} accent={stats.risk ? "var(--warning)" : undefined} />
          <Tile label="숨김" value={stats.hidden.toLocaleString()} accent={stats.hidden ? "var(--warning)" : undefined} />
          <Tile label="SYSTEM/최고권한" value={stats.system.toLocaleString()} />
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "14px 20px", flexWrap: "wrap" }}>
        <Chip active={filter === "user"} onClick={() => setFilter("user")}>사용자 작업 ({stats.user})</Chip>
        <Chip active={filter === "all"} onClick={() => setFilter("all")}>전체 ({stats.total})</Chip>
        <Chip active={filter === "risk"} onClick={() => setFilter("risk")}>⚠ 의심 {stats.risk > 0 && `(${stats.risk})`}</Chip>
        <Chip active={filter === "hidden"} onClick={() => setFilter("hidden")}>숨김 {stats.hidden > 0 && `(${stats.hidden})`}</Chip>
        <div style={{ flex: 1 }} />
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="작업명 · 명령 · 작성자 검색"
          style={{ width: 240, padding: "5px 10px", background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12.5 }} />
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", borderTop: "1px solid var(--border-subtle)" }}>
        {paged.length === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>해당하는 작업이 없습니다.</div>}
        {paged.map((e) => {
          const bookmarked = bookmarkedRowids?.has(e.rowid) ?? false;
          return (
            <div
              key={e.rowid || e.name}
              onClick={() => setSelected(e)}
              style={{ display: "flex", gap: 10, padding: "10px 20px", borderBottom: "1px solid var(--border-subtle)", cursor: "pointer" }}
              onMouseEnter={(el) => (el.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(el) => (el.currentTarget.style.background = "transparent")}
            >
              <span style={{ flexShrink: 0, marginTop: 5, width: 8, height: 8, borderRadius: 999, background: RISK_DOT[e.risk], border: e.risk === 0 ? "1px solid var(--border)" : "none" }} />
              {onToggleBookmark && Number.isFinite(e.rowid) && (
                <span onClick={(ev) => { ev.stopPropagation(); onToggleBookmark(e.rowid); }} title={bookmarked ? "북마크 해제" : "북마크"} style={{ flexShrink: 0, cursor: "pointer", color: bookmarked ? "var(--warning)" : "var(--text-faint)", fontSize: 13 }}>{bookmarked ? "★" : "☆"}</span>
              )}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{e.name}</span>
                  {!e.isMs && <Badge text="사용자" color="var(--accent)" />}
                  {e.hidden && <Badge text="숨김" color="var(--warning)" />}
                  {e.system && <Badge text="SYSTEM/최고권한" color="var(--text-dim)" />}
                  {e.tags.map((t) => <Badge key={t.label} text={t.label} color={t.severity === "danger" ? "var(--danger)" : "var(--warning)"} />)}
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{e.actions || "(동작 없음)"}</div>
                <div style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 2 }}>
                  {[e.trigger && `트리거: ${e.trigger}`, e.runAs && `실행: ${e.runAs}`, e.row.author && `작성자: ${e.row.author}`].filter(Boolean).join("  ·  ")}
                </div>
              </div>
              <span style={{ flexShrink: 0, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{e.row.timestamp || ""}</span>
            </div>
          );
        })}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "6px 20px", borderTop: "1px solid var(--border-subtle)", fontSize: 11.5, color: "var(--text-faint)" }}>
        <span>표시 <strong style={{ color: "var(--text-dim)" }}>{filtered.length.toLocaleString()}</strong> / {stats.total.toLocaleString()}건</span>
        {pageCount > 1 && (
          <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <button onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>‹ 이전</button>
            <span>{safePage + 1} / {pageCount}</span>
            <button onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>다음 ›</button>
          </span>
        )}
      </div>

      {selected && (
        <RowDetailPanel
          row={selected.row}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName={TABLE}
          onClose={() => setSelected(null)}
          onNavigate={(f, c, v) => { setSelected(null); onNavigate(f, c, v); }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined}
          onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined}
        />
      )}
    </div>
  );
}

const pgBtn = (disabled: boolean): React.CSSProperties => ({ fontSize: 11.5, padding: "3px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1 });
