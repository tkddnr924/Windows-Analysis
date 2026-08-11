"use client";

import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import RowDetailPanel from "./RowDetailPanel";
import { tagsForPath, type Tag } from "@/lib/tagging";
import { inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import type { CsvData, FetchLinkedRows } from "@/lib/types";

interface ExecutionHistoryViewProps {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange: TimeRange;
}

// ExecutionHistory correlates every "this ran / was present" signal — Amcache
// (installed programs + file entries), Prefetch runs, UserAssist — into one
// stream. An analyst reads it to triage: which executables are suspicious, are
// any unsigned, do any sit in temp/download/public paths. So this view leads
// with risk (suspicious-first ordering, signal badges, stat tiles) rather than
// presenting a flat chronological grid.

type Row = Record<string, string>;

const EXECUTABLE_RE = /\.(exe|dll|sys|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi)$/i;

interface SourceMeta {
  label: string;
  icon: string;
}
const SOURCE_META: Record<string, SourceMeta> = {
  Amcache_Programs: { label: "설치 프로그램(Amcache)", icon: "📦" },
  Amcache_Files: { label: "파일(Amcache)", icon: "📄" },
  Prefetch: { label: "Prefetch 실행", icon: "▶️" },
  UserAssist: { label: "UserAssist(실행)", icon: "🖱️" },
  SRUM: { label: "SRUM(리소스 사용)", icon: "📊" },
  BAM: { label: "BAM(백그라운드 실행)", icon: "⏱️" },
  AppCompatCache: { label: "ShimCache(존재/실행)", icon: "🗃️" },
};
function sourceMeta(src: string): SourceMeta {
  return SOURCE_META[src] ?? { label: src, icon: "•" };
}

interface Entry {
  rowid: number;
  name: string;
  path: string;
  publisher: string;
  sha1: string;
  runCount: string;
  timestamp: string;
  source: string;
  user: string;
  tags: Tag[];
  unsigned: boolean;
  /** 0 none · 1 warning · 2 danger — drives ordering and the risk dot. */
  risk: number;
  /** Path lives under C:\Windows (System32, SysWOW64, ...) — OS baseline noise
   * an analyst usually wants to hide while hunting. */
  winPath: boolean;
  row: Row;
}

function basename(p: string): string {
  const cleaned = (p || "").replace(/[\\/]+$/, "");
  const parts = cleaned.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

// Under the Windows directory: "C:\Windows\...", "\Windows\...", or the
// "%SystemRoot%\..." form Amcache sometimes stores.
function isWindowsSystemPath(p: string): boolean {
  const s = (p || "").toLowerCase();
  return /^[a-z]:\\windows(\\|$)/.test(s) || s.startsWith("\\windows\\") || s.startsWith("%systemroot%");
}

function buildEntry(row: Row): Entry {
  const path = row.program_path || "";
  const name = row.program_name || basename(path) || "(이름 없음)";
  const publisher = (row.publisher || "").trim();
  const isExe = EXECUTABLE_RE.test(name) || EXECUTABLE_RE.test(path);
  const unsigned = isExe && !publisher;

  const tags = tagsForPath(path);
  let risk = 0;
  for (const t of tags) risk = Math.max(risk, t.severity === "danger" ? 2 : 1);
  if (unsigned) risk = Math.max(risk, 1);

  return {
    rowid: Number((row as Record<string, unknown>).__rowid),
    name,
    path,
    publisher,
    sha1: row.sha1 || "",
    runCount: row.run_count || "",
    timestamp: row.timestamp || "",
    source: row.source_artifact || "",
    user: row.user || "",
    tags,
    unsigned,
    risk,
    winPath: isWindowsSystemPath(path),
    row,
  };
}

const RISK_DOT: Record<number, string> = { 0: "transparent", 1: "var(--warning)", 2: "var(--danger)" };

type SortKey = "risk" | "recent" | "oldest";

const SORT_LABEL: Record<SortKey, string> = { risk: "위험순", recent: "최근순", oldest: "오래된순" };

const ROW_HEIGHT = 62;

function StatTile({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div
      style={{
        flex: "1 1 0",
        minWidth: 96,
        background: "var(--bg-panel)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        padding: "10px 12px",
      }}
    >
      <div style={{ fontSize: 19, fontWeight: 700, color: accent ?? "var(--text)" }}>{value}</div>
      <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 2 }}>{label}</div>
    </div>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "4px 11px",
        borderRadius: 999,
        border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
        background: active ? "var(--accent-subtle)" : "transparent",
        color: active ? "var(--accent)" : "var(--text-dim)",
        fontSize: 12,
        cursor: "pointer",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </button>
  );
}

export default function ExecutionHistoryView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange,
}: ExecutionHistoryViewProps) {
  const [disabledSources, setDisabledSources] = useState<Set<string>>(new Set());
  const [onlyRisk, setOnlyRisk] = useState(false);
  const [onlyUnsigned, setOnlyUnsigned] = useState(false);
  const [sort, setSort] = useState<SortKey>("risk");
  const [excludeWindows, setExcludeWindows] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Entry | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const all = useMemo(() => (data.rows as Row[]).map(buildEntry), [data.rows]);

  const sources = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of all) counts.set(e.source, (counts.get(e.source) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [all]);

  const stats = useMemo(() => {
    let risk = 0;
    let unsigned = 0;
    let winPath = 0;
    let minTs = "";
    let maxTs = "";
    for (const e of all) {
      if (e.risk > 0) risk++;
      if (e.unsigned) unsigned++;
      if (e.winPath) winPath++;
      if (e.timestamp) {
        if (!minTs || e.timestamp < minTs) minTs = e.timestamp;
        if (!maxTs || e.timestamp > maxTs) maxTs = e.timestamp;
      }
    }
    return { total: all.length, risk, unsigned, winPath, minTs, maxTs };
  }, [all]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    let rows = all.filter((e) => {
      if (rangeActive(timeRange) && !inRange(e.timestamp, timeRange)) return false;
      if (excludeWindows && e.winPath) return false;
      if (disabledSources.has(e.source)) return false;
      if (onlyRisk && e.risk === 0) return false;
      if (onlyUnsigned && !e.unsigned) return false;
      if (needle && !(e.name.toLowerCase().includes(needle) || e.path.toLowerCase().includes(needle) || e.publisher.toLowerCase().includes(needle) || e.user.toLowerCase().includes(needle))) return false;
      return true;
    });
    rows = [...rows].sort((a, b) => {
      if (sort === "risk" && b.risk !== a.risk) return b.risk - a.risk;
      const cmp = (a.timestamp || "").localeCompare(b.timestamp || "");
      // risk ties (and both time sorts) order by time; only "oldest" ascends.
      return sort === "oldest" ? cmp : -cmp;
    });
    return rows;
  }, [all, disabledSources, onlyRisk, onlyUnsigned, sort, search, timeRange, excludeWindows]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      {/* Header: stat tiles */}
      <div style={{ padding: "16px 20px 0" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 12 }}>
          <span style={{ fontSize: 16, fontWeight: 700, color: "var(--text)" }}>실행 이력</span>
          {stats.minTs && (
            <span style={{ fontSize: 12, color: "var(--text-faint)" }}>
              {stats.minTs.slice(0, 10)} ~ {stats.maxTs.slice(0, 10)}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <StatTile label="전체 항목" value={stats.total.toLocaleString()} />
          {sources.map(([src, n]) => (
            <StatTile key={src} label={sourceMeta(src).label} value={n.toLocaleString()} />
          ))}
          <StatTile label="의심 항목" value={stats.risk.toLocaleString()} accent={stats.risk ? "var(--warning)" : undefined} />
          <StatTile label="미서명 실행파일" value={stats.unsigned.toLocaleString()} accent={stats.unsigned ? "var(--warning)" : undefined} />
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "14px 20px", flexWrap: "wrap" }}>
        <Chip active={onlyRisk} onClick={() => setOnlyRisk((v) => !v)}>⚠ 의심만 {stats.risk > 0 && `(${stats.risk})`}</Chip>
        <Chip active={onlyUnsigned} onClick={() => setOnlyUnsigned((v) => !v)}>미서명만 {stats.unsigned > 0 && `(${stats.unsigned})`}</Chip>
        {sources.length > 1 && <span style={{ width: 1, height: 18, background: "var(--border)", margin: "0 2px" }} />}
        {sources.length > 1 &&
          sources.map(([src, n]) => {
            const on = !disabledSources.has(src);
            return (
              <Chip
                key={src}
                active={on}
                onClick={() =>
                  setDisabledSources((prev) => {
                    const s = new Set(prev);
                    if (s.has(src)) s.delete(src);
                    else s.add(src);
                    return s;
                  })
                }
              >
                {sourceMeta(src).icon} {sourceMeta(src).label} ({n})
              </Chip>
            );
          })}
        <Chip active={excludeWindows} onClick={() => setExcludeWindows((v) => !v)}>
          🚫 Windows 경로 제외 {stats.winPath > 0 && `(${stats.winPath})`}
        </Chip>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>정렬</span>
          <Chip active={sort === "risk"} onClick={() => setSort("risk")}>위험순</Chip>
          <Chip active={sort === "recent"} onClick={() => setSort("recent")}>최근순</Chip>
          <Chip active={sort === "oldest"} onClick={() => setSort("oldest")}>오래된순</Chip>
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="이름 · 경로 · 게시자 검색"
          style={{
            width: 220,
            padding: "5px 10px",
            background: "var(--bg-input)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            color: "var(--text)",
            fontSize: 12.5,
          }}
        />
      </div>

      {/* List */}
      <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto", borderTop: "1px solid var(--border-subtle)" }}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((vi) => {
            const e = filtered[vi.index];
            const meta = sourceMeta(e.source);
            const bookmarked = bookmarkedRowids?.has(e.rowid) ?? false;
            const isSel = selected?.rowid === e.rowid && selected?.source === e.source;
            return (
              <div
                key={vi.key}
                onClick={() => setSelected(e)}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: ROW_HEIGHT,
                  transform: `translateY(${vi.start}px)`,
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "0 20px",
                  borderBottom: "1px solid var(--border-subtle)",
                  cursor: "pointer",
                  background: isSel ? "var(--bg-selected)" : "transparent",
                }}
                onMouseEnter={(el) => {
                  if (!isSel) el.currentTarget.style.background = "var(--bg-hover)";
                }}
                onMouseLeave={(el) => {
                  if (!isSel) el.currentTarget.style.background = "transparent";
                }}
              >
                {/* risk dot */}
                <span style={{ flexShrink: 0, width: 8, height: 8, borderRadius: 999, background: RISK_DOT[e.risk], border: e.risk === 0 ? "1px solid var(--border)" : "none" }} />

                {/* bookmark */}
                {onToggleBookmark && Number.isFinite(e.rowid) && (
                  <span
                    onClick={(ev) => {
                      ev.stopPropagation();
                      onToggleBookmark(e.rowid);
                    }}
                    title={bookmarked ? "북마크 해제" : "북마크"}
                    style={{ flexShrink: 0, cursor: "pointer", color: bookmarked ? "var(--warning)" : "var(--text-faint)", fontSize: 13 }}
                  >
                    {bookmarked ? "★" : "☆"}
                  </span>
                )}

                {/* left: name + time (read together, no ping-pong to the right) */}
                <div style={{ flex: "1 1 42%", minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontSize: 13, fontWeight: 500, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.name}</span>
                    {e.tags.map((t) => (
                      <span
                        key={t.label}
                        title={t.description}
                        style={{
                          flexShrink: 0,
                          fontSize: 10.5,
                          padding: "1px 6px",
                          borderRadius: 4,
                          background: t.severity === "danger" ? "var(--danger-subtle)" : "var(--warning-subtle)",
                          color: t.severity === "danger" ? "var(--danger)" : "var(--warning)",
                        }}
                      >
                        {t.label}
                      </span>
                    ))}
                    {e.unsigned && (
                      <span title="서명 정보가 없는 실행 파일입니다." style={{ flexShrink: 0, fontSize: 10.5, padding: "1px 6px", borderRadius: 4, background: "var(--warning-subtle)", color: "var(--warning)" }}>
                        미서명
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {e.timestamp || "—"}
                  </div>
                </div>

                {/* right: full path + source/publisher/run-count */}
                <div style={{ flex: "1 1 58%", minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {e.path || "경로 없음"}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {meta.icon} {meta.label}
                    {e.user && ` · 👤 ${e.user}`}
                    {e.publisher && ` · ${e.publisher}`}
                    {e.runCount && ` · ${e.runCount}회 실행`}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Status bar */}
      <div style={{ display: "flex", gap: 16, padding: "6px 20px", borderTop: "1px solid var(--border-subtle)", fontSize: 11.5, color: "var(--text-faint)", flexShrink: 0 }}>
        <span>
          표시 <strong style={{ color: "var(--text-dim)" }}>{filtered.length.toLocaleString()}</strong> / {stats.total.toLocaleString()}건
          {(disabledSources.size > 0 || onlyRisk || onlyUnsigned || search.trim() || rangeActive(timeRange) || excludeWindows) && " (필터 적용됨)"}
        </span>
        <span>정렬 {SORT_LABEL[sort]}</span>
      </div>

      {selected && (
        <RowDetailPanel
          row={selected.row}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName="ExecutionHistory"
          onClose={() => setSelected(null)}
          onNavigate={(f, c, v) => {
            setSelected(null);
            onNavigate(f, c, v);
          }}
          onFetchLinkedRows={onFetchLinkedRows}
          isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined}
          onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined}
        />
      )}
    </div>
  );
}
