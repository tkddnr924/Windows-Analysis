"use client";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import RowDetailPanel from "./RowDetailPanel";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import { tagsForPath, type Tag } from "@/lib/tagging";
import type { CsvData, FetchLinkedRows } from "@/lib/types";

const TABLE = "ScheduledTasks";
const PAGE = 12;

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

type Row = Record<string, string>;
type FilterKey = "all" | "user" | "review" | "hidden";

interface Entry {
  row: Row;
  rowid: number;
  name: string;
  actions: string;
  trigger: string;
  runAs: string;
  isMicrosoft: boolean;
  enabled: boolean | null;
  hidden: boolean;
  tags: Tag[];
  review: boolean;
}

function truthValue(value: string | undefined): boolean | null {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return null;
  if (["1", "true", "yes", "enabled", "사용", "예"].includes(normalized)) return true;
  if (["0", "false", "no", "disabled", "미사용", "아니오"].includes(normalized)) return false;
  return null;
}

function buildEntry(row: Row): Entry {
  const tags = tagsForPath(row.actions || "");
  const hidden = truthValue(row.hidden) === true;
  return {
    row,
    rowid: Number((row as Record<string, unknown>).__rowid),
    name: row.task_name || "(작업 이름 없음)",
    actions: row.actions || "",
    trigger: row.trigger_types || "",
    runAs: row.run_as || "",
    isMicrosoft: row.is_microsoft === "1",
    enabled: truthValue(row.enabled),
    hidden,
    tags,
    review: hidden || tags.length > 0,
  };
}

function FilterButton({ active, children, onClick }: { active: boolean; children: React.ReactNode; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={active} style={{
      height: 30, padding: "0 10px", borderRadius: "var(--radius-sm)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
      background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)",
      fontSize: 11.5, fontWeight: active ? 700 : 500, cursor: "pointer", whiteSpace: "nowrap",
    }}>
      {children}
    </button>
  );
}

function Signal({ children, tone = "neutral" }: { children: React.ReactNode; tone?: "neutral" | "warning" | "danger" | "success" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : tone === "success" ? "var(--success)" : "var(--text-dim)";
  return <span style={{ color, fontSize: 10.5, fontWeight: 650, whiteSpace: "nowrap" }}>{children}</span>;
}

function taskState(entry: Entry): React.ReactNode {
  const signals: React.ReactNode[] = [];
  if (entry.enabled === true) signals.push(<Signal key="enabled" tone="success">활성</Signal>);
  if (entry.enabled === false) signals.push(<Signal key="disabled">비활성</Signal>);
  if (entry.hidden) signals.push(<Signal key="hidden" tone="warning">숨김</Signal>);
  if (entry.tags.some((tag) => tag.severity === "danger")) signals.push(<Signal key="danger" tone="danger">검토</Signal>);
  else if (entry.tags.length > 0) signals.push(<Signal key="warning" tone="warning">검토</Signal>);
  return signals.length ? <span style={{ display: "inline-flex", gap: 7, flexWrap: "wrap" }}>{signals}</span> : <span style={{ color: "var(--text-faint)", fontSize: 11 }}>—</span>;
}

function cellStyle(extra?: CSSProperties): CSSProperties {
  return { minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...extra };
}

export default function ScheduledTasksView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE }: Props) {
  const [filter, setFilter] = useState<FilterKey>("user");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Entry | null>(null);

  const all = useMemo(() => (data.rows as Row[]).map(buildEntry), [data.rows]);
  const rangeOn = rangeActive(timeRange);
  const counts = useMemo(() => ({
    total: all.length,
    user: all.filter((entry) => !entry.isMicrosoft).length,
    review: all.filter((entry) => entry.review).length,
    hidden: all.filter((entry) => entry.hidden).length,
  }), [all]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return all
      .filter((entry) => {
        if (rangeOn && !inRange(entry.row.timestamp || "", timeRange)) return false;
        if (filter === "user" && entry.isMicrosoft) return false;
        if (filter === "review" && !entry.review) return false;
        if (filter === "hidden" && !entry.hidden) return false;
        if (!query) return true;
        return [entry.name, entry.actions, entry.runAs, entry.trigger, entry.row.author || ""].some((value) => value.toLowerCase().includes(query));
      })
      .sort((left, right) => Number(right.review) - Number(left.review) || Number(left.isMicrosoft) - Number(right.isMicrosoft) || left.name.localeCompare(right.name));
  }, [all, filter, rangeOn, search, timeRange]);

  useEffect(() => setPage(0), [filter, rangeOn, search, timeRange]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = filtered.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <header style={{ flexShrink: 0, padding: "15px 20px 12px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 9, flexWrap: "wrap" }}>
          <strong style={{ color: "var(--text)", fontSize: 16 }}>작업 스케줄러</strong>
          <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? `등록 시각 기준 ${filtered.length.toLocaleString()}건` : `등록 작업 ${counts.total.toLocaleString()}건`}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 11, flexWrap: "wrap" }}>
          <span style={{ color: "var(--text-faint)", fontSize: 11, marginRight: 1 }}>표시</span>
          <FilterButton active={filter === "user"} onClick={() => setFilter("user")}>비-Microsoft 작업 {counts.user.toLocaleString()}</FilterButton>
          <FilterButton active={filter === "all"} onClick={() => setFilter("all")}>전체 {counts.total.toLocaleString()}</FilterButton>
          <FilterButton active={filter === "review"} onClick={() => setFilter("review")}>검토 신호 {counts.review.toLocaleString()}</FilterButton>
          <FilterButton active={filter === "hidden"} onClick={() => setFilter("hidden")}>숨김 {counts.hidden.toLocaleString()}</FilterButton>
          <div style={{ flex: 1, minWidth: 12 }} />
          <div style={{ position: "relative", width: "min(100%, 290px)" }}>
            <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="작업 이름 · 명령 · 계정 · 트리거 검색" aria-label="작업 스케줄러 검색"
              onFocus={(event) => { event.currentTarget.style.borderColor = "var(--accent)"; event.currentTarget.style.boxShadow = "0 0 0 2px var(--accent-subtle)"; }}
              onBlur={(event) => { event.currentTarget.style.borderColor = "var(--border)"; event.currentTarget.style.boxShadow = "none"; }}
              style={{ width: "100%", height: 30, padding: "0 30px 0 10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-input)", color: "var(--text)", fontSize: 11.5, outline: "none" }} />
            {search && <button type="button" onClick={() => setSearch("")} aria-label="검색어 지우기" style={{ position: "absolute", top: 0, right: 0, width: 30, height: 30, display: "grid", placeItems: "center", border: 0, background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 16 }} /></button>}
          </div>
        </div>
      </header>

      <section aria-label="예약 작업 목록" style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        <div style={{ minWidth: 900 }}>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 1.25fr) minmax(260px, 2fr) minmax(145px, .9fr) minmax(130px, .85fr) minmax(130px, .75fr) 145px 34px", gap: 14, alignItems: "center", padding: "9px 20px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", background: "var(--bg-panel)", fontSize: 10.5, fontWeight: 650 }}>
            <span>작업 이름</span><span>실행 명령</span><span>실행 계정</span><span>트리거</span><span>상태</span><span>등록 시각</span><span aria-label="북마크" />
          </div>
          {pageRows.map((entry) => {
            const bookmarked = bookmarkedRowids?.has(entry.rowid) ?? false;
            const canBookmark = onToggleBookmark && Number.isFinite(entry.rowid);
            return (
              <div key={Number.isFinite(entry.rowid) ? entry.rowid : entry.name} style={{ display: "grid", gridTemplateColumns: "minmax(180px, 1.25fr) minmax(260px, 2fr) minmax(145px, .9fr) minmax(130px, .85fr) minmax(130px, .75fr) 145px 34px", gap: 14, alignItems: "center", minHeight: 55, padding: "0 20px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${bookmarked ? "var(--accent)" : "transparent"}`, background: bookmarked ? "var(--accent-subtle)" : "transparent" }}>
                <button type="button" onClick={() => setSelected(entry)} aria-label={`${entry.name} 상세 보기`} style={{ gridColumn: "1 / 7", display: "grid", gridTemplateColumns: "minmax(180px, 1.25fr) minmax(260px, 2fr) minmax(145px, .9fr) minmax(130px, .85fr) minmax(130px, .75fr) 145px", gap: 14, alignItems: "center", minWidth: 0, width: "100%", padding: "9px 0", border: 0, background: "transparent", color: "inherit", textAlign: "left", cursor: "pointer" }}>
                  <span title={entry.name} style={cellStyle({ color: "var(--text)", fontSize: 12.5, fontWeight: 650 })}>{entry.name}</span>
                  <span title={entry.actions || "동작 정보 없음"} style={cellStyle({ color: entry.actions ? "var(--text-dim)" : "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" })}>{entry.actions || "동작 정보 없음"}</span>
                  <span title={entry.runAs || "계정 정보 없음"} style={cellStyle({ color: entry.runAs ? "var(--text-dim)" : "var(--text-faint)", fontSize: 11.5 })}>{entry.runAs || "계정 정보 없음"}</span>
                  <span title={entry.trigger || "트리거 정보 없음"} style={cellStyle({ color: entry.trigger ? "var(--text-dim)" : "var(--text-faint)", fontSize: 11.5 })}>{entry.trigger || "트리거 정보 없음"}</span>
                  <span style={cellStyle()}>{taskState(entry)}</span>
                  <time style={cellStyle({ color: "var(--text-faint)", fontSize: 10.5, fontFamily: "var(--mono)" })}>{entry.row.timestamp || "시간 정보 없음"}</time>
                </button>
                {canBookmark && <button type="button" onClick={() => onToggleBookmark(entry.rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크"} title={bookmarked ? "북마크 해제" : "북마크"} style={{ justifySelf: "end", width: 28, height: 28, display: "grid", placeItems: "center", border: 0, background: "transparent", color: bookmarked ? "var(--accent)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 18 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 18 }} />}</button>}
              </div>
            );
          })}
          {!pageRows.length && <div style={{ padding: "28px 20px", color: "var(--text-faint)", fontSize: 12.5 }}>{rangeOn ? "기간 필터 내 데이터 없음" : "조건에 맞는 작업이 없습니다."}</div>}
        </div>
      </section>

      <footer style={{ flexShrink: 0, display: "flex", alignItems: "center", minHeight: 42, padding: "0 20px", borderTop: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 11.5 }}>
        <span>표시 {filtered.length.toLocaleString()} / {counts.total.toLocaleString()}건</span>
        {pageCount > 1 && <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
          <button type="button" onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pageButton(safePage === 0)}>이전</button>
          <span>{safePage + 1} / {pageCount}</span>
          <button type="button" onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pageButton(safePage >= pageCount - 1)}>다음</button>
        </div>}
      </footer>

      {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(file, column, value) => { setSelected(null); onNavigate(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} isBookmarked={Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
    </div>
  );
}

function pageButton(disabled: boolean): CSSProperties {
  return { height: 27, padding: "0 9px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "transparent", color: "var(--text-dim)", fontSize: 11, cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.45 : 1 };
}
