"use client";
import AccountFilterChips from "@/components/AccountFilterChips";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, formatEvidenceTimestamp, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";

type Row = Record<string, string>;
type Filter = "all" | "threat" | "protection" | "scan";

interface Props {
  data: CsvData;
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

interface DefenderEntry {
  row: Row;
  rowid: number;
  timestamp: string;
  section: Exclude<Filter, "all">;
  title: string;
  detail: string;
  action: string;
  user: string;
  attention: boolean;
}

const FILTER_LABELS: Record<Filter, string> = { all: "전체", threat: "탐지", protection: "보호 상태", scan: "검사" };

function isNeutralized(action: string): boolean {
  return /격리|제거|quarantine|remove|clean|차단|block/i.test(action || "");
}

function protectionNeedsAttention(row: Row): boolean {
  const value = `${row.title || ""} ${row.event_id || ""}`;
  return /실시간 보호 사용 안 함|바이러스 검사.*사용 안 함|5001|5010|5012/.test(value);
}

function entryFor(row: Row): DefenderEntry | null {
  if (row.section !== "threat" && row.section !== "tampering" && row.section !== "scan") return null;
  const section: Exclude<Filter, "all"> = row.section === "tampering" ? "protection" : row.section;
  const action = row.action || row.remediation || "";
  return {
    row,
    rowid: Number((row as Record<string, unknown>).__rowid),
    timestamp: row.timestamp || "",
    section,
    title: row.title || "(제목 없음)",
    detail: row.detail || row.process || row.source || "",
    action,
    user: row.user || "",
    attention: section === "threat" ? Boolean(action) && !isNeutralized(action) : section === "protection" && protectionNeedsAttention(row),
  };
}

function newestScanByType(entries: DefenderEntry[]): DefenderEntry[] {
  const seen = new Set<string>();
  return entries.filter((entry) => {
    if (entry.section !== "scan") return true;
    const key = `${entry.title}\u0000${entry.row.category || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function FilterButton({ active, children, onClick }: { active: boolean; children: React.ReactNode; onClick: () => void }) {
  return <button type="button" onClick={onClick} aria-pressed={active} style={{ height: 30, padding: "0 10px", borderRadius: "var(--radius-sm)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", fontSize: 11.5, fontWeight: active ? 700 : 500, cursor: "pointer", whiteSpace: "nowrap" }}>{children}</button>;
}

function cellStyle(extra?: CSSProperties): CSSProperties {
  return { minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...extra };
}

export default function DefenderView({ data, onNavigate, onFetchLinkedRows, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE, accountDirectory }: Props) {
  const [filter, setFilter] = useState<Filter>("all");
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<DefenderEntry | null>(null);
  const rangeOn = rangeActive(timeRange);

  // Keep every raw evidence row through range filtering. Scan de-duplication
  // comes afterwards so a period still shows that scan type's newest record
  // *inside that period*, not a newer record from outside it.
  const sourceEntries = useMemo(() => (data.rows as Row[])
    .map(entryFor)
    .filter((entry): entry is DefenderEntry => entry !== null)
    .sort((left, right) => (right.timestamp || "").localeCompare(left.timestamp || "")), [data.rows]);
  const periodEntries = useMemo(
    () => newestScanByType(sourceEntries.filter((entry) => !rangeOn || inRange(entry.timestamp, timeRange))),
    [rangeOn, sourceEntries, timeRange],
  );
  const counts = useMemo(() => ({ all: periodEntries.length, threat: periodEntries.filter((entry) => entry.section === "threat").length, protection: periodEntries.filter((entry) => entry.section === "protection").length, scan: periodEntries.filter((entry) => entry.section === "scan").length }), [periodEntries]);
  const latestProtection = useMemo(() => periodEntries.find((entry) => entry.section === "protection") ?? null, [periodEntries]);
  const allAccounts = useMemo(
    () => [...new Set(periodEntries.map((entry) => entry.user || ""))].sort((a, b) => a.localeCompare(b)),
    [periodEntries],
  );
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return periodEntries.filter((entry) => {
      if (filter !== "all" && entry.section !== filter) return false;
      if (hiddenAccounts.has(entry.user || "")) return false;
      return !query || [entry.title, entry.detail, entry.action, entry.user, entry.row.process || "", entry.row.category || ""].some((value) => value.toLocaleLowerCase().includes(query));
    });
  }, [filter, hiddenAccounts, periodEntries, search]);

  useEffect(() => setSelected(null), [filter, search, timeRange.end, timeRange.start]);
  const emptyText = rangeOn && periodEntries.length === 0 ? "기간 필터 내 Microsoft Defender 활동이 없습니다." : sourceEntries.length === 0 ? "Microsoft Defender 활동이 없습니다." : "검색·필터 조건에 일치하는 Microsoft Defender 활동이 없습니다.";

  return <section className="dfir-view" aria-labelledby="defender-title" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
    <div style={{ minHeight: "100%", display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", background: "var(--bg-panel)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", padding: "14px 16px", borderBottom: "1px solid var(--border)" }}>
        <strong id="defender-title" style={{ color: "var(--text)", fontSize: 15 }}>Microsoft Defender 활동</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{counts.all.toLocaleString()}건</span>
        {latestProtection && <span style={{ minWidth: 0, color: latestProtection.attention ? "var(--danger)" : "var(--text-dim)", fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>마지막 보호 상태 기록: {latestProtection.title}</span>}
        <span style={{ marginLeft: "auto", color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "전역 기간 필터 적용" : "전체 기간"}</span>
      </header>

      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", padding: "10px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
        {(Object.keys(FILTER_LABELS) as Filter[]).map((key) => <FilterButton key={key} active={filter === key} onClick={() => setFilter(key)}>{FILTER_LABELS[key]} {counts[key].toLocaleString()}</FilterButton>)}
        <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
        <label style={{ marginLeft: "auto", minWidth: "min(100%, 260px)", flex: "1 1 260px" }}><span className="sr-only">Microsoft Defender 활동 검색</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="위협명 · 조치 · 경로 · 사용자 검색" style={{ width: "100%", height: 32, boxSizing: "border-box", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg)", color: "var(--text)", padding: "0 10px", fontSize: 12 }} /></label>
      </div>

      <div style={{ minWidth: 760, display: "grid", gridTemplateColumns: "190px 110px minmax(260px, 1fr) minmax(140px, 0.45fr) minmax(110px, 0.35fr)", gap: 12, padding: "9px 16px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span>시간</span><span>구분</span><span>활동</span><span>조치</span><span>사용자</span></div>

      <div role="region" aria-label="Microsoft Defender 활동 원장" style={{ minWidth: 760, flex: 1 }}>
        {filtered.map((entry) => {
          const bookmarked = Number.isFinite(entry.rowid) && bookmarkedRowids?.has(entry.rowid);
          const tone = entry.attention ? "var(--danger)" : entry.section === "protection" ? "var(--warning)" : "var(--text-dim)";
          const actionLabel = entry.action || (entry.section === "threat" ? "조치 확인 필요" : "조치 이벤트 미확인");
          return <button key={`${entry.rowid}-${entry.timestamp}-${entry.title}`} type="button" className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(entry)} style={{ borderRadius: "var(--radius-sm)", width: "100%", minWidth: 760, display: "grid", gridTemplateColumns: "190px 110px minmax(260px, 1fr) minmax(140px, 0.45fr) minmax(110px, 0.35fr)", gap: 12, alignItems: "center", textAlign: "left", padding: "10px 16px", border: 0, borderBottom: "1px solid var(--border-subtle)", borderLeft: "3px solid transparent", background: "transparent", color: "var(--text)", cursor: "pointer" }} onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "transparent"; }}>
            <span style={cellStyle({ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-time)" })}>{formatEvidenceTimestamp(entry.timestamp)}</span>
            <span style={cellStyle({ color: tone, fontWeight: 700, fontSize: 11.5 })}>{FILTER_LABELS[entry.section]}</span>
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "block", ...cellStyle({ fontSize: 13, fontWeight: 700, color: "var(--text)" }) }}>{entry.title}</span>
              {entry.detail && <span style={{ display: "block", marginTop: 2, ...cellStyle({ fontSize: 11.5, color: "var(--text-dim)" }) }}>{entry.detail}</span>}
            </span>
            <span style={cellStyle({ color: entry.attention ? "var(--danger)" : "var(--text-dim)", fontSize: 12 })}>{actionLabel}</span>
            <span style={cellStyle({ color: "var(--text-dim)", fontSize: 12 })}>{resolveAccountDisplay(entry.user, accountDirectory) || "—"}</span>
          </button>;
        })}
        {filtered.length === 0 && <div role="status" style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13, padding: 16 }}>{emptyText}</div>}
      </div>
    </div>
    {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName="Defender" onClose={() => setSelected(null)} onNavigate={(file, column, value) => { setSelected(null); onNavigate?.(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
  </section>;
}
