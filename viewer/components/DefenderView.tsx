"use client";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { EMPTY_TIME_RANGE, formatEvidenceTimestamp, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
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
  // 시간순 정렬 — 기본은 오래된 순(오름차순).
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
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
    const kept = periodEntries.filter((entry) => {
      if (filter !== "all" && entry.section !== filter) return false;
      if (hiddenAccounts.has(entry.user || "")) return false;
      return !query || [entry.title, entry.detail, entry.action, entry.user, entry.row.process || "", entry.row.category || ""].some((value) => value.toLocaleLowerCase().includes(query));
    });
    // 시각 없는 기록은 정렬 방향과 무관하게 뒤로 보낸다.
    return kept.sort((left, right) => {
      if (!left.timestamp || !right.timestamp) return left.timestamp ? -1 : right.timestamp ? 1 : 0;
      const compare = left.timestamp.localeCompare(right.timestamp);
      return sortDir === "asc" ? compare : -compare;
    });
  }, [filter, hiddenAccounts, periodEntries, search, sortDir]);

  useEffect(() => setSelected(null), [filter, search, timeRange.end, timeRange.start]);
  const emptyText = rangeOn && periodEntries.length === 0 ? "기간 필터 내 Microsoft Defender 활동이 없습니다." : sourceEntries.length === 0 ? "Microsoft Defender 활동이 없습니다." : "검색·필터 조건에 일치하는 Microsoft Defender 활동이 없습니다.";

  return <section className="dfir-view" aria-labelledby="defender-title" style={{ flex: 1, minHeight: 0, minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
    <ViewHeader icon={ShieldOutlinedIcon} title="Microsoft Defender 활동" meta={<>{counts.all.toLocaleString()}건{latestProtection && <span style={{ marginLeft: 8, color: latestProtection.attention ? "var(--danger)" : "var(--text-dim)", fontFamily: "var(--sans)" }}>마지막 보호 상태 기록: {latestProtection.title}</span>}</>} right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "전역 기간 필터 적용" : "전체 기간"}</span>} titleId="defender-title">
        <HeaderSearchInput value={search} onChange={setSearch} placeholder="위협명 · 조치 · 경로 · 사용자 검색" ariaLabel="Microsoft Defender 활동 검색" width={300} />
        <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account: string) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
        <SortDropdown value={sortDir} onChange={(next) => setSortDir(next as "asc" | "desc")} />
        <SelectDropdown
          icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
          label="구분"
          options={(Object.keys(FILTER_LABELS) as Filter[]).map((key) => ({ value: key, label: FILTER_LABELS[key], count: counts[key] }))}
          value={filter}
          onChange={(next) => setFilter(next as Filter)}
        />
      
      </ViewHeader>

    <main role="region" aria-label="Microsoft Defender 활동 원장" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
      {filtered.map((entry) => {
        const bookmarked = Number.isFinite(entry.rowid) && bookmarkedRowids?.has(entry.rowid);
        // 타일·배지 색이 상태 신호: 주의 필요=danger, 보호 상태=warning,
        // 검사=accent, 무력화된 탐지=success.
        const tone = entry.attention ? "var(--danger)" : entry.section === "protection" ? "var(--warning)" : entry.section === "scan" ? "var(--accent)" : "var(--success)";
        const actionLabel = entry.action || (entry.section === "threat" ? "조치 확인 필요" : "조치 이벤트 미확인");
        return (
          <button key={`${entry.rowid}-${entry.timestamp}-${entry.title}`} type="button" className={bookmarked ? "dfir-bookmarked-row" : undefined} onClick={() => setSelected(entry)} aria-label={`${entry.title} 상세 보기`} style={{ borderRadius: "var(--radius-md)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .15s ease, border-color .15s ease" }} onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}>
            <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
              <ShieldOutlinedIcon sx={{ fontSize: 17, color: tone }} />
            </span>
            <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                <span style={cellStyle({ fontSize: 13.5, fontWeight: 700, color: "var(--text)" })}>{entry.title}</span>
                <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: tone, border: `1px solid ${tone}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{FILTER_LABELS[entry.section]}</span>
                {entry.row.source && <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 700, color: "var(--text-dim)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "1px 7px", whiteSpace: "nowrap" }}>{entry.row.source}</span>}
              </span>
              {entry.detail && <span title={entry.detail} style={cellStyle({ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)" })}>{entry.detail}</span>}
            </span>
            <span title={actionLabel} style={cellStyle({ width: 168, flexShrink: 0, color: entry.attention ? "var(--danger)" : "var(--text-dim)", fontSize: 12, fontWeight: entry.attention ? 700 : 500 })}>{actionLabel}</span>
            <span style={cellStyle({ width: 128, flexShrink: 0, color: entry.user ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12 })}>{resolveAccountDisplay(entry.user, accountDirectory) || "계정 정보 없음"}</span>
            <span style={{ width: 172, flexShrink: 0, textAlign: "right", fontFamily: "var(--mono)", fontSize: 12.5, color: entry.timestamp ? "var(--text-time)" : "var(--text-faint)", whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(entry.timestamp) || "시간 정보 없음"}</span>
          </button>
        );
      })}
      {filtered.length === 0 && <div role="status" style={{ minHeight: 180, display: "grid", placeItems: "center", color: "var(--text-faint)", fontSize: 13, padding: 16 }}>{emptyText}</div>}
    </main>
    {selected && <RowDetailPanel row={selected.row} columns={data.columns} focusedColumn={null} fileBaseName="Defender" onClose={() => setSelected(null)} onNavigate={(file, column, value) => { setSelected(null); onNavigate?.(file, column, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark && Number.isFinite(selected.rowid) ? bookmarkedRowids?.has(selected.rowid) ?? false : undefined} onToggleBookmark={onToggleBookmark && Number.isFinite(selected.rowid) ? () => onToggleBookmark(selected.rowid) : undefined} />}
  </section>;
}
