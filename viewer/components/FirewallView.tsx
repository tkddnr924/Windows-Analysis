"use client";
import SecurityOutlinedIcon from "@mui/icons-material/SecurityOutlined";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import PaginationControls from "@/components/PaginationControls";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { bareAccount } from "@/lib/viewShared";

const TABLE = "FirewallHistory";
const PAGE = 10;
// 카드 타일·유형 뱃지 색 — 규칙 추가는 성공(눈에 띄어야 할 새 정책), 삭제·차단·
// 서비스 중지는 위험, 변경은 주의, 나머지는 중립.
const KIND_COLOR: Record<string, string> = {
  "규칙 추가": "var(--success)",
  "규칙 변경": "var(--warning)",
  "규칙 삭제": "var(--danger)",
  "모든 규칙 삭제": "var(--danger)",
  "수신 차단": "var(--danger)",
  "서비스 중지": "var(--danger)",
  "설정 변경": "var(--text-dim)",
  "프로필 전환": "var(--text-dim)",
};
const DIRECTION_COLOR: Record<string, string> = {
  인바운드: "#f2a86f",
  아웃바운드: "#9b7ef8",
};
const ACTION_COLOR: Record<string, string> = {
  허용: "var(--success)",
  "보안 허용": "var(--success)",
  차단: "var(--danger)",
};

interface Row {
  __rowid?: number;
  timestamp?: string;
  kind?: string;
  rule_name?: string;
  rule_id?: string;
  app_path?: string;
  service?: string;
  direction?: string;
  action?: string;
  protocol?: string;
  local_ports?: string;
  remote_ports?: string;
  profiles?: string;
  account?: string;
  modifying_app?: string;
  detail?: string;
  event_id?: string;
  provider?: string;
  record_key?: string;
}

interface Props {
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

export default function FirewallView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
  accountDirectory,
}: Props) {
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [sortDir, setSortDir] = useState("asc");
  const [page, setPage] = useState(0);
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);

  const inRangeRows = useMemo(
    () => (data.rows as Row[]).filter((row) => inRange(row.timestamp ?? "", timeRange) && !hiddenAccounts.has(bareAccount(row.account ?? ""))),
    [data.rows, timeRange, hiddenAccounts],
  );

  const allAccounts = useMemo(
    () => [...new Set((data.rows as Row[]).map((row) => bareAccount(row.account ?? "")))].filter(Boolean).sort((a, b) => a.localeCompare(b)),
    [data.rows],
  );

  const kindOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of inRangeRows) counts.set(row.kind || "(유형 없음)", (counts.get(row.kind || "(유형 없음)") ?? 0) + 1);
    return [
      { value: "all", label: "전체", count: inRangeRows.length },
      ...[...counts.entries()].sort((a, b) => b[1] - a[1]).map(([kind, count]) => ({ value: kind, label: kind, count, color: KIND_COLOR[kind] })),
    ];
  }, [inRangeRows]);

  const shown = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = inRangeRows.filter((row) => {
      if (kindFilter !== "all" && (row.kind || "(유형 없음)") !== kindFilter) return false;
      if (!needle) return true;
      return [row.rule_name, row.app_path, row.account, row.modifying_app, row.local_ports, row.remote_ports, row.detail]
        .some((value) => (value ?? "").toLowerCase().includes(needle));
    });
    return filtered.sort((left, right) => {
      const compared = (left.timestamp || "￿").localeCompare(right.timestamp || "￿");
      return sortDir === "asc" ? compared : -compared;
    });
  }, [inRangeRows, query, kindFilter, sortDir]);

  const pageCount = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const paged = shown.slice(safePage * PAGE, safePage * PAGE + PAGE);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0, background: "var(--bg)" }}>
      <ViewHeader icon={SecurityOutlinedIcon} title="방화벽 이력" meta={`${shown.length.toLocaleString()}건`}>
        <HeaderSearchInput value={query} onChange={(next) => { setPage(0); setQuery(next); }} placeholder="규칙 · 경로 · 계정 · 포트 검색" ariaLabel="방화벽 이력 검색" width={300} />
        <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
        <SortDropdown value={sortDir} onChange={setSortDir} />
        <SelectDropdown
          icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
          label="유형"
          options={kindOptions}
          value={kindFilter}
          onChange={(next) => { setPage(0); setKindFilter(next); }}
        />
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {shown.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {inRangeRows.length === 0 ? "기간 내 방화벽 이력이 없습니다." : "검색 또는 필터 조건에 맞는 방화벽 이력이 없습니다."}
          </div>
        ) : paged.map((row, index) => {
          const rowid = Number((row as Record<string, unknown>).__rowid);
          const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
          const kindColor = KIND_COLOR[row.kind ?? ""] ?? "var(--text-dim)";
          const title = row.rule_name || row.detail || "(규칙 이름 없음)";
          const detailLine = row.detail && row.detail !== title ? row.detail : "";
          const line2 = row.app_path || row.modifying_app || detailLine;
          const ports = [row.protocol, row.local_ports && `로컬 ${row.local_ports}`, row.remote_ports && `원격 ${row.remote_ports}`].filter(Boolean).join(" · ");
          const accountLabel = row.account ? resolveAccountDisplay(bareAccount(row.account), accountDirectory) : "";
          return (
            <div key={`${rowid}-${index}`} className={bookmarked ? "dfir-bookmarked-row" : undefined}
              onMouseEnter={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(event) => { if (!bookmarked) event.currentTarget.style.background = "var(--bg-panel)"; }}
              style={{ display: "flex", alignItems: "center", gap: 10, minHeight: 58, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", transition: "background .15s ease, border-color .15s ease" }}>
              <div role="button" tabIndex={0} onClick={() => setSelected(row as Record<string, string>)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(row as Record<string, string>); } }} aria-label={`${title} 상세 보기`} style={{ flex: 1, display: "flex", alignItems: "center", gap: 12, minWidth: 0, cursor: "pointer", outlineOffset: -2 }}>
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${kindColor} 15%, transparent)` }}>
                  <SecurityOutlinedIcon sx={{ fontSize: 17, color: kindColor }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                    <span title={title} style={{ minWidth: 0, fontSize: 13.5, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</span>
                    {row.kind && <Pill color={kindColor}>{row.kind}</Pill>}
                    {row.direction && <Pill color={DIRECTION_COLOR[row.direction] ?? "var(--text-dim)"}>{row.direction}</Pill>}
                    {row.action && <Pill color={ACTION_COLOR[row.action] ?? "var(--text-dim)"}>{row.action}</Pill>}
                  </span>
                  {(line2 || ports) && (
                    <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, fontSize: 12, color: "var(--text-dim)" }}>
                      {line2 && <span title={line2} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{line2}</span>}
                      {line2 && ports && <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>}
                      {ports && <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{ports}</span>}
                    </span>
                  )}
                </span>
                {accountLabel && <span title={accountLabel} style={{ flexShrink: 0, maxWidth: 130, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: "var(--text-dim)" }}>{accountLabel}</span>}
                <span style={{ flexShrink: 0, width: 172, textAlign: "right", color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, whiteSpace: "nowrap" }}>{row.timestamp || "시간 정보 없음"}</span>
              </div>
              {onToggleBookmark && Number.isFinite(rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={() => onToggleBookmark(rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
            </div>
          );
        })}
        {shown.length > 0 && (
          <PaginationControls
            ariaLabel="방화벽 이력 페이지"
            page={safePage}
            pageCount={pageCount}
            onChange={setPage}
            summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, shown.length).toLocaleString()} / ${shown.length.toLocaleString()})`}
          />
        )}
      </main>

      {selected && spec && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
    </div>
  );
}

function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{children}</span>;
}
