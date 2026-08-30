"use client";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import SwapHorizOutlinedIcon from "@mui/icons-material/SwapHorizOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import CallReceivedIcon from "@mui/icons-material/CallReceived";
import CallMadeIcon from "@mui/icons-material/CallMade";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { formatEvidenceTimestamp, inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { bareAccount, tsMs } from "@/lib/viewShared";

// A gap longer than this between consecutive events of the same peer starts a
// new session. RDP sessions cluster their connect/logon/reconnect/disconnect
// events within a short window; 10 minutes keeps a burst together without
// merging unrelated activity hours apart.
const SESSION_GAP_MS = 10 * 60 * 1000;

const DIRECTION_LABEL: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드" };
// 인바운드/아웃바운드는 프로그램 기본 블루와 겹치지 않는 오렌지/퍼플 조합으로 구분한다.
const DIRECTION_COLOR: Record<string, string> = { inbound: "#f2a86f", outbound: "#9b7ef8" };
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

function clusterSessions(data: CsvData, timeRange: TimeRange): Session[] {
  const events: FlowEvent[] = data.rows
    .map((row) => ({
      row,
      rowid: Number((row as unknown as Record<string, unknown>).__rowid),
      timestamp: row.timestamp ?? "",
      direction: row.direction ?? "",
      remote_address: row.remote_address ?? "",
      account: bareAccount(row.account ?? ""),
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
    // A peer can produce adjacent sessions for different principals. Do not
    // inherit the first account across a later account (or blank-account)
    // event just because it shares the same IP and falls within the gap.
    const accountConflict = e.account.toLocaleLowerCase() !== (cur?.account ?? "").toLocaleLowerCase();
    const isNew =
      !cur || cur.direction !== e.direction || addrConflict || accountConflict || (Number.isFinite(t) && Number.isFinite(lastMs) && t - lastMs > SESSION_GAP_MS);

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
  /** IP -> host for the whole case, so a remote IP that is a registered host
   * shows the host name. Empty until the case network map is loaded. */
  hostIpMap?: Record<string, { id: string; name: string }>;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

type ResultFilter = "all" | "success" | "fail";

export default function SessionFlowView({
  fileName,
  data,
  hostIpMap = {},
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
  accountDirectory,
}: SessionFlowViewProps) {
  const isSmb = fileName === "SmbHistory";
  const [dirFilter, setDirFilter] = useState<string | undefined>(undefined);
  // RDP는 성공 세션이 분석 출발점이라 결과 필터 기본값을 성공으로 둔다. SMB는 전체 유지.
  const [resultFilter, setResultFilter] = useState<ResultFilter>(isSmb ? "all" : "success");
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(fileName);
  const allSessions = useMemo(() => clusterSessions(data, timeRange), [data, timeRange]);
  const accounts = useMemo(
    () => [...new Set(allSessions.map((s) => s.account))].sort((a, b) => a.localeCompare(b)),
    [allSessions],
  );

  const sessions = useMemo(() => {
    const q = query.trim().toLowerCase();
    return allSessions.filter((s) => {
      if (dirFilter && s.direction !== dirFilter) return false;
      if (hiddenAccounts.has(s.account)) return false;
      if (resultFilter === "success" && s.success === 0) return false;
      if (resultFilter === "fail" && s.fail === 0) return false;
      if (q && !s.remote_address.toLowerCase().includes(q) && !s.account.toLowerCase().includes(q) && !(hostIpMap[s.remote_address]?.name.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [allSessions, dirFilter, hiddenAccounts, resultFilter, query, hostIpMap]);

  function toggle(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }


  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <ViewHeader icon={DesktopWindowsOutlinedIcon} title={isSmb ? "SMB 연결 이력" : "원격 접근 이력 (RDP)"} meta={`${sessions.length.toLocaleString()}개 세션`}>
          <HeaderSearchInput value={query} onChange={setQuery} placeholder="IP 또는 계정 검색" width={300} />
          {!isSmb && accounts.length > 0 && (
            <AccountFilterChips
              accounts={accounts}
              hidden={hiddenAccounts}
              onToggle={(account) => setHiddenAccounts((previous) => {
                const next = new Set(previous);
                if (next.has(account)) next.delete(account);
                else next.add(account);
                return next;
              })}
              onReset={() => setHiddenAccounts(new Set())}
              accountDirectory={accountDirectory}
            />
          )}
          <SelectDropdown
            icon={<SwapHorizOutlinedIcon sx={{ fontSize: 15 }} />}
            label="방향"
            options={[
              { value: "all", label: "전체" },
              { value: "inbound", label: "인바운드", color: DIRECTION_COLOR.inbound },
              { value: "outbound", label: "아웃바운드", color: DIRECTION_COLOR.outbound },
            ]}
            value={dirFilter ?? "all"}
            onChange={(next) => setDirFilter(next === "all" ? undefined : next)}
          />
          <SelectDropdown
            icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />}
            label="결과"
            options={[
              { value: "all", label: "전체" },
              { value: "success", label: "성공", color: "var(--success)" },
              { value: "fail", label: "실패", color: "var(--danger)" },
            ]}
            value={resultFilter}
            onChange={(next) => setResultFilter(next as ResultFilter)}
          />
      </ViewHeader>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {sessions.length === 0 && (
          <div style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>
            {allSessions.length === 0 ? "세션이 없습니다." : "조건에 맞는 세션이 없습니다."}
          </div>
        )}
        {sessions.map((s) => {
          const open = expanded.has(s.key);
          const dirColor = DIRECTION_COLOR[s.direction] ?? "var(--text-dim)";
          const DirIcon = s.direction === "inbound" ? CallReceivedIcon : CallMadeIcon;
          const registeredHost = hostIpMap[s.remote_address];
          const accountLabel = resolveAccountDisplay(s.account, accountDirectory) || "계정 정보 없음";
          const sameDay = s.start.slice(0, 10) === s.end.slice(0, 10);
          return (
            <section key={s.key} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${dirColor} 48%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
              <button
                type="button"
                onClick={() => toggle(s.key)}
                aria-expanded={open}
                aria-label={`${DIRECTION_LABEL[s.direction] ?? s.direction} ${registeredHost ? registeredHost.name : s.remote_address || "주소 없음"} 세션의 이벤트 ${s.events.length}건 ${open ? "접기" : "펼치기"}`}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .18s ease", outlineOffset: -2 }}
                onMouseEnter={(e) => { if (!open) e.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = open ? `color-mix(in srgb, ${dirColor} 7%, transparent)` : "transparent"; }}
                onFocus={(e) => { e.currentTarget.style.outline = "2px solid var(--accent)"; }}
                onBlur={(e) => { e.currentTarget.style.outline = "none"; }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${dirColor} 16%, transparent)` }}>
                  <DirIcon sx={{ fontSize: 17, color: dirColor }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span title={registeredHost ? `등록 호스트: ${registeredHost.name} (${s.remote_address})` : s.remote_address || "주소 없음"} style={{ display: "flex", alignItems: "baseline", gap: 8, minWidth: 0 }}>
                    {registeredHost ? (
                      <>
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: "var(--host-registered-text)" }}>{registeredHost.name}</span>
                        <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)" }}>{s.remote_address}</span>
                      </>
                    ) : (
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{s.remote_address || "(주소 없음)"}</span>
                    )}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: s.account ? "var(--text-dim)" : "var(--text-faint)" }}>{accountLabel}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {s.events.length.toLocaleString()}건</span>
                  </span>
                </span>
                <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", borderRadius: "var(--radius-sm)", color: dirColor, border: `1px solid ${dirColor}`, whiteSpace: "nowrap" }}>
                  {DIRECTION_LABEL[s.direction] ?? s.direction}
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0 }}>
                  {s.success > 0 && <Pill color="var(--success)">성공 {s.success}</Pill>}
                  {s.fail > 0 && <Pill color="var(--danger)">실패 {s.fail}</Pill>}
                </span>
                <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {formatEvidenceTimestamp(s.start)} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? formatEvidenceTimestamp(s.end).slice(11) : formatEvidenceTimestamp(s.end)}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label={`원본 이벤트 ${s.events.length}건`} style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {s.events.map((ev, i) => {
                    const bm = (bookmarkedRowids?.has(ev.rowid) ?? false) && Number.isFinite(ev.rowid);
                    return (
                    <div
                      key={i}
                      className={bm ? "dfir-bookmarked-row" : undefined}
                      style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 10, minHeight: 44, padding: "8px 14px 8px 60px", borderTop: i === 0 ? "none" : "1px solid var(--border-subtle)", fontSize: 13, background: "transparent", transition: "background .15s ease" }}
                      onMouseEnter={(e) => { if (!bm) e.currentTarget.style.background = "var(--bg-hover)"; }}
                      onMouseLeave={(e) => { if (!bm) e.currentTarget.style.background = "transparent"; }}
                    >
                      <button
                        type="button"
                        onClick={() => setSelected(ev.row)}
                        aria-label={`${formatEvidenceTimestamp(ev.timestamp)} ${ev.description || "원본 이벤트"} 상세 보기`}
                        style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, padding: 0, border: "none", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: "inherit", outlineOffset: 2 }}
                      >
                        <span style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text-time)", width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{formatEvidenceTimestamp(ev.timestamp)}</span>
                        <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: RESULT_COLOR[ev.result] ?? "var(--text-faint)" }} />
                        {ev.result && <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: RESULT_COLOR[ev.result] ?? "var(--text-faint)" }}>{ev.result}</span>}
                        <span title={ev.description} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ev.description}</span>
                        {ev.account && ev.account !== s.account && <span style={{ flexShrink: 0, color: "var(--text-dim)", fontSize: 12 }}>{resolveAccountDisplay(ev.account, accountDirectory)}</span>}
                      </button>
                      {onToggleBookmark && Number.isFinite(ev.rowid) && (
                        <button
                          type="button"
                          onClick={() => onToggleBookmark(ev.rowid)}
                          title={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크에 추가"}
                          aria-label={bookmarkedRowids?.has(ev.rowid) ? "북마크 해제" : "북마크"}
                          className={bookmarkedRowids?.has(ev.rowid) ? "dfir-bookmark-control" : undefined}
                          style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", cursor: "pointer", color: bookmarkedRowids?.has(ev.rowid) ? "var(--bookmark-control)" : "var(--text-faint)" }}
                        >
                          {bookmarkedRowids?.has(ev.rowid) ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}
                        </button>
                      )}
                    </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </div>

      {selected && spec && (
        <RowDetailPanel
          row={selected}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName={fileName}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => {
            setSelected(null);
            onNavigate(targetFile, targetColumn, value);
          }}
          onFetchLinkedRows={onFetchLinkedRows}
          accountDirectory={accountDirectory}
          isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined}
          onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined}
        />
      )}
    </div>
  );
}

function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span style={{ color, fontSize: 12, fontWeight: 700, padding: "2px 7px", borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
      {children}
    </span>
  );
}

