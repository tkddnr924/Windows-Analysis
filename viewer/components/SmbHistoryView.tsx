"use client";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { bareAccount } from "@/lib/viewShared";

const TABLE = "SmbHistory";
const RESULT_COLOR: Record<string, string> = {
  성공: "var(--success)",
  실패: "var(--danger)",
};

interface Row {
  __rowid?: number;
  timestamp?: string;
  remote_address?: string;
  account?: string;
  result?: string;
  description?: string;
  event_id?: string;
  record_key?: string;
}

interface Peer {
  ip: string;
  attempts: number;
  fail: number;
  success: number;
  accounts: string[];
  first: string;
  last: string;
  events: Row[];
}


interface Props {
  fileName: string;
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
  accountDirectory?: AccountDirectory;
}

type ResultFilter = "all" | "fail" | "success";

/**
 * SMB authentication is represented as individual event records rather than
 * durable sessions. The analyst ledger therefore groups only the navigation
 * surface by source IP, while the expanded rows retain every original event.
 */
export default function SmbHistoryView({
  data,
  onNavigate,
  onFetchLinkedRows,
  bookmarkedRowids,
  onToggleBookmark,
  timeRange = EMPTY_TIME_RANGE,
  accountDirectory,
}: Props) {
  const [query, setQuery] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  // 계정별 체크 필터 — 기본은 전체 표시, 체크 해제한 계정만 숨긴다.
  const [hiddenAccounts, setHiddenAccounts] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);

  const peers = useMemo(() => {
    const byIp = new Map<string, Peer>();
    for (const raw of data.rows as Row[]) {
      const timestamp = raw.timestamp ?? "";
      if (!inRange(timestamp, timeRange)) continue;

      if (hiddenAccounts.has(bareAccount(raw.account ?? ""))) continue;
      const ip = raw.remote_address || "주소 정보 없음";
      const peer = byIp.get(ip) ?? {
        ip,
        attempts: 0,
        fail: 0,
        success: 0,
        accounts: [],
        first: timestamp,
        last: timestamp,
        events: [],
      };
      if (!byIp.has(ip)) byIp.set(ip, peer);

      peer.attempts += 1;
      if (raw.result === "실패") peer.fail += 1;
      if (raw.result === "성공") peer.success += 1;

      const account = bareAccount(raw.account ?? "");
      if (account && !peer.accounts.includes(account)) peer.accounts.push(account);
      if (timestamp) {
        if (!peer.first || timestamp < peer.first) peer.first = timestamp;
        if (!peer.last || timestamp > peer.last) peer.last = timestamp;
      }
      peer.events.push(raw);
    }

    return [...byIp.values()]
      .map((peer) => ({ ...peer, events: peer.events.sort((left, right) => (left.timestamp ?? "").localeCompare(right.timestamp ?? "")) }))
      .sort((left, right) => right.attempts - left.attempts || left.ip.localeCompare(right.ip));
  }, [data.rows, timeRange, hiddenAccounts]);

  const allAccounts = useMemo(
    () => [...new Set((data.rows as Row[]).map((raw) => bareAccount(raw.account ?? "")))].sort((a, b) => a.localeCompare(b)),
    [data.rows],
  );

  const shownPeers = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return peers.filter((peer) => {
      if (resultFilter === "fail" && peer.fail === 0) return false;
      if (resultFilter === "success" && peer.success === 0) return false;
      if (!needle) return true;
      return peer.ip.toLowerCase().includes(needle) || peer.accounts.some((account) => account.toLowerCase().includes(needle));
    });
  }, [peers, query, resultFilter]);

  const eventCount = useMemo(() => shownPeers.reduce((count, peer) => count + peer.attempts, 0), [shownPeers]);

  function toggle(ip: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0, background: "var(--bg)" }}>
      <ViewHeader icon={DnsOutlinedIcon} title="SMB 접속 이력" meta={`${shownPeers.length.toLocaleString()}개 원격 주소 · ${eventCount.toLocaleString()}건`}>
          <HeaderSearchInput value={query} onChange={setQuery} placeholder="원격 주소 · 계정 검색" ariaLabel="SMB 접속 이력 검색" width={300} />
          <AccountFilterChips accounts={allAccounts} hidden={hiddenAccounts} onToggle={(account) => setHiddenAccounts((previous) => { const next = new Set(previous); if (next.has(account)) next.delete(account); else next.add(account); return next; })} onReset={() => setHiddenAccounts(new Set())} accountDirectory={accountDirectory} />
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

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {shownPeers.length === 0 ? (
          <div style={{ padding: 44, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>
            {peers.length === 0 ? "기간 내 SMB 접속 이력이 없습니다." : "검색 또는 필터 조건에 맞는 SMB 접속 이력이 없습니다."}
          </div>
        ) : shownPeers.map((peer) => {
          const open = expanded.has(peer.ip);
          // 접속 결과가 한눈에 보이도록 타일 색으로 신호를 준다: 실패만 있으면
          // danger, 성공이 섞이면 success, 결과 없으면 중립.
          const peerColor = peer.fail > 0 && peer.success === 0 ? "var(--danger)" : peer.success > 0 ? "var(--success)" : "var(--text-dim)";
          const accountsLabel = peer.accounts.length ? peer.accounts.map((account) => resolveAccountDisplay(account, accountDirectory)).join(", ") : "계정 정보 없음";
          const sameDay = peer.first.slice(0, 10) === peer.last.slice(0, 10);
          return (
            <section key={peer.ip} style={{ marginBottom: 10, border: `1px solid ${open ? `color-mix(in srgb, ${peerColor} 42%, var(--border))` : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", overflow: "hidden", transition: "border-color .18s ease" }}>
              <button
                type="button"
                onClick={() => toggle(peer.ip)}
                aria-expanded={open}
                aria-label={`${peer.ip} 접속 이벤트 ${peer.attempts}건 ${open ? "접기" : "펼치기"}`}
                style={{ width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 60, padding: "11px 14px", border: "none", background: open ? `color-mix(in srgb, ${peerColor} 6%, transparent)` : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .18s ease", outlineOffset: -2 }}
                onMouseEnter={(event) => { if (!open) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = open ? `color-mix(in srgb, ${peerColor} 6%, transparent)` : "transparent"; }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${peerColor} 15%, transparent)` }}>
                  <DnsOutlinedIcon sx={{ fontSize: 17, color: peerColor }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{peer.ip}</span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0, color: "var(--text-dim)", fontSize: 12 }}>
                    <span title={accountsLabel} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: peer.accounts.length ? "var(--text-dim)" : "var(--text-faint)" }}>{accountsLabel}</span>
                    <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>·</span>
                    <span style={{ flexShrink: 0, color: "var(--text-faint)" }}>이벤트 {peer.attempts.toLocaleString()}건</span>
                  </span>
                </span>
                <span style={{ display: "flex", gap: 4, alignItems: "center", flexShrink: 0, fontSize: 12 }}>
                  {peer.success > 0 && <ResultPill color="var(--success)">성공 {peer.success.toLocaleString()}</ResultPill>}
                  {peer.fail > 0 && <ResultPill color="var(--danger)">실패 {peer.fail.toLocaleString()}</ResultPill>}
                  {peer.success === 0 && peer.fail === 0 && <span style={{ color: "var(--text-faint)" }}>결과 정보 없음</span>}
                </span>
                <span style={{ flexShrink: 0, color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "nowrap" }}>
                  {peer.first ? (<>{peer.first} <span style={{ color: "var(--text-faint)" }}>→</span> {sameDay ? peer.last.slice(11) : peer.last}</>) : "시간 정보 없음"}
                </span>
                <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 20, color: "var(--text-faint)", flexShrink: 0, transform: open ? "none" : "rotate(-90deg)", transition: "transform .18s ease" }} />
              </button>
              {open && (
                <div role="region" aria-label={`원본 이벤트 ${peer.attempts}건`} style={{ borderTop: "1px solid var(--border-subtle)", background: "var(--bg)" }}>
                  {peer.events.map((event, index) => {
                    const rowid = Number((event as Record<string, unknown>).__rowid);
                    const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                    const resultColor = RESULT_COLOR[event.result ?? ""] ?? "var(--text-faint)";
                    return (
                      <div key={`${rowid}-${event.timestamp}-${index}`} className={bookmarked ? "dfir-bookmarked-row" : undefined} style={{ borderRadius: 0, display: "flex", alignItems: "center", gap: 8, minHeight: 42, padding: "7px 14px 7px 60px", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", transition: "background .15s ease" }} onMouseEnter={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { if (!bookmarked) mouseEvent.currentTarget.style.background = "transparent"; }}>
                        <div role="button" tabIndex={0} onClick={() => setSelected(event as Record<string, string>)} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelected(event as Record<string, string>); } }} style={{ flex: 1, display: "flex", alignItems: "center", gap: 10, minWidth: 0, color: "var(--text)", cursor: "pointer", outlineOffset: 2 }}>
                          <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 12.5, width: 176, flexShrink: 0, whiteSpace: "nowrap" }}>{event.timestamp || "시간 정보 없음"}</span>
                          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, background: resultColor }} />
                          <span style={{ flexShrink: 0, color: resultColor, fontSize: 12, fontWeight: 700, width: 34 }}>{event.result || "정보"}</span>
                          <span title={resolveAccountDisplay(bareAccount(event.account ?? ""), accountDirectory) || "계정 정보 없음"} style={{ width: 150, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: event.account ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12.5 }}>{resolveAccountDisplay(bareAccount(event.account ?? ""), accountDirectory) || "계정 정보 없음"}</span>
                          <span title={event.description || "상세 정보 없음"} style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 12.5 }}>{event.description || "상세 정보 없음"}</span>
                          <span style={{ flexShrink: 0, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{event.event_id ? `EID ${event.event_id}` : ""}</span>
                        </div>
                        {onToggleBookmark && Number.isFinite(rowid) && <button type="button" className={bookmarked ? "dfir-bookmark-control" : undefined} onClick={() => onToggleBookmark(rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          );
        })}
      </main>

      {selected && spec && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
    </div>
  );
}

const clearButtonStyle: React.CSSProperties = {
  position: "absolute",
  right: 5,
  top: "50%",
  transform: "translateY(-50%)",
  display: "inline-flex",
  padding: 2,
  color: "var(--text-faint)",
  border: "none",
  background: "transparent",
  cursor: "pointer",
};

function ResultPill({ color, children }: { color: string; children: React.ReactNode }) {
  return <span style={{ color, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${color} 15%, transparent)`, whiteSpace: "nowrap" }}>{children}</span>;
}
