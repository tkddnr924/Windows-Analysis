"use client";

import { useMemo, useState } from "react";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import { inRange, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

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

function bareAccount(name: string): string {
  if (!name) return "";
  const tail = name.replace(/\//g, "\\").split("\\").pop() ?? name;
  return tail.split("@")[0].trim();
}

function timeSpan(first: string, last: string): string {
  if (!first) return "시간 정보 없음";
  if (!last || first === last) return first;
  return `${first} ~ ${last}`;
}

interface Props {
  fileName: string;
  data: CsvData;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
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
}: Props) {
  const [query, setQuery] = useState("");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Record<string, string> | null>(null);
  const spec = getArtifactView(TABLE);

  const peers = useMemo(() => {
    const byIp = new Map<string, Peer>();
    for (const raw of data.rows as Row[]) {
      const timestamp = raw.timestamp ?? "";
      if (!inRange(timestamp, timeRange)) continue;

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
  }, [data.rows, timeRange]);

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
      <header style={{ flexShrink: 0, padding: "12px 16px 10px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
          <strong style={{ fontSize: 15, color: "var(--text)" }}>SMB 접속 이력</strong>
          <span style={{ color: "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" }}>{shownPeers.length.toLocaleString()}개 원격 주소 · {eventCount.toLocaleString()}건</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 9, flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 260px", maxWidth: 430 }}>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="원격 주소 · 계정 검색"
              aria-label="SMB 접속 이력 검색"
              onFocus={(event) => { event.currentTarget.style.borderColor = "var(--accent)"; event.currentTarget.style.boxShadow = "0 0 0 2px var(--accent-subtle)"; }}
              onBlur={(event) => { event.currentTarget.style.borderColor = "var(--border)"; event.currentTarget.style.boxShadow = "none"; }}
              style={{ width: "100%", height: 31, padding: "0 31px 0 10px", fontSize: 12, fontFamily: "var(--mono)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", color: "var(--text)", background: "var(--bg-elevated)", outline: "none" }}
            />
            {query && <button type="button" onClick={() => setQuery("")} aria-label="검색어 지우기" style={clearButtonStyle}><CloseOutlinedIcon sx={{ fontSize: 16 }} /></button>}
          </div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            {([
              ["전체", "all", "var(--accent)"],
              ["실패 포함", "fail", "var(--danger)"],
              ["성공 포함", "success", "var(--success)"],
            ] as const).map(([label, value, color]) => {
              const active = resultFilter === value;
              return <button key={value} type="button" onClick={() => setResultFilter(value)} aria-pressed={active} style={{ height: 30, padding: "0 10px", fontSize: 11.5, fontWeight: active ? 700 : 550, color: active ? color : "var(--text-dim)", background: active ? `color-mix(in srgb, ${color} 13%, transparent)` : "transparent", border: `1px solid ${active ? color : "var(--border)"}`, borderRadius: "var(--radius-sm)", cursor: "pointer" }}>{label}</button>;
            })}
          </div>
        </div>
      </header>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
        <div style={{ minWidth: 720, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", overflow: "hidden", background: "var(--bg-panel)" }}>
          {shownPeers.length > 0 && <div style={{ display: "grid", gridTemplateColumns: "32px minmax(140px, .8fr) minmax(150px, .9fr) minmax(210px, 1.35fr) minmax(170px, 1.05fr) minmax(118px, .7fr) 50px", gap: 8, alignItems: "center", padding: "8px 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span /><span>원격 주소</span><span>시도 계정</span><span>관찰 시간</span><span>결과</span><span style={{ textAlign: "right" }}>이벤트</span><span /></div>}
          {shownPeers.length === 0 ? <div style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>{peers.length === 0 ? "기간 내 SMB 접속 이력이 없습니다." : "검색 또는 필터 조건에 맞는 SMB 접속 이력이 없습니다."}</div> : shownPeers.map((peer) => {
            const open = expanded.has(peer.ip);
            return <section key={peer.ip} style={{ borderTop: "1px solid var(--border-subtle)" }}>
              <button
                type="button"
                onClick={() => toggle(peer.ip)}
                aria-expanded={open}
                style={{ width: "100%", display: "grid", gridTemplateColumns: "32px minmax(140px, .8fr) minmax(150px, .9fr) minmax(210px, 1.35fr) minmax(170px, 1.05fr) minmax(118px, .7fr) 50px", gap: 8, alignItems: "center", padding: "10px 12px", color: "var(--text)", border: "none", background: "transparent", cursor: "pointer", textAlign: "left", outlineOffset: -2 }}
                onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
              >
                {open ? <KeyboardArrowDownOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon aria-hidden="true" sx={{ fontSize: 18, color: "var(--text-faint)" }} />}
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700 }}>{peer.ip}</span>
                <span title={peer.accounts.join(", ") || "계정 정보 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: peer.accounts.length ? "var(--text-dim)" : "var(--text-faint)", fontSize: 11.5 }}>{peer.accounts.length ? peer.accounts.join(", ") : "계정 정보 없음"}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{timeSpan(peer.first, peer.last)}</span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5, minWidth: 0, fontSize: 10.5 }}>
                  {peer.success > 0 && <ResultPill color="var(--success)">성공 {peer.success.toLocaleString()}</ResultPill>}
                  {peer.fail > 0 && <ResultPill color="var(--danger)">실패 {peer.fail.toLocaleString()}</ResultPill>}
                  {peer.success === 0 && peer.fail === 0 && <span style={{ color: "var(--text-faint)" }}>결과 정보 없음</span>}
                </span>
                <span style={{ textAlign: "right", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{peer.attempts.toLocaleString()}건</span>
                <span />
              </button>
              {open && <div style={{ borderTop: "1px solid var(--border-subtle)", background: "color-mix(in srgb, var(--bg-elevated) 34%, transparent)" }}>
                <div style={{ display: "grid", gridTemplateColumns: "170px 80px minmax(130px, .6fr) minmax(250px, 1.45fr) 68px 32px", gap: 8, padding: "6px 12px 6px 44px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-faint)", fontSize: 10, fontWeight: 700 }}><span>시간</span><span>결과</span><span>계정</span><span>이벤트</span><span>Event ID</span><span /></div>
                {peer.events.map((event, index) => {
                  const rowid = Number((event as Record<string, unknown>).__rowid);
                  const bookmarked = Number.isFinite(rowid) && (bookmarkedRowids?.has(rowid) ?? false);
                  const rowBackground = bookmarked ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent";
                  const resultColor = RESULT_COLOR[event.result ?? ""] ?? "var(--text-faint)";
                  return <div key={`${rowid}-${event.timestamp}-${index}`} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 32px", gap: 8, alignItems: "center", minHeight: 36, padding: "6px 12px 6px 44px", background: rowBackground, boxShadow: bookmarked ? "inset 3px 0 0 var(--accent)" : undefined }} onMouseEnter={(mouseEvent) => { mouseEvent.currentTarget.style.background = "var(--bg-hover)"; }} onMouseLeave={(mouseEvent) => { mouseEvent.currentTarget.style.background = rowBackground; }}>
                    <div role="button" tabIndex={0} onClick={() => setSelected(event as Record<string, string>)} onKeyDown={(keyboardEvent) => { if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") { keyboardEvent.preventDefault(); setSelected(event as Record<string, string>); } }} style={{ display: "grid", gridTemplateColumns: "170px 80px minmax(130px, .6fr) minmax(250px, 1.45fr) 68px", gap: 8, alignItems: "center", minWidth: 0, color: "var(--text)", cursor: "pointer", outlineOffset: 2 }}>
                      <span style={{ color: "var(--text-time)", fontFamily: "var(--mono)", fontSize: 11.5, whiteSpace: "nowrap" }}>{event.timestamp || "시간 정보 없음"}</span>
                      <span style={{ color: resultColor, fontSize: 11.5, fontWeight: 700 }}>{event.result || "정보"}</span>
                      <span title={bareAccount(event.account ?? "") || "계정 정보 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: event.account ? "var(--text-dim)" : "var(--text-faint)", fontSize: 11.5 }}>{bareAccount(event.account ?? "") || "계정 정보 없음"}</span>
                      <span title={event.description || "상세 정보 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 11.5 }}>{event.description || "상세 정보 없음"}</span>
                      <span style={{ color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{event.event_id || "—"}</span>
                    </div>
                    {onToggleBookmark && Number.isFinite(rowid) && <button type="button" onClick={() => onToggleBookmark(rowid)} aria-label={bookmarked ? "북마크 해제" : "북마크 추가"} title={bookmarked ? "북마크 해제" : "북마크 추가"} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 26, height: 26, padding: 0, border: "none", background: "transparent", color: bookmarked ? "var(--accent)" : "var(--text-faint)", cursor: "pointer" }}>{bookmarked ? <BookmarkOutlinedIcon sx={{ fontSize: 16 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 16 }} />}</button>}
                  </div>;
                })}
              </div>}
            </section>;
          })}
        </div>
      </main>

      {selected && spec && <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={TABLE} onClose={() => setSelected(null)} onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }} onFetchLinkedRows={onFetchLinkedRows} isBookmarked={onToggleBookmark ? bookmarkedRowids?.has(Number((selected as Record<string, unknown>).__rowid)) ?? false : undefined} onToggleBookmark={onToggleBookmark ? () => onToggleBookmark(Number((selected as Record<string, unknown>).__rowid)) : undefined} />}
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
