"use client";

import { useEffect, useState } from "react";
import type { Bookmark, FetchLinkedRows, Host, ResultRow } from "@/lib/types";
import { getArtifactView, resolveArtifactView } from "@/lib/artifactViews";
import TagList from "./TagList";
import RowDetailPanel from "./RowDetailPanel";

interface BookmarksViewProps {
  bookmarks: Bookmark[];
  hosts: Host[];
  hostIpMap: Record<string, { id: string; name: string }>;
  currentHostId: string | null;
  onRemove: (bookmark: Bookmark) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
}

// Bookmark entries retain their source SQLite path. BrowserActivity cache
// bodies live one host-directory above ANALYSIS_OVERVIEW/BROWSER, so derive
// that directory instead of relying on whichever host happens to be selected.
function hostDirFromResultPath(fullPath: string): string | undefined {
  const normalized = fullPath.replace(/\\/g, "/");
  const match = normalized.match(/^(.*)\/(?:ANALYSIS_OVERVIEW|BROWSER)\//i);
  return match?.[1];
}

function SortChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "2px 9px",
        borderRadius: 999,
        border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
        background: active ? "var(--accent-subtle)" : "transparent",
        color: active ? "var(--accent)" : "var(--text-dim)",
        fontSize: 11,
        cursor: "pointer",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </button>
  );
}

export default function BookmarksView({ bookmarks, hosts, hostIpMap, currentHostId, onRemove, onNavigate, onFetchLinkedRows }: BookmarksViewProps) {
  // Clicking a bookmark opens the shared detail panel (same everywhere), built
  // from the cached source row — not a jump to the source tab.
  const [detail, setDetail] = useState<{ bookmark: Bookmark; row: Record<string, string>; columns: string[] } | null>(null);
  // Bookmarks are case-shared; resolve which host each belongs to (stored, or
  // derived from the .sqlite path for bookmarks saved before host attribution).
  const hostOf = (b: Bookmark): { id: string; name: string } => {
    if (b.hostId || b.hostName) return { id: b.hostId ?? "", name: b.hostName || b.hostId || "(알 수 없는 호스트)" };
    const h = hosts.find((x) => b.fullPath.startsWith(x.dir));
    return { id: h?.id ?? "", name: h?.name ?? "(알 수 없는 호스트)" };
  };
  const [rowCache, setRowCache] = useState<Record<string, ResultRow>>({});
  // Bookmarks are the analyst's shortlist of key events; reading them oldest →
  // newest by when each event happened reconstructs the incident timeline. That
  // "event time" needs the source row, so it's resolved here (against rowCache)
  // rather than sorting on the bookmark's own taggedAt.
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [viewMode, setViewMode] = useState<"timeline" | "sequence">("timeline");
  // Resolve exactly the bookmarked row.  Loading whole BrowserActivity or
  // Registry tables here made an 8-item bookmark list appear to hang.
  useEffect(() => {
    const keyOf = (b: Bookmark) => `${b.fullPath}\u0000${b.tableName}#${b.rowid}`;
    const missing = [...bookmarks.reduce((unique, b) => {
      const key = keyOf(b);
      if (rowCache[key] === undefined) unique.set(key, b);
      return unique;
    }, new Map<string, Bookmark>()).values()];
    if (missing.length === 0) return;
    let cancelled = false;
    Promise.all(missing.map(async (b) => {
      const key = keyOf(b);
      try { return [key, await window.api.resultRow(b.fullPath, b.tableName, b.rowid)] as const; }
      catch { return [key, { columns: [] as string[], row: null }] as const; }
    })).then((pairs) => {
      if (cancelled) return;
      setRowCache((prev) => {
        const next = { ...prev };
        for (const [key, data] of pairs) next[key] = data;
        return next;
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => { cancelled = true; };
  }, [bookmarks]);

  if (bookmarks.length === 0) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-faint)", gap: 8 }}>
        <span style={{ fontSize: 32 }}>🔖</span>
        <span>북마크한 항목이 없습니다.</span>
        <span style={{ fontSize: 11.5 }}>아무 테이블에서나 ☆ 아이콘을 클릭해 의심 항목을 표시하세요.</span>
      </div>
    );
  }

  // Resolve each bookmark to its source row + event time, then order by that
  // time. Rows still loading (or missing) have no event time and sink to the
  // bottom so the loaded, placeable events read as a clean chronology.
  const entries = bookmarks.map((bookmark) => {
    const data = rowCache[`${bookmark.fullPath}\u0000${bookmark.tableName}#${bookmark.rowid}`];
    const loaded = data !== undefined;
    const row = data?.row ?? undefined;
    const columns = data?.columns ?? [];
    const spec = resolveArtifactView(bookmark.tableName, columns) ?? getArtifactView(bookmark.tableName);
    // A field-scoped bookmark (e.g. $MFT SI-Created) reads its time from that
    // field; others use the artifact's timeline/timestamp column.
    const eventTime = row ? ((bookmark.field ? row[bookmark.field] : row[spec?.timelineField ?? "timestamp"] || row.timestamp) || "") : "";
    return { bookmark, row, columns, spec, eventTime, loaded };
  });
  const sorted = [...entries].sort((a, b) => {
    if (!a.eventTime && !b.eventTime) return a.bookmark.taggedAt < b.bookmark.taggedAt ? -1 : 1;
    if (!a.eventTime) return 1;
    if (!b.eventTime) return -1;
    const cmp = a.eventTime.localeCompare(b.eventTime);
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Augment each entry with its host + any remote peer/direction, for the
  // sequence-diagram (UML-ish) view: hosts become lifelines and RDP/SMB rows
  // become host↔peer messages.
  const seqEntries: SeqEntry[] = sorted.map((e) => {
    const h = hostOf(e.bookmark);
    const rawPeer = (e.row?.remote_address ?? "").trim();
    const pHost = rawPeer ? hostIpMap[rawPeer] : undefined;
    return {
      ...e,
      hostKey: h.id || h.name,
      hostName: h.name,
      hostId: h.id,
      peer: rawPeer,
      peerHostKey: pHost ? pHost.id || pHost.name : "",
      peerHostName: pHost?.name ?? "",
      direction: e.row?.direction ?? "",
    };
  });

  return (
    <div className="dfir-view" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "9px 14px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-panel)",
          flexShrink: 0,
        }}
      >
        <strong style={{ fontSize: 13 }}>🔖 북마크 타임라인</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{bookmarks.length.toLocaleString()}건 · 분석가 판단 의심 행위</span>
        <div style={{ display: "flex", gap: 4, marginLeft: 8 }}>
          <SortChip active={sortDir === "asc"} onClick={() => setSortDir("asc")}>오래된순</SortChip>
          <SortChip active={sortDir === "desc"} onClick={() => setSortDir("desc")}>최근순</SortChip>
        </div>
        <div style={{ display: "flex", gap: 4, marginLeft: 4 }}>
          <SortChip active={viewMode === "timeline"} onClick={() => setViewMode("timeline")}>타임라인</SortChip>
          <SortChip active={viewMode === "sequence"} onClick={() => setViewMode("sequence")}>시퀀스</SortChip>
        </div>
        <span style={{ color: "var(--text-faint)", fontSize: 11, marginLeft: "auto", textAlign: "right" }}>
          케이스를 다시 파싱하면 행 번호가 바뀌어 원본 위치가 어긋날 수 있습니다.
        </span>
      </div>

      {viewMode === "sequence" ? (
        <BookmarkSequence entries={seqEntries} currentHostId={currentHostId} onOpen={(e) => e.row && setDetail({ bookmark: e.bookmark, row: e.row, columns: e.columns })} />
      ) : (
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "8px 14px 14px" }}>
        {sorted.map(({ bookmark, row, columns, spec, eventTime, loaded }, idx) => {
          const notFound = loaded && !row;
          const tags = row && spec?.tags ? spec.tags(row) : [];
          // Dot color = the flagged event's severity; plain analyst picks (no
          // tags) get the neutral accent so the rail still reads as "my picks".
          const color = tags.some((t) => t.severity === "danger")
            ? "var(--danger)"
            : tags.some((t) => t.severity === "warning")
              ? "var(--warning)"
              : "var(--accent)";
          const last = idx === sorted.length - 1;
          const host = hostOf(bookmark);
          const title = !loaded
            ? "불러오는 중..."
            : notFound
              ? "원본 행을 찾을 수 없습니다 (케이스가 다시 파싱되었을 수 있음)"
              : spec
                ? spec.title(row!)
                : bookmark.tableName;
          return (
            <div key={bookmark.id} style={{ position: "relative", display: "flex", gap: 12, padding: "8px 0 8px 20px" }}>
              {/* rail + dot */}
              <span style={{ position: "absolute", left: 4, top: 13, width: 10, height: 10, borderRadius: "50%", background: color, border: "2px solid var(--bg)", zIndex: 1 }} />
              {!last && <span style={{ position: "absolute", left: 8, top: 21, bottom: -8, width: 2, background: "var(--border)" }} />}

              {/* event time (the incident chronology axis) */}
              <span style={{ flex: "0 0 148px", fontFamily: "var(--mono)", fontSize: 11.5, color: eventTime ? "var(--text-dim)" : "var(--text-faint)", paddingTop: 1 }}>
                {eventTime || "시간 없음"}
              </span>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div onClick={() => row && setDetail({ bookmark, row, columns })} style={{ cursor: row ? "pointer" : "default" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{title}</span>
                    <span style={{ fontSize: 10.5, fontWeight: 600, padding: "1px 7px", borderRadius: "var(--radius-lg)", background: "var(--bg-elevated)", color: "var(--text-faint)" }}>{bookmark.tableName}</span>
                    {bookmark.field && <span style={{ fontSize: 10.5, fontWeight: 700, padding: "1px 7px", borderRadius: "var(--radius-lg)", background: "var(--accent-subtle)", color: "var(--accent)" }}>🕑 {fieldLabel(bookmark.field)}</span>}
                    <span style={{ fontSize: 10.5, fontWeight: 600, padding: "1px 7px", borderRadius: "var(--radius-lg)", background: "var(--bg-elevated)", color: host.id === currentHostId ? "var(--accent)" : "var(--text-faint)" }}>🖥️ {host.name}</span>
                    {row && <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--accent)" }}>원본 →</span>}
                  </div>
                  {row && spec?.subtitle && <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all" }}>{spec.subtitle(row)}</div>}
                  {tags.length > 0 && <div style={{ marginTop: 6 }}><TagList tags={tags} /></div>}
                </div>
              </div>

              <button
                onClick={() => onRemove(bookmark)}
                title="북마크 제거"
                style={{ flexShrink: 0, alignSelf: "flex-start", fontSize: 11, padding: "3px 9px", background: "var(--bg-elevated)", color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", cursor: "pointer" }}
              >
                제거
              </button>
            </div>
          );
        })}
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
        }}
      >
        <span>
          총 <strong style={{ color: "var(--text-dim)" }}>{bookmarks.length.toLocaleString()}</strong>건 북마크
        </span>
      </div>

      {detail && (
        <RowDetailPanel
          row={detail.row}
          columns={detail.columns}
          focusedColumn={null}
          fileBaseName={detail.bookmark.tableName}
          onClose={() => setDetail(null)}
          onNavigate={(f, c, v) => { setDetail(null); onNavigate(f, c, v); }}
          onFetchLinkedRows={onFetchLinkedRows}
          hostDir={hostDirFromResultPath(detail.bookmark.fullPath)}
          isBookmarked
          onToggleBookmark={() => { onRemove(detail.bookmark); setDetail(null); }}
        />
      )}
    </div>
  );
}

type SeqEntry = {
  bookmark: Bookmark;
  columns: string[];
  loaded: boolean;
  row?: Record<string, string>;
  spec: ReturnType<typeof getArtifactView>;
  eventTime: string;
  hostKey: string;
  hostName: string;
  hostId: string;
  peer: string;
  peerHostKey: string;
  peerHostName: string;
  direction: string;
};

// Human label for a per-timestamp bookmark's field ($MFT SI/FN times).
const _FIELD_LABELS: Record<string, string> = {
  si_created: "SI 생성", si_modified: "SI 수정", si_mft_modified: "SI MFT수정", si_accessed: "SI 접근",
  fn_created: "FN 생성", fn_modified: "FN 수정", fn_mft_modified: "FN MFT수정", fn_accessed: "FN 접근",
  created: "계정 생성", last_login: "최근 로그인", password_last_set: "암호 변경", last_failed_login: "로그인 실패",
};
function fieldLabel(field: string): string {
  return _FIELD_LABELS[field] ?? field;
}

// An artifact-type icon for a bookmarked event, so the sequence diagram reads
// as icons/logos rather than dense text. Falls back to a pin.
function iconFor(e: SeqEntry): string {
  const t = (e.bookmark.tableName || "").toLowerCase();
  if (t.includes("defender")) return "\u{1F6E1}\u{FE0F}";        // 🛡️
  if (t.includes("smb")) return "\u{1F4C1}";                       // 📁
  if (t.includes("remotedesktop") || t.includes("rdp")) return "\u{1F5A5}\u{FE0F}"; // 🖥️
  if (t.includes("powershell")) return "\u26A1";                   // ⚡
  if (t.includes("registry")) return "\u{1F511}";                  // 🔑
  if (t.includes("scheduledtask") || t.includes("task")) return "\u23F0"; // ⏰
  if (t.startsWith("wer")) return "\u{1F4A5}";                     // WER crash
  if (t.startsWith("mft")) return "\u{1F5C2}\u{FE0F}";             // 🗂️ $MFT entry
  if (t.includes("targetinfo")) return "\u{1F464}";               // 👤 account
  if (t.includes("execution") || t.includes("prefetch") || t.includes("amcache") || t.includes("srum")) return "\u{1F680}"; // rocket (bright; replaced dark ▶)
  if (t.includes("browser")) return "\u{1F310}";                   // 🌐
  if (t.includes("event") || t.includes("security") || t.includes("system")) return "\u{1F4C4}"; // 📄
  return "\u{1F4CC}";                                              // 📌
}

// A UML-ish sequence diagram of the bookmarked events: each host (and each
// remote peer IP referenced) is a lifeline; time flows downward; RDP/SMB rows
// with a remote address + direction become arrows between lifelines, everything
// else is a note on its host's lifeline. Click any event to open its detail.
function BookmarkSequence({ entries, currentHostId, onOpen }: { entries: SeqEntry[]; currentHostId: string | null; onOpen: (e: SeqEntry) => void }) {
  const GUTTER = 118;
  const COL = 176;
  const ROW = 48;
  const [hover, setHover] = useState<{ x: number; y: number; e: SeqEntry } | null>(null);

  const trunc = (str: string, n = 30) => (str.length > n ? str.slice(0, n) + "…" : str);

  const hostParts: { key: string; label: string; kind: "host" }[] = [];
  const seen = new Set<string>();
  const addHost = (key: string, label: string) => {
    if (key && !seen.has(key)) {
      seen.add(key);
      hostParts.push({ key, label, kind: "host" });
    }
  };
  for (const e of entries) {
    addHost(e.hostKey, e.hostName);
    if (e.peerHostKey) addHost(e.peerHostKey, e.peerHostName); // a peer IP that is another host
  }
  const peerParts: { key: string; label: string; kind: "peer" }[] = [];
  const seenP = new Set<string>();
  for (const e of entries) {
    const ip = e.peer;
    if (ip && !e.peerHostKey && !seen.has(ip) && !seenP.has(ip)) {
      seenP.add(ip);
      peerParts.push({ key: ip, label: ip, kind: "peer" });
    }
  }
  const participants = [...hostParts, ...peerParts.slice(0, 10)];
  const idxOf = new Map(participants.map((p, i) => [p.key, i] as const));
  const xOf = (key: string) => {
    const i = idxOf.get(key);
    return i === undefined ? -1 : GUTTER + i * COL + COL / 2;
  };
  const width = Math.max(GUTTER + participants.length * COL + 16, 560);
  const HEADER_H = 46; // sticky host-header band height
  const BODY_TOP = 8;  // top pad inside the scrolling body svg
  const bodyHeight = BODY_TOP + entries.length * ROW + 24;

  if (participants.length === 0) {
    return <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 20, color: "var(--text-faint)" }}>표시할 항목이 없습니다.</div>;
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
      <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 8 }}>
        세로축 = 시간 순서. 각 아이콘이 북마크한 이벤트입니다 — 마우스를 올리면 요약, 클릭하면 상세를 봅니다.
      </div>
      {/* Host/peer header band — sticks to the top of the scroll area so the
          lifelines stay labeled while the events scroll under it. */}
      <div style={{ position: "sticky", top: 0, zIndex: 5, background: "var(--bg)" }}>
        <svg width={width} height={HEADER_H} style={{ maxWidth: "none", display: "block" }}>
          {participants.map((p) => {
            const x = xOf(p.key);
            const isHost = p.kind === "host";
            const cur = isHost && p.key === currentHostId;
            return (
              <g key={p.key}>
                <rect x={x - COL / 2 + 8} y={8} width={COL - 16} height={32} rx={6} fill={isHost ? "var(--accent-subtle)" : "var(--bg-elevated)"} stroke={cur ? "var(--accent)" : isHost ? "var(--accent)" : "var(--border)"} strokeWidth={cur ? 1.8 : 1} />
                <text x={x} y={28} textAnchor="middle" fontSize="11.5" fontWeight={isHost ? 700 : 500} fill={isHost ? "var(--text)" : "var(--text-dim)"} style={{ fontFamily: isHost ? undefined : "var(--mono)" }}>
                  {(isHost ? "🖥️ " : "") + trunc(p.label, isHost ? 16 : 20)}
                </text>
                <line x1={x} y1={40} x2={x} y2={HEADER_H} stroke="var(--border)" strokeDasharray="3 4" />
              </g>
            );
          })}
        </svg>
      </div>

      <svg width={width} height={bodyHeight} style={{ maxWidth: "none", display: "block" }}>
        <defs>
          <marker id="seqarrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 Z" fill="var(--accent)" />
          </marker>
        </defs>
        {participants.map((p) => (
          <line key={p.key} x1={xOf(p.key)} y1={0} x2={xOf(p.key)} y2={bodyHeight - 10} stroke="var(--border)" strokeDasharray="3 4" />
        ))}
        {entries.map((e, idx) => {
          const y = BODY_TOP + idx * ROW + ROW / 2;
          const tags = e.spec?.tags && e.row ? e.spec.tags(e.row) : [];
          const color = tags.some((t) => t.severity === "danger") ? "var(--danger)" : tags.some((t) => t.severity === "warning") ? "var(--warning)" : "var(--accent)";
          const hx = xOf(e.hostKey);
          const peerKey = e.peerHostKey || e.peer;
          const peerX = peerKey ? xOf(peerKey) : -1;
          const isMsg = peerX >= 0 && hx >= 0 && peerX !== hx;
          const inbound = e.direction !== "outbound";
          const from = isMsg ? (inbound ? peerX : hx) : 0;
          const to = isMsg ? (inbound ? hx : peerX) : 0;
          const iconX = isMsg ? (from + to) / 2 : hx;
          const active = hover?.e.bookmark.id === e.bookmark.id;
          return (
            <g
              key={e.bookmark.id}
              style={{ cursor: "pointer" }}
              onClick={() => onOpen(e)}
              onMouseEnter={(ev) => setHover({ x: ev.clientX, y: ev.clientY, e })}
              onMouseMove={(ev) => setHover({ x: ev.clientX, y: ev.clientY, e })}
              onMouseLeave={() => setHover(null)}
            >
              <rect x={0} y={y - ROW / 2} width={width} height={ROW} fill={active ? "var(--bg-hover)" : "transparent"} />
              <text x={6} y={y + 3} fontSize="9.5" fill="var(--text-time)" fontFamily="var(--mono)">{(e.eventTime || "시간없음").slice(5, 19)}</text>
              {isMsg && <line x1={from} y1={y} x2={to} y2={y} stroke={color} strokeWidth={1.8} markerEnd="url(#seqarrow)" />}
              <circle cx={iconX} cy={y} r={13} fill="var(--bg-panel)" stroke={color} strokeWidth={active ? 2.2 : 1.5} />
              <text x={iconX} y={y + 1} textAnchor="middle" dominantBaseline="central" fontSize="14">{iconFor(e)}</text>
            </g>
          );
        })}
      </svg>
      {hover && (() => {
        const e = hover.e;
        const title = e.spec && e.row ? e.spec.title(e.row) : e.bookmark.tableName;
        const tags = e.spec?.tags && e.row ? e.spec.tags(e.row) : [];
        const peerKey = e.peerHostKey || e.peer;
        const inbound = e.direction !== "outbound";
        const peerLabel = e.peerHostName || e.peer;
        return (
          <div
            style={{
              position: "fixed", left: hover.x + 16, top: hover.y + 16, zIndex: 60, pointerEvents: "none", maxWidth: 340,
              background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", padding: "8px 11px",
            }}
          >
            <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text)", marginBottom: 4, wordBreak: "break-all" }}>{iconFor(e)} {title}</div>
            <div style={{ fontSize: 10.5, color: "var(--text-time)", fontFamily: "var(--mono)", marginBottom: 4 }}>🕑 {e.eventTime || "시간 정보 없음"}</div>
            <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
              🖥️ {e.hostName}{peerKey && peerLabel ? `  ${inbound ? "←" : "→"}  ${peerLabel}` : ""}
            </div>
            {tags.length > 0 && (
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
                {tags.slice(0, 4).map((t, i) => {
                  const c = t.severity === "danger" ? "var(--danger)" : "var(--warning)";
                  return <span key={i} style={{ fontSize: 9.5, fontWeight: 700, padding: "0 5px", borderRadius: 4, color: c, border: `1px solid ${c}` }}>{t.label}</span>;
                })}
              </div>
            )}
            <div style={{ fontSize: 9.5, color: "var(--text-faint)", marginTop: 6 }}>클릭 → 상세 보기</div>
          </div>
        );
      })()}
    </div>
  );
}
