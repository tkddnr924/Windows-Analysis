"use client";

import { useEffect, useState } from "react";
import type { Bookmark, CsvData, FetchLinkedRows, Host } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import TagList from "./TagList";
import RowDetailPanel from "./RowDetailPanel";

interface BookmarksViewProps {
  bookmarks: Bookmark[];
  hosts: Host[];
  currentHostId: string | null;
  onRemove: (bookmark: Bookmark) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
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

export default function BookmarksView({ bookmarks, hosts, currentHostId, onRemove, onNavigate, onFetchLinkedRows }: BookmarksViewProps) {
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
  const [rowCache, setRowCache] = useState<Record<string, CsvData>>({});
  // Bookmarks are the analyst's shortlist of key events; reading them oldest →
  // newest by when each event happened reconstructs the incident timeline. That
  // "event time" needs the source row, so it's resolved here (against rowCache)
  // rather than sorting on the bookmark's own taggedAt.
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [viewMode, setViewMode] = useState<"timeline" | "sequence">("timeline");

  useEffect(() => {
    const missing = [...new Set(bookmarks.map((b) => b.fullPath))].filter((p) => !rowCache[p]);
    if (missing.length === 0) return;
    Promise.all(missing.map((p) => window.api.readResultFile(p).then((data) => [p, data] as const))).then((pairs) => {
      setRowCache((prev) => {
        const next = { ...prev };
        for (const [p, data] of pairs) next[p] = data;
        return next;
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    const data = rowCache[bookmark.fullPath];
    const row = data?.rows.find((r) => Number((r as unknown as Record<string, unknown>).__rowid) === bookmark.rowid);
    const spec = getArtifactView(bookmark.tableName);
    const eventTime = row ? row[spec?.timelineField ?? "timestamp"] || row.timestamp || "" : "";
    return { bookmark, data, row, spec, eventTime };
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
    return {
      ...e,
      hostKey: h.id || h.name,
      hostName: h.name,
      hostId: h.id,
      peer: e.row?.remote_address ?? "",
      direction: e.row?.direction ?? "",
    };
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
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
        <BookmarkSequence entries={seqEntries} currentHostId={currentHostId} onOpen={(e) => e.row && e.data && setDetail({ bookmark: e.bookmark, row: e.row, columns: e.data.columns })} />
      ) : (
      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "8px 14px 14px" }}>
        {sorted.map(({ bookmark, data, row, spec, eventTime }, idx) => {
          const notFound = data !== undefined && !row;
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
          const title = !data
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
                <div onClick={() => row && data && setDetail({ bookmark, row, columns: data.columns })} style={{ cursor: row ? "pointer" : "default" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{title}</span>
                    <span style={{ fontSize: 10.5, fontWeight: 600, padding: "1px 7px", borderRadius: "var(--radius-lg)", background: "var(--bg-elevated)", color: "var(--text-faint)" }}>{bookmark.tableName}</span>
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
          isBookmarked
          onToggleBookmark={() => { onRemove(detail.bookmark); setDetail(null); }}
        />
      )}
    </div>
  );
}

type SeqEntry = {
  bookmark: Bookmark;
  data?: CsvData;
  row?: Record<string, string>;
  spec: ReturnType<typeof getArtifactView>;
  eventTime: string;
  hostKey: string;
  hostName: string;
  hostId: string;
  peer: string;
  direction: string;
};

// A UML-ish sequence diagram of the bookmarked events: each host (and each
// remote peer IP referenced) is a lifeline; time flows downward; RDP/SMB rows
// with a remote address + direction become arrows between lifelines, everything
// else is a note on its host's lifeline. Click any event to open its detail.
function BookmarkSequence({ entries, currentHostId, onOpen }: { entries: SeqEntry[]; currentHostId: string | null; onOpen: (e: SeqEntry) => void }) {
  const GUTTER = 118;
  const COL = 176;
  const TOP = 58;
  const ROW = 48;

  const trunc = (str: string, n = 30) => (str.length > n ? str.slice(0, n) + "…" : str);

  const hostParts: { key: string; label: string; kind: "host" }[] = [];
  const seen = new Set<string>();
  for (const e of entries) {
    if (!seen.has(e.hostKey)) {
      seen.add(e.hostKey);
      hostParts.push({ key: e.hostKey, label: e.hostName, kind: "host" });
    }
  }
  const peerParts: { key: string; label: string; kind: "peer" }[] = [];
  const seenP = new Set<string>();
  for (const e of entries) {
    const ip = e.peer;
    if (ip && !seen.has(ip) && !seenP.has(ip)) {
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
  const height = TOP + entries.length * ROW + 24;

  if (participants.length === 0) {
    return <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 20, color: "var(--text-faint)" }}>표시할 항목이 없습니다.</div>;
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12 }}>
      <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 8 }}>
        세로축 = 시간 순서. 🖥️ = 등록 호스트(라이프라인), 나머지 = 원격 IP. RDP/SMB는 방향 화살표, 그 외는 호스트 위의 이벤트입니다.
      </div>
      <svg width={width} height={height} style={{ maxWidth: "none", display: "block" }}>
        <defs>
          <marker id="seqarrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
            <path d="M0,0 L7,3 L0,6 Z" fill="var(--accent)" />
          </marker>
        </defs>
        {participants.map((p) => {
          const x = xOf(p.key);
          const isHost = p.kind === "host";
          const cur = isHost && p.key === currentHostId;
          return (
            <g key={p.key}>
              <line x1={x} y1={TOP - 14} x2={x} y2={height - 10} stroke="var(--border)" strokeDasharray="3 4" />
              <rect x={x - COL / 2 + 8} y={8} width={COL - 16} height={32} rx={6} fill={isHost ? "var(--accent-subtle)" : "var(--bg-elevated)"} stroke={cur ? "var(--accent)" : isHost ? "var(--accent)" : "var(--border)"} strokeWidth={cur ? 1.8 : 1} />
              <text x={x} y={28} textAnchor="middle" fontSize="11.5" fontWeight={isHost ? 700 : 500} fill={isHost ? "var(--text)" : "var(--text-dim)"} style={{ fontFamily: isHost ? undefined : "var(--mono)" }}>
                {(isHost ? "🖥️ " : "") + trunc(p.label, isHost ? 16 : 20)}
              </text>
            </g>
          );
        })}
        {entries.map((e, idx) => {
          const y = TOP + idx * ROW + ROW / 2;
          const tags = e.spec?.tags && e.row ? e.spec.tags(e.row) : [];
          const color = tags.some((t) => t.severity === "danger") ? "var(--danger)" : tags.some((t) => t.severity === "warning") ? "var(--warning)" : "var(--accent)";
          const hx = xOf(e.hostKey);
          const label = trunc(e.spec && e.row ? e.spec.title(e.row) : e.bookmark.tableName, 30);
          const peerX = e.peer ? xOf(e.peer) : -1;
          const isMsg = peerX >= 0 && hx >= 0;
          const inbound = e.direction !== "outbound";
          const from = isMsg ? (inbound ? peerX : hx) : 0;
          const to = isMsg ? (inbound ? hx : peerX) : 0;
          return (
            <g key={e.bookmark.id} style={{ cursor: "pointer" }} onClick={() => onOpen(e)}>
              <rect x={0} y={y - ROW / 2} width={width} height={ROW} fill="transparent" />
              <text x={6} y={y + 3} fontSize="9.5" fill="var(--text-time)" fontFamily="var(--mono)">{(e.eventTime || "시간없음").slice(5, 19)}</text>
              {isMsg ? (
                <>
                  <line x1={from} y1={y} x2={to} y2={y} stroke={color} strokeWidth={1.8} markerEnd="url(#seqarrow)" />
                  <text x={(from + to) / 2} y={y - 6} textAnchor="middle" fontSize="10" fill="var(--text-dim)">{label}</text>
                </>
              ) : (
                <>
                  <circle cx={hx} cy={y} r={4} fill={color} />
                  <rect x={hx + 10} y={y - 11} width={Math.min(COL - 24, label.length * 6.6 + 16)} height={22} rx={5} fill="var(--bg-elevated)" stroke={color} strokeOpacity={0.55} />
                  <text x={hx + 18} y={y + 4} fontSize="10.5" fill="var(--text)">{label}</text>
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
