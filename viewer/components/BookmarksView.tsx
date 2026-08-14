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
  onUpdateNote: (id: string, note: string) => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows: FetchLinkedRows;
}

// `taggedAt` is stored as a UTC ISO string (`new Date().toISOString()`),
// but every other time in this app is KST (the parser converts to UTC+9
// and writes a plain "YYYY-MM-DD HH:MM:SS.fff" string). Rendering the raw
// ISO/UTC value here made it look 9 hours off from everything else. Convert
// to KST wall-clock in the same format — computed explicitly as UTC+9 (not
// via the viewer machine's locale) so it matches the app's fixed KST
// convention regardless of where the viewer runs.
function formatTaggedAt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const kst = new Date(d.getTime() + 9 * 60 * 60 * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${kst.getUTCFullYear()}-${p(kst.getUTCMonth() + 1)}-${p(kst.getUTCDate())} ${p(kst.getUTCHours())}:${p(kst.getUTCMinutes())}:${p(kst.getUTCSeconds())}`;
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

export default function BookmarksView({ bookmarks, hosts, currentHostId, onRemove, onUpdateNote, onNavigate, onFetchLinkedRows }: BookmarksViewProps) {
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
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftNote, setDraftNote] = useState("");
  // Bookmarks are the analyst's shortlist of key events; reading them oldest →
  // newest by when each event happened reconstructs the incident timeline. That
  // "event time" needs the source row, so it's resolved here (against rowCache)
  // rather than sorting on the bookmark's own taggedAt.
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

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

  // Group the time-sorted bookmarks by host so it's clear which machine each
  // came from (bookmarks are shared across the case's hosts); the open host first.
  const groupedHosts = (() => {
    const m = new Map<string, { id: string; name: string; items: typeof sorted }>();
    for (const e of sorted) {
      const h = hostOf(e.bookmark);
      const key = h.id || h.name;
      if (!m.has(key)) m.set(key, { id: h.id, name: h.name, items: [] });
      m.get(key)!.items.push(e);
    }
    return [...m.values()].sort((a, b) => (a.id === currentHostId ? -1 : b.id === currentHostId ? 1 : a.name.localeCompare(b.name)));
  })();

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
        <span style={{ color: "var(--text-faint)", fontSize: 11, marginLeft: "auto", textAlign: "right" }}>
          케이스를 다시 파싱하면 행 번호가 바뀌어 원본 위치가 어긋날 수 있습니다.
        </span>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {groupedHosts.map((group) => (
          <div key={group.id || group.name}>
            <div style={{ position: "sticky", top: 0, zIndex: 1, display: "flex", alignItems: "center", gap: 8, padding: "6px 14px", background: "var(--bg-elevated)", borderBottom: "1px solid var(--border)", fontSize: 11.5, fontWeight: 700, color: "var(--text-dim)" }}>
              🖥️ {group.name}
              <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{group.items.length}건</span>
              {group.id === currentHostId && <span style={{ color: "var(--accent)", fontWeight: 600 }}>· 현재 호스트</span>}
            </div>
        <div style={{ padding: "8px 14px 14px" }}>
        {group.items.map(({ bookmark, data, row, spec, eventTime }, idx) => {
          const notFound = data !== undefined && !row;
          const tags = row && spec?.tags ? spec.tags(row) : [];
          // Dot color = the flagged event's severity; plain analyst picks (no
          // tags) get the neutral accent so the rail still reads as "my picks".
          const color = tags.some((t) => t.severity === "danger")
            ? "var(--danger)"
            : tags.some((t) => t.severity === "warning")
              ? "var(--warning)"
              : "var(--accent)";
          const last = idx === group.items.length - 1;
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
                    {row && <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--accent)" }}>원본 →</span>}
                  </div>
                  {row && spec?.subtitle && <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all" }}>{spec.subtitle(row)}</div>}
                  {tags.length > 0 && <div style={{ marginTop: 6 }}><TagList tags={tags} /></div>}
                </div>

                {/* analyst note — the judgment this timeline exists to capture */}
                {editingId === bookmark.id ? (
                  <input
                    autoFocus
                    value={draftNote}
                    onChange={(e) => setDraftNote(e.target.value)}
                    onBlur={() => { onUpdateNote(bookmark.id, draftNote); setEditingId(null); }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") { onUpdateNote(bookmark.id, draftNote); setEditingId(null); }
                      if (e.key === "Escape") setEditingId(null);
                    }}
                    placeholder="이 항목이 의심스러운 이유..."
                    style={{ marginTop: 6, width: "100%", padding: "5px 8px", background: "var(--bg-input)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", color: "var(--text)", fontSize: 12 }}
                  />
                ) : (
                  <div
                    onClick={() => { setEditingId(bookmark.id); setDraftNote(bookmark.note); }}
                    style={{ marginTop: 6, fontSize: 12, color: bookmark.note ? "var(--text)" : "var(--text-faint)", cursor: "pointer", fontStyle: bookmark.note ? "normal" : "italic" }}
                  >
                    {bookmark.note ? `📝 ${bookmark.note}` : "판단 메모 추가..."}
                  </div>
                )}
                <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 4 }} title="북마크한 시각 (KST)">
                  북마크 {formatTaggedAt(bookmark.taggedAt)}
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
          </div>
        ))}
      </div>

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
