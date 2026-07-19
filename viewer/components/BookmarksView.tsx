"use client";

import { useEffect, useState } from "react";
import type { Bookmark, CsvData } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";
import TagList from "./TagList";

interface BookmarksViewProps {
  bookmarks: Bookmark[];
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onRemove: (bookmark: Bookmark) => void;
  onUpdateNote: (id: string, note: string) => void;
}

export default function BookmarksView({ bookmarks, onNavigate, onRemove, onUpdateNote }: BookmarksViewProps) {
  const [rowCache, setRowCache] = useState<Record<string, CsvData>>({});
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftNote, setDraftNote] = useState("");

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

  const sorted = [...bookmarks].sort((a, b) => (a.taggedAt < b.taggedAt ? 1 : a.taggedAt > b.taggedAt ? -1 : 0));

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minWidth: 0 }}>
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
        <strong style={{ fontSize: 13 }}>🔖 북마크</strong>
        <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{bookmarks.length.toLocaleString()}건</span>
        <span style={{ color: "var(--text-faint)", fontSize: 11, marginLeft: "auto", textAlign: "right" }}>
          케이스를 다시 파싱하면 행 번호가 바뀌어 원본 위치가 어긋날 수 있습니다.
        </span>
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {sorted.map((bookmark) => {
          const data = rowCache[bookmark.fullPath];
          const row = data?.rows.find((r) => Number((r as unknown as Record<string, unknown>).__rowid) === bookmark.rowid);
          const spec = getArtifactView(bookmark.tableName);
          const notFound = data !== undefined && !row;

          return (
            <div key={bookmark.id} style={{ padding: "12px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                <div
                  style={{ flex: 1, minWidth: 0, cursor: row ? "pointer" : "default" }}
                  onClick={() => row && onNavigate(bookmark.tableName, "__rowid", String(bookmark.rowid))}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span
                      style={{
                        fontSize: 10.5,
                        fontWeight: 600,
                        padding: "2px 7px",
                        borderRadius: "var(--radius-lg)",
                        background: "var(--bg-elevated)",
                        color: "var(--text-faint)",
                      }}
                    >
                      {bookmark.tableName}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{bookmark.taggedAt}</span>
                  </div>
                  <div style={{ marginTop: 4, fontSize: 13, fontWeight: 600 }}>
                    {!data
                      ? "불러오는 중..."
                      : notFound
                        ? "원본 행을 찾을 수 없습니다 (케이스가 다시 파싱되었을 수 있음)"
                        : spec
                          ? spec.title(row!)
                          : bookmark.tableName}
                  </div>
                  {row && spec?.subtitle && (
                    <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 2 }}>{spec.subtitle(row)}</div>
                  )}
                  {row && spec?.tags && spec.tags(row).length > 0 && (
                    <div style={{ marginTop: 6 }}>
                      <TagList tags={spec.tags(row)} />
                    </div>
                  )}
                </div>
                <button
                  onClick={() => onRemove(bookmark)}
                  title="북마크 제거"
                  style={{
                    flexShrink: 0,
                    fontSize: 11,
                    padding: "3px 9px",
                    background: "var(--bg-elevated)",
                    color: "var(--text-faint)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)",
                    cursor: "pointer",
                  }}
                >
                  제거
                </button>
              </div>

              <div style={{ marginTop: 8 }}>
                {editingId === bookmark.id ? (
                  <div style={{ display: "flex", gap: 6 }}>
                    <input
                      autoFocus
                      value={draftNote}
                      onChange={(e) => setDraftNote(e.target.value)}
                      onBlur={() => {
                        onUpdateNote(bookmark.id, draftNote);
                        setEditingId(null);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          onUpdateNote(bookmark.id, draftNote);
                          setEditingId(null);
                        }
                        if (e.key === "Escape") setEditingId(null);
                      }}
                      style={{
                        flex: 1,
                        padding: "5px 8px",
                        background: "var(--bg-input)",
                        border: "1px solid var(--accent)",
                        borderRadius: "var(--radius-sm)",
                        color: "var(--text)",
                        fontSize: 12,
                      }}
                    />
                  </div>
                ) : (
                  <div
                    onClick={() => {
                      setEditingId(bookmark.id);
                      setDraftNote(bookmark.note);
                    }}
                    style={{
                      fontSize: 12,
                      color: bookmark.note ? "var(--text)" : "var(--text-faint)",
                      cursor: "pointer",
                      padding: "4px 0",
                    }}
                  >
                    {bookmark.note || "메모 추가..."}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
