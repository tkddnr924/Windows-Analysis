"use client";

import { useEffect, useState } from "react";
import { resolveArtifactView, getArtifactView } from "@/lib/artifactViews";
import type { FetchLinkedRows } from "@/lib/types";
import ArtifactDetailView from "./ArtifactDetailView";

interface RowDetailPanelProps {
  row: Record<string, string>;
  columns: string[];
  focusedColumn: string | null;
  fileBaseName: string;
  onClose: () => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Bookmark state + toggle for this row, bound by the parent. Omitted when
   * the host view has no bookmarking (then no bookmark control is shown). */
  isBookmarked?: boolean;
  onToggleBookmark?: () => void;
}

function tryPrettyJson(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

// Turn literal escape sequences ("\r\n", "\n", "\t") — which many EventData
// blobs store as two-character text, not real whitespace — into actual line
// breaks/tabs so multi-line content reads normally. Display-only.
function unescapeWhitespace(s: string): string {
  return s
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\n")
    .replace(/\\t/g, "\t");
}

function RawFieldValue({ column, value, focused }: { column: string; value: string; focused: boolean }) {
  const [copied, setCopied] = useState(false);
  const [beautified, setBeautified] = useState(true);
  const [unescaped, setUnescaped] = useState(false);
  const pretty = tryPrettyJson(value);
  const isJson = pretty !== null;
  const hasEscapes = /\\[rnt]/.test(value);
  const baseText = isJson && beautified ? pretty! : value || "(empty)";
  const shownText = unescaped ? unescapeWhitespace(baseText) : baseText;

  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  }

  return (
    <div
      style={{
        padding: "10px 16px",
        borderBottom: "1px solid var(--border-subtle)",
        background: focused ? "var(--accent-subtle)" : "transparent",
        borderLeft: `2px solid ${focused ? "var(--accent)" : "transparent"}`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ color: "var(--accent)", fontWeight: 600, fontFamily: "var(--mono)", fontSize: 12 }}>{column}</span>
        {isJson && (
          <button
            onClick={() => setBeautified((b) => !b)}
            title={beautified ? "원본(압축) 보기" : "보기 좋게 정렬"}
            style={{
              marginLeft: "auto",
              fontSize: 11,
              padding: "2px 8px",
              background: "var(--bg-elevated)",
              color: "var(--accent)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              cursor: "pointer",
            }}
          >
            {beautified ? "{ } 원본" : "{ } 정렬"}
          </button>
        )}
        {hasEscapes && (
          <button
            onClick={() => setUnescaped((u) => !u)}
            title={unescaped ? "이스케이프 원본(\\r \\n \\t) 보기" : "\\r \\n \\t 를 실제 줄바꿈·탭으로 치환"}
            style={{
              marginLeft: isJson ? 0 : "auto",
              fontSize: 11,
              padding: "2px 8px",
              background: unescaped ? "var(--accent-subtle)" : "var(--bg-elevated)",
              color: "var(--accent)",
              border: `1px solid ${unescaped ? "var(--accent)" : "var(--border)"}`,
              borderRadius: "var(--radius-sm)",
              cursor: "pointer",
            }}
          >
            ↵ \n 치환
          </button>
        )}
        <button
          onClick={copy}
          style={{
            marginLeft: isJson || hasEscapes ? 0 : "auto",
            fontSize: 11,
            padding: "2px 8px",
            background: "var(--bg-elevated)",
            color: "var(--text-dim)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            cursor: "pointer",
          }}
        >
          {copied ? "복사됨" : "복사"}
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          fontFamily: "var(--mono)",
          fontSize: 12.5,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          color: value ? "var(--text)" : "var(--text-faint)",
        }}
      >
        {shownText}
      </pre>
    </div>
  );
}

export default function RowDetailPanel({ row, columns, focusedColumn, fileBaseName, onClose, onNavigate, onFetchLinkedRows, isBookmarked, onToggleBookmark }: RowDetailPanelProps) {
  // EventLog-derived overview rows (PowerShell/RDP/SMB correlations) carry only
  // a `record_key` link to the raw event, not the event itself. To give ONE
  // detail everywhere, when such a link exists we load the linked raw EventLog
  // row and show the shared EventLog detail for it — so a PowerShell command
  // and its source Security/PowerShell event render the exact same panel.
  const recordKey = row.record_key || "";
  const canLink = Boolean(recordKey && onFetchLinkedRows);
  const [linked, setLinked] = useState<{ row: Record<string, string>; columns: string[] } | null | undefined>(undefined);

  useEffect(() => {
    if (!canLink) { setLinked(null); return; }
    let alive = true;
    setLinked(undefined);
    onFetchLinkedRows!("EventLog_Events", "_record_key", recordKey)
      .then((res) => {
        if (!alive) return;
        const r = res?.rows?.[0];
        setLinked(r ? { row: r, columns: Object.keys(r).filter((c) => c !== "__rowid") } : null);
      })
      .catch(() => alive && setLinked(null));
    return () => { alive = false; };
  }, [canLink, recordKey, onFetchLinkedRows]);

  const useLinked = Boolean(canLink && linked && (linked as { row: Record<string, string> }).row);
  const effRow = useLinked ? (linked as { row: Record<string, string> }).row : row;
  const effCols = useLinked ? (linked as { columns: string[] }).columns : columns;
  const effSpec = useLinked ? getArtifactView("EventLog_Events") ?? resolveArtifactView(fileBaseName, columns) : resolveArtifactView(fileBaseName, columns);
  const spec = effSpec;
  const linkLoading = canLink && linked === undefined;
  const [showRaw, setShowRaw] = useState(!resolveArtifactView(fileBaseName, columns));

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(1,4,9,0.6)",
        display: "flex",
        justifyContent: "flex-end",
        zIndex: 100,
        animation: "fadeIn 0.15s ease",
      }}
    >
      <style>{`
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideIn { from { transform: translateX(24px); opacity: 0.6; } to { transform: translateX(0); opacity: 1; } }
      `}</style>
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 480,
          maxWidth: "80vw",
          height: "100%",
          background: "var(--bg-panel)",
          borderLeft: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          boxShadow: "var(--shadow-panel)",
          animation: "slideIn 0.18s ease",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            padding: "12px 16px",
            borderBottom: "1px solid var(--border)",
            flexShrink: 0,
            background: "var(--bg-elevated)",
          }}
        >
          <strong style={{ fontSize: 13 }}>{spec && !showRaw ? "주요 필드" : "전체 필드"}</strong>
          {spec && (
            <button
              onClick={() => setShowRaw((v) => !v)}
              style={{
                marginLeft: 10,
                fontSize: 11,
                padding: "3px 9px",
                background: "transparent",
                color: "var(--accent)",
                border: "1px solid var(--accent)",
                borderRadius: "var(--radius-lg)",
                cursor: "pointer",
              }}
            >
              {showRaw ? "주요 필드 보기" : "전체 필드 보기"}
            </button>
          )}
          {onToggleBookmark && (
            <button
              onClick={onToggleBookmark}
              title={isBookmarked ? "북마크 해제" : "북마크에 추가"}
              style={{
                marginLeft: "auto",
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontSize: 11.5,
                padding: "4px 10px",
                background: isBookmarked ? "var(--warning-subtle)" : "transparent",
                color: isBookmarked ? "var(--warning)" : "var(--text-dim)",
                border: `1px solid ${isBookmarked ? "var(--warning)" : "var(--border)"}`,
                borderRadius: "var(--radius-lg)",
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              {isBookmarked ? "★ 북마크됨" : "☆ 북마크"}
            </button>
          )}
          <button
            onClick={onClose}
            style={{
              marginLeft: onToggleBookmark ? 8 : "auto",
              background: "transparent",
              border: "none",
              color: "var(--text-dim)",
              fontSize: 20,
              cursor: "pointer",
              lineHeight: 1,
              padding: 4,
              borderRadius: "var(--radius-sm)",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            ×
          </button>
        </div>
        <div style={{ overflowY: "auto", flex: 1 }}>
          {linkLoading ? (
            <div style={{ padding: 20, color: "var(--text-dim)", fontSize: 12.5 }}>원본 이벤트 로그를 불러오는 중...</div>
          ) : spec && !showRaw ? (
            <ArtifactDetailView spec={spec} row={effRow} onNavigate={onNavigate} onFetchLinkedRows={onFetchLinkedRows} />
          ) : (
            effCols.map((col) => (
              <RawFieldValue key={col} column={col} value={effRow[col] ?? ""} focused={col === focusedColumn} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
