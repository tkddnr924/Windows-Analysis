"use client";

import { useEffect, useState } from "react";
import { getArtifactView } from "@/lib/artifactViews";
import ArtifactDetailView from "./ArtifactDetailView";

interface RowDetailPanelProps {
  row: Record<string, string>;
  columns: string[];
  focusedColumn: string | null;
  fileBaseName: string;
  onClose: () => void;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
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

function RawFieldValue({ column, value, focused }: { column: string; value: string; focused: boolean }) {
  const [copied, setCopied] = useState(false);
  const pretty = tryPrettyJson(value);

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
        <button
          onClick={copy}
          style={{
            marginLeft: "auto",
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
        {pretty ?? value ?? "(empty)"}
      </pre>
    </div>
  );
}

export default function RowDetailPanel({ row, columns, focusedColumn, fileBaseName, onClose, onNavigate }: RowDetailPanelProps) {
  const spec = getArtifactView(fileBaseName);
  const [showRaw, setShowRaw] = useState(!spec);

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
          <button
            onClick={onClose}
            style={{
              marginLeft: "auto",
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
          {spec && !showRaw ? (
            <ArtifactDetailView spec={spec} row={row} onNavigate={onNavigate} />
          ) : (
            columns.map((col) => (
              <RawFieldValue key={col} column={col} value={row[col] ?? ""} focused={col === focusedColumn} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
