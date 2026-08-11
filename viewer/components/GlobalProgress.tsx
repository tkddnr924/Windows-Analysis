"use client";

interface Props {
  hostName: string;
  stepLabel: string;
  percent: number;
  complete: boolean;
  hadError: boolean;
  /** Jump to the parsing screen (undefined = no navigation available here). */
  onOpen?: () => void;
  onDismiss: () => void;
}

// A slim always-on-top bar so an in-progress (or just-finished) parse stays
// visible after the user navigates away from the RunPipeline screen.
export default function GlobalProgress({ hostName, stepLabel, percent, complete, hadError, onOpen, onDismiss }: Props) {
  const color = hadError ? "var(--danger)" : complete ? "var(--success)" : "var(--accent)";
  return (
    <div
      style={{
        position: "fixed",
        left: "50%",
        bottom: 16,
        transform: "translateX(-50%)",
        zIndex: 1000,
        minWidth: 360,
        maxWidth: "90vw",
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow-panel)",
        padding: "10px 14px",
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontSize: 13 }}>{complete ? (hadError ? "⚠️" : "✅") : "⏳"}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            🖥️ {hostName || "호스트"} <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>· {stepLabel}</span>
          </div>
        </div>
        <span style={{ fontSize: 15, fontWeight: 700, fontVariantNumeric: "tabular-nums", color }}>{percent}%</span>
        {onOpen && (
          <button onClick={onOpen} style={{ fontSize: 11, fontWeight: 600, padding: "3px 9px", background: "var(--accent-subtle)", color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-lg)", cursor: "pointer", whiteSpace: "nowrap" }}>
            진행 화면
          </button>
        )}
        {complete && (
          <button onClick={onDismiss} title="닫기" style={{ fontSize: 13, background: "transparent", border: "none", color: "var(--text-faint)", cursor: "pointer" }}>
            ×
          </button>
        )}
      </div>
      <div style={{ height: 5, background: "var(--bg)", borderRadius: 999, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${percent}%`, background: color, borderRadius: 999, transition: "width 0.3s ease" }} />
      </div>
    </div>
  );
}
