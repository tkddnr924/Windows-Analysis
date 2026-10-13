"use client";

import { useState } from "react";
import CheckIcon from "@mui/icons-material/Check";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";

export const valueControlButtonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 4,
  minHeight: 25,
  fontSize: 11.5,
  padding: "2px 9px",
  background: "transparent",
  color: "var(--accent)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  cursor: "pointer",
};

// Copies the raw value. "boxed" sits in a value toolbar; "plain" is the borderless field-row icon.
export function CopyButton({ value, label, variant = "boxed" }: { value: string; label?: string; variant?: "boxed" | "plain" }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const plain = variant === "plain";
  const idleColor = plain ? "var(--text-faint)" : "var(--text-dim)";
  const prefix = label ? `${label} ` : "";

  async function copy(event: React.MouseEvent) {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setCopyError(false);
      window.setTimeout(() => setCopied(false), 1000);
    } catch {
      setCopyError(true);
      window.setTimeout(() => setCopyError(false), 2400);
    }
  }

  const button = (
    <button
      onClick={copy}
      title={copyError ? "복사 실패" : copied ? "복사됨" : "복사"}
      aria-label={copyError ? `${prefix}복사 실패` : copied ? `${prefix}복사됨` : `${prefix}값 복사`}
      style={plain
        ? { ...valueControlButtonStyle, width: 34, height: 32, padding: 0, border: "none", color: copyError ? "var(--danger)" : idleColor, flexShrink: 0, transition: "background .12s ease, color .12s ease" }
        : { ...valueControlButtonStyle, width: 28, padding: 0, color: copyError ? "var(--danger)" : idleColor }}
      onMouseEnter={plain ? (event) => { event.currentTarget.style.background = "var(--bg-elevated)"; event.currentTarget.style.color = "var(--text)"; } : undefined}
      onMouseLeave={plain ? (event) => { event.currentTarget.style.background = "transparent"; event.currentTarget.style.color = copyError ? "var(--danger)" : idleColor; } : undefined}
    >
      {copied ? <CheckIcon sx={{ fontSize: plain ? 19 : 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: plain ? 18 : 15 }} />}
    </button>
  );
  if (plain) return button;
  return (
    <>
      {button}
      {copyError && <span role="status" style={{ color: "var(--danger)", fontSize: 10.5, whiteSpace: "nowrap" }}>복사 실패</span>}
    </>
  );
}

export function JsonToggleButton({ beautified, onToggle }: { beautified: boolean; onToggle: () => void }) {
  return (
    <button onClick={onToggle} title={beautified ? "원본(압축) 보기" : "보기 좋게 정렬"} style={valueControlButtonStyle}>
      {"{ }"}
    </button>
  );
}
