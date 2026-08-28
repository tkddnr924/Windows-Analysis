"use client";

import { useId, useState } from "react";
import CheckIcon from "@mui/icons-material/Check";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import { useModalDialog } from "@/lib/useModalDialog";

// A full-screen overlay that shows one code/text blob on its own — for when a
// ScriptBlock (or any long code field) is too big to read inside the detail
// panel's small scroll box. Copy + wrap toggle + Escape/click-outside close.
export default function CodeModal({
  code,
  title = "코드 보기",
  onClose,
}: {
  code: string;
  title?: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [wrap, setWrap] = useState(true);
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setCopyError(false);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopyError(true);
      window.setTimeout(() => setCopyError(false), 2400);
    }
  }

  const btnStyle: React.CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 4,
    minHeight: 28,
    fontSize: 11.5,
    padding: "3px 10px",
    background: "var(--bg-elevated)",
    color: "var(--text-dim)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    cursor: "pointer",
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(1,4,9,0.75)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 200,
        padding: 24,
      }}
    >
      <div
        ref={dialogRef}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{
          width: "min(1000px, 92vw)",
          height: "min(820px, 86vh)",
          display: "flex",
          flexDirection: "column",
          background: "var(--bg-panel)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow-panel)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 14px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-elevated)",
            flexShrink: 0,
          }}
        >
          <strong id={titleId} style={{ fontSize: 13 }}>{title}</strong>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{code.length.toLocaleString()}자</span>
          <button className="nm-btn" onClick={() => setWrap((w) => !w)} style={{ ...btnStyle, marginLeft: "auto" }}>
            {wrap ? "줄바꿈 끄기" : "줄바꿈 켜기"}
          </button>
          <button className="nm-btn" onClick={copyCode} title={copyError ? "복사 실패" : copied ? "복사됨" : "복사"} aria-label={copyError ? "복사 실패" : copied ? "복사됨" : "코드 복사"} style={{ ...btnStyle, width: 32, padding: 0, color: copyError ? "var(--danger)" : btnStyle.color }}>
            {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
          </button>
          <button className="nm-btn"
            onClick={onClose}
            data-dialog-autofocus
            aria-label="코드 보기 닫기"
            title="닫기 (Esc)"
            style={{ ...btnStyle, fontSize: 16, lineHeight: 1, padding: "2px 8px" }}
          >
            ×
          </button>
        </div>
        {copyError && <div role="status" style={{ padding: "6px 14px", color: "var(--danger)", borderBottom: "1px solid var(--border-subtle)", fontSize: 11.5 }}>클립보드에 복사하지 못했습니다. 권한을 확인한 뒤 다시 시도하세요.</div>}
        <pre
          style={{
            margin: 0,
            flex: 1,
            overflow: "auto",
            padding: 16,
            fontFamily: "var(--mono)",
            fontSize: 13,
            lineHeight: 1.55,
            whiteSpace: wrap ? "pre-wrap" : "pre",
            wordBreak: wrap ? "break-word" : "normal",
            color: "var(--text)",
          }}
        >
          {code}
        </pre>
      </div>
    </div>
  );
}
