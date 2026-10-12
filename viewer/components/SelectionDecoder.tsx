"use client";

import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from "react";
import CheckIcon from "@mui/icons-material/Check";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import { decodeBase64, decodeHex, decodeUrl, type DecodeResult } from "@/lib/textDecoders";

const DECODERS: { id: string; label: string; run: (text: string) => DecodeResult }[] = [
  { id: "base64", label: "Base64", run: decodeBase64 },
  { id: "url", label: "URL", run: decodeUrl },
  { id: "hex", label: "Hex", run: decodeHex },
];

const MARGIN = 8;
const WIDTH = 470;

const buttonStyle: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: 24,
  fontSize: 11.5,
  padding: "1px 9px",
  background: "var(--bg-elevated)",
  color: "var(--text-dim)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  cursor: "pointer",
};

/** Display-only decode popup for text selected inside `containerRef`. The
 * evidence text itself is never changed. */
export default function SelectionDecoder({ containerRef }: { containerRef: RefObject<HTMLElement | null> }) {
  const popupRef = useRef<HTMLDivElement>(null);
  const [selection, setSelection] = useState<{ text: string; top: number; bottom: number; left: number } | null>(null);
  const [decoded, setDecoded] = useState<{ label: string; result: DecodeResult } | null>(null);
  const [copied, setCopied] = useState(false);
  const [top, setTop] = useState(0);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const capture = () => {
      const current = window.getSelection();
      const text = current?.toString() ?? "";
      if (!current || !text.trim() || !current.rangeCount || !container.contains(current.anchorNode)) return;
      const rect = current.getRangeAt(0).getBoundingClientRect();
      setSelection({ text, top: rect.top, bottom: rect.bottom, left: Math.max(MARGIN, Math.min(rect.left, window.innerWidth - WIDTH - MARGIN)) });
      setDecoded(null);
      setCopied(false);
    };
    const close = () => setSelection(null);
    container.addEventListener("mouseup", capture);
    // Capture phase: nested scrollers (e.g. CodeMirror) do not bubble scroll.
    container.addEventListener("scroll", close, true);
    return () => {
      container.removeEventListener("mouseup", capture);
      container.removeEventListener("scroll", close, true);
    };
  }, [containerRef]);

  // Re-measure whenever the content grows: below the selection if it fits,
  // else above it, else pinned inside the viewport.
  useLayoutEffect(() => {
    if (!selection || !popupRef.current) return;
    const height = popupRef.current.offsetHeight;
    const below = selection.bottom + 6;
    const above = selection.top - height - 6;
    if (below + height <= window.innerHeight - MARGIN) setTop(below);
    else if (above >= MARGIN) setTop(above);
    else setTop(Math.max(MARGIN, window.innerHeight - height - MARGIN));
  }, [selection, decoded]);

  if (!selection) return null;

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div ref={popupRef} role="dialog" aria-label="선택 문자열 디코딩" onMouseUp={(event) => event.stopPropagation()} onClick={(event) => event.stopPropagation()} style={{ position: "fixed", top, left: selection.left, zIndex: 210, width: WIDTH, maxWidth: `calc(100vw - ${MARGIN * 2}px)`, maxHeight: `calc(100vh - ${MARGIN * 2}px)`, display: "flex", flexDirection: "column", gap: 8, padding: 10, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
        <span style={{ fontSize: 11.5, color: "var(--text-faint)", marginRight: 4 }}>선택 {selection.text.length.toLocaleString()}자 디코딩</span>
        {DECODERS.map((decoder) => {
          const active = decoded?.label === decoder.label;
          return <button key={decoder.id} type="button" className="nm-btn" onClick={() => { setDecoded({ label: decoder.label, result: decoder.run(selection.text) }); setCopied(false); }} aria-pressed={active} style={{ ...buttonStyle, color: active ? "var(--accent)" : buttonStyle.color, borderColor: active ? "var(--accent)" : "var(--border)" }}>{decoder.label}</button>;
        })}
        <button type="button" className="nm-btn" onClick={() => setSelection(null)} aria-label="디코딩 창 닫기" style={{ ...buttonStyle, marginLeft: "auto", padding: "1px 7px" }}>×</button>
      </div>
      {decoded && (decoded.result.ok ? (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11.5, color: "var(--text-faint)", flexShrink: 0 }}>
            <span>{decoded.label} 디코딩 · {decoded.result.encoding}</span>
            <button type="button" className="nm-btn" onClick={() => decoded.result.ok && copy(decoded.result.text)} aria-label="디코딩 결과 복사" title={copied ? "복사됨" : "복사"} style={{ ...buttonStyle, minHeight: 22, width: 26, padding: 0, marginLeft: "auto" }}>{copied ? <CheckIcon sx={{ fontSize: 14, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 13 }} />}</button>
          </div>
          <pre style={{ margin: 0, minHeight: 0, maxHeight: 260, overflow: "auto", padding: 8, background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--text)" }}>{decoded.result.text}</pre>
        </>
      ) : (
        <div role="status" style={{ fontSize: 12, color: "var(--warning)" }}>{decoded.result.error}</div>
      ))}
    </div>
  );
}
