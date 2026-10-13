"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import CheckIcon from "@mui/icons-material/Check";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import { hexDump } from "@/lib/textDecoders";
import { useModalDialog } from "@/lib/useModalDialog";

// The app's --mono is a proportional face; hex columns need a real monospace.
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";
const COLUMNS = Array.from({ length: 16 }, (_, index) => index);

function byteColor(byte: number): string {
  if (byte === 0) return "var(--text-faint)";
  if (byte >= 0x20 && byte < 0x7f) return "var(--text)";
  return "#8fcaff";
}

/** Read-only hex viewer: offset / 16 hex cells / ASCII, with linked hover and
 * click(+Shift) range selection and a status bar for the selected bytes. */
export function HexViewer({ bytes, maxHeight = 320, fontSize = 12 }: { bytes: Uint8Array; maxHeight?: number | string; fontSize?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const [anchor, setAnchor] = useState<number | null>(null);
  const [focus, setFocus] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  // New buffer: offsets from the previous one are meaningless.
  useEffect(() => { setAnchor(null); setFocus(null); setHover(null); }, [bytes]);
  const start = anchor === null ? null : Math.min(anchor, focus ?? anchor);
  const end = anchor === null ? null : Math.max(anchor, focus ?? anchor);
  const selected = (index: number) => start !== null && end !== null && index >= start && index <= end;
  const select = (index: number, extend: boolean) => {
    if (extend && anchor !== null) setFocus(index);
    else { setAnchor(index); setFocus(index); }
  };
  const selection = start === null || end === null ? bytes : bytes.subarray(start, end + 1);
  const copy = async (kind: "hex" | "dump") => {
    const text = kind === "hex" ? Array.from(selection, (byte) => byte.toString(16).padStart(2, "0")).join(" ") : hexDump(bytes);
    try { await navigator.clipboard.writeText(text); setCopied(kind); window.setTimeout(() => setCopied(null), 1200); } catch { setCopied(null); }
  };
  const cell = (index: number, content: string, width: string, extra: React.CSSProperties = {}) => {
    const byte = bytes[index];
    const active = selected(index);
    return (
      <span
        key={`${width}-${index}`}
        onMouseEnter={() => setHover(index)}
        onMouseDown={(event) => { event.preventDefault(); select(index, event.shiftKey); }}
        style={{ width, textAlign: "center", cursor: "pointer", borderRadius: 3, color: active ? "var(--text)" : byteColor(byte), background: active ? "color-mix(in srgb, var(--accent) 38%, transparent)" : hover === index ? "color-mix(in srgb, var(--accent) 18%, transparent)" : "transparent", ...extra }}
      >{content}</span>
    );
  };
  const rows = Math.ceil(bytes.length / 16);
  // Large values (e.g. 284 KB REG_BINARY) would create ~570k nodes; render visible rows only.
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowHeight = Math.round(fontSize * 1.65);
  const virtualizer = useVirtualizer({ count: rows, getScrollElement: () => scrollRef.current, estimateSize: () => rowHeight, overscan: 16 });
  const virtualRows = virtualizer.getVirtualItems();
  const padTop = virtualRows[0]?.start ?? 0;
  const padBottom = virtualRows.length ? virtualizer.getTotalSize() - virtualRows[virtualRows.length - 1].end : 0;
  const info = start === null || end === null ? hover : start;
  const infoByte: number | undefined = info === null ? undefined : bytes[info];
  const status = start !== null && end !== null && end > start
    ? `선택 0x${start.toString(16).toUpperCase()}–0x${end.toString(16).toUpperCase()} · ${(end - start + 1).toLocaleString()} bytes`
    : info !== null && infoByte !== undefined
      ? `Offset 0x${info.toString(16).toUpperCase().padStart(8, "0")} (${info.toLocaleString()}) · 0x${infoByte.toString(16).toUpperCase().padStart(2, "0")} · ${infoByte} · ${infoByte >= 0x20 && infoByte < 0x7f ? `'${String.fromCharCode(infoByte)}'` : "비인쇄 문자"}`
      : `${bytes.length.toLocaleString()} bytes · 클릭으로 선택, Shift+클릭으로 범위 선택`;
  const button: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 4, minHeight: 22, padding: "0 7px", fontSize: 11, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer" };
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0, border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", background: "var(--bg-input)", overflow: "hidden" }}>
      <div ref={scrollRef} onMouseLeave={() => setHover(null)} style={{ flex: "0 1 auto", minHeight: 0, overflow: "auto", maxHeight, fontFamily: MONO, fontSize, lineHeight: `${rowHeight}px`, userSelect: "none" }}>
        <div style={{ display: "inline-block", minWidth: "100%", padding: "4px 10px 6px" }}>
          <div style={{ position: "sticky", top: 0, display: "flex", alignItems: "center", gap: 14, padding: "2px 0 4px", marginBottom: 2, borderBottom: "1px solid var(--border-subtle)", background: "var(--bg-input)", color: "var(--text-faint)", whiteSpace: "pre" }}>
            <span style={{ width: "8ch" }}>Offset</span>
            <span style={{ display: "flex", gap: 0 }}>{COLUMNS.map((column) => <span key={column} style={{ width: "3ch", textAlign: "center", marginRight: column === 7 ? "1ch" : 0, color: hover !== null && hover % 16 === column ? "var(--accent)" : undefined }}>{column.toString(16).toUpperCase().padStart(2, "0")}</span>)}</span>
            <span>ASCII</span>
          </div>
          {padTop > 0 && <div style={{ height: padTop }} />}
          {virtualRows.map(({ index: row }) => {
            const base = row * 16;
            const indexes = COLUMNS.map((column) => base + column).filter((index) => index < bytes.length);
            const rowHovered = hover !== null && Math.floor(hover / 16) === row;
            return (
              <div key={row} style={{ display: "flex", alignItems: "center", gap: 14, height: rowHeight, whiteSpace: "pre" }}>
                <span style={{ width: "8ch", color: rowHovered ? "var(--accent)" : "var(--text-faint)" }}>{base.toString(16).toUpperCase().padStart(8, "0")}</span>
                <span style={{ display: "flex", width: "49ch" }}>{indexes.map((index) => cell(index, bytes[index].toString(16).toUpperCase().padStart(2, "0"), "3ch", { marginRight: index % 16 === 7 ? "1ch" : 0 }))}</span>
                <span style={{ display: "flex", borderLeft: "1px solid var(--border-subtle)", paddingLeft: 10 }}>{indexes.map((index) => cell(index, bytes[index] >= 0x20 && bytes[index] < 0x7f ? String.fromCharCode(bytes[index]) : ".", "1ch"))}</span>
              </div>
            );
          })}
          {padBottom > 0 && <div style={{ height: padBottom }} />}
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 8px", borderTop: "1px solid var(--border-subtle)", background: "var(--bg-panel)", fontSize: 11, color: "var(--text-dim)" }}>
        <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: MONO }}>{status}</span>
        <button type="button" onClick={() => copy("hex")} style={button} title={start === null ? "전체 바이트를 Hex로 복사" : "선택 바이트를 Hex로 복사"}>{copied === "hex" ? <CheckIcon sx={{ fontSize: 13, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 12 }} />}{start === null ? "Hex" : "선택 Hex"}</button>
        <button type="button" onClick={() => copy("dump")} style={button} title="Hex 덤프 전체 복사">{copied === "dump" ? <CheckIcon sx={{ fontSize: 13, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 12 }} />}덤프</button>
      </div>
    </div>
  );
}

/** Full-size hex viewer in a modal, same shell as the code view. */
export function HexModal({ bytes, title, onClose }: { bytes: Uint8Array; title: string; onClose: () => void }) {
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}>
      <div ref={dialogRef} onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={{ width: "min(900px, 92vw)", maxHeight: "86vh", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)" }}>
          <strong id={titleId} style={{ fontSize: 13 }}>{title}</strong>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{bytes.length.toLocaleString()} bytes</span>
          <button type="button" className="nm-btn" onClick={onClose} data-dialog-autofocus aria-label="Hex 보기 닫기" title="닫기 (Esc)" style={{ marginLeft: "auto", minHeight: 28, padding: "2px 8px", fontSize: 16, lineHeight: 1, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer" }}>×</button>
        </div>
        <div style={{ padding: 12, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <HexViewer bytes={bytes} maxHeight="calc(86vh - 120px)" fontSize={13} />
        </div>
      </div>
    </div>
  );
}
