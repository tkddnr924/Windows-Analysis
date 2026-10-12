"use client";

import { useContext, useEffect, useMemo, useState } from "react";
import OpenInFullOutlinedIcon from "@mui/icons-material/OpenInFullOutlined";
import type { MftRecordBody } from "@/lib/types";
import { RecordScopeContext } from "@/lib/recordScope";
import { MFT_DATA_STATUS_LABELS } from "@/lib/artifactViews";
import { decodeBytes } from "@/lib/textDecoders";
import CodeModal from "./CodeModal";
import { HexModal, HexViewer } from "./HexViewer";

const RESIDENT = new Set(["resident", "resident_empty"]);

/** Resident $DATA stored in FileSystemEntries.data (≤ ~700 bytes per record):
 * read automatically for the selected record and shown as text or hex. Other
 * states show the parser-stored data_status; nothing is guessed. */
export default function MftResidentData({ row }: { row: Record<string, string> }) {
  const scope = useContext(RecordScopeContext);
  const rowid = Number(row.__rowid);
  const status = row.data_status ?? "";
  const resident = RESIDENT.has(status);
  const [body, setBody] = useState<MftRecordBody | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"text" | "hex">("text");
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setBody(null);
    setError(null);
    setMode("text");
    if (!resident || !scope?.fullPath || !Number.isSafeInteger(rowid)) return;
    let alive = true;
    window.api.mftRecordBody(scope.fullPath, rowid)
      .then((value) => { if (alive) setBody(value); })
      .catch(() => { if (alive) setError("Resident 본문을 불러오지 못했습니다."); });
    return () => { alive = false; };
  }, [resident, scope?.fullPath, rowid]);

  const bytes = useMemo(() => {
    if (!body?.bodyB64) return new Uint8Array();
    const binary = atob(body.bodyB64);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }, [body?.bodyB64]);
  const decoded = useMemo(() => (bytes.length ? decodeBytes(bytes) : null), [bytes]);
  // Binary bodies open in hex; text bodies in text.
  const effectiveMode = decoded && !decoded.ok ? "hex" : mode;
  const shown = decoded?.ok ? decoded.text : "";

  if (!resident) {
    return <span style={{ fontSize: 12.5, color: "var(--text-dim)" }}>{MFT_DATA_STATUS_LABELS[status] ?? (status || "본문 상태가 저장되지 않았습니다")} — 저장된 본문이 없습니다.</span>;
  }
  if (error) return <span role="alert" style={{ fontSize: 12, color: "var(--danger)" }}>{error}</span>;
  if (!body) return <span style={{ fontSize: 12, color: "var(--text-faint)" }}>본문을 불러오는 중…</span>;
  // Absent BLOB (null) is not an empty body; empty is only present with 0 bytes.
  if (body.dataPresent === null) return <span style={{ fontSize: 12.5, color: "var(--warning)" }}>본문 상태는 「{MFT_DATA_STATUS_LABELS[body.dataStatus ?? ""] ?? "미상"}」이지만 저장된 본문이 없습니다.</span>;
  if (!bytes.length) return <span style={{ fontSize: 12.5, color: "var(--text-dim)" }}>빈 Resident 본문 (0 Bytes)</span>;

  const tab = (value: "text" | "hex", label: string, disabled = false) => (
    <button type="button" disabled={disabled} aria-pressed={effectiveMode === value} onClick={() => setMode(value)} style={{ minHeight: 22, padding: "0 8px", fontSize: 11, fontWeight: 650, border: "none", borderRadius: "var(--radius)", cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.45 : 1, background: effectiveMode === value ? "var(--accent-subtle)" : "transparent", color: effectiveMode === value ? "var(--accent)" : "var(--text-faint)" }}>{label}</button>
  );
  return (
    <div style={{ display: "grid", gap: 6, minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{Number(body.dataLen ?? bytes.length).toLocaleString()} Bytes{decoded?.ok ? ` · ${decoded.encoding}` : " · 바이너리"}{body.truncated ? " · 앞부분만 표시" : ""}</span>
        <span style={{ display: "inline-flex", gap: 2, padding: 2, marginLeft: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
          {tab("text", "텍스트", !decoded?.ok)}
          {tab("hex", "Hex")}
        </span>
        <button type="button" className="nm-btn" onClick={() => setExpanded(true)} aria-label="Resident 본문 확장 보기" title="확장 보기" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 26, height: 26, padding: 0, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer" }}>
          <OpenInFullOutlinedIcon sx={{ fontSize: 14 }} />
        </button>
      </div>
      {effectiveMode === "hex"
        ? <HexViewer bytes={bytes} maxHeight={260} />
        : <pre style={{ margin: 0, maxHeight: 260, overflow: "auto", padding: 8, background: "var(--bg-input)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius)", fontFamily: "var(--mono)", fontSize: 12, lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-word", color: "var(--text)" }}>{shown}</pre>}
      {expanded && (effectiveMode === "hex"
        ? <HexModal bytes={bytes} title={`${row.file_name || "Resident 본문"} · $DATA Hex`} onClose={() => setExpanded(false)} />
        : <CodeModal code={shown} title={`${row.file_name || "Resident 본문"} · $DATA 텍스트`} onClose={() => setExpanded(false)} />)}
    </div>
  );
}
