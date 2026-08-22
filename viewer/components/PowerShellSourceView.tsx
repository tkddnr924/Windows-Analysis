"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useModalDialog } from "@/lib/useModalDialog";

// A focused analysis view for one PowerShell script block: the source on the
// left, a decoding/deobfuscation workbench on the right. Separate from the
// generic CodeModal (which just shows a blob larger) — this one understands
// PowerShell.

// Automatic/built-in variables and scope prefixes that must NOT be renamed
// when normalizing obfuscated variable names (they carry meaning).
const AUTO_VARS = new Set([
  "_", "true", "false", "null", "args", "input", "this", "pscmdlet", "psboundparameters",
  "matches", "error", "host", "home", "pwd", "pid", "profile", "psscriptroot", "pscommandpath",
  "env", "foreach", "switch", "lastexitcode", "stacktrace", "ofs", "shellid", "executioncontext",
  "myinvocation", "nestedpromptlevel", "consolefilename", "eventargs", "event", "eventsubscriber",
  "sender", "psversiontable", "allnodes", "true", "false",
  // scope / drive prefixes ($global:x, $env:PATH, ...) — left as-is
  "global", "script", "local", "private", "using", "variable", "workflow",
]);

const VAR_RE = /\$(\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)/g;

// Rewrite every distinct user variable to $Value_1, $Value_2, ... in first-seen
// order (PowerShell variable names are case-insensitive, so folding is too),
// and return the alias→original legend so the analyst can map back. Automatic
// variables and scope prefixes are skipped.
function normalizeVariables(code: string): { code: string; legend: { alias: string; original: string }[] } {
  const alias = new Map<string, string>(); // lowerName -> $Value_n
  const original = new Map<string, string>(); // lowerName -> first-seen spelling
  let counter = 0;

  code.replace(VAR_RE, (full, inner: string) => {
    const name = inner.startsWith("{") ? inner.slice(1, -1) : inner;
    const lower = name.toLowerCase();
    if (AUTO_VARS.has(lower)) return full;
    if (!alias.has(lower)) {
      counter += 1;
      alias.set(lower, `$Value_${counter}`);
      original.set(lower, name);
    }
    return full;
  });

  const out = code.replace(VAR_RE, (full, inner: string) => {
    const name = inner.startsWith("{") ? inner.slice(1, -1) : inner;
    return alias.get(name.toLowerCase()) ?? full;
  });

  const legend = [...alias.entries()].map(([lower, a]) => ({ alias: a, original: `$${original.get(lower) ?? lower}` }));
  return { code: out, legend };
}

function countReplacement(s: string): number {
  let n = 0;
  for (const ch of s) if (ch === "�") n += 1;
  return n;
}

function decodeBytes(bytes: Uint8Array, enc: string): string {
  try {
    return new TextDecoder(enc).decode(bytes);
  } catch {
    return "";
  }
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

interface Conversion {
  note: string;
  output: string;
}

// PowerShell's -EncodedCommand payload is UTF-16LE base64; other base64 blobs
// are usually UTF-8. Decode both and keep whichever has fewer replacement
// characters (i.e. looks like real text).
function convertBase64(sel: string): Conversion {
  const cleaned = sel.replace(/[^A-Za-z0-9+/=]/g, "");
  if (cleaned.length < 4) throw new Error("Base64로 보이는 문자가 없습니다.");
  const bytes = base64ToBytes(cleaned);
  const u16 = decodeBytes(bytes, "utf-16le");
  const u8 = decodeBytes(bytes, "utf-8");
  const useU16 = u16.length > 0 && countReplacement(u16) <= countReplacement(u8);
  return { note: `Base64 → ${useU16 ? "UTF-16LE" : "UTF-8"} (${bytes.length} bytes)`, output: useU16 ? u16 : u8 };
}

function convertUrl(sel: string): Conversion {
  const s = sel.trim();
  let out: string;
  try {
    out = decodeURIComponent(s.replace(/\+/g, "%20"));
  } catch {
    out = s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }
  return { note: "URL 디코드", output: out };
}

// A drag over something like "BYTE[] (111,234,23,123)" — pull the 0–255 numbers
// and turn them back into text (UTF-8 if valid, else Latin1).
function convertBytes(sel: string): Conversion {
  const nums = (sel.match(/\d+/g) ?? []).map(Number).filter((n) => n >= 0 && n <= 255);
  if (!nums.length) throw new Error("0–255 범위의 숫자를 찾지 못했습니다.");
  const bytes = new Uint8Array(nums);
  const u8 = decodeBytes(bytes, "utf-8");
  let latin = "";
  for (const n of nums) latin += String.fromCharCode(n);
  const useU8 = u8.length > 0 && countReplacement(u8) === 0;
  return { note: `${nums.length} bytes → ${useU8 ? "UTF-8" : "Latin1"}`, output: useU8 ? u8 : latin };
}

interface Result {
  id: number;
  note: string;
  input: string;
  output: string;
  error?: boolean;
}

export default function PowerShellSourceView({
  code,
  title = "소스코드 보기",
  onClose,
}: {
  code: string;
  title?: string;
  onClose: () => void;
}) {
  const [normalized, setNormalized] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [selection, setSelection] = useState("");
  const [results, setResults] = useState<Result[]>([]);
  const [copiedAll, setCopiedAll] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const counter = useRef(0);
  const titleId = useId();
  const dialogRef = useModalDialog(onClose);

  const norm = useMemo(() => normalizeVariables(code), [code]);
  const shown = normalized ? norm.code : code;

  useEffect(() => {
    function onSel() {
      setSelection(window.getSelection?.()?.toString() ?? "");
    }
    document.addEventListener("selectionchange", onSel);
    return () => {
      document.removeEventListener("selectionchange", onSel);
    };
  }, []);

  async function copyText(value: string, onSuccess?: () => void) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyError(false);
      onSuccess?.();
    } catch {
      setCopyError(true);
      window.setTimeout(() => setCopyError(false), 2400);
    }
  }

  function runConvert(kind: "base64" | "url" | "bytes") {
    const sel = (window.getSelection?.()?.toString() ?? selection).trim();
    counter.current += 1;
    const id = counter.current;
    if (!sel) {
      setResults((r) => [
        { id, note: "선택 없음", input: "", output: "먼저 왼쪽 소스코드에서 변환할 부분을 드래그로 선택하세요.", error: true },
        ...r,
      ]);
      return;
    }
    try {
      const c = kind === "base64" ? convertBase64(sel) : kind === "url" ? convertUrl(sel) : convertBytes(sel);
      setResults((r) => [{ id, note: c.note, input: sel, output: c.output }, ...r]);
    } catch (e) {
      setResults((r) => [{ id, note: "변환 실패", input: sel, output: e instanceof Error ? e.message : String(e), error: true }, ...r]);
    }
  }

  const btn: React.CSSProperties = {
    fontSize: 11,
    padding: "3px 9px",
    background: "var(--bg-elevated)",
    color: "var(--text-dim)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-sm)",
    cursor: "pointer",
    whiteSpace: "nowrap",
  };
  const convertBtn: React.CSSProperties = { ...btn, color: "var(--accent)", borderColor: "var(--border)" };

  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}
    >
      <div
        ref={dialogRef}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{
          width: "min(1280px, 96vw)",
          height: "min(860px, 90vh)",
          display: "flex",
          flexDirection: "column",
          background: "var(--bg-panel)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow-panel)",
          overflow: "hidden",
        }}
      >
        {/* header */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)", flexShrink: 0 }}>
          <strong id={titleId} style={{ fontSize: 13 }}>{title}</strong>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{code.length.toLocaleString()}자</span>
          <button
            onClick={() => setNormalized((v) => !v)}
            title="난독화된 변수 이름을 $Value_1, $Value_2 …로 치환"
            style={{ ...btn, marginLeft: "auto", color: normalized ? "var(--accent)" : "var(--text-dim)", borderColor: normalized ? "var(--accent)" : "var(--border)" }}
          >
            {normalized ? "✓ 변수 정리됨" : "변수 정리"}
          </button>
          <button onClick={() => setWrap((w) => !w)} style={btn}>{wrap ? "줄바꿈 끄기" : "줄바꿈 켜기"}</button>
          <button onClick={() => void copyText(shown, () => { setCopiedAll(true); window.setTimeout(() => setCopiedAll(false), 1200); })} style={{ ...btn, color: copyError ? "var(--danger)" : btn.color }}>
            {copyError ? "복사 실패" : copiedAll ? "복사됨" : "코드 복사"}
          </button>
          <button onClick={onClose} data-dialog-autofocus aria-label="소스코드 보기 닫기" title="닫기 (Esc)" style={{ ...btn, fontSize: 16, lineHeight: 1, padding: "2px 8px" }}>×</button>
        </div>
        {copyError && <div role="status" style={{ padding: "6px 14px", color: "var(--danger)", borderBottom: "1px solid var(--border-subtle)", fontSize: 11.5 }}>클립보드에 복사하지 못했습니다. 권한을 확인한 뒤 다시 시도하세요.</div>}

        {/* body: code | analysis */}
        <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
          {/* left: source code */}
          <div style={{ flex: "1 1 58%", minWidth: 0, display: "flex", flexDirection: "column", borderRight: "1px solid var(--border)" }}>
            <pre
              style={{
                margin: 0,
                flex: 1,
                overflow: "auto",
                padding: 16,
                fontFamily: "var(--mono)",
                fontSize: 12.5,
                lineHeight: 1.55,
                whiteSpace: wrap ? "pre-wrap" : "pre",
                wordBreak: wrap ? "break-word" : "normal",
                color: "var(--text)",
                userSelect: "text",
              }}
            >
              {shown}
            </pre>
            {normalized && norm.legend.length > 0 && (
              <div style={{ flexShrink: 0, maxHeight: 140, overflow: "auto", borderTop: "1px solid var(--border)", padding: "8px 16px", background: "var(--bg-input)" }}>
                <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", marginBottom: 4 }}>변수 매핑 ({norm.legend.length})</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "2px 14px" }}>
                  {norm.legend.map((l) => (
                    <span key={l.alias} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", whiteSpace: "nowrap" }}>
                      <span style={{ color: "var(--accent)" }}>{l.alias}</span> = {l.original}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* right: analysis panel */}
          <div style={{ flex: "1 1 42%", minWidth: 0, display: "flex", flexDirection: "column", background: "var(--bg-panel)" }}>
            <div style={{ flexShrink: 0, padding: "10px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginBottom: 8 }}>
                왼쪽에서 변환할 부분을 <strong>드래그로 선택</strong>한 뒤 버튼을 누르세요.
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button onMouseDown={(e) => e.preventDefault()} onClick={() => runConvert("base64")} style={convertBtn}>Base64 디코드</button>
                <button onMouseDown={(e) => e.preventDefault()} onClick={() => runConvert("url")} style={convertBtn}>URL 디코드</button>
                <button onMouseDown={(e) => e.preventDefault()} onClick={() => runConvert("bytes")} style={convertBtn}>바이트 배열 → 문자열</button>
                {results.length > 0 && (
                  <button onMouseDown={(e) => e.preventDefault()} onClick={() => setResults([])} style={{ ...btn, marginLeft: "auto" }}>
                    결과 지우기
                  </button>
                )}
              </div>
              {selection.trim() && (
                <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  선택: {selection.trim().slice(0, 80)}{selection.trim().length > 80 ? "…" : ""}
                </div>
              )}
            </div>

            <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
              {results.length === 0 && (
                <div style={{ color: "var(--text-faint)", fontSize: 12, textAlign: "center", padding: 20 }}>
                  변환 결과가 여기에 쌓입니다. 디코딩된 값을 다시 선택해 연속으로 변환할 수도 있습니다.
                </div>
              )}
              {results.map((r) => (
                <div key={r.id} style={{ border: `1px solid ${r.error ? "var(--danger)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", overflow: "hidden", flexShrink: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 10px", background: "var(--bg-elevated)", fontSize: 11 }}>
                    <span style={{ color: r.error ? "var(--danger)" : "var(--accent)", fontWeight: 600 }}>{r.note}</span>
                    {!r.error && (
                      <button
                        onClick={() => void copyText(r.output)}
                        style={{ marginLeft: "auto", ...btn, fontSize: 10, padding: "1px 7px" }}
                      >
                        복사
                      </button>
                    )}
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 10,
                      fontFamily: "var(--mono)",
                      fontSize: 12,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      color: r.error ? "var(--danger)" : "var(--text)",
                      userSelect: "text",
                      maxHeight: 260,
                      overflow: "auto",
                    }}
                  >
                    {r.output}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
