"use client";
import PaginationControls from "@/components/PaginationControls";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import AccountCircleOutlinedIcon from "@mui/icons-material/AccountCircleOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import ExpandLessOutlinedIcon from "@mui/icons-material/ExpandLessOutlined";
import ExpandMoreOutlinedIcon from "@mui/icons-material/ExpandMoreOutlined";
import OpenInFullOutlinedIcon from "@mui/icons-material/OpenInFullOutlined";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import CheckIcon from "@mui/icons-material/Check";
import type { ArtifactViewSpec, DetailSectionSpec, FieldKind, FieldSpec, LinkSpec } from "@/lib/artifactViews";
import { getArtifactView } from "@/lib/artifactViews";
import type { CacheBodyPreview, FetchLinkedRows } from "@/lib/types";
import { isExactSid, resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { parsePrivileges, lookupPrivilege } from "@/lib/privileges";
import TagList from "./TagList";
import MiniTimeline from "./MiniTimeline";
import CodeModal from "./CodeModal";

// Renders a raw Windows PrivilegeList (event 4672/4673) as a simple readable
// list: each Se*Privilege with a plain "what it is" description. No risk
// judgment — these privileges are normal on admin/service logons.
function PrivilegeList({ raw }: { raw: string }) {
  const names = parsePrivileges(raw);
  if (names.length === 0) {
    return <span style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{raw}</span>;
  }
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        background: "var(--bg-input)",
        overflow: "hidden",
      }}
    >
      {names.map((name, i) => (
        <div
          key={name}
          style={{
            display: "flex",
            gap: 10,
            padding: "5px 9px",
            borderTop: i === 0 ? "none" : "1px solid var(--border-subtle)",
          }}
        >
          <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, wordBreak: "break-all", flex: "0 0 45%" }}>{name}</span>
          <span style={{ fontSize: 11.5, color: "var(--text-dim)", flex: 1 }}>{lookupPrivilege(name) ?? "-"}</span>
        </div>
      ))}
    </div>
  );
}

function formatBytes(value: string): string {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return value;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDurationMs(value: string): string {
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return value;
  if (ms < 1000) return `${ms.toLocaleString()} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}초`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(1)}분`;
  return `${(minutes / 60).toFixed(1)}시간`;
}

function prettyJsonOrNull(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

// Renders a code/JSON blob. When the value parses as JSON it defaults to a
// beautified (indented) view with a toggle back to the original one-line
// form; otherwise it just shows the raw text. An expand button opens the
// content full-screen (CodeModal) — the detail panel's box is small, and a
// PowerShell ScriptBlock can be hundreds of lines. Used for `json`/`code`
// fields and for any plain field whose value turns out to be JSON.
function CodeOrJsonBlock({ raw, expandTitle }: { raw: string; expandTitle?: string }) {
  const pretty = prettyJsonOrNull(raw);
  const [beautified, setBeautified] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const isJson = pretty !== null;
  const shown = isJson && beautified ? (pretty as string) : raw;

  async function copy() {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setCopyError(false);
      window.setTimeout(() => setCopied(false), 1000);
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
    color: "var(--accent)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    cursor: "pointer",
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 6, marginBottom: 4 }}>
        {isJson && (
          <button className="nm-btn"
            onClick={() => setBeautified((b) => !b)}
            title={beautified ? "원본(압축) 보기" : "보기 좋게 정렬"}
            style={btnStyle}
          >
            {"{ }"}
          </button>
        )}
        <button className="nm-btn" onClick={copy} title={copyError ? "복사 실패" : copied ? "복사됨" : "복사"} aria-label={copyError ? "복사 실패" : copied ? "복사됨" : "값 복사"} style={{ ...btnStyle, width: 32, padding: 0, color: copyError ? "var(--danger)" : "var(--text-dim)" }}>
          {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
        </button>
        <button className="nm-btn" onClick={() => setExpanded(true)} title="크게 보기" aria-label="크게 보기" style={{ ...btnStyle, width: 32, padding: 0, color: "var(--text-dim)" }}>
          <OpenInFullOutlinedIcon aria-hidden="true" sx={{ fontSize: 15 }} />
        </button>
      </div>
      {copyError && <div role="status" style={{ marginBottom: 4, color: "var(--danger)", fontSize: 10.5 }}>클립보드에 복사하지 못했습니다.</div>}
      {expanded && <CodeModal code={shown} title={expandTitle ?? "코드 보기"} onClose={() => setExpanded(false)} />}
      <pre
        style={{
          margin: 0,
          padding: 8,
          background: "var(--bg-input)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          fontFamily: "var(--mono)",
          fontSize: 12,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          maxHeight: 260,
          overflow: "auto",
        }}
      >
        {shown}
      </pre>
    </div>
  );
}

function Badge({ text, color }: { text: string; color?: string }) {
  if (!text) return null;
  return (
    <span
      className="dfir-tag"
      style={{
        background: color ? `${color}22` : "var(--bg-elevated)",
        color: color ?? "var(--text-dim)",
        border: `1px solid ${color ? `${color}55` : "var(--border)"}`,
      }}
    >
      {text}
    </span>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  return (
    <button
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setCopyError(false);
          window.setTimeout(() => setCopied(false), 1000);
        } catch {
          setCopyError(true);
          window.setTimeout(() => setCopyError(false), 2400);
        }
      }}
      className="nm-btn"
      title={copyError ? "복사 실패" : copied ? "복사됨" : "복사"}
      aria-label={copyError ? "복사 실패" : copied ? "복사됨" : "값 복사"}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: 32,
        height: 28,
        padding: 0,
        background: "var(--bg-elevated)",
        color: copyError ? "var(--danger)" : "var(--text-dim)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-md)",
        cursor: "pointer",
        flexShrink: 0,
      }}
    >
      {copied ? <CheckIcon sx={{ fontSize: 16, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
    </button>
  );
}

function AccountSidValue({ sid, accountDirectory }: { sid: string; accountDirectory?: AccountDirectory }) {
  const accountName = resolveAccountDisplay(sid, accountDirectory);

  return (
    <div>
      <div style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{sid}</div>
      {accountName !== sid && (
        <div style={{ marginTop: 6 }}>
          <span className="dfir-tag dfir-tag--info">
            <AccountCircleOutlinedIcon sx={{ fontSize: 14 }} aria-hidden />
            {accountName}
          </span>
        </div>
      )}
    </div>
  );
}

function AccountValue({ account, accountDirectory }: { account: string; accountDirectory?: AccountDirectory }) {
  const display = resolveAccountDisplay(account, accountDirectory);
  return (
    <span>
      <span className="dfir-tag dfir-tag--info">
        <AccountCircleOutlinedIcon sx={{ fontSize: 14 }} aria-hidden />
        {display}
      </span>
      {display !== account && isExactSid(account) && <span style={{ display: "block", marginTop: 5, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{account}</span>}
    </span>
  );
}

function parseByteSize(value: string): number | null {
  const match = value.trim().match(/^([\d,.]+)\s*(bytes?|kb|mb|gb|tb)?$/i);
  if (!match) return null;
  const amount = Number(match[1].replace(/,/g, ""));
  if (!Number.isFinite(amount) || amount < 0) return null;
  const unit = (match[2] || "bytes").toLowerCase();
  const multiplier = unit.startsWith("tb") ? 1024 ** 4 : unit.startsWith("gb") ? 1024 ** 3 : unit.startsWith("mb") ? 1024 ** 2 : unit.startsWith("kb") ? 1024 : 1;
  return Math.round(amount * multiplier);
}

function ByteSizeValue({ value }: { value: string }) {
  const bytes = parseByteSize(value);
  const [unit, setUnit] = useState<"Bytes" | "KB" | "MB" | "GB">("Bytes");
  if (bytes === null) return <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{value}</span>;
  const divisor = unit === "GB" ? 1024 ** 3 : unit === "MB" ? 1024 ** 2 : unit === "KB" ? 1024 : 1;
  const display = unit === "Bytes" ? `${bytes.toLocaleString()} Bytes` : `${(bytes / divisor).toLocaleString(undefined, { maximumFractionDigits: 2 })} ${unit}`;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}>{display}</span>
      <div role="group" aria-label="크기 단위" style={{ display: "inline-flex", gap: 2, padding: 2, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)" }}>
        {(["Bytes", "KB", "MB", "GB"] as const).map((nextUnit) => (
          <button key={nextUnit} type="button" onClick={() => setUnit(nextUnit)} aria-pressed={unit === nextUnit} style={{ padding: "3px 6px", border: "none", borderRadius: "var(--radius-sm)", cursor: "pointer", fontSize: 10.5, fontWeight: 650, background: unit === nextUnit ? "var(--accent-subtle)" : "transparent", color: unit === nextUnit ? "var(--accent)" : "var(--text-faint)" }}>
            {nextUnit}
          </button>
        ))}
      </div>
    </div>
  );
}

function decodeBase64Text(value: string): string {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return "";
  }
}

const CACHE_TEXT_PREVIEW_B64_CAP = 192 * 1024;

function cacheContentType(row: Record<string, string>): string {
  if (row.mime) return row.mime;
  const path = (row.url || "").split(/[?#]/)[0].toLowerCase();
  if (path.endsWith(".js")) return "application/javascript";
  if (path.endsWith(".css")) return "text/css";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".html") || path.endsWith(".htm")) return "text/html";
  if (path.endsWith(".svg")) return "image/svg+xml";
  return "";
}

function CacheDataValue({ row, hostDir }: { row: Record<string, string>; hostDir?: string }) {
  const [state, setState] = useState<"idle" | "loading" | "ready" | "unavailable">("idle");
  const [body, setBody] = useState<CacheBodyPreview | null>(null);
  const loadTokenRef = useRef(0);
  const contentType = cacheContentType(row);
  const cacheIdentity = `${hostDir ?? ""}\u0000${row.account ?? ""}\u0000${row.url ?? ""}\u0000${row.cache_key ?? ""}`;
  const recoveryStateKnown = row.cache_body_recovered !== undefined;
  const hasRecoveredBody = row.cache_body_recovered === "1";

  // Decoding or JSON formatting a multi-megabyte body in the WebView used to
  // monopolize the event loop after the IPC result arrived. The Rust command
  // already returns a bounded base64 response; keep the visible text prefix
  // smaller still, so opening it never has to paint an unbounded <pre>.
  const textPreview = useMemo(() => {
    if (!body || !(/^text\//i.test(contentType) || /json|javascript|xml|svg/i.test(contentType))) return "";
    return decodeBase64Text(body.bodyB64.slice(0, CACHE_TEXT_PREVIEW_B64_CAP));
  }, [body, contentType]);
  const textPreviewTruncated = Boolean(body && (body.truncated || body.bodyB64.length > CACHE_TEXT_PREVIEW_B64_CAP));

  useEffect(() => {
    // Cache detail opens must not start disk I/O on their own. In addition to
    // avoiding unnecessary work for normal cache metadata, this keeps a
    // legacy overview (which has no recovery marker) responsive until the
    // analyst deliberately requests its body.
    loadTokenRef.current += 1;
    setState("idle");
    setBody(null);
    return () => { loadTokenRef.current += 1; };
  }, [cacheIdentity]);

  function loadRecoveredBody() {
    if (!hostDir || !row.account || !row.url) {
      setState("unavailable");
      return;
    }
    const loadToken = loadTokenRef.current + 1;
    loadTokenRef.current = loadToken;
    setState("loading");
    setBody(null);
    // `cache_entry_body` performs filesystem/SQLite work on a Rust blocking
    // worker. The local guard keeps a later selection from receiving this
    // response, while the drawer and the rest of the app stay interactive.
    window.api.cacheEntryBody(hostDir, row.account, row.url, row.cache_key || "")
      .then((response) => {
        if (loadToken !== loadTokenRef.current) return;
        if (!response.bodyB64) { setState("unavailable"); return; }
        setBody(response);
        setState("ready");
      })
      .catch(() => {
        if (loadToken === loadTokenRef.current) setState("unavailable");
      });
  }

  if (state === "loading") return <span style={{ display: "inline-flex", alignItems: "center", gap: 7, color: "var(--text-dim)", fontSize: 12 }}><CircularProgress size={14} thickness={4} sx={{ color: "var(--accent)" }} />복구 데이터 불러오는 중</span>;
  if (state === "unavailable") return <span style={{ color: "var(--warning)", fontSize: 12.5, fontWeight: 650 }}>복구 데이터 확인 불가 · 원본 캐시를 다시 확인하세요</span>;
  if (state === "idle") {
    if (!hasRecoveredBody) {
      if (recoveryStateKnown) return <span style={{ color: "var(--danger)", fontSize: 12.5, fontWeight: 650 }}>파싱 실패</span>;
      return <span style={{ color: "var(--text-faint)", fontSize: 12 }}>이전 분석 데이터 · 재파싱 필요</span>;
    }
    if (!(row.cache_key || "").trim()) return <span style={{ color: "var(--text-faint)", fontSize: 12 }}>캐시 식별자 없음 · 재파싱 필요</span>;
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <button type="button" onClick={loadRecoveredBody} style={{ padding: "4px 8px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--accent)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}>복구 데이터 열기</button>
      </div>
    );
  }
  if (!body) return null;
  if (/^image\//i.test(contentType) && !body.truncated) return <img src={`data:${contentType.split(";")[0]};base64,${body.bodyB64}`} alt="복구된 캐시 데이터" style={{ display: "block", maxWidth: "100%", maxHeight: 360, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-input)" }} />;
  if (/^text\//i.test(contentType) || /json|javascript|xml|svg/i.test(contentType)) return <div><CodeOrJsonBlock raw={textPreview} expandTitle="캐시 데이터" />{textPreviewTruncated && <div style={{ marginTop: 6, color: "var(--text-faint)", fontSize: 11.5 }}>복구된 본문 {body.decodedSize.toLocaleString()} Bytes 중 성능 보호용 미리보기만 표시합니다.</div>}</div>;
  const byteLength = parseByteSize(row.size_bytes || row.size || "");
  return <span style={{ color: "var(--text-dim)", fontSize: 12.5 }}>바이너리 데이터 복구됨{byteLength !== null ? ` · ${byteLength.toLocaleString()} Bytes` : body.decodedSize ? ` · ${body.decodedSize.toLocaleString()} Bytes` : ""}{body.truncated ? " (미리보기 제한)" : ""}</span>;
}

function FieldRow({ field, row, onFetchLinkedRows, hostDir, accountDirectory, onToggleFieldBookmark, isFieldBookmarked }: { field: FieldSpec; row: Record<string, string>; onFetchLinkedRows?: FetchLinkedRows; hostDir?: string; accountDirectory?: AccountDirectory; onToggleFieldBookmark?: (field: string) => void; isFieldBookmarked?: (field: string) => boolean }) {
  const raw = field.compute ? field.compute(row) ?? "" : row[field.key];
  if ((raw === undefined || raw === null || raw === "") && !field.showWhenEmpty) return null;

  const kind: FieldKind = field.kind ?? "text";
  const label = field.label ?? field.key;
  const displayValue = raw ? field.valueLabels?.[raw] ?? raw : field.emptyLabel ?? "값 없음";
  // Code/JSON fields provide their own adjacent copy + expand controls in
  // CodeOrJsonBlock. Rendering the generic field copy control as well creates
  // two identical actions for the same evidence value.
  // Plain fields that happen to contain JSON also render CodeOrJsonBlock, so
  // they must use its single copy control instead of adding FieldRow's copy.
  const hasInlineCodeControls = kind === "code" || kind === "json" || kind === "cacheData" || prettyJsonOrNull(raw) !== null;

  let content: React.ReactNode;
  switch (kind) {
    case "badge": {
      const color = field.badgeColors?.[displayValue];
      content = <Badge text={displayValue} color={color} />;
      break;
    }
    case "bytes":
      content = <span>{formatBytes(raw)}</span>;
      break;
    case "hash":
      content = (
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--accent)", wordBreak: "break-all" }}>
          {raw}
        </span>
      );
      break;
    case "path":
      content = (
        <span style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{raw}</span>
      );
      break;
    case "code":
    case "json":
      content = <CodeOrJsonBlock raw={raw} expandTitle={label} />;
      break;
    case "privileges":
      content = <PrivilegeList raw={raw} />;
      break;
    case "accountSid":
      content = <AccountSidValue sid={raw} accountDirectory={accountDirectory} />;
      break;
    case "account":
      content = <AccountValue account={raw} accountDirectory={accountDirectory} />;
      break;
    case "byteSize":
      content = <ByteSizeValue value={raw} />;
      break;
    case "durationMs":
      content = <span>{formatDurationMs(raw)}</span>;
      break;
    case "cacheData":
      content = <CacheDataValue row={row} hostDir={hostDir} />;
      break;
    default:
      // A plain text/path field can still hold a JSON blob (e.g. a registry
      // value, a serialized argument) — offer the same beautify toggle when
      // the value actually parses as JSON, otherwise render it inline.
      content = prettyJsonOrNull(raw) ? <CodeOrJsonBlock raw={raw} expandTitle={label} /> : <span style={{ fontSize: 12.5 }}>{displayValue}</span>;
  }

  return (
    <div style={{ minWidth: 0, maxWidth: "100%", padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
        <span style={{ minWidth: 0, fontSize: 11, color: "var(--text-faint)", overflowWrap: "anywhere" }}>{label}</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, flexShrink: 0 }}>
          {!hasInlineCodeControls && raw && <CopyButton value={raw} />}
          {field.bookmarkable && raw && onToggleFieldBookmark && (
            <button
              type="button"
              className={isFieldBookmarked?.(field.key) ? "dfir-bookmark-control" : undefined}
              onClick={() => onToggleFieldBookmark(field.key)}
              aria-label={`${label} ${isFieldBookmarked?.(field.key) ? "북마크 해제" : "북마크"}`}
              title={isFieldBookmarked?.(field.key) ? "이 시각 북마크 해제" : "이 시각 북마크"}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 24, height: 22, padding: 0, border: `1px solid ${isFieldBookmarked?.(field.key) ? "var(--bookmark-outline)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", background: isFieldBookmarked?.(field.key) ? "var(--bookmark-row)" : "var(--bg-elevated)", color: isFieldBookmarked?.(field.key) ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}
            >
              {isFieldBookmarked?.(field.key) ? <BookmarkOutlinedIcon sx={{ fontSize: 14 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 14 }} />}
            </button>
          )}
        </span>
      </div>
      <div style={{ minWidth: 0, maxWidth: "100%", marginTop: 3, overflowWrap: "anywhere", wordBreak: "break-word" }}>{content}</div>
    </div>
  );
}

const LINKED_ROWS_PAGE_SIZE = 10;
const EMBEDDED_ROWS_PAGE_SIZE = 10;

function LinkedRowList({
  link,
  rows,
}: {
  link: LinkSpec;
  rows: Record<string, string>[];
}) {
  const targetSpec = getArtifactView(link.targetFile);
  return rows.map((record, index) => {
    const isPrefetchReference = link.targetFile === "Prefetch_LoadedFiles";
    const title = isPrefetchReference
      ? record.loaded_filename || "(파일명 없음)"
      : targetSpec ? targetSpec.title(record) : Object.values(record)[1] ?? "";
    const subtitle = isPrefetchReference
      ? record.file_reference || ""
      : targetSpec?.subtitle?.(record) ?? "";
    return (
      <div
        key={record.__rowid || `${title}-${index}`}
        style={{
          padding: "8px 10px",
          borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)",
          fontSize: 12.5,
          background: index % 2 ? "var(--bg-input)" : "transparent",
        }}
      >
        <div style={{ color: "var(--text)", wordBreak: "break-all", lineHeight: 1.45 }}>{title}</div>
        {subtitle && <div style={{ marginTop: 2, color: "var(--text-faint)", fontSize: 11.5, wordBreak: "break-all" }}>{subtitle}</div>}
      </div>
    );
  });
}

function LinkPagination({
  page,
  pageSize,
  rowCount,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  rowCount: number;
  onPageChange: (page: number) => void;
}) {
  if (rowCount === 0) return null;
  const totalPages = Math.max(1, Math.ceil(rowCount / pageSize));
  const start = page * pageSize + 1;
  const end = Math.min((page + 1) * pageSize, rowCount);
  const buttonStyle: React.CSSProperties = {
    padding: "3px 8px",
    borderRadius: "var(--radius-sm)",
    border: "1px solid var(--border)",
    background: "var(--bg-elevated)",
    color: "var(--text-dim)",
    fontSize: 11,
  };
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "7px 10px", borderTop: "1px solid var(--border-subtle)", fontSize: 11.5, color: "var(--text-faint)" }}>
      <span>{start.toLocaleString()}–{end.toLocaleString()} / {rowCount.toLocaleString()}개</span>
      <PaginationControls ariaLabel="연결 레코드 페이지" page={page} pageCount={totalPages} onChange={onPageChange} />
    </div>
  );
}

// Standard related-evidence links remain an accordion. They now use database
// pages too, avoiding a full source-table materialisation when expanded.
function LinkAccordion({ link, value, onFetchLinkedRows }: { link: LinkSpec; value: string; onFetchLinkedRows: FetchLinkedRows }) {
  const [expanded, setExpanded] = useState(false);
  const [rows, setRows] = useState<Record<string, string>[] | null>(null);
  const [rowCount, setRowCount] = useState(0);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(0);

  useEffect(() => {
    if (!expanded) return;
    let active = true;
    setLoading(true);
    setNotFound(false);
    onFetchLinkedRows(link.targetFile, link.targetColumn, value, { offset: page * LINKED_ROWS_PAGE_SIZE, limit: LINKED_ROWS_PAGE_SIZE })
      .then((result) => {
        if (!active) return;
        if (!result) setNotFound(true);
        else {
          setRows(result.rows);
          setRowCount(result.rowCount);
        }
      })
      .catch(() => { if (active) setNotFound(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [expanded, link, onFetchLinkedRows, page, value]);

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
      <button type="button" onClick={() => { setExpanded((current) => !current); setPage(0); }} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: 8, fontSize: 12, padding: "8px 10px", background: "var(--accent-subtle)", color: "var(--accent)", border: "none", cursor: "pointer", fontWeight: 600 }}>
        <span style={{ fontSize: 9 }}>{expanded ? "▾" : "▸"}</span>
        <span style={{ flex: 1 }}>{link.label}</span>
        {rowCount > 0 && <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{rowCount.toLocaleString()}</span>}
      </button>
      {expanded && (
        <div style={{ borderTop: "1px solid var(--border)", maxHeight: 260, overflow: "auto" }}>
          {loading && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-dim)" }}>불러오는 중...</div>}
          {notFound && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-faint)" }}>연결된 원본 테이블을 찾을 수 없습니다.</div>}
          {!loading && rows?.length === 0 && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-faint)" }}>연결된 항목이 없습니다.</div>}
          {!loading && rows && <LinkedRowList link={link} rows={rows} />}
          {!loading && rows && <LinkPagination page={page} pageSize={LINKED_ROWS_PAGE_SIZE} rowCount={rowCount} onPageChange={setPage} />}
        </div>
      )}
    </div>
  );
}

function EmbeddedLinkRows({ link, value, onFetchLinkedRows }: { link: LinkSpec; value: string; onFetchLinkedRows: FetchLinkedRows }) {
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [rows, setRows] = useState<Record<string, string>[] | null>(null);
  const [rowCount, setRowCount] = useState(0);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(true);
  const sectionRef = useRef<HTMLDivElement>(null);
  const savedDrawerScrollTop = useRef<number | null>(null);

  function changePage(nextPage: number) {
    const drawerScroller = sectionRef.current?.closest<HTMLElement>("[data-detail-scroll-container]");
    savedDrawerScrollTop.current = drawerScroller?.scrollTop ?? null;
    setPage(nextPage);
  }

  // The database request changes the rows asynchronously. Restore the
  // enclosing drawer's position after React commits those rows so changing a
  // reference-file page never throws an analyst back to the evidence header.
  useLayoutEffect(() => {
    const savedTop = savedDrawerScrollTop.current;
    if (savedTop === null) return;
    const drawerScroller = sectionRef.current?.closest<HTMLElement>("[data-detail-scroll-container]");
    if (!drawerScroller) return;
    drawerScroller.scrollTop = savedTop;
    const frame = requestAnimationFrame(() => { drawerScroller.scrollTop = savedTop; });
    savedDrawerScrollTop.current = null;
    return () => cancelAnimationFrame(frame);
  }, [page, loading, rows]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setFailed(false);
    onFetchLinkedRows(link.targetFile, link.targetColumn, value, { search: query, offset: page * EMBEDDED_ROWS_PAGE_SIZE, limit: EMBEDDED_ROWS_PAGE_SIZE })
      .then((result) => {
        if (!active) return;
        if (!result) setFailed(true);
        else {
          setRows(result.rows);
          setRowCount(result.rowCount);
        }
      })
      .catch(() => { if (active) setFailed(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [link, onFetchLinkedRows, page, query, value]);

  function submitSearch(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(0);
    setQuery(queryInput.trim());
  }

  return (
    <div ref={sectionRef} style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
      <div className="dfir-section-label" style={{ marginBottom: 8 }}>{link.label}</div>
      <form onSubmit={submitSearch} style={{ display: "flex", gap: 6, marginBottom: 8 }}>
        <input value={queryInput} onChange={(event) => setQueryInput(event.target.value)} aria-label="참조 파일 검색" placeholder="파일명 또는 경로 검색" style={{ minWidth: 0, flex: 1, height: 30, padding: "0 9px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-input)", color: "var(--text)", fontSize: 12 }} />
        <button type="submit" style={{ height: 30, padding: "0 10px", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", background: "var(--accent-subtle)", color: "var(--accent)", fontSize: 12, cursor: "pointer" }}>검색</button>
      </form>
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
        <div aria-live="polite" style={{ maxHeight: 240, overflowY: "auto", overscrollBehavior: "contain" }}>
          {loading && <div style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 52, padding: "10px", color: "var(--text-dim)", fontSize: 12 }}><CircularProgress size={14} thickness={5} /> 참조 파일을 불러오는 중</div>}
          {failed && <div style={{ minHeight: 52, padding: "10px", color: "var(--danger)", fontSize: 12 }}>참조 파일을 조회하지 못했습니다.</div>}
          {!loading && !failed && rows?.length === 0 && <div style={{ minHeight: 52, padding: "10px", color: "var(--text-faint)", fontSize: 12 }}>{query ? "검색 결과가 없습니다." : "Prefetch에 기록된 참조 파일이 없습니다."}</div>}
          {!loading && !failed && rows && <LinkedRowList link={link} rows={rows} />}
        </div>
        {!loading && !failed && rows && <LinkPagination page={page} pageSize={EMBEDDED_ROWS_PAGE_SIZE} rowCount={rowCount} onPageChange={changePage} />}
      </div>
    </div>
  );
}

function DetailSection({ section, row, onFetchLinkedRows, hostDir, accountDirectory, onToggleFieldBookmark, isFieldBookmarked }: { section: DetailSectionSpec; row: Record<string, string>; onFetchLinkedRows?: FetchLinkedRows; hostDir?: string; accountDirectory?: AccountDirectory; onToggleFieldBookmark?: (field: string) => void; isFieldBookmarked?: (field: string) => boolean }) {
  const visibleFields = section.fields.filter((field) => field.showWhenEmpty || (field.compute ? field.compute(row) : row[field.key]));
  const [expanded, setExpanded] = useState(section.collapsible?.defaultExpanded ?? true);
  if (visibleFields.length === 0) return null;

  const heading = typeof section.heading === "function" ? section.heading(row) : section.heading;
  const summary = section.collapsible?.summary?.(row, visibleFields.length) ?? `${visibleFields.length}개 필드`;
  if (!section.collapsible) {
    return (
      <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="dfir-section-label" style={{ marginBottom: 6 }}>{heading}</div>
        {visibleFields.map((field) => <FieldRow key={field.key} field={field} row={row} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDir} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />)}
      </div>
    );
  }

  return (
    <section style={{ borderBottom: "1px solid var(--border-subtle)" }}>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded((current) => !current)}
        style={{ width: "100%", display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", background: "transparent", border: "none", color: "var(--text)", cursor: "pointer", textAlign: "left" }}
      >
        {expanded ? <ExpandLessOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} aria-hidden /> : <ExpandMoreOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} aria-hidden />}
        <span className="dfir-section-label" style={{ flex: "0 0 auto" }}>{heading}</span>
        <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginLeft: "auto", color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{summary}</span>
      </button>
      {expanded && (
        <div style={{ padding: "0 16px 12px" }}>
          {visibleFields.map((field) => <FieldRow key={field.key} field={field} row={row} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDir} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />)}
        </div>
      )}
    </section>
  );
}

interface ArtifactDetailViewProps {
  spec: ArtifactViewSpec;
  row: Record<string, string>;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Host evidence directory, required only for on-demand Browser Cache bodies. */
  hostDir?: string;
  /** Display-only exact SID directory for this record's authoritative host. */
  accountDirectory?: AccountDirectory;
  onToggleFieldBookmark?: (field: string) => void;
  isFieldBookmarked?: (field: string) => boolean;
}

export default function ArtifactDetailView({ spec, row, onNavigate, onFetchLinkedRows, hostDir, accountDirectory, onToggleFieldBookmark, isFieldBookmarked }: ArtifactDetailViewProps) {
  const title = spec.title(row);
  const subtitle = spec.subtitle?.(row);
  const tags = spec.tags?.(row) ?? [];

  const timelinePoints = (spec.timelineFields ?? [])
    .map((f) => ({ label: f.label, value: row[f.key] ?? "" }))
    .filter((p) => p.value);

  const activeLinks = (spec.links ?? []).filter((link) => row[link.key]);
  const activeEmbeddedLinks = (spec.embeddedLinks ?? []).filter((link) => row[link.key]);

  // The record's time. Always surfaced when present — the primary timeline
  // field if the spec declares one, else a plain "timestamp"/"last_write".
  const timeValue = (spec.timelineField ? row[spec.timelineField] : "") || row.timestamp || row.last_write || "";

  return (
    <div style={{ minWidth: 0, maxWidth: "100%" }}>
      <div style={{ padding: "18px 16px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="dfir-section-label" style={{ marginBottom: 7 }}>증거 개요</div>
        <div style={{ minWidth: 0, maxWidth: "100%", fontSize: 16, fontWeight: 700, overflowWrap: "anywhere", wordBreak: "break-word" }}>{title}</div>
        {timeValue && spec.overviewTime !== "hide" && (
          <div style={{ fontSize: 12.5, color: "var(--text-dim)", fontFamily: "var(--mono)", fontWeight: 550, marginTop: 7 }}>
            {timeValue}
          </div>
        )}
        {subtitle && (
          <div style={{ minWidth: 0, maxWidth: "100%", fontSize: 12.5, color: "var(--text-dim)", marginTop: 3, overflowWrap: "anywhere", wordBreak: "break-word" }}>
            {subtitle}
          </div>
        )}
        {spec.badges && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            {spec.badges.map((b) => {
              const value = b.compute ? b.compute(row) ?? "" : row[b.key];
              if (!value) return null;
              const displayValue = b.valueLabels?.[value] ?? value;
              return <Badge key={b.key} text={displayValue} color={b.badgeColors?.[displayValue]} />;
            })}
          </div>
        )}
        {activeLinks.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 10 }}>
            {activeLinks.map((link) =>
              onFetchLinkedRows ? (
                <LinkAccordion key={link.key} link={link} value={row[link.key]} onFetchLinkedRows={onFetchLinkedRows} />
              ) : (
                <button
                  key={link.key}
                  onClick={() => onNavigate(link.targetFile, link.targetColumn, row[link.key])}
                  style={{
                    textAlign: "left",
                    fontSize: 12,
                    padding: "7px 10px",
                    background: "var(--accent-subtle)",
                    color: "var(--accent)",
                    border: "1px solid var(--accent)",
                    borderRadius: "var(--radius-md)",
                    cursor: "pointer",
                  }}
                >
                  → {link.label}
                </button>
              )
            )}
          </div>
        )}
      </div>

      {timelinePoints.length >= 2 && (
        <div style={{ padding: "14px 16px 10px", borderBottom: "1px solid var(--border-subtle)" }}>
          <div className="dfir-section-label" style={{ marginBottom: 6 }}>{spec.timelineHeading ?? "시간 흐름"}</div>
          <MiniTimeline points={timelinePoints} />
        </div>
      )}

      {spec.sections.map((section, index) => (
        <DetailSection key={`${typeof section.heading === "string" ? section.heading : "computed"}-${index}`} section={section} row={row} onFetchLinkedRows={onFetchLinkedRows} hostDir={hostDir} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />
      ))}

      {activeEmbeddedLinks.map((link) =>
        onFetchLinkedRows ? (
          <EmbeddedLinkRows key={link.key} link={link} value={row[link.key]} onFetchLinkedRows={onFetchLinkedRows} />
        ) : null
      )}

      {tags.length > 0 && (
        <div style={{ padding: "14px 16px 18px", borderBottom: "1px solid var(--border-subtle)" }}>
          <div className="dfir-section-label" style={{ marginBottom: 7 }}>분석 주의</div>
          <TagList tags={tags} />
        </div>
      )}
    </div>
  );
}
