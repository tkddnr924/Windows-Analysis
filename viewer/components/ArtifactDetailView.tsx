"use client";
import PaginationControls from "@/components/PaginationControls";

import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import AccountCircleOutlinedIcon from "@mui/icons-material/AccountCircleOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkOutlinedIcon from "@mui/icons-material/BookmarkOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import ExpandLessOutlinedIcon from "@mui/icons-material/ExpandLessOutlined";
import ExpandMoreOutlinedIcon from "@mui/icons-material/ExpandMoreOutlined";
import OpenInFullOutlinedIcon from "@mui/icons-material/OpenInFullOutlined";
import { CopyButton, JsonToggleButton, valueControlButtonStyle } from "./ValueControls";
import { prettyJsonOrNull, unescapeControlSequences } from "@/lib/jsonText";
import { fallbackLinkedRowTitle } from "@/lib/linkedRowTitle";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";
import PersonOutlineOutlinedIcon from "@mui/icons-material/PersonOutlineOutlined";
import type { ArtifactViewSpec, DetailSectionSpec, FieldKind, FieldSpec, LinkSpec } from "@/lib/artifactViews";
import { getArtifactView } from "@/lib/artifactViews";
import type { BrowserRecord, BrowserVisitFlow, FetchLinkedRows } from "@/lib/types";
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import VisitFlowGraphModal from "./VisitFlowGraph";
import { HexViewer } from "./HexViewer";
import { bodyKind } from "@/lib/browserView";
import { MACHINE_SCOPE_LABEL, MACHINE_SCOPE_USER, resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { OVERVIEW_TABLE_NAMES } from "@/lib/overviewLabels";
import { parsePrivileges, lookupPrivilege } from "@/lib/privileges";
import TagList from "./TagList";
import MiniTimeline from "./MiniTimeline";
import CodeModal from "./CodeModal";
import MftResidentData from "./MftResidentData";

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
        borderRadius: "var(--radius)",
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
  // Beautified view also expands control escapes; copy keeps the raw value.
  const shown = pretty !== null && beautified ? unescapeControlSequences(pretty) : raw;
  const isJson = pretty !== null;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 6, marginBottom: 4 }}>
        {isJson && <JsonToggleButton beautified={beautified} onToggle={() => setBeautified((b) => !b)} />}
        <CopyButton value={raw} />
        <button onClick={() => setExpanded(true)} title="크게 보기" aria-label="크게 보기" style={{ ...valueControlButtonStyle, width: 28, padding: 0, color: "var(--text-dim)" }}>
          <OpenInFullOutlinedIcon aria-hidden="true" sx={{ fontSize: 15 }} />
        </button>
      </div>
      {expanded && <CodeModal code={shown} title={expandTitle ?? "코드 보기"} onClose={() => setExpanded(false)} />}
      <pre
        style={{
          margin: 0,
          padding: 8,
          background: "var(--bg-input)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
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


function AccountValue({ account, accountDirectory }: { account: string; accountDirectory?: AccountDirectory }) {
  const display = resolveAccountDisplay(account, accountDirectory);
  // Label only; the raw value stays in the tooltip and the copy button.
  return (
    <span className="dfir-tag dfir-tag--info" title={display !== account ? account : undefined}>
      <AccountCircleOutlinedIcon sx={{ fontSize: 14 }} aria-hidden />
      {display}
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
      <div role="group" aria-label="크기 단위" style={{ display: "inline-flex", gap: 2, padding: 2, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)" }}>
        {(["Bytes", "KB", "MB", "GB"] as const).map((nextUnit) => (
          <button key={nextUnit} type="button" onClick={() => setUnit(nextUnit)} aria-pressed={unit === nextUnit} style={{ padding: "3px 6px", border: "none", borderRadius: "var(--radius)", cursor: "pointer", fontSize: 10.5, fontWeight: 650, background: unit === nextUnit ? "var(--accent-subtle)" : "transparent", color: unit === nextUnit ? "var(--accent)" : "var(--text-faint)" }}>
            {nextUnit}
          </button>
        ))}
      </div>
    </div>
  );
}

const CACHE_BODY_CHUNK = 1024 * 1024;

function base64Bytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

// Stored cache body (BrowserCacheDetails.body), read only on request and in
// chunks; nothing is reread from collected cache files (docs-07 R01, R03).
function CacheBodyView({ hostDir, recordId, contentType, total }: { hostDir: string; recordId: string; contentType: string; total: number }) {
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const identity = `${hostDir}\u0000${recordId}`;
  const tokenRef = useRef(0);
  useEffect(() => { tokenRef.current += 1; setBytes(null); setLoading(false); setError(false); }, [identity]);
  const load = () => {
    const token = ++tokenRef.current;
    const offset = bytes?.length ?? 0;
    setLoading(true);
    setError(false);
    window.api.browserCacheBody(hostDir, recordId, offset, CACHE_BODY_CHUNK)
      .then((chunk) => {
        if (token !== tokenRef.current) return;
        const next = base64Bytes(chunk.dataB64);
        setBytes((previous) => {
          if (!previous) return next;
          const merged = new Uint8Array(previous.length + next.length);
          merged.set(previous);
          merged.set(next, previous.length);
          return merged;
        });
      })
      .catch(() => { if (token === tokenRef.current) setError(true); })
      .finally(() => { if (token === tokenRef.current) setLoading(false); });
  };
  const kind = bytes ? bodyKind(bytes, contentType) : null;
  const complete = Boolean(bytes && bytes.length >= total);
  const text = useMemo(() => (bytes && kind === "text" ? new TextDecoder("utf-8").decode(bytes) : ""), [bytes, kind]);
  const imageUrl = useMemo(() => {
    if (!bytes || kind !== "image" || !complete) return "";
    let binary = "";
    for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
    return `data:${contentType.split(";")[0]};base64,${btoa(binary)}`;
  }, [bytes, kind, complete, contentType]);
  const button: React.CSSProperties = { padding: "4px 9px", borderRadius: "var(--radius)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--accent)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 };
  return (
    <div style={{ display: "grid", gap: 8 }}>
      {bytes && (kind === "image" && imageUrl
        ? <img src={imageUrl} alt="캐시 본문" style={{ display: "block", maxWidth: "100%", maxHeight: 360, border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-input)" }} />
        : kind === "text" ? <CodeOrJsonBlock raw={text} expandTitle="캐시 본문" />
        : <HexViewer bytes={bytes} maxHeight={320} />)}
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {!complete && (
          <button type="button" disabled={loading} onClick={load} style={button}>
            {loading ? "불러오는 중…" : bytes ? `나머지 불러오기 · ${bytes.length.toLocaleString()} / ${total.toLocaleString()} bytes` : `본문 열기 · ${total.toLocaleString()} bytes`}
          </button>
        )}
        {error && <span role="alert" style={{ color: "var(--danger)", fontSize: 11.5 }}>본문을 불러오지 못했습니다</span>}
      </div>
    </div>
  );
}

function ExtraRows({ rows }: { rows: [string, string | null | undefined, boolean?][] }) {
  const shown = rows.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!shown.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(96px, 30%) minmax(0, 1fr)", gap: "3px 8px" }}>
      {shown.map(([label, value, mono]) => (
        <Fragment key={label}>
          <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{label}</span>
          <span style={{ fontSize: 12, color: "var(--text)", fontFamily: mono ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{value}</span>
        </Fragment>
      ))}
    </div>
  );
}

function ExtraSection({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
      <div className="dfir-section-label" style={{ marginBottom: 7 }}>{heading}</div>
      {children}
    </div>
  );
}

// Stored relations of one BrowserActivity record: URL summary, search terms,
// download URL chain, cache response and the collected input (docs-07).
function BrowserRecordExtras({ recordId, eventType, hostDir }: { recordId: string; eventType: string; hostDir: string }) {
  const [record, setRecord] = useState<BrowserRecord | null>(null);
  const [failed, setFailed] = useState(false);
  const [flowState, setFlowState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [flow, setFlow] = useState<BrowserVisitFlow | null>(null);
  const [flowOpen, setFlowOpen] = useState(false);
  const flowToken = useRef(0);
  useEffect(() => {
    let alive = true;
    flowToken.current += 1;
    setRecord(null);
    setFailed(false);
    setFlowOpen(false);
    setFlow(null);
    setFlowState("idle");
    window.api.browserRecord(hostDir, recordId).then((result) => { if (alive) setRecord(result); }).catch(() => { if (alive) setFailed(true); });
    return () => { alive = false; };
  }, [hostDir, recordId]);
  const loadFlow = () => {
    const token = ++flowToken.current;
    setFlowOpen(true);
    setFlowState("loading");
    window.api.browserVisitFlow(hostDir, recordId)
      .then((result) => { if (token !== flowToken.current) return; setFlow(result); setFlowState("ready"); })
      .catch(() => { if (token === flowToken.current) setFlowState("error"); });
  };
  if (failed) return <ExtraSection heading="연결 기록"><span role="alert" style={{ color: "var(--danger)", fontSize: 12 }}>불러오지 못했습니다</span></ExtraSection>;
  if (!record) return null;
  const summary = record.urlSummary;
  const cache = record.cache;
  const bodyLength = Number(cache?.body_length);
  return (
    <>
      {summary && (
        <ExtraSection heading="URL 요약">
          {eventType === "url_summary"
            ? <ExtraRows rows={[["urls.id", summary.url_id, true], ["숨김", summary.hidden], ["마지막 방문 원문", summary.last_visit_raw, true], ["원본", [summary.source_table, summary.source_rowid].filter(Boolean).join(" #"), true]]} />
            : <ExtraRows rows={[["누적 방문 횟수", summary.visit_count], ["주소창 직접 입력 횟수", summary.typed_count], ["마지막 방문", summary.timestamp, true]]} />}
        </ExtraSection>
      )}
      {record.searchTerms.length > 0 && (
        <ExtraSection heading={`검색어 (${record.searchTerms.length})`}>
          <div style={{ display: "grid", gap: 4 }}>
            {record.searchTerms.map((term) => (
              <div key={term.search_id} style={{ display: "flex", gap: 8, alignItems: "baseline", fontSize: 12.5 }}>
                <span style={{ fontWeight: 650 }}>{term.term}</span>
                {term.normalized_term && term.normalized_term !== term.term && <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{term.normalized_term}</span>}
              </div>
            ))}
          </div>
        </ExtraSection>
      )}
      {record.downloadChain.length > 0 && (
        <ExtraSection heading={`다운로드 URL 체인 (${record.downloadChain.length})`}>
          <ol style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 4 }}>
            {record.downloadChain.map((link) => (
              <li key={link.ordinal} style={{ display: "grid", gridTemplateColumns: "24px minmax(0, 1fr)", gap: 6, fontFamily: "var(--mono)", fontSize: 11.5 }}>
                <span style={{ color: "var(--text-faint)", textAlign: "right" }}>{link.chain_index ?? link.ordinal}</span>
                <span style={{ wordBreak: "break-all" }}>{link.url}{link.url_decoded && link.url_decoded !== link.url && <span style={{ display: "block", color: "var(--text-dim)" }}>{link.url_decoded}</span>}</span>
              </li>
            ))}
          </ol>
        </ExtraSection>
      )}
      {cache && (
        <ExtraSection heading="캐시 응답">
          <div style={{ display: "grid", gap: 10 }}>
            <ExtraRows rows={[
              ["상태 줄", cache.status_line, true], ["Content-Type", cache.content_type, true], ["Content-Encoding", cache.content_encoding, true],
              ["Content-Length", cache.content_length], ["저장 본문 크기", cache.body_size], ["본문 파일", cache.body_file, true],
              ["본문 크기", cache.body_bytes],
              ["Server", cache.server, true], ["Date", cache.date, true], ["Last-Modified", cache.last_modified, true], ["ETag", cache.etag, true],
              ["Cache-Control", cache.cache_control, true], ["Location", cache.location, true],
            ]} />
            {cache.all_headers && <CodeOrJsonBlock raw={cache.all_headers} expandTitle="응답 헤더" />}
            {Number.isFinite(bodyLength) && cache.body_length !== null && cache.body_length !== undefined && (
              <CacheBodyView hostDir={hostDir} recordId={recordId} contentType={cache.content_type || ""} total={bodyLength} />
            )}
          </div>
        </ExtraSection>
      )}
      {record.input && (
        <ExtraSection heading="수집 입력">
          <ExtraRows rows={[["원본 파일", record.input.source_file, true], ["facts DB", record.input.facts_db, true]]} />
        </ExtraSection>
      )}
      {eventType === "visit" && (
        <div style={{ padding: "14px 16px 18px" }}>
          <button type="button" onClick={loadFlow} style={{ display: "inline-flex", alignItems: "center", gap: 7, padding: "8px 13px", borderRadius: "var(--radius)", border: "1px solid var(--accent)", background: "var(--accent-subtle)", color: "var(--accent)", cursor: "pointer", fontSize: 12.5, fontWeight: 650 }}>
            <AccountTreeOutlinedIcon sx={{ fontSize: 16 }} />이동 흐름 보기
          </button>
          {flowOpen && <VisitFlowGraphModal state={flowState} graph={flow} onRetry={loadFlow} onClose={() => setFlowOpen(false)} />}
        </div>
      )}
    </>
  );
}

// Same-generation metadata interfaces shown as a separate reference; never
// copied into the event (docs-08 R15).
function LocalNetworkReference({ hostDir, datasetId }: { hostDir: string; datasetId?: string }) {
  const [interfaces, setInterfaces] = useState<{ id: string; name: string; addresses: string; gateways: string; dns: string }[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let alive = true;
    // Never show another host's interfaces while the new lookup is pending.
    setInterfaces(null);
    setFailed(false);
    window.api.hostMetadata(hostDir, { kind: "network" }).then((meta) => {
      if (!alive) return;
      const join = (rows: Record<string, unknown>[], id: string) => rows.filter((entry) => entry.metadata_id === id).map((entry) => String(entry.address ?? "")).filter(Boolean).join(", ");
      const list = (meta.rows as Record<string, unknown>[])
        .filter((entry) => !datasetId || entry.dataset_id === datasetId)
        .map((entry) => {
          const id = String(entry.metadata_id ?? "");
          const addresses = join(meta.addresses as Record<string, unknown>[], id);
          const gateways = join(meta.gateways as Record<string, unknown>[], id);
          const dns = join(meta.dnsServers as Record<string, unknown>[], id);
          return { id, name: String(entry.interface_name || entry.value || entry.key || ""), addresses, gateways, dns };
        })
        .filter((entry) => entry.addresses || entry.gateways || entry.dns);
      setInterfaces(list);
    }).catch(() => { if (alive) setFailed(true); });
    return () => { alive = false; };
  }, [hostDir, datasetId, attempt]);
  if (failed) {
    return (
      <ExtraSection heading="로컬 네트워크 참조 (수집 시점)">
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span role="alert" style={{ fontSize: 12, color: "var(--danger)" }}>네트워크 정보를 불러오지 못했습니다.</span>
          <button type="button" onClick={() => setAttempt((value) => value + 1)} style={{ marginLeft: "auto", fontSize: 12, padding: "3px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text)", cursor: "pointer" }}>다시 시도</button>
        </div>
      </ExtraSection>
    );
  }
  if (!interfaces?.length) return null;
  return (
    <ExtraSection heading="로컬 네트워크 참조 (수집 시점)">
      <div style={{ display: "grid", gap: 8 }}>
        {interfaces.map((entry) => (
          <div key={entry.id} style={{ padding: "8px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", display: "grid", gap: 4 }}>
            <span style={{ fontSize: 12, fontWeight: 650 }}>{entry.name}</span>
            <ExtraRows rows={[["주소", entry.addresses, true], ["게이트웨이", entry.gateways, true], ["DNS", entry.dns, true]]} />
          </div>
        ))}
      </div>
    </ExtraSection>
  );
}

function FieldRow({ field, row, accountDirectory, onToggleFieldBookmark, isFieldBookmarked }: { field: FieldSpec; row: Record<string, string>; accountDirectory?: AccountDirectory; onToggleFieldBookmark?: (field: string) => void; isFieldBookmarked?: (field: string) => boolean }) {
  // resultRow returns SQL NULL as null; treat it as an empty value.
  const raw: string = (field.compute ? field.compute(row) : row[field.key]) ?? "";
  if (raw === "" && !field.showWhenEmpty) return null;

  const kind: FieldKind = field.kind ?? "text";
  const label = field.label ?? field.key;
  const displayValue = raw ? field.valueLabels?.[raw] ?? raw : field.emptyLabel ?? "값 없음";
  // Code/JSON fields provide their own adjacent copy + expand controls in
  // CodeOrJsonBlock. Rendering the generic field copy control as well creates
  // two identical actions for the same evidence value.
  // Plain fields that happen to contain JSON also render CodeOrJsonBlock, so
  // they must use its single copy control instead of adding FieldRow's copy.
  const hasInlineCodeControls = kind === "code" || kind === "json" || kind === "mftData" || prettyJsonOrNull(raw) !== null;

  let content: React.ReactNode;
  switch (kind) {
    case "badge": {
      const color = field.badgeColors?.[displayValue] ?? field.badgeColor;
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
      content = <AccountValue account={raw} accountDirectory={accountDirectory} />;
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
    case "mftData":
      content = <MftResidentData row={row} />;
      break;
    default:
      // A plain text/path field can still hold a JSON blob (e.g. a registry
      // value, a serialized argument) — offer the same beautify toggle when
      // the value actually parses as JSON, otherwise render it inline.
      content = prettyJsonOrNull(raw) ? <CodeOrJsonBlock raw={raw} expandTitle={label} /> : <span style={{ fontSize: 12.5 }}>{displayValue}</span>;
  }

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, maxWidth: "100%", padding: "8px 11px", marginBottom: 6, background: "var(--bg-elevated)", border: "1px solid color-mix(in srgb, var(--text-faint) 38%, transparent)", borderRadius: "var(--radius)" }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ minWidth: 0, fontSize: 11.5, fontWeight: 650, color: "var(--text-faint)", overflowWrap: "anywhere" }}>{label}</div>
        <div style={{ minWidth: 0, maxWidth: "100%", marginTop: 3, overflowWrap: "anywhere", wordBreak: "break-word" }}>{content}</div>
      </div>
      {((!hasInlineCodeControls && raw) || (field.bookmarkable && raw && onToggleFieldBookmark)) && (
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4, flexShrink: 0 }}>
          {!hasInlineCodeControls && raw && <CopyButton value={raw} variant="plain" />}
          {field.bookmarkable && raw && onToggleFieldBookmark && (
            <button
              type="button"
              className={isFieldBookmarked?.(field.key) ? "dfir-bookmark-control" : undefined}
              onClick={() => onToggleFieldBookmark(field.key)}
              aria-label={`${label} ${isFieldBookmarked?.(field.key) ? "북마크 해제" : "북마크"}`}
              title={isFieldBookmarked?.(field.key) ? "이 시각 북마크 해제" : "이 시각 북마크"}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 24, height: 22, padding: 0, border: `1px solid ${isFieldBookmarked?.(field.key) ? "var(--bookmark-outline)" : "var(--border)"}`, borderRadius: "var(--radius)", background: isFieldBookmarked?.(field.key) ? "var(--bookmark-row)" : "var(--bg-elevated)", color: isFieldBookmarked?.(field.key) ? "var(--bookmark-control)" : "var(--text-faint)", cursor: "pointer" }}
            >
              {isFieldBookmarked?.(field.key) ? <BookmarkOutlinedIcon sx={{ fontSize: 14 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 14 }} />}
            </button>
          )}
        </span>
      )}
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
      : targetSpec ? targetSpec.title(record) : fallbackLinkedRowTitle(record);
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
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(0);
  // Page and rows belong to one source row; reset before fetching another.
  const [shownSource, setShownSource] = useState({ link, value });
  if (shownSource.link !== link || shownSource.value !== value) {
    setShownSource({ link, value });
    setPage(0);
    setRows(null);
    setRowCount(0);
    setNotFound(false);
    setFailed(false);
  }

  useEffect(() => {
    if (!expanded) return;
    let active = true;
    setLoading(true);
    setNotFound(false);
    setFailed(false);
    onFetchLinkedRows(link.targetFile, link.targetColumn, value, { offset: page * LINKED_ROWS_PAGE_SIZE, limit: LINKED_ROWS_PAGE_SIZE })
      .then((result) => {
        if (!active) return;
        if (!result) setNotFound(true);
        else {
          setRows(result.rows);
          setRowCount(result.rowCount);
        }
      })
      .catch(() => { if (active) setFailed(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [expanded, link, onFetchLinkedRows, page, value, attempt]);

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", overflow: "hidden" }}>
      <button type="button" onClick={() => { setExpanded((current) => !current); setPage(0); }} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: 8, fontSize: 12, padding: "8px 10px", background: "var(--accent-subtle)", color: "var(--accent)", border: "none", cursor: "pointer", fontWeight: 600 }}>
        <span style={{ fontSize: 9 }}>{expanded ? "▾" : "▸"}</span>
        <span style={{ flex: 1 }}>{link.label}</span>
        {rowCount > 0 && <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{rowCount.toLocaleString()}</span>}
      </button>
      {expanded && (
        <div style={{ borderTop: "1px solid var(--border)", maxHeight: 260, overflow: "auto" }}>
          {loading && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-dim)" }}>불러오는 중...</div>}
          {notFound && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-faint)" }}>연결된 원본 테이블을 찾을 수 없습니다.</div>}
          {failed && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px" }}>
              <span role="alert" style={{ fontSize: 12, color: "var(--danger)" }}>연결된 항목을 조회하지 못했습니다.</span>
              <button type="button" onClick={() => setAttempt((current) => current + 1)} style={{ marginLeft: "auto", fontSize: 12, padding: "3px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--text)", cursor: "pointer" }}>다시 시도</button>
            </div>
          )}
          {!loading && !failed && !notFound && rows?.length === 0 && <div style={{ padding: "10px", fontSize: 12, color: "var(--text-faint)" }}>연결된 항목이 없습니다.</div>}
          {!loading && !failed && !notFound && rows && <LinkedRowList link={link} rows={rows} />}
          {!loading && !failed && !notFound && rows && <LinkPagination page={page} pageSize={LINKED_ROWS_PAGE_SIZE} rowCount={rowCount} onPageChange={setPage} />}
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
  // Search and page belong to one detail row; reset them before fetching another row.
  const [shownValue, setShownValue] = useState(value);
  if (shownValue !== value) {
    setShownValue(value);
    setQueryInput("");
    setQuery("");
    setPage(0);
    setRows(null);
    setRowCount(0);
  }

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
        <input value={queryInput} onChange={(event) => setQueryInput(event.target.value)} aria-label="참조 파일 검색" placeholder="파일명 또는 경로 검색" style={{ minWidth: 0, flex: 1, height: 30, padding: "0 9px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-input)", color: "var(--text)", fontSize: 12 }} />
        <button type="submit" style={{ height: 30, padding: "0 10px", border: "1px solid var(--accent)", borderRadius: "var(--radius)", background: "var(--accent-subtle)", color: "var(--accent)", fontSize: 12, cursor: "pointer" }}>검색</button>
      </form>
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", overflow: "hidden" }}>
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

function DetailSection({ section, row, accountDirectory, onToggleFieldBookmark, isFieldBookmarked }: { section: DetailSectionSpec; row: Record<string, string>; accountDirectory?: AccountDirectory; onToggleFieldBookmark?: (field: string) => void; isFieldBookmarked?: (field: string) => boolean }) {
  const visibleFields = section.fields.filter((field) => field.showWhenEmpty || (field.compute ? field.compute(row) : row[field.key]));
  const [expanded, setExpanded] = useState(section.collapsible?.defaultExpanded ?? true);
  if (visibleFields.length === 0) return null;

  const heading = typeof section.heading === "function" ? section.heading(row) : section.heading;
  const summary = section.collapsible?.summary?.(row, visibleFields.length) ?? `${visibleFields.length}개 필드`;
  if (!section.collapsible) {
    return (
      <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="dfir-section-label" style={{ marginBottom: 6 }}>{heading}</div>
        {visibleFields.map((field) => <FieldRow key={field.key} field={field} row={row} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />)}
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
          {visibleFields.map((field) => <FieldRow key={field.key} field={field} row={row} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />)}
        </div>
      )}
    </section>
  );
}

interface ArtifactDetailViewProps {
  spec: ArtifactViewSpec;
  row: Record<string, string>;
  evidenceTime?: { value: string; label?: string };
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Host evidence directory, required only for on-demand Browser Cache bodies. */
  hostDir?: string;
  /** Display-only exact SID directory for this record's authoritative host. */
  accountDirectory?: AccountDirectory;
  onToggleFieldBookmark?: (field: string) => void;
  isFieldBookmarked?: (field: string) => boolean;
  /** Panel content placed at spec sections marked with `slot`. */
  slots?: Partial<Record<"relatedEvidence", React.ReactNode>>;
}

export default function ArtifactDetailView({ spec, row, evidenceTime, onNavigate, onFetchLinkedRows, hostDir, accountDirectory, onToggleFieldBookmark, isFieldBookmarked, slots }: ArtifactDetailViewProps) {
  const title = spec.title(row);
  const subtitle = spec.subtitle?.(row);
  const tags = spec.tags?.(row) ?? [];

  const timelinePoints = (spec.timelineFields ?? []).map((f) => ({ label: f.label, value: row[f.key] ?? "" }));

  const activeLinks = (spec.links ?? []).filter((link) => row[link.key]);
  const activeEmbeddedLinks = (spec.embeddedLinks ?? []).filter((link) => row[link.key]);

  // Selection context does not replace any original evidence field.
  const timeValue = evidenceTime?.value ?? ((spec.timelineField ? row[spec.timelineField] : "") || row.timestamp || row.last_write || "");
  const showTime = Boolean(timeValue && (evidenceTime || spec.overviewTime !== "hide"));
  // docs-23 common top: an _OVERVIEW record's common columns are shown here
  // once (artifact specs do not repeat them).
  const isOverviewRecord = Boolean(row.overview_name);
  const timeLabel = evidenceTime?.label ?? (isOverviewRecord ? row.timestamp_kind : "");
  const accountText = row.account === MACHINE_SCOPE_USER
    ? `${MACHINE_SCOPE_LABEL} (HKLM)`
    : row.account || (row.account_sid ? resolveAccountDisplay(row.account_sid, accountDirectory) || row.account_sid : "");
  const eventTypeText = isOverviewRecord ? spec.eventTypeLabels?.[row.event_type] ?? row.event_type ?? "" : "";
  const accountChip = isOverviewRecord ? accountText : "";
  const descriptionText = isOverviewRecord && row.description && row.description !== title && row.description !== row.event_type ? row.description : "";

  return (
    <div style={{ minWidth: 0, maxWidth: "100%" }}>
      {row.overview_name === "RdpCache" && row.image && (
        <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)", lineHeight: 0 }}>
          <img src={`data:image/png;base64,${row.image}`} alt={`${row.source_file} ${row.fragment_index}`} style={{ maxWidth: "100%", imageRendering: "pixelated", border: "1px solid var(--border)", borderRadius: "var(--radius)" }} />
        </div>
      )}
      <div style={{ padding: "18px 16px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div className="dfir-section-label" style={{ marginBottom: 8 }}>증거 개요{isOverviewRecord && OVERVIEW_TABLE_NAMES[row.overview_name] ? ` · ${OVERVIEW_TABLE_NAMES[row.overview_name]}` : ""}</div>
        <div style={{ padding: "12px 14px", background: "var(--bg-elevated)", border: "1px solid color-mix(in srgb, var(--text-faint) 38%, transparent)", borderRadius: "var(--radius)" }}>
          <div style={{ minWidth: 0, maxWidth: "100%", fontSize: 16, fontWeight: 700, overflowWrap: "anywhere", wordBreak: "break-word" }}>{title}</div>
          {showTime && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5, color: "var(--text-time)", fontFamily: "var(--mono)", fontWeight: 550, marginTop: 7 }}>
              {timeLabel && <span style={{ color: "var(--text-dim)", fontFamily: "var(--sans)", fontWeight: 500 }}>{timeLabel}</span>}
              {timeValue}
              <CopyButton value={timeValue} variant="plain" />
            </div>
          )}
          {subtitle && !showTime && (
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, minWidth: 0, maxWidth: "100%", fontSize: 12.5, color: "var(--text-time)", fontFamily: "var(--mono)", fontWeight: 550, marginTop: 7, overflowWrap: "anywhere", wordBreak: "break-word" }}>
              <span style={{ minWidth: 0 }}>{subtitle}</span>
              <CopyButton value={subtitle} variant="plain" />
            </div>
          )}
          {(eventTypeText || accountChip) && (
            <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6, marginTop: 10 }}>
              {eventTypeText && (
                <span title="기록 종류" style={{ display: "inline-flex", alignItems: "center", gap: 5, maxWidth: "100%", minHeight: 24, padding: "2px 9px", borderRadius: "var(--radius)", border: "1px solid color-mix(in srgb, var(--accent) 45%, var(--border))", background: "var(--accent-subtle)", color: "var(--accent)", fontSize: 12, fontWeight: 700, overflowWrap: "anywhere" }}>
                  <CategoryOutlinedIcon aria-hidden="true" sx={{ fontSize: 14 }} />{eventTypeText}
                </span>
              )}
              {accountChip && (
                <span title={["계정", row.account_sid && row.account_sid !== accountChip ? row.account_sid : ""].filter(Boolean).join("\n")} style={{ display: "inline-flex", alignItems: "center", gap: 5, maxWidth: "100%", minHeight: 24, padding: "2px 10px", borderRadius: 999, border: "1px solid var(--border)", background: "var(--bg-panel)", color: "var(--text)", fontSize: 12, fontWeight: 650, overflowWrap: "anywhere" }}>
                  <PersonOutlineOutlinedIcon aria-hidden="true" sx={{ fontSize: 14, color: "var(--text-dim)" }} />{accountChip}
                </span>
              )}
            </div>
          )}
          {descriptionText && <div title="설명" style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 12.5, lineHeight: 1.5, overflowWrap: "anywhere" }}>{descriptionText}</div>}
        </div>
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
                    borderRadius: "var(--radius)",
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

      <MiniTimeline points={timelinePoints} heading={spec.timelineHeading ?? "시간 흐름"} />

      {spec.sections.map((section, index) => section.slot ? (
        // Content supplied by the opening panel, placed where the spec puts it.
        <Fragment key={`slot-${section.slot}-${index}`}>{slots?.[section.slot] ?? null}</Fragment>
      ) : (
        <DetailSection key={`${typeof section.heading === "string" ? section.heading : "computed"}-${index}`} section={section} row={row} accountDirectory={accountDirectory} onToggleFieldBookmark={onToggleFieldBookmark} isFieldBookmarked={isFieldBookmarked} />
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

      {hostDir && row.overview_name === "BrowserActivity" && row.record_id && (
        <BrowserRecordExtras recordId={row.record_id} eventType={row.event_type} hostDir={hostDir} />
      )}
      {hostDir && (row.overview_name === "RemoteDesktopHistory" || row.overview_name === "SmbHistory") && (
        <LocalNetworkReference hostDir={hostDir} datasetId={row.dataset_id} />
      )}
    </div>
  );
}
