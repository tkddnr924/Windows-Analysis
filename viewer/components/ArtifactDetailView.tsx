"use client";

import { useState } from "react";
import type { ArtifactViewSpec, FieldKind, FieldSpec, LinkSpec } from "@/lib/artifactViews";
import { getArtifactView } from "@/lib/artifactViews";
import type { FetchLinkedRows } from "@/lib/types";
import { parsePrivileges, lookupPrivilege } from "@/lib/privileges";
import TagList from "./TagList";
import MiniTimeline from "./MiniTimeline";

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

function prettyJsonOrNull(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

function Badge({ text, color }: { text: string; color?: string }) {
  if (!text) return null;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "3px 10px",
        borderRadius: "var(--radius-lg)",
        fontSize: 11,
        fontWeight: 600,
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
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1000);
        });
      }}
      style={{
        fontSize: 10,
        padding: "1px 6px",
        background: "var(--bg-elevated)",
        color: "var(--text-faint)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        cursor: "pointer",
        flexShrink: 0,
      }}
    >
      {copied ? "복사됨" : "복사"}
    </button>
  );
}

function FieldRow({ field, row }: { field: FieldSpec; row: Record<string, string> }) {
  const raw = field.compute ? field.compute(row) ?? "" : row[field.key];
  if (raw === undefined || raw === null || raw === "") return null;

  const kind: FieldKind = field.kind ?? "text";
  const label = field.label ?? field.key;
  const displayValue = field.valueLabels?.[raw] ?? raw;

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
    case "json": {
      const pretty = kind === "json" ? prettyJsonOrNull(raw) : null;
      content = (
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
          {pretty ?? raw}
        </pre>
      );
      break;
    }
    case "privileges":
      content = <PrivilegeList raw={raw} />;
      break;
    default:
      content = <span style={{ fontSize: 12.5 }}>{displayValue}</span>;
  }

  return (
    <div style={{ padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
        <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</span>
        <CopyButton value={raw} />
      </div>
      <div style={{ marginTop: 3 }}>{content}</div>
    </div>
  );
}

const MAX_INLINE_LINKED_ROWS = 500;

// A detail-view link ("이 exe가 로드한 파일 보기" 등) shown as an inline
// accordion: expanding it lazily pulls the matching rows from the target
// table and lists them right here, instead of navigating to another tab.
// Each linked row is summarized with the TARGET table's own title()/subtitle()
// spec, so the labeling stays consistent with how that table renders itself.
function LinkAccordion({
  link,
  value,
  onFetchLinkedRows,
}: {
  link: LinkSpec;
  value: string;
  onFetchLinkedRows: FetchLinkedRows;
}) {
  const [expanded, setExpanded] = useState(false);
  const [rows, setRows] = useState<Record<string, string>[] | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const targetSpec = getArtifactView(link.targetFile);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && rows === null && !notFound) {
      setLoading(true);
      try {
        const result = await onFetchLinkedRows(link.targetFile, link.targetColumn, value);
        if (result) setRows(result.rows);
        else setNotFound(true);
      } finally {
        setLoading(false);
      }
    }
  }

  const shown = rows ? rows.slice(0, MAX_INLINE_LINKED_ROWS) : [];

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
      <button
        onClick={toggle}
        style={{
          width: "100%",
          textAlign: "left",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 12,
          padding: "8px 10px",
          background: "var(--accent-subtle)",
          color: "var(--accent)",
          border: "none",
          cursor: "pointer",
          fontWeight: 600,
        }}
      >
        <span style={{ fontSize: 9 }}>{expanded ? "▾" : "▸"}</span>
        <span style={{ flex: 1 }}>{link.label}</span>
        {rows && <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{rows.length.toLocaleString()}</span>}
      </button>
      {expanded && (
        <div style={{ borderTop: "1px solid var(--border)", maxHeight: 260, overflow: "auto" }}>
          {loading && <div style={{ padding: "8px 10px", fontSize: 12, color: "var(--text-dim)" }}>불러오는 중...</div>}
          {notFound && (
            <div style={{ padding: "8px 10px", fontSize: 12, color: "var(--text-faint)" }}>원본 테이블을 찾을 수 없습니다.</div>
          )}
          {rows && rows.length === 0 && (
            <div style={{ padding: "8px 10px", fontSize: 12, color: "var(--text-faint)" }}>연결된 항목이 없습니다.</div>
          )}
          {shown.map((r, i) => {
            const title = targetSpec ? targetSpec.title(r) : Object.values(r)[1] ?? "";
            const subtitle = targetSpec?.subtitle?.(r) ?? "";
            return (
              <div
                key={i}
                style={{
                  padding: "6px 10px",
                  borderTop: i === 0 ? "none" : "1px solid var(--border-subtle)",
                  fontSize: 12,
                }}
              >
                <div style={{ wordBreak: "break-all" }}>{title}</div>
                {subtitle && (
                  <div style={{ fontSize: 11, color: "var(--text-faint)", wordBreak: "break-all" }}>{subtitle}</div>
                )}
              </div>
            );
          })}
          {rows && rows.length > MAX_INLINE_LINKED_ROWS && (
            <div style={{ padding: "6px 10px", fontSize: 11, color: "var(--text-faint)", borderTop: "1px solid var(--border-subtle)" }}>
              외 {(rows.length - MAX_INLINE_LINKED_ROWS).toLocaleString()}개 더 (표시 생략)
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface ArtifactDetailViewProps {
  spec: ArtifactViewSpec;
  row: Record<string, string>;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
}

export default function ArtifactDetailView({ spec, row, onNavigate, onFetchLinkedRows }: ArtifactDetailViewProps) {
  const title = spec.title(row);
  const subtitle = spec.subtitle?.(row);
  const tags = spec.tags?.(row) ?? [];

  const timelinePoints = (spec.timelineFields ?? [])
    .map((f) => ({ label: f.label, value: row[f.key] ?? "" }))
    .filter((p) => p.value);

  const activeLinks = (spec.links ?? []).filter((link) => row[link.key]);

  return (
    <div>
      <div style={{ padding: "18px 16px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div style={{ fontSize: 16, fontWeight: 700, wordBreak: "break-word" }}>{title}</div>
        {subtitle && (
          <div style={{ fontSize: 12.5, color: "var(--text-dim)", marginTop: 3, wordBreak: "break-word" }}>
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
        {tags.length > 0 && (
          <div style={{ marginTop: 8 }}>
            <TagList tags={tags} />
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
          <div
            style={{
              fontSize: 10.5,
              fontWeight: 700,
              color: "var(--text-faint)",
              textTransform: "uppercase",
              letterSpacing: 0.6,
              marginBottom: 6,
            }}
          >
            시간 흐름
          </div>
          <MiniTimeline points={timelinePoints} />
        </div>
      )}

      {spec.sections.map((section) => {
        const visibleFields = section.fields.filter((f) => (f.compute ? f.compute(row) : row[f.key]));
        if (visibleFields.length === 0) return null;
        return (
          <div key={section.heading} style={{ padding: "14px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
            <div
              style={{
                fontSize: 10.5,
                fontWeight: 700,
                color: "var(--text-faint)",
                textTransform: "uppercase",
                letterSpacing: 0.6,
                marginBottom: 6,
              }}
            >
              {section.heading}
            </div>
            {visibleFields.map((f) => (
              <FieldRow key={f.key} field={f} row={row} />
            ))}
          </div>
        );
      })}
    </div>
  );
}
