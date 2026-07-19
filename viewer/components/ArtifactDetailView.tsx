"use client";

import { useState } from "react";
import type { ArtifactViewSpec, FieldKind, FieldSpec } from "@/lib/artifactViews";
import TagList from "./TagList";
import MiniTimeline from "./MiniTimeline";

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

interface ArtifactDetailViewProps {
  spec: ArtifactViewSpec;
  row: Record<string, string>;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
}

export default function ArtifactDetailView({ spec, row, onNavigate }: ArtifactDetailViewProps) {
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
          <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10 }}>
            {activeLinks.map((link) => (
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
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(88,166,255,0.22)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "var(--accent-subtle)")}
              >
                → {link.label}
              </button>
            ))}
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
