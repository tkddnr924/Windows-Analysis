"use client";

import type { Tag } from "@/lib/tagging";

const SEVERITY_STYLE: Record<Tag["severity"], { color: string; background: string }> = {
  warning: { color: "var(--warning)", background: "var(--warning-subtle)" },
  danger: { color: "var(--danger)", background: "var(--danger-subtle)" },
};

const SEVERITY_ICON: Record<Tag["severity"], string> = {
  warning: "⚠",
  danger: "⛔",
};

export default function TagList({ tags }: { tags: Tag[] }) {
  if (tags.length === 0) return null;
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {tags.map((tag) => {
        const { color, background } = SEVERITY_STYLE[tag.severity];
        return (
          <span
            key={tag.label}
            title={tag.description ?? (tag.severity === "danger" ? "위험 신호 — 확인 필요" : "이상 신호 — 확인 권장")}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "3px 10px",
              borderRadius: "var(--radius-lg)",
              fontSize: 11,
              fontWeight: 700,
              background,
              color,
              border: `1px solid ${color}`,
            }}
          >
            <span aria-hidden>{SEVERITY_ICON[tag.severity]}</span>
            {tag.label}
          </span>
        );
      })}
    </div>
  );
}
