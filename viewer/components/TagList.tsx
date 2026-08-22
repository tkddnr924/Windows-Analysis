"use client";

import type { Tag } from "@/lib/tagging";

export default function TagList({ tags }: { tags: Tag[] }) {
  if (tags.length === 0) return null;
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {tags.map((tag) => {
        return (
          <span
            key={tag.label}
            title={tag.description ?? (tag.severity === "danger" ? "위험 신호 — 확인 필요" : "이상 신호 — 확인 권장")}
            className={`dfir-tag dfir-tag--${tag.severity === "danger" ? "critical" : "attention"}`}
          >
            {tag.label}
          </span>
        );
      })}
    </div>
  );
}
