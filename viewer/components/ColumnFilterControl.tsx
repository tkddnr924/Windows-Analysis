"use client";

import { useState } from "react";
import type { FilterMode, ColumnFilterValue } from "@/lib/types";

const MODE_CYCLE: FilterMode[] = ["contains", "exclude", "exact"];
const MODE_META: Record<FilterMode, { short: string; title: string }> = {
  contains: { short: "포함", title: "포함 — 클릭하면 제외로 전환" },
  exclude: { short: "제외", title: "제외 — 클릭하면 일치로 전환" },
  exact: { short: "일치", title: "일치 — 클릭하면 포함으로 전환" },
};

interface ColumnFilterControlProps {
  value: ColumnFilterValue | undefined;
  onChange: (value: ColumnFilterValue | undefined) => void;
}

export default function ColumnFilterControl({ value, onChange }: ColumnFilterControlProps) {
  // Mode is remembered locally even with no filter text yet, so clicking
  // the mode toggle before typing anything still "sticks" once you type.
  const [localMode, setLocalMode] = useState<FilterMode>(value?.mode ?? "contains");
  const mode = value?.mode ?? localMode;
  const text = value?.value ?? "";
  const active = Boolean(text);

  function setText(next: string) {
    onChange(next ? { mode, value: next } : undefined);
  }

  function cycleMode() {
    const next = MODE_CYCLE[(MODE_CYCLE.indexOf(mode) + 1) % MODE_CYCLE.length];
    setLocalMode(next);
    if (text) onChange({ mode: next, value: text });
  }

  return (
    <div
      onClick={(e) => e.stopPropagation()}
      style={{
        display: "flex",
        alignItems: "stretch",
        background: "var(--bg-input)",
        border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
        borderRadius: "var(--radius-sm)",
        overflow: "hidden",
      }}
    >
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="필터..."
        style={{
          flex: 1,
          minWidth: 0,
          padding: "4px 6px",
          background: "transparent",
          border: "none",
          color: "var(--text)",
          fontSize: 11,
          fontFamily: "var(--mono)",
        }}
      />
      <button
        onClick={cycleMode}
        title={MODE_META[mode].title}
        style={{
          flexShrink: 0,
          padding: "0 8px",
          fontSize: 10,
          fontWeight: 700,
          background: active ? "var(--accent)" : "transparent",
          color: active ? "#0d1117" : "var(--text-faint)",
          border: "none",
          borderLeft: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
          cursor: "pointer",
          whiteSpace: "nowrap",
        }}
      >
        {MODE_META[mode].short}
      </button>
    </div>
  );
}
