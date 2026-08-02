"use client";

import type { CSSProperties } from "react";
import { toBound } from "@/lib/timeRange";

interface DateTimeInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  style?: CSSProperties;
  ariaLabel?: string;
}

// A plain text field for an incident-window bound, typed as "YYYY-MM-DD HH:mm:ss"
// (24-hour, seconds/time optional). The native <input type="datetime-local">
// forces the OS locale's format on us — 오전/오후 in Korean, dd/mm/yyyy in en-GB —
// with no way to pin it to the ISO layout every timestamp in this app uses. A
// text field gives us that layout exactly and consistently. A non-empty value
// that doesn't parse gets a red border but is otherwise ignored by the filter.
export default function DateTimeInput({ value, onChange, placeholder = "YYYY-MM-DD HH:mm:ss", style, ariaLabel }: DateTimeInputProps) {
  const invalid = value.trim() !== "" && toBound(value, "start") === "";
  return (
    <input
      type="text"
      inputMode="numeric"
      spellCheck={false}
      value={value}
      aria-label={ariaLabel}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      style={{
        fontFamily: "var(--mono)",
        ...style,
        ...(invalid ? { borderColor: "var(--danger)" } : null),
      }}
    />
  );
}
