"use client";

import { useEffect, useRef, useState, type CSSProperties } from "react";
import { createPortal } from "react-dom";
import CalendarMonthOutlinedIcon from "@mui/icons-material/CalendarMonthOutlined";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import { toBound } from "@/lib/timeRange";
import { monthGrid, parsePickerValue, pickDay, setTimePart, type RangeEdge, type TimePart } from "@/lib/dateTimePicker";

interface DateTimeInputProps {
  value: string;
  onChange: (value: string) => void;
  /** Default time when a day is picked without one: start 00:00:00, end 23:59:59. */
  edge?: RangeEdge;
  placeholder?: string;
  style?: CSSProperties;
  ariaLabel?: string;
}

const WEEKDAYS = ["일", "월", "화", "수", "목", "금", "토"];
const PANEL_WIDTH = 248;

// Text field for an incident-window bound, "YYYY-MM-DD HH:mm:ss" (24-hour).
// The native datetime-local input imposes the OS locale format, so the
// calendar is a custom popover writing the same ISO layout.
export default function DateTimeInput({ value, onChange, edge = "start", placeholder = "YYYY-MM-DD HH:mm:ss", style, ariaLabel }: DateTimeInputProps) {
  const invalid = value.trim() !== "" && toBound(value, "start") === "";
  const anchor = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);

  const openPicker = () => {
    const rect = anchor.current?.getBoundingClientRect();
    if (!rect) return;
    const left = Math.max(8, Math.min(rect.right - PANEL_WIDTH, window.innerWidth - PANEL_WIDTH - 8));
    setPosition({ top: rect.bottom + 6, left });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div ref={anchor} style={{ position: "relative", minWidth: 0 }}>
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
          paddingRight: 28,
          ...(invalid ? { borderColor: "var(--danger)" } : null),
        }}
      />
      <button
        type="button"
        aria-label={ariaLabel ? `${ariaLabel} 달력` : "달력"}
        aria-expanded={open}
        onClick={() => (open ? setOpen(false) : openPicker())}
        style={{ position: "absolute", right: 3, top: "50%", transform: "translateY(-50%)", display: "grid", placeItems: "center", width: 22, height: 22, padding: 0, border: "none", borderRadius: "var(--radius)", background: open ? "var(--accent-subtle)" : "transparent", color: open ? "var(--accent)" : "var(--text-faint)", cursor: "pointer" }}
      >
        <CalendarMonthOutlinedIcon sx={{ fontSize: 15 }} />
      </button>
      {open && position && createPortal(
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 60 }} />
          <PickerPanel value={value} edge={edge} onChange={onChange} style={{ position: "fixed", top: position.top, left: position.left, zIndex: 61 }} />
        </>,
        document.body,
      )}
    </div>
  );
}

function PickerPanel({ value, edge, onChange, style }: { value: string; edge: RangeEdge; onChange: (value: string) => void; style: CSSProperties }) {
  const parsed = parsePickerValue(value);
  const initial = parsed?.date ?? localToday();
  const [view, setView] = useState({ year: Number(initial.slice(0, 4)), month: Number(initial.slice(5, 7)) - 1 });
  // Header click drills up: days → months of a year → 12-year page.
  const [level, setLevel] = useState<"day" | "month" | "year">("day");
  const shift = (delta: number) =>
    setView(({ year, month }) => {
      const index = year * 12 + month + delta;
      return { year: Math.floor(index / 12), month: index % 12 };
    });
  const yearPage = view.year - (((view.year % 12) + 12) % 12);
  const step = level === "day" ? 1 : level === "month" ? 12 : 144;
  const stepLabel = level === "day" ? "달" : level === "month" ? "해" : "12년";
  const title = level === "day"
    ? `${view.year}-${String(view.month + 1).padStart(2, "0")}`
    : level === "month" ? String(view.year) : `${yearPage}–${yearPage + 11}`;
  const selectedYear = parsed ? Number(parsed.date.slice(0, 4)) : null;
  const selectedMonth = parsed ? Number(parsed.date.slice(5, 7)) - 1 : null;
  const cell = (active: boolean, current: boolean): CSSProperties => ({
    height: 36,
    padding: 0,
    border: current && !active ? "1px solid var(--border)" : "1px solid transparent",
    borderRadius: "var(--radius)",
    background: active ? "var(--accent)" : "transparent",
    color: active ? "var(--bg)" : "var(--text)",
    fontFamily: "var(--mono)",
    fontSize: 12,
    fontWeight: active ? 700 : 500,
    cursor: "pointer",
  });
  const today = localToday();
  const time = parsed?.time ?? (edge === "start" ? "00:00:00" : "23:59:59");
  const [hour, minute, second] = time.split(":");
  const timeField = (part: TimePart, current: string, label: string) => (
    <input
      type="number"
      aria-label={label}
      min={0}
      max={part === "hour" ? 23 : 59}
      disabled={!parsed}
      value={current}
      onChange={(e) => onChange(setTimePart(value, part, Number(e.target.value), edge))}
      style={{ width: 44, padding: "4px 4px", textAlign: "center", fontFamily: "var(--mono)", fontSize: 12, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--text)", colorScheme: "dark" }}
    />
  );

  return (
    <div role="dialog" aria-label="날짜·시각 선택" style={{ ...style, width: PANEL_WIDTH, padding: 10, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius)", boxShadow: "var(--shadow-panel)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <button type="button" aria-label={`이전 ${stepLabel}`} onClick={() => shift(-step)} style={navButton}><ChevronLeftIcon sx={{ fontSize: 18 }} /></button>
        <button
          type="button"
          disabled={level === "year"}
          aria-label={level === "day" ? "월 선택" : level === "month" ? "연도 선택" : undefined}
          onClick={() => setLevel(level === "day" ? "month" : "year")}
          style={{ padding: "3px 8px", border: "none", borderRadius: "var(--radius)", background: "transparent", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 700, color: "var(--text)", cursor: level === "year" ? "default" : "pointer" }}
        >
          {title}
        </button>
        <button type="button" aria-label={`다음 ${stepLabel}`} onClick={() => shift(step)} style={navButton}><ChevronRightIcon sx={{ fontSize: 18 }} /></button>
      </div>
      {level === "year" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 4 }}>
          {Array.from({ length: 12 }, (_, i) => yearPage + i).map((year) => (
            <button key={year} type="button" onClick={() => { setView(({ month }) => ({ year, month })); setLevel("month"); }} style={cell(selectedYear === year, Number(today.slice(0, 4)) === year)}>
              {year}
            </button>
          ))}
        </div>
      )}
      {level === "month" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 4 }}>
          {Array.from({ length: 12 }, (_, month) => (
            <button key={month} type="button" onClick={() => { setView(({ year }) => ({ year, month })); setLevel("day"); }} style={cell(selectedYear === view.year && selectedMonth === month, today.slice(0, 7) === `${view.year}-${String(month + 1).padStart(2, "0")}`)}>
              {`${month + 1}월`}
            </button>
          ))}
        </div>
      )}
      {level === "day" && <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 2 }}>
        {WEEKDAYS.map((day, i) => (
          <span key={day} style={{ textAlign: "center", fontSize: 10.5, fontWeight: 650, color: i === 0 ? "var(--danger)" : "var(--text-faint)", padding: "2px 0" }}>{day}</span>
        ))}
        {monthGrid(view.year, view.month).map(({ date, inMonth }) => {
          const selected = parsed?.date === date;
          return (
            <button
              key={date}
              type="button"
              title={date}
              onClick={() => onChange(pickDay(value, date, edge))}
              style={{
                height: 28,
                padding: 0,
                border: date === today && !selected ? "1px solid var(--border)" : "1px solid transparent",
                borderRadius: "var(--radius)",
                background: selected ? "var(--accent)" : "transparent",
                color: selected ? "var(--bg)" : inMonth ? "var(--text)" : "var(--text-faint)",
                opacity: inMonth || selected ? 1 : 0.55,
                fontSize: 12,
                fontWeight: selected ? 700 : 500,
                cursor: "pointer",
              }}
            >
              {Number(date.slice(8, 10))}
            </button>
          );
        })}
      </div>}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, marginTop: 8, paddingTop: 8, borderTop: "1px solid var(--border)", color: "var(--text-faint)" }}>
        {timeField("hour", hour, "시")}:{timeField("minute", minute, "분")}:{timeField("second", second, "초")}
      </div>
    </div>
  );
}

const navButton: CSSProperties = { display: "grid", placeItems: "center", width: 26, height: 26, padding: 0, border: "none", borderRadius: "var(--radius)", background: "transparent", color: "var(--text-dim)", cursor: "pointer" };

function localToday(): string {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
}
