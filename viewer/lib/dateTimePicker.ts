// Calendar/time picker state for the "YYYY-MM-DD HH:mm:ss" range fields.
// Pure string math on calendar dates; no timezone conversion.

export type RangeEdge = "start" | "end";
export type TimePart = "hour" | "minute" | "second";

const pad = (value: number, width = 2) => String(value).padStart(width, "0");

const isoDate = (year: number, month: number, day: number): string => {
  const d = new Date(Date.UTC(year, month, day));
  return `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
};

/** 6×7 Sunday-first grid for a 0-based month. */
export function monthGrid(year: number, month: number): { date: string; inMonth: boolean }[] {
  const firstWeekday = new Date(Date.UTC(year, month, 1)).getUTCDay();
  return Array.from({ length: 42 }, (_, i) => {
    const date = isoDate(year, month, 1 - firstWeekday + i);
    return { date, inMonth: Number(date.slice(5, 7)) === month + 1 };
  });
}

/** Date and optional time of a typed value; null when not a real date/time. */
export function parsePickerValue(value: string): { date: string; time: string | null } | null {
  const m = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  if (!m) return null;
  const [, y, mo, d, hh, mm, ss] = m;
  if (isoDate(Number(y), Number(mo) - 1, Number(d)) !== `${y}-${mo}-${d}`) return null;
  if (hh === undefined) return { date: `${y}-${mo}-${d}`, time: null };
  const time = [Number(hh), Number(mm), Number(ss ?? 0)];
  if (time[0] > 23 || time[1] > 59 || time[2] > 59) return null;
  return { date: `${y}-${mo}-${d}`, time: time.map((n) => pad(n)).join(":") };
}

const edgeTime = (edge: RangeEdge) => (edge === "start" ? "00:00:00" : "23:59:59");

/** Choosing a day keeps the typed time; otherwise the edge's whole-day bound. */
export function pickDay(current: string, date: string, edge: RangeEdge): string {
  return `${date} ${parsePickerValue(current)?.time ?? edgeTime(edge)}`;
}

/** Set one time field; no-op until a date exists. */
export function setTimePart(current: string, part: TimePart, value: number, edge: RangeEdge = "start"): string {
  const parsed = parsePickerValue(current);
  if (!parsed) return current;
  const [h, m, s] = (parsed.time ?? edgeTime(edge)).split(":").map(Number);
  const max = part === "hour" ? 23 : 59;
  const next = Math.min(max, Math.max(0, Math.trunc(Number.isFinite(value) ? value : 0)));
  const parts = { hour: h, minute: m, second: s, [part]: next };
  return `${parsed.date} ${pad(parts.hour)}:${pad(parts.minute)}:${pad(parts.second)}`;
}
