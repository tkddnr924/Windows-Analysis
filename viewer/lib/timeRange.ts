// A global time-range filter used across all views to narrow every table to
// a suspected incident window. Timestamps are the parser's fixed
// "YYYY-MM-DD HH:MM:SS.fff" (KST) strings, so plain string comparison is
// chronological — no timezone math needed.

import type { ArtifactViewSpec } from "./artifactViews";

export interface TimeRange {
  /** Free-typed "YYYY-MM-DD HH:mm:ss" text (seconds/time optional), "" when unset. */
  start: string;
  end: string;
}

export const EMPTY_TIME_RANGE: TimeRange = { start: "", end: "" };

// Reject calendar dates and clock times that don't exist (2024-13-45, 99:99).
function validParts(date: string, hh?: string, mm?: string, ss?: string): boolean {
  const [y, mo, d] = date.split("-").map(Number);
  if (mo < 1 || mo > 12 || d < 1) return false;
  if (d > new Date(Date.UTC(y, mo, 0)).getUTCDate()) return false;
  if (hh !== undefined && Number(hh) > 23) return false;
  if (mm !== undefined && Number(mm) > 59) return false;
  return ss === undefined || Number(ss) <= 59;
}

// Turn a user-typed bound into the parser's "YYYY-MM-DD hh:mm:ss.fff" precision
// so a plain string compare against entry.timestamp is chronological. Accepts,
// in decreasing precision: full "YYYY-MM-DD HH:mm:ss", "YYYY-MM-DD HH:mm", and
// date-only "YYYY-MM-DD" (which spans the whole day). "T" or space separator.
// Missing pieces widen to the edge — start floors, end ceils. Returns "" on an
// unparseable/partial value so it simply doesn't constrain the range.
export function toBound(value: string, edge: "start" | "end"): string {
  if (!value) return "";
  const m = value.trim().match(/^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  if (!m) return "";
  const [, date, hh, mm, ss] = m;
  if (!validParts(date, hh, mm, ss)) return "";
  const floor = edge === "start";
  const H = hh ?? (floor ? "00" : "23");
  const M = mm ?? (floor ? "00" : "59");
  const S = ss ?? (floor ? "00" : "59");
  const F = floor ? "000" : "999";
  return `${date} ${H}:${M}:${S}.${F}`;
}

export function rangeActive(range: TimeRange): boolean {
  return Boolean(range.start || range.end);
}

/** Normalized bounds for string compares; "" means unconstrained. */
export function rangeBounds(range: TimeRange): TimeRange {
  return { start: toBound(range.start, "start"), end: toBound(range.end, "end") };
}

// Per-range bound cache: row filters call inRange with one range object per
// render, so the bound regex runs once per range instead of once per row.
const boundsCache = new WeakMap<TimeRange, TimeRange>();

/** True if `ts` falls within the range. An empty ts is excluded whenever the
 * range is active (a row with no time can't be placed in the window). */
export function inRange(ts: string, range: TimeRange): boolean {
  let bounds = boundsCache.get(range);
  if (!bounds) {
    bounds = rangeBounds(range);
    boundsCache.set(range, bounds);
  }
  const { start: startBound, end: endBound } = bounds;
  if (!startBound && !endBound) return true;
  if (!ts) return false;
  if (startBound && ts < startBound) return false;
  if (endBound && ts > endBound) return false;
  return true;
}

/** Display parser-local evidence time without applying browser locale or a
 * timezone conversion. This keeps every analyst view on the fixed
 * YYYY-MM-DD HH:mm:ss.fff convention even when old records lack milliseconds. */
export function formatEvidenceTimestamp(value: string): string {
  const match = value.trim().match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?$/);
  if (!match) return value || "시간 정보 없음";
  return `${match[1]} ${match[2]}.${(match[3] ?? "").padEnd(3, "0")}`;
}

const TS_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/;
// Rows inspected per column when inferring the time column.
const TIME_COLUMN_SAMPLE = 200;

/** The column a table should be time-filtered on: the artifact's declared
 * timeline field, else a plain "timestamp" column, else the first column (in
 * column order) whose sampled values look like a formatted timestamp. Returns
 * null when the table has no time column at all — left unfiltered. */
export function timeColumnFor(
  spec: ArtifactViewSpec | null,
  columns: string[],
  rows: Record<string, string>[]
): string | null {
  if (spec?.timelineField && columns.includes(spec.timelineField)) return spec.timelineField;
  if (columns.includes("timestamp")) return "timestamp";
  const sample = rows.slice(0, TIME_COLUMN_SAMPLE);
  return columns.find((c) => sample.some((row) => TS_RE.test(row[c] ?? ""))) ?? null;
}
