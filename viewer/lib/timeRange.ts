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

/** True if `ts` falls within the range. An empty ts is excluded whenever the
 * range is active (a row with no time can't be placed in the window). */
export function inRange(ts: string, range: TimeRange): boolean {
  const startBound = toBound(range.start, "start");
  const endBound = toBound(range.end, "end");
  if (!startBound && !endBound) return true;
  if (!ts) return false;
  if (startBound && ts < startBound) return false;
  if (endBound && ts > endBound) return false;
  return true;
}

const TS_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/;

/** The column a table should be time-filtered on: the artifact's declared
 * timeline field, else a plain "timestamp" column, else the first column whose
 * sample value looks like a formatted timestamp. Returns null when the table
 * has no time column at all — such tables are left unfiltered. */
export function timeColumnFor(
  spec: ArtifactViewSpec | null,
  columns: string[],
  sampleRow: Record<string, string> | undefined
): string | null {
  if (spec?.timelineField && columns.includes(spec.timelineField)) return spec.timelineField;
  if (columns.includes("timestamp")) return "timestamp";
  if (sampleRow) {
    for (const c of columns) {
      if (TS_RE.test(sampleRow[c] ?? "")) return c;
    }
  }
  return null;
}
