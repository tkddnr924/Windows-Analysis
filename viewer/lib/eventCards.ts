// Shared helpers of the event card views (service, firewall, BITS, WER,
// Defender, SMB, remote access, RDP cache, scheduled tasks). No runtime imports
// (Node tests).

type Cells = Record<string, string | undefined>;

/** List and in-card page size (10-per-page rule). */
export const PAGE_SIZE = 10;

export const RESULT_COLOR: Record<string, string> = { 성공: "var(--success)", 실패: "var(--danger)", 정보: "var(--text-faint)" };
export const DIRECTION_COLOR: Record<string, string> = { inbound: "#f2a86f", outbound: "#9b7ef8" };

/** Color of a stored result; values without their own color stay visible. */
export const resultColor = (result: string | undefined) => RESULT_COLOR[result ?? ""] ?? "var(--text-faint)";

/** Stored SQLite rowid attached by the backend (NaN when absent). */
export const rowidOf = (row: object) => Number((row as Record<string, unknown>).__rowid);

export interface CountOption {
  value: string;
  label: string;
  count: number;
  color?: string;
}

/** Stored-value options with counts over `rows`, ordered by label. */
export function optionsOf<R>(rows: R[], pick: (row: R) => string, label: (value: string, row: R) => string = (value) => value, empty = "(없음)"): CountOption[] {
  const tally = new Map<string, { label: string; count: number }>();
  for (const row of rows) {
    const value = pick(row);
    const entry = tally.get(value) ?? { label: value ? label(value, row) : empty, count: 0 };
    entry.count += 1;
    tally.set(value, entry);
  }
  return [...tally.entries()].sort(([, a], [, b]) => a.label.localeCompare(b.label)).map(([value, entry]) => ({ value, label: entry.label, count: entry.count }));
}

/** Label per distinct stored value, taken from its first row ("" → `empty`). */
export function valueLabels<R>(rows: R[], pick: (row: R) => string, label: (value: string, row: R) => string = (value) => value, empty = "(없음)"): Map<string, string> {
  const labels = new Map<string, string>();
  for (const row of rows) {
    const value = pick(row);
    if (!labels.has(value)) labels.set(value, value ? label(value, row) : empty);
  }
  return labels;
}

/** Options for every stored value plus current selections; counts come from the
 *  set narrowed by every other condition (0 when none remain). */
export function facetOptions(labels: Map<string, string>, counts: Record<string, number>, selected: readonly string[], colors?: Record<string, string>): CountOption[] {
  return [...new Set([...labels.keys(), ...selected])]
    .map((value) => ({ value, label: labels.get(value) ?? value, count: counts[value] ?? 0, color: colors?.[value] }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

/** Earliest and latest stored timestamps, independent of display order ("" when untimed). */
export function timeSpan(events: Cells[]): { from: string; to: string } {
  let from = "";
  let to = "";
  for (const event of events) {
    const timestamp = event.timestamp ?? "";
    if (!timestamp) continue;
    if (!from || timestamp < from) from = timestamp;
    if (!to || timestamp > to) to = timestamp;
  }
  return { from, to };
}

/** Clamped page of `total` items with its [start, end) slice and summary text. */
export function pageWindow(total: number, page: number, size = PAGE_SIZE): { page: number; pageCount: number; start: number; end: number; summary: string } {
  const pageCount = Math.max(1, Math.ceil(total / size));
  const safePage = Math.min(Math.max(page, 0), pageCount - 1);
  const start = safePage * size;
  const end = Math.min(start + size, total);
  return { page: safePage, pageCount, start, end, summary: `(${(total ? start + 1 : 0).toLocaleString()}–${end.toLocaleString()} / ${total.toLocaleString()})` };
}
