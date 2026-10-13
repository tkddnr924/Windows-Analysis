// BITS history helpers (docs-15). Cards follow the stored job_group_key
// (record-keyed when no job id was recorded, R03). Sibling imports carry `.ts`
// so Node tests can load them.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { facetAllows, groupEvents, type EventGroup } from "./eventOrder.ts";

type Cells = Record<string, string | undefined>;

export interface BitsFilter {
  search: string;
  kinds: string[];
  results: string[];
  /** bitsAccountKey values. */
  accounts: string[];
}

export const DEFAULT_BITS_FILTER: BitsFilter = { search: "", kinds: [], results: [], accounts: [] };

/** Owner SID (stored candidate) first, else the raw owner text. */
export const bitsAccountKey = (row: Cells) => row.account_sid || row.owner_sid || row.owner_sid_candidate || row.owner_raw || "";

function matches(row: Cells, filter: BitsFilter): boolean {
  if (!facetAllows(filter.kinds, row.event_type) || !facetAllows(filter.results, row.result) || !facetAllows(filter.accounts, bitsAccountKey(row))) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.job_name, row.job_id, row.url, row.local_path, row.local_path_resolved, row.process, row.account, row.account_sid, row.owner_raw, row.owner_sid_candidate].some((value) => (value ?? "").toLowerCase().includes(needle));
}

export interface BitsCard<R extends Cells> extends EventGroup<R> {
  isJob: boolean;
}

/** Time order (direction), untimed last, ties by record_id (R11). */
export function buildBitsCards<R extends Cells>(rows: R[], filter: BitsFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): BitsCard<R>[] {
  return groupEvents<R, BitsCard<R>>(rows, {
    inPeriod,
    periodSet,
    direction,
    keyOf: (row) => row.job_group_key || `record:${row.record_id}`,
    create: (key) => ({ key, isJob: key.startsWith("job:"), events: [], matched: new Set() }),
    matches: (row) => matches(row, filter),
  });
}

/** host/path without scheme and query (full URL stays on hover). */
export function urlLabel(url: string): string {
  const match = /^[a-z][a-z0-9+.-]*:\/\/([^?#]+)/i.exec(url);
  return match ? match[1] : url;
}
