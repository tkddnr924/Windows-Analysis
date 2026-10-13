// BITS history helpers (docs-15). Cards follow the stored job_group_key
// (record-keyed when no job id was recorded, R03). No runtime imports (Node tests).

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
  const pick = (values: string[], value: string | undefined) => !values.length || values.includes(value ?? "");
  if (!pick(filter.kinds, row.event_type) || !pick(filter.results, row.result) || !pick(filter.accounts, bitsAccountKey(row))) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.job_name, row.job_id, row.url, row.local_path, row.local_path_resolved, row.process, row.account, row.account_sid, row.owner_raw, row.owner_sid_candidate].some((value) => (value ?? "").toLowerCase().includes(needle));
}

/** Time order (direction), untimed last, ties by record_id (R11). */
function compareRows(a: Cells, b: Cells, direction: "asc" | "desc"): number {
  const left = a.timestamp ?? "";
  const right = b.timestamp ?? "";
  if (!left !== !right) return left ? -1 : 1;
  const order = left.localeCompare(right);
  return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
}

export interface BitsCard<R extends Cells> {
  key: string;
  isJob: boolean;
  events: R[];
  matched: Set<string>;
}

export function buildBitsCards<R extends Cells>(rows: R[], filter: BitsFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): BitsCard<R>[] {
  const cards = new Map<string, BitsCard<R>>();
  for (const row of rows) {
    if (row.timestamp ? !inPeriod(row.timestamp) : periodSet) continue;
    const key = row.job_group_key || `record:${row.record_id}`;
    let card = cards.get(key);
    if (!card) {
      card = { key, isJob: key.startsWith("job:"), events: [], matched: new Set() };
      cards.set(key, card);
    }
    card.events.push(row);
    if (matches(row, filter)) card.matched.add(row.record_id ?? "");
  }
  const kept = [...cards.values()].filter((card) => card.matched.size > 0);
  for (const card of kept) card.events.sort((a, b) => compareRows(a, b, direction));
  return kept.sort((a, b) => compareRows(a.events[0], b.events[0], direction) || a.key.localeCompare(b.key));
}

/** host/path without scheme and query (full URL stays on hover). */
export function urlLabel(url: string): string {
  const match = /^[a-z][a-z0-9+.-]*:\/\/([^?#]+)/i.exec(url);
  return match ? match[1] : url;
}
