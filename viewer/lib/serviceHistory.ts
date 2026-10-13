// Service history helpers (docs-12). Cards follow the stored group_key
// (case-insensitive key, single-candidate 7040 alias, record-kind 7026 kept
// apart — all decided at storage time). No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

export interface ServiceFilter {
  search: string;
  results: string[];
  states: string[];
  startTypes: string[];
  /** Selected service_account_sid (or service_account when no SID). */
  serviceAccounts: string[];
  kinds: string[];
}

export const DEFAULT_SERVICE_FILTER: ServiceFilter = { search: "", results: [], states: [], startTypes: [], serviceAccounts: [], kinds: [] };

export const serviceAccountKey = (row: Cells) => row.service_account_sid || row.service_account || "";

function matches(row: Cells, filter: ServiceFilter): boolean {
  const pick = (values: string[], value: string | undefined) => !values.length || values.includes(value ?? "");
  if (!pick(filter.results, row.result) || !pick(filter.states, row.state) || !pick(filter.startTypes, row.start_type_after) || !pick(filter.kinds, row.event_type)) return false;
  if (filter.serviceAccounts.length && !filter.serviceAccounts.includes(serviceAccountKey(row))) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.account, row.account_sid, row.service_name, row.service_key].some((value) => (value ?? "").toLowerCase().includes(needle));
}

/** Time order (direction), untimed last, ties by record_id (R08). */
function compareRows(a: Cells, b: Cells, direction: "asc" | "desc"): number {
  const left = a.timestamp ?? "";
  const right = b.timestamp ?? "";
  if (!left !== !right) return left ? -1 : 1;
  const order = left.localeCompare(right);
  return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
}

export interface ServiceCard<R extends Cells> {
  key: string;
  /** Every in-scope event of the group. */
  events: R[];
  /** record_ids matching the conditions. */
  matched: Set<string>;
}

/** Cards with at least one matching event; each keeps its whole in-scope context (R05/R07). */
export function buildServiceCards<R extends Cells>(rows: R[], filter: ServiceFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): ServiceCard<R>[] {
  const cards = new Map<string, ServiceCard<R>>();
  for (const row of rows) {
    if (row.timestamp ? !inPeriod(row.timestamp) : periodSet) continue;
    const key = row.group_key || `record::${row.record_id}`;
    let card = cards.get(key);
    if (!card) {
      card = { key, events: [], matched: new Set() };
      cards.set(key, card);
    }
    card.events.push(row);
    if (matches(row, filter)) card.matched.add(row.record_id ?? "");
  }
  const kept = [...cards.values()].filter((card) => card.matched.size > 0);
  for (const card of kept) card.events.sort((a, b) => compareRows(a, b, direction));
  // Card order: first event in the chosen direction.
  return kept.sort((a, b) => compareRows(a.events[0], b.events[0], direction) || a.key.localeCompare(b.key));
}
