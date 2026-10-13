// Service history helpers (docs-12). Cards follow the stored group_key
// (case-insensitive key, single-candidate 7040 alias, record-kind 7026 kept
// apart — all decided at storage time). Sibling imports carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { facetAllows, groupEvents, type EventGroup } from "./eventOrder.ts";

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
  if (!facetAllows(filter.results, row.result) || !facetAllows(filter.states, row.state) || !facetAllows(filter.startTypes, row.start_type_after) || !facetAllows(filter.kinds, row.event_type)) return false;
  if (filter.serviceAccounts.length && !filter.serviceAccounts.includes(serviceAccountKey(row))) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.account, row.account_sid, row.service_name, row.service_key].some((value) => (value ?? "").toLowerCase().includes(needle));
}

export type ServiceCard<R extends Cells> = EventGroup<R>;

/** Cards with at least one matching event; each keeps its whole in-scope
 * context (R05/R07). Time order (direction), untimed last, ties by record_id (R08). */
export function buildServiceCards<R extends Cells>(rows: R[], filter: ServiceFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): ServiceCard<R>[] {
  return groupEvents<R, ServiceCard<R>>(rows, {
    inPeriod,
    periodSet,
    direction,
    keyOf: (row) => row.group_key || `record::${row.record_id}`,
    create: (key) => ({ key, events: [], matched: new Set() }),
    matches: (row) => matches(row, filter),
  });
}
