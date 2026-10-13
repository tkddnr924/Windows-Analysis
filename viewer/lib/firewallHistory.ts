// Firewall history helpers (docs-14). Cards follow the stored rule_id; rows
// without a rule stay single. Sibling imports carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { facetAllows, groupEvents, type EventGroup } from "./eventOrder.ts";

type Cells = Record<string, string | undefined>;

export interface FirewallFilter {
  search: string;
  kinds: string[];
  directions: string[];
  actions: string[];
  /** protocol_number values; "" = unrecorded (kept apart from "0"). */
  protocols: string[];
}

export const DEFAULT_FIREWALL_FILTER: FirewallFilter = { search: "", kinds: [], directions: [], actions: [], protocols: [] };

function matches(row: Cells, filter: FirewallFilter): boolean {
  if (!facetAllows(filter.kinds, row.event_type) || !facetAllows(filter.directions, row.direction) || !facetAllows(filter.actions, row.action) || !facetAllows(filter.protocols, row.protocol_number)) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.rule_name, row.rule_id, row.app_path, row.app_path_resolved, row.local_ports, row.remote_ports, row.detail, row.account, row.account_sid].some((value) => (value ?? "").toLowerCase().includes(needle));
}

export interface FirewallCard<R extends Cells> extends EventGroup<R> {
  isRule: boolean;
}

/** Time order (direction), untimed last, ties by record_id (R12). */
export function buildFirewallCards<R extends Cells>(rows: R[], filter: FirewallFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): FirewallCard<R>[] {
  return groupEvents<R, FirewallCard<R>>(rows, {
    inPeriod,
    periodSet,
    direction,
    keyOf: (row) => (row.rule_id ? `rule::${row.rule_id}` : `record::${row.record_id}`),
    create: (key, row) => ({ key, isRule: Boolean(row.rule_id), events: [], matched: new Set() }),
    matches: (row) => matches(row, filter),
  });
}

/** `@{Package_Version_…?ms-resource://…}` → package name; other names unchanged (raw on hover). */
export function ruleDisplayName(name: string): string {
  const match = /^@\{([^_?}]+)_[^?}]*\?ms-resource:/.exec(name);
  return match ? match[1] : name;
}
