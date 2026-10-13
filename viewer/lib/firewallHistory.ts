// Firewall history helpers (docs-14). Cards follow the stored rule_id; rows
// without a rule stay single. No runtime imports (Node tests).

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
  const pick = (values: string[], value: string | undefined) => !values.length || values.includes(value ?? "");
  if (!pick(filter.kinds, row.event_type) || !pick(filter.directions, row.direction) || !pick(filter.actions, row.action) || !pick(filter.protocols, row.protocol_number)) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.search_text, row.rule_name, row.rule_id, row.app_path, row.app_path_resolved, row.local_ports, row.remote_ports, row.detail, row.account, row.account_sid].some((value) => (value ?? "").toLowerCase().includes(needle));
}

/** Time order (direction), untimed last, ties by record_id (R12). */
function compareRows(a: Cells, b: Cells, direction: "asc" | "desc"): number {
  const left = a.timestamp ?? "";
  const right = b.timestamp ?? "";
  if (!left !== !right) return left ? -1 : 1;
  const order = left.localeCompare(right);
  return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
}

export interface FirewallCard<R extends Cells> {
  key: string;
  isRule: boolean;
  /** Every in-period event of the card. */
  events: R[];
  /** record_ids matching the conditions. */
  matched: Set<string>;
}

export function buildFirewallCards<R extends Cells>(rows: R[], filter: FirewallFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): FirewallCard<R>[] {
  const cards = new Map<string, FirewallCard<R>>();
  for (const row of rows) {
    if (row.timestamp ? !inPeriod(row.timestamp) : periodSet) continue;
    const key = row.rule_id ? `rule::${row.rule_id}` : `record::${row.record_id}`;
    let card = cards.get(key);
    if (!card) {
      card = { key, isRule: Boolean(row.rule_id), events: [], matched: new Set() };
      cards.set(key, card);
    }
    card.events.push(row);
    if (matches(row, filter)) card.matched.add(row.record_id ?? "");
  }
  const kept = [...cards.values()].filter((card) => card.matched.size > 0);
  for (const card of kept) card.events.sort((a, b) => compareRows(a, b, direction));
  return kept.sort((a, b) => compareRows(a.events[0], b.events[0], direction) || a.key.localeCompare(b.key));
}

/** `@{Package_Version_…?ms-resource://…}` → package name; other names unchanged (raw on hover). */
export function ruleDisplayName(name: string): string {
  const match = /^@\{([^_?}]+)_[^?}]*\?ms-resource:/.exec(name);
  return match ? match[1] : name;
}
