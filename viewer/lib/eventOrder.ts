// Shared event order and grouping for the card views (BITS, service, firewall,
// Defender, SMB, remote access, WER). No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

/** Time order (direction), untimed last, ties by record_id. */
export function compareEvents(a: Cells, b: Cells, direction: "asc" | "desc" = "asc"): number {
  const left = a.timestamp ?? "";
  const right = b.timestamp ?? "";
  if (!left !== !right) return left ? -1 : 1;
  const order = left < right ? -1 : left > right ? 1 : 0;
  return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
}

/** Ascending copy for card representatives and ranges (independent of display direction). */
export function chronological<R extends Cells>(events: R[]): R[] {
  return [...events].sort((a, b) => compareEvents(a, b));
}

/** Facet check: an empty selection keeps every value. */
export function facetAllows(values: string[], value: string | undefined): boolean {
  return !values.length || values.includes(value ?? "");
}

/** Untimed events count only when no period is set. */
export function inScope(event: Cells, inPeriod: (timestamp: string) => boolean, periodSet: boolean): boolean {
  return event.timestamp ? inPeriod(event.timestamp) : !periodSet;
}

export interface EventGroup<R> {
  key: string;
  /** Every in-scope event of the group, sorted. */
  events: R[];
  /** record_ids matching the conditions. */
  matched: Set<string>;
}

export interface GroupEventsOptions<R, G> {
  inPeriod: (timestamp: string) => boolean;
  periodSet: boolean;
  direction?: "asc" | "desc";
  keyOf: (row: R) => string;
  /** New group for the first row of `key` (events/matched start empty). */
  create: (key: string, row: R) => G;
  matches: (row: R) => boolean;
}

/** Groups with at least one matching event; each keeps its whole in-scope
 * context. Events and groups follow compareEvents (group: its first event). */
export function groupEvents<R extends Cells, G extends EventGroup<R>>(rows: R[], options: GroupEventsOptions<R, G>): G[] {
  const { inPeriod, periodSet, direction = "asc", keyOf, create, matches } = options;
  const groups = new Map<string, G>();
  for (const row of rows) {
    if (!inScope(row, inPeriod, periodSet)) continue;
    const key = keyOf(row);
    let group = groups.get(key);
    if (!group) {
      group = create(key, row);
      groups.set(key, group);
    }
    group.events.push(row);
    if (matches(row)) group.matched.add(row.record_id ?? "");
  }
  const kept = [...groups.values()].filter((group) => group.matched.size > 0);
  for (const group of kept) group.events.sort((a, b) => compareEvents(a, b, direction));
  return kept.sort((a, b) => compareEvents(a.events[0], b.events[0], direction) || a.key.localeCompare(b.key));
}
