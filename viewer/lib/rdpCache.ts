// RDP bitmap cache helpers (docs-10). Reads stored _OVERVIEW RdpCache rows only.
// No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

export interface RdpFilter {
  search: string;
  /** Selected account keys (empty: all). */
  accounts: string[];
  /** Selected stored status values (empty: all). */
  statuses: string[];
}

export const DEFAULT_RDP_FILTER: RdpFilter = { search: "", accounts: [], statuses: [] };

/** Account identity: stored SID when present, else the account name. */
export const accountKeyOf = (row: Cells) => row.account_sid || row.account || "";

export interface RdpGroup<R extends Cells> {
  /** accountKeyOf + "\0" + source_file. */
  key: string;
  /** accountKeyOf value (filter identity). */
  identity: string;
  account: string;
  accountSid: string;
  source: string;
  /** Displayable fragments: tile_count desc, record_id. */
  fragments: R[];
  /** Failed rows and rows without image data. */
  errors: R[];
}

const SEARCH_FIELDS = ["source_file", "account", "account_sid"];

export type RdpFacet = "accounts" | "statuses";

export const RDP_FACET_VALUE: Record<RdpFacet, (row: Cells) => string> = {
  accounts: accountKeyOf,
  statuses: (row) => row.status ?? "",
};

/** Every condition except `skip`. */
function matches(row: Cells, filter: RdpFilter, skip: RdpFacet | null = null): boolean {
  for (const facet of ["accounts", "statuses"] as const) {
    if (facet !== skip && filter[facet].length && !filter[facet].includes(RDP_FACET_VALUE[facet](row))) return false;
  }
  const needle = filter.search.trim().toLowerCase();
  return !needle || SEARCH_FIELDS.some((field) => (row[field] ?? "").toLowerCase().includes(needle));
}

/** Rows per stored value of one facet under every other condition. */
export function rdpFacetCounts(rows: Cells[], filter: RdpFilter, facet: RdpFacet): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of rows) {
    if (!matches(row, filter, facet)) continue;
    const value = RDP_FACET_VALUE[facet](row);
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

const num = (value: string | undefined) => (value === undefined || value === "" ? -1 : Number(value));

export function buildRdpGroups<R extends Cells>(rows: R[], filter: RdpFilter): RdpGroup<R>[] {
  const groups = new Map<string, RdpGroup<R>>();
  for (const row of rows) {
    if (!matches(row, filter)) continue;
    // Every user has a Cache0000.bin: key on account identity + file.
    const identity = accountKeyOf(row);
    const key = `${identity}\u0000${row.source_file ?? ""}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, identity, account: "", accountSid: "", source: row.source_file ?? "", fragments: [], errors: [] };
      groups.set(key, group);
    }
    // Keep both name and SID even when the first row lacks one of them.
    if (!group.account && row.account) group.account = row.account;
    if (!group.accountSid && row.account_sid) group.accountSid = row.account_sid;
    if (row.event_type === "fragment" && row.status === "ok" && row.image) group.fragments.push(row);
    else group.errors.push(row);
  }
  for (const group of groups.values()) {
    group.fragments.sort((a, b) => num(b.tile_count) - num(a.tile_count) || (a.record_id ?? "").localeCompare(b.record_id ?? ""));
    group.errors.sort((a, b) => num(a.tile_index) - num(b.tile_index) || (a.record_id ?? "").localeCompare(b.record_id ?? ""));
  }
  return [...groups.values()].sort((a, b) => a.identity.localeCompare(b.identity) || a.source.localeCompare(b.source));
}

export const RDP_STATUS_LABELS: Record<string, string> = { ok: "정상", corrupted: "손상", unreadable_file: "파일 읽기 실패" };
