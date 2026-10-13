// SMB history helpers (docs-09). Navigation groups by stored remote address;
// events without an address are never merged. Sibling imports carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { compareEvents, groupEvents, inScope, type EventGroup } from "./eventOrder.ts";

type Cells = Record<string, string | undefined>;

export interface SmbFilter {
  /** Results to keep (empty: all — docs-09 keeps the all-results default). */
  results: string[];
  directions: string[];
  /** Selected stored account_key values ("" is the no-account bucket). */
  accounts: string[];
  search: string;
}

export const DEFAULT_SMB_FILTER: SmbFilter = { results: [], directions: [], accounts: [], search: "" };

// docs-09 R10 search columns (stored values only).
const SEARCH_FIELDS = [
  "remote_address", "remote_address_raw", "workstation_name", "share_name", "share_path", "target_file",
  "access_rights", "access_mask", "description", "event_id", "account", "account_raw", "account_domain",
  "account_upn", "account_sid", "target_user_sid", "subject_user_sid",
];

export type SmbFacet = "results" | "directions" | "accounts";

export const SMB_FACET_VALUE: Record<SmbFacet, (event: Cells) => string> = {
  results: (event) => event.result ?? "",
  directions: (event) => event.direction ?? "",
  accounts: (event) => event.account_key ?? "",
};
const FACETS: SmbFacet[] = ["results", "directions", "accounts"];

/** Every condition except `skip`. */
function matches(event: Cells, filter: SmbFilter, skip: SmbFacet | null = null): boolean {
  for (const facet of FACETS) {
    if (facet !== skip && filter[facet].length && !filter[facet].includes(SMB_FACET_VALUE[facet](event))) return false;
  }
  const needle = filter.search.trim().toLowerCase();
  return !needle || SEARCH_FIELDS.some((field) => (event[field] ?? "").toLowerCase().includes(needle));
}

export interface SmbGroup<E extends Cells> extends EventGroup<E> {
  /** key: "address:<addr>" or "record:<id>". */
  address: string;
}

/** Groups with at least one matching event; each keeps its whole in-scope context (R11; untimed only without a period, R13). */
export function buildSmbGroups<E extends Cells>(events: E[], filter: SmbFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): SmbGroup<E>[] {
  return groupEvents<E, SmbGroup<E>>(events, {
    inPeriod,
    periodSet,
    keyOf: (event) => {
      const address = (event.remote_address ?? "").trim();
      return address ? `address:${address}` : `record:${event.record_id}`;
    },
    create: (key, event) => ({ key, address: (event.remote_address ?? "").trim(), events: [], matched: new Set() }),
    matches: (event) => matches(event, filter),
  });
}

/** Events per stored value of one facet under every other condition and the
 *  period (shows what that facet's selection hides). */
export function smbFacetCounts(events: Cells[], filter: SmbFilter, facet: SmbFacet, inPeriod: (timestamp: string) => boolean, periodSet = false): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet) || !matches(event, filter, facet)) continue;
    const value = SMB_FACET_VALUE[facet](event);
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

/** Distinct stored share names in first-seen order (R04). */
export function groupShares(group: { events: Cells[] }): string[] {
  const shares: string[] = [];
  for (const event of group.events) if (event.share_name && !shares.includes(event.share_name)) shares.push(event.share_name);
  return shares;
}

export type ContextItem<E extends Cells> =
  | { key: string; kind: "linked"; time: string; record: E; children: { row: E; relation: string }[] }
  | { key: string; kind: "single"; time: string; row: E };

/** Context tab: stored SmbRelations put context rows under their SMB record
 *  (A02); unlinked context rows stay single. Time order, NULL last (R13). */
export function buildContextItems<E extends Cells>(records: E[], context: E[], relations: Cells[], inPeriod: (timestamp: string) => boolean, periodSet = false): ContextItem<E>[] {
  const contextById = new Map(context.map((row) => [row.record_id ?? "", row]));
  const recordById = new Map(records.map((row) => [row.record_id ?? "", row]));
  const children = new Map<string, { row: E; relation: string }[]>();
  const linked = new Set<string>();
  for (const relation of relations) {
    const row = contextById.get(relation.context_id ?? "");
    if (!row || !recordById.has(relation.record_id ?? "")) continue;
    linked.add(relation.context_id ?? "");
    const list = children.get(relation.record_id ?? "") ?? [];
    list.push({ row, relation: relation.relation_kind ?? "" });
    children.set(relation.record_id ?? "", list);
  }
  const items: ContextItem<E>[] = [];
  for (const [recordId, list] of children) {
    const record = recordById.get(recordId)!;
    list.sort((a, b) => compareEvents(a.row, b.row));
    items.push({ key: `linked:${recordId}`, kind: "linked", time: record.timestamp ?? "", record, children: list });
  }
  for (const row of context) if (!linked.has(row.record_id ?? "")) items.push({ key: `single:${row.record_id}`, kind: "single", time: row.timestamp ?? "", row });
  return items
    .filter((item) => (item.time ? inPeriod(item.time) : !periodSet))
    .sort((a, b) => compareEvents({ timestamp: a.time, record_id: a.key }, { timestamp: b.time, record_id: b.key }));
}

// Stored enumerations → short labels; unknown values stay raw.
export const SMB_DIRECTION_LABELS: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드", unknown: "방향 미확인" };
export const RELATION_LABELS: Record<string, string> = { logon_instance_end: "로그온 종료", special_privileges: "특수 권한" };
// SmbContext event_type → short label.
export const CONTEXT_KIND_LABELS: Record<string, string> = {
  ntlm_credential_validation: "NTLM 검증",
  special_privileges_assigned: "특수 권한",
  logon_instance_end: "로그온 종료",
  system_start: "시스템 시작",
  audit_policy_change: "감사 정책 변경",
  log_cleared: "로그 삭제",
  insecure_guest_auth_enabled: "Guest 인증 허용 설정",
};
export const EVIDENCE_KIND_LABELS: Record<string, string> = {
  service_state: "서비스 상태",
  service_start_type_change: "시작 유형 변경",
  service_configuration: "서비스 설정",
  service_subkey: "서비스 하위 키",
  share_configuration: "공유 설정",
  share_definition: "공유 정의",
  control_set_selection: "ControlSet",
};
