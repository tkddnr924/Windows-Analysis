// SMB history helpers (docs-09). Navigation groups by stored remote address;
// events without an address are never merged. No runtime imports (Node tests).

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

function matchesExceptResult(event: Cells, filter: SmbFilter): boolean {
  if (filter.directions.length && !filter.directions.includes(event.direction ?? "")) return false;
  if (filter.accounts.length && !filter.accounts.includes(event.account_key ?? "")) return false;
  const needle = filter.search.trim().toLowerCase();
  if (needle && !SEARCH_FIELDS.some((field) => (event[field] ?? "").toLowerCase().includes(needle))) return false;
  return true;
}

function matches(event: Cells, filter: SmbFilter): boolean {
  return (!filter.results.length || filter.results.includes(event.result ?? "")) && matchesExceptResult(event, filter);
}

/** Untimed events count only when no period is set (R13). */
function inScope(event: Cells, inPeriod: (timestamp: string) => boolean, periodSet: boolean): boolean {
  if (!event.timestamp) return !periodSet;
  return inPeriod(event.timestamp);
}

const byTime = (left: Cells, right: Cells) => {
  const a = left.timestamp ?? "";
  const b = right.timestamp ?? "";
  if (!a !== !b) return a ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : (left.record_id ?? "").localeCompare(right.record_id ?? "");
};

export interface SmbGroup<E extends Cells> {
  /** "address:<addr>" or "record:<id>". */
  key: string;
  address: string;
  /** Every in-scope event of the group, time order. */
  events: E[];
  /** record_ids that match the event conditions. */
  matched: Set<string>;
}

/** Groups with at least one matching event; each keeps its whole in-scope context (R11). */
export function buildSmbGroups<E extends Cells>(events: E[], filter: SmbFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): SmbGroup<E>[] {
  const groups = new Map<string, SmbGroup<E>>();
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet)) continue;
    const address = (event.remote_address ?? "").trim();
    const key = address ? `address:${address}` : `record:${event.record_id}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, address, events: [], matched: new Set() };
      groups.set(key, group);
    }
    group.events.push(event);
    if (matches(event, filter)) group.matched.add(event.record_id ?? "");
  }
  const kept = [...groups.values()].filter((group) => group.matched.size > 0);
  for (const group of kept) group.events.sort(byTime);
  return kept.sort((left, right) => byTime(left.events[0], right.events[0]) || left.key.localeCompare(right.key));
}

/** Events per result under every other condition. */
export function smbResultCounts(events: Cells[], filter: SmbFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet) || !matchesExceptResult(event, filter)) continue;
    const result = event.result ?? "";
    counts[result] = (counts[result] ?? 0) + 1;
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
    list.sort((a, b) => byTime(a.row, b.row));
    items.push({ key: `linked:${recordId}`, kind: "linked", time: record.timestamp ?? "", record, children: list });
  }
  for (const row of context) if (!linked.has(row.record_id ?? "")) items.push({ key: `single:${row.record_id}`, kind: "single", time: row.timestamp ?? "", row });
  return items
    .filter((item) => (item.time ? inPeriod(item.time) : !periodSet))
    .sort((a, b) => byTime({ timestamp: a.time, record_id: a.key }, { timestamp: b.time, record_id: b.key }));
}

// Stored enumerations → short labels; unknown values stay raw.
export const SMB_DIRECTION_LABELS: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드" };
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
  share_configuration: "공유 설정",
  share_definition: "공유 정의",
  control_set_selection: "ControlSet",
};
