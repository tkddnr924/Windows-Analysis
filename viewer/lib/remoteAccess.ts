// Remote access history helpers (docs-08). Groups follow stored segments only;
// rows without a segment are never joined by time or address. No runtime
// imports (Node tests).

type Cells = Record<string, string | undefined>;

export interface RemoteFilter {
  /** Results to keep (empty: all). Default keeps 성공 (docs-08 R08/A04). */
  results: string[];
  directions: string[];
  scopes: string[];
  logonTypes: string[];
  /** Selected account_key values (empty: all; "" is the no-account bucket). */
  accounts: string[];
  search: string;
}

// 성공 + remote scope by default; local/unknown stay selectable (R01, R08).
export const DEFAULT_FILTER: RemoteFilter = { results: ["성공"], directions: [], scopes: ["remote"], logonTypes: [], accounts: [], search: "" };

/** Account chip identity: lower-case domain\name (same account whether the
 *  row was keyed by SID or name); without a name, the stored key. */
export function accountKeyOf(event: Cells): string {
  const name = (event.account_name || event.account || "").trim();
  if (!name) return event.account_key ?? "";
  const domain = (event.account_domain ?? "").trim();
  return (domain ? `${domain}\\${name}` : name).toLowerCase();
}

const SEARCH_FIELDS = ["remote_address", "remote_address_raw", "remote_computer", "account", "account_raw", "account_upn", "account_sid", "target_user_sid", "description"];

function matchesExceptResult(event: Cells, filter: RemoteFilter): boolean {
  if (filter.directions.length && !filter.directions.includes(event.direction ?? "")) return false;
  if (filter.scopes.length && !filter.scopes.includes(event.access_scope ?? "")) return false;
  if (filter.logonTypes.length && !filter.logonTypes.includes(event.logon_type ?? "")) return false;
  if (filter.accounts.length && !filter.accounts.includes(accountKeyOf(event))) return false;
  const needle = filter.search.trim().toLowerCase();
  if (needle && !SEARCH_FIELDS.some((field) => (event[field] ?? "").toLowerCase().includes(needle))) return false;
  return true;
}

function matches(event: Cells, filter: RemoteFilter): boolean {
  return (!filter.results.length || filter.results.includes(event.result ?? "")) && matchesExceptResult(event, filter);
}

/** Untimed events count only when no period is set (docs-08 R12). */
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

export interface RemoteGroup<E extends Cells, S> {
  /** "segment:<id>" or "record:<id>" — stable within one result generation. */
  key: string;
  segment: S | null;
  /** Every in-scope event of the group, time order. */
  events: E[];
  /** record_ids that match the event conditions. */
  matched: Set<string>;
}

/** Groups with at least one matching event; each keeps its whole in-scope context. */
export function buildGroups<E extends Cells, S>(events: E[], segments: Map<string, S>, filter: RemoteFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): RemoteGroup<E, S>[] {
  const groups = new Map<string, RemoteGroup<E, S>>();
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet)) continue;
    const segmentId = event.segment_id;
    const key = segmentId ? `segment:${segmentId}` : `record:${event.record_id}`;
    let group = groups.get(key);
    if (!group) {
      group = { key, segment: segmentId ? segments.get(segmentId) ?? null : null, events: [], matched: new Set() };
      groups.set(key, group);
    }
    group.events.push(event);
    if (matches(event, filter)) group.matched.add(event.record_id ?? "");
  }
  const kept = [...groups.values()].filter((group) => group.matched.size > 0);
  for (const group of kept) group.events.sort(byTime);
  return kept.sort((left, right) => byTime(left.events[0], right.events[0]) || left.key.localeCompare(right.key));
}

/** Events per result under every other condition (shows what the result filter hides). */
export function resultCounts(events: Cells[], filter: RemoteFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet) || !matchesExceptResult(event, filter)) continue;
    const result = event.result ?? "";
    counts[result] = (counts[result] ?? 0) + 1;
  }
  return counts;
}

export function isLoopbackAddress(value: string): boolean {
  const raw = value.trim().toLocaleLowerCase();
  if (!raw) return false;
  const hostName = /^[a-z][a-z0-9.-]*:\d+$/.test(raw) ? raw.replace(/:\d+$/, "") : raw;
  if (hostName === "localhost" || hostName === "localhost.localdomain") return true;
  const bracketed = raw.match(/^\[([^\]]+)](?::\d+)?$/)?.[1] ?? raw;
  const withoutZone = bracketed.replace(/%[\w.-]+$/, "");
  const address = /^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(withoutZone) ? withoutZone.replace(/:\d+$/, "") : withoutZone;
  return /^127(?:\.\d{1,3}){3}$/.test(address) || address === "::1" || address === "0:0:0:0:0:0:0:1" || /^::ffff:127(?:\.\d{1,3}){3}$/.test(address);
}

/** Every registered host on the address (docs-08 R14); none for loopback/LOCAL. */
export function hostCandidates<H>(address: string | undefined, ipHosts: Record<string, H[]>): H[] {
  const value = (address ?? "").trim();
  if (!value || value.toUpperCase() === "LOCAL" || isLoopbackAddress(value)) return [];
  return ipHosts[value] ?? [];
}

// Stored enumerations → short labels; unknown values stay raw.
export const STAGE_LABELS: Record<string, string> = {
  transport: "전송 연결",
  transport_warning: "전송 경고",
  authentication: "인증",
  logon: "로그온",
  shell: "셸 시작",
  reconnect: "재연결",
  disconnect: "연결 끊김",
  logoff: "로그오프",
  error_transition: "오류 전이",
};
export const SCOPE_LABELS: Record<string, string> = { remote: "원격", local: "로컬", unknown: "미확인" };
export const DIRECTION_LABELS: Record<string, string> = { inbound: "인바운드", outbound: "아웃바운드", unknown: "방향 미확인" };
export const ID_SPACE_LABELS: Record<string, string> = { lsm_session: "LSM 세션", security_logon: "Security 로그온", rcm_session: "RCM 세션", client_connection: "클라이언트 연결" };
export const BOUND_KIND_LABELS: Record<string, string> = {
  session_logon: "세션 로그온",
  session_logoff: "세션 로그오프",
  session_disconnect: "세션 끊김",
  logon_instance_start: "로그온 시작",
  logon_instance_end: "로그온 종료",
};
export const label = (labels: Record<string, string>, value: string | undefined) => (value ? labels[value] ?? value : "");
