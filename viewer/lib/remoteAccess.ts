// Remote access history helpers (docs-08). Groups follow stored segments only;
// rows without a segment are never joined by time or address. Sibling imports
// carry `.ts` for Node tests.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { groupEvents, inScope, type EventGroup } from "./eventOrder.ts";

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

// 성공 + remote scope by default; unknown scope shows under 전체. Console sessions are not stored.
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

export type RemoteFacet = "results" | "directions" | "scopes" | "logonTypes" | "accounts";

export const FACET_VALUE: Record<RemoteFacet, (event: Cells) => string> = {
  results: (event) => event.result ?? "",
  directions: (event) => event.direction ?? "",
  scopes: (event) => event.access_scope ?? "",
  logonTypes: (event) => event.logon_type ?? "",
  accounts: accountKeyOf,
};
const FACETS: RemoteFacet[] = ["results", "directions", "scopes", "logonTypes", "accounts"];

/** Every condition except `skip`. */
function matches(event: Cells, filter: RemoteFilter, skip: RemoteFacet | null = null): boolean {
  for (const facet of FACETS) {
    if (facet !== skip && filter[facet].length && !filter[facet].includes(FACET_VALUE[facet](event))) return false;
  }
  const needle = filter.search.trim().toLowerCase();
  return !needle || SEARCH_FIELDS.some((field) => (event[field] ?? "").toLowerCase().includes(needle));
}

export interface RemoteGroup<E extends Cells, S> extends EventGroup<E> {
  /** key: "segment:<id>" or "record:<id>" — stable within one result generation. */
  segment: S | null;
}

/** Groups with at least one matching event; each keeps its whole in-scope context (untimed only without a period, R12). */
export function buildGroups<E extends Cells, S>(events: E[], segments: Map<string, S>, filter: RemoteFilter, inPeriod: (timestamp: string) => boolean, periodSet = false): RemoteGroup<E, S>[] {
  return groupEvents<E, RemoteGroup<E, S>>(events, {
    inPeriod,
    periodSet,
    keyOf: (event) => (event.segment_id ? `segment:${event.segment_id}` : `record:${event.record_id}`),
    create: (key, event) => ({ key, segment: event.segment_id ? segments.get(event.segment_id) ?? null : null, events: [], matched: new Set() }),
    matches: (event) => matches(event, filter),
  });
}

/** Events per stored value of one facet under every other condition and the
 *  period (shows what that facet's selection hides). */
export function facetCounts(events: Cells[], filter: RemoteFilter, facet: RemoteFacet, inPeriod: (timestamp: string) => boolean, periodSet = false): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (!inScope(event, inPeriod, periodSet) || !matches(event, filter, facet)) continue;
    const value = FACET_VALUE[facet](event);
    counts[value] = (counts[value] ?? 0) + 1;
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
export const ID_SPACE_LABELS: Record<string, string> = { lsm_session: "LSM 세션", security_logon: "Security 로그온", rdp_client_connection: "클라이언트 연결" };
export const label = (labels: Record<string, string>, value: string | undefined) => (value ? labels[value] ?? value : "");
