import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_FILTER, ID_SPACE_LABELS, accountKeyOf, buildGroups, facetCounts, hostCandidates } from "./remoteAccess.ts";

const ev = (record_id: string, timestamp: string, extra: Record<string, string> = {}) => ({ record_id, timestamp, result: "성공", direction: "inbound", access_scope: "remote", ...extra });
const always = () => true;

test("stored segments group events; rows without a segment stay single; NULL times sort last", () => {
  const events = [
    ev("b", "2026-01-01 10:05:00.000", { segment_id: "s1" }),
    ev("a", "2026-01-01 10:00:00.000", { segment_id: "s1" }),
    ev("c", "2026-01-01 10:01:00.000"),
    ev("d", "2026-01-01 10:01:00.000"),
    ev("u", "", { segment_id: "s2" }),
  ];
  const groups = buildGroups(events, new Map([["s1", { segment_id: "s1" }], ["s2", { segment_id: "s2" }]]), { ...DEFAULT_FILTER, results: [] }, always);
  assert.deepEqual(groups.map((g: { key: string; events: { record_id: string }[] }) => [g.key, g.events.map((e) => e.record_id)]), [
    ["segment:s1", ["a", "b"]],
    ["record:c", ["c"]],
    ["record:d", ["d"]],
    ["segment:s2", ["u"]],
  ]);
});

test("event conditions pick groups but keep their whole context with match counts", () => {
  const events = [
    ev("a", "2026-01-01 10:00:00.000", { segment_id: "s1", result: "정보" }),
    ev("b", "2026-01-01 10:01:00.000", { segment_id: "s1", result: "성공" }),
    ev("c", "2026-01-01 11:00:00.000", { segment_id: "s2", result: "정보" }),
  ];
  const groups = buildGroups(events, new Map(), DEFAULT_FILTER, always);
  assert.equal(DEFAULT_FILTER.results.join(), "성공");
  // Local/unknown-scope evidence is kept but not shown by default (R01).
  assert.deepEqual(buildGroups([ev("l", "2026-01-01 12:00:00.000", { access_scope: "local", direction: "unknown" })], new Map(), DEFAULT_FILTER, always), []);
  assert.deepEqual(groups.map((g: { key: string; events: unknown[]; matched: Set<string> }) => [g.key, g.events.length, [...g.matched]]), [["segment:s1", 2, ["b"]]]);
  assert.deepEqual(facetCounts(events, DEFAULT_FILTER, "results", always), { 성공: 1, 정보: 2 });
});

test("facet counts use stored values (incl. unknown) and every other condition plus period", () => {
  const events = [
    ev("a", "2026-01-01 10:00:00.000", { access_scope: "unknown", direction: "inbound" }),
    ev("b", "2026-01-01 10:01:00.000", { access_scope: "local", direction: "unknown" }),
    ev("c", "2026-01-01 10:02:00.000", { access_scope: "remote", direction: "outbound" }),
    ev("d", "2026-02-01 10:00:00.000", { access_scope: "remote", direction: "outbound" }),
    ev("e", "2026-01-01 10:03:00.000", { access_scope: "remote", direction: "outbound", result: "정보" }),
  ];
  const january = (timestamp: string) => timestamp.startsWith("2026-01");
  // Scope counts ignore the scope filter itself but honour result + period.
  assert.deepEqual(facetCounts(events, DEFAULT_FILTER, "scopes", january, true), { unknown: 1, local: 1, remote: 1 });
  // Direction counts honour the default remote scope.
  assert.deepEqual(facetCounts(events, DEFAULT_FILTER, "directions", january, true), { outbound: 1 });
  assert.deepEqual(facetCounts(events, { ...DEFAULT_FILTER, scopes: [] }, "directions", january, true), { inbound: 1, unknown: 1, outbound: 1 });
  assert.deepEqual(facetCounts(events, DEFAULT_FILTER, "accounts", always), { "": 2 });
});

test("search covers SID, remote computer and description; account filter uses the identity key", () => {
  const events = [
    ev("a", "2026-01-01 10:00:00.000", { account_key: "S-1-5-21-9", account: "alice", account_domain: "CORP", target_user_sid: "S-1-5-21-9" }),
    ev("b", "2026-01-01 10:01:00.000", { account_key: "other\\alice", account: "Alice", account_domain: "OTHER", remote_computer: "WS-07" }),
    ev("c", "2026-01-01 10:02:00.000", { description: "RDP 인증 성공" }),
  ];
  const ids = (filter: object) => buildGroups(events, new Map(), { ...DEFAULT_FILTER, results: [], ...filter }, always).map((g: { events: { record_id: string }[] }) => g.events[0].record_id);
  assert.deepEqual(ids({ search: "s-1-5-21-9" }), ["a"]);
  assert.deepEqual(ids({ search: "ws-07" }), ["b"]);
  assert.deepEqual(ids({ search: "인증" }), ["c"]);
  // Same short name in another domain is a different account.
  assert.deepEqual(ids({ accounts: ["corp\\alice"] }), ["a"]);
  assert.deepEqual(ids({ directions: ["unknown"] }), []);
});

test("account chips: SID-keyed and name-keyed rows of one domain account share an entry; no-domain stays apart", () => {
  assert.equal(accountKeyOf({ account_key: "S-1-5-21-1-500", account: "Administrator", account_domain: "WIN-A" }), accountKeyOf({ account_key: "win-a\\administrator", account: "Administrator", account_domain: "WIN-A" }));
  assert.notEqual(accountKeyOf({ account: "administrator" }), accountKeyOf({ account: "administrator", account_domain: "WIN-A" }));
  assert.notEqual(accountKeyOf({ account: "administrator", account_domain: "DESKTOP-1" }), accountKeyOf({ account: "administrator", account_domain: "WIN-A" }));
  assert.equal(accountKeyOf({}), "");
});

test("untimed events stay visible without a period and drop out with one", () => {
  const events = [ev("t", "2026-01-01 10:00:00.000"), ev("u", "")];
  const inPeriod = (timestamp: string) => timestamp.startsWith("2026-01-01");
  assert.deepEqual(buildGroups(events, new Map(), { ...DEFAULT_FILTER, results: [] }, always, false).map((g: { key: string }) => g.key), ["record:t", "record:u"]);
  assert.deepEqual(buildGroups(events, new Map(), { ...DEFAULT_FILTER, results: [] }, inPeriod, true).map((g: { key: string }) => g.key), ["record:t"]);
});

test("every registered host on an address is a candidate; loopback and LOCAL never are", () => {
  const map = { "10.0.0.5": [{ id: "h1", name: "A" }, { id: "h2", name: "B" }] };
  assert.deepEqual(hostCandidates("10.0.0.5", map).map((h: { name: string }) => h.name), ["A", "B"]);
  assert.deepEqual(hostCandidates("127.0.0.1", { "127.0.0.1": [{ id: "h1", name: "A" }] }), []);
  assert.deepEqual(hostCandidates("LOCAL", map), []);
  assert.deepEqual(hostCandidates("", map), []);
});

test("every id_space the Rust correlator emits has a label", () => {
  // rust/core/src/remote_access/relations.rs IdSpace::as_str
  assert.deepEqual(Object.keys(ID_SPACE_LABELS).sort(), ["lsm_session", "rdp_client_connection", "security_logon"]);
});
