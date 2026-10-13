import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_FIREWALL_FILTER, buildFirewallCards, ruleDisplayName } from "./firewallHistory.ts";

type Row = Record<string, string>;
const ev = (record_id: string, timestamp: string, extra: Row = {}): Row => ({ record_id, timestamp, event_type: "방화벽 이벤트 2097", ...extra });
const always = () => true;
const keys = (cards: { key: string }[]) => cards.map((card) => card.key);

const rows = [
  ev("a", "2026-09-23 20:05:33.608", { rule_id: "{R1}", action: "차단", direction: "인바운드", protocol_number: "256" }),
  ev("b", "2026-09-23 19:59:44.855", { rule_id: "{R1}", action: "허용", direction: "인바운드", protocol_number: "256" }),
  ev("c", "2026-09-23 20:49:11.033", { rule_id: "{R1}", event_type: "규칙 삭제" }),
  ev("n", "2026-09-29 18:09:07.140", { event_type: "수신 차단 알림", protocol_number: "6", app_path: "C:\\oraclexe\\oracle.exe" }),
  ev("z", "", { event_type: "방화벽 이벤트 1030", protocol_number: "0" }),
];

test("cards follow the stored rule_id; rows without a rule stay single; untimed last", () => {
  const cards = buildFirewallCards(rows, DEFAULT_FIREWALL_FILTER, always, false, "asc");
  assert.deepEqual(keys(cards), ["rule::{R1}", "record::n", "record::z"]);
  assert.deepEqual(cards[0].events.map((row: Row) => row.record_id), ["b", "a", "c"]);
  assert.deepEqual(keys(buildFirewallCards(rows, DEFAULT_FIREWALL_FILTER, always, false, "desc")), ["record::n", "rule::{R1}", "record::z"]);
});

test("filters keep the whole rule history with match counts", () => {
  const blocked = buildFirewallCards(rows, { ...DEFAULT_FIREWALL_FILTER, actions: ["차단"] }, always, false, "asc");
  assert.deepEqual(keys(blocked), ["rule::{R1}"]);
  assert.deepEqual([...blocked[0].matched], ["a"]);
  assert.equal(blocked[0].events.length, 3);
});

test("protocol filter separates unrecorded from 0; search covers app path and rule id", () => {
  assert.deepEqual(keys(buildFirewallCards(rows, { ...DEFAULT_FIREWALL_FILTER, protocols: ["0"] }, always, false, "asc")), ["record::z"]);
  assert.deepEqual(keys(buildFirewallCards(rows, { ...DEFAULT_FIREWALL_FILTER, protocols: [""] }, always, false, "asc")), ["rule::{R1}"]);
  assert.deepEqual(keys(buildFirewallCards(rows, { ...DEFAULT_FIREWALL_FILTER, search: "oracle.exe" }, always, false, "asc")), ["record::n"]);
  assert.deepEqual(keys(buildFirewallCards(rows, { ...DEFAULT_FIREWALL_FILTER, search: "{r1}" }, always, false, "asc")), ["rule::{R1}"]);
});

test("period drops outside and untimed rows", () => {
  assert.deepEqual(keys(buildFirewallCards(rows, DEFAULT_FIREWALL_FILTER, (t: string) => t >= "2026-09-29", true, "asc")), ["record::n"]);
});

test("package resource rule names show the package name only", () => {
  assert.equal(ruleDisplayName("@{Microsoft.WindowsMaps_11.2403.4.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsMaps/Resources/AppStoreName}"), "Microsoft.WindowsMaps");
  assert.equal(ruleDisplayName("Usermode Font Driver Host"), "Usermode Font Driver Host");
  assert.equal(ruleDisplayName("@{weird}"), "@{weird}");
});
