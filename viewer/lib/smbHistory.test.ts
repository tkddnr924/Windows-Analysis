import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_SMB_FILTER, buildContextItems, buildSmbGroups, groupShares, smbResultCounts } from "./smbHistory.ts";

type Ev = Record<string, string>;
const ev = (record_id: string, timestamp: string, extra: Ev = {}): Ev => ({ record_id, timestamp, result: "성공", direction: "inbound", remote_address: "10.0.0.5", ...extra });
const always = () => true;
const keys = (groups: { key: string }[]) => groups.map((group) => group.key);
const ids = (group: { events: Ev[] }) => group.events.map((event) => event.record_id);

test("default filter keeps every result; groups are per address and keep the whole context", () => {
  assert.deepEqual(DEFAULT_SMB_FILTER, { results: [], directions: [], accounts: [], search: "" });
  const events = [
    ev("b", "2026-01-01 10:05:00.000"),
    ev("a", "2026-01-01 10:00:00.000", { result: "실패" }),
    ev("c", "2026-01-01 09:00:00.000", { remote_address: "10.0.0.9" }),
  ];
  const all = buildSmbGroups(events, DEFAULT_SMB_FILTER, always);
  assert.deepEqual(keys(all), ["address:10.0.0.9", "address:10.0.0.5"]);
  assert.deepEqual(ids(all[1]), ["a", "b"]);
  const failed = buildSmbGroups(events, { ...DEFAULT_SMB_FILTER, results: ["실패"] }, always);
  assert.deepEqual(keys(failed), ["address:10.0.0.5"]);
  // R11: match count vs whole address context.
  assert.deepEqual(ids(failed[0]), ["a", "b"]);
  assert.deepEqual([...failed[0].matched], ["a"]);
});

test("address-less events are never merged into one peer (R07)", () => {
  const events = [ev("x", "2026-01-01 10:00:00.000", { remote_address: "" }), ev("y", "2026-01-01 10:01:00.000", { remote_address: "" })];
  assert.deepEqual(keys(buildSmbGroups(events, DEFAULT_SMB_FILTER, always)), ["record:x", "record:y"]);
});

test("same-time events order by record_id; untimed events sort last and drop out with a period (R13)", () => {
  const events = [ev("z", ""), ev("m2", "2026-01-01 10:00:00.000"), ev("m1", "2026-01-01 10:00:00.000")];
  assert.deepEqual(ids(buildSmbGroups(events, DEFAULT_SMB_FILTER, always)[0]), ["m1", "m2", "z"]);
  assert.deepEqual(ids(buildSmbGroups(events, DEFAULT_SMB_FILTER, always, true)[0]), ["m1", "m2"]);
});

test("search covers share, path, file, rights, EID, UPN and SIDs; account filter uses the stored identity key (R03, R10)", () => {
  const events = [
    ev("a", "2026-01-01 10:00:00.000", { account_key: "S-1-5-21-9", account: "alice", account_domain: "CORP", account_sid: "S-1-5-21-9", share_name: "\\\\*\\C$", share_path: "\\??\\C:\\", target_file: "Windows\\evil.exe", access_rights: "WriteData", event_id: "5145" }),
    ev("b", "2026-01-01 10:01:00.000", { account_key: "su@example.com", account: "su", account_upn: "su@example.com", event_id: "4625", result: "실패" }),
  ];
  const find = (search: string) => buildSmbGroups(events, { ...DEFAULT_SMB_FILTER, search }, always).flatMap((group: { matched: Set<string> }) => [...group.matched]);
  assert.deepEqual(find("c$"), ["a"]);
  assert.deepEqual(find("evil.exe"), ["a"]);
  assert.deepEqual(find("writedata"), ["a"]);
  assert.deepEqual(find("4625"), ["b"]);
  assert.deepEqual(find("example.com"), ["b"]);
  assert.deepEqual(find("s-1-5-21-9"), ["a"]);
  const byAccount = buildSmbGroups(events, { ...DEFAULT_SMB_FILTER, accounts: ["su@example.com"] }, always);
  assert.deepEqual([...byAccount[0].matched], ["b"]);
});

test("result counts follow every other condition; shares list distinct stored names", () => {
  const events = [
    ev("a", "2026-01-01 10:00:00.000", { share_name: "\\\\*\\IPC$" }),
    ev("b", "2026-01-01 10:01:00.000", { result: "실패", share_name: "\\\\*\\IPC$" }),
    ev("c", "2026-01-01 10:02:00.000", { direction: "outbound", result: "", share_name: "\\\\srv\\data" }),
  ];
  assert.deepEqual(smbResultCounts(events, { ...DEFAULT_SMB_FILTER, results: ["성공"], directions: ["inbound"] }, always), { 성공: 1, 실패: 1 });
  const [group] = buildSmbGroups(events, DEFAULT_SMB_FILTER, always);
  assert.deepEqual(groupShares(group), ["\\\\*\\IPC$", "\\\\srv\\data"]);
});

test("context tab: stored relations attach context rows under their SMB record; the rest stay single, time ordered", () => {
  const records = [ev("r1", "2026-01-01 10:00:00.000")];
  const context = [
    { record_id: "c-end", timestamp: "2026-01-01 10:00:05.000", event_type: "logon_instance_end" },
    { record_id: "c-priv", timestamp: "2026-01-01 09:59:59.000", event_type: "special_privileges_assigned" },
    { record_id: "c-ntlm", timestamp: "2026-01-01 09:59:00.000", event_type: "ntlm_credential_validation" },
    { record_id: "c-boot", timestamp: "", event_type: "system_start" },
  ];
  const relations = [
    { record_id: "r1", ordinal: "1", context_id: "c-end", relation_kind: "logon_instance_end" },
    { record_id: "r1", ordinal: "0", context_id: "c-priv", relation_kind: "special_privileges" },
  ];
  const items = buildContextItems(records, context, relations, always);
  assert.deepEqual(items.map((item: { key: string }) => item.key), ["single:c-ntlm", "linked:r1", "single:c-boot"]);
  const linked = items[1];
  assert.equal(linked.kind, "linked");
  if (linked.kind !== "linked") return;
  // Children follow time order; the relation kind is kept.
  assert.deepEqual(linked.children.map((child: { row: Ev; relation: string }) => [child.row.record_id, child.relation]), [["c-priv", "special_privileges"], ["c-end", "logon_instance_end"]]);
  // A period drops untimed singles.
  assert.deepEqual(buildContextItems(records, context, relations, always, true).map((item: { key: string }) => item.key), ["single:c-ntlm", "linked:r1"]);
});
