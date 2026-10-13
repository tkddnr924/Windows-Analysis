import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_RDP_FILTER, accountKeyOf, buildRdpGroups, rdpFacetCounts } from "./rdpCache.ts";

type Row = Record<string, string>;
const frag = (record_id: string, tile_count: string, extra: Row = {}): Row => ({ record_id, event_type: "fragment", status: "ok", account: "alice", source_file: "Cache0000.bin", tile_count, image: "iVBOR", ...extra });

test("groups per account + file; fragments by tile count desc then record_id; failed rows kept apart", () => {
  const rows = [
    frag("b", "3"), frag("a", "3"), frag("c", "9"),
    frag("d", "2", { source_file: "Cache0001.bin" }),
    { record_id: "e", event_type: "tile", status: "corrupted", account: "alice", source_file: "Cache0001.bin", tile_index: "12", error: "runs past end" },
    frag("f", "4", { account: "bob" }),
  ];
  const groups = buildRdpGroups(rows, DEFAULT_RDP_FILTER);
  assert.deepEqual(groups.map((g: { key: string }) => g.key), ["alice\u0000Cache0000.bin", "alice\u0000Cache0001.bin", "bob\u0000Cache0000.bin"]);
  assert.deepEqual(groups[0].fragments.map((r: Row) => r.record_id), ["c", "a", "b"]);
  assert.deepEqual(groups[1].errors.map((r: Row) => r.record_id), ["e"]);
});

test("groups key on the account identity: SID-only rows of different users stay apart", () => {
  const rows = [
    frag("a", "1", { account: "", account_sid: "S-1-5-21-1001" }),
    frag("b", "1", { account: "", account_sid: "S-1-5-21-1002" }),
    frag("c", "1", { account_sid: "S-1-5-21-1001" }),
  ];
  const groups = buildRdpGroups(rows, DEFAULT_RDP_FILTER);
  assert.deepEqual(groups.map((g: { key: string; account: string; accountSid: string; fragments: Row[] }) => [g.key, g.account, g.accountSid, g.fragments.map((r) => r.record_id)]), [
    ["S-1-5-21-1001\u0000Cache0000.bin", "alice", "S-1-5-21-1001", ["a", "c"]],
    ["S-1-5-21-1002\u0000Cache0000.bin", "", "S-1-5-21-1002", ["b"]],
  ]);
});

test("search covers file, account and SID; account filter uses SID when stored; status filter", () => {
  const rows = [frag("a", "2", { account_sid: "S-1-5-21-9" }), frag("b", "2", { account: "bob", source_file: "Cache0002.bin" }), { record_id: "e", event_type: "tile", status: "unreadable_file", account: "bob", source_file: "bcache24.bmc" }];
  const ids = (filter: object) => buildRdpGroups(rows, { ...DEFAULT_RDP_FILTER, ...filter }).flatMap((g: { fragments: Row[]; errors: Row[] }) => [...g.fragments, ...g.errors].map((r) => r.record_id));
  assert.deepEqual(ids({ search: "cache0002" }), ["b"]);
  assert.deepEqual(ids({ search: "s-1-5-21-9" }), ["a"]);
  assert.deepEqual(ids({ search: "BOB" }).sort(), ["b", "e"]);
  assert.equal(accountKeyOf(rows[0]), "S-1-5-21-9");
  assert.deepEqual(ids({ accounts: ["S-1-5-21-9"] }), ["a"]);
  assert.deepEqual(ids({ statuses: ["unreadable_file"] }), ["e"]);
  // A fragment row without image data is a failure, not a blank tile.
  const noImage = buildRdpGroups([frag("x", "2", { image: "" })], DEFAULT_RDP_FILTER);
  assert.deepEqual([noImage[0].fragments.length, noImage[0].errors.length], [0, 1]);
});

test("account and status counts follow the other conditions, not their own selection", () => {
  const rows = [frag("a", "1"), frag("b", "1", { account: "bob" }), { record_id: "e", event_type: "tile", status: "corrupted", account: "bob", source_file: "Cache0001.bin" }];
  const filter = { ...DEFAULT_RDP_FILTER, accounts: ["alice"], statuses: ["corrupted"] };
  assert.deepEqual(rdpFacetCounts(rows, filter, "accounts"), { bob: 1 });
  assert.deepEqual(rdpFacetCounts(rows, filter, "statuses"), { ok: 1 });
  assert.deepEqual(rdpFacetCounts(rows, { ...DEFAULT_RDP_FILTER, search: "cache0001" }, "accounts"), { bob: 1 });
});
