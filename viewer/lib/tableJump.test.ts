import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { pendingFilterFor, rowidFilterValue, rowidJumpState, rowsWithJumpRow } from "./tableJump.ts";

const pending = { tableKey: "/h/_OVERVIEW/Defender.sqlite\u0000DefenderEvents", column: "__rowid", value: "42" };

test("a pending filter is only handed to the table it targets", () => {
  assert.equal(pendingFilterFor(pending, pending.tableKey), pending);
  // A dedicated view never consumed it; a later raw table must not inherit it.
  assert.equal(pendingFilterFor(pending, "/h/EVENTLOG/Security.sqlite\u0000Security"), null);
  assert.equal(pendingFilterFor(null, pending.tableKey), null);
});

test("only an exact __rowid column filter is a row jump", () => {
  assert.equal(rowidFilterValue([{ id: "__rowid", value: { mode: "exact", value: "120001" } }]), "120001");
  assert.equal(rowidFilterValue([{ id: "__rowid", value: { mode: "contains", value: "1" } }]), null);
  assert.equal(rowidFilterValue([{ id: "__rowid", value: { mode: "exact", value: "" } }]), null);
  assert.equal(rowidFilterValue([{ id: "user", value: { mode: "exact", value: "1" } }]), null);
  assert.equal(rowidFilterValue([]), null);
});

test("a jump target beyond the loaded chunk is looked up, not reported as 0 rows", () => {
  const loaded = [{ __rowid: "1" }, { __rowid: "2" }];
  assert.equal(rowidJumpState(loaded, "2", false), "loaded");
  assert.equal(rowidJumpState(loaded, "120001", false), "lookup");
  // Fully loaded table without the row: the row does not exist.
  assert.equal(rowidJumpState(loaded, "120001", true), "missing");
});

test("a looked-up row joins the rows only while it is the jump target", () => {
  const loaded = [{ __rowid: "1" }];
  const fetched = { rowid: "120001", row: { __rowid: "120001" } };
  assert.deepEqual(rowsWithJumpRow(loaded, "120001", fetched), [{ __rowid: "1" }, { __rowid: "120001" }]);
  assert.equal(rowsWithJumpRow(loaded, null, fetched), loaded);
  assert.equal(rowsWithJumpRow(loaded, "7", fetched), loaded);
  assert.equal(rowsWithJumpRow(loaded, "120001", null), loaded);
  // Already loaded: no duplicate.
  assert.equal(rowsWithJumpRow([{ __rowid: "120001" }], "120001", fetched).length, 1);
});
