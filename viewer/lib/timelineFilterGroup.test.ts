import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { groupCheckState, toggleGroupChild, toggleGroupParent } from "./timelineFilterGroup.ts";

const ALL = ["visit", "download", "cache", "other"];

test("child toggle on a hidden table shows only the clicked key", () => {
  const next = toggleGroupChild({ tableHidden: true, hidden: new Set(ALL) }, ALL, "download");
  assert.equal(next.tableHidden, false);
  assert.deepEqual([...next.hidden].sort(), ["cache", "other", "visit"]);
});

test("child toggle on a visible table flips only that key", () => {
  const hidden = toggleGroupChild({ tableHidden: false, hidden: new Set<string>() }, ALL, "cache").hidden;
  assert.deepEqual([...hidden], ["cache"]);
  assert.deepEqual([...toggleGroupChild({ tableHidden: false, hidden }, ALL, "cache").hidden], []);
});

test("parent toggle hides the table when all visible, otherwise shows everything", () => {
  const hiddenTable = toggleGroupParent({ tableHidden: false, hidden: new Set<string>() }, ALL);
  assert.equal(hiddenTable.tableHidden, true);
  const shown = toggleGroupParent({ tableHidden: false, hidden: new Set(["visit"]) }, ALL);
  assert.equal(shown.tableHidden, false);
  assert.equal(shown.hidden.size, 0);
});

test("check state treats a hidden table as nothing visible", () => {
  assert.deepEqual(groupCheckState({ tableHidden: true, hidden: new Set(["visit"]) }, ALL), { checked: false, indeterminate: false });
  assert.deepEqual(groupCheckState({ tableHidden: false, hidden: new Set(["visit"]) }, ALL), { checked: false, indeterminate: true });
  assert.deepEqual(groupCheckState({ tableHidden: false, hidden: new Set<string>() }, ALL), { checked: true, indeterminate: false });
});
