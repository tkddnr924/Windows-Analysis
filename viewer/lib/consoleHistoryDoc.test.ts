import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { buildConsoleDoc, findMatches } from "./consoleHistoryDoc.ts";

test("multi-line commands keep their original file line numbers, gaps included", () => {
  const doc = buildConsoleDoc([
    { line_number: "1", command: "Get-Date" },
    { line_number: "2", command: "foreach ($x in 1..2) {\n  $x\n}" },
    { line_number: "9", command: "exit" },
  ]);
  assert.equal(doc.text, "Get-Date\nforeach ($x in 1..2) {\n  $x\n}\nexit");
  assert.deepEqual(doc.sourceLines, [1, 2, 3, 4, 9]);
});

test("rows without a stored line number get no invented number", () => {
  const doc = buildConsoleDoc([{ command: "a" }, { line_number: "", command: "b\nc" }]);
  assert.deepEqual(doc.sourceLines, [null, null, null]);
});

test("search is case-insensitive, literal and non-overlapping", () => {
  assert.deepEqual(findMatches("Net stop BITS\nnet start bits", "bits"), [{ from: 9, to: 13 }, { from: 24, to: 28 }]);
  assert.deepEqual(findMatches("a.b axb", "a.b"), [{ from: 0, to: 3 }]);
  assert.deepEqual(findMatches("aaaa", "aa"), [{ from: 0, to: 2 }, { from: 2, to: 4 }]);
  assert.deepEqual(findMatches("abc", ""), []);
});
