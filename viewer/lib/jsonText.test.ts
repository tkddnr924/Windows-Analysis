import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { hasControlSequences, prettyJsonOrNull, unescapeControlSequences } from "./jsonText.ts";

test("prettyJsonOrNull indents objects/arrays and rejects other text", () => {
  assert.equal(prettyJsonOrNull(' {"a":1} '), '{\n  "a": 1\n}');
  assert.equal(prettyJsonOrNull("[1]"), "[\n  1\n]");
  assert.equal(prettyJsonOrNull("plain"), null);
  assert.equal(prettyJsonOrNull("{broken"), null);
  assert.equal(prettyJsonOrNull("42"), null);
});

test("unescapeControlSequences expands \\r\\n, \\n, \\t", () => {
  assert.equal(unescapeControlSequences("a\\r\\nb\\nc\\rd\\te"), "a\nb\nc\nd    e");
});

test("unescapeControlSequences preserves escaped backslashes like C:\\\\Windows", () => {
  assert.equal(unescapeControlSequences("C:\\\\Windows\\\\new"), "C:\\\\Windows\\\\new");
  assert.equal(unescapeControlSequences("C:\\\\temp\\nnext"), "C:\\\\temp\nnext");
});

test("hasControlSequences ignores escaped backslash pairs", () => {
  assert.equal(hasControlSequences("C:\\\\Windows\\\\new"), false);
  assert.equal(hasControlSequences("line\\nline"), true);
});
