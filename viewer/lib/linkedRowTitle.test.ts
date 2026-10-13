import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { fallbackLinkedRowTitle } from "./linkedRowTitle.ts";

test("fallback title skips __rowid and identifier columns", () => {
  const record = { __rowid: "7", record_id: "3f2a9c1e-0000-4000-8000-000000000001", host_id: "h1", name: "notepad.exe" };
  assert.equal(fallbackLinkedRowTitle(record), "notepad.exe");
});

test("fallback title skips empty and UUID-valued columns", () => {
  assert.equal(fallbackLinkedRowTitle({ __rowid: "1", ref: "3F2A9C1E-0000-4000-8000-000000000001", path: "", label: "x" }), "x");
  assert.equal(fallbackLinkedRowTitle({ __rowid: "1", record_id: "abc" }), "");
});
