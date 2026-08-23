import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../components/RunPipeline.tsx", import.meta.url), "utf8");

test("navigation/unmount has no whole-queue cancellation path", () => {
  // The desktop viewer has no React component test runner. Keep this focused
  // source contract alongside the view: an all-run cancellation is valid only
  // from the analyst's explicit whole-cancel handler, never component cleanup.
  const allCancel = [...source.matchAll(/cancelPipeline\(undefined, true\)/g)];
  assert.equal(allCancel.length, 1);
  assert.ok(allCancel[0].index > source.indexOf("function handleCancel()"));
  assert.match(source, /This is the sole whole-queue cancellation path/);
});
