import assert from "node:assert/strict";
import test from "node:test";
// Node's strip-types runner requires an explicit extension while Next resolves
// the same module without one.
// @ts-expect-error app bundling resolves the extensionless import separately.
import { graphEdgesForScope } from "./hostGraphScope.ts";

const edges = [
  { host: "DEV", peer: "113.52.97.81", id: "dev-external" },
  { host: "MAINDB1", peer: "DEV", id: "db-to-dev" },
];

test("host-focused graph and inspector exclude another host's relationships", () => {
  assert.deepEqual(
    graphEdgesForScope(edges, "maindb1", false).map((edge) => edge.id),
    ["db-to-dev"],
  );
});

test("host-focused graph exposes an empty set when the selected host has no direct RDP evidence", () => {
  assert.deepEqual(graphEdgesForScope(edges, "OCR", false), []);
  assert.deepEqual(graphEdgesForScope(edges, "OCR", true), edges);
});
