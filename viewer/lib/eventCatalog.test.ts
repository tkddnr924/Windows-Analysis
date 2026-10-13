import test from "node:test";
import assert from "node:assert/strict";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { lookupEventCatalog } from "./eventCatalog.ts";

test("persistence events share one category label", () => {
  const keys: [string, string][] = [
    ["Microsoft-Windows-Security-Auditing", "4698"],
    ["Microsoft-Windows-Security-Auditing", "4699"],
    ["Microsoft-Windows-TaskScheduler", "100"],
    ["Microsoft-Windows-TaskScheduler", "102"],
    ["Microsoft-Windows-TaskScheduler", "107"],
    ["Microsoft-Windows-TaskScheduler", "110"],
  ];
  for (const [provider, id] of keys) assert.equal(lookupEventCatalog(provider, id)?.category, "영속성", `${provider}|${id}`);
});
