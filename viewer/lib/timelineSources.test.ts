import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { createCrossViewDeduper, orderTimelineFiles } from "./timelineSources.ts";

const refs = (...items: [string, string, number][]) => JSON.stringify(items.map(([fullPath, tableName, rowid]) => ({ fullPath, tableName, rowid })));

test("a source event already shown by another view is not repeated; the same view keeps its own records", () => {
  const admit = createCrossViewDeduper();
  const timeline = refs(["/h/TIMELINE/Timeline_Activities.sqlite", "Timeline_Activities", 7]);
  assert.equal(admit("ExecutionHistory", "2026-09-23 15:37:05.000", { __source_refs: timeline }), true);
  assert.equal(admit("TimelineActivities", "2026-09-23 15:37:05.000", { __source_refs: timeline }), false);
  // Same view, same source: distinct derived records (e.g. visit and download) stay.
  const browser = refs(["/h/BROWSER/History.sqlite", "urls", 1]);
  assert.equal(admit("BrowserActivity", "2026-01-01 00:00:00.000", { __source_refs: browser }), true);
  assert.equal(admit("BrowserActivity", "2026-01-01 00:00:00.000", { __source_refs: browser }), true);
  // Different time of the same source is a different timeline point.
  assert.equal(admit("TimelineActivities", "2026-09-23 16:00:00.000", { __source_refs: timeline }), true);
  // Path case/separators do not split one source.
  assert.equal(admit("WerReports", "2026-01-02 00:00:00.000", { __source_refs: refs(["C:\\H\\WER\\a.sqlite", "WER_Reports", 1]) }), true);
  assert.equal(admit("ExecutionHistory", "2026-01-02 00:00:00.000", { __source_refs: refs(["c:/h/wer/A.sqlite", "WER_Reports", 1]) }), false);
  // No evidence links: never deduplicated.
  assert.equal(admit("UsnJournal", "2026-01-03 00:00:00.000", {}), true);
  assert.equal(admit("RecycleBin", "2026-01-03 00:00:00.000", {}), true);
});

test("only the confirmed views are inputs, ExecutionHistory first", () => {
  const files = ["UsnJournal", "JumpListEntries", "TimelineActivities", "BrowserActivity", "WerReports", "ExecutionHistory", "Defender", "RemoteDesktopHistory"].map((name) => ({ name }));
  assert.deepEqual(orderTimelineFiles(files).map((file: { name: string }) => file.name), ["ExecutionHistory", "BrowserActivity", "RemoteDesktopHistory", "Defender", "WerReports", "TimelineActivities", "JumpListEntries"]);
});
