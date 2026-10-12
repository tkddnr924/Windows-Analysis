import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_LIST_FILTERS, EXTENSION_PRESETS, NOISE_FOLDERS, activeFilterCount, activityOf, describeFilters, noiseExcluded, presetActive, timeBounds, timeKeysFor, toListOptions, withNoiseExcluded, withTimeKeys, withTimeMode } from "./mftListFilters.ts";

test("defaults list files only, sorted by path, without other conditions", () => {
  assert.deepEqual(toListOptions(DEFAULT_LIST_FILTERS, "v1"), { sortKey: "path", sortDesc: false, kind: "file", volumeId: "v1" });
  assert.equal(activeFilterCount(DEFAULT_LIST_FILTERS), 0);
  assert.deepEqual(describeFilters(DEFAULT_LIST_FILTERS), []);
});

test("a period with only a start, only an end, or both", () => {
  const range = (timeFrom: string, timeTo: string) => timeBounds({ ...DEFAULT_LIST_FILTERS, timeMode: "range", timeFrom, timeTo });
  assert.deepEqual(range("2026-09-28", ""), { start: "2026-09-28 00:00:00.000" });
  assert.deepEqual(range("", "2026-09-29 10:00"), { end: "2026-09-29 10:00:59.999" });
  assert.deepEqual(range("2026-09-28", "2026-09-29 10:00"), { start: "2026-09-28 00:00:00.000", end: "2026-09-29 10:00:59.999" });
  assert.ok(range("", "").error, "an empty period is reported, not ignored");
  assert.deepEqual(timeBounds(DEFAULT_LIST_FILTERS), {});
});

test("impossible dates, hours and reversed ranges are errors, never a shifted period", () => {
  const range = (timeFrom: string, timeTo = "") => timeBounds({ ...DEFAULT_LIST_FILTERS, timeMode: "range", timeFrom, timeTo });
  for (const bad of ["2026-02-30", "2026-13-01", "2026-09-28 25:00", "2026-09-28 10:60", "2026-09-28 10:00:61", "28/09/2026"]) {
    const bounds = range(bad);
    assert.ok(bounds.error, bad);
    assert.equal(bounds.start, undefined, bad);
  }
  assert.ok(range("2024-02-29").start, "leap day is a real date");
  const reversed = range("2026-09-29", "2026-09-28");
  assert.ok(reversed.error);
  assert.equal(reversed.start, undefined);
  assert.ok(timeBounds({ ...DEFAULT_LIST_FILTERS, timeMode: "around", anchor: "2026-02-30 10:00:00" }).error);
  assert.equal(toListOptions({ ...DEFAULT_LIST_FILTERS, timeMode: "range", timeFrom: "2026-02-30" }, "v").timeStart, undefined);
});

test("around an anchor keeps milliseconds and crosses day boundaries", () => {
  const filters = { ...DEFAULT_LIST_FILTERS, timeMode: "around" as const, anchor: "2026-09-28 23:58:30.250", aroundBefore: 10, aroundAfter: 5 };
  assert.deepEqual(timeBounds(filters), { start: "2026-09-28 23:48:30.250", end: "2026-09-29 00:03:30.250" });
});

test("activity choice maps to time fields and back", () => {
  assert.deepEqual(timeKeysFor("created", false), ["created"]);
  assert.deepEqual(timeKeysFor("both", true), ["created", "modified", "fn_created", "fn_modified"]);
  assert.deepEqual(activityOf(["modified", "fn_modified"]), { activity: "modified", withFn: true });
  assert.equal(activityOf(["accessed"]), null, "a hand-picked set is shown as custom");
  assert.deepEqual(activityOf(DEFAULT_LIST_FILTERS.timeKeys), { activity: "created", withFn: true });
});

test("time fields go to the query as one OR set; sort follows the first", () => {
  const timed = withTimeMode(withTimeKeys(DEFAULT_LIST_FILTERS, ["modified", "created"]), "around");
  assert.deepEqual(timed.timeKeys, ["created", "modified"], "canonical order");
  assert.equal(timed.sortKey, "created");
  assert.deepEqual(toListOptions({ ...timed, anchor: "2026-09-28 12:00:00" }, "v1").timeKeys, ["created", "modified"]);
  assert.equal(withTimeKeys(timed, ["modified"]).sortKey, "modified");
  assert.equal(withTimeMode({ ...DEFAULT_LIST_FILTERS, sortKey: "size" }, "range").sortKey, "size");
  assert.deepEqual(withTimeKeys(timed, []).timeKeys, ["created", "modified"], "at least one field stays selected");
});

test("the update-noise switch adds and removes only its own folders", () => {
  const custom = { ...DEFAULT_LIST_FILTERS, excludePaths: ["\\Windows\\Temp"] };
  const on = withNoiseExcluded(custom, true);
  assert.equal(noiseExcluded(on), true);
  assert.deepEqual(on.excludePaths, ["\\Windows\\Temp", ...NOISE_FOLDERS]);
  assert.deepEqual(withNoiseExcluded(on, false).excludePaths, ["\\Windows\\Temp"]);
  assert.deepEqual(describeFilters(on), ["Windows 업데이트 폴더 제외", "제외: \\Windows\\Temp"]);
  assert.deepEqual(toListOptions({ ...DEFAULT_LIST_FILTERS, excludePaths: [" \\A ", "\\A", ""] }, "v").excludePaths, ["\\A"]);
});

test("size presets become byte bounds and flags pass through only when on", () => {
  const options = toListOptions({ ...DEFAULT_LIST_FILTERS, size: "large", residentOnly: true, siBeforeFn: true, inUse: "0", pathPrefix: " \\Users ", kind: "all" }, "v1");
  assert.equal(options.sizeMin, 100 * 1024 * 1024);
  assert.equal(options.sizeMax, undefined);
  assert.equal(options.residentOnly, true);
  assert.equal(options.siBeforeFn, true);
  assert.equal(options.pathIncomplete, undefined);
  assert.equal(options.inUse, 0);
  assert.equal(options.pathPrefix, "\\Users");
  assert.equal(options.kind, undefined);
});

test("extension presets are recognised regardless of order and case", () => {
  const filters = { ...DEFAULT_LIST_FILTERS, extension: EXTENSION_PRESETS.archive.extensions.slice().reverse().join(", ").toUpperCase() };
  assert.equal(presetActive(filters, "archive"), true);
  assert.equal(presetActive(filters, "executable"), false);
  assert.equal(activeFilterCount(filters), 1);
  assert.deepEqual(describeFilters(filters), ["확장자: 압축"]);
});
