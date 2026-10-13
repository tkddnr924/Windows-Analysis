import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { monthGrid, parsePickerValue, pickDay, setTimePart } from "./dateTimePicker.ts";

test("month grid starts on Sunday and covers 6 weeks", () => {
  const grid = monthGrid(2026, 9); // October 2026, 1st is a Thursday
  assert.equal(grid.length, 42);
  assert.deepEqual(grid[0], { date: "2026-09-27", inMonth: false });
  assert.deepEqual(grid[4], { date: "2026-10-01", inMonth: true });
  assert.deepEqual(grid[41], { date: "2026-11-07", inMonth: false });
});

test("parse keeps typed parts and rejects impossible values", () => {
  assert.deepEqual(parsePickerValue("2026-10-13 21:05:09"), { date: "2026-10-13", time: "21:05:09" });
  assert.deepEqual(parsePickerValue("2026-10-13"), { date: "2026-10-13", time: null });
  assert.equal(parsePickerValue("2026-02-30"), null);
  assert.equal(parsePickerValue(""), null);
});

test("picking a day keeps an existing time, else uses the edge default", () => {
  assert.equal(pickDay("2026-10-13 21:05:09", "2026-10-20", "start"), "2026-10-20 21:05:09");
  assert.equal(pickDay("", "2026-10-20", "start"), "2026-10-20 00:00:00");
  assert.equal(pickDay("", "2026-10-20", "end"), "2026-10-20 23:59:59");
});

test("time parts are clamped and zero-padded", () => {
  assert.equal(setTimePart("2026-10-20 00:00:00", "hour", 7), "2026-10-20 07:00:00");
  assert.equal(setTimePart("2026-10-20 07:00:00", "minute", 75), "2026-10-20 07:59:00");
  assert.equal(setTimePart("2026-10-20", "second", -3, "end"), "2026-10-20 23:59:00");
  assert.equal(setTimePart("", "hour", 5), "");
});
