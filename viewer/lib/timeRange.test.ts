import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { inRange, rangeBounds, timeColumnFor } from "./timeRange.ts";

test("date-only end bound covers the whole day for backend string compares", () => {
  assert.deepEqual(rangeBounds({ start: "2026-09-28", end: "2026-09-28" }), {
    start: "2026-09-28 00:00:00.000",
    end: "2026-09-28 23:59:59.999",
  });
  // A record late on the end date stays inside the window.
  const { end } = rangeBounds({ start: "", end: "2026-09-28" });
  assert.ok("2026-09-28 21:44:30.478" <= end);
});

test("partial or unset bounds do not constrain the range", () => {
  assert.deepEqual(rangeBounds({ start: "2", end: "" }), { start: "", end: "" });
  assert.deepEqual(rangeBounds({ start: "2026-09-28 10:15", end: "" }), { start: "2026-09-28 10:15:00.000", end: "" });
});

test("impossible calendar dates or clock times are rejected", () => {
  assert.deepEqual(rangeBounds({ start: "2024-13-45", end: "2024-10-13 99:99" }), { start: "", end: "" });
  assert.deepEqual(rangeBounds({ start: "2023-02-29", end: "2024-02-30" }), { start: "", end: "" });
  assert.deepEqual(rangeBounds({ start: "2024-02-29 23:59:60", end: "" }), { start: "", end: "" });
  assert.equal(rangeBounds({ start: "2024-02-29 23:59:59", end: "" }).start, "2024-02-29 23:59:59.000");
});

test("time column does not depend on the first row having a value", () => {
  const columns = ["name", "si_created", "si_modified"];
  const rows = [
    { name: "a", si_created: "", si_modified: "2024-01-01 00:00:00.000" },
    { name: "b", si_created: "2024-01-02 00:00:00.000", si_modified: "2024-01-02 00:00:00.000" },
  ];
  assert.equal(timeColumnFor(null, columns, rows), "si_created");
  assert.equal(timeColumnFor(null, columns, []), null);
});

test("inRange keeps results when the same range object is reused", () => {
  const range = { start: "2024-01-01", end: "2024-01-01" };
  assert.equal(inRange("2024-01-01 12:00:00.000", range), true);
  assert.equal(inRange("2024-01-02 00:00:00.000", range), false);
  assert.equal(inRange("", range), false);
});
