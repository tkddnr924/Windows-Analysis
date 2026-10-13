import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { RESULT_COLOR, facetOptions, optionsOf, pageWindow, resultColor, timeSpan, valueLabels } from "./eventCards.ts";

type Row = Record<string, string>;

test("result colors cover every stored result; unknown results still get a color", () => {
  assert.equal(RESULT_COLOR["정보"], "var(--text-faint)");
  assert.equal(resultColor("정보"), "var(--text-faint)");
  assert.equal(resultColor("실패"), "var(--danger)");
  assert.equal(resultColor("기타"), "var(--text-faint)");
  assert.equal(resultColor(undefined), "var(--text-faint)");
});

test("card time span is earliest → latest whatever the display order", () => {
  const asc: Row[] = [{ timestamp: "2026-09-23 20:05:33.608" }, { timestamp: "" }, { timestamp: "2026-09-23 20:49:11.034" }];
  const desc = [...asc].reverse();
  for (const events of [asc, desc]) assert.deepEqual(timeSpan(events), { from: "2026-09-23 20:05:33.608", to: "2026-09-23 20:49:11.034" });
  assert.deepEqual(timeSpan([{ timestamp: "" }]), { from: "", to: "" });
});

test("stored-value options: row-based labels, empty bucket label, label order", () => {
  const rows: Row[] = [{ k: "b", name: "Bravo" }, { k: "a", name: "Alpha" }, { k: "b", name: "Bravo" }, { k: "" }];
  assert.deepEqual(optionsOf(rows, (row: Row) => row.k, (_value: string, row: Row) => row.name), [
    { value: "", label: "(없음)", count: 1 },
    { value: "a", label: "Alpha", count: 1 },
    { value: "b", label: "Bravo", count: 2 },
  ]);
  assert.equal(optionsOf(rows, (row: Row) => row.k, undefined, "(계정 없음)")[0].label, "(계정 없음)");
});

test("facet options list every stored value and selection; counts come from the narrowed set", () => {
  const labels = valueLabels([{ d: "outbound" }, { d: "inbound" }, { d: "unknown" }, { d: "" }], (row: Row) => row.d, (value: string) => value.toUpperCase(), "(계정 없음)");
  const options = facetOptions(labels, { inbound: 3 }, ["gone"], { inbound: "red" });
  assert.deepEqual(options, [
    { value: "", label: "(계정 없음)", count: 0, color: undefined },
    { value: "gone", label: "gone", count: 0, color: undefined },
    { value: "inbound", label: "INBOUND", count: 3, color: "red" },
    { value: "outbound", label: "OUTBOUND", count: 0, color: undefined },
    { value: "unknown", label: "UNKNOWN", count: 0, color: undefined },
  ]);
});

test("page window clamps the page and summarises the slice", () => {
  assert.deepEqual(pageWindow(25, 7), { page: 2, pageCount: 3, start: 20, end: 25, summary: "(21–25 / 25)" });
  assert.deepEqual(pageWindow(0, 3), { page: 0, pageCount: 1, start: 0, end: 0, summary: "(0–0 / 0)" });
});
