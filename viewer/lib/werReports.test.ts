import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_WER_FILTER, buildWerCards, exceptionLabel } from "./werReports.ts";

type Row = Record<string, string>;
const ev = (record_id: string, timestamp: string, extra: Row = {}): Row => ({ record_id, timestamp, error_type: "APPCRASH", error_class: "crash", reporting_stage: "report_generated", ...extra });
const always = () => true;
const keys = (cards: { key: string }[]) => cards.map((card) => card.key);

const rows = [
  ev("r1", "2026-09-15 02:13:56.204", { app_name: "mc3504.exe" }),
  ev("e1", "2026-09-15 02:13:54.361", { error_type: "Application Error", reporting_stage: "app_error_event", app_name: "mc3504.exe", search_text: "C:\\Windows\\TEMP\\mc3504.exe" }),
  ev("f1", "2026-09-15 02:14:00.000", { reporting_stage: "report_written" }),
  ev("lone", "2026-09-16 00:00:00.000", { error_type: "MoAppCrash", error_class: "unclassified" }),
  ev("u", ""),
];
// Stored relations, both directions; f1 joins through r1 only.
const relations = [
  { record_id: "e1", related_record_id: "r1" }, { record_id: "r1", related_record_id: "e1" },
  { record_id: "r1", related_record_id: "f1" }, { record_id: "f1", related_record_id: "r1" },
];

test("stored relations join records transitively; unrelated records stay single; untimed last", () => {
  const cards = buildWerCards(rows, relations, DEFAULT_WER_FILTER, always, false, "asc");
  assert.deepEqual(cards.map((card: { events: Row[] }) => card.events.map((row) => row.record_id)), [["e1", "r1", "f1"], ["lone"], ["u"]]);
  assert.equal(cards[0].key, "e1");
});

test("filters keep the related records with match counts; search uses search_text", () => {
  const files = buildWerCards(rows, relations, { ...DEFAULT_WER_FILTER, stages: ["report_written"] }, always, false, "asc");
  assert.equal(files.length, 1);
  assert.deepEqual([...files[0].matched], ["f1"]);
  assert.equal(files[0].events.length, 3);
  assert.deepEqual(keys(buildWerCards(rows, relations, { ...DEFAULT_WER_FILTER, search: "temp\\mc3504" }, always, false, "asc")), ["e1"]);
  assert.deepEqual(keys(buildWerCards(rows, relations, { ...DEFAULT_WER_FILTER, classes: ["unclassified"] }, always, false, "asc")), ["lone"]);
});

test("period drops outside and untimed rows; relations to dropped rows do not pull them back", () => {
  const cards = buildWerCards(rows, relations, DEFAULT_WER_FILTER, (t: string) => t >= "2026-09-15 02:13:55", true, "asc");
  assert.deepEqual(cards.map((card: { events: Row[] }) => card.events.map((row) => row.record_id)), [["r1", "f1"], ["lone"]]);
});

test("documented exception codes show their meaning; unknown codes stay raw", () => {
  assert.equal(exceptionLabel("c00000fd"), "c00000fd (스택 오버플로)");
  assert.equal(exceptionLabel("0xC0000005"), "0xC0000005 (메모리 접근 위반)");
  assert.equal(exceptionLabel("e0434352"), "e0434352");
  assert.equal(exceptionLabel(""), "");
});
