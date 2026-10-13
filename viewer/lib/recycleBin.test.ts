import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_RECYCLE_FILTER, filterRecycleRows, recycleFileName } from "./recycleBin.ts";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { formatSize } from "./byteSize.ts";

type Row = Record<string, string>;
const SID = "S-1-5-21-1-2-3-500";
const row = (record_id: string, timestamp: string, extra: Row = {}): Row => ({ record_id, timestamp, account_sid: SID, ...extra });
const ids = (rows: Row[]) => rows.map((r) => r.record_id);
const always = () => true;

const rows = [
  row("b", "2026-09-29 15:23:28.114", { original_path: "C:\\Users\\Administrator\\Downloads\\tool.exe", recycle_name: "C4K320.exe" }),
  row("a", "2026-09-28 10:00:00.000", { original_path: "D:\\share\\보고서.hwp", recycle_name: "03IX0Y.hwp", account_sid: "S-1-5-21-1-2-3-1001", account: "kim" }),
  row("u", "", { recycle_name: "BIG.txt", status: "unreadable_file" }),
];

test("time order follows direction; unreadable rows without a time stay last", () => {
  assert.deepEqual(ids(filterRecycleRows(rows, DEFAULT_RECYCLE_FILTER, always, false, "asc")), ["a", "b", "u"]);
  assert.deepEqual(ids(filterRecycleRows(rows, DEFAULT_RECYCLE_FILTER, always, false, "desc")), ["b", "a", "u"]);
});

test("a period excludes untimed rows and rows outside it", () => {
  const inPeriod = (ts: string) => ts.startsWith("2026-09-29");
  assert.deepEqual(ids(filterRecycleRows(rows, DEFAULT_RECYCLE_FILTER, inPeriod, true, "asc")), ["b"]);
});

test("search covers path, name, account and SID; account facet uses the SID", () => {
  const find = (search: string) => ids(filterRecycleRows(rows, { ...DEFAULT_RECYCLE_FILTER, search }, always, false, "asc"));
  assert.deepEqual(find("보고서"), ["a"]);
  assert.deepEqual(find("c4k320"), ["b"]);
  assert.deepEqual(find("KIM"), ["a"]);
  assert.deepEqual(find("-500"), ["b", "u"]);
  assert.deepEqual(ids(filterRecycleRows(rows, { ...DEFAULT_RECYCLE_FILTER, accounts: [SID] }, always, false, "asc")), ["b", "u"]);
});

test("file name comes from the original path, else the paired name", () => {
  assert.equal(recycleFileName(rows[0]), "tool.exe");
  assert.equal(recycleFileName(row("x", "", { original_path: "\\\\server\\share\\dir\\" })), "dir");
  assert.equal(recycleFileName(rows[2]), "BIG.txt");
  assert.equal(recycleFileName(row("y", "")), "");
});

test("unknown size is not zero", () => {
  assert.equal(formatSize(""), "—");
  assert.equal(formatSize(undefined), "—");
  assert.equal(formatSize("0"), "0 B");
  assert.equal(formatSize("3590816"), "3.4 MB");
});
