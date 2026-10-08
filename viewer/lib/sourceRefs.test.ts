import assert from "node:assert/strict";
import test from "node:test";
// Node's built-in TypeScript runner requires an explicit local extension;
// Next's bundler resolves the application import without one.
// @ts-expect-error node --experimental-strip-types test entry
import { bookmarkRefKeys, isRecordBookmarked, parseSourceRefs, sourceRefKey } from "./sourceRefs.ts";
import type { Bookmark } from "./types.ts";

const RAW_DB = "/cases/CASE/host-a/EVENTLOG/Security.sqlite";
const OTHER_RAW_DB = "/cases/CASE/host-a/EVENTLOG/System.sqlite";
const MFT_DB = "/cases/CASE/host-a/_OVERVIEW/MFT_Records.sqlite";

const bookmark = (over: Partial<Bookmark>): Bookmark => ({
  id: "bm",
  fullPath: RAW_DB,
  tableName: "Security",
  rowid: 57,
  note: "",
  taggedAt: "",
  ...over,
});

const refs = (entries: { fullPath: string; tableName: string; rowid: number }[]) => JSON.stringify(entries);

test("one raw bookmark shows on the overview, search and timeline views alike", () => {
  const keys = bookmarkRefKeys([bookmark({})]);
  const sourceRefs = parseSourceRefs(refs([{ fullPath: RAW_DB, tableName: "Security", rowid: 57 }]));

  // Derived overview row.
  assert.equal(
    isRecordBookmarked(keys, { fullPath: "/cases/CASE/host-a/_OVERVIEW/ServiceHistory.sqlite", tableName: "ServiceHistory", rowid: 3 }, sourceRefs),
    true,
  );
  // Same evidence reached through another derived table (timeline row).
  assert.equal(
    isRecordBookmarked(keys, { fullPath: "/cases/CASE/host-a/_OVERVIEW/RemoteDesktopHistory.sqlite", tableName: "RemoteDesktopHistory", rowid: 11 }, sourceRefs),
    true,
  );
  // Search hit on the raw row itself, which carries no refs.
  assert.equal(isRecordBookmarked(keys, { fullPath: RAW_DB, tableName: "Security", rowid: 57 }, []), true);
});

test("same table and rowid in a different source file is a different record", () => {
  const keys = bookmarkRefKeys([bookmark({ fullPath: RAW_DB, tableName: "Security", rowid: 57 })]);
  const otherFileRefs = parseSourceRefs(refs([{ fullPath: OTHER_RAW_DB, tableName: "Security", rowid: 57 }]));
  assert.equal(
    isRecordBookmarked(keys, { fullPath: "/cases/CASE/host-a/_OVERVIEW/ServiceHistory.sqlite", tableName: "ServiceHistory", rowid: 3 }, otherFileRefs),
    false,
  );
});

test("a row with several origins shows bookmarked when any origin is", () => {
  const keys = bookmarkRefKeys([bookmark({ fullPath: OTHER_RAW_DB, tableName: "System", rowid: 9 })]);
  const multi = parseSourceRefs(refs([
    { fullPath: RAW_DB, tableName: "Security", rowid: 57 },
    { fullPath: OTHER_RAW_DB, tableName: "System", rowid: 9 },
  ]));
  assert.equal(isRecordBookmarked(keys, { fullPath: "/x/_OVERVIEW/ExecutionHistory.sqlite", tableName: "ExecutionHistory", rowid: 1 }, multi), true);
});

test("per-timestamp bookmarks do not collide with whole-row ones", () => {
  const fieldKeys = bookmarkRefKeys([bookmark({ fullPath: MFT_DB, tableName: "MFT_Records", rowid: 42, field: "si_created" })]);
  const mftRefs = parseSourceRefs(refs([{ fullPath: MFT_DB, tableName: "MFT_Records", rowid: 42 }]));
  const self = { fullPath: "/cases/CASE/host-a/_OVERVIEW/FileSystemEntries.sqlite", tableName: "FileSystemEntries", rowid: 7 };

  assert.equal(isRecordBookmarked(fieldKeys, self, mftRefs, "si_created"), true);
  assert.equal(isRecordBookmarked(fieldKeys, self, mftRefs, "si_modified"), false);
  assert.equal(isRecordBookmarked(fieldKeys, self, mftRefs), false);
});

test("path separator and case differences still identify the same record", () => {
  const keys = bookmarkRefKeys([bookmark({ fullPath: "C:\\cases\\CASE\\host-a\\EVENTLOG\\Security.sqlite" })]);
  assert.equal(keys.has(sourceRefKey("C:/CASES/case/host-a/EVENTLOG/Security.sqlite", "security", 57)), true);
});

test("absent or malformed refs are treated as no refs", () => {
  assert.deepEqual(parseSourceRefs(undefined), []);
  assert.deepEqual(parseSourceRefs(""), []);
  assert.deepEqual(parseSourceRefs("not json"), []);
  assert.deepEqual(parseSourceRefs(JSON.stringify({ fullPath: RAW_DB })), []);
  // An entry without a verified path cannot be a bookmark target.
  assert.deepEqual(parseSourceRefs(refs([{ fullPath: "", tableName: "Security", rowid: 1 }])), []);
  assert.deepEqual(parseSourceRefs(JSON.stringify([{ fullPath: RAW_DB, tableName: "Security", rowid: "x" }])), []);
});
