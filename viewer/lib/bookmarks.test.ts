import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { bookmarkRecordKey, bookmarkRecordKeys } from "./bookmarks.ts";

test("a field bookmark on any field marks its record", () => {
  const keys = bookmarkRecordKeys([
    { tableName: "TargetInfo", recordId: "a", field: "home_directory" },
    { tableName: "TargetInfo", recordId: "b" },
    { tableName: "Metadata", recordId: "c", field: "created" },
  ]);
  assert.ok(keys.has(bookmarkRecordKey("TargetInfo", "a")));
  assert.ok(keys.has(bookmarkRecordKey("TargetInfo", "b")));
  assert.ok(!keys.has(bookmarkRecordKey("TargetInfo", "c")));
});
