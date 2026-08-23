import assert from "node:assert/strict";
import test from "node:test";
// Node's built-in TypeScript runner requires an explicit local extension;
// Next's bundler resolves the application import without one.
// @ts-expect-error node --experimental-strip-types test entry
import { searchHitHostMatchesSourceBookmark } from "./searchBookmark.ts";
import type { Bookmark, Host, SearchHit } from "./types.ts";

const host = (id: string, dir: string): Host => ({
  id,
  name: id,
  targetDir: dir,
  dir,
  createdAt: "",
  lastRunAt: null,
  lastRunStatus: null,
  artifactsRun: [],
});

const hit: SearchHit = {
  hostId: "host-a",
  hostName: "host-a",
  fileName: "Overview",
  tableName: "Overview",
  fullPath: "/cases/CASE/host-a/_OVERVIEW/Overview.sqlite",
  rowid: 1,
  matchColumn: "value",
  matchValue: "needle",
  timestamp: "",
  recordKey: "Raw::Records::1",
};

const legacyBookmark = (fullPath: string): Bookmark => ({
  id: "legacy",
  fullPath,
  tableName: "Records",
  rowid: 1,
  note: "",
  taggedAt: "",
});

test("legacy source bookmark cannot match another host with a shared path prefix", () => {
  const hosts = [host("host-a", "/cases/CASE/host-a"), host("host-b", "/cases/CASE/host-a-copy")];
  assert.equal(
    searchHitHostMatchesSourceBookmark(hit, legacyBookmark("/cases/CASE/host-a-copy/RAW/Records.sqlite"), hosts),
    false,
  );
  assert.equal(
    searchHitHostMatchesSourceBookmark(hit, legacyBookmark("/cases/CASE/host-a/RAW/Records.sqlite"), hosts),
    true,
  );
});
