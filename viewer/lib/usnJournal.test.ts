import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { ambiguityLabels, candidateSides, groupHeadline, matchedCount, reasonFlags, renameStatusLabel } from "./usnJournal.ts";

type Cells = Record<string, string>;
const rename = (event: Cells, candidates: Cells[] = []) => ({ event, candidates });
const entry = (group: Cells, renames: ReturnType<typeof rename>[] = [], members: Cells[] = []) => ({ group, renames, members });

test("headline prefers the stored rename pair, then the name change, then the last name", () => {
  assert.equal(groupHeadline(entry({ first_file_name: "a", last_file_name: "b", distinct_file_name_count: "2" }, [rename({ old_file_name: "old.doc", new_file_name: "new.doc" })])), "old.doc → new.doc");
  assert.equal(groupHeadline(entry({}, [rename({ old_file_name: "", new_file_name: "new.doc", status: "missing_old" })])), "? → new.doc");
  assert.equal(groupHeadline(entry({ first_file_name: "a.tmp", last_file_name: "b.txt", distinct_file_name_count: "2" })), "a.tmp → b.txt");
  assert.equal(groupHeadline(entry({ first_file_name: "x.log", last_file_name: "x.log", distinct_file_name_count: "1" })), "x.log");
  assert.equal(groupHeadline(entry({})), "(이름 없음)");
});

test("an ambiguous rename with several OLD names shows the count instead of picking one", () => {
  const ambiguous = rename({ status: "ambiguous", new_file_name: "b.txt" }, [{ role: "old", file_name: "a1.txt" }, { role: "old", file_name: "a2.txt" }, { role: "new", file_name: "b.txt" }]);
  assert.equal(groupHeadline(entry({}, [ambiguous])), "이전 이름 후보 2개 → b.txt");
});

test("candidates split by role (both counts on each side); the stored representative is marked", () => {
  const sides = candidateSides(rename({ old_record_id: "r1", new_record_id: "r3" }, [
    { record_id: "r1", role: "old" }, { record_id: "r2", role: "both" }, { record_id: "r3", role: "new" },
  ]));
  assert.deepEqual(sides.old.map((c) => [c.candidate.record_id, c.representative]), [["r1", true], ["r2", false]]);
  assert.deepEqual(sides.new.map((c) => [c.candidate.record_id, c.representative]), [["r2", false], ["r3", true]]);
});

test("stored statuses and ambiguity reasons get labels; unknown values stay verbatim", () => {
  assert.equal(renameStatusLabel("paired"), "짝 확인");
  assert.equal(renameStatusLabel("ambiguous"), "모호");
  assert.equal(renameStatusLabel("new_status"), "new_status");
  assert.deepEqual(ambiguityLabels("multiple_old_names,multiple_old_parents|future_reason"), ["이전 이름이 여러 개", "이전 이름의 부모 참조가 서로 다름", "future_reason"]);
  assert.deepEqual(ambiguityLabels(undefined), []);
});

test("reason text splits on | without empty flags; matches are counted from members", () => {
  assert.deepEqual(reasonFlags("FILE_CREATE|DATA_EXTEND||CLOSE"), ["FILE_CREATE", "DATA_EXTEND", "CLOSE"]);
  assert.deepEqual(reasonFlags(undefined), []);
  assert.equal(matchedCount(entry({}, [], [{ __matched: "true" }, { __matched: "false" }, {}])), 1);
});
