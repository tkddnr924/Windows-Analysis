import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_TASK_FILTER, filterTasks, isParseProblem, splitByTime, taskAccountKey, taskCounts } from "./scheduledTasks.ts";

type Row = Record<string, string>;
const def = (record_id: string, extra: Row = {}): Row => ({ record_id, event_type: "작업 정의", task_name: record_id, is_microsoft: "1", parse_status: "parsed", timestamp: "", ...extra });
const always = () => true;
const ids = (rows: Row[]) => rows.map((row) => row.record_id);

test("search uses the stored search_text plus account and SID; no per-page child lookups", () => {
  const rows = [
    def("a", { search_text: "updater %windir%\\system32\\rundll32.exe evil.dll,run timetrigger" }),
    def("b", { account: "LocalSystem", account_sid: "S-1-5-18" }),
    def("c", { task_description: "nothing" }),
  ];
  const find = (search: string) => ids(filterTasks(rows, { ...DEFAULT_TASK_FILTER, search }, always, false));
  assert.deepEqual(find("RUNDLL32"), ["a"]);
  assert.deepEqual(find("timetrigger"), ["a"]);
  assert.deepEqual(find("s-1-5-18"), ["b"]);
  assert.deepEqual(find("localsystem"), ["b"]);
});

test("review, hidden, non-Microsoft and parse-problem views follow stored columns; counts agree with filters", () => {
  const rows = [
    def("a", { review_signal_count: "2", review_signals: "script_host_command, hidden_declared", hidden: "1" }),
    def("b", { is_microsoft: "0" }),
    def("c", { parse_status: "partial", parse_error: "0x40: truncated" }),
    def("d", { enabled: "0" }),
    { record_id: "e", event_type: "작업 스케줄러 이벤트", parse_status: "ok", timestamp: "2026-01-01 00:00:00.000", is_microsoft: "" },
  ];
  const view = (show: string) => ids(filterTasks(rows, { ...DEFAULT_TASK_FILTER, show }, always, false));
  assert.deepEqual(view("review"), ["a"]);
  assert.deepEqual(view("hidden"), ["a"]);
  // Events carry no Microsoft classification: not counted as non-Microsoft.
  assert.deepEqual(view("user"), ["b"]);
  assert.deepEqual(view("parse"), ["c"]);
  assert.equal(isParseProblem({ parse_status: "ok" }), false);
  assert.equal(isParseProblem({ parse_status: "parse_failed" }), true);
  const counts = taskCounts(rows);
  assert.deepEqual([counts.review, counts.hidden, counts.user, counts.parse, counts.enabled, counts.disabled], [1, 1, 1, 1, 0, 1]);
  assert.deepEqual(ids(filterTasks(rows, { ...DEFAULT_TASK_FILTER, kinds: ["작업 스케줄러 이벤트"] }, always, false)), ["e"]);
  assert.deepEqual(ids(filterTasks(rows, { ...DEFAULT_TASK_FILTER, state: "disabled" }, always, false)), ["d"]);
});

test("account filter keys on the stored SID first; untimed rows split off and drop out under a period", () => {
  const rows = [
    def("t2", { timestamp: "2026-01-02 00:00:00.000", run_as_sid: "S-1-5-18", run_as: "SYSTEM" }),
    def("t1", { timestamp: "2026-01-01 00:00:00.000", run_as: "alice" }),
    def("t0", { timestamp: "2026-01-01 00:00:00.000", account_sid: "S-1-5-21-9", run_as: "alice" }),
    def("u", {}),
  ];
  assert.equal(taskAccountKey(rows[0]), "S-1-5-18");
  assert.equal(taskAccountKey(rows[1]), "alice");
  assert.deepEqual(ids(filterTasks(rows, { ...DEFAULT_TASK_FILTER, accounts: ["S-1-5-18"] }, always, false)), ["t2"]);
  const all = filterTasks(rows, DEFAULT_TASK_FILTER, always, false);
  const { timed, untimed } = splitByTime(all, "asc");
  // Same time → record_id order.
  assert.deepEqual(ids(timed), ["t0", "t1", "t2"]);
  assert.deepEqual(ids(untimed), ["u"]);
  assert.deepEqual(ids(splitByTime(all, "desc").timed), ["t2", "t0", "t1"]);
  assert.deepEqual(ids(filterTasks(rows, DEFAULT_TASK_FILTER, always, true)), ["t2", "t1", "t0"]);
});

test("list command line prefers the stored resolved command (docs-24), raw kept for hover", () => {
  // @ts-expect-error -- Node test import
  return import("./scheduledTasks.ts").then(({ resolvedActionSummaries }) => {
    const map = resolvedActionSummaries([
      { record_id: "a", ordinal: "1", command: "%windir%\\b.exe", command_resolved: "C:\\Windows\\b.exe", arguments: "" },
      { record_id: "a", ordinal: "0", command: "%SystemRoot%\\system32\\clipesu.exe", command_resolved: "C:\\Windows\\system32\\clipesu.exe", arguments: "-e" },
      { record_id: "c", ordinal: "0", command: "", class_id: "{AE31}" },
      { record_id: "d", ordinal: "0", command: "%ProgramData%\\x.exe", command_resolved: "", arguments: "/q" },
    ]);
    assert.deepEqual(map.get("a"), { text: "C:\\Windows\\system32\\clipesu.exe -e · C:\\Windows\\b.exe", raw: "%SystemRoot%\\system32\\clipesu.exe -e · %windir%\\b.exe" });
    assert.deepEqual(map.get("c"), { text: "COM:{AE31}", raw: "COM:{AE31}" });
    // No stored resolution → raw stays (no guessing).
    assert.deepEqual(map.get("d"), { text: "%ProgramData%\\x.exe /q", raw: "%ProgramData%\\x.exe /q" });
  });
});
