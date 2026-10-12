import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { executionDisplay, executionSearchValues, executionSource } from "./executionHistory.ts";

// Shapes copied from the real IDC_20261009_104922 ExecutionHistory rows.
const shellCoreStart = {
  event_type: "Shell-Core 9707", event_id: "9707", command_line: "unregmp2.exe /FirstLogon",
  description: "Run 키 명령 처리 시작", account: "Administrator", account_role: "event_subject",
};
const processCreate = {
  event_type: "Security 4688", event_id: "4688", program_name: "autochk.exe", program_path: "C:\\Windows\\System32\\autochk.exe",
  process_id: "0x274", parent_process_id: "0x240", parent_process_path: "C:\\Windows\\System32\\smss.exe",
  description: "새 프로세스 생성", account: "LocalSystem", account_sid: "S-1-5-18", account_role: "creator",
};

test("command-only Shell-Core rows show the raw command and never an inferred program", () => {
  const display = executionDisplay(shellCoreStart, "");
  assert.equal(display.title, "unregmp2.exe /FirstLogon");
  assert.equal(display.titleIsCommand, true);
  assert.equal(display.detail, "");
  assert.equal(display.detailIsPath, false);
});

test("rows with a program keep name and path; commands go to the detail line only when no path exists", () => {
  assert.deepEqual(executionDisplay(processCreate, "autochk.exe"), { title: "autochk.exe", titleIsCommand: false, detail: processCreate.program_path, detailIsPath: true });
  const commandWithName = executionDisplay({ program_name: "a.exe", command_line: "a.exe /x" }, "a.exe");
  assert.deepEqual(commandWithName, { title: "a.exe", titleIsCommand: false, detail: "a.exe /x", detailIsPath: true });
  assert.deepEqual(executionDisplay({ event_type: "Security 4688", description: "새 프로세스 생성" }, ""), { title: "(이름 없음)", titleIsCommand: false, detail: "", detailIsPath: true });
});

test("every EventLog channel is one source, so one toggle hides 4688 and Shell-Core events", () => {
  const rows: Record<string, string>[] = [
    { ...processCreate, event_provider: "Microsoft-Windows-Security-Auditing" },
    { ...shellCoreStart, event_provider: "Microsoft-Windows-Shell-Core" },
    { event_type: "Amcache_Programs" },
    { event_type: "WER" },
  ];
  assert.deepEqual(rows.map(executionSource), ["EventLog", "EventLog", "Amcache", "WER"]);
  const disabled = new Set(["EventLog"]);
  assert.deepEqual(rows.filter((row) => !disabled.has(executionSource(row))).map((row) => row.event_type), ["Amcache_Programs", "WER"]);
});

test("search covers commands, parent paths, resolved paths, hashes and SIDs", () => {
  const values = executionSearchValues({ ...processCreate, sha1: "abc", program_path_resolved: "C:\\R\\x.exe" });
  for (const needle of ["autochk.exe", "smss.exe", "S-1-5-18", "abc", "C:\\R\\x.exe", "LocalSystem", "Security 4688"]) {
    assert.ok(values.some((value: string) => value.includes(needle)), needle);
  }
  assert.ok(executionSearchValues(shellCoreStart).includes("unregmp2.exe /FirstLogon"));
});

test("Windows path exclusion applies to KNOWNFOLDERID paths the list shows as C:\\Windows", async () => {
  // @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
  const { resolveKnownFolderPath } = await import("./knownFolders.ts");
  // @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
  const { isWindowsSystemPath } = await import("./executionHistory.ts");
  // Real UserAssist value from IDC_20261012_112701.
  const userAssist = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\msiexec.exe";
  assert.equal(isWindowsSystemPath(resolveKnownFolderPath(userAssist) ?? userAssist), true);
  assert.equal(isWindowsSystemPath("c:\\windows\\syswow64\\msiexec.exe"), true);
  const programFiles = "{6D809377-6AF0-444B-8957-A3773F02200E}\\TeamViewer\\TeamViewer.exe";
  assert.equal(isWindowsSystemPath(resolveKnownFolderPath(programFiles) ?? programFiles), false);
  assert.equal(isWindowsSystemPath("C:\\Users\\Public\\Desktop\\TeamViewer.lnk"), false);
});
