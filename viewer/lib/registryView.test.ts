import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { QUICK_GROUPS, QUICK_SECTIONS, applyValueChunk, emptyValueChunks, filetimeToKst, formatRegistryValue, hiveGroups, hiveLabel, isNavigable, quickGroupOf, resolutionLabel, typeLabel } from "./registryView.ts";

const value = (cells: Record<string, string>) => ({ value_read_status: "ok", value_data_length: "4", ...cells });

test("numbers show hex and decimal; FILETIME converts to KST and keeps the raw count", () => {
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_DWORD", value_preview: "1033" })).primary, "0x00000409 (1033)");
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_QWORD", value_preview: "18446744073709551615", value_data_length: "8" })).primary, "0xFFFFFFFFFFFFFFFF (18446744073709551615)");
  assert.equal(filetimeToKst("134146637996496353"), "2026-02-04 16:29:59.649");
  assert.equal(filetimeToKst("0"), null, "0 is no time, not 1601");
  const ft = formatRegistryValue(value({ value_type_name: "REG_FILETIME", value_preview: "134146637996496353", value_data_length: "8" }));
  assert.deepEqual([ft.kind, ft.primary, ft.secondary], ["time", "2026-02-04 16:29:59.649", "134146637996496353"]);
});

test("strings, multi-strings, binary, empty and failed reads stay distinct", () => {
  assert.deepEqual(formatRegistryValue(value({ value_type_name: "REG_MULTI_SZ", value_preview: "[\"ko\",\"en-US\"]" })).lines, ["ko", "en-US"]);
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_EXPAND_SZ", value_preview: "%SystemRoot%\\x.dll" })).primary, "%SystemRoot%\\x.dll");
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_BINARY", value_hex_preview: "4d5a9000" })).primary, "4D 5A 90 00");
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_NONE", value_read_status: "empty", value_data_length: "0" })).kind, "empty");
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_SZ", value_read_status: "error", value_read_error: "cell" })).kind, "error");
  // A string that is stored as empty text but has bytes is not "empty".
  assert.equal(formatRegistryValue(value({ value_type_name: "REG_SZ", value_preview: "", value_hex_preview: "0000", value_data_length: "2" })).kind, "text");
});

test("unknown type codes show as hex, known names stay", () => {
  assert.equal(typeLabel("4294901778"), "0xFFFF0012");
  assert.equal(typeLabel("REG_SZ"), "REG_SZ");
  assert.equal(typeLabel(undefined), "—");
});

test("quick access: settings (autorun, security, remote) apart from records; anything unmapped stays under 기타", () => {
  const group = (category: string, subtype = "") => quickGroupOf({ category, subtype });
  assert.equal(group("자격 증명 보호"), "security");
  assert.equal(group("보안 설정", "PowerShell"), "security");
  assert.equal(group("공유 폴더"), "remote");
  assert.equal(group("SQL 인증"), "remote");
  assert.equal(group("원격 접속", "RMM"), "remote");
  assert.equal(group("자동 실행", "TaskCache"), "autorun");
  assert.equal(group("기타 레지스트리", "ShimCache"), "shimcache");
  assert.equal(group("기타 레지스트리", "RunMRU"), "activity");
  assert.equal(group("설치 프로그램 (MSI)", "MsiInstall"), "install");
  assert.equal(group("기타 레지스트리", "PendingFileRename"), "other");
  const sectionOf = (key: string) => QUICK_GROUPS.find((g: { key: string }) => g.key === key)?.section;
  assert.deepEqual(["autorun", "security", "remote"].map(sectionOf), ["settings", "settings", "settings"]);
  assert.deepEqual(["activity", "install", "shimcache", "other"].map(sectionOf), ["records", "records", "records", "records"]);
  assert.deepEqual(QUICK_SECTIONS.map((s: { key: string }) => s.key), ["settings", "records"]);
  assert.deepEqual(QUICK_GROUPS.map((g: { key: string }) => g.key).slice(-1), ["other"]);
});

test("archive history: Bandizip recent archives and RecentDocs of archive types; other RecentDocs stay in 사용자 활동", () => {
  const recentDocs = (ext: string) => quickGroupOf({ category: "기타 레지스트리", subtype: "RecentDocs", key_path: `\\ROOT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\${ext}` });
  assert.equal(quickGroupOf({ category: "기타 레지스트리", subtype: "BandizipRecentArchive" }), "archive");
  assert.equal(recentDocs(".zip"), "archive");
  assert.equal(recentDocs(".7Z"), "archive");
  assert.equal(recentDocs(".txt"), "activity");
  assert.equal(recentDocs("Folder"), "activity");
  assert.equal(QUICK_GROUPS.find((g: { key: string }) => g.key === "archive")?.section, "records");
});

test("a chunk answers only the value and position it was asked for", () => {
  const a = { ...emptyValueChunks("A"), loading: true };
  const fromA = { recordId: "A", field: "hex" as const, extraLength: 0 };
  const first = applyValueChunk(a, fromA, "AABB");
  assert.deepEqual([first.hex, first.loading], ["AABB", false]);
  // A's late answer after B is selected leaves B untouched.
  const b = emptyValueChunks("B");
  assert.equal(applyValueChunk(b, fromA, "AABB"), b);
  // A repeated answer for an old position is dropped too.
  assert.equal(applyValueChunk(first, fromA, "AABB"), first);
  const text = applyValueChunk({ ...first, loading: true }, { recordId: "A", field: "text", extraLength: 0 }, "xy");
  assert.deepEqual([text.hex, text.text], ["AABB", "xy"]);
});

test("only stored targets that point at a key or value navigate", () => {
  assert.equal(isNavigable("exact_value"), true);
  assert.equal(isNavigable("ancestor_key"), true);
  assert.equal(isNavigable("missing_hive"), false);
  assert.equal(resolutionLabel("parent_key"), "상위 키");
  assert.equal(resolutionLabel("something_new"), "something_new");
});

test("hives group into system, user, other and RegBack in stored order", () => {
  const hive = (hiveId: string, hiveName: string, isRegback = false) => ({ hiveId, hiveName, isRegback, ordinal: 0 });
  const groups = hiveGroups([hive("a", "Amcache.hve"), hive("b", "SOFTWARE"), hive("c", "Administrator_NTUSER.DAT"), hive("d", "SOFTWARE", true), hive("e", "SYSTEM")]);
  assert.deepEqual(groups.map((g) => [g.title, g.hives.map((h) => h.hiveId)]), [["시스템", ["b", "e"]], ["사용자", ["c"]], ["기타", ["a"]], ["RegBack", ["d"]]]);
  assert.deepEqual(hiveLabel("Administrator_NTUSER.DAT"), { name: "NTUSER.DAT", owner: "Administrator" });
  assert.deepEqual(hiveLabel(".NET v4.5 Classic_UsrClass.dat"), { name: "UsrClass.dat", owner: ".NET v4.5 Classic" });
  assert.deepEqual(hiveLabel("SOFTWARE"), { name: "SOFTWARE", owner: null });
});
