import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { attachmentsByMessage, bodyKind, browserScopes, downloadStateLabel, messageThread, transitionLabel } from "./browserView.ts";

const input = (inputId: string, browser: string, profile: string, label: string, kind: string, count: number, account: string | null = label) =>
  ({ inputId, inputKind: kind, browser, profile, accountLabel: label, account, accountSid: account ? `sid-${account}` : null, sourceFile: null, recordCount: count });

test("history and cache inputs of one browser profile form one scope; labels never merge different profiles", () => {
  const scopes = browserScopes([
    input("a", "Chrome", "Default", "alice", "history", 10),
    input("b", "Chrome", "Default", "alice", "cache", 5),
    input("c", "Chrome", "Profile 1", "alice", "history", 2),
    input("d", "Edge", "Default", "bob", "history", 1, null),
  ]);
  assert.deepEqual(scopes.map((scope: { inputIds: string[]; recordCount: number }) => [scope.inputIds, scope.recordCount]), [[["a", "b"], 15], [["c"], 2], [["d"], 1]]);
  assert.equal(scopes[0].label, "Chrome · Default");
  assert.equal(scopes[0].owner, "alice");
  // An unconfirmed account stays empty instead of reusing the collected label.
  assert.equal(scopes[2].account, null);
});

test("stored transition names and qualifiers read as labels; unknown names stay raw", () => {
  assert.equal(transitionLabel("TYPED", "FROM_ADDRESS_BAR,CHAIN_END"), "주소창 직접 입력 · 주소창, 체인 끝");
  assert.equal(transitionLabel("LINK", ""), "링크 클릭");
  assert.equal(transitionLabel("NEW_CORE", "NEW_FLAG"), "NEW_CORE · NEW_FLAG");
  assert.equal(transitionLabel("", ""), "");
});

test("download states follow Chromium DownloadState; others stay as stored", () => {
  assert.equal(downloadStateLabel("1"), "완료");
  assert.equal(downloadStateLabel("4"), "중단");
  assert.equal(downloadStateLabel("3"), "3");
  assert.equal(downloadStateLabel(""), "");
});

const message = (ordinal: number, current: string | null, branch: string | null = null) => ({ ordinal: String(ordinal), on_current_branch: current ?? undefined, branch_ordinal: branch ?? undefined, content: `m${ordinal}` });

test("current branch keeps branch order; other branches stay visible in the full view", () => {
  const messages = [message(0, "1", "0"), message(1, "0"), message(2, "1", "2"), message(3, "1", "1")];
  assert.deepEqual(messageThread(messages, "current").map((m: { content: string }) => m.content), ["m0", "m3", "m2"]);
  const all = messageThread(messages, "all");
  assert.deepEqual(all.map((m: { content: string; offBranch: boolean }) => [m.content, m.offBranch]), [["m0", false], ["m1", true], ["m2", false], ["m3", false]]);
  // Without branch evidence every message is shown in stored order.
  assert.deepEqual(messageThread([message(1, null), message(0, null)], "current").map((m: { content: string }) => m.content), ["m0", "m1"]);
});

test("attachments group by their message; unlinked ones stay separate", () => {
  const groups = attachmentsByMessage([{ message_ordinal: "0", file_name: "a" }, { file_name: "b" }, { message_ordinal: "0", file_name: "c" }]);
  assert.deepEqual(groups.get("0")?.map((a: { file_name: string }) => a.file_name), ["a", "c"]);
  assert.deepEqual(groups.get("")?.map((a: { file_name: string }) => a.file_name), ["b"]);
});

test("cache body kind: declared images and text types, then strict UTF-8 text, else binary", () => {
  const utf8 = new TextEncoder();
  assert.equal(bodyKind(new Uint8Array([0x89, 0x50]), "image/png"), "image");
  assert.equal(bodyKind(utf8.encode("{}"), "application/json; charset=utf-8"), "text");
  assert.equal(bodyKind(utf8.encode("한글 본문"), ""), "text");
  assert.equal(bodyKind(new Uint8Array([0x66, 0x00, 0x67]), ""), "binary");
  assert.equal(bodyKind(new Uint8Array([0xff, 0xfe, 0x41]), ""), "binary");
});
