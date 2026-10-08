import assert from "node:assert/strict";
import test from "node:test";
// Node's strip-types runner intentionally needs explicit extensions.
// @ts-expect-error app bundling resolves the extensionless import separately.
import { allParseBlocked, canStartParse } from "./parseEligibility.ts";

test("parse runs only after the backend confirms newly added data", () => {
  assert.equal(canStartParse({ status: "ready", canParse: true, reason: "" }), true);
  assert.equal(canStartParse({ status: "ready", canParse: false, reason: "새 수집 파일이 없습니다." }), false);
});

test("an unchecked, in-flight, or failed check never enables the parse button", () => {
  assert.equal(canStartParse(undefined), false);
  assert.equal(canStartParse({ status: "checking" }), false);
  assert.equal(canStartParse({ status: "error", message: "확인 실패" }), false);
});

test("전체 파싱 is blocked only when every host is confirmed unchanged", () => {
  const unchanged = { status: "ready", canParse: false, reason: "변경 없음" } as const;
  assert.equal(allParseBlocked([], {}), true);
  assert.equal(allParseBlocked(["a", "b"], { a: unchanged, b: unchanged }), true);
  assert.equal(allParseBlocked(["a", "b"], { a: unchanged, b: { status: "ready", canParse: true, reason: "" } }), false);
  assert.equal(allParseBlocked(["a", "b"], { a: unchanged }), false);
  assert.equal(allParseBlocked(["a", "b"], { a: unchanged, b: { status: "checking" } }), false);
});
