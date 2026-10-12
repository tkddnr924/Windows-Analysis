import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { acbFlagNames, yesNo } from "./accountFields.ts";

test("stored 0/1 account flags map to 예/아니오 and unknown stays empty", () => {
  assert.equal(yesNo("1"), "예");
  assert.equal(yesNo("0"), "아니오");
  assert.equal(yesNo(null), "");
  assert.equal(yesNo(undefined), "");
});

test("ACB flag names come from details_json; malformed or missing details fall back to empty", () => {
  // Shapes from the real IDC_20261012_142320 Administrator/Guest rows.
  assert.equal(acbFlagNames('{"acb_flags":["Normal","PwNoExpire"],"acb":528}'), "Normal, PwNoExpire");
  assert.equal(acbFlagNames('{"acb_flags":["Disabled","PwNotRequired","Normal","PwNoExpire"]}'), "Disabled, PwNotRequired, Normal, PwNoExpire");
  assert.equal(acbFlagNames('{"acb":528}'), "");
  assert.equal(acbFlagNames("not json"), "");
  assert.equal(acbFlagNames(null), "");
});
