import assert from "node:assert/strict";
import test from "node:test";
// Node's strip-types runner intentionally needs explicit extensions. The app
// import remains extensionless for Next/Tauri bundling.
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { accountDirectoryFromEntries, isExactSid, resolveAccountDisplay } from "./accountIdentity.ts";

test("exact SID resolution preserves unmapped and non-SID evidence values", () => {
  const directory = accountDirectoryFromEntries([
    { sid: "S-1-5-21-1-2-3-1001", accountName: "alice", sourceArtifact: "SAM" },
  ]);
  assert.equal(resolveAccountDisplay("S-1-5-21-1-2-3-1001", directory), "alice");
  assert.equal(resolveAccountDisplay("S-1-5-21-1-2-3-9999", directory), "S-1-5-21-1-2-3-9999");
  assert.equal(resolveAccountDisplay("DOMAIN\\alice", directory), "DOMAIN\\alice");
  assert.equal(resolveAccountDisplay('{"UserSid":"S-1-5-21-1-2-3-1001"}', directory), '{"UserSid":"S-1-5-21-1-2-3-1001"}');
  assert.equal(isExactSid("S-1-5-18"), true);
  assert.equal(isExactSid("S-1-5-user"), false);
});
