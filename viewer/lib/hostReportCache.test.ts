import assert from "node:assert/strict";
import test from "node:test";
// Node's strip-types runner intentionally needs explicit extensions.
// @ts-expect-error app bundling resolves the extensionless import separately.
import { selectVisibleHostReport, shouldLoadHostReport } from "./hostReportCache.ts";

test("a completed published host reloads instead of retaining an older unpublished manifest", () => {
  const priorUnpublished = {
    hostRunAt: "2026-08-23 22:58:39.000",
    report: { runId: "old", published: false },
  };
  assert.equal(
    shouldLoadHostReport(priorUnpublished, "2026-08-23 23:07:50.232", false, priorUnpublished.report.runId, "new"),
    true,
  );
  assert.equal(
    shouldLoadHostReport(
      { hostRunAt: "2026-08-23 23:07:50.232", report: { runId: "new", published: true } },
      "2026-08-23 23:07:50.232",
      false,
      "new",
      "new",
    ),
    false,
  );
});

test("an active host never fetches a prior terminal manifest", () => {
  assert.equal(shouldLoadHostReport(undefined, "2026-08-23 23:07:50.232", true, undefined, "new"), false);
});

test("a stale manifest is never displayable while the new published run synchronizes", () => {
  const stale = {
    hostRunAt: "2026-08-23 22:58:39.000",
    report: { runId: "old", published: false },
  };
  assert.equal(
    selectVisibleHostReport(stale, "2026-08-23 23:07:50.232", false, "new"),
    null,
  );
  assert.deepEqual(
    selectVisibleHostReport(
      { hostRunAt: "2026-08-23 23:07:50.232", report: { runId: "new", published: true } },
      "2026-08-23 23:07:50.232",
      false,
      "new",
    ),
    { runId: "new", published: true },
  );
});
