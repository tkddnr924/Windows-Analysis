import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { OVERVIEW_WAIT, hostProgress, interpretLine, overallPercent } from "./pipelineProgress.ts";

const base = { currentArtifact: null, totalSteps: 18, completedSteps: 0, overviewDone: 0, overviewTotal: 0 };

test("overview progress lines carry done/total", () => {
  assert.deepEqual(interpretLine("[종합 분석 진행] 7/52"), { kind: "overview", done: 7, total: 52 });
  assert.deepEqual(interpretLine("[완료] Registry"), { kind: "done", name: "Registry" });
  assert.deepEqual(interpretLine("[종합 분석 진행] x/52"), { kind: "none" });
});

test("parsing has its own 0-100% bar and no overview bar yet", () => {
  const view = hostProgress({ ...base, currentArtifact: "EventLog · Registry", completedSteps: 9 });
  assert.equal(view.parse.percent, 50);
  assert.equal(view.parse.label, "EventLog · Registry 파싱 중…");
  assert.equal(view.parse.detail, "9 / 18 단계");
  assert.equal(view.overview, null);
});

test("overview phase: parsing reads 100% and overview counts from 0", () => {
  const started = hostProgress({ ...base, currentArtifact: "_OVERVIEW", completedSteps: 18 });
  assert.equal(started.parse.percent, 100);
  assert.equal(started.parse.active, false);
  assert.equal(started.overview?.percent, 0);
  assert.equal(started.overview?.label, "종합 분석 생성 중…");

  const halfway = hostProgress({ ...base, currentArtifact: "_OVERVIEW", completedSteps: 18, overviewDone: 26, overviewTotal: 52 });
  assert.equal(halfway.overview?.percent, 50);
  assert.equal(halfway.overview?.detail, "26 / 52 단계");
  // The last step still runs until the run itself finishes.
  const last = hostProgress({ ...base, currentArtifact: "_OVERVIEW", completedSteps: 18, overviewDone: 52, overviewTotal: 52 });
  assert.equal(last.overview?.percent, 99);
});

test("waiting for an overview slot shows an idle overview bar", () => {
  const view = hostProgress({ ...base, currentArtifact: OVERVIEW_WAIT, completedSteps: 17 });
  assert.equal(view.parse.percent, 100);
  assert.equal(view.overview?.label, "종합 분석 대기 중…");
  assert.equal(view.overview?.detail, "다른 호스트의 종합 분석이 끝나면 시작");
  assert.equal(view.overview?.percent, 0);
});

test("the single global bar combines parsing and overview", () => {
  assert.equal(overallPercent({ ...base, completedSteps: 9 }), 25);
  assert.equal(overallPercent({ ...base, currentArtifact: "_OVERVIEW", completedSteps: 18, overviewDone: 26, overviewTotal: 52 }), 75);
  assert.equal(overallPercent({ ...base, totalSteps: 0 }), 0);
});
