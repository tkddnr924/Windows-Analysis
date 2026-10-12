import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { groupBySessionId, toPsEvent } from "./powershellSessions.ts";

const row = (rowid: number, timestamp: string, extra: Record<string, string>) =>
  toPsEvent({ __rowid: String(rowid), timestamp, process_id: "100", ...extra });

test("records sharing a Host ID form one session even across long gaps", () => {
  const sessions = groupBySessionId([
    row(1, "2026-01-01 10:00:00.000", { session_id: "host-a", event_type: "엔진 시작" }),
    row(2, "2026-01-01 15:00:00.000", { session_id: "host-a", event_type: "엔진 종료" }),
  ]);
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].sessionId, "host-a");
  assert.equal(sessions[0].end, "2026-01-01 15:00:00.000");
});

test("same PID and close time never merge records without a Host ID", () => {
  const sessions = groupBySessionId([
    row(3, "2026-01-01 10:00:01.000", { event_type: "스크립트 블록" }),
    row(4, "2026-01-01 10:00:02.000", { event_type: "스크립트 블록" }),
    row(5, "2026-01-01 10:00:00.000", { session_id: "host-b", event_type: "엔진 시작" }),
  ]);
  assert.deepEqual(sessions.map((s: { key: string }) => s.key), ["host:host-b", "row:3", "row:4"]);
  assert.equal(sessions[1].sessionId, null);
});

test("different Host IDs stay apart even with the same PID", () => {
  const sessions = groupBySessionId([
    row(6, "2026-01-01 10:00:00.000", { session_id: "host-c" }),
    row(7, "2026-01-01 10:00:01.000", { session_id: "host-d" }),
  ]);
  assert.equal(sessions.length, 2);
});
