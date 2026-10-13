import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { chronological } from "./eventOrder.ts";

type Row = Record<string, string>;
const ev = (record_id: string, timestamp: string, section: string): Row => ({ record_id, timestamp, section });

test("chronological ignores display direction for representative picks", () => {
  const asc = [ev("1", "2026-01-01 00:00:00", "threat"), ev("2", "2026-01-01 00:01:00", "threat_action"), ev("3", "2026-01-01 00:02:00", "threat_action"), ev("4", "", "threat_action")];
  const desc = [asc[2], asc[1], asc[0], asc[3]];
  for (const events of [asc, desc]) {
    const ordered: Row[] = chronological(events);
    assert.deepEqual(ordered.map((row) => row.record_id), ["1", "2", "3", "4"]);
    assert.equal(ordered.filter((row) => row.timestamp).reverse().find((row) => row.section === "threat_action")?.record_id, "3");
  }
  assert.deepEqual(desc.map((row) => row.record_id), ["3", "2", "1", "4"]);
});
