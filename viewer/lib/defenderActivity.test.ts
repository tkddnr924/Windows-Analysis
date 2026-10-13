import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_DEFENDER_FILTER, buildDefenderItems, groupIndex, latestProtection, selectedSections, summarizeActivity } from "./defenderActivity.ts";

type Row = Record<string, string>;
const ev = (record_id: string, section: string, timestamp: string, extra: Row = {}): Row => ({ record_id, section, section_label: section, timestamp, event_type: section, ...extra });
const always = () => true;
const keys = (items: { key: string }[]) => items.map((item) => item.key);

const rows = [
  ev("d1", "threat", "2026-09-08 01:49:40.218", { threat_name: "Exploit:X", severity: "심각", result: "unknown", search_text: "Exploit:X TmpE40D.tmp" }),
  ev("d2", "threat", "2026-09-08 01:49:41.000", { threat_name: "Exploit:X", severity: "심각", result: "unknown" }),
  ev("a1", "threat_action", "2026-09-08 01:49:54.328", { threat_name: "Exploit:X", result: "success" }),
  // Same threat name and time but no stored detection membership: stays alone (R04).
  ev("lone", "threat", "2026-09-08 01:49:40.218", { threat_name: "Exploit:X", severity: "심각" }),
  ev("s1", "scan", "2026-08-23 07:34:59.759", { event_type: "scan_started" }),
  ev("s2", "scan", "2026-08-23 07:36:44.364", { event_type: "scan_completed", result: "success" }),
  ev("h1", "health", "2026-08-23 00:45:13.838"),
  ev("c1", "tampering", "", { event_type: "configuration_changed" }),
];
const index = groupIndex(
  [{ detection_key: "D", record_id: "d1" }, { detection_key: "D", record_id: "d2" }, { detection_key: "D", record_id: "a1" }],
  [{ scan_entry_id: "S", start_record_id: "s1", completion_record_id: "s2", cancel_record_id: "", error_record_id: "" }],
);

test("stored detection/scan groups become one item; unlinked rows stay single; default shows detections only; untimed last", () => {
  assert.deepEqual(keys(buildDefenderItems(rows, index, DEFAULT_DEFENDER_FILTER, always, false, "asc")), ["D", "record::lone"]);
  const items = buildDefenderItems(rows, index, { ...DEFAULT_DEFENDER_FILTER, sections: ["threat", "threat_action", "scan", "tampering"] }, always, false, "asc");
  assert.deepEqual(keys(items), ["S", "D", "record::lone", "record::c1"]);
  const detection = items[1];
  assert.equal(detection.key, "D");
  assert.equal(detection.kind, "detection");
  assert.deepEqual(detection.events.map((row: Row) => row.record_id), ["d1", "d2", "a1"]);
  assert.equal(items[0].kind, "scan");
  const withHealth = buildDefenderItems(rows, index, { ...DEFAULT_DEFENDER_FILTER, sections: ["health"] }, always, false, "asc");
  assert.deepEqual(keys(withHealth), ["record::h1"]);
});

test("filters keep the whole group with match counts; search uses search_text", () => {
  const success = buildDefenderItems(rows, index, { ...DEFAULT_DEFENDER_FILTER, sections: [], results: ["success"] }, always, false, "desc");
  assert.deepEqual(keys(success), ["D", "S"]);
  assert.deepEqual([...success[0].matched], ["a1"]);
  assert.equal(success[0].events.length, 3);
  const searched = buildDefenderItems(rows, index, { ...DEFAULT_DEFENDER_FILTER, search: "tmpe40d" }, always, false, "asc");
  assert.deepEqual(keys(searched), ["D"]);
});

test("period excludes outside and untimed rows; sections default to detections and actions", () => {
  const inSeptember = (timestamp: string) => timestamp >= "2026-09-01";
  assert.deepEqual(keys(buildDefenderItems(rows, index, DEFAULT_DEFENDER_FILTER, inSeptember, true, "asc")), ["D", "record::lone"]);
  assert.deepEqual(selectedSections(DEFAULT_DEFENDER_FILTER, ["health", "scan", "threat", "threat_action"]), ["threat", "threat_action"]);
  assert.deepEqual(selectedSections({ ...DEFAULT_DEFENDER_FILTER, sections: ["health"] }, ["health", "scan"]), ["health"]);
  assert.deepEqual(selectedSections({ ...DEFAULT_DEFENDER_FILTER, sections: [] }, ["health", "scan"]), ["health", "scan"]);
});

test("latest protection per feature inside the period; same-time conflicts are not decided", () => {
  const states = [
    { feature: "realtime_protection", state: "on", timestamp: "2026-08-14 00:00:00.000", record_id: "x1" },
    { feature: "realtime_protection", state: "off", timestamp: "2026-09-28 00:00:00.000", record_id: "x2" },
    { feature: "ioav", state: "on", timestamp: "2026-09-01 00:00:00.000", record_id: "y1" },
    { feature: "ioav", state: "off", timestamp: "2026-09-01 00:00:00.000", record_id: "y2" },
    { feature: "behavior_monitoring", state: "unknown", timestamp: "2026-09-01 00:00:00.000", record_id: "z1" },
  ];
  const all = latestProtection(states, always);
  assert.deepEqual(all.map((entry: { feature: string; state: string | null }) => [entry.feature, entry.state]), [["realtime_protection", "off"], ["ioav", null]]);
  assert.equal(all[1].tie, 2);
  assert.equal(all[0].count, 2);
  const august = latestProtection(states, (timestamp: string) => timestamp < "2026-09-01");
  assert.deepEqual(august.map((entry: { feature: string; state: string | null }) => [entry.feature, entry.state]), [["realtime_protection", "on"]]);
  // Same-time equal states: the stored Rust order (observation_ordinal) picks
  // the latest record, not the order rows happened to be read in.
  const tied = latestProtection([
    { feature: "ioav", state: "on", timestamp: "2026-09-02 00:00:00.000", record_id: "late", observation_ordinal: "1" },
    { feature: "ioav", state: "on", timestamp: "2026-09-02 00:00:00.000", record_id: "early", observation_ordinal: "0" },
  ], always);
  assert.equal(tied[0].recordId, "late");
});

test("activity summary counts within the period", () => {
  const summaryRows = [
    ev("s1", "scan", "2026-09-01 00:00:00.000", { event_type: "scan_started" }),
    ev("s2", "scan", "2026-09-01 00:01:00.000", { event_type: "scan_completed" }),
    ev("s3", "scan", "2026-09-02 00:00:00.000", { event_type: "scan_cancelled" }),
    ev("g1", "signature", "2026-09-01 00:00:00.000", { event_type: "signature_updated", signature_version_current: "1.1" }),
    ev("g2", "signature", "2026-09-03 00:00:00.000", { event_type: "signature_updated", signature_version_current: "1.2" }),
    ev("g3", "signature", "2026-09-04 00:00:00.000", { event_type: "signature_update_failed", result: "failure" }),
    ev("h1", "history", "2026-09-05 00:00:00.000"),
    ev("c1", "tampering", "2026-09-06 00:00:00.000", { event_type: "configuration_changed", config_change_kind: "added", config_exclusion_kind: "Paths" }),
    ev("c2", "tampering", "2026-09-07 00:00:00.000", { event_type: "configuration_changed", config_change_kind: "removed", config_exclusion_kind: "Paths" }),
    ev("c3", "tampering", "2026-09-08 00:00:00.000", { event_type: "configuration_changed", config_change_kind: "changed" }),
    ev("old", "history", "2026-08-01 00:00:00.000"),
  ];
  const summary = summarizeActivity(summaryRows, (timestamp: string) => timestamp >= "2026-09-01", true);
  assert.deepEqual(summary.scan, { started: 1, completed: 1, cancelled: 1, failed: 0, last: "2026-09-02 00:00:00.000" });
  assert.deepEqual(summary.signature, { updated: 2, failed: 1, version: "1.2", last: "2026-09-04 00:00:00.000" });
  assert.deepEqual(summary.history, { count: 1, last: "2026-09-05 00:00:00.000" });
  assert.deepEqual(summary.config, { count: 3, exclusionsAdded: 1, exclusionsRemoved: 1, last: "2026-09-08 00:00:00.000" });
});
