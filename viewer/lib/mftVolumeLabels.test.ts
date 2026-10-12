import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { volumeLabels } from "./mftVolumeLabels.ts";

const input = (volume_id: string, source_relative: string | null, record_count = "10", extra: Record<string, string | null> = {}) =>
  ({ volume_id, volume_label: null, drive_letter: null, input_name: "$MFT", source_relative, record_count, ...extra });

test("short labels when inputs already differ", () => {
  assert.deepEqual(volumeLabels([input("v1", "A/NonVolatile/METADATA/C/$MFT"), input("v2", "A/NonVolatile/METADATA/D/$MFT")]), {
    v1: "$MFT · METADATA/C/$MFT · 10건",
    v2: "$MFT · METADATA/D/$MFT · 10건",
  });
});

test("matching suffixes and counts keep the distinguishing path prefix", () => {
  const labels = volumeLabels([input("v1", "capture-A/NonVolatile/METADATA/C/$MFT"), input("v2", "capture-B/NonVolatile/METADATA/C/$MFT")]);
  assert.notEqual(labels.v1, labels.v2);
  assert.match(labels.v1, /capture-A/);
  assert.match(labels.v2, /capture-B/);
});

test("fully identical metadata falls back to the internal input key", () => {
  const labels = volumeLabels([input("v1", null), input("v2", null)]);
  assert.notEqual(labels.v1, labels.v2);
  assert.match(labels.v2, /v2/);
});
