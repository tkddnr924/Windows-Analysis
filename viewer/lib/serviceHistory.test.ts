import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_SERVICE_FILTER, buildServiceCards } from "./serviceHistory.ts";

type Row = Record<string, string>;
const ev = (record_id: string, group_key: string, timestamp: string, extra: Row = {}): Row => ({ record_id, group_key, group_key_kind: "service_key", timestamp, event_type: "시작 유형 변경", result: "정보", ...extra });
const always = () => true;
const keys = (cards: { key: string }[]) => cards.map((card) => card.key);

test("cards follow the stored group_key; record-kind groups stay independent; whole context kept with match counts", () => {
  const rows = [
    ev("b", "bits", "2026-01-02 00:00:00.000"),
    ev("a", "bits", "2026-01-01 00:00:00.000", { result: "실패" }),
    ev("r1", "record::r1", "2026-01-03 00:00:00.000", { group_key_kind: "record", event_type: "부팅/시스템 시작 드라이버 로드 실패", result: "실패" }),
    ev("r2", "record::r2", "2026-01-03 00:00:00.000", { group_key_kind: "record", event_type: "부팅/시스템 시작 드라이버 로드 실패", result: "실패" }),
  ];
  const all = buildServiceCards(rows, DEFAULT_SERVICE_FILTER, always, false, "asc");
  assert.deepEqual(keys(all), ["bits", "record::r1", "record::r2"]);
  assert.deepEqual(all[0].events.map((row: Row) => row.record_id), ["a", "b"]);
  const failed = buildServiceCards(rows, { ...DEFAULT_SERVICE_FILTER, results: ["실패"] }, always, false, "asc");
  assert.deepEqual(keys(failed), ["bits", "record::r1", "record::r2"]);
  assert.deepEqual([...failed[0].matched], ["a"]);
  assert.equal(failed[0].events.length, 2);
});

test("search covers stored search_text plus common account/SID; filters on state, start type, service account SID, kind", () => {
  const rows = [
    ev("a", "svc", "2026-01-01 00:00:00.000", { search_text: "teamviewer c:\\program files\\teamviewer\\teamviewer_service.exe localsystem", service_account_sid: "S-1-5-18", event_type: "서비스 설치", start_type_after: "자동 시작" }),
    ev("b", "bits", "2026-01-02 00:00:00.000", { account: "alice", account_sid: "S-1-5-21-9", state: "실행" }),
  ];
  const ids = (filter: object) => buildServiceCards(rows, { ...DEFAULT_SERVICE_FILTER, ...filter }, always, false, "asc").flatMap((card: { matched: Set<string> }) => [...card.matched]);
  assert.deepEqual(ids({ search: "TeamViewer_Service" }), ["a"]);
  assert.deepEqual(ids({ search: "s-1-5-21-9" }), ["b"]);
  assert.deepEqual(ids({ search: "alice" }), ["b"]);
  assert.deepEqual(ids({ states: ["실행"] }), ["b"]);
  assert.deepEqual(ids({ startTypes: ["자동 시작"] }), ["a"]);
  assert.deepEqual(ids({ serviceAccounts: ["S-1-5-18"] }), ["a"]);
  assert.deepEqual(ids({ kinds: ["서비스 설치"] }), ["a"]);
});

test("same time orders by record_id; untimed events sort last in either direction and drop out under a period", () => {
  const rows = [ev("z", "svc", ""), ev("m2", "svc", "2026-01-01 00:00:00.000"), ev("m1", "svc", "2026-01-01 00:00:00.000"), ev("o", "other", "2025-01-01 00:00:00.000")];
  const asc = buildServiceCards(rows, DEFAULT_SERVICE_FILTER, always, false, "asc");
  assert.deepEqual(asc.find((card: { key: string }) => card.key === "svc")?.events.map((row: Row) => row.record_id), ["m1", "m2", "z"]);
  assert.deepEqual(keys(asc), ["other", "svc"]);
  const desc = buildServiceCards(rows, DEFAULT_SERVICE_FILTER, always, false, "desc");
  assert.deepEqual(keys(desc), ["svc", "other"]);
  // Ties stay in record_id order regardless of direction.
  assert.deepEqual(desc[0].events.map((row: Row) => row.record_id), ["m1", "m2", "z"]);
  const period = buildServiceCards(rows, DEFAULT_SERVICE_FILTER, always, true, "asc");
  assert.deepEqual(period.find((card: { key: string }) => card.key === "svc")?.events.map((row: Row) => row.record_id), ["m1", "m2"]);
});
