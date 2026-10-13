import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { DEFAULT_BITS_FILTER, bitsAccountKey, buildBitsCards, urlLabel } from "./bitsHistory.ts";

type Row = Record<string, string>;
const ev = (record_id: string, timestamp: string, extra: Row = {}): Row => ({ record_id, timestamp, job_group_key: `record:${record_id}`, event_type: "BITS 경고", result: "미확인", ...extra });
const always = () => true;
const keys = (cards: { key: string }[]) => cards.map((card) => card.key);

const rows = [
  ev("c", "2026-08-24 17:40:48.107", { job_group_key: "job:A", event_type: "BITS URL 전송 종료", result: "성공", url: "http://host.example/files/abc?P1=1" }),
  ev("a", "2026-08-24 17:40:26.550", { job_group_key: "job:A", event_type: "BITS 전송 작업 생성", result: "정보", owner_sid_candidate: "S-1-5-21-1-1001", owner_raw: "JAITSERVER\\USER" }),
  ev("b", "2026-08-24 17:40:26.557", { job_group_key: "job:A", event_type: "BITS 작업 파일 기록", result: "정보", local_path: "C:\\Users\\USER\\AppData\\Local\\Temp\\x.bin" }),
  // Same job name, no job id: never merged (R03).
  ev("n1", "2026-08-25 00:00:00.000", { job_name: "Font Download" }),
  ev("n2", "2026-08-25 00:00:00.000", { job_name: "Font Download" }),
  ev("u", ""),
];

test("cards follow the stored job_group_key; unidentified rows stay single; untimed last", () => {
  const cards = buildBitsCards(rows, DEFAULT_BITS_FILTER, always, false, "asc");
  assert.deepEqual(keys(cards), ["job:A", "record:n1", "record:n2", "record:u"]);
  assert.deepEqual(cards[0].events.map((row: Row) => row.record_id), ["a", "b", "c"]);
  assert.deepEqual(keys(buildBitsCards(rows, DEFAULT_BITS_FILTER, always, false, "desc")), ["record:n1", "record:n2", "job:A", "record:u"]);
});

test("filters keep the whole job with match counts; search reaches url and local path", () => {
  const success = buildBitsCards(rows, { ...DEFAULT_BITS_FILTER, results: ["성공"] }, always, false, "asc");
  assert.deepEqual(keys(success), ["job:A"]);
  assert.deepEqual([...success[0].matched], ["c"]);
  assert.equal(success[0].events.length, 3);
  assert.deepEqual(keys(buildBitsCards(rows, { ...DEFAULT_BITS_FILTER, search: "x.bin" }, always, false, "asc")), ["job:A"]);
  assert.deepEqual(keys(buildBitsCards(rows, { ...DEFAULT_BITS_FILTER, search: "host.example" }, always, false, "asc")), ["job:A"]);
});

test("account filter uses the owner SID candidate, else the raw owner", () => {
  assert.equal(bitsAccountKey({ owner_sid_candidate: "S-1-5-21-1-1001", owner_raw: "JAITSERVER\\USER" }), "S-1-5-21-1-1001");
  assert.equal(bitsAccountKey({ owner_raw: "NT AUTHORITY\\LOCAL SERVICE" }), "NT AUTHORITY\\LOCAL SERVICE");
  assert.deepEqual(keys(buildBitsCards(rows, { ...DEFAULT_BITS_FILTER, accounts: ["S-1-5-21-1-1001"] }, always, false, "asc")), ["job:A"]);
});

test("period drops outside and untimed rows", () => {
  assert.deepEqual(keys(buildBitsCards(rows, DEFAULT_BITS_FILTER, (t: string) => t >= "2026-08-25", true, "asc")), ["record:n1", "record:n2"]);
});

test("url label drops the query string", () => {
  assert.equal(urlLabel("http://host.example/files/abc?P1=1&P2=2"), "host.example/files/abc");
  assert.equal(urlLabel("not a url"), "not a url");
});
