import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { groupServiceEvents } from "./serviceGrouping.ts";

const row = (over: Record<string, string>) => ({
  timestamp: "",
  service_name: "",
  service_key: "",
  event_id: "",
  description: "",
  image_path: "",
  result: "정보",
  record_key: "",
  ...over,
});

// 7040이 표시 이름과 짧은 이름을 함께 남기므로, 설치(7045·짧은 이름)와
// 상태/종료(7036·7034·표시 이름)가 한 서비스 카드로 모여야 한다.
test("7040이 알려 준 별칭으로 같은 서비스의 이력이 한 카드로 모인다", () => {
  const groups = groupServiceEvents([
    row({ timestamp: "2026-01-01 10:00:00.000", service_name: "SvcShort", service_key: "SvcShort", event_id: "7045", description: "서비스 설치", image_path: "C:\\Tools\\svc.exe" }),
    row({ timestamp: "2026-01-01 10:05:00.000", service_name: "Svc Display Name", service_key: "SvcShort", event_id: "7040", description: "시작 유형 변경" }),
    row({ timestamp: "2026-01-01 10:10:00.000", service_name: "Svc Display Name", event_id: "7036", description: "서비스 상태 변경" }),
    row({ timestamp: "2026-01-01 10:20:00.000", service_name: "Svc Display Name", event_id: "7034", description: "서비스 비정상 종료", result: "실패" }),
  ]);
  assert.equal(groups.length, 1);
  const svc = groups[0];
  assert.equal(svc.key, "SvcShort");
  // 제목은 사람이 읽을 표시 이름을 쓴다.
  assert.equal(svc.name, "Svc Display Name");
  assert.equal(svc.installs, 1);
  assert.equal(svc.startTypeChanges, 1);
  assert.equal(svc.stateChanges, 1);
  assert.equal(svc.failures, 1);
  assert.equal(svc.imagePath, "C:\\Tools\\svc.exe");
  assert.equal(svc.events.length, 4);
  assert.equal(svc.first, "2026-01-01 10:00:00.000");
  assert.equal(svc.last, "2026-01-01 10:20:00.000");
});

// 연결 근거(7040)가 없으면 같은 표시 이름이라도 추측으로 합치지 않는다.
test("별칭 근거가 없는 이름은 짧은 이름과 합쳐지지 않는다", () => {
  const groups = groupServiceEvents([
    row({ timestamp: "2026-01-01 10:00:00.000", service_name: "SvcShort", service_key: "SvcShort", event_id: "7045" }),
    row({ timestamp: "2026-01-01 10:10:00.000", service_name: "Svc Display Name", event_id: "7036" }),
  ]);
  assert.equal(groups.length, 2);
  assert.deepEqual(groups.map((g) => g.key).sort(), ["Svc Display Name", "SvcShort"]);
});

// 7026은 서비스 이름 자리에 드라이버 목록이 오는 부팅 단위 기록이라 파생이
// 이름을 비운다. 전부 한 카드로 뭉치면 기간·실패 수가 과도하게 합산된다.
test("이름 없는 7026 기록은 원본 레코드마다 독립 항목으로 남는다", () => {
  const groups = groupServiceEvents([
    row({ timestamp: "2026-01-01 01:00:00.000", event_id: "7026", description: "부팅/시스템 시작 드라이버 로드 실패", result: "실패", record_key: "System::1" }),
    row({ timestamp: "2026-02-01 01:00:00.000", event_id: "7026", description: "부팅/시스템 시작 드라이버 로드 실패", result: "실패", record_key: "System::2" }),
  ]);
  assert.equal(groups.length, 2);
  for (const group of groups) assert.equal(group.events.length, 1);
});

// 기간 필터는 집계 전에 적용된다.
test("기간 밖 이벤트는 카드에 들어가지 않는다", () => {
  const groups = groupServiceEvents(
    [
      row({ timestamp: "2026-01-01 10:00:00.000", service_name: "A", service_key: "A", event_id: "7045" }),
      row({ timestamp: "2026-03-01 10:00:00.000", service_name: "A", service_key: "A", event_id: "7036" }),
    ],
    (timestamp) => timestamp < "2026-02-01",
  );
  assert.equal(groups.length, 1);
  assert.equal(groups[0].events.length, 1);
});
