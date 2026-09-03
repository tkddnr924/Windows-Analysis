// 서비스 이력(_OVERVIEW/ServiceHistory) 행을 서비스 단위 카드로 묶는다.
//
// SCM 이벤트는 서비스를 두 가지 이름으로 부른다 — 7045(설치)는 짧은 서비스
// 이름(`ServiceName`), 7036/7034 같은 상태 기록은 표시 이름(`param1`)을 쓴다.
// 둘을 잇는 근거는 7040(시작 유형 변경) 하나뿐이다: 표시 이름(param1)과 짧은
// 이름(param4)을 한 레코드에 함께 담는다. 파생 빌더는 이를 각각 `service_name`
// 과 `service_key`로 보존한다.
//
// 그래서 집계는 (1) 7040이 제공한 `표시 이름 → 짧은 이름` 대응표를 먼저 만들고
// (2) 그 근거가 있는 이름만 짧은 이름으로 정규화해 묶는다. 근거가 없는 이름은
// 절대 추측으로 합치지 않는다 — 동명이인 서비스를 한 이력으로 만들면 증거를
// 왜곡한다.

export type ServiceRow = Record<string, string>;

export interface ServiceGroup {
  /** 집계 키 — 근거가 있으면 짧은 서비스 이름, 없으면 원문 이름. */
  key: string;
  /** 카드 제목 — 사람이 읽을 표시 이름을 우선한다. */
  name: string;
  imagePath: string;
  installs: number;
  startTypeChanges: number;
  stateChanges: number;
  failures: number;
  first: string;
  last: string;
  events: ServiceRow[];
}

/** 7040처럼 두 이름을 함께 가진 레코드에서만 대응표를 만든다.
 *
 * 표시 이름은 사람이 읽는 라벨이라 전역 유일성이 보장되지 않는다 — 같은 표시
 * 이름이 서로 다른 서비스에 쓰이거나 수집 기간 중 바뀌었을 수 있다. 그래서
 * 후보 짧은 이름을 **집합으로 모아 정확히 하나일 때만** 별칭으로 인정한다.
 * 후보가 둘 이상이면 어느 서비스인지 판별할 근거가 없으므로 별칭을 만들지
 * 않는다(입력 순서에 따라 임의의 서비스로 합쳐지는 것을 막는다).
 *
 * Windows 서비스 이름은 대소문자를 구분하지 않으므로 표시 이름 키도 그렇게 다룬다. */
export function displayToShortName(rows: ServiceRow[]): Map<string, string> {
  const candidates = new Map<string, Set<string>>();
  for (const row of rows) {
    const display = (row.service_name || "").trim();
    const short = (row.service_key || "").trim();
    if (!display || !short || display.toLowerCase() === short.toLowerCase()) continue;
    const key = display.toLowerCase();
    const set = candidates.get(key) ?? new Set<string>();
    set.add(short);
    candidates.set(key, set);
  }
  const alias = new Map<string, string>();
  for (const [display, shorts] of candidates) {
    // 후보가 정확히 하나일 때만 — 모호하면 결합하지 않는다.
    if (shorts.size === 1) alias.set(display, [...shorts][0]);
  }
  return alias;
}

export function groupServiceEvents(
  rows: ServiceRow[],
  inRange: (timestamp: string) => boolean = () => true,
): ServiceGroup[] {
  const alias = displayToShortName(rows);
  const byKey = new Map<string, ServiceGroup>();
  for (const raw of rows) {
    const timestamp = raw.timestamp ?? "";
    if (!inRange(timestamp)) continue;
    const name = raw.service_name || "";
    // 레코드 자신의 짧은 이름이 있으면 그것이 가장 강한 근거다.
    const canonical = raw.service_key || alias.get(name.trim().toLowerCase()) || name;
    // 7026(부팅 드라이버 로드 실패)은 서비스 이름 자리에 드라이버 목록이 와
    // 파생이 이름을 비워 둔다. 서비스로 묶을 근거가 없으므로 원본 레코드마다
    // 독립 항목으로 남긴다 — 서로 다른 부팅·드라이버가 한 덩어리로 합쳐지면
    // 카드의 기간과 실패 건수가 과도하게 합산된다.
    const key = canonical || `${raw.description || "(서비스 정보 없음)"}::${raw.record_key || timestamp}`;
    let service = byKey.get(key);
    if (!service) {
      service = {
        key,
        name: name || raw.description || "(서비스 정보 없음)",
        imagePath: "",
        installs: 0,
        startTypeChanges: 0,
        stateChanges: 0,
        failures: 0,
        first: timestamp,
        last: timestamp,
        events: [],
      };
      byKey.set(key, service);
    }
    // 짧은 이름으로 묶였더라도 제목은 표시 이름을 우선한다. 원본의 두 이름은
    // 각 이벤트 행에 그대로 남아 상세에서 모두 확인된다.
    if (name && name !== canonical) service.name = name;
    if (!service.imagePath && raw.image_path) service.imagePath = raw.image_path;
    if (raw.event_id === "7045") service.installs += 1;
    else if (raw.event_id === "7040") service.startTypeChanges += 1;
    else if (raw.event_id === "7036") service.stateChanges += 1;
    if (raw.result === "실패") service.failures += 1;
    if (timestamp) {
      if (!service.first || timestamp < service.first) service.first = timestamp;
      if (!service.last || timestamp > service.last) service.last = timestamp;
    }
    service.events.push(raw);
  }
  for (const service of byKey.values()) {
    service.events.sort((a, b) => (a.timestamp ?? "").localeCompare(b.timestamp ?? ""));
  }
  return [...byKey.values()];
}
