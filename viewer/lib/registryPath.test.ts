import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error app bundling resolves the extensionless import separately.
import { displayRegistryKeyPath, hiveMountPoint } from "./registryPath.ts";

// 산출물 이름에서 하이브를 인식해 라이브 마운트 지점을 고른다. 계정 접두와
// 중복 수집 접미사(_2), RegBack 접미사는 하이브 판별에 영향을 주면 안 된다.
test("하이브 이름에서 마운트 지점을 고른다", () => {
  const cases: [string, string | null][] = [
    ["SOFTWARE", "HKLM\\SOFTWARE"],
    ["SYSTEM", "HKLM\\SYSTEM"],
    ["DEFAULT", "HKU\\.DEFAULT"],
    ["SAM", "HKLM\\SAM"],
    ["SOFTWARE_RegBack", "HKLM\\SOFTWARE"],
    ["SYSTEM_RegBack_2", "HKLM\\SYSTEM"],
    ["NTUSER.DAT", "HKCU"],
    ["Administrator_NTUSER.DAT", "HKCU"],
    ["Administrator_UsrClass.dat", "HKCU\\Software\\Classes"],
    ["UsrClass.dat", "HKCU\\Software\\Classes"],
    ["Amcache.hve", null],
    ["", null],
  ];
  for (const [hive, expected] of cases) {
    assert.equal(hiveMountPoint(hive), expected, `hive=${hive}`);
  }
});

// 하이브 루트 키 이름으로 확인된 형태만 치환한다.
test("하이브 루트 형태일 때만 마운트 지점으로 치환한다", () => {
  assert.equal(
    displayRegistryKeyPath("\\CMI-CreateHive{D43B12B8-09B5-40DB-B4F6-F6DFEB78DAEC}\\Microsoft\\Windows", "SOFTWARE"),
    "HKLM\\SOFTWARE\\Microsoft\\Windows",
  );
  assert.equal(
    displayRegistryKeyPath("\\ROOT\\ControlSet001\\Services", "SYSTEM"),
    "HKLM\\SYSTEM\\ControlSet001\\Services",
  );
  assert.equal(
    displayRegistryKeyPath("\\NTUSER.DAT\\Software\\Microsoft", "Administrator_NTUSER.DAT"),
    "HKCU\\Software\\Microsoft",
  );
  assert.equal(
    displayRegistryKeyPath("\\S-1-5-21-1-2-3-1001_Classes\\CLSID", "Administrator_UsrClass.dat"),
    "HKCU\\Software\\Classes\\CLSID",
  );
});

// 안전장치: 하이브를 모르거나 루트 형태가 아니면 원문을 그대로 둔다.
test("근거가 없으면 원본 경로를 바꾸지 않는다", () => {
  // 축약 경로(루트 키가 없는 형태)
  assert.equal(
    displayRegistryKeyPath("\\Software\\Microsoft\\Windows", "SOFTWARE"),
    "\\Software\\Microsoft\\Windows",
  );
  // 알 수 없는 하이브
  assert.equal(
    displayRegistryKeyPath("\\ROOT\\Something", "Amcache.hve"),
    "\\ROOT\\Something",
  );
  // 역슬래시로 시작하지 않는 경로는 그대로
  assert.equal(displayRegistryKeyPath("HKLM\\SOFTWARE\\X", "SOFTWARE"), "HKLM\\SOFTWARE\\X");
  // 빈 값
  assert.equal(displayRegistryKeyPath("", "SOFTWARE"), "");
  assert.equal(displayRegistryKeyPath(null, null), "");
});
