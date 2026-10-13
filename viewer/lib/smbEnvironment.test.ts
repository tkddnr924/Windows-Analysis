import assert from "node:assert/strict";
import test from "node:test";
// @ts-expect-error -- TypeScript uses bundler resolution while this test uses Node directly.
import { summarizeEnvironment } from "./smbEnvironment.ts";

type Row = Record<string, string>;
const value = (set: string, status: string, key: string, name: string, data: string, extra: Row = {}): Row => ({
  evidence_kind: key.endsWith("Parameters") ? "share_configuration" : key.includes("Shares") ? "share_definition" : "service_configuration",
  control_set: set.toLowerCase(), control_set_status: status, entry_kind: "value",
  key_path: `\\ROOT\\${set}\\Services\\LanmanServer${key}`, value_name: name, value_data: data, timestamp: "2026-01-27 09:17:24.843", ...extra,
});

test("active ControlSet values become labelled meanings with raw evidence kept", () => {
  const summary = summarizeEnvironment([
    { evidence_kind: "control_set_selection", key_path: "\\ROOT\\Select", value_name: "Current", value_data: "1", entry_kind: "value" },
    value("ControlSet001", "active", "", "Start", "2"),
    value("ControlSet001", "active", "", "ObjectName", "LocalSystem"),
    value("ControlSet001", "active", "", "DependOnService", "[\"SamSS\", \"Srv2\"]"),
    value("ControlSet001", "active", "", "Type", "32"),
    value("ControlSet001", "active", "", "DisplayName", "@%systemroot%\\system32\\srvsvc.dll,-100"),
    value("ControlSet001", "active", "\\Parameters", "restrictnullsessaccess", "1"),
    value("ControlSet001", "active", "\\Parameters", "NullSessionPipes", "[]"),
    value("ControlSet001", "active", "\\Parameters", "autodisconnect", "15"),
    value("ControlSet001", "active", "\\Parameters", "enablesecuritysignature", "0"),
    value("ControlSet001", "active", "\\Parameters", "SomeNewValue", "7"),
    value("ControlSet002", "inactive", "", "Start", "4"),
  ]);
  assert.equal(summary.activeSet, "ControlSet001");
  const service = Object.fromEntries(summary.service.map((item: { name: string; value: string }) => [item.name, item.value]));
  assert.equal(service.Start, "자동");
  assert.equal(service.ObjectName, "LocalSystem");
  assert.equal(service.DependOnService, "SamSS, Srv2");
  assert.equal(service.Type, "공유 프로세스");
  // Resource-string display names carry no case meaning.
  assert.equal(service.DisplayName, undefined);
  const security = Object.fromEntries(summary.security.map((item: { name: string; value: string; state?: string }) => [item.name, [item.value, item.state]]));
  assert.deepEqual(security.restrictnullsessaccess, ["켜짐", "on"]);
  assert.deepEqual(security.NullSessionPipes, ["없음", undefined]);
  assert.deepEqual(security.autodisconnect, ["15분", undefined]);
  assert.deepEqual(security.enablesecuritysignature, ["꺼짐", "off"]);
  // Unknown values stay visible as stored.
  assert.deepEqual(security.SomeNewValue, ["7", undefined]);
  // Other ControlSets report changed and missing values only.
  const [other] = summary.otherSets;
  assert.equal(other.set, "ControlSet002");
  assert.deepEqual(other.differences.find((d: { name: string }) => d.name === "Start"), { name: "Start", active: "2", other: "4" });
  assert.deepEqual(other.differences.find((d: { name: string }) => d.name === "ObjectName"), { name: "ObjectName", active: "LocalSystem", other: "" });
  assert.equal(summarizeEnvironment([value("ControlSet001", "active", "", "Start", "2"), value("ControlSet002", "inactive", "", "Start", "2")]).otherSets[0].differences.length, 0);
});

test("shares come from stored Shares values only; no values means none registered", () => {
  const empty = summarizeEnvironment([
    { evidence_kind: "share_definition", control_set: "controlset001", control_set_status: "active", entry_kind: "key", key_path: "\\ROOT\\ControlSet001\\Services\\LanmanServer\\Shares", timestamp: "2026-01-27 09:17:24.817" },
  ]);
  assert.deepEqual(empty.shares, []);
  assert.equal(empty.sharesKeyTime, "2026-01-27 09:17:24.817");
  const one = summarizeEnvironment([
    value("ControlSet001", "active", "\\Shares", "Data", "[\"CSCFlags=0\", \"MaxUses=4294967295\", \"Path=D:\\\\Data\", \"Permissions=0\", \"Remark=team\", \"Type=0\"]"),
    value("ControlSet001", "active", "\\Shares\\Security", "Data", "", { value_data_hex: "0100" }),
  ]);
  assert.deepEqual(one.shares, [{ name: "Data", path: "D:\\Data", type: "디스크", remark: "team" }]);
});

test("service state events are listed in time order with the latest first-class", () => {
  const summary = summarizeEnvironment([
    { evidence_kind: "service_state", service_name: "LanmanServer", state: "실행", timestamp: "2026-09-29 00:18:35.284", event_id: "7036" },
    { evidence_kind: "service_state", service_name: "LanmanServer", state: "중지", timestamp: "2026-08-14 04:34:54.278", event_id: "7036" },
    { evidence_kind: "service_start_type_change", service_name: "LanmanServer", start_type_before: "자동 시작", start_type_after: "사용 안 함", timestamp: "2026-09-01 10:00:00.000", event_id: "7040" },
  ]);
  assert.deepEqual(summary.events.map((event: { text: string }) => event.text), ["중지", "자동 시작 → 사용 안 함", "실행"]);
  assert.equal(summary.lastState?.text, "실행");
});
