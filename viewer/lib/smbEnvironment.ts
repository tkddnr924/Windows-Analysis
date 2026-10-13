// SMB server environment summary (docs-09 A05): stored LanmanServer registry
// values and SCM events → labelled meanings. Raw values stay attached; unknown
// names are shown as stored. No runtime imports (Node tests).

type Row = Record<string, string | undefined>;

export interface EnvItem {
  /** Stored value name. */
  name: string;
  label: string;
  /** Meaning of the stored value (or the value itself when no mapping exists). */
  value: string;
  /** Stored value text. */
  raw: string;
  keyPath: string;
  /** Boolean flags only. */
  state?: "on" | "off";
  note?: string;
}

export interface EnvEvent { time: string; text: string; eventId: string; kind: string }
export interface EnvShare { name: string; path: string; type: string; remark: string }

export interface EnvSummary {
  activeSet: string;
  service: EnvItem[];
  security: EnvItem[];
  shares: EnvShare[];
  sharesKeyTime: string;
  serviceKeyTime: string;
  parametersKeyTime: string;
  events: EnvEvent[];
  lastState: EnvEvent | null;
  otherSets: { set: string; differences: { name: string; active: string; other: string }[] }[];
}

// docs: learn.microsoft.com — services registry tree (Start/Type/ErrorControl), SC sidtype.
const START: Record<string, string> = { "0": "부팅", "1": "시스템", "2": "자동", "3": "수동", "4": "사용 안 함" };
const SERVICE_TYPE: Record<string, string> = { "16": "단독 프로세스", "32": "공유 프로세스" };
const ERROR_CONTROL: Record<string, string> = { "0": "무시", "1": "보통", "2": "심각", "3": "치명" };
const SID_TYPE: Record<string, string> = { "0": "없음", "1": "제한 없음", "3": "제한됨" };
const SHARE_TYPE: Record<number, string> = { 0: "디스크", 1: "프린터", 2: "장치", 3: "IPC" };

// Display order + label; resource strings and opaque blobs are left to the raw table.
const SERVICE_FIELDS: [string, string][] = [
  ["start", "시작 유형"], ["objectname", "실행 계정"], ["imagepath", "실행 파일"], ["servicedll", "서비스 DLL"],
  ["dependonservice", "의존 서비스"], ["type", "서비스 형태"], ["errorcontrol", "오류 처리"], ["servicesidtype", "서비스 SID"],
  ["requiredprivileges", "필요 권한"],
];
const SERVICE_SKIP = new Set(["displayname", "description", "failureactions", "servicedllunloadonstop"]);
const FLAGS: Record<string, string> = {
  restrictnullsessaccess: "익명 접근 제한",
  requiresecuritysignature: "SMB 서명 필수",
  enablesecuritysignature: "SMB 서명 사용",
  enableforcedlogoff: "로그온 시간 만료 시 연결 해제",
  smb1: "SMB1 서버",
  smb2: "SMB2/3 서버",
  autoshareserver: "관리 공유 자동 생성",
  autosharewks: "관리 공유 자동 생성",
};
const SECURITY_ORDER = ["smb1", "smb2", "requiresecuritysignature", "enablesecuritysignature", "restrictnullsessaccess", "nullsessionpipes", "nullsessionshares", "autoshareserver", "autosharewks", "autodisconnect", "enableforcedlogoff", "guid"];
// MS Learn "Overview of SMB signing": SMB2+ ignores EnableSecuritySignature.
const NOTES: Record<string, string> = { enablesecuritysignature: "SMB1에만 적용" };

const lower = (value: string | undefined) => (value ?? "").toLowerCase();
const setOf = (row: Row) => (row.key_path ?? "").split("\\").find((part) => /^controlset\d+$/i.test(part)) ?? "";
/** Key path below the ControlSet, lower-case (for cross-set comparison). */
const relativeKey = (row: Row) => {
  const parts = (row.key_path ?? "").split("\\");
  const index = parts.findIndex((part) => /^controlset\d+$/i.test(part));
  return lower(parts.slice(index + 1).join("\\"));
};
const isParameters = (row: Row) => relativeKey(row).endsWith("lanmanserver\\parameters");
const isServiceKey = (row: Row) => relativeKey(row).endsWith("lanmanserver");
const isShares = (row: Row) => relativeKey(row).endsWith("lanmanserver\\shares");

function list(raw: string): string[] | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(String) : null;
  } catch {
    return null;
  }
}

function serviceItem(row: Row): EnvItem {
  const name = row.value_name ?? "";
  const raw = row.value_data ?? "";
  const key = lower(name);
  const label = SERVICE_FIELDS.find(([field]) => field === key)?.[1] ?? name;
  const items = list(raw);
  const value = key === "start" ? START[raw] ?? raw
    : key === "type" ? SERVICE_TYPE[raw] ?? raw
    : key === "errorcontrol" ? ERROR_CONTROL[raw] ?? raw
    : key === "servicesidtype" ? SID_TYPE[raw] ?? raw
    : items ? (items.length ? items.join(", ") : "없음") : raw;
  return { name, label, value, raw, keyPath: row.key_path ?? "" };
}

function securityItem(row: Row): EnvItem {
  const name = row.value_name ?? "";
  const raw = row.value_data ?? "";
  const key = lower(name);
  const base = { name, raw, keyPath: row.key_path ?? "", note: NOTES[key] };
  if (FLAGS[key] && (raw === "0" || raw === "1")) return { ...base, label: FLAGS[key], value: raw === "1" ? "켜짐" : "꺼짐", state: raw === "1" ? "on" : "off" };
  if (key === "nullsessionpipes" || key === "nullsessionshares") {
    const items = list(raw);
    return { ...base, label: key === "nullsessionpipes" ? "익명 허용 파이프" : "익명 허용 공유", value: items ? (items.length ? items.join(", ") : "없음") : raw };
  }
  if (key === "autodisconnect") return { ...base, label: "유휴 연결 끊기", value: raw === "4294967295" ? "사용 안 함" : /^\d+$/.test(raw) ? `${raw}분` : raw };
  if (key === "guid") return { ...base, label: "서버 GUID", value: raw };
  return { ...base, label: name, value: raw };
}

const rank = (order: string[], name: string) => {
  const index = order.indexOf(lower(name));
  return index < 0 ? order.length : index;
};

function share(row: Row): EnvShare {
  const fields = new Map<string, string>();
  for (const entry of list(row.value_data ?? "") ?? []) {
    const at = entry.indexOf("=");
    if (at > 0) fields.set(entry.slice(0, at).toLowerCase(), entry.slice(at + 1));
  }
  const typeRaw = fields.get("type") ?? "";
  const typeNumber = Number(typeRaw);
  // 0x80000000 marks a special (administrative) share.
  const type = /^\d+$/.test(typeRaw) ? `${SHARE_TYPE[typeNumber % 0x80000000] ?? typeRaw}${typeNumber >= 0x80000000 ? " · 특수" : ""}` : typeRaw;
  return { name: row.value_name ?? "", path: fields.get("path") ?? "", type, remark: fields.get("remark") ?? "" };
}

export function summarizeEnvironment(rows: Row[]): EnvSummary {
  const selection = rows.find((row) => row.evidence_kind === "control_set_selection" && lower(row.value_name) === "current");
  const sets = [...new Set(rows.map(setOf).filter(Boolean))];
  const bySelection = selection?.value_data ? sets.find((set) => lower(set) === `controlset${selection.value_data!.padStart(3, "0")}`) : undefined;
  const activeSet = rows.find((row) => row.control_set_status === "active" && setOf(row))?.key_path?.split("\\").find((part) => /^controlset\d+$/i.test(part))
    ?? bySelection ?? (sets.length === 1 ? sets[0] : [...sets].sort()[0] ?? "");
  const active = rows.filter((row) => setOf(row) && lower(setOf(row)) === lower(activeSet));
  const values = active.filter((row) => row.entry_kind === "value");
  const keyTime = (match: (row: Row) => boolean) => active.find(match)?.timestamp ?? "";

  const service = values
    .filter((row) => (isServiceKey(row) && !SERVICE_SKIP.has(lower(row.value_name))) || (isParameters(row) && lower(row.value_name) === "servicedll"))
    .map(serviceItem)
    .sort((a, b) => rank(SERVICE_FIELDS.map(([field]) => field), a.name) - rank(SERVICE_FIELDS.map(([field]) => field), b.name));
  const security = values
    .filter((row) => isParameters(row) && !["servicedll", "servicedllunloadonstop"].includes(lower(row.value_name)))
    .map(securityItem)
    .sort((a, b) => rank(SECURITY_ORDER, a.name) - rank(SECURITY_ORDER, b.name));
  const shares = values.filter(isShares).map(share);

  const events = rows
    .filter((row) => row.evidence_kind === "service_state" || row.evidence_kind === "service_start_type_change")
    .map((row): EnvEvent => ({
      time: row.timestamp ?? "",
      text: row.evidence_kind === "service_state" ? row.state ?? "" : [row.start_type_before, row.start_type_after].filter(Boolean).join(" → "),
      eventId: row.event_id ?? "",
      kind: row.evidence_kind ?? "",
    }))
    .sort((a, b) => (a.time && b.time ? a.time.localeCompare(b.time) : a.time ? -1 : b.time ? 1 : 0));
  const lastState = [...events].reverse().find((event) => event.kind === "service_state") ?? null;

  const activeValues = new Map(values.map((row) => [`${relativeKey(row)}|${lower(row.value_name)}`, row]));
  const otherSets = sets.filter((set) => lower(set) !== lower(activeSet)).sort().map((set) => {
    const otherValues = new Map(rows.filter((row) => lower(setOf(row)) === lower(set) && row.entry_kind === "value").map((row) => [`${relativeKey(row)}|${lower(row.value_name)}`, row]));
    const differences: { name: string; active: string; other: string }[] = [];
    for (const key of new Set([...activeValues.keys(), ...otherValues.keys()])) {
      const left = activeValues.get(key);
      const right = otherValues.get(key);
      const a = left?.value_data ?? left?.value_data_hex ?? "";
      const b = right?.value_data ?? right?.value_data_hex ?? "";
      if (!left || !right || a !== b) differences.push({ name: (left ?? right)?.value_name ?? "", active: left ? a : "", other: right ? b : "" });
    }
    return { set, differences };
  });

  return {
    activeSet,
    service,
    security,
    shares,
    sharesKeyTime: keyTime(isShares),
    serviceKeyTime: keyTime(isServiceKey),
    parametersKeyTime: keyTime(isParameters),
    events,
    lastState,
    otherSets,
  };
}
