// Registry explorer helpers (docs-06). Stored values are decoded only where the
// registry type defines the encoding; nothing is inferred. No runtime imports
// (Node tests).

type Cells = Record<string, string | undefined>;

/** Numeric type names (vendor/device property types) as their raw hex code. */
export function typeLabel(typeName: string | undefined): string {
  if (!typeName) return "—";
  if (/^\d+$/.test(typeName)) return `0x${Number(typeName).toString(16).toUpperCase().padStart(8, "0")}`;
  return typeName;
}

/** FILETIME (100 ns since 1601 UTC) → KST text like other stored times; 0 = none. */
export function filetimeToKst(raw: string | undefined): string | null {
  if (!raw || !/^\d+$/.test(raw)) return null;
  const ticks = BigInt(raw);
  if (ticks === BigInt(0)) return null;
  const ms = Number(ticks / BigInt(10000)) - 11644473600000;
  const date = new Date(ms + 9 * 3600 * 1000);
  if (Number.isNaN(date.getTime())) return null;
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${pad(date.getUTCMilliseconds(), 3)}`;
}

function spacedHex(hex: string): string {
  return (hex.match(/.{1,2}/g) ?? []).join(" ").toUpperCase();
}

export type ValueKind = "text" | "lines" | "number" | "time" | "binary" | "empty" | "error";

export interface FormattedValue {
  kind: ValueKind;
  primary: string;
  /** Raw form when `primary` is decoded (FILETIME count). */
  secondary?: string;
  /** REG_MULTI_SZ items. */
  lines?: string[];
}

/** One value for list/detail. Reads `value_preview` (list) or
 *  `value_data_text` (detail) and the hex preview. */
export function formatRegistryValue(row: Cells): FormattedValue {
  const status = row.value_read_status;
  if (status === "error") return { kind: "error", primary: row.value_read_error || "읽기 실패" };
  const length = Number(row.value_data_length ?? 0);
  if (status === "empty" || length === 0) return { kind: "empty", primary: "" };
  const text = row.value_data_text ?? row.value_preview ?? "";
  const hex = row.value_data_hex ?? row.value_hex_preview ?? "";
  const type = row.value_type_name ?? "";
  switch (type) {
    case "REG_SZ":
    case "REG_EXPAND_SZ":
    case "REG_LINK":
      return { kind: "text", primary: text };
    case "REG_MULTI_SZ": {
      try {
        const parsed: unknown = JSON.parse(text);
        if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) return { kind: "lines", primary: parsed.join(" · "), lines: parsed };
      } catch {
        // Stored text that is not a JSON list stays as it is.
      }
      return { kind: "text", primary: text };
    }
    case "REG_DWORD":
    case "REG_DWORD_BIG_ENDIAN":
    case "REG_QWORD":
      if (/^\d+$/.test(text)) {
        const width = type === "REG_QWORD" ? 16 : 8;
        return { kind: "number", primary: `0x${BigInt(text).toString(16).toUpperCase().padStart(width, "0")} (${text})` };
      }
      return { kind: "text", primary: text };
    case "REG_FILETIME": {
      const time = filetimeToKst(text);
      return time ? { kind: "time", primary: time, secondary: text } : { kind: "text", primary: text };
    }
    default:
      return { kind: "binary", primary: spacedHex(hex) };
  }
}

export const QUICK_SECTIONS = [
  { key: "settings", label: "설정" },
  { key: "records", label: "기록" },
] as const;

export const QUICK_GROUPS = [
  { key: "autorun", label: "자동 실행", section: "settings" },
  { key: "security", label: "보안·자격 증명", section: "settings" },
  { key: "remote", label: "원격·공유", section: "settings" },
  { key: "activity", label: "사용자 활동", section: "records" },
  { key: "archive", label: "압축 기록", section: "records" },
  { key: "install", label: "설치 프로그램", section: "records" },
  { key: "shimcache", label: "ShimCache", section: "records" },
  { key: "other", label: "기타", section: "records" },
] as const;
export type QuickGroupKey = (typeof QUICK_GROUPS)[number]["key"];

const ACTIVITY_SUBTYPES = new Set(["RecentDocs", "RunMRU", "TypedPaths", "TypedURLs", "WordWheelQuery"]);
// RecentDocs extension subkeys that hold archives.
const ARCHIVE_EXTENSIONS = new Set([".zip", ".7z", ".rar", ".alz", ".egg", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zipx", ".cab"]);

/** Quick access group (docs-06) from the stored category/subtype. */
export function quickGroupOf(finding: Cells): QuickGroupKey {
  const category = finding.category ?? "";
  const subtype = finding.subtype ?? "";
  if (subtype === "ShimCache") return "shimcache";
  if (subtype === "BandizipRecentArchive") return "archive";
  if (subtype === "RecentDocs" && ARCHIVE_EXTENSIONS.has((finding.key_path ?? "").split("\\").pop()?.toLowerCase() ?? "")) return "archive";
  if (ACTIVITY_SUBTYPES.has(subtype)) return "activity";
  if (category === "자동 실행") return "autorun";
  if (category === "자격 증명 보호" || category === "보안 설정") return "security";
  if (category === "공유 폴더" || category === "SQL 인증" || category === "원격 접속" || category.includes("Sysinternals")) return "remote";
  if (category.startsWith("설치 프로그램")) return "install";
  return "other";
}

/** Value data loaded past the detail cap, owned by one value. */
export interface ValueChunks {
  recordId: string;
  hex: string;
  text: string;
  loading: boolean;
  error: string | null;
}

export function emptyValueChunks(recordId: string): ValueChunks {
  return { recordId, hex: "", text: "", loading: false, error: null };
}

/** Appends a chunk only to the value and position it was requested for;
 *  late or repeated answers return `state` unchanged. */
export function applyValueChunk(state: ValueChunks, request: { recordId: string; field: "hex" | "text"; extraLength: number }, data: string): ValueChunks {
  if (state.recordId !== request.recordId || state[request.field].length !== request.extraLength) return state;
  return { ...state, [request.field]: state[request.field] + data, loading: false, error: null };
}

const RESOLUTION: Record<string, string> = {
  exact_value: "값",
  exact_key: "키",
  parent_key: "상위 키",
  ancestor_key: "가까운 상위 키",
  ambiguous: "후보 여러 개",
  unresolved: "위치 미확인",
  unavailable: "확인 불가",
  missing_hive: "하이브 미수집",
};

export function resolutionLabel(resolution: string | undefined): string {
  return (resolution && RESOLUTION[resolution]) || resolution || "";
}

export function isNavigable(resolution: string | undefined): boolean {
  return resolution === "exact_value" || resolution === "exact_key" || resolution === "parent_key" || resolution === "ancestor_key";
}

const SYSTEM_HIVES = new Set(["SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT", "COMPONENTS", "DRIVERS", "ELAM", "BBI", "BCD-TEMPLATE", "USERDIFF"]);
const USER_HIVE = /^(.*)_(NTUSER\.DAT|UsrClass\.dat)$/i;

/** "Administrator_NTUSER.DAT" → owner + file; other hives keep their name. */
export function hiveLabel(hiveName: string): { name: string; owner: string | null } {
  const match = hiveName.match(USER_HIVE);
  return match ? { name: match[2], owner: match[1] } : { name: hiveName, owner: null };
}

interface HiveLike {
  hiveId: string;
  hiveName: string;
  isRegback: boolean;
}

/** System · user · other · RegBack sections, stored order inside each. */
export function hiveGroups<T extends HiveLike>(hives: T[]): { title: string; hives: T[] }[] {
  const sections: { title: string; test: (hive: T) => boolean }[] = [
    { title: "시스템", test: (hive) => !hive.isRegback && SYSTEM_HIVES.has(hive.hiveName.toUpperCase()) },
    { title: "사용자", test: (hive) => !hive.isRegback && (USER_HIVE.test(hive.hiveName) || /^(NTUSER\.DAT|UsrClass\.dat)$/i.test(hive.hiveName)) },
    { title: "기타", test: (hive) => !hive.isRegback },
    { title: "RegBack", test: (hive) => hive.isRegback },
  ];
  const taken = new Set<string>();
  return sections
    .map(({ title, test }) => {
      const list = hives.filter((hive) => !taken.has(hive.hiveId) && test(hive));
      list.forEach((hive) => taken.add(hive.hiveId));
      return { title, hives: list };
    })
    .filter((section) => section.hives.length > 0);
}

export const SEARCH_FIELD_LABELS: Record<string, string> = {
  key: "키 경로",
  value_name: "값 이름",
  value_data: "값 데이터",
  value_hex: "16진",
};
