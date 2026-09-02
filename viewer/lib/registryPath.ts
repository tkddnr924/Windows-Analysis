// 오프라인 하이브를 직접 파싱하면 경로 첫 구간이 라이브 마운트 지점이 아니라
// 하이브 파일 안에 기록된 루트 키 이름(`CMI-CreateHive{GUID}`,
// `S-1-5-…_Classes` 등)으로 나온다. 분석가가 읽는 위치 그대로 보이도록
// 표시할 때만 마운트 지점으로 치환한다 — 저장된 원본 key_path는 건드리지 않는다.

/** 하이브 파일 이름 → 라이브 레지스트리 마운트 지점. */
const HIVE_MOUNTS: [RegExp, string][] = [
  [/^SOFTWARE$/i, "HKLM\\SOFTWARE"],
  [/^SYSTEM$/i, "HKLM\\SYSTEM"],
  [/^SAM$/i, "HKLM\\SAM"],
  [/^SECURITY$/i, "HKLM\\SECURITY"],
  [/^COMPONENTS$/i, "HKLM\\COMPONENTS"],
  [/^DEFAULT$/i, "HKU\\.DEFAULT"],
  [/(?:^|_)NTUSER\.DAT$/i, "HKCU"],
  [/(?:^|_)USRCLASS\.DAT$/i, "HKCU\\Software\\Classes"],
];

// 하이브 루트 키 이름으로 확인된 형태만 치환 대상으로 삼는다. 평범한 키 이름
// (`\Software\…`)을 마운트 지점으로 잘못 갈아치우지 않기 위한 안전장치.
const HIVE_ROOT_FORMS: RegExp[] = [
  /^CMI-CreateHive\{[0-9A-Fa-f-]+\}$/,
  /^CsiTool-CreateHive-?\{?[0-9A-Fa-f-]+\}?$/,
  /^\{[0-9A-Fa-f-]{36}\}/, // systemprofile NTUSER: `{GUID}X:/…/ntuser.dat`
  /^S-\d+(?:-\d+)+_Classes$/i,
  /^\$\$\$PROTO\.HIV$/i,
  /^ROOT$/i,
  /^(?:NTUSER\.DAT|UsrClass\.dat)$/i,
];

/** 수집 산출물 이름에서 하이브 이름만 남긴다(경로·확장자·중복 수집 접미사 제거). */
function hiveStem(hive: string): string {
  const base = hive.trim().split(/[\\/]/).pop() ?? "";
  return base
    .replace(/\.sqlite$/i, "")
    .replace(/_\d+$/, "")
    .replace(/_RegBack$/i, "");
}

/** 하이브가 라이브 레지스트리에서 붙는 위치. 모르는 하이브면 null. */
export function hiveMountPoint(hive: string | null | undefined): string | null {
  const stem = hiveStem(hive ?? "");
  if (!stem) return null;
  return HIVE_MOUNTS.find(([pattern]) => pattern.test(stem))?.[1] ?? null;
}

/** 하이브 루트 키 이름을 마운트 지점으로 바꾼 표시용 경로. 하이브를 모르거나
 * 루트 형태가 아니면(축약 경로 `…\Control\Lsa` 포함) 원본을 그대로 돌려준다. */
export function displayRegistryKeyPath(keyPath: string | null | undefined, hive: string | null | undefined): string {
  const raw = (keyPath ?? "").trim();
  if (!raw.startsWith("\\")) return raw;
  const mount = hiveMountPoint(hive);
  if (!mount) return raw;
  const rest = raw.slice(1);
  const separator = rest.indexOf("\\");
  const root = separator < 0 ? rest : rest.slice(0, separator);
  if (!HIVE_ROOT_FORMS.some((pattern) => pattern.test(root))) return raw;
  return mount + (separator < 0 ? "" : rest.slice(separator));
}
