import type { AccountDirectoryEntry } from "./types";

export type AccountDirectory = Readonly<Record<string, string>>;

// Resolve only a complete SID token. URLs, EventData JSON, paths and compound
// values must remain exact evidence text rather than receiving a guessed label.
const EXACT_SID = /^S-\d+(?:-\d+)+$/i;

export function isExactSid(value: string | null | undefined): boolean {
  return Boolean(value && EXACT_SID.test(value.trim()));
}

export function accountDirectoryFromEntries(entries: AccountDirectoryEntry[]): AccountDirectory {
  const directory: Record<string, string> = {};
  for (const entry of entries) {
    const sid = entry.sid.trim();
    const accountName = entry.accountName.trim();
    if (!isExactSid(sid) || !accountName || accountName.toLowerCase() === sid.toLowerCase()) continue;
    directory[sid.toLowerCase()] = accountName;
  }
  return directory;
}

/** Returns an analyst-readable name for a mapped exact SID; otherwise preserves
 * the raw input. This makes partial TargetInfo data safe and non-deceptive. */
export function resolveAccountDisplay(value: string | null | undefined, directory?: AccountDirectory): string {
  if (!value || !isExactSid(value)) return value ?? "";
  return directory?.[value.trim().toLowerCase()] ?? value;
}

/** SOFTWARE·SYSTEM 하이브에서 나온 레지스트리 항목의 계정 자리값. 특정 사용자
 * 계정이 아니라 컴퓨터 전역(HKLM) 설정이라는 뜻이므로, NT AUTHORITY\SYSTEM
 * 계정으로 오해되지 않도록 표시 문구를 분리한다. 저장된 원본 값은 그대로 두고
 * 화면 표기만 바꾼다(기존 증거 DB 호환). */
export const MACHINE_SCOPE_USER = "(시스템)";
export const MACHINE_SCOPE_LABEL = "시스템 전역";

/** 계정 컬럼 표시값 — 시스템 전역 자리값을 먼저 걸러내고, 나머지는 SID 해석. */
export function resolveUserDisplay(value: string | null | undefined, directory?: AccountDirectory): string {
  if ((value ?? "").trim() === MACHINE_SCOPE_USER) return MACHINE_SCOPE_LABEL;
  return resolveAccountDisplay(value, directory);
}
