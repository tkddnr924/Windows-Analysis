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
