/** Backend eligibility plus pending/error states. */
export type ParseEligibilityEntry =
  | { status: "checking" }
  | { status: "ready"; canParse: boolean; reason: string }
  | { status: "error"; message: string };

export type ParseEligibilityMap = Record<string, ParseEligibilityEntry | undefined>;

export function canStartParse(entry: ParseEligibilityEntry | undefined): boolean {
  return entry?.status === "ready" && entry.canParse;
}

export function parseBlockedLabel(entry: ParseEligibilityEntry | undefined): string | null {
  if (!entry || entry.status === "checking") return null;
  if (entry.status === "error") return entry.message || "새 데이터 여부를 확인하지 못했습니다.";
  return null;
}

/** Unchecked hosts are revalidated by the bulk-run action. */
export function allParseBlocked(hostIds: string[], map: ParseEligibilityMap): boolean {
  if (hostIds.length === 0) return true;
  return hostIds.every((hostId) => {
    const entry = map[hostId];
    return entry?.status === "ready" && !entry.canParse;
  });
}
