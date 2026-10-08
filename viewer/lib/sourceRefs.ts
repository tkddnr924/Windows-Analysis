import type { Bookmark } from "./types";

/**
 * Coordinates of the raw evidence record a result row was derived from.
 * Contract (docs-01) rows are not bookmark targets, so bookmark state is always
 * matched on these source coordinates — never on a derived record_id and never
 * by guessing a file name.
 *
 * The backend attaches `__source_refs` (the JSON string form of this array) to
 * every primary contract row, containing host-root-verified paths only.
 */
export interface SourceRef {
  fullPath: string;
  tableName: string;
  rowid: number;
}

/** Separators and case differ per platform; normalise once before comparing. */
function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

/**
 * Identity of one bookmark. The field is part of the key, so a whole-row
 * bookmark and a per-timestamp bookmark on the same record never collide.
 */
export function sourceRefKey(fullPath: string, tableName: string, rowid: number, field?: string): string {
  return `${normalizePath(fullPath)}\u0000${tableName.trim().toLowerCase()}\u0000${rowid}\u0000${field ?? ""}`;
}

/** Reads a row's `__source_refs`. Missing or malformed values mean "no refs". */
export function parseSourceRefs(raw: unknown): SourceRef[] {
  if (typeof raw !== "string" || !raw.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const refs: SourceRef[] = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object") continue;
    const { fullPath, tableName, rowid } = entry as Record<string, unknown>;
    // An unverified path cannot be a bookmark target, so drop the entry.
    if (typeof fullPath !== "string" || !fullPath) continue;
    if (typeof tableName !== "string" || !tableName) continue;
    const row = typeof rowid === "number" ? rowid : Number(rowid);
    if (!Number.isSafeInteger(row)) continue;
    refs.push({ fullPath, tableName, rowid: row });
  }
  return refs;
}

/** Bookmark identities of one host, for display comparisons. */
export function bookmarkRefKeys(bookmarks: Bookmark[]): Set<string> {
  return new Set(bookmarks.map((bookmark) => sourceRefKey(bookmark.fullPath, bookmark.tableName, bookmark.rowid, bookmark.field)));
}

/**
 * Whether this row shows as bookmarked: its own coordinates are bookmarked, or
 * one of the source records it points at is. Raw rows carry no refs and match
 * on themselves. Pass `field` to check a single timestamp bookmark.
 */
export function isRecordBookmarked(
  keys: Set<string>,
  self: { fullPath: string; tableName: string; rowid: number },
  refs: SourceRef[],
  field?: string,
): boolean {
  if (keys.has(sourceRefKey(self.fullPath, self.tableName, self.rowid, field))) return true;
  return refs.some((ref) => keys.has(sourceRefKey(ref.fullPath, ref.tableName, ref.rowid, field)));
}
