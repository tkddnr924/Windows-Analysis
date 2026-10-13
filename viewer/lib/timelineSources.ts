// Master timeline inputs (docs-18): _OVERVIEW tables only. A raw event linked
// from several views is shown once — by the first view read — while one
// view's own records over a shared source stay distinct. No runtime imports
// (Node tests).

// Timeline inputs and read order (user-confirmed 2026-10-13, for speed).
// ExecutionHistory first so shared execution events stay there. BrowserActivity
// enters through its timelineInclude (visit/download, no cache).
const TIMELINE_FILE_ORDER = [
  "ExecutionHistory",
  "BrowserActivity",
  "RemoteDesktopHistory",
  "Defender",
  "WerReports",
  "TimelineActivities",
  "JumpListEntries",
];

/** Allowed timeline files in read order; anything else is not an input. */
export function orderTimelineFiles<F extends { name: string }>(files: F[]): F[] {
  return TIMELINE_FILE_ORDER.flatMap((name) => files.filter((file) => file.name === name));
}

/** Source coordinate keys of a row's `__source_refs` (host-verified paths). */
function sourceKeys(raw: unknown): string[] {
  if (typeof raw !== "string" || !raw.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const keys: string[] = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object") continue;
    const { fullPath, tableName, rowid } = entry as Record<string, unknown>;
    if (typeof fullPath !== "string" || typeof tableName !== "string") continue;
    const path = fullPath.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
    keys.push(`${path}\u0000${tableName.trim().toLowerCase()}\u0000${String(rowid)}`);
  }
  return keys;
}

/**
 * admit(view, ts, row, remember): false when another view already showed one of
 * the row's sources at ts. `remember=false` (the last file read) skips storing.
 */
export function createCrossViewDeduper() {
  const shownBy = new Map<string, string>();
  return (view: string, ts: string, row: Record<string, unknown>, remember = true): boolean => {
    const keys = sourceKeys(row.__source_refs).map((key) => `${key}\u0000${ts}`);
    if (keys.some((key) => (shownBy.get(key) ?? view) !== view)) return false;
    if (remember) for (const key of keys) if (!shownBy.has(key)) shownBy.set(key, view);
    return true;
  };
}
