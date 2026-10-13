// Row jumps ("open source record", search hits) into a DataTable.

/** A filter queued for one table, identified by fullPath + tableName. */
export interface PendingFilter {
  tableKey: string;
  column: string;
  value: string;
}

/** The pending filter, only when it targets this table. */
export function pendingFilterFor(pending: PendingFilter | null, tableKey: string): PendingFilter | null {
  return pending && pending.tableKey === tableKey ? pending : null;
}

export const ROWID_COLUMN = "__rowid";

/** Target rowid of an active exact __rowid filter. */
export function rowidFilterValue(filters: readonly { id: string; value: unknown }[]): string | null {
  for (const filter of filters) {
    if (filter.id !== ROWID_COLUMN || !filter.value || typeof filter.value !== "object") continue;
    const { mode, value } = filter.value as { mode?: unknown; value?: unknown };
    if (mode === "exact" && typeof value === "string" && value) return value;
  }
  return null;
}

export type RowidJumpState = "loaded" | "lookup" | "missing";

/** Whether the target row is resident, must be fetched, or does not exist. */
export function rowidJumpState(rows: readonly Record<string, string>[], rowid: string, fullyLoaded: boolean): RowidJumpState {
  if (rows.some((row) => String(row[ROWID_COLUMN] ?? "") === rowid)) return "loaded";
  return fullyLoaded ? "missing" : "lookup";
}

/** Appends a fetched jump row while it is the active target and not resident. */
export function rowsWithJumpRow<T extends Record<string, string>>(
  rows: T[],
  rowid: string | null,
  fetched: { rowid: string; row: T } | null,
): T[] {
  if (!rowid || !fetched || fetched.rowid !== rowid) return rows;
  if (rows.some((row) => String(row[ROWID_COLUMN] ?? "") === rowid)) return rows;
  return [...rows, fetched.row];
}
