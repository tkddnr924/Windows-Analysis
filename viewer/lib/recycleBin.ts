// Recycle Bin view helpers: one card per stored $I record (_OVERVIEW RecycleBin).
// Sibling imports carry `.ts` so Node tests can load them.

// @ts-expect-error -- TypeScript uses bundler resolution while Node tests need the extension.
import { compareEvents, facetAllows, inScope } from "./eventOrder.ts";

type Cells = Record<string, string | undefined>;

export interface RecycleFilter {
  search: string;
  /** account_sid values. */
  accounts: string[];
}

export const DEFAULT_RECYCLE_FILTER: RecycleFilter = { search: "", accounts: [] };

/** Last segment of the original path, else the $I/$R paired name. */
export function recycleFileName(row: Cells): string {
  const last = (row.original_path ?? "").split("\\").filter(Boolean).pop();
  return last || row.recycle_name || "";
}

function matches(row: Cells, filter: RecycleFilter): boolean {
  if (!facetAllows(filter.accounts, row.account_sid)) return false;
  const needle = filter.search.trim().toLowerCase();
  return !needle || [row.original_path, row.recycle_name, row.account, row.account_sid, row.mft_path].some((value) => (value ?? "").toLowerCase().includes(needle));
}

/** In-period matching rows in time order (direction), untimed last. */
export function filterRecycleRows<R extends Cells>(rows: R[], filter: RecycleFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean, direction: "asc" | "desc"): R[] {
  return rows
    .filter((row) => inScope(row, inPeriod, periodSet) && matches(row, filter))
    .sort((a, b) => compareEvents(a, b, direction));
}
