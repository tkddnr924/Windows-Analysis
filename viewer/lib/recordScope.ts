import { createContext } from "react";

/**
 * Coordinates of the result row the screen is showing. Under the storage
 * contract (docs-01) a derived row is identified by record_id and its evidence
 * lives in that DB's source_records, so the shared detail panel needs to know
 * which file/table/row it is looking at. It never infers a `<table>::<rowid>`
 * pointer from row values.
 *
 * The rowid is read from the row's __rowid, so only file and table live here.
 */
export interface RecordScope {
  fullPath: string;
  tableName: string;
  /** Opens a source record in the result view; omitted = display only. */
  openRecord?: (fullPath: string, tableName: string, rowid: number) => void;
  /**
   * Bookmarks a source record. Bookmarks only ever target raw evidence rows,
   * so when a derived row has several origins the analyst picks one here — the
   * UI never chooses a representative origin.
   */
  bookmarkSource?: (fullPath: string, tableName: string, rowid: number) => void;
  isSourceBookmarked?: (fullPath: string, tableName: string, rowid: number) => boolean;
}

export const RecordScopeContext = createContext<RecordScope | null>(null);
