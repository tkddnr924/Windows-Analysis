import type { Bookmark } from "./types";

// docs-20: bookmark identity = _OVERVIEW table + record_id + optional field.
export const bookmarkKey = (tableName: string, recordId: string, field?: string): string =>
  `${tableName}\u0000${recordId}\u0000${field ?? ""}`;

export function bookmarkKeys(bookmarks: Bookmark[]): Set<string> {
  return new Set(bookmarks.map((bookmark) => bookmarkKey(bookmark.tableName, bookmark.recordId, bookmark.field)));
}

// Record-level identity: true when any field (or the record) is bookmarked.
export const bookmarkRecordKey = (tableName: string, recordId: string): string => `${tableName}\u0000${recordId}`;

export function bookmarkRecordKeys(bookmarks: Pick<Bookmark, "tableName" | "recordId" | "field">[]): Set<string> {
  return new Set(bookmarks.map((bookmark) => bookmarkRecordKey(bookmark.tableName, bookmark.recordId)));
}
