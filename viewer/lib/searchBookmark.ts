import type { Bookmark, Host, SearchHit } from "./types";

function normalizedPath(value: string): string {
  return value.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
}

/** True only when the complete path is within a host directory, not merely
 * when the two strings share a prefix (for example `host-a` vs `host-a-copy`). */
export function pathBelongsToHostSegmentSafe(fullPath: string, hostDir: string): boolean {
  const path = normalizedPath(fullPath);
  const root = normalizedPath(hostDir);
  return path === root || path.startsWith(`${root}/`);
}

/**
 * A legacy bookmark has no hostId. Source-record bookmark matching may use it
 * only after its persisted path proves that it belongs to the search hit's
 * authoritative host. Direct search-hit matching already compares fullPath.
 */
export function searchHitHostMatchesSourceBookmark(hit: SearchHit, bookmark: Bookmark, hosts: Host[]): boolean {
  if (bookmark.hostId) return Boolean(hit.hostId) && bookmark.hostId === hit.hostId;
  if (!hit.hostId) return false;
  const host = hosts.find((candidate) => candidate.id === hit.hostId);
  return Boolean(host && pathBelongsToHostSegmentSafe(bookmark.fullPath, host.dir));
}
