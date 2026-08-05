import { resolveArtifactView } from "./artifactViews";
import type { CategoryEntry, TimelineEntry } from "./types";

// Only files whose artifactViews.ts spec declares timelineField are
// included — that's the project's own curated "this artifact matters for
// analysis" list, so the _OVERVIEW correlation tables (already-derived, would
// double-count) are excluded. EventLog is now one table per source .evtx with
// an arbitrary name, so those are resolved by their columns after a read.
export async function buildMasterTimeline(categories: CategoryEntry[]): Promise<TimelineEntry[]> {
  const entries: TimelineEntry[] = [];

  for (const category of categories) {
    const files = await window.api.listResultFiles(category.fullPath);
    for (const file of files) {
      // A named spec is known up-front; an unnamed table (per-file EventLog)
      // needs its columns, so read it and resolve by column shape.
      let spec = resolveArtifactView(file.name);
      let data = spec ? null : await window.api.readResultFile(file.fullPath, file.tableName);
      if (!spec) spec = resolveArtifactView(file.name, data!.columns);
      if (!spec?.timelineField) continue;

      if (!data) data = await window.api.readResultFile(file.fullPath, file.tableName);
      const timelineField = spec.timelineField;
      for (const row of data.rows) {
        entries.push({
          timestamp: row[timelineField] ?? "",
          category: category.name,
          table: file.name,
          summary: spec.title(row),
          subtitle: spec.subtitle?.(row) ?? "",
          tags: spec.tags?.(row) ?? [],
          rowid: Number((row as unknown as Record<string, unknown>).__rowid),
          fullPath: file.fullPath,
          row,
          columns: data.columns,
        });
      }
    }
  }

  // Plain string compare works because every timestamp is already
  // formatted YYYY-MM-DD hh:mm:ss.fff by the parser — lexicographic order
  // is chronological order. Rows with no timestamp value (empty string)
  // sort last rather than being dropped from the merged view.
  entries.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  return entries;
}
