import { resolveArtifactView } from "./artifactViews";
import type { CategoryEntry, TimelineEntry } from "./types";

// Hand control back to the event loop so pending clicks/renders are processed
// mid-build. MessageChannel isn't subject to setTimeout's 4ms nested clamp, so
// it yields cheaply; fall back to setTimeout where it's unavailable.
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof MessageChannel === "undefined") {
      setTimeout(resolve, 0);
      return;
    }
    const ch = new MessageChannel();
    ch.port1.onmessage = () => {
      ch.port1.close();
      resolve();
    };
    ch.port2.postMessage(0);
  });
}

// Rows processed between yields. Big enough that the per-yield overhead stays
// negligible, small enough that the UI never freezes for more than a frame.
const YIELD_EVERY = 8000;

// Only files whose artifactViews.ts spec declares timelineField are included —
// the project's curated "this artifact matters for analysis" list. Most
// _OVERVIEW correlations are excluded (no timelineField) because they'd
// double-count the raw artifacts they derive from. The one exception is
// ExecutionHistory: it's the ONLY source of a timestamp for SRUM (first
// sighting), AppCompatCache/ShimCache, BAM and UserAssist — none of which have
// a raw table of their own — so it opts in, and the raw Amcache/Prefetch specs
// drop their timelineField so they don't appear twice. EventLog is now one
// table per source .evtx with an arbitrary name, resolved by columns after a
// read.
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
      let sinceYield = 0;
      for (const row of data.rows) {
        const timestamp = (row[timelineField] ?? "").trim();
        // A timeline has no defensible position for a record without a time.
        // Do not allocate/render it only to sink it below chronological data.
        if (timestamp && (spec.timelineInclude?.(row) ?? true)) {
          entries.push({
            timestamp,
            category: category.name,
            table: file.name,
            // The timeline names the event itself (for ScheduledTasks, the
            // task name), while a detail panel may use an evidence-type title.
            summary: (spec.timelineTitle ?? spec.title)(row),
            subtitle: (spec.timelineSubtitle ?? spec.subtitle)?.(row) ?? "",
            tags: spec.tags?.(row) ?? [],
            rowid: Number((row as unknown as Record<string, unknown>).__rowid),
            fullPath: file.fullPath,
            row,
            columns: data.columns,
          });
        }
        // Big tables (EventLog can be ~700k rows) would otherwise block the
        // renderer's single thread for seconds; yield so the UI stays live.
        if (++sinceYield >= YIELD_EVERY) {
          sinceYield = 0;
          await yieldToEventLoop();
        }
      }
    }
  }

  // Plain string compare works because every timestamp is already
  // formatted YYYY-MM-DD hh:mm:ss.fff by the parser — lexicographic order
  // is chronological order. Rows without timestamps were excluded above.
  await yieldToEventLoop(); // let queued UI events through before the big sort
  entries.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  return entries;
}
