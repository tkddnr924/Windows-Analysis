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
// Thrown when the caller aborts an in-flight build (e.g. the analyst navigates
// away from the timeline tab). Lets the caller distinguish a cancel from a real
// failure and simply drop the partial result.
export class TimelineBuildAborted extends Error {
  constructor() {
    super("timeline build aborted");
    this.name = "TimelineBuildAborted";
  }
}


// 워커에서 캐시 디코딩·JSON 파싱·보강을 수행한다. 입력 버퍼는 transferable로
// zero-copy 이동하고, 결과는 청크로 나눠 받으므로 메인 스레드는 짧은 수신
// 처리만 한다. builtForRunAt이 다르면(오래된 캐시) null, 워커 생성이 불가하면
// 예외를 던져 호출부가 메인 스레드 폴백을 타게 한다.
export function loadCachedTimelineInWorker(
  buffer: ArrayBuffer,
  builtForRunAt: string,
  signal?: AbortSignal,
): Promise<TimelineEntry[] | null> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./timelineCacheLoader.worker.ts", import.meta.url));
    const collected: TimelineEntry[] = [];
    const cleanup = () => {
      worker.terminate();
      signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(new TimelineBuildAborted());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.onmessage = (
      event: MessageEvent<{ type: "chunk" | "done" | "miss"; entries?: TimelineEntry[] }>,
    ) => {
      if (event.data.type === "chunk" && event.data.entries) {
        collected.push(...event.data.entries);
        return;
      }
      cleanup();
      resolve(event.data.type === "done" ? collected : null);
    };
    worker.onerror = () => {
      cleanup();
      reject(new Error("timeline cache worker failed"));
    };
    worker.postMessage({ buffer, builtForRunAt }, [buffer]);
  });
}

// The parse pipeline writes the timeline cache with raw rows only — the
// presentation strings and tags come from the TS specs, which stay the single
// source of wording. This fills them in on load, chunked so the UI stays live.
// Entries built in the viewer already carry tags and pass through unchanged.
export async function enrichCachedTimeline(
  entries: TimelineEntry[],
  signal?: AbortSignal,
): Promise<TimelineEntry[]> {
  if (!entries.length || entries[0].tags !== undefined) return entries;
  let sinceYield = 0;
  for (const entry of entries) {
    const spec = resolveArtifactView(entry.table, entry.columns);
    if (spec) {
      entry.summary = (spec.timelineTitle ?? spec.title)(entry.row);
      entry.subtitle = (spec.timelineSubtitle ?? spec.subtitle)?.(entry.row) ?? "";
    }
    entry.tags = spec?.tags?.(entry.row) ?? [];
    if (++sinceYield >= YIELD_EVERY) {
      sinceYield = 0;
      await yieldToEventLoop();
      if (signal?.aborted) throw new TimelineBuildAborted();
    }
  }
  return entries;
}

export async function buildMasterTimeline(
  categories: CategoryEntry[],
  signal?: AbortSignal,
): Promise<TimelineEntry[]> {
  const entries: TimelineEntry[] = [];
  const throwIfAborted = () => {
    if (signal?.aborted) throw new TimelineBuildAborted();
  };

  for (const category of categories) {
    throwIfAborted();
    const files = await window.api.listResultFiles(category.fullPath);
    for (const file of files) {
      throwIfAborted();
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
        // renderer's single thread for seconds; yield so the UI stays live, and
        // stop promptly if the analyst has already navigated away.
        if (++sinceYield >= YIELD_EVERY) {
          sinceYield = 0;
          await yieldToEventLoop();
          throwIfAborted();
        }
      }
    }
  }

  // Plain string compare works because every timestamp is already
  // formatted YYYY-MM-DD hh:mm:ss.fff by the parser — lexicographic order
  // is chronological order. Rows without timestamps were excluded above.
  await yieldToEventLoop(); // let queued UI events through before the big sort
  throwIfAborted(); // don't spend seconds sorting a result nobody is waiting for
  entries.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  return entries;
}
