import { resolveArtifactView } from "./artifactViews";
import { browsableResultFiles } from "./resultTables";
import { executionSourceKey, browserActivityKindKey } from "./timelineKeys";
import { createCrossViewDeduper, orderTimelineFiles } from "./timelineSources";
import type { CategoryEntry, TimelineSourcePage } from "./types";

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

// 백엔드 TIMELINE_LOGIC_VERSION(main.rs)과 동기화한다 — 구조 로직(필터키·검색
// blob·include 규칙·원본 식별자)이 바뀌면 양쪽을 올려 기존 캐시를
// 무효화(재빌드)한다. 3 = 저장 계약(docs-01) 전환: 파생 행은 record_id로
// 식별하고 원본 포인터는 source_records에 있다. 4 = docs-18: _OVERVIEW만 입력,
// 여러 뷰가 연결한 같은 원본 사건은 한 번만. 5 = 입력을 6개 뷰로 제한. 6 = 브라우저 방문·다운로드 추가.
export const TIMELINE_LOGIC_VERSION = 6;

// 소스 테이블을 페이지로 읽는 청크 크기. 이 청크 하나가 빌드 중 프런트 메모리
// 피크의 상한이다(전체 테이블을 한 번에 올리지 않는다).
const READ_CHUNK = 20000;
// 백엔드로 한 번에 insert하는 행 수 — IPC 왕복과 트랜잭션 크기의 균형.
const INSERT_BATCH = 5000;
// insert 청크 바이트 상한(백엔드 8MB 한도 아래). EventLog의 큰 EventData
// 행이 배치를 부풀려 거부되지 않도록 행 수와 함께 이 값에서도 flush한다.
const MAX_INSERT_BATCH_BYTES = 4 * 1024 * 1024;

// Thrown when the caller aborts an in-flight build (e.g. the analyst navigates
// away from the timeline tab). Lets the caller distinguish a cancel from a real
// failure and simply drop the partial result.
export class TimelineBuildAborted extends Error {
  constructor() {
    super("timeline build aborted");
    this.name = "TimelineBuildAborted";
  }
}

// 각 결과 테이블을 페이지 청크로 읽어 TS 스펙으로 변환하고, 경량 행 + 검색용
// 원본값(search_blob) + 원본행(row_json)을 백엔드 sqlite로 스트리밍 insert한다.
// 정렬은 SQL 인덱스가 담당하므로 프런트에서 전체 배열을 만들지 않는다 —
// 피크 메모리는 청크 1개. 완료되면 백엔드가 인덱스를 만들고 원자 rename한다.
export async function streamBuildTimeline(
  categories: CategoryEntry[],
  hostDir: string,
  builtForRunAt: string,
  signal?: AbortSignal,
): Promise<void> {
  const throwIfAborted = () => {
    if (signal?.aborted) throw new TimelineBuildAborted();
  };
  const token = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  await window.api.masterTimelineBuildBegin(hostDir, token, builtForRunAt);
  try {
    let batch: string[] = [];
    let batchBytes = 0;
    const flush = async () => {
      if (!batch.length) return;
      await window.api.masterTimelineBuildInsert(hostDir, token, batch.join("\n"));
      await window.api.masterTimelineBuildDrain(token);
      batch = [];
      batchBytes = 0;
    };
    let sinceYield = 0;
    // docs-18: _OVERVIEW only; raw facts are evidence behind source_records.
    const admit = createCrossViewDeduper();
    for (const category of categories.filter((entry) => entry.name === "_OVERVIEW")) {
      throwIfAborted();
      // 상세 전용 자식 표(source_records·ExecutionTimes…)는 사건 행이 아니다.
      const files = orderTimelineFiles(
        browsableResultFiles(await window.api.listResultFiles(category.fullPath))
          .filter((file) => resolveArtifactView(file.name)?.timelineField),
      );
      for (const [fileIndex, file] of files.entries()) {
        throwIfAborted();
        const spec = resolveArtifactView(file.name);
        if (!spec?.timelineField) continue;
        const timelineField = spec.timelineField;
        const group = file.name;
        const remember = fileIndex < files.length - 1;
        let offset: number | null = 0;
        // eslint-disable-next-line no-constant-condition
        while (true) {
          throwIfAborted();
          const page: TimelineSourcePage = await window.api.timelineSourcePage(file.fullPath, file.tableName, offset ?? 0, READ_CHUNK);
          if (!page.rows.length) break;
          for (const row of page.rows) {
            const ts = (row[timelineField] ?? "").trim();
            // A timeline has no defensible position for a record without a time.
            if (!ts || !(spec.timelineInclude?.(row) ?? true)) continue;
            if (!admit(file.name, ts, row, remember)) continue;
            const filterKey =
              file.name === "ExecutionHistory"
                ? executionSourceKey(row)
                : file.name === "BrowserActivity"
                  ? browserActivityKindKey(row)
                  : "";
            const line = JSON.stringify({
              ts,
              category: category.name,
              source_table: file.name,
              artifact_group: group,
              filter_key: filterKey,
              has_tags: (spec.tags?.(row) ?? []).length ? 1 : 0,
              full_path: file.fullPath,
              rowid_src: Number((row as unknown as Record<string, unknown>).__rowid) || 0,
              // 파생 행의 식별자는 record_id, 원본 근거는 그 DB의 source_records.
              record_id: row.record_id || "",
              event_time: row.timestamp || "",
              // 행 사본(row_json)과 검색 문자열(search_blob)은 보내지 않는다 —
              // 같은 증거를 두 벌 더 만들어 IPC로 나르면 원본보다 큰 payload가
              // 된다. 백엔드가 full_path+rowid로 원본에서 직접 만든다.
            });
            batch.push(line);
            batchBytes += line.length + 1;
            if (batch.length >= INSERT_BATCH || batchBytes >= MAX_INSERT_BATCH_BYTES) await flush();
            // Big tables (UsnJournal can be ~350k rows) would block the renderer's
            // single thread; yield so the UI stays live and abort stays prompt.
            if (++sinceYield >= YIELD_EVERY) {
              sinceYield = 0;
              await yieldToEventLoop();
              throwIfAborted();
            }
          }
          // 페이지는 행 수 또는 바이트 예산 중 먼저 걸리는 쪽에서 끊긴다 —
          // 짧은 페이지를 테이블 끝으로 오해하면 증거가 누락되므로, 종료는
          // 백엔드가 알려주는 nextOffset으로만 판단한다.
          if (page.nextOffset === null) break;
          offset = page.nextOffset;
        }
      }
    }
    await flush();
    await window.api.masterTimelineBuildFinish(hostDir, token);
  } catch (error) {
    await window.api.masterTimelineBuildAbort(hostDir, token).catch(() => {});
    throw error;
  }
}
