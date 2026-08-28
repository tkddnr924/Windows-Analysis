// 통합 타임라인 캐시 로더 — 워커 스레드에서 디코딩·JSON 파싱·문구/태그 보강을
// 수행해 메인 윈도우(렌더러)가 멈추지 않게 한다. 입력은 zero-copy로 넘어온
// ArrayBuffer, 출력은 청크 단위로 나눠 보내 메인 스레드의 구조 복제가 한 번에
// 길게 블록되지 않게 한다.
import { resolveArtifactView } from "./artifactViews";
import type { TimelineEntry } from "./types";

export type TimelineLoaderRequest = {
  buffer: ArrayBuffer;
  builtForRunAt: string;
};

export type TimelineLoaderResponse =
  | { type: "chunk"; entries: TimelineEntry[] }
  | { type: "done" }
  | { type: "miss" };

const CHUNK = 5_000;

self.onmessage = (event: MessageEvent<TimelineLoaderRequest>) => {
  const { buffer, builtForRunAt } = event.data;
  const post = (message: TimelineLoaderResponse) =>
    (self as unknown as Worker).postMessage(message);
  try {
    const raw = new TextDecoder().decode(buffer);
    const cached = JSON.parse(raw) as { builtForRunAt?: string; entries?: TimelineEntry[] };
    if (cached.builtForRunAt !== builtForRunAt || !Array.isArray(cached.entries)) {
      post({ type: "miss" });
      return;
    }
    const entries = cached.entries;
    // 파서가 만든 캐시는 원본 행만 담는다 — 표시 문구와 의심 태그는 TS 스펙이
    // 정의하므로 여기서 채운다. 이미 보강된 캐시(뷰어 빌드본)는 그대로 통과.
    if (entries.length > 0 && (entries[0] as { tags?: unknown }).tags === undefined) {
      for (const entry of entries) {
        const spec = resolveArtifactView(entry.table, entry.columns);
        if (spec) {
          entry.summary = (spec.timelineTitle ?? spec.title)(entry.row);
          entry.subtitle = (spec.timelineSubtitle ?? spec.subtitle)?.(entry.row) ?? "";
        }
        entry.tags = spec?.tags?.(entry.row) ?? [];
      }
    }
    for (let start = 0; start < entries.length; start += CHUNK) {
      post({ type: "chunk", entries: entries.slice(start, start + CHUNK) });
    }
    post({ type: "done" });
  } catch {
    post({ type: "miss" });
  }
};
