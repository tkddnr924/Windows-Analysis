// 타임라인 파생 필터키·라벨 — 스트리밍 빌드(masterTimeline.ts)와 렌더
// 컴포넌트(MasterTimeline.tsx)가 공유한다. 빌드가 이 키를 sqlite filter_key로
// materialize하고, 렌더는 같은 라벨로 필터 메뉴를 그린다(로직 단일 소스).

export const EXECUTION_SOURCE_LABELS: Record<string, string> = {
  amcache: "Amcache",
  userassist: "UserAssist",
  prefetch: "Prefetch",
  srum: "SRUM",
  bam: "BAM",
  wer: "WER",
  other: "기타",
};

export const BROWSER_KIND_LABEL: Record<string, string> = {
  visit: "BrowserActivity:Visit",
  download: "BrowserActivity:Download",
  cache: "BrowserActivity:Cache",
  other: "BrowserActivity:기타",
};

export function executionSourceKey(row: Record<string, string>): string {
  const source = (row.source_artifact || "").trim().toLowerCase();
  if (source.startsWith("amcache")) return "amcache";
  if (source === "userassist") return "userassist";
  if (source === "prefetch") return "prefetch";
  if (source === "srum") return "srum";
  if (source === "bam") return "bam";
  if (source === "wer") return "wer";
  return "other";
}

export function browserActivityKindKey(row: Record<string, string>): string {
  const kind = (row.kind || "").trim().toLowerCase();
  if (kind === "visit" || kind === "download" || kind === "cache") return kind;
  return "other";
}
