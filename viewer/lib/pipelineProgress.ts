// Parser progress protocol and the per-host progress bars derived from it.

/** Section printed while the host waits for an overview slot. */
export const OVERVIEW_WAIT = "_OVERVIEW 대기";
export const OVERVIEW = "_OVERVIEW";

// "=== <phase> ===" sections, per-artifact "[시작] X" / "[완료] X" lines and
// "[종합 분석 진행] done/total" overview steps.
export type LineSignal =
  | { kind: "section"; name: string }
  | { kind: "start"; name: string }
  | { kind: "done"; name: string }
  | { kind: "failure"; name: string }
  | { kind: "overview"; done: number; total: number }
  | { kind: "none" };

export function interpretLine(line: string): LineSignal {
  const section = line.match(/^=== (.+) ===$/);
  if (section) return { kind: "section", name: section[1] };
  const start = line.match(/^\[시작\] (\S+)/);
  if (start) return { kind: "start", name: start[1] };
  const done = line.match(/^\[완료\] (\S+)/);
  if (done) return { kind: "done", name: done[1] };
  const overview = line.match(/^\[종합 분석 진행\] (\d+)\/(\d+)$/);
  if (overview) return { kind: "overview", done: Number(overview[1]), total: Number(overview[2]) };
  const failure = line.match(/^\[!\]\s+(.+?)\s+failed:/);
  if (failure) return { kind: "failure", name: failure[1].trim() };
  return { kind: "none" };
}

export interface ProgressState {
  currentArtifact: string | null;
  /** Artifacts to parse; the overview has its own steps. */
  totalSteps: number;
  completedSteps: number;
  overviewDone: number;
  overviewTotal: number;
}

export interface ProgressBar {
  label: string;
  percent: number;
  detail: string;
  /** Still moving (animated label). */
  active: boolean;
}

// A phase reads 100% only once the next phase has started.
function ratio(done: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(99, Math.round((Math.min(done, total) / total) * 100));
}

export function hostProgress(state: ProgressState): { parse: ProgressBar; overview: ProgressBar | null } {
  const overview = state.currentArtifact === OVERVIEW || state.currentArtifact === OVERVIEW_WAIT;
  const parseLabel = overview
    ? "파싱 완료"
    : state.currentArtifact === "파일 확인"
      ? "원본 파일 확인 중…"
      : state.currentArtifact ? `${state.currentArtifact} 파싱 중…` : "준비 중…";
  const parse: ProgressBar = {
    label: parseLabel,
    percent: overview ? 100 : ratio(state.completedSteps, state.totalSteps),
    detail: state.totalSteps > 0 ? `${Math.min(state.completedSteps, state.totalSteps)} / ${state.totalSteps} 단계` : "파싱 준비 중",
    active: !overview,
  };
  if (!overview) return { parse, overview: null };
  const waiting = state.currentArtifact === OVERVIEW_WAIT;
  return {
    parse,
    overview: {
      label: waiting ? "종합 분석 대기 중…" : "종합 분석 생성 중…",
      percent: waiting ? 0 : ratio(state.overviewDone, state.overviewTotal),
      detail: waiting
        ? "다른 호스트의 종합 분석이 끝나면 시작"
        : state.overviewTotal > 0 ? `${Math.min(state.overviewDone, state.overviewTotal)} / ${state.overviewTotal} 단계` : "준비 중",
      active: true,
    },
  };
}

/** One bar for the global notice: parsing and overview weigh half each. */
export function overallPercent(state: ProgressState): number {
  if (state.totalSteps <= 0) return 0;
  const view = hostProgress(state);
  const overview = view.overview?.percent ?? 0;
  return Math.min(99, Math.round((view.parse.percent + overview) / 2));
}
