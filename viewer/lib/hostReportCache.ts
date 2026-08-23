/**
 * The immutable parse manifest belongs to the host's terminal run timestamp.
 * Keeping that timestamp beside the cached response prevents a previous run's
 * publication state from being rendered after a later terminal refresh.
 */
export interface HostReportCacheEntry<T> {
  hostRunAt: string;
  report: T | null;
}

type RunIdentified = { runId?: string };

/**
 * A cached manifest is displayable only when it belongs to the host's current
 * persisted run and, for an in-session terminal run, to that exact immutable
 * run id. Fetching a fresh manifest is not enough: this gate prevents stale
 * publication text/actions from painting during the refresh gap.
 */
export function selectVisibleHostReport<T extends RunIdentified>(
  cached: HostReportCacheEntry<T> | undefined,
  hostLastRunAt: string | null,
  hasActiveRun: boolean,
  terminalRunId?: string,
): T | null {
  if (!cached || !hostLastRunAt || hasActiveRun || cached.hostRunAt !== hostLastRunAt) return null;
  if (terminalRunId !== undefined && cached.report?.runId !== terminalRunId) return null;
  return cached.report;
}

export function isHostReportSyncPending<T extends RunIdentified>(
  cached: HostReportCacheEntry<T> | undefined,
  hostLastRunAt: string | null,
  hasActiveRun: boolean,
  terminalRunId?: string,
): boolean {
  if (!hostLastRunAt || hasActiveRun || cached?.report === null) return false;
  return selectVisibleHostReport(cached, hostLastRunAt, hasActiveRun, terminalRunId) === null;
}

export function shouldLoadHostReport<T>(
  cached: HostReportCacheEntry<T> | undefined,
  hostLastRunAt: string | null,
  hasActiveRun: boolean,
  cachedRunId: string | undefined,
  expectedRunId?: string,
): boolean {
  if (!hostLastRunAt || hasActiveRun) return false;
  return cached?.hostRunAt !== hostLastRunAt
    || (expectedRunId !== undefined && cachedRunId !== expectedRunId);
}
