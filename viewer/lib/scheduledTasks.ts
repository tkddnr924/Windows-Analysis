// Scheduled task helpers (docs-11). Reads stored _OVERVIEW ScheduledTasks
// columns only (search_text, review_signals, parse_status, summaries).
// No runtime imports (Node tests).

type Cells = Record<string, string | undefined>;

export type TaskShow = "all" | "user" | "review" | "hidden" | "parse";
export type TaskState = "all" | "enabled" | "disabled";

export interface TaskFilter {
  search: string;
  show: TaskShow | string;
  state: TaskState | string;
  /** Selected event_type values (empty: all). */
  kinds: string[];
  /** Selected account keys (empty: all). */
  accounts: string[];
}

export const DEFAULT_TASK_FILTER: TaskFilter = { search: "", show: "all", state: "all", kinds: [], accounts: [] };

const PARSE_OK = new Set(["parsed", "ok"]);
/** Stored parse status other than parsed/ok (R12). */
export const isParseProblem = (row: Cells) => Boolean(row.parse_status) && !PARSE_OK.has(row.parse_status ?? "");
export const hasReview = (row: Cells) => Number(row.review_signal_count) > 0;
export const isHidden = (row: Cells) => row.hidden === "1";
/** Only definitions carry the Microsoft classification (events have none). */
export const isNonMicrosoft = (row: Cells) => row.is_microsoft === "0";

/** Account identity: stored SID first, then the raw name. */
export const taskAccountKey = (row: Cells) => row.run_as_sid || row.account_sid || row.run_as || row.account || "";

function matchesShow(row: Cells, show: string): boolean {
  if (show === "user") return isNonMicrosoft(row);
  if (show === "review") return hasReview(row);
  if (show === "hidden") return isHidden(row);
  if (show === "parse") return isParseProblem(row);
  return true;
}

export function filterTasks<R extends Cells>(rows: R[], filter: TaskFilter, inPeriod: (timestamp: string) => boolean, periodSet: boolean): R[] {
  const needle = filter.search.trim().toLowerCase();
  return rows.filter((row) => {
    if (periodSet && !(row.timestamp && inPeriod(row.timestamp))) return false;
    if (!matchesShow(row, filter.show)) return false;
    if (filter.state === "enabled" && row.enabled !== "1") return false;
    if (filter.state === "disabled" && row.enabled !== "0") return false;
    if (filter.kinds.length && !filter.kinds.includes(row.event_type ?? "")) return false;
    if (filter.accounts.length && !filter.accounts.includes(taskAccountKey(row))) return false;
    if (!needle) return true;
    return [row.search_text, row.account, row.account_sid, row.run_as, row.run_as_sid, row.task_name, row.task_path, row.event_type]
      .some((value) => (value ?? "").toLowerCase().includes(needle));
  });
}

/** Timed rows by time (direction), ties by record_id; untimed rows apart by name. */
export function splitByTime<R extends Cells>(rows: R[], direction: "asc" | "desc"): { timed: R[]; untimed: R[] } {
  const timed = rows.filter((row) => row.timestamp).sort((a, b) => {
    const order = (a.timestamp ?? "").localeCompare(b.timestamp ?? "");
    return (direction === "asc" ? order : -order) || (a.record_id ?? "").localeCompare(b.record_id ?? "");
  });
  const untimed = rows.filter((row) => !row.timestamp).sort((a, b) => (a.task_name ?? "").localeCompare(b.task_name ?? "") || (a.record_id ?? "").localeCompare(b.record_id ?? ""));
  return { timed, untimed };
}

export function taskCounts(rows: Cells[]) {
  return {
    total: rows.length,
    user: rows.filter(isNonMicrosoft).length,
    review: rows.filter(hasReview).length,
    hidden: rows.filter(isHidden).length,
    parse: rows.filter(isParseProblem).length,
    enabled: rows.filter((row) => row.enabled === "1").length,
    disabled: rows.filter((row) => row.enabled === "0").length,
  };
}

// Stored review signal codes → short labels (R13).
export const REVIEW_SIGNAL_LABELS: Record<string, string> = {
  hidden_declared: "숨김 선언",
  script_host_command: "스크립트 호스트",
  encoded_command_argument: "인코딩 명령",
};
export const reviewSignalList = (row: Cells) => (row.review_signals ?? "").split(",").map((signal) => signal.trim()).filter(Boolean);

/** Per-task command line from TaskActions: stored `command_resolved` first
 *  (docs-24 path rule), raw command kept for hover; COM actions as COM:{clsid}. */
export function resolvedActionSummaries(actions: Cells[]): Map<string, { text: string; raw: string }> {
  const byRecord = new Map<string, Cells[]>();
  for (const action of actions) {
    const list = byRecord.get(action.record_id ?? "") ?? [];
    list.push(action);
    byRecord.set(action.record_id ?? "", list);
  }
  const result = new Map<string, { text: string; raw: string }>();
  for (const [recordId, list] of byRecord) {
    list.sort((a, b) => Number(a.ordinal ?? 0) - Number(b.ordinal ?? 0));
    const line = (action: Cells, resolved: boolean) => {
      const command = (resolved && action.command_resolved) || action.command || "";
      if (!command) return action.class_id ? `COM:${action.class_id}` : "";
      return [command, action.arguments].filter(Boolean).join(" ");
    };
    result.set(recordId, {
      text: list.map((action) => line(action, true)).filter(Boolean).join(" · "),
      raw: list.map((action) => line(action, false)).filter(Boolean).join(" · "),
    });
  }
  return result;
}
