// Display rules for ExecutionHistory rows (docs viewer-01). Pure, so the list
// view and tests share them. No runtime imports: tests run on Node directly.

type Row = Record<string, string | undefined>;

/** docs-01: account_role says whose account the common account columns are. */
export const ACCOUNT_ROLE_LABELS: Record<string, string> = {
  creator: "생성 요청자",
  target: "대상 계정",
  event_subject: "이벤트 기록 계정",
};

/** Evidence source key. Every EventLog channel is one `EventLog` source
 * (design rule); event_type keeps Security 4688 / Shell-Core 9707 apart.
 * Amcache sub-tables merge. */
export function executionSource(row: Row): string {
  if (row.event_provider) return "EventLog";
  const type = row.event_type || "";
  return /^Amcache/.test(type) ? "Amcache" : type;
}

export interface ExecutionDisplay {
  title: string;
  /** Title is a raw command (Shell-Core) — no program name was recorded. */
  titleIsCommand: boolean;
  detail: string;
  /** Detail is a path/command value (mono), not prose. */
  detailIsPath: boolean;
}

/** `name` is the recorded program name (or path leaf). A command is never
 * parsed into a program name or path (docs-01: Command may be truncated). */
export function executionDisplay(row: Row, name: string): ExecutionDisplay {
  const path = row.program_path || "";
  const command = row.command_line || "";
  if (!name && !path && command) {
    return { title: command, titleIsCommand: true, detail: "", detailIsPath: false };
  }
  return { title: name || "(이름 없음)", titleIsCommand: false, detail: path || command, detailIsPath: true };
}

const SEARCH_COLUMNS = [
  "program_name", "program_path", "program_path_resolved", "command_line", "parent_process_path",
  "publisher", "sha1", "account", "account_sid", "event_type",
] as const;

export function executionSearchValues(row: Row): string[] {
  return SEARCH_COLUMNS.map((column) => row[column] || "").filter(Boolean);
}

/** True for paths under the Windows directory ("Windows 경로 제외"). Pass the
 * displayed path: KNOWNFOLDERID prefixes must be resolved by the caller. */
export function isWindowsSystemPath(path: string): boolean {
  const value = (path || "").toLowerCase();
  return /^[a-z]:\\windows(\\|$)/.test(value)
    || value.startsWith("\\windows\\") || value.startsWith("%systemroot%") || value.startsWith("\\systemroot\\")
    || /\\device\\harddiskvolume\d+\\windows\\/.test(value)
    || /(^|\\)windows\\(system32|syswow64|winsxs)\\/.test(value);
}
