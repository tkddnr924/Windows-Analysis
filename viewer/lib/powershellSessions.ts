// PowerShell session grouping (docs viewer-02): only the stored Host ID
// (session_id) links records. Time, account or PID never infer a session, and
// records without a Host ID stay standalone. No runtime imports (Node tests).

export interface PsEvent {
  row: Record<string, string>;
  rowid: number;
  timestamp: string;
  account: string;
  process: string;
  processId: string;
  command: string;
  scriptBlock: string;
  hostApplication: string;
  kind: string;
}

export interface PsSession {
  key: string;
  /** Stored Host ID; null for a standalone record. */
  sessionId: string | null;
  account: string;
  process: string;
  processId: string;
  start: string;
  end: string;
  events: PsEvent[];
}

export function toPsEvent(row: Record<string, string>): PsEvent {
  return {
    row,
    rowid: Number((row as Record<string, unknown>).__rowid),
    timestamp: row.timestamp ?? "",
    account: row.account ?? "",
    process: row.process ?? "",
    processId: row.process_id ?? "",
    command: row.command ?? "",
    scriptBlock: row.script_block ?? "",
    hostApplication: row.host_application ?? "",
    kind: row.event_type ?? "",
  };
}

/** Timed events grouped by Host ID; others one per entry. Oldest first. */
export function groupBySessionId(events: PsEvent[]): PsSession[] {
  const sorted = [...events].sort((left, right) => left.timestamp.localeCompare(right.timestamp) || left.rowid - right.rowid);
  const byHost = new Map<string, PsSession>();
  const entries: PsSession[] = [];
  for (const event of sorted) {
    const sessionId = (event.row.session_id ?? "").trim();
    let entry = sessionId ? byHost.get(sessionId) : undefined;
    if (!entry) {
      entry = {
        key: sessionId ? `host:${sessionId}` : `row:${event.rowid}`,
        sessionId: sessionId || null,
        account: event.account,
        process: event.process,
        processId: event.processId,
        start: event.timestamp,
        end: event.timestamp,
        events: [],
      };
      if (sessionId) byHost.set(sessionId, entry);
      entries.push(entry);
    }
    if (!entry.account && event.account) entry.account = event.account;
    if (!entry.process && event.process) entry.process = event.process;
    if (!entry.processId && event.processId) entry.processId = event.processId;
    entry.events.push(event);
    entry.end = event.timestamp;
  }
  return entries;
}
