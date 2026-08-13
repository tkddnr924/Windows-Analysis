export interface CsvData {
  columns: string[];
  rows: Record<string, string>[];
  rowCount: number;
}

export interface Host {
  id: string;
  name: string;
  targetDir: string;
  /** cases/<caseId>/<hostId>/ — holds one .sqlite per artifact output + bookmarks.json. */
  dir: string;
  createdAt: string;
  lastRunAt: string | null;
  lastRunStatus: string | null;
  artifactsRun: string[];
}

export interface Case {
  id: string;
  name: string;
  createdAt: string;
  /** cases/<caseId>/ */
  dir: string;
  hosts: Host[];
}

export interface CategoryEntry {
  name: string;
  fullPath: string;
}

// One browsable table. A single .sqlite now holds several tables (e.g. a
// registry hive dump, or a Chrome History DB's urls/visits/downloads), so the
// browsable unit is a (file, table) pair rather than a whole file.
export interface ResultFileEntry {
  /** Display name = the table name. */
  name: string;
  /** Source .sqlite basename without extension (e.g. "SOFTWARE"), used to
   * group a file's tables together in the sidebar. */
  fileName: string;
  /** The table within the file this entry refers to. */
  tableName: string;
  relativePath: string;
  fullPath: string;
  rowCount: number;
}

/** An analyst annotation on one row, persisted in cases/<id>/bookmarks.json.
 * fullPath is the same absolute .sqlite path used everywhere else in the app
 * (ResultFileEntry.fullPath) — the renderer has no Node `path` module
 * (contextIsolation), so a case-relative path would need main-process help
 * to resolve back to a real file; the absolute path needs none. */
export interface Bookmark {
  id: string;
  fullPath: string;
  tableName: string;
  rowid: number;
  note: string;
  taggedAt: string;
  /** Which host in the case this bookmark's row belongs to (bookmarks are
   * case-level and shared across hosts). Optional for backward compatibility
   * with bookmarks saved before host attribution existed. */
  hostId?: string;
  hostName?: string;
}

export interface BookmarkInput {
  fullPath: string;
  tableName: string;
  rowid: number;
  hostId?: string;
  hostName?: string;
}

export interface PipelineLogEntry {
  line: string;
  stream: "stdout" | "stderr";
}

/** error is set when the pipeline itself failed to run — kept separate from
 * "cases is legitimately empty" so the GUI never conflates the two. */
export interface ListCasesResult {
  cases: Case[];
  error: string | null;
}

export interface RunHostOptions {
  caseId: string;
  hostId: string;
  /** Artifact names to run — omit to run all. */
  only?: string[];
}

export interface PipelineResult {
  exitCode: number | null;
}
