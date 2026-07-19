export interface CsvData {
  columns: string[];
  rows: Record<string, string>[];
  rowCount: number;
}

export interface CaseSummary {
  id: string;
  name: string;
  targetDir: string;
  /** cases/<id>/ — root folder holding one .sqlite file per artifact output. */
  dir: string;
  createdAt: string;
  lastRunAt: string | null;
  lastRunStatus: string | null;
  artifactsRun: string[];
}

export interface CategoryEntry {
  name: string;
  fullPath: string;
}

export interface ResultFileEntry {
  name: string;
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
}

export interface BookmarkInput {
  fullPath: string;
  tableName: string;
  rowid: number;
}

export interface PipelineLogEntry {
  line: string;
  stream: "stdout" | "stderr";
}

/** error is set when the pipeline itself failed to run — kept separate from
 * "cases is legitimately empty" so the GUI never conflates the two. */
export interface ListCasesResult {
  cases: CaseSummary[];
  error: string | null;
}

export interface RunCaseOptions {
  caseId: string;
  /** Artifact names to run — omit to run all. */
  only?: string[];
}

export interface PipelineResult {
  exitCode: number | null;
}
