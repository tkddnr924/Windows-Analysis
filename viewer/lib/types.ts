import type { Tag } from "./tagging";

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

/** An analyst annotation on one row, persisted in cases/<id>/bookmarks.json. */
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

export interface TimelineEntry {
  /** Already formatted YYYY-MM-DD hh:mm:ss.fff (KST) by the parser — empty when the row has no value in its artifact's timelineField. */
  timestamp: string;
  category: string;
  table: string;
  summary: string;
  subtitle: string;
  tags: Tag[];
  rowid: number;
  fullPath: string;
  /** Kept so clicking a timeline row can open its detail view directly, without a re-fetch or a tab switch. */
  row: Record<string, string>;
  columns: string[];
}

export type FilterMode = "contains" | "exclude" | "exact";

export interface ColumnFilterValue {
  mode: FilterMode;
  value: string;
}

export interface PipelineLogEntry {
  line: string;
  stream: "stdout" | "stderr";
}

export interface RunCaseOptions {
  caseId: string;
  /** Artifact names to run — omit to run all. */
  only?: string[];
}

export interface PipelineResult {
  exitCode: number | null;
}

export interface ElectronApi {
  pickFolder(): Promise<string | null>;
  listCases(): Promise<CaseSummary[]>;
  createCase(name: string, targetDir: string): Promise<CaseSummary>;
  listArtifacts(): Promise<string[]>;
  runCase(options: RunCaseOptions): Promise<PipelineResult>;
  cancelPipeline(): Promise<boolean>;
  onPipelineLog(callback: (entry: PipelineLogEntry) => void): () => void;
  listCategories(caseDir: string): Promise<CategoryEntry[]>;
  listResultFiles(categoryDir: string): Promise<ResultFileEntry[]>;
  readResultFile(fullPath: string): Promise<CsvData>;
  listBookmarks(caseDir: string): Promise<Bookmark[]>;
  toggleBookmark(caseDir: string, entry: BookmarkInput): Promise<Bookmark[]>;
  updateBookmarkNote(caseDir: string, id: string, note: string): Promise<Bookmark[]>;
}

declare global {
  interface Window {
    api: ElectronApi;
  }
}
