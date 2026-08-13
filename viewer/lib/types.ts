import type { Tag } from "./tagging";

export interface CsvData {
  columns: string[];
  rows: Record<string, string>[];
  rowCount: number;
}

/** One collected machine within a case: a target folder + its parsed output.
 * This is the browsable unit — artifacts, timeline, and bookmarks all live at
 * the host level. */
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

/** An incident. Groups the hosts (machines) involved so an analyst can pivot
 * between them within one investigation. */
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

// One browsable table. A single .sqlite may hold several tables (a registry
// hive dump, a Chrome History DB, ...), so the browsable unit is a (file,
// table) pair.
export interface ResultFileEntry {
  /** Display name = the table name. */
  name: string;
  /** Source .sqlite basename (no extension), used to group a file's tables. */
  fileName: string;
  /** The table within the file. */
  tableName: string;
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

/** Resolves a detail-view link (e.g. "이 exe가 로드한 파일") to the actual
 * matching rows in the target table, so they can be shown inline instead of
 * navigating away. Returns null if the target table isn't found. */
export type FetchLinkedRows = (
  targetFile: string,
  targetColumn: string,
  value: string
) => Promise<{ rows: Record<string, string>[] } | null>;

export type FilterMode = "contains" | "exclude" | "exact";

export interface ColumnFilterValue {
  mode: FilterMode;
  value: string;
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

export interface ElectronApi {
  pickFolder(): Promise<string | null>;
  listCases(): Promise<ListCasesResult>;
  createCase(name: string): Promise<Case>;
  createHost(caseId: string, name: string, targetDir: string): Promise<Host>;
  deleteCase(caseId: string): Promise<boolean>;
  deleteHost(caseId: string, hostId: string): Promise<boolean>;
  listArtifacts(): Promise<string[]>;
  runHost(options: RunHostOptions): Promise<PipelineResult>;
  cancelPipeline(): Promise<boolean>;
  onPipelineLog(callback: (entry: PipelineLogEntry) => void): () => void;
  /** hostDir = a host's cases/<caseId>/<hostId>/ folder. */
  listCategories(hostDir: string): Promise<CategoryEntry[]>;
  listResultFiles(categoryDir: string): Promise<ResultFileEntry[]>;
  readResultFile(fullPath: string, tableName?: string): Promise<CsvData>;
  listColumnValues(fullPath: string, column: string, tableName?: string): Promise<{ value: string; count: number }[]>;
  searchCase(query: string, hosts: { id: string; name: string; dir: string }[]): Promise<SearchHit[]>;
  listBookmarks(hostDir: string): Promise<Bookmark[]>;
  toggleBookmark(hostDir: string, entry: BookmarkInput): Promise<Bookmark[]>;
  updateBookmarkNote(hostDir: string, id: string, note: string): Promise<Bookmark[]>;
}

declare global {
  interface Window {
    api: ElectronApi;
  }
}

export interface SearchHit {
  hostId: string;
  hostName: string;
  fileName: string;
  tableName: string;
  fullPath: string;
  rowid: number;
  /** The first column whose value contained the query (for a labelled preview). */
  matchColumn: string;
  columns: string[];
  row: Record<string, string>;
}
