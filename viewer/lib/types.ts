import type { Tag } from "./tagging";

export interface CsvData {
  columns: string[];
  rows: Record<string, string>[];
  rowCount: number;
}

/** A small, queryable page of related evidence records for the shared detail drawer. */
export interface LinkedRowsPage {
  rows: Record<string, string>[];
  rowCount: number;
}

export interface BrowserActivityQuery {
  account?: string;
  kinds: string[];
  day?: string;
  search?: string;
  start?: string;
  end?: string;
  offset: number;
  limit: number;
  /** Only summary ledgers request newest-first ordering; the daily evidence ledger remains chronological. */
  descending?: boolean;
}

export interface BrowserVisitedDomainStat {
  rowId: number;
  domain: string;
  visitCount: number;
  /** Exact count of distinct stored URLs represented by the hostname. */
  urlCount: number;
}

export interface BrowserActivityInsights {
  visitTotal: number;
  topVisitedDomains: BrowserVisitedDomainStat[];
  downloadTotal: number;
  downloads: Record<string, string>[];
}

/** A bounded, exact-cache-record preview. `truncated` means the recovered
 * response is larger than the IPC-safe prefix returned in `bodyB64`. */
export interface CacheBodyPreview {
  bodyB64: string;
  decodedSize: number;
  truncated: boolean;
}

/** A server-paginated page of host-normalised browser visit domains. */
export interface BrowserDomainStatsPage {
  domains: BrowserVisitedDomainStat[];
  total: number;
}

export interface BrowserActivitySummary {
  accounts: string[];
  days: { value: string; count: number }[];
  total: number;
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
  /** Wall-clock seconds the last parse took (shown as a "소요" tag). */
  lastRunDurationSecs?: number | null;
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

/** Parser-provided source and recovery summary for one result table. */
export interface ResultProvenance {
  sourceFile: string;
  recovery: string;
}

/** A supplementary source input that the parser explicitly consumed. */
export interface ArtifactInputFile {
  name: string;
  kind: "hive" | "transactionLog" | string;
  detail: string;
}

export interface ParseReportArtifact {
  name: string;
  status: "completed" | "failed" | "cancelled" | "running";
  inputs: ParseReportInput[];
}

/** A source evidence file consumed by one parser during its most recent run. */
export interface ParseReportInput {
  name: string;
  /** Absolute source path, retained to distinguish files with the same name. */
  sourcePath?: string;
  /** Number of rows extracted from this exact evidence file. */
  recordCount?: number;
  /** Registry transaction log applied to its primary hive. */
  recoveryLog?: boolean;
}

export interface ParseReport {
  runAt: string;
  artifacts: ParseReportArtifact[];
  overview: { name: string; rowCount: number }[];
}

/** An analyst annotation on one row, persisted in cases/<id>/bookmarks.json. */
export interface Bookmark {
  id: string;
  fullPath: string;
  tableName: string;
  rowid: number;
  note: string;
  taggedAt: string;
  /** For rows that carry several timestamps (e.g. an $MFT record's SI/FN
   * Created/Modified/...), which one this bookmark marks — so the same row can
   * be bookmarked on each time independently. Absent for whole-row bookmarks. */
  field?: string;
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
  field?: string;
  hostId?: string;
  hostName?: string;
}

/** One direct SQLite lookup used by the bookmark timeline. */
export interface ResultRow {
  columns: string[];
  row: Record<string, string> | null;
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
  value: string,
  query?: { search?: string; offset?: number; limit?: number }
) => Promise<LinkedRowsPage | null>;

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

/** A sighting of a filesystem path in another artifact (JumpList today;
 * Shellbag/LNK later) — used to tag rows in the $MFT explorer. */
export interface PathReference {
  /** lowercased target path, for matching against $MFT paths */
  path: string;
  kind: string;
  account: string;
  label: string;
  fields: Record<string, string>;
  /** Source sqlite + row, so the viewer can bookmark this reference's
   * timestamps. Empty fullPath / rowid < 0 = not bookmarkable (e.g. Shellbag). */
  fullPath: string;
  tableName: string;
  rowid: number;
}

/** Metadata-only cache entry (no body). Use cacheEntryBody() to fetch body on demand. */
export interface CacheMeta {
  account: string;
  url: string;
  contentType: string;
  status: string;
  responseTime: string;
  bodySize: string;
  cacheKey: string;
}

/** @deprecated use CacheMeta — kept for backward-compat in case something still references it */
export type CacheEntry = CacheMeta;

/** AI conversation extracted from the browser cache. */
export interface AiConversation {
  provider: string;
  account: string;
  title: string;
  /** Cache observation time; this is the timestamp used for the global period filter. */
  date: string;
  /** Provider payload time values, retained independently from cache observation time. */
  createdAt: string;
  updatedAt: string;
  url: string;
  /** Pretty-printed raw JSON of the conversation object. */
  rawJson: string;
}

export interface AiConversationPage {
  conversations: AiConversation[];
  total: number;
  sourceCount: number;
  sourcesRead: number;
  /** Cache files that could not be read; other files may still have results. */
  sourceFailures: string[];
}

/** One EventLog result table used by the account-detail activity query. */
export interface AccountEventSource {
  fullPath: string;
  tableName: string;
  logName: string;
}

/** Server-side filters for exact account-correlated EventLog activity. */
export interface AccountEventQuery {
  sid: string;
  username: string;
  search?: string;
  start?: string;
  end?: string;
  offset: number;
  limit: number;
}

/** One bounded, globally ordered account-activity page. */
export interface AccountEventPage {
  rows: Record<string, string>[];
  rowCount: number;
  /** Number of EventLog tables submitted to the server for this query. */
  sourceCount: number;
  /** Sources whose query could start; zero distinguishes total read failure from no matches. */
  sourcesRead: number;
  /** EventLog evidence sources that could not be read; successful sources remain usable. */
  sourceFailures: AccountEventSourceFailure[];
}

/** A safely described EventLog source read failure for analyst follow-up. */
export interface AccountEventSourceFailure {
  logName: string;
  tableName: string;
  reason: string;
}

export interface ElectronApi {
  /** Resize the single desktop window to fit the current application stage. */
  setWindowLayout(layout: "setup" | "analysis"): Promise<void>;
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
  /** Rebuilds only a legacy ExecutionHistory overview to add raw record links. */
  refreshExecutionHistoryOverview(hostDir: string): Promise<boolean>;
  resultProvenance(fullPath: string, tableName: string): Promise<ResultProvenance[]>;
  artifactInputFiles(sourceFile: string): Promise<ArtifactInputFile[]>;
  parseReport(hostDir: string): Promise<ParseReport | null>;
  readResultFile(fullPath: string, tableName?: string): Promise<CsvData>;
  linkedResultRows(fullPath: string, tableName: string, matchColumn: string, matchValue: string, search: string, offset: number, limit: number): Promise<LinkedRowsPage>;
  resultRow(fullPath: string, tableName: string, rowid: number): Promise<ResultRow>;
  browserActivitySummary(fullPath: string, tableName: string, query: BrowserActivityQuery): Promise<BrowserActivitySummary>;
  browserActivityInsights(fullPath: string, tableName: string, account: string | undefined, start: string | undefined, end: string | undefined): Promise<BrowserActivityInsights>;
  browserActivityDomains(fullPath: string, tableName: string, account: string | undefined, start: string | undefined, end: string | undefined, offset: number, limit: number): Promise<BrowserDomainStatsPage>;
  browserActivityPage(fullPath: string, tableName: string, query: BrowserActivityQuery): Promise<CsvData>;
  accountEventPage(sources: AccountEventSource[], query: AccountEventQuery): Promise<AccountEventPage>;
  aiReferrals(fullPath: string, tableName: string, start: string | undefined, end: string | undefined, offset: number, limit: number): Promise<CsvData>;
  mftChildren(fullPath: string, parentEntry: number): Promise<Record<string, string>[]>;
  mftSearch(fullPath: string, query: string, limit: number): Promise<Record<string, string>[]>;
  mftRow(fullPath: string, rowid: number): Promise<Record<string, string> | null>;
  listColumnValues(fullPath: string, column: string, tableName?: string): Promise<{ value: string; count: number }[]>;
  searchCase(query: string, hosts: { id: string; name: string; dir: string }[]): Promise<SearchHit[]>;
  listBookmarks(hostDir: string): Promise<Bookmark[]>;
  toggleBookmark(hostDir: string, entry: BookmarkInput): Promise<Bookmark[]>;
  updateBookmarkNote(hostDir: string, id: string, note: string): Promise<Bookmark[]>;
  /** Cross-artifact references to filesystem paths for a host. */
  pathReferences(hostDir: string): Promise<PathReference[]>;
  /** Fetch an IPC-bounded preview for one exact cache record. An empty bodyB64
   * means the parser did not retain a recoverable response body. */
  cacheEntryBody(hostDir: string, account: string, url: string, cacheKey: string): Promise<CacheBodyPreview>;
  /** AI conversations extracted from browser cache, filtered and paged by cache timestamp. */
  aiConversations(hostDir: string, query: { start?: string; end?: string; offset: number; limit: number }): Promise<AiConversationPage>;
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
