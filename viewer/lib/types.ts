import type { Tag } from "./tagging";

export interface CsvData {
  columns: string[];
  rows: Record<string, string>[];
  rowCount: number;
}

/** 타임라인 빌드 전용 원본 페이지 — 행 수가 아니라 바이트 예산으로 끊긴다.
 *  종료는 `nextOffset === null`로만 판단한다(짧은 페이지 ≠ 테이블 끝). */
export interface TimelineSourcePage {
  columns: string[];
  rows: Record<string, string>[];
  nextOffset: number | null;
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

/** One visit node of the reconstructed navigation graph. */
export interface VisitGraphNode {
  /** visits.id — the entry visit when same-URL re-navigations were collapsed. */
  visitId: string;
  url: string;
  title: string;
  time: string;
  /** Decoded page-transition label (e.g. "링크 클릭 · 서버 리다이렉트"). */
  transition: string;
  /** Raw visits.transition integer (decoded form is in `transition`). */
  transitionRaw: string;
  /** A visit of the looked-up page itself (or its cache document origin). */
  isTarget: boolean;
  /** Same-URL 재이동(리다이렉트·리로드)으로 이 노드에 접힌 방문 수. */
  reloads: number;
  /** Cross-site referrer recorded on this visit (may not be a page in the
   *  visits table, e.g. https://chatgpt.com/). */
  externalReferrer: string;
}

/** One navigation edge, provable against the DB via the child's link column. */
export interface VisitGraphEdge {
  /** Parent (navigation source) node's visits.id. */
  from: string;
  /** Child (navigation destination) node's visits.id. */
  to: string;
  /** "from_visit" (same tab) | "opener_visit" (new tab). */
  kind: string;
}

/** The navigation neighbourhood of a browser visit/cache record: ancestors
 *  (where it came from), descendants (where the user went next) and sibling
 *  branches off shared ancestors, as one graph. */
export interface BrowserVisitGraph {
  nodes: VisitGraphNode[];
  edges: VisitGraphEdge[];
  sourceFile: string;
  /** For a cache resource: the navigated page it was attributed to. */
  matchedPage: string;
  note: string;
  /** 방문·노드 상한에 걸려 일부 연결만 표시한 경우. */
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

/** One collected machine: a target folder + its parsed output. This is the
 * browsable unit — artifacts live under the direct host folder. */
export interface Host {
  id: string;
  name: string;
  targetDir: string;
  /** cases/<hostId>/ — holds this host's parsed output. */
  dir: string;
  createdAt: string;
  lastRunAt: string | null;
  lastRunStatus: string | null;
  artifactsRun: string[];
  /** Wall-clock seconds the last parse took (shown as a "소요" tag). */
  lastRunDurationSecs?: number | null;
}

/** Compatibility collection for the direct host store. The app exposes one
 * root collection; it does not create a per-case directory. */
export interface Case {
  id: string;
  name: string;
  createdAt: string;
  /** cases/ (root host store) */
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
  status: "completed" | "failed" | "cancelled" | "running" | "no_input";
  /** The parser explicitly ran a source-discovery pass for this artifact. */
  inputDiscoveryChecked?: boolean;
  /** At least one source file was found, even if it yielded zero records. */
  evidenceDiscovered?: boolean;
  /** Files sealed in isolated staging after this parser completed. */
  outputs?: string[];
  /** Files from this artifact actually published to the live host result. */
  publishedOutputs?: string[];
  /** Publication is intentionally separate from parser completion. */
  publicationStatus?: "published" | "withheld" | "not_published" | string;
  /** Structured parser or panic failure for this artifact only. */
  error?: string;
  /** 탐색(순회·내용 판별) 중 접근·읽기 실패 — 발견 0건이 실제 무증거인지
   *  접근 불가였는지 구분하는 근거. */
  discoveryErrors?: string[];
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
  /** 이 원본 파일을 읽거나 해석하지 못한 사유 — 0건 성공과 구분된다. */
  error?: string;
}

export interface ParseReport {
  runId?: string;
  runAt: string;
  /** Terminal lifecycle of this parser attempt; absent in pre-manifest reports. */
  status?: "ok" | "error" | "cancelled" | string;
  durationMs?: number;
  /** True only when this run made one or more outputs visible live. */
  published?: boolean;
  errors?: string[];
  registryHives?: ParseReportRegistryHive[];
  /** Per-hive Amcache transaction-log outcome; mirrors registryHives. */
  amcacheHives?: ParseReportAmcacheHive[];
  /** Recovery policy used by this run; disabled means live hive records only. */
  registryRecovery?: ParseReportRegistryRecovery;
  /** Parser stages that completed; this does not imply their results were published. */
  completedArtifacts?: string[];
  /** Artifact names with at least one output published by this run. */
  publishedArtifacts?: string[];
  /** Exact host-relative files published by this run. */
  publishedOutputs?: string[];
  artifacts: ParseReportArtifact[];
  overview: { name: string; rowCount: number }[];
}

export interface ParseReportRegistryHive {
  sourcePath: string;
  status: "completed" | "failed" | string;
  rowCount: number;
  /** Sibling LOG1/LOG2 files found beside the hive, whether or not applied. */
  recoveryLogsDiscovered?: number;
  /** Transaction logs actually applied during parsing. */
  recoveryLogCount: number;
  /** False for temporary live-only Registry parsing. */
  recoveryEnabled?: boolean;
  recoveredRowCount: number;
  /** Time queued behind the process-wide Registry deleted-recovery cap. */
  recoveryPermitWaitMs?: number;
  buildRecoveryMs: number;
  iterationAndSqliteWriteMs: number;
  error?: string;
}

export interface MftChildrenPage {
  rows: Record<string, string>[];
  /** 첫 페이지(offset 0)에서만 계산된다. 후속 페이지는 -1 — 호출자가 보관한 값을 쓴다. */
  total: number;
}

export interface ParseReportAmcacheHive {
  sourcePath: string;
  status: "completed" | "skipped_corrupted" | string;
  /** Sibling LOG1/LOG2 files found beside the hive. */
  logsDiscovered: number;
  /** Transaction logs actually applied; 0 after a no-log fallback. */
  logsApplied: number;
  /** Why discovered logs could not be applied (primary hive parsed without them). */
  logApplyError?: string;
  /** Why the hive itself was skipped as corrupted. */
  error?: string;
}

export interface ParseReportRegistryRecovery {
  mode: "enabled" | "disabled" | string;
  deletedCellRecoveryApplied: boolean;
  transactionLogsApplied: boolean;
}

/** A deliberately bounded preview of one immutable parser-run log. */
export interface ParseLogPreview {
  text: string;
  truncated: boolean;
}

/** An analyst annotation on one row, persisted in the direct host-store root
 * `cases/bookmarks.json`. */
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
  /** Event time carried over from the overview row this bookmark was promoted
   * from. Raw source records (e.g. Registry) may lack the execution timestamp,
   * so the bookmark timeline prefers this when present. */
  eventTime?: string;
  /** Which direct host this bookmark's row belongs to (bookmarks are shared
   * across registered hosts). Optional for backward compatibility
   * with bookmarks saved before host attribution existed. */
  hostId?: string;
  hostName?: string;
}

export interface BookmarkInput {
  fullPath: string;
  tableName: string;
  rowid: number;
  field?: string;
  eventTime?: string;
  hostId?: string;
  hostName?: string;
}

/** One direct SQLite lookup used by the bookmark timeline. */
export interface ResultRow {
  columns: string[];
  row: Record<string, string> | null;
}

export interface MftRecordsPage {
  rows: Record<string, string>[];
  total: number;
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

/** 백엔드 sqlite로 materialize된 마스터 타임라인 — 검색·필터·정렬·페이지를
 * SQL로 처리해 프런트가 전체 엔트리를 메모리에 상주시키지 않는다. */
export interface TimelineMeta {
  exists: boolean;
  builtForRunAt: string;
  logicVersion: number;
  total: number;
}
export interface TimelineFacetCount {
  key: string;
  count: number;
}
export interface TimelineTableFacet {
  artifactGroup: string;
  sourceTable: string;
  category: string;
  count: number;
}
export interface TimelineFacets {
  tables: TimelineTableFacet[];
  execSources: TimelineFacetCount[];
  browserKinds: TimelineFacetCount[];
}
export interface TimelineQuery {
  search?: string;
  hiddenSourceTables?: string[];
  hiddenExecSources?: string[];
  hiddenBrowserKinds?: string[];
  onlySuspicious?: boolean;
  start?: string;
  end?: string;
  /** true = 최신 먼저(내림차순). */
  sortDesc?: boolean;
  offset: number;
  limit: number;
}
/** 페이지가 실어오는 경량 타임라인 행 — 원본 값 전체는 rowJson에 담겨 상세/
 * 태그 재계산에 쓰이고, 페이지당 100행만 메모리에 있다. */
export interface TimelinePageRow {
  ts: string;
  category: string;
  sourceTable: string;
  artifactGroup: string;
  fullPath: string;
  rowidSrc: number;
  recordKey: string;
  eventTime: string;
  rowJson: string;
}
export interface TimelinePage {
  rows: TimelinePageRow[];
  total: number;
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
  /** Immutable parser invocation id. Events from concurrent hosts never share state. */
  runId: string;
  hostId: string;
  status: "queued" | "running" | "complete" | "partial" | "error" | "cancelled";
  line: string;
  stream: "stdout" | "stderr" | "lifecycle";
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
  /** Path-safe immutable invocation id, generated before it enters the queue. */
  runId?: string;
  /** Artifact names to run — omit to run all. */
  only?: string[];
}

export interface PipelineResult {
  runId: string;
  hostId: string;
  /** `partial` means completed artifacts were committed but one or more
   * sources/artifacts failed; see the immutable parse report for detail. */
  status: "complete" | "partial" | "error" | "cancelled";
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
  /** 파생 테이블 rowid — 원문 단건 조회 키. */
  rowId: number;
  /** 원본 캐시 행 키(`<파일>::CacheEntries::<rowid>`) — 다른 화면과 북마크를 공유한다. */
  sourceRecordKey: string;
  /** 파생 시점에 센 메시지 수. 목록은 원문을 받지 않는다. */
  messageCount: number;
}

/** 대화 원문 — 목록이 아니라 대화를 열 때만 조회한다. */
export interface AiConversationDetail {
  rawJson: string;
  sourceRecordKey: string;
}

export interface AiConversationPage {
  conversations: AiConversation[];
  total: number;
  sourceCount: number;
  sourcesRead: number;
  /** Cache files that could not be read; other files may still have results. */
  sourceFailures: string[];
  /** 파생 테이블 자체가 없는 이전 파싱본 — "기간 내 데이터 없음"과 구별한다. */
  derivedMissing: boolean;
}

/** WMI-Activity 로그의 구독 이벤트(5859~5861)만 서버에서 걸러 온 결과 —
 *  원본 EventLog 전체를 IPC로 옮기지 않는다. rows에는 __rowid가 있어 원본
 *  EventLog 행 기준 북마크가 연결된다. 로그가 없으면 fullPath가 빈 문자열. */
export interface WmiSubscriptionEvents {
  columns: string[];
  rows: Record<string, string>[];
  fullPath: string;
  tableName: string;
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

/** A display-only exact SID-to-account mapping from the parsed TargetInfo
 * overview for one authoritative host directory. */
export interface AccountDirectoryEntry {
  sid: string;
  accountName: string;
  sourceArtifact: string;
}

export interface ElectronApi {
  /** Resize the single desktop window to fit the current application stage. */
  pickFolder(): Promise<string | null>;
  listCases(): Promise<ListCasesResult>;
  createCase(name: string): Promise<Case>;
  createHost(caseId: string, name: string, targetDir: string): Promise<Host>;
  /** Changes display metadata only; evidence and result paths remain immutable. */
  renameHost(caseId: string, hostId: string, name: string): Promise<Host>;
  deleteCase(caseId: string): Promise<boolean>;
  deleteHost(caseId: string, hostId: string): Promise<boolean>;
  listArtifacts(): Promise<string[]>;
  runHost(options: RunHostOptions): Promise<PipelineResult>;
  /** Omit runId only for the explicit cancel-all action. */
  cancelPipeline(runId?: string, cancelAll?: boolean): Promise<boolean>;
  onPipelineLog(callback: (entry: PipelineLogEntry) => void): () => void;
  /** hostDir = a host's direct cases/<hostId>/ folder. */
  listCategories(hostDir: string): Promise<CategoryEntry[]>;
  /** sqlite 타임라인 스트리밍 빌드 — begin → (insert · drain)* → finish/abort. */
  masterTimelineBuildBegin(hostDir: string, token: string, builtForRunAt: string): Promise<void>;
  masterTimelineBuildInsert(hostDir: string, token: string, ndjson: string): Promise<void>;
  masterTimelineBuildDrain(token: string): Promise<void>;
  masterTimelineBuildFinish(hostDir: string, token: string): Promise<void>;
  masterTimelineBuildAbort(hostDir: string, token: string): Promise<void>;
  masterTimelineMeta(hostDir: string): Promise<TimelineMeta>;
  masterTimelineFacets(hostDir: string): Promise<TimelineFacets>;
  masterTimelinePage(hostDir: string, query: TimelineQuery): Promise<TimelinePage>;
  listResultFiles(categoryDir: string): Promise<ResultFileEntry[]>;
  /** Rebuilds only a legacy ExecutionHistory overview to add raw record links. */
  refreshExecutionHistoryOverview(hostDir: string): Promise<boolean>;
  refreshWerReportsOverview(hostDir: string): Promise<boolean>;
  resultProvenance(fullPath: string, tableName: string): Promise<ResultProvenance[]>;
  artifactInputFiles(sourceFile: string): Promise<ArtifactInputFile[]>;
  parseReport(hostDir: string): Promise<ParseReport | null>;
  /** Reads a bounded immutable run log; never scans or reparses evidence. */
  parseRunLog(hostDir: string, runId: string): Promise<ParseLogPreview>;
  /** Reads the existing TargetInfo account map. It never reparses evidence. */
  accountDirectory(hostDir: string): Promise<AccountDirectoryEntry[]>;
  readResultFile(fullPath: string, tableName?: string): Promise<CsvData>;
  readResultFilePage(fullPath: string, tableName: string | undefined, offset: number, limit: number): Promise<CsvData>;
  timelineSourcePage(fullPath: string, tableName: string | undefined, offset: number, limit: number): Promise<TimelineSourcePage>;
  linkedResultRows(fullPath: string, tableName: string, matchColumn: string, matchValue: string, search: string, offset: number, limit: number): Promise<LinkedRowsPage>;
  resultRow(fullPath: string, tableName: string, rowid: number): Promise<ResultRow>;
  browserActivitySummary(fullPath: string, tableName: string, query: BrowserActivityQuery): Promise<BrowserActivitySummary>;
  browserActivityInsights(fullPath: string, tableName: string, account: string | undefined, start: string | undefined, end: string | undefined): Promise<BrowserActivityInsights>;
  browserActivityDomains(fullPath: string, tableName: string, account: string | undefined, start: string | undefined, end: string | undefined, offset: number, limit: number, ascending?: boolean): Promise<BrowserDomainStatsPage>;
  browserActivityPage(fullPath: string, tableName: string, query: BrowserActivityQuery): Promise<CsvData>;
  accountEventPage(sources: AccountEventSource[], query: AccountEventQuery): Promise<AccountEventPage>;
  aiReferrals(fullPath: string, tableName: string, start: string | undefined, end: string | undefined, offset: number, limit: number): Promise<CsvData>;
  mftChildren(fullPath: string, parentEntry: number, offset?: number, limit?: number): Promise<MftChildrenPage>;
  mftSearch(fullPath: string, query: string, limit: number): Promise<Record<string, string>[]>;
  mftRow(fullPath: string, rowid: number): Promise<Record<string, string> | null>;
  mftRecordsPage(fullPath: string, query: string, offset: number, limit: number, options?: { sortKey?: string; sortDesc?: boolean; filesOnly?: boolean; namePattern?: string; timeKey?: string; timeStart?: string; timeEnd?: string }): Promise<MftRecordsPage>;
  usnJrnlPage(fullPath: string, query: { search?: string; reason?: string; start?: string; end?: string; ascending?: boolean; offset: number; limit: number }): Promise<CsvData>;
  listColumnValues(fullPath: string, column: string, tableName?: string): Promise<{ value: string; count: number }[]>;
  searchCase(query: string, hosts: { id: string; name: string; dir: string }[], offset: number, limit: number, range?: { start?: string; end?: string }, categories?: string[]): Promise<SearchCasePage>;
  listBookmarks(hostDir: string): Promise<Bookmark[]>;
  toggleBookmark(hostDir: string, entry: BookmarkInput): Promise<Bookmark[]>;
  updateBookmarkNote(hostDir: string, id: string, note: string): Promise<Bookmark[]>;
  /** Cross-artifact references to filesystem paths for a host. */
  pathReferences(hostDir: string, paths: string[]): Promise<PathReference[]>;
  pathReferenceAccounts(hostDir: string): Promise<string[]>;
  /** Fetch an IPC-bounded preview for one exact cache record. An empty bodyB64
   * means the parser did not retain a recoverable response body. */
  cacheEntryBody(hostDir: string, account: string, url: string, cacheKey: string): Promise<CacheBodyPreview>;
  /** Reconstruct the visit navigation graph (ancestors + descendants +
   *  sibling branches) for a browser visit (pass its URL) or a cache record
   *  (also pass its cacheKey) from the raw History DB on demand. */
  /** sourceFile: 행의 `_source_file` — 같은 브라우저의 History만 조회하는 출처
   *  고정에 쓰인다. 없으면(구 파싱본) 계정 후보 전체에서 조회한다. */
  browserVisitGraph(hostDir: string, account: string, url: string, cacheKey?: string, sourceFile?: string): Promise<BrowserVisitGraph>;
  /** AI conversations extracted from browser cache, filtered and paged by cache timestamp. */
  aiConversations(hostDir: string, query: { start?: string; end?: string; offset: number; limit: number }): Promise<AiConversationPage>;
  aiConversationDetail(hostDir: string, rowId: number): Promise<AiConversationDetail>;
  /** WMI-Activity 로그의 구독 이벤트(5859~5861)만 서버에서 걸러 받는다. */
  wmiSubscriptionEvents(hostDir: string): Promise<WmiSubscriptionEvents>;
  /** PowerShellHistory 원문(절단 없는 컬럼) 검색 — 일치 rowid 집합 반환. */
  powershellSearchRowids(fullPath: string, query: string): Promise<number[]>;
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
  /** Bounded preview of the first matching value; the exact source row is
   * queried only after the analyst opens its detail panel. */
  matchValue: string;
  /** Candidate evidence time selected by the query without serialising the
   * complete SQLite row. Empty when the artifact provides no time. */
  timestamp: string;
  /** Bounded source-evidence pointer retained by overview rows. When present,
   * a bookmark must be stored against this raw record rather than the derived
   * overview row. Empty when the searched table has no source pointer. */
  recordKey: string;
}

export interface SearchCasePage {
  hits: SearchHit[];
  /** Offset cursor for requesting the next exact page; null means exhausted. */
  nextOffset: number | null;
  /** Sources that could not be searched. Results remain partial rather than
   * being silently presented as a complete empty search. */
  sourceFailures: string[];
}
