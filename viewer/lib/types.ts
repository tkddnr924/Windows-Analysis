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

/** Browser record filter (docs-07). Empty lists mean all. */
export interface BrowserFilter {
  inputIds?: string[];
  /** visit, url_summary, download, cache */
  kinds?: string[];
  day?: string;
  /** Records without a representative time; time filters do not apply. */
  untimed?: boolean;
  start?: string;
  end?: string;
  search?: string;
  /** Only stored AI referral markers. */
  referral?: boolean;
}

/** One collected browser input; label, confirmed account and SID stay apart. */
export interface BrowserInputInfo {
  inputId: string;
  inputKind: string;
  browser: string | null;
  profile: string | null;
  accountLabel: string | null;
  account: string | null;
  accountSid: string | null;
  sourceFile: string | null;
  recordCount: number;
}

export interface BrowserDomainStat {
  domain: string;
  /** Individual visit events on the host. */
  visitCount: number;
  urlCount: number;
}

export interface BrowserSummary {
  /** Event days (visit/download/cache); URL summaries excluded. */
  days: { value: string; count: number }[];
  untimed: number;
  kinds: { value: string; count: number }[];
  visitTotal: number;
  topDomains: BrowserDomainStat[];
  domainTotal: number;
  downloadTotal: number;
  downloads: Record<string, string>[];
}

export interface BrowserDomainPage {
  domains: BrowserDomainStat[];
  total: number;
}

export interface BrowserPage {
  rows: Record<string, string>[];
  rowCount: number;
}

/** One stored browser record with its relations; the cache body is separate. */
export interface BrowserRecord {
  row: Record<string, string>;
  input: Record<string, string> | null;
  urlSummary: Record<string, string> | null;
  searchTerms: Record<string, string>[];
  downloadChain: Record<string, string>[];
  cache: Record<string, string> | null;
  sources: Record<string, string>[];
}

export interface BrowserCacheBody {
  dataB64: string;
  offset: number;
  total: number;
}

export interface VisitFlowNode {
  recordId: string;
  visitId: string;
  url: string;
  title: string;
  time: string;
  transition: string;
  qualifiers: string;
  externalReferrer: string;
  isTarget: boolean;
}

export interface VisitFlowEdge {
  from: string;
  to: string;
  /** "from_visit" (same tab) | "opener_visit" (new tab). */
  kind: string;
}

export interface BrowserVisitFlow {
  nodes: VisitFlowNode[];
  edges: VisitFlowEdge[];
  truncated: boolean;
}

export interface AiQuery {
  /** conversation | list_entry */
  kind?: string;
  untimed?: boolean;
  start?: string;
  end?: string;
  search?: string;
  offset: number;
  limit: number;
  ascending?: boolean;
}

export interface AiPage {
  rows: Record<string, string>[];
  rowCount: number;
  kinds: { value: string; count: number }[];
}

export interface AiRecord {
  row: Record<string, string>;
  messages: Record<string, string>[];
  attachments: Record<string, string>[];
  interpretation: string | null;
  sources: Record<string, string>[];
  snapshots: Record<string, string>[];
}

export interface AiResponseChunk {
  data: string;
  offset: number;
  total: number;
}

/** One collected machine: a target folder + its parsed output. This is the
 * browsable unit — artifacts live under the direct host folder. */
export interface Host {
  id: string;
  name: string;
  targetDir: string;
  /** windows_analysis_cases/<hostId>/ — holds this host's parsed output. */
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
  /** windows_analysis_cases/ (root host store) */
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
  /** True for _OVERVIEW contract (derived) DBs; false for raw parser facts. */
  derived?: boolean;
  /** Set when the file or table could not be read (not 0 rows). */
  readError?: string;
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

/** Parse button state (UI-01). `reason` is the Korean sentence shown as-is; a
 * failed check rejects the call instead of returning a value. */
export interface ParseEligibility {
  canParse: boolean;
  reason: string;
}

/** An analyst annotation on one _OVERVIEW record (docs-20), persisted in
 * `windows_analysis_cases/bookmarks.json`. Re-parsing a host removes its bookmarks. */
export interface Bookmark {
  id: string;
  /** `_OVERVIEW/<table>.sqlite` of the record. */
  fullPath: string;
  tableName: string;
  recordId: string;
  note: string;
  taggedAt: string;
  /** Selected time field (e.g. si_created); absent for whole-row bookmarks. */
  field?: string;
  /** Time shown when the bookmark was set (field value or row timestamp). */
  eventTime?: string;
  hostId?: string;
  hostName?: string;
}

export interface BookmarkInput {
  fullPath: string;
  tableName: string;
  recordId: string;
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

/** One collected `$J` input (internal key — not a volume or journal ID). */
export interface UsnInput {
  input_id: string;
  input_name: string | null;
  source_relative: string | null;
  record_count: number;
  group_count: number;
}

export interface UsnFilterOption {
  value: string;
  count: number;
}

export interface UsnOverview {
  inputs: UsnInput[];
  eventTypes: UsnFilterOption[];
  reasonFlags: UsnFilterOption[];
}

/** A group is listed when one member meets every member condition. */
export interface UsnGroupOptions {
  inputId?: string;
  /** File name or stored reason text of a member. */
  search?: string;
  /** Representative type of the stored group. */
  eventType?: string;
  /** Full reasons: any of these flags on a member. */
  reasonFlags?: string[];
  timeStart?: string;
  timeEnd?: string;
  descending?: boolean;
}

/** Stored group, every member (stored order, `__matched` = "true" for hits) and rename events. */
export interface UsnGroupEntry {
  group: Record<string, string>;
  members: Record<string, string>[];
  renames: UsnRenameEntry[];
}

/** Stored rename event and every OLD/NEW candidate (parent reference from its journal record). */
export interface UsnRenameEntry {
  event: Record<string, string>;
  candidates: Record<string, string>[];
}

export interface UsnGroupsPage {
  groups: UsnGroupEntry[];
  total: number;
}

/** One stored registry hive input (docs-06), loaded or not. */
export interface RegistryHive {
  hiveId: string;
  ordinal: number;
  hiveName: string;
  sourceFile: string | null;
  inventorySource: string;
  inputStatus: string | null;
  loadStatus: string;
  loadError: string | null;
  inputError: string | null;
  isRegback: boolean;
  keyCount: number;
  valueCount: number;
  rootCount: number;
  logsDiscovered: number | null;
  logsApplied: number | null;
  logError: string | null;
  unresolvedCount: number;
}

/** One page of keys or values with the full count. */
export interface RegistryRowsPage {
  rows: Record<string, string>[];
  total: number;
}

/** A slice of a value's stored hex (byte-aligned) or text. */
export interface RegistryValueChunk {
  data: string;
  offset: number;
  total: number;
}

export interface RegistryAncestor {
  recordId: string;
  keyName: string | null;
  parentStatus: string | null;
  /** Position among siblings in tree order. */
  position: number;
}

export interface RegistryEntry {
  entry: Record<string, string>;
  key: Record<string, string>;
  ancestors: RegistryAncestor[];
}

export interface RegistrySearchOptions {
  query: string;
  hiveId?: string;
  keyRecordId?: string;
  keys?: boolean;
  valueNames?: boolean;
  valueData?: boolean;
}

export interface RegistrySearchHit {
  recordId: string;
  rowid: number;
  entryKind: "key" | "value";
  hiveId: string;
  keyRecordId: string;
  keyPath: string | null;
  valueName: string | null;
  valueDisplayName: string | null;
  valueTypeName: string | null;
  /** "key" | "value_name" | "value_data" | "value_hex" */
  fields: string[];
  snippet: string | null;
}

export interface RegistrySearchPage {
  hits: RegistrySearchHit[];
  /** Resume after this rowid; null = scanned to the end of the scope. */
  nextCursor: number | null;
  scannedTo: number;
  rangeStart: number;
  rangeEnd: number;
}

export interface RegistryQuickAccess {
  available: boolean;
  items: { finding: Record<string, string>; targets: Record<string, string>[] }[];
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
  /** 원시 테이블이 보관한 `<테이블>::<rowid>` 포인터. 파생 행은 비어 있다. */
  recordKey: string;
  /** 파생 레코드 ID. 화면 식별·조회는 (파일·표·rowid)로 하므로 표시에는 쓰지
   * 않는다 — 재파싱 전후 기록을 잇는 키가 아니라는 계약(docs-01)을 화면이
   * 어기지 않게 보관만 한다. */
  recordId: string;
  eventTime: string;
  /** 원본 행 — 백엔드가 페이지마다 원본 파일에서 읽어 붙인다. */
  row: Record<string, string>;
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

/** A PathReferences row the parser linked to a file record as a candidate
 * (PathReferenceCandidates) — path evidence, never "the same file". */
export interface FileReference {
  fileRecordId: string;
  /** "path" | "path_and_drive" */
  matchBasis: string;
  /** Stored PathReferences row (all columns). */
  row: Record<string, string>;
}

/** Recursive file list filters (docs-04 §3). */
export interface MftListOptions {
  sortKey?: string;
  sortDesc?: boolean;
  /** "file" | "dir" | undefined (both) */
  kind?: string;
  /** 1 in use, 0 not in use, undefined both */
  inUse?: number;
  extension?: string;
  namePattern?: string;
  pathPrefix?: string;
  excludePaths?: string[];
  sizeMin?: number;
  sizeMax?: number;
  pathIncomplete?: boolean;
  residentOnly?: boolean;
  siBeforeFn?: boolean;
  /** Period filter fields; a record matches when any of them is in range. */
  timeKeys?: string[];
  timeStart?: string;
  timeEnd?: string;
  volumeId?: string;
}


/** Server-side filters for one TargetInfo account's stored activity
 * (TargetAccountEvents). `recordId` is the account parent record_id. */
export interface AccountEventQuery {
  recordId: string;
  /** Result generation the account row was loaded from. */
  datasetId: string;
  search?: string;
  start?: string;
  end?: string;
  offset: number;
  limit: number;
}

/** One bounded, ordered page of stored account activity. Rows use EventLog
 * keys plus the raw source coordinates used as the bookmark key. */
export interface AccountEventPage {
  rows: Record<string, string>[];
  rowCount: number;
  /** Result predates target_info=2: re-parse needed, not "no activity". */
  stale: boolean;
  /** The account row's result generation was replaced: reload the host view. */
  replaced: boolean;
}

/** A display-only exact SID-to-account mapping, read from the host's
 * Metadata.sqlite (kind='account', scope='machine', key=lower(SID)).
 * `sourceArtifact` is metadata.name_source — where the name was confirmed. */
export interface AccountDirectoryEntry {
  sid: string;
  accountName: string;
  sourceArtifact: string;
}

/** 결과 DB의 한 행 — 셀은 TEXT이거나 NULL(미확인)이다. INTEGER·REAL은 IPC
 * 경계(lib/tauriApi.ts)에서 문자열로 정규화하고 NULL은 그대로 둔다. 그래서
 * 0/1 플래그는 "0"/"1", 미확인은 null로 도착한다 — 빈 문자열과 구분된다. */
export type DBRow = Record<string, string>;

/** FileSystemEntries가 담은 입력(볼륨) 문맥. 같은 값이라고 해서 실제로
 * 같은 볼륨이라는 증거는 아니다(docs-01). */
export interface MftVolume {
  volume_id: string;
  volume_label: string | null;
  drive_letter: string | null;
  input_name: string | null;
  source_relative: string | null;
  record_count: string;
}

/** 상주 $DATA 본문 — 상세에서 명시적으로 요청할 때만 받는다. dataPresent가
 * null이면 비상주·미확보이고, 길이 0 BLOB(dataLen 0)과 다르다. dataStatus는
 * 파서가 저장한 상태(resident/resident_empty/nonresident/unavailable/not_applicable). */
export interface MftRecordBody {
  dataPresent: true | null;
  dataLen: number | null;
  truncated: boolean;
  bodyB64: string | null;
  dataStatus: string | null;
}

/** Metadata.sqlite 조회 결과 — 부모 metadata 행과 그 자식 테이블들. */
export interface HostMetadata {
  rows: DBRow[];
  addresses: DBRow[];
  gateways: DBRow[];
  dnsServers: DBRow[];
  groups: DBRow[];
  candidates: DBRow[];
}

/** 발행된 파생 DB가 현재 저장 계약(overview_contract 1)을 따르는지. 맞지
 * 않으면 화면은 재파싱을 안내한다 — 읽는 시점에 DB를 고쳐 쓰지 않는다. */
export interface OverviewContractStatus {
  contractOk: boolean;
  legacyFiles: string[];
}

export interface ElectronApi {
  /** Resize the single desktop window to fit the current application stage. */
  pickFolder(): Promise<string | null>;
  listCases(): Promise<ListCasesResult>;
  createHost(caseId: string, name: string, targetDir: string): Promise<Host>;
  /** Changes display metadata only; evidence and result paths remain immutable. */
  renameHost(caseId: string, hostId: string, name: string): Promise<Host>;
  deleteHost(caseId: string, hostId: string): Promise<boolean>;
  listArtifacts(): Promise<string[]>;
  runHost(options: RunHostOptions): Promise<PipelineResult>;
  /** Omit runId only for the explicit cancel-all action. */
  cancelPipeline(runId?: string, cancelAll?: boolean): Promise<boolean>;
  onPipelineLog(callback: (entry: PipelineLogEntry) => void): () => void;
  /** hostDir = a host's direct windows_analysis_cases/<hostId>/ folder. */
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
  /** 발행된 파생 DB가 저장 계약을 따르는지 확인한다. 읽기 전용이다 — 낡은
   * 결과는 다시 쓰지 않고 재파싱을 안내한다. */
  overviewContractStatus(hostDir: string): Promise<OverviewContractStatus>;
  parseReport(hostDir: string): Promise<ParseReport | null>;
  /** Reads a bounded immutable run log; never scans or reparses evidence. */
  parseRunLog(hostDir: string, runId: string): Promise<ParseLogPreview>;
  /** Reports whether new evidence appeared since the last parse. Reads existing
   * run reports and lists collection files only; it never writes. */
  hostParseEligibility(caseId: string, hostId: string): Promise<ParseEligibility>;
  /** Opens the stored run log with the OS default application (UI-05). */
  openParseRunLog(hostDir: string, runId: string): Promise<void>;
  /** Metadata.sqlite의 계정 조회 결과. 증거를 다시 파싱하지 않는다. */
  accountDirectory(hostDir: string): Promise<AccountDirectoryEntry[]>;
  /** 호스트 공통 참조 정보(Metadata.sqlite) — 호스트 화면의 상세 속성. */
  hostMetadata(hostDir: string, options?: { metadataIds?: string[]; kind?: string }): Promise<HostMetadata>;
  /** 한 결과 행의 상세 전용 자식 표(ExecutionTimes·TaskActions 등) 행들.
   * 목록·검색에는 올리지 않고 행 상세에서만 조회한다. `via`: 자식 표를 링크로
   * 써서 `via.table`의 record_id = 링크 행 `via.key` 행을 돌려준다(링크 컬럼은 `link.` 접두).
   * `key`: 부모 record_id를 담은 자식 컬럼(기본 record_id). */
  readRecordChildren(fullPath: string, tableName: string, rowid: number, childTable: string, options?: { key?: string; via?: { table: string; key: string } }): Promise<DBRow[]>;
  readResultFile(fullPath: string, tableName?: string): Promise<CsvData>;
  readResultFilePage(fullPath: string, tableName: string | undefined, offset: number, limit: number): Promise<CsvData>;
  timelineSourcePage(fullPath: string, tableName: string | undefined, offset: number, limit: number): Promise<TimelineSourcePage>;
  linkedResultRows(fullPath: string, tableName: string, matchColumn: string, matchValue: string, search: string, offset: number, limit: number): Promise<LinkedRowsPage>;
  resultRow(fullPath: string, tableName: string, rowid: number): Promise<ResultRow>;
  resultRowByRecordId(fullPath: string, tableName: string, recordId: string): Promise<ResultRow>;
  /** docs-21: analyst-added host addresses (cleared on re-parse). */
  listAnalystAddresses(hostDir: string): Promise<string[]>;
  addAnalystAddress(hostDir: string, address: string): Promise<string[]>;
  removeAnalystAddress(hostDir: string, address: string): Promise<string[]>;
  browserScope(fullPath: string): Promise<BrowserInputInfo[]>;
  browserSummary(fullPath: string, filter: BrowserFilter): Promise<BrowserSummary>;
  browserDomains(fullPath: string, filter: BrowserFilter, offset: number, limit: number, ascending: boolean): Promise<BrowserDomainPage>;
  browserPage(fullPath: string, filter: BrowserFilter, offset: number, limit: number, descending: boolean): Promise<BrowserPage>;
  /** Record-level reads resolve `_OVERVIEW/BrowserActivity.sqlite` under the host. */
  browserRecord(hostDir: string, recordId: string): Promise<BrowserRecord>;
  browserCacheBody(hostDir: string, recordId: string, offset: number, length: number): Promise<BrowserCacheBody>;
  browserVisitFlow(hostDir: string, recordId: string): Promise<BrowserVisitFlow>;
  accountEventPage(hostDir: string, query: AccountEventQuery): Promise<AccountEventPage>;
  aiPage(fullPath: string, query: AiQuery): Promise<AiPage>;
  aiRecord(fullPath: string, recordId: string): Promise<AiRecord>;
  aiResponseBody(fullPath: string, sourceDb: string, sourceTable: string, sourceRowid: number, offset: number, length: number): Promise<AiResponseChunk>;
  /** parentEntry null = 부모 연결 미확인 묶음. parentSeq null + parentEntry = 볼륨 루트. */
  mftChildren(fullPath: string, parentEntry: number | null, parentSeq: number | null, offset?: number, limit?: number, volumeId?: string): Promise<MftChildrenPage>;
  mftSearch(fullPath: string, query: string, limit: number, volumeId?: string): Promise<DBRow[]>;
  /** 상주 $DATA 본문 — 상세에서 분석가가 요청할 때만 호출한다. */
  mftRecordBody(fullPath: string, rowid: number, volumeId?: string): Promise<MftRecordBody>;
  /** 결과가 담은 볼륨 문맥 목록. 선택한 볼륨 안에서만 경로·부모를 해석한다. */
  mftVolumes(dbPath: string): Promise<MftVolume[]>;
  mftRecordsPage(fullPath: string, query: string, offset: number, limit: number, options?: MftListOptions): Promise<MftRecordsPage>;
  /** docs-05 inputs + stored representative types / reason flags of one input. */
  usnOverview(fullPath: string, inputId?: string): Promise<UsnOverview>;
  /** Stored change groups with every member and rename event. */
  usnGroupsPage(fullPath: string, options: UsnGroupOptions, offset: number, limit: number): Promise<UsnGroupsPage>;
  registryHives(fullPath: string): Promise<RegistryHive[]>;
  /** parentRecordId null: hive roots (or the unresolved bucket). */
  registryKeys(fullPath: string, hiveId: string, parentRecordId: string | null, unresolved: boolean, offset: number, limit: number): Promise<RegistryRowsPage>;
  registryValues(fullPath: string, keyRecordId: string, offset: number, limit: number): Promise<RegistryRowsPage>;
  registryEntry(fullPath: string, recordId: string): Promise<RegistryEntry>;
  /** Data past the detail cap: `offset`/`length` in hex digits or characters. */
  registryValueChunk(fullPath: string, recordId: string, field: "hex" | "text", offset: number, length: number): Promise<RegistryValueChunk>;
  registrySearch(fullPath: string, options: RegistrySearchOptions, cursor: number | null, limit: number): Promise<RegistrySearchPage>;
  registryQuickAccess(fullPath: string): Promise<RegistryQuickAccess>;
  searchCase(query: string, hosts: { id: string; name: string; dir: string }[], offset: number, limit: number, range?: { start?: string; end?: string }, categories?: string[]): Promise<SearchCasePage>;
  listBookmarks(hostDir: string): Promise<Bookmark[]>;
  toggleBookmark(hostDir: string, entry: BookmarkInput): Promise<Bookmark[]>;
  /** Stored candidate references for the file records on screen. */
  fileReferences(hostDir: string, datasetId: string, volumeId: string | undefined, fileRecordIds: string[]): Promise<FileReference[]>;
  pathReferenceAccounts(hostDir: string): Promise<string[]>;
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
  /** 파생 레코드 ID(record_id). */
  recordId: string;
}

export interface SearchCasePage {
  hits: SearchHit[];
  /** Offset cursor for requesting the next exact page; null means exhausted. */
  nextOffset: number | null;
  /** Sources that could not be searched. Results remain partial rather than
   * being silently presented as a complete empty search. */
  sourceFailures: string[];
}
