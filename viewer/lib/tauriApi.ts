// Tauri implementation of the `window.api` surface the React frontend expects
// (previously provided by the Electron preload). Maps each call onto a Tauri
// command (invoke) or the pipeline-log event stream (listen). Imported for its
// side effect at the top of the app entry so `window.api` exists before any
// component effect runs. No-ops on the server (static export) and outside a
// Tauri webview.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AccountDirectoryEntry, Bookmark, BookmarkInput, Case, CategoryEntry, CsvData, DBRow, ElectronApi, Host, HostMetadata, LinkedRowsPage, MftChildrenPage,
  ListCasesResult, CacheMeta, CacheBodyPreview, BrowserVisitGraph, PathReference, PipelineLogEntry, PipelineResult, ResultFileEntry, ResultProvenance, ArtifactInputFile, ParseReport, ParseEligibility, RunHostOptions, SearchCasePage, AiConversation, AiConversationPage, AiConversationDetail, BrowserActivityQuery, BrowserActivitySummary, BrowserActivityInsights, BrowserDomainStatsPage, AccountEventPage, AccountEventQuery, AccountEventSource, MftRecordBody, MftVolume, OverviewContractStatus, RecordSource, ResultRow, MftRecordsPage, ParseLogPreview, TimelineMeta, TimelineFacets, TimelinePage, TimelineSourcePage, TimelineQuery,
} from "./types";

// 저장 계약(docs-01)의 결과 DB는 INTEGER·REAL 컬럼을 쓴다. 화면 코드는 셀을
// 문자열로 다루므로 IPC 경계에서 숫자만 문자열로 바꾼다. NULL은 그대로 둔다 —
// "미확인"과 "빈 값"은 증거 판단이 다르기 때문에 합치지 않는다.
function cells<T>(row: T): T {
  const raw = row as unknown as Record<string, unknown>;
  for (const key in raw) {
    const value = raw[key];
    if (typeof value === "number" || typeof value === "boolean") raw[key] = String(value);
  }
  return row;
}

function rows<T>(list: T[]): T[] {
  for (const row of list) cells(row);
  return list;
}

function table<T extends { rows: Record<string, string>[] }>(data: T): T {
  rows(data.rows);
  return data;
}

function makeApi(): ElectronApi {
  return {
    pickFolder: () => invoke<string | null>("pick_folder"),
    listCases: () => invoke<ListCasesResult>("list_cases"),
    createCase: (name) => invoke<Case>("create_case", { name }),
    createHost: (caseId, name, targetDir) => invoke<Host>("create_host", { caseId, name, targetDir }),
    renameHost: (caseId, hostId, name) => invoke<Host>("rename_host", { caseId, hostId, name }),
    deleteCase: (caseId) => invoke<boolean>("delete_case", { caseId }),
    deleteHost: (caseId, hostId) => invoke<boolean>("delete_host", { caseId, hostId }),
    listArtifacts: () => invoke<string[]>("list_artifacts"),
    runHost: (options: RunHostOptions) => invoke<PipelineResult>("run_host", { options }),
    cancelPipeline: (runId, cancelAll) => invoke<boolean>("cancel_pipeline", { runId: runId ?? null, cancelAll: cancelAll ?? false }),
    onPipelineLog: (callback: (entry: PipelineLogEntry) => void) => {
      let unlisten: (() => void) | null = null;
      let cancelled = false;
      listen<PipelineLogEntry>("pipeline-log", (e) => callback(e.payload)).then((f) => {
        if (cancelled) f();
        else unlisten = f;
      });
      return () => { cancelled = true; if (unlisten) unlisten(); };
    },
    listCategories: (hostDir) => invoke<CategoryEntry[]>("list_categories", { hostDir }),
    listResultFiles: (categoryDir) => invoke<ResultFileEntry[]>("list_result_files", { categoryDir }),
    overviewContractStatus: (hostDir) => invoke<OverviewContractStatus>("overview_contract_status", { hostDir }),
    resultProvenance: (fullPath, tableName) => invoke<ResultProvenance[]>("result_provenance", { fullPath, tableName }),
    artifactInputFiles: (sourceFile) => invoke<ArtifactInputFile[]>("artifact_input_files", { sourceFile }),
    parseReport: (hostDir) => invoke<ParseReport | null>("parse_report", { hostDir }),
    parseRunLog: (hostDir, runId) => invoke<ParseLogPreview>("parse_run_log", { hostDir, runId }),
    hostParseEligibility: (caseId, hostId) => invoke<ParseEligibility>("host_parse_eligibility", { caseId, hostId }),
    openParseRunLog: (hostDir, runId) => invoke<void>("open_parse_run_log", { hostDir, runId }),
    accountDirectory: (hostDir) => invoke<AccountDirectoryEntry[]>("account_directory", { hostDir }),
    hostMetadata: (hostDir, options) => invoke<HostMetadata>("host_metadata", { hostDir, metadataIds: options?.metadataIds ?? null, kind: options?.kind ?? null })
      .then((meta) => { rows(meta.rows); rows(meta.addresses); rows(meta.gateways); rows(meta.dnsServers); rows(meta.groups); rows(meta.candidates); return meta; }),
    readRecordSources: (fullPath, tableName, rowid) => invoke<RecordSource[]>("read_record_sources", { fullPath, tableName, rowid }).then(rows),
    readRecordChildren: (fullPath, tableName, rowid, childTable) => invoke<DBRow[]>("read_record_children", { fullPath, tableName, rowid, childTable }).then(rows),
    readResultFile: (fullPath, tableName) => invoke<CsvData>("read_result_file", { fullPath, tableName: tableName ?? null }).then(table),
    readResultFilePage: (fullPath, tableName, offset, limit) => invoke<CsvData>("read_result_file_page", { fullPath, tableName: tableName ?? null, offset, limit }).then(table),
    timelineSourcePage: (fullPath, tableName, offset, limit) => invoke<TimelineSourcePage>("timeline_source_page", { fullPath, tableName: tableName ?? null, offset, limit }).then(table),
    linkedResultRows: (fullPath, tableName, matchColumn, matchValue, search, offset, limit) => invoke<LinkedRowsPage>("linked_result_rows", { fullPath, tableName, matchColumn, matchValue, search, offset, limit }).then(table),
    resultRow: (fullPath, tableName, rowid) => invoke<ResultRow>("result_row", { fullPath, tableName, rowid }).then((result) => { if (result.row) cells(result.row); return result; }),
    browserActivitySummary: (fullPath, tableName, query) => invoke<BrowserActivitySummary>("browser_activity_summary", { fullPath, tableName, query }),
    browserActivityInsights: (fullPath, tableName, account, start, end) => invoke<BrowserActivityInsights>("browser_activity_insights", { fullPath, tableName, account, start, end })
      .then((insights) => { rows(insights.downloads); return insights; }),
    browserActivityDomains: (fullPath, tableName, account, start, end, offset, limit, ascending) => invoke<BrowserDomainStatsPage>("browser_activity_domains", { fullPath, tableName, account, start, end, offset, limit, ascending: ascending ?? null }),
    browserActivityPage: (fullPath, tableName, query) => invoke<CsvData>("browser_activity_page", { fullPath, tableName, query }).then(table),
    accountEventPage: (sources: AccountEventSource[], query: AccountEventQuery) => invoke<AccountEventPage>("account_event_page", { sources, query }).then(table),
    aiReferrals: (fullPath, tableName, start, end, offset, limit) => invoke<CsvData>("ai_referrals", { fullPath, tableName, start, end, offset, limit }).then(table),
    // 볼륨 문맥은 호출자가 고른 값만 넘긴다 — 미지정은 볼륨 구분 없는 조회다.
    mftChildren: (fullPath, parentEntry, offset, limit, volumeId) => invoke<MftChildrenPage>("mft_children", { fullPath, parentEntry: parentEntry ?? null, offset, limit, volumeId: volumeId ?? null }).then(table),
    mftSearch: (fullPath, query, limit, volumeId) => invoke<DBRow[]>("mft_search", { fullPath, query, limit, volumeId: volumeId ?? null }).then(rows),
    mftRow: (fullPath, rowid, volumeId) => invoke<DBRow | null>("mft_row", { fullPath, rowid, volumeId: volumeId ?? null }).then((row) => (row ? cells(row) : row)),
    mftRecordBody: (fullPath, rowid, volumeId) => invoke<MftRecordBody>("mft_record_body", { fullPath, rowid, volumeId: volumeId ?? null }),
    mftVolumes: (dbPath) => invoke<MftVolume[]>("mft_volumes", { dbPath }).then(rows),
    usnJrnlPage: (fullPath, query) => invoke<CsvData>("usnjrnl_page", { fullPath, search: query.search ?? "", reason: query.reason ?? "", start: query.start ?? "", end: query.end ?? "", ascending: query.ascending ?? false, offset: query.offset, limit: query.limit }).then(table),
    mftRecordsPage: (fullPath, query, offset, limit, options) => invoke<MftRecordsPage>("mft_records_page", { fullPath, query, offset, limit, sortKey: options?.sortKey ?? null, sortDesc: options?.sortDesc ?? null, filesOnly: options?.filesOnly ?? null, namePattern: options?.namePattern ?? null, timeKey: options?.timeKey ?? null, timeStart: options?.timeStart ?? null, timeEnd: options?.timeEnd ?? null, volumeId: options?.volumeId ?? null }).then(table),
    listColumnValues: (fullPath, column, tableName) =>
      invoke<{ value: string; count: number }[]>("list_column_values", { fullPath, column, tableName: tableName ?? null })
        .then((values) => values.map((entry) => ({ ...entry, value: entry.value === null ? entry.value : String(entry.value) }))),
    searchCase: (query, hosts, offset, limit, range, categories) => invoke<SearchCasePage>("search_case", { query, hosts, offset, limit, start: range?.start || null, end: range?.end || null, categories: categories && categories.length ? categories : null }),
    listBookmarks: (caseDir) => invoke<Bookmark[]>("list_bookmarks", { caseDir }),
    toggleBookmark: (caseDir, entry: BookmarkInput) => invoke<Bookmark[]>("toggle_bookmark", { caseDir, entry }),
    updateBookmarkNote: (caseDir, id, note) => invoke<Bookmark[]>("update_bookmark_note", { caseDir, id, note }),
    // 타임라인 전량을 한 번에 넘기면 요청 직렬화·파싱이 메인 스레드를 수 초
    // 막는다 — 원본을 청크로 읽어 NDJSON 배치로 흘려 넣는다(begin →
    // [insert → drain]* → finish, 마지막에 원자 rename). 매 배치 후 drain을
    // await해 in-flight를 1배치로 묶으므로 메인 스레드·메모리 피크가 상수다.
    masterTimelineBuildBegin: (hostDir, token, builtForRunAt) => invoke<void>("master_timeline_build_begin", { hostDir, token, builtForRunAt }),
    masterTimelineBuildInsert: (hostDir, token, ndjson) => invoke<void>("master_timeline_build_insert", { hostDir, token, ndjson }),
    masterTimelineBuildDrain: (token) => invoke<void>("master_timeline_build_drain", { token }),
    masterTimelineBuildFinish: (hostDir, token) => invoke<void>("master_timeline_build_finish", { hostDir, token }),
    masterTimelineBuildAbort: (hostDir, token) => invoke<void>("master_timeline_build_abort", { hostDir, token }),
    masterTimelineMeta: (hostDir) => invoke<TimelineMeta>("master_timeline_meta", { hostDir }),
    masterTimelineFacets: (hostDir) => invoke<TimelineFacets>("master_timeline_facets", { hostDir }),
    masterTimelinePage: (hostDir, query) => invoke<TimelinePage>("master_timeline_page", { hostDir, query })
      .then((page) => { for (const row of page.rows) cells(row.row); return page; }),
    pathReferences: (hostDir, paths) => invoke<PathReference[]>("path_references", { hostDir, paths })
      .then((references) => { for (const reference of references) cells(reference.fields); return references; }),
    pathReferenceAccounts: (hostDir) => invoke<string[]>("path_reference_accounts", { hostDir }),
    cacheEntryBody: (hostDir, account, url, cacheKey) => invoke<CacheBodyPreview>("cache_entry_body", { hostDir, account, url, cacheKey }),
    browserVisitGraph: (hostDir, account, url, cacheKey, sourceFile) => invoke<BrowserVisitGraph>("browser_visit_graph", { hostDir, account, url, cacheKey: cacheKey ?? null, sourceFile: sourceFile ?? null }),
    aiConversations: (hostDir, query) => invoke<AiConversationPage>("ai_conversations", { hostDir, query }),
    aiConversationDetail: (hostDir, rowId) => invoke<AiConversationDetail>("ai_conversation_detail", { hostDir, rowId }),
    powershellSearchRowids: (fullPath, query) => invoke<number[]>("powershell_search_rowids", { fullPath, query }),
  };
}

if (typeof window !== "undefined") {
  // Assign only when not already provided (Electron preload wins if present).
  if (!window.api) {
    window.api = makeApi();
  }
}
