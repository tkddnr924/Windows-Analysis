// Tauri implementation of the `window.api` surface the React frontend expects
// (previously provided by the Electron preload). Maps each call onto a Tauri
// command (invoke) or the pipeline-log event stream (listen). Imported for its
// side effect at the top of the app entry so `window.api` exists before any
// component effect runs. No-ops on the server (static export) and outside a
// Tauri webview.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AccountDirectoryEntry, Bookmark, BookmarkInput, Case, CategoryEntry, CsvData, ElectronApi, Host,
  ListCasesResult, CacheMeta, CacheBodyPreview, BrowserVisitGraph, PathReference, PipelineLogEntry, PipelineResult, ResultFileEntry, ResultProvenance, ArtifactInputFile, ParseReport, RunHostOptions, SearchCasePage, AiConversation, AiConversationPage, AiConversationDetail, BrowserActivityQuery, BrowserActivitySummary, BrowserActivityInsights, BrowserDomainStatsPage, AccountEventPage, AccountEventQuery, AccountEventSource, ResultRow, MftRecordsPage, ParseLogPreview, WmiSubscriptionEvents, TimelineMeta, TimelineFacets, TimelinePage, TimelineSourcePage, TimelineQuery,
} from "./types";

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
    refreshExecutionHistoryOverview: (hostDir) => invoke<boolean>("refresh_execution_history_overview", { hostDir }),
    resultProvenance: (fullPath, tableName) => invoke<ResultProvenance[]>("result_provenance", { fullPath, tableName }),
    artifactInputFiles: (sourceFile) => invoke<ArtifactInputFile[]>("artifact_input_files", { sourceFile }),
    parseReport: (hostDir) => invoke<ParseReport | null>("parse_report", { hostDir }),
    parseRunLog: (hostDir, runId) => invoke<ParseLogPreview>("parse_run_log", { hostDir, runId }),
    accountDirectory: (hostDir) => invoke<AccountDirectoryEntry[]>("account_directory", { hostDir }),
    readResultFile: (fullPath, tableName) => invoke<CsvData>("read_result_file", { fullPath, tableName: tableName ?? null }),
    readResultFilePage: (fullPath, tableName, offset, limit) => invoke<CsvData>("read_result_file_page", { fullPath, tableName: tableName ?? null, offset, limit }),
    timelineSourcePage: (fullPath, tableName, offset, limit) => invoke<TimelineSourcePage>("timeline_source_page", { fullPath, tableName: tableName ?? null, offset, limit }),
    linkedResultRows: (fullPath, tableName, matchColumn, matchValue, search, offset, limit) => invoke("linked_result_rows", { fullPath, tableName, matchColumn, matchValue, search, offset, limit }),
    resultRow: (fullPath, tableName, rowid) => invoke<ResultRow>("result_row", { fullPath, tableName, rowid }),
    browserActivitySummary: (fullPath, tableName, query) => invoke<BrowserActivitySummary>("browser_activity_summary", { fullPath, tableName, query }),
    browserActivityInsights: (fullPath, tableName, account, start, end) => invoke<BrowserActivityInsights>("browser_activity_insights", { fullPath, tableName, account, start, end }),
    browserActivityDomains: (fullPath, tableName, account, start, end, offset, limit, ascending) => invoke<BrowserDomainStatsPage>("browser_activity_domains", { fullPath, tableName, account, start, end, offset, limit, ascending: ascending ?? null }),
    browserActivityPage: (fullPath, tableName, query) => invoke<CsvData>("browser_activity_page", { fullPath, tableName, query }),
    accountEventPage: (sources: AccountEventSource[], query: AccountEventQuery) => invoke<AccountEventPage>("account_event_page", { sources, query }),
    aiReferrals: (fullPath, tableName, start, end, offset, limit) => invoke<CsvData>("ai_referrals", { fullPath, tableName, start, end, offset, limit }),
    mftChildren: (fullPath, parentEntry, offset, limit) => invoke<import("./types").MftChildrenPage>("mft_children", { fullPath, parentEntry, offset, limit }),
    mftSearch: (fullPath, query, limit) => invoke<Record<string, string>[]>("mft_search", { fullPath, query, limit }),
    mftRow: (fullPath, rowid) => invoke<Record<string, string> | null>("mft_row", { fullPath, rowid }),
    usnJrnlPage: (fullPath, query) => invoke<CsvData>("usnjrnl_page", { fullPath, search: query.search ?? "", reason: query.reason ?? "", start: query.start ?? "", end: query.end ?? "", ascending: query.ascending ?? false, offset: query.offset, limit: query.limit }),
    mftRecordsPage: (fullPath, query, offset, limit, options) => invoke<MftRecordsPage>("mft_records_page", { fullPath, query, offset, limit, sortKey: options?.sortKey ?? null, sortDesc: options?.sortDesc ?? null, filesOnly: options?.filesOnly ?? null, namePattern: options?.namePattern ?? null, timeKey: options?.timeKey ?? null, timeStart: options?.timeStart ?? null, timeEnd: options?.timeEnd ?? null }),
    listColumnValues: (fullPath, column, tableName) =>
      invoke<{ value: string; count: number }[]>("list_column_values", { fullPath, column, tableName: tableName ?? null }),
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
    masterTimelinePage: (hostDir, query) => invoke<TimelinePage>("master_timeline_page", { hostDir, query }),
    pathReferences: (hostDir, paths) => invoke<PathReference[]>("path_references", { hostDir, paths }),
    pathReferenceAccounts: (hostDir) => invoke<string[]>("path_reference_accounts", { hostDir }),
    cacheEntryBody: (hostDir, account, url, cacheKey) => invoke<CacheBodyPreview>("cache_entry_body", { hostDir, account, url, cacheKey }),
    browserVisitGraph: (hostDir, account, url, cacheKey, sourceFile) => invoke<BrowserVisitGraph>("browser_visit_graph", { hostDir, account, url, cacheKey: cacheKey ?? null, sourceFile: sourceFile ?? null }),
    aiConversations: (hostDir, query) => invoke<AiConversationPage>("ai_conversations", { hostDir, query }),
    aiConversationDetail: (hostDir, rowId) => invoke<AiConversationDetail>("ai_conversation_detail", { hostDir, rowId }),
    wmiSubscriptionEvents: (hostDir) => invoke<WmiSubscriptionEvents>("wmi_subscription_events", { hostDir }),
    powershellSearchRowids: (fullPath, query) => invoke<number[]>("powershell_search_rowids", { fullPath, query }),
  };
}

if (typeof window !== "undefined") {
  // Assign only when not already provided (Electron preload wins if present).
  if (!window.api) {
    window.api = makeApi();
  }
}
