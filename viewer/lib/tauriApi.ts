// Tauri implementation of the `window.api` surface the React frontend expects
// (previously provided by the Electron preload). Maps each call onto a Tauri
// command (invoke) or the pipeline-log event stream (listen). Imported for its
// side effect at the top of the app entry so `window.api` exists before any
// component effect runs. No-ops on the server (static export) and outside a
// Tauri webview.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  Bookmark, BookmarkInput, Case, CategoryEntry, CsvData, ElectronApi, Host,
  ListCasesResult, CacheMeta, CacheBodyPreview, PathReference, PipelineLogEntry, PipelineResult, ResultFileEntry, ResultProvenance, ArtifactInputFile, ParseReport, RunHostOptions, SearchHit, AiConversation, AiConversationPage, BrowserActivityQuery, BrowserActivitySummary, BrowserActivityInsights, BrowserDomainStatsPage, AccountEventPage, AccountEventQuery, AccountEventSource, ResultRow,
} from "./types";

function makeApi(): ElectronApi {
  return {
    setWindowLayout: (layout) => invoke<void>("set_window_layout", { layout }),
    pickFolder: () => invoke<string | null>("pick_folder"),
    listCases: () => invoke<ListCasesResult>("list_cases"),
    createCase: (name) => invoke<Case>("create_case", { name }),
    createHost: (caseId, name, targetDir) => invoke<Host>("create_host", { caseId, name, targetDir }),
    deleteCase: (caseId) => invoke<boolean>("delete_case", { caseId }),
    deleteHost: (caseId, hostId) => invoke<boolean>("delete_host", { caseId, hostId }),
    listArtifacts: () => invoke<string[]>("list_artifacts"),
    runHost: (options: RunHostOptions) => invoke<PipelineResult>("run_host", { options }),
    cancelPipeline: () => invoke<boolean>("cancel_pipeline"),
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
    readResultFile: (fullPath, tableName) => invoke<CsvData>("read_result_file", { fullPath, tableName: tableName ?? null }),
    linkedResultRows: (fullPath, tableName, matchColumn, matchValue, search, offset, limit) => invoke("linked_result_rows", { fullPath, tableName, matchColumn, matchValue, search, offset, limit }),
    resultRow: (fullPath, tableName, rowid) => invoke<ResultRow>("result_row", { fullPath, tableName, rowid }),
    browserActivitySummary: (fullPath, tableName, query) => invoke<BrowserActivitySummary>("browser_activity_summary", { fullPath, tableName, query }),
    browserActivityInsights: (fullPath, tableName, account, start, end) => invoke<BrowserActivityInsights>("browser_activity_insights", { fullPath, tableName, account, start, end }),
    browserActivityDomains: (fullPath, tableName, account, start, end, offset, limit) => invoke<BrowserDomainStatsPage>("browser_activity_domains", { fullPath, tableName, account, start, end, offset, limit }),
    browserActivityPage: (fullPath, tableName, query) => invoke<CsvData>("browser_activity_page", { fullPath, tableName, query }),
    accountEventPage: (sources: AccountEventSource[], query: AccountEventQuery) => invoke<AccountEventPage>("account_event_page", { sources, query }),
    aiReferrals: (fullPath, tableName, start, end, offset, limit) => invoke<CsvData>("ai_referrals", { fullPath, tableName, start, end, offset, limit }),
    mftChildren: (fullPath, parentEntry) => invoke<Record<string, string>[]>("mft_children", { fullPath, parentEntry }),
    mftSearch: (fullPath, query, limit) => invoke<Record<string, string>[]>("mft_search", { fullPath, query, limit }),
    mftRow: (fullPath, rowid) => invoke<Record<string, string> | null>("mft_row", { fullPath, rowid }),
    listColumnValues: (fullPath, column, tableName) =>
      invoke<{ value: string; count: number }[]>("list_column_values", { fullPath, column, tableName: tableName ?? null }),
    searchCase: (query, hosts) => invoke<SearchHit[]>("search_case", { query, hosts }),
    listBookmarks: (caseDir) => invoke<Bookmark[]>("list_bookmarks", { caseDir }),
    toggleBookmark: (caseDir, entry: BookmarkInput) => invoke<Bookmark[]>("toggle_bookmark", { caseDir, entry }),
    updateBookmarkNote: (caseDir, id, note) => invoke<Bookmark[]>("update_bookmark_note", { caseDir, id, note }),
    pathReferences: (hostDir) => invoke<PathReference[]>("path_references", { hostDir }),
    cacheEntryBody: (hostDir, account, url, cacheKey) => invoke<CacheBodyPreview>("cache_entry_body", { hostDir, account, url, cacheKey }),
    aiConversations: (hostDir, query) => invoke<AiConversationPage>("ai_conversations", { hostDir, query }),
  };
}

if (typeof window !== "undefined") {
  // Assign only when not already provided (Electron preload wins if present).
  if (!window.api) {
    window.api = makeApi();
  }
}
