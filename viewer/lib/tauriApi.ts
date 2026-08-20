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
  ListCasesResult, CacheEntry, PathReference, PipelineLogEntry, PipelineResult, ResultFileEntry, RunHostOptions, SearchHit,
} from "./types";

function makeApi(): ElectronApi {
  return {
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
    readResultFile: (fullPath, tableName) => invoke<CsvData>("read_result_file", { fullPath, tableName: tableName ?? null }),
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
    cacheEntries: (hostDir) => invoke<CacheEntry[]>("cache_entries", { hostDir }),
  };
}

if (typeof window !== "undefined") {
  // Assign only when not already provided (Electron preload wins if present).
  if (!window.api) {
    window.api = makeApi();
  }
}
