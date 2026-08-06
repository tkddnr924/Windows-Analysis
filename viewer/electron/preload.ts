import { contextBridge, ipcRenderer } from "electron";
import type {
  Bookmark,
  BookmarkInput,
  Case,
  Host,
  CategoryEntry,
  CsvData,
  ListCasesResult,
  PipelineLogEntry,
  PipelineResult,
  ResultFileEntry,
  RunHostOptions,
} from "./types";

contextBridge.exposeInMainWorld("api", {
  pickFolder: (): Promise<string | null> => ipcRenderer.invoke("pick-folder"),
  listCases: (): Promise<ListCasesResult> => ipcRenderer.invoke("list-cases"),
  createCase: (name: string): Promise<Case> => ipcRenderer.invoke("create-case", name),
  createHost: (caseId: string, name: string, targetDir: string): Promise<Host> =>
    ipcRenderer.invoke("create-host", caseId, name, targetDir),
  deleteCase: (caseId: string): Promise<boolean> => ipcRenderer.invoke("delete-case", caseId),
  deleteHost: (caseId: string, hostId: string): Promise<boolean> => ipcRenderer.invoke("delete-host", caseId, hostId),
  listArtifacts: (): Promise<string[]> => ipcRenderer.invoke("list-artifacts"),
  runHost: (options: RunHostOptions): Promise<PipelineResult> => ipcRenderer.invoke("run-host", options),
  cancelPipeline: (): Promise<boolean> => ipcRenderer.invoke("cancel-pipeline"),
  onPipelineLog: (callback: (entry: PipelineLogEntry) => void): (() => void) => {
    const listener = (_event: unknown, entry: PipelineLogEntry) => callback(entry);
    ipcRenderer.on("pipeline-log", listener);
    return () => ipcRenderer.removeListener("pipeline-log", listener);
  },
  listCategories: (caseDir: string): Promise<CategoryEntry[]> => ipcRenderer.invoke("list-categories", caseDir),
  listResultFiles: (categoryDir: string): Promise<ResultFileEntry[]> =>
    ipcRenderer.invoke("list-result-files", categoryDir),
  readResultFile: (fullPath: string, tableName?: string): Promise<CsvData> =>
    ipcRenderer.invoke("read-result-file", fullPath, tableName),
  listColumnValues: (fullPath: string, column: string, tableName?: string): Promise<{ value: string; count: number }[]> =>
    ipcRenderer.invoke("list-column-values", fullPath, column, tableName),
  listBookmarks: (caseDir: string): Promise<Bookmark[]> => ipcRenderer.invoke("list-bookmarks", caseDir),
  toggleBookmark: (caseDir: string, entry: BookmarkInput): Promise<Bookmark[]> =>
    ipcRenderer.invoke("toggle-bookmark", caseDir, entry),
  updateBookmarkNote: (caseDir: string, id: string, note: string): Promise<Bookmark[]> =>
    ipcRenderer.invoke("update-bookmark-note", caseDir, id, note),
});
