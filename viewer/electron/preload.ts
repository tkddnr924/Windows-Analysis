import { contextBridge, ipcRenderer } from "electron";
import type {
  Bookmark,
  BookmarkInput,
  CaseSummary,
  CategoryEntry,
  CsvData,
  PipelineLogEntry,
  PipelineResult,
  ResultFileEntry,
  RunCaseOptions,
} from "./types";

contextBridge.exposeInMainWorld("api", {
  pickFolder: (): Promise<string | null> => ipcRenderer.invoke("pick-folder"),
  listCases: (): Promise<CaseSummary[]> => ipcRenderer.invoke("list-cases"),
  createCase: (name: string, targetDir: string): Promise<CaseSummary> =>
    ipcRenderer.invoke("create-case", name, targetDir),
  listArtifacts: (): Promise<string[]> => ipcRenderer.invoke("list-artifacts"),
  runCase: (options: RunCaseOptions): Promise<PipelineResult> => ipcRenderer.invoke("run-case", options),
  cancelPipeline: (): Promise<boolean> => ipcRenderer.invoke("cancel-pipeline"),
  onPipelineLog: (callback: (entry: PipelineLogEntry) => void): (() => void) => {
    const listener = (_event: unknown, entry: PipelineLogEntry) => callback(entry);
    ipcRenderer.on("pipeline-log", listener);
    return () => ipcRenderer.removeListener("pipeline-log", listener);
  },
  listCategories: (caseDir: string): Promise<CategoryEntry[]> => ipcRenderer.invoke("list-categories", caseDir),
  listResultFiles: (categoryDir: string): Promise<ResultFileEntry[]> =>
    ipcRenderer.invoke("list-result-files", categoryDir),
  readResultFile: (fullPath: string): Promise<CsvData> => ipcRenderer.invoke("read-result-file", fullPath),
  listBookmarks: (caseDir: string): Promise<Bookmark[]> => ipcRenderer.invoke("list-bookmarks", caseDir),
  toggleBookmark: (caseDir: string, entry: BookmarkInput): Promise<Bookmark[]> =>
    ipcRenderer.invoke("toggle-bookmark", caseDir, entry),
  updateBookmarkNote: (caseDir: string, id: string, note: string): Promise<Bookmark[]> =>
    ipcRenderer.invoke("update-bookmark-note", caseDir, id, note),
});
