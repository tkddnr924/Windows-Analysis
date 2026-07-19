import { app, BrowserWindow, dialog, ipcMain, type IpcMainInvokeEvent } from "electron";
import { spawn, type ChildProcessWithoutNullStreams } from "child_process";
import Database from "better-sqlite3";
import * as fs from "fs";
import * as path from "path";
import type {
  Bookmark,
  BookmarkInput,
  CaseSummary,
  CategoryEntry,
  CsvData,
  PipelineLogEntry,
  PipelineResult,
  ProjectRootStatus,
  ResultFileEntry,
  RunCaseOptions,
} from "./types";

const isDev = process.env.NODE_ENV === "development";

// In dev, viewer/electron/main.ts -> project root is two levels up, and the
// pipeline (main.py), its venv, and cases/ all live there. A packaged build
// has no such fixed relationship — electron-builder's portable target
// self-extracts to a temp directory at runtime, so __dirname no longer
// points anywhere near the actual Windows-Analysis checkout. In that case
// the user must explicitly point the app at their checkout folder (the one
// containing main.py/venv/cases), persisted here across restarts.
interface AppConfig {
  projectRoot?: string;
}

// Computed lazily (not at module load) — app.getPath() is only reliably
// valid after the 'ready' event, and every caller here runs from an
// ipcMain handler, which is always well after that.
function configPath(): string {
  return path.join(app.getPath("userData"), "config.json");
}

function readAppConfig(): AppConfig {
  try {
    return JSON.parse(fs.readFileSync(configPath(), "utf-8"));
  } catch {
    return {};
  }
}

function writeAppConfig(config: AppConfig): void {
  const file = configPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(config, null, 2), "utf-8");
}

function defaultProjectRoot(): string {
  return path.resolve(__dirname, "..", "..");
}

function isValidProjectRoot(root: string): boolean {
  return fs.existsSync(path.join(root, "main.py"));
}

function projectRoot(): string {
  if (isDev) return defaultProjectRoot();
  return readAppConfig().projectRoot ?? defaultProjectRoot();
}

function pythonExe(): string {
  return path.join(projectRoot(), "venv", "Scripts", "python.exe");
}

function mainPy(): string {
  return path.join(projectRoot(), "main.py");
}

function casesDir(): string {
  return path.join(projectRoot(), "cases");
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    backgroundColor: "#1e1e1e",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (isDev) {
    win.loadURL("http://localhost:3000");
  } else {
    win.loadFile(path.join(__dirname, "..", "out", "index.html"));
  }
}

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("pick-folder", async (): Promise<string | null> => {
  const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  if (result.canceled || result.filePaths.length === 0) return null;
  return result.filePaths[0];
});

ipcMain.handle("get-project-root", (): ProjectRootStatus => {
  const root = projectRoot();
  return { root, valid: isValidProjectRoot(root) };
});

ipcMain.handle("pick-project-root", async (): Promise<ProjectRootStatus | null> => {
  const result = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  if (result.canceled || result.filePaths.length === 0) return null;
  const root = result.filePaths[0];
  const valid = isValidProjectRoot(root);
  if (valid) writeAppConfig({ projectRoot: root });
  return { root, valid };
});

// --- main.py invocation helpers ---

function runPython(args: string[]): Promise<{ stdout: string; exitCode: number | null }> {
  return new Promise((resolve, reject) => {
    const pythonExePath = pythonExe();
    const mainPyPath = mainPy();
    if (!fs.existsSync(pythonExePath) || !fs.existsSync(mainPyPath)) {
      reject(new Error(`python(${pythonExePath}) 또는 main.py(${mainPyPath})를 찾을 수 없습니다.`));
      return;
    }
    const proc = spawn(pythonExePath, [mainPyPath, ...args], { cwd: projectRoot() });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf-8")));
    proc.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf-8")));
    proc.on("close", (exitCode) => {
      if (exitCode !== 0) {
        reject(new Error(stderr || `main.py exited with code ${exitCode}`));
        return;
      }
      resolve({ stdout, exitCode });
    });
    proc.on("error", reject);
  });
}

// main.py's Case dataclass is snake_case; the renderer side uses camelCase.
// `dir` isn't a real dataclass field on the Python side (it's a computed
// @property, so it doesn't survive asdict()) — reconstructed here from the
// same cases/<id>/ layout common/case_store.py uses.
function caseFromPython(raw: Record<string, unknown>): CaseSummary {
  const id = raw.id as string;
  return {
    id,
    name: raw.name as string,
    targetDir: raw.target_dir as string,
    dir: path.join(casesDir(), id),
    createdAt: raw.created_at as string,
    lastRunAt: (raw.last_run_at as string | null) ?? null,
    lastRunStatus: (raw.last_run_status as string | null) ?? null,
    artifactsRun: (raw.artifacts_run as string[] | undefined) ?? [],
  };
}

ipcMain.handle("list-cases", async (): Promise<CaseSummary[]> => {
  try {
    const { stdout } = await runPython(["--list-cases"]);
    const raw = JSON.parse(stdout.trim());
    return Array.isArray(raw) ? raw.map(caseFromPython) : [];
  } catch {
    return [];
  }
});

ipcMain.handle("create-case", async (_event, name: string, targetDir: string): Promise<CaseSummary> => {
  const { stdout } = await runPython(["--create-case", name, "--target", targetDir]);
  return caseFromPython(JSON.parse(stdout.trim()));
});

ipcMain.handle("list-artifacts", (): Promise<string[]> => {
  return new Promise((resolve) => {
    const pythonExePath = pythonExe();
    const mainPyPath = mainPy();
    if (!fs.existsSync(pythonExePath) || !fs.existsSync(mainPyPath)) {
      resolve([]);
      return;
    }
    const proc = spawn(pythonExePath, [mainPyPath, "--list-artifacts"], { cwd: projectRoot() });
    let out = "";
    proc.stdout.on("data", (chunk: Buffer) => (out += chunk.toString("utf-8")));
    proc.on("close", () => {
      try {
        const names = JSON.parse(out.trim());
        resolve(Array.isArray(names) ? names : []);
      } catch {
        resolve([]);
      }
    });
    proc.on("error", () => resolve([]));
  });
});

// --- Parsing (main.py --run-case), streamed straight into the GUI ---

let currentPipelineProcess: ChildProcessWithoutNullStreams | null = null;

ipcMain.handle(
  "run-case",
  (event: IpcMainInvokeEvent, options: RunCaseOptions): Promise<PipelineResult> => {
    return new Promise((resolve) => {
      if (currentPipelineProcess) {
        resolve({ exitCode: -1 });
        return;
      }
      const pythonExePath = pythonExe();
      const mainPyPath = mainPy();
      if (!fs.existsSync(pythonExePath) || !fs.existsSync(mainPyPath)) {
        event.sender.send("pipeline-log", {
          line: `[electron] python(${pythonExePath}) 또는 main.py(${mainPyPath})를 찾을 수 없습니다.`,
          stream: "stderr",
        } satisfies PipelineLogEntry);
        resolve({ exitCode: -1 });
        return;
      }

      const args = [mainPyPath, "--run-case", options.caseId];
      if (options.only && options.only.length > 0) args.push("--only", options.only.join(","));

      const proc = spawn(pythonExePath, args, { cwd: projectRoot() });
      currentPipelineProcess = proc;

      const emit = (stream: "stdout" | "stderr", chunk: Buffer) => {
        for (const line of chunk.toString("utf-8").split(/\r?\n/)) {
          if (line.length === 0) continue;
          event.sender.send("pipeline-log", { line, stream } satisfies PipelineLogEntry);
        }
      };
      proc.stdout.on("data", (chunk: Buffer) => emit("stdout", chunk));
      proc.stderr.on("data", (chunk: Buffer) => emit("stderr", chunk));

      proc.on("close", (code) => {
        currentPipelineProcess = null;
        resolve({ exitCode: code });
      });
      proc.on("error", (err) => {
        currentPipelineProcess = null;
        event.sender.send("pipeline-log", {
          line: `[electron] 파이썬 프로세스를 시작하지 못했습니다: ${err.message}`,
          stream: "stderr",
        } satisfies PipelineLogEntry);
        resolve({ exitCode: -1 });
      });
    });
  }
);

ipcMain.handle("cancel-pipeline", (): boolean => {
  if (!currentPipelineProcess) return false;
  currentPipelineProcess.kill();
  currentPipelineProcess = null;
  return true;
});

// --- Result browsing: one .sqlite file per artifact output, organized
// under cases/<id>/CATEGORY/... — mirrors the project's original CSV
// folder layout, just swapping .csv for .sqlite. ---

ipcMain.handle("list-categories", (_event, caseDir: string): CategoryEntry[] => {
  if (!fs.existsSync(caseDir)) return [];
  return fs
    .readdirSync(caseDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({ name: entry.name, fullPath: path.join(caseDir, entry.name) }))
    .sort((a, b) => a.name.localeCompare(b.name));
});

// write_rows_to_sqlite() connects (which creates the file) even for a
// zero-row result but returns before creating any table, so an empty
// result is always a 0-byte file — a cheap, reliable way to skip "no data"
// files without opening each one. A real SQLite file is at least 100 bytes
// (the fixed header size) once a table exists.
const EMPTY_SQLITE_MAX_BYTES = 100;

function firstTableName(db: InstanceType<typeof Database>): string | null {
  const row = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 1").get() as
    | { name: string }
    | undefined;
  return row?.name ?? null;
}

function findResultFiles(dir: string, baseDir: string): ResultFileEntry[] {
  const results: ResultFileEntry[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findResultFiles(fullPath, baseDir));
      continue;
    }
    if (!entry.isFile() || !entry.name.toLowerCase().endsWith(".sqlite")) continue;
    if (fs.statSync(fullPath).size <= EMPTY_SQLITE_MAX_BYTES) continue;

    const db = new Database(fullPath, { readonly: true, fileMustExist: true });
    try {
      const tableName = firstTableName(db);
      if (!tableName) continue;
      const { count } = db.prepare(`SELECT COUNT(*) as count FROM "${tableName}"`).get() as { count: number };
      results.push({
        name: entry.name.replace(/\.sqlite$/i, ""),
        relativePath: path.relative(baseDir, fullPath),
        fullPath,
        rowCount: count,
      });
    } finally {
      db.close();
    }
  }
  return results;
}

ipcMain.handle("list-result-files", (_event, categoryDir: string): ResultFileEntry[] => {
  if (!fs.existsSync(categoryDir)) return [];
  return findResultFiles(categoryDir, categoryDir).sort((a, b) => a.relativePath.localeCompare(b.relativePath));
});

ipcMain.handle("read-result-file", (_event, fullPath: string): CsvData => {
  const db = new Database(fullPath, { readonly: true, fileMustExist: true });
  try {
    const tableName = firstTableName(db);
    if (!tableName) return { columns: [], rows: [], rowCount: 0 };
    // rowid is SQLite's built-in per-table row identifier (stable within one
    // parse; these tables have no explicit PK). Aliased as __rowid and kept
    // out of `columns` (which still comes from PRAGMA table_info, so the
    // visible column list is unchanged) — it rides along on each row object
    // purely for cross-artifact navigation and bookmarking.
    const rows = db.prepare(`SELECT rowid AS __rowid, * FROM "${tableName}"`).all() as Record<string, string>[];
    const columnInfo = db.prepare(`PRAGMA table_info("${tableName}")`).all() as { name: string }[];
    const columns = columnInfo.map((c) => c.name);
    return { columns, rows, rowCount: rows.length };
  } finally {
    db.close();
  }
});

// --- Bookmarks: analyst annotations on individual rows, stored separately
// from the SQLite parsing output in cases/<id>/bookmarks.json (plain JSON,
// not part of the pipeline's own artifacts). A bookmark's `rowid` only means
// "row N in that file's table at the time it was tagged" — re-parsing a case
// drops and recreates every table, which can reassign rowids, so old
// bookmarks may point at the wrong (or a missing) row after a re-parse. That
// limitation is surfaced in the Bookmarks UI rather than hidden. ---

function bookmarksPath(caseDir: string): string {
  return path.join(caseDir, "bookmarks.json");
}

function readBookmarks(caseDir: string): Bookmark[] {
  const file = bookmarksPath(caseDir);
  if (!fs.existsSync(file)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

function writeBookmarks(caseDir: string, bookmarks: Bookmark[]): void {
  fs.writeFileSync(bookmarksPath(caseDir), JSON.stringify(bookmarks, null, 2), "utf-8");
}

ipcMain.handle("list-bookmarks", (_event, caseDir: string): Bookmark[] => readBookmarks(caseDir));

ipcMain.handle("toggle-bookmark", (_event, caseDir: string, entry: BookmarkInput): Bookmark[] => {
  const bookmarks = readBookmarks(caseDir);
  const idx = bookmarks.findIndex((b) => b.fullPath === entry.fullPath && b.rowid === entry.rowid);
  if (idx >= 0) {
    bookmarks.splice(idx, 1);
  } else {
    bookmarks.push({
      id: `${entry.fullPath}#${entry.rowid}`,
      fullPath: entry.fullPath,
      tableName: entry.tableName,
      rowid: entry.rowid,
      note: "",
      taggedAt: new Date().toISOString(),
    });
  }
  writeBookmarks(caseDir, bookmarks);
  return bookmarks;
});

ipcMain.handle("update-bookmark-note", (_event, caseDir: string, id: string, note: string): Bookmark[] => {
  const bookmarks = readBookmarks(caseDir);
  const target = bookmarks.find((b) => b.id === id);
  if (target) target.note = note;
  writeBookmarks(caseDir, bookmarks);
  return bookmarks;
});
