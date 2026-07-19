"use client";

import { useCallback, useEffect, useState } from "react";
import Sidebar from "@/components/Sidebar";
import DataTable from "@/components/DataTable";
import TabBar from "@/components/TabBar";
import RunPipeline from "@/components/RunPipeline";
import MasterTimeline from "@/components/MasterTimeline";
import BookmarksView from "@/components/BookmarksView";
import ProjectRootSetup from "@/components/ProjectRootSetup";
import { buildMasterTimeline } from "@/lib/masterTimeline";
import type {
  Bookmark,
  CaseSummary,
  CategoryEntry,
  CsvData,
  ProjectRootStatus,
  ResultFileEntry,
  TimelineEntry,
} from "@/lib/types";

interface TabState {
  file: ResultFileEntry;
  data: CsvData | null;
  loading: boolean;
  error: string | null;
}

type Mode = "run" | "browse";
type VirtualTab = "timeline" | "bookmarks" | null;

export default function Home() {
  const [projectRootStatus, setProjectRootStatus] = useState<ProjectRootStatus | null>(null);
  const [mode, setMode] = useState<Mode>("browse");
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [selectedCase, setSelectedCase] = useState<CaseSummary | null>(null);
  const [categories, setCategories] = useState<CategoryEntry[]>([]);
  const [tabs, setTabs] = useState<TabState[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);
  const [pendingFilter, setPendingFilter] = useState<{ column: string; value: string } | null>(null);
  const [activeVirtualTab, setActiveVirtualTab] = useState<VirtualTab>(null);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [masterTimeline, setMasterTimeline] = useState<{ caseId: string; entries: TimelineEntry[] } | null>(null);
  const [masterTimelineLoading, setMasterTimelineLoading] = useState(false);

  const refreshCases = useCallback(async (): Promise<CaseSummary[]> => {
    const list = await window.api.listCases();
    setCases(list);
    return list;
  }, []);

  useEffect(() => {
    // Never let a rejected/hung IPC call leave the app stuck on the loading
    // screen forever — worst case, fall through to the setup screen so the
    // user can still pick a folder.
    window.api
      .getProjectRoot()
      .then(setProjectRootStatus)
      .catch(() => setProjectRootStatus({ root: "", valid: false }));
  }, []);

  useEffect(() => {
    if (!projectRootStatus?.valid) return;
    refreshCases().then((list) => {
      if (list.length === 0) setMode("run");
    });
  }, [projectRootStatus, refreshCases]);

  const selectCase = useCallback(async (c: CaseSummary) => {
    setSelectedCase(c);
    setTabs([]);
    setActivePath(null);
    setActiveVirtualTab(null);
    setMasterTimeline(null);
    const [found, caseBookmarks] = await Promise.all([window.api.listCategories(c.dir), window.api.listBookmarks(c.dir)]);
    setCategories(found);
    setBookmarks(caseBookmarks);
  }, []);

  async function handleSelectFile(file: ResultFileEntry) {
    setActiveVirtualTab(null);
    setActivePath(file.fullPath);

    const alreadyOpen = tabs.some((t) => t.file.fullPath === file.fullPath);
    setTabs((prev) =>
      prev.some((t) => t.file.fullPath === file.fullPath) ? prev : [...prev, { file, data: null, loading: true, error: null }]
    );
    if (alreadyOpen) return;

    try {
      const data = await window.api.readResultFile(file.fullPath);
      setTabs((prev) => prev.map((t) => (t.file.fullPath === file.fullPath ? { ...t, data, loading: false } : t)));
    } catch (e) {
      setTabs((prev) => prev.map((t) => (t.file.fullPath === file.fullPath ? { ...t, error: String(e), loading: false } : t)));
    }
  }

  function handleCloseTab(fullPath: string) {
    setTabs((prev) => {
      const idx = prev.findIndex((t) => t.file.fullPath === fullPath);
      const next = prev.filter((t) => t.file.fullPath !== fullPath);
      if (activePath === fullPath) {
        const fallback = next[idx] ?? next[idx - 1] ?? next[0] ?? null;
        setActivePath(fallback ? fallback.file.fullPath : null);
      }
      return next;
    });
  }

  async function handleNavigate(targetFile: string, targetColumn: string, value: string) {
    const targetBaseName = targetFile.toLowerCase();
    for (const cat of categories) {
      const files = await window.api.listResultFiles(cat.fullPath);
      const match = files.find((f) => f.name.toLowerCase() === targetBaseName);
      if (match) {
        await handleSelectFile(match);
        setPendingFilter({ column: targetColumn, value });
        return;
      }
    }
  }

  async function handleSelectTimeline() {
    setActiveVirtualTab("timeline");
    if (!selectedCase || masterTimeline?.caseId === selectedCase.id) return;
    setMasterTimelineLoading(true);
    try {
      const entries = await buildMasterTimeline(categories);
      setMasterTimeline({ caseId: selectedCase.id, entries });
    } finally {
      setMasterTimelineLoading(false);
    }
  }

  function handleSelectBookmarks() {
    setActiveVirtualTab("bookmarks");
  }

  async function handleToggleBookmark(file: ResultFileEntry, rowid: number) {
    if (!selectedCase) return;
    const result = await window.api.toggleBookmark(selectedCase.dir, {
      fullPath: file.fullPath,
      tableName: file.name,
      rowid,
    });
    setBookmarks(result);
  }

  async function handleRemoveBookmark(bookmark: Bookmark) {
    if (!selectedCase) return;
    const result = await window.api.toggleBookmark(selectedCase.dir, {
      fullPath: bookmark.fullPath,
      tableName: bookmark.tableName,
      rowid: bookmark.rowid,
    });
    setBookmarks(result);
  }

  async function handleUpdateBookmarkNote(id: string, note: string) {
    if (!selectedCase) return;
    const result = await window.api.updateBookmarkNote(selectedCase.dir, id, note);
    setBookmarks(result);
  }

  const activeTab = tabs.find((t) => t.file.fullPath === activePath) ?? null;
  const activeTimeline = selectedCase && masterTimeline?.caseId === selectedCase.id ? masterTimeline.entries : null;
  const activeBookmarkedRowids = activeTab
    ? new Set(bookmarks.filter((b) => b.fullPath === activeTab.file.fullPath).map((b) => b.rowid))
    : undefined;

  if (!projectRootStatus) {
    return (
      <main style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-faint)" }}>
        불러오는 중...
      </main>
    );
  }

  if (!projectRootStatus.valid) {
    return <ProjectRootSetup status={projectRootStatus} onConfigured={setProjectRootStatus} />;
  }

  return (
    <main style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          flexShrink: 0,
          background: "var(--bg-panel)",
          borderBottom: "1px solid var(--border)",
          padding: "0 8px",
        }}
      >
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", padding: "0 12px 0 4px", letterSpacing: 0.2 }}>
          🔎 Windows Triage
        </span>
        <div style={{ width: 1, height: 18, background: "var(--border)", margin: "0 4px" }} />
        {(["run", "browse"] as const).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              padding: "10px 16px",
              background: "transparent",
              color: mode === m ? "var(--text)" : "var(--text-dim)",
              border: "none",
              borderBottom: mode === m ? "2px solid var(--accent)" : "2px solid transparent",
              cursor: "pointer",
              fontSize: 12.5,
              fontWeight: mode === m ? 600 : 400,
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span>{m === "run" ? "▶" : "📊"}</span>
            {m === "run" ? "파싱 실행" : "결과 보기"}
          </button>
        ))}
      </div>

      {mode === "run" && (
        <RunPipeline
          cases={cases}
          onCasesChanged={refreshCases}
          onOpenResults={(c) => {
            selectCase(c);
            setMode("browse");
          }}
        />
      )}

      {mode === "browse" && (
        <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
          <Sidebar
            cases={cases}
            selectedCase={selectedCase}
            onSelectCase={selectCase}
            categories={categories}
            selectedFile={activeTab?.file ?? null}
            onSelectFile={handleSelectFile}
            activeVirtualTab={activeVirtualTab}
            onSelectTimeline={handleSelectTimeline}
            onSelectBookmarks={handleSelectBookmarks}
            bookmarkCount={bookmarks.length}
          />
          <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
            <TabBar
              tabs={tabs.map((t) => ({ key: t.file.fullPath, label: t.file.name }))}
              activeKey={activeVirtualTab ? null : activePath}
              onActivate={(key) => {
                setActiveVirtualTab(null);
                setActivePath(key);
              }}
              onClose={handleCloseTab}
            />

            {activeVirtualTab === "timeline" && (
              <MasterTimeline entries={activeTimeline} loading={masterTimelineLoading} onNavigate={handleNavigate} />
            )}

            {activeVirtualTab === "bookmarks" && (
              <BookmarksView
                bookmarks={bookmarks}
                onNavigate={handleNavigate}
                onRemove={handleRemoveBookmark}
                onUpdateNote={handleUpdateBookmarkNote}
              />
            )}

            {!activeVirtualTab && !activeTab && (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-faint)", gap: 8 }}>
                <span style={{ fontSize: 32 }}>📄</span>
                <span>왼쪽에서 결과 파일을 선택하세요.</span>
              </div>
            )}
            {!activeVirtualTab && activeTab && activeTab.loading && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)" }}>
                불러오는 중...
              </div>
            )}
            {!activeVirtualTab && activeTab && activeTab.error && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--danger)" }}>
                {activeTab.error}
              </div>
            )}
            {!activeVirtualTab && activeTab && !activeTab.loading && !activeTab.error && activeTab.data && (
              <DataTable
                fileName={activeTab.file.name}
                data={activeTab.data}
                initialFilter={pendingFilter}
                onInitialFilterConsumed={() => setPendingFilter(null)}
                onNavigate={handleNavigate}
                bookmarkedRowids={activeBookmarkedRowids}
                onToggleBookmark={(rowid) => handleToggleBookmark(activeTab.file, rowid)}
              />
            )}
          </div>
        </div>
      )}
    </main>
  );
}
