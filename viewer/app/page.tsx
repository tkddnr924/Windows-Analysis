"use client";

import "@/lib/tauriApi";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Sidebar from "@/components/Sidebar";
import DataTable from "@/components/DataTable";
import RunPipeline from "@/components/RunPipeline";
import MasterTimeline from "@/components/MasterTimeline";
import BookmarksView from "@/components/BookmarksView";
import CaseSearchView from "@/components/CaseSearchView";
import HostConnectionView, { type HostGraph, type ConnRecord } from "@/components/HostConnectionView";
import SessionFlowView from "@/components/SessionFlowView";
import SmbHistoryView from "@/components/SmbHistoryView";
import BitsView from "@/components/BitsView";
import FirewallView from "@/components/FirewallView";
import PowerShellFlowView from "@/components/PowerShellFlowView";
import TargetInfoView from "@/components/TargetInfoView";
import ExecutionHistoryView from "@/components/ExecutionHistoryView";
import RdpCacheView from "@/components/RdpCacheView";
import ScheduledTasksView from "@/components/ScheduledTasksView";
import DefenderView from "@/components/DefenderView";
import RegistryFindingsView from "@/components/RegistryFindingsView";
import WerView from "@/components/WerView";
import MftView from "@/components/MftView";
import BrowserHistoryView from "@/components/BrowserHistoryView";
import GlobalProgress from "@/components/GlobalProgress";
import { usePipelineRun } from "@/lib/usePipelineRun";
import CircularProgress from "@mui/material/CircularProgress";
import { buildMasterTimeline, enrichCachedTimeline, loadCachedTimelineInWorker, TimelineBuildAborted } from "@/lib/masterTimeline";
import { convertFileSrc } from "@tauri-apps/api/core";
import { getArtifactView } from "@/lib/artifactViews";
import { EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";
import { searchHitHostMatchesSourceBookmark } from "@/lib/searchBookmark";
import { accountDirectoryFromEntries, type AccountDirectory } from "@/lib/accountIdentity";
import type { AccountEventPage, AccountEventQuery, AccountEventSource, Bookmark, Case, Host, CategoryEntry, CsvData, ResultFileEntry, TimelineEntry, SearchHit } from "@/lib/types";

interface TabState {
  file: ResultFileEntry;
  data: CsvData | null;
  loading: boolean;
  error: string | null;
}

type VirtualTab = "timeline" | "bookmarks" | "connections" | "search" | null;

// A browsable unit is a (file, table) pair — a single .sqlite can hold several
// tables now, so identity is the path + table name.
const keyOf = (f: ResultFileEntry): string => `${f.fullPath}\u0000${f.tableName}`;
// A host dir is cases/<host>; its parent is the direct host-store root.
// Bookmarks live there so they remain shared across registered hosts.
// 원본(전용 뷰 없는) 테이블의 페이지 로딩 청크 크기.
const RAW_TABLE_CHUNK = 20000;

const parentDir = (dir: string): string => dir.slice(0, Math.max(dir.lastIndexOf("/"), dir.lastIndexOf("\\")));
const accountDirectoryKey = (host: Pick<Host, "id" | "dir">): string => `${host.id}\u0000${host.dir.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase()}`;

type SourceRecordRef = { fileName?: string; tableName: string; rowid: number };

// Overview rows retain a raw-evidence pointer. EventLog correlations use
// "<table>::<rowid>" ("Security_2::57" — the parser writes the unique output
// table name and the row's actual SQLite rowid; older hosts carry the legacy
// "Security.evtx::<EventRecordID>" form, which needs a re-parse to bookmark
// reliably). ExecutionHistory uses "Amcache::Amcache_Files::123" so tables
// from different source databases do not collide. Bookmarks are
// source-evidence annotations, so this bridges an overview row to the source
// record in either form.
function sourceRecordRef(value: string | undefined): SourceRecordRef | null {
  const parts = (value || "").split("::");
  if (parts.length !== 2 && parts.length !== 3) return null;
  const rowid = Number(parts.at(-1));
  if (!Number.isSafeInteger(rowid)) return null;
  if (parts.length === 2) return { tableName: parts[0].replace(/\.evtx$/i, ""), rowid };
  return { fileName: parts[0], tableName: parts[1], rowid };
}

function sourceBookmarkKey(tableName: string, rowid: number, fileName?: string): string {
  const table = tableName.replace(/\.evtx$/i, "").trim().toLowerCase();
  const file = fileName?.trim().toLowerCase();
  return file ? `${file}::${table}::${rowid}` : `${table}::${rowid}`;
}

function resultFileStem(fullPath: string): string {
  return fullPath.replace(/\\/g, "/").split("/").pop()?.replace(/\.sqlite$/i, "") || "";
}

export default function Home() {
  const [cases, setCases] = useState<Case[]>([]);
  const [casesError, setCasesError] = useState<string | null>(null);
  const [casesLoading, setCasesLoading] = useState(true);
  // The backend exposes one internal root collection for compatibility. The
  // analyst never chooses a CASE: host folders are stored directly under
  // cases/<hostId>, then opened from the host ledger.
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [categories, setCategories] = useState<CategoryEntry[]>([]);
  const [tabs, setTabs] = useState<TabState[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);
  const [pendingFilter, setPendingFilter] = useState<{ column: string; value: string } | null>(null);
  const [activeVirtualTab, setActiveVirtualTab] = useState<VirtualTab>(null);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  // Bookmark persistence failures must remain visible to the analyst. Do not
  // optimistically change the local list: a failed disk write is not a saved
  // annotation.
  const [bookmarkError, setBookmarkError] = useState<string | null>(null);
  const [masterTimeline, setMasterTimeline] = useState<{ hostId: string; entries: TimelineEntry[] } | null>(null);
  const [masterTimelineLoading, setMasterTimelineLoading] = useState(false);
  // Cancels an in-flight master-timeline build. Building scans every result
  // table (EventLog alone can be hundreds of thousands of rows), so once the
  // analyst leaves the timeline tab or switches host the work must stop rather
  // than keep churning the render thread and slowing whatever they opened next.
  const timelineBuildRef = useRef<AbortController | null>(null);
  // Guards the post-parse prebuild so it runs once per (host, run) rather than
  // on every incidental case-list refresh (which would re-parse a large cache
  // JSON repeatedly). Keyed by host id + last run time.
  const prebuiltTimelineKeyRef = useRef<string | null>(null);
  const [hostGraph, setHostGraph] = useState<{ caseId: string; graph: HostGraph } | null>(null);
  const [hostGraphLoading, setHostGraphLoading] = useState(false);
  // All IPs of every host in the case (a host can have several NICs). Shared by
  // every 케이스 분석 view so a remote IP that is really another host is
  // recognised as that host, whichever of its addresses appears. Cached per case.
  const [caseNetwork, setCaseNetwork] = useState<{ caseId: string; sig: string; nonce: number; ipToHost: Record<string, { id: string; name: string }>; hostIps: Record<string, string[]> } | null>(null);
  // Bumped when a parse finishes so the network map reloads even if the host
  // SET is unchanged (re-parsing an existing host adds/updates its TargetInfo).
  const [netNonce, setNetNonce] = useState(0);
  const [timeRange, setTimeRange] = useState<TimeRange>(EMPTY_TIME_RANGE);
  // Directory values are a display cache only. Each key includes the
  // authoritative host id and its case directory, so identical host names or
  // SIDs never leak labels across machines.
  const [accountDirectories, setAccountDirectories] = useState<Record<string, AccountDirectory>>({});
  const accountDirectoryCache = useRef<Record<string, AccountDirectory>>({});
  const accountDirectoryRequests = useRef(new Map<string, Promise<AccountDirectory>>());
  // Multiple bounded parser slots can finish together.  Only the newest
  // list-cases response may update visible case/host metadata; an older disk
  // read returning late must not restore a just-finished host to `미실행`.
  const caseRefreshSequence = useRef(0);

  const loadAccountDirectory = useCallback((host: Pick<Host, "id" | "dir">): Promise<AccountDirectory> => {
    const key = accountDirectoryKey(host);
    const cached = accountDirectoryCache.current[key];
    if (cached) return Promise.resolve(cached);
    const pending = accountDirectoryRequests.current.get(key);
    if (pending) return pending;
    const request = window.api.accountDirectory(host.dir)
      .then((entries) => {
        const directory = accountDirectoryFromEntries(entries);
        accountDirectoryCache.current[key] = directory;
        setAccountDirectories((current) => current[key] === directory ? current : { ...current, [key]: directory });
        return directory;
      })
      .finally(() => accountDirectoryRequests.current.delete(key));
    accountDirectoryRequests.current.set(key, request);
    return request;
  }, []);

  // Preload per-host maps with a small fixed worker pool. Bookmarks and case
  // search can span multiple hosts; this avoids a disk IPC request per visible
  // SID while also avoiding unbounded SQLite opens in large cases.
  useEffect(() => {
    const hosts = activeVirtualTab === "bookmarks" || activeVirtualTab === "search"
      ? selectedCase?.hosts ?? []
      : selectedHost ? [selectedHost] : [];
    let next = 0;
    const worker = async () => {
      while (next < hosts.length) {
        const host = hosts[next++];
        try {
          await loadAccountDirectory(host);
        } catch {
          // Partial/missing TargetInfo must keep the raw SID, not turn the
          // whole analysis view into an error state. A later reopen retries.
        }
      }
    };
    void Promise.all(Array.from({ length: Math.min(4, hosts.length) }, worker));
  }, [activeVirtualTab, selectedCase?.id, selectedCase?.hosts, selectedHost, loadAccountDirectory]);

  const refreshCases = useCallback(async (): Promise<Case[]> => {
    const sequence = ++caseRefreshSequence.current;
    setCasesLoading(true);
    try {
      const result = await window.api.listCases();
      if (sequence !== caseRefreshSequence.current) return result.cases;
      setCases(result.cases);
      setCasesError(result.error);
      // Keep the drilled-in root collection in sync with live host metadata.
      setSelectedCase((prev) => (prev ? result.cases.find((c) => c.id === prev.id) ?? null : null));
      return result.cases;
    } finally {
      if (sequence === caseRefreshSequence.current) setCasesLoading(false);
    }
  }, []);

  // listCases performs the legacy layout migration before returning the root
  // collection. Do not create CASE_* metadata/folders from the UI.
  const bootstrapHostStore = useCallback(() => {
    void refreshCases()
      .then((available) => setSelectedCase(available[0] ?? null))
      .catch((error) => setCasesError(String(error)));
  }, [refreshCases]);

  useEffect(() => {
    bootstrapHostStore();
  }, [bootstrapHostStore]);

  // Leaving the timeline tab cancels any build still scanning the result set,
  // so it stops competing with the view the analyst just opened. Switching host
  // is handled where the host changes (it also clears the built timeline).
  useEffect(() => {
    if (activeVirtualTab !== "timeline" && timelineBuildRef.current) {
      timelineBuildRef.current.abort();
      timelineBuildRef.current = null;
      setMasterTimelineLoading(false);
    }
  }, [activeVirtualTab]);


  // Parse state lives here (not in RunPipeline) so it survives navigating to
  // another screen mid-parse; the child process runs in the Electron main
  // process regardless. onDone refreshes the case list when a run finishes.
  const run = usePipelineRun(() => {
    refreshCases();
    setNetNonce((n) => n + 1);
  });

  // Open a host for browsing: raw results stay in cases/<host>/ and bookmarks
  // are loaded from the shared direct-store root.
  // _OVERVIEW 파일 목록은 조회가 비싸다(테이블별 COUNT, MFT 수백만 행 포함).
  // 호스트를 열 때 한 번만 읽어 사이드바와 기본 뷰 선택이 공유한다.
  const [overviewFiles, setOverviewFiles] = useState<ResultFileEntry[] | null>(null);

  const openHost = useCallback(async (h: Host) => {
    setSelectedHost(h);
    setTabs([]);
    setActivePath(null);
    setActiveVirtualTab(null);
    setMasterTimeline(null);
    const [found, hostBookmarks] = await Promise.all([window.api.listCategories(h.dir), window.api.listBookmarks(parentDir(h.dir))]);
    setCategories(found);
    setBookmarks(hostBookmarks);
    // 결과 보기의 첫 화면은 호스트 정보다. 없으면(파싱 전 등) 빈 상태 유지.
    const overview = found.find((category) => category.name === "_OVERVIEW");
    if (overview) {
      const files = await window.api.listResultFiles(overview.fullPath);
      setOverviewFiles(files);
      const targetInfo = files.find((file) => file.name === "TargetInfo");
      if (targetInfo) void handleSelectFile(targetInfo);
    } else {
      setOverviewFiles([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function backToHosts() {
    setOverviewFiles(null);
    setSelectedHost(null);
    setCategories([]);
    setTabs([]);
    setActivePath(null);
    setActiveVirtualTab(null);
    setBookmarks([]);
    setMasterTimeline(null);
  }

  // A tab/selection is a (file, table) pair now that one .sqlite holds several
  // tables, so identity is the file path + table name, not the path alone.
  async function handleSelectFile(file: ResultFileEntry) {
    setActiveVirtualTab(null);
    const key = keyOf(file);
    setActivePath(key);

    const alreadyOpen = tabs.some((t) => keyOf(t.file) === key);
    setTabs((prev) => (prev.some((t) => keyOf(t.file) === key) ? prev : [...prev, { file, data: null, loading: true, error: null }]));
    if (alreadyOpen) return;
    // 새로 여는 탭은 이어받기 실패 기록을 지워 재시도 기회를 준다.
    rawLoadFailed.current.delete(key);

    try {
      if (file.tableName === "MFT_Records") {
        // The $MFT table can hold ~1M rows; the Explorer view (MftView) reads
        // SQLite lazily by dbPath, so we skip loading every row into a tab.
        setTabs((prev) => prev.map((t) => (keyOf(t.file) === key ? { ...t, data: { columns: [], rows: [], rowCount: 0 }, loading: false } : t)));
        return;
      }
      // Older saved hosts predate ExecutionHistory's raw-record key. Rebuild
      // only this lightweight derived overview once, not the evidence parsers,
      // so existing bookmarks can synchronize with its source artifacts.
      if (file.tableName === "ExecutionHistory" && selectedHost) {
        const refreshed = await window.api.refreshExecutionHistoryOverview(selectedHost.dir);
        // The master timeline is a materialized in-memory row set. Its entries
        // must be rebuilt after an overview upgrade so its RowDetailPanel gets
        // the exact same record fields as the ExecutionHistory view.
        if (refreshed) setMasterTimeline(null);
      }
      const isBrowserActivity = getArtifactView(file.name)?.customView === "browserHistory";
      // 전용 뷰(customView)가 없는 원본 테이블은 DataTable로 렌더된다. 원본
      // EventLog처럼 수십만 행짜리 테이블을 통째로 IPC에 싣지 않도록 이
      // 경로만 청크 단위로 받고, 스크롤 시 이어 받는다. 개요 뷰들은 전체
      // 행을 집계(세션 묶음·건수)에 쓰므로 기존 전량 로드를 유지한다.
      const isPagedRaw = !isBrowserActivity && !getArtifactView(file.name)?.customView;
      const data = isBrowserActivity
        ? { columns: [], rows: [], rowCount: file.rowCount }
        : isPagedRaw
          ? await window.api.readResultFilePage(file.fullPath, file.tableName, 0, RAW_TABLE_CHUNK)
          : await window.api.readResultFile(file.fullPath, file.tableName);
      setTabs((prev) => prev.map((t) => (keyOf(t.file) === key ? { ...t, data, loading: false } : t)));
    } catch (e) {
      setTabs((prev) => prev.map((t) => (keyOf(t.file) === key ? { ...t, error: String(e), loading: false } : t)));
    }
  }

  // 원본 테이블 청크 크기 — 초기 로드와 스크롤 이어받기 단위.
  const rawLoadInFlight = useRef<Set<string>>(new Set());
  // 이어받기가 실패한 탭 — onLoadMore는 렌더마다 새 함수라 effect가 계속
  // 재실행되므로, 실패를 기록하지 않으면 영구 오류(파일 교체·권한 등)에서
  // 같은 IPC를 무한 재시도한다. 실패한 키는 자동 이어받기를 멈추고 이미 받은
  // 행만 유지한다. unhandled rejection도 여기서 흡수한다.
  const rawLoadFailed = useRef<Set<string>>(new Set());
  async function loadMoreRawRows() {
    if (!activeTab?.data) return;
    const key = keyOf(activeTab.file);
    const loaded = activeTab.data.rows.length;
    if (loaded >= activeTab.data.rowCount || rawLoadInFlight.current.has(key) || rawLoadFailed.current.has(key)) return;
    rawLoadInFlight.current.add(key);
    try {
      const page = await window.api.readResultFilePage(activeTab.file.fullPath, activeTab.file.tableName, loaded, RAW_TABLE_CHUNK);
      setTabs((prev) => prev.map((t) => {
        if (keyOf(t.file) !== key || !t.data) return t;
        // 요청 시점의 오프셋과 현재 행 수가 다르면(탭을 닫았다 바로 다시 열어
        // 초기 청크가 새로 로드된 경우) 늦게 온 응답이라 이어붙이지 않는다.
        if (t.data.rows.length !== loaded) return t;
        return { ...t, data: { ...t.data, rows: [...t.data.rows, ...page.rows], rowCount: page.rowCount } };
      }));
    } catch (e) {
      rawLoadFailed.current.add(key);
      console.error(`raw chunk load failed for ${key}:`, e);
    } finally {
      rawLoadInFlight.current.delete(key);
    }
  }

  // EventLog is now one table per source .evtx, so a cross-artifact link into
  // "EventLog_Events" (e.g. RDP/PowerShell "이벤트 로그 원본 보기") can't target a
  // single fixed table. The _record_key value encodes the real log table —
  // "Security_2::57" (legacy hosts: "Security.evtx::123") — so resolve the
  // target table from it.
  function resolveTargetFile(targetFile: string, targetColumn: string, value: string): string {
    if (targetColumn === "_record_key" && value.includes("::")) {
      return value.split("::")[0].replace(/\.evtx$/i, "");
    }
    return targetFile;
  }

  async function handleNavigate(targetFile: string, targetColumn: string, value: string) {
    const targetBaseName = resolveTargetFile(targetFile, targetColumn, value).toLowerCase();
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

  // Same target-table lookup as handleNavigate, but asks SQLite for only the
  // requested linked-record page. Detail drawers must not materialise a full
  // Prefetch loaded-file table just to show a small related-evidence list.
  const fetchLinkedRows = useCallback(
    async (targetFile: string, targetColumn: string, value: string, query?: { search?: string; offset?: number; limit?: number }) => {
      const targetBaseName =
        targetColumn === "_record_key" && value.includes("::")
          ? value.split("::")[0].replace(/\.evtx$/i, "").toLowerCase()
          : targetFile.toLowerCase();
      for (const cat of categories) {
        const files = await window.api.listResultFiles(cat.fullPath);
        const match = files.find((f) => f.name.toLowerCase() === targetBaseName);
        if (match) {
          return window.api.linkedResultRows(
            match.fullPath,
            match.tableName,
            targetColumn,
            value,
            query?.search ?? "",
            query?.offset ?? 0,
            query?.limit ?? 100,
          );
        }
      }
      return null;
    },
    [categories]
  );

  // The Tauri command performs structured account-role matching and returns a
  // bounded globally ordered page.  Keeping the scan out of the webview avoids
  // loading whole EventLog tables just to render this account-detail list.
  const loadAccountEvents = useCallback(
    async (sid: string, username: string, query: Omit<AccountEventQuery, "sid" | "username">): Promise<AccountEventPage> => {
      const sources: AccountEventSource[] = [];
      for (const cat of categories) {
        if (cat.name.toUpperCase() !== "EVENTLOG") continue;
        const files = await window.api.listResultFiles(cat.fullPath);
        for (const f of files) {
          sources.push({ fullPath: f.fullPath, tableName: f.tableName, logName: f.name });
        }
      }
      return window.api.accountEventPage(sources, { sid, username, ...query });
    },
    [categories]
  );

  // Return the host's master timeline, preferring the on-disk cache written by
  // an earlier build. The cache is keyed by the host's last run time, so a
  // re-parse (new lastRunAt) misses it and forces a rebuild; `allowCache: false`
  // forces one too (used when an ExecutionHistory code-refresh invalidated it).
  // On a cache miss it builds (respecting the abort signal) and re-caches.
  const buildOrLoadTimeline = useCallback(
    async (
      host: Host,
      cats: CategoryEntry[],
      signal: AbortSignal,
      allowCache = true,
      cacheOnly = false,
    ): Promise<TimelineEntry[] | null> => {
      const builtForRunAt = host.lastRunAt ?? "";
      if (allowCache) {
        // 1순위: asset 프로토콜로 파일을 받아 워커에서 파싱·보강 — JSON.parse와
        // 태그 계산이 워커 스레드에서 돌아 메인 윈도우가 멈추지 않는다.
        try {
          const url = convertFileSrc(`${host.dir}/_master_timeline.cache.json`);
          const response = await fetch(url);
          if (response.ok) {
            // ArrayBuffer는 워커로 zero-copy 이동한다 — 메인 스레드에서
            // 대형 문자열을 만들거나 복사하지 않는다.
            const buffer = await response.arrayBuffer();
            if (signal.aborted) throw new TimelineBuildAborted();
            const entries = await loadCachedTimelineInWorker(buffer, builtForRunAt, signal);
            if (entries) return entries;
          }
        } catch (error) {
          if (error instanceof TimelineBuildAborted) throw error;
          // asset 프로토콜/워커를 쓸 수 없는 환경 — 아래 IPC 경로로 폴백.
        }
        try {
          const raw = await window.api.loadMasterTimeline(host.dir);
          if (raw) {
            const cached = JSON.parse(raw) as { builtForRunAt?: string; entries?: TimelineEntry[] };
            if (cached.builtForRunAt === builtForRunAt && Array.isArray(cached.entries)) {
              return await enrichCachedTimeline(cached.entries, signal);
            }
          }
        } catch {
          // Missing/corrupt cache is not an error — fall through and rebuild.
        }
      }
      // 백그라운드 프리로드는 캐시 적중만 노린다 — 캐시가 없다고 전체 결과
      // 스캔(빌드)을 몰래 돌리지 않는다.
      if (cacheOnly) return null;
      const entries = await buildMasterTimeline(cats, signal);
      // Persist for instant subsequent opens. Best-effort: a write failure must
      // not fail the (already built) timeline the analyst is waiting for.
      void window.api.saveMasterTimeline(host.dir, JSON.stringify({ builtForRunAt, entries })).catch(() => {});
      return entries;
    },
    [],
  );

  // Prebuild + cache the master timeline as soon as a parse finishes, so the
  // first "통합 타임라인" open is instant rather than kicking off the full
  // result-set scan on the render thread. Runs in the background, is
  // cancellable, and skips work when the host already has a fresh cache.
  useEffect(() => {
    if (!run.runComplete || !run.completedHostId) return;
    const host = selectedCase?.hosts.find((h) => h.id === run.completedHostId);
    if (!host) return;
    const key = `${host.id}:${host.lastRunAt ?? ""}`;
    if (prebuiltTimelineKeyRef.current === key) return;
    const controller = new AbortController();
    void (async () => {
      try {
        const cats = await window.api.listCategories(host.dir);
        const entries = await buildOrLoadTimeline(host, cats, controller.signal);
        if (controller.signal.aborted || !entries) return;
        prebuiltTimelineKeyRef.current = key;
        if (selectedHost?.id === host.id) {
          setMasterTimeline({ hostId: host.id, entries });
        }
      } catch {
        // Aborted (navigated away / superseded) or failed — the lazy open path
        // rebuilds on demand, so a background failure is silent by design.
      }
    })();
    return () => controller.abort();
  }, [run.runComplete, run.completedHostId, selectedCase, buildOrLoadTimeline, selectedHost?.id]);

  // 호스트를 선택하면 타임라인 캐시를 백그라운드에서 미리 읽고 보강해 둔다 —
  // 첫 "통합 타임라인" 클릭이 로드/보강을 기다리지 않게. 캐시가 없으면 아무
  // 것도 하지 않는다(전체 결과 스캔은 클릭 시에만).
  const timelinePreloadKeyRef = useRef<string | null>(null);
  useEffect(() => {
    const host = selectedHost;
    if (!host) return;
    if (masterTimeline?.hostId === host.id) return;
    if (run.runs.some((item) => item.hostId === host.id && (item.status === "running" || item.status === "queued"))) return;
    const key = `${host.id}:${host.lastRunAt ?? ""}`;
    if (timelinePreloadKeyRef.current === key) return;
    timelinePreloadKeyRef.current = key;
    const controller = new AbortController();
    // 결과 보기 직후의 대시보드 로딩과 경쟁하지 않도록, 화면이 자리잡은 뒤
    // 유휴 시점에 시작한다. 그 전에 탭을 클릭하면 클릭 경로가 대신 처리한다.
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const entries = await buildOrLoadTimeline(host, [], controller.signal, true, true);
          if (controller.signal.aborted || !entries) return;
          prebuiltTimelineKeyRef.current = key;
          setMasterTimeline((current) => current?.hostId === host.id ? current : { hostId: host.id, entries });
        } catch {
          // 취소되었거나 캐시가 깨진 경우 — 클릭 시 경로가 다시 처리한다.
        }
      })();
    }, 1500);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedHost?.id, selectedHost?.lastRunAt, masterTimeline?.hostId, run.runs, buildOrLoadTimeline]);

  async function handleSelectTimeline() {
    setActiveVirtualTab("timeline");
    if (!selectedHost) return;
    // Keep the timeline and ExecutionHistory detail on one source of truth.
    // This is a derived-table-only compatibility upgrade; raw evidence is not
    // parsed again. A refresh here also means any cached timeline is stale.
    const refreshed = await window.api.refreshExecutionHistoryOverview(selectedHost.dir);
    if (!refreshed && masterTimeline?.hostId === selectedHost.id) return;
    // Supersede any build still running from an earlier click so two scans of
    // the (large) result set never compete for the render thread at once.
    timelineBuildRef.current?.abort();
    const controller = new AbortController();
    timelineBuildRef.current = controller;
    const host = selectedHost;
    setMasterTimelineLoading(true);
    try {
      const entries = await buildOrLoadTimeline(host, categories, controller.signal, !refreshed);
      if (!controller.signal.aborted && entries) setMasterTimeline({ hostId: host.id, entries });
    } catch (error) {
      if (!(error instanceof TimelineBuildAborted)) throw error;
    } finally {
      // Only the current build owns the loading flag; a superseded one that
      // lost the race must not flip it off under the newer build.
      if (timelineBuildRef.current === controller) {
        timelineBuildRef.current = null;
        setMasterTimelineLoading(false);
      }
    }
  }

  function handleSelectBookmarks() {
    setActiveVirtualTab("bookmarks");
  }

  function isLoopbackAddress(value: string): boolean {
    const raw = value.trim().toLocaleLowerCase();
    if (!raw) return false;
    const hostName = /^[a-z][a-z0-9.-]*:\d+$/.test(raw) ? raw.replace(/:\d+$/, "") : raw;
    if (hostName === "localhost" || hostName === "localhost.localdomain") return true;
    const bracketed = raw.match(/^\[([^\]]+)](?::\d+)?$/)?.[1] ?? raw;
    const withoutZone = bracketed.replace(/%[\w.-]+$/, "");
    const address = /^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(withoutZone) ? withoutZone.replace(/:\d+$/, "") : withoutZone;
    return /^127(?:\.\d{1,3}){3}$/.test(address) || address === "::1" || address === "0:0:0:0:0:0:0:1" || /^::ffff:127(?:\.\d{1,3}){3}$/.test(address);
  }

  // Read every host's network IPs (all NICs) from its TargetInfo overview and
  // build ip -> host and host -> ips maps. One place, so every case-analysis
  // view agrees on which IP belongs to which host.
  async function loadCaseNetwork(): Promise<{ ipToHost: Record<string, { id: string; name: string }>; hostIps: Record<string, string[]> }> {
    const ipToHost: Record<string, { id: string; name: string }> = {};
    const hostIps: Record<string, string[]> = {};
    for (const h of selectedCase?.hosts ?? []) {
      let ips: string[] = [];
      try {
        const cats = await window.api.listCategories(h.dir);
        const ov = cats.find((c) => c.name === "_OVERVIEW");
        if (ov) {
          const files = await window.api.listResultFiles(ov.fullPath);
          const ti = files.find((f) => f.name === "TargetInfo");
          if (ti) {
            const d = await window.api.readResultFile(ti.fullPath, ti.tableName);
            ips = [...new Set(d.rows.filter((r) => r.category === "NetworkInterface" && r.value).flatMap((r) => r.value.split(/[,\s]+/)).map((s) => s.trim()).filter(Boolean))];
          }
        }
      } catch {
        ips = [];
      }
      hostIps[h.id] = ips;
      // Loopback identifies the current machine, not a host-to-host relation.
      // Keep it in the raw interface list but never resolve a remote peer to it.
      for (const ip of ips) if (!isLoopbackAddress(ip)) ipToHost[ip] = { id: h.id, name: h.name };
    }
    return { ipToHost, hostIps };
  }

  // Auto-(re)load the case network map whenever the case or its host set
  // changes — so a host added (or re-parsed) later is picked up automatically
  // and its IPs become recognizable everywhere.
  useEffect(() => {
    if (!selectedCase) {
      setCaseNetwork(null);
      return;
    }
    const sig = selectedCase.hosts.map((h) => h.id).sort().join(",");
    if (caseNetwork?.caseId === selectedCase.id && caseNetwork.sig === sig && caseNetwork.nonce === netNonce) return;
    let cancelled = false;
    loadCaseNetwork().then((net) => {
      if (!cancelled) setCaseNetwork({ caseId: selectedCase.id, sig, nonce: netNonce, ...net });
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCase, netNonce]);

  // Case-level host-connection graph: read every registered host's RDP history
  // (RemoteDesktopHistory) and its IPs (TargetInfo) from the _OVERVIEW folder,
  // then link inbound/outbound connections. Remote IPs that match a registered
  // host's IP become host↔host edges; the rest are external nodes.
  async function buildHostGraph(): Promise<HostGraph> {
    const hosts: HostGraph["hosts"] = [];
    const ipToHost = new Map<string, string>();
    const perHost: { name: string; rdp: Record<string, string>[] }[] = [];
    const rdpSourceFailures: string[] = [];
    const networkMappingFailures: string[] = [];

    for (const h of selectedCase?.hosts ?? []) {
      let cats: CategoryEntry[] = [];
      try {
        cats = await window.api.listCategories(h.dir);
      } catch {
        rdpSourceFailures.push(`${h.name} 분석 폴더`);
        cats = [];
      }
      const ov = cats.find((c) => c.name === "_OVERVIEW");
      if (!ov) {
        rdpSourceFailures.push(`${h.name} 분석 개요`);
        hosts.push({ name: h.name, ips: [] });
        continue;
      }
      let files: ResultFileEntry[] = [];
      try {
        files = await window.api.listResultFiles(ov.fullPath);
      } catch {
        rdpSourceFailures.push(`${h.name} 분석 결과`);
        hosts.push({ name: h.name, ips: [] });
        continue;
      }
      const ti = files.find((f) => f.name === "TargetInfo");
      let ips: string[] = [];
      if (ti) {
        try {
          const d = await window.api.readResultFile(ti.fullPath, ti.tableName);
          ips = [...new Set(d.rows.filter((r) => r.category === "NetworkInterface" && r.value).flatMap((r) => r.value.split(/[,\s]+/)).map((s) => s.trim()).filter(Boolean))];
        } catch {
          networkMappingFailures.push(`${h.name} 네트워크 정보`);
          ips = [];
        }
      }
      hosts.push({ name: h.name, ips });
      ips.filter((ip) => !isLoopbackAddress(ip)).forEach((ip) => ipToHost.set(ip, h.name));
      const readRows = async (fname: string) => {
        const f = files.find((x) => x.name === fname);
        if (!f) {
          rdpSourceFailures.push(`${h.name} ${fname} 결과 없음`);
          return [] as Record<string, string>[];
        }
        try {
          return (await window.api.readResultFile(f.fullPath, f.tableName)).rows;
        } catch {
          rdpSourceFailures.push(`${h.name} ${fname}`);
          return [] as Record<string, string>[];
        }
      };
      perHost.push({ name: h.name, rdp: await readRows("RemoteDesktopHistory") });
    }

    // A single "LOCAL" node collects console/AD-style sessions; loopback stays
    // per-host (HOST/127.0.0.1) so every host's localhost tooling isn't merged.
    const classify = (remote: string, owner: string) => {
      if (isLoopbackAddress(remote)) return { id: `${owner} loop`, label: `${owner}/${remote}`, kind: "loopback" as const, isHost: false };
      const peerHost = ipToHost.get(remote);
      if (peerHost) return { id: peerHost, label: peerHost, kind: "host" as const, isHost: true };
      if (remote.toUpperCase() === "LOCAL") return { id: "LOCAL", label: "LOCAL", kind: "local" as const, isHost: false };
      return { id: remote, label: remote, kind: "external" as const, isHost: false };
    };

    // Emit one raw record per RDP row (pre-classified but not aggregated), so
    // the view can apply the time-range filter and aggregate on the client —
    // no re-read needed when the incident window changes.
    const records: ConnRecord[] = [];
    for (const ph of perHost) {
      for (const r of ph.rdp) {
        const remote = r.remote_address;
        if (!remote) continue;
        const direction = r.direction === "outbound" ? "outbound" : r.direction === "inbound" ? "inbound" : "unknown";
        const c = classify(remote, ph.name);
        if (c.isHost && c.id === ph.name) continue; // self
        records.push({
          host: ph.name,
          peer: c.id,
          peerLabel: c.label,
          peerKind: c.kind,
          peerIsHost: c.isHost,
          direction,
          timestamp: r.timestamp || "",
          // normalize DOMAIN\/HOST\ prefix to the bare username (matches the RDP view)
          account: ((r.account || "").replace(/\//g, "\\").split("\\").pop() || "").split("@")[0],
          result: r.result || "",
        });
      }
    }
    return {
      hosts,
      records,
      rdpSourceFailures: [...new Set(rdpSourceFailures)],
      networkMappingFailures: [...new Set(networkMappingFailures)],
    };
  }

  async function handleSelectConnections(force = false) {
    setActiveVirtualTab("connections");
    if (!selectedCase) return;
    if (!force && hostGraph?.caseId === selectedCase.id) return;
    setHostGraphLoading(true);
    try {
      const graph = await buildHostGraph();
      setHostGraph({ caseId: selectedCase.id, graph });
    } finally {
      setHostGraphLoading(false);
    }
  }

  // Keyed by (fullPath, tableName, rowid) so any view holding those three —
  // the data table or the master timeline — can toggle a bookmark the same way.
  async function handleToggleBookmark(fullPath: string, tableName: string, rowid: number, field?: string, eventTime?: string) {
    if (!selectedHost) return;
    try {
      const result = await window.api.toggleBookmark(parentDir(selectedHost.dir), { fullPath, tableName, rowid, field, eventTime, hostId: selectedHost.id, hostName: selectedHost.name });
      setBookmarks(result);
      setBookmarkError(null);
    } catch {
      setBookmarkError("북마크를 저장하지 못했습니다. 분석 저장소 권한을 확인하세요.");
    }
  }

  // Overview bookmarks belong to the underlying raw evidence record. This
  // keeps their visual marker shared by the overview, master timeline and raw
  // artifact view instead of creating competing per-view annotations.
  async function handleToggleSourceAwareBookmark(
    row: Record<string, string> | undefined,
    fullPath: string,
    tableName: string,
    rowid: number,
    field?: string,
  ) {
    if (!selectedHost) return;
    const source = sourceRecordRef(row?.record_key || row?._record_key);
    // 승격 저장 시 개요 행의 사건 시각을 북마크에 함께 남긴다 — 원시 레코드
    // (Registry 등)에는 실행 시각 컬럼이 없어, 없으면 북마크 시간축이
    // last_write 같은 다른 시각으로 밀려 분석가가 기대한 위치에 안 보인다.
    const overviewTime = row?.timestamp || "";
    if (source) {
      for (const category of categories) {
        const files = await window.api.listResultFiles(category.fullPath);
        const sourceFile = files.find((file) => {
          const tableMatches = file.tableName.trim().toLowerCase() === source.tableName.trim().toLowerCase();
          const fileMatches = !source.fileName || resultFileStem(file.fullPath).trim().toLowerCase() === source.fileName.trim().toLowerCase();
          return tableMatches && fileMatches;
        });
        if (sourceFile) {
          await handleToggleBookmark(sourceFile.fullPath, sourceFile.tableName, source.rowid, field, overviewTime || undefined);
          return;
        }
      }
    }
    await handleToggleBookmark(fullPath, tableName, rowid, field);
  }

  async function handleToggleActiveRowBookmark(rowid: number, field?: string) {
    if (!activeTab) return;
    const row = activeTab.data?.rows.find((entry) => Number((entry as Record<string, unknown>).__rowid) === rowid);
    await handleToggleSourceAwareBookmark(row, activeTab.file.fullPath, activeTab.file.tableName, rowid, field);
  }

  async function handleToggleTimelineBookmark(entry: TimelineEntry) {
    await handleToggleSourceAwareBookmark(entry.row, entry.fullPath, entry.table, entry.rowid);
  }

  async function handleRemoveBookmark(bookmark: Bookmark) {
    if (!selectedHost) return;
    try {
      const result = await window.api.toggleBookmark(parentDir(selectedHost.dir), {
        fullPath: bookmark.fullPath,
        tableName: bookmark.tableName,
        rowid: bookmark.rowid,
        field: bookmark.field,
      });
      setBookmarks(result);
      setBookmarkError(null);
    } catch {
      setBookmarkError("북마크를 저장하지 못했습니다. 분석 저장소 권한을 확인하세요.");
    }
  }

  async function handleUpdateBookmarkNote(id: string, note: string) {
    if (!selectedHost) return;
    try {
      const result = await window.api.updateBookmarkNote(parentDir(selectedHost.dir), id, note);
      setBookmarks(result);
      setBookmarkError(null);
    } catch {
      setBookmarkError("북마크 메모를 저장하지 못했습니다. 분석 저장소 권한을 확인하세요.");
    }
  }

  // Open a search hit's exact row (same cross-host logic as bookmarks).
  async function handleOpenSearchHit(h: SearchHit) {
    const target =
      selectedCase?.hosts.find((x) => x.id === h.hostId) ??
      (!h.hostId ? selectedCase?.hosts.find((x) => {
        const sourcePath = h.fullPath.replace(/\\/g, "/").replace(/\/+$/, "");
        const hostPath = x.dir.replace(/\\/g, "/").replace(/\/+$/, "");
        return sourcePath === hostPath || sourcePath.startsWith(`${hostPath}/`);
      }) : undefined);
    if (target && target.id !== selectedHost?.id) {
      await openHost(target);
    }
    const entry: ResultFileEntry = {
      name: h.tableName,
      fileName: h.fileName,
      tableName: h.tableName,
      relativePath: "",
      fullPath: h.fullPath,
      rowCount: 0,
    };
    await handleSelectFile(entry);
    setPendingFilter({ column: "__rowid", value: String(h.rowid) });
  }

  async function findSearchHitSourceFile(target: Host, source: SourceRecordRef): Promise<ResultFileEntry | null> {
    const targetCategories = await window.api.listCategories(target.dir);
    for (const category of targetCategories) {
      const files = await window.api.listResultFiles(category.fullPath);
      const sourceFile = files.find((file) => {
        const tableMatches = file.tableName.trim().toLowerCase() === source.tableName.trim().toLowerCase();
        const fileMatches = !source.fileName || resultFileStem(file.fullPath).trim().toLowerCase() === source.fileName.trim().toLowerCase();
        return tableMatches && fileMatches;
      });
      if (sourceFile) return sourceFile;
    }
    return null;
  }

  function isSearchHitBookmarked(hit: SearchHit): boolean {
    const direct = bookmarks.some((bookmark) =>
      bookmark.fullPath === hit.fullPath
      && bookmark.tableName === hit.tableName
      && bookmark.rowid === hit.rowid
      && !bookmark.field
    );
    if (direct) return true;

    const source = sourceRecordRef(hit.recordKey);
    if (!source) return false;
    return bookmarks.some((bookmark) =>
      searchHitHostMatchesSourceBookmark(hit, bookmark, selectedCase?.hosts ?? [])
      && !bookmark.field
      && bookmark.tableName.trim().replace(/\.evtx$/i, "").toLowerCase() === source.tableName.trim().replace(/\.evtx$/i, "").toLowerCase()
      && bookmark.rowid === source.rowid
      && (!source.fileName || resultFileStem(bookmark.fullPath).trim().toLowerCase() === source.fileName.trim().toLowerCase())
    );
  }

  // Search results can belong to any registered host. Persist the exact raw
  // record against that hit's host/case, rather than the currently selected
  // host, so the common detail panel and analysis-info view stay synchronized.
  async function handleToggleSearchHitBookmark(h: SearchHit) {
    const target =
      selectedCase?.hosts.find((host) => host.id === h.hostId) ??
      (!h.hostId ? selectedCase?.hosts.find((host) => {
        const sourcePath = h.fullPath.replace(/\\/g, "/").replace(/\/+$/, "");
        const hostPath = host.dir.replace(/\\/g, "/").replace(/\/+$/, "");
        return sourcePath === hostPath || sourcePath.startsWith(`${hostPath}/`);
      }) : undefined);
    if (!target) {
      setBookmarkError("검색 결과의 호스트를 찾을 수 없어 북마크를 저장하지 못했습니다.");
      return;
    }
    try {
      const source = sourceRecordRef(h.recordKey);
      let fullPath = h.fullPath;
      let tableName = h.tableName;
      let rowid = h.rowid;
      if (source) {
        const sourceFile = await findSearchHitSourceFile(target, source);
        if (!sourceFile) {
          setBookmarkError("검색 결과가 가리키는 원본 증거 레코드를 찾을 수 없어 북마크를 저장하지 못했습니다.");
          return;
        }
        fullPath = sourceFile.fullPath;
        tableName = sourceFile.tableName;
        rowid = source.rowid;
      }
      const result = await window.api.toggleBookmark(parentDir(target.dir), {
        fullPath,
        tableName,
        rowid,
        field: undefined,
        hostId: target.id,
        hostName: target.name,
      });
      setBookmarks(result);
      setBookmarkError(null);
    } catch {
      setBookmarkError("북마크를 저장하지 못했습니다. 분석 저장소 권한을 확인하세요.");
    }
  }

  const activeTab = tabs.find((t) => keyOf(t.file) === activePath) ?? null;
  const activeTimeline = selectedHost && masterTimeline?.hostId === selectedHost.id ? masterTimeline.entries : null;
  const currentAccountDirectory = selectedHost ? accountDirectories[accountDirectoryKey(selectedHost)] : undefined;
  const accountDirectoryForHostId = useCallback(
    (hostId: string): AccountDirectory | undefined => {
      const host = selectedCase?.hosts.find((candidate) => candidate.id === hostId);
      return host ? accountDirectories[accountDirectoryKey(host)] : undefined;
    },
    [accountDirectories, selectedCase?.hosts],
  );
  const bookmarksForCurrentHost = useMemo(
    () => bookmarks.filter((bookmark) => !bookmark.hostId || bookmark.hostId === selectedHost?.id),
    [bookmarks, selectedHost?.id],
  );
  const bookmarkedSourceKeys = useMemo(() => new Set(bookmarksForCurrentHost.flatMap((bookmark) => [
      sourceBookmarkKey(bookmark.tableName, bookmark.rowid),
      sourceBookmarkKey(bookmark.tableName, bookmark.rowid, resultFileStem(bookmark.fullPath)),
    ])), [bookmarksForCurrentHost]);
  const activeBookmarkedRowids = useMemo(() => {
    if (!activeTab?.data) return undefined;
    const directRows = new Set(
      bookmarksForCurrentHost
        .filter((bookmark) => bookmark.fullPath === activeTab.file.fullPath && bookmark.tableName === activeTab.file.tableName)
        .map((bookmark) => bookmark.rowid),
    );
    return new Set(
      activeTab.data.rows
        .filter((row) => {
          const rowid = Number((row as Record<string, unknown>).__rowid);
          if (directRows.has(rowid)) return true;
          const source = sourceRecordRef(row.record_key || row._record_key);
          return source ? bookmarkedSourceKeys.has(sourceBookmarkKey(source.tableName, source.rowid, source.fileName)) : false;
        })
        .map((row) => Number((row as Record<string, unknown>).__rowid)),
    );
  }, [activeTab, bookmarkedSourceKeys, bookmarksForCurrentHost]);
  // Timeline rows span many files, so a per-file rowid set isn't enough —
  // key on fullPath+rowid to tell which timeline entries are bookmarked.
  const bookmarkedKeys = new Set(bookmarksForCurrentHost.map((b) => `${b.fullPath}#${b.rowid}`));
  const isTimelineEntryBookmarked = (entry: TimelineEntry) => {
    if (bookmarkedKeys.has(`${entry.fullPath}#${entry.rowid}`)) return true;
    const source = sourceRecordRef(entry.row.record_key || entry.row._record_key);
    return Boolean(source && bookmarkedSourceKeys.has(sourceBookmarkKey(source.tableName, source.rowid, source.fileName)));
  };
  // Full bookmark records for the active table — the MFT view needs the per-
  // timestamp `field`, not just which rowids are bookmarked.
  const activeTableBookmarks = activeTab
    ? bookmarksForCurrentHost.filter((b) => b.fullPath === activeTab.file.fullPath && b.tableName === activeTab.file.tableName)
    : [];

  // A parse keeps running in the Electron main process even after we leave the
  // RunPipeline screen; this floating bar keeps its progress visible everywhere
  // but that screen (which has its own detailed panel).
  const runningPipelineCount = run.runs.filter((entry) => entry.status === "running").length;
  const queuedPipelineCount = run.runs.filter((entry) => entry.status === "queued").length;
  const globalProgress = run.active ? (
    <GlobalProgress
      hostName={run.runningHostName ?? ""}
      stepLabel={run.stepLabel}
      percent={run.percent}
      complete={run.runComplete}
      hadError={run.hadError}
      runningCount={runningPipelineCount}
      queuedCount={queuedPipelineCount}
      onOpen={selectedHost ? backToHosts : undefined}
      onDismiss={run.dismiss}
    />
  ) : null;

  // The direct host store is being bootstrapped or its legacy layout is being
  // migrated before the host intake screen opens.
  if (!selectedCase) {
    return (
      <main className="dfir-app" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <div className="dfir-view" style={{ flex: 1, display: "grid", placeItems: "center", padding: 24 }}>
          {casesLoading ? (
            <div role="status" aria-live="polite" style={{ display: "inline-flex", alignItems: "center", gap: 8, color: "var(--text-dim)", fontSize: 13 }}>
              <CircularProgress size={16} thickness={5} aria-hidden="true" />분석 저장소를 준비하는 중
            </div>
          ) : (
            <div role="alert" style={{ maxWidth: 460, color: "var(--text)", fontSize: 13, lineHeight: 1.55 }}>
              <strong style={{ display: "block", marginBottom: 6 }}>분석 저장소를 불러오지 못했습니다.</strong>
              <span style={{ color: "var(--text-dim)" }}>{casesError || "저장소에 등록된 호스트가 없습니다."}</span>
              <button type="button" onClick={bootstrapHostStore} style={{ display: "block", marginTop: 12 }}>
                다시 시도
              </button>
            </div>
          )}
        </div>
      </main>
    );
  }

  // Screen 1: the session is ready; register and parse hosts.
  if (!selectedHost) {
    return (
      <main className="dfir-app" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <RunPipeline activeCase={selectedCase} onChanged={refreshCases} onOpenHost={openHost} run={run} />
      </main>
    );
  }

  // Screen 3: a host is open → browse its artifacts.
  return (
    <main className="dfir-app" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div className="dfir-workspace" style={{ flex: 1, minHeight: 0, display: "flex" }}>
        <Sidebar
          activeCase={selectedCase}
          activeHost={selectedHost}
          onSelectHost={openHost}
          onBackToHosts={backToHosts}
          categories={categories}
          overviewFiles={overviewFiles}
          // A virtual analysis view (timeline/bookmarks/etc.) is the current
          // navigation target. Do not leave its previously opened source file
          // highlighted in the sidebar at the same time.
          selectedFile={activeVirtualTab ? null : activeTab?.file ?? null}
          onSelectFile={handleSelectFile}
          activeVirtualTab={activeVirtualTab}
          onSelectTimeline={handleSelectTimeline}
          onSelectBookmarks={handleSelectBookmarks}
          onSelectConnections={handleSelectConnections}
          onSelectSearch={() => setActiveVirtualTab("search")}
          bookmarkCount={bookmarks.length}
          timeRange={timeRange}
          onTimeRangeChange={setTimeRange}
          onNavigate={handleNavigate}
        />
          <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column" }}>
            {bookmarkError && (
              <div role="alert" style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0, minHeight: 34, padding: "6px 14px", borderBottom: "1px solid color-mix(in srgb, var(--danger) 45%, var(--border))", background: "color-mix(in srgb, var(--danger) 10%, var(--bg-panel))", color: "var(--text)", fontSize: 12.5 }}>
                <span>{bookmarkError}</span>
                <button type="button" onClick={() => setBookmarkError(null)} aria-label="북마크 저장 오류 닫기" style={{ marginLeft: "auto", padding: "2px 7px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "transparent", color: "var(--text-dim)", cursor: "pointer", fontSize: 11 }}>닫기</button>
              </div>
            )}
            {activeVirtualTab === "timeline" && (
              <MasterTimeline
                entries={activeTimeline}
                loading={masterTimelineLoading}
                onNavigate={handleNavigate}
                onFetchLinkedRows={fetchLinkedRows}
                isBookmarked={isTimelineEntryBookmarked}
                onToggleBookmark={handleToggleTimelineBookmark}
                globalTimeRange={timeRange}
                accountDirectory={currentAccountDirectory}
              />
            )}

            {activeVirtualTab === "bookmarks" && (
              <BookmarksView
                bookmarks={bookmarks}
                hosts={selectedCase?.hosts ?? []}
                hostIpMap={caseNetwork?.caseId === selectedCase?.id ? caseNetwork.ipToHost : {}}
                currentHostId={selectedHost?.id ?? null}
                timeRange={timeRange}
                onRemove={handleRemoveBookmark}
                onNavigate={handleNavigate}
                onFetchLinkedRows={fetchLinkedRows}
                accountDirectoryForHost={accountDirectoryForHostId}
              />
            )}

            {activeVirtualTab === "search" && (
              <CaseSearchView
                hosts={selectedCase?.hosts ?? []}
                currentHostId={selectedHost?.id ?? null}
                timeRange={timeRange}
                isBookmarked={isSearchHitBookmarked}
                onOpenSource={handleOpenSearchHit}
                onToggleBookmark={handleToggleSearchHitBookmark}
                onFetchLinkedRows={fetchLinkedRows}
                accountDirectoryForHost={accountDirectoryForHostId}
              />
            )}

            {activeVirtualTab === "connections" && (
              <HostConnectionView
                graph={selectedCase && hostGraph?.caseId === selectedCase.id ? hostGraph.graph : null}
                loading={hostGraphLoading}
                timeRange={timeRange}
                focusHostName={selectedHost?.name ?? null}
                onRefresh={() => handleSelectConnections(true)}
                onOpenHost={(name) => {
                  const h = selectedCase?.hosts.find((x) => x.name === name);
                  if (h) openHost(h);
                }}
              />
            )}

            {!activeVirtualTab && !activeTab && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-faint)", fontSize: 13 }}>
                좌측에서 볼 항목을 선택하세요.
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
            {!activeVirtualTab && activeTab && !activeTab.loading && !activeTab.error && activeTab.data &&
              (getArtifactView(activeTab.file.name)?.customView === "mft" ? (
                <MftView
                  dbPath={activeTab.file.fullPath}
                  tableBookmarks={activeTableBookmarks}
                  onToggleBookmark={(rowid, field) => handleToggleBookmark(activeTab.file.fullPath, activeTab.file.tableName, rowid, field)}
                  allBookmarks={bookmarks}
                  onBookmarkRef={(fullPath, tableName, rowid, field) => handleToggleBookmark(fullPath, tableName, rowid, field)}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "targetInfo" ? (
                <TargetInfoView
                  data={activeTab.data}
                  loadAccountEvents={loadAccountEvents}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  tableBookmarks={activeTableBookmarks}
                  onToggleBookmark={(rowid, field) => handleToggleBookmark(activeTab.file.fullPath, activeTab.file.tableName, rowid, field)}
                  eventBookmarks={bookmarks}
                  onToggleEventBookmark={(fullPath, tableName, rowid) => handleToggleBookmark(fullPath, tableName, rowid)}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "executionHistory" ? (
                <ExecutionHistoryView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "defender" ? (
                <DefenderView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "wer" ? (
                <WerView
                  data={activeTab.data}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "registryFindings" ? (
                <RegistryFindingsView
                  data={activeTab.data}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "browserHistory" ? (
                <BrowserHistoryView
                  dbPath={activeTab.file.fullPath}
                  tableName={activeTab.file.tableName}
                  hostDir={selectedHost?.dir ?? ""}
                  timeRange={timeRange}
                  // BrowserActivity is server-paginated, so the active tab
                  // deliberately has no materialised rows. Deriving the
                  // bookmark set from activeTab.data therefore always
                  // produced an empty set and made a successful toggle look
                  // like it had failed. These are raw BrowserActivity rows,
                  // so use the table-scoped bookmark records directly.
                  bookmarkedRowids={new Set(activeTableBookmarks.map((bookmark) => bookmark.rowid))}
                  onToggleBookmark={(rowid) => handleToggleBookmark(activeTab.file.fullPath, activeTab.file.tableName, rowid)}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "firewall" ? (
                <FirewallView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "bits" ? (
                <BitsView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "smb" ? (
                <SmbHistoryView
                  fileName={activeTab.file.name}
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "scheduledTasks" ? (
                <ScheduledTasksView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  timeRange={timeRange}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.customView === "rdpCache" ? (
                <RdpCacheView data={activeTab.data} mode={activeTab.file.name === "RdpBitmapCache" ? "tiles" : "fragments"} />
              ) : getArtifactView(activeTab.file.name)?.customView === "powershellFlow" ? (
                <PowerShellFlowView
                  data={activeTab.data}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleActiveRowBookmark(rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : getArtifactView(activeTab.file.name)?.flowView ? (
                <SessionFlowView
                  fileName={activeTab.file.name}
                  data={activeTab.data}
                  hostIpMap={caseNetwork?.caseId === selectedCase?.id ? caseNetwork.ipToHost : {}}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleBookmark(activeTab.file.fullPath, activeTab.file.tableName, rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ) : (
                <DataTable
                  fileName={activeTab.file.name}
                  data={activeTab.data}
                  onLoadMore={activeTab.data.rows.length < activeTab.data.rowCount ? loadMoreRawRows : undefined}
                  initialFilter={pendingFilter}
                  onInitialFilterConsumed={() => setPendingFilter(null)}
                  onNavigate={handleNavigate}
                  onFetchLinkedRows={fetchLinkedRows}
                  bookmarkedRowids={activeBookmarkedRowids}
                  onToggleBookmark={(rowid) => handleToggleBookmark(activeTab.file.fullPath, activeTab.file.tableName, rowid)}
                  timeRange={timeRange}
                  accountDirectory={currentAccountDirectory}
                />
              ))}
          </div>
        </div>
      {globalProgress}
    </main>
  );
}
