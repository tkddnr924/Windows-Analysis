"use client";
import { toBound } from "@/lib/timeRange";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { DateRangeDropdown, HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";
import PaginationControls from "@/components/PaginationControls";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Bookmark, MftRecordsPage, PathReference } from "@/lib/types";
import CircularProgress from "@mui/material/CircularProgress";
import IconButton from "@mui/material/IconButton";
import useMediaQuery from "@mui/material/useMediaQuery";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import InsertDriveFileOutlinedIcon from "@mui/icons-material/InsertDriveFileOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import ViewListOutlinedIcon from "@mui/icons-material/ViewListOutlined";
import RowDetailPanel from "./RowDetailPanel";

// File-system information is read from the MFT_Records overview table. The
// table can hold ~1M rows, so folders load lazily and search queries SQLite
// directly instead of materializing all records in the browser.

type Row = Record<string, string>;

// 폴더 펼치기 한 페이지의 자식 수 — 초과분은 "더 불러오기"로 이어 받는다.
const MFT_CHILDREN_PAGE = 100;

const ROOT_ENTRY = 5;
const LIST_FETCH_SIZE = 200; // lazy 로딩 배치 크기
const LIST_ROW_HEIGHT = 56;
// 시각 기준 정렬·기간 필터 키 → 라벨/컬럼. si_* 4종에 더해 fn_*($FILE_NAME
// 0x30)도 제공한다 — timestomping은 주로 $SI만 조작되므로 $FN 기준 정렬이
// 조작 전 시각으로 표를 놓고 비교하는 수단이 된다(T7).
const MFT_TIME_SORTS: Record<string, { label: string; column: string }> = {
  created: { label: "생성 시각", column: "si_created" },
  modified: { label: "수정 시각", column: "si_modified" },
  accessed: { label: "접근 시각", column: "si_accessed" },
  mft_modified: { label: "MFT 수정 시각", column: "si_mft_modified" },
  fn_created: { label: "생성 시각 ($FN)", column: "fn_created" },
  fn_modified: { label: "수정 시각 ($FN)", column: "fn_modified" },
  fn_accessed: { label: "접근 시각 ($FN)", column: "fn_accessed" },
  fn_mft_modified: { label: "MFT 수정 시각 ($FN)", column: "fn_mft_modified" },
};

interface Props {
  dbPath: string;
  /** Bookmarks already scoped to this MFT table — which records (and which
   *  specific timestamps) are starred. */
  tableBookmarks: Bookmark[];
  onToggleBookmark: (rowid: number, field: string) => void;
  /** All bookmarks for the case (any table) — lets the JumpList/Shellbag detail
   *  modal show whether a reference's timestamp is already bookmarked. */
  allBookmarks: Bookmark[];
  /** Toggle a bookmark on an arbitrary (source sqlite, table, row, field) —
   *  used for JumpList reference timestamps. */
  onBookmarkRef: (fullPath: string, tableName: string, rowid: number, field: string) => void;
}


/** dbPath is <hostDir>/_OVERVIEW/MFT_Records.sqlite — strip the tail to get
 *  the host folder the other artifacts live under. */
function hostDirOf(dbPath: string): string {
  const parts = dbPath.split(/[\\/]/);
  return parts.slice(0, Math.max(0, parts.length - 2)).join("/");
}

type RefMap = Map<string, PathReference[]>;

/// References for a row's path, optionally limited to selected accounts
/// (accountFilter === null means "no filtering — show all").
function refsFor(refs: RefMap, row: Row, accountFilter: Set<string> | null): PathReference[] {
  const p = (row.path || "").toLowerCase();
  if (!p) return [];
  const all = refs.get(p) ?? [];
  if (!accountFilter) return all;
  return all.filter((r) => accountFilter.has(r.account));
}

function referenceTags(refs: RefMap, row: Row, accountFilter: Set<string> | null): { account: string; kind: string }[] {
  const seen = new Set<string>();
  const tags: { account: string; kind: string }[] = [];
  for (const reference of refsFor(refs, row, accountFilter)) {
    const key = `${reference.account}|${reference.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    tags.push({ account: reference.account, kind: reference.kind });
  }
  return tags;
}

function referenceTagSummary(tags: { account: string; kind: string }[]) {
  const [first] = tags;
  if (!first) return "";
  const label = `${first.kind} · ${first.account || "미상"}`;
  return tags.length > 1 ? `${label} +${tags.length - 1}` : label;
}

function referenceTagTitle(tags: { account: string; kind: string }[]) {
  return tags.map((tag) => `${tag.kind} · ${tag.account || "미상"}`).join(", ");
}

function isDir(r: Row): boolean {
  return r.is_directory === "Y";
}
function fmtSize(v: string): string {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default function MftView({ dbPath, tableBookmarks, onToggleBookmark, allBookmarks, onBookmarkRef }: Props) {
  const [root, setRoot] = useState<{ rows: Row[]; total: number } | null>(null);
  const [childrenCache, setChildrenCache] = useState<Record<string, { rows: Row[]; total: number }>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loadingEntry, setLoadingEntry] = useState<Set<string>>(new Set());
  const [failedEntries, setFailedEntries] = useState<Set<string>>(new Set());
  // 첫 페이지는 받았는데 "더 불러오기"만 실패한 폴더 — 최초 실패와 분리해야
  // 이미 적재된 행이 오류 문구에 가려지지 않고, 버튼으로 재시도할 수 있다.
  const [loadMoreFailed, setLoadMoreFailed] = useState<Set<string>>(new Set());
  const [rootError, setRootError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Row | null>(null);
  const [referenceDetail, setReferenceDetail] = useState<PathReference | null>(null);
  // Cross-artifact sightings of a path (JumpList today), indexed by lowercased
  // path so the tree can tag rows without a query per row.
  const [pathRefs, setPathRefs] = useState<RefMap>(new Map());
  const [pathRefsError, setPathRefsError] = useState<string | null>(null);
  // Accounts seen across all references, and which are currently shown. An
  // investigator can uncheck accounts unrelated to the attack so their
  // JumpList/Shellbag tags stop cluttering the tree.
  const [refAccounts, setRefAccounts] = useState<string[]>([]);
  const [selAccounts, setSelAccounts] = useState<Set<string>>(new Set());

  // 교차 참조는 파싱 단계에서 만든 _OVERVIEW/PathReferences 파생 테이블을
  // "지금 화면에 로드된 경로"만 배치로 조회한다 — 화면 진입 시 전체
  // JumpList·Shellbag을 재구성해 통째로 들고 있던 방식을 대체 (협약: 즉석
  // 가공 금지). 계정 필터 목록은 파생 테이블 집계로 따로 받는다.
  const requestedRefPaths = useRef<Set<string>>(new Set());
  useEffect(() => {
    requestedRefPaths.current = new Set();
    setPathRefs(new Map());
    setPathRefsError(null);
    let alive = true;
    window.api.pathReferenceAccounts(hostDirOf(dbPath)).then((accounts) => {
      if (!alive) return;
      setRefAccounts(accounts);
      setSelAccounts(new Set(accounts)); // default: all accounts shown
    }).catch(() => {
      if (!alive) return;
      setRefAccounts([]);
      setSelAccounts(new Set());
    });
    return () => { alive = false; };
  }, [dbPath]);



  const toggleAccount = useCallback((acct: string) => {
    setSelAccounts((s) => { const n = new Set(s); if (n.has(acct)) n.delete(acct); else n.add(acct); return n; });
  }, []);

  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<"tree" | "list">("tree");
  const [results, setResults] = useState<Row[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const searchSeq = useRef(0);
  const [listRows, setListRows] = useState<Row[]>([]);

  useEffect(() => {
    const pending: string[] = [];
    const collect = (row: Row | undefined) => {
      const path = (row?.path || "").toLowerCase();
      if (!path || requestedRefPaths.current.has(path)) return;
      requestedRefPaths.current.add(path);
      pending.push(path);
    };
    root?.rows.forEach(collect);
    Object.values(childrenCache).forEach((page) => page.rows.forEach(collect));
    listRows.forEach(collect);
    (results ?? []).forEach(collect);
    if (pending.length === 0) return;
    let alive = true;
    window.api.pathReferences(hostDirOf(dbPath), pending).then((list) => {
      if (!alive) return;
      setPathRefsError(null);
      if (list.length === 0) return;
      setPathRefs((prev) => {
        const merged: RefMap = new Map(prev);
        for (const r of list) {
          const arr = merged.get(r.path);
          if (arr) merged.set(r.path, [...arr, r]); else merged.set(r.path, [r]);
        }
        return merged;
      });
    }).catch(() => {
      // $MFT evidence remains usable without optional cross-artifact tags;
      // make that degraded state explicit instead of silently looking empty.
      // 실패한 배치의 경로는 요청 이력에서 되돌린다 — 다음 트리 확장·검색으로
      // effect가 다시 돌 때 자연 재시도되고, 일시 오류가 해당 경로들의 태그를
      // 세션 내내 누락시키지 않는다 (재등록 선점으로 중복 요청은 없음).
      for (const path of pending) requestedRefPaths.current.delete(path);
      if (alive) setPathRefsError("교차 참조 정보를 불러오지 못했습니다.");
    });
    return () => { alive = false; };
  }, [dbPath, root, childrenCache, listRows, results]);
  const [listTotal, setListTotal] = useState<number | null>(null);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  // 재귀 목록 전용 필터 — 기본은 파일만, 경로 오름차순.
  const [listSortKey, setListSortKey] = useState("path");
  const [listSortDesc, setListSortDesc] = useState(false);
  const [listFilesOnly, setListFilesOnly] = useState(true);
  const [listPattern, setListPattern] = useState("");
  // 재귀 목록 전용 시간 범위 — 시각 정렬 중이면 그 시각, 아니면 생성 시각 기준.
  const [listTimeStart, setListTimeStart] = useState("");
  const [listTimeEnd, setListTimeEnd] = useState("");
  const listSeq = useRef(0);

  useEffect(() => {
    let cancelled = false;
    setRoot(null);
    setRootError(null);
    setChildrenCache({});
    setExpanded(new Set());
    setFailedEntries(new Set());
    setLoadMoreFailed(new Set());
    setSelected(null);
    setReferenceDetail(null);
    window.api.mftChildren(dbPath, ROOT_ENTRY, 0, MFT_CHILDREN_PAGE).then((page) => {
      if (!cancelled) setRoot(page);
    }).catch(() => {
      if (!cancelled) {
        setRoot({ rows: [], total: 0 });
        setRootError("최상위 파일 시스템 레코드를 읽지 못했습니다.");
      }
    });
    return () => {
      cancelled = true;
    };
  }, [dbPath]);

  const loadChildren = useCallback(
    async (entry: string) => {
      if (childrenCache[entry]) return;
      setLoadingEntry((s) => new Set(s).add(entry));
      setFailedEntries((s) => { const next = new Set(s); next.delete(entry); return next; });
      try {
        const page = await window.api.mftChildren(dbPath, Number(entry), 0, MFT_CHILDREN_PAGE);
        setChildrenCache((c) => ({ ...c, [entry]: page }));
      } catch {
        setFailedEntries((s) => new Set(s).add(entry));
      } finally {
        setLoadingEntry((s) => {
          const n = new Set(s);
          n.delete(entry);
          return n;
        });
      }
    },
    [dbPath, childrenCache],
  );

  // 대형 폴더(수만 자식)에서 전체를 한 번에 IPC로 받지 않도록 페이지로 이어
  // 받는다 — "더 불러오기" 버튼이 다음 페이지를 기존 목록 뒤에 붙인다.
  const loadMoreChildren = useCallback(
    async (entry: string) => {
      const cached = entry === String(ROOT_ENTRY) ? root : childrenCache[entry];
      if (!cached || cached.rows.length >= cached.total || loadingEntry.has(entry)) return;
      setLoadingEntry((s) => new Set(s).add(entry));
      try {
        const page = await window.api.mftChildren(dbPath, Number(entry), cached.rows.length, MFT_CHILDREN_PAGE);
        // 후속 페이지는 서버가 COUNT를 생략하고 total=-1을 준다 — 첫 페이지의
        // 값을 유지한다.
        const merged = { rows: [...cached.rows, ...page.rows], total: page.total >= 0 ? page.total : cached.total };
        if (entry === String(ROOT_ENTRY)) setRoot(merged);
        else setChildrenCache((c) => ({ ...c, [entry]: merged }));
        setLoadMoreFailed((s) => { const n = new Set(s); n.delete(entry); return n; });
      } catch {
        setLoadMoreFailed((s) => new Set(s).add(entry));
      } finally {
        setLoadingEntry((s) => {
          const n = new Set(s);
          n.delete(entry);
          return n;
        });
      }
    },
    [dbPath, childrenCache, root, loadingEntry],
  );

  const toggle = useCallback(
    (r: Row) => {
      const entry = r.entry;
      setExpanded((s) => {
        const n = new Set(s);
        if (n.has(entry)) n.delete(entry);
        else {
          n.add(entry);
          void loadChildren(entry);
        }
        return n;
      });
    },
    [loadChildren],
  );

  // debounced search
  useEffect(() => {
    if (viewMode !== "tree") return;
    const seq = ++searchSeq.current;
    const q = search.trim();
    if (q.length < 2) {
      setResults(null);
      setSearching(false);
      setSearchError(null);
      return;
    }
    setSearching(true);
    setSearchError(null);
    const t = setTimeout(() => {
      window.api.mftSearch(dbPath, q, 500).then((rows) => {
        if (seq === searchSeq.current) {
          setResults(rows);
          setSearching(false);
        }
      }).catch(() => {
        if (seq === searchSeq.current) {
          setResults([]);
          setSearching(false);
          setSearchError("파일 시스템 검색 결과를 읽지 못했습니다.");
        }
      });
    }, 250);
    return () => clearTimeout(t);
  }, [search, dbPath, viewMode]);

  // The recursive list owns its own bounded SQLite page. It intentionally
  // does not reuse tree search results, which are capped and may omit paths.
  const listQuery = search.trim().length >= 2 ? search.trim() : "";
  const listTimeKey = MFT_TIME_SORTS[listSortKey] ? listSortKey : "created";
  const listOptions = useMemo(
    () => ({
      sortKey: listSortKey,
      sortDesc: listSortDesc,
      filesOnly: listFilesOnly,
      namePattern: listPattern.trim() || undefined,
      timeKey: listTimeKey,
      timeStart: toBound(listTimeStart, "start") || undefined,
      timeEnd: toBound(listTimeEnd, "end") || undefined,
    }),
    [listSortKey, listSortDesc, listFilesOnly, listPattern, listTimeKey, listTimeStart, listTimeEnd],
  );
  // 필터·정렬·검색이 바뀌면 처음부터 다시, 스크롤이 끝에 닿으면 이어서 불러온다.
  useEffect(() => {
    if (viewMode !== "list") return;
    const seq = ++listSeq.current;
    setListLoading(true);
    setListError(null);
    setListRows([]);
    setListTotal(null);
    window.api.mftRecordsPage(dbPath, listQuery, 0, LIST_FETCH_SIZE, listOptions).then((page) => {
      if (seq !== listSeq.current) return;
      setListRows(page.rows as Row[]);
      setListTotal(page.total);
      setListLoading(false);
    }).catch(() => {
      if (seq !== listSeq.current) return;
      setListError("파일 시스템 레코드 목록을 읽지 못했습니다.");
      setListLoading(false);
    });
  }, [dbPath, listQuery, viewMode, listOptions]);
  const loadMoreList = useCallback(() => {
    if (listLoading || listTotal === null || listRows.length >= listTotal) return;
    const seq = listSeq.current;
    setListLoading(true);
    window.api.mftRecordsPage(dbPath, listQuery, listRows.length, LIST_FETCH_SIZE, listOptions).then((page) => {
      if (seq !== listSeq.current) return;
      setListRows((previous) => [...previous, ...(page.rows as Row[])]);
      setListTotal(page.total);
      setListLoading(false);
    }).catch(() => {
      if (seq !== listSeq.current) return;
      setListError("파일 시스템 레코드 목록을 읽지 못했습니다.");
      setListLoading(false);
    });
  }, [dbPath, listQuery, listOptions, listLoading, listRows.length, listTotal]);

  const bmRowids = useMemo(() => new Set(tableBookmarks.map((b) => b.rowid)), [tableBookmarks]);
  const bmFieldKeys = useMemo(() => new Set(tableBookmarks.map((b) => `${b.rowid}@${b.field ?? ""}`)), [tableBookmarks]);
  const selectedRowid = selected ? Number(selected.__rowid) : null;
  const stackedInspector = useMediaQuery("(max-width: 960px)");
  const detailPanel = selected ? (
    <RowDetailPanel
      row={selected}
      columns={Object.keys(selected).filter((key) => key !== "__rowid")}
      focusedColumn={null}
      fileBaseName="MFT_Records"
      variant="docked"
      onClose={() => setSelected(null)}
      onNavigate={() => {}}
      isBookmarked={bmRowids.has(Number(selected.__rowid))}
      onToggleBookmark={() => onToggleBookmark(Number(selected.__rowid), "")}
      onToggleFieldBookmark={(field) => onToggleBookmark(Number(selected.__rowid), field)}
      isFieldBookmarked={(field) => bmFieldKeys.has(`${selected.__rowid}@${field}`)}
      relatedEvidence={refsFor(pathRefs, selected, selAccounts).map((reference, index) => ({
        id: `${reference.fullPath}:${reference.tableName}:${reference.rowid}:${index}`,
        label: `${reference.kind} · ${reference.account || "미상"}`,
        subtitle: reference.label,
        onOpen: () => setReferenceDetail(reference),
      }))}
    />
  ) : (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 9, minHeight: "100%", padding: 24, color: "var(--text-faint)", fontSize: 13 }}>
      <InsertDriveFileOutlinedIcon sx={{ fontSize: 30, color: "var(--text-faint)" }} />
      파일을 선택하면 MFT 정보를 표시합니다.
    </div>
  );

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <ViewHeader icon={FolderOpenOutlinedIcon} title="파일 시스템 정보" meta="$MFT" right={<div role="group" aria-label="MFT 보기 방식" style={{ display: "flex", gap: 4 }}>
            <button type="button" aria-pressed={viewMode === "tree"} className={viewMode === "tree" ? "nm-btn" : undefined} onClick={() => setViewMode("tree")} style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "3px 11px", border: `1px solid ${viewMode === "tree" ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: viewMode === "tree" ? "var(--accent-subtle)" : "transparent", color: viewMode === "tree" ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}><AccountTreeOutlinedIcon sx={{ fontSize: 15 }} />탐색기</button>
            <button type="button" aria-pressed={viewMode === "list"} className={viewMode === "list" ? "nm-btn" : undefined} onClick={() => setViewMode("list")} style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "3px 11px", border: `1px solid ${viewMode === "list" ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: viewMode === "list" ? "var(--accent-subtle)" : "transparent", color: viewMode === "list" ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}><ViewListOutlinedIcon sx={{ fontSize: 15 }} />전체 목록</button>
          </div>}>
          <HeaderSearchInput value={search} onChange={setSearch} placeholder="파일명 · 경로 검색 (2자 이상)" ariaLabel="파일명 또는 경로 검색" width={300} />
          {refAccounts.length > 0 && (
            <AccountFilterChips
              accounts={refAccounts}
              hidden={new Set(refAccounts.filter((account) => !selAccounts.has(account)))}
              onToggle={toggleAccount}
              onReset={() => setSelAccounts(new Set(refAccounts))}
              emptyLabel="(계정 미상)"
              ariaLabel="교차 참조 계정 필터"
            />
          )}
        {pathRefsError && <div role="status" style={{ marginTop: 8, color: "var(--warning)", fontSize: 11.5 }}>{pathRefsError}</div>}
      
      </ViewHeader>

      <div className={`mft-content mft-content--${viewMode}`} style={{ flex: 1, minHeight: 0, display: "grid", gap: 10, padding: 14, background: "var(--bg)", gridTemplateColumns: stackedInspector ? "minmax(0, 1fr)" : "minmax(0, 7fr) minmax(300px, 3fr)", gridTemplateRows: stackedInspector ? "minmax(300px, 1fr) minmax(260px, .75fr)" : undefined }}>
        <aside aria-label={viewMode === "tree" ? "파일 탐색기" : "재귀 파일 시스템 목록"} style={{ minWidth: 0, minHeight: 0, overflow: "hidden", padding: viewMode === "tree" ? "8px 10px 14px" : "0", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)", display: "flex", flexDirection: "column" }}>
          {viewMode === "list" ? (
            <MftRecordList rows={listRows} total={listTotal} loading={listLoading} error={listError} query={listQuery} bmRowids={bmRowids} selectedRowid={selectedRowid} refs={pathRefs} accountFilter={selAccounts} onSelect={setSelected} onLoadMore={loadMoreList} sortKey={listSortKey} onSortKey={setListSortKey} sortDesc={listSortDesc} onSortDesc={setListSortDesc} filesOnly={listFilesOnly} onFilesOnly={setListFilesOnly} pattern={listPattern} onPattern={setListPattern} timeStart={listTimeStart} timeEnd={listTimeEnd} onTimeRange={(next) => { setListTimeStart(next.start); setListTimeEnd(next.end); }} timeLabel={MFT_TIME_SORTS[listTimeKey]?.label ?? "생성 시각"} />
          ) : <>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
              {results !== null ? (
                <SearchResults rows={results} searching={searching} error={searchError} bmRowids={bmRowids} selectedRowid={selectedRowid} onSelect={setSelected} refs={pathRefs} accountFilter={selAccounts} />
              ) : root === null ? (
                <div style={{ minHeight: 100, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, color: "var(--text-dim)", fontSize: 12.5 }}>
                  <CircularProgress size={17} thickness={4} />
                  파일 시스템 레코드를 불러오는 중
                </div>
              ) : rootError ? (
                <div style={{ padding: "16px 8px", color: "var(--danger)", fontSize: 12.5 }}>{rootError}</div>
              ) : (
                <>
                  {root.rows.map((r) => (
                    <TreeNode
                      key={r.entry + "-" + r.__rowid}
                      row={r}
                      depth={0}
                      expanded={expanded}
                      childrenCache={childrenCache}
                      loadingEntry={loadingEntry}
                      failedEntries={failedEntries}
                      loadMoreFailed={loadMoreFailed}
                      bmRowids={bmRowids}
                      selectedRowid={selectedRowid}
                      onToggle={toggle}
                      onSelect={setSelected}
                      onLoadMore={loadMoreChildren}
                      refs={pathRefs}
                      accountFilter={selAccounts}
                    />
                  ))}
                  {root.rows.length < root.total && (
                    <button
                      type="button"
                      disabled={loadingEntry.has(String(ROOT_ENTRY))}
                      onClick={() => loadMoreChildren(String(ROOT_ENTRY))}
                      style={{ display: "block", marginLeft: 27, minHeight: 27, padding: "2px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", color: "var(--accent)", cursor: "pointer", fontSize: 11.5 }}
                    >
                      {loadingEntry.has(String(ROOT_ENTRY))
                        ? "불러오는 중…"
                        : loadMoreFailed.has(String(ROOT_ENTRY))
                          ? `이어받기 실패 — 다시 시도 (${root.rows.length.toLocaleString()}/${root.total.toLocaleString()})`
                          : `더 불러오기 (${root.rows.length.toLocaleString()}/${root.total.toLocaleString()})`}
                    </button>
                  )}
                </>
              )}
            </div>
          </>}
        </aside>
        <section aria-label="선택 항목 MFT 정보" style={{ minWidth: 0, minHeight: 0, overflow: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg-panel)" }}>{detailPanel}</section>
      </div>
      {referenceDetail && (
        <RowDetailPanel
          row={{ ...referenceDetail.fields, __rowid: String(referenceDetail.rowid) }}
          columns={Object.keys(referenceDetail.fields)}
          focusedColumn={null}
          fileBaseName={referenceDetail.tableName || referenceDetail.kind}
          onClose={() => setReferenceDetail(null)}
          onNavigate={() => {}}
          isBookmarked={referenceDetail.rowid >= 0 && allBookmarks.some((bookmark) => bookmark.fullPath === referenceDetail.fullPath && bookmark.rowid === referenceDetail.rowid)}
          onToggleBookmark={referenceDetail.rowid >= 0 ? () => onBookmarkRef(referenceDetail.fullPath, referenceDetail.tableName, referenceDetail.rowid, "") : undefined}
        />
      )}
    </div>
  );
}

function MftRecordList({ rows, total, loading, error, query, bmRowids, selectedRowid, refs, accountFilter, onSelect, onLoadMore, sortKey, onSortKey, sortDesc, onSortDesc, filesOnly, onFilesOnly, pattern, onPattern, timeStart, timeEnd, onTimeRange, timeLabel }: {
  rows: Row[];
  total: number | null;
  loading: boolean;
  error: string | null;
  query: string;
  bmRowids: Set<number>;
  selectedRowid: number | null;
  refs: RefMap;
  accountFilter: Set<string> | null;
  onSelect: (row: Row) => void;
  onLoadMore: () => void;
  sortKey: string;
  onSortKey: (key: string) => void;
  sortDesc: boolean;
  onSortDesc: (desc: boolean) => void;
  filesOnly: boolean;
  onFilesOnly: (value: boolean) => void;
  pattern: string;
  onPattern: (value: string) => void;
  timeStart: string;
  timeEnd: string;
  onTimeRange: (next: { start: string; end: string }) => void;
  timeLabel: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => LIST_ROW_HEIGHT, overscan: 12 });
  // 시각/크기 기준 정렬이면 그 값을 열로 함께 보여준다.
  const sortValue: { label: string; column: string; mono: boolean } | null =
    MFT_TIME_SORTS[sortKey] ? { ...MFT_TIME_SORTS[sortKey], mono: true }
    : sortKey === "size" ? { label: "크기", column: "file_size", mono: true }
    : null;
  const grid = sortValue ? "minmax(0, 3fr) 176px minmax(108px, 1fr)" : "minmax(0, 3fr) minmax(108px, 1fr)";
  const virtualItems = virtualizer.getVirtualItems();
  const lastVisibleIndex = virtualItems.length ? virtualItems[virtualItems.length - 1].index : 0;
  // lazy 로딩: 스크롤이 끝 30행 안쪽에 닿으면 다음 배치를 이어서 불러온다.
  useEffect(() => {
    if (loading || total === null || rows.length >= total) return;
    if (lastVisibleIndex >= rows.length - 30) onLoadMore();
  }, [lastVisibleIndex, loading, rows.length, total, onLoadMore]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: 0 }); }, [query, sortKey, sortDesc, filesOnly, pattern, timeStart, timeEnd]);

  return <section aria-label="MFT 재귀 목록" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
    <header style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", flexShrink: 0, padding: "8px 12px", borderBottom: "1px solid var(--border)" }}>
      <strong style={{ fontSize: 12.5, color: "var(--text)" }}>재귀 목록</strong>
      {/* 재귀 목록 전용 필터 — X-Ways 리컬시브 뷰처럼 이 화면에서만 쓴다. */}
      <input
        value={pattern}
        onChange={(event) => onPattern(event.target.value)}
        placeholder="파일명 패턴 (예: *.txt)"
        aria-label="파일명 패턴 필터"
        style={{ flex: "0 1 190px", minWidth: 130, minHeight: 30, padding: "4px 10px", fontSize: 12, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
      />
      <SelectDropdown
        icon={<SortOutlinedIcon sx={{ fontSize: 15 }} />}
        label="정렬"
        options={[
          { value: "path", label: "경로" },
          { value: "name", label: "파일 이름" },
          ...Object.entries(MFT_TIME_SORTS).map(([value, spec]) => ({ value, label: spec.label })),
          { value: "size", label: "크기" },
        ]}
        value={sortKey}
        defaultValue="path"
        onChange={onSortKey}
      />
      <SelectDropdown
        label="방향"
        options={[
          { value: "asc", label: "오름차순" },
          { value: "desc", label: "내림차순" },
        ]}
        value={sortDesc ? "desc" : "asc"}
        defaultValue="asc"
        onChange={(next: string) => onSortDesc(next === "desc")}
      />
      <span title={`${timeLabel} 기준으로 거릅니다`} style={{ display: "inline-flex" }}>
        <DateRangeDropdown start={timeStart} end={timeEnd} onChange={onTimeRange} onReset={() => onTimeRange({ start: "", end: "" })} />
      </span>
      <button
        type="button"
        className="nm-btn"
        aria-pressed={!filesOnly}
        onClick={() => onFilesOnly(!filesOnly)}
        title={filesOnly ? "폴더도 함께 표시" : "파일만 표시"}
        style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 31, padding: "4px 11px", background: filesOnly ? "var(--bg-elevated)" : "var(--accent-subtle)", color: filesOnly ? "var(--text-dim)" : "var(--accent)", border: `1px solid ${filesOnly ? "var(--border)" : "color-mix(in srgb, var(--accent) 58%, var(--border))"}`, borderRadius: "var(--radius-md)", cursor: "pointer", fontSize: 12, fontWeight: filesOnly ? 500 : 650, whiteSpace: "nowrap" }}
      >
        <FolderOutlinedIcon sx={{ fontSize: 15 }} />폴더 포함
      </button>
      <span style={{ marginLeft: "auto", color: "var(--text-faint)", fontSize: 11.5, fontVariantNumeric: "tabular-nums" }}>
        {total !== null ? `${rows.length.toLocaleString()} / ${total.toLocaleString()}건` : "\u00a0"}
        {loading && rows.length > 0 && " · 불러오는 중…"}
      </span>
    </header>
    {loading && rows.length === 0 ? <div role="status" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, flex: 1, color: "var(--text-dim)", fontSize: 12.5 }}><CircularProgress size={17} thickness={4} />MFT 레코드를 불러오는 중</div> : error ? <div role="alert" style={{ padding: 16, color: "var(--danger)", fontSize: 12.5 }}>{error}</div> : !rows.length ? <div role="status" style={{ display: "grid", placeItems: "center", flex: 1, color: "var(--text-faint)", fontSize: 12.5 }}>{query || pattern ? "일치하는 MFT 레코드가 없습니다." : "표시할 MFT 레코드가 없습니다."}</div> : <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
      <div style={{ minWidth: 0 }}>
        <div aria-hidden="true" style={{ display: "grid", gridTemplateColumns: grid, gap: 10, alignItems: "center", minHeight: 32, padding: "0 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span>파일 이름 / 경로</span>{sortValue && <span>{sortValue.label}</span>}<span>교차 참조</span></div>
        <div style={{ position: "relative", height: virtualizer.getTotalSize() }}>{virtualItems.map((virtualRow) => {
          const row = rows[virtualRow.index];
          const bookmarked = bmRowids.has(Number(row.__rowid));
          const selected = selectedRowid !== null && Number(row.__rowid) === selectedRowid;
          const tags = referenceTags(refs, row, accountFilter).slice(0, 2);
          const path = row.path || row.file_name || "경로 정보 없음";
          const isFolder = row.is_directory === "Y";
          return <div key={virtualRow.key} className={bookmarked ? `dfir-bookmarked-row${selected ? " dfir-bookmarked-row--selected" : ""}` : undefined} style={{ position: "absolute", top: 0, left: 0, width: "100%", height: LIST_ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)`, borderBottom: "1px solid var(--border-subtle)", background: selected ? "var(--bg-selected)" : "transparent" }}>
            <button type="button" onClick={() => onSelect(row)} title={path} aria-label={`${row.file_name || path} MFT 정보 보기`} style={{ display: "grid", gridTemplateColumns: grid, gap: 10, alignItems: "center", width: "100%", height: "100%", padding: "0 12px", border: 0, background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
              <span style={{ minWidth: 0, display: "grid", gridTemplateRows: "18px 16px", gap: 2 }}>
                <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6, color: "var(--text)", fontSize: 12.5, fontWeight: 650 }}>{isFolder && <FolderOutlinedIcon sx={{ flexShrink: 0, fontSize: 14, color: "var(--text-faint)" }} />}<span title={row.file_name || "(이름 없음)"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.file_name || "(이름 없음)"}</span>{row.in_use === "N" && <span style={{ flexShrink: 0, color: "var(--danger)", fontSize: 10.5, fontWeight: 650 }}>삭제됨</span>}</span>
                <span title={path} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 10.5, fontFamily: "var(--mono)" }}>{path}</span>
              </span>
              {sortValue && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: row[sortValue.column] ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums" }}>{sortValue.column === "file_size" ? fmtSize(row.file_size) : row[sortValue.column] || "시간 정보 없음"}</span>}
              <span title={tags.map((tag) => `${tag.kind} · ${tag.account || "미상"}`).join(", ") || "교차 참조 없음"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: tags.length ? "var(--accent)" : "var(--text-faint)", fontSize: 11 }}>{tags.length ? tags.map((tag) => `${tag.kind} · ${tag.account || "미상"}`).join(" / ") : "—"}</span>
            </button>
          </div>;
        })}</div>
      </div>
    </div>}
  </section>;
}
function TreeNode({
  row,
  depth,
  expanded,
  childrenCache,
  loadingEntry,
  failedEntries,
  loadMoreFailed,
  bmRowids,
  selectedRowid,
  onToggle,
  onSelect,
  onLoadMore,
  refs,
  accountFilter,
}: {
  row: Row;
  depth: number;
  expanded: Set<string>;
  childrenCache: Record<string, { rows: Row[]; total: number }>;
  loadingEntry: Set<string>;
  failedEntries: Set<string>;
  loadMoreFailed: Set<string>;
  bmRowids: Set<number>;
  selectedRowid: number | null;
  onToggle: (r: Row) => void;
  onSelect: (r: Row) => void;
  onLoadMore: (entry: string) => void;
  refs: RefMap;
  accountFilter: Set<string> | null;
}) {
  const dir = isDir(row);
  const open = expanded.has(row.entry);
  const kids = childrenCache[row.entry];
  const deleted = row.in_use === "N";
  const bm = bmRowids.has(Number(row.__rowid));
  const isSel = selectedRowid !== null && Number(row.__rowid) === selectedRowid;

  // A folder click updates the same shared MFT inspector and expands/collapses
  // the branch; a file click only updates the inspector.
  const handleRowClick = () => { onSelect(row); if (dir) onToggle(row); };

  // (account, kind) chips for other artifacts that reference this exact path,
  // de-duplicated (a path can appear many times in one JumpList).
  const rowTags = referenceTags(refs, row, accountFilter);
  const tagSummary = referenceTagSummary(rowTags);
  const childRegionId = `mft-children-${String(row.__rowid).replace(/[^a-zA-Z0-9_-]/g, "-")}`;

  return (
    <>
      <div
        className={bm ? `dfir-bookmarked-row${isSel ? " dfir-bookmarked-row--selected" : ""}` : undefined}
        style={{ minHeight: 32, padding: "2px 7px", paddingLeft: 7 + depth * 16, borderRadius: "var(--radius-sm)", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent", borderLeft: "2px solid transparent" }}
        onMouseEnter={(e) => { if (!isSel && !bm) e.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(e) => { if (!isSel && !bm) e.currentTarget.style.background = "transparent"; }}
      >
        <div style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 5 }}>
          {dir ? (
            <IconButton
              size="small"
              aria-label={open ? "폴더 접기" : "폴더 펼치기"}
              aria-expanded={open}
              aria-controls={childRegionId}
              onClick={() => onToggle(row)}
              sx={{ flexShrink: 0, width: 20, height: 20, p: 0, color: "var(--text-faint)", borderRadius: "var(--radius-sm)" }}
            >
              {open ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17 }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 17 }} />}
            </IconButton>
          ) : <span style={{ flex: "0 0 20px" }} />}
          <button
            type="button"
            onClick={handleRowClick}
            aria-expanded={dir ? open : undefined}
            aria-controls={dir ? childRegionId : undefined}
            title={dir ? "MFT 정보 보기 및 폴더 접기/펼치기" : "MFT 정보 보기"}
            style={{ display: "flex", alignItems: "center", gap: 5, flex: "1 1 0", minWidth: 0, minHeight: 24, padding: 0, border: 0, background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}
          >
            {dir
              ? (open ? <FolderOpenOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 17, color: "var(--accent)" }} /> : <FolderOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 17, color: "var(--text-faint)" }} />)
              : <InsertDriveFileOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 16, color: "var(--text-faint)" }} />}
            <span style={{ flex: "1 1 0", minInlineSize: "8ch", minWidth: 0, fontSize: 13, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.file_name || "(이름 없음)"}</span>
            {deleted && <span style={{ flexShrink: 0, fontSize: 10.5, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: "var(--radius-sm)", padding: "0 6px" }}>삭제됨</span>}
            {tagSummary && <span title={referenceTagTitle(rowTags)} style={{ flex: "0 1 176px", maxWidth: 176, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 10.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "1px 7px", textAlign: "center" }}>{tagSummary}</span>}
          </button>
        </div>
      </div>
      {dir && (
        <div id={childRegionId} hidden={!open}>
        {open && (loadingEntry.has(row.entry) && !kids ? (
          <div style={{ display: "flex", alignItems: "center", gap: 6, paddingLeft: 7 + (depth + 1) * 16 + 20, minHeight: 27, fontSize: 11.5, color: "var(--text-faint)" }}><CircularProgress size={13} thickness={4} /> 하위 항목을 불러오는 중</div>
        ) : failedEntries.has(row.entry) && !kids ? (
          <div style={{ paddingLeft: 7 + (depth + 1) * 16 + 20, minHeight: 27, fontSize: 11.5, lineHeight: "27px", color: "var(--danger)" }}>하위 항목을 읽지 못했습니다. 접었다가 다시 펼쳐 재시도할 수 있습니다.</div>
        ) : kids && kids.rows.length === 0 ? (
          <div style={{ paddingLeft: 7 + (depth + 1) * 16 + 20, minHeight: 27, fontSize: 11.5, lineHeight: "27px", color: "var(--text-faint)" }}>비어 있음</div>
        ) : (
          <>
            {(kids?.rows ?? []).map((c) => (
              <TreeNode
                key={c.entry + "-" + c.__rowid}
                row={c}
                depth={depth + 1}
                expanded={expanded}
                childrenCache={childrenCache}
                loadingEntry={loadingEntry}
                failedEntries={failedEntries}
                loadMoreFailed={loadMoreFailed}
                bmRowids={bmRowids}
                selectedRowid={selectedRowid}
                onToggle={onToggle}
                onSelect={onSelect}
                onLoadMore={onLoadMore}
                refs={refs}
                accountFilter={accountFilter}
              />
            ))}
            {kids && kids.rows.length < kids.total && (
              <button
                type="button"
                disabled={loadingEntry.has(row.entry)}
                onClick={() => onLoadMore(row.entry)}
                style={{ display: "block", marginLeft: 7 + (depth + 1) * 16 + 20, minHeight: 27, padding: "2px 10px", border: `1px solid ${loadMoreFailed.has(row.entry) ? "var(--danger)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", color: loadMoreFailed.has(row.entry) ? "var(--danger)" : "var(--accent)", cursor: "pointer", fontSize: 11.5 }}
              >
                {loadingEntry.has(row.entry)
                  ? "불러오는 중…"
                  : loadMoreFailed.has(row.entry)
                    ? `이어받기 실패 — 다시 시도 (${kids.rows.length.toLocaleString()}/${kids.total.toLocaleString()})`
                    : `더 불러오기 (${kids.rows.length.toLocaleString()}/${kids.total.toLocaleString()})`}
              </button>
            )}
          </>
        ))}
        </div>
      )}
    </>
  );
}

function SearchResults({ rows, searching, error, bmRowids, selectedRowid, onSelect, refs, accountFilter }: { rows: Row[]; searching: boolean; error: string | null; bmRowids: Set<number>; selectedRowid: number | null; onSelect: (r: Row) => void; refs: RefMap; accountFilter: Set<string> | null }) {
  if (searching && rows.length === 0) return <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "16px 8px", color: "var(--text-faint)", fontSize: 12.5 }}><CircularProgress size={15} thickness={4} /> 검색 중</div>;
  if (error) return <div style={{ padding: "16px 8px", color: "var(--danger)", fontSize: 12.5 }}>{error}</div>;
  if (rows.length === 0) return <div style={{ padding: "16px 8px", color: "var(--text-faint)", fontSize: 12.5 }}>일치하는 항목이 없습니다.</div>;
  return (
    <div style={{ paddingTop: 4 }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)", padding: "6px 7px" }}>검색 결과 {rows.length}건{rows.length >= 500 ? " (상위 500건)" : ""}</div>
      {rows.map((r) => {
        const deleted = r.in_use === "N";
        const isSel = selectedRowid !== null && Number(r.__rowid) === selectedRowid;
        const bookmarked = bmRowids.has(Number(r.__rowid));
        const rowTags = referenceTags(refs, r, accountFilter);
        const tagSummary = referenceTagSummary(rowTags);
        return (
          <div
            key={r.entry + "-" + r.__rowid}
            role="button"
            tabIndex={0}
            className={bookmarked ? `dfir-bookmarked-row${isSel ? " dfir-bookmarked-row--selected" : ""}` : undefined}
            onClick={() => onSelect(r)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(r); }
            }}
            onMouseEnter={(e) => { if (!isSel && !bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(e) => { if (!isSel && !bookmarked) e.currentTarget.style.background = "transparent"; }}
            style={{ minHeight: 34, padding: "3px 7px", borderRadius: "var(--radius-sm)", cursor: "pointer", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent", borderLeft: "2px solid transparent" }}
          >
            <div style={{ minWidth: 0 }}>
              <div style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}>
              {isDir(r) ? <FolderOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 16, color: "var(--text-faint)" }} /> : <InsertDriveFileOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 15, color: "var(--text-faint)" }} />}
              <span style={{ flex: "1 1 0", minInlineSize: "8ch", minWidth: 0, fontSize: 12.5, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.file_name || "(이름 없음)"}</span>
              {deleted && <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: "var(--radius-xs)", padding: "1px 5px", textAlign: "center" }}>삭제됨</span>}
              {tagSummary && <span title={referenceTagTitle(rowTags)} style={{ flex: "0 1 156px", maxWidth: 156, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 9.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "0 4px" }}>{tagSummary}</span>}
              </div>
              <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 1 }}>{r.path}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

