"use client";
import FilterListOutlinedIcon from "@mui/icons-material/FilterListOutlined";
import AccountFilterChips from "@/components/AccountFilterChips";
import { HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";
import MftListFilterModal from "@/components/MftListFilterModal";

import { useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FileReference, MftListOptions, MftRecordsPage, MftVolume } from "@/lib/types";
import { MFT_PATH_STATUS_LABELS } from "@/lib/artifactViews";
import { volumeLabels } from "@/lib/mftVolumeLabels";
import { DEFAULT_LIST_FILTERS, MFT_TIME_FIELDS, describeFilters, toListOptions, type ListFilters } from "@/lib/mftListFilters";
import { artifactChipTone } from "./MasterTimeline";
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
import { RecordScopeContext } from "@/lib/recordScope";

// 파일 시스템 정보는 화면용 파생 테이블(_OVERVIEW/FileSystemEntries)에서
// 읽는다. 수십만~백만 행 규모라 폴더는 지연 로딩하고, 검색·목록은 SQLite를
// 직접 조회한다. 플래그는 0/1이고 미확인은 NULL이다(Y/N 아님).

type Row = Record<string, string>;

// 폴더 펼치기 한 페이지의 자식 수 — 초과분은 "더 불러오기"로 이어 받는다.
const MFT_CHILDREN_PAGE = 100;

const ROOT_ENTRY = 5;
// 저장된 부모 연결이 확인되지 않은 레코드(순번 불일치·부모 미확인) 묶음의 내부 키.
const ORPHAN_KEY = "__unlinked__";
const LIST_FETCH_SIZE = 200; // lazy 로딩 배치 크기
// 스크롤 이어받기로 재귀 목록에 상주시킬 행 상한. 원본 테이블 경로의
// MAX_RESIDENT_RAW_ROWS(app/page.tsx)와 같은 값·같은 계약이다 — 수백만 행
// $MFT를 끝까지 스크롤해도 웹뷰 메모리가 무한히 커지지 않게 막고, 그
// 지점부터는 패턴·시간 필터로 좁혀 보게 한다(상한 도달은 화면에 표시한다).
const MAX_RESIDENT_LIST_ROWS = 100000;
const LIST_ROW_HEIGHT = 56;
// 시각 기준 정렬·기간 필터 키 → 라벨/컬럼(lib/mftListFilters). $FN 기준은
// timestomping 비교 수단이다(T7).
const MFT_TIME_SORTS = MFT_TIME_FIELDS;

interface Props {
  dbPath: string;
  /** docs-20: FileSystemEntries rows are bookmarked by their record_id. */
  isRowBookmarked: (row: Row, field?: string) => boolean;
  onToggleBookmark: (rowid: number, field: string) => void;
  /** Stored PathReferences row of a JumpList/Shellbag reference. */
  isReferenceBookmarked: (row: Row) => boolean;
  onToggleReferenceBookmark?: (row: Row) => void;
}


/** dbPath는 <hostDir>/_OVERVIEW/FileSystemEntries.sqlite — 뒤 두 조각을 떼면
 *  다른 아티팩트가 있는 호스트 폴더다. */
function hostDirOf(dbPath: string): string {
  const parts = dbPath.split(/[\\/]/);
  return parts.slice(0, Math.max(0, parts.length - 2)).join("/");
}

// Stored candidate references keyed by FileSystemEntries.record_id.
type RefMap = Map<string, FileReference[]>;

/// References for a row, limited to checked accounts. References without an
/// account are not an account choice (the chip list holds only known
/// accounts), so they stay visible (accountFilter null = no filtering).
function refsFor(refs: RefMap, row: Row, accountFilter: Set<string> | null): FileReference[] {
  const all = refs.get(row.record_id ?? "") ?? [];
  if (!accountFilter) return all;
  return all.filter((reference) => !reference.row.account || accountFilter.has(reference.row.account));
}

function referenceTags(refs: RefMap, row: Row, accountFilter: Set<string> | null): { account: string; kind: string }[] {
  const seen = new Set<string>();
  const tags: { account: string; kind: string }[] = [];
  for (const reference of refsFor(refs, row, accountFilter)) {
    const account = reference.row.account ?? "";
    const kind = reference.row.event_type ?? "";
    const key = `${account}|${kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    tags.push({ account, kind });
  }
  return tags;
}

// Reference kind → short code + artifact palette key (MasterTimeline chips).
const KIND_ORDER = ["Jumplist", "Shellbag", "ScheduledTasks", "ServiceHistory", "WerReports", "FirewallHistory"];
const REFERENCE_KIND: Record<string, { code: string; tone: string }> = {
  Jumplist: { code: "JL", tone: "JUMPLIST" },
  Shellbag: { code: "SB", tone: "REGISTRY" },
  WerReports: { code: "WER", tone: "WER" },
  ScheduledTasks: { code: "TASK", tone: "TASKSCHEDULER" },
  FirewallHistory: { code: "FW", tone: "FIREWALL" },
  ServiceHistory: { code: "SVC", tone: "SERVICE" },
};

/** One compact chip per reference kind; kind, count and accounts in the tooltip. */
function ReferenceChips({ refs, row, accountFilter }: { refs: RefMap; row: Row; accountFilter: Set<string> | null }) {
  const kinds = new Map<string, { count: number; accounts: Set<string> }>();
  for (const reference of refsFor(refs, row, accountFilter)) {
    const kind = reference.row.event_type || "경로 참조";
    const entry = kinds.get(kind) ?? { count: 0, accounts: new Set<string>() };
    entry.count += 1;
    entry.accounts.add(reference.row.account || "미상");
    kinds.set(kind, entry);
  }
  if (!kinds.size) return null;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 3, flexShrink: 0 }}>
      {/* Fixed kind order so the same chips line up across rows. */}
      {[...kinds.entries()].sort(([a], [b]) => (KIND_ORDER.indexOf(a) + 1 || 99) - (KIND_ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b)).map(([kind, { count, accounts }]) => {
        const spec = REFERENCE_KIND[kind];
        const tone = artifactChipTone("", spec?.tone ?? kind);
        return (
          <span key={kind} title={`${kind} 경로 후보 ${count}건 · ${[...accounts].join(", ")}`} style={{ display: "inline-flex", alignItems: "center", gap: 2, height: 17, padding: "0 5px", fontSize: 9.5, fontWeight: 750, letterSpacing: 0.3, lineHeight: 1, color: tone.color, background: tone.background, border: `1px solid ${tone.border}`, borderRadius: 4, whiteSpace: "nowrap" }}>
            {spec?.code ?? kind.slice(0, 3).toUpperCase()}
            {count > 1 && <span style={{ opacity: 0.75, fontWeight: 650 }}>{count}</span>}
          </span>
        );
      })}
    </span>
  );
}

/** 0/1/NULL — 미확인(null)을 파일로 단정하지 않는다. */
function dirFlag(r: Row): boolean | null {
  if (r.is_directory === "1") return true;
  if (r.is_directory === "0") return false;
  return null;
}
function isDir(r: Row): boolean {
  return dirFlag(r) === true;
}
/** Released record (in_use=0) — not a deletion time or recoverability claim. */
function isUnused(r: Row): boolean {
  return r.in_use === "0";
}
/** Stored path_status other than complete: the shown path is partial. */
function pathIssue(r: Row): string {
  return r.path_status && r.path_status !== "complete" ? MFT_PATH_STATUS_LABELS[r.path_status] ?? r.path_status : "";
}

function RowBadges({ row, size = 10.5 }: { row: Row; size?: number }) {
  const issue = pathIssue(row);
  const badge = (text: string, color: string, title: string) => <span title={title} style={{ flexShrink: 0, fontSize: size, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius)", padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>;
  return <>
    {isUnused(row) && badge("비사용", "var(--warning)", "MFT 레코드 할당 해제 — 삭제 시각·복구 가능성의 증거가 아닙니다")}
    {issue && badge("경로 불완전", "var(--text-dim)", issue)}
  </>;
}

/** NULL/absent size is unknown ("—"), never "0 B". */
function fmtSize(v: string | null | undefined): string {
  if (v === null || v === undefined || v === "") return "—";
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default function MftView({ dbPath, isRowBookmarked, onToggleBookmark, isReferenceBookmarked, onToggleReferenceBookmark }: Props) {
  // Coordinates of what this screen shows; the detail panel reads
  // source_records with them. The outer "open source record" action is kept.
  const outerScope = useContext(RecordScopeContext);
  const recordScope = useMemo(
    () => ({ ...outerScope, fullPath: dbPath, tableName: "FileSystemEntries" }),
    [dbPath, outerScope],
  );
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
  const selectedRowid = selected ? Number(selected.__rowid) : null;
  const [referenceDetail, setReferenceDetail] = useState<FileReference | null>(null);
  // Stored candidate references (PathReferenceCandidates) keyed by the file
  // record_id, fetched for the rows on screen in batches.
  // Map은 in-place로 병합하고 래퍼 객체만 새로 만들어 리렌더한다 — 배치마다
  // new Map(prev)로 전량 복사하면 목록 이어받기가 O(N²)가 된다.
  const [pathRefs, setPathRefs] = useState<{ map: RefMap }>({ map: new Map() });
  const [pathRefsError, setPathRefsError] = useState<string | null>(null);
  // Accounts seen across all references, and which are currently shown. An
  // investigator can uncheck accounts unrelated to the attack so their
  // JumpList/Shellbag tags stop cluttering the tree.
  const [refAccounts, setRefAccounts] = useState<string[]>([]);
  const [selAccounts, setSelAccounts] = useState<Set<string>>(new Set());
  // 결과가 담은 입력(볼륨) 문맥. entry·parent_entry는 입력 안에서만 의미가
  // 있으므로(docs-01) 항상 하나를 골라 그 안에서만 조회한다.
  const [volumes, setVolumes] = useState<MftVolume[]>([]);
  const [volumeId, setVolumeId] = useState<string>("");
  const [volumesError, setVolumesError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    setVolumes([]);
    setVolumeId("");
    setVolumesError(null);
    window.api.mftVolumes(dbPath).then((list) => {
      if (!alive) return;
      setVolumes(list);
      setVolumeId(list[0]?.volume_id ?? "");
    }).catch(() => {
      if (!alive) return;
      setVolumesError("볼륨 목록을 불러오지 못했습니다.");
    });
    return () => { alive = false; };
  }, [dbPath]);
  const volumeArg = volumeId || undefined;

  // 교차 참조: 파서가 저장한 후보(PathReferenceCandidates)를 지금 화면에 올라온
  // 레코드 ID 배치로만 조회한다. 입력·결과 세대가 바뀌면 이전 응답을 버린다.
  const requestedRefIds = useRef<Set<string>>(new Set());
  const refGeneration = useRef(0);
  // 재귀 목록에서 교차참조 요청을 이미 검사한 지점 — 목록은 뒤로만 append
  // 되므로 이 커서 이후만 훑으면 된다.
  const listRefCursor = useRef(0);
  useEffect(() => {
    refGeneration.current += 1;
    setLoadingEntry(new Set());
    requestedRefIds.current = new Set();
    listRefCursor.current = 0;
    setPathRefs({ map: new Map() });
    setPathRefsError(null);
    setReferenceDetail(null);
  }, [dbPath, volumeArg]);
  useEffect(() => {
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
    if (!volumeArg) return;
    const pending: string[] = [];
    let datasetId = "";
    const collect = (row: Row | undefined) => {
      const id = row?.record_id ?? "";
      if (!id || requestedRefIds.current.has(id)) return;
      requestedRefIds.current.add(id);
      pending.push(id);
      datasetId ||= row?.dataset_id ?? "";
    };
    root?.rows.forEach(collect);
    Object.values(childrenCache).forEach((page) => page.rows.forEach(collect));
    // 목록은 커서 이후 구간만 — 필터 변경으로 목록이 다시 차면 커서를 되돌린다.
    const listCursorBefore = Math.min(listRefCursor.current, listRows.length);
    for (let i = listCursorBefore; i < listRows.length; i += 1) collect(listRows[i]);
    listRefCursor.current = listRows.length;
    (results ?? []).forEach(collect);
    if (pending.length === 0 || !datasetId) return;
    const generation = refGeneration.current;
    window.api.fileReferences(hostDirOf(dbPath), datasetId, volumeArg, pending).then((list) => {
      if (generation !== refGeneration.current) return;
      setPathRefsError(null);
      if (list.length === 0) return;
      setPathRefs((prev) => {
        for (const reference of list) {
          const arr = prev.map.get(reference.fileRecordId);
          if (arr) arr.push(reference); else prev.map.set(reference.fileRecordId, [reference]);
        }
        return { map: prev.map };
      });
    }).catch((error) => {
      if (generation !== refGeneration.current) return;
      // File evidence stays usable; the failed ids are retried on the next batch.
      for (const id of pending) requestedRefIds.current.delete(id);
      listRefCursor.current = Math.min(listRefCursor.current, listCursorBefore);
      setPathRefsError(typeof error === "string" ? error : "교차 참조 정보를 불러오지 못했습니다.");
    });
  }, [dbPath, volumeArg, root, childrenCache, listRows, results]);
  const [listTotal, setListTotal] = useState<number | null>(null);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  // 재귀 목록 필터 — 한 상태로 관리(lib/mftListFilters), 모달 「적용」 시 반영.
  const [listFilters, setListFilters] = useState<ListFilters>(DEFAULT_LIST_FILTERS);
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
    if (!volumeArg) return;
    // Root folder: the server reads the root seq from the stored root record.
    window.api.mftChildren(dbPath, ROOT_ENTRY, null, 0, MFT_CHILDREN_PAGE, volumeArg).then((page) => {
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
  }, [dbPath, volumeArg]);

  // Folder seq per expanded entry — children link only to (entry, seq).
  const folderSeq = useRef<Map<string, number>>(new Map());
  const fetchChildren = useCallback(
    (entry: string, offset: number) => window.api.mftChildren(
      dbPath,
      entry === ORPHAN_KEY ? null : Number(entry),
      entry === ORPHAN_KEY || entry === String(ROOT_ENTRY) ? null : folderSeq.current.get(entry) ?? null,
      offset,
      MFT_CHILDREN_PAGE,
      volumeArg,
    ),
    [dbPath, volumeArg],
  );

  const loadChildren = useCallback(
    async (entry: string) => {
      if (childrenCache[entry]) return;
      setLoadingEntry((s) => new Set(s).add(entry));
      setFailedEntries((s) => { const next = new Set(s); next.delete(entry); return next; });
      // Responses from a previous input/result generation are discarded.
      const generation = refGeneration.current;
      try {
        // ORPHAN_KEY lists records whose stored parent link is not verified,
        // so they never vanish from the tree.
        const page = await fetchChildren(entry, 0);
        if (generation === refGeneration.current) setChildrenCache((c) => ({ ...c, [entry]: page }));
      } catch {
        if (generation === refGeneration.current) setFailedEntries((s) => new Set(s).add(entry));
      } finally {
        if (generation === refGeneration.current) setLoadingEntry((s) => {
          const n = new Set(s);
          n.delete(entry);
          return n;
        });
      }
    },
    [childrenCache, fetchChildren],
  );

  // 대형 폴더(수만 자식)에서 전체를 한 번에 IPC로 받지 않도록 페이지로 이어
  // 받는다 — "더 불러오기" 버튼이 다음 페이지를 기존 목록 뒤에 붙인다.
  const loadMoreChildren = useCallback(
    async (entry: string) => {
      const cached = entry === String(ROOT_ENTRY) ? root : childrenCache[entry];
      if (!cached || cached.rows.length >= cached.total || loadingEntry.has(entry)) return;
      setLoadingEntry((s) => new Set(s).add(entry));
      const generation = refGeneration.current;
      try {
        const page = await fetchChildren(entry, cached.rows.length);
        if (generation !== refGeneration.current) return;
        // 후속 페이지는 서버가 COUNT를 생략하고 total=-1을 준다 — 첫 페이지의
        // 값을 유지한다.
        const merged = { rows: [...cached.rows, ...page.rows], total: page.total >= 0 ? page.total : cached.total };
        if (entry === String(ROOT_ENTRY)) setRoot(merged);
        else setChildrenCache((c) => ({ ...c, [entry]: merged }));
        setLoadMoreFailed((s) => { const n = new Set(s); n.delete(entry); return n; });
      } catch {
        if (generation === refGeneration.current) setLoadMoreFailed((s) => new Set(s).add(entry));
      } finally {
        if (generation === refGeneration.current) setLoadingEntry((s) => {
          const n = new Set(s);
          n.delete(entry);
          return n;
        });
      }
    },
    [childrenCache, root, loadingEntry, fetchChildren],
  );


  const toggle = useCallback(
    (r: Row) => {
      const entry = r.entry;
      if (r.seq) folderSeq.current.set(entry, Number(r.seq));
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
    if (viewMode !== "tree" || !volumeArg) return;
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
      window.api.mftSearch(dbPath, q, 500, volumeArg).then((rows) => {
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
  }, [search, dbPath, viewMode, volumeArg]);

  // The recursive list owns its own bounded SQLite page. It intentionally
  // does not reuse tree search results, which are capped and may omit paths.
  const listQuery = search.trim().length >= 2 ? search.trim() : "";
  const listOptions = useMemo<MftListOptions>(() => toListOptions(listFilters, volumeArg), [listFilters, volumeArg]);
  // Filter dialog preview: same query as the list, one row, total only.
  const countListFor = useCallback(
    (options: MftListOptions) => window.api.mftRecordsPage(dbPath, listQuery, 0, 1, { ...options, volumeId: volumeArg }).then((page) => page.total),
    [dbPath, listQuery, volumeArg],
  );
  // 필터·정렬·검색이 바뀌면 처음부터 다시, 스크롤이 끝에 닿으면 이어서 불러온다.
  useEffect(() => {
    if (viewMode !== "list" || !volumeArg) return;
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
    // 상주 상한 도달 — 더 싣지 않는다. 화면에는 상한 안내를 띄운다.
    if (listRows.length >= MAX_RESIDENT_LIST_ROWS) return;
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

  const stackedInspector = useMediaQuery("(max-width: 960px)");
  const detailPanel = selected ? (
    <RowDetailPanel
      row={selected}
      columns={Object.keys(selected).filter((key) => key !== "__rowid")}
      focusedColumn={null}
      fileBaseName="FileSystemEntries"
      variant="docked"
      onClose={() => setSelected(null)}
      onNavigate={() => {}}
      isBookmarked={isRowBookmarked(selected)}
      onToggleBookmark={() => onToggleBookmark(Number(selected.__rowid), "")}
      onToggleFieldBookmark={(field) => onToggleBookmark(Number(selected.__rowid), field)}
      isFieldBookmarked={(field) => isRowBookmarked(selected, field)}
      relatedEvidence={refsFor(pathRefs.map, selected, selAccounts).map((reference) => ({
        id: `${reference.row.record_id}:${reference.fileRecordId}`,
        label: `${reference.row.event_type || "경로 참조"} · ${reference.row.account || "미상"}`,
        subtitle: reference.row.label || reference.row.target_path || reference.row.path,
        onOpen: () => setReferenceDetail(reference),
      }))}
    />
  ) : (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 9, minHeight: "100%", padding: 24, color: "var(--text-faint)", fontSize: 13 }}>
      <InsertDriveFileOutlinedIcon sx={{ fontSize: 30, color: "var(--text-faint)" }} />
      파일을 선택하면 파일 시스템 레코드 정보를 표시합니다.
    </div>
  );

  return (
    <RecordScopeContext.Provider value={recordScope}>
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <ViewHeader icon={FolderOpenOutlinedIcon} title="파일 시스템 정보" meta="$MFT" right={<div role="group" aria-label="MFT 보기 방식" style={{ display: "flex", gap: 4 }}>
            <button type="button" aria-pressed={viewMode === "tree"} className={viewMode === "tree" ? "nm-btn" : undefined} onClick={() => setViewMode("tree")} style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "3px 11px", border: `1px solid ${viewMode === "tree" ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius)", background: viewMode === "tree" ? "var(--accent-subtle)" : "transparent", color: viewMode === "tree" ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}><AccountTreeOutlinedIcon sx={{ fontSize: 15 }} />탐색기</button>
            <button type="button" aria-pressed={viewMode === "list"} className={viewMode === "list" ? "nm-btn" : undefined} onClick={() => setViewMode("list")} style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 30, padding: "3px 11px", border: `1px solid ${viewMode === "list" ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius)", background: viewMode === "list" ? "var(--accent-subtle)" : "transparent", color: viewMode === "list" ? "var(--accent)" : "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}><ViewListOutlinedIcon sx={{ fontSize: 15 }} />전체 목록</button>
          </div>}>
          <HeaderSearchInput value={search} onChange={setSearch} placeholder="파일명 · 경로 · 확장자 · 계정 검색 (2자 이상)" ariaLabel="파일명, 경로, 확장자 또는 계정 검색" width={300} />
          {volumes.length > 0 && (
            <SelectDropdown
              label="입력"
              options={volumes.map((volume) => ({ value: volume.volume_id, label: volumeLabels(volumes)[volume.volume_id] }))}
              value={volumeId}
              defaultValue={volumes[0]?.volume_id ?? ""}
              onChange={setVolumeId}
            />
          )}
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
        {volumesError && <div role="status" style={{ marginTop: 8, color: "var(--warning)", fontSize: 11.5 }}>{volumesError}</div>}
        {pathRefsError && <div role="status" style={{ marginTop: 8, color: "var(--warning)", fontSize: 11.5 }}>{pathRefsError}</div>}
      
      </ViewHeader>

      <div className={`mft-content mft-content--${viewMode}`} style={{ flex: 1, minHeight: 0, display: "grid", gap: 10, padding: 14, background: "var(--bg)", gridTemplateColumns: stackedInspector ? "minmax(0, 1fr)" : "minmax(0, 7fr) minmax(300px, 3fr)", gridTemplateRows: stackedInspector ? "minmax(300px, 1fr) minmax(260px, .75fr)" : undefined }}>
        <aside aria-label={viewMode === "tree" ? "파일 탐색기" : "재귀 파일 시스템 목록"} style={{ minWidth: 0, minHeight: 0, overflow: "hidden", padding: viewMode === "tree" ? "8px 10px 14px" : "0", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", display: "flex", flexDirection: "column" }}>
          {viewMode === "list" ? (
            <MftRecordList rows={listRows} total={listTotal} loading={listLoading} error={listError} query={listQuery} isBookmarked={isRowBookmarked} selectedRowid={selectedRowid} selectedRow={selected} refs={pathRefs.map} accountFilter={selAccounts} onSelect={setSelected} onLoadMore={loadMoreList} filters={listFilters} onFilters={setListFilters} countFor={countListFor} />
          ) : <>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
              {results !== null ? (
                <SearchResults rows={results} searching={searching} error={searchError} isBookmarked={isRowBookmarked} selectedRowid={selectedRowid} onSelect={setSelected} refs={pathRefs.map} accountFilter={selAccounts} />
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
                      isBookmarked={isRowBookmarked}
                      selectedRowid={selectedRowid}
                      onToggle={toggle}
                      onSelect={setSelected}
                      onLoadMore={loadMoreChildren}
                      refs={pathRefs.map}
                      accountFilter={selAccounts}
                    />
                  ))}
                  {root.rows.length < root.total && (
                    <button
                      type="button"
                      disabled={loadingEntry.has(String(ROOT_ENTRY))}
                      onClick={() => loadMoreChildren(String(ROOT_ENTRY))}
                      style={{ display: "block", marginLeft: 27, minHeight: 27, padding: "2px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: "var(--accent)", cursor: "pointer", fontSize: 11.5 }}
                    >
                      {loadingEntry.has(String(ROOT_ENTRY))
                        ? "불러오는 중…"
                        : loadMoreFailed.has(String(ROOT_ENTRY))
                          ? `이어받기 실패 — 다시 시도 (${root.rows.length.toLocaleString()}/${root.total.toLocaleString()})`
                          : `더 불러오기 (${root.rows.length.toLocaleString()}/${root.total.toLocaleString()})`}
                    </button>
                  )}
                  {/* 부모를 확인하지 못한 레코드는 트리 어디에도 붙지 않는다 —
                      묶음으로 따로 보여 주지 않으면 조용히 사라진다. */}
                  <OrphanBucket
                    open={expanded.has(ORPHAN_KEY)}
                    page={childrenCache[ORPHAN_KEY]}
                    loading={loadingEntry.has(ORPHAN_KEY)}
                    failed={failedEntries.has(ORPHAN_KEY)}
                    loadMoreFailed={loadMoreFailed.has(ORPHAN_KEY)}
                    onToggle={() => setExpanded((previous) => {
                      const next = new Set(previous);
                      if (next.has(ORPHAN_KEY)) next.delete(ORPHAN_KEY);
                      else { next.add(ORPHAN_KEY); void loadChildren(ORPHAN_KEY); }
                      return next;
                    })}
                    onLoadMore={() => loadMoreChildren(ORPHAN_KEY)}
                    isBookmarked={isRowBookmarked}
                    selectedRowid={selectedRowid}
                    onSelect={setSelected}
                    refs={pathRefs.map}
                    accountFilter={selAccounts}
                  />
                </>
              )}
            </div>
          </>}
        </aside>
        <section aria-label="선택 항목 파일 시스템 정보" style={{ minWidth: 0, minHeight: 0, overflow: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)" }}>
          {detailPanel}
        </section>
      </div>
      {referenceDetail && (
        // Stored PathReferences row; evidence/origins read from its own DB.
        <RecordScopeContext.Provider value={{ ...outerScope, fullPath: `${hostDirOf(dbPath)}/_OVERVIEW/PathReferences.sqlite`, tableName: "PathReferences" }}>
          <RowDetailPanel
            row={{ ...referenceDetail.row, __match_basis: referenceDetail.matchBasis }}
            columns={Object.keys(referenceDetail.row).filter((key) => key !== "__rowid")}
            focusedColumn={null}
            fileBaseName="PathReferences"
            onClose={() => setReferenceDetail(null)}
            onNavigate={() => {}}
            isBookmarked={isReferenceBookmarked(referenceDetail.row)}
            onToggleBookmark={onToggleReferenceBookmark ? () => onToggleReferenceBookmark(referenceDetail.row) : undefined}
          />
        </RecordScopeContext.Provider>
      )}
    </div>
    </RecordScopeContext.Provider>
  );
}

function MftRecordList({ rows, total, loading, error, query, isBookmarked, selectedRowid, selectedRow, refs, accountFilter, onSelect, onLoadMore, filters, onFilters, countFor }: {
  rows: Row[];
  total: number | null;
  loading: boolean;
  error: string | null;
  query: string;
  isBookmarked: (row: Row) => boolean;
  selectedRowid: number | null;
  selectedRow: Row | null;
  refs: RefMap;
  accountFilter: Set<string> | null;
  onSelect: (row: Row) => void;
  onLoadMore: () => void;
  filters: ListFilters;
  onFilters: (next: ListFilters) => void;
  countFor: (options: MftListOptions) => Promise<number>;
}) {
  const [filterOpen, setFilterOpen] = useState(false);
  const { sortKey, sortDesc } = filters;
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => LIST_ROW_HEIGHT, overscan: 12 });
  // Time column: the sorted time when sorting by one, else SI modified (docs-04 §2 list column).
  const timeColumn = MFT_TIME_SORTS[sortKey] ?? MFT_TIME_SORTS.modified;
  const grid = "minmax(0, 3fr) 176px 92px minmax(108px, 1fr)";
  const virtualItems = virtualizer.getVirtualItems();
  const lastVisibleIndex = virtualItems.length ? virtualItems[virtualItems.length - 1].index : 0;
  // 목록 상한에 도달했는지 — 도달하면 이어받기를 멈추고 헤더에 안내를 띄운다.
  // 조용히 멈추면 분석가가 "레코드가 여기까지"로 오판한다.
  const capped = rows.length >= MAX_RESIDENT_LIST_ROWS;
  // lazy 로딩: 스크롤이 끝 30행 안쪽에 닿으면 다음 배치를 이어서 불러온다.
  useEffect(() => {
    if (loading || total === null || rows.length >= total || capped) return;
    if (lastVisibleIndex >= rows.length - 30) onLoadMore();
  }, [lastVisibleIndex, loading, rows.length, total, capped, onLoadMore]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: 0 }); }, [query, filters]);
  const summary = describeFilters(filters);
  const sortLabel = sortKey === "path" ? "경로" : sortKey === "name" ? "파일 이름" : sortKey === "size" ? "크기" : MFT_TIME_SORTS[sortKey]?.short ?? sortKey;
  const chip: React.CSSProperties = { display: "inline-flex", alignItems: "center", minHeight: 24, padding: "0 9px", fontSize: 11.5, borderRadius: 999, border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", whiteSpace: "nowrap", maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis" };

  return <section aria-label="MFT 재귀 목록" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
    <header style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", flexShrink: 0, padding: "8px 12px", borderBottom: "1px solid var(--border)" }}>
      <button type="button" onClick={() => setFilterOpen(true)} aria-haspopup="dialog" style={{ display: "inline-flex", alignItems: "center", gap: 6, minHeight: 30, padding: "0 12px", fontSize: 12, fontWeight: 650, border: `1px solid ${summary.length ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius)", background: summary.length ? "var(--accent-subtle)" : "var(--bg-elevated)", color: summary.length ? "var(--accent)" : "var(--text)", cursor: "pointer" }}>
        <FilterListOutlinedIcon sx={{ fontSize: 16 }} />필터{summary.length ? ` (${summary.length})` : ""}
      </button>
      {/* Active conditions; a click reopens the dialog. */}
      {summary.map((text) => <button key={text} type="button" onClick={() => setFilterOpen(true)} title={text} style={chip}>{text}</button>)}
      <span style={{ ...chip, cursor: "default", background: "transparent", borderColor: "var(--border-subtle)", color: "var(--text-faint)" }}>정렬 {sortLabel} {sortDesc ? "↓" : "↑"}</span>
      {summary.length > 0 && <button type="button" onClick={() => onFilters({ ...DEFAULT_LIST_FILTERS, sortKey: filters.sortKey, sortDesc: filters.sortDesc, timeKeys: filters.timeKeys })} style={{ minHeight: 24, padding: "0 9px", fontSize: 11.5, border: "none", background: "transparent", color: "var(--text-dim)", cursor: "pointer", textDecoration: "underline" }}>초기화</button>}
      <span style={{ display: "inline-flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
        {capped && <span role="status" style={{ color: "var(--warning)", fontSize: 11.5, fontWeight: 650, whiteSpace: "nowrap" }}>목록 상한 {MAX_RESIDENT_LIST_ROWS.toLocaleString()}건 · 필터로 좁혀 보세요</span>}
        <span style={{ color: "var(--text-faint)", fontSize: 11.5, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
          {total !== null ? `${rows.length.toLocaleString()} / ${total.toLocaleString()}건` : "\u00a0"}
          {loading && rows.length > 0 && " · 불러오는 중…"}
        </span>
      </span>
    </header>
    {filterOpen && <MftListFilterModal filters={filters} anchorRow={selectedRow} countFor={countFor} onApply={onFilters} onClose={() => setFilterOpen(false)} />}
    {loading && rows.length === 0 ? <div role="status" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, flex: 1, color: "var(--text-dim)", fontSize: 12.5 }}><CircularProgress size={17} thickness={4} />MFT 레코드를 불러오는 중</div> : error ? <div role="alert" style={{ padding: 16, color: "var(--danger)", fontSize: 12.5 }}>{error}</div> : !rows.length ? <div role="status" style={{ display: "grid", placeItems: "center", flex: 1, color: "var(--text-faint)", fontSize: 12.5 }}>{query || summary.length ? "조건에 맞는 MFT 레코드가 없습니다." : "표시할 MFT 레코드가 없습니다."}</div> : <div ref={scrollRef} style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
      <div style={{ minWidth: 0 }}>
        <div aria-hidden="true" style={{ display: "grid", gridTemplateColumns: grid, gap: 10, alignItems: "center", minHeight: 32, padding: "0 12px", borderBottom: "1px solid var(--border)", color: "var(--text-faint)", fontSize: 10.5, fontWeight: 700 }}><span>파일 이름 / 경로</span><span>{timeColumn.label}</span><span style={{ textAlign: "right" }}>크기</span><span>경로 참조 흔적</span></div>
        <div style={{ position: "relative", height: virtualizer.getTotalSize() }}>{virtualItems.map((virtualRow) => {
          const row = rows[virtualRow.index];
          const bookmarked = isBookmarked(row);
          const selected = selectedRowid !== null && Number(row.__rowid) === selectedRowid;
          const tags = referenceTags(refs, row, accountFilter).slice(0, 2);
          const path = row.path || row.file_name || "경로 정보 없음";
          const isFolder = isDir(row);
          return <div key={virtualRow.key} className={bookmarked ? `dfir-bookmarked-row${selected ? " dfir-bookmarked-row--selected" : ""}` : undefined} style={{ position: "absolute", top: 0, left: 0, width: "100%", height: LIST_ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)`, borderBottom: "1px solid var(--border-subtle)", background: selected ? "var(--bg-selected)" : "transparent" }}>
            <button type="button" onClick={() => onSelect(row)} title={path} aria-label={`${row.file_name || path} MFT 정보 보기`} style={{ display: "grid", gridTemplateColumns: grid, gap: 10, alignItems: "center", width: "100%", height: "100%", padding: "0 12px", border: 0, background: "transparent", color: "inherit", cursor: "pointer", textAlign: "left" }}>
              <span style={{ minWidth: 0, display: "grid", gridTemplateRows: "18px 16px", gap: 2 }}>
                <span style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6, color: "var(--text)", fontSize: 12.5, fontWeight: 650 }}>{isFolder && <FolderOutlinedIcon sx={{ flexShrink: 0, fontSize: 14, color: "var(--text-faint)" }} />}<span title={row.file_name || "(이름 없음)"} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.file_name || "(이름 없음)"}</span><RowBadges row={row} /></span>
                <span title={path} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-faint)", fontSize: 10.5, fontFamily: "var(--mono)" }}>{path}</span>
              </span>
              <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: row[timeColumn.column] ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums" }}>{row[timeColumn.column] || "시간 정보 없음"}</span>
              <span style={{ textAlign: "right", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)", fontVariantNumeric: "tabular-nums" }}>{isFolder ? "" : fmtSize(row.file_size)}</span>
              <span style={{ minWidth: 0, overflow: "hidden", display: "flex", alignItems: "center", color: "var(--text-faint)", fontSize: 11 }}>{tags.length ? <ReferenceChips refs={refs} row={row} accountFilter={accountFilter} /> : "—"}</span>
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
  isBookmarked,
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
  isBookmarked: (row: Row) => boolean;
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
  const deleted = isUnused(row);
  const bm = isBookmarked(row);
  const isSel = selectedRowid !== null && Number(row.__rowid) === selectedRowid;

  // A folder click updates the same shared MFT inspector and expands/collapses
  // the branch; a file click only updates the inspector.
  const handleRowClick = () => { onSelect(row); if (dir) onToggle(row); };

  const childRegionId = `mft-children-${String(row.__rowid).replace(/[^a-zA-Z0-9_-]/g, "-")}`;

  return (
    <>
      <div
        className={bm ? `dfir-bookmarked-row${isSel ? " dfir-bookmarked-row--selected" : ""}` : undefined}
        style={{ minHeight: 32, padding: "2px 7px", paddingLeft: 7 + depth * 16, borderRadius: "var(--radius)", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent", borderLeft: "2px solid transparent" }}
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
              sx={{ flexShrink: 0, width: 20, height: 20, p: 0, color: "var(--text-faint)", borderRadius: "var(--radius)" }}
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
            <RowBadges row={row} />
            <ReferenceChips refs={refs} row={row} accountFilter={accountFilter} />
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
                isBookmarked={isBookmarked}
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
                style={{ display: "block", marginLeft: 7 + (depth + 1) * 16 + 20, minHeight: 27, padding: "2px 10px", border: `1px solid ${loadMoreFailed.has(row.entry) ? "var(--danger)" : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: loadMoreFailed.has(row.entry) ? "var(--danger)" : "var(--accent)", cursor: "pointer", fontSize: 11.5 }}
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

function SearchResults({ rows, searching, error, isBookmarked, selectedRowid, onSelect, refs, accountFilter, caption = true }: { rows: Row[]; searching: boolean; error: string | null; isBookmarked: (row: Row) => boolean; selectedRowid: number | null; onSelect: (r: Row) => void; refs: RefMap; accountFilter: Set<string> | null; caption?: boolean }) {
  if (searching && rows.length === 0) return <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "16px 8px", color: "var(--text-faint)", fontSize: 12.5 }}><CircularProgress size={15} thickness={4} /> 검색 중</div>;
  if (error) return <div style={{ padding: "16px 8px", color: "var(--danger)", fontSize: 12.5 }}>{error}</div>;
  if (rows.length === 0) return <div style={{ padding: "16px 8px", color: "var(--text-faint)", fontSize: 12.5 }}>일치하는 항목이 없습니다.</div>;
  return (
    <div style={{ paddingTop: 4 }}>
      {caption && <div style={{ fontSize: 11, color: "var(--text-faint)", padding: "6px 7px" }}>검색 결과 {rows.length}건{rows.length >= 500 ? " (상위 500건)" : ""}</div>}
      {rows.map((r) => {
        const deleted = isUnused(r);
        const isSel = selectedRowid !== null && Number(r.__rowid) === selectedRowid;
        const bookmarked = isBookmarked(r);
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
            style={{ minHeight: 34, padding: "3px 7px", borderRadius: "var(--radius)", cursor: "pointer", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent", borderLeft: "2px solid transparent" }}
          >
            <div style={{ minWidth: 0 }}>
              <div style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 6 }}>
              {isDir(r) ? <FolderOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 16, color: "var(--text-faint)" }} /> : <InsertDriveFileOutlinedIcon aria-hidden="true" sx={{ flexShrink: 0, fontSize: 15, color: "var(--text-faint)" }} />}
              <span style={{ flex: "1 1 0", minInlineSize: "8ch", minWidth: 0, fontSize: 12.5, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.file_name || "(이름 없음)"}</span>
              <RowBadges row={r} size={9.5} />
              <ReferenceChips refs={refs} row={r} accountFilter={accountFilter} />
              </div>
              <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginTop: 1 }}>{r.path}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * 부모를 확인하지 못한 레코드(parent_entry IS NULL) 묶음. 트리의 어느 폴더에도
 * 붙지 않으므로 별도 묶음으로 열어 본다 — 미확인을 0(루트)으로 단정하지
 * 않는다(docs-01).
 */
function OrphanBucket({ open, page, loading, failed, loadMoreFailed, onToggle, onLoadMore, isBookmarked, selectedRowid, onSelect, refs, accountFilter }: {
  open: boolean;
  page?: { rows: Row[]; total: number };
  loading: boolean;
  failed: boolean;
  loadMoreFailed: boolean;
  onToggle: () => void;
  onLoadMore: () => void;
  isBookmarked: (row: Row) => boolean;
  selectedRowid: number | null;
  onSelect: (row: Row) => void;
  refs: RefMap;
  accountFilter: Set<string> | null;
}) {
  const regionId = "mft-orphan-records";
  return (
    <div style={{ marginTop: 6, borderTop: "1px solid var(--border-subtle)", paddingTop: 6 }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={regionId}
        style={{ display: "flex", alignItems: "center", gap: 6, width: "100%", minHeight: 30, padding: "2px 7px", border: 0, background: "transparent", color: "var(--text-dim)", cursor: "pointer", fontSize: 12.5, fontWeight: 650, textAlign: "left" }}
      >
        {open ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} />}
        <span title="저장된 부모 연결이 확인되지 않은 레코드 — 부모 순번 불일치(재사용된 부모 번호) 또는 부모 미확인">Path Unknown{page ? ` (${page.total.toLocaleString()})` : ""}</span>
      </button>
      <div id={regionId} hidden={!open}>
        {open && (loading && !page ? (
          <div style={{ display: "flex", alignItems: "center", gap: 6, paddingLeft: 27, minHeight: 27, fontSize: 11.5, color: "var(--text-faint)" }}><CircularProgress size={13} thickness={4} /> 불러오는 중</div>
        ) : failed && !page ? (
          <div style={{ paddingLeft: 27, minHeight: 27, lineHeight: "27px", fontSize: 11.5, color: "var(--danger)" }}>Path Unknown 레코드를 읽지 못했습니다. 접었다가 다시 펼쳐 재시도할 수 있습니다.</div>
        ) : page && page.rows.length === 0 ? (
          <div style={{ paddingLeft: 27, minHeight: 27, lineHeight: "27px", fontSize: 11.5, color: "var(--text-faint)" }}>부모 연결이 확인되지 않은 레코드가 없습니다.</div>
        ) : (
          <>
            <SearchResults rows={page?.rows ?? []} searching={false} error={null} isBookmarked={isBookmarked} selectedRowid={selectedRowid} onSelect={onSelect} refs={refs} accountFilter={accountFilter} caption={false} />
            {page && page.rows.length < page.total && (
              <button
                type="button"
                disabled={loading}
                onClick={onLoadMore}
                style={{ display: "block", marginLeft: 27, minHeight: 27, padding: "2px 10px", border: `1px solid ${loadMoreFailed ? "var(--danger)" : "var(--border)"}`, borderRadius: "var(--radius)", background: "var(--bg-elevated)", color: loadMoreFailed ? "var(--danger)" : "var(--accent)", cursor: "pointer", fontSize: 11.5 }}
              >
                {loading ? "불러오는 중…" : loadMoreFailed ? `이어받기 실패 — 다시 시도 (${page.rows.length.toLocaleString()}/${page.total.toLocaleString()})` : `더 불러오기 (${page.rows.length.toLocaleString()}/${page.total.toLocaleString()})`}
              </button>
            )}
          </>
        ))}
      </div>
    </div>
  );
}
