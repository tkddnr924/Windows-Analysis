"use client";
// 레지스트리 뷰 (docs-06) — _OVERVIEW/RegistryExplorer의 모든 하이브·키·값을
// Explorer 형태로 탐색한다. 왼쪽은 하이브 트리·퀵 접근·검색 결과, 오른쪽은
// 선택한 키의 값 목록과 값 상세. 원본 파싱 DB는 읽지 않는다.
import AppLoader from "@/components/AppLoader";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import ArticleOutlinedIcon from "@mui/icons-material/ArticleOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import CheckIcon from "@mui/icons-material/Check";
import CircularProgress from "@mui/material/CircularProgress";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import FolderOutlinedIcon from "@mui/icons-material/FolderOutlined";
import FolderZipOutlinedIcon from "@mui/icons-material/FolderZipOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import IconButton from "@mui/material/IconButton";
import Inventory2OutlinedIcon from "@mui/icons-material/Inventory2Outlined";
import KeyboardArrowDownOutlinedIcon from "@mui/icons-material/KeyboardArrowDownOutlined";
import KeyboardArrowRightOutlinedIcon from "@mui/icons-material/KeyboardArrowRightOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import MoreHorizOutlinedIcon from "@mui/icons-material/MoreHorizOutlined";
import PersonOutlinedIcon from "@mui/icons-material/PersonOutlined";
import PlayCircleOutlinedIcon from "@mui/icons-material/PlayCircleOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import StorageOutlinedIcon from "@mui/icons-material/StorageOutlined";
import Tooltip from "@mui/material/Tooltip";
import { FilterDropdown, HeaderSearchInput, ViewHeader } from "@/components/FilterControls";
import { HexViewer } from "@/components/HexViewer";
import type { RegistryAncestor, RegistryEntry, RegistryHive, RegistryQuickAccess, RegistrySearchHit, RegistrySearchOptions } from "@/lib/types";
import { displayRegistryKeyPath, hiveMountPoint } from "@/lib/registryPath";
import { QUICK_GROUPS, QUICK_SECTIONS, SEARCH_FIELD_LABELS, applyValueChunk, emptyValueChunks, formatRegistryValue, hiveGroups, hiveLabel, isNavigable, quickGroupOf, resolutionLabel, typeLabel, type QuickGroupKey, type ValueChunks } from "@/lib/registryView";

type Row = Record<string, string>;

interface Props {
  dbPath: string;
  /** Bookmark state of the raw record a key/value row points at. */
  isRowBookmarked?: (row: Row) => boolean;
  onToggleBookmark?: (rowid: number) => void;
}

const CHILD_PAGE = 200;
const VALUE_PAGE = 2000;
const SEARCH_PAGE = 100;
const QUICK_GROUP_PAGE = 100;
const LOAD_STATUS: Record<string, string> = { not_parsed: "파싱 안 됨", facts_missing: "결과 없음", facts_unreadable: "읽기 실패" };

type ChildPage = { rows: Row[]; total: number; loading: boolean; error: string | null };
type LeftTab = "tree" | "quick" | "search";

const hiveNode = (hiveId: string) => `hive:${hiveId}`;
const lostNode = (hiveId: string) => `lost:${hiveId}`;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function typeTone(typeName: string | undefined): string {
  if (!typeName) return "var(--text-faint)";
  if (typeName.endsWith("_SZ") || typeName === "REG_LINK") return "var(--accent)";
  if (typeName.includes("WORD") || typeName === "REG_FILETIME") return "var(--warning)";
  return "var(--text-dim)";
}

function TypeBadge({ typeName }: { typeName: string | undefined }) {
  const tone = typeTone(typeName);
  return <span style={{ display: "inline-block", fontSize: 10.5, fontFamily: "var(--mono)", fontWeight: 650, color: tone, background: `color-mix(in srgb, ${tone} 12%, transparent)`, borderRadius: 4, padding: "1px 6px", whiteSpace: "nowrap" }}>{typeLabel(typeName)}</span>;
}

function useCopy(): [string | null, (text: string, id: string) => void] {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = useCallback((text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id);
      window.setTimeout(() => setCopied((current) => (current === id ? null : current)), 1200);
    }).catch(() => {});
  }, []);
  return [copied, copy];
}

export default function RegistryView({ dbPath, isRowBookmarked, onToggleBookmark }: Props) {
  const [hives, setHives] = useState<RegistryHive[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [leftTab, setLeftTab] = useState<LeftTab>("tree");
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [children, setChildren] = useState<Record<string, ChildPage>>({});
  const childrenRef = useRef(children);
  childrenRef.current = children;
  const [selectedKey, setSelectedKey] = useState<{ hiveId: string; recordId: string } | null>(null);
  const [keyInfo, setKeyInfo] = useState<RegistryEntry | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [values, setValues] = useState<{ rows: Row[]; total: number } | null>(null);
  const [valuesLoading, setValuesLoading] = useState(false);
  const [valuesError, setValuesError] = useState<string | null>(null);
  const [selectedValueId, setSelectedValueId] = useState<string | null>(null);
  const [valueEntry, setValueEntry] = useState<RegistryEntry | null>(null);
  const [valueFilter, setValueFilter] = useState("");
  const [scrollTarget, setScrollTarget] = useState<string | null>(null);
  const keySeq = useRef(0);
  const valueSeq = useRef(0);

  const hiveById = useMemo(() => new Map((hives ?? []).map((hive) => [hive.hiveId, hive])), [hives]);

  useEffect(() => {
    let alive = true;
    window.api.registryHives(dbPath).then((result) => { if (alive) setHives(result); }).catch((e) => { if (alive) setError(String(e)); });
    return () => { alive = false; };
  }, [dbPath]);

  // Children of a tree node; `minimum` widens the first window for reveal.
  const loadChildren = useCallback(async (node: string, hiveId: string, parent: string | null, unresolved: boolean, minimum = CHILD_PAGE, append = false) => {
    const current = childrenRef.current[node];
    if (current?.loading) return current;
    const offset = append && current ? current.rows.length : 0;
    const limit = append ? CHILD_PAGE : Math.max(CHILD_PAGE, minimum);
    if (!append && current && current.rows.length >= minimum && !current.error) return current;
    setChildren((prev) => ({ ...prev, [node]: { rows: prev[node]?.rows ?? [], total: prev[node]?.total ?? 0, loading: true, error: null } }));
    try {
      const page = await window.api.registryKeys(dbPath, hiveId, parent, unresolved, offset, limit);
      const rows = append && current ? [...current.rows, ...page.rows] : page.rows;
      const next = { rows, total: page.total, loading: false, error: null };
      setChildren((prev) => ({ ...prev, [node]: next }));
      childrenRef.current = { ...childrenRef.current, [node]: next };
      return next;
    } catch (e) {
      setChildren((prev) => ({ ...prev, [node]: { rows: prev[node]?.rows ?? [], total: prev[node]?.total ?? 0, loading: false, error: String(e) } }));
      return null;
    }
  }, [dbPath]);

  const expand = useCallback((node: string, open: boolean) => {
    setExpanded((prev) => {
      if (prev.has(node) === open) return prev;
      const next = new Set(prev);
      if (open) next.add(node); else next.delete(node);
      return next;
    });
  }, []);

  const toggleHive = useCallback(async (hive: RegistryHive) => {
    const node = hiveNode(hive.hiveId);
    if (expanded.has(node)) { expand(node, false); return; }
    expand(node, true);
    const roots = await loadChildren(node, hive.hiveId, null, false);
    // A single root opens with its hive.
    if (roots && roots.rows.length === 1 && hive.unresolvedCount === 0) {
      const root = roots.rows[0];
      expand(root.record_id, true);
      void loadChildren(root.record_id, hive.hiveId, root.record_id, false);
    }
  }, [expand, expanded, loadChildren]);

  const toggleKey = useCallback((row: Row) => {
    const open = !expanded.has(row.record_id);
    expand(row.record_id, open);
    if (open) void loadChildren(row.record_id, row.hive_id, row.record_id, false);
  }, [expand, expanded, loadChildren]);

  // Select a key (values + header) and optionally a value. Values come in
  // pages; a value to select is paged in until it is loaded.
  const selectKey = useCallback((hiveId: string, recordId: string, valueId: string | null = null) => {
    setSelectedKey({ hiveId, recordId });
    setSelectedValueId(valueId);
    setValueFilter("");
    const seq = ++keySeq.current;
    setValues(null);
    setValuesError(null);
    setKeyInfo(null);
    setKeyError(null);
    window.api.registryEntry(dbPath, recordId)
      .then((info) => { if (keySeq.current === seq) setKeyInfo(info); })
      .catch((e) => { if (keySeq.current === seq) setKeyError(String(e)); });
    // The loading flag also covers this paging so 「더 불러오기」 can't fetch the same range.
    setValuesLoading(true);
    void (async () => {
      try {
        let rows: Row[] = [];
        let total = 0;
        do {
          const page = await window.api.registryValues(dbPath, recordId, rows.length, VALUE_PAGE);
          if (keySeq.current !== seq) return;
          rows = [...rows, ...page.rows];
          total = page.total;
          setValues({ rows, total });
          if (!page.rows.length) break;
        } while (valueId && rows.length < total && !rows.some((row) => row.record_id === valueId));
      } catch (e) {
        if (keySeq.current === seq) setValuesError(String(e));
      } finally {
        if (keySeq.current === seq) setValuesLoading(false);
      }
    })();
  }, [dbPath]);

  const loadMoreValues = useCallback(() => {
    if (!selectedKey || !values || valuesLoading) return;
    const seq = keySeq.current;
    setValuesLoading(true);
    window.api.registryValues(dbPath, selectedKey.recordId, values.rows.length, VALUE_PAGE)
      .then((page) => {
        if (keySeq.current !== seq) return;
        const seen = new Set(values.rows.map((row) => row.record_id));
        setValues({ rows: [...values.rows, ...page.rows.filter((row) => !seen.has(row.record_id))], total: page.total });
      })
      .catch((e) => { if (keySeq.current === seq) setValuesError(String(e)); })
      .finally(() => { if (keySeq.current === seq) setValuesLoading(false); });
  }, [dbPath, selectedKey, values, valuesLoading]);
  // A value filter must see every value, not just the loaded pages.
  useEffect(() => {
    if (valueFilter.trim() && values && values.rows.length < values.total && !valuesLoading && !valuesError) loadMoreValues();
  }, [valueFilter, values, valuesLoading, valuesError, loadMoreValues]);

  useEffect(() => {
    if (!selectedValueId) { setValueEntry(null); return; }
    const seq = ++valueSeq.current;
    setValueEntry(null);
    window.api.registryEntry(dbPath, selectedValueId).then((info) => { if (valueSeq.current === seq) setValueEntry(info); }).catch(() => {});
  }, [dbPath, selectedValueId]);

  // Open the tree down to an entry's key and scroll to it.
  const openTreeTo = useCallback(async (info: RegistryEntry) => {
    const hiveId = info.key.hive_id;
    if (!hiveById.has(hiveId)) return false;
    const chain: RegistryAncestor[] = info.ancestors;
    const top = chain[0];
    const hiveKey = hiveNode(hiveId);
    expand(hiveKey, true);
    if (top?.parentStatus === "unresolved") {
      await loadChildren(hiveKey, hiveId, null, false);
      expand(lostNode(hiveId), true);
      await loadChildren(lostNode(hiveId), hiveId, null, true, top.position + 1);
    } else if (top) {
      await loadChildren(hiveKey, hiveId, null, false, top.position + 1);
    }
    for (let i = 0; i < chain.length - 1; i++) {
      expand(chain[i].recordId, true);
      await loadChildren(chain[i].recordId, hiveId, chain[i].recordId, false, chain[i + 1].position + 1);
    }
    setScrollTarget(info.key.record_id);
    return true;
  }, [expand, hiveById, loadChildren]);

  // Open the tree down to a key or value and select it.
  const reveal = useCallback(async (recordId: string) => {
    const info = await window.api.registryEntry(dbPath, recordId);
    if (!(await openTreeTo(info))) return;
    const isValue = info.entry.entry_kind === "value";
    selectKey(info.key.hive_id, info.key.record_id, isValue ? info.entry.record_id : null);
  }, [dbPath, openTreeTo, selectKey]);

  // Hive picker: open the hive in the tree and scroll to it.
  const openHive = useCallback((hive: RegistryHive) => {
    setLeftTab("tree");
    if (!expanded.has(hiveNode(hive.hiveId))) void toggleHive(hive);
    setScrollTarget(hiveNode(hive.hiveId));
  }, [expanded, toggleHive]);

  useEffect(() => {
    if (!scrollTarget) return;
    const timer = window.setTimeout(() => {
      document.querySelector(`[data-registry-node="${CSS.escape(scrollTarget)}"]`)?.scrollIntoView({ block: "center" });
      setScrollTarget(null);
    }, 60);
    return () => window.clearTimeout(timer);
  }, [scrollTarget, children, leftTab]);

  // ---- search -------------------------------------------------------------
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "hive" | "key">("all");
  const [fields, setFields] = useState({ keys: true, valueNames: true, valueData: true });
  const [hits, setHits] = useState<RegistrySearchHit[]>([]);
  const [searchState, setSearchState] = useState<{ running: boolean; cursor: number | null; done: boolean; progress: number; error: string | null }>({ running: false, cursor: null, done: false, progress: 0, error: null });
  const searchSeq = useRef(0);
  const searchOptions = useMemo<RegistrySearchOptions>(() => ({
    query: query.trim(),
    hiveId: scope === "hive" ? selectedKey?.hiveId : undefined,
    keyRecordId: scope === "key" ? selectedKey?.recordId : undefined,
    keys: fields.keys,
    valueNames: fields.valueNames,
    valueData: fields.valueData,
  }), [query, scope, selectedKey, fields]);

  // Scan in steps until a page of hits is collected, the scope ends or the
  // analyst stops; each step returns within about a second.
  const runSearch = useCallback(async (resume: boolean) => {
    const seq = ++searchSeq.current;
    const options = searchOptions;
    if (options.query.length < 2) {
      setHits([]);
      setSearchState({ running: false, cursor: null, done: false, progress: 0, error: null });
      return;
    }
    let cursor = resume ? searchState.cursor : null;
    let collected = resume ? hits.length : 0;
    const target = collected + SEARCH_PAGE;
    if (!resume) setHits([]);
    setSearchState((prev) => ({ ...prev, running: true, done: false, error: null, progress: resume ? prev.progress : 0 }));
    try {
      for (;;) {
        const page = await window.api.registrySearch(dbPath, options, cursor, target - collected);
        if (searchSeq.current !== seq) return;
        collected += page.hits.length;
        setHits((prev) => [...prev, ...page.hits]);
        const span = Math.max(1, page.rangeEnd - page.rangeStart + 1);
        const progress = Math.min(1, (page.scannedTo - page.rangeStart + 1) / span);
        cursor = page.nextCursor;
        const done = cursor === null;
        setSearchState({ running: !done && collected < target, cursor, done, progress: done ? 1 : progress, error: null });
        if (done || collected >= target) return;
      }
    } catch (e) {
      if (searchSeq.current === seq) setSearchState((prev) => ({ ...prev, running: false, error: String(e) }));
    }
  }, [dbPath, hits.length, searchOptions, searchState.cursor]);

  // Debounced new search on query/scope/field change.
  const optionsKey = JSON.stringify(searchOptions);
  useEffect(() => {
    if (searchOptions.query.length < 2) {
      searchSeq.current++;
      setHits([]);
      setSearchState({ running: false, cursor: null, done: false, progress: 0, error: null });
      // The search tab disappears with its query; don't leave it selected.
      setLeftTab((tab) => (tab === "search" ? "tree" : tab));
      return;
    }
    setLeftTab("search");
    const timer = window.setTimeout(() => { void runSearch(false); }, 350);
    return () => window.clearTimeout(timer);
    // runSearch reads the latest state; optionsKey is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [optionsKey]);
  const stopSearch = () => { searchSeq.current++; setSearchState((prev) => ({ ...prev, running: false })); };

  // ---- quick access ---------------------------------------------------------
  const [quick, setQuick] = useState<RegistryQuickAccess | null>(null);
  const [quickError, setQuickError] = useState<string | null>(null);
  useEffect(() => {
    if (leftTab !== "quick" || quick) return;
    window.api.registryQuickAccess(dbPath).then(setQuick).catch((e) => setQuickError(String(e)));
  }, [dbPath, leftTab, quick]);

  const totals = useMemo(() => (hives ?? []).reduce((acc, hive) => ({ keys: acc.keys + hive.keyCount, values: acc.values + hive.valueCount }), { keys: 0, values: 0 }), [hives]);
  const selectedHive = selectedKey ? hiveById.get(selectedKey.hiveId) : undefined;

  const tabButton = (tab: LeftTab, label: string, count?: number) => {
    const active = leftTab === tab;
    // The explorer tab follows the key open on the right.
    const onClick = () => { setLeftTab(tab); if (tab === "tree" && keyInfo) void openTreeTo(keyInfo); };
    return (
      <button key={tab} type="button" role="tab" aria-selected={active} onClick={onClick} style={{ flex: 1, minHeight: 30, border: "none", borderRadius: 7, cursor: "pointer", fontSize: 12.5, fontWeight: active ? 650 : 500, background: active ? "var(--bg-panel)" : "transparent", boxShadow: active ? "0 1px 2px rgba(0,0,0,0.35), inset 0 0 0 1px var(--border)" : "none", color: active ? "var(--text)" : "var(--text-dim)" }}>
        {label}{count !== undefined && <span style={{ marginLeft: 5, fontSize: 11, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{count.toLocaleString()}</span>}
      </button>
    );
  };

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)" }}>
      <ViewHeader icon={AccountTreeOutlinedIcon} title="레지스트리" meta={hives ? `하이브 ${hives.length} · 키 ${totals.keys.toLocaleString()} · 값 ${totals.values.toLocaleString()}` : ""}>
        <HeaderSearchInput value={query} onChange={setQuery} placeholder="키 경로 · 값 이름 · 데이터 · 16진" ariaLabel="레지스트리 검색" width={340} />
        {hives && <HivePicker hives={hives} current={selectedHive} onOpen={openHive} />}
      </ViewHeader>
      {error ? (
        <div role="alert" style={{ flex: 1, display: "grid", placeItems: "center", color: "var(--danger)", fontSize: 13, padding: 16 }}>{error}</div>
      ) : !hives ? (
        <div style={{ flex: 1, display: "grid", placeItems: "center" }}><AppLoader message="레지스트리를 불러오는 중" /></div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(300px, 380px) minmax(0, 1fr)", gap: 12, padding: 12 }}>
          <aside aria-label="레지스트리 탐색" style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
            <div role="tablist" aria-label="탐색 방식" style={{ display: "flex", gap: 2, margin: 8, padding: 3, borderRadius: 9, background: "var(--bg-input, var(--bg-elevated))", border: "1px solid var(--border-subtle)" }}>
              {tabButton("tree", "탐색기")}
              {tabButton("quick", "퀵 접근", quick?.items.length)}
              {(query.trim().length >= 2 || hits.length > 0) && tabButton("search", "검색", hits.length)}
            </div>
            <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "0 6px 10px" }}>
              {leftTab === "tree" && (
                <HiveTree
                  hives={hives}
                  expanded={expanded}
                  pages={children}
                  selectedKeyId={selectedKey?.recordId ?? null}
                  onToggleHive={toggleHive}
                  onToggleKey={toggleKey}
                  onToggleLost={(hive) => { const node = lostNode(hive.hiveId); const open = !expanded.has(node); expand(node, open); if (open) void loadChildren(node, hive.hiveId, null, true); }}
                  onSelectKey={(row) => { selectKey(row.hive_id, row.record_id); if (!expanded.has(row.record_id) && Number(row.stored_subkey_count) > 0) toggleKey(row); }}
                  onMore={(node, hiveId, parent, unresolved) => void loadChildren(node, hiveId, parent, unresolved, CHILD_PAGE, true)}
                />
              )}
              {leftTab === "quick" && (
                <QuickAccessPanel quick={quick} error={quickError} hiveById={hiveById} onOpen={(id) => { void reveal(id); }} />
              )}
              {leftTab === "search" && (
                <SearchPanel
                  hits={hits}
                  query={query.trim()}
                  state={searchState}
                  scope={scope}
                  onScope={setScope}
                  scopeLabel={{ hive: selectedHive ? hiveLabel(selectedHive.hiveName).name : null, key: keyInfo?.key.key_name ?? null }}
                  fields={fields}
                  onFields={setFields}
                  hiveById={hiveById}
                  onOpen={(hit) => { void reveal(hit.recordId); }}
                  onMore={() => { void runSearch(true); }}
                  onStop={stopSearch}
                />
              )}
            </div>
          </aside>
          <section aria-label="키와 값" style={{ minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
            {!selectedKey ? (
              <div role="status" style={{ flex: 1, display: "grid", placeItems: "center", alignContent: "center", gap: 8, color: "var(--text-faint)", fontSize: 12.5 }}>
                <AccountTreeOutlinedIcon sx={{ fontSize: 28, opacity: 0.6 }} />
                키 선택
              </div>
            ) : (
              <>
                <KeyHeader
                  info={keyInfo}
                  error={keyError}
                  hive={selectedHive}
                  isRowBookmarked={isRowBookmarked}
                  onToggleBookmark={onToggleBookmark}
                  onSelectAncestor={(ancestor) => { if (selectedKey) selectKey(selectedKey.hiveId, ancestor.recordId); setScrollTarget(ancestor.recordId); }}
                />
                <ValueList
                  values={values}
                  error={valuesError}
                  loadingMore={valuesLoading}
                  onMore={loadMoreValues}
                  filter={valueFilter}
                  onFilter={setValueFilter}
                  selectedId={selectedValueId}
                  onSelect={setSelectedValueId}
                  isRowBookmarked={isRowBookmarked}
                />
                {selectedValueId && <ValueInspector key={selectedValueId} dbPath={dbPath} entry={valueEntry?.entry.record_id === selectedValueId ? valueEntry : null} isRowBookmarked={isRowBookmarked} onToggleBookmark={onToggleBookmark} onClose={() => setSelectedValueId(null)} />}
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

// ---- tree -----------------------------------------------------------------

function HiveTree({ hives, expanded, pages, selectedKeyId, onToggleHive, onToggleKey, onToggleLost, onSelectKey, onMore }: {
  hives: RegistryHive[];
  expanded: Set<string>;
  pages: Record<string, ChildPage>;
  selectedKeyId: string | null;
  onToggleHive: (hive: RegistryHive) => void;
  onToggleKey: (row: Row) => void;
  onToggleLost: (hive: RegistryHive) => void;
  onSelectKey: (row: Row) => void;
  onMore: (node: string, hiveId: string, parent: string | null, unresolved: boolean) => void;
}) {
  const renderKeys = (node: string, hiveId: string, parent: string | null, unresolved: boolean, depth: number): React.ReactNode => {
    const page = pages[node];
    if (!page) return null;
    if (page.error && !page.rows.length) return <div role="alert" style={{ paddingLeft: 10 + depth * 16, fontSize: 11.5, color: "var(--danger)", minHeight: 26, lineHeight: "26px" }}>{page.error}</div>;
    if (page.loading && !page.rows.length) return <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, paddingLeft: 30 + depth * 16, minHeight: 26, fontSize: 11.5, color: "var(--text-faint)" }}><CircularProgress size={12} thickness={4} />불러오는 중</div>;
    return (
      <>
        {page.rows.map((row) => {
          const open = expanded.has(row.record_id);
          const hasChildren = Number(row.stored_subkey_count) > 0;
          return (
            <div key={row.record_id}>
              <TreeRow
                nodeId={row.record_id}
                depth={depth}
                open={open}
                hasChildren={hasChildren}
                selected={row.record_id === selectedKeyId}
                icon={!hasChildren ? <ArticleOutlinedIcon sx={{ fontSize: 15, color: "var(--text-faint)" }} /> : open ? <FolderOpenOutlinedIcon sx={{ fontSize: 16, color: "var(--accent)" }} /> : <FolderOutlinedIcon sx={{ fontSize: 16, color: "var(--text-faint)" }} />}
                label={row.key_name || "(이름 없음)"}
                trailing={<>
                  {row.key_read_status === "partial" && <span title="일부 읽기" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--warning)" }} />}
                  {hasChildren && <span style={{ fontSize: 10.5, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{Number(row.stored_subkey_count).toLocaleString()}</span>}
                </>}
                onToggle={() => onToggleKey(row)}
                onSelect={() => onSelectKey(row)}
              />
              {open && renderKeys(row.record_id, hiveId, row.record_id, false, depth + 1)}
            </div>
          );
        })}
        {page.rows.length < page.total && (
          <button type="button" disabled={page.loading} onClick={() => onMore(node, hiveId, parent, unresolved)} style={{ display: "block", margin: "2px 0 4px", marginLeft: 30 + depth * 16, minHeight: 26, padding: "0 10px", fontSize: 11.5, border: "1px solid var(--border)", borderRadius: 6, background: "transparent", color: "var(--accent)", cursor: "pointer" }}>
            {page.loading ? "불러오는 중…" : `더 불러오기 · ${page.rows.length.toLocaleString()} / ${page.total.toLocaleString()}`}
          </button>
        )}
      </>
    );
  };

  return (
    <div role="tree" aria-label="하이브">
      {hiveGroups(hives).map((group) => (
        <div key={group.title} style={{ marginBottom: 6 }}>
          <div style={{ padding: "8px 8px 4px", fontSize: 10.5, fontWeight: 700, letterSpacing: 0.4, color: "var(--text-faint)" }}>{group.title}</div>
          {group.hives.map((hive) => {
            const node = hiveNode(hive.hiveId);
            const open = expanded.has(node);
            const loaded = hive.loadStatus === "loaded";
            const label = hiveLabel(hive.hiveName);
            const mount = hiveMountPoint(hive.hiveName);
            return (
              <div key={hive.hiveId}>
                <TreeRow
                  nodeId={node}
                  depth={0}
                  open={open}
                  hasChildren={loaded && hive.keyCount > 0}
                  selected={false}
                  disabled={!loaded}
                  icon={<StorageOutlinedIcon sx={{ fontSize: 16, color: loaded ? "var(--text-dim)" : "var(--text-faint)" }} />}
                  label={<span style={{ display: "inline-flex", alignItems: "baseline", gap: 6, minWidth: 0 }}>
                    <span style={{ fontWeight: 650 }}>{label.name}</span>
                    {label.owner && <span style={{ fontSize: 11.5, color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis" }}>{label.owner}</span>}
                  </span>}
                  title={[hive.sourceFile, mount].filter(Boolean).join("\n")}
                  trailing={!loaded
                    ? <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--warning)" }}>{LOAD_STATUS[hive.loadStatus] ?? hive.loadStatus}</span>
                    : <span style={{ fontSize: 10.5, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{hive.keyCount.toLocaleString()}</span>}
                  onToggle={() => loaded && onToggleHive(hive)}
                  onSelect={() => loaded && onToggleHive(hive)}
                />
                {open && renderKeys(node, hive.hiveId, null, false, 1)}
                {open && hive.unresolvedCount > 0 && (
                  <div>
                    <TreeRow
                      nodeId={lostNode(hive.hiveId)}
                      depth={1}
                      open={expanded.has(lostNode(hive.hiveId))}
                      hasChildren
                      selected={false}
                      icon={<FolderOutlinedIcon sx={{ fontSize: 16, color: "var(--warning)" }} />}
                      label={<span style={{ color: "var(--text-dim)" }}>부모 미확인</span>}
                      trailing={<span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>{hive.unresolvedCount.toLocaleString()}</span>}
                      onToggle={() => onToggleLost(hive)}
                      onSelect={() => onToggleLost(hive)}
                    />
                    {expanded.has(lostNode(hive.hiveId)) && renderKeys(lostNode(hive.hiveId), hive.hiveId, null, true, 2)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function TreeRow({ nodeId, depth, open, hasChildren, selected, disabled = false, icon, label, title, trailing, onToggle, onSelect }: {
  nodeId: string;
  depth: number;
  open: boolean;
  hasChildren: boolean;
  selected: boolean;
  disabled?: boolean;
  icon: React.ReactNode;
  label: React.ReactNode;
  title?: string;
  trailing?: React.ReactNode;
  onToggle: () => void;
  onSelect: () => void;
}) {
  return (
    <div
      role="treeitem"
      aria-expanded={hasChildren ? open : undefined}
      aria-selected={selected}
      aria-disabled={disabled || undefined}
      data-registry-node={nodeId}
      tabIndex={disabled ? -1 : 0}
      title={title}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (event.key === "Enter") { event.preventDefault(); onSelect(); }
        if (event.key === "ArrowRight" && hasChildren && !open) { event.preventDefault(); onToggle(); }
        if (event.key === "ArrowLeft" && open) { event.preventDefault(); onToggle(); }
      }}
      onMouseEnter={(event) => { if (!selected && !disabled) event.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(event) => { event.currentTarget.style.background = selected ? "var(--bg-selected)" : "transparent"; }}
      style={{ display: "flex", alignItems: "center", gap: 6, minHeight: 28, paddingLeft: 4 + depth * 16, paddingRight: 8, borderRadius: 6, cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.6 : 1, background: selected ? "var(--bg-selected)" : "transparent", boxShadow: selected ? "inset 2px 0 0 var(--accent)" : undefined }}
    >
      <span
        role="presentation"
        onClick={(event) => { event.stopPropagation(); if (hasChildren) onToggle(); }}
        style={{ display: "inline-flex", width: 18, flexShrink: 0, color: "var(--text-faint)", visibility: hasChildren ? "visible" : "hidden" }}
      >
        {open ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 17 }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 17 }} />}
      </span>
      <span style={{ display: "inline-flex", flexShrink: 0 }}>{icon}</span>
      <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, color: "var(--text)" }}>{label}</span>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6, flexShrink: 0 }}>{trailing}</span>
    </div>
  );
}

// ---- right pane -------------------------------------------------------------

function HivePicker({ hives, current, onOpen }: { hives: RegistryHive[]; current: RegistryHive | undefined; onOpen: (hive: RegistryHive) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <FilterDropdown icon={<StorageOutlinedIcon sx={{ fontSize: 15 }} />} label="하이브" valueLabel={current ? hiveLabel(current.hiveName).name : String(hives.length)} align="left" minWidth={380} ariaLabel="하이브 선택" open={open} onToggle={setOpen}>
      {hiveGroups(hives).map((group, index) => (
        <div key={group.title} role="listbox" aria-label={group.title} style={{ display: "grid", gap: 1, marginTop: index ? 6 : 0, paddingTop: index ? 6 : 0, borderTop: index ? "1px solid var(--border-subtle)" : "none" }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6, padding: "4px 10px 4px" }}>
            <span style={{ fontSize: 10.5, fontWeight: 650, letterSpacing: 0.3, color: "var(--text-faint)" }}>{group.title}</span>
            <span style={{ fontSize: 10, color: "var(--text-faint)", opacity: 0.7, fontVariantNumeric: "tabular-nums" }}>{group.hives.length}</span>
          </div>
          {group.hives.map((hive) => {
            const label = hiveLabel(hive.hiveName);
            const loaded = hive.loadStatus === "loaded";
            const selected = current?.hiveId === hive.hiveId;
            const mount = hiveMountPoint(hive.hiveName);
            const rest = selected ? "color-mix(in srgb, var(--accent) 13%, transparent)" : "transparent";
            return (
              <button key={hive.hiveId} type="button" role="option" aria-selected={selected} disabled={!loaded} title={[hive.sourceFile, mount].filter(Boolean).join("\n") || undefined}
                onClick={() => { onOpen(hive); setOpen(false); }}
                onMouseEnter={(event) => { if (loaded && !selected) event.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(event) => { event.currentTarget.style.background = rest; }}
                style={{ display: "grid", gridTemplateColumns: "16px minmax(0, 1fr) auto", alignItems: "center", gap: 9, height: 30, padding: "0 10px", border: "none", borderRadius: 7, background: rest, color: "var(--text)", cursor: loaded ? "pointer" : "default", opacity: loaded ? 1 : 0.55, textAlign: "left", fontSize: 12.5 }}>
                <StorageOutlinedIcon sx={{ fontSize: 14, color: selected ? "var(--accent)" : "var(--text-faint)" }} />
                <span style={{ minWidth: 0, display: "flex", alignItems: "baseline", gap: 7, overflow: "hidden", whiteSpace: "nowrap" }}>
                  <span style={{ flexShrink: 0, fontWeight: selected ? 650 : 550, color: selected ? "var(--accent)" : "var(--text)" }}>{label.name}</span>
                  {label.owner && <span style={{ flexShrink: 0, color: "var(--text-dim)" }}>{label.owner}</span>}
                  {hive.isRegback && <span style={{ flexShrink: 0, alignSelf: "center", fontSize: 9.5, fontWeight: 650, color: "var(--text-dim)", background: "var(--bg-hover)", borderRadius: 4, padding: "1px 5px" }}>RegBack</span>}
                  {mount && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)" }}>{mount}</span>}
                </span>
                {loaded
                  ? <span style={{ fontSize: 11, fontVariantNumeric: "tabular-nums", color: "var(--text-faint)" }}>{hive.keyCount.toLocaleString()}</span>
                  : <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--warning)" }}>{LOAD_STATUS[hive.loadStatus] ?? hive.loadStatus}</span>}
              </button>
            );
          })}
        </div>
      ))}
    </FilterDropdown>
  );
}

function BookmarkButton({ row, isRowBookmarked, onToggleBookmark, size = 16 }: { row: Row; isRowBookmarked?: (row: Row) => boolean; onToggleBookmark?: (rowid: number) => void; size?: number }) {
  const bookmarked = isRowBookmarked?.(row) ?? false;
  return (
    <Tooltip title={bookmarked ? "북마크 해제" : "북마크"}>
      <span>
        <IconButton className={bookmarked ? "dfir-bookmark-control" : undefined} aria-label={bookmarked ? "북마크 해제" : "북마크"} disabled={!onToggleBookmark || !row.__rowid} size="small" onClick={() => onToggleBookmark?.(Number(row.__rowid))} sx={{ color: bookmarked ? "var(--bookmark-control)" : "var(--text-faint)", borderRadius: "var(--radius)" }}>
          {bookmarked ? <BookmarkIcon sx={{ fontSize: size }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: size }} />}
        </IconButton>
      </span>
    </Tooltip>
  );
}

function KeyHeader({ info, error, hive, isRowBookmarked, onToggleBookmark, onSelectAncestor }: {
  info: RegistryEntry | null;
  error: string | null;
  hive: RegistryHive | undefined;
  isRowBookmarked?: (row: Row) => boolean;
  onToggleBookmark?: (rowid: number) => void;
  onSelectAncestor: (ancestor: RegistryAncestor) => void;
}) {
  const [copied, copy] = useCopy();
  if (error) return <div role="alert" title={error} style={{ minHeight: 86, padding: "12px 14px", borderBottom: "1px solid var(--border-subtle)", fontSize: 12.5, color: "var(--danger)" }}>키 정보를 불러오지 못했습니다</div>;
  if (!info) return <div style={{ minHeight: 86, borderBottom: "1px solid var(--border-subtle)" }} />;
  const key = info.key;
  const display = displayRegistryKeyPath(key.key_path, hive?.hiveName);
  const label = hive ? hiveLabel(hive.hiveName) : null;
  const declaredValues = Number(key.key_value_count);
  const storedValues = Number(key.stored_value_count);
  const chip: React.CSSProperties = { display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5, color: "var(--text-dim)", whiteSpace: "nowrap" };
  const chipValue: React.CSSProperties = { color: "var(--text)", fontVariantNumeric: "tabular-nums" };
  // Breadcrumb from the stored ancestors; the hive root shows its mount point.
  const rootShown = displayRegistryKeyPath(`\\${info.ancestors[0]?.keyName ?? ""}`, hive?.hiveName);
  const segments = info.ancestors.map((ancestor, index) => ({ ancestor, label: index === 0 ? rootShown.replace(/^\\/, "") || "(이름 없음)" : ancestor.keyName || "(이름 없음)" }));
  return (
    <div style={{ flexShrink: 0, display: "grid", gap: 8, padding: "12px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8, minWidth: 0 }}>
        <nav aria-label="키 경로" style={{ flex: 1, minWidth: 0, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 2, fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: 1.6 }}>
          {segments.map(({ ancestor, label: text }, index) => {
            const last = index === segments.length - 1;
            return (
              <span key={ancestor.recordId} style={{ display: "inline-flex", alignItems: "center", gap: 2, minWidth: 0 }}>
                {index > 0 && <span aria-hidden="true" style={{ color: "var(--text-faint)" }}>\</span>}
                {last
                  ? <span style={{ color: "var(--text)", fontWeight: 700, wordBreak: "break-all" }}>{text}</span>
                  : <button type="button" onClick={() => onSelectAncestor(ancestor)} style={{ padding: 0, border: "none", background: "transparent", color: "var(--text-dim)", cursor: "pointer", font: "inherit", wordBreak: "break-all" }}
                      onMouseEnter={(event) => { event.currentTarget.style.color = "var(--accent)"; }} onMouseLeave={(event) => { event.currentTarget.style.color = "var(--text-dim)"; }}>{text}</button>}
              </span>
            );
          })}
        </nav>
        <Tooltip title={copied === "path" ? "복사됨" : "경로 복사"}>
          <IconButton size="small" aria-label="키 경로 복사" onClick={() => copy(display, "path")} sx={{ color: "var(--text-faint)", borderRadius: "var(--radius)" }}>
            {copied === "path" ? <CheckIcon sx={{ fontSize: 15, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
          </IconButton>
        </Tooltip>
        <BookmarkButton row={key} isRowBookmarked={isRowBookmarked} onToggleBookmark={onToggleBookmark} />
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "6px 16px" }}>
        {label && <span style={chip}><StorageOutlinedIcon sx={{ fontSize: 14 }} /><span style={chipValue}>{label.name}</span>{label.owner && <span>{label.owner}</span>}{hive?.isRegback && <span style={{ fontSize: 10, fontWeight: 700, border: "1px solid var(--border)", borderRadius: 999, padding: "0 6px" }}>RegBack</span>}</span>}
        <span style={chip}>마지막 기록 <span style={{ ...chipValue, fontFamily: "var(--mono)", color: key.key_last_write ? "var(--text-time)" : "var(--text-faint)" }}>{key.key_last_write || "—"}</span></span>
        <span style={chip}>하위 키 <span style={chipValue}>{Number(key.stored_subkey_count).toLocaleString()}</span></span>
        <span style={chip}>값 <span style={chipValue}>{storedValues.toLocaleString()}</span>{Number.isFinite(declaredValues) && declaredValues !== storedValues && <span title="키에 선언된 값 수">/ 선언 {declaredValues.toLocaleString()}</span>}</span>
        {key.key_read_status === "partial" && <span style={{ ...chip, color: "var(--warning)" }} title={key.key_read_error || undefined}>일부 읽기</span>}
      </div>
    </div>
  );
}

function ValueList({ values, error, loadingMore, onMore, filter, onFilter, selectedId, onSelect, isRowBookmarked }: {
  values: { rows: Row[]; total: number } | null;
  error: string | null;
  loadingMore: boolean;
  onMore: () => void;
  filter: string;
  onFilter: (value: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  isRowBookmarked?: (row: Row) => boolean;
}) {
  const needle = filter.trim().toLowerCase();
  const loaded = values?.rows;
  const shown = useMemo(() => (loaded ?? []).filter((row) => !needle || (row.value_display_name ?? row.value_name ?? "").toLowerCase().includes(needle) || (row.value_preview ?? "").toLowerCase().includes(needle)), [loaded, needle]);
  const selectedRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => { selectedRef.current?.scrollIntoView({ block: "nearest" }); }, [selectedId, loaded]);
  const grid = "minmax(140px, 0.9fr) 112px minmax(0, 2fr) 76px 24px";
  return (
    <div style={{ flex: 1, minHeight: 120, display: "flex", flexDirection: "column" }}>
      <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 10, padding: "8px 14px" }}>
        <strong style={{ fontSize: 12.5 }}>값</strong>
        <span style={{ fontSize: 11.5, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{values ? (needle ? `${shown.length.toLocaleString()} / ${values.total.toLocaleString()}` : values.total.toLocaleString()) : ""}</span>
        {values && values.total > 8 && (
          <input value={filter} onChange={(event) => onFilter(event.target.value)} placeholder="이름 · 데이터 필터" aria-label="값 필터" style={{ marginLeft: "auto", width: 220, height: 28, padding: "0 10px", fontSize: 12, background: "var(--bg-input, var(--bg-elevated))", border: "1px solid var(--border)", borderRadius: 7, color: "var(--text)", outline: "none" }} />
        )}
      </div>
      <div role="grid" aria-label="값 목록" style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "0 8px 8px" }}>
        {error ? <div role="alert" style={{ padding: 12, color: "var(--danger)", fontSize: 12.5 }}>{error}</div>
          : !values ? <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, padding: 12, color: "var(--text-faint)", fontSize: 12 }}><CircularProgress size={13} thickness={4} />불러오는 중</div>
          : values.total === 0 ? <div role="status" style={{ padding: "18px 12px", color: "var(--text-faint)", fontSize: 12.5 }}>값 없음</div>
          : <>
            <div role="row" style={{ display: "grid", gridTemplateColumns: grid, gap: 12, padding: "0 8px 4px", fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", position: "sticky", top: 0, background: "var(--bg-panel)", zIndex: 1 }}>
              <span role="columnheader">이름</span><span role="columnheader">형식</span><span role="columnheader">데이터</span><span role="columnheader" style={{ textAlign: "right" }}>크기</span><span />
            </div>
            {shown.map((row) => {
              const selected = row.record_id === selectedId;
              const formatted = formatRegistryValue(row);
              const isDefault = row.value_is_default === "1";
              const bookmarked = isRowBookmarked?.(row) ?? false;
              return (
                <div key={row.record_id} ref={selected ? selectedRef : undefined} role="row" tabIndex={0} aria-selected={selected}
                  onClick={() => onSelect(row.record_id)}
                  onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(row.record_id); } }}
                  onMouseEnter={(event) => { if (!selected) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = selected ? "var(--bg-selected)" : "transparent"; }}
                  style={{ display: "grid", gridTemplateColumns: grid, gap: 12, alignItems: "center", minHeight: 30, padding: "0 8px", borderRadius: 6, cursor: "pointer", background: selected ? "var(--bg-selected)" : "transparent", boxShadow: selected ? "inset 2px 0 0 var(--accent)" : undefined }}>
                  <span role="gridcell" title={row.value_name} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontStyle: isDefault ? "italic" : undefined, color: isDefault ? "var(--text-dim)" : "var(--text)" }}>{isDefault ? "(기본값)" : row.value_name}</span>
                  <span role="gridcell"><TypeBadge typeName={row.value_type_name} /></span>
                  <span role="gridcell" title={formatted.kind === "text" || formatted.kind === "lines" ? formatted.primary : undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12, color: formatted.kind === "error" ? "var(--danger)" : formatted.kind === "empty" ? "var(--text-faint)" : formatted.kind === "binary" ? "var(--text-dim)" : "var(--text)" }}>
                    {formatted.kind === "empty" ? "(빈 데이터)" : formatted.kind === "error" ? "읽기 실패" : formatted.primary}
                    {row.value_read_status === "partial" && <span style={{ marginLeft: 6, fontSize: 10.5, color: "var(--warning)", fontFamily: "inherit" }}>일부</span>}
                  </span>
                  <span role="gridcell" style={{ textAlign: "right", fontSize: 11, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{Number(row.value_data_length).toLocaleString()} B</span>
                  <span role="gridcell" style={{ display: "inline-flex", justifyContent: "center" }}>{bookmarked && <BookmarkIcon aria-label="북마크됨" sx={{ fontSize: 13, color: "var(--bookmark-control)" }} />}</span>
                </div>
              );
            })}
            {shown.length === 0 && (values.rows.length < values.total
              ? <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, padding: "14px 8px", color: "var(--text-faint)", fontSize: 12 }}><CircularProgress size={13} thickness={4} />불러오는 중</div>
              : <div role="status" style={{ padding: "14px 8px", color: "var(--text-faint)", fontSize: 12 }}>일치하는 값 없음</div>)}
            {values.rows.length < values.total && (
              <button type="button" disabled={loadingMore} onClick={onMore} style={{ margin: "6px 8px 0", minHeight: 26, padding: "0 10px", fontSize: 11.5, border: "1px solid var(--border)", borderRadius: 6, background: "transparent", color: "var(--accent)", cursor: "pointer" }}>
                {loadingMore ? "불러오는 중…" : `더 불러오기 · ${values.rows.length.toLocaleString()} / ${values.total.toLocaleString()}`}
              </button>
            )}
          </>}
      </div>
    </div>
  );
}

// One chunk of value data past the detail cap (hex digits / characters).
const VALUE_CHUNK = 4 * 1024 * 1024;

function ValueInspector({ dbPath, entry, isRowBookmarked, onToggleBookmark, onClose }: { dbPath: string; entry: RegistryEntry | null; isRowBookmarked?: (row: Row) => boolean; onToggleBookmark?: (rowid: number) => void; onClose: () => void }) {
  const [tab, setTab] = useState<"value" | "hex">("value");
  const [copied, copy] = useCopy();
  // Data past the detail cap, appended chunk by chunk to this value only.
  const base = entry?.entry;
  const [extra, setExtra] = useState<ValueChunks>(() => emptyValueChunks(base?.record_id ?? ""));
  useEffect(() => { setTab("value"); setExtra(emptyValueChunks(base?.record_id ?? "")); }, [base?.record_id]);
  const ownHex = extra.recordId === base?.record_id ? extra.hex : "";
  const ownText = extra.recordId === base?.record_id ? extra.text : "";
  const row = useMemo<Row | undefined>(() => (base ? { ...base, value_data_hex: (base.value_data_hex ?? "") + ownHex, value_data_text: base.value_data_text == null ? base.value_data_text : base.value_data_text + ownText } : undefined), [base, ownHex, ownText]);
  const formatted = row ? formatRegistryValue(row) : null;
  const bytes = useMemo(() => (row?.value_data_hex ? hexToBytes(row.value_data_hex) : new Uint8Array()), [row?.value_data_hex]);
  const isBinary = formatted?.kind === "binary";
  const effective = isBinary ? "hex" : tab;
  const field: "hex" | "text" = effective === "hex" ? "hex" : "text";
  const loadedLength = field === "hex" ? (row?.value_data_hex ?? "").length : [...(row?.value_data_text ?? "")].length;
  const totalLength = Number(field === "hex" ? base?.value_hex_length : base?.value_text_length) || 0;
  const remaining = Boolean(base) && extra.recordId === base?.record_id && loadedLength < totalLength;
  const loadRest = () => {
    if (!base || extra.loading || extra.recordId !== base.record_id) return;
    const request = { recordId: base.record_id, field, extraLength: extra[field].length };
    setExtra((prev) => (prev.recordId === request.recordId ? { ...prev, loading: true, error: null } : prev));
    window.api.registryValueChunk(dbPath, base.record_id, field, loadedLength, VALUE_CHUNK)
      .then((chunk) => setExtra((prev) => applyValueChunk(prev, request, chunk.data)))
      .catch((e) => setExtra((prev) => (prev.recordId === request.recordId ? { ...prev, loading: false, error: String(e) } : prev)));
  };
  const tabButton = (value: "value" | "hex", label: string, disabled = false) => (
    <button type="button" aria-pressed={effective === value} disabled={disabled} onClick={() => setTab(value)} style={{ minHeight: 24, padding: "0 10px", fontSize: 11.5, fontWeight: effective === value ? 650 : 500, border: "none", borderRadius: 6, cursor: disabled ? "default" : "pointer", background: effective === value ? "var(--bg-panel)" : "transparent", boxShadow: effective === value ? "inset 0 0 0 1px var(--border)" : "none", color: disabled ? "var(--text-faint)" : effective === value ? "var(--text)" : "var(--text-dim)" }}>{label}</button>
  );
  return (
    <div aria-label="값 상세" style={{ flex: "0 0 44%", minHeight: 180, display: "flex", flexDirection: "column", borderTop: "1px solid var(--border)", background: "var(--bg-elevated)" }}>
      {!row || !formatted ? (
        <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, padding: 14, color: "var(--text-faint)", fontSize: 12 }}><CircularProgress size={13} thickness={4} />불러오는 중</div>
      ) : (
        <>
          <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 10, padding: "8px 8px 8px 14px", borderBottom: "1px solid var(--border-subtle)" }}>
            <strong style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13, fontStyle: row.value_is_default === "1" ? "italic" : undefined }}>{row.value_is_default === "1" ? "(기본값)" : row.value_name}</strong>
            <TypeBadge typeName={row.value_type_name} />
            <span style={{ fontSize: 11.5, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{Number(row.value_data_length).toLocaleString()} bytes</span>
            {row.value_read_status !== "ok" && <span style={{ fontSize: 11.5, fontWeight: 650, color: row.value_read_status === "error" ? "var(--danger)" : row.value_read_status === "partial" ? "var(--warning)" : "var(--text-faint)" }} title={row.value_read_error || undefined}>{row.value_read_status === "empty" ? "빈 데이터" : row.value_read_status === "partial" ? "일부 읽기" : "읽기 실패"}</span>}
            {remaining && (
              <button type="button" disabled={extra.loading} onClick={loadRest} title={extra.error ?? undefined} style={{ height: 24, padding: "0 10px", fontSize: 11.5, border: `1px solid ${extra.error ? "var(--danger)" : "var(--warning)"}`, borderRadius: 6, background: "transparent", color: extra.error ? "var(--danger)" : "var(--warning)", cursor: "pointer", whiteSpace: "nowrap" }}>
                {extra.loading ? "불러오는 중…" : `나머지 불러오기 · ${(field === "hex" ? loadedLength / 2 : loadedLength).toLocaleString()} / ${(field === "hex" ? totalLength / 2 : totalLength).toLocaleString()}${field === "hex" ? " bytes" : "자"}`}
              </button>
            )}
            <span style={{ marginLeft: "auto", display: "inline-flex", gap: 2, padding: 2, borderRadius: 8, background: "var(--bg-input, var(--bg-panel))" }}>
              {tabButton("value", "값", isBinary)}
              {tabButton("hex", "Hex", bytes.length === 0)}
            </span>
            <Tooltip title={copied === "value" ? "복사됨" : "값 복사"}>
              <IconButton size="small" aria-label="값 복사" onClick={() => copy(formatted.lines ? formatted.lines.join("\n") : formatted.kind === "binary" ? row.value_data_hex : formatted.primary, "value")} sx={{ color: "var(--text-faint)", borderRadius: "var(--radius)" }}>
                {copied === "value" ? <CheckIcon sx={{ fontSize: 15, color: "var(--success)" }} /> : <ContentCopyOutlinedIcon sx={{ fontSize: 15 }} />}
              </IconButton>
            </Tooltip>
            <BookmarkButton row={row} isRowBookmarked={isRowBookmarked} onToggleBookmark={onToggleBookmark} />
            <IconButton size="small" aria-label="값 상세 닫기" onClick={onClose} sx={{ color: "var(--text-faint)", borderRadius: "var(--radius)", fontSize: 16 }}>×</IconButton>
          </div>
          <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14, ...(effective === "hex" ? { display: "flex", flexDirection: "column" } : {}) }}>
            {effective === "hex" ? (
              bytes.length ? <HexViewer bytes={bytes} maxHeight="100%" /> : <span style={{ fontSize: 12.5, color: "var(--text-faint)" }}>데이터 없음</span>
            ) : formatted.kind === "empty" ? (
              <span style={{ fontSize: 12.5, color: "var(--text-faint)" }}>(빈 데이터)</span>
            ) : formatted.kind === "error" ? (
              <span style={{ fontSize: 12.5, color: "var(--danger)" }}>{formatted.primary}</span>
            ) : formatted.kind === "lines" ? (
              <ol style={{ margin: 0, paddingLeft: 0, listStyle: "none", display: "grid", gap: 2, fontFamily: "var(--mono)", fontSize: 12.5 }}>
                {formatted.lines?.map((line, index) => (
                  <li key={index} style={{ display: "grid", gridTemplateColumns: "32px minmax(0, 1fr)", gap: 8 }}>
                    <span style={{ color: "var(--text-faint)", textAlign: "right" }}>{index}</span>
                    <span style={{ wordBreak: "break-all", color: line ? "var(--text)" : "var(--text-faint)" }}>{line || "(빈 문자열)"}</span>
                  </li>
                ))}
              </ol>
            ) : formatted.kind === "number" || formatted.kind === "time" ? (
              <div style={{ display: "grid", gap: 6 }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 18, fontWeight: 650, color: formatted.kind === "time" ? "var(--text-time)" : "var(--text)" }}>{formatted.primary}</span>
                {formatted.secondary && <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }}>FILETIME {formatted.secondary}</span>}
              </div>
            ) : (
              <pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: 1.55, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text)" }}>{formatted.primary || <span style={{ color: "var(--text-faint)" }}>(빈 문자열)</span>}</pre>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ---- quick access -------------------------------------------------------------

const STATUS_TONE: Record<string, string> = { 의심: "var(--danger)", 주의: "var(--warning)" };

const GROUP_ICON: Record<QuickGroupKey, typeof ShieldOutlinedIcon> = {
  autorun: PlayCircleOutlinedIcon,
  security: ShieldOutlinedIcon,
  remote: LanOutlinedIcon,
  activity: PersonOutlinedIcon,
  archive: FolderZipOutlinedIcon,
  install: Inventory2OutlinedIcon,
  shimcache: HistoryOutlinedIcon,
  other: MoreHorizOutlinedIcon,
};

function StatusPill({ status, count }: { status: string; count?: number }) {
  const tone = STATUS_TONE[status];
  if (!tone) return null;
  return (
    <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", gap: 4, height: 18, padding: "0 7px", borderRadius: 999, fontSize: 10.5, fontWeight: 700, color: tone, background: `color-mix(in srgb, ${tone} 14%, transparent)`, border: `1px solid color-mix(in srgb, ${tone} 34%, transparent)`, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
      <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", background: tone }} />
      {status}{count !== undefined && ` ${count.toLocaleString()}`}
    </span>
  );
}

/** "\a\b\c" → name "c" and parent "\a\b"; other names stay whole. */
function splitPathName(name: string): { name: string; parent: string | null } {
  const at = name.lastIndexOf("\\");
  if (at <= 0 || at === name.length - 1) return { name, parent: null };
  return { name: name.slice(at + 1), parent: name.slice(0, at) };
}

function QuickAccessPanel({ quick, error, hiveById, onOpen }: { quick: RegistryQuickAccess | null; error: string | null; hiveById: Map<string, RegistryHive>; onOpen: (recordId: string) => void }) {
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Set<QuickGroupKey> | null>(null);
  const [limits, setLimits] = useState<Record<string, number>>({});
  const [active, setActive] = useState<string | null>(null);
  const needle = filter.trim().toLowerCase();
  const grouped = useMemo(() => {
    const map = new Map<QuickGroupKey, NonNullable<typeof quick>["items"]>();
    for (const item of quick?.items ?? []) {
      const f = item.finding;
      if (needle && ![f.name, f.value, f.key_path, f.category, f.subtype, f.source].some((text) => (text ?? "").toLowerCase().includes(needle))) continue;
      const key = quickGroupOf(f);
      map.set(key, [...(map.get(key) ?? []), item]);
    }
    return map;
  }, [quick, needle]);
  // All groups start collapsed.
  const opened = open ?? new Set<QuickGroupKey>();
  if (error) return <div role="alert" style={{ padding: 12, color: "var(--danger)", fontSize: 12.5 }}>{error}</div>;
  if (!quick) return <div role="status" style={{ display: "flex", alignItems: "center", gap: 6, padding: 12, color: "var(--text-faint)", fontSize: 12 }}><CircularProgress size={13} thickness={4} />불러오는 중</div>;
  if (!quick.available) return <div role="status" style={{ padding: 12, color: "var(--text-faint)", fontSize: 12.5 }}>퀵 접근 데이터 없음</div>;
  const renderGroup = (group: (typeof QUICK_GROUPS)[number]) => {
    const items = grouped.get(group.key) ?? [];
    const isOpen = opened.has(group.key) || Boolean(needle);
    const flagged = (status: string) => items.filter((item) => item.finding.status === status).length;
    const limit = limits[group.key] ?? QUICK_GROUP_PAGE;
    const Icon = GROUP_ICON[group.key];
    return (
      <section key={group.key} aria-label={group.label}>
        <button type="button" aria-expanded={isOpen} onClick={() => setOpen(() => { const next = new Set(opened); if (next.has(group.key)) next.delete(group.key); else next.add(group.key); return next; })}
          onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
          onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
          style={{ width: "100%", display: "flex", alignItems: "center", gap: 7, minHeight: 32, padding: "0 6px", border: "none", borderRadius: 6, background: "transparent", color: "var(--text)", cursor: "pointer", fontSize: 12.5, fontWeight: 650 }}>
          {isOpen ? <KeyboardArrowDownOutlinedIcon sx={{ fontSize: 16, color: "var(--text-faint)" }} /> : <KeyboardArrowRightOutlinedIcon sx={{ fontSize: 16, color: "var(--text-faint)" }} />}
          <Icon sx={{ fontSize: 16, color: "var(--text-dim)" }} />
          {group.label}
          <span style={{ fontSize: 11, fontWeight: 500, color: "var(--text-faint)", fontVariantNumeric: "tabular-nums" }}>{items.length.toLocaleString()}</span>
          <span style={{ marginLeft: "auto", display: "inline-flex", gap: 4 }}>
            {(["의심", "주의"] as const).map((status) => flagged(status) > 0 && <StatusPill key={status} status={status} count={flagged(status)} />)}
          </span>
        </button>
        {isOpen && (
          <div style={{ display: "grid", gap: 3, padding: "2px 0 8px 22px" }}>
            {items.slice(0, limit).map((item) => {
              const f = item.finding;
              const tone = STATUS_TONE[f.status ?? ""];
              const first = item.targets[0];
              const navigable = item.targets.some((target) => isNavigable(target.resolution) && target.target_record_id);
              const selected = active === f.record_id;
              const openTarget = (target: Row | undefined) => { if (target && isNavigable(target.resolution) && target.target_record_id) { setActive(f.record_id); onOpen(target.target_record_id); } };
              const hive = first?.hive_id ? hiveById.get(first.hive_id) : undefined;
              const title = splitPathName(f.name || "");
              const rest = tone ? `color-mix(in srgb, ${tone} 6%, transparent)` : "transparent";
              return (
                <div key={f.record_id} role="button" tabIndex={navigable ? 0 : -1} aria-disabled={!navigable || undefined} title={f.name || undefined}
                  onClick={() => openTarget(item.targets.find((target) => isNavigable(target.resolution)))}
                  onKeyDown={(event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); openTarget(item.targets.find((target) => isNavigable(target.resolution))); } }}
                  onMouseEnter={(event) => { if (navigable && !selected) event.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(event) => { event.currentTarget.style.background = selected ? "var(--bg-selected)" : rest; }}
                  style={{ display: "grid", gap: 3, padding: "7px 9px", borderRadius: 7, cursor: navigable ? "pointer" : "default", background: selected ? "var(--bg-selected)" : rest, border: `1px solid ${selected ? "color-mix(in srgb, var(--accent) 45%, transparent)" : tone ? `color-mix(in srgb, ${tone} 18%, transparent)` : "transparent"}`, opacity: navigable ? 1 : 0.65 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                    {tone && <StatusPill status={f.status ?? ""} />}
                    <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 650 }}>{title.name || "(이름 없음)"}</span>
                    {first && first.resolution !== "exact_value" && <span style={{ flexShrink: 0, marginLeft: "auto", fontSize: 10.5, color: isNavigable(first.resolution) ? "var(--text-dim)" : "var(--warning)" }}>{resolutionLabel(first.resolution)}</span>}
                    {!first && <span style={{ flexShrink: 0, marginLeft: "auto", fontSize: 10.5, color: "var(--warning)" }}>대상 없음</span>}
                  </span>
                  {f.value && <span title={f.value} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}>{f.value}</span>}
                  <span style={{ display: "flex", gap: 8, fontSize: 10.5, color: "var(--text-faint)", minWidth: 0 }}>
                    <span style={{ whiteSpace: "nowrap" }}>{hive ? hiveLabel(hive.hiveName).name : f.source}{hive?.isRegback ? " · RegBack" : ""}</span>
                    {f.account && f.account !== "(시스템)" && <span style={{ whiteSpace: "nowrap" }}>{f.account}</span>}
                    {f.subtype && <span style={{ whiteSpace: "nowrap" }}>{f.subtype}</span>}
                    {title.parent && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{title.parent}</span>}
                  </span>
                  {item.targets.length > 1 && (
                    <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {item.targets.map((target) => (
                        <button key={target.ordinal} type="button" disabled={!isNavigable(target.resolution)} onClick={(event) => { event.stopPropagation(); openTarget(target); }} style={{ fontSize: 10.5, padding: "1px 7px", borderRadius: 999, border: "1px solid var(--border)", background: "transparent", color: "var(--text-dim)", cursor: isNavigable(target.resolution) ? "pointer" : "default" }}>
                          근거 {Number(target.ordinal) + 1} · {resolutionLabel(target.resolution)}
                        </button>
                      ))}
                    </span>
                  )}
                </div>
              );
            })}
            {items.length > limit && (
              <button type="button" onClick={() => setLimits((prev) => ({ ...prev, [group.key]: limit + QUICK_GROUP_PAGE }))} style={{ justifySelf: "start", minHeight: 24, padding: "0 10px", fontSize: 11.5, border: "1px solid var(--border)", borderRadius: 6, background: "transparent", color: "var(--accent)", cursor: "pointer" }}>
                더 보기 · {limit.toLocaleString()} / {items.length.toLocaleString()}
              </button>
            )}
          </div>
        )}
      </section>
    );
  };
  return (
    <div style={{ display: "grid", gap: 2 }}>
      <input value={filter} onChange={(event) => { setFilter(event.target.value); setOpen(null); }} placeholder="퀵 접근 필터" aria-label="퀵 접근 필터" style={{ margin: "0 4px 4px", height: 30, padding: "0 10px", fontSize: 12, background: "var(--bg-input, var(--bg-elevated))", border: "1px solid var(--border)", borderRadius: 7, color: "var(--text)", outline: "none" }} />
      {QUICK_SECTIONS.map((section, index) => {
        const groups = QUICK_GROUPS.filter((group) => group.section === section.key && (grouped.get(group.key) ?? []).length > 0);
        if (!groups.length) return null;
        return (
          <div key={section.key} role="group" aria-label={section.label} style={{ display: "grid", gap: 1, marginTop: index ? 8 : 0, paddingTop: index ? 8 : 0, borderTop: index ? "1px solid var(--border-subtle)" : "none" }}>
            <div style={{ padding: "4px 8px", fontSize: 10.5, fontWeight: 700, letterSpacing: 0.4, color: "var(--text-faint)" }}>{section.label}</div>
            {groups.map(renderGroup)}
          </div>
        );
      })}
    </div>
  );
}

// ---- search ---------------------------------------------------------------------

function Highlight({ text, query }: { text: string; query: string }) {
  if (!query) return <>{text}</>;
  const at = text.toLowerCase().indexOf(query.toLowerCase());
  if (at < 0) return <>{text}</>;
  return <>{text.slice(0, at)}<mark style={{ background: "color-mix(in srgb, var(--accent) 30%, transparent)", color: "inherit", borderRadius: 2 }}>{text.slice(at, at + query.length)}</mark>{text.slice(at + query.length)}</>;
}

function SearchPanel({ hits, query, state, scope, onScope, scopeLabel, fields, onFields, hiveById, onOpen, onMore, onStop }: {
  hits: RegistrySearchHit[];
  query: string;
  state: { running: boolean; cursor: number | null; done: boolean; progress: number; error: string | null };
  scope: "all" | "hive" | "key";
  onScope: (scope: "all" | "hive" | "key") => void;
  scopeLabel: { hive: string | null; key: string | null };
  fields: { keys: boolean; valueNames: boolean; valueData: boolean };
  onFields: (fields: { keys: boolean; valueNames: boolean; valueData: boolean }) => void;
  hiveById: Map<string, RegistryHive>;
  onOpen: (hit: RegistrySearchHit) => void;
  onMore: () => void;
  onStop: () => void;
}) {
  const [active, setActive] = useState<string | null>(null);
  const scopeButton = (value: "all" | "hive" | "key", label: string, disabled: boolean) => (
    <button type="button" aria-pressed={scope === value} disabled={disabled} onClick={() => onScope(value)} title={label}
      style={{ flex: 1, minWidth: 0, minHeight: 26, padding: "0 8px", fontSize: 11.5, fontWeight: scope === value ? 650 : 500, border: "none", borderRadius: 6, cursor: disabled ? "default" : "pointer", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", background: scope === value ? "var(--bg-panel)" : "transparent", boxShadow: scope === value ? "inset 0 0 0 1px var(--border)" : "none", color: disabled ? "var(--text-faint)" : scope === value ? "var(--text)" : "var(--text-dim)" }}>{label}</button>
  );
  const fieldChip = (key: keyof typeof fields, label: string) => {
    const on = fields[key];
    const last = on && Object.values(fields).filter(Boolean).length === 1;
    return <button type="button" aria-pressed={on} disabled={last} onClick={() => onFields({ ...fields, [key]: !on })} style={{ height: 24, padding: "0 10px", fontSize: 11.5, borderRadius: 999, cursor: last ? "default" : "pointer", border: `1px solid ${on ? "var(--accent)" : "var(--border)"}`, background: on ? "var(--accent-subtle)" : "transparent", color: on ? "var(--accent)" : "var(--text-dim)" }}>{label}</button>;
  };
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div style={{ display: "grid", gap: 6, padding: "0 4px" }}>
        <div role="group" aria-label="검색 범위" style={{ display: "flex", gap: 2, padding: 2, borderRadius: 8, background: "var(--bg-input, var(--bg-elevated))" }}>
          {scopeButton("all", "전체 하이브", false)}
          {scopeButton("hive", scopeLabel.hive ? `하이브 · ${scopeLabel.hive}` : "선택 하이브", !scopeLabel.hive)}
          {scopeButton("key", scopeLabel.key ? `키 아래 · ${scopeLabel.key}` : "선택 키 아래", !scopeLabel.key)}
        </div>
        <div role="group" aria-label="검색 대상" style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {fieldChip("keys", "키 경로")}
          {fieldChip("valueNames", "값 이름")}
          {fieldChip("valueData", "값 데이터")}
        </div>
        <div style={{ display: "grid", gap: 4 }}>
          <div aria-hidden="true" style={{ height: 3, borderRadius: 999, background: "var(--border-subtle)", overflow: "hidden" }}>
            <div style={{ width: `${Math.round(state.progress * 100)}%`, height: "100%", background: state.done ? "var(--success)" : "var(--accent)", transition: "width .2s ease" }} />
          </div>
          <div role="status" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11.5, color: "var(--text-dim)" }}>
            {state.running && <CircularProgress size={11} thickness={5} sx={{ color: "var(--accent)" }} />}
            <span style={{ fontVariantNumeric: "tabular-nums" }}>{hits.length.toLocaleString()}건{state.done ? "" : "+"}</span>
            <span style={{ color: "var(--text-faint)" }}>{state.done ? "검색 완료" : state.running ? `${Math.round(state.progress * 100)}% 검색 중` : state.cursor !== null ? `${Math.round(state.progress * 100)}%에서 멈춤` : ""}</span>
            {state.running
              ? <button type="button" onClick={onStop} style={{ marginLeft: "auto", height: 22, padding: "0 8px", fontSize: 11, border: "1px solid var(--border)", borderRadius: 6, background: "transparent", color: "var(--text-dim)", cursor: "pointer" }}>중지</button>
              : !state.done && state.cursor !== null && <button type="button" onClick={onMore} style={{ marginLeft: "auto", height: 22, padding: "0 8px", fontSize: 11, border: "1px solid var(--accent)", borderRadius: 6, background: "transparent", color: "var(--accent)", cursor: "pointer" }}>더 찾기</button>}
          </div>
          {state.error && <div role="alert" style={{ fontSize: 11.5, color: "var(--danger)" }}>{state.error}</div>}
        </div>
      </div>
      <div style={{ display: "grid", gap: 1 }}>
        {hits.map((hit) => {
          const hive = hiveById.get(hit.hiveId);
          const path = displayRegistryKeyPath(hit.keyPath, hive?.hiveName);
          const selected = active === hit.recordId;
          return (
            <button key={hit.recordId} type="button" onClick={() => { setActive(hit.recordId); onOpen(hit); }}
              onMouseEnter={(event) => { if (!selected) event.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(event) => { event.currentTarget.style.background = selected ? "var(--bg-selected)" : "transparent"; }}
              style={{ display: "grid", gap: 3, padding: "7px 8px", border: "none", borderRadius: 6, background: selected ? "var(--bg-selected)" : "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left" }}>
              <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                {hit.entryKind === "key" ? <FolderOutlinedIcon sx={{ fontSize: 14, color: "var(--text-faint)", flexShrink: 0 }} /> : <BoltOutlinedIcon sx={{ fontSize: 14, color: "var(--text-faint)", flexShrink: 0 }} />}
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: 650 }}>
                  {hit.entryKind === "key" ? <Highlight text={hit.keyPath?.split("\\").pop() ?? ""} query={query} /> : <Highlight text={hit.valueDisplayName ?? hit.valueName ?? ""} query={query} />}
                </span>
                <span style={{ marginLeft: "auto", display: "inline-flex", gap: 4, flexShrink: 0 }}>
                  {hit.fields.map((field) => <span key={field} style={{ fontSize: 10, color: "var(--accent)", background: "var(--accent-subtle)", borderRadius: 4, padding: "0 5px" }}>{SEARCH_FIELD_LABELS[field] ?? field}</span>)}
                </span>
              </span>
              <span title={path} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", direction: "rtl", textAlign: "left", fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)" }}>
                <bdi>{path}</bdi>
              </span>
              {hit.snippet && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" }}><Highlight text={hit.snippet} query={hit.fields.includes("value_hex") && !hit.fields.includes("value_data") ? query.replace(/\s+/g, "") : query} /></span>}
              <span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>{hive ? `${hiveLabel(hive.hiveName).name}${hiveLabel(hive.hiveName).owner ? ` · ${hiveLabel(hive.hiveName).owner}` : ""}${hive.isRegback ? " · RegBack" : ""}` : hit.hiveId}</span>
            </button>
          );
        })}
        {state.done && hits.length === 0 && <div role="status" style={{ padding: "14px 8px", color: "var(--text-faint)", fontSize: 12.5 }}>일치 결과 없음</div>}
      </div>
    </div>
  );
}
