"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Bookmark, PathReference } from "@/lib/types";

// $MFT Explorer — a two-pane view: a lazily-loaded folder tree on the left,
// a live detail panel on the right that updates as you click rows (files AND
// folders), so inspecting a folder's timestamps is a single click. The table
// can hold ~1M rows, so nothing is loaded up front: folders load their
// children on expand and search hits query SQLite directly (window.api.mft*).
// Each of a record's eight SI/FN timestamps can be bookmarked independently.

type Row = Record<string, string>;

const ROOT_ENTRY = 5;

interface Props {
  dbPath: string;
  /** Bookmarks already scoped to this MFT table — which records (and which
   *  specific timestamps) are starred. */
  tableBookmarks: Bookmark[];
  onToggleBookmark: (rowid: number, field: string) => void;
}

const TIME_FIELDS: { key: string; label: string }[] = [
  { key: "si_created", label: "생성 (Created)" },
  { key: "si_modified", label: "수정 (Modified)" },
  { key: "si_mft_modified", label: "MFT 수정 (Changed)" },
  { key: "si_accessed", label: "접근 (Accessed)" },
];
const FN_FIELDS: { key: string; label: string }[] = [
  { key: "fn_created", label: "생성 (Created)" },
  { key: "fn_modified", label: "수정 (Modified)" },
  { key: "fn_mft_modified", label: "MFT 수정 (Changed)" },
  { key: "fn_accessed", label: "접근 (Accessed)" },
];

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
function rowIcon(r: Row, isOpen: boolean): string {
  if (isDir(r)) return isOpen ? "📂" : "📁";
  return "📄";
}

export default function MftView({ dbPath, tableBookmarks, onToggleBookmark }: Props) {
  const [root, setRoot] = useState<Row[] | null>(null);
  const [childrenCache, setChildrenCache] = useState<Record<string, Row[]>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loadingEntry, setLoadingEntry] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Row | null>(null);
  // Cross-artifact sightings of a path (JumpList today), indexed by lowercased
  // path so the tree can tag rows without a query per row.
  const [pathRefs, setPathRefs] = useState<RefMap>(new Map());
  const [refModal, setRefModal] = useState<PathReference | null>(null);
  // Accounts seen across all references, and which are currently shown. An
  // investigator can uncheck accounts unrelated to the attack so their
  // JumpList/Shellbag tags stop cluttering the tree.
  const [refAccounts, setRefAccounts] = useState<string[]>([]);
  const [selAccounts, setSelAccounts] = useState<Set<string>>(new Set());

  useEffect(() => {
    let alive = true;
    window.api.pathReferences(hostDirOf(dbPath)).then((list) => {
      if (!alive) return;
      const m: RefMap = new Map();
      const accts = new Set<string>();
      for (const r of list) {
        const arr = m.get(r.path);
        if (arr) arr.push(r); else m.set(r.path, [r]);
        accts.add(r.account);
      }
      const sorted = [...accts].sort((a, b) => a.localeCompare(b));
      setPathRefs(m);
      setRefAccounts(sorted);
      setSelAccounts(new Set(sorted)); // default: all accounts shown
    }).catch(() => {});
    return () => { alive = false; };
  }, [dbPath]);

  const toggleAccount = useCallback((acct: string) => {
    setSelAccounts((s) => { const n = new Set(s); if (n.has(acct)) n.delete(acct); else n.add(acct); return n; });
  }, []);

  const [search, setSearch] = useState("");
  const [results, setResults] = useState<Row[] | null>(null);
  const [searching, setSearching] = useState(false);
  const searchSeq = useRef(0);

  useEffect(() => {
    let cancelled = false;
    window.api.mftChildren(dbPath, ROOT_ENTRY).then((rows) => {
      if (!cancelled) setRoot(rows);
    });
    return () => {
      cancelled = true;
    };
  }, [dbPath]);

  const loadChildren = useCallback(
    async (entry: string) => {
      if (childrenCache[entry]) return;
      setLoadingEntry((s) => new Set(s).add(entry));
      const rows = await window.api.mftChildren(dbPath, Number(entry));
      setChildrenCache((c) => ({ ...c, [entry]: rows }));
      setLoadingEntry((s) => {
        const n = new Set(s);
        n.delete(entry);
        return n;
      });
    },
    [dbPath, childrenCache],
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
    const q = search.trim();
    if (q.length < 2) {
      setResults(null);
      setSearching(false);
      return;
    }
    setSearching(true);
    const seq = ++searchSeq.current;
    const t = setTimeout(() => {
      window.api.mftSearch(dbPath, q, 500).then((rows) => {
        if (seq === searchSeq.current) {
          setResults(rows);
          setSearching(false);
        }
      });
    }, 250);
    return () => clearTimeout(t);
  }, [search, dbPath]);

  const bmRowids = useMemo(() => new Set(tableBookmarks.map((b) => b.rowid)), [tableBookmarks]);
  const bmFieldKeys = useMemo(() => new Set(tableBookmarks.map((b) => `${b.rowid}@${b.field ?? ""}`)), [tableBookmarks]);
  const selectedRowid = selected ? Number(selected.__rowid) : null;

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "16px 20px 10px", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10 }}>
          <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🗂️ $MFT 파일 탐색기</span>
          <span style={{ fontSize: 12, color: "var(--text-faint)" }}>폴더 왼쪽 화살표로 펼치고, 행을 클릭하면 오른쪽에 상세가 표시됩니다.</span>
        </div>
        <div style={{ position: "relative", maxWidth: 460 }}>
          <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)", pointerEvents: "none" }}>🔍</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="파일명 · 경로 검색 (2자 이상)"
            style={{ width: "100%", padding: "7px 26px 7px 30px", fontSize: 12.5, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
          />
          {search && (
            <span onClick={() => setSearch("")} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", cursor: "pointer", color: "var(--text-faint)", fontSize: 13 }}>✕</span>
          )}
        </div>
        {refAccounts.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
            <span style={{ fontSize: 11, color: "var(--text-faint)" }}>👤 JumpList/Shellbag 계정:</span>
            {refAccounts.map((a) => {
              const on = selAccounts.has(a);
              return (
                <label key={a || "(none)"} style={{ display: "inline-flex", alignItems: "center", gap: 4, cursor: "pointer", fontSize: 11.5, fontWeight: 600, padding: "2px 8px", borderRadius: "var(--radius-lg)", border: `1px solid ${on ? "var(--accent)" : "var(--border)"}`, color: on ? "var(--accent)" : "var(--text-faint)", background: on ? "var(--accent-subtle, transparent)" : "transparent" }}>
                  <input type="checkbox" checked={on} onChange={() => toggleAccount(a)} style={{ accentColor: "var(--accent)", width: 12, height: 12 }} />
                  {a || "(계정 미상)"}
                </label>
              );
            })}
          </div>
        )}
      </div>

      <div style={{ flex: 1, minHeight: 0, display: "flex", borderTop: "1px solid var(--border)" }}>
        {/* left: Explorer (60%) */}
        <div style={{ flex: 6, minWidth: 0, overflow: "auto", padding: "8px 10px 16px" }}>
          {results !== null ? (
            <SearchResults rows={results} searching={searching} bmRowids={bmRowids} selectedRowid={selectedRowid} onSelect={setSelected} />
          ) : root === null ? (
            <div style={{ padding: 20, color: "var(--text-dim)" }}>불러오는 중...</div>
          ) : (
            root.map((r) => (
              <TreeNode
                key={r.entry + "-" + r.__rowid}
                row={r}
                depth={0}
                expanded={expanded}
                childrenCache={childrenCache}
                loadingEntry={loadingEntry}
                bmRowids={bmRowids}
                selectedRowid={selectedRowid}
                onToggle={toggle}
                onSelect={setSelected}
                refs={pathRefs}
                accountFilter={selAccounts}
              />
            ))
          )}
        </div>

        {/* right: live detail (40%) */}
        <div style={{ flex: 4, minWidth: 320, overflow: "auto", borderLeft: "1px solid var(--border)", background: "var(--bg-panel)" }}>
          {selected ? (
            <DetailPane row={selected} bmFieldKeys={bmFieldKeys} onToggleBookmark={onToggleBookmark} refs={refsFor(pathRefs, selected, selAccounts)} onOpenRef={setRefModal} />
          ) : (
            <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5, textAlign: "center", marginTop: 40 }}>
              왼쪽에서 파일·폴더를 클릭하면
              <br />
              여기에 상세 정보가 표시됩니다.
            </div>
          )}
        </div>
      </div>
      {refModal && <RefModal ref={refModal} onClose={() => setRefModal(null)} />}
    </div>
  );
}

function TreeNode({
  row,
  depth,
  expanded,
  childrenCache,
  loadingEntry,
  bmRowids,
  selectedRowid,
  onToggle,
  onSelect,
  refs,
  accountFilter,
}: {
  row: Row;
  depth: number;
  expanded: Set<string>;
  childrenCache: Record<string, Row[]>;
  loadingEntry: Set<string>;
  bmRowids: Set<number>;
  selectedRowid: number | null;
  onToggle: (r: Row) => void;
  onSelect: (r: Row) => void;
  refs: RefMap;
  accountFilter: Set<string> | null;
}) {
  const dir = isDir(row);
  const open = expanded.has(row.entry);
  const kids = childrenCache[row.entry];
  const deleted = row.in_use === "N";
  const bm = bmRowids.has(Number(row.__rowid));
  const isSel = selectedRowid !== null && Number(row.__rowid) === selectedRowid;

  // Clicking a folder row selects it AND toggles open/closed — click to open,
  // click again to collapse (the little arrow does the same).
  const handleRowClick = () => { onSelect(row); if (dir) onToggle(row); };

  // (account, kind) chips for other artifacts that reference this exact path,
  // de-duplicated (a path can appear many times in one JumpList).
  const rowTags = (() => {
    const seen = new Set<string>();
    const out: { account: string; kind: string }[] = [];
    for (const r of refsFor(refs, row, accountFilter)) {
      const key = `${r.account}|${r.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ account: r.account, kind: r.kind });
    }
    return out;
  })();

  return (
    <>
      <div
        onClick={handleRowClick}
        style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 6px", paddingLeft: 6 + depth * 16, borderRadius: "var(--radius-sm)", cursor: "pointer", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent" }}
        onMouseEnter={(e) => { if (!isSel) e.currentTarget.style.background = "var(--bg-hover)"; }}
        onMouseLeave={(e) => { if (!isSel) e.currentTarget.style.background = "transparent"; }}
        title={dir ? "클릭: 열기 + 상세 · 화살표: 접기/펼치기" : "클릭: 상세 보기"}
      >
        <span
          onClick={(e) => {
            if (dir) {
              e.stopPropagation();
              onToggle(row);
            }
          }}
          style={{ width: 14, textAlign: "center", color: "var(--text-faint)", fontSize: 10, cursor: dir ? "pointer" : "default" }}
        >
          {dir ? (open ? "▾" : "▸") : ""}
        </span>
        <span style={{ fontSize: 13 }}>{rowIcon(row, open)}</span>
        <span style={{ fontSize: 12.5, color: "var(--text)", wordBreak: "break-all" }}>{row.file_name || "(이름 없음)"}</span>
        {deleted && <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: 3, padding: "0 4px" }}>삭제됨</span>}
        {bm && <span style={{ fontSize: 11, color: "var(--warning)" }}>★</span>}
        {rowTags.map((t, i) => (
          <span key={i} title={`${t.account || "?"} 계정의 ${t.kind}`} style={{ fontSize: 9.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: 3, padding: "0 4px", whiteSpace: "nowrap" }}>
            {t.account ? `${t.account}, ${t.kind}` : t.kind}
          </span>
        ))}
        {!dir && <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{fmtSize(row.file_size)}</span>}
      </div>
      {dir && open && (
        loadingEntry.has(row.entry) && !kids ? (
          <div style={{ paddingLeft: 6 + (depth + 1) * 16 + 18, fontSize: 11.5, color: "var(--text-faint)", padding: "2px 0" }}>불러오는 중...</div>
        ) : kids && kids.length === 0 ? (
          <div style={{ paddingLeft: 6 + (depth + 1) * 16 + 18, fontSize: 11.5, color: "var(--text-faint)" }}>(비어 있음)</div>
        ) : (
          (kids ?? []).map((c) => (
            <TreeNode
              key={c.entry + "-" + c.__rowid}
              row={c}
              depth={depth + 1}
              expanded={expanded}
              childrenCache={childrenCache}
              loadingEntry={loadingEntry}
              bmRowids={bmRowids}
              selectedRowid={selectedRowid}
              onToggle={onToggle}
              onSelect={onSelect}
              refs={refs}
              accountFilter={accountFilter}
            />
          ))
        )
      )}
    </>
  );
}

function SearchResults({ rows, searching, bmRowids, selectedRowid, onSelect }: { rows: Row[]; searching: boolean; bmRowids: Set<number>; selectedRowid: number | null; onSelect: (r: Row) => void }) {
  if (searching && rows.length === 0) return <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>검색 중...</div>;
  if (rows.length === 0) return <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>일치하는 항목이 없습니다.</div>;
  return (
    <div style={{ paddingTop: 4 }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)", padding: "4px 8px" }}>검색 결과 {rows.length}건{rows.length >= 500 ? " (상위 500건)" : ""}</div>
      {rows.map((r) => {
        const deleted = r.in_use === "N";
        const isSel = selectedRowid !== null && Number(r.__rowid) === selectedRowid;
        return (
          <div
            key={r.entry + "-" + r.__rowid}
            onClick={() => onSelect(r)}
            onMouseEnter={(e) => { if (!isSel) e.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(e) => { if (!isSel) e.currentTarget.style.background = "transparent"; }}
            style={{ padding: "5px 8px", borderRadius: "var(--radius-sm)", cursor: "pointer", opacity: deleted ? 0.55 : 1, background: isSel ? "var(--bg-selected)" : "transparent" }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 13 }}>{rowIcon(r, false)}</span>
              <span style={{ fontSize: 12.5, color: "var(--text)", wordBreak: "break-all" }}>{r.file_name || "(이름 없음)"}</span>
              {deleted && <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: 3, padding: "0 4px" }}>삭제됨</span>}
              {bmRowids.has(Number(r.__rowid)) && <span style={{ fontSize: 11, color: "var(--warning)" }}>★</span>}
            </div>
            <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 1, wordBreak: "break-all" }}>{r.path}</div>
          </div>
        );
      })}
    </div>
  );
}

function DetailPane({ row, bmFieldKeys, onToggleBookmark, refs, onOpenRef }: { row: Row; bmFieldKeys: Set<string>; onToggleBookmark: (rowid: number, field: string) => void; refs: PathReference[]; onOpenRef: (r: PathReference) => void }) {
  const dir = isDir(row);
  const rowid = Number(row.__rowid);
  const meta: [string, string][] = [
    ["종류", dir ? "폴더" : "파일"],
    ["크기", dir ? "" : fmtSize(row.file_size) || "0 B"],
    ["확장자", row.extension],
    ["사용 중", row.in_use === "Y" ? "예 (할당됨)" : "아니오 (삭제됨)"],
    ["엔트리 / 시퀀스", `${row.entry} / ${row.seq}`],
    ["부모 엔트리", row.parent_entry],
  ];

  const TimeRow = ({ f }: { f: { key: string; label: string } }) => {
    const val = row[f.key] || "";
    const isBm = bmFieldKeys.has(`${rowid}@${f.key}`);
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0", borderTop: "1px solid var(--border-subtle)" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{f.label}</div>
          <div style={{ fontSize: 11.5, fontFamily: "var(--mono)", color: val ? "var(--text)" : "var(--text-faint)", wordBreak: "break-all" }}>{val || "—"}</div>
        </div>
        {val && (
          <button
            onClick={() => onToggleBookmark(rowid, f.key)}
            title={isBm ? "이 시각 북마크 해제" : "이 시각 북마크"}
            style={{ flexShrink: 0, fontSize: 12, padding: "2px 8px", borderRadius: "var(--radius-lg)", cursor: "pointer", background: isBm ? "var(--warning-subtle)" : "transparent", color: isBm ? "var(--warning)" : "var(--text-dim)", border: `1px solid ${isBm ? "var(--warning)" : "var(--border)"}`, fontWeight: 600 }}
          >
            {isBm ? "★" : "☆"}
          </button>
        )}
      </div>
    );
  };

  return (
    <div style={{ padding: "14px 16px 18px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 16 }}>{rowIcon(row, false)}</span>
        <span style={{ fontSize: 14, fontWeight: 700, wordBreak: "break-all" }}>{row.file_name || "(이름 없음)"}</span>
        {row.in_use === "N" && <span style={{ fontSize: 10, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: 3, padding: "0 5px" }}>삭제됨</span>}
      </div>
      <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", wordBreak: "break-all", marginBottom: 12 }}>{row.path}</div>

      {meta.filter(([, v]) => v).map(([k, v]) => (
        <div key={k} style={{ display: "flex", gap: 10, padding: "5px 0", borderBottom: "1px solid var(--border-subtle)" }}>
          <span style={{ flex: "0 0 96px", color: "var(--text-faint)", fontSize: 11.5 }}>{k}</span>
          <span style={{ flex: 1, color: "var(--text)", fontSize: 12, wordBreak: "break-all", fontFamily: /확장자|엔트리|부모/.test(k) ? "var(--mono)" : undefined }}>{v}</span>
        </div>
      ))}

      <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", margin: "14px 0 0" }}>$STANDARD_INFORMATION (0x10)</div>
      <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 2 }}>각 시각을 개별 북마크할 수 있습니다</div>
      {TIME_FIELDS.map((f) => <TimeRow key={f.key} f={f} />)}

      <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--text-faint)", margin: "14px 0 2px" }}>$FILE_NAME (0x30)</div>
      {FN_FIELDS.map((f) => <TimeRow key={f.key} f={f} />)}

      {refs.length > 0 && (
        <>
          <div style={{ fontSize: 10.5, fontWeight: 700, color: "var(--accent)", margin: "16px 0 2px" }}>
            다른 아티팩트에서 발견 ({refs.length})
          </div>
          <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 4 }}>클릭하면 상세 내용을 볼 수 있습니다</div>
          {refs.map((r, i) => (
            <div
              key={i}
              onClick={() => onOpenRef(r)}
              style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", marginBottom: 4, borderRadius: "var(--radius-sm)", cursor: "pointer", border: "1px solid var(--border)", background: "var(--bg-elevated)" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-elevated)")}
            >
              <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: 3, padding: "0 4px", whiteSpace: "nowrap" }}>{r.kind}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11.5, color: "var(--text)" }}>{r.account || "(계정 미상)"}</div>
                {r.label && <div style={{ fontSize: 10, color: "var(--text-faint)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{r.label}</div>}
              </div>
              <span style={{ fontSize: 12, color: "var(--text-faint)" }}>›</span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// Modal showing all raw fields of one cross-artifact reference.
function RefModal({ ref: r, onClose }: { ref: PathReference; onClose: () => void }) {
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ width: "min(680px, 90vw)", maxHeight: "82vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", padding: 20 }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: 3, padding: "1px 6px" }}>{r.kind}</span>
          <span style={{ fontSize: 15, fontWeight: 700 }}>{r.account || "(계정 미상)"}</span>
          <button onClick={onClose} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>✕</button>
        </div>
        {Object.entries(r.fields).map(([k, v]) => (
          <div key={k} style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--border-subtle)" }}>
            <span style={{ flex: "0 0 150px", color: "var(--text-faint)", fontSize: 11.5, fontFamily: "var(--mono)" }}>{k}</span>
            <span style={{ flex: 1, color: "var(--text)", fontSize: 12, wordBreak: "break-all", fontFamily: "var(--mono)" }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
