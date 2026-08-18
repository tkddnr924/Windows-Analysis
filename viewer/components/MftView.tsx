"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Bookmark } from "@/lib/types";

// $MFT Explorer. The table can hold ~1M rows, so nothing is loaded up front:
// folders load their children on expand, and search hits are queried straight
// from SQLite (window.api.mft*). Timestamps are hidden in the tree (Explorer-
// like) and shown only in the detail panel, where each of the eight SI/FN
// times can be bookmarked independently.

type Row = Record<string, string>;

const ROOT_ENTRY = 5;

interface Props {
  dbPath: string;
  /** Bookmarks already scoped to this MFT table — used to show which records
   *  (and which specific timestamps) are starred. */
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

export default function MftView({ dbPath, tableBookmarks, onToggleBookmark }: Props) {
  const [root, setRoot] = useState<Row[] | null>(null);
  const [childrenCache, setChildrenCache] = useState<Record<string, Row[]>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loadingEntry, setLoadingEntry] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<Row | null>(null);

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

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "16px 20px 10px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10 }}>
          <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🗂️ $MFT 파일 탐색기</span>
          <span style={{ fontSize: 12, color: "var(--text-faint)" }}>폴더를 펼쳐 탐색하고, 클릭하면 타임스탬프 등 상세를 봅니다.</span>
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
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "0 12px 16px" }}>
        {results !== null ? (
          <SearchResults rows={results} searching={searching} bmRowids={bmRowids} onOpen={setDetail} />
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
              onToggle={toggle}
              onOpen={setDetail}
            />
          ))
        )}
      </div>

      {detail && (
        <MftDetail
          row={detail}
          onClose={() => setDetail(null)}
          bmFieldKeys={bmFieldKeys}
          onToggleBookmark={onToggleBookmark}
        />
      )}
    </div>
  );
}

function rowIcon(r: Row, isOpen: boolean): string {
  if (isDir(r)) return isOpen ? "📂" : "📁";
  return "📄";
}

function TreeNode({
  row,
  depth,
  expanded,
  childrenCache,
  loadingEntry,
  bmRowids,
  onToggle,
  onOpen,
}: {
  row: Row;
  depth: number;
  expanded: Set<string>;
  childrenCache: Record<string, Row[]>;
  loadingEntry: Set<string>;
  bmRowids: Set<number>;
  onToggle: (r: Row) => void;
  onOpen: (r: Row) => void;
}) {
  const dir = isDir(row);
  const open = expanded.has(row.entry);
  const kids = childrenCache[row.entry];
  const deleted = row.in_use === "N";
  const bm = bmRowids.has(Number(row.__rowid));

  return (
    <>
      <div
        onClick={() => (dir ? onToggle(row) : onOpen(row))}
        onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 6px", paddingLeft: 6 + depth * 16, borderRadius: "var(--radius-sm)", cursor: "pointer", opacity: deleted ? 0.55 : 1 }}
        title={dir ? "클릭: 펼치기/접기" : "클릭: 상세 보기"}
      >
        <span style={{ width: 12, textAlign: "center", color: "var(--text-faint)", fontSize: 10 }}>{dir ? (open ? "▾" : "▸") : ""}</span>
        <span style={{ fontSize: 13 }}>{rowIcon(row, open)}</span>
        <span style={{ fontSize: 12.5, color: "var(--text)", wordBreak: "break-all" }}>{row.file_name || "(이름 없음)"}</span>
        {deleted && <span style={{ fontSize: 9.5, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: 3, padding: "0 4px" }}>삭제됨</span>}
        {bm && <span style={{ fontSize: 11, color: "var(--warning)" }}>★</span>}
        {!dir && <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{fmtSize(row.file_size)}</span>}
        {dir && (
          <span
            onClick={(e) => {
              e.stopPropagation();
              onOpen(row);
            }}
            title="폴더 상세 보기"
            style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-faint)", cursor: "pointer" }}
          >
            상세
          </span>
        )}
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
              onToggle={onToggle}
              onOpen={onOpen}
            />
          ))
        )
      )}
    </>
  );
}

function SearchResults({ rows, searching, bmRowids, onOpen }: { rows: Row[]; searching: boolean; bmRowids: Set<number>; onOpen: (r: Row) => void }) {
  if (searching && rows.length === 0) return <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>검색 중...</div>;
  if (rows.length === 0) return <div style={{ padding: 16, color: "var(--text-faint)", fontSize: 12.5 }}>일치하는 항목이 없습니다.</div>;
  return (
    <div style={{ paddingTop: 4 }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)", padding: "4px 8px" }}>검색 결과 {rows.length}건{rows.length >= 500 ? " (상위 500건)" : ""}</div>
      {rows.map((r) => {
        const deleted = r.in_use === "N";
        return (
          <div
            key={r.entry + "-" + r.__rowid}
            onClick={() => onOpen(r)}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            style={{ padding: "5px 8px", borderRadius: "var(--radius-sm)", cursor: "pointer", opacity: deleted ? 0.55 : 1 }}
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

function MftDetail({ row, onClose, bmFieldKeys, onToggleBookmark }: { row: Row; onClose: () => void; bmFieldKeys: Set<string>; onToggleBookmark: (rowid: number, field: string) => void }) {
  const dir = isDir(row);
  const rowid = Number(row.__rowid);
  const meta: [string, string][] = [
    ["경로", row.path],
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
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0", borderTop: "1px solid var(--border-subtle)" }}>
        <span style={{ flex: "0 0 150px", fontSize: 12, color: "var(--text-faint)" }}>{f.label}</span>
        <span style={{ flex: 1, fontSize: 12.5, fontFamily: "var(--mono)", color: val ? "var(--text)" : "var(--text-faint)" }}>{val || "—"}</span>
        {val && (
          <button
            onClick={() => onToggleBookmark(rowid, f.key)}
            title={isBm ? "이 시각 북마크 해제" : "이 시각 북마크"}
            style={{ flexShrink: 0, fontSize: 11, padding: "2px 8px", borderRadius: "var(--radius-lg)", cursor: "pointer", background: isBm ? "var(--warning-subtle)" : "transparent", color: isBm ? "var(--warning)" : "var(--text-dim)", border: `1px solid ${isBm ? "var(--warning)" : "var(--border)"}`, fontWeight: 600 }}
          >
            {isBm ? "★" : "☆"}
          </button>
        )}
      </div>
    );
  };

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 680, maxWidth: "100%", maxHeight: "86vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--border)", position: "sticky", top: 0, background: "var(--bg-panel)" }}>
          <span style={{ fontSize: 16 }}>{rowIcon(row, false)}</span>
          <span style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>{row.file_name || "(이름 없음)"}</span>
          {row.in_use === "N" && <span style={{ fontSize: 10, fontWeight: 700, color: "var(--danger)", border: "1px solid var(--danger)", borderRadius: 3, padding: "0 5px" }}>삭제됨</span>}
          <button onClick={onClose} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ padding: "14px 18px 18px" }}>
          {meta.filter(([, v]) => v).map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ flex: "0 0 130px", color: "var(--text-faint)", fontSize: 12 }}>{k}</span>
              <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: /경로|확장자|엔트리|부모/.test(k) ? "var(--mono)" : undefined }}>{v}</span>
            </div>
          ))}

          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "16px 0 2px" }}>
            $STANDARD_INFORMATION (0x10) <span style={{ fontWeight: 400 }}>· 각 시각을 개별 북마크할 수 있습니다</span>
          </div>
          {TIME_FIELDS.map((f) => <TimeRow key={f.key} f={f} />)}

          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "16px 0 2px" }}>$FILE_NAME (0x30)</div>
          {FN_FIELDS.map((f) => <TimeRow key={f.key} f={f} />)}
        </div>
      </div>
    </div>
  );
}
