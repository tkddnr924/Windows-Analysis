"use client";

import { useMemo, useState } from "react";
import type { Host, SearchHit } from "@/lib/types";
import { getArtifactView } from "@/lib/artifactViews";

interface Props {
  hosts: Host[];
  currentHostId: string | null;
  onOpenHit: (hit: SearchHit) => void;
}

// Case-wide substring search across every host's every table. The heavy lifting
// (scanning all SQLite files) happens in the main process; this is just the
// query box + grouped results.
export default function CaseSearchView({ hosts, currentHostId, onOpenHit }: Props) {
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [ran, setRan] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);

  async function run() {
    const q = query.trim();
    if (q.length < 2) return;
    setBusy(true);
    try {
      const res = await window.api.searchCase(q, hosts.map((h) => ({ id: h.id, name: h.name, dir: h.dir })));
      setHits(res);
      setRan(q);
    } finally {
      setBusy(false);
    }
  }

  // Group hits by host → table for a scannable result tree.
  const groups = useMemo(() => {
    const byHost = new Map<string, { hostId: string; hostName: string; tables: Map<string, SearchHit[]> }>();
    for (const h of hits) {
      const key = h.hostId || h.hostName;
      let g = byHost.get(key);
      if (!g) {
        g = { hostId: h.hostId, hostName: h.hostName || "(알 수 없는 호스트)", tables: new Map() };
        byHost.set(key, g);
      }
      const t = g.tables.get(h.tableName) ?? [];
      t.push(h);
      g.tables.set(h.tableName, t);
    }
    return [...byHost.values()].sort((a, b) => (a.hostId === currentHostId ? -1 : b.hostId === currentHostId ? 1 : a.hostName.localeCompare(b.hostName)));
  }, [hits, currentHostId]);

  const capped = hits.length >= 600;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0, minWidth: 0 }}>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0 }}>
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 8 }}>🔍 케이스 전체 검색</div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ position: "relative", flex: "1 1 320px", maxWidth: 480 }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 13, color: "var(--text-faint)" }}>🔍</span>
            <input
              value={query}
              autoFocus
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="IP · 계정 · 파일명 · 명령 등 (모든 호스트·테이블 검색)"
              style={{ width: "100%", padding: "8px 12px 8px 32px", fontSize: 13, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
            />
          </div>
          <button
            onClick={run}
            disabled={busy || query.trim().length < 2}
            style={{ padding: "8px 16px", fontSize: 13, fontWeight: 600, borderRadius: "var(--radius-md)", cursor: busy || query.trim().length < 2 ? "default" : "pointer", border: "1px solid var(--accent)", background: "var(--accent-subtle)", color: "var(--accent)", opacity: busy || query.trim().length < 2 ? 0.5 : 1 }}
          >
            {busy ? "검색 중…" : "검색"}
          </button>
          <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>모든 호스트의 모든 테이블에서 값을 포함하는 행을 찾습니다.</span>
        </div>
        {ran && !busy && (
          <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
            <b style={{ color: "var(--text)" }}>&quot;{ran}&quot;</b> · {hits.length.toLocaleString()}건{capped ? "+ (상한 도달, 검색어를 좁혀보세요)" : ""}
          </div>
        )}
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {busy && <div style={{ padding: 30, textAlign: "center", color: "var(--text-dim)" }}>모든 호스트를 검색하는 중…</div>}
        {!busy && ran && hits.length === 0 && <div style={{ padding: 30, textAlign: "center", color: "var(--text-faint)" }}>일치하는 행이 없습니다.</div>}
        {!busy && !ran && <div style={{ padding: 30, textAlign: "center", color: "var(--text-faint)" }}>검색어를 입력하고 Enter를 누르세요 (2자 이상).</div>}

        {!busy && groups.map((g) => (
          <div key={g.hostId || g.hostName}>
            <div style={{ position: "sticky", top: 0, zIndex: 2, display: "flex", alignItems: "center", gap: 8, padding: "7px 14px", background: "var(--bg-elevated)", borderBottom: "1px solid var(--border)", fontSize: 12, fontWeight: 700, color: "var(--text-dim)" }}>
              🖥️ {g.hostName}
              <span style={{ color: "var(--text-faint)", fontWeight: 400 }}>{[...g.tables.values()].reduce((n, t) => n + t.length, 0)}건</span>
              {g.hostId === currentHostId && <span style={{ color: "var(--accent)", fontWeight: 600 }}>· 현재 호스트</span>}
            </div>
            {[...g.tables.entries()].map(([tableName, tblHits]) => (
              <div key={tableName}>
                <div style={{ padding: "5px 14px 3px 22px", fontSize: 11, color: "var(--text-faint)", fontWeight: 600 }}>{tableName} · {tblHits.length}</div>
                {tblHits.map((h, i) => {
                  const spec = getArtifactView(h.tableName);
                  const title = spec ? spec.title(h.row) : (h.row[h.matchColumn] || h.tableName);
                  const time = (spec?.timelineField ? h.row[spec.timelineField] : "") || h.row.timestamp || h.row.last_write || "";
                  const snippet = h.row[h.matchColumn] ?? "";
                  return (
                    <div
                      key={i}
                      onClick={() => onOpenHit(h)}
                      style={{ padding: "7px 14px 7px 22px", borderBottom: "1px solid var(--border-subtle)", cursor: "pointer" }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
                        <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", wordBreak: "break-all" }}>{title}</span>
                        {time && <span style={{ fontSize: 11, color: "var(--text-time)", fontFamily: "var(--mono)" }}>🕑 {time}</span>}
                      </div>
                      {h.matchColumn && (
                        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all", fontFamily: "var(--mono)" }}>
                          <span style={{ color: "var(--text-faint)" }}>{h.matchColumn}:</span> {snippet.length > 180 ? snippet.slice(0, 180) + "…" : snippet}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
