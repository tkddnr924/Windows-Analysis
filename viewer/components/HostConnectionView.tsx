"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { inRange, rangeActive, EMPTY_TIME_RANGE, type TimeRange } from "@/lib/timeRange";

export interface HostNode {
  name: string;
  ips: string[];
}
export type PeerKind = "host" | "external" | "local" | "loopback";

// One RDP connection event, pre-classified but not aggregated. The view
// applies the time-range filter and aggregates these into edges on the client.
export interface ConnRecord {
  host: string;
  peer: string;
  peerLabel: string;
  peerKind: PeerKind;
  peerIsHost: boolean;
  direction: "inbound" | "outbound";
  timestamp: string;
  account: string;
  result: string;
}
export interface HostGraph {
  hosts: HostNode[];
  records: ConnRecord[];
}

interface ConnEdge {
  host: string;
  peer: string;
  peerLabel: string;
  peerKind: PeerKind;
  peerIsHost: boolean;
  direction: "inbound" | "outbound";
  count: number;
  first: string;
  last: string;
  accounts: string[];
  success: number;
  fail: number;
}

interface Props {
  graph: HostGraph | null;
  loading: boolean;
  timeRange?: TimeRange;
  onRefresh?: () => void;
  /** Open a registered host for browsing (from the side panel). */
  onOpenHost?: (hostName: string) => void;
}

type DirFilter = "all" | "inbound" | "outbound";

const VB_W = 1000;
const VB_H = 640;
type XY = { x: number; y: number };

const KIND_COLOR: Record<PeerKind, string> = {
  host: "var(--accent)",
  local: "var(--warning)",
  loopback: "#a78bfa",
  external: "var(--text-faint)",
};
const KIND_LABEL: Record<PeerKind, string> = {
  host: "등록 호스트",
  local: "LOCAL (콘솔/AD 경유 가능성)",
  loopback: "로컬 루프백 (원격/터널링 도구 등)",
  external: "외부 IP (확인됨)",
};

export interface LayoutParams {
  repulsion: number; // node-to-node push — larger = more spread
  linkDist: number; // rest length of connection springs
  gravity: number; // pull toward centre — smaller = looser
}
export const DEFAULT_LAYOUT: LayoutParams = { repulsion: 17000, linkDist: 215, gravity: 0.01 };

// A tiny deterministic force-directed layout (repulsion + edge springs +
// centering), run for a fixed number of iterations. Keyed on the node set so
// positions stay put when only the time filter (edge weights) changes.
function computeLayout(ids: string[], adj: [string, string][], hosts: Set<string>, params: LayoutParams): Record<string, XY> {
  const N = ids.length;
  const cx = VB_W / 2;
  const cy = VB_H / 2;
  const pos: Record<string, XY> = {};
  const R = Math.min(340, 70 + N * 8);
  ids.forEach((id, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, N);
    const j = ((i * 2654435761) % 1000) / 1000 - 0.5; // deterministic jitter
    pos[id] = { x: cx + Math.cos(a) * R + j * 24, y: cy + Math.sin(a) * (R * 0.72) + j * 24 };
  });
  if (N <= 1) return pos;

  const REP = params.repulsion;
  const SPRING_LEN = params.linkDist;
  const SPRING_K = 0.04;
  const CENTER_K = params.gravity;
  const iters = N > 120 ? 160 : 340;
  let temp = 34;
  const cool = Math.pow(1.2 / temp, 1 / iters);

  for (let it = 0; it < iters; it++) {
    const disp: Record<string, XY> = {};
    for (const id of ids) disp[id] = { x: 0, y: 0 };
    // repulsion (O(N^2), fine for the small node counts here)
    for (let i = 0; i < N; i++) {
      for (let k = i + 1; k < N; k++) {
        const A = pos[ids[i]];
        const B = pos[ids[k]];
        let dx = A.x - B.x;
        let dy = A.y - B.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) {
          dx = (i - k) * 0.1 + 0.1;
          dy = 0.1;
          d2 = dx * dx + dy * dy;
        }
        const f = REP / d2;
        const d = Math.sqrt(d2);
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        disp[ids[i]].x += fx;
        disp[ids[i]].y += fy;
        disp[ids[k]].x -= fx;
        disp[ids[k]].y -= fy;
      }
    }
    // springs along adjacency
    for (const [a, b] of adj) {
      const A = pos[a];
      const B = pos[b];
      if (!A || !B) continue;
      const dx = B.x - A.x;
      const dy = B.y - A.y;
      const d = Math.max(1, Math.hypot(dx, dy));
      const f = SPRING_K * (d - SPRING_LEN);
      const fx = (dx / d) * f;
      const fy = (dy / d) * f;
      disp[a].x += fx;
      disp[a].y += fy;
      disp[b].x -= fx;
      disp[b].y -= fy;
    }
    // centering (hosts pulled a touch harder so they settle in the middle)
    for (const id of ids) {
      const pull = CENTER_K * (hosts.has(id) ? 1.6 : 1);
      disp[id].x += (cx - pos[id].x) * pull;
      disp[id].y += (cy - pos[id].y) * pull;
    }
    for (const id of ids) {
      const dx = disp[id].x;
      const dy = disp[id].y;
      const d = Math.max(0.01, Math.hypot(dx, dy));
      pos[id].x += (dx / d) * Math.min(d, temp);
      pos[id].y += (dy / d) * Math.min(d, temp);
      // generous bounds — the view auto-fits, so let nodes spread out
      pos[id].x = Math.max(-600, Math.min(VB_W + 600, pos[id].x));
      pos[id].y = Math.max(-600, Math.min(VB_H + 600, pos[id].y));
    }
    temp *= cool;
  }
  return pos;
}

// Fit every node's bounding box into the viewBox with padding, so however far
// the layout spreads, it opens fully visible.
function fitView(pos: Record<string, XY>, ids: string[]): { tx: number; ty: number; k: number } {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const id of ids) {
    const p = pos[id];
    if (!p) continue;
    minX = Math.min(minX, p.x);
    maxX = Math.max(maxX, p.x);
    minY = Math.min(minY, p.y);
    maxY = Math.max(maxY, p.y);
  }
  if (!Number.isFinite(minX)) return { tx: 0, ty: 0, k: 1 };
  const pad = 80;
  const spanX = maxX - minX + pad * 2;
  const spanY = maxY - minY + pad * 2;
  const k = Math.max(0.3, Math.min(2, Math.min(VB_W / spanX, VB_H / spanY)));
  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  return { tx: VB_W / 2 - k * cx, ty: VB_H / 2 - k * cy, k };
}

export default function HostConnectionView({ graph, loading, timeRange = EMPTY_TIME_RANGE, onRefresh, onOpenHost }: Props) {
  const [pos, setPos] = useState<Record<string, XY>>({});
  const [view, setView] = useState({ tx: 0, ty: 0, k: 1 });
  const [selected, setSelected] = useState<string | null>(null);
  const [hoverNode, setHoverNode] = useState<string | null>(null);
  const [hoverEdge, setHoverEdge] = useState<ConnEdge | null>(null);
  const [mouse, setMouse] = useState<XY>({ x: 0, y: 0 });
  // view controls
  const [hostsOnly, setHostsOnly] = useState(false); // show only registered hosts (hide external IPs)
  const [excludeLocal, setExcludeLocal] = useState(false); // hide the LOCAL node
  const [excludeLoopback, setExcludeLoopback] = useState(false); // hide loopback (HOST/127.0.0.1) nodes
  const [dirFilter, setDirFilter] = useState<DirFilter>("all");
  const [search, setSearch] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [layout, setLayout] = useState<LayoutParams>(DEFAULT_LAYOUT);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const gRef = useRef<SVGGElement | null>(null);
  const prevIdsKey = useRef<string>("");
  const drag = useRef<{ mode: "node" | "pan" | null; id?: string; moved: boolean; sx: number; sy: number; last?: XY }>({ mode: null, moved: false, sx: 0, sy: 0 });

  const rangeOn = rangeActive(timeRange);

  // Stable topology (all nodes + adjacency + total weight) — independent of the
  // time filter, so the layout doesn't reshuffle when the window changes.
  const topo = useMemo(() => {
    const meta: Record<string, { label: string; kind: PeerKind; isHost: boolean; ips: string[] }> = {};
    const weight: Record<string, number> = {};
    if (!graph) return { ids: [] as string[], adj: [] as [string, string][], meta, weight, hosts: new Set<string>() };
    for (const h of graph.hosts) meta[h.name] = { label: h.name, kind: "host", isHost: true, ips: h.ips };
    const adjSet = new Set<string>();
    for (const r of graph.records) {
      if (!meta[r.peer]) meta[r.peer] = { label: r.peerLabel, kind: r.peerKind, isHost: false, ips: [] };
      weight[r.host] = (weight[r.host] || 0) + 1;
      weight[r.peer] = (weight[r.peer] || 0) + 1;
      const [a, b] = r.host < r.peer ? [r.host, r.peer] : [r.peer, r.host];
      adjSet.add(`${a} ${b}`);
    }
    const ids = Object.keys(meta);
    const adj = [...adjSet].map((s) => s.split(" ") as [string, string]);
    return { ids, adj, meta, weight, hosts: new Set(graph.hosts.map((h) => h.name)) };
  }, [graph]);

  const idsKey = useMemo(() => [...topo.ids].sort().join("|"), [topo.ids]);

  // Recompute the layout when the node set changes OR the user tunes the
  // spacing sliders. On a topology change we re-fit and clear the selection;
  // on a slider tweak we keep the current view so the spreading is visible.
  useEffect(() => {
    if (topo.ids.length === 0) return;
    const next = computeLayout(topo.ids, topo.adj, topo.hosts, layout);
    setPos(next);
    if (prevIdsKey.current !== idsKey) {
      prevIdsKey.current = idsKey;
      setSelected(null);
      setView(fitView(next, topo.ids));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [idsKey, layout]);

  // Filter by incident window, then aggregate to directed edges.
  const { edges, totalRecords, shownRecords } = useMemo(() => {
    if (!graph) return { edges: [] as ConnEdge[], totalRecords: 0, shownRecords: 0 };
    const recs = graph.records.filter((r) => !rangeOn || inRange(r.timestamp, timeRange));
    const em = new Map<string, ConnEdge & { accountsSet: Set<string> }>();
    for (const r of recs) {
      const key = `${r.host}|${r.peer}|${r.direction}`;
      let e = em.get(key);
      if (!e) {
        e = { host: r.host, peer: r.peer, peerLabel: r.peerLabel, peerKind: r.peerKind, peerIsHost: r.peerIsHost, direction: r.direction, count: 0, first: r.timestamp, last: r.timestamp, accounts: [], accountsSet: new Set(), success: 0, fail: 0 };
        em.set(key, e);
      }
      e.count += 1;
      if (r.timestamp) {
        if (!e.first || r.timestamp < e.first) e.first = r.timestamp;
        if (!e.last || r.timestamp > e.last) e.last = r.timestamp;
      }
      if (r.account) e.accountsSet.add(r.account);
      if (r.result === "성공") e.success += 1;
      else if (r.result === "실패") e.fail += 1;
    }
    const edges = [...em.values()].map(({ accountsSet, ...e }) => ({ ...e, accounts: [...accountsSet] }));
    return { edges, totalRecords: graph.records.length, shownRecords: recs.length };
  }, [graph, rangeOn, timeRange]);

  // Apply the view filters (direction + node-kind exclusions) to get the edges
  // actually drawn; the time filter already shaped `edges`.
  const visibleEdges = useMemo(
    () =>
      edges.filter((e) => {
        if (dirFilter !== "all" && e.direction !== dirFilter) return false;
        if (hostsOnly && !e.peerIsHost) return false;
        if (excludeLocal && e.peerKind === "local") return false;
        if (excludeLoopback && e.peerKind === "loopback") return false;
        return true;
      }),
    [edges, dirFilter, hostsOnly, excludeLocal, excludeLoopback]
  );

  // Nodes to render: registered hosts always; external nodes only when they
  // still have a visible edge (and only if externals aren't hidden).
  const visibleNodes = useMemo(() => {
    const s = new Set<string>();
    for (const h of graph?.hosts ?? []) s.add(h.name);
    if (!hostsOnly) for (const e of visibleEdges) s.add(e.peer);
    for (const e of visibleEdges) s.add(e.host);
    return s;
  }, [visibleEdges, graph, hostsOnly]);

  const searchSet = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return null;
    return new Set([...visibleNodes].filter((id) => (topo.meta[id]?.label ?? id).toLowerCase().includes(q)));
  }, [search, visibleNodes, topo.meta]);

  const liveNodes = useMemo(() => {
    const s = new Set<string>();
    for (const e of visibleEdges) {
      s.add(e.host);
      s.add(e.peer);
    }
    return s;
  }, [visibleEdges]);

  // neighbours of the hovered/selected node — used for highlight/dim
  const focusId = hoverNode ?? selected;
  const neighbours = useMemo(() => {
    if (!focusId) return null;
    const s = new Set<string>([focusId]);
    for (const e of visibleEdges) {
      if (e.host === focusId) s.add(e.peer);
      if (e.peer === focusId) s.add(e.host);
    }
    return s;
  }, [focusId, visibleEdges]);

  // If a filter hides the currently selected node, drop the side panel.
  useEffect(() => {
    if (selected && !visibleNodes.has(selected)) setSelected(null);
  }, [visibleNodes, selected]);

  if (loading) return <Center>케이스의 호스트 연결 관계를 모으는 중…</Center>;
  if (!graph || graph.hosts.length === 0) return <Center>등록된 호스트가 없습니다.</Center>;

  const radiusOf = (id: string) => {
    const w = topo.weight[id] || 1;
    const base = 5 + Math.sqrt(w) * 1.1;
    return Math.max(topo.hosts.has(id) ? 11 : 6, Math.min(base, 20));
  };

  // ---- coordinate helpers (screen → svg/group space) ----
  const toGraph = (cx: number, cy: number): XY => {
    const g = gRef.current;
    const svg = svgRef.current;
    if (!g || !svg) return { x: 0, y: 0 };
    const pt = svg.createSVGPoint();
    pt.x = cx;
    pt.y = cy;
    const m = g.getScreenCTM();
    if (!m) return { x: 0, y: 0 };
    const p = pt.matrixTransform(m.inverse());
    return { x: p.x, y: p.y };
  };
  const toVB = (cx: number, cy: number): XY => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const pt = svg.createSVGPoint();
    pt.x = cx;
    pt.y = cy;
    const m = svg.getScreenCTM();
    if (!m) return { x: 0, y: 0 };
    const p = pt.matrixTransform(m.inverse());
    return { x: p.x, y: p.y };
  };

  const onDownNode = (e: React.PointerEvent, id: string) => {
    e.stopPropagation();
    svgRef.current?.setPointerCapture(e.pointerId);
    drag.current = { mode: "node", id, moved: false, sx: e.clientX, sy: e.clientY };
  };
  const onDownBg = (e: React.PointerEvent) => {
    svgRef.current?.setPointerCapture(e.pointerId);
    drag.current = { mode: "pan", moved: false, sx: e.clientX, sy: e.clientY, last: toVB(e.clientX, e.clientY) };
  };
  const onMove = (e: React.PointerEvent) => {
    setMouse({ x: e.clientX, y: e.clientY });
    const d = drag.current;
    if (!d.mode) return;
    if (d.mode === "node" && d.id) {
      if (!d.moved && Math.hypot(e.clientX - d.sx, e.clientY - d.sy) < 4) return;
      d.moved = true;
      const p = toGraph(e.clientX, e.clientY);
      setPos((prev) => ({ ...prev, [d.id!]: p }));
    } else if (d.mode === "pan" && d.last) {
      const c = toVB(e.clientX, e.clientY);
      const l = d.last;
      setView((v) => ({ ...v, tx: v.tx + (c.x - l.x), ty: v.ty + (c.y - l.y) }));
      d.last = c;
      if (Math.hypot(e.clientX - d.sx, e.clientY - d.sy) > 4) d.moved = true;
    }
  };
  const onUp = () => {
    const d = drag.current;
    if (d.mode === "node" && !d.moved && d.id) setSelected((s) => (s === d.id ? null : d.id!));
    if (d.mode === "pan" && !d.moved) setSelected(null);
    drag.current = { mode: null, moved: false, sx: 0, sy: 0 };
  };
  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const c = toVB(e.clientX, e.clientY);
    setView((v) => {
      const k = Math.max(0.3, Math.min(3.5, v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
      return { k, tx: c.x - (k / v.k) * (c.x - v.tx), ty: c.y - (k / v.k) * (c.y - v.ty) };
    });
  };
  const resetView = () => {
    const next = computeLayout(topo.ids, topo.adj, topo.hosts, layout);
    setPos(next);
    setView(fitView(next, topo.ids));
  };

  const selMeta = selected ? topo.meta[selected] : null;
  const selEdges = selected ? visibleEdges.filter((e) => e.host === selected || e.peer === selected) : [];
  const hostCount = graph.hosts.length;
  const externalCount = topo.ids.length - hostCount;
  const hasLocalNode = topo.ids.some((id) => topo.meta[id]?.kind === "local");
  const hasLoopbackNode = topo.ids.some((id) => topo.meta[id]?.kind === "loopback");

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "18px 22px" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 2 }}>🔗 호스트 연결</div>
          <div style={{ fontSize: 12, color: "var(--text-faint)" }}>
            노드를 클릭하면 상세가 옆에 뜹니다. 드래그로 이동, 빈 공간 드래그로 화면 이동, 휠로 확대/축소.
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <button
            onClick={() => setShowSettings((v) => !v)}
            title="노드 간격/거리 조절"
            style={{ ...btn, borderColor: showSettings ? "var(--accent)" : "var(--border)", background: showSettings ? "var(--accent-subtle)" : "var(--bg-elevated)", color: showSettings ? "var(--accent)" : "var(--text-dim)" }}
          >
            ⚙ 레이아웃
          </button>
          <button onClick={resetView} title="레이아웃 다시 계산 + 화면 맞춤" style={btn}>
            ⤢ 정렬
          </button>
          <button onClick={onRefresh} title="다른 호스트를 파싱한 뒤 눌러 새로고침" style={btn}>
            ⟳ 새로고침
          </button>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", margin: "12px 0" }}>
        {rangeOn && <span style={chip("var(--accent)")}>기간 필터 적용됨 · {shownRecords.toLocaleString()} / {totalRecords.toLocaleString()}건</span>}
        {topo.meta["LOCAL"]?.kind === "local" && <span style={chip("var(--warning)")}>🏢 LOCAL 세션 존재 — 콘솔/AD 서버(도메인 컨트롤러) 경유 가능성</span>}
      </div>

      {/* controls: node-kind toggles, direction filter, search, counts */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <ToggleBtn active={hostsOnly} onClick={() => setHostsOnly((v) => !v)} title="외부 IP를 숨기고 등록된 호스트만 표시">
          등록 호스트
        </ToggleBtn>
        {!hostsOnly && hasLocalNode && (
          <ToggleBtn active={excludeLocal} onClick={() => setExcludeLocal((v) => !v)} title="LOCAL 노드를 숨김">
            Local 제외
          </ToggleBtn>
        )}
        {!hostsOnly && hasLoopbackNode && (
          <ToggleBtn active={excludeLoopback} onClick={() => setExcludeLoopback((v) => !v)} title="로컬호스트(HOST/127.0.0.1) 노드를 숨김">
            로컬호스트 제외
          </ToggleBtn>
        )}

        <div style={{ display: "inline-flex", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: 2, gap: 2 }}>
          {([["all", "전체"], ["inbound", "인바운드"], ["outbound", "아웃바운드"]] as [DirFilter, string][]).map(([v, label]) => {
            const active = dirFilter === v;
            return (
              <button key={v} onClick={() => setDirFilter(v)} style={{ fontSize: 11.5, padding: "4px 11px", border: "none", borderRadius: "var(--radius-sm)", cursor: "pointer", fontWeight: active ? 700 : 500, background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)" }}>
                {label}
              </button>
            );
          })}
        </div>

        <div style={{ position: "relative", flex: "0 1 240px", minWidth: 160 }}>
          <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)", pointerEvents: "none" }}>🔍</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="IP · 호스트명 검색"
            style={{ width: "100%", padding: "6px 24px 6px 28px", fontSize: 12.5, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
          />
          {search && (
            <span onClick={() => setSearch("")} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", cursor: "pointer", color: "var(--text-faint)", fontSize: 13 }}>✕</span>
          )}
        </div>

        <span style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--text-faint)" }}>
          호스트 {hostCount}{!hostsOnly && externalCount > 0 ? ` · 외부 IP ${externalCount}` : ""} · 연결 {visibleEdges.length}
        </span>
      </div>

      {/* legend */}
      <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 11.5, color: "var(--text-dim)", flexWrap: "wrap" }}>
        <Legend color={KIND_COLOR.host} label="등록 호스트" />
        <Legend color={KIND_COLOR.external} label="외부 IP" />
        <Legend color={KIND_COLOR.local} label="LOCAL" />
        <Legend color={KIND_COLOR.loopback} label="루프백" />
        <span style={{ color: "var(--warning)" }}>― 인바운드</span>
        <span>― 아웃바운드</span>
      </div>

      <div style={{ position: "relative", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", background: "var(--bg-panel)", overflow: "hidden" }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${VB_W} ${VB_H}`}
          width="100%"
          style={{ display: "block", height: 560, touchAction: "none", cursor: drag.current.mode === "pan" ? "grabbing" : "grab" }}
          onPointerDown={onDownBg}
          onPointerMove={onMove}
          onPointerUp={onUp}
          onPointerLeave={onUp}
          onWheel={onWheel}
        >
          <defs>
            <marker id="ar-in" markerWidth="9" markerHeight="9" refX="6.5" refY="4" orient="auto">
              <path d="M2,1.5 L6.5,4 L2,6.5" fill="none" stroke="var(--warning)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
            <marker id="ar-out" markerWidth="9" markerHeight="9" refX="6.5" refY="4" orient="auto">
              <path d="M2,1.5 L6.5,4 L2,6.5" fill="none" stroke="var(--text-faint)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
            <marker id="ar-hi" markerWidth="9" markerHeight="9" refX="6.5" refY="4" orient="auto">
              <path d="M2,1.5 L6.5,4 L2,6.5" fill="none" stroke="var(--accent)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
          </defs>

          <g ref={gRef} transform={`translate(${view.tx} ${view.ty}) scale(${view.k})`}>
            {/* edges */}
            {visibleEdges.map((e, i) => {
              const A = pos[e.host];
              const B = pos[e.peer];
              if (!A || !B) return null;
              const src = e.direction === "inbound" ? B : A;
              const dst = e.direction === "inbound" ? A : B;
              const dx = dst.x - src.x;
              const dy = dst.y - src.y;
              const len = Math.max(1, Math.hypot(dx, dy));
              const ux = dx / len;
              const uy = dy / len;
              const rS = radiusOf(e.direction === "inbound" ? e.peer : e.host);
              const rD = radiusOf(e.direction === "inbound" ? e.host : e.peer);
              const sx = src.x + ux * rS;
              const sy = src.y + uy * rS;
              const ex = dst.x - ux * (rD + 5);
              const ey = dst.y - uy * (rD + 5);
              // curve them apart so inbound/outbound between a pair don't overlap
              const off = (e.direction === "inbound" ? 1 : -1) * 16;
              const mx = (sx + ex) / 2 - uy * off;
              const my = (sy + ey) / 2 + ux * off;
              const active = hoverEdge === e || (neighbours != null && neighbours.has(e.host) && neighbours.has(e.peer));
              const dim = (neighbours != null || hoverEdge != null) && !active;
              const inbound = e.direction === "inbound";
              return (
                <path
                  key={i}
                  d={`M ${sx} ${sy} Q ${mx} ${my} ${ex} ${ey}`}
                  fill="none"
                  stroke={active ? "var(--accent)" : inbound ? "var(--warning)" : "var(--text-faint)"}
                  strokeWidth={(active ? 2.6 : Math.min(1 + Math.log10(e.count + 1), 3)) / view.k}
                  strokeOpacity={dim ? 0.1 : active ? 1 : 0.5}
                  markerEnd={active ? "url(#ar-hi)" : inbound ? "url(#ar-in)" : "url(#ar-out)"}
                  style={{ cursor: "pointer" }}
                  onPointerEnter={() => setHoverEdge(e)}
                  onPointerLeave={() => setHoverEdge(null)}
                />
              );
            })}

            {/* nodes */}
            {topo.ids.map((id) => {
              const p = pos[id];
              if (!p || !visibleNodes.has(id)) return null;
              const m = topo.meta[id];
              const r = radiusOf(id);
              const color = KIND_COLOR[m.kind];
              const isSel = selected === id;
              const searchDim = searchSet != null && !searchSet.has(id);
              const focusDim = neighbours != null && !neighbours.has(id);
              const filterDim = rangeOn && !liveNodes.has(id);
              const op = searchDim ? 0.12 : focusDim ? 0.2 : filterDim ? 0.32 : 1;
              const showLabel = (searchSet != null && searchSet.has(id)) || visibleNodes.size <= 45 || isSel || hoverNode === id || (neighbours != null && neighbours.has(id));
              return (
                <g
                  key={id}
                  transform={`translate(${p.x} ${p.y})`}
                  opacity={op}
                  style={{ cursor: "pointer" }}
                  onPointerDown={(ev) => onDownNode(ev, id)}
                  onPointerEnter={() => setHoverNode(id)}
                  onPointerLeave={() => setHoverNode(null)}
                >
                  <circle
                    r={r}
                    fill={color}
                    fillOpacity={m.kind === "host" ? 0.9 : 0.32}
                    stroke={isSel ? "var(--accent)" : color}
                    strokeWidth={(isSel ? 3.2 : 1.4) / view.k}
                  />
                  {m.kind === "host" && (
                    <text textAnchor="middle" dy={r / 3} fontSize={Math.min(r, 15) / view.k} style={{ pointerEvents: "none" }}>
                      🖥️
                    </text>
                  )}
                  {showLabel && (
                    <text
                      textAnchor="middle"
                      y={r + 12 / view.k}
                      fontSize={11 / view.k}
                      fontWeight={m.kind === "host" ? 700 : 500}
                      fill={m.kind === "host" ? "var(--text)" : "var(--text-dim)"}
                      style={{ pointerEvents: "none", paintOrder: "stroke" }}
                      stroke="var(--bg-panel)"
                      strokeWidth={3 / view.k}
                    >
                      {m.label}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {visibleEdges.length === 0 && (
          <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-faint)", fontSize: 12.5, pointerEvents: "none" }}>
            {totalRecords > 0 && (rangeOn || dirFilter !== "all" || hostsOnly || excludeLocal || excludeLoopback) ? "조건에 맞는 RDP 연결이 없습니다." : "RDP 접속 기록이 없습니다."}
          </div>
        )}

        {/* adjustable layout panel */}
        {showSettings && (
          <div style={settingsPanel}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <span style={{ fontSize: 12.5, fontWeight: 700 }}>⚙ 레이아웃 조절</span>
              <button onClick={() => setShowSettings(false)} style={{ ...btn, padding: "1px 7px" }}>✕</button>
            </div>
            <Slider label="노드 간격" hint="멀리 ↔ 가까이" value={layout.repulsion} min={5000} max={45000} step={1000} onChange={(v) => setLayout((p) => ({ ...p, repulsion: v }))} />
            <Slider label="연결 거리" hint="선으로 이어진 노드 간" value={layout.linkDist} min={90} max={420} step={5} onChange={(v) => setLayout((p) => ({ ...p, linkDist: v }))} />
            <Slider label="중심 쏠림" hint="흩어짐 ↔ 모임" value={layout.gravity} min={0.004} max={0.05} step={0.002} format={(v) => v.toFixed(3)} onChange={(v) => setLayout((p) => ({ ...p, gravity: v }))} />
            <button onClick={() => setLayout(DEFAULT_LAYOUT)} style={{ ...btn, width: "100%", marginTop: 8, justifyContent: "center" }}>
              기본값으로
            </button>
            <div style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 6, lineHeight: 1.4 }}>
              조절 후 배치가 흩어지면 <b>⤢ 정렬</b>로 화면을 다시 맞출 수 있어요.
            </div>
          </div>
        )}

        {/* edge tooltip follows the cursor */}
        {hoverEdge && drag.current.mode == null && (
          <FloatingTip mouse={mouse} edge={hoverEdge} />
        )}

        {/* click-to-inspect side panel */}
        {selMeta && (
          <div style={panel}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
              <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "var(--mono)", wordBreak: "break-all" }}>
                {selMeta.kind === "host" ? "🖥️ " : selMeta.kind === "local" ? "🏢 " : selMeta.kind === "loopback" ? "🔁 " : ""}
                {selMeta.label}
              </div>
              <button onClick={() => setSelected(null)} style={{ ...btn, padding: "2px 8px" }}>
                ✕
              </button>
            </div>
            <div style={{ fontSize: 11, color: KIND_COLOR[selMeta.kind], marginTop: 2 }}>{KIND_LABEL[selMeta.kind]}</div>
            {selMeta.ips.length > 0 && <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 4, fontFamily: "var(--mono)" }}>IP: {selMeta.ips.join(", ")}</div>}
            {selMeta.kind === "host" && onOpenHost && (
              <button onClick={() => onOpenHost(selMeta.label)} style={{ ...btn, width: "100%", marginTop: 8, justifyContent: "center", color: "var(--accent)", borderColor: "var(--accent)", background: "var(--accent-subtle)" }}>
                이 호스트 열기 →
              </button>
            )}
            <div style={{ fontSize: 11.5, color: "var(--text-dim)", margin: "8px 0 4px" }}>
              연결 {selEdges.length}건 · 인바운드 {selEdges.filter((e) => e.direction === "inbound").reduce((s, e) => s + e.count, 0).toLocaleString()} · 아웃바운드 {selEdges.filter((e) => e.direction === "outbound").reduce((s, e) => s + e.count, 0).toLocaleString()}회
            </div>
            <div style={{ overflow: "auto", flex: 1, marginTop: 4, display: "flex", flexDirection: "column", gap: 6 }}>
              {selEdges.length === 0 && <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>이 기간에 연결이 없습니다.</div>}
              {[...selEdges].sort((a, b) => (b.last || "").localeCompare(a.last || "")).map((e, i) => {
                const other = e.host === selected ? e.peerLabel : e.host;
                const arrow = e.direction === "inbound" ? (e.host === selected ? "← " : "→ ") : e.host === selected ? "→ " : "← ";
                return (
                  <div key={i} style={{ padding: "7px 9px", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)", borderLeft: `3px solid ${e.direction === "inbound" ? "var(--warning)" : "var(--text-faint)"}` }}>
                    <div style={{ fontSize: 11.5, fontWeight: 600, fontFamily: "var(--mono)" }}>
                      <span style={{ color: e.direction === "inbound" ? "var(--warning)" : "var(--text-dim)" }}>{e.direction === "inbound" ? "인바운드 " : "아웃바운드 "}</span>
                      {arrow}
                      {other}
                    </div>
                    <div style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 2 }}>
                      {e.count.toLocaleString()}회 · 성공 {e.success}{e.fail ? ` · 실패 ${e.fail}` : ""}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 2 }}>
                      {e.first?.slice(0, 16)} ~ {e.last?.slice(0, 16)}
                    </div>
                    {e.accounts.length > 0 && <div style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 2 }}>👤 {e.accounts.join(", ")}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 8 }}>
        원 크기 = 접속량. LOCAL = 콘솔/AD 경유 가능성, 루프백(HOST/127.0.0.1) = 원격/터널링 도구 가능성. 전역 기간 필터가 이 뷰에도 적용됩니다.
      </div>
    </div>
  );
}

function FloatingTip({ mouse, edge }: { mouse: XY; edge: ConnEdge }) {
  const w = typeof window !== "undefined" ? window.innerWidth : 1200;
  const h = typeof window !== "undefined" ? window.innerHeight : 800;
  return (
    <div
      style={{
        position: "fixed",
        left: Math.min(mouse.x + 16, w - 320),
        top: Math.min(mouse.y + 16, h - 120),
        zIndex: 50,
        pointerEvents: "none",
        maxWidth: 300,
        padding: "8px 11px",
        background: "var(--bg-elevated)",
        border: "1px solid var(--accent)",
        borderRadius: "var(--radius-md)",
        boxShadow: "0 6px 24px rgba(0,0,0,.35)",
        fontSize: 12,
      }}
    >
      <div style={{ fontWeight: 700, fontFamily: "var(--mono)" }}>
        {edge.direction === "inbound" ? `${edge.peerLabel} → ${edge.host}` : `${edge.host} → ${edge.peerLabel}`}
      </div>
      <div style={{ color: "var(--text-dim)", marginTop: 3 }}>
        {edge.direction === "inbound" ? "인바운드" : "아웃바운드"} · {edge.count.toLocaleString()}회 · 성공 {edge.success} / 실패 {edge.fail}
      </div>
      <div style={{ color: "var(--text-faint)", marginTop: 3, fontFamily: "var(--mono)", fontSize: 11 }}>
        {edge.first?.slice(0, 19)} ~ {edge.last?.slice(0, 19)}
      </div>
    </div>
  );
}

const btn: React.CSSProperties = {
  flexShrink: 0,
  padding: "7px 12px",
  fontSize: 12,
  fontWeight: 600,
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  border: "1px solid var(--border)",
  background: "var(--bg-elevated)",
  color: "var(--text-dim)",
};

const panel: React.CSSProperties = {
  position: "absolute",
  top: 10,
  right: 10,
  bottom: 10,
  width: 290,
  display: "flex",
  flexDirection: "column",
  padding: "12px 14px",
  background: "color-mix(in srgb, var(--bg-elevated) 92%, transparent)",
  backdropFilter: "blur(3px)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-lg)",
  boxShadow: "0 8px 30px rgba(0,0,0,.3)",
};

const settingsPanel: React.CSSProperties = {
  position: "absolute",
  top: 10,
  left: 10,
  width: 232,
  padding: "11px 13px",
  background: "color-mix(in srgb, var(--bg-elevated) 94%, transparent)",
  backdropFilter: "blur(3px)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-lg)",
  boxShadow: "0 8px 30px rgba(0,0,0,.3)",
  zIndex: 6,
};

const chip = (color: string): React.CSSProperties => ({
  display: "inline-flex",
  alignItems: "center",
  padding: "4px 10px",
  fontSize: 11.5,
  borderRadius: 999,
  border: `1px solid ${color}`,
  background: `color-mix(in srgb, ${color} 12%, transparent)`,
  color: "var(--text-dim)",
});

function Slider({ label, hint, value, min, max, step, onChange, format }: { label: string; hint?: string; value: number; min: number; max: number; step: number; onChange: (v: number) => void; format?: (v: number) => string }) {
  return (
    <div style={{ marginBottom: 9 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", fontSize: 11.5, marginBottom: 2 }}>
        <span style={{ fontWeight: 600 }}>{label}</span>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)" }}>{format ? format(value) : Math.round(value)}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{ width: "100%", accentColor: "var(--accent)", cursor: "pointer" }}
      />
      {hint && <div style={{ fontSize: 9.5, color: "var(--text-faint)", marginTop: 1 }}>{hint}</div>}
    </div>
  );
}

function ToggleBtn({ active, onClick, title, children }: { active: boolean; onClick: () => void; title?: string; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{ ...btn, borderColor: active ? "var(--accent)" : "var(--border)", background: active ? "var(--accent-subtle)" : "var(--bg-elevated)", color: active ? "var(--accent)" : "var(--text-dim)" }}
    >
      {active ? "☑" : "☐"} {children}
    </button>
  );
}

function Center({ children }: { children: React.ReactNode }) {
  return <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)" }}>{children}</div>;
}
function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 12, height: 12, borderRadius: "50%", background: color, opacity: 0.85 }} />
      {label}
    </span>
  );
}
