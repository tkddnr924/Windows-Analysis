"use client";

import { useMemo, useState } from "react";
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

// Aggregated edge (host ↔ peer, one direction) shown on the diagram + table.
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
}

const NODE_W = 176;
const NODE_H = 46;
const ROW_GAP = 26;
const WIDTH = 960;

export default function HostConnectionView({ graph, loading, timeRange = EMPTY_TIME_RANGE, onRefresh }: Props) {
  const [hoverEdge, setHoverEdge] = useState<ConnEdge | null>(null);
  const [hoverNode, setHoverNode] = useState<string | null>(null);
  const [mouse, setMouse] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const rangeOn = rangeActive(timeRange);

  // Filter by incident window, then aggregate to edges. Client-side so
  // changing the window is instant and needs no re-read.
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

  const layout = useMemo(() => {
    if (!graph) return null;
    const hostNames = new Set(graph.hosts.map((h) => h.name));
    const labelOf: Record<string, string> = {};
    const kindOf: Record<string, PeerKind> = {};
    const weight: Record<string, number> = {}; // total events touching a node (for sort)
    for (const h of graph.hosts) {
      labelOf[h.name] = h.name;
      kindOf[h.name] = "host";
    }
    const inboundPeers = new Set<string>();
    const outboundPeers = new Set<string>();
    for (const e of edges) {
      weight[e.host] = (weight[e.host] || 0) + e.count;
      weight[e.peer] = (weight[e.peer] || 0) + e.count;
      if (!e.peerIsHost) {
        labelOf[e.peer] = e.peerLabel;
        kindOf[e.peer] = e.peerKind;
        (e.direction === "inbound" ? inboundPeers : outboundPeers).add(e.peer);
      }
    }
    // busiest peers first so the eye lands on the active ones
    const byWeight = (a: string, b: string) => (weight[b] || 0) - (weight[a] || 0);
    const left = [...inboundPeers].sort(byWeight);
    const right = [...outboundPeers].filter((p) => !inboundPeers.has(p)).sort(byWeight);
    const center = graph.hosts.map((h) => h.name).sort(byWeight);

    const colH = (n: number) => n * NODE_H + Math.max(0, n - 1) * ROW_GAP;
    const height = Math.max(colH(left.length), colH(center.length), colH(right.length), NODE_H) + 44;
    const leftX = 28;
    const centerX = (WIDTH - NODE_W) / 2;
    const rightX = WIDTH - NODE_W - 28;
    const place = (ids: string[], x: number): Record<string, { x: number; y: number }> => {
      const total = colH(ids.length);
      let y = (height - total) / 2;
      const map: Record<string, { x: number; y: number }> = {};
      for (const id of ids) {
        map[id] = { x, y };
        y += NODE_H + ROW_GAP;
      }
      return map;
    };
    const pos = { ...place(left, leftX), ...place(right, rightX), ...place(center, centerX) };
    const hasLocal = kindOf["LOCAL"] === "local";
    return { pos, height, hostNames, labelOf, kindOf, hasLocal, hasOutbound: right.length > 0 };
  }, [graph, edges]);

  if (loading) return <Center>케이스의 호스트 연결 관계를 모으는 중…</Center>;
  if (!graph || graph.hosts.length === 0) return <Center>등록된 호스트가 없습니다.</Center>;

  const { pos, height, hostNames, labelOf, kindOf, hasLocal } = layout!;
  const anchorR = (id: string) => ({ x: pos[id].x + NODE_W, y: pos[id].y + NODE_H / 2 });
  const anchorL = (id: string) => ({ x: pos[id].x, y: pos[id].y + NODE_H / 2 });

  // Which edges are highlighted: the hovered edge, or every edge touching the
  // hovered node. Endpoints of highlighted edges light up; the rest dims.
  const edgeActive = (e: ConnEdge) =>
    hoverEdge === e || (hoverNode != null && (e.host === hoverNode || e.peer === hoverNode));
  const anyHover = hoverEdge != null || hoverNode != null;
  const activeNodes = new Set<string>();
  if (anyHover) for (const e of edges) if (edgeActive(e)) { activeNodes.add(e.host); activeNodes.add(e.peer); }
  const nodeActive = (id: string) => !anyHover || activeNodes.has(id);

  const nodeFill = (id: string) => {
    const k = kindOf[id];
    if (k === "host") return "var(--accent-subtle)";
    if (k === "local") return "color-mix(in srgb, var(--warning) 16%, var(--bg-elevated))";
    return "var(--bg-elevated)";
  };
  const nodeStroke = (id: string) => {
    const k = kindOf[id];
    if (k === "host") return "var(--accent)";
    if (k === "local") return "var(--warning)";
    return "var(--border)";
  };
  const nodeSub = (id: string) => {
    const k = kindOf[id];
    if (k === "host") return graph.hosts.find((h) => h.name === id)?.ips.slice(0, 2).join(", ") || "";
    if (k === "local") return "AD/콘솔 가능성?";
    if (k === "loopback") return "로컬 프로그램?";
    return "외부 IP";
  };
  const nodeIcon = (id: string) => ({ host: "🖥️ ", local: "🏢 ", loopback: "🔁 " }[kindOf[id] as string] || "");

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "18px 22px" }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div>
          <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 2 }}>🔗 호스트 연결</div>
          <div style={{ fontSize: 12, color: "var(--text-faint)" }}>
            RDP 접속 기록 기반. 노드에 마우스를 올리면 관련 연결만 밝게 표시됩니다.
          </div>
        </div>
        <button onClick={onRefresh} title="다른 호스트를 파싱한 뒤 눌러 새로고침" style={refreshBtn}>
          ⟳ 새로고침
        </button>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", margin: "12px 0" }}>
        {rangeOn && (
          <span style={chip("var(--accent)")}>
            기간 필터 적용됨 · {shownRecords.toLocaleString()} / {totalRecords.toLocaleString()}건
          </span>
        )}
        {hasLocal && <span style={chip("var(--warning)")}>🏢 LOCAL 세션 존재 — 콘솔/AD 서버(도메인 컨트롤러) 경유 가능성</span>}
      </div>

      {/* legend */}
      <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 11.5, color: "var(--text-dim)", flexWrap: "wrap" }}>
        <Legend swatch="var(--accent)" label="등록 호스트" />
        <Legend swatch="var(--bg-elevated)" label="외부 IP (확인됨)" border />
        <Legend swatch="var(--warning)" label="LOCAL (AD/콘솔)" />
        <span style={{ color: "var(--warning)" }}>▬ 인바운드(외부→호스트)</span>
        <span>▬ 아웃바운드(호스트→외부)</span>
      </div>

      <div
        style={{ position: "relative", overflowX: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", background: "var(--bg-panel)", padding: 8 }}
        onMouseMove={(ev) => setMouse({ x: ev.clientX, y: ev.clientY })}
      >
        {edges.length === 0 ? (
          <div style={{ padding: 32, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>
            {totalRecords > 0 && rangeOn ? "이 기간에 해당하는 RDP 연결이 없습니다." : "RDP 접속 기록이 없습니다."}
          </div>
        ) : (
          <svg viewBox={`0 0 ${WIDTH} ${height}`} width={WIDTH} style={{ maxWidth: "100%", height: "auto" }}>
            <defs>
              <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6 Z" fill="var(--text-faint)" />
              </marker>
              <marker id="arrowIn" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6 Z" fill="var(--warning)" />
              </marker>
            </defs>

            {/* edges — draw dimmed ones first so highlighted sit on top */}
            {[...edges]
              .map((e, i) => ({ e, i }))
              .sort((a, b) => Number(edgeActive(a.e)) - Number(edgeActive(b.e)))
              .map(({ e, i }) => {
                const inbound = e.direction === "inbound";
                const src = inbound ? e.peer : e.host;
                const dst = inbound ? e.host : e.peer;
                if (!pos[src] || !pos[dst]) return null;
                const a = anchorR(src).x <= anchorL(dst).x ? anchorR(src) : anchorL(src);
                const b = anchorR(src).x <= anchorL(dst).x ? anchorL(dst) : anchorR(dst);
                const midX = (a.x + b.x) / 2;
                const active = edgeActive(e);
                const dim = anyHover && !active;
                return (
                  <path
                    key={i}
                    d={`M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`}
                    fill="none"
                    stroke={active ? "var(--accent)" : inbound ? "var(--warning)" : "var(--text-faint)"}
                    strokeWidth={active ? 3 : Math.min(1 + Math.log10(e.count + 1), 3)}
                    strokeOpacity={dim ? 0.12 : active ? 1 : 0.5}
                    markerEnd={inbound ? "url(#arrowIn)" : "url(#arrow)"}
                    style={{ cursor: "pointer", transition: "stroke-opacity .1s" }}
                    onMouseEnter={() => setHoverEdge(e)}
                    onMouseLeave={() => setHoverEdge(null)}
                  />
                );
              })}

            {/* nodes */}
            {Object.entries(pos).map(([id, p]) => {
              const isHost = hostNames.has(id);
              const on = nodeActive(id);
              return (
                <g
                  key={id}
                  transform={`translate(${p.x} ${p.y})`}
                  style={{ cursor: "pointer", transition: "opacity .1s" }}
                  opacity={on ? 1 : 0.28}
                  onMouseEnter={() => setHoverNode(id)}
                  onMouseLeave={() => setHoverNode(null)}
                >
                  <rect
                    width={NODE_W}
                    height={NODE_H}
                    rx={8}
                    fill={nodeFill(id)}
                    stroke={hoverNode === id ? "var(--accent)" : nodeStroke(id)}
                    strokeWidth={isHost || kindOf[id] === "local" || hoverNode === id ? 1.8 : 1}
                  />
                  <text x={NODE_W / 2} y={NODE_H / 2 - 3} textAnchor="middle" fontSize="12.5" fontWeight={isHost ? 700 : 500} fill={isHost ? "var(--text)" : "var(--text-dim)"}>
                    {nodeIcon(id)}
                    {labelOf[id] ?? id}
                  </text>
                  <text x={NODE_W / 2} y={NODE_H / 2 + 13} textAnchor="middle" fontSize="9.5" fill="var(--text-faint)">
                    {nodeSub(id)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}

        {/* floating tooltip that follows the cursor */}
        {hoverEdge && (
          <div
            style={{
              position: "fixed",
              left: Math.min(mouse.x + 16, (typeof window !== "undefined" ? window.innerWidth : 1200) - 320),
              top: Math.min(mouse.y + 16, (typeof window !== "undefined" ? window.innerHeight : 800) - 130),
              zIndex: 50,
              pointerEvents: "none",
              maxWidth: 300,
              padding: "9px 12px",
              background: "var(--bg-elevated)",
              border: "1px solid var(--accent)",
              borderRadius: "var(--radius-md)",
              boxShadow: "0 6px 24px rgba(0,0,0,.35)",
              fontSize: 12,
            }}
          >
            <div style={{ fontWeight: 700, fontFamily: "var(--mono)" }}>
              {hoverEdge.direction === "inbound" ? `${hoverEdge.peerLabel} → ${hoverEdge.host}` : `${hoverEdge.host} → ${hoverEdge.peerLabel}`}
            </div>
            <div style={{ color: "var(--text-dim)", marginTop: 3 }}>
              {hoverEdge.direction === "inbound" ? "인바운드" : "아웃바운드"} · {hoverEdge.count.toLocaleString()}회 · 성공 {hoverEdge.success} / 실패 {hoverEdge.fail}
            </div>
            <div style={{ color: "var(--text-faint)", marginTop: 3, fontFamily: "var(--mono)", fontSize: 11 }}>
              {hoverEdge.first?.slice(0, 19)} ~ {hoverEdge.last?.slice(0, 19)}
            </div>
            {hoverEdge.accounts.length > 0 && (
              <div style={{ color: "var(--text-faint)", marginTop: 3, fontSize: 11 }}>👤 {hoverEdge.accounts.join(", ")}</div>
            )}
          </div>
        )}
      </div>

      {/* connection table */}
      <div style={{ marginTop: 18 }}>
        <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 8 }}>연결 상세 ({edges.length})</div>
        <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {edges.length === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>표시할 연결이 없습니다.</div>}
          {[...edges]
            .sort((a, b) => (b.last || "").localeCompare(a.last || ""))
            .map((e, i, arr) => (
              <div
                key={i}
                onMouseEnter={() => setHoverEdge(e)}
                onMouseLeave={() => setHoverEdge(null)}
                style={{ display: "flex", gap: 10, padding: "8px 14px", borderBottom: i < arr.length - 1 ? "1px solid var(--border-subtle)" : "none", borderLeft: `3px solid ${e.direction === "inbound" ? "var(--warning)" : "var(--text-faint)"}`, background: hoverEdge === e ? "var(--bg-elevated)" : "transparent", alignItems: "baseline", flexWrap: "wrap" }}
              >
                <span style={{ fontSize: 10.5, fontWeight: 700, color: e.direction === "inbound" ? "var(--warning)" : "var(--text-dim)", flexShrink: 0, width: 60 }}>{e.direction === "inbound" ? "인바운드" : "아웃바운드"}</span>
                <span style={{ fontSize: 12.5, fontWeight: 600, fontFamily: "var(--mono)" }}>
                  {e.direction === "inbound" ? `${e.peerLabel} → 🖥️ ${e.host}` : `🖥️ ${e.host} → ${e.peerLabel}`}
                </span>
                <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{e.count.toLocaleString()}회 · 성공 {e.success}{e.fail ? ` · 실패 ${e.fail}` : ""}</span>
                <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{e.first?.slice(0, 16)} ~ {e.last?.slice(0, 16)}</span>
                {e.accounts.length > 0 && <div style={{ flexBasis: "100%", fontSize: 10.5, color: "var(--text-faint)" }}>👤 {e.accounts.join(", ")}</div>}
              </div>
            ))}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 8 }}>
          LOCAL = 콘솔/AD 경유 가능성, HOST/127.0.0.1 = 로컬 루프백(원격/터널링 도구 등). 전역 기간 필터가 이 뷰에도 적용됩니다.
        </div>
      </div>
    </div>
  );
}

const refreshBtn: React.CSSProperties = {
  flexShrink: 0,
  padding: "7px 13px",
  fontSize: 12.5,
  fontWeight: 600,
  borderRadius: "var(--radius-md)",
  cursor: "pointer",
  border: "1px solid var(--border)",
  background: "var(--bg-elevated)",
  color: "var(--text-dim)",
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

function Center({ children }: { children: React.ReactNode }) {
  return <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)" }}>{children}</div>;
}
function Legend({ swatch, label, border }: { swatch: string; label: string; border?: boolean }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 12, height: 12, borderRadius: 3, background: swatch, border: border ? "1px solid var(--border)" : "none" }} />
      {label}
    </span>
  );
}
