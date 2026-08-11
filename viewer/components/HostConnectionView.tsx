"use client";

import { useMemo, useState } from "react";

export interface HostNode {
  name: string;
  ips: string[];
}
export type PeerKind = "host" | "external" | "local" | "loopback";
export interface ConnEdge {
  host: string; // registered host (the log owner)
  peer: string; // node id (host name / IP / "LOCAL" / "HOST loop")
  peerLabel: string; // display label for the peer node
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
export interface HostGraph {
  hosts: HostNode[];
  edges: ConnEdge[];
}

interface Props {
  graph: HostGraph | null;
  loading: boolean;
}

const NODE_W = 158;
const NODE_H = 40;
const ROW_GAP = 20;

export default function HostConnectionView({ graph, loading }: Props) {
  const [hover, setHover] = useState<ConnEdge | null>(null);

  const edges = graph ? graph.edges : [];

  const layout = useMemo(() => {
    if (!graph) return null;
    const hostNames = new Set(graph.hosts.map((h) => h.name));

    // Node metadata (label + kind) derived from the edges.
    const labelOf: Record<string, string> = {};
    const kindOf: Record<string, PeerKind> = {};
    for (const h of graph.hosts) {
      labelOf[h.name] = h.name;
      kindOf[h.name] = "host";
    }
    const inboundPeers = new Set<string>();
    const outboundPeers = new Set<string>();
    for (const e of graph.edges) {
      if (!e.peerIsHost) {
        labelOf[e.peer] = e.peerLabel;
        kindOf[e.peer] = e.peerKind;
      }
      if (e.peerIsHost) continue;
      (e.direction === "inbound" ? inboundPeers : outboundPeers).add(e.peer);
    }
    const left = [...inboundPeers];
    const right = [...outboundPeers].filter((p) => !inboundPeers.has(p));
    const center = graph.hosts.map((h) => h.name);

    const colH = (n: number) => n * NODE_H + Math.max(0, n - 1) * ROW_GAP;
    const height = Math.max(colH(left.length), colH(center.length), colH(right.length), NODE_H) + 40;
    const width = 920;
    const leftX = 24;
    const centerX = (width - NODE_W) / 2;
    const rightX = width - NODE_W - 24;

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
    const pos: Record<string, { x: number; y: number }> = {
      ...place(left, leftX),
      ...place(right, rightX),
      ...place(center, centerX),
    };
    const hasLocal = kindOf["LOCAL"] === "local";
    return { pos, width, height, hostNames, labelOf, kindOf, left, right, center, hasLocal };
  }, [graph]);

  if (loading) return <Center>케이스의 호스트 연결 관계를 모으는 중…</Center>;
  if (!graph || graph.hosts.length === 0) return <Center>등록된 호스트가 없습니다.</Center>;

  const { pos, width, height, hostNames, labelOf, kindOf, hasLocal } = layout!;
  const anchorRight = (id: string) => ({ x: pos[id].x + NODE_W, y: pos[id].y + NODE_H / 2 });
  const anchorLeft = (id: string) => ({ x: pos[id].x, y: pos[id].y + NODE_H / 2 });

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
  const nodeIcon = (id: string) => {
    const k = kindOf[id];
    if (k === "host") return "🖥️ ";
    if (k === "local") return "🏢 ";
    if (k === "loopback") return "🔁 ";
    return "";
  };

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "18px 22px" }}>
      <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 2 }}>🔗 호스트 연결</div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 14 }}>
        RDP 접속 기록 기반. 밝은 노드 = 등록된 호스트, 어두운 노드 = 확인된 외부 IP. 화살표 방향이 접속 방향(인바운드/아웃바운드)입니다.
      </div>

      {hasLocal && (
        <div style={{ marginBottom: 12, padding: "8px 12px", background: "color-mix(in srgb, var(--warning) 12%, transparent)", border: "1px solid var(--warning)", borderRadius: "var(--radius-md)", fontSize: 12, color: "var(--text-dim)" }}>
          🏢 <b>LOCAL</b> 세션이 있습니다 — 콘솔/도메인 컨트롤러(AD 서버)를 통한 접속일 가능성이 있습니다.
        </div>
      )}

      {/* legend */}
      <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 11.5, color: "var(--text-dim)", flexWrap: "wrap" }}>
        <Legend swatch="var(--accent)" label="등록 호스트" />
        <Legend swatch="var(--bg-elevated)" label="외부 IP (확인됨)" border />
        <Legend swatch="var(--warning)" label="LOCAL (AD/콘솔)" />
        <span>🔁 HOST/127.0.0.1 = 로컬 루프백</span>
        <span>→ 인바운드</span>
        <span>→ 아웃바운드</span>
      </div>

      <div style={{ overflowX: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", background: "var(--bg-panel)", padding: 8 }}>
        {edges.length === 0 ? (
          <div style={{ padding: 28, textAlign: "center", color: "var(--text-faint)", fontSize: 12.5 }}>RDP 접속 기록이 없습니다.</div>
        ) : (
          <svg viewBox={`0 0 ${width} ${height}`} width={width} style={{ maxWidth: "100%", height: "auto" }}>
            <defs>
              <marker id="arrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
                <path d="M0,0 L7,3 L0,6 Z" fill="var(--text-faint)" />
              </marker>
              <marker id="arrowIn" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">
                <path d="M0,0 L7,3 L0,6 Z" fill="var(--warning)" />
              </marker>
            </defs>

            {/* edges */}
            {edges.map((e, i) => {
              const inbound = e.direction === "inbound";
              const src = inbound ? e.peer : e.host;
              const dst = inbound ? e.host : e.peer;
              if (!pos[src] || !pos[dst]) return null;
              const a = anchorRight(src).x <= anchorLeft(dst).x ? anchorRight(src) : anchorLeft(src);
              const b = anchorRight(src).x <= anchorLeft(dst).x ? anchorLeft(dst) : anchorRight(dst);
              const midX = (a.x + b.x) / 2;
              const isHover = hover === e;
              return (
                <path
                  key={i}
                  d={`M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`}
                  fill="none"
                  stroke={isHover ? "var(--accent)" : inbound ? "var(--warning)" : "var(--text-faint)"}
                  strokeWidth={isHover ? 2.5 : Math.min(1 + Math.log10(e.count + 1), 3)}
                  strokeOpacity={isHover ? 1 : 0.55}
                  markerEnd={inbound ? "url(#arrowIn)" : "url(#arrow)"}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHover(e)}
                  onMouseLeave={() => setHover(null)}
                />
              );
            })}

            {/* nodes */}
            {Object.entries(pos).map(([id, p]) => {
              const isHost = hostNames.has(id);
              return (
                <g key={id} transform={`translate(${p.x} ${p.y})`}>
                  <rect
                    width={NODE_W}
                    height={NODE_H}
                    rx={7}
                    fill={nodeFill(id)}
                    stroke={nodeStroke(id)}
                    strokeWidth={isHost || kindOf[id] === "local" ? 1.5 : 1}
                    opacity={isHost ? 1 : 0.82}
                  />
                  <text x={NODE_W / 2} y={NODE_H / 2 - 3} textAnchor="middle" fontSize="11.5" fontWeight={isHost ? 700 : 500} fill={isHost ? "var(--text)" : "var(--text-dim)"}>
                    {nodeIcon(id)}
                    {labelOf[id] ?? id}
                  </text>
                  <text x={NODE_W / 2} y={NODE_H / 2 + 12} textAnchor="middle" fontSize="9" fill="var(--text-faint)">
                    {nodeSub(id)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {hover && (
        <div style={{ marginTop: 12, padding: "10px 14px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", fontSize: 12.5 }}>
          <b>{hover.direction === "inbound" ? `${hover.peerLabel} → ${hover.host}` : `${hover.host} → ${hover.peerLabel}`}</b>
          {" · "}
          {hover.direction === "inbound" ? "인바운드" : "아웃바운드"} · {hover.count.toLocaleString()}회
          <div style={{ color: "var(--text-dim)", marginTop: 3 }}>
            {hover.first} ~ {hover.last} · 계정: {hover.accounts.join(", ") || "—"} · 성공 {hover.success} / 실패 {hover.fail}
          </div>
        </div>
      )}

      {/* connection table */}
      <div style={{ marginTop: 18 }}>
        <div style={{ fontSize: 13.5, fontWeight: 700, marginBottom: 8 }}>연결 상세 ({edges.length})</div>
        <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {edges.length === 0 && <div style={{ padding: 20, color: "var(--text-faint)", fontSize: 12.5 }}>RDP 접속 기록이 없습니다.</div>}
          {[...edges].sort((a, b) => (b.last || "").localeCompare(a.last || "")).map((e, i, arr) => (
            <div key={i} style={{ display: "flex", gap: 10, padding: "8px 14px", borderBottom: i < arr.length - 1 ? "1px solid var(--border-subtle)" : "none", borderLeft: `3px solid ${e.direction === "inbound" ? "var(--warning)" : "var(--text-faint)"}`, alignItems: "baseline", flexWrap: "wrap" }}>
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
          LOCAL = 콘솔/AD 경유 가능성, HOST/127.0.0.1 = 로컬 루프백(원격/터널링 도구 등). 아웃바운드 기록이 없는 호스트는 인바운드만 표시됩니다.
        </div>
      </div>
    </div>
  );
}

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
