"use client";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import AccountTreeOutlinedIcon from "@mui/icons-material/AccountTreeOutlined";
import CloseIcon from "@mui/icons-material/Close";
import CircularProgress from "@mui/material/CircularProgress";
import ReplayOutlinedIcon from "@mui/icons-material/ReplayOutlined";
import OpenInNewOutlinedIcon from "@mui/icons-material/OpenInNewOutlined";
import type { BrowserVisitGraph, VisitGraphEdge, VisitGraphNode } from "@/lib/types";

// 유입 흐름 모달 — 원본 History의 방문 연결(from_visit·opener_visit)을 2D
// 그래프로 그린다. 선택한 항목의 방문(대상)이 끝점이 아니라, 조상(유입)·후행
// 이동·형제 분기까지 백엔드가 추적한 이웃 전체가 가로(시간 진행 방향)로
// 퍼져나가는 트리 형태로 배치된다. 노드 하나 = visits 행 하나(같은 URL
// 재이동은 entry에 접힘)이고, 간선은 자식 행의 링크 컬럼 그대로다.

const NODE_W = 224;
const NODE_H = 78;
const COL_W = 296;
const ROW_H = 100;
const PAD = 40;
const MIN_ZOOM = 0.08;
const MAX_ZOOM = 2.5;
// 초기 뷰에서 이 배율보다 작아져야 전체가 보이면, 전체 맞춤 대신 선택
// 항목 중심으로 연다 (긴 사슬이 알아볼 수 없는 실선으로 나오는 것 방지).
const FIT_READABLE = 0.5;
const FOCUS_ZOOM = 0.9;

interface LaidNode {
  node: VisitGraphNode;
  x: number;
  y: number;
}

interface Layout {
  nodes: LaidNode[];
  edges: VisitGraphEdge[];
  /** 자식 → 그 노드로 들어오는 간선(부모 연결). 노드당 최대 1개. */
  parentOf: Map<string, VisitGraphEdge>;
  width: number;
  height: number;
}

function visitDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return (url || "").replace(/^https?:\/\//, "").split("/")[0] || url;
  }
}

// 각 노드는 부모가 최대 1개(백엔드의 접힌 그래프 계약)라 숲(forest)이다 —
// 깊이(루트로부터의 거리)를 열로, 리프 순서 기반 tidy 배치를 행으로 쓴다.
function layoutGraph(graph: BrowserVisitGraph): Layout {
  const byId = new Map(graph.nodes.map((n) => [n.visitId, n]));
  const children = new Map<string, string[]>();
  const parentOf = new Map<string, VisitGraphEdge>();
  for (const edge of graph.edges) {
    if (!byId.has(edge.from) || !byId.has(edge.to) || parentOf.has(edge.to)) continue;
    parentOf.set(edge.to, edge);
    const list = children.get(edge.from);
    if (list) list.push(edge.to);
    else children.set(edge.from, [edge.to]);
  }
  const timeOf = (id: string) => byId.get(id)?.time || "";
  const idNum = (id: string) => {
    const n = Number(id);
    return Number.isFinite(n) ? n : Number.MAX_SAFE_INTEGER;
  };
  const byVisitOrder = (a: string, b: string) =>
    timeOf(a) < timeOf(b) ? -1 : timeOf(a) > timeOf(b) ? 1 : idNum(a) - idNum(b);

  const pos = new Map<string, { col: number; row: number }>();
  const visited = new Set<string>();
  let row = 0;
  const place = (id: string, depth: number): number => {
    visited.add(id);
    const kids = (children.get(id) ?? []).filter((k) => !visited.has(k)).sort(byVisitOrder);
    let y: number;
    if (kids.length === 0) {
      y = row;
      row += 1;
    } else {
      const ys = kids.map((k) => place(k, depth + 1));
      y = (ys[0] + ys[ys.length - 1]) / 2;
    }
    pos.set(id, { col: depth, row: y });
    return y;
  };
  const roots = graph.nodes
    .filter((n) => !parentOf.has(n.visitId))
    .map((n) => n.visitId)
    .sort(byVisitOrder);
  for (const root of roots) {
    if (!visited.has(root)) {
      place(root, 0);
      row += 0.35; // 트리 사이 간격
    }
  }
  // 순환 데이터 방어 — 어느 루트에서도 닿지 못한 노드도 반드시 배치한다.
  for (const n of graph.nodes) {
    if (!visited.has(n.visitId)) {
      place(n.visitId, 0);
      row += 0.35;
    }
  }

  let maxCol = 0;
  let maxRow = 0;
  const laid: LaidNode[] = graph.nodes.map((n) => {
    const p = pos.get(n.visitId) ?? { col: 0, row: 0 };
    maxCol = Math.max(maxCol, p.col);
    maxRow = Math.max(maxRow, p.row);
    return { node: n, x: PAD + p.col * COL_W, y: PAD + p.row * ROW_H };
  });
  return {
    nodes: laid,
    edges: graph.edges.filter((e) => parentOf.get(e.to) === e),
    parentOf,
    width: PAD * 2 + maxCol * COL_W + NODE_W,
    height: PAD * 2 + maxRow * ROW_H + NODE_H,
  };
}

function GraphNodeCard({ laid, selected, onSelect }: { laid: LaidNode; selected: boolean; onSelect: () => void }) {
  const n = laid.node;
  const accent = n.isTarget ? "var(--danger)" : "var(--accent)";
  const border = n.isTarget
    ? "color-mix(in srgb, var(--danger) 60%, var(--border))"
    : selected
      ? "var(--accent)"
      : "var(--border)";
  return (
    <button
      type="button"
      onClick={onSelect}
      title={`${n.title ? `${n.title}\n` : ""}${n.url}`}
      style={{
        position: "absolute",
        left: laid.x,
        top: laid.y,
        width: NODE_W,
        height: NODE_H,
        display: "flex",
        flexDirection: "column",
        alignItems: "stretch",
        gap: 3,
        padding: "8px 10px",
        borderRadius: "var(--radius-md)",
        border: `1px solid ${border}`,
        background: n.isTarget ? "color-mix(in srgb, var(--danger) 8%, var(--bg-elevated))" : "var(--bg-elevated)",
        boxShadow: selected
          ? `0 0 0 2px color-mix(in srgb, ${accent} 45%, transparent)`
          : n.isTarget
            ? "0 0 0 1px color-mix(in srgb, var(--danger) 25%, transparent)"
            : "none",
        color: "var(--text)",
        cursor: "pointer",
        textAlign: "left",
        overflow: "hidden",
      }}
    >
      <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
        <span style={{ flexShrink: 0, fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700, color: accent, padding: "0px 5px", borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${accent} 13%, transparent)` }}>
          {n.visitId || "?"}
        </span>
        <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-time)" }}>{n.time || "시간 미상"}</span>
        {n.reloads > 0 && (
          <span title={`같은 URL로 ${n.reloads}회 재이동(리다이렉트·리로드)이 이 방문에 접혀 있습니다`} style={{ flexShrink: 0, marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 2, fontSize: 9.5, fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-faint)", padding: "0 4px", borderRadius: 999, border: "1px solid var(--border-subtle)", background: "var(--bg-input)" }}>
            <ReplayOutlinedIcon sx={{ fontSize: 10 }} />{n.reloads}
          </span>
        )}
        {n.isTarget && (
          <span style={{ flexShrink: 0, marginLeft: n.reloads > 0 ? 0 : "auto", fontSize: 9, fontWeight: 800, letterSpacing: 0.3, color: "var(--danger)", padding: "0 5px", borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--danger) 14%, transparent)" }}>이 항목</span>
        )}
      </span>
      <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, fontWeight: n.isTarget ? 700 : 600 }}>
        {n.title || visitDomain(n.url)}
      </span>
      <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>{n.url}</span>
    </button>
  );
}

// 하단 상세 패널 — 노드 카드에 다 못 싣는 원시 근거(전체 URL·transition·부모
// 링크 컬럼 값)를 선택한 노드에 대해 그대로 보여준다.
function NodeDetail({ node, parentEdge }: { node: VisitGraphNode; parentEdge?: VisitGraphEdge }) {
  const newTab = parentEdge?.kind === "opener_visit";
  const rows: Array<[string, React.ReactNode]> = [
    ["시간", node.time || "시간 미상"],
    ["visits.id", node.visitId || "?"],
    [
      "부모 연결",
      parentEdge ? (
        <span style={{ color: newTab ? "var(--warning)" : "var(--accent)" }}>
          {parentEdge.kind}={parentEdge.from}
          <span style={{ color: "var(--text-faint)" }}> · {newTab ? "새 탭에서 열림" : "같은 탭 이동"}</span>
        </span>
      ) : (
        "없음 · 유입 시작점 (from_visit·opener 없음)"
      ),
    ],
    ["transition", `${node.transitionRaw} · ${node.transition}`],
  ];
  if (node.reloads > 0) rows.push(["재이동", `같은 URL로 ${node.reloads}회 (리다이렉트·리로드, 이 방문에 접힘)`]);
  if (node.externalReferrer) rows.push(["외부 referrer", node.externalReferrer]);
  return (
    <div style={{ flexShrink: 0, maxHeight: 168, overflowY: "auto", borderTop: "1px solid var(--border)", padding: "10px 16px 12px", background: "var(--bg-panel)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {node.isTarget && <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: 0.3, color: "var(--danger)", padding: "1px 6px", borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--danger) 14%, transparent)" }}>이 항목의 방문</span>}
        {node.title && <span style={{ fontSize: 12.5, fontWeight: 700, overflowWrap: "anywhere" }}>{node.title}</span>}
      </div>
      <div style={{ marginTop: 4, display: "flex", alignItems: "flex-start", gap: 5, fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-dim)", overflowWrap: "anywhere", wordBreak: "break-all", userSelect: "text" }}>
        <OpenInNewOutlinedIcon sx={{ fontSize: 12, flexShrink: 0, marginTop: "2px", opacity: 0.6 }} />{node.url}
      </div>
      <div style={{ marginTop: 7, display: "grid", gridTemplateColumns: "max-content 1fr", columnGap: 12, rowGap: 3 }}>
        {rows.map(([label, value]) => (
          <span key={label} style={{ display: "contents" }}>
            <span style={{ fontSize: 10.5, fontWeight: 650, color: "var(--text-faint)" }}>{label}</span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", overflowWrap: "anywhere", wordBreak: "break-all", userSelect: "text" }}>{value}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function GraphCanvas({ graph }: { graph: BrowserVisitGraph }) {
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const viewportRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const viewRef = useRef(view);
  viewRef.current = view;
  // 팬 상태. setPointerCapture를 뷰포트에 걸면 이후 click이 노드가 아닌
  // 뷰포트를 타깃해 노드 선택이 죽는다 — 캡처 없이 window 리스너로 추적하고,
  // 드래그로 끝난 click만 suppress 플래그로 무시한다.
  const suppressClickRef = useRef(false);
  const [selectedId, setSelectedId] = useState<string | null>(() => {
    // 기본 선택: 대상(이 항목) 방문 중 가장 최근 것.
    const targets = graph.nodes.filter((n) => n.isTarget);
    const latest = targets.reduce<VisitGraphNode | null>((best, n) => (!best || n.time > best.time ? n : best), null);
    return latest?.visitId ?? graph.nodes[graph.nodes.length - 1]?.visitId ?? null;
  });

  const fit = () => {
    const el = viewportRef.current;
    if (!el) return;
    const { clientWidth: vw, clientHeight: vh } = el;
    if (vw === 0 || vh === 0) return;
    const k = Math.min(Math.max(Math.min((vw - 24) / layout.width, (vh - 24) / layout.height), MIN_ZOOM), 1);
    setView({ x: (vw - layout.width * k) / 2, y: (vh - layout.height * k) / 2, k });
  };
  // 뷰포트 가운데를 기준으로 확대·축소 (+·− 버튼용).
  const zoomBy = (factor: number) => {
    const el = viewportRef.current;
    if (!el) return;
    const cx = el.clientWidth / 2;
    const cy = el.clientHeight / 2;
    const prev = viewRef.current;
    const k = Math.min(Math.max(prev.k * factor, MIN_ZOOM), MAX_ZOOM);
    const scale = k / prev.k;
    setView({ x: cx - (cx - prev.x) * scale, y: cy - (cy - prev.y) * scale, k });
  };
  // 주어진 노드를 뷰포트 가운데로 (배율은 읽을 수 있는 수준을 보장).
  const centerOn = (id: string | null, zoom?: number) => {
    const el = viewportRef.current;
    if (!el) return;
    const laid = (id && layout.nodes.find((l) => l.node.visitId === id)) || layout.nodes[layout.nodes.length - 1];
    if (!laid) return;
    const k = zoom ?? Math.max(viewRef.current.k, FOCUS_ZOOM);
    setView({ x: el.clientWidth / 2 - (laid.x + NODE_W / 2) * k, y: el.clientHeight / 2 - (laid.y + NODE_H / 2) * k, k });
  };
  // 초기 뷰: 전체 맞춤이 읽을 수 있는 배율이면 전체를, 그래프가 길어 전체
  // 맞춤이 너무 작아지면 대신 선택 항목(대상 방문) 중심으로 확대해서 연다 —
  // 전체 조망은 ⤢ 버튼으로 언제든 가능하다.
  useLayoutEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const kFit = Math.min((el.clientWidth - 24) / layout.width, (el.clientHeight - 24) / layout.height, 1);
    if (kFit >= FIT_READABLE) fit();
    else centerOn(selectedId, FOCUS_ZOOM);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  // React의 wheel 리스너는 passive라 preventDefault가 통하지 않는다 — 직접
  // non-passive로 붙여 커서 기준 줌으로 쓴다.
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const rect = el.getBoundingClientRect();
      const px = event.clientX - rect.left;
      const py = event.clientY - rect.top;
      const prev = viewRef.current;
      const k = Math.min(Math.max(prev.k * Math.exp(-event.deltaY * 0.0016), MIN_ZOOM), MAX_ZOOM);
      const scale = k / prev.k;
      setView({ x: px - (px - prev.x) * scale, y: py - (py - prev.y) * scale, k });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const selected = selectedId ? layout.nodes.find((l) => l.node.visitId === selectedId)?.node ?? null : null;
  const targetCount = graph.nodes.filter((n) => n.isTarget).length;
  // 현재 배율에서 그래프가 뷰포트를 벗어나는지 — 벗어나면 이동 안내를 띄운다.
  const viewportEl = viewportRef.current;
  const overflowing =
    !!viewportEl &&
    (layout.width * view.k > viewportEl.clientWidth + 8 || layout.height * view.k > viewportEl.clientHeight + 8);

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
      <div
        ref={viewportRef}
        onPointerDown={(event) => {
          if (event.button !== 0) return;
          const drag = { lastX: event.clientX, lastY: event.clientY, moved: false };
          const onMove = (move: PointerEvent) => {
            const dx = move.clientX - drag.lastX;
            const dy = move.clientY - drag.lastY;
            if (!drag.moved && Math.abs(dx) + Math.abs(dy) <= 3) return;
            drag.moved = true;
            drag.lastX = move.clientX;
            drag.lastY = move.clientY;
            setView((v) => ({ ...v, x: v.x + dx, y: v.y + dy }));
          };
          const onUp = () => {
            window.removeEventListener("pointermove", onMove);
            window.removeEventListener("pointerup", onUp);
            // pointerup 직후 같은 태스크에서 click이 디스패치된다 — 그 한 번만 무시.
            suppressClickRef.current = drag.moved;
            setTimeout(() => { suppressClickRef.current = false; }, 0);
          };
          window.addEventListener("pointermove", onMove);
          window.addEventListener("pointerup", onUp);
        }}
        onClickCapture={(event) => {
          // 드래그로 끝난 클릭이 노드 선택으로 새지 않게 막는다.
          if (suppressClickRef.current) {
            event.stopPropagation();
            event.preventDefault();
          }
        }}
        style={{ position: "relative", flex: 1, minHeight: 0, overflow: "hidden", background: "var(--bg-input)", cursor: "grab", touchAction: "none" }}
      >
        <div style={{ position: "absolute", left: 0, top: 0, width: layout.width, height: layout.height, transformOrigin: "0 0", transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})` }}>
          <svg width={layout.width} height={layout.height} style={{ position: "absolute", left: 0, top: 0, overflow: "visible", pointerEvents: "none" }} aria-hidden="true">
            <defs>
              <marker id="vfg-arrow-same" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0.6 L7.4,4 L0,7.4 Z" fill="var(--accent)" />
              </marker>
              <marker id="vfg-arrow-newtab" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0.6 L7.4,4 L0,7.4 Z" fill="var(--warning)" />
              </marker>
            </defs>
            {layout.edges.map((edge) => {
              const from = layout.nodes.find((l) => l.node.visitId === edge.from);
              const to = layout.nodes.find((l) => l.node.visitId === edge.to);
              if (!from || !to) return null;
              const x1 = from.x + NODE_W;
              const y1 = from.y + NODE_H / 2;
              const x2 = to.x;
              const y2 = to.y + NODE_H / 2;
              const bend = Math.max(36, (x2 - x1) / 2);
              const newTab = edge.kind === "opener_visit";
              const color = newTab ? "var(--warning)" : "var(--accent)";
              return (
                <path
                  key={`${edge.from}-${edge.to}`}
                  d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`}
                  fill="none"
                  stroke={color}
                  strokeWidth={1.6}
                  strokeDasharray={newTab ? "5 4" : undefined}
                  strokeOpacity={0.65}
                  markerEnd={`url(#${newTab ? "vfg-arrow-newtab" : "vfg-arrow-same"})`}
                />
              );
            })}
          </svg>
          {layout.nodes.map((laid) => (
            <GraphNodeCard key={laid.node.visitId} laid={laid} selected={laid.node.visitId === selectedId} onSelect={() => setSelectedId(laid.node.visitId)} />
          ))}
        </div>
        {overflowing && (
          <div style={{ position: "absolute", top: 10, left: 10, padding: "4px 9px", borderRadius: "var(--radius-md)", border: "1px solid var(--border-subtle)", background: "color-mix(in srgb, var(--bg-panel) 88%, transparent)", color: "var(--text-faint)", fontSize: 10.5, pointerEvents: "none" }}>
            화면 밖에 더 있습니다 — 드래그·휠로 이동 · ⤢ 전체 보기
          </div>
        )}
        {/* 확대·축소 컨트롤 */}
        <div style={{ position: "absolute", top: 10, right: 10, display: "flex", gap: 5 }}>
          {([
            ["−", () => zoomBy(1 / 1.3), "축소"],
            ["+", () => zoomBy(1.3), "확대"],
            ["⌖", () => centerOn(selectedId), "선택 항목으로 이동"],
            ["⤢", fit, "전체 보기"],
          ] as Array<[string, () => void, string]>).map(([label, onClick, title]) => (
            <button key={title} type="button" onClick={onClick} title={title} aria-label={title} style={{ width: 26, height: 26, display: "inline-flex", alignItems: "center", justifyContent: "center", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 13, fontWeight: 700 }}>
              {label}
            </button>
          ))}
        </div>
        {/* 범례 + 규모 요약 */}
        <div style={{ position: "absolute", left: 10, bottom: 10, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", padding: "5px 10px", borderRadius: "var(--radius-md)", border: "1px solid var(--border-subtle)", background: "color-mix(in srgb, var(--bg-panel) 88%, transparent)", fontSize: 10.5, color: "var(--text-faint)", pointerEvents: "none" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 16, height: 0, borderTop: "2px solid var(--accent)" }} />같은 탭 이동 (from_visit)
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 16, height: 0, borderTop: "2px dashed var(--warning)" }} />새 탭 열림 (opener_visit)
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 9, height: 9, borderRadius: 3, border: "1.5px solid var(--danger)", background: "color-mix(in srgb, var(--danger) 10%, transparent)" }} />이 항목의 방문 {targetCount}개
          </span>
          <span style={{ fontFamily: "var(--mono)" }}>노드 {graph.nodes.length} · 이동 {graph.edges.length}</span>
        </div>
      </div>
      {selected && <NodeDetail node={selected} parentEdge={layout.parentOf.get(selected.visitId)} />}
    </div>
  );
}

export default function VisitFlowGraphModal({ state, graph, isCache, onRetry, onClose }: { state: "idle" | "loading" | "ready" | "error"; graph: BrowserVisitGraph | null; isCache: boolean; onRetry: () => void; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  const hasGraph = state === "ready" && graph && graph.nodes.length > 0;
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, zIndex: 1100, display: "flex", alignItems: "center", justifyContent: "center", padding: 20, background: "rgba(1,4,9,0.6)" }}>
      <div role="dialog" aria-modal="true" aria-label="브라우저 유입 흐름 그래프" onClick={(event) => event.stopPropagation()} style={{ display: "flex", flexDirection: "column", width: "min(1240px, 96vw)", height: hasGraph ? "86vh" : undefined, maxHeight: "86vh", minHeight: 0, overflow: "hidden", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)" }}>
        <header style={{ display: "flex", flexShrink: 0, alignItems: "center", gap: 10, padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <AccountTreeOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} />
          <span style={{ fontSize: 14, fontWeight: 700 }}>유입 흐름 · 페이지 이동 그래프</span>
          {graph?.sourceFile && <span style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{graph.sourceFile}</span>}
          <button ref={closeRef} type="button" onClick={onClose} aria-label="닫기" style={{ marginLeft: "auto", display: "inline-flex", padding: 4, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}>
            <CloseIcon sx={{ fontSize: 18 }} />
          </button>
        </header>
        {state === "loading" && <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-dim)", fontSize: 12.5, padding: 24 }}><CircularProgress size={16} thickness={4} sx={{ color: "var(--accent)" }} />원본 방문 기록에서 이동 그래프 복원 중…</div>}
        {state === "error" && (
          <div role="alert" style={{ display: "flex", flexDirection: "column", gap: 10, padding: 24, color: "var(--text-dim)", fontSize: 12.5 }}>
            유입 흐름을 불러오지 못했습니다.
            <button type="button" onClick={onRetry} style={{ alignSelf: "flex-start", padding: "5px 10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg-elevated)", color: "var(--text)", cursor: "pointer", fontSize: 12 }}>다시 시도</button>
          </div>
        )}
        {state === "ready" && !hasGraph && <div role="status" style={{ padding: 24, color: "var(--text-faint)", fontSize: 12.5, lineHeight: 1.6 }}>{graph?.note || "이 항목에 대한 방문 유입 흐름을 찾지 못했습니다."}</div>}
        {hasGraph && (
          <>
            {(isCache && graph!.matchedPage) || graph!.truncated ? (
              <div style={{ flexShrink: 0, display: "flex", flexDirection: "column", gap: 6, padding: "9px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
                {isCache && graph!.matchedPage && (
                  <div style={{ color: "var(--text-dim)", fontSize: 11.5, lineHeight: 1.5 }}>
                    {graph!.note}
                    <span style={{ marginLeft: 6, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)", wordBreak: "break-all" }}>기준 페이지: {graph!.matchedPage}</span>
                  </div>
                )}
                {graph!.truncated && <div role="status" style={{ color: "var(--warning)", fontSize: 11.5 }}>방문·연결이 많아 가까운 일부만 표시했습니다 — 더 많은 이동이 있을 수 있습니다.</div>}
              </div>
            ) : null}
            <GraphCanvas graph={graph!} />
          </>
        )}
      </div>
    </div>
  );
}
