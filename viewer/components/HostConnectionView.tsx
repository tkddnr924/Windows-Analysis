"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import useMediaQuery from "@mui/material/useMediaQuery";
import CircularProgress from "@mui/material/CircularProgress";
import ZoomInOutlinedIcon from "@mui/icons-material/ZoomInOutlined";
import ZoomOutOutlinedIcon from "@mui/icons-material/ZoomOutOutlined";
import CenterFocusStrongOutlinedIcon from "@mui/icons-material/CenterFocusStrongOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import OpenInNewOutlinedIcon from "@mui/icons-material/OpenInNewOutlined";
import { graphEdgesForScope } from "@/lib/hostGraphScope";
import PaginationControls from "@/components/PaginationControls";
import {
  EMPTY_TIME_RANGE,
  formatEvidenceTimestamp,
  inRange,
  rangeActive,
  type TimeRange,
} from "@/lib/timeRange";

export interface HostNode {
  name: string;
  ips: string[];
}
export type PeerKind = "host" | "external" | "local" | "loopback";
export type ConnDirection = "inbound" | "outbound" | "unknown";
export interface ConnRecord {
  host: string;
  peer: string;
  peerLabel: string;
  peerKind: PeerKind;
  peerIsHost: boolean;
  direction: ConnDirection;
  timestamp: string;
  account: string;
  result: string;
}
export interface HostGraph {
  hosts: HostNode[];
  records: ConnRecord[];
  rdpSourceFailures?: string[];
  networkMappingFailures?: string[];
}
interface Edge {
  key: string;
  host: string;
  peer: string;
  direction: ConnDirection;
  rows: ConnRecord[];
  count: number;
  first: string;
  last: string;
  accounts: string[];
  success: number;
  fail: number;
}
interface Node {
  key: string;
  label: string;
  registered: boolean;
  x: number;
  y: number;
}
interface Props {
  graph: HostGraph | null;
  loading: boolean;
  timeRange?: TimeRange;
  focusHostName?: string | null;
  onRefresh?: () => void;
  onOpenHost?: (name: string) => void;
}
const DEFAULT_GRAPH = { width: 960, height: 560 };
const PEER = 16, FOCUS = 22, LIMIT = 12, ALL_LIMIT = 30;
const NODE_LABEL_WIDTH = 124;
const NODE_LABEL_BOTTOM = 36;
const graphLabelWidth = (width: number) =>
  Math.max(1, Math.min(NODE_LABEL_WIDTH, Math.max(1, width - 16)));
const graphLabelHalf = (width: number) => graphLabelWidth(width) / 2;
const key = (v: string) => v.toLocaleLowerCase();
const dir = (v: ConnDirection) =>
  v === "inbound"
    ? "인바운드"
    : v === "outbound"
    ? "아웃바운드"
    : "방향 정보 없음";
function edges(rows: ConnRecord[]): Edge[] {
  const map = new Map<string, ConnRecord[]>();
  rows.forEach((r) => {
    const k = `${r.host}\u0000${r.peer}\u0000${r.direction}`;
    map.set(k, [...(map.get(k) ?? []), r]);
  });
  return [...map.entries()].map(([key, rows]) => {
    const d = rows.map((r) => r.timestamp).filter(Boolean).sort();
    return {
      key,
      host: rows[0].host,
      peer: rows[0].peerLabel,
      direction: rows[0].direction,
      rows,
      count: rows.length,
      first: d[0] ?? "",
      last: d.at(-1) ?? "",
      accounts: [...new Set(rows.map((r) => r.account).filter(Boolean))],
      success: rows.filter((r) => r.result === "성공").length,
      fail: rows.filter((r) => r.result === "실패").length,
    };
  }).sort((a, b) =>
    b.fail - a.fail || b.count - a.count ||
    (b.last || "").localeCompare(a.last || "")
  );
}
function catalog(hosts: HostNode[], es: Edge[]) {
  const known = new Set(hosts.map((h) => key(h.name))),
    m = new Map<string, { key: string; label: string; registered: boolean }>();
  hosts.forEach((h) =>
    m.set(key(h.name), { key: key(h.name), label: h.name, registered: true })
  );
  es.forEach((e) => {
    m.set(key(e.host), {
      key: key(e.host),
      label: e.host,
      registered: known.has(key(e.host)),
    });
    const k = key(e.peer);
    m.set(k, {
      key: k,
      label: e.peer,
      registered: m.get(k)?.registered ?? known.has(k),
    });
  });
  return [...m.values()].sort((a, b) =>
    Number(b.registered) - Number(a.registered) ||
    a.label.localeCompare(b.label, "ko")
  );
}
function pickFocus(
  ns: ReturnType<typeof catalog>,
  es: Edge[],
  wanted?: string | null,
) {
  const registered = ns.filter((node) => node.registered);
  const requested = wanted && key(wanted);
  if (requested && registered.some((n) => n.key === requested)) return requested;
  const score = new Map<string, number>();
  es.forEach((e) =>
    [key(e.host), key(e.peer)].forEach((k) =>
      score.set(k, (score.get(k) ?? 0) + e.count + e.fail * 5)
    )
  );
  return (registered.length ? registered : ns).sort((a, b) =>
    (score.get(b.key) ?? 0) - (score.get(a.key) ?? 0) ||
    a.label.localeCompare(b.label, "ko")
  )[0]?.key ?? null;
}
/**
 * The inspector must describe the same subset that is drawn.  In the
 * host-focused view a case can have relations for another registered host;
 * showing those in the list while drawing the selected host made the graph
 * look broken (and, more importantly, mixed two different investigations).
 */
function layout(
  hosts: HostNode[],
  es: Edge[],
  focus: string | null,
  all: boolean,
  viewport = DEFAULT_GRAPH,
) {
  // The model always follows the actual measured viewport.  A graph that is
  // wider or taller than its overflow-hidden pane makes nodes unreachable on
  // compact windows, so do not impose a virtual canvas minimum here.
  const w = Math.max(1, viewport.width);
  const h = Math.max(1, viewport.height);
  const labelHalf = graphLabelHalf(w);
  const insetX = Math.min(
    w / 2,
    Math.max(labelHalf + 4, Math.min(68, Math.max(26, w * .1))),
  );
  const insetY = Math.min(66, Math.max(30, h * .12));
  const ns = catalog(hosts, es);
  if (all) {
    const shown = es.slice(0, ALL_LIMIT), used = catalog(hosts, shown);
    const cols = Math.max(
      3,
      Math.min(6, Math.floor((w - 120) / 145) || 3),
    );
    const rows = Math.max(1, Math.ceil(used.length / cols));
    const xGap = cols > 1 ? Math.max(0, (w - insetX * 2) / (cols - 1)) : 0;
    const yGap = rows > 1 ? Math.max(0, (h - insetY * 2) / (rows - 1)) : 0;
    return {
      nodes: used.map((n, i) => ({
        ...n,
        x: cols === 1 ? w / 2 : insetX + (i % cols) * xGap,
        y: rows === 1 ? h / 2 : insetY + Math.floor(i / cols) * yGap,
      })),
      shown,
      hidden: es.length - shown.length,
      w,
      h,
      focus: null,
    };
  }
  const f = ns.find((n) => n.key === focus) ?? ns[0];
  if (!f) {
    return { nodes: [], shown: [], hidden: 0, w, h, focus: null };
  }
  const rel = es.filter((e) => key(e.host) === f.key || key(e.peer) === f.key),
    shown = rel.slice(0, LIMIT),
    groups: {
      in: { key: string; label: string; registered: boolean }[];
      out: { key: string; label: string; registered: boolean }[];
      unknown: { key: string; label: string; registered: boolean }[];
    } = { in: [], out: [], unknown: [] };
  const seen = new Set<string>();
  shown.forEach((e) => {
    const other = key(e.host) === f.key ? key(e.peer) : key(e.host);
    if (seen.has(other)) return;
    seen.add(other);
    const n = ns.find((n) => n.key === other);
    if (!n) return;
    const rels = shown.filter((x) =>
      key(x.host) === other || key(x.peer) === other
    );
    const ds = new Set(rels.map((x) => {
      if (x.direction === "unknown") return "unknown";
      const owner = key(x.host) === f.key;
      return (owner && x.direction === "outbound") ||
          (!owner && x.direction === "inbound")
        ? "out"
        : "in";
    }));
    groups[ds.size === 1 ? [...ds][0] : "unknown"].push(n);
  });
  const side = Math.max(groups.in.length, groups.out.length);
  const cy = Math.round(h / 2);
  const lanePitch = Math.max(0, Math.min(118, (h - insetY * 2) / Math.max(1, side - 1)));
  const nodes: Node[] = [{ ...f, x: w / 2, y: cy }];
  const put = (xs: typeof groups.in, x: number, y: number) =>
    xs.forEach((n, i) =>
      nodes.push({ ...n, x, y: y - (xs.length - 1) * lanePitch / 2 + i * lanePitch })
    );
  put(groups.in, Math.max(insetX, w * .18), cy);
  put(groups.out, Math.min(w - insetX, w * .82), cy);
  put(groups.unknown, w / 2, Math.min(h - insetY, cy + side * lanePitch / 2 + 86));
  return {
    nodes,
    shown,
    hidden: rel.length - shown.length,
    w,
    h,
    focus: f.key,
  };
}
function Button(
  { children, ...p }:
    & { children: React.ReactNode }
    & React.ButtonHTMLAttributes<HTMLButtonElement>,
) {
  return (
    <button type="button" className="nm-btn" {...p} style={{ ...button, ...p.style }}>
      {children}
    </button>
  );
}
export default function HostConnectionView(
  {
    graph,
    loading,
    timeRange = EMPTY_TIME_RANGE,
    focusHostName,
    onRefresh,
    onOpenHost,
  }: Props,
) {
  const [search, setSearch] = useState(""),
    [direction, setDirection] = useState<"all" | ConnDirection>("all"),
    [result, setResult] = useState<"all" | "success" | "fail">("all"),
    [includeLocal, setIncludeLocal] = useState(false),
    [includeLoopback, setIncludeLoopback] = useState(false),
    [scope, setScope] = useState<"host" | "overall">("host"),
    [focus, setFocus] = useState<string | null>(null),
    [selected, setSelected] = useState<string | null>(null);
  const compactLayout = useMediaQuery("(max-width: 1000px)");
  const range = rangeActive(timeRange),
    rows = graph?.records ?? [],
    scoped = useMemo(
      () =>
        rows.filter((r) =>
          (!range || Boolean(r.timestamp) && inRange(r.timestamp, timeRange)) &&
          (includeLocal || r.peerKind !== "local") &&
          (includeLoopback || r.peerKind !== "loopback") &&
          (direction === "all" || r.direction === direction) &&
          (result === "all" ||
            (result === "success"
              ? r.result === "성공"
              : r.result === "실패")) &&
          (!search.trim() ||
            [r.host, r.peer, r.peerLabel, r.account, r.result].some((v) =>
              v.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())
            ))
        ),
      [
        rows,
        range,
        timeRange,
        includeLocal,
        includeLoopback,
        direction,
        result,
        search,
      ],
    );
  const es = useMemo(() => edges(scoped), [scoped]),
    ns = useMemo(() => catalog(graph?.hosts ?? [], es), [graph?.hosts, es]),
    registeredNodes = useMemo(() => ns.filter((node) => node.registered), [ns]),
    defaultFocus = useMemo(() => pickFocus(ns, es, focusHostName), [
      ns,
      es,
      focusHostName,
    ]),
    activeFocus = focus && registeredNodes.some((n) => n.key === focus)
      ? focus
      : defaultFocus,
    visibleEdges = useMemo(
      () => graphEdgesForScope(es, activeFocus, scope === "overall"),
      [es, activeFocus, scope],
    ),
    focusHostLabel = registeredNodes.find((node) => node.key === activeFocus)
      ?.label ?? null,
    edge = visibleEdges.find((e) => e.key === selected) ?? null,
    noTime = range ? rows.filter((r) => !r.timestamp).length : 0;
  if (loading) {
    return (
      <Center>
        <CircularProgress size={18} />원격 접근 관계를 불러오는 중입니다.
      </Center>
    );
  }
  if (!graph) {
    return (
      <Center>
        원격 접근 관계를 불러오지 못했습니다.{" "}
        {onRefresh && <Button onClick={onRefresh}>다시 불러오기</Button>}
      </Center>
    );
  }
  const selectNode = (node: Node) => {
    if (node.registered) {
      setFocus(node.key);
      setSelected(null);
      setScope("host");
      return;
    }
    const related = es.find((edge) =>
      key(edge.host) === node.key || key(edge.peer) === node.key
    );
    if (related) setSelected(related.key);
  };
  return (
    <main
      className="dfir-view"
      style={{
        flex: 1,
        minHeight: 0,
        overflow: "auto",
        padding: "18px 20px",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <section style={surface}>
        <header style={head}>
          <strong>원격 접근 관계 (RDP)</strong>
          <span>
            {scoped.length.toLocaleString()}개 이벤트 ·{" "}
            {es.length.toLocaleString()}개 관계
          </span>
          <span>{range ? "전역 기간 필터 적용" : "전체 기간"}</span>
          {graph.rdpSourceFailures?.length
            ? (
              <span style={warning}>
                일부 RDP 원본 미확인 {graph.rdpSourceFailures.length}건
              </span>
            )
            : null}
          {graph.networkMappingFailures?.length
            ? (
              <span>
                네트워크 매핑 미확인 {graph.networkMappingFailures.length}건
              </span>
            )
            : null}
          {onRefresh && (
            <Button onClick={onRefresh} style={{ marginLeft: "auto" }}>
              <RefreshOutlinedIcon sx={{ fontSize: 15 }} />새로고침
            </Button>
          )}
        </header>
        <div style={toolbar}>
          <Button
            aria-pressed={includeLocal}
            onClick={() => setIncludeLocal((v) => !v)}
          >
            로컬 {includeLocal ? "포함" : "제외"}
          </Button>
          <Button
            aria-pressed={includeLoopback}
            onClick={() => setIncludeLoopback((v) => !v)}
          >
            루프백 {includeLoopback ? "포함" : "제외"}
          </Button>
          <select
            aria-label="방향 필터"
            value={direction}
            onChange={(e) => setDirection(e.target.value as typeof direction)}
            style={field}
          >
            <option value="all">방향 전체</option>
            <option value="inbound">인바운드</option>
            <option value="outbound">아웃바운드</option>
            <option value="unknown">방향 정보 없음</option>
          </select>
          <select
            aria-label="결과 필터"
            value={result}
            onChange={(e) => setResult(e.target.value as typeof result)}
            style={field}
          >
            <option value="all">결과 전체</option>
            <option value="success">성공</option>
            <option value="fail">실패</option>
          </select>
          <div role="group" aria-label="관계 그래프 범위" style={{ display: "inline-flex" }}>
            <Button aria-pressed={scope === "host"} onClick={() => setScope("host")} style={{ borderRadius: "var(--radius-sm) 0 0 var(--radius-sm)", borderColor: scope === "host" ? "var(--accent)" : "var(--border)", background: scope === "host" ? "var(--accent-subtle)" : "transparent", color: scope === "host" ? "var(--accent)" : "var(--text-dim)" }}>
              호스트별 관계
            </Button>
            <Button aria-pressed={scope === "overall"} onClick={() => setScope("overall")} style={{ marginLeft: -1, borderRadius: "0 var(--radius-sm) var(--radius-sm) 0", borderColor: scope === "overall" ? "var(--accent)" : "var(--border)", background: scope === "overall" ? "var(--accent-subtle)" : "transparent", color: scope === "overall" ? "var(--accent)" : "var(--text-dim)" }}>
              관계 개요
            </Button>
          </div>
          <select
            aria-label="등록 호스트 중심 선택"
            value={activeFocus ?? ""}
            onChange={(e) => {
              setFocus(e.target.value);
              setSelected(null);
              setScope("host");
            }}
            style={field}
          >
            <option value="">등록 호스트 선택</option>
            {registeredNodes.map((n) => <option key={n.key} value={n.key}>{n.label}
            </option>)}
          </select>
          <input
            aria-label="호스트, 상대, 계정 검색"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="호스트 · 상대 · 계정 검색"
            style={{
              ...field,
              marginLeft: "auto",
              minWidth: 210,
              flex: "1 1 230px",
            }}
          />
        </div>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: compactLayout
              ? "minmax(0,1fr)"
              : "minmax(0,1fr) minmax(286px,340px)",
            gridTemplateRows: compactLayout ? "minmax(280px, 1fr) auto" : undefined,
            minHeight: 0,
            // A percentage height beneath an auto-sized grid can briefly be
            // zero during the desktop shell's view transition. Give the graph
            // row a real flex basis, so its ResizeObserver never receives an
            // unusable canvas and a selected, isolated host remains visible.
            minBlockSize: 460,
            flex: "1 1 460px",
          }}
        >
          <GraphPane
            hosts={graph.hosts}
            edges={visibleEdges}
            focus={activeFocus}
            overall={scope === "overall"}
            selected={selected}
            onNode={selectNode}
            hasRows={rows.length > 0}
            showNoTime={range && noTime > 0}
            noTime={noTime}
          />
          <aside
            style={{
              padding: 14,
              borderLeft: compactLayout ? undefined : "1px solid var(--border)",
              borderTop: compactLayout ? "1px solid var(--border)" : undefined,
              overflow: "auto",
            }}
          >
            {edge
              ? (
                <Inspector
                  edge={edge}
                  onOpenHost={onOpenHost}
                  hosts={new Set(graph.hosts.map((h) => h.name))}
                />
              )
              : <List
                edges={visibleEdges}
                focusHostName={scope === "host" ? focusHostLabel : null}
                onSelect={setSelected}
              />}
          </aside>
        </div>
      </section>
    </main>
  );
}
type ForcePoint = Node & {
  vx: number;
  vy: number;
  pinned: boolean;
  anchorX: number;
  anchorY: number;
};
type GraphDrag =
  | { kind: "pan"; x: number; y: number; px: number; py: number; moved: boolean }
  | { kind: "node"; key: string; x: number; y: number; moved: boolean }
  | null;

function GraphPane(
  {
    hosts,
    edges: allEdges,
    focus,
    overall,
    selected,
    onNode,
    hasRows,
    showNoTime,
    noTime,
  }: {
    hosts: HostNode[];
    edges: Edge[];
    focus: string | null;
    overall: boolean;
    selected: string | null;
    onNode: (node: Node) => void;
    hasRows: boolean;
    showNoTime: boolean;
    noTime: number;
  },
) {
  const viewportRef = useRef<HTMLElement>(null);
  const [viewport, setViewport] = useState(DEFAULT_GRAPH);
  useEffect(() => {
    const element = viewportRef.current;
    if (!element) return;
    const measure = () => {
      const rect = element.getBoundingClientRect();
      // Ignore the transient zero-size observation while a responsive layout
      // is being mounted.  Once it has a real size, use it verbatim rather
      // than growing the virtual graph beyond the visible pane.
      if (rect.width <= 0 || rect.height <= 0) return;
      setViewport((current) => {
        const next = {
          width: Math.max(1, Math.floor(rect.width)),
          height: Math.max(1, Math.floor(rect.height)),
        };
        return current.width === next.width && current.height === next.height
          ? current
          : next;
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const value = useMemo(
    () => layout(hosts, allEdges, focus, overall, viewport),
    [hosts, allEdges, focus, overall, viewport],
  );
  const hasGraph = allEdges.length > 0 || (!overall && Boolean(focus));
  return (
    <section
      ref={viewportRef}
      aria-label="RDP 관계 그래프"
      style={{
        minWidth: 0,
        minHeight: 460,
        height: "100%",
        position: "relative",
        overflow: "hidden",
        background: "var(--bg-app)",
      }}
    >
      {hasGraph
        ? <ForceGraph value={value} selected={selected} onNode={onNode} />
        : (
          <Center>
            {hasRows
              ? "현재 필터 조건에 맞는 RDP 관계가 없습니다."
              : "확인된 RDP 접속 기록이 없습니다."}
          </Center>
        )}
      {(overall || showNoTime || (!overall && value.nodes.length === 1)) && (
        <div style={noticeOverlay}>
          {overall && (
            <div style={notice}>
              {`관계 개요 · 상위 ${value.shown.length.toLocaleString()} / 전체 ${allEdges.length.toLocaleString()} 관계 (실패 수 · 이벤트 수 · 최근 시각 순)`}
            </div>
          )}
          {showNoTime && (
            <div style={notice}>
              시간 정보가 없는 이벤트 {noTime.toLocaleString()}개는 기간 범위에서 제외했습니다.
            </div>
          )}
          {!overall && value.nodes.length === 1 && (
            <div style={notice}>선택한 등록 호스트와 직접 연결된 RDP 관계가 없습니다.</div>
          )}
        </div>
      )}
    </section>
  );
}

function seedFor(value: string) {
  return [...value].reduce((hash, char) => ((hash * 31) + char.charCodeAt(0)) >>> 0, 7);
}

function ForceGraph(
  { value, selected, onNode }: {
    value: ReturnType<typeof layout>;
    selected: string | null;
    onNode: (node: Node) => void;
  },
) {
  const [z, setZ] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [revision, setRevision] = useState(0);
  const [points, setPoints] = useState<ForcePoint[]>([]);
  const pointsRef = useRef<ForcePoint[]>([]);
  const drag = useRef<GraphDrag>(null);
  const suppressNodeClick = useRef(new Set<string>());
  const userTransform = useRef(false);
  const raf = useRef<number | null>(null);
  const viewportRef = useRef<HTMLDivElement>(null);
  const previous = useRef<{
    model: string;
    revision: number;
    width: number;
    height: number;
  } | null>(null);
  const nodeRadius = (point: ForcePoint) => point.key === value.focus ? FOCUS : PEER;
  const limits = (point: ForcePoint) => {
    const radius = nodeRadius(point);
    const labelHalf = graphLabelHalf(value.w);
    const side = Math.min(
      value.w / 2,
      Math.max(radius + 8, labelHalf + 4, value.w * .1),
    );
    const top = Math.min(58, Math.max(radius + 10, value.h * .12));
    const bottom = Math.min(
      radius + NODE_LABEL_BOTTOM,
      Math.max(radius + 10, value.h * .12),
    );
    return {
      minX: Math.min(value.w / 2, side),
      maxX: Math.max(Math.min(value.w / 2, side), value.w - side),
      minY: Math.min(value.h / 2, top),
      maxY: Math.max(Math.min(value.h / 2, top), value.h - bottom),
    };
  };
  const constrain = (point: ForcePoint, x: number, y: number) => {
    const bound = limits(point);
    return {
      x: Math.max(bound.minX, Math.min(bound.maxX, x)),
      y: Math.max(bound.minY, Math.min(bound.maxY, y)),
    };
  };
  const commit = (next: ForcePoint[]) => {
    pointsRef.current = next;
    setPoints(next.map((point) => ({ ...point })));
  };
  const applyFit = (visible: ForcePoint[]) => {
    if (!visible.length) {
      setZ(1);
      setPan({ x: 0, y: 0 });
      return;
    }
    const labelHalf = graphLabelHalf(value.w);
    const minX = Math.min(...visible.map((point) => point.x - labelHalf));
    const maxX = Math.max(...visible.map((point) => point.x + labelHalf));
    const minY = Math.min(...visible.map((point) => point.y - nodeRadius(point) - 18));
    const maxY = Math.max(...visible.map((point) => point.y + nodeRadius(point) + NODE_LABEL_BOTTOM));
    const width = Math.max(1, maxX - minX);
    const height = Math.max(1, maxY - minY);
    const scale = Math.max(
      .35,
      Math.min(1.8, Math.min(Math.max(1, value.w - 32) / width, Math.max(1, value.h - 48) / height)),
    );
    setZ(scale);
    setPan({
      x: (value.w - width * scale) / 2 - minX * scale,
      y: (value.h - height * scale) / 2 - minY * scale,
    });
  };

  useEffect(() => {
    if (raf.current) cancelAnimationFrame(raf.current);
    const centerX = value.w / 2;
    const centerY = value.h / 2;
    const model = `${value.focus ?? ""}|${value.nodes.map((node) => node.key).sort().join("|")}|${value.shown.map((edge) => edge.key).sort().join("|")}`;
    const prior = previous.current;
    const preserve = prior?.model === model && prior.revision === revision;
    if (!preserve) userTransform.current = false;
    const shouldAutoFit = !userTransform.current;
    const priorPoints = new Map(pointsRef.current.map((point) => [point.key, point]));
    const initial = value.nodes.map((node) => {
      const hash = seedFor(`${node.key}:${revision}`);
      const jitterX = ((hash % 1000) / 1000 - .5) * 72;
      const jitterY = (((hash >>> 10) % 1000) / 1000 - .5) * 96;
      const point: ForcePoint = {
        ...node,
        x: node.key === value.focus ? centerX : node.x + jitterX,
        y: node.key === value.focus ? centerY : node.y + jitterY,
        vx: 0,
        vy: 0,
        pinned: node.key === value.focus,
        anchorX: node.x,
        anchorY: node.y,
      };
      const previousPoint = priorPoints.get(node.key);
      if (preserve && previousPoint && prior) {
        point.x = previousPoint.x / prior.width * value.w;
        point.y = previousPoint.y / prior.height * value.h;
        point.pinned = previousPoint.pinned || node.key === value.focus;
      }
      const position = constrain(point, point.x, point.y);
      point.x = position.x;
      point.y = position.y;
      return point;
    });
    previous.current = { model, revision, width: value.w, height: value.h };
    pointsRef.current = initial;
    setPoints(initial);
    if (shouldAutoFit) applyFit(initial);
    let ticks = 0;
    const overview = value.focus === null;
    const run = () => {
      const next = pointsRef.current.map((point) => ({ ...point }));
      const byKey = new Map(next.map((point) => [point.key, point]));
      for (let i = 0; i < next.length; i++) {
        const point = next[i];
        if (point.pinned) continue;
        const direction = value.shown.find((edge) => key(edge.host) === point.key || key(edge.peer) === point.key)?.direction;
        const targetX = overview
          ? point.anchorX
          : direction === "inbound"
          ? value.w * .18
          : direction === "outbound"
          ? value.w * .82
          : centerX;
        const targetY = overview
          ? point.anchorY
          : direction === "unknown"
          ? value.h * .76
          : centerY;
        point.vx += (targetX - point.x) * (overview ? .015 : .01);
        point.vy += (targetY - point.y) * (overview ? .015 : .01);
      }
      for (let i = 0; i < next.length; i++) for (let j = i + 1; j < next.length; j++) {
        const a = next[i], b = next[j];
        const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
        const minimum = nodeRadius(a) + nodeRadius(b) + 42;
        const repel = Math.max(0, minimum * minimum / distance - 10) * .032;
        const ux = dx / distance, uy = dy / distance;
        if (!a.pinned) { a.vx -= ux * repel; a.vy -= uy * repel; }
        if (!b.pinned) { b.vx += ux * repel; b.vy += uy * repel; }
      }
      value.shown.forEach((edge) => {
        const a = byKey.get(key(edge.host)), b = byKey.get(key(edge.peer));
        if (!a || !b) return;
        const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
        const desiredDistance = Math.max(180, Math.min(440, value.w * (overview ? .34 : .42)));
        const pull = (distance - desiredDistance) * (overview ? .006 : .012);
        const ux = dx / distance, uy = dy / distance;
        if (!a.pinned) { a.vx += ux * pull; a.vy += uy * pull; }
        if (!b.pinned) { b.vx -= ux * pull; b.vy -= uy * pull; }
      });
      next.forEach((point) => {
        if (point.pinned) return;
        point.vx *= .78;
        point.vy *= .78;
        const position = constrain(point, point.x + point.vx, point.y + point.vy);
        point.x = position.x;
        point.y = position.y;
      });
      pointsRef.current = next;
      ticks++;
      if (ticks % 3 === 0 || ticks >= 210) setPoints(next.map((point) => ({ ...point })));
      if (ticks < 210) raf.current = requestAnimationFrame(run);
      else if (shouldAutoFit && !userTransform.current) applyFit(next);
    };
    raf.current = requestAnimationFrame(run);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [value, revision]);

  // Effects run after paint. More importantly, a shell resize can invalidate
  // the current simulation before its next animation frame. Render the model
  // positions until the simulation has a complete matching point set instead
  // of leaving a data-backed graph blank in that interval.
  const renderPoints = points.length === value.nodes.length &&
      points.every((point) => value.nodes.some((node) => node.key === point.key))
    ? points
    : value.nodes.map((node) => ({
      ...node,
      vx: 0,
      vy: 0,
      pinned: node.key === value.focus,
      anchorX: node.x,
      anchorY: node.y,
    }));
  const renderByKey = useMemo(
    () => new Map(renderPoints.map((point) => [point.key, point])),
    [renderPoints],
  );
  const fitView = () => {
    userTransform.current = true;
    applyFit(pointsRef.current);
  };
  const reflow = () => {
    userTransform.current = false;
    setRevision((current) => current + 1);
  };
  const endDrag = () => {
    const state = drag.current;
    if (state?.kind === "node" && state.moved) {
      suppressNodeClick.current.add(state.key);
      userTransform.current = true;
    }
    if (state?.kind === "pan" && state.moved) {
      userTransform.current = true;
    }
    drag.current = null;
    // `drag` is a ref so a terminal pointer event otherwise would not repaint
    // the grab cursor after a cancelled/captured interaction.
    setPan((current) => ({ ...current }));
  };
  const graphPoint = (event: React.PointerEvent) => {
    const bounds = viewportRef.current?.getBoundingClientRect();
    if (!bounds) return { x: 0, y: 0 };
    return { x: (event.clientX - bounds.left - pan.x) / z, y: (event.clientY - bounds.top - pan.y) / z };
  };
  return (
    <div
      ref={viewportRef}
      style={{ position: "relative", width: "100%", height: "100%", minHeight: 0, overflow: "hidden" }}
      onPointerMove={(e) => {
        const state = drag.current;
        if (!state) return;
        if (state.kind === "pan") {
          if (Math.hypot(e.clientX - state.x, e.clientY - state.y) > 4) state.moved = true;
          setPan({
            x: state.px + e.clientX - state.x,
            y: state.py + e.clientY - state.y,
          });
        } else {
          const position = graphPoint(e);
          const point = pointsRef.current.find((item) => item.key === state.key);
          if (!point) return;
          if (Math.hypot(e.clientX - state.x, e.clientY - state.y) > 4) state.moved = true;
          const next = constrain(point, position.x, position.y);
          point.x = next.x;
          point.y = next.y;
          point.vx = 0; point.vy = 0; point.pinned = true;
          commit(pointsRef.current);
        }
      }}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onLostPointerCapture={endDrag}
      onWheel={(e) => { if (!e.ctrlKey && !e.metaKey) return; e.preventDefault(); userTransform.current = true; setZ((value) => Math.max(.35, Math.min(1.8, value + (e.deltaY < 0 ? .1 : -.1)))); }}
    >
      <div
        style={{
          position: "absolute",
          top: 8,
          right: 8,
          zIndex: 3,
          display: "flex",
          justifyContent: "flex-end",
          gap: 4,
          padding: 8,
          pointerEvents: "none",
        }}
      >
        <span style={{ display: "inline-flex", gap: 4, pointerEvents: "auto" }}>
          <Button
            aria-label="축소"
            title="축소"
            onClick={() => {
              userTransform.current = true;
              setZ((v) => Math.max(.35, v - .1));
            }}
          >
            <ZoomOutOutlinedIcon sx={{ fontSize: 16 }} />
          </Button>
          <Button
            aria-label="확대"
            title="확대"
            onClick={() => {
              userTransform.current = true;
              setZ((v) => Math.min(1.8, v + .1));
            }}
          >
            <ZoomInOutlinedIcon sx={{ fontSize: 16 }} />
          </Button>
          <Button
            aria-label="화면 맞춤 및 위치 초기화"
            title="화면 맞춤"
            onClick={fitView}
          >
            <CenterFocusStrongOutlinedIcon sx={{ fontSize: 16 }} />
          </Button>
          <Button aria-label="자동 배치 다시 계산" title="재배치" onClick={reflow}>재배치</Button>
        </span>
      </div>
      <div
        aria-label="그래프 노드 구분"
        style={{
          position: "absolute",
          zIndex: 3,
          top: 10,
          left: 12,
          display: "flex",
          gap: 10,
          color: "var(--text-faint)",
          fontSize: 10.5,
          pointerEvents: "none",
        }}
      >
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><span aria-hidden="true" style={{ width: 12, height: 12, border: "1px solid var(--text-dim)", borderRadius: "50%", boxShadow: "inset 0 0 0 2px var(--bg-app), inset 0 0 0 3px var(--text-dim)" }} />등록 호스트</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><span aria-hidden="true" style={{ width: 12, height: 12, border: "1px solid var(--text-faint)", borderRadius: "50%" }} />RDP 상대</span>
      </div>
      <div
        style={{
          position: "absolute",
          inset: 0,
          width: value.w,
          height: value.h,
          transform: `translate(${pan.x}px,${pan.y}px) scale(${z})`,
          transformOrigin: "0 0",
          cursor: drag.current?.kind === "pan" ? "grabbing" : "grab",
        }}
        onPointerDown={(e) => {
          if ((e.target as Element).closest("button")) return;
          drag.current = { kind: "pan", x: e.clientX, y: e.clientY, px: pan.x, py: pan.y, moved: false };
          e.currentTarget.setPointerCapture(e.pointerId);
        }}
      >
        <svg
          aria-hidden="true"
          width={value.w}
          height={value.h}
          style={{ position: "absolute", inset: 0, overflow: "visible" }}
        >
          <defs>
            <marker
              id="rdp-arrow"
              markerWidth="8"
              markerHeight="8"
              refX="6"
              refY="3"
              orient="auto"
            >
              <path d="M0,0 L0,6 L7,3 z" fill="var(--text-dim)" />
            </marker>
          </defs>
          {value.shown.map((e) => {
            const a = renderByKey.get(key(e.host)), b = renderByKey.get(key(e.peer));
            if (!a || !b) return null;
            const from = e.direction === "inbound" ? b : a,
              to = e.direction === "inbound" ? a : b,
              d = Math.hypot(to.x - from.x, to.y - from.y) || 1,
              ux = (to.x - from.x) / d,
              uy = (to.y - from.y) / d,
              fromRadius = nodeRadius(from),
              toRadius = nodeRadius(to);
            return (
              <line
                key={e.key}
                x1={from.x + ux * (fromRadius + 4)}
                y1={from.y + uy * (fromRadius + 4)}
                x2={to.x - ux * (toRadius + 6)}
                y2={to.y - uy * (toRadius + 6)}
                stroke={selected === e.key ? "var(--accent)" : "var(--text-dim)"}
                strokeWidth={selected === e.key ? 2.5 : 1.4}
                strokeDasharray={e.direction === "unknown" ? "5 5" : undefined}
                markerEnd={e.direction === "unknown"
                  ? undefined
                  : "url(#rdp-arrow)"}
              />
            );
          })}
        </svg>
        {renderPoints.map((n) => {
          const r = nodeRadius(n);
          return (
            <div
              key={n.key}
              style={{
                position: "absolute",
                left: n.x,
                top: n.y,
                transform: "translate(-50%,-50%)",
                width: graphLabelWidth(value.w),
                textAlign: "center",
                pointerEvents: "none",
              }}
            >
              <button
                type="button"
                aria-label={`${
                  n.registered ? "등록 호스트" : "RDP 상대"
                } ${n.label} 선택`}
                title={n.label}
                onPointerDown={(event) => {
                  event.stopPropagation();
                  drag.current = { kind: "node", key: n.key, x: event.clientX, y: event.clientY, moved: false };
                  event.currentTarget.setPointerCapture(event.pointerId);
                }}
                onPointerUp={endDrag}
                onPointerCancel={endDrag}
                onLostPointerCapture={endDrag}
                onClick={() => {
                  if (suppressNodeClick.current.delete(n.key)) return;
                  onNode(n);
                }}
                style={{
                  width: r * 2,
                  height: r * 2,
                  borderRadius: "50%",
                  border: `2px solid ${
                    n.key === value.focus
                      ? "var(--accent)"
                      : n.registered
                      ? "var(--text-dim)"
                      : "var(--border)"
                  }`,
                  background: n.key === value.focus
                    ? "var(--accent-subtle)"
                    : "var(--bg-elevated)",
                  boxShadow: n.key === value.focus
                    ? "0 0 0 3px var(--accent-subtle)"
                    : n.registered
                    ? "inset 0 0 0 3px var(--bg-elevated), inset 0 0 0 4px var(--text-dim)"
                    : "none",
                  cursor: "pointer",
                  pointerEvents: "auto",
                }}>
                {n.registered && <span aria-hidden="true" style={{ display: "block", width: 4, height: 4, margin: "auto", borderRadius: "50%", background: "var(--text-dim)" }} />}
              </button>
              <span
                title={n.label}
                style={{
                  display: "block",
                  marginTop: 4,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  fontSize: 11,
                  fontWeight: n.registered ? 700 : 550,
                  color: "var(--text)",
                }}
              >
                {n.label}
              </span>
            </div>
          );
        })}
      </div>
      <p
        style={{
          position: "absolute",
          left: 12,
          bottom: 6,
          margin: 0,
          color: "var(--text-faint)",
          fontSize: 10.5,
          pointerEvents: "none",
        }}
      >
        자동 배치 · 노드 거리는 분석 순서나 위험도를 뜻하지 않습니다.
      </p>
    </div>
  );
}
function List(
  {
    edges,
    focusHostName,
    onSelect,
  }: {
    edges: Edge[];
    focusHostName: string | null;
    onSelect: (k: string) => void;
  },
) {
  return (
    <div>
      <strong>관계 목록</strong>
      <p style={muted}>
        {focusHostName
          ? `${focusHostName} 기준 필터 적용 관계 ${edges.length.toLocaleString()}개`
          : `모든 필터 적용 관계 ${edges.length.toLocaleString()}개`}
      </p>
      {edges.length === 0 && focusHostName && (
        <p style={muted}>
          선택한 등록 호스트와 직접 연결된 RDP 관계가 없습니다. 다른 호스트의 관계는
          관계 개요에서 확인할 수 있습니다.
        </p>
      )}
      {edges.map((e) => (
        <button
          key={e.key}
          type="button"
          onClick={() => onSelect(e.key)}
          style={listRow}
        >
          <span style={{ minWidth: 0 }}>
            <span style={ellipsis}>
              {e.host} · {dir(e.direction)} · {e.peer}
            </span>
            <span style={small}>
              {e.last ? formatEvidenceTimestamp(e.last) : "시간 정보 없음"}
            </span>
          </span>
          <span>{e.count}건</span>
        </button>
      ))}
    </div>
  );
}
function Inspector(
  { edge, onOpenHost, hosts }: {
    edge: Edge;
    onOpenHost?: (name: string) => void;
    hosts: Set<string>;
  },
) {
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [edge.key]);
  const size = 20,
    total = Math.max(1, Math.ceil(edge.rows.length / size)),
    current = Math.min(page, total - 1),
    rows = edge.rows.slice(current * size, current * size + size),
    names = [edge.host, edge.peer].filter((v, i, a) =>
      a.indexOf(v) === i && hosts.has(v)
    );
  return (
    <div>
      <strong>선택한 관계</strong>
      <p style={{ color: "var(--text-dim)", fontSize: 12 }}>
        {edge.host} · {dir(edge.direction)} · {edge.peer}
      </p>
      <dl style={facts}>
        <dt>이벤트</dt>
        <dd>{edge.count.toLocaleString()}개</dd>
        <dt>시간 범위</dt>
        <dd>
          {edge.first
            ? `${formatEvidenceTimestamp(edge.first)} ~ ${
              formatEvidenceTimestamp(edge.last)
            }`
            : "시간 정보 없음"}
        </dd>
        <dt>결과</dt>
        <dd>성공 {edge.success}개 · 실패 {edge.fail}개</dd>
        <dt>계정</dt>
        <dd>{edge.accounts.join(", ") || "계정 정보 없음"}</dd>
      </dl>
      {names.map((n) =>
        onOpenHost && (
          <Button key={n} onClick={() => onOpenHost(n)}>
            <OpenInNewOutlinedIcon sx={{ fontSize: 15 }} />
            {n} 열기
          </Button>
        )
      )}
      <div style={{ marginTop: 12 }}>
        {rows.map((r, i) => (
          <div key={`${r.timestamp}-${i}`} style={listRow}>
            <span>
              {r.account || "계정 정보 없음"}
              <span style={small}>
                {r.timestamp
                  ? formatEvidenceTimestamp(r.timestamp)
                  : "시간 정보 없음"}
              </span>
            </span>
            <span
              style={{
                color: r.result === "실패"
                  ? "var(--danger)"
                  : r.result === "성공"
                  ? "var(--success)"
                  : "var(--text-faint)",
              }}
            >
              {r.result || "정보 없음"}
            </span>
          </div>
        ))}
        {edge.rows.length > size && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "flex-end",
              gap: 6,
              paddingTop: 10,
              fontSize: 11.5,
              color: "var(--text-faint)",
            }}
          >
            <PaginationControls
              ariaLabel="접속 기록 페이지"
              page={current}
              pageCount={total}
              onChange={setPage}
              summary={`(${(current * size + 1).toLocaleString()}–${Math.min((current + 1) * size, edge.rows.length).toLocaleString()} / ${edge.rows.length.toLocaleString()})`}
            />
          </div>
        )}
      </div>
    </div>
  );
}
function Center({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        minHeight: 220,
        display: "grid",
        placeItems: "center",
        gap: 8,
        color: "var(--text-dim)",
        fontSize: 12,
      }}
    >
      {children}
    </div>
  );
}
const surface: React.CSSProperties = {
  flex: "1 0 auto",
  minHeight: "min(520px, max(0px, calc(100dvh - 160px)))",
  display: "flex",
  flexDirection: "column",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-lg)",
  background: "var(--bg-panel)",
  boxShadow: "var(--shadow-panel)",
  overflow: "hidden",
};
const head: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  flexWrap: "wrap",
  padding: "12px 14px",
  borderBottom: "1px solid var(--border)",
  color: "var(--text-faint)",
  fontSize: 11.5,
};
const toolbar: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 7,
  flexWrap: "wrap",
  padding: "10px 14px",
  borderBottom: "1px solid var(--border-subtle)",
};
const button: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: 4,
  minHeight: 29,
  padding: "3px 8px",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  background: "var(--bg-elevated)",
  color: "var(--text-dim)",
  cursor: "pointer",
  fontSize: 11.5,
};
const field: React.CSSProperties = {
  minHeight: 30,
  padding: "4px 8px",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  background: "var(--bg-elevated)",
  color: "var(--text)",
  fontSize: 12,
};
const warning: React.CSSProperties = { color: "var(--warning)" };
const notice: React.CSSProperties = {
  padding: "7px 12px",
  borderTop: "1px solid var(--border)",
  color: "var(--text-faint)",
  fontSize: 11.5,
};
const noticeOverlay: React.CSSProperties = {
  position: "absolute",
  zIndex: 4,
  left: 0,
  right: 0,
  bottom: 28,
  background: "var(--bg-panel)",
  borderTop: "1px solid var(--border)",
  pointerEvents: "none",
};
const muted: React.CSSProperties = {
  margin: "4px 0 10px",
  color: "var(--text-faint)",
  fontSize: 11.5,
};
const ellipsis: React.CSSProperties = {
  display: "block",
  overflow: "hidden",
  whiteSpace: "nowrap",
  textOverflow: "ellipsis",
};
const small: React.CSSProperties = {
  display: "block",
  marginTop: 2,
  color: "var(--text-faint)",
  fontFamily: "var(--mono)",
  fontSize: 10.5,
};
const listRow: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "minmax(0,1fr) auto",
  gap: 8,
  width: "100%",
  padding: "8px 0",
  border: 0,
  borderBottom: "1px solid var(--border-subtle)",
  background: "transparent",
  color: "var(--text-dim)",
  textAlign: "left",
  fontSize: 11.5,
  cursor: "pointer",
};
const facts: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "76px minmax(0,1fr)",
  gap: "7px 8px",
  padding: "10px 0",
  borderTop: "1px solid var(--border-subtle)",
  borderBottom: "1px solid var(--border-subtle)",
  fontSize: 11.5,
};
