"use client";
import { FilterDropdown, HeaderSearchInput, SelectDropdown, ViewHeader } from "@/components/FilterControls";
import HostConnection3D from "@/components/HostConnection3D";
import AccountTreeOutlinedIcon2 from "@mui/icons-material/AccountTreeOutlined";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import useMediaQuery from "@mui/material/useMediaQuery";
import CircularProgress from "@mui/material/CircularProgress";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
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
}
const DEFAULT_GRAPH = { width: 960, height: 560 };
const PEER = 16, FOCUS = 22, LIMIT = 12, ALL_LIMIT = 30;
const NODE_LABEL_WIDTH = 124;
const NODE_LABEL_BOTTOM = 36;
const graphLabelWidth = (width: number) =>
  Math.max(1, Math.min(NODE_LABEL_WIDTH, Math.max(1, width - 16)));
const graphLabelHalf = (width: number) => graphLabelWidth(width) / 2;
const key = (v: string) => v.toLocaleLowerCase();
/** RFC1918 사설 IP — 호스트 대역과 달라도 내부로 취급한다. */
const isPrivateIp = (label: string): boolean =>
  /^10\./.test(label.trim()) ||
  /^192\.168\./.test(label.trim()) ||
  /^172\.(1[6-9]|2\d|3[01])\./.test(label.trim());
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
    const shown = es, used = catalog(hosts, shown);
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
  }: Props,
) {
  const [search, setSearch] = useState(""),
    [direction, setDirection] = useState<"all" | ConnDirection>("all"),
    [viewMode, setViewMode] = useState<"external" | "internal">("external"),
    // 상세는 노드(호스트/상대) 중심 — 어떤 관계 하나가 아니라 "얘가 누구와
    // 연결했는지"를 본다.
    [selected, setSelected] = useState<string | null>(null);
  const compactLayout = useMediaQuery("(max-width: 1000px)");
  const hostNets = useMemo(
    () => [...new Set((graph?.hosts ?? []).flatMap((h) => h.ips.map((ip) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(ip.trim())).filter(Boolean).map((m) => `${m![1]}.${m![2]}.${m![3]}`)))],
    [graph?.hosts],
  );
  const internalNets = useMemo(() => new Set(hostNets), [hostNets]);
  const isInternalRecord = useCallback((r: ConnRecord) => {
    if (r.peerIsHost || r.peerKind === "local" || r.peerKind === "loopback") return true;
    // RFC1918 사설 대역은 호스트 대역과 달라도 사실상 내부다.
    if (isPrivateIp(r.peerLabel)) return true;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(r.peerLabel.trim());
    return Boolean(m) && internalNets.has(`${m![1]}.${m![2]}.${m![3]}`);
  }, [internalNets]);
  const range = rangeActive(timeRange),
    rows = graph?.records ?? [],
    scoped = useMemo(
      () =>
        rows.filter((r) =>
          (!range || Boolean(r.timestamp) && inRange(r.timestamp, timeRange)) &&
          // 외부 뷰의 목적은 외부 호스트 연결 파악 — 로컬/루프백 제외.
          // 내부 뷰에서는 호스트 자체 활동으로 살려서 보여준다.
          (viewMode === "internal" || (r.peerKind !== "local" && r.peerKind !== "loopback")) &&
          (direction === "all" || r.direction === direction || (viewMode === "external" && isInternalRecord(r))) &&
          // 이 뷰는 실제 성립한 접속만 다룬다 — 성공 기록만 표기.
          r.result === "성공" &&
          (!search.trim() ||
            [r.host, r.peer, r.peerLabel, r.account, r.result].some((v) =>
              v.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())
            ))
        ),
      [
        rows,
        range,
        timeRange,
        direction,
        viewMode,
        isInternalRecord,
        search,
      ],
    );
  const es = useMemo(() => edges(scoped), [scoped]),
    isInternalEdge = useMemo(() => {
      const nets = new Set(hostNets);
      return (e: Edge) => {
        const kind = e.rows[0]?.peerKind;
        if (e.rows[0]?.peerIsHost || kind === "local" || kind === "loopback") return true;
        if (isPrivateIp(e.peer)) return true;
        const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(e.peer.trim());
        return Boolean(m) && nets.has(`${m![1]}.${m![2]}.${m![3]}`);
      };
    }, [hostNets]),
    // 그래프에는 전체 관계를 넘기고(지형 구성용) 목록·선택은 뷰 모드 기준.
    visibleEdges = useMemo(
      () => es.filter((e) => (viewMode === "internal" ? isInternalEdge(e) : !isInternalEdge(e))),
      [es, viewMode, isInternalEdge],
    ),
    // 상세도 뷰 모드를 따른다: 외부 뷰에선 외부 상대만, 내부 뷰에선
    // 내부(같은 대역·호스트 간·로컬) 상대만 나열한다.
    selectedNodeEdges = useMemo(
      () => (selected
        ? es.filter((e) =>
            (viewMode === "internal" ? isInternalEdge(e) : !isInternalEdge(e)) &&
            (key(e.host) === selected || key(e.peer) === selected))
        : []),
      [es, selected, viewMode, isInternalEdge],
    ),
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
    setSelected(node.key);
  };
  return (
    <main
      className="dfir-view"
      style={{
        flex: 1,
        minHeight: 0,
        overflow: "auto",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <section style={surface}>
        <ViewHeader
          icon={AccountTreeOutlinedIcon2}
          title="원격 접근 관계 (RDP)"
          meta={<>{scoped.length.toLocaleString()}개 이벤트 · {es.length.toLocaleString()}개 관계{graph.rdpSourceFailures?.length ? <span style={{ ...warning, marginLeft: 8 }}>일부 RDP 원본 미확인 {graph.rdpSourceFailures.length}건</span> : null}{graph.networkMappingFailures?.length ? <span style={{ marginLeft: 8 }}>네트워크 매핑 미확인 {graph.networkMappingFailures.length}건</span> : null}</>}
          right={<>
            <span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{range ? "전역 기간 필터 적용" : "전체 기간"}</span>
            {onRefresh && (
              <Button onClick={onRefresh}>
                <RefreshOutlinedIcon sx={{ fontSize: 15 }} />새로고침
              </Button>
            )}
          </>}
        >
          <HeaderSearchInput value={search} onChange={setSearch} placeholder="호스트 · 상대 · 계정 검색" ariaLabel="호스트, 상대, 계정 검색" width={300} />
          <SelectDropdown
            label="보기"
            options={[
              { value: "external", label: "외부 호스트 뷰" },
              { value: "internal", label: "내부 호스트 뷰" },
            ]}
            value={viewMode}
            defaultValue="external"
            onChange={(next) => { setViewMode(next as typeof viewMode); setSelected(null); }}
          />
          <SelectDropdown
            label="방향"
            options={[
              { value: "all", label: "전체" },
              { value: "inbound", label: "인바운드", color: "#f2a86f" },
              { value: "outbound", label: "아웃바운드", color: "#9b7ef8" },
              { value: "unknown", label: "방향 정보 없음" },
            ]}
            value={direction}
            onChange={(next) => setDirection(next as typeof direction)}
          />
        </ViewHeader>

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
            edges={es}
            mode={viewMode}
            focus={null}
            overall={true}
            selected={selected}
            onNode={selectNode}
            onClear={() => setSelected(null)}
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
            {selected && selectedNodeEdges.length > 0
              ? (
                <NodeInspector
                  nodeKey={selected}
                  edges={selectedNodeEdges}
                  onBack={() => setSelected(null)}
                  onSelectNode={setSelected}
                  hosts={new Set(graph.hosts.map((h) => h.name))}
                />
              )
              : <List
                edges={visibleEdges}
                viewMode={viewMode}
                selected={selected}
                onSelect={setSelected}
              />}
          </aside>
        </div>
      </section>
    </main>
  );
}
type GraphDrag =
  | { kind: "pan"; x: number; y: number; px: number; py: number; moved: boolean }
  | null;

function GraphPane(
  {
    hosts,
    edges: allEdges,
    mode,
    focus,
    overall,
    selected,
    onNode,
    onClear,
    hasRows,
    showNoTime,
    noTime,
  }: {
    hosts: HostNode[];
    edges: Edge[];
    mode: "external" | "internal";
    focus: string | null;
    overall: boolean;
    selected: string | null;
    onNode: (node: Node) => void;
    onClear: () => void;
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
  // 등록 호스트 IP의 /24 접두사 — 3D 뷰가 "호스트와 같은 네트워크" 색을
  // 구분하는 기준.
  const hostNets = useMemo(
    () => [...new Set(hosts.flatMap((h) => h.ips.map((ip) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(ip.trim())).filter(Boolean).map((m) => `${m![1]}.${m![2]}.${m![3]}`)))],
    [hosts],
  );
  const hostNetInfo = useMemo(
    () => hosts.map((h) => ({
      key: h.name.toLocaleLowerCase(),
      nets: [...new Set(h.ips.map((ip) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(ip.trim())).filter(Boolean).map((m) => `${m![1]}.${m![2]}.${m![3]}`))],
    })),
    [hosts],
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
        ? (
          <HostConnection3D
            nodes={value.nodes}
            edges={value.shown}
            hostNets={hostNets}
            hostNetInfo={hostNetInfo}
            mode={mode}
            width={viewport.width}
            height={viewport.height}
            selected={selected}
            onNode={(node) => onNode({ ...node, x: 0, y: 0 })}
            onClear={onClear}
          />
        )
        : (
          <Center>
            {hasRows
              ? "현재 필터 조건에 맞는 RDP 관계가 없습니다."
              : "확인된 RDP 접속 기록이 없습니다."}
          </Center>
        )}
      {showNoTime && (
        <div style={noticeOverlay}>
          <div style={notice}>
            시간 정보가 없는 이벤트 {noTime.toLocaleString()}개는 기간 범위에서 제외했습니다.
          </div>
        </div>
      )}
    </section>
  );
}

function List(
  {
    edges,
    viewMode,
    selected,
    onSelect,
  }: {
    edges: Edge[];
    viewMode: "external" | "internal";
    selected: string | null;
    onSelect: (k: string) => void;
  },
) {
  // 그래프와 같은 단위로 묶는다: 상대(피어) 하나 = 카드 하나.
  // 방향·호스트별 낱개 행 대신 상대 기준으로 요약해 목록이 의미를 가진다.
  const groups = useMemo(() => {
    const map = new Map<string, {
      key: string;
      label: string;
      edges: Edge[];
      count: number;
      inbound: number;
      outbound: number;
      fail: number;
      hosts: string[];
      last: string;
    }>();
    for (const e of edges) {
      const groupKey = key(e.peer);
      const entry = map.get(groupKey) ?? { key: groupKey, label: e.peer, edges: [], count: 0, inbound: 0, outbound: 0, fail: 0, hosts: [], last: "" };
      entry.edges.push(e);
      entry.count += e.count;
      entry.fail += e.fail;
      if (e.direction === "inbound") entry.inbound += e.count;
      if (e.direction === "outbound") entry.outbound += e.count;
      if (!entry.hosts.includes(e.host)) entry.hosts.push(e.host);
      if (e.last && e.last > entry.last) entry.last = e.last;
      map.set(groupKey, entry);
    }
    return [...map.values()].sort((a, b) => b.fail - a.fail || b.count - a.count || (b.last || "").localeCompare(a.last || ""));
  }, [edges]);

  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [edges]);
  const PAGE = 10;
  const pageCount = Math.max(1, Math.ceil(groups.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageGroups = groups.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div>
      <strong>{viewMode === "external" ? "외부 상대" : "내부 상대"}</strong>
      <p style={muted}>
        {groups.length.toLocaleString()}곳 · 관계 {edges.length.toLocaleString()}개
      </p>
      {groups.length === 0 && (
        <p style={muted}>
          {viewMode === "external"
            ? "필터 조건에 맞는 외부 접속 상대가 없습니다."
            : "필터 조건에 맞는 내부 이동 상대가 없습니다."}
        </p>
      )}
      {pageGroups.map((group) => {
        const isSelected = selected === group.key;
        return (
          <button
            key={group.key}
            type="button"
            onClick={() => onSelect(group.key)}
            onMouseEnter={(event) => { if (!isSelected) event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = isSelected ? "var(--accent-subtle)" : "var(--bg-panel)"; }}
            style={{ width: "100%", display: "grid", gap: 4, marginBottom: 6, padding: "8px 10px", border: `1px solid ${isSelected ? "color-mix(in srgb, var(--accent) 58%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: isSelected ? "var(--accent-subtle)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", transition: "background .15s ease, border-color .15s ease" }}
          >
            <span title={group.label} style={{ display: "block", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 700 }}>{group.label}</span>
            <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, fontSize: 11, flexWrap: "wrap" }}>
              {group.inbound > 0 && <span style={{ color: "#f2a86f", fontWeight: 650 }}>인바운드 {group.inbound.toLocaleString()}건</span>}
              {group.outbound > 0 && <span style={{ color: "#9b7ef8", fontWeight: 650 }}>아웃바운드 {group.outbound.toLocaleString()}건</span>}
            </span>
          </button>
        );
      })}
      {groups.length > 0 && (
        <div style={{ display: "flex", justifyContent: "center", marginTop: 8 }}>
          <PaginationControls ariaLabel="관계 목록 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, groups.length).toLocaleString()} / ${groups.length.toLocaleString()})`} />
        </div>
      )}
    </div>
  );
}
function NodeInspector(
  { nodeKey, edges, onBack, onSelectNode, hosts }: {
    nodeKey: string;
    edges: Edge[];
    onBack: () => void;
    onSelectNode: (k: string) => void;
    hosts: Set<string>;
  },
) {
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [nodeKey]);
  // 이 패널은 "이 노드가 누구와 연결했는지"를 본다 — 상대 호스트 목록과
  // 방향·횟수만. 개별 시각은 원격 접근 이력 뷰의 몫이다.
  const label = useMemo(() => {
    for (const e of edges) {
      if (key(e.host) === nodeKey) return e.host;
      if (key(e.peer) === nodeKey) return e.peer;
    }
    return nodeKey;
  }, [edges, nodeKey]);
  const registered = hosts.has(label) || [...hosts].some((h) => key(h) === nodeKey);
  const counterparts = useMemo(() => {
    const map = new Map<string, { key: string; label: string; inbound: number; outbound: number; count: number; fail: number }>();
    for (const e of edges) {
      const otherLabel = key(e.host) === nodeKey ? e.peer : e.host;
      const otherKey = key(otherLabel);
      const entry = map.get(otherKey) ?? { key: otherKey, label: otherLabel, inbound: 0, outbound: 0, count: 0, fail: 0 };
      entry.count += e.count;
      entry.fail += e.fail;
      if (e.direction === "inbound") entry.inbound += e.count;
      if (e.direction === "outbound") entry.outbound += e.count;
      map.set(otherKey, entry);
    }
    return [...map.values()].sort((a, b) => b.fail - a.fail || b.count - a.count);
  }, [edges, nodeKey]);
  const size = 10;
  const total = Math.max(1, Math.ceil(counterparts.length / size));
  const current = Math.min(page, total - 1);
  const rows = counterparts.slice(current * size, current * size + size);
  return (
    <div>
      <button
        type="button"
        className="nm-btn"
        onClick={onBack}
        style={{ display: "inline-flex", alignItems: "center", gap: 5, minHeight: 28, marginBottom: 8, padding: "3px 10px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--bg-elevated)", color: "var(--text-dim)", cursor: "pointer", fontSize: 11.5, fontWeight: 650 }}
      >
        ← 목록으로
      </button>
      <strong style={{ display: "block" }}>연결한 호스트</strong>
      <p style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>
        <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{label}</span>
        {registered && <span style={{ flexShrink: 0, fontSize: 10.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "0 6px" }}>등록 호스트</span>}
      </p>
      {/* 확정 규칙: 노드 상세는 상대 목록(등록 칩)과 방향·횟수 집계만 —
          총계·계정·호스트 열기 제어는 원격 접근 이력 뷰의 몫이라 두지 않는다. */}
      <div style={{ marginTop: 12 }}>
        {rows.map((r) => (
          <button
            key={r.key}
            type="button"
            onClick={() => onSelectNode(r.key)}
            style={{ ...listRow, width: "100%", cursor: "pointer", background: "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", textAlign: "left" }}
            onMouseEnter={(event) => { event.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseLeave={(event) => { event.currentTarget.style.background = "transparent"; }}
          >
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 650 }}>{r.label}</span>
                {hosts.has(r.label) && <span style={{ flexShrink: 0, fontSize: 10.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-sm)", padding: "0 6px" }}>등록</span>}
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 2, fontSize: 10.5 }}>
                {r.inbound > 0 && <span style={{ color: "#f2a86f", fontWeight: 650 }}>인바운드 {r.inbound.toLocaleString()}건</span>}
                {r.outbound > 0 && <span style={{ color: "#9b7ef8", fontWeight: 650 }}>아웃바운드 {r.outbound.toLocaleString()}건</span>}
              </span>
            </span>
            <span style={{ flexShrink: 0, fontWeight: 700 }}>
              {r.count.toLocaleString()}회
              {r.fail > 0 && <span style={{ color: "var(--danger)", fontWeight: 650 }}> · 실패 {r.fail.toLocaleString()}</span>}
            </span>
          </button>
        ))}
        {counterparts.length > size && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6, paddingTop: 10, fontSize: 11.5, color: "var(--text-faint)" }}>
            <PaginationControls
              ariaLabel="연결 호스트 페이지"
              page={current}
              pageCount={total}
              onChange={setPage}
              summary={`(${(current * size + 1).toLocaleString()}–${Math.min((current + 1) * size, counterparts.length).toLocaleString()} / ${counterparts.length.toLocaleString()})`}
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
