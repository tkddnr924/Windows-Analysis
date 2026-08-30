"use client";
// 원격 접근 관계의 3D 육각 지도 — three.js(WebGL) 기반이라 선·타일의 가림이
// 깊이 버퍼로 자연스럽게 처리되고, 드래그로 회전해 위/아래/멀리 떠 있는
// 클러스터를 실제 3D 공간에서 볼 수 있다. 좌표는 해시로 고정(결정적)이라
// 물리 시뮬레이션 없이 같은 데이터는 항상 같은 자리에 놓인다.
import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";

// 등록 호스트와 같은 네트워크(/24) 대역은 푸른 계열, 외부는 밝은 회색 계열.
const BLUE_TONES = ["#5f8fd8", "#6d84cf", "#4f9bc4", "#7490e2", "#54a3ab"];
// 내부 뷰에서 등록 호스트마다 부여하는 고유 색 — 루프백/로컬 상대는 소속
// 호스트와 같은 색을 받아 어느 호스트의 자체 활동인지 보인다.
const HOST_TONES = ["#e08a8a", "#e5b078", "#c493e2", "#7fc9a0", "#dfcf7d", "#e79bb6"];
const GRAY_TONES = ["#8b95a2", "#75808d", "#9aa4b0", "#67727f", "#828e9b"];
const ACCENT = "#e08a8a";
const DIRECTION_COLOR: Record<string, string> = {
  in: "#f2a86f",
  out: "#9b7ef8",
  bidi: "#5bc8c0",
  unknown: "#8fa0b6",
};
const TILE_PEER = 10;
const TILE_HOST = 16;

export interface Graph3DNode {
  key: string;
  label: string;
  registered: boolean;
}

export interface Graph3DEdge {
  key: string;
  host: string;
  peer: string;
  direction: "inbound" | "outbound" | "unknown";
  count: number;
  fail: number;
  last: string;
  /** 원본 이벤트 행 — peerKind(local/loopback) 판별용. */
  rows?: { peerKind?: string }[];
}

interface Props {
  nodes: Graph3DNode[];
  edges: Graph3DEdge[];
  /** 등록 호스트들이 속한 /24 대역 접두사 목록 ("a.b.c"). */
  hostNets: string[];
  /** 호스트별 /24 목록 — 외부 뷰에서 네트워크가 다른 호스트를 별개
   * 지형으로 나누는 기준. */
  hostNetInfo: { key: string; nets: string[] }[];
  /** 외부 뷰: 내부(같은 대역·호스트 간) 이동선 숨김, 지형은 한 벌집.
   * 내부 뷰: 호스트·같은 대역을 떼어놓고 내부 이동선만 표기. */
  mode: "external" | "internal";
  width: number;
  height: number;
  selected: string | null;
  onNode: (node: Graph3DNode) => void;
  /// 재클릭·배경 클릭 해제 시 부모 선택까지 비운다 — activeKey가 이전
  /// selected로 되돌아가 강조·상세가 남는 것을 막는다 (확정 규칙: 재클릭·
  /// 배경 클릭으로 해제).
  onClear: () => void;
}

const lowerKey = (v: string) => v.toLocaleLowerCase();

/** RFC1918 사설 IP — 호스트 대역과 달라도 내부로 취급한다. */
function isPrivateIp(label: string): boolean {
  // 네 옥텟 모두 0~255인 유효 IPv4만 RFC1918로 분류한다 — 접두사 정규식만
  // 쓰면 10.999.1.1 같은 손상·비정상 주소가 내부 클러스터로 이동해 외부
  // 통신 판단을 왜곡한다. 비정상 주소는 외부/미상으로 남긴다.
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(label.trim());
  if (!m) return false;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((value) => value > 255)) return false;
  return octets[0] === 10
    || (octets[0] === 192 && octets[1] === 168)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31);
}

function networkGroupOf(label: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/.exec(label.trim());
  return m ? `${m[1]}.${m[2]}.${m[3]}` : null;
}

function hashOf(text: string): number {
  return [...text].reduce((h, ch) => ((h * 31) + ch.charCodeAt(0)) >>> 0, 7);
}

/** 아발란체 믹서 — 비슷한 문자열(같은 대역 IP)의 해시가 한 방향으로
 * 몰리지 않게 비트를 고르게 섞는다. */
function mixHash(value: number): number {
  let h = value >>> 0;
  h ^= h >>> 16;
  h = Math.imul(h, 0x45d9f3b);
  h ^= h >>> 16;
  h = Math.imul(h, 0x45d9f3b);
  h ^= h >>> 16;
  return h >>> 0;
}

/** 벌집 나선 순서의 axial 오프셋 (flat-top, XZ 평면). */
function hexSpiralOffsets(count: number, spacing: number): { x: number; z: number }[] {
  const out: { x: number; z: number }[] = [{ x: 0, z: 0 }];
  const dirs = [
    [1, 0],
    [1, -1],
    [0, -1],
    [-1, 0],
    [-1, 1],
    [0, 1],
  ];
  for (let ring = 1; out.length < count; ring++) {
    let q = -ring;
    let r = ring;
    for (let side = 0; side < 6 && out.length < count; side++) {
      for (let step = 0; step < ring && out.length < count; step++) {
        out.push({ x: spacing * Math.sqrt(3) * (q + r / 2), z: spacing * 1.5 * r });
        q += dirs[side][0];
        r += dirs[side][1];
      }
    }
  }
  return out.slice(0, count);
}

interface LaidNode extends Graph3DNode {
  id: string;
  tone: string;
  net: string;
  /** 등록 호스트와 같은 /24 대역의 미등록 상대. */
  sameNet?: boolean;
  r: number;
  fx: number;
  fy: number;
  fz: number;
}

interface LaidLink {
  key: string;
  /** 이 선으로 합쳐진 원본 관계 키들 — 목록 선택 강조 매칭용. */
  keys: string[];
  source: string;
  target: string;
  tone: string;
  /** 옅게 그려두는 톤 — 같은 대역 선의 기본 상태. */
  dimTone: string;
  sameNet: boolean;
  unknownDirection: boolean;
}

/** 결정적 3D 배치: 호스트 벌집은 원점, /24 대역 클러스터는 해시가 정하는
 * 연속적인 (x, 높이, 깊이)에 떠 있는 벌집 섬으로. */
function layout3d(nodes: Graph3DNode[], edges: Graph3DEdge[], hostNets: string[], hostNetInfo: { key: string; nets: string[] }[], mode: "external" | "internal") {
  const weight = new Map<string, number>();
  edges.forEach((e) => {
    weight.set(lowerKey(e.host), (weight.get(lowerKey(e.host)) ?? 0) + e.count);
    weight.set(lowerKey(e.peer), (weight.get(lowerKey(e.peer)) ?? 0) + e.count);
  });

  const hostNetSet = new Set(hostNets);
  const hosts = nodes.filter((n) => n.registered);
  // 루프백/로컬 상대는 대역 클러스터가 아니라 소속 호스트 옆에 붙인다.
  const loopbackKeys = new Set<string>();
  const loopbackOwner = new Map<string, { owner: string; count: number }>();
  edges.forEach((e) => {
    const kind = e.rows?.[0]?.peerKind;
    if (kind !== "local" && kind !== "loopback") return;
    const peerKey = lowerKey(e.peer);
    loopbackKeys.add(peerKey);
    const current = loopbackOwner.get(peerKey);
    if (!current || e.count > current.count) {
      loopbackOwner.set(peerKey, { owner: lowerKey(e.host), count: e.count });
    }
  });
  const peers = nodes.filter((n) => !n.registered && !loopbackKeys.has(n.key));
  const loopbackNodes = nodes.filter((n) => !n.registered && loopbackKeys.has(n.key));
  const groups = new Map<string, { label: string; net: string; members: Graph3DNode[] }>();
  peers.forEach((n) => {
    const net = networkGroupOf(n.label);
    const gk = net ? `net:${net}` : `one:${n.key}`;
    const g = groups.get(gk) ?? { label: net ? `${net}.x` : n.label, net: net ? `${net}.x` : "", members: [] };
    g.members.push(n);
    groups.set(gk, g);
  });

  const laid: LaidNode[] = [];
  const shade = (tone: string, mi: number) =>
    `#${new THREE.Color(tone).offsetHSL(0, 0, (((mi % 4) - 1.5) * 0.05)).getHexString()}`;
  const byWeight = (a: Graph3DNode, b: Graph3DNode) =>
    (weight.get(b.key) ?? 0) - (weight.get(a.key) ?? 0) || a.label.localeCompare(b.label, "ko");

  const sortedGroups = [...groups.values()].sort((a, b) => {
    const wa = a.members.reduce((acc, m) => acc + (weight.get(m.key) ?? 0), 0);
    const wb = b.members.reduce((acc, m) => acc + (weight.get(m.key) ?? 0), 0);
    return wb - wa || a.label.localeCompare(b.label, "ko");
  });
  const isSameNet = (g: { net: string }) => {
    const prefix = g.net ? g.net.replace(/\.x$/, "") : "";
    return Boolean(prefix) && hostNetSet.has(prefix);
  };
  const sameNetGroups = sortedGroups.filter(isSameNet);
  // 사설(RFC1918) 대역은 호스트 대역과 달라도 내부다 — 다만 망을 나눈
  // 의도를 존중해 호스트 지형과 병합하지는 않고 별도 내부 클러스터로 둔다.
  const isPrivateGroup = (g: { net: string; members: Graph3DNode[] }) =>
    !isSameNet(g) && (g.net ? isPrivateIp(g.net.replace(/\.x$/, ".0")) : g.members.some((m) => isPrivateIp(m.label)));
  const privateGroups = sortedGroups.filter(isPrivateGroup);
  const externalGroups = sortedGroups.filter((g) => !isSameNet(g) && !isPrivateGroup(g));

  // 중앙 지형: 등록 호스트 + 같은 대역 상대를 하나의 벌집 나선으로 —
  // 격자가 이어져 면이 맞닿으므로 같은 네트워크임이 그림 자체로 보인다.
  const sameNetKeys = new Set<string>();
  sameNetGroups.forEach((g) => g.members.forEach((m) => sameNetKeys.add(m.key)));
  const privateKeys = new Set<string>();
  privateGroups.forEach((g) => g.members.forEach((m) => privateKeys.add(m.key)));
  const hostTone = new Map<string, string>();
  let hostRadius = 0;
  if (mode === "external") {
    // 등록 호스트도 /24가 다르면 별개 지형 — 사무망/클라우드처럼 다른
    // 대역의 호스트를 한 벌집으로 묶지 않는다. 색 원칙(호스트 로즈,
    // 같은 대역 파랑)은 지형마다 동일하게 유지된다.
    type Terrain = { net: string; hostList: typeof hosts; peerGroups: typeof sameNetGroups };
    const netsOf = (hostKey: string) => hostNetInfo.find((h) => h.key === hostKey)?.nets ?? [];
    // 대역을 하나라도 공유하는 호스트들은 같은 지형이다 — 호스트가 IP를
    // 여러 개 가질 때 첫 대역만 보면 같은 망인데도 갈라진다 (union-find).
    const parent = new Map<string, string>();
    const find = (net: string): string => {
      if (!parent.has(net)) parent.set(net, net);
      let root = net;
      while (parent.get(root) !== root) root = parent.get(root)!;
      let cursor = net;
      while (parent.get(cursor) !== root) {
        const next = parent.get(cursor)!;
        parent.set(cursor, root);
        cursor = next;
      }
      return root;
    };
    const union = (a: string, b: string) => { parent.set(find(a), find(b)); };
    hostNetInfo.forEach((h) => {
      for (let i = 1; i < h.nets.length; i++) union(h.nets[0], h.nets[i]);
    });
    const terrains = new Map<string, Terrain>();
    hosts.forEach((h) => {
      const nets = netsOf(h.key);
      const terrainKey = nets.length ? find(nets[0]) : `solo:${h.key}`;
      const terrain = terrains.get(terrainKey) ?? { net: terrainKey, hostList: [], peerGroups: [] };
      terrain.hostList.push(h);
      terrains.set(terrainKey, terrain);
    });
    sameNetGroups.forEach((g) => {
      const prefix = g.net.replace(/\.x$/, "");
      const owner = terrains.get(find(prefix))
        ?? [...terrains.values()].find((t) => t.hostList.some((h) => netsOf(h.key).includes(prefix)))
        ?? [...terrains.values()][0];
      owner?.peerGroups.push(g);
    });
    // 사설 대역: 호스트 지형과 병합하지 않는 자기만의 내부 지형.
    privateGroups.forEach((g) => {
      const prefix = g.net ? g.net.replace(/\.x$/, "") : g.label;
      terrains.set(`private:${prefix}`, { net: prefix, hostList: [], peerGroups: [g] });
    });
    const terrainSize = (t: Terrain) => t.hostList.length + t.peerGroups.reduce((acc, g) => acc + g.members.length, 0);
    const terrainList = [...terrains.values()].sort((a, b) => terrainSize(b) - terrainSize(a));
    const placedTerrains: { x: number; z: number; r: number }[] = [];
    terrainList.forEach((terrain, ti) => {
      const offsets = hexSpiralOffsets(terrainSize(terrain), TILE_HOST + 0.8);
      const radius = offsets.reduce((acc, o) => Math.max(acc, Math.hypot(o.x, o.z)), 0) + TILE_HOST;
      let at = { x: 0, z: 0 };
      if (ti > 0) {
        const seed = mixHash(hashOf(terrain.net));
        const angle0 = ((seed % 360) / 360) * Math.PI * 2;
        for (let k = 0; k < 400; k++) {
          const rad = 40 + k * 8;
          const ang = angle0 + k * 2.399963;
          const x = Math.cos(ang) * rad;
          const z = Math.sin(ang) * rad;
          if (placedTerrains.every((q) => Math.hypot(x - q.x, z - q.z) > radius + q.r + 46)) {
            at = { x, z };
            break;
          }
        }
      }
      placedTerrains.push({ x: at.x, z: at.z, r: radius });
      let slot = 0;
      terrain.hostList.forEach((h) => {
        hostTone.set(h.key, ACCENT);
        laid.push({ ...h, id: h.key, tone: ACCENT, net: "", r: TILE_HOST, fx: at.x + offsets[slot].x, fy: 0, fz: at.z + offsets[slot].z });
        slot += 1;
      });
      terrain.peerGroups.forEach((g, gi) => {
        const members = [...g.members].sort(byWeight);
        const tone = BLUE_TONES[gi % BLUE_TONES.length];
        members.forEach((m, mi) => {
          laid.push({ ...m, id: m.key, tone: shade(tone, mi), net: g.net, sameNet: true, r: TILE_HOST, fx: at.x + offsets[slot].x, fy: 0, fz: at.z + offsets[slot].z });
          slot += 1;
        });
      });
      hostRadius = Math.max(hostRadius, Math.hypot(at.x, at.z) + radius);
    });
  } else {
    // 내부 뷰: 호스트별 고유 색, 전부 낱개 배치.
    const centerOffsets = hexSpiralOffsets(hosts.length, TILE_HOST * 3.2);
    hosts.forEach((h, hi) => {
      const tone = HOST_TONES[hi % HOST_TONES.length];
      hostTone.set(h.key, tone);
      laid.push({ ...h, id: h.key, tone, net: "", r: TILE_HOST, fx: centerOffsets[hi].x, fy: 0, fz: centerOffsets[hi].z });
    });
    hostRadius = centerOffsets.reduce((acc, o) => Math.max(acc, Math.hypot(o.x, o.z)), 0) + TILE_HOST;
  }

  if (mode === "internal" && loopbackNodes.length > 0) {
    const perHostIndex = new Map<string, number>();
    const hostPos = new Map(laid.filter((n) => n.registered).map((n) => [n.id, { x: n.fx, z: n.fz }]));
    loopbackNodes.forEach((n) => {
      const owner = loopbackOwner.get(n.key)?.owner ?? hosts[0]?.key ?? "";
      const index = perHostIndex.get(owner) ?? 0;
      perHostIndex.set(owner, index + 1);
      const base = hostPos.get(owner) ?? { x: 0, z: 0 };
      const angle = -Math.PI / 2 + index * (Math.PI / 3);
      const distance = TILE_HOST * 3 + TILE_PEER;
      laid.push({
        ...n,
        id: n.key,
        // 소속 호스트와 같은 색 — 크기(작음)와 흰 점 없음으로 구분된다.
        tone: hostTone.get(owner) ?? ACCENT,
        net: "",
        r: TILE_PEER,
        fx: base.x + Math.cos(angle) * distance,
        fy: 0,
        fz: base.z + Math.sin(angle) * distance,
      });
    });
  }

  // 외부 대역: 해시 산개 (회색 계열).
  const placed: { x: number; z: number; r: number }[] = [
    { x: 0, z: 0, r: hostRadius + 60 },
  ];
  const scatterGroups = mode === "external"
    ? externalGroups
    : [...sameNetGroups, ...privateGroups].flatMap((g) => g.members.map((m) => ({ label: m.label, net: g.net, network: true, members: [m] })));
  scatterGroups.forEach((g, gi) => {
    const members = [...g.members].sort(byWeight);
    const offsets = hexSpiralOffsets(members.length, TILE_PEER + 0.8);
    const radius = offsets.reduce((acc, o) => Math.max(acc, Math.hypot(o.x, o.z)), 0) + TILE_PEER;
    const seed = mixHash(hashOf(g.label));
    const u = ((mixHash(seed ^ 0x9e3779b9) % 4096) / 4096) * 2 - 1;
    const v = ((mixHash(seed ^ 0x85ebca6b) % 4096) / 4096) * 2 - 1;
    const elevation = (((mixHash(seed ^ 0xc2b2ae35) % 4096) / 4096) * 2 - 1) * 170;
    const x0 = u * 340;
    const z0 = v * 340;
    const angle0 = ((seed % 360) / 360) * Math.PI * 2;
    let spot: { x: number; z: number } | null = null;
    for (let k = 0; k < 500 && !spot; k++) {
      const rad = k * 7;
      const ang = angle0 + k * 2.399963;
      const x = x0 + Math.cos(ang) * rad;
      const z = z0 + Math.sin(ang) * rad;
      if (Math.hypot(x, z) < hostRadius + 60) continue;
      if (placed.every((q) => Math.hypot(x - q.x, z - q.z) > radius + q.r + 14)) {
        spot = { x, z };
        placed.push({ x, z, r: radius });
      }
    }
    const at = spot ?? { x: x0, z: z0 };
    // 내부 뷰: 색으로 구분하는 건 등록 호스트뿐 — 나머지는 단일 푸른색.
    const tone = mode === "external"
      ? GRAY_TONES[gi % GRAY_TONES.length]
      : BLUE_TONES[0];
    members.forEach((m, mi) => {
      laid.push({
        ...m,
        id: m.key,
        tone: mode === "external" ? shade(tone, mi) : tone,
        net: g.net,
        r: TILE_PEER,
        fx: at.x + offsets[mi].x,
        fy: elevation,
        fz: at.z + offsets[mi].z,
      });
    });
  });

  // 호스트↔상대 쌍당 선 하나 — 연결 여부만 보이면 되므로 방향·건수별로
  // 겹쳐 그리지 않는다. 양방향이면 청록, 한쪽이면 해당 방향 색.
  const pairMap = new Map<string, { source: string; target: string; keys: string[]; dirs: Set<string>; count: number }>();
  edges.forEach((e) => {
    const source = e.direction === "inbound" ? lowerKey(e.peer) : lowerKey(e.host);
    const target = e.direction === "inbound" ? lowerKey(e.host) : lowerKey(e.peer);
    const pairKey = [lowerKey(e.host), lowerKey(e.peer)].sort().join("|");
    const entry = pairMap.get(pairKey) ?? { source, target, keys: [], dirs: new Set<string>(), count: 0 };
    entry.keys.push(e.key);
    entry.dirs.add(e.direction);
    entry.count += e.count;
    pairMap.set(pairKey, entry);
  });
  const hostKeySet = new Set(hosts.map((h) => h.key));
  let visiblePairs = [...pairMap.values()].filter((pair) => {
    const internal = (sameNetKeys.has(pair.source) || sameNetKeys.has(pair.target) || privateKeys.has(pair.source) || privateKeys.has(pair.target) || loopbackKeys.has(pair.source) || loopbackKeys.has(pair.target) || (hostKeySet.has(pair.source) && hostKeySet.has(pair.target)));
    return mode === "external" ? !internal : internal;
  });
  if (mode === "external") {
    // 외부 상대가 지형(호스트·같은 대역) 안 여러 대상과 오갔어도 선은
    // 하나 — 왕래가 가장 많은 대상으로 대표선을 그리고 나머지 관계 키는
    // 강조 매칭을 위해 함께 담는다.
    const centerSet = new Set([...hostKeySet, ...sameNetKeys]);
    const byExternal = new Map<string, typeof visiblePairs>();
    const passthrough: typeof visiblePairs = [];
    visiblePairs.forEach((pair) => {
      const external = centerSet.has(pair.source) ? (centerSet.has(pair.target) ? null : pair.target) : pair.source;
      if (!external) {
        passthrough.push(pair);
        return;
      }
      const bucket = byExternal.get(external) ?? [];
      bucket.push(pair);
      byExternal.set(external, bucket);
    });
    visiblePairs = [
      ...passthrough,
      ...[...byExternal.values()].map((bucket) => {
        const best = bucket.reduce((acc, pair) => (pair.count > acc.count ? pair : acc), bucket[0]);
        return {
          ...best,
          keys: bucket.flatMap((pair) => pair.keys),
          dirs: new Set(bucket.flatMap((pair) => [...pair.dirs])),
          count: bucket.reduce((acc, pair) => acc + pair.count, 0),
        };
      }),
    ];
  }
  const links: LaidLink[] = visiblePairs.map((pair) => {
    const hasIn = pair.dirs.has("inbound");
    const hasOut = pair.dirs.has("outbound");
    const tone = hasIn && hasOut ? "bidi" : hasIn ? "in" : hasOut ? "out" : "unknown";
    const color = DIRECTION_COLOR[tone];
    return {
      key: pair.keys[0],
      keys: pair.keys,
      source: pair.source,
      target: pair.target,
      tone: color,
      // 배경색 쪽으로 눌러 둔 옅은 톤 — 붙어 있는 같은 대역 선이 평소에
      // 거슬리지 않게 한다.
      dimTone: `#${new THREE.Color(color).lerp(new THREE.Color("#141b28"), 0.8).getHexString()}`,
      sameNet: sameNetKeys.has(pair.source) || sameNetKeys.has(pair.target),
      unknownDirection: !hasIn && !hasOut,
    };
  });
  return { laid, links };
}

export default function HostConnection3D({ nodes, edges, hostNets, hostNetInfo, mode, width, height, selected, onNode, onClear }: Props) {
  const graphRef = useRef<{ cameraPosition: (pos: object, lookAt?: object, ms?: number) => void; zoomToFit: (ms?: number, px?: number) => void } | null>(null);
  const [hoverKey, setHoverKey] = useState<string | null>(null);
  // 타일을 클릭하면 호버 강조를 고정(핀)한다 — 배경 클릭이나 재클릭으로 해제.
  const [pinnedKey, setPinnedKey] = useState<string | null>(null);
  // WebGL 컴포넌트는 창(window)이 있어야 하므로 마운트 후 직접 불러온다 —
  // next/dynamic은 ref를 전달하지 않아 카메라 제어가 불가능하다.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [ForceGraph3D, setForceGraph3D] = useState<React.ComponentType<any> | null>(null);
  useEffect(() => {
    let active = true;
    void import("react-force-graph-3d").then((mod) => {
      if (active) setForceGraph3D(() => mod.default);
    });
    return () => { active = false; };
  }, []);

  const { laid, links } = useMemo(() => layout3d(nodes, edges, hostNets, hostNetInfo, mode), [nodes, edges, hostNets, hostNetInfo, mode]);
  const statsByKey = useMemo(() => {
    const map = new Map<string, { count: number; fail: number; last: string }>();
    edges.forEach((e) => {
      for (const k of [lowerKey(e.host), lowerKey(e.peer)]) {
        const entry = map.get(k) ?? { count: 0, fail: 0, last: "" };
        entry.count += e.count;
        entry.fail += e.fail;
        if (e.last && e.last > entry.last) entry.last = e.last;
        map.set(k, entry);
      }
    });
    return map;
  }, [edges]);
  // 뷰 모드가 바뀌면 이전 뷰의 핀·호버 강조를 지운다.
  useEffect(() => {
    setPinnedKey(null);
    setHoverKey(null);
  }, [mode]);
  // 목록으로 돌아가는 등 부모 선택이 비워지면 핀도 함께 해제한다 —
  // 핀만 남아 강조·정보 패널이 유지되는 것을 막는다.
  useEffect(() => {
    if (selected === null) setPinnedKey(null);
  }, [selected]);
  // 강조 기준점: 호버 > 클릭 고정(핀) > 선택된 노드 — 셋 다 같은
  // 하이라이트와 정보 패널을 띄운다. selected는 노드 키다.
  const activeKey = hoverKey ?? pinnedKey ?? selected;
  const hoverTileInfo = useMemo(() => {
    if (!activeKey) return null;
    const node = laid.find((n) => n.id === activeKey);
    if (!node) return null;
    return { label: node.label, net: node.net, stats: statsByKey.get(node.id) ?? null };
  }, [activeKey, laid, statsByKey]);
  const hoverLinked = useMemo(() => {
    if (!activeKey) return null;
    const set = new Set<string>([activeKey]);
    // 외부 뷰에서 같은 대역(미등록) 타일은 내부 이동선을 그리지 않으므로
    // "연결됨" 전파 없이 그 타일만 밝힌다.
    const focal = laid.find((n) => n.id === activeKey);
    if (mode === "external" && focal?.sameNet) return set;
    const nodeById = new Map(laid.map((n) => [n.id, n]));
    edges.forEach((e) => {
      const hostKey = lowerKey(e.host);
      const peerKey = lowerKey(e.peer);
      const other = hostKey === activeKey ? peerKey : peerKey === activeKey ? hostKey : null;
      if (!other) return;
      // 외부 뷰에서 등록 호스트 강조: 보이는 선이 있는 외부 상대만 —
      // 내부(같은 대역·다른 등록 호스트)는 선이 없으므로 밝히지 않는다.
      if (mode === "external" && focal?.registered) {
        const info = nodeById.get(other);
        if (info && (info.registered || info.sameNet)) return;
      }
      set.add(other);
    });
    return set;
  }, [edges, activeKey, laid, mode]);

  // 시작 카메라: 위에서 내려보는 정돈된 등각 시점 + 전체 화면 맞춤.
  // 회전은 지평선 아래로 뒤집히지 않게 제한하고, 강한 앰비언트 광으로
  // 앱의 파스텔 플랫 톤을 유지한다 (번들거리는 3D 광택 제거).
  const model = useMemo(() => `${laid.length}|${links.length}`, [laid.length, links.length]);
  useEffect(() => {
    if (!ForceGraph3D) return;
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      const graph = graphRef.current as unknown as {
        cameraPosition: (pos: object, lookAt?: object, ms?: number) => void;
        zoomToFit: (ms?: number, px?: number) => void;
        controls?: () => { minPolarAngle: number; maxPolarAngle: number; enableDamping?: boolean };
        scene?: () => THREE.Scene;
      } | null;
      if (!graph || !graph.controls?.()) {
        if (tries > 50) window.clearInterval(timer);
        return;
      }
      window.clearInterval(timer);
      // 낮게 눕힌 시점(고도 ~28°, 야 ~25°). zoomToFit은 낮은 각도에서
      // 오동작하므로 노드 분포에서 거리를 직접 계산해 고정한다.
      const maxExtent = laid.reduce((acc, n) => Math.max(acc, Math.hypot(n.fx, n.fz) + Math.abs(n.fy)), 1);
      const distance = Math.max(480, maxExtent * 2.2);
      const direction = { x: 300, y: 380, z: 640 };
      const length = Math.hypot(direction.x, direction.y, direction.z);
      graph.cameraPosition(
        { x: (direction.x / length) * distance, y: (direction.y / length) * distance, z: (direction.z / length) * distance },
        { x: 0, y: 0, z: 0 },
        0,
      );
      const controls = graph.controls?.() as unknown as { minPolarAngle: number; maxPolarAngle: number; enablePan?: boolean } | undefined;
      if (controls) {
        controls.minPolarAngle = 0.12;
        controls.maxPolarAngle = 1.45;
        controls.enablePan = true;
      }
      const scene = graph.scene?.();
      if (scene && !scene.getObjectByName("wina-ambient")) {
        const ambient = new THREE.AmbientLight(0xffffff, 1.0);
        ambient.name = "wina-ambient";
        scene.add(ambient);
      }

    }, 60);
    return () => window.clearInterval(timer);
  }, [ForceGraph3D, model]);

  const nodeObject = (raw: object) => {
    const node = raw as LaidNode;
    const group = new THREE.Group();
    const dimmed = Boolean(hoverLinked) && !hoverLinked?.has(node.id);
    const tileHeight = node.registered ? 7 : 5;
    const geometry = new THREE.CylinderGeometry(node.r, node.r, tileHeight, 6);
    const material = new THREE.MeshLambertMaterial({
      color: node.tone,
      transparent: true,
      opacity: dimmed ? 0.18 : node.registered ? 0.98 : 0.9,
    });
    const prism = new THREE.Mesh(geometry, material);
    // 노드 원점 = 타일 윗면 중심 — 선이 옆면·꼭짓점을 뚫지 않고
    // 윗면에 내려앉는다.
    prism.position.set(0, -tileHeight / 2, 0);
    group.add(prism);
    if (activeKey === node.id) {
      // 흰 캡으로 덮지 않고, 타일 색을 밝히고 모서리 외곽선만 두른다.
      material.emissive = new THREE.Color(node.tone);
      material.emissiveIntensity = 0.5;
      const outline = new THREE.LineSegments(
        new THREE.EdgesGeometry(geometry),
        new THREE.LineBasicMaterial({ color: "#e6edf5", transparent: true, opacity: 0.85 }),
      );
      outline.position.copy(prism.position);
      group.add(outline);
    }
    return group;
  };

  if (!ForceGraph3D) {
    return <div style={{ width: "100%", height: "100%" }} />;
  }
  return (
    <div style={{ position: "relative", width: "100%", height: "100%", minHeight: 0, overflow: "hidden" }} onContextMenu={(event) => event.preventDefault()}>
      <ForceGraph3D
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ref={graphRef as any}
        graphData={{ nodes: laid, links }}
        width={width}
        height={height}
        backgroundColor="rgba(0,0,0,0)"
        showNavInfo={false}
        cooldownTicks={0}
        warmupTicks={0}
        enableNodeDrag={false}
        nodeThreeObject={nodeObject}
        nodeLabel={() => ""}
        onNodeClick={(raw: object) => {
          const node = raw as LaidNode;
          if (pinnedKey === node.id) {
            setPinnedKey(null);
            onClear();
          } else {
            setPinnedKey(node.id);
            onNode({ key: node.key, label: node.label, registered: node.registered });
          }
        }}
        onBackgroundClick={() => { setPinnedKey(null); onClear(); }}
        onNodeHover={(raw: object | null) => {
          setHoverKey(raw ? (raw as LaidNode).id : null);
        }}
        linkColor={(raw: object) => {
          const link = raw as LaidLink;
          if (activeKey !== null) {
            const sourceKey = typeof link.source === "object" ? (link.source as LaidNode).id : String(link.source);
            const targetKey = typeof link.target === "object" ? (link.target as LaidNode).id : String(link.target);
            return sourceKey === activeKey || targetKey === activeKey ? link.tone : link.dimTone;
          }
          return link.tone;
        }}
        linkOpacity={0.5}
        linkWidth={(raw: object) => {
          const link = raw as LaidLink;
          const sourceKey = typeof link.source === "object" ? (link.source as LaidNode).id : String(link.source);
          const targetKey = typeof link.target === "object" ? (link.target as LaidNode).id : String(link.target);
          const emphasized = activeKey !== null && (sourceKey === activeKey || targetKey === activeKey);
          // 양방향(청록)은 왕복 왕래라는 뜻이므로 한 단계 더 굵게.
          const bidirectional = link.tone === DIRECTION_COLOR.bidi;
          // 강조 중엔 관련 없는 선을 가늘게 가라앉힌다 (호버와 동일).
          if (!emphasized && activeKey !== null) return 0.45;
          return emphasized ? (bidirectional ? 2.7 : 2.2) : (bidirectional ? 1.7 : 1.1);
        }}
        linkCurvature={0.08}
        linkDirectionalParticles={0}
      />
      <div
        aria-label="그래프 범례"
        style={{ position: "absolute", zIndex: 3, top: 10, left: 12, display: "grid", gap: 7, padding: "9px 12px", background: "color-mix(in srgb, var(--bg-panel) 88%, transparent)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text-dim)", fontSize: 11.5, pointerEvents: "none" }}
      >
        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 12, height: 12, borderRadius: 3, background: "color-mix(in srgb, #e08a8a 55%, transparent)", border: "1px solid #e08a8a" }} />
            등록 호스트
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 12, height: 12, borderRadius: 3, background: "color-mix(in srgb, #5f8fd8 45%, transparent)", border: "1px solid #5f8fd8" }} />
            내부 대역 (미등록)
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 12, height: 12, borderRadius: 3, background: "color-mix(in srgb, #9aa4b0 40%, transparent)", border: "1px solid #9aa4b0" }} />
            외부 상대 (미등록)
          </span>
        </div>
        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 16, height: 0, borderTop: "2px solid #f2a86f" }} />
            인바운드 (들어옴)
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 16, height: 0, borderTop: "2px solid #9b7ef8" }} />
            아웃바운드 (나감)
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
            <span aria-hidden="true" style={{ width: 16, height: 0, borderTop: "2px solid #5bc8c0" }} />
            양방향
          </span>
        </div>
      </div>
      {hoverTileInfo && (
        <div
          role="status"
          aria-label="호버한 노드 정보"
          style={{ position: "absolute", right: 12, top: 10, zIndex: 4, minWidth: 210, maxWidth: 320, padding: "10px 13px", background: "color-mix(in srgb, var(--bg-panel) 92%, transparent)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", pointerEvents: "none", fontSize: 12.5, color: "var(--text-dim)" }}
        >
          <div style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13.5, color: "var(--text)", overflowWrap: "anywhere" }}>{hoverTileInfo.label}</div>
          {hoverTileInfo.net && <div style={{ marginTop: 2, color: "var(--text-faint)", fontFamily: "var(--mono)", fontSize: 11.5 }}>{hoverTileInfo.net} 대역</div>}
          {hoverTileInfo.stats && (
            <div style={{ marginTop: 3 }}>
              이벤트 {hoverTileInfo.stats.count.toLocaleString()}건
              {hoverTileInfo.stats.fail > 0 && <span style={{ color: "var(--danger)" }}> · 실패 {hoverTileInfo.stats.fail.toLocaleString()}</span>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
