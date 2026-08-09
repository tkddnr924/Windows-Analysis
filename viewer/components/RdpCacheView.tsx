"use client";

import { useMemo, useState } from "react";
import type { CsvData } from "@/lib/types";

interface RdpCacheViewProps {
  data: CsvData;
}

// RDP bitmap cache: the tiles mstsc.exe cached from remote sessions, each a
// fragment of what was on screen. The parser reassembles adjacent tiles (their
// touching edges match exactly) into "fragment" images — reconstructed screen
// regions — and also keeps a per-file "mosaic" (all tiles in cache order) plus
// the leftover single "tile"s. Every image rides as a base64 PNG. This view
// leads with the reconstructed fragments, since that's what an analyst reads.

type Row = Record<string, string>;

interface Group {
  source: string;
  mosaic: Row | null;
  fragments: Row[];
  tiles: Row[];
}

function src(b64: string): string {
  return `data:image/png;base64,${b64}`;
}

export default function RdpCacheView({ data }: RdpCacheViewProps) {
  const [zoom, setZoom] = useState<{ img: string; label: string } | null>(null);
  const [showTiles, setShowTiles] = useState<Set<string>>(new Set());

  const groups = useMemo(() => {
    const rows = data.rows as Row[];
    const byFile = new Map<string, Group>();
    for (const r of rows) {
      const key = r.source_file || "(unknown)";
      let g = byFile.get(key);
      if (!g) {
        g = { source: key, mosaic: null, fragments: [], tiles: [] };
        byFile.set(key, g);
      }
      if (r.kind === "mosaic") g.mosaic = r;
      else if (r.kind === "fragment") g.fragments.push(r);
      else if (r.image) g.tiles.push(r);
    }
    for (const g of byFile.values()) {
      g.fragments.sort((a, b) => Number(b.tile_count) - Number(a.tile_count));
    }
    return [...byFile.values()].sort((a, b) => a.source.localeCompare(b.source));
  }, [data.rows]);

  const totalFrag = groups.reduce((n, g) => n + g.fragments.length, 0);

  function toggleTiles(source: string) {
    setShowTiles((prev) => {
      const next = new Set(prev);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return next;
    });
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 4 }}>
        <span style={{ fontSize: 16, fontWeight: 700 }}>🖼️ RDP 비트맵 캐시</span>
        <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{groups.length}개 파일 · 복원 조각 {totalFrag.toLocaleString()}개</span>
      </div>
      <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginBottom: 20, lineHeight: 1.6 }}>
        원격 세션 화면 조각입니다. 경계 픽셀이 일치하는 타일을 이어붙여 화면 일부를 복원했습니다.
        타일에 좌표가 없어 완전 복원은 불가하며, 이어붙지 않은 조각은 아래 낱장 타일과 모자이크에서 볼 수 있습니다.
      </div>

      {groups.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>캐시 타일이 없습니다.</div>}

      {groups.map((g) => (
        <section key={g.source} style={{ marginBottom: 30 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
            <span style={{ fontSize: 14, fontWeight: 700 }}>{g.source}</span>
            <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>
              복원 {g.fragments.length}개 · 낱장 {g.tiles.length.toLocaleString()}개
            </span>
          </div>

          {/* reconstructed fragments — the main content */}
          {g.fragments.length > 0 ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-start" }}>
              {g.fragments.map((f) => (
                <div
                  key={f.fragment_index}
                  onClick={() => setZoom({ img: src(f.image), label: `${g.source} · 복원 조각 ${f.fragment_index} (${f.tile_count} 타일)` })}
                  title={`${f.tile_count} 타일 · ${f.cols}×${f.rows}`}
                  style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: 4, background: "var(--bg)", cursor: "zoom-in" }}
                >
                  <img src={src(f.image)} alt={`복원 조각 ${f.fragment_index}`} style={{ display: "block", imageRendering: "pixelated", maxWidth: 360 }} />
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "var(--text-faint)", fontSize: 12 }}>이어붙은 조각이 없습니다 (아래 모자이크/낱장 참고).</div>
          )}

          {/* mosaic — see everything at once */}
          {g.mosaic?.image && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginBottom: 4 }}>전체 모자이크 (캐시 순서)</div>
              <div
                onClick={() => setZoom({ img: src(g.mosaic!.image), label: `${g.source} · 전체 모자이크` })}
                title="클릭하면 원본 크기로 확대"
                style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-md)", overflow: "hidden", cursor: "zoom-in", background: "var(--bg)", lineHeight: 0 }}
              >
                <img src={src(g.mosaic.image)} alt="모자이크" style={{ width: "100%", display: "block", imageRendering: "pixelated" }} />
              </div>
            </div>
          )}

          {/* leftover single tiles — collapsed */}
          {g.tiles.length > 0 && (
            <div style={{ marginTop: 12 }}>
              <button
                onClick={() => toggleTiles(g.source)}
                style={{ background: "transparent", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: "pointer", fontSize: 12, padding: "4px 12px" }}
              >
                {showTiles.has(g.source) ? "낱장 타일 접기" : `낱장 타일 ${g.tiles.length.toLocaleString()}개 펼치기`}
              </button>
              {showTiles.has(g.source) && (
                <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {g.tiles.map((t) => (
                    <div key={t.tile_index} style={{ position: "relative", lineHeight: 0 }}>
                      <img
                        src={src(t.image)}
                        alt={`타일 ${t.tile_index}`}
                        title={`타일 ${t.tile_index} · ${t.width}×${t.height}${Number(t.count) > 1 ? ` · ${t.count}회` : ""}`}
                        onClick={() => setZoom({ img: src(t.image), label: `${g.source} · 타일 ${t.tile_index}` })}
                        style={{ width: 64, height: 64, objectFit: "none", objectPosition: "top left", border: "1px solid var(--border-subtle)", cursor: "zoom-in", background: "var(--bg)", imageRendering: "pixelated" }}
                      />
                      {Number(t.count) > 1 && (
                        <span style={{ position: "absolute", right: 1, bottom: 1, background: "rgba(0,0,0,0.7)", color: "#fff", fontSize: 9, padding: "0 3px", borderRadius: 3 }}>×{t.count}</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>
      ))}

      {zoom && (
        <div
          onClick={() => setZoom(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 1000, display: "flex", flexDirection: "column", alignItems: "center", padding: 24, overflow: "auto", cursor: "zoom-out" }}
        >
          <div style={{ color: "#fff", fontSize: 13, marginBottom: 10, flexShrink: 0 }}>{zoom.label} — 클릭하면 닫기</div>
          <img src={zoom.img} alt={zoom.label} style={{ imageRendering: "pixelated", maxWidth: "none" }} />
        </div>
      )}
    </div>
  );
}
