"use client";

import { useMemo, useState } from "react";
import type { CsvData } from "@/lib/types";

interface RdpCacheViewProps {
  data: CsvData;
  // "fragments" = the stitched/reconstructed images (붙여진, in 종합 분석);
  // "tiles" = the raw single cache tiles (원본, in 원본 데이터).
  mode?: "fragments" | "tiles";
}

// RDP bitmap cache: the tiles mstsc.exe cached from remote sessions, each a
// fragment of what was on screen. The parser reassembles adjacent tiles (their
// touching edges match exactly) into "fragment" images — reconstructed screen
// regions — and also keeps a per-file "mosaic" (all tiles in cache order) plus
// the leftover single "tile"s. Every image rides as a base64 PNG. The stitched
// fragments/mosaic ("붙여진") live in 종합 분석; the raw tiles ("원본") stay here.

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

export default function RdpCacheView({ data, mode = "fragments" }: RdpCacheViewProps) {
  const [zoom, setZoom] = useState<{ img: string; label: string } | null>(null);
  const isTiles = mode === "tiles";

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
    // Only keep files that have something to show in this mode. The mosaic
    // (all tiles laid out) belongs with the raw tiles, not the reconstruction.
    return [...byFile.values()]
      .filter((g) => (isTiles ? g.tiles.length > 0 || g.mosaic : g.fragments.length > 0))
      .sort((a, b) => a.source.localeCompare(b.source));
  }, [data.rows, isTiles]);

  const totalFrag = groups.reduce((n, g) => n + g.fragments.length, 0);
  const totalTiles = groups.reduce((n, g) => n + g.tiles.length, 0);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 4 }}>
        <span style={{ fontSize: 16, fontWeight: 700 }}>🖼️ {isTiles ? "RDP 캐시 원본 타일" : "RDP 비트맵 캐시 (복원)"}</span>
        <span style={{ fontSize: 12, color: "var(--text-faint)" }}>
          {isTiles
            ? `${groups.length}개 파일 · 낱장 타일 ${totalTiles.toLocaleString()}개`
            : `${groups.length}개 파일 · 복원 조각 ${totalFrag.toLocaleString()}개`}
        </span>
      </div>
      <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginBottom: 20, lineHeight: 1.6 }}>
        {isTiles
          ? "원격 세션에서 캐시된 낱장 비트맵 타일(원본)입니다. 이어붙여 복원한 이미지는 [종합 분석 › RDP 캐시]에서 볼 수 있습니다."
          : "경계 픽셀이 일치하는 타일을 이어붙여 화면 일부를 복원한 이미지입니다. 타일에 좌표가 없어 완전 복원은 불가하며, 낱장 원본 타일은 [원본 데이터 › RdpCache]에 있습니다."}
      </div>

      {groups.length === 0 && (
        <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>{isTiles ? "캐시 타일이 없습니다." : "복원된 조각이 없습니다."}</div>
      )}

      {groups.map((g) => (
        <section key={g.source} style={{ marginBottom: 30 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
            <span style={{ fontSize: 14, fontWeight: 700 }}>{g.source}</span>
            <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>
              {isTiles ? `낱장 ${g.tiles.length.toLocaleString()}개` : `복원 ${g.fragments.length}개`}
            </span>
          </div>

          {isTiles ? (
            /* raw single tiles + the see-all mosaic — the content in 원본 데이터 */
            <>
            {g.mosaic?.image && (
              <div style={{ marginBottom: 14 }}>
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
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
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
            </>
          ) : (
            /* reconstructed fragments only — no raw tiles/mosaic here */
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
