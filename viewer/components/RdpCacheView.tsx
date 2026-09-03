"use client";
import PaginationControls from "@/components/PaginationControls";
import { SelectDropdown } from "@/components/FilterControls";

import { useId, useMemo, useState } from "react";
import PhotoLibraryOutlinedIcon from "@mui/icons-material/PhotoLibraryOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import type { CsvData } from "@/lib/types";
import { useModalDialog } from "@/lib/useModalDialog";

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
  account: string;
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
  const zoomTitleId = useId();
  const zoomDialogRef = useModalDialog(() => setZoom(null), Boolean(zoom));
  // Which account's cache to show; null = all accounts.
  const [selAccount, setSelAccount] = useState<string | null>(null);
  const isTiles = mode === "tiles";

  const groups = useMemo(() => {
    const rows = data.rows as Row[];
    const byFile = new Map<string, Group>();
    for (const r of rows) {
      const account = r.account || "unknown";
      const source = r.source_file || "(unknown)";
      // Key on account + file: every user has a Cache0000.bin, so keying on the
      // filename alone would merge different users' caches together.
      const key = `${account}\u0000${source}`;
      let g = byFile.get(key);
      if (!g) {
        g = { account, source, mosaic: null, fragments: [], tiles: [] };
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
      .sort((a, b) => a.account.localeCompare(b.account) || a.source.localeCompare(b.source));
  }, [data.rows, isTiles]);

  // Account tabs (sorted; a selected tab narrows the view to that account).
  const accounts = useMemo(
    () => [...new Set(groups.map((g) => g.account))].sort((a, b) => a.localeCompare(b)),
    [groups],
  );
  const visible = useMemo(
    () => (selAccount ? groups.filter((g) => g.account === selAccount) : groups),
    [groups, selAccount],
  );

  const totalFrag = visible.reduce((n, g) => n + g.fragments.length, 0);
  const totalTiles = visible.reduce((n, g) => n + g.tiles.length, 0);
  const accountCount = accounts.length;

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <header style={{ flexShrink: 0, padding: "12px 16px 10px", borderBottom: "1px solid var(--border)", background: "var(--bg-panel)" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <PhotoLibraryOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} aria-hidden="true" /><strong style={{ fontSize: 15, color: "var(--text)" }}>{isTiles ? "RDP 캐시 원본 타일" : "RDP 비트맵 캐시 (복원)"}</strong>
        <span style={{ fontSize: 12, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>
          {(accountCount > 0 ? `계정 ${accountCount}명 · ` : "") + (isTiles
            ? `${visible.length}개 파일 · 낱장 타일 ${totalTiles.toLocaleString()}개`
            : `${visible.length}개 파일 · 복원 조각 ${totalFrag.toLocaleString()}개`)}
        </span>
      </div>
      {accounts.length > 1 && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginTop: 9 }}>
          <SelectDropdown
            icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />}
            label="계정"
            options={[{ value: "__all", label: "전체" }, ...accounts.map((a) => ({ value: a, label: a }))]}
            value={selAccount ?? "__all"}
            defaultValue="__all"
            onChange={(next) => setSelAccount(next === "__all" ? null : next)}
          />
        </div>
      )}
      </header>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "16px 16px 24px" }}>
      {visible.length === 0 && (
        <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>{isTiles ? "캐시 타일이 없습니다." : "복원된 조각이 없습니다."}</div>
      )}

      {visible.map((g) => (
        <section key={`${g.account} ${g.source}`} style={{ marginBottom: 30 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, borderBottom: "1px solid var(--border-subtle)", paddingBottom: 6 }}>
            {g.account && (
              <span style={{ fontSize: 11.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-lg)", padding: "1px 8px" }}>
                <PersonOutlineIcon aria-hidden="true" sx={{ fontSize: 14 }} /> {g.account}
              </span>
            )}
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
            <FileGallery
              items={g.tiles}
              pageSize={96}
              columns="repeat(auto-fill, 66px)"
              renderItem={(t) => (
                <div key={t.tile_index} style={{ position: "relative", lineHeight: 0 }}>
                  <img
                    src={src(t.image)}
                    alt={`타일 ${t.tile_index}`}
                    title={`타일 ${t.tile_index} · ${t.width}×${t.height}${Number(t.count) > 1 ? ` · ${t.count}회` : ""} · 클릭하면 확대`}
                    onClick={() => setZoom({ img: src(t.image), label: `${g.source} · 타일 ${t.tile_index}` })}
                    style={{ width: 64, height: 64, objectFit: "none", objectPosition: "top left", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-xs)", cursor: "zoom-in", background: "var(--bg)", imageRendering: "pixelated" }}
                  />
                  {Number(t.count) > 1 && (
                    <span style={{ position: "absolute", right: 1, bottom: 1, background: "rgba(0,0,0,0.7)", color: "#fff", fontSize: 9, padding: "0 3px", borderRadius: "var(--radius-xs)" }}>×{t.count}</span>
                  )}
                </div>
              )}
            />
            </>
          ) : (
            /* reconstructed fragments only — 세션(파일)별 갤러리 + 페이지네이션 */
            <FileGallery
              items={g.fragments}
              pageSize={10}
              renderItem={(f) => (
                <button
                  key={f.fragment_index}
                  type="button"
                  onClick={() => setZoom({ img: src(f.image), label: `${g.source} · 복원 조각 ${f.fragment_index} (${f.tile_count} 타일)` })}
                  title={`${f.tile_count} 타일 · ${f.cols}×${f.rows} · 클릭하면 확대`}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 180, padding: 6, border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg)", cursor: "zoom-in", overflow: "hidden" }}
                >
                  <img src={src(f.image)} alt={`복원 조각 ${f.fragment_index}`} style={{ maxWidth: "100%", maxHeight: "100%", imageRendering: "pixelated" }} />
                </button>
              )}
            />
          )}
        </section>
      ))}

      {zoom && (
        <div
          onClick={() => setZoom(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 1000, display: "flex", flexDirection: "column", alignItems: "center", padding: 24, overflow: "auto", cursor: "zoom-out" }}
        >
          <div
            ref={zoomDialogRef}
            onClick={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby={zoomTitleId}
            tabIndex={-1}
            style={{ margin: "auto", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 0, maxWidth: "100%", cursor: "default" }}
          >
            <div style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, color: "#fff", fontSize: 13, marginBottom: 10, flexShrink: 0 }}>
              <span id={zoomTitleId} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{zoom.label}</span>
              <button type="button" onClick={() => setZoom(null)} data-dialog-autofocus aria-label="확대 이미지 닫기" title="닫기 (Esc)" style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, padding: 0, border: "1px solid rgba(255,255,255,.24)", borderRadius: "var(--radius-sm)", background: "rgba(0,0,0,.28)", color: "#fff", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 18 }} /></button>
            </div>
            <img
              src={zoom.img}
              alt={zoom.label}
              onLoad={(event) => {
                const image = event.currentTarget;
                const fitWidth = window.innerWidth * 0.88 / image.naturalWidth;
                const fitHeight = window.innerHeight * 0.78 / image.naturalHeight;
                const scale = Math.max(1, Math.min(2.5, fitWidth, fitHeight));
                image.style.width = `${Math.round(image.naturalWidth * scale)}px`;
              }}
              style={{ imageRendering: "pixelated", maxWidth: "none" }}
            />
          </div>
        </div>
      )}
      </main>
    </div>
  );
}

/// 세션(캐시 파일)별 이미지 갤러리 — 균일한 그리드 + 자체 페이지네이션.
function FileGallery<T>({
  items,
  renderItem,
  pageSize,
  columns = "repeat(auto-fill, minmax(210px, 1fr))",
}: {
  items: T[];
  renderItem: (item: T) => React.ReactNode;
  pageSize: number;
  columns?: string;
}) {
  const [page, setPage] = useState(0);
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const start = safePage * pageSize;
  const shown = items.slice(start, start + pageSize);
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: columns, gap: 8 }}>
        {shown.map(renderItem)}
      </div>
      {pageCount > 1 && (
        <div style={{ display: "flex", justifyContent: "center", marginTop: 10 }}>
          <PaginationControls
            ariaLabel="복원 이미지 페이지"
            page={safePage}
            pageCount={pageCount}
            onChange={setPage}
            summary={`(${(start + 1).toLocaleString()}–${Math.min(items.length, start + pageSize).toLocaleString()} / ${items.length.toLocaleString()})`}
          />
        </div>
      )}
    </div>
  );
}

