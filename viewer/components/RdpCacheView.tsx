"use client";
// RDP 비트맵 캐시 (docs-10) — _OVERVIEW RdpCache의 복원 조각과 실패 행만 보여 준다.
// 타일·모자이크는 표시하지 않는다(2026-10-13 사용자 결정).
import { useEffect, useId, useMemo, useState } from "react";
import BrokenImageOutlinedIcon from "@mui/icons-material/BrokenImageOutlined";
import CloseOutlinedIcon from "@mui/icons-material/CloseOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import PhotoLibraryOutlinedIcon from "@mui/icons-material/PhotoLibraryOutlined";
import PaginationControls from "@/components/PaginationControls";
import { HeaderSearchInput, MultiSelectDropdown, ViewHeader } from "@/components/FilterControls";
import type { CsvData, FetchLinkedRows } from "@/lib/types";
import { useModalDialog } from "@/lib/useModalDialog";
import { resolveAccountDisplay, type AccountDirectory } from "@/lib/accountIdentity";
import { DEFAULT_RDP_FILTER, RDP_STATUS_LABELS, accountKeyOf, buildRdpGroups, type RdpFilter } from "@/lib/rdpCache";
import RowDetailPanel from "./RowDetailPanel";

type Row = Record<string, string>;

interface Props {
  fileName: string;
  /** Full stored RdpCache table (_OVERVIEW). */
  data: CsvData;
  hostDir?: string;
  onNavigate: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  accountDirectory?: AccountDirectory;
}

const PAGE_SIZE = 12;
const src = (b64: string) => `data:image/png;base64,${b64}`;

export default function RdpCacheView({ fileName, data, hostDir, onNavigate, onFetchLinkedRows, accountDirectory }: Props) {
  const [filter, setFilter] = useState<RdpFilter>(DEFAULT_RDP_FILTER);
  const [zoom, setZoom] = useState<{ row: Row; label: string } | null>(null);
  const [selected, setSelected] = useState<Row | null>(null);
  const [broken, setBroken] = useState<Set<string>>(new Set());
  const zoomTitleId = useId();
  const zoomDialogRef = useModalDialog(() => setZoom(null), Boolean(zoom));
  const update = (patch: Partial<RdpFilter>) => setFilter((previous) => ({ ...previous, ...patch }));
  useEffect(() => setBroken(new Set()), [data]);

  const groups = useMemo(() => buildRdpGroups(data.rows, filter), [data.rows, filter]);
  const accountLabel = (row: Row) => resolveAccountDisplay(row.account_sid || row.account || "", accountDirectory) || row.account || row.account_sid || "";
  const accountOptions = useMemo(() => {
    const byKey = new Map<string, { label: string; count: number }>();
    for (const row of data.rows) {
      const key = accountKeyOf(row);
      const entry = byKey.get(key) ?? { label: key ? resolveAccountDisplay(key, accountDirectory) || row.account || key : "(계정 없음)", count: 0 };
      entry.count += 1;
      byKey.set(key, entry);
    }
    return [...byKey.entries()].map(([value, entry]) => ({ value, label: entry.label, count: entry.count }));
  }, [data.rows, accountDirectory]);
  const statusOptions = useMemo(() => {
    const tally = new Map<string, number>();
    for (const row of data.rows) tally.set(row.status ?? "", (tally.get(row.status ?? "") ?? 0) + 1);
    return [...tally.entries()].map(([value, count]) => ({ value, label: RDP_STATUS_LABELS[value] ?? (value || "(없음)"), count }));
  }, [data.rows]);
  const fragmentCount = groups.reduce((sum, group) => sum + group.fragments.length, 0);
  const errorCount = groups.reduce((sum, group) => sum + group.errors.length, 0);
  const markBroken = (recordId: string) => setBroken((previous) => (previous.has(recordId) ? previous : new Set(previous).add(recordId)));

  return (
    <div style={{ flex: 1, minHeight: 0, minWidth: 0, display: "flex", flexDirection: "column" }}>
      <ViewHeader icon={PhotoLibraryOutlinedIcon} title="RDP 비트맵 캐시" meta={`파일 ${groups.length.toLocaleString()} · 복원 조각 ${fragmentCount.toLocaleString()}${errorCount ? ` · 오류 ${errorCount.toLocaleString()}` : ""}`}>
        <HeaderSearchInput value={filter.search} onChange={(search) => update({ search })} placeholder="캐시 파일 · 계정 · SID" ariaLabel="RDP 캐시 검색" width={240} />
        {accountOptions.length > 1 && <MultiSelectDropdown icon={<PersonOutlineIcon sx={{ fontSize: 15 }} />} label="계정" ariaLabel="계정" options={accountOptions} selected={filter.accounts} onChange={(accounts) => update({ accounts })} />}
        {statusOptions.length > 1 && <MultiSelectDropdown icon={<FactCheckOutlinedIcon sx={{ fontSize: 15 }} />} label="상태" ariaLabel="상태" options={statusOptions} selected={filter.statuses} onChange={(statuses) => update({ statuses })} />}
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "14px 16px 24px" }}>
        {groups.length === 0 && <div role="status" style={{ color: "var(--text-faint)", textAlign: "center", padding: 44, fontSize: 13 }}>{data.rows.length === 0 ? "기록 없음" : "일치하는 기록 없음"}</div>}
        {groups.map((group) => (
          <section key={group.key} aria-label={group.source} style={{ marginBottom: 26 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, paddingBottom: 6, borderBottom: "1px solid var(--border-subtle)", flexWrap: "wrap" }}>
              {(group.account || group.accountSid) && (
                <span title={group.accountSid || undefined} style={{ display: "inline-flex", alignItems: "center", gap: 3, fontSize: 11.5, fontWeight: 700, color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius)", padding: "1px 8px" }}>
                  <PersonOutlineIcon aria-hidden="true" sx={{ fontSize: 14 }} /> {accountLabel({ account: group.account, account_sid: group.accountSid })}
                </span>
              )}
              <span style={{ fontSize: 14, fontWeight: 700, fontFamily: "var(--mono)" }}>{group.source}</span>
              <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>복원 {group.fragments.length.toLocaleString()}</span>
              {group.errors.length > 0 && <span style={{ fontSize: 11.5, fontWeight: 700, color: "var(--danger)" }}>오류 {group.errors.length.toLocaleString()}</span>}
            </div>

            {group.fragments.length > 0 && (
              <Gallery items={group.fragments} resetKey={`${group.key}|${filter.search}|${filter.accounts.join()}|${filter.statuses.join()}`} render={(row) => {
                const label = `${group.source} · 복원 조각 ${row.fragment_index}`;
                const failed = broken.has(row.record_id);
                return (
                  <div key={row.record_id} style={{ position: "relative", display: "flex", flexDirection: "column", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--bg-panel)", overflow: "hidden" }}>
                    <button type="button" onClick={() => (failed ? setSelected(row) : setZoom({ row, label }))} aria-label={`${label} ${failed ? "상세" : "확대"}`}
                      style={{ height: 170, display: "flex", alignItems: "center", justifyContent: "center", padding: 6, border: "none", background: "var(--bg)", cursor: failed ? "pointer" : "zoom-in" }}>
                      {failed
                        ? <span style={{ display: "grid", justifyItems: "center", gap: 4, color: "var(--danger)", fontSize: 12 }}><BrokenImageOutlinedIcon sx={{ fontSize: 28 }} />이미지 디코딩 실패</span>
                        : <img src={src(row.image)} alt={label} onError={() => markBroken(row.record_id)} style={{ maxWidth: "100%", maxHeight: "100%", imageRendering: "pixelated" }} />}
                    </button>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 6px 5px 10px", borderTop: "1px solid var(--border-subtle)", fontSize: 11.5, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
                      <span style={{ fontWeight: 700, color: "var(--text)" }}>#{row.fragment_index}</span>
                      <span>타일 {row.tile_count}</span>
                      {row.width && row.height && <span style={{ color: "var(--text-faint)" }}>{row.width}×{row.height}</span>}
                      <button type="button" onClick={() => setSelected(row)} aria-label={`${label} 상세`} title="상세"
                        style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", justifyContent: "center", width: 24, height: 24, padding: 0, border: "none", background: "transparent", color: "var(--text-faint)", cursor: "pointer" }}>
                        <InfoOutlinedIcon sx={{ fontSize: 15 }} />
                      </button>
                    </div>
                  </div>
                );
              }} />
            )}

            {group.errors.length > 0 && (
              <div role="list" aria-label={`${group.source} 오류`} style={{ marginTop: 10, border: "1px solid color-mix(in srgb, var(--danger) 40%, var(--border))", borderRadius: "var(--radius)", overflow: "hidden" }}>
                {group.errors.map((row, index) => (
                  <button key={row.record_id} role="listitem" type="button" onClick={() => setSelected(row)}
                    onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "7px 12px", border: "none", borderTop: index === 0 ? "none" : "1px solid var(--border-subtle)", background: "transparent", color: "var(--text)", cursor: "pointer", textAlign: "left", fontSize: 12.5 }}>
                    <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 750, color: "var(--danger)", padding: "1px 8px", borderRadius: "var(--radius)", background: "color-mix(in srgb, var(--danger) 14%, transparent)" }}>{RDP_STATUS_LABELS[row.status] ?? (row.status || "이미지 없음")}</span>
                    {row.tile_index && <span style={{ flexShrink: 0, fontFamily: "var(--mono)", color: "var(--text-dim)" }}>타일 {row.tile_index}</span>}
                    {row.fragment_index && <span style={{ flexShrink: 0, fontFamily: "var(--mono)", color: "var(--text-dim)" }}>조각 {row.fragment_index}</span>}
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)" }}>{row.error}</span>
                  </button>
                ))}
              </div>
            )}
          </section>
        ))}
      </main>

      {zoom && (
        <div onClick={() => setZoom(null)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 1000, display: "flex", flexDirection: "column", alignItems: "center", padding: 24, overflow: "auto", cursor: "zoom-out" }}>
          <div ref={zoomDialogRef} onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby={zoomTitleId} tabIndex={-1}
            style={{ margin: "auto", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 0, maxWidth: "100%", cursor: "default" }}>
            <div style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, color: "#fff", fontSize: 13, marginBottom: 10, flexShrink: 0 }}>
              <span id={zoomTitleId} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{zoom.label}</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "rgba(255,255,255,.7)" }}>타일 {zoom.row.tile_count} · {zoom.row.cols}×{zoom.row.rows} · {zoom.row.width}×{zoom.row.height}</span>
              <button type="button" onClick={() => { setSelected(zoom.row); setZoom(null); }} aria-label="상세" title="상세" style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, padding: 0, border: "1px solid rgba(255,255,255,.24)", borderRadius: "var(--radius)", background: "rgba(0,0,0,.28)", color: "#fff", cursor: "pointer" }}><InfoOutlinedIcon sx={{ fontSize: 17 }} /></button>
              <button type="button" onClick={() => setZoom(null)} data-dialog-autofocus aria-label="확대 이미지 닫기" title="닫기 (Esc)" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, padding: 0, border: "1px solid rgba(255,255,255,.24)", borderRadius: "var(--radius)", background: "rgba(0,0,0,.28)", color: "#fff", cursor: "pointer" }}><CloseOutlinedIcon sx={{ fontSize: 18 }} /></button>
            </div>
            <img src={src(zoom.row.image)} alt={zoom.label}
              onError={() => { markBroken(zoom.row.record_id); setZoom(null); }}
              onLoad={(event) => {
                const image = event.currentTarget;
                const fitWidth = window.innerWidth * 0.88 / image.naturalWidth;
                const fitHeight = window.innerHeight * 0.78 / image.naturalHeight;
                image.style.width = `${Math.round(image.naturalWidth * Math.max(1, Math.min(2.5, fitWidth, fitHeight)))}px`;
              }}
              style={{ imageRendering: "pixelated", maxWidth: "none" }} />
          </div>
        </div>
      )}

      {selected && (
        <RowDetailPanel row={selected} columns={data.columns} focusedColumn={null} fileBaseName={fileName} hostDir={hostDir}
          onClose={() => setSelected(null)}
          onNavigate={(targetFile, targetColumn, value) => { setSelected(null); onNavigate(targetFile, targetColumn, value); }}
          onFetchLinkedRows={onFetchLinkedRows} accountDirectory={accountDirectory} />
      )}
    </div>
  );
}

/** Per-file grid with its own paging; returns to page 1 when the filter changes. */
function Gallery({ items, render, resetKey }: { items: Row[]; render: (row: Row) => React.ReactNode; resetKey: string }) {
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [resetKey]);
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const start = safePage * PAGE_SIZE;
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 8 }}>
        {items.slice(start, start + PAGE_SIZE).map(render)}
      </div>
      {pageCount > 1 && (
        <div style={{ display: "flex", justifyContent: "center", marginTop: 10 }}>
          <PaginationControls ariaLabel="복원 조각 페이지" page={safePage} pageCount={pageCount} onChange={setPage}
            summary={`(${(start + 1).toLocaleString()}–${Math.min(items.length, start + PAGE_SIZE).toLocaleString()} / ${items.length.toLocaleString()})`} />
        </div>
      )}
    </div>
  );
}
