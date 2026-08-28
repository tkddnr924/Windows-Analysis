"use client";
import CategoryOutlinedIcon from "@mui/icons-material/CategoryOutlined";

import { useMemo, useState } from "react";
import type { CsvData } from "@/lib/types";
import { EMPTY_TIME_RANGE, inRange, rangeActive, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import PaginationControls from "@/components/PaginationControls";
import { HeaderSearchInput, SelectDropdown, SortDropdown, ViewHeader } from "@/components/FilterControls";
import ReportProblemOutlinedIcon from "@mui/icons-material/ReportProblemOutlined";
import SearchIcon from "@mui/icons-material/Search";
import SortOutlinedIcon from "@mui/icons-material/SortOutlined";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import ExtensionOutlinedIcon from "@mui/icons-material/ExtensionOutlined";
import ScienceOutlinedIcon from "@mui/icons-material/ScienceOutlined";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";

// Windows Error Reporting (Report.wer) detail view. The parser stores every
// report field in one `report` JSON column (+ a few promoted scalars); this
// view parses that JSON back out and lays it into meaningful sections —
// fault signature, loaded modules, OS info — instead of a raw blob.

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
  timeRange?: TimeRange;
}

type Parsed = {
  row: Row;
  rowid: number;
  report: Record<string, unknown>;
  appName: string;
  appPath: string;
  eventType: string;
  friendly: string;
  timestamp: string;
};

function safeParse(s: string): Record<string, unknown> {
  try {
    const o = JSON.parse(s || "{}");
    return o && typeof o === "object" && !Array.isArray(o) ? (o as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
function basename(p: string): string {
  return p ? p.replace(/\//g, "\\").split("\\").filter(Boolean).pop() || p : "";
}
// AppName/AppPath 키가 없는 보고서(업데이트 실패·진단·스토어 앱 등)는
// Sig 배열의 "Application Name" 항목이나 TargetAppId 끝 조각에서 이름을 찾는다.
function sigAppName(report: Record<string, unknown>): string {
  if (!Array.isArray(report.Sig)) return "";
  let fallback = "";
  for (const item of report.Sig) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const name = str(o.Name);
    const value = str(o.Value);
    if (!value) continue;
    if (/application\s*name|응용\s*프로그램\s*이름/i.test(name)) return basename(value);
    if (!fallback && /\.(exe|dll|sys)$/i.test(value)) fallback = basename(value);
  }
  return fallback;
}
function targetAppIdName(targetAppId: string): string {
  const tail = targetAppId.split("!").filter(Boolean).pop() || "";
  return /[\\/.]/.test(tail) ? basename(tail) : "";
}
function str(v: unknown): string {
  return v === undefined || v === null ? "" : String(v);
}
// EventType → tone. Crashes/exceptions are danger, hangs are warning.
function typeTone(t: string): string {
  if (/HANG/i.test(t)) return "var(--warning)";
  if (/CRASH|BEX|FATAL|Exception|CLR/i.test(t)) return "var(--danger)";
  return "var(--accent)";
}

export default function WerView({ data, bookmarkedRowids, onToggleBookmark, timeRange = EMPTY_TIME_RANGE }: Props) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("전체");
  const [detail, setDetail] = useState<Parsed | null>(null);
  const [page, setPage] = useState(0);
  // 시간순 정렬 — 기본은 오래된 순(오름차순).
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const parsed = useMemo<Parsed[]>(
    () =>
      data.rows.map((row) => {
        const report = safeParse(row.report);
        const appPath = row.AppPath || str(report.AppPath);
        return {
          row,
          rowid: Number((row as unknown as Record<string, unknown>).__rowid),
          report,
          appName:
            row.AppName ||
            str(report.AppName) ||
            basename(appPath) ||
            sigAppName(report) ||
            targetAppIdName(str(report.TargetAppId) || row.TargetAppId || "") ||
            str(report.OriginalFilename),
          appPath,
          eventType: row.EventType || str(report.EventType),
          friendly: str(report.FriendlyEventName),
          timestamp: row.timestamp || "",
        };
      }),
    [data.rows],
  );

  const types = useMemo(() => {
    const seen: string[] = [];
    for (const p of parsed) if (p.eventType && !seen.includes(p.eventType)) seen.push(p.eventType);
    return seen.sort();
  }, [parsed]);

  const rangeOn = rangeActive(timeRange);
  // 전역 기간 필터 — 건수 표기·유형 칩·목록 모두 이 범위 안에서 센다.
  const ranged = useMemo(
    () => (rangeOn ? parsed.filter((p) => inRange(p.timestamp, timeRange)) : parsed),
    [parsed, rangeOn, timeRange],
  );
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = ranged.filter((p) => {
      if (typeFilter !== "전체" && p.eventType !== typeFilter) return false;
      if (q && ![p.appName, p.appPath, p.eventType, p.friendly, str(p.report.ReportIdentifier)].some((v) => v.toLowerCase().includes(q)))
        return false;
      return true;
    });
    // timestamp 형식(YYYY-MM-DD HH:mm:ss.mmm)은 문자열 비교가 곧 시간 비교.
    // 시각 없는 보고서는 정렬 방향과 무관하게 뒤로 보낸다.
    return filtered.sort((a, b) => {
      if (!a.timestamp || !b.timestamp) return a.timestamp ? -1 : b.timestamp ? 1 : 0;
      const c = a.timestamp.localeCompare(b.timestamp);
      return sortDir === "asc" ? c : -c;
    });
  }, [ranged, search, typeFilter, sortDir]);

  const PAGE = 10;
  const pageCount = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = shown.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div className="dfir-view" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: "var(--bg)", overflow: "hidden" }}>
      <ViewHeader icon={ReportProblemOutlinedIcon} title="Windows 오류 보고 (WER)" meta={`${ranged.length.toLocaleString()}건`} right={<span style={{ color: "var(--text-faint)", fontSize: 11.5 }}>{rangeOn ? "전역 기간 필터 적용" : "전체 기간"}</span>}>
          <HeaderSearchInput value={search} onChange={(value) => { setSearch(value); setPage(0); }} placeholder="앱 이름 · 경로 · 이벤트 유형 검색" width={300} />
          <SortDropdown value={sortDir} onChange={(next) => { setSortDir(next as "asc" | "desc"); setPage(0); }} />
          {types.length > 1 && (
            <SelectDropdown
              icon={<CategoryOutlinedIcon sx={{ fontSize: 15 }} />}
              label="유형"
              options={["전체", ...types].map((t) => ({ value: t, label: t, count: t === "전체" ? ranged.length : ranged.filter((p) => p.eventType === t).length }))}
              value={typeFilter}
              onChange={(next) => { setTypeFilter(next); setPage(0); }}
            />
          )}
        
      </ViewHeader>

      <main style={{ flex: 1, minHeight: 0, overflow: "auto", padding: 14 }}>
        {parsed.length === 0 && <div style={{ padding: 30, textAlign: "center", color: "var(--text-faint)", fontSize: 13 }}>WER 보고서가 없습니다.</div>}
        {pageRows.map((p, i) => {
          const bm = (bookmarkedRowids?.has(p.rowid) ?? false) && Number.isFinite(p.rowid);
          const tone = typeTone(p.eventType);
          return (
            <div
              key={i}
              className={bm ? "dfir-bookmarked-row" : undefined}
              onClick={() => setDetail(p)}
              onMouseEnter={(e) => { if (!bm) e.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(e) => { if (!bm) e.currentTarget.style.background = "var(--bg-panel)"; }}
              style={{ borderRadius: "var(--radius-md)", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", cursor: "pointer", transition: "background .15s ease, border-color .15s ease" }}
              title="클릭하면 WER 상세 보기"
            >
              <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tone} 15%, transparent)` }}>
                <ReportProblemOutlinedIcon sx={{ fontSize: 17, color: tone }} />
              </span>
              <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                  <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: "var(--text)" }}>{p.appName || p.friendly || p.eventType || "(이름 없음)"}</span>
                  <Pill text={p.eventType || "?"} color={tone} />
                  {p.friendly && <span style={{ flexShrink: 0, fontSize: 12, color: "var(--text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 260 }}>{p.friendly}</span>}
                </span>
                <span title={p.appPath || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: p.appPath ? "var(--text-dim)" : "var(--text-faint)", fontFamily: "var(--mono)" }}>{p.appPath || "경로 정보 없음"}</span>
              </span>
              <span style={{ flexShrink: 0, width: 172, textAlign: "right", fontSize: 12.5, color: p.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{p.timestamp || "시간 정보 없음"}</span>
            </div>
          );
        })}
      </main>

      {shown.length > 0 && (
        <div style={{ flexShrink: 0, display: "flex", justifyContent: "center", padding: "6px 0 10px", borderTop: "1px solid var(--border-subtle)" }}>
          <PaginationControls ariaLabel="WER 페이지" page={safePage} pageCount={pageCount} onChange={setPage} summary={`(${(safePage * PAGE + 1).toLocaleString()}–${Math.min((safePage + 1) * PAGE, shown.length).toLocaleString()} / ${shown.length.toLocaleString()})`} />
        </div>
      )}

      {detail && (
        <RowDetailPanel
          row={detail.row}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName="WER_Reports"
          onClose={() => setDetail(null)}
          onNavigate={() => {}}
          isBookmarked={onToggleBookmark ? (bookmarkedRowids?.has(detail.rowid) ?? false) : undefined}
          onToggleBookmark={onToggleBookmark && Number.isFinite(detail.rowid) ? () => onToggleBookmark(detail.rowid) : undefined}
        />
      )}
    </div>
  );
}


// --- detail ---

function asPairs(v: unknown): { k: string; val: string }[] {
  // Sig/DynamicSig hold [{Name,Value}]; State/OsInfo hold [{Key,Value}].
  if (!Array.isArray(v)) return [];
  return v.map((item, i) => {
    if (item && typeof item === "object") {
      const o = item as Record<string, unknown>;
      const k = str(o.Name ?? o.Key) || `#${i}`;
      return { k, val: str(o.Value) };
    }
    return { k: `#${i}`, val: str(item) };
  });
}
function asList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(str) : [];
}

function WerDetailModal({ p, onClose, isBookmarked, onToggleBookmark }: { p: Parsed; onClose: () => void; isBookmarked?: boolean; onToggleBookmark?: () => void }) {
  const [showRaw, setShowRaw] = useState(false);
  const [showModules, setShowModules] = useState(false);
  const [showOs, setShowOs] = useState(false);
  const d = p.report;
  const tone = typeTone(p.eventType);

  const sig = asPairs(d.Sig);
  const dynSig = asPairs(d.DynamicSig);
  const state = asPairs(d.State);
  const osInfo = asPairs(d.OsInfo);
  const modules = asList(d.LoadedModule);

  const summary: [string, string][] = [
    ["프로그램", p.appPath || p.appName],
    ["원본 파일명", str(d.OriginalFilename)],
    ["이벤트 유형", [p.eventType, p.friendly].filter(Boolean).join(" · ")],
    ["치명적 오류", str(d.IsFatal) === "1" ? "예" : str(d.IsFatal) === "0" ? "아니오" : ""],
    ["버킷 ID", str(d["Response.BucketId"])],
  ];
  const reportMeta: [string, string][] = [
    ["보고서 ID", str(d.ReportIdentifier)],
    ["대상 앱 버전", str(d.TargetAppVer)],
    ["대상 앱 ID", str(d.TargetAppId) || p.row.TargetAppId || ""],
    ["동의(Consent)", str(d.Consent)],
    ["보고서 상태", str(d.ReportStatus)],
  ];

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 720, maxWidth: "100%", maxHeight: "86vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--border)", borderLeft: `3px solid ${tone}`, position: "sticky", top: 0, background: "var(--bg-panel)", zIndex: 1 }}>
          <span className="dfir-section-label">증거 상세</span>
          <span style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>{p.appName || p.friendly || p.eventType || "(이름 없음)"}</span>
          <Pill text={p.eventType || "?"} color={tone} />
          {onToggleBookmark && (
            <button
              className={isBookmarked ? "dfir-bookmark-control" : undefined}
              onClick={onToggleBookmark}
              title={isBookmarked ? "북마크 해제" : "북마크에 추가"}
              style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5, padding: "4px 10px", background: isBookmarked ? "var(--bookmark-row)" : "transparent", color: isBookmarked ? "var(--bookmark-control)" : "var(--text-dim)", border: `1px solid ${isBookmarked ? "var(--bookmark-outline)" : "var(--border)"}`, borderRadius: "var(--radius-lg)", cursor: "pointer", fontWeight: 600 }}
            >
              {isBookmarked ? "북마크됨" : "북마크"}
            </button>
          )}
          <button onClick={onClose} style={{ marginLeft: onToggleBookmark ? 8 : "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ padding: "14px 18px 18px" }}>
          {p.timestamp && (
            <div style={{ fontSize: 13, color: "var(--text)", fontFamily: "var(--mono)", fontWeight: 600, marginBottom: 12 }}><span className="dfir-tag dfir-tag--info">기준 시간</span> {p.timestamp}</div>
          )}

          <MetaRows rows={summary} />

          {sig.length > 0 && <KVSection heading={<><ExtensionOutlinedIcon sx={{ fontSize: 14 }} /> 오류 시그니처 (Sig)</>} pairs={sig} highlight />}
          {dynSig.length > 0 && <KVSection heading={<><ScienceOutlinedIcon sx={{ fontSize: 14 }} /> 동적 시그니처 (DynamicSig)</>} pairs={dynSig} />}

          <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "16px 0 6px" }}><DescriptionOutlinedIcon sx={{ fontSize: 14 }} /> 보고서 정보</div>
          <MetaRows rows={reportMeta} />

          {modules.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <button onClick={() => setShowModules((v) => !v)} style={collapseBtn}>
                {showModules ? "▾" : "▸"} 로드된 모듈 <span style={{ color: "var(--text-faint)" }}>({modules.length})</span>
              </button>
              {showModules && (
                <div style={{ marginTop: 6, maxHeight: 260, overflow: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg)" }}>
                  {modules.map((m, i) => (
                    <div key={i} style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-dim)", padding: "3px 10px", borderBottom: i < modules.length - 1 ? "1px solid var(--border-subtle)" : "none", wordBreak: "break-all" }}>{m}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          {(osInfo.length > 0 || state.length > 0) && (
            <div style={{ marginTop: 12 }}>
              <button onClick={() => setShowOs((v) => !v)} style={collapseBtn}>
                {showOs ? "▾" : "▸"} OS 정보 · 상태 <span style={{ color: "var(--text-faint)" }}>({osInfo.length + state.length})</span>
              </button>
              {showOs && (
                <div style={{ marginTop: 6 }}>
                  {osInfo.length > 0 && <KVSection heading="OsInfo" pairs={osInfo} compact />}
                  {state.length > 0 && <KVSection heading="State" pairs={state} compact />}
                </div>
              )}
            </div>
          )}

          <div style={{ marginTop: 12 }}>
            <button onClick={() => setShowRaw((v) => !v)} style={collapseBtn}>
              {showRaw ? "▾" : "▸"} 원본 전체 (JSON)
            </button>
            {showRaw && (
              <pre style={{ marginTop: 6, maxHeight: 340, overflow: "auto", fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-dim)", background: "var(--bg)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "10px 12px", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {JSON.stringify(d, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetaRows({ rows }: { rows: [string, string][] }) {
  const shown = rows.filter(([, v]) => v);
  return (
    <>
      {shown.map(([k, v]) => (
        <div key={k} style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
          <span style={{ flex: "0 0 108px", color: "var(--text-faint)", fontSize: 12 }}>{k}</span>
          <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: /경로|프로그램|버전|ID|파일/.test(k) ? "var(--mono)" : undefined }}>{v}</span>
        </div>
      ))}
    </>
  );
}

function KVSection({ heading, pairs, highlight, compact }: { heading: React.ReactNode; pairs: { k: string; val: string }[]; highlight?: boolean; compact?: boolean }) {
  return (
    <div style={{ marginTop: compact ? 8 : 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 700, color: "var(--text-faint)", marginBottom: 6 }}>{heading}</div>
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-md)", background: "var(--bg)", overflow: "hidden" }}>
        {pairs.map((p, i) => (
          <div key={i} style={{ display: "flex", gap: 12, padding: "5px 10px", borderTop: i === 0 ? "none" : "1px solid var(--border-subtle)", alignItems: "baseline" }}>
            <span style={{ flex: "0 0 40%", color: "var(--text-faint)", fontSize: 11.5, wordBreak: "break-all" }}>{p.k}</span>
            <span style={{ flex: 1, color: highlight ? "var(--accent)" : "var(--text)", fontSize: 12, fontWeight: highlight ? 600 : 400, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{p.val || "—"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const collapseBtn: React.CSSProperties = { background: "transparent", border: "none", color: "var(--text-dim)", fontSize: 12, fontWeight: 700, cursor: "pointer", padding: "4px 0" };

function Pill({ text, color }: { text: string; color: string }) {
  return <span style={{ fontSize: 11.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: "var(--radius-sm)", padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>;
}
