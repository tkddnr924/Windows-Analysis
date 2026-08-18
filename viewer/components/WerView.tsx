"use client";

import { useMemo, useState } from "react";
import type { CsvData } from "@/lib/types";

// Windows Error Reporting (Report.wer) detail view. The parser stores every
// report field in one `report` JSON column (+ a few promoted scalars); this
// view parses that JSON back out and lays it into meaningful sections —
// fault signature, loaded modules, OS info — instead of a raw blob.

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  bookmarkedRowids?: Set<number>;
  onToggleBookmark?: (rowid: number) => void;
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
function str(v: unknown): string {
  return v === undefined || v === null ? "" : String(v);
}
// EventType → tone. Crashes/exceptions are danger, hangs are warning.
function typeTone(t: string): string {
  if (/HANG/i.test(t)) return "var(--warning)";
  if (/CRASH|BEX|FATAL|Exception|CLR/i.test(t)) return "var(--danger)";
  return "var(--accent)";
}

export default function WerView({ data, bookmarkedRowids, onToggleBookmark }: Props) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("전체");
  const [detail, setDetail] = useState<Parsed | null>(null);
  const [page, setPage] = useState(0);

  const parsed = useMemo<Parsed[]>(
    () =>
      data.rows.map((row) => {
        const report = safeParse(row.report);
        const appPath = row.AppPath || str(report.AppPath);
        return {
          row,
          rowid: Number((row as unknown as Record<string, unknown>).__rowid),
          report,
          appName: row.AppName || str(report.AppName) || basename(appPath),
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

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return parsed.filter((p) => {
      if (typeFilter !== "전체" && p.eventType !== typeFilter) return false;
      if (q && ![p.appName, p.appPath, p.eventType, p.friendly, str(p.report.ReportIdentifier)].some((v) => v.toLowerCase().includes(q)))
        return false;
      return true;
    });
  }, [parsed, search, typeFilter]);

  const PAGE = 50;
  const pageCount = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = shown.slice(safePage * PAGE, (safePage + 1) * PAGE);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 2 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>💥 Windows 오류 보고 (WER)</span>
        <span style={{ fontSize: 12.5, color: "var(--text-faint)" }}>{parsed.length.toLocaleString()}건</span>
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 12 }}>
        앱 크래시·행(APPCRASH/BEX/AppHang 등) 보고서. 클릭하면 오류 시그니처·로드된 모듈 등 상세를 봅니다.
      </div>

      <div style={{ position: "relative", maxWidth: 420, marginBottom: 12 }}>
        <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", fontSize: 12, color: "var(--text-faint)", pointerEvents: "none" }}>🔍</span>
        <input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(0);
          }}
          placeholder="앱 이름 · 경로 · 이벤트 유형 검색"
          style={{ width: "100%", padding: "7px 26px 7px 30px", fontSize: 12.5, fontFamily: "var(--mono)", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--text)", outline: "none" }}
        />
        {search && (
          <span onClick={() => setSearch("")} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", cursor: "pointer", color: "var(--text-faint)", fontSize: 13 }}>
            ✕
          </span>
        )}
      </div>

      {types.length > 1 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
          {["전체", ...types].map((t) => {
            const active = typeFilter === t;
            const count = t === "전체" ? parsed.length : parsed.filter((p) => p.eventType === t).length;
            return (
              <button
                key={t}
                onClick={() => {
                  setTypeFilter(t);
                  setPage(0);
                }}
                style={{ fontSize: 11.5, padding: "3px 10px", borderRadius: 999, cursor: "pointer", whiteSpace: "nowrap", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}` }}
              >
                {t} <span style={{ color: "var(--text-faint)" }}>{count.toLocaleString()}</span>
              </button>
            );
          })}
        </div>
      )}

      {parsed.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13 }}>WER 보고서가 없습니다.</div>}

      <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
        {pageRows.map((p, i) => {
          const bm = (bookmarkedRowids?.has(p.rowid) ?? false) && Number.isFinite(p.rowid);
          return (
            <div
              key={i}
              onClick={() => setDetail(p)}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              style={{ padding: "9px 12px", borderBottom: i < pageRows.length - 1 ? "1px solid var(--border-subtle)" : "none", cursor: "pointer", boxShadow: bm ? "inset 3px 0 0 var(--warning)" : undefined }}
              title="클릭하면 WER 상세 보기"
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)" }}>{p.appName || "(이름 없음)"}</span>
                <Pill text={p.eventType || "?"} color={typeTone(p.eventType)} />
                {p.friendly && <span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>{p.friendly}</span>}
              </div>
              {p.appPath && (
                <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 3, wordBreak: "break-all" }}>{p.appPath}</div>
              )}
              {p.timestamp && <div style={{ fontSize: 10.5, color: "var(--text-time)", fontFamily: "var(--mono)", marginTop: 2 }}>🕑 {p.timestamp}</div>}
            </div>
          );
        })}
      </div>

      {pageCount > 1 && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginTop: 12 }}>
          <button onClick={() => setPage(safePage - 1)} disabled={safePage === 0} style={pgBtn(safePage === 0)}>‹ 이전</button>
          <span style={{ fontSize: 11.5, color: "var(--text-dim)" }}>
            {safePage + 1} / {pageCount}{" "}
            <span style={{ color: "var(--text-faint)" }}>({(safePage * PAGE + 1).toLocaleString()}–{Math.min((safePage + 1) * PAGE, shown.length).toLocaleString()} / {shown.length.toLocaleString()})</span>
          </span>
          <button onClick={() => setPage(safePage + 1)} disabled={safePage >= pageCount - 1} style={pgBtn(safePage >= pageCount - 1)}>다음 ›</button>
        </div>
      )}

      {detail && (
        <WerDetailModal
          p={detail}
          onClose={() => setDetail(null)}
          isBookmarked={onToggleBookmark ? (bookmarkedRowids?.has(detail.rowid) ?? false) : undefined}
          onToggleBookmark={onToggleBookmark && Number.isFinite(detail.rowid) ? () => onToggleBookmark(detail.rowid) : undefined}
        />
      )}
    </div>
  );
}

const pgBtn = (disabled: boolean): React.CSSProperties => ({ fontSize: 11.5, padding: "3px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1 });

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
          <span style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>💥 {p.appName || "(이름 없음)"}</span>
          <Pill text={p.eventType || "?"} color={tone} />
          {onToggleBookmark && (
            <button
              onClick={onToggleBookmark}
              title={isBookmarked ? "북마크 해제" : "북마크에 추가"}
              style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11.5, padding: "4px 10px", background: isBookmarked ? "var(--warning-subtle)" : "transparent", color: isBookmarked ? "var(--warning)" : "var(--text-dim)", border: `1px solid ${isBookmarked ? "var(--warning)" : "var(--border)"}`, borderRadius: "var(--radius-lg)", cursor: "pointer", fontWeight: 600 }}
            >
              {isBookmarked ? "★ 북마크됨" : "☆ 북마크"}
            </button>
          )}
          <button onClick={onClose} style={{ marginLeft: onToggleBookmark ? 8 : "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>

        <div style={{ padding: "14px 18px 18px" }}>
          {p.timestamp && (
            <div style={{ fontSize: 13, color: "var(--text)", fontFamily: "var(--mono)", fontWeight: 600, marginBottom: 12 }}>🕑 {p.timestamp}</div>
          )}

          <MetaRows rows={summary} />

          {sig.length > 0 && <KVSection heading="🧩 오류 시그니처 (Sig)" pairs={sig} highlight />}
          {dynSig.length > 0 && <KVSection heading="🧪 동적 시그니처 (DynamicSig)" pairs={dynSig} />}

          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "16px 0 6px" }}>📄 보고서 정보</div>
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

function KVSection({ heading, pairs, highlight, compact }: { heading: string; pairs: { k: string; val: string }[]; highlight?: boolean; compact?: boolean }) {
  return (
    <div style={{ marginTop: compact ? 8 : 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", marginBottom: 6 }}>{heading}</div>
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
  return <span style={{ fontSize: 10.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: 4, padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>;
}
