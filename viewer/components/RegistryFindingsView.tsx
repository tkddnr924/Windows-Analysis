"use client";

import { useMemo, useState } from "react";
import { tagsForPath } from "@/lib/tagging";
import type { CsvData } from "@/lib/types";

type Row = Record<string, string>;

interface Props {
  data: CsvData;
}

// status → color. 의심(danger) / 주의(warning) / 정보·정상(neutral/ok)
function statusColor(status: string): string {
  if (status === "의심") return "var(--danger)";
  if (status === "주의") return "var(--warning)";
  if (status === "정상") return "var(--success)";
  return "var(--text-faint)";
}

// Category display order + icon (unknown categories fall through, appended).
const CATEGORY_META: { key: string; icon: string }[] = [
  { key: "자격 증명 보호", icon: "🔑" },
  { key: "공유 폴더", icon: "📁" },
  { key: "SQL 인증", icon: "🗄️" },
  { key: "자동 실행", icon: "🚀" },
  { key: "기타 레지스트리", icon: "🧩" },
];

// Categories that split into sub-tabs, and the row field each tabs on:
// autoruns by the account (user) they belong to, 기타 레지스트리 by finding
// type (RunMRU / TypedPaths / ShimCache).
const TAB_FIELD: Record<string, string> = { "자동 실행": "user", "기타 레지스트리": "subtype" };

// A value that reads as a filesystem/UNC path (share folders, typed paths).
function looksLikePath(v: string): boolean {
  return /^[a-zA-Z]:\\|^\\\\/.test(v);
}

export default function RegistryFindingsView({ data }: Props) {
  const [detail, setDetail] = useState<Row | null>(null);
  const { groups, warnCount, dangerCount } = useMemo(() => {
    const rows = data.rows;
    // autoruns get a suspicious re-classification from the command path so the
    // view flags them even though the parser leaves them as neutral "정보".
    const enriched = rows.map((r) => {
      if (r.category === "자동 실행" && tagsForPath(r.command || r.value).length > 0) {
        return { ...r, status: "의심" };
      }
      return r;
    });
    const byCat = new Map<string, Row[]>();
    for (const r of enriched) {
      const c = r.category || "기타";
      if (!byCat.has(c)) byCat.set(c, []);
      byCat.get(c)!.push(r);
    }
    const ordered: { cat: string; icon: string; rows: Row[] }[] = [];
    for (const { key, icon } of CATEGORY_META) {
      if (byCat.has(key)) {
        ordered.push({ cat: key, icon, rows: byCat.get(key)! });
        byCat.delete(key);
      }
    }
    for (const [cat, rows2] of byCat) ordered.push({ cat, icon: "🔧", rows: rows2 });

    const warnCount = enriched.filter((r) => r.status === "주의").length;
    const dangerCount = enriched.filter((r) => r.status === "의심").length;
    return { groups: ordered, warnCount, dangerCount };
  }, [data.rows]);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 2 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🔎 레지스트리 특이사항</span>
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 18 }}>레지스트리에서 점검 가치가 있는 설정을 추려 보여줍니다.</div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
        <Tile label="의심" value={dangerCount} tone={dangerCount ? "danger" : "ok"} />
        <Tile label="주의" value={warnCount} tone={warnCount ? "warning" : "ok"} />
        <Tile label="전체 항목" value={data.rows.length} tone="neutral" />
      </div>

      {data.rows.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13 }}>레지스트리 특이사항이 없습니다.</div>}

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {groups.map(({ cat, icon, rows }) => (
          <FindingSection key={cat} cat={cat} icon={icon} rows={rows} tabField={TAB_FIELD[cat]} onSelect={setDetail} />
        ))}
      </div>

      {detail && <RfDetailModal row={detail} onClose={() => setDetail(null)} />}
    </div>
  );
}

// One category card. When `tabField` is set (자동 실행 → user, 기타 레지스트리 →
// subtype) it shows a tab bar and filters its rows to the active tab.
function FindingSection({ cat, icon, rows, tabField, onSelect }: { cat: string; icon: string; rows: Row[]; tabField?: string; onSelect: (r: Row) => void }) {
  const tabs = useMemo(() => {
    if (!tabField) return [];
    const seen: string[] = [];
    for (const r of rows) {
      const v = r[tabField] || "(기타)";
      if (!seen.includes(v)) seen.push(v);
    }
    return seen;
  }, [rows, tabField]);
  const [tab, setTab] = useState<string>("전체");
  const shown = tabField && tab !== "전체" ? rows.filter((r) => (r[tabField] || "(기타)") === tab) : rows;

  const worst = rows.some((r) => r.status === "의심") ? "var(--danger)" : rows.some((r) => r.status === "주의") ? "var(--warning)" : "var(--border)";
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${worst}` }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{icon} {cat}</span>
        <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{rows.length}</span>
      </div>

      {tabField && tabs.length > 1 && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", padding: "8px 14px 0" }}>
          {["전체", ...tabs].map((t) => {
            const active = tab === t;
            const count = t === "전체" ? rows.length : rows.filter((r) => (r[tabField] || "(기타)") === t).length;
            const label = tabField === "user" && t !== "전체" ? (t === "(시스템)" ? t : `👤 ${t}`) : t;
            return (
              <button
                key={t}
                onClick={() => setTab(t)}
                style={{ fontSize: 11.5, padding: "3px 10px", borderRadius: 999, cursor: "pointer", whiteSpace: "nowrap",
                  background: active ? "var(--accent-subtle)" : "transparent",
                  color: active ? "var(--accent)" : "var(--text-dim)",
                  border: `1px solid ${active ? "var(--accent)" : "var(--border)"}` }}
              >
                {label} <span style={{ color: "var(--text-faint)" }}>{count.toLocaleString()}</span>
              </button>
            );
          })}
        </div>
      )}

      <div style={{ padding: "6px 14px 12px" }}>
        {shown.map((r, i) => (
          <div
            key={i}
            onClick={() => onSelect(r)}
            onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            style={{ padding: "8px 8px", margin: "0 -8px", borderRadius: "var(--radius-sm)", borderBottom: i < shown.length - 1 ? "1px solid var(--border-subtle)" : "none", cursor: "pointer" }}
            title="클릭하면 레지스트리 키·값 상세 보기"
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", wordBreak: "break-all" }}>{r.name}</span>
              <Pill text={r.status} color={statusColor(r.status)} />
              {r.subtype && <span style={{ fontSize: 10, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: 4, padding: "0 5px" }}>{r.subtype}</span>}
              {(r.detail === "Run" || r.detail === "RunOnce" || r.detail === "Policy Run") && (
                <span style={{ fontSize: 10, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: 4, padding: "0 5px" }}>{r.detail}</span>
              )}
              {r.user && r.user !== "(시스템)" && <span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>👤 {r.user}</span>}
            </div>
            {r.value && (
              <div style={{ fontSize: looksLikePath(r.value) ? 12.5 : 12, fontWeight: looksLikePath(r.value) ? 600 : 400, color: looksLikePath(r.value) ? "var(--accent)" : "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 3, wordBreak: "break-all" }}>
                {looksLikePath(r.value) ? "📂 " : ""}{r.value}
              </div>
            )}
            {r.detail && !["Run", "RunOnce", "Policy Run"].includes(r.detail) && r.subtype === "ShimCache" && (
              <div style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 3 }}>{r.detail}</div>
            )}
            {r.key_path && (
              <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 3, wordBreak: "break-all" }} title={r.key_path}>
                🔑 {r.key_path}{r.source ? `  ·  ${r.source}` : ""}
              </div>
            )}
            {r.timestamp && (
              <div style={{ fontSize: 10.5, color: "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 2 }}>🕑 {r.timestamp}</div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

function RfDetailModal({ row, onClose }: { row: Row; onClose: () => void }) {
  const kind = row.detail === "Run" || row.detail === "RunOnce" || row.detail === "Policy Run" ? row.detail : "";
  // Secondary fields. No explanation line — just what the registry actually holds.
  const meta: [string, string][] = [
    ["분류", row.category],
    ["항목(값 이름)", row.name],
    ["자동실행 위치", kind],
    ["사용자", row.user && row.user !== "(시스템)" ? row.user : ""],
  ];
  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.6)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: 660, maxWidth: "100%", maxHeight: "82vh", overflow: "auto", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-panel)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: "1px solid var(--border)", borderLeft: `3px solid ${statusColor(row.status)}` }}>
          <span style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>{row.name}</span>
          <Pill text={row.status} color={statusColor(row.status)} />
          <button onClick={onClose} style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-faint)", fontSize: 18, cursor: "pointer" }}>×</button>
        </div>
        <div style={{ padding: "14px 18px 18px" }}>
          {row.timestamp && (
            <div style={{ fontSize: 13, color: "var(--text)", fontFamily: "var(--mono)", fontWeight: 600, marginBottom: 12 }}>
              🕑 {row.timestamp} <span style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--sans)", fontWeight: 400 }}>(키 마지막 수정)</span>
            </div>
          )}
          {/* The raw registry key + value. */}
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", marginBottom: 6 }}>🔑 레지스트리 키 · 값</div>
          <div style={{ background: "var(--bg)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", padding: "12px 14px", marginBottom: 16, fontFamily: "var(--mono)" }}>
            <EvRow label="키 경로" value={row.key_path} />
            <EvRow label="값 이름" value={row.name} />
            <EvRow label="값" value={row.value} highlight />
            {row.command && <EvRow label="명령" value={row.command} highlight />}
            <EvRow label="하이브" value={row.source} last />
          </div>
          {meta.filter(([, v]) => v).map(([k, v]) => (
            <div key={k} style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ flex: "0 0 108px", color: "var(--text-faint)", fontSize: 12 }}>{k}</span>
              <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EvRow({ label, value, highlight, last }: { label: string; value: string; highlight?: boolean; last?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: last ? "none" : "1px solid var(--border-subtle)", alignItems: "baseline" }}>
      <span style={{ flex: "0 0 70px", color: "var(--text-faint)", fontSize: 11, fontFamily: "var(--sans)" }}>{label}</span>
      <span style={{ flex: 1, color: highlight ? "var(--accent)" : "var(--text)", fontSize: 13, fontWeight: highlight ? 700 : 500, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>{value || "—"}</span>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: number; tone: "ok" | "warning" | "danger" | "neutral" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : tone === "ok" ? "var(--success)" : "var(--accent)";
  return (
    <div style={{ minWidth: 110, padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderLeft: `3px solid ${color}`, borderRadius: "var(--radius-md)" }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 800, color }}>{value.toLocaleString()}</div>
    </div>
  );
}

function Pill({ text, color }: { text: string; color: string }) {
  return <span style={{ fontSize: 10.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: 4, padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>;
}
