"use client";

import { useMemo } from "react";
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
  { key: "공유 폴더", icon: "📁" },
  { key: "SQL 인증", icon: "🗄️" },
  { key: "자동 실행", icon: "🚀" },
];

export default function RegistryFindingsView({ data }: Props) {
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

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(420px, 1fr))", gap: 16, alignItems: "start" }}>
        {groups.map(({ cat, icon, rows }) => {
          const worst = rows.some((r) => r.status === "의심") ? "var(--danger)" : rows.some((r) => r.status === "주의") ? "var(--warning)" : "var(--border)";
          return (
            <section key={cat} style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${worst}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{icon} {cat}</span>
                <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{rows.length}</span>
              </div>
              <div style={{ padding: "6px 14px 12px" }}>
                {rows.map((r, i) => (
                  <div key={i} style={{ padding: "8px 0", borderBottom: i < rows.length - 1 ? "1px solid var(--border-subtle)" : "none" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", wordBreak: "break-all" }}>{r.name}</span>
                      <Pill text={r.status} color={statusColor(r.status)} />
                      {r.user && r.user !== "(시스템)" && <span style={{ fontSize: 10.5, color: "var(--text-faint)" }}>👤 {r.user}</span>}
                    </div>
                    {r.value && (
                      <div style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)", marginTop: 2, wordBreak: "break-all" }}>{r.value}</div>
                    )}
                    {r.detail && r.detail !== "Run" && r.detail !== "RunOnce" && r.detail !== "Policy Run" && (
                      <div style={{ fontSize: 11, color: statusColor(r.status), marginTop: 2 }}>{r.detail}</div>
                    )}
                    {r.detail && (r.detail === "Run" || r.detail === "RunOnce" || r.detail === "Policy Run") && (
                      <div style={{ fontSize: 10.5, color: "var(--text-faint)", marginTop: 2 }}>{r.detail}</div>
                    )}
                    {r.key_path && (
                      <div style={{ fontSize: 10, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 2, wordBreak: "break-all" }} title={r.key_path}>
                        {r.source} · {r.key_path}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          );
        })}
      </div>
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
