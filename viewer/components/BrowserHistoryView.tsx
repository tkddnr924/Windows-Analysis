"use client";

import { useMemo } from "react";
import type { CsvData } from "@/lib/types";

type Row = Record<string, string>;

interface Props {
  data: CsvData;
}

export default function BrowserHistoryView({ data }: Props) {
  const { accounts, visitTotal, downloadTotal } = useMemo(() => {
    const byAcct = new Map<string, { visits: Row[]; downloads: Row[] }>();
    for (const r of data.rows) {
      const a = r.account || "(알 수 없음)";
      if (!byAcct.has(a)) byAcct.set(a, { visits: [], downloads: [] });
      const g = byAcct.get(a)!;
      if (r.kind === "download") g.downloads.push(r);
      else g.visits.push(r);
    }
    const byTime = (a: Row, b: Row) => (b.timestamp || "").localeCompare(a.timestamp || "");
    const accounts = [...byAcct.entries()]
      .map(([account, g]) => ({
        account,
        visits: g.visits.sort(byTime),
        downloads: g.downloads.sort(byTime),
      }))
      .sort((a, b) => b.downloads.length - a.downloads.length || b.visits.length - a.visits.length);
    return {
      accounts,
      visitTotal: data.rows.filter((r) => r.kind !== "download").length,
      downloadTotal: data.rows.filter((r) => r.kind === "download").length,
    };
  }, [data.rows]);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 2 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🌐 브라우저 활동</span>
        <span style={{ fontSize: 13, color: "var(--text-dim)" }}>Chrome 방문 기록 · 다운로드 (계정별)</span>
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 18 }}>URL은 평문으로 디코딩해 표시합니다.</div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
        <Tile label="계정" value={accounts.length} tone="neutral" />
        <Tile label="방문 URL" value={visitTotal} tone="neutral" />
        <Tile label="다운로드" value={downloadTotal} tone={downloadTotal ? "warning" : "ok"} />
      </div>

      {accounts.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13 }}>브라우저 기록이 없습니다.</div>}

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {accounts.map(({ account, visits, downloads }) => (
          <section key={account} style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${downloads.length ? "var(--warning)" : "var(--accent)"}` }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: "var(--text)" }}>👤 {account}</span>
              <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>방문 {visits.length} · 다운로드 {downloads.length}</span>
            </div>
            <div style={{ padding: "6px 14px 12px" }}>
              {downloads.length > 0 && (
                <>
                  <SubHead>⬇ 다운로드</SubHead>
                  {downloads.map((d, i) => (
                    <div key={`d${i}`} style={{ padding: "8px 0", borderBottom: "1px solid var(--border-subtle)" }}>
                      <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", wordBreak: "break-all" }}>{d.title || "(파일명 없음)"}</span>
                        {d.size && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{d.size}</span>}
                        {d.danger && <Pill text={`위험: ${d.danger}`} color="var(--danger)" />}
                        <span style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{d.timestamp}</span>
                      </div>
                      {d.detail && <KV k="저장 경로" v={d.detail} mono />}
                      {d.source_url && <KV k="출처" v={d.source_url} mono link />}
                      {d.mime && <KV k="유형" v={d.mime} />}
                    </div>
                  ))}
                </>
              )}

              {visits.length > 0 && (
                <>
                  <SubHead>🔗 방문 URL</SubHead>
                  {visits.map((v, i) => (
                    <div key={`v${i}`} style={{ display: "flex", gap: 10, padding: "6px 0", borderBottom: i < visits.length - 1 ? "1px solid var(--border-subtle)" : "none", alignItems: "baseline" }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        {v.title && <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{v.title}</div>}
                        <div title={v.url_raw} style={{ fontSize: 11.5, color: "var(--accent)", fontFamily: "var(--mono)", wordBreak: "break-all" }}>{v.url}</div>
                      </div>
                      <span style={{ flexShrink: 0, fontSize: 10.5, color: "var(--text-faint)" }}>{v.visit_count && `${v.visit_count}회`}</span>
                      <span style={{ flexShrink: 0, fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{v.timestamp}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

function SubHead({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-dim)", margin: "8px 0 4px", textTransform: "uppercase", letterSpacing: 0.4 }}>{children}</div>;
}

function KV({ k, v, mono, link }: { k: string; v: string; mono?: boolean; link?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 8, marginTop: 2, fontSize: 11.5 }}>
      <span style={{ flex: "0 0 60px", color: "var(--text-faint)" }}>{k}</span>
      <span style={{ flex: 1, color: link ? "var(--accent)" : "var(--text-dim)", fontFamily: mono ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{v}</span>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: number; tone: "ok" | "warning" | "neutral" }) {
  const color = tone === "warning" ? "var(--warning)" : tone === "ok" ? "var(--success)" : "var(--accent)";
  return (
    <div style={{ minWidth: 110, padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderLeft: `3px solid ${color}`, borderRadius: "var(--radius-md)" }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 800, color }}>{value.toLocaleString()}</div>
    </div>
  );
}

function Pill({ text, color }: { text: string; color: string }) {
  return <span style={{ fontSize: 10, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: 4, padding: "0 5px" }}>{text}</span>;
}
