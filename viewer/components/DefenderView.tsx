"use client";

import { useMemo } from "react";
import type { CsvData } from "@/lib/types";

type Row = Record<string, string>;

interface Props {
  data: CsvData;
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
}

function sevColor(sev: string): string {
  if (/심각|critical|높음|high/i.test(sev)) return "var(--danger)";
  if (/보통|medium|경고|moderate/i.test(sev)) return "var(--warning)";
  return "var(--text-faint)";
}

// Quarantine/remove = the threat was neutralised (good); allow/"탐지만" = it
// slipped through (bad) — color the action accordingly.
function actionColor(action: string): string {
  if (/격리|제거|quarantine|remove|clean|차단|block/i.test(action)) return "var(--success)";
  if (/허용|allow|탐지만/i.test(action)) return "var(--danger)";
  return "var(--text-dim)";
}

function Card({ title, count, accent, children }: { title: string; count?: number; accent?: string; children: React.ReactNode }) {
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${accent ?? "var(--border)"}` }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{title}</span>
        {count !== undefined && <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{count}건</span>}
      </div>
      <div style={{ padding: "8px 16px 14px" }}>{children}</div>
    </section>
  );
}

export default function DefenderView({ data }: Props) {
  const { threats, tampering, scans, signature, rtOff, historyCleared } = useMemo(() => {
    const rows = data.rows;
    const threats = rows.filter((r) => r.section === "threat").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const tampering = rows.filter((r) => r.section === "tampering").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const scans = rows.filter((r) => r.section === "scan").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const signature = rows.find((r) => r.section === "signature") ?? null;
    const rtOff = tampering.find((r) => (r.title || "").includes("실시간 보호")) ?? null;
    const historyCleared = tampering.find((r) => (r.title || "").includes("기록 삭제")) ?? null;
    return { threats, tampering, scans, signature, rtOff, historyCleared };
  }, [data.rows]);

  const hasData = data.rows.length > 0;

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      {/* Hero */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 4 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🛡️ Windows Defender</span>
        {signature && <span style={{ fontSize: 13, color: "var(--text-dim)" }}>보안 인텔리전스 {signature.detail}</span>}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 18 }}>이벤트 로그를 종합한 백신 활동 요약</div>

      {/* Summary tiles */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
        <Tile label="탐지된 위협" value={`${threats.length}건`} tone={threats.length ? "danger" : "ok"} />
        <Tile
          label="실시간 보호"
          value={rtOff ? "해제됨" : "이벤트 없음"}
          sub={rtOff ? rtOff.timestamp : undefined}
          tone={rtOff ? "danger" : "ok"}
        />
        <Tile
          label="검사 기록 삭제"
          value={historyCleared ? "있음" : "없음"}
          sub={historyCleared ? historyCleared.timestamp : undefined}
          tone={historyCleared ? "warning" : "ok"}
        />
      </div>

      {!hasData && <div style={{ color: "var(--text-faint)", fontSize: 13 }}>Defender 이벤트 로그가 없습니다.</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 16, maxWidth: 1100 }}>
        {/* Threats */}
        {threats.length > 0 && (
          <Card title="🦠 탐지된 위협" count={threats.length} accent="var(--danger)">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {threats.map((t, i) => (
                <div key={i} style={{ padding: "10px 12px", background: "var(--bg-elevated)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13.5, fontWeight: 700, color: "var(--text)", fontFamily: "var(--mono)" }}>{t.title}</span>
                    {t.severity && <Pill text={t.severity} color={sevColor(t.severity)} />}
                    {t.category && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{t.category}</span>}
                    <span style={{ marginLeft: "auto" }}><Pill text={t.action || "-"} color={actionColor(t.action)} /></span>
                  </div>
                  <div style={{ marginTop: 6, display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px", fontSize: 12 }}>
                    <KV label="탐지 시각" v={t.timestamp} mono />
                    {t.action_time && <KV label="조치 시각" v={t.action_time} mono />}
                    {t.process && t.process !== "Unknown" && <KV label="프로세스" v={t.process} mono />}
                    {t.user && <KV label="사용자" v={t.user} />}
                    {t.source && <KV label="탐지원" v={t.source} />}
                    {t.detail && <KV label="경로/내용" v={t.detail} mono />}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Tampering / protection state */}
        {tampering.length > 0 && (
          <Card title="⚠️ 보호 상태 · 변조" count={tampering.length} accent="var(--warning)">
            <div style={{ display: "flex", flexDirection: "column" }}>
              {tampering.map((t, i) => (
                <div key={i} style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: i < tampering.length - 1 ? "1px solid var(--border-subtle)" : "none" }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)", flex: "0 0 150px" }}>{t.timestamp || "-"}</span>
                  <div style={{ flex: 1 }}>
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)" }}>{t.title}</span>
                    {t.detail && <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all" }}>{t.detail}</div>}
                    {t.user && <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 1 }}>👤 {t.user}</div>}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* Scans */}
        {scans.length > 0 && (
          <Card title="🔍 최근 검사" count={scans.length}>
            <div style={{ display: "flex", flexDirection: "column" }}>
              {scans.map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: i < scans.length - 1 ? "1px solid var(--border-subtle)" : "none", fontSize: 12.5 }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)", flex: "0 0 150px" }}>{s.timestamp || "-"}</span>
                  <span style={{ color: "var(--text)", fontWeight: 600 }}>{s.title}</span>
                  {s.user && <span style={{ marginLeft: "auto", color: "var(--text-faint)", fontSize: 11 }}>{s.user}</span>}
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone: "ok" | "warning" | "danger" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : "var(--success)";
  return (
    <div style={{ minWidth: 150, padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", borderLeft: `3px solid ${color}` }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 16, fontWeight: 700, color }}>{value}</div>
      {sub && <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 1 }}>{sub}</div>}
    </div>
  );
}

function Pill({ text, color }: { text: string; color: string }) {
  return (
    <span style={{ fontSize: 10.5, fontWeight: 700, color, border: `1px solid ${color}`, borderRadius: 4, padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>
  );
}

function KV({ label, v, mono }: { label: string; v: string; mono?: boolean }) {
  return (
    <>
      <span style={{ color: "var(--text-faint)" }}>{label}</span>
      <span style={{ color: "var(--text-dim)", fontFamily: mono ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{v}</span>
    </>
  );
}
