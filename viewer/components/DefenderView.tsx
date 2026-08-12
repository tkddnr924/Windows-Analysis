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

// Quarantine/remove/block = the threat was neutralised (good); allow / "탐지만" =
// it slipped through (bad, needs attention).
function isNeutralized(action: string): boolean {
  return /격리|제거|quarantine|remove|clean|차단|block/i.test(action || "");
}
function actionColor(action: string): string {
  if (isNeutralized(action)) return "var(--success)";
  if (/허용|allow|탐지만/i.test(action || "")) return "var(--danger)";
  return "var(--text-dim)";
}

// A tampering entry's severity for the protection timeline dot.
function tamperTone(r: Row): "ok" | "danger" | "warning" {
  const t = r.title || "";
  const eid = r.event_id || "";
  if (t.includes("복원") || eid === "5000") return "ok";
  if (t.includes("실시간 보호 사용 안 함") || ["5001", "5010", "5012"].includes(eid)) return "danger";
  return "warning";
}
const toneColor = { ok: "var(--success)", danger: "var(--danger)", warning: "var(--warning)" };

export default function DefenderView({ data, onNavigate }: Props) {
  const { threats, unhandled, tampering, scans, signature, rtState, lastScan, historyCleared } = useMemo(() => {
    const rows = data.rows;
    const rawThreats = rows.filter((r) => r.section === "threat");
    // Un-neutralised threats (slipped through) float to the top; then newest first.
    const threats = [...rawThreats].sort((a, b) => {
      const an = isNeutralized(a.action) ? 1 : 0;
      const bn = isNeutralized(b.action) ? 1 : 0;
      if (an !== bn) return an - bn;
      return (b.timestamp || "").localeCompare(a.timestamp || "");
    });
    const unhandled = rawThreats.filter((r) => !isNeutralized(r.action)).length;

    const tampering = rows.filter((r) => r.section === "tampering").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const scans = rows.filter((r) => r.section === "scan").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const signature = rows.find((r) => r.section === "signature") ?? null;

    // Current real-time-protection state = the most recent RT event.
    const rtRows = tampering.filter((r) => (r.title || "").includes("실시간 보호"));
    const rtLatest = rtRows[0] ?? null; // tampering is newest-first
    const rtState = rtLatest ? { on: (rtLatest.title || "").includes("복원"), at: rtLatest.timestamp } : null;

    const lastScan = scans[0] ?? null;
    const historyCleared = tampering.find((r) => (r.title || "").includes("기록 삭제")) ?? null;
    return { threats, unhandled, tampering, scans, signature, rtState, lastScan, historyCleared };
  }, [data.rows]);

  const hasData = data.rows.length > 0;
  const goSource = (r: Row) => {
    if (onNavigate && r.record_key) onNavigate("EventLog_Events", "_record_key", r.record_key);
  };

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      {/* Hero */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 4 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🛡️ Windows Defender</span>
        {signature && <span style={{ fontSize: 13, color: "var(--text-dim)" }}>보안 인텔리전스 {signature.detail}</span>}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 18 }}>
        이벤트 로그를 종합한 백신 활동 요약 · 항목을 클릭하면 원본 이벤트 로그로 이동합니다.
      </div>

      {/* Summary tiles */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 20 }}>
        <Tile label="탐지된 위협" value={`${threats.length}건`} sub={unhandled ? `미조치 ${unhandled}건` : threats.length ? "모두 조치됨" : undefined} tone={unhandled ? "danger" : threats.length ? "warning" : "ok"} />
        <Tile
          label="실시간 보호"
          value={rtState ? (rtState.on ? "정상 (복원됨)" : "해제됨") : "이벤트 없음"}
          sub={rtState ? rtState.at : undefined}
          tone={rtState ? (rtState.on ? "ok" : "danger") : "ok"}
        />
        <Tile label="검사 기록 삭제" value={historyCleared ? "있음" : "없음"} sub={historyCleared ? historyCleared.timestamp : undefined} tone={historyCleared ? "warning" : "ok"} />
        <Tile label="마지막 검사" value={lastScan ? lastScan.title : "기록 없음"} sub={lastScan ? lastScan.timestamp : undefined} tone="ok" />
      </div>

      {!hasData && <div style={{ color: "var(--text-faint)", fontSize: 13 }}>Defender 이벤트 로그가 없습니다.</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 16, maxWidth: 1100 }}>
        {/* Threats */}
        {threats.length > 0 && (
          <Card title="🦠 탐지된 위협" count={threats.length} accent="var(--danger)" note={unhandled ? `미조치 ${unhandled}건` : undefined}>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {threats.map((t, i) => {
                const neutral = isNeutralized(t.action);
                return (
                  <div
                    key={i}
                    onClick={() => goSource(t)}
                    title={t.record_key ? "클릭하면 원본 이벤트 로그로 이동" : undefined}
                    style={{ padding: "10px 12px", background: "var(--bg-elevated)", border: `1px solid ${neutral ? "var(--border-subtle)" : "var(--danger)"}`, borderRadius: "var(--radius-md)", cursor: t.record_key ? "pointer" : "default" }}
                    onMouseEnter={(e) => t.record_key && (e.currentTarget.style.background = "var(--bg-hover)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-elevated)")}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 13.5, fontWeight: 700, color: "var(--text)", fontFamily: "var(--mono)" }}>{t.title}</span>
                      {t.severity && <Pill text={t.severity} color={sevColor(t.severity)} />}
                      {t.category && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{t.category}</span>}
                      <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
                        <Pill text={neutral ? t.action : "⚠ 미조치"} color={actionColor(t.action)} filled={!neutral} />
                        {t.record_key && <span style={{ fontSize: 11, color: "var(--text-faint)" }}>원본 →</span>}
                      </span>
                    </div>
                    <div style={{ marginTop: 6, display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px", fontSize: 12 }}>
                      <KV label="탐지 시각" v={t.timestamp} mono />
                      {t.action_time && <KV label="조치 시각" v={t.action_time} mono />}
                      {t.process && t.process !== "Unknown" && <KV label="프로세스" v={t.process} mono />}
                      {t.user && <KV label="사용자" v={t.user} />}
                      {t.source && <KV label="탐지원" v={t.source} />}
                      {t.origin && t.origin !== "알 수 없음" && <KV label="원본" v={t.origin} />}
                      {t.remediation && <KV label="치료 수행" v={t.remediation} />}
                      {t.additional_actions && <KV label="추가 조치" v={t.additional_actions} />}
                      {t.detail && <KV label="경로/내용" v={t.detail} mono />}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        {/* Protection state timeline */}
        {tampering.length > 0 && (
          <Card title="⚠️ 보호 상태 · 변조 타임라인" count={tampering.length} accent="var(--warning)">
            <div style={{ position: "relative", paddingLeft: 6 }}>
              {tampering.map((t, i) => {
                const tone = tamperTone(t);
                const color = toneColor[tone];
                const last = i === tampering.length - 1;
                return (
                  <div
                    key={i}
                    onClick={() => goSource(t)}
                    title={t.record_key ? "클릭하면 원본 이벤트 로그로 이동" : undefined}
                    style={{ position: "relative", display: "flex", gap: 12, padding: "8px 6px 8px 20px", cursor: t.record_key ? "pointer" : "default", borderRadius: "var(--radius-sm)" }}
                    onMouseEnter={(e) => t.record_key && (e.currentTarget.style.background = "var(--bg-hover)")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    {/* rail + dot */}
                    <span style={{ position: "absolute", left: 4, top: 13, width: 9, height: 9, borderRadius: "50%", background: color, border: "2px solid var(--bg-panel)", zIndex: 1 }} />
                    {!last && <span style={{ position: "absolute", left: 8, top: 20, bottom: -8, width: 1, background: "var(--border)" }} />}
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)", flex: "0 0 150px" }}>{t.timestamp || "-"}</span>
                    <div style={{ flex: 1 }}>
                      <span style={{ fontSize: 12.5, fontWeight: 600, color }}>{t.title}</span>
                      {t.detail && <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all" }}>{t.detail}</div>}
                      {t.user && <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 1 }}>👤 {t.user}</div>}
                    </div>
                    {t.record_key && <span style={{ fontSize: 11, color: "var(--text-faint)", alignSelf: "center" }}>원본 →</span>}
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        {/* Scans */}
        {scans.length > 0 && (
          <Card title="🔍 최근 검사" count={scans.length}>
            <div style={{ display: "flex", flexDirection: "column" }}>
              {scans.map((s, i) => (
                <div
                  key={i}
                  onClick={() => goSource(s)}
                  title={s.record_key ? "클릭하면 원본 이벤트 로그로 이동" : undefined}
                  style={{ display: "flex", gap: 12, padding: "6px 6px", borderBottom: i < scans.length - 1 ? "1px solid var(--border-subtle)" : "none", fontSize: 12.5, cursor: s.record_key ? "pointer" : "default", borderRadius: "var(--radius-sm)" }}
                  onMouseEnter={(e) => s.record_key && (e.currentTarget.style.background = "var(--bg-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
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

function Card({ title, count, accent, note, children }: { title: string; count?: number; accent?: string; note?: string; children: React.ReactNode }) {
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${accent ?? "var(--border)"}` }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{title}</span>
        {count !== undefined && <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{count}건</span>}
        {note && <span style={{ marginLeft: "auto", fontSize: 11.5, fontWeight: 700, color: "var(--danger)" }}>{note}</span>}
      </div>
      <div style={{ padding: "8px 16px 14px" }}>{children}</div>
    </section>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone: "ok" | "warning" | "danger" }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : "var(--success)";
  return (
    <div style={{ minWidth: 150, maxWidth: 260, padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", borderLeft: `3px solid ${color}` }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 16, fontWeight: 700, color, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
      {sub && <div style={{ fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)", marginTop: 1 }}>{sub}</div>}
    </div>
  );
}

function Pill({ text, color, filled }: { text: string; color: string; filled?: boolean }) {
  return (
    <span style={{ fontSize: 10.5, fontWeight: 700, color: filled ? "var(--bg)" : color, background: filled ? color : "transparent", border: `1px solid ${color}`, borderRadius: 4, padding: "0 6px", whiteSpace: "nowrap" }}>{text}</span>
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
