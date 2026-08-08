"use client";

import { useEffect, useMemo, useState } from "react";
import { tagsForPath } from "@/lib/tagging";
import type { CategoryEntry, Host } from "@/lib/types";

type Row = Record<string, string>;

interface Props {
  host: Host;
  categories: CategoryEntry[];
  /** Open an overview table (by its table name, e.g. "Defender") as a tab. */
  onOpenTable: (name: string) => void;
  onOpenTimeline: () => void;
}

function basename(p: string): string {
  const c = (p || "").replace(/[\\/]+$/, "");
  const parts = c.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function isUserAccount(sid: string): boolean {
  const m = sid.match(/-(\d+)$/);
  const rid = m ? Number(m[1]) : NaN;
  return /^S-1-5-21-/.test(sid) && (rid === 500 || rid >= 1000);
}

export default function HostDashboard({ host, categories, onOpenTable, onOpenTimeline }: Props) {
  const [rows, setRows] = useState<Record<string, Row[]>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      const ov = categories.find((c) => c.name === "_OVERVIEW");
      const acc: Record<string, Row[]> = {};
      if (ov) {
        const files = await window.api.listResultFiles(ov.fullPath);
        for (const name of ["TargetInfo", "Defender", "ExecutionHistory"]) {
          const f = files.find((x) => x.name === name);
          if (f) {
            try {
              const d = await window.api.readResultFile(f.fullPath, f.tableName);
              acc[name] = d.rows;
            } catch {
              /* overview not built yet — leave empty */
            }
          }
        }
      }
      if (!cancelled) {
        setRows(acc);
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [categories, host.id]);

  const model = useMemo(() => {
    const ti = rows.TargetInfo ?? [];
    const def = rows.Defender ?? [];
    const exec = rows.ExecutionHistory ?? [];

    const system: Record<string, string> = {};
    for (const r of ti) if (r.category === "SystemInfo") system[r.name] = r.value;

    const accounts = ti.filter((r) => r.category === "Account");
    const users = accounts.filter((a) => isUserAccount(a.name));
    const interfaces = ti.filter((r) => r.category === "NetworkInterface" && r.value);
    const networks = ti.filter((r) => r.category === "Network");

    const threats = def.filter((r) => r.section === "threat").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const tampering = def.filter((r) => r.section === "tampering").sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));

    const suspicious = exec
      .filter((r) => tagsForPath(r.program_path).length > 0)
      .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));

    return { system, users, interfaces, networks, threats, tampering, suspicious, execTotal: exec.length };
  }, [rows]);

  const computer = model.system.ComputerName || host.name || "호스트";
  const os = [model.system.ProductName, model.system.CurrentBuild && `Build ${model.system.CurrentBuild}`].filter(Boolean).join(" · ");

  if (loading) {
    return <Center>대시보드 불러오는 중…</Center>;
  }

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "22px 26px" }}>
      {/* Hero */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 2 }}>
        <span style={{ fontSize: 24, fontWeight: 800, color: "var(--text)" }}>🖥️ {computer}</span>
        {os && <span style={{ fontSize: 13, color: "var(--text-dim)" }}>{os}</span>}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 18 }}>
        {host.name} · 핵심 지표 요약 — 카드를 클릭하면 상세 화면으로 이동합니다.
      </div>

      {/* Stat tiles */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 22 }}>
        <Stat label="탐지된 위협" value={model.threats.length} tone={model.threats.length ? "danger" : "ok"} onClick={() => onOpenTable("Defender")} />
        <Stat label="의심 실행" value={model.suspicious.length} tone={model.suspicious.length ? "warning" : "ok"} onClick={() => onOpenTable("ExecutionHistory")} />
        <Stat label="보호 변조" value={model.tampering.length} tone={model.tampering.length ? "warning" : "ok"} onClick={() => onOpenTable("Defender")} />
        <Stat label="사용자 계정" value={model.users.length} tone="neutral" onClick={() => onOpenTable("TargetInfo")} />
        <Stat label="네트워크 IP" value={model.interfaces.length} tone="neutral" onClick={() => onOpenTable("TargetInfo")} />
        <Stat label="실행 이력" value={model.execTotal} tone="neutral" onClick={() => onOpenTable("ExecutionHistory")} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 16, alignItems: "start" }}>
        {/* Threats */}
        <Card title="🦠 탐지된 위협" count={model.threats.length} accent="var(--danger)" onOpen={() => onOpenTable("Defender")}>
          {model.threats.length === 0 ? (
            <Empty>탐지된 위협 없음</Empty>
          ) : (
            model.threats.slice(0, 6).map((t, i) => (
              <Line key={i} time={t.timestamp} title={t.title} sub={`${t.severity || ""}${t.action ? " · " + t.action : ""}`} tone="danger" />
            ))
          )}
        </Card>

        {/* Suspicious executions */}
        <Card title="⚡ 의심 실행" count={model.suspicious.length} accent="var(--warning)" onOpen={() => onOpenTable("ExecutionHistory")}>
          {model.suspicious.length === 0 ? (
            <Empty>의심 경로 실행 없음</Empty>
          ) : (
            model.suspicious.slice(0, 6).map((r, i) => (
              <Line key={i} time={r.timestamp} title={r.program_name || basename(r.program_path)} sub={r.program_path} tone="warning" mono />
            ))
          )}
        </Card>

        {/* Protection tampering */}
        {model.tampering.length > 0 && (
          <Card title="🛡️ 보호 상태 변조" count={model.tampering.length} accent="var(--warning)" onOpen={() => onOpenTable("Defender")}>
            {model.tampering.slice(0, 6).map((t, i) => (
              <Line key={i} time={t.timestamp} title={t.title} sub={t.detail} tone="warning" />
            ))}
          </Card>
        )}

        {/* Accounts */}
        <Card title="👤 사용자 계정" count={model.users.length} onOpen={() => onOpenTable("TargetInfo")}>
          {model.users.length === 0 ? (
            <Empty>계정 정보 없음</Empty>
          ) : (
            model.users.slice(0, 8).map((a, i) => (
              <Line key={i} title={a.username || basename(a.value)} sub={`RID ${a.rid}${a.last_login ? " · 최근 로그인 " + a.last_login : ""}`} />
            ))
          )}
        </Card>

        {/* Network */}
        <Card title="🌐 네트워크" count={model.interfaces.length} onOpen={() => onOpenTable("TargetInfo")}>
          {model.interfaces.length === 0 ? (
            <Empty>네트워크 정보 없음</Empty>
          ) : (
            model.interfaces.slice(0, 8).map((n, i) => (
              <Line key={i} title={n.value} sub={[n.gateway && `GW ${n.gateway}`, n.dns_server && `DNS ${n.dns_server}`].filter(Boolean).join(" · ")} mono />
            ))
          )}
          {model.networks.length > 0 && (
            <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-faint)" }}>
              연결 네트워크: {model.networks.map((n) => n.value).join(", ")}
            </div>
          )}
        </Card>

        {/* System + timeline entry */}
        <Card title="🖥️ 시스템" onOpen={() => onOpenTable("TargetInfo")}>
          <KV k="컴퓨터 이름" v={model.system.ComputerName} />
          <KV k="운영체제" v={model.system.ProductName} />
          <KV k="빌드" v={model.system.CurrentBuild} />
          <KV k="설치 시각" v={model.system.InstallDate} />
          <KV k="표준 시간대" v={model.system.TimeZone} />
          <KV k="마지막 종료" v={model.system.LastShutdownTime} />
          <button onClick={onOpenTimeline} style={{ marginTop: 10, width: "100%", padding: "7px", background: "var(--accent-subtle)", color: "var(--accent)", border: "1px solid var(--accent)", borderRadius: "var(--radius-md)", cursor: "pointer", fontWeight: 600, fontSize: 12 }}>
            🕑 통합 타임라인 열기
          </button>
        </Card>
      </div>
    </div>
  );
}

function Center({ children }: { children: React.ReactNode }) {
  return <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)" }}>{children}</div>;
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 12, color: "var(--text-faint)", padding: "4px 0" }}>{children}</div>;
}

function Stat({ label, value, tone, onClick }: { label: string; value: number; tone: "ok" | "warning" | "danger" | "neutral"; onClick: () => void }) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : tone === "ok" ? "var(--success)" : "var(--accent)";
  return (
    <button onClick={onClick} style={{ minWidth: 120, textAlign: "left", padding: "10px 14px", background: "var(--bg-panel)", border: "1px solid var(--border)", borderLeft: `3px solid ${color}`, borderRadius: "var(--radius-md)", cursor: "pointer" }}>
      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 800, color }}>{value.toLocaleString()}</div>
    </button>
  );
}

function Card({ title, count, accent, onOpen, children }: { title: string; count?: number; accent?: string; onOpen?: () => void; children: React.ReactNode }) {
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <div
        onClick={onOpen}
        style={{ display: "flex", alignItems: "center", gap: 8, padding: "11px 14px", borderBottom: "1px solid var(--border-subtle)", borderLeft: `3px solid ${accent ?? "var(--border)"}`, cursor: onOpen ? "pointer" : "default" }}
      >
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{title}</span>
        {count !== undefined && <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{count}</span>}
        {onOpen && <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--accent)" }}>열기 ›</span>}
      </div>
      <div style={{ padding: "8px 14px 12px" }}>{children}</div>
    </section>
  );
}

function Line({ time, title, sub, tone, mono }: { time?: string; title: string; sub?: string; tone?: "danger" | "warning"; mono?: boolean }) {
  const dot = tone === "danger" ? "var(--danger)" : tone === "warning" ? "var(--warning)" : "var(--text-faint)";
  return (
    <div style={{ display: "flex", gap: 8, padding: "5px 0", borderBottom: "1px solid var(--border-subtle)", alignItems: "baseline" }}>
      {tone && <span style={{ flex: "0 0 auto", width: 6, height: 6, borderRadius: 999, background: dot, alignSelf: "center" }} />}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, color: "var(--text)", fontWeight: 600, fontFamily: mono ? "var(--mono)" : undefined, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{title}</div>
        {sub && <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: mono ? "var(--mono)" : undefined, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{sub}</div>}
      </div>
      {time && <span style={{ flex: "0 0 auto", fontSize: 10.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{time}</span>}
    </div>
  );
}

function KV({ k, v }: { k: string; v?: string }) {
  return (
    <div style={{ display: "flex", gap: 10, padding: "4px 0", borderBottom: "1px solid var(--border-subtle)", fontSize: 12.5 }}>
      <span style={{ flex: "0 0 96px", color: "var(--text-faint)" }}>{k}</span>
      <span style={{ flex: 1, color: "var(--text-dim)", wordBreak: "break-all" }}>{v || "—"}</span>
    </div>
  );
}
