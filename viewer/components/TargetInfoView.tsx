"use client";

import { useMemo } from "react";
import type { CsvData } from "@/lib/types";

interface TargetInfoViewProps {
  data: CsvData;
}

// TargetInfo is a correlation of registry-derived system facts (OS build,
// computer name, time zone, shutdown time), the machine's local user profiles,
// and the networks it has connected to. Presented as a summary dashboard rather
// than a flat table, since an analyst reads it to orient — "what machine is
// this, who used it, where was it" — not to scan rows.

type Row = Record<string, string>;

const SYSTEM_LABELS: Record<string, string> = {
  ProductName: "운영체제",
  DisplayVersion: "버전",
  CurrentBuild: "빌드",
  EditionID: "에디션",
  RegisteredOwner: "등록 소유자",
  InstallDate: "설치 시각",
  ComputerName: "컴퓨터 이름",
  TimeZone: "표준 시간대",
  LastShutdownTime: "마지막 종료 시각",
};

// Display order for the system card — anything not listed falls to the end.
const SYSTEM_ORDER = [
  "ComputerName",
  "ProductName",
  "EditionID",
  "DisplayVersion",
  "CurrentBuild",
  "InstallDate",
  "LastShutdownTime",
  "TimeZone",
  "RegisteredOwner",
];

interface Account {
  sid: string;
  path: string;
  username: string;
  /** Interactive human account (built-in Administrator or RID ≥ 1000) vs a
   * machine/service identity (LocalSystem, LocalService, ...). */
  isUser: boolean;
  /** Account creation date + last login, from the SAM hive (blank when SAM
   * wasn't collected or the account has no SAM entry). */
  created: string;
  lastLogin: string;
}

function basename(p: string): string {
  const cleaned = p.replace(/[\\/]+$/, "");
  const parts = cleaned.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function classifyAccount(sid: string, path: string, username: string, created: string, lastLogin: string): Account {
  const ridMatch = sid.match(/-(\d+)$/);
  const rid = ridMatch ? Number(ridMatch[1]) : NaN;
  // S-1-5-21-… is a machine/domain-issued account; RID 500 is the built-in
  // Administrator, RID ≥ 1000 are created users. Everything else (S-1-5-18/19/20)
  // is a service identity.
  const isUser = /^S-1-5-21-/.test(sid) && (rid === 500 || rid >= 1000);
  return { sid, path, username: username || basename(path), isUser, created, lastLogin };
}

function KeyVal({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <span style={{ flex: "0 0 130px", color: "var(--text-dim)", fontSize: 12.5 }}>{label}</span>
      <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all" }}>{children || "—"}</span>
    </div>
  );
}

function Card({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <section
      style={{
        background: "var(--bg-panel)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        boxShadow: "var(--shadow-card)",
        overflow: "hidden",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 16px",
          borderBottom: "1px solid var(--border-subtle)",
          fontWeight: 600,
          fontSize: 13,
          color: "var(--text)",
        }}
      >
        {title}
        {count !== undefined && <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 12 }}>{count}</span>}
      </header>
      <div style={{ padding: "8px 16px 14px" }}>{children}</div>
    </section>
  );
}

export default function TargetInfoView({ data }: TargetInfoViewProps) {
  const { system, users, services, networks, computerName, osSummary } = useMemo(() => {
    const rows = data.rows as Row[];

    // The source hives are parsed once per copy, so identical facts repeat —
    // dedupe on the value triple before anything else.
    const seen = new Set<string>();
    const dedup: Row[] = [];
    for (const r of rows) {
      const key = `${r.category}|${r.name}|${r.value}|${r.timestamp}`;
      if (seen.has(key)) continue;
      seen.add(key);
      dedup.push(r);
    }

    const system = new Map<string, { value: string; timestamp: string }>();
    const accounts: Account[] = [];
    const netMap = new Map<string, string>(); // name -> latest timestamp

    for (const r of dedup) {
      const cat = r.category;
      if (cat === "OS" || cat === "System") {
        // Prefer a non-empty value; some rows carry only a timestamp
        // (e.g. LastShutdownTime), which we surface as the value.
        const value = r.value || r.timestamp || "";
        const prev = system.get(r.name);
        if (!prev || (!prev.value && value)) system.set(r.name, { value, timestamp: r.timestamp });
      } else if (cat === "Account") {
        accounts.push(classifyAccount(r.name, r.value, r.username ?? "", r.created ?? "", r.last_login ?? ""));
      } else if (cat === "Network") {
        const name = r.value;
        const existing = netMap.get(name);
        if (!existing || r.timestamp > existing) netMap.set(name, r.timestamp);
      }
    }

    const users = accounts.filter((a) => a.isUser).sort((a, b) => a.username.localeCompare(b.username));
    const services = accounts.filter((a) => !a.isUser).sort((a, b) => a.username.localeCompare(b.username));
    const networks = [...netMap.entries()]
      .map(([name, timestamp]) => ({ name, timestamp }))
      .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));

    const computerName = system.get("ComputerName")?.value || "알 수 없는 시스템";
    const product = system.get("ProductName")?.value || "";
    const build = system.get("CurrentBuild")?.value || "";
    const osSummary = [product, build && `Build ${build}`].filter(Boolean).join(" · ");

    return { system, users, services, networks, computerName, osSummary };
  }, [data.rows]);

  const orderedSystem = useMemo(() => {
    const keys = [...system.keys()];
    keys.sort((a, b) => {
      const ia = SYSTEM_ORDER.indexOf(a);
      const ib = SYSTEM_ORDER.indexOf(b);
      return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
    });
    return keys;
  }, [system]);

  return (
    <div style={{ flex: 1, minHeight: 0, overflow: "auto", padding: "20px 24px" }}>
      {/* Hero */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 4 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: "var(--text)" }}>🖥️ {computerName}</span>
        {osSummary && <span style={{ fontSize: 13, color: "var(--text-dim)" }}>{osSummary}</span>}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-faint)", marginBottom: 20 }}>분석 대상 시스템 정보</div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16, alignItems: "start" }}>
        {/* 시스템 */}
        <Card title="시스템">
          {orderedSystem.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>정보 없음</div>}
          {orderedSystem.map((k) => (
            <KeyVal key={k} label={SYSTEM_LABELS[k] ?? k}>
              {system.get(k)?.value}
            </KeyVal>
          ))}
        </Card>

        {/* 네트워크 */}
        <Card title="연결한 네트워크" count={networks.length}>
          {networks.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>기록 없음</div>}
          {networks.map((n) => (
            <div key={n.name} style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <span style={{ color: "var(--text)", fontSize: 12.5, wordBreak: "break-all" }}>{n.name}</span>
              <span style={{ color: "var(--text-faint)", fontSize: 12, whiteSpace: "nowrap" }}>{n.timestamp || "—"}</span>
            </div>
          ))}
        </Card>

        {/* 사용자 계정 */}
        <Card title="사용자 계정" count={users.length}>
          {users.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>계정 없음</div>}
          {users.map((a) => (
            <AccountRow key={a.sid} account={a} highlight />
          ))}
        </Card>

        {/* 시스템/서비스 계정 */}
        <Card title="시스템 · 서비스 계정" count={services.length}>
          {services.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>없음</div>}
          {services.map((a) => (
            <AccountRow key={a.sid} account={a} />
          ))}
        </Card>
      </div>
    </div>
  );
}

function AccountRow({ account, highlight }: { account: Account; highlight?: boolean }) {
  return (
    <div style={{ padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: highlight ? 600 : 500, color: highlight ? "var(--text)" : "var(--text-dim)" }}>
          {highlight ? "👤" : "⚙️"} {account.username}
        </span>
      </div>
      {account.path && (
        <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 2, wordBreak: "break-all" }}>{account.path}</div>
      )}
      {(account.created || account.lastLogin) && (
        <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2, display: "flex", gap: 10, flexWrap: "wrap" }}>
          {account.created && <span>🗓️ 생성 {account.created}</span>}
          {account.lastLogin && <span>마지막 로그온 {account.lastLogin}</span>}
        </div>
      )}
      <div style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 1, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{account.sid}</div>
    </div>
  );
}
