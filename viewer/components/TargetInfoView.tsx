"use client";

import { useEffect, useMemo, useState } from "react";
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
  // The rest come from the SAM hive (blank when SAM wasn't collected or the
  // account has no SAM entry) — shown in the account detail panel.
  fullName: string;
  rid: string;
  homeDir: string;
  created: string;
  lastLogin: string;
  passwordLastSet: string;
  lastFailedLogin: string;
  loginCount: string;
  failedLoginCount: string;
  disabled: string;
  specialAccount: string;
  groups: string;
  accountFlags: string;
}

function basename(p: string): string {
  const cleaned = p.replace(/[\\/]+$/, "");
  const parts = cleaned.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function buildAccount(r: Row): Account {
  const sid = r.name || "";
  const ridMatch = sid.match(/-(\d+)$/);
  const ridNum = ridMatch ? Number(ridMatch[1]) : NaN;
  // S-1-5-21-… is a machine/domain-issued account; RID 500 is the built-in
  // Administrator, RID ≥ 1000 are created users. Everything else (S-1-5-18/19/20)
  // is a service identity.
  const isUser = /^S-1-5-21-/.test(sid) && (ridNum === 500 || ridNum >= 1000);
  return {
    sid,
    path: r.value || "",
    username: r.username || basename(r.value || ""),
    isUser,
    fullName: r.full_name || "",
    rid: r.rid || (Number.isFinite(ridNum) ? String(ridNum) : ""),
    homeDir: r.home_directory || r.value || "",
    created: r.created || "",
    lastLogin: r.last_login || "",
    passwordLastSet: r.password_last_set || "",
    lastFailedLogin: r.last_failed_login || "",
    loginCount: r.login_count || "",
    failedLoginCount: r.failed_login_count || "",
    disabled: r.disabled || "",
    specialAccount: r.special_account || "",
    groups: r.groups || "",
    accountFlags: r.account_flags || "",
  };
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

interface NetInterface {
  guid: string;
  ip: string;
  subnet: string;
  gateway: string;
  dns: string;
  dhcpServer: string;
  domain: string;
  dhcp: string;
  leaseObtained: string;
  leaseTerminates: string;
}

export default function TargetInfoView({ data }: TargetInfoViewProps) {
  const [selectedAccount, setSelectedAccount] = useState<Account | null>(null);
  const { system, users, services, networks, interfaces, computerName, osSummary } = useMemo(() => {
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
    const ifaceMap = new Map<string, NetInterface>(); // ip+guid -> interface

    for (const r of dedup) {
      const cat = r.category;
      if (cat === "OS" || cat === "System") {
        // Prefer a non-empty value; some rows carry only a timestamp
        // (e.g. LastShutdownTime), which we surface as the value.
        const value = r.value || r.timestamp || "";
        const prev = system.get(r.name);
        if (!prev || (!prev.value && value)) system.set(r.name, { value, timestamp: r.timestamp });
      } else if (cat === "Account") {
        accounts.push(buildAccount(r));
      } else if (cat === "Network") {
        const name = r.value;
        const existing = netMap.get(name);
        if (!existing || r.timestamp > existing) netMap.set(name, r.timestamp);
      } else if (cat === "NetworkInterface" && r.value) {
        const key = `${r.value}|${r.name}`;
        if (!ifaceMap.has(key)) {
          ifaceMap.set(key, {
            guid: r.name ?? "",
            ip: r.value ?? "",
            subnet: r.subnet_mask ?? "",
            gateway: r.gateway ?? "",
            dns: r.dns_server ?? "",
            dhcpServer: r.dhcp_server ?? "",
            domain: r.domain ?? "",
            dhcp: r.dhcp_enabled ?? "",
            leaseObtained: r.lease_obtained ?? "",
            leaseTerminates: r.lease_terminates ?? "",
          });
        }
      }
    }

    const users = accounts.filter((a) => a.isUser).sort((a, b) => a.username.localeCompare(b.username));
    const services = accounts.filter((a) => !a.isUser).sort((a, b) => a.username.localeCompare(b.username));
    const networks = [...netMap.entries()]
      .map(([name, timestamp]) => ({ name, timestamp }))
      .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
    const interfaces = [...ifaceMap.values()].sort((a, b) => a.ip.localeCompare(b.ip));

    const computerName = system.get("ComputerName")?.value || "알 수 없는 시스템";
    const product = system.get("ProductName")?.value || "";
    const build = system.get("CurrentBuild")?.value || "";
    const osSummary = [product, build && `Build ${build}`].filter(Boolean).join(" · ");

    return { system, users, services, networks, interfaces, computerName, osSummary };
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

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
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

        {/* IP 구성 (어댑터) */}
        <Card title="IP 구성 (네트워크 어댑터)" count={interfaces.length}>
          {interfaces.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>IP 구성 정보 없음</div>}
          {interfaces.map((n) => (
            <div key={`${n.ip}|${n.guid}`} style={{ padding: "8px 0", borderBottom: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{n.ip}</span>
                {n.dhcp && (
                  <span style={{ fontSize: 10, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: 4, padding: "0 5px" }}>
                    DHCP {n.dhcp}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11.5, color: "var(--text-dim)", marginTop: 3, display: "grid", gridTemplateColumns: "auto 1fr", gap: "1px 8px" }}>
                {n.gateway && (<><span style={{ color: "var(--text-faint)" }}>게이트웨이</span><span style={{ fontFamily: "var(--mono)" }}>{n.gateway}</span></>)}
                {n.subnet && (<><span style={{ color: "var(--text-faint)" }}>서브넷</span><span style={{ fontFamily: "var(--mono)" }}>{n.subnet}</span></>)}
                {n.dns && (<><span style={{ color: "var(--text-faint)" }}>DNS</span><span style={{ fontFamily: "var(--mono)" }}>{n.dns}</span></>)}
                {n.dhcpServer && (<><span style={{ color: "var(--text-faint)" }}>DHCP 서버</span><span style={{ fontFamily: "var(--mono)" }}>{n.dhcpServer}</span></>)}
                {n.domain && (<><span style={{ color: "var(--text-faint)" }}>도메인</span><span>{n.domain}</span></>)}
                {n.leaseObtained && (<><span style={{ color: "var(--text-faint)" }}>임대 시작</span><span style={{ fontFamily: "var(--mono)" }}>{n.leaseObtained}</span></>)}
                {n.leaseTerminates && (<><span style={{ color: "var(--text-faint)" }}>임대 만료</span><span style={{ fontFamily: "var(--mono)" }}>{n.leaseTerminates}</span></>)}
              </div>
            </div>
          ))}
        </Card>

        {/* 사용자 계정 */}
        <Card title="사용자 계정" count={users.length}>
          {users.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>계정 없음</div>}
          {users.map((a) => (
            <AccountRow key={a.sid} account={a} highlight onSelect={() => setSelectedAccount(a)} />
          ))}
        </Card>

        {/* 시스템/서비스 계정 */}
        <Card title="시스템 · 서비스 계정" count={services.length}>
          {services.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 12.5 }}>없음</div>}
          {services.map((a) => (
            <AccountRow key={a.sid} account={a} onSelect={() => setSelectedAccount(a)} />
          ))}
        </Card>
      </div>

      {selectedAccount && <AccountDetailModal account={selectedAccount} onClose={() => setSelectedAccount(null)} />}
    </div>
  );
}

function AccountRow({ account, highlight, onSelect }: { account: Account; highlight?: boolean; onSelect: () => void }) {
  return (
    <div
      onClick={onSelect}
      title="자세히 보기"
      style={{ padding: "7px 6px", margin: "0 -6px", borderRadius: "var(--radius-sm)", borderBottom: "1px solid var(--border-subtle)", cursor: "pointer" }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: highlight ? 600 : 500, color: highlight ? "var(--text)" : "var(--text-dim)" }}>
          {highlight ? "👤" : "⚙️"} {account.username}
        </span>
        {account.disabled === "예" && (
          <span style={{ fontSize: 10, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: 4, padding: "0 5px" }}>비활성</span>
        )}
        {account.specialAccount.startsWith("예") && (
          <span title={account.specialAccount} style={{ fontSize: 10, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: 4, padding: "0 5px" }}>숨김</span>
        )}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-faint)" }}>›</span>
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

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <span style={{ flex: "0 0 150px", color: "var(--text-dim)", fontSize: 12.5 }}>{label}</span>
      <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: mono ? "var(--mono)" : "var(--sans)" }}>
        {value || "—"}
      </span>
    </div>
  );
}

function AccountDetailModal({ account, onClose }: { account: Account; onClose: () => void }) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: 24 }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(640px, 94vw)",
          maxHeight: "88vh",
          display: "flex",
          flexDirection: "column",
          background: "var(--bg-panel)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          boxShadow: "var(--shadow-panel)",
          overflow: "hidden",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)", flexShrink: 0 }}>
          <span style={{ fontSize: 15, fontWeight: 700 }}>{account.isUser ? "👤" : "⚙️"} {account.username || "(이름 없음)"}</span>
          {account.fullName && account.fullName !== account.username && (
            <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{account.fullName}</span>
          )}
          {account.disabled === "예" && (
            <span style={{ fontSize: 11, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: 4, padding: "1px 6px" }}>비활성</span>
          )}
          <button
            onClick={onClose}
            title="닫기 (Esc)"
            style={{ marginLeft: "auto", background: "transparent", border: "none", color: "var(--text-dim)", fontSize: 20, cursor: "pointer", lineHeight: 1, padding: 4 }}
          >
            ×
          </button>
        </div>
        <div style={{ padding: "6px 16px 16px", overflow: "auto" }}>
          <DetailRow label="계정명" value={account.username} />
          <DetailRow label="계정 SID" value={account.sid} mono />
          <DetailRow label="RID" value={account.rid} mono />
          <DetailRow label="홈 디렉토리" value={account.homeDir} mono />
          <DetailRow label="생성 일시" value={account.created} mono />
          <DetailRow label="최근 로그인 일시" value={account.lastLogin} mono />
          <DetailRow label="비밀번호 마지막 변경" value={account.passwordLastSet} mono />
          <DetailRow label="비밀번호 오류 일시" value={account.lastFailedLogin} mono />
          <DetailRow label="로그인 횟수" value={account.loginCount} />
          <DetailRow label="비밀번호 오류 횟수" value={account.failedLoginCount} />
          <DetailRow label="SpecialAccount" value={account.specialAccount} />
          <DetailRow label="그룹" value={account.groups} />
          <DetailRow label="권한 / 속성" value={account.accountFlags} />
        </div>
      </div>
    </div>
  );
}
