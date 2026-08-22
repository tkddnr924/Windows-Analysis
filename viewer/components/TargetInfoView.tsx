"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import ArrowBackOutlinedIcon from "@mui/icons-material/ArrowBackOutlined";
import BookmarkBorderOutlinedIcon from "@mui/icons-material/BookmarkBorderOutlined";
import BookmarkIcon from "@mui/icons-material/Bookmark";
import ChevronLeftOutlinedIcon from "@mui/icons-material/ChevronLeftOutlined";
import ChevronRightOutlinedIcon from "@mui/icons-material/ChevronRightOutlined";
import CircularProgress from "@mui/material/CircularProgress";
import DesktopWindowsOutlinedIcon from "@mui/icons-material/DesktopWindowsOutlined";
import LanOutlinedIcon from "@mui/icons-material/LanOutlined";
import ManageAccountsOutlinedIcon from "@mui/icons-material/ManageAccountsOutlined";
import PersonOutlineIcon from "@mui/icons-material/PersonOutlineOutlined";
import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import WarningAmberOutlinedIcon from "@mui/icons-material/WarningAmberOutlined";
import type { AccountEventPage, AccountEventQuery, CsvData, Bookmark } from "@/lib/types";
import type { FetchLinkedRows } from "@/lib/types";
import { toBound, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";

interface TargetInfoViewProps {
  data: CsvData;
  /** Fetch EventLog rows involving an account (by SID or username) — account
   * management (creation/group/pw) + logons. Enables the account detail page. */
  loadAccountEvents?: (sid: string, username: string, query: Omit<AccountEventQuery, "sid" | "username">) => Promise<AccountEventPage>;
  /** Global incident period selected in the sidebar. */
  timeRange: TimeRange;
  /** Threaded so the account-event detail uses the same shared EventLog detail
   * panel (RowDetailPanel) as every other view. */
  onNavigate?: (targetFile: string, targetColumn: string, value: string) => void;
  onFetchLinkedRows?: FetchLinkedRows;
  /** Per-timestamp bookmarking of account rows (생성/최근 로그인/비밀번호 …). */
  tableBookmarks?: Bookmark[];
  onToggleBookmark?: (rowid: number, field: string) => void;
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
  rowid: number;
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
  /** RID embedded in the SAM F record — differs from `rid` (the key/folder RID)
   * under RID hijacking. */
  ridSam: string;
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
  sourceArtifact: string;
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
    rowid: Number((r as unknown as Record<string, unknown>).__rowid),
    sid,
    path: r.value || "",
    username: r.username || basename(r.value || ""),
    isUser,
    fullName: r.full_name || "",
    rid: r.rid || (Number.isFinite(ridNum) ? String(ridNum) : ""),
    ridSam: r.rid_sam || "",
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
    sourceArtifact: r.source_artifact || "",
  };
}

function KeyVal({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(94px, 0.7fr) minmax(0, 1.3fr)", gap: 10, padding: "7px 0", borderBottom: "1px solid var(--border-subtle)" }}>
      <span style={{ color: "var(--text-dim)", fontSize: 13 }}>{label}</span>
      <span style={{ color: "var(--text)", fontSize: 13, wordBreak: "break-all" }}>{children || "—"}</span>
    </div>
  );
}

function SectionHeading({ title, count, leading }: { title: string; count?: number; leading?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 44, padding: "0 16px", borderBottom: "1px solid var(--border)", fontWeight: 750, fontSize: 15, color: "var(--text)" }}>
      {leading}
      <span>{title}</span>
      {count !== undefined && <span style={{ color: "var(--text-dim)", fontWeight: 600, fontSize: 12 }}>{count.toLocaleString()}건</span>}
    </div>
  );
}

function HostSurface({ children }: { children: React.ReactNode }) {
  return <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>{children}</section>;
}

function DetailSurface({ title, count, trailing, children }: { title: string; count?: number; trailing?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
      <div style={{ minHeight: 40, display: "flex", alignItems: "center", padding: "0 14px", borderBottom: "1px solid var(--border-subtle)", fontSize: 13, fontWeight: 700 }}>
        {title}
        {count !== undefined && <span style={{ marginLeft: 7, color: "var(--text-faint)", fontSize: 11.5, fontWeight: 500 }}>{count.toLocaleString()}건</span>}
        {trailing && <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center" }}>{trailing}</span>}
      </div>
      <div style={{ padding: "8px 14px 12px" }}>{children}</div>
    </section>
  );
}

interface NetInterface {
  row: Row;
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

interface NetworkProfile {
  row: Row;
  name: string;
  timestamp: string;
}

export default function TargetInfoView({ data, loadAccountEvents, timeRange, onNavigate, onFetchLinkedRows, tableBookmarks, onToggleBookmark }: TargetInfoViewProps) {
  const bmRowids = useMemo(() => new Set((tableBookmarks ?? []).map((b) => b.rowid)), [tableBookmarks]);
  const [selectedAccount, setSelectedAccount] = useState<Account | null>(null);
  const [selectedInterface, setSelectedInterface] = useState<NetInterface | null>(null);
  const [selectedNetwork, setSelectedNetwork] = useState<NetworkProfile | null>(null);
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
    const netMap = new Map<string, NetworkProfile>(); // profile name -> latest raw registry row
    const ifaceMap = new Map<string, NetInterface>(); // ip+guid -> interface

    for (const r of dedup) {
      const cat = r.category;
      if (cat === "SystemInfo" || cat === "OS" || cat === "System") {
        // Prefer a non-empty value; some rows carry only a timestamp
        // (e.g. LastShutdownTime), which we surface as the value.
        const value = r.value || r.timestamp || "";
        const prev = system.get(r.name);
        if (!prev || (!prev.value && value)) system.set(r.name, { value, timestamp: r.timestamp });
      } else if (cat === "Account") {
        accounts.push(buildAccount(r));
      } else if (cat === "Network") {
        const name = r.value || "";
        const existing = netMap.get(name);
        if (!existing || r.timestamp > existing.timestamp) {
          netMap.set(name, { row: r, name, timestamp: r.timestamp || "" });
        }
      } else if (cat === "NetworkInterface" && r.value) {
        const key = `${r.value}|${r.name}`;
        if (!ifaceMap.has(key)) {
          ifaceMap.set(key, {
            row: r,
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
    const networks = [...netMap.values()]
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

  // Clicking an account opens a full page (not a modal) — account detail plus
  // the EventLog activity for its SID.
  if (selectedAccount) {
    return <AccountDetailPage account={selectedAccount} onBack={() => setSelectedAccount(null)} loadEvents={loadAccountEvents} timeRange={timeRange} onNavigate={onNavigate} onFetchLinkedRows={onFetchLinkedRows} tableBookmarks={tableBookmarks} onToggleBookmark={onToggleBookmark} />;
  }

  const accounts = [...users, ...services];

  return (
    <div className="dfir-view" style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <header className="target-info-header" style={{ flexShrink: 0, minHeight: 56, display: "flex", alignItems: "center", gap: 12, padding: "0 24px", background: "var(--bg)", borderBottom: "1px solid var(--border)", zIndex: 2 }}>
        <h1 style={{ margin: 0, minWidth: 0, color: "var(--text)", fontSize: 20, lineHeight: 1.2, fontWeight: 760, letterSpacing: "-0.02em", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>호스트 정보 <span style={{ color: "var(--text-faint)", padding: "0 3px" }}>|</span> {computerName}</h1>
        {osSummary && <span style={{ marginLeft: "auto", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 13 }}>{osSummary}</span>}
      </header>

      <div style={{ flex: 1, minHeight: 0, overflowY: "auto", overflowX: "hidden", overscrollBehavior: "contain", padding: "14px 24px 32px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <HostSurface>
          <SectionHeading title="계정 정보" count={accounts.length} leading={<ManageAccountsOutlinedIcon sx={{ fontSize: 19, color: "var(--accent)" }} />} />
          <AccountRegistry accounts={accounts} bookmarkedRowids={bmRowids} onSelect={setSelectedAccount} />
        </HostSurface>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(390px, 1fr))", gap: 14, alignItems: "start" }}>
          <HostSurface>
            <SectionHeading title="시스템" leading={<DesktopWindowsOutlinedIcon sx={{ fontSize: 19, color: "var(--accent)" }} />} />
            <div style={{ padding: "0 16px 14px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(225px, 1fr))", columnGap: 20 }}>
              {orderedSystem.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13, paddingTop: 12 }}>시스템 정보가 없습니다.</div>}
              {orderedSystem.map((k) => <KeyVal key={k} label={SYSTEM_LABELS[k] ?? k}>{system.get(k)?.value}</KeyVal>)}
            </div>
          </HostSurface>

          <HostSurface>
            <SectionHeading title="네트워크 어댑터" count={interfaces.length} leading={<LanOutlinedIcon sx={{ fontSize: 19, color: "var(--accent)" }} />} />
            <div style={{ margin: "0 16px 14px", display: "flex", flexDirection: "column", borderTop: "1px solid var(--border)" }}>
              {interfaces.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13, paddingTop: 12 }}>IP 구성 정보가 없습니다.</div>}
              {interfaces.map((n) => (
                <button
                  type="button"
                  key={`${n.ip}|${n.guid}`}
                  onClick={() => { setSelectedNetwork(null); setSelectedInterface(n); }}
                  style={{ display: "flex", alignItems: "center", minHeight: 40, padding: "0 12px", background: selectedInterface?.guid === n.guid && selectedInterface?.ip === n.ip ? "var(--bg-selected)" : "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", color: "var(--text)", cursor: "pointer", fontFamily: "inherit", textAlign: "left" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = selectedInterface?.guid === n.guid && selectedInterface?.ip === n.ip ? "var(--bg-selected)" : "transparent")}
                >
                  <span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 750 }}>{n.ip}</span>
                  <ChevronRightOutlinedIcon sx={{ marginLeft: "auto", fontSize: 18, color: "var(--text-faint)" }} />
                </button>
              ))}
            </div>
          </HostSurface>
        </div>

        <HostSurface>
          <SectionHeading title="연결한 네트워크" count={networks.length} leading={<LanOutlinedIcon sx={{ fontSize: 19, color: "var(--accent)" }} />} />
          {networks.length === 0 && <div style={{ color: "var(--text-faint)", fontSize: 13, padding: "12px 16px" }}>연결 기록이 없습니다.</div>}
          <div style={{ padding: "0 16px 14px", display: "flex", flexDirection: "column" }}>
            {networks.map((n) => (
              <button
                type="button"
                key={`${n.name}|${n.timestamp}`}
                title={`${n.name} 상세 보기`}
                aria-label={`${n.name} 네트워크 프로필 상세 보기`}
                onClick={() => { setSelectedInterface(null); setSelectedNetwork(n); }}
                style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto 24px", width: "100%", gap: 16, alignItems: "center", minHeight: 40, padding: "0 2px", background: selectedNetwork?.name === n.name && selectedNetwork?.timestamp === n.timestamp ? "var(--bg-selected)" : "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", color: "inherit", cursor: "pointer", fontFamily: "inherit", textAlign: "left" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = selectedNetwork?.name === n.name && selectedNetwork?.timestamp === n.timestamp ? "var(--bg-selected)" : "transparent")}
              >
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text)", fontSize: 13 }}>{n.name}</span>
                <span style={{ color: "var(--text-time)", fontSize: 12, whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{n.timestamp || "—"}</span>
                <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)" }} />
              </button>
            ))}
          </div>
        </HostSurface>
        </div>
      </div>
      {selectedInterface && (
        <RowDetailPanel
          row={selectedInterface.row}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName="TargetInfo_NetworkInterface"
          onClose={() => setSelectedInterface(null)}
          onNavigate={onNavigate ?? (() => {})}
          onFetchLinkedRows={onFetchLinkedRows}
        />
      )}
      {selectedNetwork && (
        <RowDetailPanel
          row={selectedNetwork.row}
          columns={data.columns}
          focusedColumn={null}
          fileBaseName="TargetInfo_NetworkProfile"
          onClose={() => setSelectedNetwork(null)}
          onNavigate={onNavigate ?? (() => {})}
          onFetchLinkedRows={onFetchLinkedRows}
        />
      )}
    </div>
  );
}

function AccountRegistry({ accounts, bookmarkedRowids, onSelect }: { accounts: Account[]; bookmarkedRowids: Set<number>; onSelect: (account: Account) => void }) {
  const accountGrid: React.CSSProperties = { display: "grid", minWidth: 820, gridTemplateColumns: "minmax(150px, 1.1fr) 92px minmax(190px, 2fr) minmax(166px, 1fr) minmax(210px, 1.55fr) 24px", gap: 10 };
  return (
    <div style={{ padding: "0 16px 14px", overflowX: "auto", overscrollBehaviorX: "contain" }}>
      {accounts.length === 0 ? <div style={{ color: "var(--text-faint)", fontSize: 13, paddingTop: 12 }}>계정이 없습니다.</div> : <>
        <div style={{ ...accountGrid, minHeight: 32, alignItems: "center", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", fontSize: 11.5, fontWeight: 650 }}>
          <span>계정</span><span>유형</span><span>프로필 경로</span><span>생성 시간</span><span>SID</span><span />
        </div>
        {accounts.map((a) => <AccountRow key={a.rowid} account={a} bookmarked={bookmarkedRowids.has(a.rowid)} onSelect={() => onSelect(a)} gridStyle={accountGrid} />)}
      </>}
    </div>
  );
}

function AccountRow({ account, bookmarked, onSelect, gridStyle }: { account: Account; bookmarked?: boolean; onSelect: () => void; gridStyle: React.CSSProperties }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      title="자세히 보기"
      style={{ ...gridStyle, width: "100%", alignItems: "center", textAlign: "left", minHeight: 52, padding: "7px 0", background: bookmarked ? "var(--accent-subtle)" : "transparent", border: "none", borderBottom: "1px solid var(--border-subtle)", borderLeft: bookmarked ? "3px solid var(--accent)" : "3px solid transparent", color: "inherit", cursor: "pointer", fontFamily: "inherit" }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = bookmarked ? "var(--accent-subtle)" : "transparent")}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
        <span title={account.username} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 14, fontWeight: 700, color: "var(--text)" }}>{account.username || "(이름 없음)"}</span>
        {account.disabled === "예" && (
          <span style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", minHeight: 20, lineHeight: 1, whiteSpace: "nowrap", fontSize: 10, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "2px 6px" }}>비활성</span>
        )}
        {account.specialAccount.startsWith("예") && (
          <span title={account.specialAccount} style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", minHeight: 20, lineHeight: 1, whiteSpace: "nowrap", fontSize: 10, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius-sm)", padding: "2px 6px" }}>숨김</span>
        )}
      </div>
      <span style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 4, width: "fit-content", minHeight: 23, padding: "1px 6px", borderRadius: "var(--radius-sm)", background: account.isUser ? "var(--accent-subtle)" : "var(--tag-neutral-bg)", border: `1px solid ${account.isUser ? "var(--accent)" : "var(--border)"}`, color: account.isUser ? "var(--accent)" : "var(--tag-neutral-fg)", fontSize: 10.5, fontWeight: 700 }}>
        {account.isUser ? <PersonOutlineIcon sx={{ fontSize: 14 }} /> : <SettingsOutlinedIcon sx={{ fontSize: 14 }} />}
        {account.isUser ? "사용자" : "시스템"}
      </span>
      <span title={account.path || undefined} style={{ minWidth: 0, color: "var(--text)", fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{account.path || "—"}</span>
      <span style={{ minWidth: 0, color: "var(--text-dim)", fontSize: 11.5, fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{account.created || "—"}</span>
      <span title={account.sid} style={{ minWidth: 0, color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{account.sid}</span>
      <ChevronRightOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} />
    </button>
  );
}

function DetailRow({ label, value, mono, bm }: { label: string; value: string; mono?: boolean; bm?: { active: boolean; onToggle: () => void } }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "8px 10px", margin: "0 -10px", borderBottom: "1px solid var(--border-subtle)", borderLeft: bm?.active ? "3px solid var(--accent)" : "3px solid transparent", background: bm?.active ? "var(--accent-subtle)" : "transparent", alignItems: "center" }}>
      <span style={{ flex: "0 0 142px", color: "var(--text-dim)", fontSize: 12 }}>{label}</span>
      <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: mono ? "var(--mono)" : "var(--sans)" }}>
        {value || "—"}
      </span>
      {bm && value && (
        <button
          onClick={bm.onToggle}
          title={bm.active ? "이 시각 북마크 해제" : "이 시각 북마크"}
          style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 25, height: 24, padding: 0, borderRadius: "var(--radius-sm)", cursor: "pointer", background: bm.active ? "var(--bg-elevated)" : "transparent", color: bm.active ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${bm.active ? "var(--accent)" : "var(--border)"}` }}
        >
          {bm.active ? <BookmarkIcon sx={{ fontSize: 15 }} /> : <BookmarkBorderOutlinedIcon sx={{ fontSize: 15 }} />}
        </button>
      )}
    </div>
  );
}

const EVENT_LABELS: Record<string, string> = {
  "4720": "계정 생성", "4722": "계정 활성화", "4723": "비밀번호 변경 시도", "4724": "비밀번호 재설정",
  "4725": "계정 비활성화", "4726": "계정 삭제", "4738": "계정 변경", "4740": "계정 잠김",
  "4767": "계정 잠금 해제", "4781": "계정 이름 변경", "4728": "전역 그룹에 추가", "4729": "전역 그룹에서 제거",
  "4732": "로컬 그룹에 추가", "4733": "로컬 그룹에서 제거", "4756": "유니버설 그룹에 추가", "4757": "유니버설 그룹에서 제거",
  "4624": "로그온", "4625": "로그온 실패", "4634": "로그오프", "4647": "로그오프", "4648": "명시적 자격증명 로그온",
  "4672": "특수 권한 부여", "4776": "자격증명 검증",
};
const evPgBtn = (disabled: boolean): React.CSSProperties => ({ fontSize: 11.5, padding: "3px 10px", background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.4 : 1 });

function DetailGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ padding: "10px 0 2px" }}>
      <div style={{ paddingBottom: 7, borderBottom: "1px solid var(--border)", color: "var(--text)", fontSize: 12.5, fontWeight: 750 }}>{title}</div>
      <div style={{ padding: "0 10px" }}>{children}</div>
    </section>
  );
}

function parseEd(row: Row): Record<string, unknown> {
  try {
    return row.EventData ? JSON.parse(row.EventData) : {};
  } catch {
    return {};
  }
}

// Flatten nested EventData (e.g. 1149's EventXML.{Param1,Param2,…}) into
// "Key" / "Parent.Child" string pairs, so nested objects show their real values
// instead of "[object Object]".
function flattenEd(obj: unknown, prefix = ""): [string, string][] {
  if (!obj || typeof obj !== "object") return [];
  const out: [string, string][] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) out.push(...flattenEd(v, key));
    else out.push([key, Array.isArray(v) ? v.join(", ") : String(v ?? "")]);
  }
  return out;
}

// One-line summary of an event from its (flattened) data — labeled fields first,
// falling back to the first few short values for events (like 1149) that stash
// everything in unlabeled EventXML params.
function eventSummary(row: Row): string {
  const flat = flattenEd(parseEd(row));
  const val = (...pats: RegExp[]) => {
    for (const [k, v] of flat) if (v && v !== "-" && pats.some((p) => p.test(k))) return v;
    return "";
  };
  const parts: string[] = [];
  const target = val(/target.*user|membername/i);
  const group = val(/group.*name/i);
  const actor = val(/subject.*user/i);
  const logon = val(/logontype/i);
  const ip = val(/ipaddress|clientaddress|\baddress\b/i);
  if (target) parts.push(`대상: ${target}`);
  if (group) parts.push(`그룹: ${group}`);
  if (actor && actor !== target) parts.push(`수행: ${actor}`);
  if (logon) parts.push(`로그온타입 ${logon}`);
  if (ip && !["::1", "127.0.0.1", "-"].includes(ip)) parts.push(`IP ${ip}`);
  if (parts.length === 0) {
    for (const [, v] of flat) {
      if (v && v.length <= 48 && v !== "-" && !/^\d+$/.test(v)) parts.push(v);
      if (parts.length >= 3) break;
    }
  }
  return parts.join(" · ");
}

function AccountDetailPage({ account, onBack, loadEvents, timeRange, onNavigate, onFetchLinkedRows, tableBookmarks, onToggleBookmark }: { account: Account; onBack: () => void; loadEvents?: (sid: string, username: string, query: Omit<AccountEventQuery, "sid" | "username">) => Promise<AccountEventPage>; timeRange: TimeRange; onNavigate?: (targetFile: string, targetColumn: string, value: string) => void; onFetchLinkedRows?: FetchLinkedRows; tableBookmarks?: Bookmark[]; onToggleBookmark?: (rowid: number, field: string) => void }) {
  const [events, setEvents] = useState<AccountEventPage | null>(null);
  const [eventsAccountKey, setEventsAccountKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<Row | null>(null);
  const [evPage, setEvPage] = useState(0);
  const [pageFilterKey, setPageFilterKey] = useState("");
  const [renderedPage, setRenderedPage] = useState(0);
  const [renderedFilterKey, setRenderedFilterKey] = useState("");
  const [eventSearchDraft, setEventSearchDraft] = useState("");
  const [eventSearch, setEventSearch] = useState("");
  const requestSequence = useRef(0);
  const EV_PAGE_SIZE = 10;
  const accountKey = `${account.rowid}\u0000${account.sid}`;
  const filterKey = `${accountKey}\u0000${eventSearch}\u0000${timeRange.start}\u0000${timeRange.end}`;
  // A global range can change while the user is on page N.  Deriving page 0
  // until state catches up avoids dispatching a stale page-N request first.
  const requestedPage = pageFilterKey === filterKey ? evPage : 0;

  // Per-timestamp bookmark state for this account's SAM/profile row.
  const bmKeys = useMemo(() => new Set((tableBookmarks ?? []).map((b) => `${b.rowid}@${b.field ?? ""}`)), [tableBookmarks]);
  const mkBm = (field: string) =>
    onToggleBookmark && Number.isFinite(account.rowid)
      ? { active: bmKeys.has(`${account.rowid}@${field}`), onToggle: () => onToggleBookmark(account.rowid, field) }
      : undefined;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onBack();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onBack]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setEventSearch((current) => current === eventSearchDraft ? current : eventSearchDraft);
    }, 280);
    return () => window.clearTimeout(timeout);
  }, [eventSearchDraft]);

  useEffect(() => {
    if (pageFilterKey !== filterKey) {
      setPageFilterKey(filterKey);
      setEvPage(0);
    }
  }, [filterKey, pageFilterKey]);

  useEffect(() => {
    if (!loadEvents) return;
    let cancelled = false;
    const sequence = ++requestSequence.current;
    setLoading(true);
    setEventsError(null);
    loadEvents(account.sid, account.username, {
      search: eventSearch,
      start: toBound(timeRange.start, "start") || undefined,
      end: toBound(timeRange.end, "end") || undefined,
      offset: requestedPage * EV_PAGE_SIZE,
      limit: EV_PAGE_SIZE,
    })
      .then((page) => {
        if (cancelled || sequence !== requestSequence.current) return;
        setEvents(page);
        setEventsAccountKey(accountKey);
        setRenderedPage(requestedPage);
        setRenderedFilterKey(filterKey);
      })
      .catch((error: unknown) => {
        if (cancelled || sequence !== requestSequence.current) return;
        setEventsError(error instanceof Error ? error.message : "알 수 없는 오류");
        // A refresh failure must not erase the last successful evidence page.
      })
      .finally(() => { if (!cancelled && sequence === requestSequence.current) setLoading(false); });
    return () => { cancelled = true; };
  }, [account.sid, account.username, accountKey, eventSearch, loadEvents, requestedPage, timeRange.end, timeRange.start]);

  const hijack = account.rid && account.ridSam && account.rid !== account.ridSam;
  const visibleEvents = eventsAccountKey === accountKey ? events : null;
  const initialLoading = loading && !visibleEvents;
  const refreshing = loading && Boolean(visibleEvents);
  const evCount = visibleEvents?.rowCount ?? 0;
  const evPageCount = Math.max(1, Math.ceil(evCount / EV_PAGE_SIZE));
  const renderedSafePage = Math.min(renderedPage, evPageCount - 1);
  const pagedEvents = visibleEvents?.rows ?? [];
  const eventRangeStart = evCount === 0 ? 0 : renderedSafePage * EV_PAGE_SIZE + 1;
  const eventRangeEnd = Math.min((renderedSafePage + 1) * EV_PAGE_SIZE, evCount);
  const showingPriorQuery = Boolean(visibleEvents && (renderedFilterKey !== filterKey || renderedSafePage !== requestedPage));
  const sourceFailures = visibleEvents?.sourceFailures ?? [];
  const failedSourceText = sourceFailures.slice(0, 2)
    .map((failure) => `${failure.logName} / ${failure.tableName} (${failure.reason})`)
    .join(" · ");
  const failedSourceMore = sourceFailures.length > 2 ? ` 외 ${sourceFailures.length - 2}개` : "";
  const allSourcesUnreadable = Boolean(visibleEvents && visibleEvents.sourceCount > 0 && visibleEvents.sourcesRead === 0);
  const identityRows = [
    ["계정명", account.username || "(이름 없음)", false],
    ["계정 SID", account.sid, true],
    ["홈 디렉터리", account.homeDir, true],
  ] as const;
  const timeRows = [
    ["생성 시각", account.created, "created"],
    ["최근 로그온", account.lastLogin, "last_login"],
    ["비밀번호 마지막 변경", account.passwordLastSet, "password_last_set"],
    ["마지막 로그인 실패", account.lastFailedLogin, "last_failed_login"],
  ] as const;
  const stateRows = [
    ["계정 상태", account.disabled === "예" ? "비활성" : account.disabled === "아니오" ? "활성" : account.disabled],
    ["특수 계정", account.specialAccount],
    ["로그온 횟수", account.loginCount],
    ["로그인 실패 횟수", account.failedLoginCount],
    ["그룹", account.groups],
    ["권한 / 속성", account.accountFlags],
  ] as const;
  const sameRid = Boolean(account.rid && (!account.ridSam || account.rid === account.ridSam));

  return (
    <div className="dfir-view" style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <header style={{ flexShrink: 0, minHeight: 56, display: "flex", alignItems: "center", gap: 10, padding: "0 24px", background: "var(--bg)", borderBottom: "1px solid var(--border)", zIndex: 2 }}>
        <button onClick={onBack} title="호스트 정보로 돌아가기" aria-label="호스트 정보로 돌아가기" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 28, background: "transparent", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--accent)", cursor: "pointer", padding: 0 }}>
          <ArrowBackOutlinedIcon sx={{ fontSize: 17 }} />
        </button>
        <h1 style={{ margin: 0, color: "var(--text)", fontSize: 20, lineHeight: 1.2, fontWeight: 760, letterSpacing: "-0.02em" }}>계정 상세 <span style={{ color: "var(--text-faint)", padding: "0 3px" }}>|</span> {account.username || "(이름 없음)"}</h1>
        {account.fullName && account.fullName !== account.username && <span style={{ color: "var(--text-dim)", fontSize: 13 }}>{account.fullName}</span>}
        {account.disabled === "예" && <span style={{ marginLeft: "auto", flexShrink: 0, display: "inline-flex", alignItems: "center", minHeight: 22, padding: "1px 7px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-dim)", fontSize: 11, whiteSpace: "nowrap" }}>비활성</span>}
      </header>
      <div className="target-info-account-detail-scroll" style={{ flex: 1, minHeight: 0, overflowY: "auto", overflowX: "hidden", overscrollBehavior: "contain", padding: "14px 24px 32px" }}>
      {hijack && (
        <div style={{ background: "var(--danger-subtle)", border: "1px solid var(--danger)", borderRadius: "var(--radius-md)", padding: "10px 14px", marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 700, color: "var(--danger)" }}><WarningAmberOutlinedIcon sx={{ fontSize: 17 }} /> RID Hijacking 의심</div>
          <div style={{ fontSize: 12, color: "var(--text)", marginTop: 3 }}>
            SAM 키(폴더) RID <b>{account.rid}</b> 와 F 레코드 RID <b>{account.ridSam}</b> 가 다릅니다.
            이 계정은 로그온 시 RID {account.ridSam}{account.ridSam === "500" ? "(Administrator)" : ""} 권한으로 동작할 수 있습니다.
          </div>
        </div>
      )}

      <div className="target-info-account-detail-grid">
        <DetailSurface title="계정 증거">
          <DetailGroup title="식별">
            {identityRows.filter(([, value]) => Boolean(value)).map(([label, value, mono]) => <DetailRow key={label} label={label} value={value} mono={mono} />)}
          </DetailGroup>
          {(account.rid || account.ridSam || stateRows.some(([, value]) => Boolean(value))) && <DetailGroup title="인증 및 상태">
            {sameRid && <DetailRow label="RID" value={account.rid} mono />}
            {!sameRid && account.rid && <DetailRow label="RID (SAM 키 / 폴더)" value={account.rid} mono />}
            {!sameRid && account.ridSam && <DetailRow label="RID (SAM F 레코드)" value={account.ridSam} mono />}
            {stateRows.filter(([, value]) => Boolean(value)).map(([label, value]) => <DetailRow key={label} label={label} value={value} />)}
          </DetailGroup>}
          <DetailGroup title="시간 정보">
            {timeRows.map(([label, value, field]) => <DetailRow key={field} label={label} value={value} mono bm={mkBm(field)} />)}
          </DetailGroup>
        </DetailSurface>

        <DetailSurface title="EventLog 활동" trailing={visibleEvents && evCount > 0 ? <span style={{ color: "var(--text-time)", fontSize: 11.5, fontFamily: "var(--mono)", fontWeight: 500 }}>{eventRangeStart}–{eventRangeEnd} / {evCount.toLocaleString()}건</span> : undefined}>
          {!loadEvents && <div style={{ fontSize: 12.5, color: "var(--text-faint)" }}>이벤트 로그 연동을 사용할 수 없습니다.</div>}
          {loadEvents && <input
            type="search"
            value={eventSearchDraft}
            onChange={(event) => setEventSearchDraft(event.target.value)}
            placeholder="이벤트명, ID, Provider 검색"
            aria-label="EventLog 활동 검색"
            style={{ boxSizing: "border-box", width: "100%", height: 32, marginBottom: 8, padding: "0 10px", background: "var(--bg)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", fontFamily: "var(--sans)", fontSize: 12.5, outline: "none" }}
          />}
          {loadEvents && initialLoading && <div style={{ display: "flex", alignItems: "center", gap: 8, minHeight: 48, color: "var(--text-dim)", fontSize: 12.5 }}><CircularProgress size={16} thickness={4} /> 이 계정의 EventLog 활동을 불러오는 중…</div>}
          {loadEvents && refreshing && <div style={{ display: "flex", alignItems: "center", gap: 6, minHeight: 24, marginBottom: 6, color: "var(--text-dim)", fontSize: 11.5 }}><CircularProgress size={14} thickness={4} /> 결과 갱신 중… {showingPriorQuery ? "이전 결과 표시 중" : "현재 결과 확인 중"}</div>}
          {loadEvents && sourceFailures.length > 0 && <div title={`일부 EventLog 원본을 열 수 없어 결과가 불완전할 수 있습니다 · 읽기 실패: ${sourceFailures.map((failure) => `${failure.logName} / ${failure.tableName} (${failure.reason})`).join(" · ")}`} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 8, padding: "6px 8px", borderLeft: "2px solid var(--warning)", background: "var(--warning-subtle)", color: "var(--warning)", fontSize: 11.5, lineHeight: 1.35 }}>일부 EventLog 원본을 열 수 없어 결과가 불완전할 수 있습니다 · 읽기 실패: {failedSourceText}{failedSourceMore}</div>}
          {loadEvents && eventsError && <div title={eventsError} style={{ paddingBottom: 8, color: "var(--danger)", fontSize: 12.5 }}>{visibleEvents ? "새 EventLog 결과를 불러오지 못했습니다. 이전 결과 표시 중." : `EventLog 활동을 불러오지 못했습니다: ${eventsError}`}</div>}
          {loadEvents && !initialLoading && visibleEvents && evCount === 0 && <div style={{ fontSize: 12.5, color: allSourcesUnreadable ? "var(--warning)" : "var(--text-faint)" }}>{allSourcesUnreadable ? "읽을 수 있는 EventLog 원본이 없습니다. 원본 읽기 실패를 확인하세요." : eventSearch.trim() ? "검색 조건과 기간 필터에 일치하는 EventLog가 없습니다." : "선택한 기간에 이 계정과 관련된 EventLog가 없습니다."}</div>}
          {loadEvents && visibleEvents && evCount > 0 && <div style={{ overflowX: "auto", pointerEvents: refreshing ? "none" : "auto", opacity: refreshing ? 0.65 : 1 }}><div style={{ minWidth: 660 }}>
          {pagedEvents.map((r, i) => {
            const eid = r.EventID || "";
            const label = EVENT_LABELS[eid] || `Event ${eid}`;
            return (
              <button
                type="button"
                key={`${r._record_key || r.EventRecordID || r.timestamp}|${i}`}
                onClick={() => setSelectedEvent(r)}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                style={{ display: "grid", gridTemplateColumns: "minmax(174px, 1.15fr) minmax(150px, 1fr) 70px minmax(160px, 1fr) 22px", width: "100%", alignItems: "center", columnGap: 10, minHeight: 42, padding: "6px 2px", background: "transparent", border: "none", borderBottom: i < pagedEvents.length - 1 ? "1px solid var(--border-subtle)" : "none", color: "inherit", cursor: "pointer", fontFamily: "inherit", textAlign: "left" }}
              >
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 650, color: "var(--text-time)", fontFamily: "var(--mono)" }}>{r.timestamp || "시간 정보 없음"}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13, fontWeight: 700, color: "var(--text)" }}>{label}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{eid || "—"}</span>
                <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12, color: "var(--text-dim)" }}>{r.Provider || r._log || "—"}</span>
                <ChevronRightOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)" }} />
              </button>
            );
          })}
          </div></div>}
          {loadEvents && visibleEvents && evPageCount > 1 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6, marginTop: 10 }}>
              <button onClick={() => { setPageFilterKey(filterKey); setEvPage(renderedSafePage - 1); }} disabled={refreshing || renderedSafePage === 0} aria-label="이전 이벤트 페이지" title="이전" style={{ ...evPgBtn(refreshing || renderedSafePage === 0), display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 26, padding: 0 }}><ChevronLeftOutlinedIcon sx={{ fontSize: 17 }} /></button>
              <span style={{ fontSize: 11.5, color: "var(--text-dim)" }}>{renderedSafePage + 1} / {evPageCount} 쪽 <span style={{ color: "var(--text-faint)" }}>({evCount.toLocaleString()}건)</span></span>
              <button onClick={() => { setPageFilterKey(filterKey); setEvPage(renderedSafePage + 1); }} disabled={refreshing || renderedSafePage >= evPageCount - 1} aria-label="다음 이벤트 페이지" title="다음" style={{ ...evPgBtn(refreshing || renderedSafePage >= evPageCount - 1), display: "inline-flex", alignItems: "center", justifyContent: "center", width: 28, height: 26, padding: 0 }}><ChevronRightOutlinedIcon sx={{ fontSize: 17 }} /></button>
            </div>
          )}
        </DetailSurface>
      </div>
      </div>

      {selectedEvent && (
        <RowDetailPanel
          row={selectedEvent}
          columns={Object.keys(selectedEvent)}
          focusedColumn={null}
          fileBaseName="EventLog_Events"
          onClose={() => setSelectedEvent(null)}
          onNavigate={onNavigate ?? (() => {})}
          onFetchLinkedRows={onFetchLinkedRows}
        />
      )}
    </div>
  );
}

function EventDetailModal({ row, onClose }: { row: Row; onClose: () => void }) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const eid = row.EventID || "";
  const label = EVENT_LABELS[eid] || `Event ${eid}`;
  const summary = eventSummary(row);
  // System/meta columns to show (skip internal + the raw EventData blob, which
  // is expanded field-by-field below).
  const META_ORDER = ["timestamp", "EventID", "LevelName", "Provider", "Channel", "Computer", "EventRecordID", "ProcessID", "ThreadID", "UserID", "_log", "_record_key"];
  const meta = META_ORDER.filter((k) => row[k]).map((k) => [k, row[k]] as [string, string]);
  // Flatten so nested objects (e.g. 1149 EventXML) expand into readable rows
  // rather than "[object Object]".
  const edEntries = flattenEd(parseEd(row)).filter(([, v]) => v !== "");

  return (
    <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(1,4,9,0.7)", zIndex: 300, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: "min(720px, 96vw)", maxHeight: "88vh", display: "flex", flexDirection: "column", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-panel)", overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 16px", borderBottom: "1px solid var(--border)", background: "var(--bg-elevated)", flexShrink: 0 }}>
          <span style={{ fontSize: 14.5, fontWeight: 700 }}>{label}</span>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>EventID {eid} · {row._log || row.Channel || ""}</span>
          <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{row.timestamp}</span>
          <button onClick={onClose} title="닫기 (Esc)" style={{ background: "transparent", border: "none", color: "var(--text-dim)", fontSize: 20, cursor: "pointer", lineHeight: 1, padding: "0 4px" }}>×</button>
        </div>
        <div style={{ padding: "6px 16px 16px", overflow: "auto" }}>
          {summary && <div style={{ fontSize: 12.5, color: "var(--text-dim)", padding: "4px 0 8px" }}>{summary}</div>}
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "8px 0 2px" }}>이벤트</div>
          {meta.map(([k, v]) => (
            <DetailRow key={k} label={k} value={v} mono={k === "_record_key" || k === "UserID"} />
          ))}
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-faint)", margin: "12px 0 2px" }}>EventData ({edEntries.length})</div>
          {edEntries.length === 0 && <div style={{ fontSize: 12, color: "var(--text-faint)", padding: "6px 0" }}>추가 데이터 없음</div>}
          {edEntries.map(([k, v]) => (
            <DetailRow key={k} label={k} value={String(v)} mono />
          ))}
        </div>
      </div>
    </div>
  );
}
