"use client";
import { lookupEventCatalog } from "@/lib/eventCatalog";
import EventNoteOutlinedIcon from "@mui/icons-material/EventNoteOutlined";
import { ViewHeader } from "@/components/FilterControls";

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
import WifiOutlinedIcon from "@mui/icons-material/WifiOutlined";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import type { AccountEventPage, AccountEventQuery, CsvData, Bookmark } from "@/lib/types";
import type { FetchLinkedRows } from "@/lib/types";
import { toBound, type TimeRange } from "@/lib/timeRange";
import RowDetailPanel from "./RowDetailPanel";
import type { AccountDirectory } from "@/lib/accountIdentity";
import { basename } from "@/lib/viewShared";
import PaginationControls from "@/components/PaginationControls";

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
  /** Account EventLog rows come from a raw source table, not TargetInfo. */
  eventBookmarks?: Bookmark[];
  onToggleEventBookmark?: (fullPath: string, tableName: string, rowid: number) => void;
  accountDirectory?: AccountDirectory;
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

export default function TargetInfoView({ data, loadAccountEvents, timeRange, onNavigate, onFetchLinkedRows, tableBookmarks, onToggleBookmark, eventBookmarks, onToggleEventBookmark, accountDirectory }: TargetInfoViewProps) {
  const bmRowids = useMemo(() => new Set((tableBookmarks ?? []).map((b) => b.rowid)), [tableBookmarks]);
  const [selectedAccount, setSelectedAccount] = useState<Account | null>(null);
  // 좌측 범주 내비게이션(25%)에서 고른 섹션을 우측(75%)에 표시한다.
  const [section, setSection] = useState<"accounts" | "system" | "interfaces" | "networks">("accounts");
  // 시스템 값 카드 클릭 → 즉시 복사, 잠깐 "복사됨" 표시.
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
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
    return <AccountDetailPage account={selectedAccount} onBack={() => setSelectedAccount(null)} loadEvents={loadAccountEvents} timeRange={timeRange} onNavigate={onNavigate} onFetchLinkedRows={onFetchLinkedRows} tableBookmarks={tableBookmarks} onToggleBookmark={onToggleBookmark} eventBookmarks={eventBookmarks} onToggleEventBookmark={onToggleEventBookmark} accountDirectory={accountDirectory} />;
  }

  const accounts = [...users, ...services];

  const sections = [
    { key: "accounts" as const, label: "계정 정보", icon: ManageAccountsOutlinedIcon },
    { key: "system" as const, label: "시스템", icon: DesktopWindowsOutlinedIcon },
    { key: "interfaces" as const, label: "네트워크 어댑터", icon: LanOutlinedIcon },
    { key: "networks" as const, label: "연결한 네트워크", icon: WifiOutlinedIcon },
  ];

  return (
    <div className="dfir-view" style={{ flex: 1, minWidth: 0, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg)" }}>
      <ViewHeader icon={InfoOutlinedIcon} title={<>호스트 정보 <span aria-hidden="true" style={{ color: "var(--text-faint)", padding: "0 2px" }}>|</span> {computerName}</>} right={osSummary ? <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12.5 }}>{osSummary}</span> : undefined} />

      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "minmax(170px, 15%) minmax(0, 1fr)", overflow: "hidden" }}>
        <nav aria-label="호스트 정보 범주" style={{ minHeight: 0, overflow: "auto", padding: 10, borderRight: "1px solid var(--border)" }}>
          <div style={{ padding: "4px 8px 8px", color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700 }}>호스트 범주</div>
          {sections.map(({ key, label, icon: Icon }) => {
            const active = section === key;
            return (
              <button key={key} type="button" onClick={() => setSection(key)} className={active ? "nm-btn" : undefined} style={{ width: "100%", minHeight: 36, marginBottom: 2, padding: "0 10px", display: "flex", alignItems: "center", justifyContent: "flex-start", gap: 8, border: active ? "1px solid color-mix(in srgb, var(--accent) 45%, var(--border))" : "1px solid transparent", borderRadius: "var(--radius-md)", background: active ? "var(--accent-subtle)" : "transparent", color: active ? "var(--text)" : "var(--text-dim)", cursor: "pointer", textAlign: "left" }}>
                <Icon sx={{ fontSize: 16, flexShrink: 0, color: active ? "var(--accent)" : "inherit" }} />
                <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 12.5, fontWeight: active ? 700 : 550 }}>{label}</span>
              </button>
            );
          })}
        </nav>

        <section style={{ minWidth: 0, minHeight: 0, overflow: "auto", overscrollBehavior: "contain", padding: 14 }}>
          {section === "accounts" && <AccountRegistry accounts={accounts} bookmarkedRowids={bmRowids} onSelect={setSelectedAccount} />}

          {section === "system" && (
            orderedSystem.length === 0 ? (
              <div style={{ color: "var(--text-faint)", fontSize: 13 }}>시스템 정보가 없습니다.</div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 8, alignContent: "start" }}>
                {orderedSystem.map((k) => {
                  const value = system.get(k)?.value || "";
                  // 시각·빌드류 값은 모노스페이스로.
                  const mono = /Time|Date|Build/i.test(k) || /^\d{4}-\d{2}-\d{2}/.test(value);
                  const copied = copiedKey === k;
                  return (
                    <button
                      key={k}
                      type="button"
                      title="클릭하면 값을 복사합니다"
                      aria-label={`${SYSTEM_LABELS[k] ?? k} 값 복사`}
                      onClick={() => {
                        if (!value) return;
                        navigator.clipboard?.writeText(value).then(() => {
                          setCopiedKey(k);
                          setTimeout(() => setCopiedKey((current) => (current === k ? null : current)), 1200);
                        });
                      }}
                      style={{ border: `1px solid ${copied ? "color-mix(in srgb, var(--success) 55%, var(--border))" : "var(--border)"}`, borderRadius: "var(--radius-md)", background: "var(--bg-panel)", padding: "10px 14px", display: "flex", alignItems: "center", gap: 12, color: "inherit", cursor: value ? "pointer" : "default", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "var(--bg-panel)"; }}
                    >
                      <span style={{ width: 150, flexShrink: 0, color: "var(--text-faint)", fontSize: 11.5, fontWeight: 700, letterSpacing: 0.3 }}>{SYSTEM_LABELS[k] ?? k}</span>
                      <span style={{ flex: 1, minWidth: 0, color: value ? "var(--text)" : "var(--text-faint)", fontSize: 14, fontWeight: 650, fontFamily: mono ? "var(--mono)" : undefined, wordBreak: "break-all" }}>{value || "정보 없음"}</span>
                      {copied && <span style={{ flexShrink: 0, color: "var(--success)", fontSize: 11.5, fontWeight: 700 }}>복사됨</span>}
                    </button>
                  );
                })}
              </div>
            )
          )}

          {section === "interfaces" && (
            interfaces.length === 0 ? <div style={{ color: "var(--text-faint)", fontSize: 13 }}>IP 구성 정보가 없습니다.</div> : interfaces.map((n) => {
              const active = selectedInterface?.guid === n.guid && selectedInterface?.ip === n.ip;
              const detailLine = [n.gateway && `게이트웨이 ${n.gateway}`, n.dns && `DNS ${n.dns}`, n.domain && `도메인 ${n.domain}`].filter(Boolean).join(" · ");
              return (
                <button
                  type="button"
                  key={`${n.ip}|${n.guid}`}
                  onClick={() => { setSelectedNetwork(null); setSelectedInterface(n); }}
                  aria-label={`${n.ip} 어댑터 상세 보기`}
                  style={{ borderRadius: "var(--radius-md)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 58, marginBottom: 8, padding: "9px 14px", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--bg-selected)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = active ? "var(--bg-selected)" : "var(--bg-panel)"; }}
                >
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "var(--accent-subtle)" }}>
                    <LanOutlinedIcon sx={{ fontSize: 17, color: "var(--accent)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 700 }}>{n.ip}</span>
                    {detailLine && <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12 }}>{detailLine}</span>}
                  </span>
                  <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
                </button>
              );
            })
          )}

          {section === "networks" && (
            networks.length === 0 ? <div style={{ color: "var(--text-faint)", fontSize: 13 }}>연결 기록이 없습니다.</div> : networks.map((n) => {
              const active = selectedNetwork?.name === n.name && selectedNetwork?.timestamp === n.timestamp;
              return (
                <button
                  type="button"
                  key={`${n.name}|${n.timestamp}`}
                  title={`${n.name} 상세 보기`}
                  aria-label={`${n.name} 네트워크 프로필 상세 보기`}
                  onClick={() => { setSelectedInterface(null); setSelectedNetwork(n); }}
                  style={{ borderRadius: "var(--radius-md)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 52, marginBottom: 8, padding: "8px 14px", border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`, background: active ? "var(--bg-selected)" : "var(--bg-panel)", color: "var(--text)", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
                  onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = "var(--bg-hover)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = active ? "var(--bg-selected)" : "var(--bg-panel)"; }}
                >
                  <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--text-dim) 14%, transparent)" }}>
                    <WifiOutlinedIcon sx={{ fontSize: 17, color: "var(--text-dim)" }} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13, fontWeight: 600 }}>{n.name}</span>
                  <span style={{ flexShrink: 0, color: n.timestamp ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, whiteSpace: "nowrap", fontFamily: "var(--mono)" }}>{n.timestamp || "시간 정보 없음"}</span>
                  <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
                </button>
              );
            })
          )}
        </section>
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
          accountDirectory={accountDirectory}
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
          accountDirectory={accountDirectory}
        />
      )}
    </div>
  );
}

function AccountRegistry({ accounts, bookmarkedRowids, onSelect }: { accounts: Account[]; bookmarkedRowids: Set<number>; onSelect: (account: Account) => void }) {
  return (
    <div>
      {accounts.length === 0 ? (
        <div style={{ color: "var(--text-faint)", fontSize: 13 }}>계정이 없습니다.</div>
      ) : (
        accounts.map((a) => <AccountRow key={a.rowid} account={a} bookmarked={bookmarkedRowids.has(a.rowid)} onSelect={() => onSelect(a)} />)
      )}
    </div>
  );
}

function AccountRow({ account, bookmarked, onSelect }: { account: Account; bookmarked?: boolean; onSelect: () => void }) {
  // 타일 색: 사용자 계정=블루, 시스템 계정=중립, 숨김(특수) 계정=옐로 경고.
  const tileColor = account.specialAccount.startsWith("예") ? "var(--warning)" : account.isUser ? "var(--accent)" : "var(--text-dim)";
  return (
    <button
      type="button"
      onClick={onSelect}
      title="자세히 보기"
      aria-label={`${account.username || "이름 없는 계정"} 계정 상세 보기${bookmarked ? ", 북마크됨" : ""}`}
      className={bookmarked ? "dfir-bookmarked-row" : undefined}
      style={{ borderRadius: "var(--radius-md)", width: "100%", display: "flex", alignItems: "center", gap: 12, minHeight: 62, marginBottom: 8, padding: "10px 14px", border: "1px solid var(--border)", background: "var(--bg-panel)", color: "inherit", cursor: "pointer", textAlign: "left", fontFamily: "inherit", transition: "background .15s ease, border-color .15s ease" }}
      onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
      onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-panel)"; }}
    >
      <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 34, height: 34, flexShrink: 0, borderRadius: "var(--radius-sm)", background: `color-mix(in srgb, ${tileColor} 15%, transparent)` }}>
        {account.isUser ? <PersonOutlineIcon sx={{ fontSize: 17, color: tileColor }} /> : <SettingsOutlinedIcon sx={{ fontSize: 17, color: tileColor }} />}
      </span>
      <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 3 }}>
        <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
          <span title={account.username} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 13.5, fontWeight: 700, color: "var(--text)" }}>{account.username || "(이름 없음)"}</span>
          <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: account.isUser ? "var(--accent)" : "var(--text-dim)", border: `1px solid ${account.isUser ? "var(--accent)" : "var(--border)"}`, borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>{account.isUser ? "사용자" : "시스템"}</span>
          {account.disabled === "예" && <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--text-faint)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>비활성</span>}
          {account.specialAccount.startsWith("예") && <span title={account.specialAccount} style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, color: "var(--warning)", border: "1px solid var(--warning)", borderRadius: "var(--radius-sm)", padding: "1px 8px", whiteSpace: "nowrap" }}>숨김</span>}
        </span>
        <span title={account.path || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: account.path ? "var(--text-dim)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" }}>{account.path || "프로필 경로 없음"}</span>
      </span>
      <span title={account.sid} style={{ width: 330, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)", fontSize: 12, fontFamily: "var(--mono)" }}>{account.sid}</span>
      <span style={{ width: 172, flexShrink: 0, textAlign: "right", color: account.created ? "var(--text-time)" : "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{account.created || "생성 시간 없음"}</span>
      <ChevronRightOutlinedIcon sx={{ fontSize: 18, color: "var(--text-faint)", flexShrink: 0 }} />
    </button>
  );
}

function DetailRow({ label, value, mono, bm }: { label: string; value: string; mono?: boolean; bm?: { active: boolean; onToggle: () => void } }) {
  return (
    <div className={bm?.active ? "dfir-bookmarked-row" : undefined} style={{ display: "flex", gap: 12, padding: "8px 10px", margin: "0 -10px", borderBottom: "1px solid var(--border-subtle)", borderLeft: "3px solid transparent", background: "transparent", alignItems: "center" }}>
      <span style={{ flex: "0 0 142px", color: "var(--text-dim)", fontSize: 12 }}>{label}</span>
      <span style={{ flex: 1, color: "var(--text)", fontSize: 12.5, wordBreak: "break-all", fontFamily: mono ? "var(--mono)" : "var(--sans)" }}>
        {value || "—"}
      </span>
      {bm && value && (
        <button
          className={bm.active ? "dfir-bookmark-control" : undefined}
          onClick={bm.onToggle}
          title={bm.active ? "이 시각 북마크 해제" : "이 시각 북마크"}
          style={{ flexShrink: 0, display: "inline-flex", alignItems: "center", justifyContent: "center", width: 25, height: 24, padding: 0, borderRadius: "var(--radius-sm)", cursor: "pointer", background: bm.active ? "var(--bookmark-row)" : "transparent", color: bm.active ? "var(--bookmark-control)" : "var(--text-dim)", border: `1px solid ${bm.active ? "var(--bookmark-outline)" : "var(--border)"}` }}
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

function AccountDetailPage({ account, onBack, loadEvents, timeRange, onNavigate, onFetchLinkedRows, tableBookmarks, onToggleBookmark, eventBookmarks, onToggleEventBookmark, accountDirectory }: { account: Account; onBack: () => void; loadEvents?: (sid: string, username: string, query: Omit<AccountEventQuery, "sid" | "username">) => Promise<AccountEventPage>; timeRange: TimeRange; onNavigate?: (targetFile: string, targetColumn: string, value: string) => void; onFetchLinkedRows?: FetchLinkedRows; tableBookmarks?: Bookmark[]; onToggleBookmark?: (rowid: number, field: string) => void; eventBookmarks?: Bookmark[]; onToggleEventBookmark?: (fullPath: string, tableName: string, rowid: number) => void; accountDirectory?: AccountDirectory }) {
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
  const eventBookmarkKeys = useMemo(() => new Set((eventBookmarks ?? [])
    .filter((bookmark) => !bookmark.field)
    .map((bookmark) => `${bookmark.fullPath}\u0000${bookmark.tableName}\u0000${bookmark.rowid}`)), [eventBookmarks]);
  const eventSource = (row: Row) => {
    const fullPath = row._source_full_path || "";
    const tableName = row._source_table_name || "";
    const rowid = Number(row.__rowid);
    return fullPath && tableName && Number.isFinite(rowid) ? { fullPath, tableName, rowid } : null;
  };
  const isEventBookmarked = (row: Row) => {
    const source = eventSource(row);
    return Boolean(source && eventBookmarkKeys.has(`${source.fullPath}\u0000${source.tableName}\u0000${source.rowid}`));
  };

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // RowDetailPanel owns Escape while a raw EventLog detail is open. Do
      // not let the account page navigate away beneath the active drawer.
      if (e.key === "Escape" && !selectedEvent) onBack();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onBack, selectedEvent]);

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
      <header style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", padding: "12px 16px 10px", minHeight: 24, background: "var(--bg-panel)", borderBottom: "1px solid var(--border)", zIndex: 2 }}>
        <button className="nm-btn" onClick={onBack} title="호스트 정보로 돌아가기" aria-label="호스트 정보로 돌아가기" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 31, height: 31, background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: "var(--radius-md)", color: "var(--accent)", cursor: "pointer", padding: 0, marginRight: 2 }}>
          <ArrowBackOutlinedIcon sx={{ fontSize: 17 }} />
        </button>
        <ManageAccountsOutlinedIcon sx={{ fontSize: 18, color: "var(--accent)" }} aria-hidden="true" />
        <strong style={{ fontSize: 15, color: "var(--text)", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>계정 상세 <span aria-hidden="true" style={{ color: "var(--text-faint)", padding: "0 2px" }}>|</span> {account.username || "(이름 없음)"}</strong>
        {account.fullName && account.fullName !== account.username && <span style={{ color: "var(--text-faint)", fontSize: 12 }}>{account.fullName}</span>}
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}>
          {account.disabled === "예"
            ? <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--text-faint)", whiteSpace: "nowrap" }}>비활성</span>
            : account.disabled === "아니오"
              ? <span style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", border: "1px solid var(--success)", borderRadius: "var(--radius-sm)", color: "var(--success)", whiteSpace: "nowrap" }}>활성</span>
              : null}
          {account.specialAccount.startsWith("예") && <span title={account.specialAccount} style={{ flexShrink: 0, fontSize: 11.5, fontWeight: 700, padding: "1px 8px", border: "1px solid var(--warning)", borderRadius: "var(--radius-sm)", color: "var(--warning)", whiteSpace: "nowrap" }}>숨김 계정</span>}
        </span>
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
            const catalogNote = lookupEventCatalog(r.Provider, eid)?.label || (EVENT_LABELS[eid] && EVENT_LABELS[eid] !== `Event ${eid}` ? EVENT_LABELS[eid] : "");
            const summary = eventSummary(r);
            const bookmarked = isEventBookmarked(r);
            return (
              <button
                type="button"
                key={`${r._record_key || r.EventRecordID || r.timestamp}|${i}`}
                className={bookmarked ? "dfir-bookmarked-row" : undefined}
                onClick={() => setSelectedEvent(r)}
                onMouseEnter={(e) => { if (!bookmarked) e.currentTarget.style.background = "var(--bg-hover)"; }}
                onMouseLeave={(e) => { if (!bookmarked) e.currentTarget.style.background = "transparent"; }}
                style={{ borderRadius: "var(--radius-sm)", display: "flex", alignItems: "center", gap: 10, width: "100%", minHeight: 50, padding: "7px 4px", background: "transparent", border: "none", borderBottom: i < pagedEvents.length - 1 ? "1px solid var(--border-subtle)" : "none", color: "inherit", cursor: "pointer", fontFamily: "inherit", textAlign: "left", transition: "background .15s ease" }}
              >
                <span aria-hidden="true" style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, flexShrink: 0, borderRadius: "var(--radius-sm)", background: "rgba(174, 189, 255, 0.14)" }}>
                  <EventNoteOutlinedIcon sx={{ fontSize: 16, color: "#aebdff" }} />
                </span>
                <span style={{ flex: 1, minWidth: 0, display: "grid", gap: 2 }}>
                  <span style={{ display: "flex", alignItems: "center", gap: 7, minWidth: 0 }}>
                    <span style={{ flexShrink: 0, fontSize: 13, fontWeight: 700, color: "var(--text)" }}>Event {eid || "—"}</span>
                    {catalogNote && <span title={catalogNote} style={{ flexShrink: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "#5bc8c0", border: "1px solid #5bc8c0", borderRadius: "var(--radius-sm)", padding: "1px 7px", fontSize: 11, fontWeight: 650 }}>{catalogNote}</span>}
                  </span>
                  <span title={summary || undefined} style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontSize: 11.5, color: "var(--text-faint)" }}>{[r.Provider || r._log, summary].filter(Boolean).join(" · ") || "—"}</span>
                </span>
                <span style={{ flexShrink: 0, width: 172, textAlign: "right", fontSize: 12.5, fontWeight: 600, color: r.timestamp ? "var(--text-time)" : "var(--text-faint)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{r.timestamp || "시간 정보 없음"}</span>
                <ChevronRightOutlinedIcon sx={{ fontSize: 17, color: "var(--text-faint)", flexShrink: 0 }} />
              </button>
            );
          })}
          </div></div>}
          {loadEvents && visibleEvents && evPageCount > 1 && (
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
              <PaginationControls ariaLabel="이벤트 페이지" page={renderedSafePage} pageCount={evPageCount} disabled={refreshing} onChange={(next) => { setPageFilterKey(filterKey); setEvPage(next); }} summary={`(${evCount.toLocaleString()}건)`} />
            </div>
          )}
        </DetailSurface>
      </div>
      </div>

      {selectedEvent && (
        <RowDetailPanel
          // Source identity stays in account-query state for exact bookmark
          // operations; it is transport metadata, not analyst-facing EventLog
          // evidence and must not appear in the common full-fields panel.
          row={Object.fromEntries(Object.entries(selectedEvent).filter(([key]) => key !== "_source_full_path" && key !== "_source_table_name" && key !== "__rowid"))}
          columns={Object.keys(selectedEvent).filter((key) => key !== "_source_full_path" && key !== "_source_table_name" && key !== "__rowid")}
          focusedColumn={null}
          fileBaseName="EventLog_Events"
          onClose={() => setSelectedEvent(null)}
          onNavigate={onNavigate ?? (() => {})}
          onFetchLinkedRows={onFetchLinkedRows}
          accountDirectory={accountDirectory}
          isBookmarked={isEventBookmarked(selectedEvent)}
          onToggleBookmark={(() => {
            const source = eventSource(selectedEvent);
            return source && onToggleEventBookmark
              ? () => onToggleEventBookmark(source.fullPath, source.tableName, source.rowid)
              : undefined;
          })()}
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
